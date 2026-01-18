use crate::asm::Assemble;
use crate::result::WispResult;
use core::slice;
use dynasmrt::aarch64::Assembler;
use dynasmrt::{ExecutableBuffer, cache_control};
use log::warn;
use region::Region;
use std::ffi::c_void;
use std::marker::PhantomData;

mod align;
mod asm;
mod errno;
mod mman;
mod result;

pub trait Unhooker: Sized {
    fn unhook(stub: &Stub<Self>) -> WispResult<()>;
}

pub struct SimpleUnhooker;

impl Unhooker for SimpleUnhooker {
    fn unhook(stub: &Stub<Self>) -> WispResult<()> {
        unsafe {
            mman::write_memory(stub.target, &stub.backup_insn)?;
            cache_control::synchronize_icache(slice::from_raw_parts(
                stub.target as _,
                stub.backup_insn.len(),
            ));
        }

        Ok(())
    }
}

pub struct Stub<U: Unhooker> {
    target: *const c_void,
    backup_insn: Vec<u8>,
    region: Region,
    _trampolines: Vec<ExecutableBuffer>,
    _fake: PhantomData<fn(U) -> U>,
}

impl<U: Unhooker> Stub<U> {
    fn new(
        target: *const c_void,
        backup_insn: Vec<u8>,
        region: Region,
        trampolines: Vec<ExecutableBuffer>,
    ) -> Self {
        Self {
            target,
            backup_insn,
            region,
            _trampolines: trampolines,
            _fake: PhantomData,
        }
    }

    pub fn target(&self) -> *const c_void {
        self.target
    }

    pub fn backup_insn(&self) -> &[u8] {
        &self.backup_insn
    }

    pub fn region(&self) -> &Region {
        &self.region
    }
}

impl<U: Unhooker> Drop for Stub<U> {
    fn drop(&mut self) {
        if let Err(err) = U::unhook(self) {
            warn!("failed to unhook: {err:?}")
        }
    }
}

#[derive(Copy, Clone)]
pub struct CustomWisp<U: Unhooker = SimpleUnhooker>(PhantomData<fn(U) -> U>);

impl<U: Unhooker> CustomWisp<U> {
    /// Replaces the target function with a proxy function.
    ///
    /// # Safety
    ///
    /// - `target_fn` and `proxy_fn` must be valid pointers to executable code.
    /// - The caller must ensure that the target function is not being executed by other threads
    ///   simultaneously to avoid race conditions during the patching process.
    pub unsafe fn replace_fn(
        target_fn: *const c_void,
        proxy_fn: *const c_void,
    ) -> WispResult<Stub<U>> {
        let region = region::query(target_fn)?;
        let branch_insn = asm::branch_to(proxy_fn)?;

        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, branch_insn.len()) };

        let mut backup_insn = Vec::new();

        backup_insn.extend_from_slice(backup_region);

        unsafe {
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
        }

        Ok(Stub::new(target_fn, backup_insn, region, Vec::new()))
    }

    /// Hooks the target function, allowing the proxy function to call the original implementation.
    ///
    /// # Safety
    ///
    /// - `target_fn` and `proxy_fn` must be valid pointers to executable code.
    /// - `backup_orig` must be a valid mutable reference to a pointer.
    /// - The caller must ensure that the target function is not being executed by other threads
    ///   simultaneously to avoid race conditions during the patching process.
    pub unsafe fn hook_fn(
        target_fn: *const c_void,
        proxy_fn: *const c_void,
        backup_orig: &mut *const c_void,
    ) -> WispResult<Stub<U>> {
        let region = region::query(target_fn)?;
        let branch_insn = asm::branch_to(proxy_fn)?;

        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, branch_insn.len()) };
        let mut backup_insn = Vec::new();

        backup_insn.extend_from_slice(backup_region);

        let trampoline_insn = unsafe {
            let target_next = target_fn.add(branch_insn.len()) as usize;

            let mut ops = Assembler::new()?;

            arm64asm!(ops
                ;; ops.extend(&backup_insn)
                ; movz x17, #(target_next & 0xffff) as _
                ; movk x17, #((target_next >> 16) & 0xffff) as _, lsl #16
                ; movk x17, #((target_next >> 32) & 0xffff) as _, lsl #32
                ; br x17
                ; brk #0
            );

            ops.assemble()?
        };

        unsafe {
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
        }

        *backup_orig = trampoline_insn.as_ptr() as _;

        Ok(Stub::new(
            target_fn,
            backup_insn,
            region,
            vec![trampoline_insn],
        ))
    }
}

pub type Wisp = CustomWisp<SimpleUnhooker>;

#[cfg(test)]
mod tests {
    use crate::Wisp;
    use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
    use region::Protection;
    use std::ffi::c_void;
    use std::{mem, ptr};

    macro_rules! repeat {
        ($n: literal, $($body:tt)*) => {
            for _ in 0..$n {
                $($body)*
            }
        };
    }

    #[test]
    fn test_region_flags() {
        assert_eq!(Protection::READ.bits() as i32, PROT_READ);
        assert_eq!(Protection::WRITE.bits() as i32, PROT_WRITE);
        assert_eq!(Protection::EXECUTE.bits() as i32, PROT_EXEC);
    }

    #[test]
    fn test_replace() {
        extern "C" fn target_fn(a: i32, b: i32) -> i32 {
            a + b
        }

        extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
            a * b
        }

        let _keep = unsafe {
            Wisp::replace_fn(target_fn as _, proxy_fn as _).expect("failed to replace func")
        };

        repeat!(100, {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(target_fn(a, b), proxy_fn(a, b));
        })
    }

    #[test]
    fn test_hook() {
        static mut ORIG_FN: *const c_void = ptr::null_mut();

        extern "C" fn target_fn(a: i32, b: i32) -> i32 {
            a + b
        }

        extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
            unsafe {
                assert_eq!(
                    mem::transmute::<*const c_void, fn(i32, i32) -> i32>(ORIG_FN)(a, b),
                    a + b
                );
            }

            a * b
        }

        #[allow(static_mut_refs)]
        let _keep = unsafe {
            Wisp::hook_fn(target_fn as _, proxy_fn as _, &mut ORIG_FN).expect("failed to hook func")
        };

        assert!(unsafe { !ORIG_FN.is_null() });

        repeat!(100, {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(target_fn(a, b), proxy_fn(a, b));
        })
    }

    #[test]
    fn test_unhook() {
        extern "C" fn replace_target(a: i32, b: i32) -> i32 {
            a + b
        }

        extern "C" fn hook_target(a: i32, b: i32) -> i32 {
            a + b
        }

        extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
            a * b
        }

        repeat!(100, {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(replace_target(a, b), a + b);
            assert_eq!(hook_target(a, b), a + b);
        });

        let replace_stub = unsafe {
            Wisp::replace_fn(replace_target as _, proxy_fn as _).expect("failed to replace func")
        };

        let mut orig_fn: *const c_void = ptr::null_mut();
        let hook_stub = unsafe {
            Wisp::hook_fn(hook_target as _, proxy_fn as _, &mut orig_fn)
                .expect("failed to hook func")
        };

        repeat!(100, {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(replace_target(a, b), a * b);
            assert_eq!(hook_target(a, b), a * b);
        });

        drop(replace_stub);
        drop(hook_stub);

        repeat!(100, {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(replace_target(a, b), a + b);
            assert_eq!(hook_target(a, b), a + b);
        });
    }

    #[test]
    #[ignore]
    fn test_unwind() {
        static mut ORIG_FN: *const c_void = ptr::null_mut();

        extern "C" fn target_fn(a: i32, b: i32) -> i32 {
            unsafe {
                libc::raise(35);
            }
            a + b
        }

        extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
            unsafe { mem::transmute::<*const c_void, fn(i32, i32) -> i32>(ORIG_FN)(a, b) }
        }

        #[allow(static_mut_refs)]
        unsafe {
            Wisp::hook_fn(target_fn as _, proxy_fn as _, &mut ORIG_FN)
                .expect("failed to hook func");
        }

        assert!(unsafe { !ORIG_FN.is_null() });

        target_fn(3, 5);
    }
}
