use crate::asm::Assemble;
use crate::result::WispResult;
use core::slice;
use dynasmrt::aarch64::Assembler;
use dynasmrt::{cache_control, ExecutableBuffer};
use std::ffi::c_void;

mod align;
mod asm;
mod errno;
mod mman;
mod result;

// Todo: drop for unhook
pub struct Stub {
    _buffer: ExecutableBuffer,
}

impl Stub {
    pub fn new(buffer: ExecutableBuffer) -> Self {
        Stub { _buffer: buffer }
    }
}

pub unsafe fn replace_fn(target_fn: *const c_void, proxy_fn: *const c_void) -> WispResult<()> {
    let branch_insn = asm::branch_to(proxy_fn)?;

    unsafe {
        mman::write_memory(target_fn, &branch_insn)?;
        cache_control::synchronize_icache(slice::from_raw_parts(target_fn as _, branch_insn.len()));
    }

    Ok(())
}

pub unsafe fn hook_fn(
    target_fn: *const c_void,
    proxy_fn: *const c_void,
    backup_orig: &mut *const c_void,
) -> WispResult<Stub> {
    let branch_insn = asm::branch_to(proxy_fn)?;

    let trampoline_insn = unsafe {
        let backup_insn = slice::from_raw_parts(target_fn as *const u8, branch_insn.len());
        let target_next = target_fn.add(branch_insn.len()) as usize;

        let mut ops = Assembler::new()?;

        arm64asm!(ops
            ;; ops.extend(backup_insn)
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
        cache_control::synchronize_icache(slice::from_raw_parts(target_fn as _, branch_insn.len()));
    }

    *backup_orig = trampoline_insn.as_ptr() as _;

    Ok(Stub::new(trampoline_insn))
}

#[cfg(test)]
mod tests {
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

        unsafe {
            super::replace_fn(target_fn as _, proxy_fn as _).expect("failed to replace func");
        }

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
            super::hook_fn(target_fn as _, proxy_fn as _, &mut ORIG_FN)
                .expect("failed to hook func")
        };

        assert!(unsafe { !ORIG_FN.is_null() });

        repeat!(100, {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(target_fn(a, b), proxy_fn(a, b));
        })
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
            super::hook_fn(target_fn as _, proxy_fn as _, &mut ORIG_FN)
                .expect("failed to hook func");
        }

        assert!(unsafe { !ORIG_FN.is_null() });

        target_fn(3, 5);
    }
}
