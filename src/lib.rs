use crate::asm::{Assemble, BRANCH_LEN};
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

#[cfg(test)]
mod tests;

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

pub trait IntoOrigAddr<'a> {
    fn into_orig_addr(self) -> Option<&'a mut *const c_void>;
}

impl<'a> IntoOrigAddr<'a> for &'a mut *const c_void {
    fn into_orig_addr(self) -> Option<&'a mut *const c_void> {
        Some(self)
    }
}

impl<'a> IntoOrigAddr<'a> for Option<&'a mut *const c_void> {
    fn into_orig_addr(self) -> Option<&'a mut *const c_void> {
        self
    }
}

#[macro_export]
macro_rules! orig_fn {
    () => {
        unsafe {
            let ptr: *const core::ffi::c_void;
            core::arch::asm!(
                "mov {tmp}, x30",
                "ldr {ptr}, [{tmp}, #8]",
                tmp = out(reg) _,
                ptr = out(reg) ptr,
            );
            ptr
        }
    };
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

        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, BRANCH_LEN) };
        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

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
    pub unsafe fn hook_fn<'a, B: IntoOrigAddr<'a>>(
        target_fn: *const c_void,
        proxy_fn: *const c_void,
        backup_orig: B,
    ) -> WispResult<Stub<U>> {
        let region = region::query(target_fn)?;
        let backup_orig = backup_orig.into_orig_addr();
        let mut trampolines = Vec::new();

        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, BRANCH_LEN) };
        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        let trampoline_insn = unsafe {
            let target_next = target_fn.byte_add(BRANCH_LEN) as usize;
            let mut ops = Assembler::new()?;

            arm64asm!(ops
                ;; ops.extend(&backup_insn)
                ; movz ip, #(target_next & 0xffff) as _
                ; movk ip, #((target_next >> 16) & 0xffff) as _, lsl #16
                ; movk ip, #((target_next >> 32) & 0xffff) as _, lsl #32
                ; br ip
                ; brk #0
            );

            ops.assemble()?
        };

        let helper_insn = if backup_orig.is_none() {
            let proxy_fn = proxy_fn as usize;
            let mut ops = Assembler::new()?;

            arm64asm!(ops
                ; stp fp, lr, [sp, #-16]!
                ; mov fp, sp
                ; movz ip, #(proxy_fn & 0xffff) as _
                ; movk ip, #((proxy_fn >> 16) & 0xffff) as _, lsl #16
                ; movk ip, #((proxy_fn >> 32) & 0xffff) as _, lsl #32
                ; blr ip
                ; ldp fp, lr, [sp], #16
                ; ret
                ;; ops.push_u64(trampoline_insn.as_ptr() as _)
            );

            Some(ops.assemble()?)
        } else {
            None
        };

        let branch_insn = asm::branch_to(
            helper_insn
                .as_ref()
                .map(|it| it.as_ptr() as _)
                .unwrap_or(proxy_fn),
        )?;

        unsafe {
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
        }

        if let Some(backup_orig) = backup_orig {
            *backup_orig = trampoline_insn.as_ptr() as _;
        }

        trampolines.push(trampoline_insn);

        if let Some(helper_insn) = helper_insn {
            trampolines.push(helper_insn)
        }

        Ok(Stub::new(target_fn, backup_insn, region, trampolines))
    }
}

pub type Wisp = CustomWisp<SimpleUnhooker>;
