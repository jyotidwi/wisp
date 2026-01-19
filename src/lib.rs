use crate::asm::{Assemble, BRANCH_LEN};
use crate::result::WispResult;
use core::slice;
use core::sync::atomic::{Ordering, compiler_fence};
use dynasmrt::aarch64::Assembler;
use dynasmrt::{DynasmApi, ExecutableBuffer, cache_control};
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
            compiler_fence(Ordering::SeqCst);
            mman::write_memory(stub.target, &stub.backup_insn)?;
            cache_control::synchronize_icache(slice::from_raw_parts(
                stub.target as _,
                stub.backup_insn.len(),
            ));
            compiler_fence(Ordering::SeqCst);
        }

        Ok(())
    }
}

pub struct Stub<U: Unhooker> {
    target: *const c_void,
    backup_insn: Vec<u8>,
    region: Region,
    _buffers: Vec<ExecutableBuffer>,
    _fake: PhantomData<fn(U) -> U>,
}

impl<U: Unhooker> Stub<U> {
    fn new(
        target: *const c_void,
        backup_insn: Vec<u8>,
        region: Region,
        buffers: Vec<ExecutableBuffer>,
    ) -> Self {
        Self {
            target,
            backup_insn,
            region,
            _buffers: buffers,
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

#[macro_export]
macro_rules! orig_fn {
    () => {
        unsafe {
            let ptr: *const core::ffi::c_void;
            core::arch::asm!(
                "mov x0, x30",
                "add x0, x0, #8",
                "blr x0",
                out("x0") ptr,
                options(nostack, preserves_flags),
                clobber_abi("C")
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
            compiler_fence(Ordering::SeqCst);
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
            compiler_fence(Ordering::SeqCst);
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
        backup_orig: Option<&mut *const c_void>,
    ) -> WispResult<Stub<U>> {
        let region = region::query(target_fn)?;

        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, BRANCH_LEN) };
        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        let (buffer, trampoline) = unsafe {
            let target_next = target_fn.byte_add(BRANCH_LEN) as usize;
            let proxy_fn = proxy_fn as usize;

            let mut ops = Assembler::new()?;

            arm64asm!(ops
                // pre-orig trampoline
                ; orig:
                ;; ops.extend(&backup_insn)  // Fixme: fix adrp etc.
                ; movz ip, #(target_next & 0xffff) as _
                ; movk ip, #((target_next >> 16) & 0xffff) as _, lsl #16
                ; movk ip, #((target_next >> 32) & 0xffff) as _, lsl #32
                ; br ip
            );

            let trampoline = ops.offset();

            arm64asm!(ops
                // pre-proxy trampoline
                ; stp fp, lr, [sp, #-16]!
                ; mov fp, sp
                ; movz ip, #(proxy_fn & 0xffff) as _
                ; movk ip, #((proxy_fn >> 16) & 0xffff) as _, lsl #16
                ; movk ip, #((proxy_fn >> 32) & 0xffff) as _, lsl #32
                ; blr ip
                ; ldp fp, lr, [sp], #16  // <-- return here
                ; ret
                // orig_fn! calls this function
                ; adr x0, <orig
                ; ret
            );

            (ops.assemble()?, trampoline)
        };

        let branch_insn = asm::branch_to(buffer.ptr(trampoline) as _)?;

        unsafe {
            compiler_fence(Ordering::SeqCst);
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
            compiler_fence(Ordering::SeqCst);
        }

        if let Some(backup_orig) = backup_orig {
            *backup_orig = buffer.as_ptr() as _;
        }

        Ok(Stub::new(target_fn, backup_insn, region, vec![buffer]))
    }
}

pub type Wisp = CustomWisp<SimpleUnhooker>;
