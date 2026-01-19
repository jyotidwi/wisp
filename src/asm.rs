use crate::result::{WispError, WispResult};
use dynasmrt::ExecutableBuffer;
use dynasmrt::aarch64::Assembler;
use std::ffi::c_void;

pub(crate) const BRANCH_LEN: usize = 16;

pub(crate) trait Assemble<T> {
    fn assemble(self) -> WispResult<T>;
}

impl Assemble<ExecutableBuffer> for Assembler {
    fn assemble(self) -> WispResult<ExecutableBuffer> {
        self.finalize().map_err(|_| WispError::Dynasm)
    }
}

#[macro_export]
macro_rules! arm64asm {
     ($ops:ident $($t:tt)*) => {
         {
             #[allow(unused_imports)]
             use dynasmrt::{dynasm, DynasmApi};

             dynasm!($ops
                 ; .arch aarch64
                 ; .alias ip, x17
                 ; .alias fp, x29
                 ; .alias lr, x30
                 $($t)*
             )
         }
     }
}

pub(crate) fn branch_to(addr: *const c_void) -> WispResult<Vec<u8>> {
    let proxy_fn = addr as usize;
    let mut ops = Assembler::new()?;

    arm64asm!(ops
        ; movz ip, #(proxy_fn & 0xffff) as _
        ; movk ip, #((proxy_fn >> 16) & 0xffff) as _, lsl #16
        ; movk ip, #((proxy_fn >> 32) & 0xffff) as _, lsl #32
        ; br ip
    );

    Ok(ops.assemble()?.to_vec())
}
