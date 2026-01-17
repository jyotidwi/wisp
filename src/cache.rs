use crate::result::{WispError, WispResult};
use std::ffi::c_void;

pub(crate) fn clear_cache(addr: usize, length: usize) -> WispResult<()> {
    unsafe {
        if !clear_cache::clear_cache(addr as *const c_void, (addr + length) as _) {
            Err(WispError::ClearCache)
        } else {
            Ok(())
        }
    }
}
