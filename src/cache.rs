use crate::result::{WispError, WispResult};
use std::ffi::c_void;

pub(crate) fn clear_cache(addr: *const c_void, length: usize) -> WispResult<()> {
    unsafe {
        if !clear_cache::clear_cache(addr, addr.add(length) as _) {
            Err(WispError::Cache)
        } else {
            Ok(())
        }
    }
}
