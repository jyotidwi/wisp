use crate::result::WispResult;
use libc::{c_int, off_t, size_t};
use std::ffi::c_void;
use syscalls::{Sysno, syscall};

pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    size: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> WispResult<*mut c_void> {
    Ok(syscall!(Sysno::mmap, addr, size, prot, flags, fd, offset).map(|ptr| ptr as _)?)
}

pub(crate) unsafe fn munmap(addr: *mut c_void, size: size_t) -> WispResult<()> {
    syscall!(Sysno::munmap, addr, size)?;
    Ok(())
}

pub(crate) unsafe fn mprotect(addr: *mut c_void, size: size_t, prot: c_int) -> WispResult<()> {
    syscall!(Sysno::mprotect, addr, size, prot)?;
    Ok(())
}
