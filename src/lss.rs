use libc::{c_int, off_t, size_t};
use std::ffi::c_void;
use syscalls::{Errno, Sysno, syscall};

pub(crate) unsafe fn mmap(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> Result<*mut c_void, Errno> {
    syscall!(Sysno::mmap, addr, len, prot, flags, fd, offset).map(|it| it as _)
}

pub(crate) unsafe fn munmap(addr: *mut c_void, len: size_t) -> Result<(), Errno> {
    syscall!(Sysno::munmap, addr, len).map(drop)
}
