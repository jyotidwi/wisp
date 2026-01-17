use crate::lss;
use crate::result::{WispError, WispResult};
use core::slice;
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use linked_list_allocator::Heap;
use std::alloc::Layout;
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::{fmt, ptr};

pub(crate) struct Trampoline<'a>(&'a mut [u8]);

impl Deref for Trampoline<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for Trampoline<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl Debug for Trampoline<'_> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Trampoline")
            .field("addr", &self.0.as_ptr())
            .field("size", &self.0.len())
            .finish()
    }
}

pub(crate) struct TrampolineAllocator {
    heap: Heap,
    region: (usize, usize),
}

impl TrampolineAllocator {
    pub fn new(size: usize) -> WispResult<TrampolineAllocator> {
        let addr = unsafe {
            lss::mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )? as usize
        };

        let heap = Heap::from_slice(unsafe { slice::from_raw_parts_mut(addr as _, size) });

        Ok(Self {
            heap,
            region: (addr, size),
        })
    }

    pub fn alloc(&mut self, size: usize) -> WispResult<Trampoline<'_>> {
        let ptr = self
            .heap
            .allocate_first_fit(Layout::from_size_align(size, 4).unwrap())
            .map_err(|_| WispError::AllocTrampoline)?;

        Ok(Trampoline(unsafe {
            slice::from_raw_parts_mut(ptr.as_ptr(), size)
        }))
    }

    pub fn free(&mut self, mut region: Trampoline) {
        unsafe {
            self.heap.deallocate(
                NonNull::new_unchecked(region.as_mut_ptr()),
                Layout::from_size_align(region.len(), 4).unwrap(),
            )
        }
    }
}

impl Drop for TrampolineAllocator {
    fn drop(&mut self) {
        unsafe {
            let _ = lss::munmap(self.region.0 as _, self.region.1);
        }
    }
}
