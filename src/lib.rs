extern crate core;

use crate::result::WispResult;
use crate::trampoline::TrampolineAllocator;
use dynasmrt::{DynasmApi, dynasm};
use libc::{_SC_PAGESIZE, PROT_EXEC, PROT_READ, PROT_WRITE};
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::ptr;
use std::sync::LazyLock;

mod cache;
mod dynasm;
mod lss;
mod result;
mod trampoline;

static PAGE_SIZE: LazyLock<usize> =
    LazyLock::new(|| unsafe { libc::sysconf(_SC_PAGESIZE) as usize });

fn page_start(ptr: *const c_void) -> *const c_void {
    ((ptr as usize) & !(*PAGE_SIZE - 1)) as _
}

fn page_end(ptr: *const c_void) -> *const c_void {
    ((ptr as usize).div_ceil(*PAGE_SIZE) * *PAGE_SIZE) as _
}

pub struct Wisp {
    allocator: TrampolineAllocator,
}

impl Wisp {
    pub fn new(buffer_size: usize) -> WispResult<Self> {
        Ok(Self {
            allocator: TrampolineAllocator::new(buffer_size)?,
        })
    }

    unsafe fn write_mem_ignore_perm(addr: *const c_void, data: &[u8]) -> WispResult<()> {
        let mut file = OpenOptions::new().write(true).open("/proc/self/mem")?;

        file.seek(SeekFrom::Start(addr as _))?;
        file.write_all(data)?;
        file.flush()?;

        Ok(())
    }

    pub unsafe fn replace_fn(target_fn: *const c_void, proxy_fn: *const c_void) -> WispResult<()> {
        let branch_insn = {
            let proxy_fn = proxy_fn as usize;
            asmgen!(
                ; movz x17, #(proxy_fn & 0xffff) as _
                ; movk x17, #((proxy_fn >> 16) & 0xffff) as _, lsl #16
                ; movk x17, #((proxy_fn >> 32) & 0xffff) as _, lsl #32
                ; br x17
            )
        };

        unsafe {
            let mprotect_addr = page_start(target_fn);
            let mprotect_size =
                page_end(target_fn.add(branch_insn.len())).byte_offset_from_unsigned(mprotect_addr);

            lss::mprotect(
                mprotect_addr as _,
                mprotect_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
            )?;
            ptr::copy_nonoverlapping(branch_insn.as_ptr(), target_fn as _, branch_insn.len());
            lss::mprotect(mprotect_addr as _, mprotect_size, PROT_READ | PROT_EXEC)?; // Fixme: perms
            // Self::write_mem_ignore_perm(target_fn, &branch_insn)?;
        }

        Ok(())
    }

    pub unsafe fn hook_fn(
        &mut self,
        target_fn: *const c_void,
        proxy_fn: *const c_void,
        backup_orig: &mut *const c_void,
    ) -> WispResult<()> {
        let branch_insn = {
            let proxy_fn = proxy_fn as usize;
            asmgen!(
                ; movz x17, #(proxy_fn & 0xffff) as _
                ; movk x17, #((proxy_fn >> 16) & 0xffff) as _, lsl #16
                ; movk x17, #((proxy_fn >> 32) & 0xffff) as _, lsl #32
                ; br x17
            )
        };

        let trampoline_insn = {
            let target_fn = unsafe { target_fn.add(branch_insn.len()) as usize };
            asmgen!(
                // (copy backup instructions before this)
                ; movz x17, #(target_fn & 0xffff) as _
                ; movk x17, #((target_fn >> 16) & 0xffff) as _, lsl #16
                ; movk x17, #((target_fn >> 32) & 0xffff) as _, lsl #32
                ; br x17
            )
        };

        let trampoline = self
            .allocator
            .alloc(branch_insn.len() + trampoline_insn.len())?;

        unsafe {
            // 1. backup the original instructions from `target_fn` to the trampoline
            ptr::copy_nonoverlapping(target_fn, trampoline.as_ptr() as _, branch_insn.len());

            // 2. branch `target_fn` to `proxy_fn`
            let mprotect_addr = page_start(target_fn);
            let mprotect_size =
                page_end(target_fn.add(branch_insn.len())).byte_offset_from_unsigned(mprotect_addr);

            lss::mprotect(
                mprotect_addr as _,
                mprotect_size as _,
                PROT_READ | PROT_WRITE | PROT_EXEC,
            )?;
            ptr::copy_nonoverlapping(branch_insn.as_ptr(), target_fn as _, branch_insn.len());
            lss::mprotect(
                mprotect_addr as _,
                mprotect_size as _,
                PROT_READ | PROT_EXEC,
            )?; // Fixme: perms

            // 3. branch `backup_orig` to original `target_fn`
            ptr::copy_nonoverlapping(
                trampoline_insn.as_ptr() as _,
                trampoline.as_ptr().add(branch_insn.len()) as _,
                trampoline_insn.len(),
            );
        }

        *backup_orig = trampoline.as_ptr() as _;

        cache::clear_cache(target_fn, branch_insn.len())?;
        cache::clear_cache(trampoline.as_ptr() as _, trampoline.len())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Wisp, lss};
    use dynasmrt::{DynasmApi, dynasm};
    use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
    use procfs::process::{MMPermissions, MMapPath, Process};
    use std::ffi::c_void;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::{mem, process, ptr, thread};

    #[test]
    fn test_mmap_trampoline() {
        const MMAP_SIZE: usize = 16 * 1024;
        const ISLAND_DISTANCE_LIMIT: usize = 1 << 48;

        Process::new(process::id() as _)
            .expect("failed to read process")
            .maps()
            .expect("failed to read process maps")
            .into_iter()
            .filter(|map| map.perms.contains(MMPermissions::EXECUTE))
            .for_each(|map| {
                let MMapPath::Path(ref pathname) = map.pathname else {
                    return;
                };

                if pathname.extension().and_then(|s| s.to_str()) != Some("so") {
                    return;
                }

                let island = unsafe {
                    lss::mmap(
                        map.address.0 as _,
                        MMAP_SIZE,
                        PROT_READ | PROT_EXEC,
                        MAP_ANONYMOUS | MAP_PRIVATE,
                        -1,
                        0,
                    )
                    .expect("failed to mmap")
                };

                unsafe {
                    lss::munmap(island, MMAP_SIZE).expect("failed to munmap");
                }

                let distance = island as usize - map.address.0 as usize;

                assert!(
                    distance < ISLAND_DISTANCE_LIMIT,
                    "island 0x{:x} too far from map 0x{:x} ({}), {} > {}",
                    island as usize,
                    map.address.0 as usize,
                    pathname.display(),
                    distance,
                    ISLAND_DISTANCE_LIMIT
                );
            })
    }

    #[test]
    fn test_dynasm_jump() {
        const MMAP_SIZE: usize = 16 * 1024;

        let mut ops = dynasmrt::aarch64::Assembler::new().unwrap();

        extern "C" fn func(x: i64) -> i64 {
            -x
        }

        let addr = func as usize;

        dynasm!(ops
            ; .arch aarch64
            ; movz x17, #(addr & 0xffff) as _
            ; movk x17, #((addr >> 16) & 0xffff) as _, lsl #16
            ; movk x17, #((addr >> 32) & 0xffff) as _, lsl #32
            ; br x17
        );

        let shellcode = ops.finalize().expect("failed to compile").to_vec();
        let shellcode = &*Box::leak(shellcode.into_boxed_slice());

        for _ in 0..100 {
            let input = fastrand::i64(..);
            let (tx, rx) = mpsc::channel();

            let handle = thread::spawn(move || unsafe {
                let mmap = lss::mmap(
                    ptr::null_mut(),
                    MMAP_SIZE,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE,
                    -1,
                    0,
                )
                .expect("failed to mmap");

                libc::memcpy(mmap as _, shellcode.as_ptr() as _, shellcode.len());
                clear_cache::clear_cache(mmap, mmap.add(MMAP_SIZE));

                let value = mem::transmute::<*mut libc::c_void, fn(i64) -> i64>(mmap)(input);

                tx.send(value).expect("failed to send value");
                lss::munmap(mmap, MMAP_SIZE).expect("failed to munmap");
            });

            let result = rx
                .recv_timeout(Duration::from_secs(3))
                .expect("failed to receive value");

            assert_eq!(result, func(input));

            handle.join().expect("failed to join thread");
        }

        unsafe {
            drop(Box::from_raw(shellcode as *const [u8] as *mut [u8]));
        }
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
            Wisp::replace_fn(target_fn as _, proxy_fn as _).expect("failed to replace func");
        }

        for _ in 0..100 {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(target_fn(a, b), proxy_fn(a, b));
        }
    }

    #[test]
    fn test_hook() {
        static mut ORIG_FN: *const c_void = ptr::null_mut();

        let mut wisp = Wisp::new(1024 * 1024).expect("failed to create wisp");

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
        unsafe {
            wisp.hook_fn(target_fn as _, proxy_fn as _, &mut ORIG_FN)
                .expect("failed to hook func");
        }

        assert!(unsafe { !ORIG_FN.is_null() });

        for _ in 0..100 {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(target_fn(a, b), proxy_fn(a, b));
        }
    }
}
