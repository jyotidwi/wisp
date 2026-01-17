use crate::result::WispResult;
use dynasmrt::{dynasm, DynasmApi};
use std::fs::OpenOptions;
use std::io::{Seek, Write};
use std::io;

mod cache;
mod dynasm;
mod lss;
mod result;

unsafe fn write_mem_ignore_perm(addr: usize, data: &[u8]) -> WispResult<()> {
    let mut file = OpenOptions::new().write(true).open("/proc/self/mem")?;

    file.seek(io::SeekFrom::Start(addr as _))?;
    file.write_all(data)?;
    file.flush()?;

    Ok(())
}

// Todo: unhook
unsafe fn hook_replace(target_fn: usize, replace_fn: usize) -> WispResult<()> {
    let branch = asmgen!(
        ; movz x17, #(replace_fn & 0xffff) as _
        ; movk x17, #((replace_fn >> 16) & 0xffff) as _, lsl #16
        ; movk x17, #((replace_fn >> 32) & 0xffff) as _, lsl #32
        ; br x17
    );

    unsafe {
        write_mem_ignore_perm(target_fn, &branch)?;
        cache::clear_cache(target_fn, branch.len())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{hook_replace, lss};
    use dynasmrt::{dynasm, DynasmApi};
    use libc::{c_char, size_t, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
    use procfs::process::{MMPermissions, MMapPath, Process};
    use std::sync::mpsc;
    use std::time::Duration;
    use std::{mem, process, ptr, thread};

    unsafe extern "C" {
        fn strlen(s: *const c_char) -> size_t;
    }

    #[test]
    fn test_find_strlen() {
        assert_ne!(strlen as usize, 0);
    }

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
    fn test_hook_replace() {
        fn target_fn(a: i32, b: i32) -> i32 {
            a + b
        }

        fn replace_fn(a: i32, b: i32) -> i32 {
            a * b
        }

        unsafe {
            hook_replace(target_fn as _, replace_fn as _).expect("failed to install hook");
        }

        for _ in 0..100 {
            let a = fastrand::i32(-1000..1000);
            let b = fastrand::i32(-1000..1000);
            assert_eq!(target_fn(a, b), replace_fn(a, b));
        }
    }
}
