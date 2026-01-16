mod lss;

#[cfg(test)]
mod tests {
    use crate::lss;
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
    fn find_strlen() {
        assert_ne!(strlen as usize, 0);
    }

    #[test]
    fn mmap_trampoline() {
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
    fn dynasm_jump() {
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

        for _ in 0..1000 {
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

                let value = mem::transmute::<*mut libc::c_void, fn(i64) -> i64>(mmap)(0xdeadbeef);

                tx.send(value).expect("failed to send value");
                lss::munmap(mmap, MMAP_SIZE).expect("failed to munmap");
            });

            let result = rx
                .recv_timeout(Duration::from_secs(3))
                .expect("failed to receive value");

            assert_eq!(result, func(0xdeadbeef));

            handle.join().expect("failed to join thread");
        }

        unsafe {
            drop(Box::from_raw(shellcode as *const [u8] as *mut [u8]));
        }
    }
}
