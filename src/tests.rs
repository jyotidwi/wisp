use crate::asm::BRANCH_LEN;
use crate::{Wisp, asm, orig_fn};
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
use region::Protection;
use std::ffi::c_void;
use std::{mem, ptr};

macro_rules! repeat {
    ($n: literal, $($body:tt)*) => {
        for _ in 0..$n {
            $($body)*
        }
    };
}

#[test]
fn test_branch_len() {
    let insn = asm::branch_to(ptr::null_mut()).expect("failed to assemble");
    assert_eq!(insn.len(), BRANCH_LEN);
}

#[test]
fn test_region_flags() {
    assert_eq!(Protection::READ.bits() as i32, PROT_READ);
    assert_eq!(Protection::WRITE.bits() as i32, PROT_WRITE);
    assert_eq!(Protection::EXECUTE.bits() as i32, PROT_EXEC);
}

#[test]
fn test_replace() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    let _keep =
        unsafe { Wisp::replace_fn(target_fn as _, proxy_fn as _).expect("failed to replace func") };

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(target_fn(a, b), proxy_fn(a, b));
    })
}

#[test]
fn test_hook() {
    static mut ORIG_FN: *const c_void = ptr::null_mut();

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
    let _keep = unsafe {
        Wisp::hook_fn(target_fn as _, proxy_fn as _, Some(&mut ORIG_FN))
            .expect("failed to hook func")
    };

    assert!(unsafe { !ORIG_FN.is_null() });

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(target_fn(a, b), proxy_fn(a, b));
    })
}

#[test]
fn test_hook_dyn_orig() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        let orig_fn = orig_fn!();

        unsafe {
            assert_eq!(
                mem::transmute::<*const c_void, fn(i32, i32) -> i32>(orig_fn)(a, b),
                a + b
            );
        }

        a * b
    }

    #[allow(static_mut_refs)]
    let _keep =
        unsafe { Wisp::hook_fn(target_fn as _, proxy_fn as _, None).expect("failed to hook func") };

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(target_fn(a, b), a * b);
    })
}

#[test]
fn test_unhook() {
    extern "C" fn replace_target(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn hook_target(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(replace_target(a, b), a + b);
        assert_eq!(hook_target(a, b), a + b);
    });

    let replace_stub = unsafe {
        Wisp::replace_fn(replace_target as _, proxy_fn as _).expect("failed to replace func")
    };

    let mut orig_fn: *const c_void = ptr::null_mut();
    let hook_stub = unsafe {
        Wisp::hook_fn(hook_target as _, proxy_fn as _, Some(&mut orig_fn))
            .expect("failed to hook func")
    };

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(replace_target(a, b), a * b);
        assert_eq!(hook_target(a, b), a * b);
    });

    drop(replace_stub);
    drop(hook_stub);

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(replace_target(a, b), a + b);
        assert_eq!(hook_target(a, b), a + b);
    });
}

#[test]
#[ignore]
fn test_unwind() {
    static mut ORIG_FN_1: *const c_void = ptr::null_mut();

    extern "C" fn target_fn_1(a: i32, b: i32) -> i32 {
        unsafe {
            libc::raise(35);
        }
        a + b
    }

    extern "C" fn proxy_fn_1(a: i32, b: i32) -> i32 {
        unsafe { mem::transmute::<*const c_void, fn(i32, i32) -> i32>(ORIG_FN_1)(a, b) }
    }

    #[allow(static_mut_refs)]
    unsafe {
        Wisp::hook_fn(target_fn_1 as _, proxy_fn_1 as _, Some(&mut ORIG_FN_1))
            .expect("failed to hook func");
    }

    target_fn_1(3, 5);

    extern "C" fn target_fn_2(a: i32, b: i32) -> i32 {
        unsafe {
            libc::raise(35);
        }
        a + b
    }

    extern "C" fn proxy_fn_2(a: i32, b: i32) -> i32 {
        let orig_fn = orig_fn!();
        unsafe { mem::transmute::<*const c_void, fn(i32, i32) -> i32>(orig_fn)(a, b) }
    }

    #[allow(static_mut_refs)]
    unsafe {
        Wisp::hook_fn(target_fn_2 as _, proxy_fn_2 as _, None).expect("failed to hook func");
    }

    target_fn_2(3, 5);
}
