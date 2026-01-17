use region::page;
use std::ffi::c_void;

pub(crate) trait PtrAlign {
    fn page_start(&self) -> Self;
    fn page_end(&self) -> Self;
}

impl PtrAlign for usize {
    fn page_start(&self) -> Self {
        self & !(page::size() - 1)
    }

    fn page_end(&self) -> Self {
        let page_size = page::size();
        self.div_ceil(page_size) * page_size
    }
}

macro_rules! impl_ptr_align {
    ($ty: ty) => {
        impl PtrAlign for $ty {
            fn page_start(&self) -> Self {
                (*self as usize).page_start() as _
            }

            fn page_end(&self) -> Self {
                (*self as usize).page_end() as _
            }
        }
    };
}

impl_ptr_align!(*const c_void);
impl_ptr_align!(*mut c_void);
