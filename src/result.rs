use std::io;
use syscalls::Errno;

#[derive(Debug, thiserror::Error)]
pub enum WispError {
    #[error("Failed to allocate memory for trampoline")]
    AllocTrampoline,

    #[error("Failed to clear cache")]
    Cache,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("Syscall error: {0}")]
    Syscall(#[from] Errno),
}

pub type WispResult<T> = Result<T, WispError>;
