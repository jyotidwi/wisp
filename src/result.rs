#[derive(Debug, thiserror::Error)]
pub enum WispError {
    #[error("Failed to write memory: {0}")]
    WriteMemory(#[from] std::io::Error),

    #[error("Failed to clear cache")]
    ClearCache,
}

pub type WispResult<T> = Result<T, WispError>;
