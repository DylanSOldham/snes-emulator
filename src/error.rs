#[derive(Debug)]
pub enum EmulatorError {
    CpuError(String),
    MemoryError(String),
    PpuError(String),
    RomError(String),
}