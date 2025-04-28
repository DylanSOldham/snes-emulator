use cpu::Cpu;

pub mod cpu;
mod error;
mod memory;
pub mod rom;

pub(crate) fn cpu_log(message: &str) {
    //println!("{}", message);
}

pub struct Emulator {
    pub(crate) cpu: Cpu,
}

impl Emulator {
}