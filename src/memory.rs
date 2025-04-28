use crate::{cpu::Cpu, error::EmulatorError};


pub(crate) trait AddressBus {
    fn read_byte(&mut self, addr: u16) -> Result<u8, EmulatorError>;
    fn write_byte(&mut self, addr: u16, byte: u8) -> Result<(), EmulatorError>;
}

unsafe impl Send for SnesBus {}
unsafe impl Sync for SnesBus {}

pub struct SnesBus {
    pub(crate) cpu: *mut Cpu,
}

impl SnesBus {
    pub fn new(cpu: *mut Cpu) -> Self {
        SnesBus {
            cpu
        }
    }

    pub fn last_cpu_instruction_cycles(&mut self) -> usize {
        unsafe { (*self.cpu).get_last_instruction_cycles() }
    }
}