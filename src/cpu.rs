use crate::{cpu_log, error::EmulatorError, memory::AddressBus};

pub const CPU_FREQ: usize = 1789773;

const FLAG_CARRY: u8 = 1 << 0;
const FLAG_ZERO: u8 = 1 << 1;
const FLAG_INTERRUPT_DISABLE: u8 = 1 << 2;
const FLAG_DECIMAL: u8 = 1 << 3;
const FLAG_B: u8 = 1 << 4;
const FLAG_ONE: u8 = 1 << 5;
const FLAG_OVERFLOW: u8 = 1 << 6;
const FLAG_NEG: u8 = 1 << 7;

#[derive(Debug, Clone, Copy, PartialEq)]
enum AddressingMode {
    Accumulator,
    Immediate,
    Implied,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    /// This is the (d, x) one
    IndexedIndirect,
    /// This is the (d),y one
    IndirectIndexed,
}

pub(crate) struct Cpu {
    pub(crate) a: u8,
    pub(crate) x: u8,
    pub(crate) y: u8,
    pub(crate) pc: u16,
    pub(crate) s: u8,
    pub(crate) p: u8,
    pub(crate) last_opcode: u8,
    pub(crate) cycle_count: u128,
    current_instruction_cycles: usize,
    active_address: Option<u16>,
}

impl Cpu {
    pub(crate) fn new() -> Self {
        Cpu {
            a: 0x0,
            x: 0x0,
            y: 0x0,
            pc: 0x0,
            s: 0xFD,
            p: 0x24,
            last_opcode: 0,
            cycle_count: 7,
            current_instruction_cycles: 0,
            active_address: None,
        }
    }

    pub(crate) fn increment_cycle_counter(&mut self){
        self.current_instruction_cycles += 1;
    }

    pub(crate) fn get_last_instruction_cycles(&mut self) -> usize {
        self.current_instruction_cycles
    }

    pub(crate) fn reset_cpu(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let pc_lower = self.read_byte(bus, 0xFFFC)? as u16;
        let pc_upper = self.read_byte(bus, 0xFFFD)? as u16;

        let pc = (pc_upper << 8) + pc_lower;
        println!("Starting execution at {:X}", pc);

        self.a = 0x0;
        self.x = 0x0;
        self.y = 0x0;
        self.s = 0xFD;
        self.p = 0x24;
        self.pc = pc;
        self.current_instruction_cycles = 0;
        self.cycle_count = 7;
        self.last_opcode = 0;
        self.active_address = None;

        Ok(())
    }

    pub(crate) fn issue_nmi(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.stack_push_word(bus, self.pc)?;
        self.stack_push_byte(bus, self.p)?;

        cpu_log("\nNMI ISSUED");

        let pc_upper = self.read_byte(bus, 0xFFFA)? as u16;
        let pc_lower = self.read_byte(bus, 0xFFFB)? as u16;
        self.pc = (pc_lower as u16) << 8 | pc_upper as u16;

        cpu_log(format!("PC {:#X}", self.pc).as_str());

        Ok(())
    }

    pub(crate) fn issue_irq(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.stack_push_word(bus, self.pc)?;
        self.stack_push_byte(bus, self.p)?;

        println!("\nIRQ ISSUED");

        let pc_upper = self.read_byte(bus, 0xFFFE)? as u16;
        let pc_lower = self.read_byte(bus, 0xFFFF)? as u16;
        self.pc = (pc_lower as u16) << 8 | pc_upper as u16;

        cpu_log(format!("PC {:#X}", self.pc).as_str());

        Ok(())
    }

    pub(crate) fn execute_instruction(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        self.current_instruction_cycles = 0;
        self.active_address = None;
        let opcode = self.read_byte(bus, self.pc)?;
        self.last_opcode = opcode;
        self.pc = self.pc.overflowing_add(1).0;

        cpu_log(format!("\n{:#06X} {:X} ", self.pc, opcode).as_str());

        match opcode {
            0x00 => self.brk(bus)?,
            0x01 => self.ora(bus, AddressingMode::IndexedIndirect)?,
            0x02 => self.stp(bus)?,
            0x03 => self.slo(bus, AddressingMode::IndexedIndirect)?,
            0x04 => self.nop(bus, AddressingMode::ZeroPage)?,
            0x05 => self.ora(bus, AddressingMode::ZeroPage)?,
            0x06 => self.asl(bus, AddressingMode::ZeroPage)?,
            0x07 => self.slo(bus, AddressingMode::ZeroPage)?,
            0x08 => self.php(bus)?,
            0x09 => self.ora(bus, AddressingMode::Immediate)?,
            0x0A => self.asl(bus, AddressingMode::Accumulator)?,
            0x0B => self.anc(bus, AddressingMode::Immediate)?,
            0x0C => self.nop(bus, AddressingMode::Absolute)?,
            0x0D => self.ora(bus, AddressingMode::Absolute)?,
            0x0E => self.asl(bus, AddressingMode::Absolute)?,
            0x0F => self.slo(bus, AddressingMode::Absolute)?,
            0x10 => self.bpl(bus)?,
            0x11 => self.ora(bus, AddressingMode::IndirectIndexed)?,
            0x12 => self.stp(bus)?,
            0x13 => self.slo(bus, AddressingMode::IndirectIndexed)?,
            0x14 => self.nop(bus, AddressingMode::ZeroPageX)?,
            0x15 => self.ora(bus, AddressingMode::ZeroPageX)?,
            0x16 => self.asl(bus, AddressingMode::ZeroPageX)?,
            0x17 => self.slo(bus, AddressingMode::ZeroPageX)?,
            0x18 => self.setflg(bus, FLAG_CARRY, false)?,
            0x19 => self.ora(bus, AddressingMode::AbsoluteY)?,
            0x1A => self.nop(bus, AddressingMode::Accumulator)?,
            0x1B => self.slo(bus, AddressingMode::AbsoluteY)?,
            0x1C => self.nop(bus, AddressingMode::AbsoluteX)?,
            0x1D => self.ora(bus, AddressingMode::AbsoluteX)?,
            0x1E => self.asl(bus, AddressingMode::AbsoluteX)?,
            0x1F => self.slo(bus, AddressingMode::AbsoluteX)?,
            0x20 => self.jsr(bus)?,
            0x21 => self.and(bus, AddressingMode::IndexedIndirect)?,
            0x22 => self.stp(bus)?,
            0x23 => self.rla(bus, AddressingMode::IndexedIndirect)?,
            0x24 => self.bit(bus, AddressingMode::ZeroPage)?,
            0x25 => self.and(bus, AddressingMode::ZeroPage)?,
            0x26 => self.rol(bus, AddressingMode::ZeroPage)?,
            0x27 => self.rla(bus, AddressingMode::ZeroPage)?,
            0x28 => self.plp(bus)?,
            0x29 => self.and(bus, AddressingMode::Immediate)?,
            0x2A => self.rol(bus, AddressingMode::Accumulator)?,
            0x2B => self.anc(bus, AddressingMode::Immediate)?,
            0x2C => self.bit(bus, AddressingMode::Absolute)?,
            0x2D => self.and(bus, AddressingMode::Absolute)?,
            0x2E => self.rol(bus, AddressingMode::Absolute)?,
            0x2F => self.rla(bus, AddressingMode::Absolute)?,
            0x30 => self.bmi(bus)?,
            0x32 => self.stp(bus)?,
            0x31 => self.and(bus, AddressingMode::IndirectIndexed)?,
            0x33 => self.rla(bus, AddressingMode::IndirectIndexed)?,
            0x34 => self.nop(bus, AddressingMode::ZeroPageX)?,
            0x35 => self.and(bus, AddressingMode::ZeroPageX)?,
            0x36 => self.rol(bus, AddressingMode::ZeroPageX)?,
            0x37 => self.rla(bus, AddressingMode::ZeroPageX)?,
            0x38 => self.setflg(bus, FLAG_CARRY, true)?,
            0x39 => self.and(bus, AddressingMode::AbsoluteY)?,
            0x3A => self.nop(bus, AddressingMode::Accumulator)?,
            0x3B => self.rla(bus, AddressingMode::AbsoluteY)?,
            0x3C => self.nop(bus, AddressingMode::AbsoluteX)?,
            0x3D => self.and(bus, AddressingMode::AbsoluteX)?,
            0x3E => self.rol(bus, AddressingMode::AbsoluteX)?,
            0x3F => self.rla(bus, AddressingMode::AbsoluteX)?,
            0x40 => self.rti(bus)?,
            0x41 => self.eor(bus, AddressingMode::IndexedIndirect)?,
            0x42 => self.stp(bus)?,
            0x43 => self.sre(bus, AddressingMode::IndexedIndirect)?,
            0x44 => self.nop(bus, AddressingMode::ZeroPage)?,
            0x45 => self.eor(bus, AddressingMode::ZeroPage)?,
            0x46 => self.lsr(bus, AddressingMode::ZeroPage)?,
            0x47 => self.sre(bus, AddressingMode::ZeroPage)?,
            0x48 => self.pha(bus)?,
            0x49 => self.eor(bus, AddressingMode::Immediate)?,
            0x4A => self.lsr(bus, AddressingMode::Accumulator)?,
            0x4B => self.alr(bus, AddressingMode::Immediate)?,
            0x4C => self.jmp(bus)?,
            0x4D => self.eor(bus, AddressingMode::Absolute)?,
            0x4E => self.lsr(bus, AddressingMode::Absolute)?,
            0x4F => self.sre(bus, AddressingMode::Absolute)?,
            0x50 => self.bvc(bus)?,
            0x51 => self.eor(bus, AddressingMode::IndirectIndexed)?,
            0x52 => self.stp(bus)?,
            0x53 => self.sre(bus, AddressingMode::IndirectIndexed)?,
            0x54 => self.nop(bus, AddressingMode::ZeroPageX)?,
            0x55 => self.eor(bus, AddressingMode::ZeroPageX)?,
            0x56 => self.lsr(bus, AddressingMode::ZeroPageX)?,
            0x57 => self.sre(bus, AddressingMode::ZeroPageX)?,
            0x58 => self.setflg(bus, FLAG_INTERRUPT_DISABLE, false)?,
            0x59 => self.eor(bus, AddressingMode::AbsoluteY)?,
            0x5A => self.nop(bus, AddressingMode::Accumulator)?,
            0x5B => self.sre(bus, AddressingMode::AbsoluteY)?,
            0x5C => self.nop(bus, AddressingMode::AbsoluteX)?,
            0x5D => self.eor(bus, AddressingMode::AbsoluteX)?,
            0x5E => self.lsr(bus, AddressingMode::AbsoluteX)?,
            0x5F => self.sre(bus, AddressingMode::AbsoluteX)?,
            0x60 => self.rts(bus)?,
            0x61 => self.adc(bus, AddressingMode::IndexedIndirect)?,
            0x62 => self.stp(bus)?,
            0x63 => self.rra(bus, AddressingMode::IndexedIndirect)?,
            0x64 => self.nop(bus, AddressingMode::ZeroPage)?,
            0x66 => self.ror(bus, AddressingMode::ZeroPage)?,
            0x65 => self.adc(bus, AddressingMode::ZeroPage)?,
            0x67 => self.rra(bus, AddressingMode::ZeroPage)?,
            0x68 => self.pla(bus)?,
            0x69 => self.adc(bus, AddressingMode::Immediate)?,
            0x6A => self.ror(bus, AddressingMode::Accumulator)?,
            0x6B => self.arr(bus, AddressingMode::Immediate)?,
            0x6C => self.jmp_indr(bus)?,
            0x6D => self.adc(bus, AddressingMode::Absolute)?,
            0x6E => self.ror(bus, AddressingMode::Absolute)?,
            0x6F => self.rra(bus, AddressingMode::Absolute)?,
            0x70 => self.bvs(bus)?,
            0x71 => self.adc(bus, AddressingMode::IndirectIndexed)?,
            0x72 => self.stp(bus)?,
            0x73 => self.rra(bus, AddressingMode::IndirectIndexed)?,
            0x74 => self.nop(bus, AddressingMode::ZeroPageX)?,
            0x75 => self.adc(bus, AddressingMode::ZeroPageX)?,
            0x76 => self.ror(bus, AddressingMode::ZeroPageX)?,
            0x77 => self.rra(bus, AddressingMode::ZeroPageX)?,
            0x78 => self.setflg(bus, FLAG_INTERRUPT_DISABLE, true)?,
            0x79 => self.adc(bus, AddressingMode::AbsoluteY)?,
            0x7A => self.nop(bus, AddressingMode::Accumulator)?,
            0x7B => self.rra(bus, AddressingMode::AbsoluteY)?,
            0x7C => self.nop(bus, AddressingMode::AbsoluteX)?,
            0x7D => self.adc(bus, AddressingMode::AbsoluteX)?,
            0x7E => self.ror(bus, AddressingMode::AbsoluteX)?,
            0x7F => self.rra(bus, AddressingMode::AbsoluteX)?,
            0x80 => self.nop(bus, AddressingMode::Immediate)?,
            0x81 => self.sta(bus, AddressingMode::IndexedIndirect)?,
            0x82 => self.nop(bus, AddressingMode::Immediate)?,
            0x83 => self.sax(bus, AddressingMode::IndexedIndirect)?,
            0x84 => self.sty(bus, AddressingMode::ZeroPage)?,
            0x85 => self.sta(bus, AddressingMode::ZeroPage)?,
            0x86 => self.stx(bus, AddressingMode::ZeroPage)?,
            0x87 => self.sax(bus, AddressingMode::ZeroPage)?,
            0x88 => self.dey(bus)?,
            0x89 => self.nop(bus, AddressingMode::Immediate)?,
            0x8A => self.txa(bus)?,
            0x8B => self.xaa(bus, AddressingMode::Immediate)?,
            0x8C => self.sty(bus, AddressingMode::Absolute)?,
            0x8D => self.sta(bus, AddressingMode::Absolute)?,
            0x8E => self.stx(bus, AddressingMode::Absolute)?,
            0x8F => self.sax(bus, AddressingMode::Absolute)?,
            0x90 => self.bcc(bus)?,
            0x91 => self.sta(bus, AddressingMode::IndirectIndexed)?,
            0x92 => self.stp(bus)?,
            0x93 => self.ahx(bus, AddressingMode::IndirectIndexed)?,
            0x94 => self.sty(bus, AddressingMode::ZeroPageX)?,
            0x95 => self.sta(bus, AddressingMode::ZeroPageX)?,
            0x96 => self.stx(bus, AddressingMode::ZeroPageY)?,
            0x97 => self.sax(bus, AddressingMode::ZeroPageY)?,
            0x98 => self.tya(bus)?,
            0x99 => self.sta(bus, AddressingMode::AbsoluteY)?,
            0x9A => self.txs(bus)?,
            0x9B => self.tas(bus, AddressingMode::AbsoluteY)?,
            0x9C => self.shy(bus, AddressingMode::AbsoluteX)?,
            0x9D => self.sta(bus, AddressingMode::AbsoluteX)?,
            0x9E => self.shx(bus, AddressingMode::AbsoluteY)?,
            0x9F => self.ahx(bus, AddressingMode::AbsoluteY)?,
            0xA0 => self.ldy(bus, AddressingMode::Immediate)?,
            0xA1 => self.lda(bus, AddressingMode::IndexedIndirect)?,
            0xA2 => self.ldx(bus, AddressingMode::Immediate)?,
            0xA3 => self.lax(bus, AddressingMode::IndexedIndirect)?,
            0xA4 => self.ldy(bus, AddressingMode::ZeroPage)?,
            0xA5 => self.lda(bus, AddressingMode::ZeroPage)?,
            0xA6 => self.ldx(bus, AddressingMode::ZeroPage)?,
            0xA7 => self.lax(bus, AddressingMode::ZeroPage)?,
            0xA8 => self.tay(bus)?,
            0xA9 => self.lda(bus, AddressingMode::Immediate)?,
            0xAA => self.tax(bus)?,
            0xAB => self.lxa(bus)?,
            0xAC => self.ldy(bus, AddressingMode::Absolute)?,
            0xAD => self.lda(bus, AddressingMode::Absolute)?,
            0xAE => self.ldx(bus, AddressingMode::Absolute)?,
            0xAF => self.lax(bus, AddressingMode::Absolute)?,
            0xB0 => self.bcs(bus)?,
            0xB1 => self.lda(bus, AddressingMode::IndirectIndexed)?,
            0xB2 => self.stp(bus)?,
            0xB3 => self.lax(bus, AddressingMode::IndirectIndexed)?,
            0xB4 => self.ldy(bus, AddressingMode::ZeroPageX)?,
            0xB5 => self.lda(bus, AddressingMode::ZeroPageX)?,
            0xB6 => self.ldx(bus, AddressingMode::ZeroPageY)?,
            0xB7 => self.lax(bus, AddressingMode::ZeroPageY)?,
            0xB8 => self.setflg(bus, FLAG_OVERFLOW, false)?,
            0xB9 => self.lda(bus, AddressingMode::AbsoluteY)?,
            0xBA => self.tsx(bus)?,
            0xBB => self.las(bus, AddressingMode::AbsoluteY)?,
            0xBC => self.ldy(bus, AddressingMode::AbsoluteX)?,
            0xBD => self.lda(bus, AddressingMode::AbsoluteX)?,
            0xBE => self.ldx(bus, AddressingMode::AbsoluteY)?,
            0xBF => self.lax(bus, AddressingMode::AbsoluteY)?,
            0xC0 => self.cpy(bus, AddressingMode::Immediate)?,
            0xC1 => self.cmp(bus, AddressingMode::IndexedIndirect)?,
            0xC2 => self.nop(bus, AddressingMode::Immediate)?,
            0xC3 => self.dcp(bus, AddressingMode::IndexedIndirect)?,
            0xC4 => self.cpy(bus, AddressingMode::ZeroPage)?,
            0xC5 => self.cmp(bus, AddressingMode::ZeroPage)?,
            0xC6 => self.dec(bus, AddressingMode::ZeroPage)?,
            0xC7 => self.dcp(bus, AddressingMode::ZeroPage)?,
            0xC8 => self.iny(bus)?,
            0xC9 => self.cmp(bus, AddressingMode::Immediate)?,
            0xCC => self.cpy(bus, AddressingMode::Absolute)?,
            0xCA => self.dex(bus)?,
            0xCB => self.axs(bus)?,
            0xCD => self.cmp(bus, AddressingMode::Absolute)?,
            0xCE => self.dec(bus, AddressingMode::Absolute)?,
            0xCF => self.dcp(bus, AddressingMode::Absolute)?,
            0xD0 => self.bne(bus)?,
            0xD1 => self.cmp(bus, AddressingMode::IndirectIndexed)?,
            0xD2 => self.stp(bus)?,
            0xD3 => self.dcp(bus, AddressingMode::IndirectIndexed)?,
            0xD4 => self.nop(bus, AddressingMode::ZeroPageX)?,
            0xD5 => self.cmp(bus, AddressingMode::ZeroPageX)?,
            0xD6 => self.dec(bus, AddressingMode::ZeroPageX)?,
            0xD7 => self.dcp(bus, AddressingMode::ZeroPageX)?,
            0xD8 => self.setflg(bus, FLAG_DECIMAL, false)?,
            0xD9 => self.cmp(bus, AddressingMode::AbsoluteY)?,
            0xDA => self.nop(bus, AddressingMode::Accumulator)?,
            0xDB => self.dcp(bus, AddressingMode::AbsoluteY)?,
            0xDC => self.nop(bus, AddressingMode::AbsoluteX)?,
            0xDD => self.cmp(bus, AddressingMode::AbsoluteX)?,
            0xDE => self.dec(bus, AddressingMode::AbsoluteX)?,
            0xDF => self.dcp(bus, AddressingMode::AbsoluteX)?,
            0xE0 => self.cpx(bus, AddressingMode::Immediate)?,
            0xE1 => self.sbc(bus, AddressingMode::IndexedIndirect)?,
            0xE2 => self.nop(bus, AddressingMode::Immediate)?,
            0xE3 => self.isc(bus, AddressingMode::IndexedIndirect)?,
            0xE4 => self.cpx(bus, AddressingMode::ZeroPage)?,
            0xE5 => self.sbc(bus, AddressingMode::ZeroPage)?,
            0xE6 => self.inc(bus, AddressingMode::ZeroPage)?,
            0xE7 => self.isc(bus, AddressingMode::ZeroPage)?,
            0xE8 => self.inx(bus)?,
            0xEA => self.nop(bus, AddressingMode::Implied)?,
            0xE9 => self.sbc(bus, AddressingMode::Immediate)?,
            0xEB => self.sbc(bus, AddressingMode::Immediate)?,
            0xEC => self.cpx(bus, AddressingMode::Absolute)?,
            0xED => self.sbc(bus, AddressingMode::Absolute)?,
            0xEE => self.inc(bus, AddressingMode::Absolute)?,
            0xEF => self.isc(bus, AddressingMode::Absolute)?,
            0xF0 => self.beq(bus)?,
            0xF1 => self.sbc(bus, AddressingMode::IndirectIndexed)?,
            0xF2 => self.stp(bus)?,
            0xF3 => self.isc(bus, AddressingMode::IndirectIndexed)?,
            0xF4 => self.nop(bus, AddressingMode::ZeroPageX)?,
            0xF5 => self.sbc(bus, AddressingMode::ZeroPageX)?,
            0xF6 => self.inc(bus, AddressingMode::ZeroPageX)?,
            0xF7 => self.isc(bus, AddressingMode::ZeroPageX)?,
            0xF8 => self.setflg(bus, FLAG_DECIMAL, true)?,
            0xF9 => self.sbc(bus, AddressingMode::AbsoluteY)?,
            0xFA => self.nop(bus, AddressingMode::Accumulator)?,
            0xFB => self.isc(bus, AddressingMode::AbsoluteY)?,
            0xFC => self.nop(bus, AddressingMode::AbsoluteX)?,
            0xFD => self.sbc(bus, AddressingMode::AbsoluteX)?,
            0xFE => self.inc(bus, AddressingMode::AbsoluteX)?,
            0xFF => self.isc(bus, AddressingMode::AbsoluteX)?,
        }

        // cpu_log(format!(" A:{:#X} X:{:#X} Y:{:#X} P:{:#X} SP:{:#X} PPU {},{} CYC:{}", 
        // self.a, self.x, self.y, self.p, self.s, self.ppu.line_num, self.ppu.cycle_num, self.cycle_count
        // ).as_str());

        self.current_instruction_cycles = self.current_instruction_cycles.max(2);
        self.cycle_count += self.current_instruction_cycles as u128;
        
        Ok(())
    }

    fn brk(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;
        self.pc += 1;

        self.stack_push_word(bus, self.pc)?;
        self.stack_push_byte(bus, self.p | FLAG_B)?;
        self.set_flag(FLAG_INTERRUPT_DISABLE, true);
        let pc_upper = self.read_byte(bus, 0xFFFE)? as u16;
        let pc_lower = self.read_byte(bus, 0xFFFF)? as u16;
        self.pc = (pc_lower as u16) << 8 | pc_upper as u16;

        cpu_log("BRK");
        Ok(())
    }

    // 0x02
    fn stp(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;
        self.read_byte(bus, self.pc)?;

        cpu_log("STP");

        //self.pc -= 1;

        Ok(())
    }

    // 0x08
    fn php(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;
        self.stack_push_byte(bus, self.p | FLAG_B | FLAG_ONE)?;

        cpu_log("PHP");

        Ok(())
    }

    // 0x01, 0x09
    fn ora(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.a = self.a | byte;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a >> 7 & 1 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("ORA");

        Ok(())
    }

    // 0x03 (Unofficial)
    fn slo(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let carry = byte >> 7 & 1 == 1;
        let new_byte = byte << 1;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.set_flag(FLAG_ZERO, new_byte == 0);
        self.set_flag(FLAG_CARRY, carry);
        self.set_flag(FLAG_NEG, new_byte >> 7 & 1 == 1);

        self.a = self.a | new_byte;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("SLO");

        Ok(())
    }

    // 0x0A
    fn asl(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let carry = byte >> 7 & 1 == 1;
        let new_byte = byte << 1;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.set_flag(FLAG_ZERO, new_byte == 0);
        self.set_flag(FLAG_CARRY, carry);
        self.set_flag(FLAG_NEG, new_byte >> 7 & 1 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("ASL");

        Ok(())
    }

    // 0x0B (Unofficial)
    fn anc(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.a = self.a & byte;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a >> 7 & 1 == 1);
        self.set_flag(FLAG_CARRY, self.p & FLAG_NEG > 0);

        self.advance_pc(addressing_mode);
        cpu_log("AND");

        Ok(())
    }

    // 0x10
    fn bpl(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;
        cpu_log("BPL");

        self.pc += 1;

        if self.get_flag(FLAG_NEG) {
            return Ok(())
        }

        self.branch_with_offset(bus, offset_byte)?;

        Ok(())
    }

    // 0x18
    fn setflg(&mut self, bus: &mut dyn AddressBus, flag: u8, value: bool) -> Result<(), EmulatorError> {
        if value {
            self.p = self.p | flag;
        } else {
            self.p = self.p & !flag;
        }

        self.read_byte(bus, self.pc)?;

        self.advance_pc(AddressingMode::Implied);
        cpu_log("SETFLG");

        Ok(())
    }

    // 0x20
    fn jsr(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let addr_lower = self.read_byte(bus, self.pc)?;
        self.read_byte(bus, self.s as u16 % 0x100 + 0x100)?;
        self.stack_push_word(bus, self.pc + 1)?;
        let addr_upper = self.read_byte(bus, self.pc + 1)?;
        let addr = ((addr_upper as u16) << 8) + addr_lower as u16;
        self.pc = addr;

        cpu_log("JSR");

        Ok(())
    }

    // 0x24
    fn bit(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.set_flag(FLAG_ZERO, self.a & byte == 0);
        self.set_flag(FLAG_OVERFLOW, byte & 1 << 6 == 1 << 6);
        self.set_flag(FLAG_NEG, byte & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("BIT");

        Ok(())
    }

    // 0x28
    fn plp(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.p = self.stack_pop_byte(bus)? & !FLAG_B | FLAG_ONE;

        cpu_log("PLP");

        Ok(())
    }

    // 0x21, 0x29
    fn and(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.a = self.a & byte;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("AND");

        Ok(())
    }

    // 0x23 (Unofficial)
    fn rla(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        let new_carry = byte >> 7 & 1 == 1;
        let mut new_byte = byte << 1;
        if self.get_flag(FLAG_CARRY) {
            new_byte |= 1;
        }

        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.a = self.a & new_byte;

        self.set_flag(FLAG_CARRY, new_carry);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a >> 7 & 1 == 1);
        
        self.advance_pc(addressing_mode);
        cpu_log("RLA");

        Ok(())
    }

    // 0x2A
    fn rol(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let new_carry = byte >> 7 & 1 == 1;
        let mut new_byte = byte << 1;
        if self.get_flag(FLAG_CARRY) {
            new_byte |= 1;
        }

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.set_flag(FLAG_CARRY, new_carry);
        self.set_flag(FLAG_ZERO, new_byte == 0);
        self.set_flag(FLAG_NEG, new_byte >> 7 & 1 == 1);
        
        self.advance_pc(addressing_mode);
        cpu_log("ROL");

        Ok(())
    }

    // 0x30
    fn bmi(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;
        cpu_log("BMI");

        self.pc += 1;

        if self.get_flag(FLAG_NEG) {
            self.branch_with_offset(bus, offset_byte)?;
        }

        Ok(())
    }

    // 0x40
    fn rti(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.p = (self.p & 0b00110000) | (self.stack_pop_byte(bus)? & 0b11001111);
        let return_addr = self.stack_pop_word(bus)?;
        self.pc = return_addr;

        cpu_log("RTI");

        Ok(())
    }

    // 0x4C
    fn jmp(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let addr: u16 = self.get_addr_absolute(bus)?;
        self.pc = addr;

        cpu_log("JMP");

        Ok(())
    }

    // 0x48
    fn pha(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.stack_push_byte(bus, self.a)?;

        cpu_log("PHA");

        Ok(())
    }

    // 0x41, 0x49
    fn eor(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.a = self.a ^ byte;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("EOR");

        Ok(())
    }

    // 0x43 (Unofficial)
    fn sre(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let carry = byte % 2 == 1;
        let new_byte = byte >> 1;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.a = self.a ^ new_byte;

        self.set_flag(FLAG_CARRY, carry);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a >> 7 & 1 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("SRE");

        Ok(())
    }

    // 0x4A
    fn lsr(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let carry = byte % 2 == 1;
        let new_byte = byte >> 1;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.set_flag(FLAG_ZERO, new_byte == 0);
        self.set_flag(FLAG_CARRY, carry);
        self.set_flag(FLAG_NEG, false);

        self.advance_pc(addressing_mode);
        cpu_log("LSR");

        Ok(())
    }

    // 0x4B (Unofficial)
    fn alr(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let new_byte = self.a & byte;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.a = new_byte >> 1;

        self.set_flag(FLAG_CARRY, new_byte % 2 == 1);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a >> 7 & 1 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("SRE");

        Ok(())
    }

    // 0x50
    fn bvc(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;

        cpu_log("BVC");

        self.pc += 1;

        if !self.get_flag(FLAG_OVERFLOW) {
            self.branch_with_offset(bus, offset_byte)?;
        }

        Ok(())
    }

    // 0x60
    fn rts(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;
        self.read_byte(bus, self.s as u16 + 0x100)?;

        let return_addr = self.stack_pop_word(bus)?;
        self.read_byte(bus, return_addr)?;
        self.pc = return_addr + 1;

        cpu_log("RTS");

        Ok(())
    }

    // 0x63 (Unofficial)
    fn rra(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let mut new_byte= byte >> 1;
        if self.get_flag(FLAG_CARRY) {
            new_byte |= 1 << 7;
        }

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.set_flag(FLAG_CARRY, byte & 1 == 1);

        let carry_addition = self.get_flag(FLAG_CARRY) as u8;
        let res0 = self.a.overflowing_add(new_byte);
        let res1 = res0.0.overflowing_add(carry_addition);

        let overflow = (res1.0 ^ self.a) & (res1.0 ^ new_byte) & (1 << 7) != 0;
        self.a = res1.0 as u8;

        self.set_flag(FLAG_CARRY, res0.1 || res1.1);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_OVERFLOW, overflow);
        self.set_flag(FLAG_NEG, self.a >> 7 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("RRA");

        Ok(())
    }

    // 0x68
    fn pla(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.a = self.stack_pop_byte(bus)?;        

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        cpu_log("PLA");

        Ok(())
    }

    // 0x61, 0x69
    fn adc(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        let carry_addition = self.get_flag(FLAG_CARRY) as u8;
        let res0 = self.a.overflowing_add(byte);
        let res1 = res0.0.overflowing_add(carry_addition);

        let overflow = (res1.0 ^ self.a) & (res1.0 ^ byte) & (1 << 7) != 0;
        self.a = res1.0 as u8;

        self.set_flag(FLAG_CARRY, res0.1 || res1.1);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_OVERFLOW, overflow);
        self.set_flag(FLAG_NEG, self.a >> 7 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("ADC");

        Ok(())
    }

    // 0x66, 0x6A
    fn ror(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let new_carry = byte & 1 != 0;
        let mut new_byte= byte >> 1;
        if self.get_flag(FLAG_CARRY) {
            new_byte |= 1 << 7;
        }

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.set_flag(FLAG_CARRY, new_carry);
        self.set_flag(FLAG_ZERO, new_byte == 0);
        self.set_flag(FLAG_NEG, new_byte >> 7 & 1 == 1);

        self.advance_pc(addressing_mode);

        cpu_log("ROR");

        Ok(())
    }

    // 0x6B (Unofficial)
    fn arr(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        let new_byte = self.a & byte;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;
        self.write_addressing_mode(bus, addressing_mode, new_byte, false)?;

        self.a = new_byte >> 1;
        if self.get_flag(FLAG_CARRY) {
            self.a |= 1 << 7;
        }

        self.set_flag(FLAG_CARRY, self.a >> 6 & 1 == 1);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a >> 7 & 1 == 1);
        self.set_flag(FLAG_OVERFLOW, ((self.a >> 6) ^ (self.a >> 5)) & 1 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("SRE");

        Ok(())
    }

    // 0x6C
    fn jmp_indr(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let indr_addr = self.get_addr_absolute(bus)?;

        let mut indr_addr_upper = indr_addr;
        if indr_addr & 0xFF == 0xFF {
            indr_addr_upper &= 0xFF00;
        } else {
            indr_addr_upper += 1;
        }

        let addr_lower = self.read_byte(bus, indr_addr)?;
        let addr_upper = self.read_byte(bus, indr_addr_upper)?;
        let addr = ((addr_upper as u16) << 8) | addr_lower as u16;

        self.pc = addr;
        cpu_log("JMP INDR {:#8X}");

        Ok(())
    }

    // 0x70
    fn bvs(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;
        cpu_log("BVS");

        self.pc += 1;

        if self.get_flag(FLAG_OVERFLOW) {
            self.branch_with_offset(bus, offset_byte)?;
        }

        Ok(())
    }

    // 0x84
    fn sty(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.write_addressing_mode(bus, addressing_mode, self.y, true)?;
        self.advance_pc(addressing_mode);
        cpu_log("STY");
        Ok(())
    }

    // 0x85
    fn sta(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.write_addressing_mode(bus, addressing_mode, self.a, true)?;
        self.advance_pc(addressing_mode);
        cpu_log("STA");
        Ok(())
    }

    // 0x83 (Unofficial)
    fn sax(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.write_addressing_mode(bus, addressing_mode, self.a & self.x, false)?;
        self.advance_pc(addressing_mode);
        cpu_log("SAX");
        Ok(())
    }

    // 0x86
    fn stx(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.write_addressing_mode(bus, addressing_mode, self.x, true)?;
        self.advance_pc(addressing_mode);
        cpu_log("STX");

        Ok(())
    }

    // 0x88
    fn dey(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.y = self.y.overflowing_sub(1).0;

        self.set_flag(FLAG_ZERO, self.y == 0);
        self.set_flag(FLAG_NEG, self.y & 1 << 7 == 1 << 7);

        cpu_log("DEY");

        Ok(())
    }

    // 0x8A
    fn txa(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.a = self.x;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        cpu_log("TXA");

        Ok(())
    }

    // 0x8B (Unofficial)
    fn xaa(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        // The XAA instruction is supposedly unpredictable
        let magic = 0xEE;
        self.a = (self.a | magic) & self.x & byte;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a >> 7 == 1);

        self.advance_pc(addressing_mode);

        Ok(())
    }

    // 0x90
    fn bcc(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;
        cpu_log("BCC");

        self.pc += 1;

        if !self.get_flag(FLAG_CARRY) {
            self.branch_with_offset(bus, offset_byte)?;
        }

        Ok(())
    }

    // 0x93 (Unofficial)
    fn ahx(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let addr;
        let byte;

        match addressing_mode {
            AddressingMode::IndirectIndexed => {
                let base = self.read_byte(bus, self.pc)?;
                let addr_low = self.read_byte(bus, base as u16)?.overflowing_add(self.y);
                let addr_high = self.read_byte(bus, base.overflowing_add(1).0 as u16)?;
        
                byte = self.x & self.a & (addr_high.overflowing_add(1).0);
        
                addr = if addr_low.1 {
                    ((byte as u16) << 8) | addr_low.0 as u16
                } else {
                    (addr_low.0 as u16).overflowing_add((addr_high as u16) << 8).0
                };

                self.read_byte(bus, ((addr_high as u16) << 8) | addr_low.0 as u16)?;
            }
            _ => {
                let base_low = self.read_byte(bus, self.pc)?;
                let base_high = self.read_byte(bus, self.pc.overflowing_add(1).0)?;
                let addr_low = base_low.overflowing_add(self.y);
        
                byte = self.x & self.a & (base_high.overflowing_add(1).0);
                addr = if addr_low.1 {
                    ((byte as u16) << 8) | addr_low.0 as u16
                } else {
                    (addr_low.0 as u16).overflowing_add((base_high as u16) << 8).0
                };

                self.read_byte(bus, ((base_high as u16) << 8) | addr_low.0 as u16)?;
            }
        }

        self.active_address = Some(addr);
        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        self.advance_pc(addressing_mode);
        cpu_log("AHX");

        Ok(())
    }

    // 0x98
    fn tya(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        self.read_byte(bus, self.pc)?;

        self.a = self.y;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        cpu_log("TYA");
        Ok(())
    }

    // 0x9A
    fn txs(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.s = self.x;

        cpu_log("TXS");
        Ok(())
    }

    // 0x9B (Unofficial)
    fn tas(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let base_low = self.read_byte(bus, self.pc)?;
        let base_high = self.read_byte(bus, self.pc.overflowing_add(1).0)?;
        let addr_low = base_low.overflowing_add(self.y);

        self.s = self.a & self.x;

        let byte = self.a & self.x & (base_high.overflowing_add(1).0);
        let addr = if addr_low.1 {
            ((byte as u16) << 8) | addr_low.0 as u16
        } else {
            (addr_low.0 as u16).overflowing_add((base_high as u16) << 8).0
        };

        self.read_byte(bus, ((base_high as u16) << 8) | addr_low.0 as u16)?;

        self.active_address = Some(addr);
        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        self.advance_pc(addressing_mode);

        Ok(())
    }

    // 0x9C (Unofficial)
    fn shy(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let base_low = self.read_byte(bus, self.pc)?;
        let base_high = self.read_byte(bus, self.pc.overflowing_add(1).0)?;
        let addr_low = base_low.overflowing_add(self.x);

        let byte = self.y & (base_high.overflowing_add(1).0);

        let addr = if addr_low.1 {
            ((byte as u16) << 8) | addr_low.0 as u16
        } else {
            (addr_low.0 as u16).overflowing_add((base_high as u16) << 8).0
        };

        self.read_byte(bus, ((base_high as u16) << 8) | addr_low.0 as u16)?;

        self.active_address = Some(addr);
        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        self.advance_pc(addressing_mode);


        Ok(())
    }

    // 0x9E (Unofficial)
    fn shx(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        let base_low = self.read_byte(bus, self.pc)?;
        let base_high = self.read_byte(bus, self.pc.overflowing_add(1).0)?;
        let addr_low = base_low.overflowing_add(self.y);

        let byte = self.x & (base_high.overflowing_add(1).0);

        let addr = if addr_low.1 {
            ((byte as u16) << 8) | addr_low.0 as u16
        } else {
            (addr_low.0 as u16).overflowing_add((base_high as u16) << 8).0
        };

        self.read_byte(bus, ((base_high as u16) << 8) | addr_low.0 as u16)?;

        self.active_address = Some(addr);
        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        self.advance_pc(addressing_mode);


        Ok(())
    }

    // 0xA0, 0xA4
    fn ldy(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.y = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.set_flag(FLAG_ZERO, self.y == 0);
        self.set_flag(FLAG_NEG, self.y & (1 << 7) == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("LDY");
        
        Ok(())
    }

    // 0xA2, 0xA6
    fn ldx(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.x = self.read_addressing_mode(bus, addressing_mode, false)?;
        
        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & (1 << 7) == 1 << 7);

        cpu_log("LDX");

        self.advance_pc(addressing_mode);

        Ok(())
    }

    // 0xA3 (Unofficial)
    fn lax(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.a = self.read_addressing_mode(bus, addressing_mode, false)?;
        self.x = self.a;
        
        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & (1 << 7) == 1 << 7);

        cpu_log("LAX");
        self.advance_pc(addressing_mode);

        Ok(())
    }

    // 0xA8
    fn tay(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.y = self.a;

        self.set_flag(FLAG_ZERO, self.y == 0);
        self.set_flag(FLAG_NEG, self.y & 1 << 7 == 1 << 7);

        cpu_log("TAY");

        Ok(())
    }

    // 0xA9
    fn lda(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        self.a = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & (1 << 7) != 0);

        self.advance_pc(addressing_mode);
        cpu_log("LDA");

        Ok(())
    }

    // 0xAA
    fn tax(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        
        self.read_byte(bus, self.pc)?;
        
        self.x = self.a;

        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & 1 << 7 == 1 << 7);

        cpu_log("TAX");

        Ok(())
    }

    // 0xAB
    fn lxa(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let byte = self.read_byte(bus, self.pc)?;
        let magic = 0b11101110;
        self.a = (self.a | magic) & byte;
        self.x = self.a;
        
        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & (1 << 7) == 1 << 7);

        cpu_log("LXA");
        self.advance_pc(AddressingMode::Immediate);

        Ok(())    
    }

    // 0xB0
    fn bcs(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;
        cpu_log("BCS");

        self.pc = self.pc.overflowing_add(1).0;

        if self.get_flag(FLAG_CARRY) {
            self.branch_with_offset(bus, offset_byte)?;
        }

        Ok(())
    }

    // 0xBA
    fn tsx(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        self.read_byte(bus, self.pc)?;
        
        self.x = self.s;

        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & 1 << 7 == 1 << 7);

        cpu_log("TSX");

        Ok(())
    }

    // 0xBB
    fn las(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        self.s = byte & self.s;
        self.a = self.s;
        self.x = self.s;

        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_NEG, self.a & (1 << 7) != 0);

        self.advance_pc(addressing_mode);
        cpu_log("LDA");

        Ok(())
    }

    // 0xC0
    fn cpy(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        let result = self.y.overflowing_sub(byte).0;

        self.set_flag(FLAG_CARRY, self.y >= byte);
        self.set_flag(FLAG_ZERO, self.y == byte);
        self.set_flag(FLAG_NEG, result & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("CPY");

        Ok(())
    }

    // 0xC3 (Unofficial)
    fn dcp(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let mut byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        byte = byte.overflowing_sub(1).0;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        let result = self.a.overflowing_sub(byte).0;
        self.set_flag(FLAG_CARRY, self.a >= byte);
        self.set_flag(FLAG_ZERO, self.a == byte);
        self.set_flag(FLAG_NEG, result & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("DCP");

        Ok(())
    }

    // 0xC6
    fn dec(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let mut byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        byte = byte.overflowing_sub(1).0;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        self.set_flag(FLAG_ZERO, byte == 0);
        self.set_flag(FLAG_NEG, byte >> 7 & 1 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("DEC");

        Ok(())
    }

    // 0xC8
    fn iny(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.y = self.y.overflowing_add(1).0;

        self.set_flag(FLAG_ZERO, self.y == 0);
        self.set_flag(FLAG_NEG, self.y & 1 << 7 == 1 << 7);

        cpu_log("INY");

        Ok(())
    }

    // 0xC1, 0xC9
    fn cmp(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        let result = self.a.overflowing_sub(byte).0;

        self.set_flag(FLAG_CARRY, self.a >= byte);
        self.set_flag(FLAG_ZERO, self.a == byte);
        self.set_flag(FLAG_NEG, result >> 7 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("CMP");

        Ok(())
    }

    // 0xCA
    fn dex(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.x = self.x.overflowing_sub(1).0;

        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & 1 << 7 == 1 << 7);

        cpu_log("DEX");

        Ok(())
    }

    // 0xCB
    fn axs(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        let byte = self.read_byte(bus, self.pc)?;
        let res = (self.a & self.x).overflowing_sub(byte);

        self.x = res.0;
        
        self.set_flag(FLAG_CARRY, !res.1);
        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & 1 << 7 == 1 << 7);

        cpu_log("DEX");

        self.pc += 1;

        Ok(())
    }

    // 0xD0
    fn bne(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;

        cpu_log("BNE");

        self.pc += 1;

        if !self.get_flag(FLAG_ZERO) {
            self.branch_with_offset(bus, offset_byte)?;
        }

        Ok(())
    }

    // 0xE0
    fn cpx(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        let result = self.x.overflowing_sub(byte).0;

        self.set_flag(FLAG_CARRY, self.x >= byte);
        self.set_flag(FLAG_ZERO, self.x == byte);
        self.set_flag(FLAG_NEG, result & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("CPX");

        Ok(())
    }

    // 0xE3
    fn isc(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let mut byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        byte = byte.overflowing_add(1).0;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        let carry_addition = !self.get_flag(FLAG_CARRY) as u8;

        let res_0 = self.a.overflowing_sub(byte);
        let res_1 = res_0.0.overflowing_sub(carry_addition);

        let clear_carry = res_0.1 || res_1.1;
        let overflow = ((res_1.0 ^ self.a) & (res_1.0 ^ !byte) & 0x80) != 0;

        self.a = res_1.0;

        self.set_flag(FLAG_CARRY, !clear_carry);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_OVERFLOW, overflow);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("ISC");

        Ok(())
    }

    // 0xE8
    fn inx(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {

        self.read_byte(bus, self.pc)?;

        self.x = self.x.overflowing_add(1).0;

        self.set_flag(FLAG_ZERO, self.x == 0);
        self.set_flag(FLAG_NEG, self.x & 1 << 7 == 1 << 7);

        cpu_log("INX");

        Ok(())
    }

    // 0xE1, 0xE9
    fn sbc(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let byte = self.read_addressing_mode(bus, addressing_mode, false)?;

        let carry_addition = !self.get_flag(FLAG_CARRY) as u8;

        let res_0 = self.a.overflowing_sub(byte);
        let res_1 = res_0.0.overflowing_sub(carry_addition);

        let clear_carry = res_0.1 || res_1.1;
        let overflow = ((res_1.0 ^ self.a) & (res_1.0 ^ !byte) & 0x80) != 0;

        self.a = res_1.0;

        self.set_flag(FLAG_CARRY, !clear_carry);
        self.set_flag(FLAG_ZERO, self.a == 0);
        self.set_flag(FLAG_OVERFLOW, overflow);
        self.set_flag(FLAG_NEG, self.a & 1 << 7 == 1 << 7);

        self.advance_pc(addressing_mode);
        cpu_log("SBC");

        Ok(())
    }

    // 0xE6
    fn inc(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {
        let mut byte = self.read_addressing_mode(bus, addressing_mode, true)?;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        byte = byte.overflowing_add(1).0;

        self.write_addressing_mode(bus, addressing_mode, byte, false)?;

        self.set_flag(FLAG_ZERO, byte == 0);
        self.set_flag(FLAG_NEG, byte >> 7 & 1 == 1);

        self.advance_pc(addressing_mode);
        cpu_log("INC");

        Ok(())
    }

    // 0xEA
    fn nop(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode) -> Result<(), EmulatorError> {

        // Reads still happen, passing some cycles
        let _ = self.read_addressing_mode(bus, addressing_mode, false)?;

        cpu_log("NOP");
        self.advance_pc(addressing_mode);
        Ok(())
    }

    // 0xF0
    fn beq(&mut self, bus: &mut dyn AddressBus) -> Result<(), EmulatorError> {
        let offset_byte = self.read_byte(bus, self.pc)?;
        cpu_log("BEQ");
        
        self.pc += 1;

        if self.p & FLAG_ZERO == FLAG_ZERO {
            self.branch_with_offset(bus, offset_byte)?;
        }

        Ok(())
    }

    fn advance_pc(&mut self, addressing_mode: AddressingMode) {
        match addressing_mode {
            AddressingMode::Accumulator |
            AddressingMode::Implied => {},
            AddressingMode::Immediate |
            AddressingMode::ZeroPage |
            AddressingMode::ZeroPageX |
            AddressingMode::ZeroPageY |
            AddressingMode::IndexedIndirect |
            AddressingMode::IndirectIndexed => { self.pc = self.pc.overflowing_add(1).0; },
            AddressingMode::Absolute  |
            AddressingMode::AbsoluteX |
            AddressingMode::AbsoluteY => { self.pc = self.pc.overflowing_add(2).0 },
        }
    }

    fn read_addressing_mode(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode, assume_pg_boundary: bool) -> Result<u8, EmulatorError> {
        let byte= match addressing_mode {
            AddressingMode::Accumulator => {
                self.read_byte(bus, self.pc)?;
                self.a
            }
            AddressingMode::Immediate => {
                self.read_byte(bus, self.pc)?
            }
            AddressingMode::Implied => {
                self.read_byte(bus, self.pc)?;
                0
            }
            AddressingMode::ZeroPage => {
                let addr = self.read_byte(bus, self.pc)? as u16;
                self.active_address = Some(addr);
                self.read_byte(bus, addr)?
            }
            AddressingMode::ZeroPageX => {
                let addr = self.get_addr_zero_x(bus)?;
                self.read_byte(bus, addr)?
            }
            AddressingMode::ZeroPageY => {
                let addr = self.get_addr_zero_y(bus)?;
                self.read_byte(bus, addr)?
            }
            AddressingMode::Absolute => {
                let addr = self.get_addr_absolute(bus)?;
                self.read_byte(bus, addr)?
            }
            AddressingMode::AbsoluteX => {
                let addr = self.get_addr_absolute_x(bus, assume_pg_boundary)?;
                self.read_byte(bus, addr)?
            }
            AddressingMode::AbsoluteY => {
                let addr = self.get_addr_absolute_y(bus, assume_pg_boundary)?;
                self.read_byte(bus, addr)?
            }
            AddressingMode::IndexedIndirect => {
                let addr = self.get_addr_indexed_indirect(bus)?;
                self.read_byte(bus, addr)?
            }
            AddressingMode::IndirectIndexed => {
                let addr = self.get_addr_indirect_indexed(bus, assume_pg_boundary)?;
                self.read_byte(bus, addr)?
            }
        };

        Ok(byte)
    }

    fn write_addressing_mode(&mut self, bus: &mut dyn AddressBus, addressing_mode: AddressingMode, byte: u8, assume_pg_boundary: bool) -> Result<(), EmulatorError> {
        match addressing_mode {
            AddressingMode::Accumulator => {
                self.a = byte;
            }
            AddressingMode::Immediate => {}
            AddressingMode::Implied => {
                return Err(EmulatorError::CpuError("Implied addressing mode should not write bytes".to_string())) 
            }
            AddressingMode::ZeroPage => {
                let addr = if let Some(addr) = self.active_address { addr } 
                else { self.read_byte(bus, self.pc)? as u16 };
                self.write_byte(bus, addr as u16, byte)?;
            }
            AddressingMode::ZeroPageX => {
                let addr = if let Some(addr) = self.active_address { addr } 
                else { self.get_addr_zero_x(bus)? };
                self.write_byte(bus, addr, byte)?;
            }
            AddressingMode::ZeroPageY => {
                let addr = if let Some(addr) = self.active_address { addr } 
                else { self.get_addr_zero_y(bus)? };
                self.write_byte(bus, addr, byte)?;
            }
            AddressingMode::Absolute => {
                let addr = if let Some(addr) = self.active_address { addr } 
                else { self.get_addr_absolute(bus)? };
                self.write_byte(bus, addr, byte)?;
            }
            AddressingMode::AbsoluteX => {
                let addr = self.get_addr_absolute_x(bus, assume_pg_boundary)?;
                self.write_byte(bus, addr, byte)?;
            }
            AddressingMode::AbsoluteY => {
                let addr = self.get_addr_absolute_y(bus, assume_pg_boundary)?;
                self.write_byte(bus, addr, byte)?;
            }
            AddressingMode::IndexedIndirect => {
                let addr = self.get_addr_indexed_indirect(bus)?;
                self.write_byte(bus, addr, byte)?;
            }
            AddressingMode::IndirectIndexed => {
                let addr = self.get_addr_indirect_indexed(bus, assume_pg_boundary)?;
                self.write_byte(bus, addr, byte)?;
            }
        }

        Ok(())
    }

    fn get_addr_absolute(&mut self, bus: &mut dyn AddressBus) -> Result<u16, EmulatorError> {
        let addr_lower = self.read_byte(bus, self.pc)?;
        let addr_upper = self.read_byte(bus, self.pc.overflowing_add(1).0)?;
        let addr = ((addr_upper as u16) << 8) + addr_lower as u16;
        self.active_address = Some(addr);
        Ok(addr)
    }

    fn get_addr_zero_x(&mut self, bus: &mut dyn AddressBus) -> Result<u16, EmulatorError> {
        let base_addr = self.read_byte(bus, self.pc)?;
        self.read_byte(bus, base_addr as u16)?;
        let addr = base_addr.overflowing_add(self.x).0 as u16;
        self.active_address = Some(addr);
        Ok(addr)
    }

    fn get_addr_zero_y(&mut self, bus: &mut dyn AddressBus) -> Result<u16, EmulatorError> {
        let base_addr = self.read_byte(bus, self.pc)?;
        self.read_byte(bus, base_addr as u16)?;
        let addr = base_addr.overflowing_add(self.y).0 as u16;
        self.active_address = Some(addr);
        Ok(addr)
    }

    fn get_addr_absolute_x(&mut self, bus: &mut dyn AddressBus, assume_pg_boundary: bool) -> Result<u16, EmulatorError> {

        if let Some(addr) = self.active_address {
            return Ok(addr)
        }

        let base_low = self.read_byte(bus, self.pc)?;
        let base_high = self.read_byte(bus, self.pc.overflowing_add(1).0)?;
        let addr_low = base_low.overflowing_add(self.x);
        let mut addr = ((base_high as u16) << 8) | addr_low.0 as u16;
        if assume_pg_boundary || addr_low.1 {
            self.read_byte(bus, addr)?;
        }
        if addr_low.1 {
            addr = addr.overflowing_add(0x100).0;
        }
        self.active_address = Some(addr);
        Ok(addr)
    }

    fn get_addr_absolute_y(&mut self, bus: &mut dyn AddressBus, assume_pg_boundary: bool) -> Result<u16, EmulatorError> {

        if let Some(addr) = self.active_address {
            return Ok(addr)
        }

        let base_low = self.read_byte(bus, self.pc)?;
        let base_high = self.read_byte(bus, self.pc.overflowing_add(1).0)?;
        let addr_low = base_low.overflowing_add(self.y);
        let mut addr = ((base_high as u16) << 8) | addr_low.0 as u16;
        if assume_pg_boundary || addr_low.1 {
            self.read_byte(bus, addr)?;
        }
        if addr_low.1 {
            addr = addr.overflowing_add(0x100).0;
        }
        self.active_address = Some(addr);
        Ok(addr)
    }

    /// The (d,x) one
    fn get_addr_indexed_indirect(&mut self, bus: &mut dyn AddressBus) -> Result<u16, EmulatorError> {

        if let Some(addr) = self.active_address {
            return Ok(addr)
        }

        let base = self.read_byte(bus, self.pc)?;
        self.read_byte(bus, base as u16)?;

        let addr_lower_addr = base.overflowing_add(self.x).0;
        let addr_upper_addr = base.overflowing_add(self.x).0.overflowing_add(1).0;
        
        let addr_lower = self.read_byte(bus, addr_lower_addr as u16)?;
        let addr_upper = self.read_byte(bus, addr_upper_addr as u16)?;
        let addr = ((addr_upper as u16) << 8) + addr_lower as u16;

        self.active_address = Some(addr);

        Ok(addr)
    }

    /// The (d),y one
    fn get_addr_indirect_indexed(&mut self, bus: &mut dyn AddressBus, assume_pg_boundary: bool) -> Result<u16, EmulatorError> {

        if let Some(addr) = self.active_address {
            return Ok(addr)
        }

        let base = self.read_byte(bus, self.pc)?;
        let addr_lower = self.read_byte(bus, base as u16)?;
        let indexed_lower = addr_lower.overflowing_add(self.y);

        let addr_upper_addr = base.overflowing_add(1);
        let addr_upper = self.read_byte(bus, addr_upper_addr.0 as u16)?;

        let mut addr = ((addr_upper as u16) << 8) + indexed_lower.0 as u16;
        if assume_pg_boundary || indexed_lower.1 {
            self.read_byte(bus, addr)?;
        }
        if indexed_lower.1 {
            addr = addr.overflowing_add(0x100).0;
        }
        
        self.active_address = Some(addr);

        Ok(addr)
    }

    fn stack_push_byte(&mut self, bus: &mut dyn AddressBus, byte: u8) -> Result<(), EmulatorError> {
        self.write_byte(bus, self.s as u16 + 0x100, byte)?;
        let new_s = self.s.overflowing_sub(1);

        self.s = new_s.0;

        Ok(())
    }

    fn stack_pop_byte(&mut self, bus: &mut dyn AddressBus) -> Result<u8, EmulatorError> {
        let new_s = self.s.overflowing_add(1);
        self.read_byte(bus, (self.s as u16) % 0x100 + 0x100)? as u16;
        let byte = self.read_byte(bus, new_s.0 as u16 + 0x100)?;

        self.s = new_s.0;

        Ok(byte)
    }

    fn stack_push_word(&mut self, bus: &mut dyn AddressBus, val: u16) -> Result<(), EmulatorError> {
        let res = self.s.overflowing_sub(2);
        self.s = res.0;

        self.write_byte(bus, (2 + self.s as u16) % 0x100 + 0x100, ((val & 0xFF00) >> 8) as u8)?;
        self.write_byte(bus, (1 + self.s as u16) % 0x100 + 0x100, (val & 0x00FF) as u8)?;

        Ok(())
    }

    fn stack_pop_word(&mut self, bus: &mut dyn AddressBus) -> Result<u16, EmulatorError> {
        let byte_lower = self.read_byte(bus, (1 + self.s as u16) % 0x100 + 0x100)? as u16;
        let byte_upper = self.read_byte(bus, (2 + self.s as u16) % 0x100 + 0x100)? as u16;
        let res = self.s.overflowing_add(2);

        if res.1 {
            cpu_log("Warning: Stack Underflow");
        }

        self.s = res.0;

        Ok(byte_lower | (byte_upper << 8))
    }

    fn branch_with_offset(&mut self, bus: &mut dyn AddressBus, offset_byte: u8) -> Result<(), EmulatorError> {
        let offset: i32 = match offset_byte {
            offset_byte if offset_byte >> 7 & 1 == 0 => offset_byte as i32,
            _ => -256 + offset_byte as i32,
        }; 
        let pc_lsb = (self.pc & 0xFF) as i32;

        self.read_byte(bus, self.pc)?;

        let new_pc = self.pc.overflowing_add(offset as u16).0;
        
        // "Oops read" - extraneous read of the incompletely added address
        if pc_lsb + offset > 0xFF || pc_lsb + offset < 0 {
            self.read_byte(bus, self.pc & 0xFF00 | new_pc & 0x00FF)?; 
        }

        self.pc = new_pc;

        Ok(())
    }

    fn read_byte(&mut self, bus: &mut dyn AddressBus, addr: u16) -> Result<u8, EmulatorError> {
        self.current_instruction_cycles += 1;
        bus.read_byte(addr)
    }

    fn write_byte(&mut self, bus: &mut dyn AddressBus, addr: u16, byte: u8) -> Result<(), EmulatorError> {
        self.current_instruction_cycles += 1;
        bus.write_byte(addr, byte)?;
        Ok(())
    }

    fn get_flag(&self, flag: u8) -> bool {
        self.p & flag == flag
    }

    fn set_flag(&mut self, flag: u8, value: bool) {
        if value {
            self.p = self.p | flag;
        } else {
            self.p = self.p & !flag;
        }
    }
}