use std::{fs, path::Path};

use crate::error::EmulatorError;

#[derive(Default)]
pub enum MappingMode {
    #[default]
    LoRom,
    HiRom,
    ExHiRom,
}

#[derive(Default)]
pub struct RomHeader {
    pub title: String,
    pub mode: MappingMode,
    pub chipset: u8,
    pub rom_size: usize,
    pub ram_size: usize,
    pub country: u8,
    pub dev_id: u8,
    pub version: u8,
    pub checksum: u16,
}

#[derive(Default)]
pub struct RomFile {
    pub header: RomHeader,
    pub rom: Vec<u8>,
    pub ram: Vec<u8>,
}

impl RomFile {
    pub fn new(path: &Path) -> Result<Self, EmulatorError> {

        let mut rom = Self::read_data(path)?;
        Self::remove_file_header(&mut rom);
        let header = Self::find_rom_header(&rom)?;

        if 0x400 * header.rom_size != rom.len() {
            return Err(EmulatorError::RomError(format!("ROM size {} does not match header {}", rom.len(), 0x400 * header.rom_size)))
        }

        let mut ram = Vec::new();
        ram.resize(0x400 * header.ram_size, 0u8);

        Ok(RomFile {
            header,
            rom,
            ram,
        })
    }

    fn read_data(path: &Path) -> Result<Vec<u8>, EmulatorError> {
        fs::read(path).map_err(|err| {
            return EmulatorError::RomError(
                format!("{} - Failed to read ROM file", err.to_string())
            )
        })
    }

    fn remove_file_header(data: &mut Vec<u8>) {
        let file_header_present = data.len() % 1024 == 512;
        if file_header_present {
            data.drain(0..512);
        }
    }

    fn find_rom_header(data: &Vec<u8>) -> Result<RomHeader, EmulatorError> {
        let checksum = data
            .iter()
            .map(|v| *v as u16)
            .fold(0u16, |sum, byte| sum.overflowing_add(byte).0);

        let header_data = [0x007FC0, 0x00FFC0, 0x40FFC0]
            .into_iter()
            .find_map(|base: usize| -> Option<&[u8]> {
                if data.len() < base+512 {
                    return None
                }
                let candidate: &[u8] = &data[base..base+512];
                let candidate_checksum = u16::from_le_bytes([candidate[0x1E], candidate[0x1F]]);
                if candidate_checksum == checksum  {
                    return Some(candidate);
                }
                None
            })
            .ok_or(EmulatorError::RomError("Failed to find ROM header".to_owned()))?;

        let title = String::from_utf8_lossy(&header_data[0..21]).into_owned();
        let mode = match header_data[21] & 0b111 {
            0 => MappingMode::LoRom,
            1 => MappingMode::HiRom,
            5 => MappingMode::ExHiRom,
            byte => return Err(EmulatorError::RomError(format!("Invalid mapping mode {}", byte).to_owned()))
        };
        let chipset = header_data[22];
        let rom_size = 1 << header_data[23];
        let ram_size = 1 << header_data[24];
        let country = header_data[25];
        let dev_id = header_data[26];
        let version = header_data[27];

        Ok(RomHeader {
            title,
            mode,
            chipset,
            rom_size,
            ram_size,
            country,
            dev_id,
            version,
            checksum,
        })
    }


}