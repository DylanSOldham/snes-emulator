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
pub struct RomFile {
    title: String,
    mode: MappingMode,
    chipset: u8,
    rom_size: usize,
    ram_size: usize,
    country: u8,
    dev_id: u8,
    rom_version: u8,
    checksum: u16,
    checksum_complement: u16,
    rom: Vec<u8>,
    ram: Vec<u8>,
}

impl RomFile {
    pub fn new(path: &Path) -> Result<Self, EmulatorError> {

        let mut data = Self::read_data(path)?;
        Self::remove_file_header(&mut data);
        let rom_header = Self::find_rom_header(&data)?;
        
        let title = String::from_utf8_lossy(&rom_header[0..21]).into_owned();
        println!("Title: {}", title);

        Ok(RomFile {
            title,
            ..Default::default()
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

    fn find_rom_header(data: &Vec<u8>) -> Result<&[u8], EmulatorError> {

        let checksum = data
            .iter()
            .map(|v| *v as u16)
            .fold(0u16, |sum, byte| sum.overflowing_add(byte).0);

        [0x007FC0, 0x00FFC0, 0x40FFC0]
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
            .ok_or(EmulatorError::RomError("Failed to find ROM header".to_owned()))
    }
}