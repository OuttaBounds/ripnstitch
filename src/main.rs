use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::str::FromStr;
use sha2::{Sha256, Digest};

#[derive(Debug)]
#[allow(dead_code)]
struct FirmwarePart {
    name: String,
    offset: u64,
    size: u64,
    padding_byte: u8,
    use_custom_padding: bool,
    has_explicit_size: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
enum FirmwareError {
    Io(io::Error),
    Parse(String),
    Config(String),
}

impl From<io::Error> for FirmwareError {
    fn from(error: io::Error) -> Self {
        FirmwareError::Io(error)
    }
}

fn parse_number(s: &str) -> Result<u64, FirmwareError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }

    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
    } else {
        u64::from_str(s)
    }
    .map_err(|e| FirmwareError::Parse(format!("Failed to parse number: {}", e)))
}

fn get_file_size(path: &Path) -> io::Result<u64> {
    Ok(fs::metadata(path)?.len())
}

fn calculate_sizes(
    parts: &mut Vec<FirmwarePart>,
    is_unpack: bool,
    input_file: &Path,
) -> Result<(), FirmwareError> {
    let total_size = if is_unpack {
        get_file_size(input_file)?
    } else {
        parts
            .iter()
            .filter(|p| p.has_explicit_size)
            .map(|p| p.offset + p.size)
            .max()
            .unwrap_or(0)
    };

    for i in 0..parts.len() {
        if !parts[i].has_explicit_size {
            if i < parts.len() - 1 {
                parts[i].size = parts[i + 1].offset - parts[i].offset;
            } else if is_unpack && total_size > 0 {
                parts[i].size = total_size - parts[i].offset;
            } else if !is_unpack {
                let filename = format!("{}.bin", parts[i].name);
                if let Ok(size) = get_file_size(Path::new(&filename)) {
                    parts[i].size = size;
                } else {
                    println!("Warning: Could not determine size for last part '{}'", parts[i].name);
                }
            }
        }
    }
    Ok(())
}

fn read_config(
    config_path: &Path,
    firmware_path: &Path,
    is_unpack: bool,
) -> Result<Vec<FirmwarePart>, FirmwareError> {
    let content = fs::read_to_string(config_path)
        .map_err(|e| FirmwareError::Config(format!("Failed to read config file: {}", e)))?;

    let mut parts = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 2 {
            continue;
        }

        let name = fields[0].trim().to_string();
        let offset = parse_number(fields[1])?;

        let (size, has_explicit_size) = if fields.len() > 2 && !fields[2].trim().is_empty() {
            (parse_number(fields[2])?, true)
        } else {
            (0, false)
        };

        let padding_byte = if fields.len() > 3 {
            parse_number(fields[3])? as u8
        } else {
            0xFF
        };

        parts.push(FirmwarePart {
            name,
            offset,
            size,
            padding_byte,
            use_custom_padding: fields.len() > 3,
            has_explicit_size,
        });
    }

    calculate_sizes(&mut parts, is_unpack, firmware_path)?;

    println!("Firmware parts:");
    for part in &parts {
        println!(
            "{}: offset=0x{:x}, size=0x{:x}{}, padding=0x{:02X}",
            part.name,
            part.offset,
            part.size,
            if part.has_explicit_size { "" } else { " (auto)" },
            part.padding_byte
        );
    }

    Ok(parts)
}

fn unpack_firmware(
    firmware_path: &Path,
    parts: &[FirmwarePart],
) -> Result<(), FirmwareError> {
    let mut firmware = File::open(firmware_path)?;
    let mut buffer = vec![0u8; 4096];

    for part in parts {
        let mut output = File::create(format!("{}.bin", part.name))?;
        firmware.seek(SeekFrom::Start(part.offset))?;

        let mut remaining = part.size;
        let mut hasher = Sha256::new();

        while remaining > 0 {
            let to_read = remaining.min(buffer.len() as u64) as usize;
            let bytes_read = firmware.read(&mut buffer[..to_read])?;
            if bytes_read == 0 {
                break;
            }
            output.write_all(&buffer[..bytes_read])?;
            hasher.update(&buffer[..bytes_read]);
            remaining -= bytes_read as u64;
        }

        let hash = format!("{:x}", hasher.finalize());
        println!(
            "Extracted {}: {} bytes, SHA256: {}",
            part.name,
            part.size - remaining,
            hash
        );
    }

    Ok(())
}

fn pack_firmware(
    firmware_path: &Path,
    parts: &[FirmwarePart],
) -> Result<(), FirmwareError> {
    let mut firmware = File::create(firmware_path)?;
    let max_size = parts
        .iter()
        .map(|p| p.offset + p.size)
        .max()
        .unwrap_or(0);

    firmware.set_len(max_size)?;
    firmware.seek(SeekFrom::Start(0))?;
    
    let fill_buffer = vec![0xFF_u8; 4096];
    let mut remaining = max_size;
    while remaining > 0 {
        let to_write = remaining.min(fill_buffer.len() as u64) as usize;
        firmware.write_all(&fill_buffer[..to_write])?;
        remaining -= to_write as u64;
    }

    let mut buffer = vec![0u8; 4096];
    for part in parts {
        if let Ok(mut input) = File::open(format!("{}.bin", part.name)) {
            firmware.seek(SeekFrom::Start(part.offset))?;
            let mut written = 0u64;
            let mut hasher = Sha256::new();

            loop {
                let bytes_read = input.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }

                let to_write = if written + bytes_read as u64 > part.size {
                    (part.size - written) as usize
                } else {
                    bytes_read
                };

                firmware.write_all(&buffer[..to_write])?;
                hasher.update(&buffer[..to_write]);
                written += to_write as u64;

                if written >= part.size {
                    break;
                }
            }

            if written < part.size {
                let padding_size = part.size - written;
                let padding_buffer = vec![part.padding_byte; 4096];
                let mut remaining_padding = padding_size;

                while remaining_padding > 0 {
                    let to_write = remaining_padding.min(padding_buffer.len() as u64) as usize;
                    firmware.write_all(&padding_buffer[..to_write])?;
                    hasher.update(&padding_buffer[..to_write]);
                    remaining_padding -= to_write as u64;
                }

                println!(
                    "Wrote {}: {} bytes (padded {} bytes with 0x{:02X}), SHA256: {:x}",
                    part.name,
                    written,
                    padding_size,
                    part.padding_byte,
                    hasher.finalize()
                );
            } else {
                println!(
                    "Wrote {}: {} bytes, SHA256: {:x}",
                    part.name,
                    written,
                    hasher.finalize()
                );
            }
        } else {
            println!("Warning: {}.bin not found, skipping", part.name);
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Usage: firmware_tool [unpack|pack] <firmware_file> <config_file>");
    println!("Config file format:");
    println!("name, offset [, size] [, padding_byte]");
    println!("Example:");
    println!("header, 0x0, 0x40");
    println!("kernel, 0x40, , 0x00     # size will be auto-calculated");
    println!("rootfs, 0x200040         # size from input file or next offset");
}

fn main() -> Result<(), FirmwareError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        print_usage();
        return Ok(());
    }

    let is_unpack = args[1] == "unpack";
    let firmware_path = Path::new(&args[2]);
    let config_path = Path::new(&args[3]);

    let parts = read_config(config_path, firmware_path, is_unpack)?;

    match args[1].as_str() {
        "unpack" => unpack_firmware(firmware_path, &parts)?,
        "pack" => pack_firmware(firmware_path, &parts)?,
        _ => {
            print_usage();
            return Ok(());
        }
    }

    Ok(())
}