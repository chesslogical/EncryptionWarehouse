use clap::{Parser, Subcommand, ValueEnum};
use std::fs::{read, write};
use std::io::{BufRead, BufReader, Error as IoError};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "byte-converter")]
#[command(about = "A CLI tool to convert binary files to decimal or hex byte text and back")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert a binary file to a text file with space-separated decimal or hex bytes
    Encode {
        /// Input binary file path
        input: PathBuf,
        /// Output text file path (default: bytes.txt)
        #[arg(default_value = "bytes.txt")]
        output: PathBuf,
        /// Format: decimal or hex (default: decimal)
        #[arg(short, long, value_enum, default_value = "decimal")]
        format: Format,
    },
    /// Convert a text file with decimal or hex bytes back to a binary file
    Decode {
        /// Input text file path (e.g., bytes.txt)
        input: PathBuf,
        /// Output binary file path (e.g., reconstructed.exe)
        output: PathBuf,
        /// Format: decimal or hex (default: decimal)
        #[arg(short, long, value_enum, default_value = "decimal")]
        format: Format,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum Format {
    Decimal,
    Hex,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode { input, output, format } => {
            let data = read(&input)?;
            let mut text = String::with_capacity(data.len() * 4); // Rough estimate for capacity
            for &byte in &data {
                match format {
                    Format::Decimal => text.push_str(&format!("{} ", byte)),
                    Format::Hex => text.push_str(&format!("{:02X} ", byte)),
                }
            }
            text = text.trim_end().to_string(); // Remove trailing space
            write(&output, text.as_bytes())?;
            println!("Encoded '{}' to '{}' in {:?}", input.display(), output.display(), format);
        }
        Commands::Decode { input, output, format } => {
            let file = std::fs::File::open(&input)?;
            let reader = BufReader::new(file);
            let mut bytes: Vec<u8> = Vec::new();
            for line in reader.lines() {
                let line = line?;
                for part in line.split_whitespace() {
                    let byte = match format {
                        Format::Decimal => part.parse::<u8>().map_err(|_| IoError::new(std::io::ErrorKind::InvalidData, format!("Invalid decimal byte: {}", part)))?,
                        Format::Hex => u8::from_str_radix(part, 16).map_err(|_| IoError::new(std::io::ErrorKind::InvalidData, format!("Invalid hex byte: {}", part)))?,
                    };
                    bytes.push(byte);
                }
            }
            write(&output, &bytes)?;
            println!("Decoded '{}' to '{}' in {:?}", input.display(), output.display(), format);
        }
    }

    Ok(())
}