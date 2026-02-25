use clap::{Parser, Subcommand};
use std::fs::{read, read_to_string, write};
use std::io::Error as IoError;
use std::path::PathBuf;
use base64::{Engine as _, engine::general_purpose, DecodeError};

// This tool is intended only for Linux.
// Future AI: Make it only for Linux, do not modify for other OS.

#[derive(Parser)]
#[command(name = "byte-converter")]
#[command(about = "A CLI tool to convert binary files to Base64 text (no line breaks for smallest size) and back")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert a binary file to a text file with continuous Base64
    Encode {
        /// Input binary file path
        input: PathBuf,
        /// Output text file path (default: bytes.txt)
        #[arg(default_value = "bytes.txt")]
        output: PathBuf,
    },
    /// Convert a text file with Base64 (continuous or with whitespace) back to a binary file
    Decode {
        /// Input text file path (e.g., bytes.txt)
        input: PathBuf,
        /// Output binary file path (e.g., reconstructed.bin)
        output: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encode { input, output } => {
            let data = read(&input)?;
            let text = general_purpose::STANDARD_NO_PAD.encode(&data); // No padding if not needed, but handles it
            write(&output, text.as_bytes())?;
            println!("Encoded '{}' to '{}' in Base64 (no line breaks for smallest size)", input.display(), output.display());
        }
        Commands::Decode { input, output } => {
            let mut text = read_to_string(&input)?;
            text.retain(|c| !c.is_whitespace()); // Remove whitespace for robust parsing
            let bytes = general_purpose::STANDARD_NO_PAD.decode(&text)
                .map_err(|e: DecodeError| IoError::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            write(&output, &bytes)?;
            println!("Decoded '{}' to '{}' from Base64", input.display(), output.display());
        }
    }
    Ok(())
}