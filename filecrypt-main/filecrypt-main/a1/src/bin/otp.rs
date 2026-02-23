// src/bin/otp.rs
// This app is designed for Linux only.
// The design choice of requiring the key.key file in the current working directory is intentional.
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libc;
use std::fs::{self, OpenOptions, metadata};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

// Configurable variables
const DEFAULT_KEY_FILE: &str = "key.key";
const CHUNK_SIZE: usize = 1_048_576; // 1MB

#[derive(Parser)]
#[command(name = "otp")]
#[command(about = "Simple file OTP XOR CLI (reversible, requires key.key >= file size)")]
struct Cli {
    /// File name
    file: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    otp(&cli.file)
}

fn get_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!("{}.tmp", path.file_name().unwrap().to_str().unwrap()));
    temp
}

fn otp(file: &str) -> Result<()> {
    let path = Path::new(file);
    
    // Prevent encrypting the key file itself
    if path.file_name().and_then(|s| s.to_str()) == Some(DEFAULT_KEY_FILE) {
        return Err(anyhow!("Cannot encrypt the key file itself: {}", DEFAULT_KEY_FILE));
    }
    
    let temp_path = get_temp_path(path);
    let parent = path.parent().and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) }).unwrap_or(Path::new("."));
    
    let result = (|| -> Result<()> {
        let file_len = metadata(path).context("Failed to get file metadata")?.len();
        let key_len = metadata(DEFAULT_KEY_FILE).context("Failed to get key metadata")?.len();
        if key_len < file_len {
            return Err(anyhow!("Key must be at least as long as the file (key: {} bytes, file: {} bytes)", key_len, file_len));
        }
        
        let input_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("Failed to open input file")?;
        let metadata = input_file.metadata().context("Failed to get file metadata")?;
        if !metadata.is_file() {
            return Err(anyhow!("Target must be a regular file"));
        }
        let mut input = BufReader::new(input_file);
        
        let key_input_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(DEFAULT_KEY_FILE)
            .context("Failed to open key file")?;
        let key_metadata = key_input_file.metadata().context("Failed to get key metadata")?;
        if !key_metadata.is_file() {
            return Err(anyhow!("Key must be a regular file"));
        }
        let mut key_input = BufReader::new(key_input_file);
        
        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);
        
        let mut file_chunk = vec![0u8; CHUNK_SIZE];
        let mut key_chunk = vec![0u8; CHUNK_SIZE];
        
        loop {
            let file_n = input.read(&mut file_chunk)?;
            if file_n == 0 {
                break;
            }
            let key_n = key_input.read(&mut key_chunk[..file_n])?;
            if key_n != file_n {
                return Err(anyhow!("Key read mismatch - key shorter than expected"));
            }
            for i in 0..file_n {
                file_chunk[i] ^= key_chunk[i];
            }
            output.write_all(&file_chunk[..file_n])?;
        }
        
        output.flush()?;
        output.get_ref().sync_all()?;
        
        Ok(())
    })();
    
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    
    fs::rename(temp_path, path).context("Failed to rename temp to original")?;
    
    let dir = OpenOptions::new()
        .read(true)
        .open(parent)
        .context("Failed to open parent directory")?;
    dir.sync_all().context("Failed to sync parent directory")?;
    
    Ok(())
}