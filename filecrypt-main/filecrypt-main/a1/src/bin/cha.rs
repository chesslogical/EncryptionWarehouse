// src/bin/cha.rs
// This app is designed for Linux only.
// The design choice of requiring the cha.key file in the current working directory is intentional.
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use dryoc::dryocstream::{DryocStream, Header, Pull, Push, Tag};
use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES as ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES as HEADERBYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES as KEYBYTES,
};
use dryoc::types::{Bytes, StackByteArray};
use libc;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;
const CHUNK_SIZE: usize = 1_048_576; // 1MB
const DEFAULT_KEY_FILE: &str = "cha.key";
#[derive(Parser)]
#[command(name = "cha")]
#[command(about = "Simple file encryption CLI using XChaCha20-Poly1305")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Encrypt the file in place
    Enc {
        file: String,
    },
    /// Decrypt the file in place
    Dec {
        file: String,
    },
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Enc { file } => {
            let mut key = load_key_from_file(DEFAULT_KEY_FILE)?;
            encrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
        Command::Dec { file } => {
            let mut key = load_key_from_file(DEFAULT_KEY_FILE)?;
            decrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
    }
}
fn get_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!("{}.tmp", path.file_name().unwrap().to_str().unwrap()));
    temp
}
fn encrypt(file: &str, key: &StackByteArray<KEYBYTES>) -> Result<()> {
    let path = Path::new(file);
    if path.file_name().map_or(false, |name| name == "cha.key") {
        return Err(anyhow!("Cannot encrypt the key file"));
    }
    let temp_path = get_temp_path(path);
    let parent = if let Some(p) = path.parent() {
        if p.as_os_str().is_empty() {
            Path::new(".")
        } else {
            p
        }
    } else {
        Path::new(".")
    };
    let result = (|| -> Result<()> {
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
        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);
        let (mut push_stream, header): (DryocStream<Push>, Header) = DryocStream::init_push(key);
        output.write_all(header.as_slice())?;
        let mut plain = vec![0u8; CHUNK_SIZE];
        loop {
            let n = input.read(&mut plain)?;
            if n == 0 {
                break;
            }
            let mut plain_chunk = plain[..n].to_vec();
            let ct = push_stream.push_to_vec(&plain_chunk, None, Tag::MESSAGE).map_err(|_| anyhow!("Encryption failed"))?;
            plain_chunk.zeroize();
            let plain_len_bytes = (n as u32).to_le_bytes();
            output.write_all(&plain_len_bytes)?;
            output.write_all(&ct)?;
        }
        plain.zeroize();
        // Append final frame
        let final_ct = push_stream.push_to_vec(&[], None, Tag::FINAL).map_err(|_| anyhow!("Encryption failed on final tag"))?;
        let plain_len_bytes = (0u32).to_le_bytes();
        output.write_all(&plain_len_bytes)?;
        output.write_all(&final_ct)?;
        output.flush()?;
        output.get_ref().sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    fs::rename(&temp_path, path).context("Failed to rename temp to original")?;
    let dir = OpenOptions::new()
        .read(true)
        .open(parent)
        .context("Failed to open parent directory")?;
    dir.sync_all().context("Failed to sync parent directory")?;
    Ok(())
}
fn decrypt(file: &str, key: &StackByteArray<KEYBYTES>) -> Result<()> {
    let path = Path::new(file);
    let temp_path = get_temp_path(path);
    let parent = if let Some(p) = path.parent() {
        if p.as_os_str().is_empty() {
            Path::new(".")
        } else {
            p
        }
    } else {
        Path::new(".")
    };
    let result = (|| -> Result<()> {
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
        let mut header_buf = [0u8; HEADERBYTES];
        input.read_exact(&mut header_buf).context("Failed to read header")?;
        let mut header: Header = Header::new();
        header.copy_from_slice(&header_buf);
        let mut pull_stream: DryocStream<Pull> = DryocStream::init_pull(key, &header);
        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);
        let mut ct = vec![0u8; CHUNK_SIZE + ABYTES];
        let mut seen_final = false;
        loop {
            let mut len_buf = [0u8; 4];
            let len_read = input.read(&mut len_buf)?;
            if len_read == 0 {
                break;
            }
            if len_read != 4 {
                return Err(anyhow!("Incomplete length prefix"));
            }
            let plain_len = u32::from_le_bytes(len_buf) as usize;
            if plain_len > CHUNK_SIZE {
                return Err(anyhow!("Frame too large"));
            }
            let ct_len = plain_len + ABYTES;
            if ct_len > ct.len() {
                ct.resize(ct_len, 0);
            }
            input.read_exact(&mut ct[..ct_len]).context("Failed to read ciphertext frame")?;
            let mut ct_chunk = ct[..ct_len].to_vec();
            let (mut plain, tag) = pull_stream.pull_to_vec(&ct_chunk, None).map_err(|_| anyhow!("Decryption failed (invalid MAC or data)"))?;
            ct_chunk.zeroize();
            if plain.len() != plain_len {
                return Err(anyhow!("Length mismatch after decryption"));
            }
            output.write_all(&plain)?;
            plain.zeroize();
            if tag == Tag::FINAL {
                seen_final = true;
                break;
            }
        }
        ct.zeroize();
        if !seen_final {
            return Err(anyhow!("Missing final tag (incomplete or invalid encryption)"));
        }
        // Check for trailing data
        let mut buf = [0u8; 1];
        if input.read(&mut buf)? != 0 {
            return Err(anyhow!("Trailing data after final tag"));
        }
        output.flush()?;
        output.get_ref().sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    fs::rename(&temp_path, path).context("Failed to rename temp to original")?;
    let dir = OpenOptions::new()
        .read(true)
        .open(parent)
        .context("Failed to open parent directory")?;
    dir.sync_all().context("Failed to sync parent directory")?;
    Ok(())
}
fn load_key_from_file(key_file: &str) -> Result<StackByteArray<KEYBYTES>> {
    let path = Path::new(key_file);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context(format!("Failed to open {}", key_file))?;
    let metadata = file.metadata().context("Failed to get key file metadata")?;
    if !metadata.is_file() {
        return Err(anyhow!("Key file must be a regular file"));
    }
    let mut key_bytes = vec![0u8; KEYBYTES];
    let mut reader = BufReader::new(file);
    reader.read_exact(&mut key_bytes).context(format!("Failed to read {}", key_file))?;
    if reader.read(&mut [0u8; 1])? != 0 {
        return Err(anyhow!("Key file must be exactly {} bytes", KEYBYTES));
    }
    let mut key: StackByteArray<KEYBYTES> = StackByteArray::new();
    key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}