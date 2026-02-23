// This app is designed for Linux only.
// The design choice of requiring the key.key file in the current working directory is intentional.
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libc;
use std::fs::{self, metadata, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use argon2::{Argon2, Params};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rpassword::read_password;
use zeroize::Zeroize;

// Configurable variables (from otp)
const DEFAULT_KEY_FILE: &str = "key.key";
const OTP_CHUNK_SIZE: usize = 1_048_576; // 1MB

// Configuration section (from otpkg, compile-time constants)
const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024;
const GEN_CHUNK_SIZE: usize = 1024 * 1024; // 1MB
const ARGON2_MEMORY_KIB: u32 = 262_144; // 256MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const SALT: &[u8] = b"detkey-v1-domain";
const PEPPER: &[u8] = b"";

#[derive(Parser)]
#[command(about = "Simple file OTP XOR CLI (reversible encrypt/decrypt, requires key.key >= file size).\nTo generate key: otp --gen --length <BYTES>")]
struct Cli {
    /// Generate key instead of processing file
    #[arg(long, conflicts_with = "file")]
    gen: bool,

    /// Number of bytes to generate (1 to 21474836480). Required if --gen.
    #[arg(long, required_if_eq("gen", "true"))]
    length: Option<u64>,

    /// File name to encrypt/decrypt (required if not --gen)
    #[arg(required_if_eq("gen", "false"))]
    file: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.gen {
        let length = cli.length.ok_or(anyhow!("--length is required when using --gen"))?;
        generate_key(length)
    } else {
        let file = cli.file.ok_or(anyhow!("File name is required when not using --gen"))?;
        otp(&file)
    }
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

        let mut file_chunk = vec![0u8; OTP_CHUNK_SIZE];
        let mut key_chunk = vec![0u8; OTP_CHUNK_SIZE];

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

fn generate_key(length: u64) -> Result<()> {
    if length == 0 || length > MAX_SIZE {
        return Err(anyhow!("Length must be between 1 and {} bytes", MAX_SIZE));
    }
    let path = Path::new(DEFAULT_KEY_FILE);
    if path.exists() {
        return Err(anyhow!("key.key already exists. Refusing to overwrite."));
    }

    println!("Enter password:");
    let mut password1 = read_password().context("Failed to read password")?.into_bytes();
    println!("Confirm password:");
    let mut password2 = read_password().context("Failed to read password")?.into_bytes();
    if password1 != password2 {
        password1.zeroize();
        password2.zeroize();
        return Err(anyhow!("Passwords do not match"));
    }
    password2.zeroize();

    let mut combined = Vec::with_capacity(password1.len() + PEPPER.len());
    combined.extend_from_slice(&password1);
    combined.extend_from_slice(PEPPER);
    password1.zeroize();

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    let mut master_key = [0u8; 32];
    argon2
        .hash_password_into(&combined, SALT, &mut master_key)
        .map_err(|e| anyhow!(e.to_string()))?;
    combined.zeroize();

    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(&master_key.into(), &nonce.into());
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Failed to create key file")?;
    let mut writer = BufWriter::new(file);
    let mut buffer = vec![0u8; GEN_CHUNK_SIZE];
    let mut remaining = length;
    while remaining > 0 {
        let chunk = remaining.min(GEN_CHUNK_SIZE as u64) as usize;
        buffer[..chunk].fill(0);
        cipher.apply_keystream(&mut buffer[..chunk]);
        writer.write_all(&buffer[..chunk]).context("Failed to write to key file")?;
        remaining -= chunk as u64;
    }
    writer.flush().context("Failed to flush key file")?;
    master_key.zeroize();
    println!("Generated {} bytes → key.key", length);
    Ok(())
}