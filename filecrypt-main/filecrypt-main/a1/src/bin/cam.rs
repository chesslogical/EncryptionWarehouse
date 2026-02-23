// src/bin/cam.rs
// This app is designed for Linux only.
// The design choice of requiring the cam.key file in the current working directory is intentional.
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use camellia::cipher::{BlockEncrypt, generic_array::GenericArray, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use dryoc::rng::copy_randombytes;
use dryoc::types::{Bytes, StackByteArray};
use libc;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use camellia::Camellia256;
use zeroize::Zeroize;
const CHUNK_SIZE: usize = 1_048_576; // 1MB
const DEFAULT_KEY_FILE: &str = "cam.key";
const ABYTES: usize = 64; // HMAC-SHA512 tag size
const HEADERBYTES: usize = 16; // IV size
const KEYBYTES: usize = 32; // Camellia-256 key is 256 bits = 32 bytes
const MAC_KEYBYTES: usize = 64;
const BLOCK_SIZE: usize = 16; // Camellia block size is 128 bits = 16 bytes
#[derive(Parser)]
#[command(name = "cam")]
#[command(about = "Simple file encryption CLI using Camellia-256")]
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
fn derive_subkeys(master_key: &[u8]) -> ([u8; MAC_KEYBYTES], [u8; KEYBYTES]) {
    let hk = Hkdf::<Sha512>::new(None, master_key);
    let mut mac_key = [0u8; MAC_KEYBYTES];
    let mut enc_key = [0u8; KEYBYTES];
    hk.expand(b"mac_key", &mut mac_key).unwrap();
    hk.expand(b"enc_key", &mut enc_key).unwrap();
    (mac_key, enc_key)
}
fn encrypt(file: &str, key: &StackByteArray<KEYBYTES>) -> Result<()> {
    let path = Path::new(file);
    if path.file_name().map_or(false, |name| name == "cam.key") {
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
        let mut iv: StackByteArray<{ HEADERBYTES }> = StackByteArray::new();
        copy_randombytes(&mut iv);
        output.write_all(iv.as_slice())?;
        let (mac_key, enc_key_arr) = derive_subkeys(key.as_slice());
        let mut mac_key_arr = StackByteArray::<MAC_KEYBYTES>::new();
        mac_key_arr.copy_from_slice(&mac_key);
        let mut enc_key = StackByteArray::<KEYBYTES>::new();
        enc_key.copy_from_slice(&enc_key_arr);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(mac_key_arr.as_slice()).map_err(|_| anyhow!("MAC init failed"))?;
        mac.update(iv.as_slice());
        let mut plain = vec![0u8; CHUNK_SIZE];
        let mut block_counter: u64 = 0;
        loop {
            let n = input.read(&mut plain)?;
            if n == 0 {
                break;
            }
            let plain_chunk = &plain[..n];
            let ct = ctr_process(enc_key.as_slice(), iv.as_slice(), plain_chunk, block_counter)?;
            output.write_all(&ct)?;
            mac.update(&ct);
            block_counter += ((n + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        }
        let tag = mac.finalize().into_bytes();
        output.write_all(&tag)?;
        plain.zeroize();
        mac_key_arr.zeroize();
        enc_key.zeroize();
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
        let file_len = metadata.len() as usize;
        if file_len < HEADERBYTES + ABYTES {
            return Err(anyhow!("File too short for encrypted data"));
        }
        let ct_len = file_len - HEADERBYTES - ABYTES;
        let mut input = BufReader::new(input_file);
        let mut iv_buf = [0u8; HEADERBYTES];
        input.read_exact(&mut iv_buf).context("Failed to read IV")?;
        let (mac_key, enc_key_arr) = derive_subkeys(key.as_slice());
        let mut mac_key_arr = StackByteArray::<MAC_KEYBYTES>::new();
        mac_key_arr.copy_from_slice(&mac_key);
        let mut enc_key = StackByteArray::<KEYBYTES>::new();
        enc_key.copy_from_slice(&enc_key_arr);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(mac_key_arr.as_slice()).map_err(|_| anyhow!("MAC init failed"))?;
        mac.update(&iv_buf);
        let mut ct = vec![0u8; CHUNK_SIZE];
        let mut remaining_ct = ct_len;
        while remaining_ct > 0 {
            let to_read = std::cmp::min(CHUNK_SIZE, remaining_ct);
            input.read_exact(&mut ct[..to_read]).context("Failed to read ct for MAC")?;
            mac.update(&ct[..to_read]);
            remaining_ct -= to_read;
        }
        let mut tag_buf = [0u8; ABYTES];
        input.read_exact(&mut tag_buf).context("Failed to read tag")?;
        mac.verify_slice(&tag_buf).map_err(|_| anyhow!("MAC verification failed - file tampered or wrong key"))?;
        // Check for trailing data (should be at EOF)
        let mut buf = [0u8; 1];
        if input.read(&mut buf)? != 0 {
            return Err(anyhow!("Trailing data after tag"));
        }
        // Now decrypt
        input.seek(SeekFrom::Start(HEADERBYTES as u64))?;
        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);
        let mut block_counter: u64 = 0;
        let mut ct = vec![0u8; CHUNK_SIZE];
        let mut remaining_ct = ct_len;
        while remaining_ct > 0 {
            let to_read = std::cmp::min(CHUNK_SIZE, remaining_ct);
            input.read_exact(&mut ct[..to_read]).context("Failed to read ct for decryption")?;
            let plain = ctr_process(enc_key.as_slice(), &iv_buf, &ct[..to_read], block_counter)?;
            output.write_all(&plain)?;
            block_counter += ((to_read + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
            remaining_ct -= to_read;
        }
        mac_key_arr.zeroize();
        enc_key.zeroize();
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
fn ctr_process(enc_key: &[u8], iv: &[u8], data: &[u8], mut block_counter: u64) -> Result<Vec<u8>> {
    let mut enc_key_arr = [0u8; KEYBYTES];
    enc_key_arr.copy_from_slice(enc_key);
    let cipher = Camellia256::new_from_slice(&enc_key_arr).map_err(|_| anyhow!("Cipher init failed"))?;
    let mut output = vec![0u8; data.len()];
    let mut keystream = [0u8; BLOCK_SIZE];
    let mut offset = 0;
    while offset < data.len() {
        let mut ctr_block = [0u8; BLOCK_SIZE];
        ctr_block.copy_from_slice(iv);
        let counter_bytes = block_counter.to_le_bytes();
        for i in 0..8 {
            ctr_block[i] ^= counter_bytes[i];
        }
        let mut block = GenericArray::from_mut_slice(&mut ctr_block);
        cipher.encrypt_block(&mut block);
        keystream.copy_from_slice(&ctr_block);
        let remaining = data.len() - offset;
        let to_copy = std::cmp::min(BLOCK_SIZE, remaining);
        for i in 0..to_copy {
            output[offset + i] = data[offset + i] ^ keystream[i];
        }
        offset += to_copy;
        block_counter += 1;
    }
    Ok(output)
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