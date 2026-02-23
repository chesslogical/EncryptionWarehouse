// src/bin/aes.rs
// This app is designed for Linux only.
// The design choice of requiring the aes.key file in the current working directory is intentional.
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, aead::AeadInPlace};
use aes_gcm_siv::Tag;
use dryoc::rng::copy_randombytes;
use dryoc::types::{Bytes, StackByteArray};
use libc;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;
const MAGIC: [u8; 4] = *b"FCRY"; // New universal magic
const VERSION: u8 = 1;
const ALGO_AES: u8 = 0;
const MODE_KEY: u8 = 0;
const TLV_ALGO: u8 = 0;
const TLV_MODE: u8 = 1;
const CHUNK_SIZE: usize = 1_048_576; // 1MB
const KEYBYTES: usize = 32;
const NONCEBYTES: usize = 12;
const ABYTES: usize = 16;
const COUNTER_BYTES: usize = 8; // For u64 counter
const DEFAULT_KEY_FILE: &str = "aes.key";
#[derive(Parser)]
#[command(name = "aes")]
#[command(about = "Simple file encryption CLI using AES-256-GCM-SIV")]
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
fn write_tlv(header: &mut Vec<u8>, typ: u8, value: &[u8]) {
    header.push(typ);
    header.extend_from_slice(&(value.len() as u16).to_be_bytes());
    header.extend_from_slice(value);
}
fn encrypt(file: &str, key: &StackByteArray<KEYBYTES>) -> Result<()> {
    let path = Path::new(file);
    if path.file_name().map_or(false, |name| name == "aes.key") {
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
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&MAGIC);
        prefix.push(VERSION);
        let mut header = Vec::new();
        write_tlv(&mut header, TLV_ALGO, &[ALGO_AES]);
        write_tlv(&mut header, TLV_MODE, &[MODE_KEY]);
        prefix.extend_from_slice(&(header.len() as u16).to_be_bytes());
        prefix.extend_from_slice(&header);
        let mut nonce_base = [0u8; NONCEBYTES];
        copy_randombytes(&mut nonce_base);
        prefix.extend_from_slice(&nonce_base);
        output.write_all(&prefix)?;
        let cipher = Aes256GcmSiv::new(aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&*key));
        let mut plain = vec![0u8; CHUNK_SIZE];
        let mut ad_vec: Vec<u8> = Vec::with_capacity(prefix.len() + COUNTER_BYTES + 1);
        let mut frame_index: u64 = 0;
        loop {
            let n = input.read(&mut plain)?;
            if n == 0 {
                break;
            }
            let mut buffer = plain[..n].to_vec();
            let tag_byte: u8 = 0; // MESSAGE
            let counter = frame_index.to_le_bytes();
            if frame_index == u64::MAX {
                return Err(anyhow!("File too large"));
            }
            ad_vec.clear();
            ad_vec.extend_from_slice(&prefix);
            ad_vec.extend_from_slice(&counter);
            ad_vec.push(tag_byte);
            let nonce_bytes = get_nonce(&nonce_base, &counter);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let tag = cipher.encrypt_in_place_detached(&nonce, &ad_vec, &mut buffer).map_err(|_| anyhow!("Encryption failed"))?;
            let ct = [buffer.as_slice(), tag.as_slice()].concat();
            buffer.zeroize();
            let plain_len_bytes = (n as u32).to_le_bytes();
            output.write_all(&plain_len_bytes)?;
            output.write_all(&ct)?;
            frame_index += 1;
        }
        plain.zeroize();
        // Append final frame
        let tag_byte: u8 = 1; // FINAL
        let counter = frame_index.to_le_bytes();
        ad_vec.clear();
        ad_vec.extend_from_slice(&prefix);
        ad_vec.extend_from_slice(&counter);
        ad_vec.push(tag_byte);
        let nonce_bytes = get_nonce(&nonce_base, &counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut buffer = vec![];
        let tag = cipher.encrypt_in_place_detached(&nonce, &ad_vec, &mut buffer).map_err(|_| anyhow!("Encryption failed on final tag"))?;
        let final_ct = [buffer.as_slice(), tag.as_slice()].concat();
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
fn get_nonce(nonce_base: &[u8; NONCEBYTES], counter: &[u8; COUNTER_BYTES]) -> [u8; NONCEBYTES] {
    let mut nonce_bytes = *nonce_base;
    nonce_bytes[(NONCEBYTES - COUNTER_BYTES)..].copy_from_slice(counter);
    nonce_bytes
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
        let mut magic_buf = [0u8; 4];
        input.read_exact(&mut magic_buf).context("Failed to read magic")?;
        let (prefix, nonce_base, cipher) = if magic_buf == MAGIC {
            let mut ver = [0u8; 1];
            input.read_exact(&mut ver).context("Failed to read version")?;
            if ver[0] != VERSION {
                return Err(anyhow!("Unsupported version"));
            }
            let mut hlen_b = [0u8; 2];
            input.read_exact(&mut hlen_b).context("Failed to read header length")?;
            let hlen = u16::from_be_bytes(hlen_b) as usize;
            let mut header = vec![0u8; hlen];
            input.read_exact(&mut header).context("Failed to read header")?;
            let (algo, mode) = parse_header_key(&header)?;
            if algo != ALGO_AES {
                return Err(anyhow!("Unsupported algorithm"));
            }
            if mode != MODE_KEY {
                return Err(anyhow!("This is not a key-encrypted file."));
            }
            let mut nonce_base = [0u8; NONCEBYTES];
            input.read_exact(&mut nonce_base).context("Failed to read nonce base")?;
            let mut prefix = Vec::new();
            prefix.extend_from_slice(&magic_buf);
            prefix.extend_from_slice(&ver);
            prefix.extend_from_slice(&hlen_b);
            prefix.extend_from_slice(&header);
            prefix.extend_from_slice(&nonce_base);
            let cipher = Aes256GcmSiv::new(aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&*key));
            (prefix, nonce_base, cipher)
        } else {
            input.seek(SeekFrom::Start(0))?;
            let mut nonce_base = [0u8; NONCEBYTES];
            input.read_exact(&mut nonce_base).context("Failed to read nonce base")?;
            let cipher = Aes256GcmSiv::new(aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&*key));
            (vec![], nonce_base, cipher)
        };
        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);
        let mut ct = vec![0u8; CHUNK_SIZE + ABYTES];
        let mut ad_vec: Vec<u8> = Vec::with_capacity(prefix.len() + COUNTER_BYTES + 1);
        let mut seen_final = false;
        let mut frame_index: u64 = 0;
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
            input.read_exact(&mut ct[..ct_len]).context("Failed to read ciphertext frame")?;
            let tag_byte = if plain_len == 0 { 1 } else { 0 };
            let counter = frame_index.to_le_bytes();
            if frame_index == u64::MAX {
                return Err(anyhow!("File too large"));
            }
            ad_vec.clear();
            ad_vec.extend_from_slice(&prefix);
            ad_vec.extend_from_slice(&counter);
            ad_vec.push(tag_byte);
            let nonce_bytes = get_nonce(&nonce_base, &counter);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let (mut buffer, tag_slice) = ct[..ct_len].split_at_mut(plain_len);
            let tag = Tag::from_slice(tag_slice);
            cipher.decrypt_in_place_detached(&nonce, &ad_vec, &mut buffer, &tag)
                .map_err(|_| anyhow!("Decryption failed (invalid MAC or data)"))?;
            if buffer.len() != plain_len {
                return Err(anyhow!("Length mismatch after decryption"));
            }
            output.write_all(&buffer)?;
            buffer.zeroize();
            if tag_byte == 1 {
                seen_final = true;
                break;
            }
            frame_index += 1;
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
fn parse_header_key(header: &[u8]) -> Result<(u8, u8)> {
    let mut slice = header;
    let mut seen_algo = false;
    let mut seen_mode = false;
    let mut algo = None;
    let mut mode = None;
    while !slice.is_empty() {
        if slice.len() < 3 {
            return Err(anyhow!("Invalid TLV in header"));
        }
        let typ = slice[0];
        let len = u16::from_be_bytes([slice[1], slice[2]]) as usize;
        slice = &slice[3..];
        if slice.len() < len {
            return Err(anyhow!("Invalid TLV length in header"));
        }
        let val = &slice[0..len];
        slice = &slice[len..];
        match typ {
            TLV_ALGO => {
                if seen_algo { return Err(anyhow!("Duplicate algo TLV")); }
                seen_algo = true;
                if len == 1 { algo = Some(val[0]) } else { return Err(anyhow!("Invalid algo length")); }
            },
            TLV_MODE => {
                if seen_mode { return Err(anyhow!("Duplicate mode TLV")); }
                seen_mode = true;
                if len == 1 { mode = Some(val[0]) } else { return Err(anyhow!("Invalid mode length")); }
            },
            _ => (), // ignore
        }
    }
    let algo = algo.ok_or(anyhow!("Missing algo in header"))?;
    let mode = mode.ok_or(anyhow!("Missing mode in header"))?;
    Ok((algo, mode))
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