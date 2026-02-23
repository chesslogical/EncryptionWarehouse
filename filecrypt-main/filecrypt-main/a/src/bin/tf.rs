// src/bin/tf.rs
// This app is designed for Linux only.
// The design choice of requiring the key.key file in the current working directory is intentional.
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use cipher::{BlockEncrypt, generic_array::GenericArray, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use dryoc::constants::CRYPTO_PWHASH_SALTBYTES as PWHASH_SALTBYTES;
use dryoc::pwhash::{Config, PwHash};
use dryoc::rng::copy_randombytes;
use dryoc::types::{Bytes, StackByteArray};
use libc;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use std::os::unix::{fs::PermissionsExt, prelude::*};
use std::path::{Path, PathBuf};
use threefish::Threefish1024;
use zeroize::Zeroize;
use rpassword::prompt_password;

// Configurable variables for Argon2id strength (change at compile time)
const ARGON2_OPSLIMIT: u64 = 4;
const ARGON2_MEMLIMIT: usize = 256 * 1024 * 1024; // 256 MiB in bytes
const MAGIC_PW: [u8; 4] = *b"FCPW"; // Magic bytes for password-encrypted files
const CHUNK_SIZE: usize = 1_048_576; // 1MB
const HARD_KEY_BYTES: [u8; KEYBYTES] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];
const DEFAULT_KEY_FILE: &str = "key.key";
const ABYTES: usize = 64; // HMAC-SHA512 tag size
const HEADERBYTES: usize = 16; // Tweak/IV size
const KEYBYTES: usize = 128;
const MAC_KEYBYTES: usize = 64;
const BLOCK_SIZE: usize = 128;

#[derive(Parser)]
#[command(name = "filecrypt")]
#[command(about = "Simple file encryption CLI using Threefish-1024")]
struct Cli {
    #[arg(long = "key", default_value = DEFAULT_KEY_FILE)]
    key_file: String,
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
    /// Generate a new key file (fails if it already exists)
    GenKey,
    /// Hard encrypt with compiled-in key (informal use only - insecure!)
    HardEnc {
        file: String,
    },
    /// Hard decrypt with compiled-in key (informal use only - insecure!)
    HardDec {
        file: String,
    },
    /// Password-based encrypt (prompts for password twice)
    PwEnc {
        file: String,
    },
    /// Password-based decrypt (prompts for password)
    PwDec {
        file: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::GenKey => gen_key(&cli.key_file),
        Command::Enc { file } => {
            let mut key = load_key_from_file(&cli.key_file)?;
            encrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
        Command::Dec { file } => {
            let mut key = load_key_from_file(&cli.key_file)?;
            decrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
        Command::HardEnc { file } => {
            let mut key = load_hard_key();
            encrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
        Command::HardDec { file } => {
            let mut key = load_hard_key();
            decrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
        Command::PwEnc { file } => pw_encrypt(file),
        Command::PwDec { file } => pw_decrypt(file),
    }
}

fn gen_key(key_file: &str) -> Result<()> {
    let mut key: StackByteArray<KEYBYTES> = StackByteArray::new();
    copy_randombytes(&mut key);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key_file)
        .context(format!("Failed to create {}", key_file))?;
    file.write_all(key.as_slice())?;
    key.zeroize();
    Ok(())
}

fn get_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!("{}.tmp", path.file_name().unwrap().to_str().unwrap()));
    temp
}

fn derive_pw_key(pw: &str, salt: &[u8]) -> Result<StackByteArray<KEYBYTES>> {
    let mut pw_bytes = pw.as_bytes().to_vec();
    let config = Config::sensitive()
        .with_opslimit(ARGON2_OPSLIMIT)
        .with_memlimit(ARGON2_MEMLIMIT)
        .with_hash_length(KEYBYTES);
    let pwhash: PwHash<Vec<u8>, Vec<u8>> = PwHash::hash_with_salt(&pw_bytes, salt.to_vec(), config)
        .map_err(|_| anyhow!("Key derivation failed"))?;
    let (hash, _, _) = pwhash.into_parts();
    if hash.len() != KEYBYTES {
        return Err(anyhow!("Derived key has incorrect length"));
    }
    let mut key: StackByteArray<KEYBYTES> = StackByteArray::new();
    key.copy_from_slice(&hash);
    pw_bytes.zeroize();
    Ok(key)
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
    let temp_path = get_temp_path(path);
    let parent = path.parent().unwrap_or(Path::new("."));
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
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(mac_key_arr.as_slice()).map_err(|_| anyhow!("MAC init failed"))?;
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
            let plain_len_bytes = (n as u32).to_le_bytes();
            output.write_all(&plain_len_bytes)?;
            output.write_all(&ct)?;
            mac.update(&plain_len_bytes);
            mac.update(&ct);
            block_counter += ((n + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        }
        // Append final frame
        let plain_len_bytes = (0u32).to_le_bytes();
        output.write_all(&plain_len_bytes)?;
        mac.update(&plain_len_bytes);
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

fn pw_encrypt(file: &str) -> Result<()> {
    let mut pw1: String = prompt_password("Enter password: ")?;
    let mut pw2: String = prompt_password("Confirm password: ")?;
    if pw1 != pw2 {
        pw1.zeroize();
        pw2.zeroize();
        return Err(anyhow!("Passwords don't match"));
    }
    let mut salt = vec![0u8; PWHASH_SALTBYTES];
    copy_randombytes(&mut salt);
    let mut key = derive_pw_key(&pw1, &salt)?;
    pw1.zeroize();
    pw2.zeroize();
    let path = Path::new(file);
    let temp_path = get_temp_path(path);
    let parent = path.parent().unwrap_or(Path::new("."));
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
        output.write_all(&MAGIC_PW)?;
        output.write_all(&salt)?;
        let mut iv: StackByteArray<{ HEADERBYTES }> = StackByteArray::new();
        copy_randombytes(&mut iv);
        output.write_all(iv.as_slice())?;
        let (mac_key, enc_key_arr) = derive_subkeys(key.as_slice());
        let mut mac_key_arr = StackByteArray::<MAC_KEYBYTES>::new();
        mac_key_arr.copy_from_slice(&mac_key);
        let mut enc_key = StackByteArray::<KEYBYTES>::new();
        enc_key.copy_from_slice(&enc_key_arr);
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(mac_key_arr.as_slice()).map_err(|_| anyhow!("MAC init failed"))?;
        mac.update(&MAGIC_PW);
        mac.update(&salt);
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
            let plain_len_bytes = (n as u32).to_le_bytes();
            output.write_all(&plain_len_bytes)?;
            output.write_all(&ct)?;
            mac.update(&plain_len_bytes);
            mac.update(&ct);
            block_counter += ((n + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        }
        // Append final frame
        let plain_len_bytes = (0u32).to_le_bytes();
        output.write_all(&plain_len_bytes)?;
        mac.update(&plain_len_bytes);
        let tag = mac.finalize().into_bytes();
        output.write_all(&tag)?;
        plain.zeroize();
        mac_key_arr.zeroize();
        enc_key.zeroize();
        output.flush()?;
        output.get_ref().sync_all()?;
        Ok(())
    })();
    key.zeroize();
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
    let parent = path.parent().unwrap_or(Path::new("."));
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
        let magic_read = input.read(&mut magic_buf)?;
        if magic_read == 4 && magic_buf == MAGIC_PW {
            return Err(anyhow!("This is a password-encrypted file; use pwdec instead."));
        }
        input.seek(SeekFrom::Start(0))?;
        let mut iv_buf = [0u8; HEADERBYTES];
        input.read_exact(&mut iv_buf).context("Failed to read IV")?;
        let (mac_key, enc_key_arr) = derive_subkeys(key.as_slice());
        let mut mac_key_arr = StackByteArray::<MAC_KEYBYTES>::new();
        mac_key_arr.copy_from_slice(&mac_key);
        let mut enc_key = StackByteArray::<KEYBYTES>::new();
        enc_key.copy_from_slice(&enc_key_arr);
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(mac_key_arr.as_slice()).map_err(|_| anyhow!("MAC init failed"))?;
        mac.update(&iv_buf);
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
            let ct_len = plain_len;
            let mut ct_chunk = vec![0u8; ct_len];
            input.read_exact(&mut ct_chunk).context("Failed to read ct")?;
            mac.update(&len_buf);
            mac.update(&ct_chunk);
            if plain_len == 0 {
                seen_final = true;
                break;
            }
        }
        if !seen_final {
            return Err(anyhow!("Missing final tag (incomplete or invalid encryption)"));
        }
        // Read tag
        let mut tag_buf = [0u8; ABYTES];
        input.read_exact(&mut tag_buf).context("Failed to read tag")?;
        mac.verify_slice(&tag_buf).map_err(|_| anyhow!("MAC verification failed - file tampered or wrong key"))?;
        // Check for trailing data
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
        loop {
            let mut len_buf = [0u8; 4];
            input.read_exact(&mut len_buf).context("Failed to read length")?;
            let plain_len = u32::from_le_bytes(len_buf) as usize;
            if plain_len == 0 {
                break;
            }
            let ct_len = plain_len;
            let mut ct_chunk = vec![0u8; ct_len];
            input.read_exact(&mut ct_chunk).context("Failed to read ct")?;
            let plain = ctr_process(enc_key.as_slice(), &iv_buf, &ct_chunk, block_counter)?;
            output.write_all(&plain)?;
            block_counter += ((plain_len + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
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

fn pw_decrypt(file: &str) -> Result<()> {
    let mut pw: String = prompt_password("Enter password: ")?;
    let path = Path::new(file);
    let temp_path = get_temp_path(path);
    let parent = path.parent().unwrap_or(Path::new("."));
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
        if magic_buf != MAGIC_PW {
            return Err(anyhow!("Not a password-encrypted file"));
        }
        let mut salt = vec![0u8; PWHASH_SALTBYTES];
        input.read_exact(&mut salt).context("Failed to read salt")?;
        let mut key = derive_pw_key(&pw, &salt)?;
        let mut iv_buf = [0u8; HEADERBYTES];
        input.read_exact(&mut iv_buf).context("Failed to read IV")?;
        let (mac_key, enc_key_arr) = derive_subkeys(key.as_slice());
        let mut mac_key_arr = StackByteArray::<MAC_KEYBYTES>::new();
        mac_key_arr.copy_from_slice(&mac_key);
        let mut enc_key = StackByteArray::<KEYBYTES>::new();
        enc_key.copy_from_slice(&enc_key_arr);
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(mac_key_arr.as_slice()).map_err(|_| anyhow!("MAC init failed"))?;
        mac.update(&MAGIC_PW);
        mac.update(&salt);
        mac.update(&iv_buf);
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
            let ct_len = plain_len;
            let mut ct_chunk = vec![0u8; ct_len];
            input.read_exact(&mut ct_chunk).context("Failed to read ct")?;
            mac.update(&len_buf);
            mac.update(&ct_chunk);
            if plain_len == 0 {
                seen_final = true;
                break;
            }
        }
        if !seen_final {
            return Err(anyhow!("Missing final tag (incomplete or invalid encryption)"));
        }
        // Read tag
        let mut tag_buf = [0u8; ABYTES];
        input.read_exact(&mut tag_buf).context("Failed to read tag")?;
        mac.verify_slice(&tag_buf).map_err(|_| anyhow!("MAC verification failed - file tampered or wrong key"))?;
        // Check for trailing data
        let mut buf = [0u8; 1];
        if input.read(&mut buf)? != 0 {
            return Err(anyhow!("Trailing data after tag"));
        }
        // Now decrypt
        input.seek(SeekFrom::Start((MAGIC_PW.len() + PWHASH_SALTBYTES + HEADERBYTES) as u64))?;
        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);
        let mut block_counter: u64 = 0;
        loop {
            let mut len_buf = [0u8; 4];
            input.read_exact(&mut len_buf).context("Failed to read length")?;
            let plain_len = u32::from_le_bytes(len_buf) as usize;
            if plain_len == 0 {
                break;
            }
            let ct_len = plain_len;
            let mut ct_chunk = vec![0u8; ct_len];
            input.read_exact(&mut ct_chunk).context("Failed to read ct")?;
            let plain = ctr_process(enc_key.as_slice(), &iv_buf, &ct_chunk, block_counter)?;
            output.write_all(&plain)?;
            block_counter += ((plain_len + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        }
        mac_key_arr.zeroize();
        enc_key.zeroize();
        output.flush()?;
        output.get_ref().sync_all()?;
        key.zeroize();
        Ok(())
    })();
    pw.zeroize();
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
    let mut output = vec![0u8; data.len()];
    let mut keystream = [0u8; BLOCK_SIZE];
    let mut offset = 0;
    while offset < data.len() {
        let mut tweak = [0u8; 16];
        tweak.copy_from_slice(iv);
        tweak[8..16].copy_from_slice(&block_counter.to_le_bytes());
        let cipher = Threefish1024::new_with_tweak(&enc_key_arr, &tweak);
        keystream.fill(0);
        let mut block = GenericArray::from_mut_slice(&mut keystream);
        cipher.encrypt_block(&mut block);
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
    if metadata.permissions().mode() != 0o100600 {
        return Err(anyhow!("Key file permissions must be 0600"));
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

fn load_hard_key() -> StackByteArray<KEYBYTES> {
    let mut hard_key: StackByteArray<KEYBYTES> = StackByteArray::new();
    hard_key.copy_from_slice(&HARD_KEY_BYTES);
    hard_key
}