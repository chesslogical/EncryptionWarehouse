// src/aes.rs
// This app is designed for Linux only.

use anyhow::{anyhow, Context, Result};
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, aead::AeadInPlace};
use aes_gcm_siv::Tag;
use dryoc::rng::{copy_randombytes, randombytes_buf};
use libc;
use rpassword::prompt_password;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

use crate::{atomic_rename, get_temp_path, CHUNK_SIZE};

const MAGIC: [u8; 4] = *b"FCRY";
const VERSION: u8 = 1;
const ALGO_AES: u8 = 0;
const MODE_KEY: u8 = 0;
const MODE_PASS: u8 = 1;
const TLV_ALGO: u8 = 0;
const TLV_MODE: u8 = 1;
const TLV_SALT: u8 = 2;
const NONCEBYTES: usize = 12;
const ABYTES: usize = 16;
const COUNTER_BYTES: usize = 8;
const SALT_BYTES: usize = 16;

pub fn encrypt(file: &str, password_mode: bool, key_file_opt: Option<String>) -> Result<()> {
    let path = Path::new(file);
    if let Some(name) = path.file_name() {
        if name == "aes.key" {
            return Err(anyhow!("Cannot encrypt the key file"));
        }
    }
    let temp_path = get_temp_path(path);
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
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
        let (key, salt_opt) = get_enc_key(password_mode, key_file_opt.as_deref(), "aes")?;
        if let Some(salt) = &salt_opt {
            write_tlv(&mut header, TLV_SALT, salt);
            write_tlv(&mut header, TLV_MODE, &[MODE_PASS]);
        } else {
            write_tlv(&mut header, TLV_MODE, &[MODE_KEY]);
        }
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
    atomic_rename(&temp_path, path, parent)?;
    Ok(())
}

pub fn decrypt(file: &str, password_mode: bool, key_file_opt: Option<String>) -> Result<()> {
    let path = Path::new(file);
    let temp_path = get_temp_path(path);
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
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
        if magic_buf != MAGIC {
            return Err(anyhow!("Invalid magic - not an encrypted file or wrong algo"));
        }
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
        let (algo_val, mode, salt_opt) = parse_header(&header)?;
        if algo_val != ALGO_AES {
            return Err(anyhow!("Unsupported algorithm"));
        }
        let mut nonce_base = [0u8; NONCEBYTES];
        input.read_exact(&mut nonce_base).context("Failed to read nonce base")?;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&magic_buf);
        prefix.extend_from_slice(&ver);
        prefix.extend_from_slice(&hlen_b);
        prefix.extend_from_slice(&header);
        prefix.extend_from_slice(&nonce_base);
        let key = get_dec_key(password_mode, key_file_opt.as_deref(), "aes", mode, salt_opt)?;
        let cipher = Aes256GcmSiv::new(aes_gcm_siv::Key::<Aes256GcmSiv>::from_slice(&*key));
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
                .map_err(|_| anyhow!("Decryption failed (invalid MAC or data) - possible corruption or wrong key"))?;
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
        let mut buf = [0u8; 1];
        if input.read(&mut buf)? != 0 {
            return Err(anyhow!("Trailing data after final tag - possible corruption"));
        }
        output.flush()?;
        output.get_ref().sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    atomic_rename(&temp_path, path, parent)?;
    Ok(())
}

fn get_enc_key(password_mode: bool, key_file: Option<&str>, algo: &str) -> Result<(Zeroizing<[u8; 32]>, Option<Vec<u8>>)> {
    if password_mode {
        let mut pass1 = prompt_password("Enter passphrase: ")?;
        let mut pass2 = prompt_password("Confirm passphrase: ")?;
        if pass1 != pass2 {
            return Err(anyhow!("Passphrases do not match"));
        }
        let salt = randombytes_buf(16);
        let key = derive_key(&pass1, &salt)?;
        pass1.zeroize();
        pass2.zeroize();
        Ok((key, Some(salt)))
    } else {
        let default = format!("{}.key", algo);
        let key_path = key_file.unwrap_or(&default);
        let key = load_key_from_file(key_path)?;
        Ok((key, None))
    }
}

fn get_dec_key(password_mode: bool, key_file: Option<&str>, algo: &str, mode: u8, salt_opt: Option<Vec<u8>>) -> Result<Zeroizing<[u8; 32]>> {
    if password_mode {
        if mode != MODE_PASS {
            return Err(anyhow!("File is encrypted with key mode; do not use --p"));
        }
        let salt = salt_opt.ok_or(anyhow!("Missing salt for password mode"))?;
        let mut pass = prompt_password("Enter passphrase: ")?;
        let key = derive_key(&pass, &salt)?;
        pass.zeroize();
        Ok(key)
    } else {
        if mode != MODE_KEY {
            return Err(anyhow!("File is encrypted with password mode; use --p"));
        }
        let default = format!("{}.key", algo);
        let key_path = key_file.unwrap_or(&default);
        load_key_from_file(key_path)
    }
}

fn derive_key(pass: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).unwrap(),
    )
    .hash_password_into(pass.as_bytes(), salt, &mut key)
    .map_err(|_| anyhow!("Key derivation failed"))?;
    Ok(Zeroizing::new(key))
}

fn load_key_from_file(key_file: &str) -> Result<Zeroizing<[u8; 32]>> {
    let path = Path::new(key_file);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context(format!("Failed to open {}", key_file))?;
    let metadata = file.metadata().context("Failed to get key file metadata")?;
    if !metadata.is_file() {
        return Err(anyhow!("Key file must be a regular file"));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(anyhow!("Key file permissions must be owner-only (0600)"));
    }
    let mut key_bytes = vec![0u8; 32];
    file.read_exact(&mut key_bytes).context(format!("Failed to read {}", key_file))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(Zeroizing::new(key))
}

fn get_nonce(nonce_base: &[u8; NONCEBYTES], counter: &[u8; COUNTER_BYTES]) -> [u8; NONCEBYTES] {
    let mut nonce_bytes = *nonce_base;
    nonce_bytes[(NONCEBYTES - COUNTER_BYTES)..].copy_from_slice(counter);
    nonce_bytes
}

fn parse_header(header: &[u8]) -> Result<(u8, u8, Option<Vec<u8>>)> {
    let mut slice = header;
    let mut algo = None;
    let mut mode = None;
    let mut salt = None;
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
                if len == 1 { algo = Some(val[0]) } else { return Err(anyhow!("Invalid algo length")); }
            }
            TLV_MODE => {
                if len == 1 { mode = Some(val[0]) } else { return Err(anyhow!("Invalid mode length")); }
            }
            TLV_SALT => {
                if len == SALT_BYTES { salt = Some(val.to_vec()) } else { return Err(anyhow!("Invalid salt length")); }
            }
            _ => (), // ignore unknown
        }
    }
    let algo = algo.ok_or(anyhow!("Missing algo in header"))?;
    let mode = mode.ok_or(anyhow!("Missing mode in header"))?;
    Ok((algo, mode, salt))
}

fn write_tlv(header: &mut Vec<u8>, typ: u8, value: &[u8]) {
    header.push(typ);
    header.extend_from_slice(&(value.len() as u16).to_be_bytes());
    header.extend_from_slice(value);
}