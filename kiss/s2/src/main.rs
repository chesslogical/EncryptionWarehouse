// This application is designed exclusively for Linux environments.
// It processes files entirely in memory without chunking or streaming, 
// prioritizing simplicity while ensuring high reliability and data integrity 
// through authenticated encryption, integrity hashes, and atomic file operations.

use aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::Nonce;
use anyhow::{Context, Result};
use argon2::Argon2;
use rand::RngCore;
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, FileTimes};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::time::SystemTime;
use tempfile::NamedTempFile;
use zeroize::Zeroize;

const MAGIC_HEADER: &[u8] = b"ENC_SIV_"; // 8 bytes
const VERSION: u8 = 1; // 1 byte
const SALT_SIZE: usize = 16;
const HEADER_SIZE: usize = MAGIC_HEADER.len() + 1 + SALT_SIZE;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const HASH_SIZE: usize = 32;
const KEY_SIZE: usize = 32;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    if filename.contains('/') || filename == "." || filename == ".." {
        anyhow::bail!("Filename must be a simple name in the current directory (no paths or special dirs).");
    }

    let current_dir = env::current_dir().context("Failed to get current directory")?;
    let file_path = current_dir.join(filename);

    if !file_path.exists() {
        anyhow::bail!("File '{}' not found in current directory.", filename);
    }
    if file_path.is_dir() {
        anyhow::bail!("'{}' is a directory, not a file.", filename);
    }

    // Get original metadata before any changes
    let metadata = file_path.metadata().context("Failed to get file metadata")?;

    // Prompt for password
    let mut password = prompt_password("Enter password: ")?;

    // Read file data
    let data = fs::read(&file_path).context("Failed to read file")?;

    // Check if encrypted
    let is_encrypted = data.len() >= HEADER_SIZE && &data[0..MAGIC_HEADER.len()] == MAGIC_HEADER && data[MAGIC_HEADER.len()] == VERSION;

    let result = if is_encrypted {
        // Decrypt
        if data.len() < HEADER_SIZE + NONCE_SIZE + TAG_SIZE + HASH_SIZE {
            anyhow::bail!("Encrypted file too short.");
        }
        let salt_start = MAGIC_HEADER.len() + 1;
        let salt = &data[salt_start..salt_start + SALT_SIZE];
        let nonce_start = salt_start + SALT_SIZE;
        let nonce_slice = &data[nonce_start..nonce_start + NONCE_SIZE];
        let nonce = Nonce::from_slice(nonce_slice);
        let ciphertext_with_tag = &data[nonce_start + NONCE_SIZE..];

        // Derive key
        let argon2 = Argon2::default();
        let mut key_bytes = vec![0u8; KEY_SIZE];
        argon2.hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        password.zeroize();
        let cipher = Aes256GcmSiv::new_from_slice(&key_bytes).map_err(|_| anyhow::anyhow!("Invalid key length"))?;

        let payload = Payload {
            msg: ciphertext_with_tag,
            aad: &[],
        };
        let mut decrypted = cipher
            .decrypt(nonce, payload)
            .map_err(|_| anyhow::anyhow!("Decryption failed: invalid password or corrupted data."))?;

        // Extract and verify hash
        if decrypted.len() < HASH_SIZE {
            anyhow::bail!("Decrypted data too short for integrity check.");
        }
        let hash_end = decrypted.len() - HASH_SIZE;
        let computed_hash = Sha256::digest(&decrypted[0..hash_end]);
        let stored_hash = &decrypted[hash_end..];
        if computed_hash.as_slice() != stored_hash {
            anyhow::bail!("Integrity check failed: data may be corrupted.");
        }
        decrypted.truncate(hash_end); // Remove hash
        decrypted
    } else {
        // Encrypt
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Derive key
        let argon2 = Argon2::default();
        let mut key_bytes = vec![0u8; KEY_SIZE];
        argon2.hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        password.zeroize();
        let cipher = Aes256GcmSiv::new_from_slice(&key_bytes).map_err(|_| anyhow::anyhow!("Invalid key length"))?;

        // Compute hash of data
        let hash = Sha256::digest(&data);

        // Append hash to data
        let mut plaintext = data.clone();
        plaintext.extend_from_slice(&hash);

        let payload = Payload {
            msg: &plaintext,
            aad: &[],
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| anyhow::anyhow!("Encryption failed."))?;

        let mut encrypted_data = Vec::with_capacity(HEADER_SIZE + NONCE_SIZE + ciphertext.len());
        encrypted_data.extend_from_slice(MAGIC_HEADER);
        encrypted_data.push(VERSION);
        encrypted_data.extend_from_slice(&salt);
        encrypted_data.extend_from_slice(&nonce_bytes);
        encrypted_data.extend_from_slice(&ciphertext); // Includes tag
        encrypted_data
    };

    // Write to temp file in same dir
    let mut temp_file = NamedTempFile::new_in(&current_dir).context("Failed to create temp file")?;
    temp_file.write_all(&result).context("Failed to write to temp file")?;
    temp_file.flush().context("Failed to flush temp file")?;
    temp_file.as_file().sync_all().context("Failed to sync temp file to disk")?;

    // Atomically replace and get the persisted file handle
    let persisted_file = temp_file.persist(&file_path).context("Failed to persist temp file")?;

    // Restore metadata using the persisted file handle
    persisted_file.set_permissions(metadata.permissions()).context("Failed to set permissions")?;
    let atime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(metadata.atime() as u64) + std::time::Duration::from_nanos(metadata.atime_nsec() as u64);
    let mtime = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(metadata.mtime() as u64) + std::time::Duration::from_nanos(metadata.mtime_nsec() as u64);
    let file_times = FileTimes::new().set_accessed(atime).set_modified(mtime);
    persisted_file.set_times(file_times).context("Failed to set file times")?;

    println!("ok");

    Ok(())
}