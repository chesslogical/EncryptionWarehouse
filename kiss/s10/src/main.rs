use std::env;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use rpassword::read_password;
use zeroize::Zeroize;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use argon2::{Argon2, Params, Version};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"SECAPP01";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const CHUNK_SIZE: usize = 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SecureAppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Argon2 error: {0}")]
    Argon2(String),

    #[error("Encryption error")]
    CryptoEncrypt,

    #[error("Decryption failed (wrong password or corrupted file)")]
    CryptoDecrypt,

    #[error("Invalid file format")]
    InvalidFormat,

    #[error("Unsupported file version")]
    UnsupportedVersion,

    #[error("Corrupted chunk length")]
    CorruptedChunk,

    #[error("Usage: secureapp E <file> | secureapp D <file>")]
    Usage,

    #[error("Passwords do not match")]
    PasswordMismatch,
}

fn main() -> Result<(), SecureAppError> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        return Err(SecureAppError::Usage);
    }

    let mode = &args[1];
    let path = PathBuf::from(&args[2]);

    if !path.exists() {
        return Err(SecureAppError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found",
        )));
    }

    match mode.as_str() {
        "E" => process_file(&path, true),
        "D" => process_file(&path, false),
        _ => Err(SecureAppError::Usage),
    }
}

fn process_file(path: &Path, encrypt: bool) -> Result<(), SecureAppError> {
    let tmp_path = path.with_extension("secureapp.tmp");
    let backup_path = path.with_extension("secureapp.bak");

    // Remove leftover temp if exists
    let _ = fs::remove_file(&tmp_path);

    let result = if encrypt {
        encrypt_to(path, &tmp_path)
    } else {
        decrypt_to(path, &tmp_path)
    };

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
        return result;
    }

    fs::rename(path, &backup_path)?;

    if let Err(e) = fs::rename(&tmp_path, path) {
        // restore original
        let _ = fs::rename(&backup_path, path);
        return Err(e.into());
    }

    let _ = fs::remove_file(&backup_path);

    Ok(())
}

fn derive_key(password: &mut String, salt: &[u8]) -> Result<[u8; KEY_LEN], SecureAppError> {
    let params = Params::new(
        128 * 1024, // 128 MiB
        4,          // iterations
        1,
        None,
    )
    .map_err(|e| SecureAppError::Argon2(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| SecureAppError::Argon2(e.to_string()))?;

    password.zeroize();
    Ok(key)
}

fn encrypt_to(input_path: &Path, output_path: &Path) -> Result<(), SecureAppError> {
    let mut input = BufReader::new(File::open(input_path)?);
    let mut output = BufWriter::new(File::create(output_path)?);

    println!("Enter password:");
    let mut password = read_password()?;

    println!("Confirm password:");
    let mut confirm = read_password()?;

    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        return Err(SecureAppError::PasswordMismatch);
    }

    confirm.zeroize();

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(&mut password, &salt)?;
    let cipher = XChaCha20Poly1305::new(&key.into());

    // Build full header
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);

    output.write_all(&header)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut nonce_counter: u64 = 0;

    loop {
        let read_bytes = input.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..8].copy_from_slice(&nonce_counter.to_le_bytes());
        let nonce = XNonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &buffer[..read_bytes],
                    aad: &header,
                },
            )
            .map_err(|_| SecureAppError::CryptoEncrypt)?;

        let chunk_len = encrypted.len() as u32;
        output.write_all(&chunk_len.to_le_bytes())?;
        output.write_all(&encrypted)?;

        nonce_counter += 1;
    }

    output.flush()?;
    Ok(())
}

fn decrypt_to(input_path: &Path, output_path: &Path) -> Result<(), SecureAppError> {
    let mut input = BufReader::new(File::open(input_path)?);
    let mut output = BufWriter::new(File::create(output_path)?);

    let mut header = vec![0u8; MAGIC.len() + 1 + SALT_LEN];
    input.read_exact(&mut header)?;

    if &header[..MAGIC.len()] != MAGIC {
        return Err(SecureAppError::InvalidFormat);
    }

    if header[MAGIC.len()] != VERSION {
        return Err(SecureAppError::UnsupportedVersion);
    }

    let salt = &header[MAGIC.len() + 1..];

    println!("Enter password:");
    let mut password = read_password()?;
    let key = derive_key(&mut password, salt)?;
    let cipher = XChaCha20Poly1305::new(&key.into());

    let mut nonce_counter: u64 = 0;

    loop {
        let mut len_bytes = [0u8; 4];

        match input.read_exact(&mut len_bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let chunk_len = u32::from_le_bytes(len_bytes) as usize;

        if chunk_len == 0 || chunk_len > MAX_CHUNK_SIZE {
            return Err(SecureAppError::CorruptedChunk);
        }

        let mut encrypted = vec![0u8; chunk_len];
        input.read_exact(&mut encrypted)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[..8].copy_from_slice(&nonce_counter.to_le_bytes());
        let nonce = XNonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &encrypted,
                    aad: &header,
                },
            )
            .map_err(|_| SecureAppError::CryptoDecrypt)?;

        output.write_all(&decrypted)?;

        nonce_counter += 1;
    }

    output.flush()?;
    Ok(())
}
