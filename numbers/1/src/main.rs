#![cfg(target_os = "linux")]

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use libc::{flock, LOCK_EX, LOCK_NB};

const MAGIC: &[u8; 8] = b"LINUXENC";
const VERSION: u8 = 1;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const HEADER_SIZE: usize = 8 + 1 + NONCE_SIZE;

fn main() {
    if let Err(e) = run() {
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let filename = env::args()
        .nth(1)
        .ok_or("Usage: ai <file>")?;

    // 🔒 Refuse to operate on key.key
    if filename == "key.key" {
        return Err("Refusing to operate on key.key".into());
    }

    let mut key = load_key()?;
    let _lock = acquire_lock(&filename)?;

    let mut data = fs::read(&filename)
        .map_err(|e| e.to_string())?;

    let result = if is_encrypted(&data) {
        decrypt(&filename, &key, &mut data)
    } else {
        encrypt(&filename, &key, &mut data)
    };

    key.zeroize();
    data.zeroize();

    result
}

fn load_key() -> Result<[u8; KEY_SIZE], String> {
    let key = fs::read("key.key")
        .map_err(|_| "key.key not found")?;

    if key.len() != KEY_SIZE {
        return Err("key.key must be exactly 32 bytes".into());
    }

    let mut k = [0u8; KEY_SIZE];
    k.copy_from_slice(&key);
    Ok(k)
}

fn acquire_lock(path: &str) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    let fd = file.as_raw_fd();
    let result = unsafe { flock(fd, LOCK_EX | LOCK_NB) };

    if result != 0 {
        return Err("File is locked by another process".into());
    }

    Ok(file)
}

fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE && &data[..8] == MAGIC
}

fn encrypt(path: &str, key: &[u8; KEY_SIZE], plaintext: &mut Vec<u8>) -> Result<(), String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = cipher.encrypt(nonce, plaintext.as_slice())
        .map_err(|_| "Encryption failed")?;

    let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&nonce_bytes);
    output.append(&mut ciphertext);

    atomic_replace(path, &output)?;

    output.zeroize();

    println!("Encrypted.");
    Ok(())
}

fn decrypt(path: &str, key: &[u8; KEY_SIZE], data: &mut Vec<u8>) -> Result<(), String> {
    if data.len() < HEADER_SIZE {
        return Err("Corrupted encrypted file".into());
    }

    if &data[..8] != MAGIC {
        return Err("Invalid magic header".into());
    }

    if data[8] != VERSION {
        return Err("Unsupported version".into());
    }

    let nonce = Nonce::from_slice(&data[9..9 + NONCE_SIZE]);
    let ciphertext = &data[HEADER_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    let mut plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Authentication failed")?;

    atomic_replace(path, &plaintext)?;

    plaintext.zeroize();

    println!("Decrypted.");
    Ok(())
}

fn atomic_replace(path: &str, data: &[u8]) -> Result<(), String> {
    let path = Path::new(path);
    let dir = path.parent().unwrap_or(Path::new("."));

    let mut rng = rand::thread_rng();
    let random: u64 = rng.next_u64();
    let pid = std::process::id();

    let tmp_name = format!(
        ".{}.ai.tmp.{}.{}",
        path.file_name().unwrap().to_string_lossy(),
        pid,
        random
    );

    let tmp_path: PathBuf = dir.join(tmp_name);

    {
        let mut tmp_file = File::create(&tmp_path)
            .map_err(|e| e.to_string())?;

        tmp_file.write_all(data)
            .map_err(|e| e.to_string())?;

        tmp_file.sync_all()
            .map_err(|e| e.to_string())?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| e.to_string())?;

    Ok(())
}
