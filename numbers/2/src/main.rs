use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    path::Path,
};
use zeroize::Zeroize;

use libc::{flock, mlock, munlock, LOCK_EX, LOCK_NB};

const KEY_FILE: &str = "key.key";
const VERSION: u8 = 1;
const NONCE_SIZE: usize = 24;
const HEADER_SIZE: usize = 1 + NONCE_SIZE;

// ================== MLOCK GUARD ==================

struct MlockGuard {
    ptr: *mut libc::c_void,
    len: usize,
}

impl MlockGuard {
    fn new(data: &mut [u8]) -> Result<Self, String> {
        let ptr = data.as_mut_ptr() as *mut libc::c_void;
        let len = data.len();

        let result = unsafe { mlock(ptr, len) };
        if result != 0 {
            return Err("mlock failed (check RLIMIT_MEMLOCK)".into());
        }

        Ok(Self { ptr, len })
    }
}

impl Drop for MlockGuard {
    fn drop(&mut self) {
        unsafe {
            munlock(self.ptr, self.len);
        }
    }
}

// ================== LOCKING ==================

fn acquire_lock(path: &str) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    let fd = file.as_raw_fd();
    let result = unsafe { flock(fd, LOCK_EX | LOCK_NB) };

    if result != 0 {
        return Err("File is locked by another process".into());
    }

    Ok(file)
}

// ================== KEY LOADING ==================

fn load_key() -> Result<Vec<u8>, String> {
    let key = fs::read(KEY_FILE).map_err(|e| e.to_string())?;

    if key.len() != 32 {
        return Err("Key must be exactly 32 bytes".into());
    }

    Ok(key)
}

// ================== FORMAT CHECK ==================

fn is_encrypted(data: &[u8]) -> bool {
    data.len() > HEADER_SIZE && data[0] == VERSION
}

// ================== ENCRYPT ==================

fn encrypt(filename: &str, key: &[u8], data: &mut Vec<u8>) -> Result<(), String> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| "Invalid key".to_string())?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.push(VERSION);
    header.extend_from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: data,
                aad: &header,
            },
        )
        .map_err(|_| "Encryption failed".to_string())?;

    let mut output = header;
    output.extend_from_slice(&ciphertext);

    atomic_replace(filename, &output)
}

// ================== DECRYPT ==================

fn decrypt(filename: &str, key: &[u8], data: &mut Vec<u8>) -> Result<(), String> {
    if data.len() < HEADER_SIZE {
        return Err("Corrupted file".into());
    }

    if data[0] != VERSION {
        return Err("Unsupported version".into());
    }

    let nonce = &data[1..HEADER_SIZE];
    let ciphertext = &data[HEADER_SIZE..];

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| "Invalid key".to_string())?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &data[..HEADER_SIZE],
            },
        )
        .map_err(|_| "Decryption failed (wrong key or tampered file)".to_string())?;

    atomic_replace(filename, &plaintext)
}

// ================== ATOMIC REPLACE ==================

fn atomic_replace(path: &str, data: &[u8]) -> Result<(), String> {
    let tmp_path = format!("{}.tmp", path);

    {
        let mut tmp = File::create(&tmp_path).map_err(|e| e.to_string())?;
        tmp.write_all(data).map_err(|e| e.to_string())?;
        tmp.sync_all().map_err(|e| e.to_string())?;
    }

    fs::rename(&tmp_path, path).map_err(|e| e.to_string())?;

    let dir = File::open(".").map_err(|e| e.to_string())?;
    dir.sync_all().map_err(|e| e.to_string())?;

    Ok(())
}

// ================== MAIN ==================

fn run() -> Result<(), String> {
    let filename = env::args()
        .nth(1)
        .ok_or("Usage: ai <file>")?;

    if filename.contains('/') {
        return Err("Only files in current directory are allowed".into());
    }

    if filename == KEY_FILE {
        return Err("Refusing to operate on key.key".into());
    }

    if !Path::new(&filename).exists() {
        return Err("File does not exist".into());
    }

    let mut key = load_key()?;
    let _mlock = MlockGuard::new(&mut key)?;

    let _lock = acquire_lock(&filename)?;

    let mut data = fs::read(&filename).map_err(|e| e.to_string())?;

    let encrypted = is_encrypted(&data);

    let result = if encrypted {
        decrypt(&filename, &key, &mut data)
    } else {
        encrypt(&filename, &key, &mut data)
    };

    key.zeroize();
    data.zeroize();

    result?;

    if encrypted {
        println!("Decrypted");
    } else {
        println!("Encrypted");
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }
}
