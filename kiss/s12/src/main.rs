//! serpent2 — simple, reliable, Linux-only file encryptor using Serpent-256
//!
//!   serpent2 encrypt [--no-backup] <file>
//!   serpent2 decrypt [--no-backup] <file>
//!
//! Password is prompted interactively (never visible in process list/history).
//! Creates .bak backup before overwriting (unless --no-backup is used).
//! Uses strong Argon2id + Serpent-256-CBC + HMAC-SHA256 (constant-time verified).

#![cfg(target_os = "linux")]
#![deny(unused_mut)]

use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use cbc::{Decryptor as CbcDec, Encryptor as CbcEnc};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use rpassword;
use secrecy::{ExposeSecret, Secret, SecretString};
use sha2::Sha256;
use std::{
    env, fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process,
};
use zeroize::Zeroize;
use num_cpus;

type HmacSha256 = Hmac<Sha256>;
type SerpentEnc = CbcEnc<serpent::Serpent>;
type SerpentDec = CbcDec<serpent::Serpent>;

const MAGIC: &[u8; 4] = b"SPT2";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const TAG_LEN: usize = 32;
const KEY_LEN: usize = 32;

const ARGON_M_KIB: u32 = 194_560; // ~190 MiB — adjust down if on very low-RAM system
const ARGON_T: u32 = 4;
const ARGON_P_MAX: u32 = 8;

const LARGE_FILE_THRESHOLD: u64 = 1_073_741_824; // 1 GiB

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        print_usage(&args[0]);
        anyhow::bail!("invalid arguments");
    }

    let mut no_backup = false;
    let cmd = &args[1];
    let mut file_arg = &args[2];

    if args.len() == 4 {
        if args[2] == "--no-backup" {
            no_backup = true;
            file_arg = &args[3];
        } else if args[3] == "--no-backup" {
            no_backup = true;
            file_arg = &args[2];
        } else {
            print_usage(&args[0]);
            anyhow::bail!("unknown option");
        }
    }

    let path = Path::new(file_arg);
    if !path.is_file() {
        anyhow::bail!("not a regular file: {}", path.display());
    }

    // Warn on potentially large files
    if let Ok(metadata) = path.metadata() {
        if metadata.len() > LARGE_FILE_THRESHOLD {
            println!("Warning: file is > 1 GiB — tool loads entire file into RAM.");
            println!("         Make sure you have enough free memory (~2–3× file size).");
            println!("Press Enter to continue or Ctrl+C to abort...");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
    }

    let password = read_password()?;

    match cmd.as_str() {
        "encrypt" => encrypt_file(path, &password, no_backup),
        "decrypt" => decrypt_file(path, &password, no_backup),
        _ => {
            print_usage(&args[0]);
            anyhow::bail!("command must be 'encrypt' or 'decrypt'");
        }
    }
}

fn print_usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {} encrypt [--no-backup] <file>", prog);
    eprintln!("  {} decrypt [--no-backup] <file>", prog);
    eprintln!();
    eprintln!("Password is prompted interactively.");
    eprintln!("Creates .bak backup by default (skipped with --no-backup).");
}

fn read_password() -> Result<SecretString> {
    let pwd = rpassword::prompt_password("Password: ")
        .context("Failed to read password")?;

    let confirm = rpassword::prompt_password("Confirm: ")
        .context("Failed to read confirmation")?;

    if pwd != confirm {
        anyhow::bail!("Passwords do not match");
    }

    Ok(SecretString::new(pwd))
}

fn encrypt_file(path: &Path, password: &SecretString, no_backup: bool) -> Result<()> {
    let plaintext = fs::read(path).context("Cannot read input file")?;

    let salt = random_bytes(SALT_LEN);
    let iv = random_bytes(IV_LEN);

    let master = derive_master_key(password.expose_secret(), &salt)?;
    let (k_enc, k_mac) = derive_subkeys(&master, &salt)?;

    let mut buffer = plaintext;
    let orig_len = buffer.len();

    let ct_slice = SerpentEnc::new_from_slices(k_enc.expose_secret(), &iv)
        .context("Cipher init failed")?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, orig_len)
        .map_err(|_| anyhow!("Encryption or padding failed"))?;

    let header = build_header(&salt, &iv);
    let mut mac = HmacSha256::new_from_slice(k_mac.expose_secret())
        .context("HMAC init failed")?;
    mac.update(&header);
    mac.update(ct_slice);
    mac.verify_slice(&[0u8; TAG_LEN])?; // dummy to force type check — real verify below

    let mut output = Vec::with_capacity(header.len() + ct_slice.len() + TAG_LEN);
    output.extend_from_slice(&header);
    output.extend_from_slice(ct_slice);
    mac = HmacSha256::new_from_slice(k_mac.expose_secret())?;
    mac.update(&header);
    mac.update(ct_slice);
    output.extend_from_slice(mac.finalize().into_bytes().as_slice());

    atomic_write_with_backup(path, &output, no_backup)?;

    buffer.zeroize();

    println!("Encrypted: {} {}", path.display(), if no_backup { "(no backup)" } else { "→ .bak created" });
    Ok(())
}

fn decrypt_file(path: &Path, password: &SecretString, no_backup: bool) -> Result<()> {
    let data = fs::read(path).context("Cannot read file")?;

    if data.len() < 4 + 1 + SALT_LEN + IV_LEN + TAG_LEN + 16 {
        anyhow::bail!("File too small to be valid");
    }

    if &data[0..4] != MAGIC {
        anyhow::bail!("Not a serpent2 file (wrong magic bytes)");
    }
    if data[4] != VERSION {
        anyhow::bail!("Unsupported format version (got {}, expected {})", data[4], VERSION);
    }

    let salt = &data[5..5 + SALT_LEN];
    let iv = &data[5 + SALT_LEN..5 + SALT_LEN + IV_LEN];
    let tag_start = data.len() - TAG_LEN;
    let ct = &data[5 + SALT_LEN + IV_LEN..tag_start];
    let tag = &data[tag_start..];

    let master = derive_master_key(password.expose_secret(), salt)?;
    let (k_enc, k_mac) = derive_subkeys(&master, salt)?;

    let header = &data[..5 + SALT_LEN + IV_LEN];

    // Constant-time MAC verification
    let mut mac = HmacSha256::new_from_slice(k_mac.expose_secret())
        .context("HMAC init failed")?;
    mac.update(header);
    mac.update(ct);
    mac.verify_slice(tag)
        .context("Authentication failed — wrong password or corrupted file")?;

    let mut buffer = ct.to_vec();
    let pt_slice = SerpentDec::new_from_slices(k_enc.expose_secret(), iv)
        .context("Cipher init failed")?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| anyhow!("Invalid padding — very likely wrong password"))?;

    atomic_write_with_backup(path, pt_slice, no_backup)?;

    buffer.zeroize();

    println!("Decrypted: {} {}", path.display(), if no_backup { "(no backup)" } else { "→ .bak created" });
    Ok(())
}

fn derive_master_key(pw: &str, salt: &[u8]) -> Result<Secret<[u8; KEY_LEN]>> {
    let p = ARGON_P_MAX.min(num_cpus::get().max(1) as u32);

    if ARGON_M_KIB < 32768 || ARGON_M_KIB > 1_048_576 {
        anyhow::bail!("Memory parameter out of safe range");
    }
    if ARGON_T < 1 || ARGON_T > 12 {
        anyhow::bail!("Time parameter out of safe range");
    }

    let params = Params::new(ARGON_M_KIB, ARGON_T, p, Some(KEY_LEN))
        .map_err(|e| anyhow!("Invalid Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(pw.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 failed: {}", e))?;

    Ok(Secret::new(key))
}

fn derive_subkeys(master: &Secret<[u8; KEY_LEN]>, salt: &[u8]) -> Result<(Secret<[u8; KEY_LEN]>, Secret<[u8; KEY_LEN]>)> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master.expose_secret());

    let mut k_enc = [0u8; KEY_LEN];
    let mut k_mac = [0u8; KEY_LEN];

    hk.expand(b"serpent2/enc/v1", &mut k_enc)
        .map_err(|e| anyhow!("HKDF enc failed: {}", e))?;
    hk.expand(b"serpent2/mac/v1", &mut k_mac)
        .map_err(|e| anyhow!("HKDF mac failed: {}", e))?;

    Ok((Secret::new(k_enc), Secret::new(k_mac)))
}

fn build_header(salt: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(4 + 1 + SALT_LEN + IV_LEN);
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.extend_from_slice(salt);
    h.extend_from_slice(iv);
    h
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    OsRng.fill_bytes(&mut v);
    v
}

fn atomic_write_with_backup(path: &Path, data: &[u8], no_backup: bool) -> Result<()> {
    if !no_backup {
        let bak = path.with_extension("bak");
        if path.exists() {
            fs::copy(path, &bak).context("Backup failed")?;
        }
    }

    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .context("Cannot create temp file")?;

    f.write_all(data).context("Write temp failed")?;
    f.sync_all().context("fsync failed")?;

    fs::rename(&tmp, path).context("Atomic rename failed")?;

    Ok(())
}