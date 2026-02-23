//! Safe, atomic, Windows-only encrypt-or-decrypt CLI using libsodium secretstream (XChaCha20-Poly1305).
//!
//! Usage: `safecrypt <path-to-file>`
//! - If the file is plaintext -> encrypts in place (atomically).
//! - If the file already has the magic header -> decrypts in place (atomically).
//!
//! Format (on disk):
//!   [MAGIC(4)='XS20'] [VERSION(1)=0x01] [KEY_ID(8)] [SS_HEADER(24)]
//!   repeated frames: [C_LEN(4, LE)] [CIPHERTEXT(C_LEN)]
//!   last frame has libsodium TAG_FINAL (we also write a zero-length final frame).
//!
//! Key management: The key is *hard-coded* as a 32-byte array. No env vars, no parsing.

use anyhow::{bail, Context, Result};
use std::env;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{BOOL, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{ReplaceFileW, REPLACEFILE_WRITE_THROUGH};
use zeroize::Zeroize;

// ---- libsodium FFI ----
use libsodium_sys as sodium;

const MAGIC: &[u8; 4] = b"XS20";
const VERSION: u8 = 0x01;

// We store a short key identifier (first 8 bytes of BLAKE2b(key || domain)) to quickly reject wrong binaries.
const KEY_ID_LEN: usize = 8;

// Secretstream constants
const SS_HEADERBYTES: usize = sodium::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;
const SS_ABYTES: usize = sodium::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

// Chunking: large enough for throughput, small enough for memory; tune if desired.
const PLAINTEXT_CHUNK: usize = 64 * 1024; // 64 KiB

// ======= HARD-CODED KEY (CHANGE THESE 32 BYTES BEFORE BUILDING) =======
const COMPILETIME_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[inline]
fn key_bytes() -> [u8; 32] {
    COMPILETIME_KEY
}

// Compute a short key id (8 bytes) to detect “wrong binary/wrong key” early.
// ID = BLAKE2b-256(key || "safecrypt-key-id"), truncated to 8 bytes.
fn key_id_for(key: &[u8; 32]) -> [u8; KEY_ID_LEN] {
    const CONTEXT: &[u8] = b"safecrypt-key-id";
    let mut out = [0u8; 32];
    unsafe {
        let rc = sodium::crypto_generichash(
            out.as_mut_ptr(),
            out.len(),
            key.as_ptr(),
            key.len() as u64,
            CONTEXT.as_ptr(),
            CONTEXT.len(),
        );
        debug_assert_eq!(rc, 0);
    }
    let mut short = [0u8; KEY_ID_LEN];
    short.copy_from_slice(&out[..KEY_ID_LEN]);
    short
}

// Windows helper: convert &OsStr to NUL-terminated wide string for Win32 APIs.
fn to_wide_null(s: &OsStr) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    v.push(0);
    v
}

// Atomic replace using ReplaceFileW with WRITE_THROUGH to ensure durability.
fn atomic_replace(original: &Path, replacement: &Path) -> Result<()> {
    let orig_w = to_wide_null(original.as_os_str());
    let repl_w = to_wide_null(replacement.as_os_str());

    unsafe {
        let ok: BOOL = ReplaceFileW(
            orig_w.as_ptr(),
            repl_w.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if ok == 0 {
            let code = GetLastError();
            bail!("ReplaceFileW failed (atomic replace). Win32 error: {}", code);
        }
    }
    Ok(())
}

// Header we write/read before the secretstream frames.
#[derive(Debug, Clone)]
struct EncHeader {
    magic: [u8; 4],
    version: u8,
    key_id: [u8; KEY_ID_LEN],
    ss_header: [u8; SS_HEADERBYTES],
}

impl EncHeader {
    fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&self.magic)?;
        w.write_all(&[self.version])?;
        w.write_all(&self.key_id)?;
        w.write_all(&self.ss_header)?;
        Ok(())
    }

    fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        let mut ver = [0u8; 1];
        let mut kid = [0u8; KEY_ID_LEN];
        let mut sshdr = [0u8; SS_HEADERBYTES];

        r.read_exact(&mut magic)?;
        r.read_exact(&mut ver)?;
        r.read_exact(&mut kid)?;
        r.read_exact(&mut sshdr)?;

        Ok(Self { magic, version: ver[0], key_id: kid, ss_header: sshdr })
    }
}

fn detect_encrypted(path: &Path) -> io::Result<bool> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    if f.read(&mut magic)? < 4 {
        return Ok(false);
    }
    Ok(&magic == MAGIC)
}

// Create a temp file next to `path`
fn tmp_path_for(path: &Path) -> PathBuf {
    // Primitive unique name: ".<orig>.<8 random bytes hex>.tmp"
    let mut rnd = [0u8; 8];
    unsafe { sodium::randombytes_buf(rnd.as_mut_ptr() as *mut _, rnd.len()); }
    let suffix = hex::encode(rnd); // keep hex crate for this convenience
    let mut tmp = path.to_path_buf();
    let fname = match path.file_name() {
        Some(n) => n.to_string_lossy().into_owned(),
        None => "file".to_string(),
    };
    let tmpname = format!(".{}.{}.tmp", fname, suffix);
    tmp.set_file_name(tmpname);
    tmp
}

fn fsync_file(file: &File) -> Result<()> {
    file.sync_all().context("sync file to disk")
}

// After replacement, best-effort fsync of the new file (REPLACEFILE_WRITE_THROUGH already asked the OS to flush).
fn fsync_path_best_effort(path: &Path) {
    if let Ok(f) = OpenOptions::new().write(true).open(path) {
        let _ = f.sync_all();
    }
}

// ========== Encryption ==========

fn encrypt_in_place(path: &Path, key: &[u8; 32]) -> Result<()> {
    // Prepare sodium
    unsafe {
        if sodium::sodium_init() < 0 {
            bail!("sodium_init failed");
        }
    }

    let key_id = key_id_for(key);

    // Open source for reading
    let in_file = File::open(path).with_context(|| format!("open for read: {}", path.display()))?;
    let mut reader = BufReader::new(in_file);

    // Create temp file in same directory
    let tmp = tmp_path_for(path);
    let tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("create temp: {}", tmp.display()))?;
    let mut writer = BufWriter::new(tmp_file);

    // Build secretstream header
    let mut ss_state = MaybeUninit::<sodium::crypto_secretstream_xchacha20poly1305_state>::uninit();
    let mut ss_header = [0u8; SS_HEADERBYTES];

    let rc = unsafe {
        sodium::crypto_secretstream_xchacha20poly1305_init_push(
            ss_state.as_mut_ptr(),
            ss_header.as_mut_ptr(),
            key.as_ptr(),
        )
    };
    if rc != 0 {
        bail!("crypto_secretstream_xchacha20poly1305_init_push failed");
    }
    let mut ss_state = unsafe { ss_state.assume_init() };

    // Write our file header
    let header = EncHeader {
        magic: *MAGIC,
        version: VERSION,
        key_id,
        ss_header,
    };
    header.write_to(&mut writer)?;

    // Stream encrypt
    let mut plain = vec![0u8; PLAINTEXT_CHUNK];
    loop {
        let n = reader.read(&mut plain)?;
        if n == 0 {
            // Explicit zero-length FINAL frame (convenient end-of-stream marker)
            let mut c = vec![0u8; SS_ABYTES];
            let mut c_len: u64 = 0;
            let rc = unsafe {
                sodium::crypto_secretstream_xchacha20poly1305_push(
                    &mut ss_state,
                    c.as_mut_ptr(),
                    &mut c_len,
                    std::ptr::null(), // m
                    0,                // mlen
                    std::ptr::null(), // ad
                    0,                // adlen
                    sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8,
                )
            };
            if rc != 0 {
                bail!("secretstream push FINAL failed");
            }
            let clen = c_len as usize;
            debug_assert_eq!(clen, SS_ABYTES);
            writer.write_all(&(clen as u32).to_le_bytes())?;
            writer.write_all(&c[..clen])?;
            break;
        } else {
            let m = &plain[..n];
            let mut c = vec![0u8; n + SS_ABYTES];
            let mut c_len: u64 = 0;
            let rc = unsafe {
                sodium::crypto_secretstream_xchacha20poly1305_push(
                    &mut ss_state,
                    c.as_mut_ptr(),
                    &mut c_len,
                    m.as_ptr(),
                    m.len() as u64,
                    std::ptr::null(),
                    0,
                    sodium::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8,
                )
            };
            if rc != 0 {
                bail!("secretstream push failed");
            }
            let clen = c_len as usize;
            writer.write_all(&(clen as u32).to_le_bytes())?;
            writer.write_all(&c[..clen])?;
        }
    }

    writer.flush()?;
    let tmp_inner = writer.into_inner().context("flush temp writer")?;
    fsync_file(&tmp_inner)?; // durability of temp before replacement
    drop(tmp_inner); // close handle before ReplaceFileW

    // Atomic replace original with tmp
    atomic_replace(path, &tmp)?;

    // Extra safety: best-effort fsync the replaced file
    fsync_path_best_effort(path);
    Ok(())
}

// ========== Decryption ==========

fn decrypt_in_place(path: &Path, key: &[u8; 32]) -> Result<()> {
    unsafe {
        if sodium::sodium_init() < 0 {
            bail!("sodium_init failed");
        }
    }

    let expected_kid = key_id_for(key);

    // Open source for reading
    let in_file = File::open(path).with_context(|| format!("open for read: {}", path.display()))?;
    let mut reader = BufReader::new(in_file);

    // Parse header
    let header = EncHeader::read_from(&mut reader)?;
    if &header.magic != MAGIC {
        bail!("Not an encrypted file (magic mismatch)");
    }
    if header.version != VERSION {
        bail!("Unsupported version: {}", header.version);
    }
    if header.key_id != expected_kid {
        bail!("Key mismatch for this file (wrong binary / key)");
    }

    // Init pull
    let mut ss_state = MaybeUninit::<sodium::crypto_secretstream_xchacha20poly1305_state>::uninit();
    let rc = unsafe {
        sodium::crypto_secretstream_xchacha20poly1305_init_pull(
            ss_state.as_mut_ptr(),
            header.ss_header.as_ptr(),
            key.as_ptr(),
        )
    };
    if rc != 0 {
        bail!("crypto_secretstream_xchacha20poly1305_init_pull failed");
    }
    let mut ss_state = unsafe { ss_state.assume_init() };

    // Create temp output
    let tmp = tmp_path_for(path);
    let tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("create temp: {}", tmp.display()))?;
    let mut writer = BufWriter::new(tmp_file);

    // Stream decrypt
    let mut final_seen = false;
    loop {
        // read the frame length (u32 little-endian)
        let mut len_buf = [0u8; 4];
        let _read_len = match reader.read_exact(&mut len_buf) {
            Ok(_) => 4,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                if final_seen {
                    break; // reached EOF right after FINAL frame
                } else {
                    bail!("Truncated file before FINAL frame");
                }
            }
            Err(e) => return Err(e).context("read frame length"),
        };
        let clen = u32::from_le_bytes(len_buf) as usize;
        if clen < SS_ABYTES {
            bail!("Ciphertext frame too short");
        }

        let mut c = vec![0u8; clen];
        reader.read_exact(&mut c)?;

        // Decrypt one frame
        let mut m = vec![0u8; clen - SS_ABYTES];
        let mut m_len: u64 = 0;
        let mut tag: u8 = 0;

        let rc = unsafe {
            sodium::crypto_secretstream_xchacha20poly1305_pull(
                &mut ss_state,
                m.as_mut_ptr(),
                &mut m_len,
                &mut tag,
                c.as_ptr(),
                c.len() as u64,
                std::ptr::null(),
                0,
            )
        };
        if rc != 0 {
            bail!("Authentication failed (corrupted or wrong key)");
        }
        m.truncate(m_len as usize);

        if tag == sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8 {
            final_seen = true;
            if !m.is_empty() {
                // If you ever set FINAL on a non-empty frame, we still write it
                writer.write_all(&m)?;
            }
            // After FINAL, we *expect* EOF (enforced at the top of the loop)
        } else {
            writer.write_all(&m)?;
        }
    }

    writer.flush()?;
    let tmp_inner = writer.into_inner().context("flush temp writer")?;
    fsync_file(&tmp_inner)?;
    drop(tmp_inner);

    atomic_replace(path, &tmp)?;
    fsync_path_best_effort(path);
    Ok(())
}

// ========== Entry point ==========

fn main() -> Result<()> {
    // Single required argument: file path
    let mut args = env::args_os();
    let _exe = args.next();
    let path = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("Usage: safecrypt <path-to-file>");
            std::process::exit(2);
        }
    };
    if args.next().is_some() {
        eprintln!("Error: only one argument is accepted (the file path).");
        std::process::exit(2);
    }

    // Load the compile-time key (hard-coded)
    let mut key = key_bytes();

    // initialize sodium once (idempotent)
    unsafe {
        if sodium::sodium_init() < 0 {
            bail!("sodium_init failed");
        }
    }

    // Decide encrypt vs decrypt by magic header
    let mode = match detect_encrypted(&path) {
        Ok(true) => "decrypt",
        Ok(false) => "encrypt",
        Err(e) => {
            // If the file failed to open (e.g., doesn't exist), bubble up a nice error.
            return Err(e).with_context(|| format!("open: {}", path.display()));
        }
    };

    let res = match mode {
        "encrypt" => encrypt_in_place(&path, &key),
        "decrypt" => decrypt_in_place(&path, &key),
        _ => unreachable!(),
    };

    // Wipe temporary key buffer (doesn't remove it from .rdata since it's hard-coded, but keeps stack clean).
    key.zeroize();

    match res {
        Ok(()) => {
            println!("OK: {}ed '{}'", mode, path.display());
            Ok(())
        }
        Err(e) => {
            eprintln!("FAILED to {} '{}': {:#}", mode, path.display(), e);
            std::process::exit(1);
        }
    }
}
