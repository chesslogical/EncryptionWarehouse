/*!
 * rsafe (Windows-only)
 *
 * This codebase is intentionally optimized and tested for Windows.
 * Non-Windows builds are explicitly disabled to keep the implementation focused and simpler.
 */

#![forbid(unsafe_op_in_unsafe_fn)]

// Prevent accidental non-Windows builds early at compile time.
#[cfg(not(windows))]
compile_error!("rsafe is currently Windows-only. Build for a Windows target (e.g., x86_64-pc-windows-msvc).");

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use fd_lock::RwLock;
use filetime::{set_file_times, FileTime};
use indicatif::{ProgressBar, ProgressStyle};
use libsodium_rs as sodium;
use sodium::crypto_pwhash;
use sodium::crypto_secretstream::{xchacha20poly1305 as secret, Key, PullState, PushState};
use sodium::{ensure_init, random};
use rpassword::prompt_password;
use std::cmp::min;
use std::error::Error as StdError;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tempfile::{Builder as TempBuilder, NamedTempFile};
use zeroize::Zeroize;

// Windows-specific extensions/constants we use
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ};

/// rsafe: atomic, password-based file encrypter/decrypter
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to file. If plaintext -> encrypt in place. If rsafe-encrypted -> decrypt in place.
    path: PathBuf,

    /// Allow operating on a symlink/junction (by default, reparse points are refused)
    #[arg(long)]
    follow_symlink: bool,

    /// Skip password confirmation on encrypt (useful for scripts)
    #[arg(long)]
    no_confirm: bool,

    /// Read passphrase from a file (first line; trailing newline trimmed)
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,

    /// Show a progress bar
    #[arg(long)]
    progress: bool,

    /// Auto-tune Argon2id opslimit to ~this many milliseconds on this machine
    #[arg(long, value_name = "MS")]
    kdf_target_ms: Option<u64>,

    /// Override Argon2id memory limit for encryption (MiB). Safe bounds enforced.
    #[arg(long, value_name = "MiB")]
    kdf_memlimit_mib: Option<usize>,
}

const MAGIC: &[u8; 8] = b"RSAFEv01";
const VERSION: u8 = 1;
const KDF_ALG_ARGON2ID: u8 = 1; // Argon2id v1.3
const RESERVED_LEN: usize = 8;
const SALT_LEN: usize = crypto_pwhash::SALTBYTES as usize; // 16
const SS_HEADER_LEN: usize = secret::HEADERBYTES as usize; // 24

// Header layout (70 bytes total):
// 0..8   MAGIC "RSAFEv01"
// 8      VERSION (u8)
// 9      KDF_ALG (u8) = 1 (Argon2id v1.3)
// 10..14 opslimit (u32 LE)
// 14..22 memlimit (u64 LE)
// 22..38 salt (16)
// 38..62 secretstream header (24)
// 62..70 reserved (8) = 0
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 8 + SALT_LEN + SS_HEADER_LEN + RESERVED_LEN;

const CHUNK: usize = 1024 * 64; // 64KiB streaming chunks (tunable)

// libsodium-rs pwhash() takes (opslimit: u64, memlimit: usize)
const OPSLIMIT: u64 = crypto_pwhash::OPSLIMIT_MODERATE;
const MEMLIMIT: usize = crypto_pwhash::MEMLIMIT_MODERATE;

// Ciphertext per-chunk bounds (pt ≤ CHUNK, ct = pt + ABYTES)
const MIN_CT_PER_CHUNK: usize = secret::ABYTES as usize;
const MAX_CT_PER_CHUNK: usize = CHUNK + secret::ABYTES as usize;

// Hard ceilings for header-provided KDF params
const MAX_KDF_OPSLIMIT: u64 = crypto_pwhash::OPSLIMIT_SENSITIVE;
const MAX_KDF_MEMLIMIT: usize = crypto_pwhash::MEMLIMIT_SENSITIVE;
const MIN_KDF_MEMLIMIT: usize = crypto_pwhash::MEMLIMIT_INTERACTIVE;

// Orphan temp cleanup threshold
const ORPHAN_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Stable exit codes
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
enum ExitCode {
    Ok = 0,
    Generic = 1,
    PasswordMismatch = 2,
    WrongPassword = 3,
    BadHeader = 4,
    Corrupted = 5,
    Locked = 6,
    SymlinkRefused = 7,
    KdfInvalid = 8,
    Io = 9,
}

/// App-specific, typed error categories (so we can map to ExitCode without string matching)
#[derive(Debug)]
enum RSafeKind {
    PasswordMismatch,
    WrongPassword,
    BadHeader,   // not rsafe / unsupported version / bad alg id / malformed header
    Corrupted,   // framing, trailing bytes, out-of-bounds, truncation
    Locked,      // lock contention
    SymlinkRefused,
    KdfInvalid,  // kdf params out of bounds
}

impl std::fmt::Display for RSafeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RSafeKind::*;
        match self {
            PasswordMismatch => write!(f, "Passwords do not match"),
            WrongPassword => write!(f, "Decryption failed (wrong password or corrupted data)"),
            BadHeader => write!(f, "Not an rsafe-encrypted file or unsupported/malformed header"),
            Corrupted => write!(f, "File appears corrupted"),
            Locked => write!(f, "File is locked by another rsafe process"),
            SymlinkRefused => write!(f, "Refusing to operate on symlink/junction (use --follow-symlink)"),
            KdfInvalid => write!(f, "KDF parameters out of allowed range for this machine"),
        }
    }
}
impl StdError for RSafeKind {}

fn main() {
    let code = match real_main() {
        Ok(()) => ExitCode::Ok as i32,
        Err(err) => {
            // Print a concise error (with context chain)
            eprintln!("rsafe: {}", err);
            for cause in err.chain().skip(1) {
                eprintln!("  caused by: {}", cause);
            }
            // Map to stable exit code
            classify_error(&err) as i32
        }
    };
    std::process::exit(code);
}

fn classify_error(err: &anyhow::Error) -> ExitCode {
    // Prefer our typed error if present at the top-level
    if let Some(kind) = err.downcast_ref::<RSafeKind>() {
        return match kind {
            RSafeKind::PasswordMismatch => ExitCode::PasswordMismatch,
            RSafeKind::WrongPassword => ExitCode::WrongPassword,
            RSafeKind::BadHeader => ExitCode::BadHeader,
            RSafeKind::Corrupted => ExitCode::Corrupted,
            RSafeKind::Locked => ExitCode::Locked,
            RSafeKind::SymlinkRefused => ExitCode::SymlinkRefused,
            RSafeKind::KdfInvalid => ExitCode::KdfInvalid,
        };
    }
    // Otherwise, heuristically bucket some common OS errors:
    if let Some(ioe) = err.downcast_ref::<std::io::Error>() {
        use std::io::ErrorKind::*;
        return match ioe.kind() {
            PermissionDenied | NotFound | AlreadyExists | WouldBlock => ExitCode::Io,
            _ => ExitCode::Generic,
        };
    }
    ExitCode::Generic
}

fn real_main() -> Result<()> {
    let args = Args::parse();

    // Initialize libsodium once.
    ensure_init().map_err(|e| anyhow!("Failed to initialize libsodium: {e:?}"))?;

    // Create a sidecar lock file next to the target and take an exclusive advisory lock.
    let parent = args.path.parent().unwrap_or_else(|| Path::new("."));
    let lock_name = format!(
        ".rsafe.lock.{}",
        args.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("target")
    );
    let lock_path = parent.join(lock_name);
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("Unable to open/create lock file: {}", lock_path.display()))?;
    let mut lock = RwLock::new(lock_file);
    let guard = lock
        .write()
        .map_err(|e| anyhow!(RSafeKind::Locked).context(e))?; // typed lock error

    // Best-effort cleanup of old orphaned temp files in the target directory.
    let _ = cleanup_orphan_temps(parent);

    // Decide encrypt vs decrypt by header magic
    let mode = detect_mode(&args.path)?;
    let res = match mode {
        Mode::Encrypt => {
            let mut password = get_password(Mode::Encrypt, &args)?;
            let res = encrypt_in_place(&args.path, &password, &args);
            password.zeroize();
            res
        }
        Mode::Decrypt => {
            let mut password = get_password(Mode::Decrypt, &args)?;
            let res = decrypt_in_place(&args.path, &password, &args);
            password.zeroize();
            res
        }
    };

    // Release the lock and best-effort remove the sidecar lock file.
    drop(guard);
    let _ = fs::remove_file(&lock_path);

    res
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn detect_mode(path: &Path) -> Result<Mode> {
    let mut f = {
        let mut oo = OpenOptions::new();
        oo.read(true).share_mode(FILE_SHARE_READ); // forbid others from writing while we sniff
        oo.open(path)?
    };
    let mut head = [0u8; HEADER_LEN]; // read enough to check magic quickly
    let n = f.read(&mut head)?;
    if n >= MAGIC.len() && &head[..MAGIC.len()] == MAGIC {
        Ok(Mode::Decrypt)
    } else {
        Ok(Mode::Encrypt)
    }
}

/// Derive a secretstream Key from password using libsodium Argon2id v1.3.
/// `opslimit` is u64; `memlimit` is usize (per libsodium-rs API).
fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    opslimit: u64,
    memlimit: usize,
) -> Result<Key> {
    let mut key_bytes = crypto_pwhash::pwhash(
        secret::KEYBYTES as usize,
        password.as_bytes(),
        salt,
        opslimit,
        memlimit,
        crypto_pwhash::ALG_ARGON2ID13, // pin exact KDF algorithm
    )
    .map_err(|_| anyhow!("Key derivation failed"))?;
    let key = Key::from_bytes(&key_bytes).map_err(|_| anyhow!("Invalid key length"))?;
    key_bytes.zeroize(); // wipe temporary derived bytes
    Ok(key)
}

/// Write a little-endian u32 length prefix.
fn write_len<W: Write>(w: &mut W, len: u32) -> Result<()> {
    w.write_all(&len.to_le_bytes())?;
    Ok(())
}

/// Encrypt file in place (atomic replace, fsync). Leaves original intact on any error.
fn encrypt_in_place(path: &Path, password: &str, args: &Args) -> Result<()> {
    if !args.follow_symlink {
        ensure_not_symlink(path)?;
    }

    // Prepare source file + metadata (capture times to restore later)
    let src = {
        let mut oo = OpenOptions::new();
        oo.read(true).share_mode(FILE_SHARE_READ); // forbid others from writing during read
        oo.open(path)?
    };
    let meta = src.metadata()?;
    let total = meta.len();
    let at = FileTime::from_last_access_time(&meta);
    let mt = FileTime::from_last_modification_time(&meta);

    // Maybe show a progress bar
    let pb = if args.progress {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template("{bar} {bytes}/{total_bytes} ({eta})")?
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Build temp file in same directory (same filesystem/volume)
    let parent = path.parent().ok_or_else(|| anyhow!("No parent directory"))?;
    let ntf: NamedTempFile = TempBuilder::new()
        .prefix(".rsafe.tmp.")
        .tempfile_in(parent)?;

    // On Windows, ReplaceFileW preserves destination ACLs/attributes.
    // We intentionally do NOT copy permissions onto the temp file to avoid
    // write issues with read-only attrs and keep temp I/O simple.

    // KDF parameters (optionally auto-tuned) and memory-limit override
    let mut chosen_memlimit = args
        .kdf_memlimit_mib
        .map(|mib| mib.saturating_mul(1024 * 1024))
        .unwrap_or(MEMLIMIT);
    // Clamp to safe bounds
    if chosen_memlimit < MIN_KDF_MEMLIMIT {
        chosen_memlimit = MIN_KDF_MEMLIMIT;
    }
    if chosen_memlimit > MAX_KDF_MEMLIMIT {
        chosen_memlimit = MAX_KDF_MEMLIMIT;
    }

    let chosen_opslimit = match args.kdf_target_ms {
        Some(ms) if ms > 0 => calibrate_opslimit(ms, chosen_memlimit),
        _ => OPSLIMIT,
    };

    // Compose header (and keep an in-memory copy to use as AAD for every record):
    // magic | version | kdf_alg | opslimit u32 | memlimit u64 | salt 16 | ss_header 24 | reserved 8
    let mut salt = [0u8; SALT_LEN];
    random::fill_bytes(&mut salt);
    let kdf_ops_u32: u32 = chosen_opslimit.try_into().unwrap_or(u32::MAX);
    let kdf_mem_u64: u64 = chosen_memlimit as u64;

    let key = derive_key(password, &salt, chosen_opslimit, chosen_memlimit)?;
    let (mut push, ss_header) =
        PushState::init_push(&key).map_err(|_| anyhow!("secretstream init failed"))?;
    // Key no longer needed beyond state initialization.
    drop(key);

    // Build AAD = exact header bytes we write
    let mut aad = Vec::with_capacity(HEADER_LEN);
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.push(KDF_ALG_ARGON2ID);
    aad.extend_from_slice(&kdf_ops_u32.to_le_bytes());
    aad.extend_from_slice(&kdf_mem_u64.to_le_bytes());
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&ss_header);
    aad.extend_from_slice(&[0u8; RESERVED_LEN]);

    // ==== Begin scoped output section (drop before into_temp_path) ====
    {
        // Use the NamedTempFile's handle directly in a scoped borrow.
        let out_file: &File = ntf.as_file();
        let mut out = BufWriter::new(out_file);

        // Write header
        out.write_all(&aad)?;

        // Stream encrypt with framed records
        let mut reader = BufReader::new(src);
        let mut buf = vec![0u8; CHUNK];
        let mut done: u64 = 0;

        if total == 0 {
            // Emit an empty FINAL frame for zero-length input
            let ct = push
                .push(&[], Some(&aad), secret::TAG_FINAL)
                .map_err(|_| anyhow!("encrypt chunk failed"))?;
            write_len(&mut out, ct.len() as u32)?;
            out.write_all(&ct)?;
        } else {
            while done < total {
                let want = min(CHUNK as u64, total - done) as usize;
                read_exact(&mut reader, &mut buf[..want])?;
                let tag = if done + want as u64 == total {
                    secret::TAG_FINAL
                } else {
                    secret::TAG_MESSAGE
                };
                let ct = push
                    .push(&buf[..want], Some(&aad), tag)
                    .map_err(|_| anyhow!("encrypt chunk failed"))?;
                write_len(&mut out, ct.len() as u32)?;
                out.write_all(&ct)?;
                done += want as u64;
                if let Some(ref pb) = pb {
                    pb.set_position(done);
                }
            }
            // Zeroize the plaintext buffer
            buf.zeroize();
        }

        // Flush buffers and fsync before replace
        out.flush()?;
        let _ = out.get_ref().sync_all();
        // reader, out drop here
    }
    // ==== End scoped output section ====

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // Now it is safe to move the NamedTempFile (no active borrows).
    let tmp = ntf.into_temp_path();

    // Atomically replace the original
    atomic_replace(path, &tmp)?;

    // Restore original timestamps (best-effort)
    let _ = set_file_times(path, at, mt);

    Ok(())
}

/// Decrypt file in place (atomic replace, fsync). Leaves original intact on any error.
fn decrypt_in_place(path: &Path, password: &str, args: &Args) -> Result<()> {
    if !args.follow_symlink {
        ensure_not_symlink(path)?;
    }

    // Capture original timestamps to preserve across the replace.
    let orig_meta = fs::metadata(path)?;
    let at = FileTime::from_last_access_time(&orig_meta);
    let mt = FileTime::from_last_modification_time(&orig_meta);

    let mut src = {
        let mut oo = OpenOptions::new();
        oo.read(true).share_mode(FILE_SHARE_READ);
        oo.open(path)?
    };

    // Read and parse header
    let mut hdr = vec![0u8; HEADER_LEN];
    src.read_exact(&mut hdr).map_err(|_| anyhow!(RSafeKind::BadHeader))?;
    if &hdr[0..MAGIC.len()] != MAGIC {
        return Err(anyhow!(RSafeKind::BadHeader));
    }
    let ver = hdr[8];
    if ver != VERSION {
        return Err(anyhow!(RSafeKind::BadHeader));
    }
    let kdf_alg = hdr[9];
    if kdf_alg != KDF_ALG_ARGON2ID {
        return Err(anyhow!(RSafeKind::BadHeader));
    }

    let opslimit = u32::from_le_bytes(hdr[10..14].try_into().unwrap()) as u64;
    let memlimit_u64 = u64::from_le_bytes(hdr[14..22].try_into().unwrap());
    let memlimit_usize: usize =
        usize::try_from(memlimit_u64).map_err(|_| anyhow!(RSafeKind::KdfInvalid))?;

    // Reject pathological KDF parameters (DoS guard)
    if opslimit == 0 || opslimit > MAX_KDF_OPSLIMIT {
        return Err(anyhow!(RSafeKind::KdfInvalid));
    }
    if memlimit_usize == 0 || memlimit_usize > MAX_KDF_MEMLIMIT {
        return Err(anyhow!(RSafeKind::KdfInvalid));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&hdr[22..(22 + SALT_LEN)]);
    let mut ss_header = [0u8; SS_HEADER_LEN];
    ss_header.copy_from_slice(&hdr[(22 + SALT_LEN)..(22 + SALT_LEN + SS_HEADER_LEN)]);
    // Enforce that reserved bytes are zero (forward-compat hygiene).
    let reserved = &hdr[(22 + SALT_LEN + SS_HEADER_LEN)..HEADER_LEN];
    if reserved.iter().any(|&b| b != 0) {
        return Err(anyhow!(RSafeKind::BadHeader).context("reserved bytes must be zero"));
    }

    let key = derive_key(password, &salt, opslimit, memlimit_usize)?;
    let mut pull = PullState::init_pull(&ss_header, &key)
        .map_err(|_| anyhow!(RSafeKind::BadHeader))?;
    // Key no longer needed beyond state initialization.
    drop(key);

    // Prepare temp output file
    let parent = path.parent().ok_or_else(|| anyhow!("No parent directory"))?;
    let ntf: NamedTempFile = TempBuilder::new()
        .prefix(".rsafe.tmp.")
        .tempfile_in(parent)?;

    // Do not copy original perms to temp on Windows; ReplaceFileW keeps dest ACLs/attrs.

    // Progress: spinner (plaintext total unknown)
    let spinner = if args.progress {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::with_template("{spinner} decrypted {bytes}").unwrap());
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    // ==== Begin scoped output section (drop before into_temp_path) ====
    {
        let out_file: &File = ntf.as_file();
        let mut out = BufWriter::new(out_file);

        // Stream framed ciphertext records -> plaintext
        let mut reader = BufReader::new(src);
        // AAD must match exactly what encrypt wrote
        let aad: &[u8] = &hdr;
        let mut total_out: u64 = 0;

        loop {
            // Read length prefix
            let mut len_buf = [0u8; 4];
            if let Err(_) = reader.read_exact(&mut len_buf) {
                return Err(anyhow!(RSafeKind::Corrupted).context("missing chunk length"));
            }
            let ct_len = u32::from_le_bytes(len_buf) as usize;
            if ct_len < MIN_CT_PER_CHUNK || ct_len > MAX_CT_PER_CHUNK {
                return Err(anyhow!(RSafeKind::Corrupted).context("chunk length out of bounds"));
            }

            let mut ct = vec![0u8; ct_len];
            reader.read_exact(&mut ct)?;
            let (mut pt, tag) = pull
                .pull(&ct, Some(aad))
                .map_err(|_| anyhow!(RSafeKind::WrongPassword))?;
            out.write_all(&pt)?;
            total_out += pt.len() as u64;

            // Zeroize plaintext buffer
            pt.zeroize();
            // Optional hygiene
            ct.zeroize();

            if let Some(ref pb) = spinner {
                pb.set_message(format!("decrypted {} bytes", total_out));
            }

            if tag == secret::TAG_FINAL {
                // must be EOF now; if there's extra bytes, refuse
                let mut probe = [0u8; 1];
                let extra = reader.read(&mut probe)?;
                if extra != 0 {
                    return Err(anyhow!(RSafeKind::Corrupted).context("trailing data after FINAL"));
                }
                break;
            }
        }

        out.flush()?;
        let _ = out.get_ref().sync_all();
        // reader, out drop here
    }
    // ==== End scoped output section ====

    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    // Close handles before the replace by ending the scope above; now consume ntf.
    let tmp = ntf.into_temp_path();

    atomic_replace(path, &tmp)?;

    // Restore original timestamps (best-effort)
    let _ = set_file_times(path, at, mt);

    Ok(())
}

/// Windows: use ReplaceFileW (with retries) to atomically replace an existing file.
/// Also handles read-only destination files by temporarily clearing the READONLY attribute.
/// On any exit path (success or failure), original attributes are restored if modified.
fn atomic_replace(dest: &Path, tmp: &tempfile::TempPath) -> Result<()> {
    use windows_sys::Win32::Foundation::BOOL;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, ReplaceFileW, SetFileAttributesW, FILE_ATTRIBUTE_READONLY,
        INVALID_FILE_ATTRIBUTES, REPLACEFILE_WRITE_THROUGH,
    };

    // Convert both paths to UTF-16.
    let dest_w: Vec<u16> = os_str_to_wide(dest.as_os_str());
    let tmp_path: &std::path::Path = tmp.as_ref();
    let tmp_w: Vec<u16> = os_str_to_wide(tmp_path.as_os_str());

    // Retry a few times to ride out brief locks from AV/indexers/OneDrive.
    let mut last_err = None;
    let mut cleared_readonly = false;
    let mut original_attrs: u32 = 0;

    for _ in 0..40 {
        let rc: BOOL = unsafe {
            ReplaceFileW(
                dest_w.as_ptr(),
                tmp_w.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH, // flush data/metadata
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            // If we cleared READONLY earlier, restore original attributes now.
            if cleared_readonly {
                unsafe {
                    // Best-effort restore; ignore result.
                    let _ = SetFileAttributesW(dest_w.as_ptr(), original_attrs);
                }
            }
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // 32: SHARING_VIOLATION, 33: LOCK_VIOLATION
            Some(32) | Some(33) => {
                last_err = Some(err);
                std::thread::sleep(Duration::from_millis(75));
                continue;
            }
            // 5: ACCESS_DENIED (can be due to READONLY dest)
            Some(5) => {
                // Try to clear READONLY exactly once.
                if !cleared_readonly {
                    unsafe {
                        let attrs = GetFileAttributesW(dest_w.as_ptr());
                        if attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY) != 0
                        {
                            original_attrs = attrs;
                            let new_attrs = attrs & !FILE_ATTRIBUTE_READONLY;
                            let _ = SetFileAttributesW(dest_w.as_ptr(), new_attrs);
                            cleared_readonly = true;
                            // Next loop iteration will retry ReplaceFileW
                            continue;
                        }
                    }
                }
                last_err = Some(err);
                std::thread::sleep(Duration::from_millis(75));
                continue;
            }
            _ => {
                if cleared_readonly {
                    unsafe {
                        let _ = SetFileAttributesW(dest_w.as_ptr(), original_attrs);
                    }
                }
                return Err(err).with_context(|| "ReplaceFileW failed");
            }
        }
    }
    let final_err = last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "ReplaceFileW timed out")
    });
    if cleared_readonly {
        unsafe {
            let _ = SetFileAttributesW(dest_w.as_ptr(), original_attrs);
        }
    }
    Err(final_err).with_context(|| "ReplaceFileW failed after retries")
}

/// read exactly `buf.len()` bytes from reader, retrying until filled
fn read_exact<R: Read>(mut r: R, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = r.read(buf)?;
        if n == 0 {
            bail!("Unexpected EOF while reading");
        }
        let tmp = buf;
        buf = &mut tmp[n..];
    }
    Ok(())
}

fn ensure_not_symlink(p: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(p)?;
    // Treat any reparse point (symlink, junction, mount point, etc.) as a symlink.
    if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(anyhow!(RSafeKind::SymlinkRefused));
    }
    Ok(())
}

fn get_password(mode: Mode, args: &Args) -> Result<String> {
    if let Some(ref pf) = args.passphrase_file {
        let mut s = fs::read_to_string(pf)
            .with_context(|| format!("Unable to read passphrase file: {}", pf.display()))?;
        // Trim trailing newline/carriage-return only.
        while matches!(s.as_bytes().last(), Some(b'\n' | b'\r')) {
            s.pop();
        }
        return Ok(s);
    }
    match mode {
        Mode::Encrypt => {
            let mut password = prompt_password("Enter password: ")?;
            if !args.no_confirm {
                let confirm = prompt_password("Confirm password: ")?;
                if password != confirm {
                    let mut c = confirm;
                    c.zeroize();
                    password.zeroize();
                    return Err(anyhow!(RSafeKind::PasswordMismatch));
                }
            }
            Ok(password)
        }
        Mode::Decrypt => Ok(prompt_password("Enter password: ")?),
    }
}

/// Very small auto-tuner: increases opslimit until pwhash ~ target_ms (caps at MAX_KDF_OPSLIMIT).
fn calibrate_opslimit(target_ms: u64, memlimit: usize) -> u64 {
    use std::time::Instant;
    let mut ops = OPSLIMIT.max(1);
    let salt = [0u8; SALT_LEN];
    let pw = b"rsafe-calibrate";

    loop {
        let start = Instant::now();
        let _ = crypto_pwhash::pwhash(16, pw, &salt, ops, memlimit, crypto_pwhash::ALG_ARGON2ID13);
        let elapsed = start.elapsed().as_millis() as u64;
        if elapsed >= target_ms || ops >= MAX_KDF_OPSLIMIT {
            break;
        }
        ops = (ops.saturating_mul(2)).min(MAX_KDF_OPSLIMIT);
    }
    ops
}

fn cleanup_orphan_temps(dir: &Path) -> Result<()> {
    let now = SystemTime::now();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(".rsafe.tmp.") {
            let p = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = match meta.modified() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if now.duration_since(modified).unwrap_or_default() > ORPHAN_MAX_AGE {
                let _ = fs::remove_file(&p);
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn os_str_to_wide(s: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}
