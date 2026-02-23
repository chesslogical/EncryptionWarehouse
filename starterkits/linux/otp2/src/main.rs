//! otp – one-time-pad style XOR transformer (in-place, Linux-only)
//!
//! **NOTE TO FUTURE SELF: THIS BINARY IS INTENDED ONLY FOR LINUX (Fedora 43+).**
//! **NO WINDOWS SUPPORT. DO NOT RE-ADD WINAPI OR ReplaceFileW LOGIC.**
//!
//! Rules:
//! - Executable, input file, and key file must all be in the SAME directory.
//! - Key file MUST be named "key.key" (next to the executable); if missing, exit.
//! - Key wraps automatically if shorter than the input.
//! - Always writes in place safely: temp file in same dir + atomic rename.
//!
//! Security: Real OTP only if key is random, ≥ plaintext length, used once.
//!           Otherwise: repeating-key XOR (obfuscation only).
//!
//! Optimizations for Fedora 43:
//! - Uses `fs::rename` for atomic replace (same-dir guaranteed)
//! - Strips setuid/setgid bits on temp file for safety
//! - Preserves original file mode (sans dangerous bits)
//! - File locking + TOCTOU identity checks
//! - Zeroizes sensitive buffers
//! - Directory fsync after rename

#![deny(unsafe_code)]
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use fs2::FileExt;
use same_file::is_same_file;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use tempfile::Builder as TempBuilder;
use zeroize::Zeroize;

/* ---------------- CLI --------------------------------------------------- */
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Simple OTP-style XOR transformer (in-place, Linux-only). Requires key.key next to exe."
)]
struct Args {
    /// INPUT file name (positional). Relative paths resolved relative to executable directory.
    #[arg(value_name = "INPUT")]
    input: PathBuf,
}

/* ---------------- Constants -------------------------------------------- */
const BUF_CAP: usize = 64 * 1024; // 64 KiB — good for modern SSDs
const REQUIRED_KEY_FILE: &str = "key.key";
const MODE_SUID: u32 = 0o4000;
const MODE_SGID: u32 = 0o2000;

/* ---------------- Helpers ---------------------------------------------- */
fn canonical_parent(path: &Path) -> Result<PathBuf> {
    let c = fs::canonicalize(path)
        .with_context(|| format!("canonicalizing path '{}'", path.display()))?;
    c.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("cannot get parent for '{}'", c.display()))
}

fn ensure_same_dir(path: &Path, dir: &Path, what: &str) -> Result<()> {
    let p_parent = canonical_parent(path)?;
    let dir_canon = fs::canonicalize(dir)?;
    let same_path = p_parent == dir_canon;
    let same_identity = is_same_file(&p_parent, &dir_canon).unwrap_or(false);
    if !(same_path || same_identity) {
        bail!(
            "{} must be in the same directory as the executable.\n {} is in: {}\n exe is in: {}",
            what,
            what,
            p_parent.display(),
            dir_canon.display()
        );
    }
    Ok(())
}

/// RAII guard to remove temp file on drop unless disarmed
struct TempGuard(Option<PathBuf>);
impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(&p);
        }
    }
}

/// fsync a directory (required after rename for durability)
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let f = OpenOptions::new().read(true).open(path)?;
    f.sync_all()
}

/* ---------------- Main -------------------------------------------------- */
fn main() -> Result<()> {
    let t0 = Instant::now();
    let args = Args::parse();

    // === Determine executable directory (the only allowed dir) ===
    let exe = std::env::current_exe().context("cannot determine path to executable")?;
    let exe_dir = exe.parent().ok_or_else(|| anyhow!("cannot determine executable directory"))?;
    let exe_dir = fs::canonicalize(exe_dir).context("canonicalizing executable directory")?;

    // === Resolve paths ===
    let key_path = exe_dir.join(REQUIRED_KEY_FILE);
    let input_path = if args.input.is_absolute() {
        args.input.clone()
    } else {
        exe_dir.join(&args.input)
    };

    if !input_path.exists() {
        bail!("input file '{}' does not exist", input_path.display());
    }

    ensure_same_dir(&input_path, &exe_dir, "Input file")?;

    // === Safety: refuse to transform key or self ===
    if key_path.exists() && is_same_file(&input_path, &key_path)? {
        bail!("refusing to transform '{}'", REQUIRED_KEY_FILE);
    }
    if is_same_file(&input_path, &exe)? {
        bail!("refusing to transform the executable itself");
    }

    // === Must be a regular file ===
    if !fs::metadata(&input_path)?.is_file() {
        bail!("refusing to transform non-regular file '{}'", input_path.display());
    }

    // === Open + lock input (exclusive) ===
    let mut in_f = File::open(&input_path)
        .with_context(|| format!("opening input '{}'", input_path.display()))?;
    in_f.lock_exclusive().context("locking input file")?;

    // === Re-check identity after lock (close race) ===
    if key_path.exists() && is_same_file(&input_path, &key_path)? {
        bail!("refusing to transform '{}'", REQUIRED_KEY_FILE);
    }
    if is_same_file(&input_path, &exe)? {
        bail!("refusing to transform the executable itself");
    }

    // === Open + lock key (shared), ensure non-empty ===
    let mut key_f = File::open(&key_path)
        .with_context(|| format!("opening key '{}'", key_path.display()))?;
    key_f.lock_shared().context("locking key file")?;
    if key_f.metadata()?.len() == 0 {
        bail!("key file is empty");
    }

    // === Capture original metadata (for mode + identity) ===
    let orig_meta = in_f.metadata()?;
    let (_orig_mode, effective_mode) = {
        use std::os::unix::fs::PermissionsExt;
        let m = orig_meta.permissions().mode();
        let eff = m & !MODE_SUID & !MODE_SGID; // strip setuid/setgid
        (m, eff)
    };
    let orig_id = {
        use std::os::unix::fs::MetadataExt;
        (orig_meta.dev(), orig_meta.ino())
    };

    // === Create temp file in same directory ===
    let tmp = TempBuilder::new()
        .prefix(".otp-tmp-")
        .tempfile_in(&exe_dir)
        .context("creating temporary file")?;
    let (mut out_f, tmp_path) = tmp.keep().context("persisting temp file")?;
    let mut tmp_guard = TempGuard(Some(tmp_path.clone()));
    out_f.lock_exclusive().context("locking temp file")?;

    // === Set temp file permissions (match original, sans setuid/setgid) ===
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, PermissionsExt::from_mode(effective_mode))
            .context("setting temp file permissions")?;
    }

    // === XOR transformation with key wrapping ===
    let mut data_buf = vec![0u8; BUF_CAP];
    let mut key_buf = vec![0u8; BUF_CAP];

    loop {
        let n = in_f.read(&mut data_buf)?;
        if n == 0 { break; }

        fill_key_slice(&mut key_f, &mut key_buf[..n])?;
        for (d, k) in data_buf[..n].iter_mut().zip(&key_buf[..n]) {
            *d ^= *k;
        }
        out_f.write_all(&data_buf[..n])?;
        data_buf[..n].zeroize();
        key_buf[..n].zeroize();
    }

    out_f.flush()?;
    out_f.sync_all()?; // ensure data is on disk

    // === Close files before rename ===
    drop(in_f);
    drop(key_f);
    drop(out_f);

    // === Final TOCTOU: verify input file wasn't replaced ===
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(&input_path)
            .with_context(|| format!("stat input before replace: {}", input_path.display()))?;
        let cur_id = (m.dev(), m.ino());
        if cur_id != orig_id {
            bail!("input file replaced during processing — aborting");
        }
    }

    // === Atomic replace via rename (same directory → atomic) ===
    fs::rename(&tmp_path, &input_path)
        .with_context(|| format!("replacing '{}'", input_path.display()))?;

    // Success: disarm cleanup
    tmp_guard.0 = None;

    // === Ensure directory entry is durable ===
    fsync_dir(&exe_dir).context("fsync directory after rename")?;

    eprintln!(
        "Success: in-place XOR '{}' using key 'key.key' in {:.2?}",
        input_path.file_name().unwrap_or_default().to_string_lossy(),
        t0.elapsed()
    );

    Ok(())
}

/* ---------------- Key fill with wrap ----------------------------------- */
fn fill_key_slice<R: Read + Seek>(key: &mut R, dest: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < dest.len() {
        let n = key.read(&mut dest[filled..])?;
        if n == 0 {
            key.seek(SeekFrom::Start(0))?;
            let n2 = key.read(&mut dest[filled..])?;
            if n2 == 0 {
                bail!("key file became unreadable");
            }
            filled += n2;
        } else {
            filled += n;
        }
    }
    Ok(())
}
