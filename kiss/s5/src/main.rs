use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit, Payload}};
use clap::{Parser, ValueEnum};
use fs2::FileExt;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use log::{info, trace, warn};
use zeroize::Zeroize;
use argon2::{Argon2, Algorithm, Version, Params};
use rpassword;

// ---------- Constants ----------
// Magic bytes for identification, including version.
const MAGIC: [u8; 8] = *b"SPSv2\0\0\0"; // Version 2 magic
const SALT_LEN: usize = 16; // Salt for key derivation
const BASE_LEN: usize = 16; // Base for nonce derivation
const TAG_LEN: usize = 16; // Poly1305 tag
const CHUNK: usize = 8 << 20; // 8 MiB chunk size
const KEY_LEN: usize = 32; // 256-bit key
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + BASE_LEN + 8;

// ---------- File Utilities ----------
fn temp_path_near(target: &Path) -> PathBuf {
    let base = target.file_name().unwrap_or_default().to_string_lossy();
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    PathBuf::from(format!(".{}.{}.sps.tmp", base, hex::encode(rnd)))
}

fn atomic_replace(temp: &Path, dst: &Path) -> Result<()> {
    fs::rename(temp, dst).context(format!("Failed to rename {} to {}", temp.display(), dst.display()))?;
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8], iterations: u32, memory: u32, parallelism: u32) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(memory * 1024, iterations, parallelism, Some(KEY_LEN))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    Ok(key)
}

// ---------- Encryption ----------
/// Encrypts the file in-place using XChaCha20-Poly1305 with a password-derived key.
/// 
/// - Generates random salt and nonce base.
/// - Derives key using Argon2id.
/// - Encrypts in chunks with unique nonces (base + chunk index).
/// - AAD for each chunk includes the full header and chunk index to bind chunks and prevent reordering.
/// - Uses atomic replacement via temp file for safety.
fn encrypt_file(input_path: &Path, output_path: &Path, password: &[u8], verbose: bool, iterations: u32, memory: u32, parallelism: u32) -> Result<()> {
    let mut file = File::open(input_path).context(format!("Failed to open input file {}", input_path.display()))?;
    file.lock_exclusive()?;
    let orig_len = file.metadata()?.len();
    if orig_len == 0 {
        warn!("Encrypting empty file: {}", input_path.display());
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut base = [0u8; BASE_LEN];
    OsRng.fill_bytes(&mut base);
    let mut key = derive_key(password, &salt, iterations, memory, parallelism)?;
    let aead = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("Invalid key length: {}", e))?;
    let mut reader = BufReader::new(&mut file);
    let is_in_place = input_path == output_path;
    let tmp = if is_in_place { temp_path_near(input_path) } else { output_path.to_path_buf() };
    let mut out_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .context(format!("Failed to create output file {}", tmp.display()))?;
    out_file.lock_exclusive()?;
    let mut writer = BufWriter::new(&mut out_file);
    // Write header
    let header: [u8; HEADER_LEN] = {
        let mut h = [0u8; HEADER_LEN];
        h[..MAGIC.len()].copy_from_slice(&MAGIC);
        h[MAGIC.len()..MAGIC.len() + SALT_LEN].copy_from_slice(&salt);
        h[MAGIC.len() + SALT_LEN..MAGIC.len() + SALT_LEN + BASE_LEN].copy_from_slice(&base);
        h[MAGIC.len() + SALT_LEN + BASE_LEN..].copy_from_slice(&orig_len.to_le_bytes());
        h
    };
    writer.write_all(&header)?;
    // Encrypt in chunks
    let mut inbuf = vec![0u8; CHUNK];
    let mut processed = 0u64;
    let mut chunk_idx = 0u64;
    while processed < orig_len {
        let n = reader.read(&mut inbuf[..])?;
        if n == 0 {
            break;
        }
        let nonce = {
            let mut nb = [0u8; 24];
            nb[..BASE_LEN].copy_from_slice(&base);
            nb[BASE_LEN..].copy_from_slice(&chunk_idx.to_le_bytes());
            nb
        };
        let aad = {
            let mut a = [0u8; HEADER_LEN + 8];
            a[..HEADER_LEN].copy_from_slice(&header);
            a[HEADER_LEN..].copy_from_slice(&chunk_idx.to_le_bytes());
            a
        };
        let payload = Payload { msg: &inbuf[..n], aad: &aad };
        let ciphertext = aead.encrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        writer.write_all(&ciphertext)?;
        processed += n as u64;
        chunk_idx += 1;
        if verbose {
            trace!("Encrypted chunk {} ({} bytes) - Progress: {:.2}%", chunk_idx, n, (processed as f64 / orig_len as f64) * 100.0);
        }
    }
    if processed != orig_len {
        drop(writer);
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!("Incomplete read during encryption (processed {} of {})", processed, orig_len));
    }
    writer.flush()?;
    drop(writer);
    key.zeroize();
    if is_in_place {
        atomic_replace(&tmp, input_path)?;
    }
    Ok(())
}

// ---------- Decryption ----------
/// Decrypts the file in-place using XChaCha20-Poly1305 with a password-derived key.
/// 
/// - Reads and validates header (magic, salt, base, orig_len).
/// - Derives key using Argon2id.
/// - Decrypts in chunks, verifying AEAD tags (fails on wrong password or corruption).
/// - AAD for each chunk includes the full header and chunk index.
/// - Checks for exact original length and no extra data.
/// - Uses atomic replacement via temp file for safety.
fn decrypt_file(input_path: &Path, output_path: &Path, password: &[u8], verbose: bool, iterations: u32, memory: u32, parallelism: u32) -> Result<()> {
    let mut file = File::open(input_path).context(format!("Failed to open input file {}", input_path.display()))?;
    file.lock_exclusive()?;
    let total_len = file.metadata()?.len();
    if total_len < HEADER_LEN as u64 {
        return Err(anyhow!("File too short for SPS container ({} bytes)", total_len));
    }
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header)?;
    if &header[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("Invalid magic bytes"));
    }
    let salt: [u8; SALT_LEN] = header[MAGIC.len()..MAGIC.len() + SALT_LEN]
        .try_into()
        .map_err(|_| anyhow!("Invalid salt"))?;
    let base: [u8; BASE_LEN] = header[MAGIC.len() + SALT_LEN..MAGIC.len() + SALT_LEN + BASE_LEN]
        .try_into()
        .map_err(|_| anyhow!("Invalid base nonce"))?;
    let orig_len = u64::from_le_bytes(
        header[MAGIC.len() + SALT_LEN + BASE_LEN..]
            .try_into()
            .map_err(|_| anyhow!("Invalid original length"))?,
    );
    let mut key = derive_key(password, &salt, iterations, memory, parallelism)?;
    let aead = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("Invalid key length: {}", e))?;
    let mut reader = BufReader::new(&mut file);
    let is_in_place = input_path == output_path;
    let tmp = if is_in_place { temp_path_near(input_path) } else { output_path.to_path_buf() };
    let mut out_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .context(format!("Failed to create output file {}", tmp.display()))?;
    out_file.lock_exclusive()?;
    let mut writer = BufWriter::new(&mut out_file);
    let mut inbuf = vec![0u8; CHUNK + TAG_LEN];
    let mut processed = 0u64;
    let mut chunk_idx = 0u64;
    while processed < orig_len {
        let expected_plaintext_len = std::cmp::min((orig_len - processed) as usize, CHUNK);
        if expected_plaintext_len == 0 {
            break;
        }
        let to_read = expected_plaintext_len + TAG_LEN;
        let n = reader.read(&mut inbuf[..to_read])?;
        if n != to_read {
            drop(writer);
            let _ = fs::remove_file(&tmp);
            return Err(anyhow!("Incomplete read during decryption (expected {}, got {}) - possible corrupted or truncated container", to_read, n));
        }
        let nonce = {
            let mut nb = [0u8; 24];
            nb[..BASE_LEN].copy_from_slice(&base);
            nb[BASE_LEN..].copy_from_slice(&chunk_idx.to_le_bytes());
            nb
        };
        let aad = {
            let mut a = [0u8; HEADER_LEN + 8];
            a[..HEADER_LEN].copy_from_slice(&header);
            a[HEADER_LEN..].copy_from_slice(&chunk_idx.to_le_bytes());
            a
        };
        let payload = Payload { msg: &inbuf[..to_read], aad: &aad };
        let plaintext = aead.decrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| anyhow!("Decryption failed: wrong password or corrupted file (chunk {})", chunk_idx))?;
        if plaintext.len() != expected_plaintext_len {
            drop(writer);
            let _ = fs::remove_file(&tmp);
            return Err(anyhow!("Decrypted chunk length mismatch (expected {}, got {})", expected_plaintext_len, plaintext.len()));
        }
        writer.write_all(&plaintext)?;
        processed += expected_plaintext_len as u64;
        chunk_idx += 1;
        if verbose {
            trace!("Decrypted chunk {} ({} bytes) - Progress: {:.2}%", chunk_idx, expected_plaintext_len, (processed as f64 / orig_len as f64) * 100.0);
        }
    }
    writer.flush()?;
    let decrypted_len = writer.get_ref().metadata()?.len();
    if decrypted_len != orig_len {
        drop(writer);
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!("Final length mismatch (expected {}, got {})", orig_len, decrypted_len));
    }
    let current_pos = file.stream_position()?;
    if current_pos != total_len {
        drop(writer);
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!("Extra data after ciphertext ({} extra bytes)", total_len - current_pos));
    }
    drop(writer);
    key.zeroize();
    if is_in_place {
        atomic_replace(&tmp, input_path)?;
    }
    Ok(())
}

// ---------- CLI ----------
#[derive(ValueEnum, Clone, Copy)]
enum ForceMode {
    Encrypt,
    Decrypt,
}

#[derive(Parser)]
#[command(name = "sps")]
#[command(about = "Simple file encryption/decryption with XChaCha20-Poly1305 using password-derived key.\nFiles must be in the current directory (no paths).")]
struct Cli {
    /// The filename to process
    filename: String,

    /// Output filename (defaults to input for in-place)
    #[arg(long)]
    output: Option<String>,

    /// Force operation (encrypt or decrypt)
    #[arg(long, value_enum)]
    force: Option<ForceMode>,

    /// Enable verbose logging
    #[arg(long)]
    verbose: bool,

    /// Argon2 iterations (default: 2)
    #[arg(long, default_value_t = 2)]
    iterations: u32,

    /// Argon2 memory in MiB (default: 19)
    #[arg(long, default_value_t = 19)]
    memory: u32,

    /// Argon2 parallelism (default: 1)
    #[arg(long, default_value_t = 1)]
    parallelism: u32,

    /// Confirm password on encryption (default: true)
    #[arg(long, default_value_t = true)]
    confirm_password: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::builder()
        .filter_level(if cli.verbose { log::LevelFilter::Trace } else { log::LevelFilter::Warn })
        .init();

    let filename = cli.filename.trim();
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") || filename.starts_with('.') {
        return Err(anyhow!("Invalid filename: paths and hidden files not allowed"));
    }
    let input_path = PathBuf::from(filename);
    if !input_path.exists() || !input_path.is_file() {
        return Err(anyhow!("File does not exist or is not a regular file: {}", filename));
    }

    let output_path = cli.output.map(PathBuf::from).unwrap_or_else(|| input_path.clone());

    let mut file = File::open(&input_path)?;
    let mut magic_buf = [0u8; MAGIC.len()];
    let read_bytes = file.read(&mut magic_buf)?;
    let has_magic = read_bytes == MAGIC.len() && magic_buf == MAGIC;
    drop(file);

    let should_encrypt = match cli.force {
        Some(ForceMode::Encrypt) => true,
        Some(ForceMode::Decrypt) => false,
        None => !has_magic,
    };

    let mut password = rpassword::prompt_password("Enter password: ")?;

    if should_encrypt {
        if cli.confirm_password {
            let mut confirm = rpassword::prompt_password("Confirm password: ")?;
            if password != confirm {
                password.zeroize();
                confirm.zeroize();
                return Err(anyhow!("Passwords don't match"));
            }
            confirm.zeroize();
        }
        info!("Encrypting file: {} -> {}", input_path.display(), output_path.display());
    } else {
        info!("Decrypting file: {} -> {}", input_path.display(), output_path.display());
    }

    let pw_bytes = password.into_bytes();
    let mut pw_bytes = pw_bytes; // mut for zeroize

    let res = if should_encrypt {
        encrypt_file(&input_path, &output_path, &pw_bytes, cli.verbose, cli.iterations, cli.memory, cli.parallelism)
    } else {
        decrypt_file(&input_path, &output_path, &pw_bytes, cli.verbose, cli.iterations, cli.memory, cli.parallelism)
    };

    pw_bytes.zeroize();

    res?;

    println!("ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_file(content: &[u8]) -> Result<NamedTempFile> {
        let mut file = NamedTempFile::new()?;
        file.write_all(content)?;
        file.flush()?;
        Ok(file)
    }

    #[test]
    fn test_derive_key() -> Result<()> {
        let password = b"testpass";
        let salt = [0u8; SALT_LEN];
        let key = derive_key(password, &salt, 2, 19, 1)?;
        assert_eq!(key.len(), KEY_LEN);
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_small() -> Result<()> {
        let content = b"Hello, world!";
        let file = create_test_file(content)?;
        let path = file.path().to_path_buf();
        let pw = b"password";
        encrypt_file(&path, &path, pw, false, 2, 19, 1)?;
        decrypt_file(&path, &path, pw, false, 2, 19, 1)?;
        let mut decrypted = Vec::new();
        let mut f = File::open(&path)?;
        f.read_to_end(&mut decrypted)?;
        assert_eq!(decrypted, content);
        Ok(())
    }

    #[test]
    fn test_decrypt_wrong_password() -> Result<()> {
        let content = b"Hello, world!";
        let file = create_test_file(content)?;
        let path = file.path().to_path_buf();
        let pw = b"password";
        encrypt_file(&path, &path, pw, false, 2, 19, 1)?;
        let wrong_pw = b"wrong";
        let result = decrypt_file(&path, &path, wrong_pw, false, 2, 19, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Decryption failed"));
        Ok(())
    }

    #[test]
    fn test_empty_file() -> Result<()> {
        let content = b"";
        let file = create_test_file(content)?;
        let path = file.path().to_path_buf();
        let pw = b"password";
        encrypt_file(&path, &path, pw, false, 2, 19, 1)?;
        decrypt_file(&path, &path, pw, false, 2, 19, 1)?;
        let mut decrypted = Vec::new();
        let mut f = File::open(&path)?;
        f.read_to_end(&mut decrypted)?;
        assert_eq!(decrypted, content);
        Ok(())
    }
}