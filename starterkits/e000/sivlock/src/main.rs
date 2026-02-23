use anyhow::{bail, Context, Result};
use clap::Parser;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aead::stream::{Nonce, StreamBE32};
use aead::stream::{NewStream, StreamPrimitive}; // for .from_aead(...), .encryptor(), .decryptor()
use aead::{KeyInit, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use rpassword::prompt_password;
use sha2::Sha256;
use zeroize::Zeroize;
use core::ffi::c_void; // for typed nulls in ReplaceFileW

/// 16-byte AEAD tag per segment
const AEAD_TAG_LEN: usize = 16;
const MAGIC: &[u8; 4] = b"AGSV";
const VERSION: u8 = 1;
const KDF_ID_ARGON2ID: u8 = 1;

// Hardening limits (kept liberal to avoid false negatives)
const MIN_CHUNK_LOG2: u8 = 10;
const MAX_CHUNK_LOG2: u8 = 30;
const MAX_LANES: u32 = 32;
const MAX_AD_LEN: usize = 64 * 1024; // 64 KiB is plenty for labels
const MAX_SALT_LEN: usize = 64;      // salts beyond this are unnecessary
const MIN_SALT_LEN_NON_RAW: usize = 16;

// Argon2 plausibility bounds (liberal)
const MIN_M_COST_MIB: u32 = 1;           // >= 1 MiB
const MAX_M_COST_MIB: u32 = 262_144;     // <= 256 GiB
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 1_000;

/// CLI: auto-only — process one file in place (encrypt if plaintext; decrypt if SIVLOCK)
#[derive(Parser)]
#[command(author, version, about="AES-256-GCM-SIV file encryption (auto mode, STREAM, Argon2id)")]
struct Cli {
    /// File to process in place (auto encrypt/decrypt)
    #[arg(value_name="FILE")]
    input: PathBuf,

    /// Associated data to bind on encryption (stored+authenticated in header)
    #[arg(long)]
    ad: Option<String>,

    /// Chunk size as power of two (default 20 = 1 MiB) [encryption only]
    #[arg(long, default_value_t=20)]
    chunk_size_log2: u8,

    /// Argon2 memory cost in MiB (default 256) [encryption only]
    #[arg(long, default_value_t=256)]
    kdf_mem_mib: u32,

    /// Argon2 time cost (default 3) [encryption only]
    #[arg(long, default_value_t=3)]
    kdf_time: u32,

    /// Argon2 lanes / parallelism (default 1) [encryption only]
    #[arg(long, default_value_t=1)]
    kdf_lanes: u32,

    /// Use a key file instead of passphrase (32 raw bytes)
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Force encrypt even if file looks like SIVLOCK (discouraged; for emergencies)
    #[arg(long)]
    force_encrypt: bool,

    /// Force decrypt even if file does not look like SIVLOCK (will likely fail)
    #[arg(long)]
    force_decrypt: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.force_encrypt && cli.force_decrypt {
        bail!("--force-encrypt and --force-decrypt are mutually exclusive");
    }

    auto_cmd(
        &cli.input,
        cli.ad.as_deref(),
        cli.chunk_size_log2,
        cli.kdf_mem_mib,
        cli.kdf_time,
        cli.kdf_lanes,
        cli.key_file.as_ref(),
        cli.force_encrypt,
        cli.force_decrypt,
    )
}

/// Auto-detect mode with **strict header validation**; replaces in place atomically.
/// - If file starts with AGSV and header is plausible & size-consistent -> decrypt
/// - If file starts with AGSV but header looks corrupted -> refuse (unless --force-encrypt)
/// - Else -> encrypt
fn auto_cmd(
    input: &Path,
    ad: Option<&str>,
    chunk_size_log2: u8,
    kdf_mem_mib: u32, kdf_time: u32, kdf_lanes: u32,
    key_file: Option<&PathBuf>,
    force_encrypt: bool,
    force_decrypt: bool,
) -> Result<()> {
    // Force overrides (expert use only)
    if force_encrypt {
        let out_buf = input.to_path_buf();
        return encrypt_cmd(input, Some(&out_buf), ad, chunk_size_log2, kdf_mem_mib, kdf_time, kdf_lanes, key_file);
    }
    if force_decrypt {
        let out_buf = input.to_path_buf();
        return decrypt_cmd(input, Some(&out_buf), ad, key_file);
    }

    let starts_with_magic = starts_with_magic_agsv(input)?;
    if starts_with_magic {
        match looks_like_agsv_strict(input) {
            Ok(true) => {
                let out_buf = input.to_path_buf();
                decrypt_cmd(input, Some(&out_buf), ad, key_file)
            }
            Ok(false) => {
                // Safety first: do NOT encrypt something that claims AGSV but looks malformed.
                bail!(
                    "File begins with 'AGSV' but has an invalid/malformed header or size mismatch.\n\
                     Refusing to encrypt in auto mode. If you truly want to treat it as plaintext, \
                     rerun with --force-encrypt (NOT recommended unless you know what you're doing)."
                );
            }
            Err(e) => Err(e),
        }
    } else {
        let out_buf = input.to_path_buf();
        encrypt_cmd(input, Some(&out_buf), ad, chunk_size_log2, kdf_mem_mib, kdf_time, kdf_lanes, key_file)
    }
}

/// Quick check: does the file start with the 4-byte magic?
fn starts_with_magic_agsv(path: &Path) -> Result<bool> {
    let mut f = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    Ok(n == 4 && &magic == MAGIC)
}

/// Strict plausibility + size-consistency check.
/// Returns true only if header fields look sane *and* file size matches header.
/// Never reads associated data contents (only lengths), so it's safe & fast.
fn looks_like_agsv_strict(path: &Path) -> Result<bool> {
    let meta = fs::metadata(path)?;
    let file_len: u64 = meta.len();

    // Minimal header (no salt/ad) + 32-byte MAC
    const MIN_HEADER_NO_SALT_NO_AD: usize = 35; // see build_header() layout
    if file_len < (MIN_HEADER_NO_SALT_NO_AD + 32) as u64 {
        return Ok(false);
    }

    let mut r = BufReader::new(File::open(path)?);

    // MAGIC
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Ok(false);
    }

    // version, flags, kdf_id, m_cost_kib(u32), t_cost(u32), lanes(u8), salt_len(u8)
    let mut fixed = [0u8; 1 + 1 + 1 + 4 + 4 + 1 + 1];
    r.read_exact(&mut fixed)?;
    let version = fixed[0];
    let flags = fixed[1];
    let kdf_id = fixed[2];
    let m_cost_kib = u32::from_le_bytes(fixed[3..7].try_into().unwrap());
    let t_cost = u32::from_le_bytes(fixed[7..11].try_into().unwrap());
    let lanes = fixed[11].max(1) as u32;
    let salt_len = fixed[12] as usize;

    if version != VERSION { return Ok(false); }
    if kdf_id != KDF_ID_ARGON2ID { return Ok(false); }
    if lanes == 0 || lanes > MAX_LANES { return Ok(false); }

    // Argon2 params plausibility
    // - m_cost_kib must be a multiple of 1024 (we store MiB * 1024)
    if m_cost_kib % 1024 != 0 { return Ok(false); }
    let mem_mib = m_cost_kib / 1024;
    if mem_mib < MIN_M_COST_MIB || mem_mib > MAX_M_COST_MIB { return Ok(false); }
    if t_cost < MIN_T_COST || t_cost > MAX_T_COST { return Ok(false); }

    let raw_key_mode = (flags & 0x01) != 0;
    if raw_key_mode {
        if salt_len != 0 { return Ok(false); }
    } else {
        if salt_len < MIN_SALT_LEN_NON_RAW || salt_len > MAX_SALT_LEN { return Ok(false); }
    }

    // Skip salt (we don't need its contents)
    if salt_len > 0 {
        let mut skip = vec![0u8; salt_len];
        r.read_exact(&mut skip)?;
    }

    // nonce_prefix(7), chunk_log2(1), plaintext_len(8), ad_len(2)
    let mut tail = [0u8; 7 + 1 + 8 + 2];
    r.read_exact(&mut tail)?;
    let _nonce_prefix = &tail[0..7];
    let chunk_log2 = tail[7];
    let plaintext_len = u64::from_le_bytes(tail[8..16].try_into().unwrap());
    let ad_len = u16::from_le_bytes(tail[16..18].try_into().unwrap()) as usize;

    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&chunk_log2) { return Ok(false); }
    if ad_len > MAX_AD_LEN { return Ok(false); }

    // Compute expected total size from header fields
    let header_len = (MIN_HEADER_NO_SALT_NO_AD + salt_len + ad_len) as u128;
    let chunk_size = 1u128 << chunk_log2;
    let pt = plaintext_len as u128;

    let chunks = if pt == 0 { 0 } else { (pt + (chunk_size - 1)) / chunk_size };
    let ciphertext_len = pt + (chunks * (AEAD_TAG_LEN as u128));
    let expected_total = header_len + 32u128 + ciphertext_len;

    Ok(expected_total == file_len as u128)
}

fn encrypt_cmd(
    input: &Path,
    output: Option<&PathBuf>,
    ad: Option<&str>,
    chunk_size_log2: u8,
    kdf_mem_mib: u32, kdf_time: u32, kdf_lanes: u32,
    key_file: Option<&PathBuf>,
) -> Result<()> {
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&chunk_size_log2) {
        bail!("chunk_size_log2 out of range ({}..={} recommended)", MIN_CHUNK_LOG2, MAX_CHUNK_LOG2);
    }
    let chunk_size: usize = 1usize << chunk_size_log2;

    let in_file = File::open(input).with_context(|| format!("open input {:?}", input))?;
    let in_len = in_file.metadata()?.len();
    let mut reader = BufReader::new(in_file);

    let out_path = output.cloned().unwrap_or_else(|| {
        let mut p = input.to_path_buf();
        p.set_extension("sgsv");
        p
    });
    let tmp_path = tmp_name(&out_path);

    // Create temp file in the same directory so the replace is same-volume.
    let out_file = File::create(&tmp_path)
        .with_context(|| format!("create temp {:?}", tmp_path))?;
    let mut writer = BufWriter::new(out_file);

    // --- Key material ---
    let (mut aead_key, mut header_mac_key, salt) = if let Some(kpath) = key_file {
        let mut f = File::open(kpath).with_context(|| format!("open key_file {:?}", kpath))?;
        let mut key = vec![];
        f.read_to_end(&mut key)?;
        if key.len() != 32 { bail!("key_file must contain exactly 32 raw key bytes"); }
        let header_mac_key = hkdf_expand(&key, b"header-mac", 32)?;
        (key, header_mac_key, vec![]) // salt_len=0 indicates raw-key mode
    } else {
        let pass = prompt_password("Enter passphrase: ")?;
        let pass_confirm = prompt_password("Confirm passphrase: ")?;
        if pass != pass_confirm { bail!("passphrases do not match"); }
        let mut pass = pass; // will be zeroized later
        let (aead_key, header_mac_key, salt) =
            kdf_argon2id_new_salt(&mut pass, kdf_mem_mib, kdf_time, kdf_lanes, 16)?;
        pass.zeroize();
        (aead_key, header_mac_key, salt)
    };

    // 7-byte nonce prefix for STREAM (the last 5 bytes are counter + last-flag)
    let mut nonce_prefix = [0u8; 7];
    rand::thread_rng().fill_bytes(&mut nonce_prefix);

    // Build header (without MAC), then MAC and write
    let ad_bytes = ad.unwrap_or("").as_bytes();
    if ad_bytes.len() > MAX_AD_LEN {
        bail!("associated data too long (max {} bytes)", MAX_AD_LEN);
    }
    let header = build_header(
        in_len, chunk_size_log2, &salt, &nonce_prefix,
        key_file.is_some(), // flags: 0 or 1<<0 for "raw key"
        kdf_mem_mib, kdf_time, kdf_lanes, ad_bytes
    );
    let header_mac = blake3::keyed_hash(
        header_mac_key.as_slice().try_into().expect("32-byte key"),
        &header
    ).as_bytes().to_vec();

    writer.write_all(&header)?;
    writer.write_all(&header_mac)?;
    writer.flush()?;

    // Prepare AEAD (AES-256-GCM-SIV) and STREAM encryptor
    let aead = Aes256GcmSiv::new_from_slice(&aead_key)
        .expect("aead key length must be 32 bytes");
    let nonce = Nonce::<Aes256GcmSiv, StreamBE32<Aes256GcmSiv>>::from_slice(&nonce_prefix);
    let mut enc = StreamBE32::<Aes256GcmSiv>::from_aead(aead, &nonce).encryptor();

    // Stream encrypt
    let mut buf = vec![0u8; chunk_size];
    let mut read_total: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            if read_total != in_len {
                bail!("unexpected EOF: read {} expected {}", read_total, in_len);
            }
            break; // nothing left to process
        }
        read_total += n as u64;
        let last = read_total == in_len;

        if last {
            // consumes `enc`
            let ct = enc.encrypt_last(Payload {
                msg: &buf[..n],
                aad: header.as_slice(),
            })?;
            writer.write_all(&ct)?;
            break;
        } else {
            let ct = enc.encrypt_next(Payload {
                msg: &buf[..n],
                aad: header.as_slice(),
            })?;
            writer.write_all(&ct)?;
        }
    }
    writer.flush()?;

    // Ensure data is durably on disk before replacing
    let out_file = writer.into_inner()?; // recover File
    out_file.sync_all()?;
    drop(out_file);

    // Close input reader before replacing on Windows
    drop(reader);

    // Replace destination atomically (Windows uses ReplaceFileW)
    atomic_replace_or_rename(&out_path, &tmp_path)?;

    // Zero key material
    zeroize_vec(&mut aead_key);
    zeroize_vec(&mut header_mac_key);
    Ok(())
}

fn decrypt_cmd(
    input: &Path,
    output: Option<&PathBuf>,
    ad: Option<&str>,
    key_file: Option<&PathBuf>,
) -> Result<()> {
    let mut reader = BufReader::new(File::open(input)?);
    // Read header (with caps to avoid unbounded allocations)
    let (header_bytes, parsed) = read_and_parse_header(&mut reader)?;

    // Optional AD check if user supplied one on the CLI
    if let Some(user_ad) = ad {
        if user_ad.as_bytes() != parsed.ad.as_slice() {
            bail!("associated data mismatch: the file was sealed with different AD");
        }
    }

    // Select key derivation
    let (mut aead_key, mut header_mac_key) = if parsed.raw_key_mode {
        let kpath = key_file.ok_or_else(|| anyhow::anyhow!("--key-file required for this file"))?;
        let mut f = File::open(kpath)?;
        let mut key = vec![];
        f.read_to_end(&mut key)?;
        if key.len() != 32 { bail!("key_file must contain exactly 32 raw key bytes"); }
        let header_mac_key = hkdf_expand(&key, b"header-mac", 32)?;
        (key, header_mac_key)
    } else {
        let pass = prompt_password("Enter passphrase: ")?;
        let mut pass = pass; // zeroize later
        // IMPORTANT: use the salt stored in the header
        let (aead_key, header_mac_key) =
            kdf_argon2id_with_salt(&mut pass, parsed.kdf_mem_mib, parsed.kdf_time, parsed.kdf_lanes, &parsed.salt)?;
        pass.zeroize();
        (aead_key, header_mac_key)
    };

    // Verify header MAC (authenticate header fields and AD)
    let mut mac_buf = [0u8; 32];
    reader.read_exact(&mut mac_buf)?;
    let expected = blake3::keyed_hash(
        header_mac_key.as_slice().try_into().expect("32-byte key"),
        &header_bytes
    );
    if expected.as_bytes() != &mac_buf {
        bail!("header authentication failed (wrong password or corrupted file)");
    }

    // Determine output path (for in-place, this will be the same as input)
    let out_path = output.cloned().unwrap_or_else(|| {
        let mut p = input.to_path_buf();
        p.set_extension("dec");
        p
    });
    let tmp_path = tmp_name(&out_path);

    // Create temp output in same dir
    let out_file = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(out_file);

    // Init AEAD stream decryptor
    let aead = Aes256GcmSiv::new_from_slice(&aead_key)
        .expect("aead key length must be 32 bytes");
    let nonce = Nonce::<Aes256GcmSiv, StreamBE32<Aes256GcmSiv>>::from_slice(&parsed.nonce_prefix);
    let mut dec = StreamBE32::<Aes256GcmSiv>::from_aead(aead, &nonce).decryptor();

    let header_for_aad = header_bytes; // use same AAD as encryption side
    let chunk_size = 1usize << parsed.chunk_size_log2;
    let mut remaining = parsed.plaintext_len;
    let mut ct_buf = vec![0u8; (chunk_size + AEAD_TAG_LEN).max(4096)];

    while remaining > 0 {
        let pt_this = (remaining as usize).min(chunk_size);
        let ct_expected = pt_this + AEAD_TAG_LEN;

        // Read exactly one ciphertext segment
        let mut read = 0usize;
        while read < ct_expected {
            let n = reader.read(&mut ct_buf[read..ct_expected])?;
            if n == 0 { bail!("truncated ciphertext"); }
            read += n;
        }

        let last = remaining as usize == pt_this;
        if last {
            // consumes `dec`
            let pt = dec.decrypt_last(Payload {
                msg: &ct_buf[..ct_expected],
                aad: &header_for_aad,
            })?;
            writer.write_all(&pt)?;
            break; // stop using `dec` after it's consumed
        } else {
            let pt = dec.decrypt_next(Payload {
                msg: &ct_buf[..ct_expected],
                aad: &header_for_aad,
            })?;
            writer.write_all(&pt)?;
            remaining -= pt_this as u64; // only needed when we keep looping
        }
    }
    writer.flush()?;

    // Ensure data is durably on disk before replacing
    let out_file = writer.into_inner()?; // recover File
    out_file.sync_all()?;
    drop(out_file);

    // Close input reader before replacing on Windows
    drop(reader);

    // Replace destination atomically
    atomic_replace_or_rename(&out_path, &tmp_path)?;

    // Zero key material
    zeroize_vec(&mut aead_key);
    zeroize_vec(&mut header_mac_key);
    Ok(())
}

/// Build the serialized header (without the 32-byte MAC).
#[allow(clippy::too_many_arguments)]
fn build_header(
    plaintext_len: u64,
    chunk_size_log2: u8,
    salt: &[u8],
    nonce_prefix: &[u8; 7],
    raw_key_mode: bool,
    kdf_mem_mib: u32, kdf_time: u32, kdf_lanes: u32,
    ad: &[u8],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(128 + salt.len() + ad.len());
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    let mut flags = 0u8;
    if raw_key_mode { flags |= 0x01; }
    h.push(flags);
    h.push(KDF_ID_ARGON2ID);
    h.extend_from_slice(&(kdf_mem_mib * 1024).to_le_bytes()); // m_cost in KiB
    h.extend_from_slice(&kdf_time.to_le_bytes());
    h.push((kdf_lanes as u8).max(1));
    h.push(salt.len() as u8);
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce_prefix);
    h.push(chunk_size_log2);
    h.extend_from_slice(&plaintext_len.to_le_bytes());
    h.extend_from_slice(&(ad.len() as u16).to_le_bytes());
    h.extend_from_slice(ad);
    h
}

/// Parse header (with sane caps) and return (raw_header_bytes_without_mac, parsed_fields)
fn read_and_parse_header<R: Read>(r: &mut R) -> Result<(Vec<u8>, ParsedHeader)> {
    // magic, ver, flags, kdf_id, m_cost, t_cost, lanes, salt_len
    let mut fixed = [0u8; 4 + 1 + 1 + 1 + 4 + 4 + 1 + 1];
    r.read_exact(&mut fixed)?;
    if &fixed[0..4] != MAGIC { bail!("bad magic"); }
    let version = fixed[4];
    if version != VERSION { bail!("unsupported version {}", version); }
    let flags = fixed[5];
    let kdf_id = fixed[6];
    if kdf_id != KDF_ID_ARGON2ID { bail!("unsupported KDF"); }
    let m_cost_kib = u32::from_le_bytes(fixed[7..11].try_into().unwrap());
    let t_cost = u32::from_le_bytes(fixed[11..15].try_into().unwrap());
    let lanes = fixed[15].max(1) as u32;
    let salt_len = fixed[16] as usize;

    if lanes == 0 || lanes > MAX_LANES { bail!("invalid lanes"); }

    let raw_key_mode = (flags & 0x01) != 0;
    if raw_key_mode {
        if salt_len != 0 { bail!("raw-key file must have zero salt"); }
    } else {
        if salt_len < MIN_SALT_LEN_NON_RAW || salt_len > MAX_SALT_LEN { bail!("invalid salt length"); }
    }

    let mut salt = vec![0u8; salt_len];
    if salt_len > 0 { r.read_exact(&mut salt)?; }

    let mut nonce_prefix = [0u8; 7];
    r.read_exact(&mut nonce_prefix)?;
    let mut rest = [0u8; 1 + 8 + 2]; // chunk_log2, plaintext_len, ad_len
    r.read_exact(&mut rest)?;
    let chunk_log2 = rest[0];
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&chunk_log2) { bail!("invalid chunk_size_log2"); }
    let plaintext_len = u64::from_le_bytes(rest[1..9].try_into().unwrap());
    let ad_len = u16::from_le_bytes(rest[9..11].try_into().unwrap()) as usize;
    if ad_len > MAX_AD_LEN { bail!("associated data too long"); }

    // Read AD
    let mut ad = vec![0u8; ad_len];
    if ad_len > 0 { r.read_exact(&mut ad)?; }

    // Reconstruct header bytes (same as written during encryption)
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(version);
    header.push(flags);
    header.push(kdf_id);
    header.extend_from_slice(&m_cost_kib.to_le_bytes());
    header.extend_from_slice(&t_cost.to_le_bytes());
    header.push(lanes as u8);
    header.push(salt_len as u8);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_prefix);
    header.push(chunk_log2);
    header.extend_from_slice(&plaintext_len.to_le_bytes());
    header.extend_from_slice(&(ad_len as u16).to_le_bytes());
    header.extend_from_slice(&ad);

    Ok((header, ParsedHeader {
        raw_key_mode,
        kdf_mem_mib: m_cost_kib / 1024,
        kdf_time: t_cost,
        kdf_lanes: lanes,
        salt,
        nonce_prefix,
        chunk_size_log2: chunk_log2,
        plaintext_len,
        ad,
    }))
}

struct ParsedHeader {
    raw_key_mode: bool,
    kdf_mem_mib: u32,
    kdf_time: u32,
    kdf_lanes: u32,
    salt: Vec<u8>,
    nonce_prefix: [u8; 7],
    chunk_size_log2: u8,
    plaintext_len: u64,
    ad: Vec<u8>,
}

fn kdf_argon2id_new_salt(
    pass: &mut String,
    mem_mib: u32, time: u32, lanes: u32,
    out_salt_len: u32,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let salt_len = out_salt_len.max(16) as usize;
    let mut salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut salt);

    let (aead_key, header_mac_key) = kdf_argon2id_core(pass, mem_mib, time, lanes, &salt)?;
    Ok((aead_key, header_mac_key, salt))
}

fn kdf_argon2id_with_salt(
    pass: &mut String,
    mem_mib: u32, time: u32, lanes: u32,
    salt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    kdf_argon2id_core(pass, mem_mib, time, lanes, salt)
}

fn kdf_argon2id_core(
    pass: &mut String,
    mem_mib: u32, time: u32, lanes: u32,
    salt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let params = Params::new(mem_mib * 1024, time, lanes, Some(64))
        .map_err(|e| anyhow::anyhow!("Argon2 Params: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut okm = vec![0u8; 64];
    argon2
        .hash_password_into(pass.as_bytes(), salt, &mut okm)
        .map_err(|e| anyhow::anyhow!("Argon2 hash failed: {e:?}"))?;
    let aead_key = hkdf_expand(&okm, b"aead-key", 32)?;
    let header_mac_key = hkdf_expand(&okm, b"header-mac", 32)?;
    zeroize_vec(&mut okm);
    Ok((aead_key, header_mac_key))
}

fn hkdf_expand(ikm: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out).map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(out)
}

fn tmp_name(target: &Path) -> PathBuf {
    let mut p = target.to_path_buf();
    let stem = target.file_name().and_then(|s| s.to_str()).unwrap_or("out");
    p.set_file_name(format!("{}.tmp-{}-{}", stem, std::process::id(), rand::random::<u32>()));
    p
}

/// Replace `dest` with `src` atomically (same directory). On Windows use ReplaceFileW.
/// If `dest` doesn't exist, falls back to a simple rename.
fn atomic_replace_or_rename(dest: &Path, src: &Path) -> io::Result<()> {
    if dest.exists() {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{ReplaceFileW, REPLACEFILE_WRITE_THROUGH};

            let dest_w: Vec<u16> = dest.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

            let ok = unsafe {
                ReplaceFileW(
                    dest_w.as_ptr(),                 // existing file
                    src_w.as_ptr(),                  // temp file
                    std::ptr::null::<u16>(),         // no backup
                    REPLACEFILE_WRITE_THROUGH,
                    std::ptr::null::<c_void>(),      // lpExclude
                    std::ptr::null::<c_void>(),      // lpReserved
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            // On Unix, rename will atomically replace.
            return fs::rename(src, dest);
        }
    } else {
        // Nothing to replace; just move into place.
        fs::rename(src, dest)
    }
}

fn zeroize_vec(v: &mut Vec<u8>) {
    v.zeroize();
    v.resize(0, 0);
}
