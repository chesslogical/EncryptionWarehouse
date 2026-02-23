#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::{bail, Context, Result};
use blake3::Hasher as B3Hasher;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use eframe::{egui, NativeOptions};
use filetime::{set_file_times, FileTime};
use fs2::FileExt;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use tempfile::Builder;
use zeroize::Zeroizing;

/* =====================  Engine constants & key  ===================== */

const MAGIC: &[u8; 4] = b"SBX2"; // format magic + version (v2 = pure-Rust)
const ALGO_ID: u8 = 2; // XChaCha20-Poly1305 stream framing
const SALT_LEN: usize = 16; // per-file salt (for subkey derivation)
const NONCE_BASE_LEN: usize = 16; // file-level random prefix for nonces
const CHUNK_SIZE: usize = 64 * 1024; // plaintext chunk size

// AEAD framing bounds (defense-in-depth; format-compatible):
const AEAD_TAG_SIZE: usize = 16; // XChaCha20-Poly1305 tag size
// Max ciphertext per frame: chunk + tag (final frame is just the tag)
const MAX_FRAME_CIPHERTEXT: usize = CHUNK_SIZE + AEAD_TAG_SIZE;

/// HARD-CODED MASTER KEY (DEFAULT) — REPLACE FOR REAL USE (64 hex chars = 32 bytes)
const MASTER_KEY_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/* =====================  RAII lock (cleans sidecar)  ===================== */

struct LockGuard {
    path: PathBuf,
    file: Option<File>,
}
impl LockGuard {
    fn acquire(target: &Path) -> Result<Self> {
        let lock_path = lock_path_for(target);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open lock file {:?}", lock_path))?;
        file.try_lock_exclusive()
            .with_context(|| format!("failed to acquire lock on {:?}", lock_path))?;
        Ok(Self {
            path: lock_path,
            file: Some(file),
        })
    }
}
impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(f) = self.file.take() {
            let _ = f.unlock();
            drop(f); // important on Windows before removing file
        }
        let _ = fs::remove_file(&self.path); // best-effort cleanup
    }
}

/* =====================  Public processing API  ===================== */

#[derive(Clone, Copy, Debug)]
enum Operation {
    Encrypted,
    Decrypted,
}

#[derive(Clone, Debug)]
struct ProcessResult {
    operation: Operation,
    path: PathBuf,
}

/// Process a path in-place (auto encrypt/decrypt). Atomic, self-verifying.
fn process_path(path: &Path) -> Result<ProcessResult> {
    let _lock = LockGuard::acquire(path)?;
    match detect_action(path)? {
        Action::Encrypt => {
            encrypt_in_place(path)?;
            Ok(ProcessResult {
                operation: Operation::Encrypted,
                path: path.to_owned(),
            })
        }
        Action::Decrypt => {
            decrypt_in_place(path)?;
            Ok(ProcessResult {
                operation: Operation::Decrypted,
                path: path.to_owned(),
            })
        }
    }
}

/* =====================  Engine (encrypt/decrypt)  ===================== */

#[derive(Clone, Copy, Debug)]
enum Action {
    Encrypt,
    Decrypt,
}

fn detect_action(path: &Path) -> Result<Action> {
    let mut f = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut buf = [0u8; 4];
    let n = f.read(&mut buf).with_context(|| "read magic failed")?;
    if n == 4 {
        if &buf == MAGIC {
            return Ok(Action::Decrypt);
        }
        if &buf == b"SBX1" {
            bail!("This file uses safebox v1 format (SBX1). Use the v1 build to decrypt first.");
        }
    }
    Ok(Action::Encrypt)
}

fn encrypt_in_place(path: &Path) -> Result<()> {
    // Preserve metadata
    let meta = fs::metadata(path).with_context(|| format!("stat {:?}", path))?;
    let perm = meta.permissions();
    let mtime = FileTime::from_last_modification_time(&meta);
    let atime = FileTime::from_last_access_time(&meta);

    let src = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, src);

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = Builder::new()
        .prefix(".safebox.")
        .suffix(".tmp")
        .tempfile_in(parent)
        .with_context(|| "create temp file")?;
    let tmp_path_buf = tmp.path().to_path_buf();

    {
        let mut writer = BufWriter::new(tmp.as_file());

        // Key derivation
        let master_key = Zeroizing::new(load_master_key()?);
        let salt = random_bytes::<SALT_LEN>();
        let subkey_bytes = b3_keyed_derive(&master_key, &salt);
        let subkey = Zeroizing::new(subkey_bytes);
        let key = Key::from_slice(&*subkey);
        let cipher = XChaCha20Poly1305::new(key);

        // Nonce base
        let nonce_base = random_bytes::<NONCE_BASE_LEN>();

        // Header: [MAGIC(4)][ALGO_ID(1)][SALT_LEN(1)][SALT(16)][NB_LEN(1)][NONCE_BASE(16)]
        let mut header =
            Vec::with_capacity(MAGIC.len() + 1 + 1 + SALT_LEN + 1 + NONCE_BASE_LEN);
        header.extend_from_slice(MAGIC);
        header.push(ALGO_ID);
        header.push(SALT_LEN as u8);
        header.extend_from_slice(&salt);
        header.push(NONCE_BASE_LEN as u8);
        header.extend_from_slice(&nonce_base);
        writer.write_all(&header)?;
        writer.flush().ok();

        // Self-check hash
        let mut plain_hasher = B3Hasher::new();

        let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
        let mut counter: u64 = 0;
        loop {
            let n = reader.read(&mut buf[..]).context("read source")?;
            if n == 0 {
                break;
            }
            plain_hasher.update(&buf[..n]);

            let nonce = make_nonce(&nonce_base, counter);
            let aad = frame_aad(&header, FrameType::Data, counter);

            let ct = cipher
                .encrypt(&nonce, Payload { msg: &buf[..n], aad: &aad })
                .map_err(|_| anyhow::anyhow!("encryption failed"))?;
            write_frame(&mut writer, FrameType::Data, counter, &ct)?;
            counter = counter
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("chunk counter overflow"))?;
        }

        // Final frame
        let nonce = make_nonce(&nonce_base, counter);
        let aad_final = frame_aad(&header, FrameType::Final, counter);
        let ct_final = cipher
            .encrypt(&nonce, Payload { msg: &[], aad: &aad_final })
            .map_err(|_| anyhow::anyhow!("final frame encryption failed"))?;
        write_frame(&mut writer, FrameType::Final, counter, &ct_final)?;

        writer.flush().context("flush temp")?;
        tmp.as_file().sync_all().context("fsync temp")?;

        // Self-verify (decrypt temp, compare hash)
        let expected = plain_hasher.finalize();
        drop(writer);
        self_verify_decrypt_hash(&tmp_path_buf, &*master_key, &expected)
            .context("encryption self-check failed")?;
    }

    sync_dir(parent)?;
    let tmp_path = tmp.into_temp_path();
    fs::set_permissions(&tmp_path, perm.clone()).ok();
    drop(reader);
    fs::rename(&tmp_path, path).with_context(|| "atomic rename")?;
    sync_dir(parent)?;
    set_file_times(path, atime, mtime).ok();
    Ok(())
}

fn decrypt_in_place(path: &Path) -> Result<()> {
    // Preserve metadata
    let meta = fs::metadata(path).with_context(|| format!("stat {:?}", path))?;
    let perm = meta.permissions();
    let mtime = FileTime::from_last_modification_time(&meta);
    let atime = FileTime::from_last_access_time(&meta);

    let src = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut reader = BufReader::with_capacity(MAX_FRAME_CIPHERTEXT, src);

    // Header
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).context("read magic")?;
    if &magic != MAGIC {
        bail!("not a safebox v2 file (bad magic)");
    }

    let mut algo = [0u8; 1];
    reader.read_exact(&mut algo)?;
    if algo[0] != ALGO_ID {
        bail!("unsupported algo id");
    }

    let mut saltlen = [0u8; 1];
    reader.read_exact(&mut saltlen)?;
    if saltlen[0] as usize != SALT_LEN {
        bail!("unsupported salt length");
    }

    let mut salt = vec![0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;

    let mut nb_len = [0u8; 1];
    reader.read_exact(&mut nb_len)?;
    if nb_len[0] as usize != NONCE_BASE_LEN {
        bail!("unsupported nonce base length");
    }
    let mut nonce_base = vec![0u8; NONCE_BASE_LEN];
    reader.read_exact(&mut nonce_base)?;

    // Key
    let master_key = Zeroizing::new(load_master_key()?);
    let subkey_bytes = b3_keyed_derive(&master_key, &salt);
    let subkey = Zeroizing::new(subkey_bytes);
    let key = Key::from_slice(&*subkey);
    let cipher = XChaCha20Poly1305::new(key);

    // AAD header bytes
    let mut header =
        Vec::with_capacity(MAGIC.len() + 1 + 1 + SALT_LEN + 1 + NONCE_BASE_LEN);
    header.extend_from_slice(&magic);
    header.extend_from_slice(&algo);
    header.extend_from_slice(&saltlen);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nb_len);
    header.extend_from_slice(&nonce_base);

    // Temp plaintext
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = Builder::new()
        .prefix(".safebox.")
        .suffix(".tmp")
        .tempfile_in(parent)
        .with_context(|| "create temp file")?;
    let mut writer = BufWriter::new(tmp.as_file());

    let mut expected_counter: u64 = 0;
    let mut hasher = B3Hasher::new();

    loop {
        match read_frame(&mut reader) {
            Ok(Some((ftype, counter, ct))) => {
                if ftype == FrameType::Data {
                    if counter != expected_counter {
                        bail!(
                            "frame out of sequence (got {}, expected {})",
                            counter,
                            expected_counter
                        );
                    }
                    let nonce = make_nonce(slice_to_array_16(&nonce_base)?, counter);
                    let aad = frame_aad(&header, FrameType::Data, counter);
                    let pt = Zeroizing::new(
                        cipher
                            .decrypt(&nonce, Payload { msg: &ct, aad: &aad })
                            .map_err(|_| anyhow::anyhow!("authentication failed"))?,
                    );
                    writer.write_all(&pt[..]).context("write plaintext")?;
                    hasher.update(&pt[..]);
                    expected_counter = expected_counter
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("counter overflow"))?;
                } else {
                    if counter != expected_counter {
                        bail!(
                            "final frame counter mismatch (got {}, expected {})",
                            counter,
                            expected_counter
                        );
                    }
                    let nonce = make_nonce(slice_to_array_16(&nonce_base)?, counter);
                    let aad = frame_aad(&header, FrameType::Final, counter);
                    let pt = Zeroizing::new(
                        cipher
                            .decrypt(&nonce, Payload { msg: &ct, aad: &aad })
                            .map_err(|_| anyhow::anyhow!("final frame authentication failed"))?,
                    );
                    if !pt.is_empty() {
                        bail!("final frame plaintext not empty");
                    }
                    // No trailing bytes allowed
                    let mut one = [0u8; 1];
                    match reader.read(&mut one) {
                        Ok(0) => {}
                        Ok(_) => bail!("trailing data after final frame"),
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                        Err(e) => return Err(e).context("checking trailing data"),
                    }
                    break;
                }
            }
            Ok(None) => bail!("truncated ciphertext (missing final frame)"),
            Err(e) => return Err(e),
        }
    }

    writer.flush().context("flush temp")?;
    tmp.as_file().sync_all().context("fsync temp")?;

    sync_dir(parent)?;
    drop(writer);
    let tmp_path = tmp.into_temp_path();
    fs::set_permissions(&tmp_path, perm.clone()).ok();
    drop(reader);
    fs::rename(&tmp_path, path).with_context(|| "atomic rename")?;
    sync_dir(parent)?;
    set_file_times(path, atime, mtime).ok();
    Ok(())
}

/* =====================  Helpers (engine)  ===================== */

fn self_verify_decrypt_hash(
    tmp_path: &Path,
    master_key: &[u8; 32],
    expected_plain_hash: &blake3::Hash,
) -> Result<()> {
    let mut reader =
        BufReader::with_capacity(MAX_FRAME_CIPHERTEXT, File::open(tmp_path)?);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("self-verify: bad magic");
    }

    let mut algo = [0u8; 1];
    reader.read_exact(&mut algo)?;
    if algo[0] != ALGO_ID {
        bail!("self-verify: bad algo id");
    }

    let mut saltlen = [0u8; 1];
    reader.read_exact(&mut saltlen)?;
    if saltlen[0] as usize != SALT_LEN {
        bail!("self-verify: bad salt length");
    }

    let mut salt = vec![0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;
    let mut nb_len = [0u8; 1];
    reader.read_exact(&mut nb_len)?;
    if nb_len[0] as usize != NONCE_BASE_LEN {
        bail!("self-verify: bad nonce base len");
    }
    let mut nonce_base = vec![0u8; NONCE_BASE_LEN];
    reader.read_exact(&mut nonce_base)?;

    let subkey_bytes = b3_keyed_derive(master_key, &salt);
    let subkey = Zeroizing::new(subkey_bytes);
    let key = Key::from_slice(&*subkey);
    let cipher = XChaCha20Poly1305::new(key);

    let mut header = Vec::new();
    header.extend_from_slice(&magic);
    header.extend_from_slice(&algo);
    header.extend_from_slice(&saltlen);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nb_len);
    header.extend_from_slice(&nonce_base);

    let mut hasher = B3Hasher::new();
    let mut expected_counter: u64 = 0;

    loop {
        match read_frame(&mut reader) {
            Ok(Some((ftype, counter, ct))) => {
                if ftype == FrameType::Data {
                    if counter != expected_counter {
                        bail!("self-verify: sequence error");
                    }
                    let nonce = make_nonce(slice_to_array_16(&nonce_base)?, counter);
                    let aad = frame_aad(&header, FrameType::Data, counter);
                    let pt = Zeroizing::new(
                        cipher
                            .decrypt(&nonce, Payload { msg: &ct, aad: &aad })
                            .map_err(|_| anyhow::anyhow!("self-verify: auth failed"))?,
                    );
                    hasher.update(&pt[..]);
                    expected_counter = expected_counter
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("self-verify: counter overflow"))?;
                } else {
                    if counter != expected_counter {
                        bail!("self-verify: final counter mismatch");
                    }
                    let nonce = make_nonce(slice_to_array_16(&nonce_base)?, counter);
                    let aad = frame_aad(&header, FrameType::Final, counter);
                    let pt = Zeroizing::new(
                        cipher
                            .decrypt(&nonce, Payload { msg: &ct, aad: &aad })
                            .map_err(|_| anyhow::anyhow!("self-verify: final auth failed"))?,
                    );
                    if !pt.is_empty() {
                        bail!("self-verify: final not empty");
                    }
                    break;
                }
            }
            Ok(None) => bail!("self-verify: missing final"),
            Err(e) => return Err(e),
        }
    }

    let got = hasher.finalize();
    if &got != expected_plain_hash {
        bail!("self-verify: plaintext hash mismatch");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FrameType {
    Data = 0x00,
    Final = 0xFF,
}
impl TryFrom<u8> for FrameType {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(FrameType::Data),
            0xFF => Ok(FrameType::Final),
            _ => bail!("unknown frame type {}", v),
        }
    }
}

fn write_frame<W: Write>(writer: &mut W, ftype: FrameType, counter: u64, ct: &[u8]) -> Result<()> {
    if ct.len() > u32::MAX as usize {
        bail!("frame too large");
    }
    writer.write_all(&[ftype as u8])?;
    writer.write_all(&counter.to_be_bytes())?;
    writer.write_all(&(ct.len() as u32).to_be_bytes())?;
    writer.write_all(ct)?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R) -> Result<Option<(FrameType, u64, Vec<u8>)>> {
    let mut hdr = [0u8; 1 + 8 + 4];
    let mut off = 0;
    while off < hdr.len() {
        match reader.read(&mut hdr[off..]) {
            Ok(0) if off == 0 => return Ok(None),
            Ok(0) => bail!("unexpected EOF while reading frame header"),
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("read frame header"),
        }
    }
    let ftype = FrameType::try_from(hdr[0])?;
    let mut cnt = [0u8; 8];
    cnt.copy_from_slice(&hdr[1..9]);
    let counter = u64::from_be_bytes(cnt);
    let mut lenb = [0u8; 4];
    lenb.copy_from_slice(&hdr[9..13]);
    let clen = u32::from_be_bytes(lenb) as usize;

    // Defensive bounds: each ciphertext frame must at least carry the AEAD tag,
    // and must not exceed our known writer's maximum frame size.
    if clen < AEAD_TAG_SIZE || clen > MAX_FRAME_CIPHERTEXT {
        bail!("invalid frame length: {}", clen);
    }

    let mut ct = vec![0u8; clen];
    reader.read_exact(&mut ct).context("read frame body")?;
    Ok(Some((ftype, counter, ct)))
}

fn b3_keyed_derive(master: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let digest = blake3::keyed_hash(master, salt);
    *digest.as_bytes()
}

fn load_master_key() -> Result<[u8; 32]> {
    decode_key_hex(MASTER_KEY_HEX).context("MASTER_KEY_HEX invalid (must be 64 hex chars)")
}

fn decode_key_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("hex decode")?;
    if bytes.len() != 32 {
        bail!("key must be 32 bytes (64 hex chars)");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn make_nonce(base: &[u8; NONCE_BASE_LEN], counter: u64) -> XNonce {
    let mut nb = [0u8; 24];
    nb[..NONCE_BASE_LEN].copy_from_slice(base);
    nb[NONCE_BASE_LEN..].copy_from_slice(&counter.to_be_bytes());
    XNonce::from_slice(&nb).clone()
}

fn frame_aad(header: &[u8], ftype: FrameType, counter: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 1 + 8);
    aad.extend_from_slice(header);
    aad.push(ftype as u8);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn slice_to_array_16(slice: &[u8]) -> Result<&[u8; 16]> {
    slice
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad nonce base length"))
}

fn lock_path_for(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("unknown");
    let mut lp = path.to_path_buf();
    lp.set_file_name(format!("{}.sbx.lock", name));
    lp
}

fn sync_dir(_dir: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        return Ok(());
    }
    #[cfg(not(target_os = "windows"))]
    {
        let d = File::open(_dir).with_context(|| format!("open dir {:?}", _dir))?;
        let _ = d.sync_all();
        Ok(())
    }
}

/* =====================  GUI (egui/eframe)  ===================== */

#[derive(Clone)]
struct Job {
    path: PathBuf,
}

enum Msg {
    Started(PathBuf),
    Finished(Result<ProcessResult>),
}

struct App {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    in_progress: bool,
    last_status: Option<String>,
    last_error: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            tx,
            rx,
            in_progress: false,
            last_status: None,
            last_error: None,
        }
    }
}

impl App {
    fn spawn_job(&mut self, job: Job) {
        if self.in_progress {
            return;
        }
        self.in_progress = true;
        self.last_error = None;
        self.last_status = Some(format!("Processing {}", job.path.display()));

        let tx = self.tx.clone();
        let path = job.path.clone();

        let _ = tx.send(Msg::Started(path.clone()));
        thread::spawn(move || {
            let result = process_path(&path);
            let _ = tx.send(Msg::Finished(result));
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain worker messages
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Started(p) => {
                    self.in_progress = true;
                    self.last_status = Some(format!("Processing {}", p.display()));
                    self.last_error = None;
                }
                Msg::Finished(res) => {
                    self.in_progress = false;
                    match res {
                        Ok(done) => {
                            self.last_error = None;
                            let what = match done.operation {
                                Operation::Encrypted => "Encrypted",
                                Operation::Decrypted => "Decrypted",
                            };
                            self.last_status =
                                Some(format!("{} {}", what, done.path.display()));
                        }
                        Err(e) => {
                            self.last_error = Some(format!("{:#}", e));
                            self.last_status = None;
                        }
                    }
                }
            }
        }

        // Accept drag & drop anywhere in the small window:
        ctx.input(|i| {
            for df in &i.raw.dropped_files {
                if let Some(p) = df.path.clone() {
                    self.spawn_job(Job { path: p });
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Safebox v2 — Encrypt/Decrypt");
            ui.add_space(8.0);
            ui.label("Choose a file to encrypt/decrypt. (Drag & drop also works.)");
            ui.add_space(10.0);

            if ui
                .add_enabled(!self.in_progress, egui::Button::new("Select file…"))
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.spawn_job(Job { path });
                }
            }

            ui.add_space(10.0);

            if let Some(s) = &self.last_status {
                ui.colored_label(ui.visuals().hyperlink_color, s);
            }
            if let Some(e) = &self.last_error {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    egui::RichText::new("Error").strong(),
                );
                ui.code(e);
            }

            if self.in_progress {
                ui.add_space(6.0);
                ui.spinner();
                ui.label("Working…");
            }
        });
    }
}

/* =====================  GUI entry  ===================== */

fn main() -> eframe::Result<()> {
    // Small, fixed-size window centered on screen:
    let size = [420.0, 180.0];
    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(size)
            .with_min_inner_size(size)
            .with_max_inner_size(size),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Safebox v2 — Encrypt/Decrypt",
        options,
        Box::new(|_| Box::<App>::default()),
    )
}
