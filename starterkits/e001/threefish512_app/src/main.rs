use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use hex::encode;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// ---------- Threefish-512 core (72 rounds, Skein v1.3 constants) ----------
const C240: u64 = 0x1BD11BDAA9FC1A22;

const R512: [[u32; 4]; 8] = [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44,  9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [ 8, 35, 56, 22],
];

const PERM8: [usize; 8] = [2, 1, 4, 7, 6, 5, 0, 3];

#[inline(always)]
fn rotl(x: u64, r: u32) -> u64 { x.rotate_left(r) }

#[derive(Clone)]
struct Threefish512 {
    k: [u64; 9], // k[0..7], k[8] = xor(k[0..7]) ^ C240
    t: [u64; 3], // t[0], t[1], t[2] = t0 ^ t1
}

impl Threefish512 {
    fn new(key_bytes: &[u8; 64], tweak_bytes: &[u8; 16]) -> Self {
        let mut k = [0u64; 9];
        let mut parity = C240;
        for (i, chunk) in key_bytes.chunks_exact(8).enumerate() {
            let ki = u64::from_le_bytes(chunk.try_into().unwrap());
            k[i] = ki;
            parity ^= ki;
        }
        k[8] = parity;
        let t0 = u64::from_le_bytes(tweak_bytes[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(tweak_bytes[8..16].try_into().unwrap());
        Threefish512 { k, t: [t0, t1, t0 ^ t1] }
    }

    #[inline(always)]
    fn subkey_word(&self, s: usize, i: usize) -> u64 {
        let base = self.k[(s + i) % 9];
        match i {
            5 => base.wrapping_add(self.t[s % 3]),
            6 => base.wrapping_add(self.t[(s + 1) % 3]),
            7 => base.wrapping_add(s as u64),
            _ => base,
        }
    }

    #[inline(always)]
    fn add_subkey(&self, v: &mut [u64; 8], s: usize) {
        for i in 0..8 {
            v[i] = v[i].wrapping_add(self.subkey_word(s, i));
        }
    }

    fn encrypt_block(&self, block: &[u8; 64]) -> [u8; 64] {
        let mut v = [0u64; 8];
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        for d in 0..72 {
            if d % 4 == 0 {
                self.add_subkey(&mut v, d / 4);
            }
            let r = R512[d & 7];

            // MIX on word pairs
            let (mut x0, mut x1) = (v[0], v[1]);
            let y0 = x0.wrapping_add(x1);
            let y1 = rotl(x1, r[0]) ^ y0;
            v[0] = y0; v[1] = y1;

            x0 = v[2]; x1 = v[3];
            let y0 = x0.wrapping_add(x1);
            let y1 = rotl(x1, r[1]) ^ y0;
            v[2] = y0; v[3] = y1;

            x0 = v[4]; x1 = v[5];
            let y0 = x0.wrapping_add(x1);
            let y1 = rotl(x1, r[2]) ^ y0;
            v[4] = y0; v[5] = y1;

            x0 = v[6]; x1 = v[7];
            let y0 = x0.wrapping_add(x1);
            let y1 = rotl(x1, r[3]) ^ y0;
            v[6] = y0; v[7] = y1;

            // permutation
            let f = v;
            for i in 0..8 {
                v[i] = f[PERM8[i]];
            }
        }

        self.add_subkey(&mut v, 18);

        let mut out = [0u8; 64];
        for (i, w) in v.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

// ---------- Skein-512 (streaming UBI) ----------
mod skein512 {
    use super::Threefish512;

    pub const NB: usize = 64; // block size (bytes)
    pub const T_KEY: u8 = 0;
    pub const T_MSG: u8 = 48;
    pub const T_OUT: u8 = 63;

    pub const IV: [u64; 8] = [
        0x4903ADFF749C51CE, 0x0D95DE399746DF03, 0x8FD1934127C79BCE, 0x9A255629FF352CB1,
        0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4, 0x991112C71A75B523, 0xAE18A40B660FCC33,
    ];

    #[inline(always)]
    fn u128_to_le_bytes(x: u128) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&(x as u64).to_le_bytes());
        out[8..].copy_from_slice(&((x >> 64) as u64).to_le_bytes());
        out
    }

    #[inline(always)]
    fn ubi_block(
        hi: [u64; 8],
        block: &[u8; NB],
        tcode: u8,
        pos_after: u128,
        first: bool,
        last: bool,
    ) -> [u64; 8] {
        // tweak = type || position || flags
        let mut t = (tcode as u128) << 120;
        t += pos_after;
        if first { t += 1u128 << 126; }
        if last  { t += 1u128 << 127; }

        let mut key_bytes = [0u8; 64];
        for (j, w) in hi.iter().enumerate() {
            key_bytes[j * 8..j * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let tweak_bytes = u128_to_le_bytes(t);

        let tf = Threefish512::new(&key_bytes, &tweak_bytes);
        let e = tf.encrypt_block(block);

        // MMO feed-forward
        let mut next = [0u64; 8];
        for j in 0..8 {
            let ej = u64::from_le_bytes(e[j * 8..j * 8 + 8].try_into().unwrap());
            let mj = u64::from_le_bytes(block[j * 8..j * 8 + 8].try_into().unwrap());
            next[j] = ej ^ mj;
        }
        next
    }

    pub struct UbiStream {
        hi: [u64; 8],
        tcode: u8,
        first: bool,
        pos: u128,
        buf: [u8; NB],
        buf_len: usize,
    }

    impl UbiStream {
        pub fn new(initial_hi: [u64; 8], tcode: u8) -> Self {
            Self {
                hi: initial_hi,
                tcode,
                first: true,
                pos: 0,
                buf: [0u8; NB],
                buf_len: 0,
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            while !data.is_empty() {
                let space = NB - self.buf_len;
                let to_copy = space.min(data.len());
                self.buf[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
                self.buf_len += to_copy;
                data = &data[to_copy..];

                // Process a full block only if more data remains, so the final block
                // (exactly 64 or partial) is done in finalize() with the Final flag.
                if self.buf_len == NB && !data.is_empty() {
                    let block: [u8; NB] = self.buf;
                    let pos_after = self.pos + NB as u128;
                    self.hi = ubi_block(self.hi, &block, self.tcode, pos_after, self.first, false);
                    self.first = false;
                    self.pos = pos_after;
                    self.buf_len = 0;
                }
            }
        }

        pub fn finalize(self) -> [u64; 8] {
            // Final block (0..=64 bytes). Pad zeros to 64.
            let mut block = [0u8; NB];
            let take = self.buf_len;
            if take > 0 {
                block[..take].copy_from_slice(&self.buf[..take]);
            }
            let pos_after = self.pos + take as u128;

            // If message was empty, we still process one zero block with pos_after = 0,
            // First=true, Final=true (per Skein spec).
            ubi_block(self.hi, &block, self.tcode, pos_after, self.first, true)
        }
    }

    #[inline]
    fn ubi_once(hi: [u64; 8], data: &[u8], tcode: u8) -> [u64; 8] {
        let mut s = UbiStream::new(hi, tcode);
        s.update(data);
        s.finalize()
    }

    /// One-shot Skein-512-512 digest (64 bytes).
    pub fn hash(bytes: &[u8]) -> [u8; 64] {
        let g1 = ubi_once(IV, bytes, T_MSG);
        let g2 = ubi_once(g1, &0u64.to_le_bytes(), T_OUT);
        let mut out = [0u8; 64];
        for (i, w) in g2.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Streaming Skein-MAC-512 (64-byte tag). Use `finalize_trunc32()` for 32-byte tag.
    pub struct SkeinMacStream {
        msg: UbiStream, // UBI over message with T_MSG
    }

    impl SkeinMacStream {
        pub fn new(mac_key: &[u8]) -> Self {
            let g1 = ubi_once(IV, mac_key, T_KEY);
            Self { msg: UbiStream::new(g1, T_MSG) }
        }
        pub fn update(&mut self, data: &[u8]) { self.msg.update(data); }
        pub fn finalize(self) -> [u8; 64] {
            let g2 = self.msg.finalize();
            let g3 = ubi_once(g2, &0u64.to_le_bytes(), T_OUT);
            let mut out = [0u8; 64];
            for (i, w) in g3.iter().enumerate() {
                out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
            }
            out
        }
        pub fn finalize_trunc32(self) -> [u8; 32] {
            let full = self.finalize();
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&full[..32]);
            tag
        }
    }
}

// ---------- Container + streaming AE (CTR + Skein-MAC) ----------
const MAGIC: [u8; 8] = *b"TF512v1\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 32;
const CHUNK: usize = 1 << 20; // 1 MiB

fn derive_keys(key_file_bytes: &[u8], salt: &[u8; SALT_LEN]) -> (Zeroizing<[u8; 64]>, Zeroizing<[u8; 64]>) {
    // Domain-separated KDF using Skein-512-512
    let mut in0 = Vec::with_capacity(6 + SALT_LEN + key_file_bytes.len());
    in0.extend_from_slice(b"TFKDF\0");
    in0.extend_from_slice(salt);
    in0.extend_from_slice(key_file_bytes);
    let k0 = skein512::hash(&in0);

    let mut in1 = Vec::with_capacity(6 + SALT_LEN + key_file_bytes.len());
    in1.extend_from_slice(b"TFKDF\x01");
    in1.extend_from_slice(salt);
    in1.extend_from_slice(key_file_bytes);
    let k1 = skein512::hash(&in1);

    let mut ek = [0u8; 64]; ek.copy_from_slice(&k0);
    let mut mk = [0u8; 64]; mk.copy_from_slice(&k1);
    (Zeroizing::new(ek), Zeroizing::new(mk))
}

struct TfCtr {
    key: [u8; 64],
    t1: u64,
    ctr: u64,
    ks: [u8; 64],
    used: usize,
}

impl TfCtr {
    fn new(enc_key: &[u8; 64], nonce: &[u8; NONCE_LEN]) -> Self {
        let nonce_lo = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
        let nonce_hi = u64::from_le_bytes(nonce[8..16].try_into().unwrap());
        Self {
            key: *enc_key,
            t1: nonce_lo ^ nonce_hi,
            ctr: 0,
            ks: [0u8; 64],
            used: 64, // force refill on first use
        }
    }
    fn refill(&mut self) {
        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&self.ctr.to_le_bytes());
        tweak[8..16].copy_from_slice(&self.t1.to_le_bytes());
        let tf = Threefish512::new(&self.key, &tweak);
        self.ks = tf.encrypt_block(&[0u8; 64]);
        self.ctr = self.ctr.wrapping_add(1);
        self.used = 0;
    }
    fn xor_into(&mut self, input: &[u8], out: &mut [u8]) {
        let mut i = 0usize;
        while i < input.len() {
            if self.used == 64 { self.refill(); }
            let take = std::cmp::min(64 - self.used, input.len() - i);
            for j in 0..take {
                out[i + j] = input[i + j] ^ self.ks[self.used + j];
            }
            i += take;
            self.used += take;
        }
    }
}

fn temp_path_near(target: &Path) -> PathBuf {
    let dir = target.parent().unwrap_or(Path::new("."));
    let base = target.file_name().unwrap_or_default().to_string_lossy();
    let mut rnd = [0u8; 8]; OsRng.fill_bytes(&mut rnd);
    dir.join(format!(".{}.{}.tf512.tmp", base, encode(rnd)))
}

// Atomic replace on Windows
#[cfg(target_os = "windows")]
fn atomic_replace(temp: &Path, dst: &Path) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{ReplaceFileW, REPLACEFILE_WRITE_THROUGH};

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    // dst must exist
    if !dst.exists() {
        return Err(anyhow!("destination does not exist: {}", dst.display()));
    }

    let replaced = wide(dst.as_os_str());
    let replacement = wide(temp.as_os_str());
    let ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(anyhow!(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn atomic_replace(temp: &Path, dst: &Path) -> Result<()> {
    if dst.exists() { fs::remove_file(dst)?; }
    fs::rename(temp, dst)?;
    Ok(())
}

fn read_key_for(target: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let dir = target.parent().unwrap_or(Path::new("."));
    let key_path = dir.join("key.key");
    let bytes = fs::read(&key_path)
        .map_err(|e| anyhow!("required key file not found: {}\n(expected at: {})", e, key_path.display()))?;
    if bytes.len() < 16 {
        return Err(anyhow!("key.key must be at least 16 bytes (recommend 64+ random bytes)"));
    }
    Ok(Zeroizing::new(bytes))
}

fn encrypt_in_place_streaming(path: &Path) -> Result<()> {
    // Stream plaintext
    let meta = fs::metadata(path)?;
    let orig_len = meta.len() as u64;
    let mut reader = BufReader::new(File::open(path)?);

    // Keys
    let key_file = read_key_for(path)?;
    let mut salt = [0u8; SALT_LEN]; OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN]; OsRng.fill_bytes(&mut nonce);
    let (enc_key, mac_key) = derive_keys(&key_file, &salt);
    let mut mac = skein512::SkeinMacStream::new(&mac_key[..]); // <-- fix: pass &[u8]
    let mut ctr = TfCtr::new(&enc_key, &nonce);

    // Header
    let mut header = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + 8);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&orig_len.to_le_bytes());

    let tmp = temp_path_near(path);
    let mut out = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
    out.write_all(&header)?;
    mac.update(&header);

    // Stream encrypt -> write -> MAC
    let mut inbuf = vec![0u8; CHUNK];
    let mut outbuf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut inbuf)?;
        if n == 0 { break; }
        ctr.xor_into(&inbuf[..n], &mut outbuf[..n]);
        mac.update(&outbuf[..n]);
        out.write_all(&outbuf[..n])?;
    }

    // Finalize and append tag
    let tag = mac.finalize_trunc32();
    out.write_all(&tag)?;
    out.sync_all()?;

    // Close handles before ReplaceFileW
    drop(out);
    drop(reader);

    // Replace original atomically
    atomic_replace(&tmp, path)?;
    Ok(())
}

fn decrypt_in_place_streaming(path: &Path) -> Result<()> {
    // Open and parse header
    let total_len = fs::metadata(path)?.len() as usize;
    if total_len < MAGIC.len() + SALT_LEN + NONCE_LEN + 8 + TAG_LEN {
        return Err(anyhow!("file too short / not a TF512 container"));
    }

    let mut f = File::open(path)?;
    let mut header = [0u8; 8 + SALT_LEN + NONCE_LEN + 8];
    f.read_exact(&mut header)?;

    if &header[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("bad magic (not TF512v1)"));
    }

    let mut idx = MAGIC.len();
    let salt = <[u8; SALT_LEN]>::try_from(&header[idx..idx + SALT_LEN]).unwrap(); idx += SALT_LEN;
    let nonce = <[u8; NONCE_LEN]>::try_from(&header[idx..idx + NONCE_LEN]).unwrap(); idx += NONCE_LEN;
    let orig_len = u64::from_le_bytes(header[idx..idx + 8].try_into().unwrap());

    let header_len = header.len();
    let ct_len = total_len.checked_sub(header_len + TAG_LEN)
        .ok_or_else(|| anyhow!("truncated file"))?;

    // Keys + MAC
    let key_file = read_key_for(path)?;
    let (enc_key, mac_key) = derive_keys(&key_file, &salt);
    let mut mac = skein512::SkeinMacStream::new(&mac_key[..]); // <-- fix
    mac.update(&header);

    // Temp output
    let tmp = temp_path_near(path);
    let mut out = OpenOptions::new().create_new(true).write(true).open(&tmp)?;

    // CTR decrypt while MAC'ing ciphertext
    let mut ctr = TfCtr::new(&enc_key, &nonce);
    let mut remaining = ct_len;
    let mut inbuf = vec![0u8; CHUNK];
    let mut ptbuf = vec![0u8; CHUNK];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, CHUNK);
        f.read_exact(&mut inbuf[..to_read])?;
        mac.update(&inbuf[..to_read]);
        ctr.xor_into(&inbuf[..to_read], &mut ptbuf[..to_read]);
        out.write_all(&ptbuf[..to_read])?;
        remaining -= to_read;
    }

    // Read and verify tag
    let mut got_tag = [0u8; TAG_LEN];
    f.read_exact(&mut got_tag)?;
    let exp_tag = mac.finalize_trunc32();

    // Compare (constant-time-ish)
    let mut diff = 0u8;
    for i in 0..TAG_LEN { diff |= got_tag[i] ^ exp_tag[i]; }
    if diff != 0 {
        drop(out);
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!("authentication failed (wrong key.key or corrupted file)"));
    }

    // Defensive length check (ciphertext length should equal original length)
    if ct_len as u64 != orig_len {
        drop(out);
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!("length mismatch (header says {}, ciphertext is {} bytes)", orig_len, ct_len));
    }

    out.sync_all()?;
    drop(out);
    drop(f);

    atomic_replace(&tmp, path)?;
    Ok(())
}

// ---------- CLI ----------
#[derive(Parser)]
#[command(name = "threefish512-app")]
#[command(about = "Threefish‑512 file locker (Windows in-place, streaming) + Skein self-test")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Atomically encrypt in place (requires key.key next to the file)
    Lock { path: PathBuf },
    /// Atomically decrypt in place (requires key.key next to the file)
    Unlock { path: PathBuf },
    /// Create a random key file (default: key.key, 64 bytes)
    GenKey {
        #[arg(long, value_name="PATH", default_value="key.key")]
        out: PathBuf,
        #[arg(long, default_value_t=64)]
        size: usize,
        /// Overwrite if exists
        #[arg(long, default_value_t=false)]
        force: bool,
    },
    /// Skein‑512‑512 self-test (vector for 0xFF)
    SelfTest,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Lock { path } => {
            encrypt_in_place_streaming(&path)?;
            println!("locked: {}", path.display());
        }
        Commands::Unlock { path } => {
            decrypt_in_place_streaming(&path)?;
            println!("unlocked: {}", path.display());
        }
        Commands::GenKey { out, size, force } => {
            if out.exists() && !force {
                return Err(anyhow!("{} exists; use --force to overwrite", out.display()));
            }
            if size < 16 { return Err(anyhow!("size must be >= 16 bytes")); }
            let mut buf = vec![0u8; size]; OsRng.fill_bytes(&mut buf);
            let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&out)?;
            f.write_all(&buf)?; f.sync_all()?;
            println!("wrote {} ({} bytes)", out.display(), size);
        }
        Commands::SelfTest => {
            // Skein-512-512("FF") known-answer test (Appendix C.2)
            let got = skein512::hash(&[0xFF]);
            let expected_hex = concat!(
                "71b7bce6fe6452227b9ced6014249e5b",
                "f9a9754c3ad618ccc4e0aae16b316cc8",
                "ca698d864307ed3e80b6ef1570812ac5",
                "272dc409b5a012df2a579102f340617a"
            );
            let ok = encode(got) == expected_hex;
            println!("self-test: {}", if ok { "OK" } else { "FAIL" });
            if !ok { return Err(anyhow!("Self-test failed")); }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn skein_vector_ff() {
        let got = skein512::hash(&[0xFF]);
        let expected = hex::decode(concat!(
            "71b7bce6fe6452227b9ced6014249e5b",
            "f9a9754c3ad618ccc4e0aae16b316cc8",
            "ca698d864307ed3e80b6ef1570812ac5",
            "272dc409b5a012df2a579102f340617a",
        ))
        .unwrap();
        assert_eq!(hex::encode(got), hex::encode(expected));
    }
}
