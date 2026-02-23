// main.rs — "no-deps" file encryption CLI for Windows & Linux
// Design: ChaCha20 stream cipher + HMAC-SHA256 (Encrypt-then-MAC),
// keys from PBKDF2-HMAC-SHA256 with per-file salt.
// Randomness: Windows RtlGenRandom; Unix /dev/urandom.
// Safe replace: write temp -> fsync (Unix) -> close handles -> atomic replace
// (Unix: rename; Windows: ReplaceFileW). Decrypt verifies MAC before writing.
//
// DISCLAIMER: Hand-rolled crypto is riskier than using audited crates.
// Use for learning or where dependencies are impossible. For real security,
// prefer RustCrypto crates. This code tries to be careful, but no promises.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};

// ---------- Constants / Format ----------
const MAGIC: &[u8; 8] = b"RZENC001";
const ALG_CHACHA20_HMACSHA256: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 32;
const HEADER_LEN: usize = 8 + 1 + 4 + SALT_LEN + NONCE_LEN + 3; // 44

const DEFAULT_PBKDF2_ITERS: u32 = 600_000;
const CHUNK: usize = 1 << 20; // 1 MiB chunks

// ---------- Utility: endian ----------
#[inline] fn u32_to_le(x: u32) -> [u8;4] { x.to_le_bytes() }
#[inline] fn le_to_u32(b: &[u8]) -> u32 { u32::from_le_bytes([b[0],b[1],b[2],b[3]]) }

// ---------- Constant-time compare ----------
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut acc: u8 = 0;
    for i in 0..a.len() { acc |= a[i] ^ b[i]; }
    acc == 0
}

// ---------- Best-effort zero ----------
fn secure_zero(buf: &mut [u8]) {
    use std::ptr::write_volatile;
    for b in buf {
        unsafe { write_volatile(b, 0); }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

// ---------- OS RNG (no crates) ----------
#[cfg(windows)]
mod osrng {
    use std::io;
    use std::ffi::c_void;
    #[link(name="advapi32")]
    extern "system" {
        // RtlGenRandom, exported as SystemFunction036
        fn SystemFunction036(RandomBuffer: *mut c_void, RandomBufferLength: u32) -> u8;
    }
    pub fn fill(buf: &mut [u8]) -> io::Result<()> {
        unsafe {
            let ok = SystemFunction036(buf.as_mut_ptr() as *mut c_void, buf.len() as u32);
            if ok == 0 { Err(io::Error::new(io::ErrorKind::Other, "RtlGenRandom failed")) }
            else { Ok(()) }
        }
    }
}

#[cfg(unix)]
mod osrng {
    use std::fs::File;
    use std::io::{self, Read};
    pub fn fill(buf: &mut [u8]) -> io::Result<()> {
        let mut f = File::open("/dev/urandom")?;
        f.read_exact(buf)
    }
}

fn fill_random(buf: &mut [u8]) -> io::Result<()> { osrng::fill(buf) }

// ---------- SHA-256 (from FIPS 180-4) ----------
#[derive(Clone)]
struct Sha256 {
    h: [u32;8],
    len_bits: u64,
    buf: [u8;64],
    buf_len: usize,
}
impl Sha256 {
    fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ],
            len_bits: 0, buf: [0u8;64], buf_len: 0
        }
    }
    #[inline] fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }
    fn compress(&mut self, block: &[u8;64]) {
        let mut w = [0u32;64];
        for i in 0..16 {
            let j = i*4;
            w[i] = u32::from_be_bytes([block[j],block[j+1],block[j+2],block[j+3]]);
        }
        for i in 16..64 {
            let s0 = Self::rotr(w[i-15], 7) ^ Self::rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            let s1 = Self::rotr(w[i-2], 17) ^ Self::rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        const K: [u32;64] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        ];
        let mut a=self.h[0]; let mut b=self.h[1]; let mut c=self.h[2]; let mut d=self.h[3];
        let mut e=self.h[4]; let mut f=self.h[5]; let mut g=self.h[6]; let mut h=self.h[7];
        for i in 0..64 {
            let s1 = Self::rotr(e, 6) ^ Self::rotr(e, 11) ^ Self::rotr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = Self::rotr(a, 2) ^ Self::rotr(a, 13) ^ Self::rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g; g = f; f = e; e = d.wrapping_add(temp1);
            d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
    fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        self.len_bits = self.len_bits.wrapping_add((data.len() as u64) * 8);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() >= need {
                self.buf[self.buf_len..self.buf_len+need].copy_from_slice(&data[..need]);
                self.compress(unsafe { &*(self.buf.as_ptr() as *const [u8;64]) });
                self.buf_len = 0;
                i += need;
            } else {
                self.buf[self.buf_len..self.buf_len+data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }
        while i + 64 <= data.len() {
            let block = unsafe { &*(data[i..i+64].as_ptr() as *const [u8;64]) };
            self.compress(block);
            i += 64;
        }
        if i < data.len() {
            let rem = &data[i..];
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }
    fn finalize(mut self) -> [u8;32] {
        // Preserve original bit length for the final 64-bit field
        let len_bits_orig = self.len_bits;

        // padding: 0x80 then zeros up to 56 mod 64
        let mut pad = [0u8; 128];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 { 56 - self.buf_len } else { 120 - self.buf_len };
        self.update(&pad[..pad_len]);

        // append original length (big-endian 64-bit)
        let len_be = len_bits_orig.to_be_bytes();
        self.update(&len_be);

        let mut out = [0u8;32];
        for (i, word) in self.h.iter().enumerate() {
            out[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

// ---------- HMAC-SHA256 ----------
struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}
impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        let mut k0 = [0u8; 64];
        if key.len() > 64 {
            let mut h = Sha256::new();
            h.update(key);
            let digest = h.finalize();
            k0[..32].copy_from_slice(&digest);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }
        let mut inner = Sha256::new(); inner.update(&ipad);
        let mut outer = Sha256::new(); outer.update(&opad);
        Self { inner, outer }
    }
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    fn finalize(mut self) -> [u8;32] {
        let inner_hash = self.inner.finalize();
        self.outer.update(&inner_hash);
        self.outer.finalize()
    }
}

// ---------- PBKDF2-HMAC-SHA256 (RFC 8018) ----------
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    assert!(iterations >= 1);
    let hlen = 32usize;
    let l = (out_len + hlen - 1) / hlen;
    let mut out = vec![0u8; out_len];
    let mut u = vec![0u8; hlen];
    let mut t = vec![0u8; hlen];
    for i in 1..=l {
        let mut mac = HmacSha256::new(password);
        mac.update(salt);
        mac.update(&u32::to_be_bytes(i as u32));
        u.copy_from_slice(&mac.finalize());
        t.copy_from_slice(&u);
        for _ in 2..=iterations {
            let mut maci = HmacSha256::new(password);
            maci.update(&u);
            u.copy_from_slice(&maci.finalize());
            for j in 0..hlen { t[j] ^= u[j]; }
        }
        let start = (i-1)*hlen;
        let end = std::cmp::min(start+hlen, out_len);
        out[start..end].copy_from_slice(&t[..end-start]);
    }
    secure_zero(&mut u);
    secure_zero(&mut t);
    out
}

// ---------- ChaCha20 (RFC 8439 core) ----------
#[derive(Clone)]
struct ChaCha20 {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    block: [u8; 64],
    offset: usize,
}
impl ChaCha20 {
    fn new(key32: &[u8;32], nonce12: &[u8;12], counter: u32) -> Self {
        let mut key = [0u32;8];
        for i in 0..8 {
            key[i] = u32::from_le_bytes([key32[i*4], key32[i*4+1], key32[i*4+2], key32[i*4+3]]);
        }
        let nonce = [
            u32::from_le_bytes([nonce12[0],nonce12[1],nonce12[2],nonce12[3]]),
            u32::from_le_bytes([nonce12[4],nonce12[5],nonce12[6],nonce12[7]]),
            u32::from_le_bytes([nonce12[8],nonce12[9],nonce12[10],nonce12[11]]),
        ];
        Self { key, nonce, counter, block: [0u8;64], offset: 64 }
    }
    #[inline] fn rotl(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }
    #[inline]
    fn qr(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
        *a = a.wrapping_add(*b); *d ^= *a; *d = Self::rotl(*d, 16);
        *c = c.wrapping_add(*d); *b ^= *c; *b = Self::rotl(*b, 12);
        *a = a.wrapping_add(*b); *d ^= *a; *d = Self::rotl(*d, 8);
        *c = c.wrapping_add(*d); *b ^= *c; *b = Self::rotl(*b, 7);
    }
    fn gen_block(&mut self) {
        let constants = [0x61707865u32, 0x3320646eu32, 0x79622d32u32, 0x6b206574u32];

        let mut s = [
            constants[0], constants[1], constants[2], constants[3],
            self.key[0], self.key[1], self.key[2], self.key[3],
            self.key[4], self.key[5], self.key[6], self.key[7],
            self.counter, self.nonce[0], self.nonce[1], self.nonce[2],
        ];
        let orig = s;

        for _ in 0..10 {
            // column rounds
            {
                let (mut a, mut b, mut c, mut d) = (s[0], s[4], s[8], s[12]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[0] = a; s[4] = b; s[8] = c; s[12] = d;
            }
            {
                let (mut a, mut b, mut c, mut d) = (s[1], s[5], s[9], s[13]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[1] = a; s[5] = b; s[9] = c; s[13] = d;
            }
            {
                let (mut a, mut b, mut c, mut d) = (s[2], s[6], s[10], s[14]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[2] = a; s[6] = b; s[10] = c; s[14] = d;
            }
            {
                let (mut a, mut b, mut c, mut d) = (s[3], s[7], s[11], s[15]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[3] = a; s[7] = b; s[11] = c; s[15] = d;
            }

            // diagonal rounds
            {
                let (mut a, mut b, mut c, mut d) = (s[0], s[5], s[10], s[15]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[0] = a; s[5] = b; s[10] = c; s[15] = d;
            }
            {
                let (mut a, mut b, mut c, mut d) = (s[1], s[6], s[11], s[12]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[1] = a; s[6] = b; s[11] = c; s[12] = d;
            }
            {
                let (mut a, mut b, mut c, mut d) = (s[2], s[7], s[8], s[13]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[2] = a; s[7] = b; s[8] = c; s[13] = d;
            }
            {
                let (mut a, mut b, mut c, mut d) = (s[3], s[4], s[9], s[14]);
                Self::qr(&mut a, &mut b, &mut c, &mut d);
                s[3] = a; s[4] = b; s[9] = c; s[14] = d;
            }
        }

        for i in 0..16 { s[i] = s[i].wrapping_add(orig[i]); }
        for (i, word) in s.iter().enumerate() {
            let bytes = word.to_le_bytes();
            self.block[i*4..i*4+4].copy_from_slice(&bytes);
        }
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }
    fn apply(&mut self, data: &mut [u8]) {
        let mut i = 0;
        while i < data.len() {
            if self.offset >= 64 { self.gen_block(); }
            let n = std::cmp::min(64 - self.offset, data.len() - i);
            for j in 0..n {
                data[i + j] ^= self.block[self.offset + j];
            }
            self.offset += n;
            i += n;
        }
    }
}

// ---------- Header helpers ----------
fn make_header(iter: u32, salt: &[u8;SALT_LEN], nonce: &[u8;NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    let mut o = 0;
    h[o..o+8].copy_from_slice(MAGIC); o += 8;
    h[o] = ALG_CHACHA20_HMACSHA256; o += 1;
    h[o..o+4].copy_from_slice(&u32_to_le(iter)); o += 4;
    h[o..o+SALT_LEN].copy_from_slice(salt); o += SALT_LEN;
    h[o..o+NONCE_LEN].copy_from_slice(nonce);
    // reserved 3 bytes are left zero
    h
}
fn parse_header(h: &[u8]) -> io::Result<(u8,u32,[u8;SALT_LEN],[u8;NONCE_LEN])> {
    if h.len() != HEADER_LEN { return Err(io::Error::new(io::ErrorKind::InvalidData, "bad header len")); }
    if &h[0..8] != MAGIC { return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic")); }
    let alg = h[8];
    let iter = le_to_u32(&h[9..13]);
    let mut salt = [0u8;SALT_LEN]; salt.copy_from_slice(&h[13..13+SALT_LEN]);
    let mut nonce = [0u8;NONCE_LEN]; nonce.copy_from_slice(&h[13+SALT_LEN..13+SALT_LEN+NONCE_LEN]);
    Ok((alg, iter, salt, nonce))
}

// ---------- Temp file path ----------
fn make_temp_path(dest: &Path) -> io::Result<PathBuf> {
    let mut rnd = [0u8;6];
    fill_random(&mut rnd)?;
    let mut suffix = String::with_capacity(12);
    const HEX: &[u8;16] = b"0123456789abcdef";
    for b in rnd {
        suffix.push(HEX[(b >> 4) as usize] as char);
        suffix.push(HEX[(b & 0xF) as usize] as char);
    }
    let mut p = dest.to_owned();
    let name = dest.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp_name = format!(".{}.rztmp-{}", name, suffix);
    p.set_file_name(tmp_name);
    Ok(p)
}

// ---------- Password ----------
fn get_passphrase() -> io::Result<Vec<u8>> {
    if let Ok(p) = env::var("RZENC_PASS") {
        return Ok(p.into_bytes());
    }
    eprint!("Enter passphrase (will be echoed): ");
    io::Write::flush(&mut io::stderr())?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    while s.ends_with('\n') || s.ends_with('\r') { s.pop(); }
    Ok(s.into_bytes())
}

// ---------- Flush directory entry after replace ----------
// On Unix we fsync the parent directory; on Windows we no-op.
#[cfg(unix)]
fn sync_dir_of(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dirfile) = File::open(parent) {
            let _ = dirfile.sync_all();
        }
    }
}
#[cfg(not(unix))]
fn sync_dir_of(_path: &Path) {}

// ---------- Atomic replace (tmp -> dest) ----------
#[cfg(windows)]
fn atomic_replace(tmp: &Path, dest: &Path) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    #[link(name="kernel32")]
    extern "system" {
        fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut c_void,
            lpReserved: *mut c_void,
        ) -> i32;
    }

    // Use flags = 0; passing write-through is unsupported and causes ERROR_INVALID_PARAMETER (87).
    let flags: u32 = 0;

    fn to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    let replaced = to_wide(dest);
    let replacement = to_wide(tmp);
    let ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),      // existing file to be replaced
            replacement.as_ptr(),   // replacement file (our temp)
            std::ptr::null(),       // no backup
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(not(windows))]
fn atomic_replace(tmp: &Path, dest: &Path) -> io::Result<()> {
    // POSIX rename() atomically replaces the destination.
    fs::rename(tmp, dest)
}

// ---------- Copy permissions (best-effort) ----------
fn copy_permissions(from: &Path, to: &Path) -> io::Result<()> {
    let perms = fs::metadata(from)?.permissions();
    fs::set_permissions(to, perms)
}

// ---------- Encrypt ----------
fn encrypt_in_place(path: &Path) -> io::Result<()> {
    let pass = get_passphrase()?;
    let mut salt = [0u8; SALT_LEN]; fill_random(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN]; fill_random(&mut nonce)?;
    let header = make_header(DEFAULT_PBKDF2_ITERS, &salt, &nonce);

    // derive 64 bytes: first 32 enc key, next 32 mac key
    let dk = pbkdf2_hmac_sha256(&pass, &salt, DEFAULT_PBKDF2_ITERS, 64);
    let mut enc_key = [0u8;32]; enc_key.copy_from_slice(&dk[0..32]);
    let mut mac_key = [0u8;32]; mac_key.copy_from_slice(&dk[32..64]);

    let mut mac = HmacSha256::new(&mac_key);
    mac.update(&header);

    // open files
    let src_meta = fs::metadata(path)?;
    if !src_meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    let mut src = File::open(path)?;
    let tmp_path = make_temp_path(path)?;
    let mut dst = OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
    copy_permissions(path, &tmp_path).ok();

    // write header
    dst.write_all(&header)?;

    // stream encrypt
    let mut cipher = ChaCha20::new(&enc_key, &nonce, 1);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 { break; }
        let chunk = &mut buf[..n];
        cipher.apply(chunk);
        dst.write_all(chunk)?;
        mac.update(chunk);
    }

    // finalize tag
    let tag = mac.finalize();
    dst.write_all(&tag)?;
    dst.sync_all()?;

    // Close handles before replacement (helps on Windows)
    drop(dst);
    drop(src);

    // atomic replace (tmp -> original path)
    let dest_path = path.to_owned();
    atomic_replace(&tmp_path, &dest_path)?;
    // best-effort flush directory entry
    sync_dir_of(&dest_path);

    // wipe secrets
    let mut pass_m = pass;
    secure_zero(&mut pass_m);
    secure_zero(&mut enc_key);
    secure_zero(&mut mac_key);
    let mut dk_m = dk;
    secure_zero(&mut dk_m);

    Ok(())
}

// ---------- Decrypt ----------
fn decrypt_in_place(path: &Path) -> io::Result<()> {
    let pass = get_passphrase()?;

    // open source and read header + tag positions
    let mut src = File::open(path)?;
    let meta = src.metadata()?;
    if !meta.is_file() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file")); }
    if meta.len() < (HEADER_LEN + TAG_LEN) as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too small"));
    }

    let mut header = [0u8; HEADER_LEN];
    src.read_exact(&mut header)?;
    let (alg, iters, salt, nonce) = parse_header(&header)?;
    if alg != ALG_CHACHA20_HMACSHA256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown algorithm"));
    }
    if iters == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad iterations"));
    }

    // read tag at end
    let file_len = meta.len() as usize;
    let ct_len = file_len - HEADER_LEN - TAG_LEN;
    src.seek(SeekFrom::Start((HEADER_LEN + ct_len) as u64))?;
    let mut tag_file = [0u8; TAG_LEN];
    src.read_exact(&mut tag_file)?;

    // derive keys
    let dk = pbkdf2_hmac_sha256(&pass, &salt, iters, 64);
    let mut enc_key = [0u8;32]; enc_key.copy_from_slice(&dk[0..32]);
    let mut mac_key = [0u8;32]; mac_key.copy_from_slice(&dk[32..64]);

    // pass 1: verify MAC (no plaintext written)
    src.seek(SeekFrom::Start(0))?;
    let mut mac = HmacSha256::new(&mac_key);
    mac.update(&header);

    // stream ciphertext into MAC
    src.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let mut remaining = ct_len;
    let mut buf = vec![0u8; CHUNK];
    while remaining > 0 {
        let need = std::cmp::min(remaining, buf.len());
        src.read_exact(&mut buf[..need])?;
        mac.update(&buf[..need]);
        remaining -= need;
    }
    let tag_calc = mac.finalize();
    if !ct_eq(&tag_calc, &tag_file) {
        // wipe secrets and fail
        let mut pass_m = pass;
        secure_zero(&mut pass_m);
        secure_zero(&mut enc_key);
        secure_zero(&mut mac_key);
        let mut dk_m = dk;
        secure_zero(&mut dk_m);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "authentication failed (wrong password or corrupted file)"));
    }

    // pass 2: decrypt to temp, then replace
    src.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let tmp_path = make_temp_path(path)?;
    let mut dst = OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
    copy_permissions(path, &tmp_path).ok();

    let mut cipher = ChaCha20::new(&enc_key, &nonce, 1);
    let mut remaining = ct_len;
    while remaining > 0 {
        let need = std::cmp::min(remaining, buf.len());
        src.read_exact(&mut buf[..need])?;
        let chunk = &mut buf[..need];
        cipher.apply(chunk);
        dst.write_all(chunk)?;
        remaining -= need;
    }
    dst.sync_all()?;

    // Close handles before replacement (helps on Windows)
    drop(dst);
    drop(src);

    atomic_replace(&tmp_path, path)?;
    sync_dir_of(path);

    // wipe secrets
    let mut pass_m = pass;
    secure_zero(&mut pass_m);
    secure_zero(&mut enc_key);
    secure_zero(&mut mac_key);
    let mut dk_m = dk;
    secure_zero(&mut dk_m);
    Ok(())
}

// ---------- CLI ----------
fn print_usage() {
    eprintln!("Usage: rzenc [E|D] <file>\n\
               Set passphrase via env var RZENC_PASS (recommended),\n\
               or it will be read from stdin (echoed).\n\
               E <file>  encrypts and replaces <file>\n\
               D <file>  decrypts and replaces <file>");
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        print_usage();
        std::process::exit(2);
    }
    let mode = args.remove(0);
    let path = Path::new(&args[0]);
    let res = match mode.as_str() {
        "E" | "e" => encrypt_in_place(path),
        "D" | "d" => decrypt_in_place(path),
        _ => { print_usage(); Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown mode")) }
    };
    if let Err(e) = res {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
