# SFE – Secure, Crash-Safe, Streaming File Encryption (Rust CLI)

Rust CLI that encrypts *in place* with **Argon2id + XChaCha20-Poly1305**, atomic replace, and careful I/O.

---

## Overview

**SFE** is a tiny Rust command-line tool for encrypting and decrypting files *in place* with production-oriented safety:
strong modern cryptography, streaming AEAD, password hardening, and crash-safe atomic replacement.  

Its interface is intentionally minimal:

```bash
# Encrypt in place
sfe E <path>

# Decrypt in place
sfe D <path>
```

### Highlights

- Key derivation: **Argon2id** (default 256 MiB, 3 passes, parallel).
- AEAD: **XChaCha20-Poly1305** in streaming mode (1 MiB chunks).
- Per-chunk nonces: 16-byte random seed + 64-bit counter.
- Header integrity: **BLAKE3** keyed MAC (32 bytes) over header.
- Crash safety: write to temp, `fsync`, then atomic replace (POSIX `rename`, Windows `ReplaceFileW`).
- Safety rails: refuses symlinks, preserves basic permissions, zeroizes secrets.
- Cross-platform: Linux & Windows.

> **Note**  
> - This project focuses on reliability and strong default cryptography, but it has not undergone third‑party security audit.  
> - For password-based encryption, the passphrase is *your root of trust*. Choose a high-entropy passphrase.

---

## Installation

### Requirements
- Rust toolchain (stable). Install via [rustup](https://rustup.rs/).
- Windows or Linux.

### Project layout
```
sfe/
├─ Cargo.toml
└─ src/
   └─ main.rs
```

### Cargo.toml
```toml
[package]
name = "sfe"
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
description = "Secure, crash-safe, streaming file encryption in place (XChaCha20-Poly1305 + Argon2id)."

[dependencies]
anyhow = "1"
argon2 = "0.5"
blake3 = "1.5"
chacha20poly1305 = "0.10.1"
rand = "0.8"
rpassword = "7"
zeroize = "1.6"
tempfile = "3.10"
num_cpus = "1.16"
cfg-if = "1.0"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.52", features = ["Win32_Storage_FileSystem"] }
```

### Build
```bash
cargo build --release
```

The binary will be at `./target/release/sfe` (or `sfe.exe` on Windows).

---

## Usage

### Encrypt a file in place
```bash
./sfe E a.txt
# Prompts for passphrase (twice). Replaces a.txt with encrypted form.
```

### Decrypt a file in place
```bash
./sfe D a.txt
# Prompts once. Replaces a.txt with plaintext.
```

### Exit codes
- `0` success  
- `1` error  
- `2` usage error  

### Tuning the KDF (optional)
Argon2id parameters can be adjusted with environment variables. The defaults aim for high password-guessing cost on commodity hardware.

```bash
# Example: 512 MiB memory, 4 passes, 8 lanes
SFE_ARGON2_M_KIB=524288 SFE_ARGON2_T=4 SFE_ARGON2_P=8 ./sfe E big.bin
```

---

## Security design (why this is production‑minded)

### Primitives
- **Key derivation:** Argon2id with random 16‑byte salt. Derives 64 bytes: first 32 for AEAD, second 32 for header MAC.
- **AEAD:** XChaCha20-Poly1305 (24‑byte nonce, 16‑byte tag) used in streaming (1 MiB plaintext chunk → 1 MiB + 16 bytes ciphertext).
- **Header MAC:** BLAKE3 keyed hash (32 bytes) over the header (ex‑MAC). Prevents header tampering before any data is processed.

### Nonce strategy
Per file, a 16‑byte random *nonce seed* is generated. For chunk `i`, the XChaCha nonce is  
`nonce = seed || LE64(i)`, guaranteeing uniqueness up to 2^64 chunks.

### Authenticated streaming & AAD binding
Each chunk is sealed with AEAD using AAD = `header_mac || LE64(i)`.  
This detects reordering, truncation, and cross‑file splicing attempts.

### Crash‑safe “in place”
- Write header and ciphertext to a temp file in the same directory.
- `fsync` the temp file.
- Atomically replace the original (`rename` on POSIX, `ReplaceFileW` on Windows).
- On POSIX, `fsync` the directory to durably record the rename.

### Defensive I/O
- Refuses symlinks; operates only on regular files.
- Preserves basic permissions (best‑effort).
- Zeroizes passphrases and derived keys in memory.

---

## File format

All multi‑byte integers are little‑endian. Header size is 96 bytes.

### Header (96 bytes)
```rust
struct HeaderV1 {
  // 4 + 1 + 1 + 1 + 1
  magic:        "SFE1"
  version:      0x01
  alg_id:       0x01   // XChaCha20-Poly1305
  kdf_id:       0x01   // Argon2id
  reserved:     0x00

  // 4 + 4 + 4
  m_cost_kib:   u32    // Argon2 memory (KiB)
  t_cost:       u32    // Argon2 iterations
  p_cost:       u32    // Argon2 lanes

  // 16 + 16
  salt:         [16]   // KDF salt
  nonce_seed:   [16]   // Nonce base for chunks

  // 4 + 8
  chunk_size:   u32    // usually 1 MiB
  plaintext_len:u64    // original file size

  // 32
  header_mac:   [32]   // BLAKE3(key=hdr_key, header_without_mac)
}
```

### Body
For each chunk `i` (0‑based):
- `nonce = nonce_seed || LE64(i)` (24 bytes)
- `aad = header_mac || LE64(i)` (40 bytes)
- `cipher_chunk = AEAD(plaintext_chunk, nonce, aad)` (len = chunk_len + 16)

---

## Threat model

- **Protects against:** offline attackers who obtain the ciphertext; accidental corruption; crash during encryption/decryption.  
- **Out of scope:** active malware on the host at encryption time; passphrase key‑logging; hardware faults beyond detection; forensic remnants in swap/pagefile/old temp files outside SFE's control.

---

## Quick self‑test

```bash
# 1) Build
cargo build --release

# 2) Make a sample file
echo "secret stuff" > a.txt

# 3) Encrypt
./target/release/sfe E a.txt
# (enter passphrase twice)

# 4) Decrypt
./target/release/sfe D a.txt
# (enter passphrase once)

# 5) Tamper test (should fail to decrypt)
./target/release/sfe E a.txt
printf "\x00" | dd of=a.txt bs=1 seek=120 status=none conv=notrunc
./target/release/sfe D a.txt  # <-- decryption should error out
```

---

## Troubleshooting

### “feature xchacha20 not found”
Use `chacha20poly1305 = "0.10.1"` with no feature flags. The XChaCha type is available by default.

### Borrow checker error around `tmp.as_file()`
Drop the writer (mutable borrow) before calling methods that take an immutable borrow of the same temp file handle.

### Windows: replace fails because file is in use
Ensure you `drop(reader)` and close any other handles on the original file before calling `ReplaceFileW`.

---

## Performance & tuning

- Default chunk size is 1 MiB; larger chunks may improve throughput on fast NVMe.  
- Argon2id memory cost (default 256 MiB) dominates encryption start time; adjust via environment if needed.  
- Parallelism (`p_cost`) defaults to `min(num_cpus, 8)` (capped at 32).  

---

## FAQ

**Q:** Does SFE change file names or extensions?  
**A:** No. It replaces the file *in place*. Consider keeping backups or working on copies if you prefer a separate output path.

**Q:** What happens if my machine crashes mid‑operation?  
**A:** You either keep the original (if crash happened before the atomic replace) or you get the fully written replacement. You never get a truncated mix.

**Q:** Can I use key files or hardware tokens?  
**A:** Not in this minimal CLI. The codebase is structured to allow future extensions such as key files or TPM/DPAPI assisted wrapping.

---

## Development notes

- Run `cargo clippy -- -D warnings` during CI.  
- Run `cargo audit` to check for vulnerable dependencies.  
- Consider adding property‑based tests and fuzzing for header parsing and chunk reassembly.  

---

## License

Dual-licensed under **MIT** or **Apache-2.0** at your option.

© 2025 SFE authors. No warranty. Use at your own risk.
