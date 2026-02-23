# threefish-best — Threefish-1024 file encryption tool (Rust)

[![](https://img.shields.io/badge/cross-platform-blue)]()
[![](https://img.shields.io/badge/encrypt-then-MAC-green)]()
[![](https://img.shields.io/badge/argon2id-KDF-orange)]()
[![](https://img.shields.io/badge/atomic-replace-purple)]()

**threefish-best** is a production-minded file encryption CLI built in Rust around
**Threefish-1024**. It’s designed to be simple (two commands), safe (verify before decrypt),
and reliable (temp-file + atomic rename). It processes any file (binary or text) and keeps the
original filename, encrypting the contents *in place*.

> **CLI** — usage is intentionally tiny:  
> `E <path>` to encrypt, `D <path>` to decrypt.

---

## Quickstart

```bash
# Build (release mode)
cargo build --release

# Windows
target\release\threefish-best.exe E a.txt
target\release\threefish-best.exe D a.txt

# Linux / macOS
./target/release/threefish-best E a.txt
./target/release/threefish-best D a.txt
```

---

## Features

- **Threefish-1024** with a per-file random 128-bit tweak.
- **CTR mode** with a 112-byte nonce and 128-bit counter baked into Threefish’s 16×64-bit block.
- **Encrypt-then-MAC** using keyed **BLAKE3** (32-byte tag stored at EOF).
- **Argon2id** password KDF; derives a 128-byte cipher key + 32-byte MAC key.
- **Pre-decrypt authenticity:** decrypt only after the MAC checks out.
- **Crash safety:** writes to a temp file in the same directory, `fsync`s, then atomic rename-replace.
- **Zeroization:** passphrases/keys wiped from memory after use.

---

## Build

Requires a recent stable Rust toolchain. Copy the two project files and build:

```bash
cargo build --release
```

---

## Usage

```bash
# Encrypt (prompts for passphrase twice)
threefish-best E <file>

# Decrypt (prompts once)
threefish-best D <file>
```

Encryption writes a small authenticated header in front of the ciphertext and appends a 32-byte tag at EOF.  
Decryption verifies the MAC *before* it writes any plaintext. Files are replaced atomically via a temp file in the same directory.

---

## Security design

- **Key derivation:** Argon2id (v1.3). Defaults: `m=256 MiB`, `t=3`, `p=1`. Tunable via env (see below).
- **Cipher:** Threefish-1024 with per-file random 16-byte tweak.
- **Mode:** CTR.  
  Keystream block = `Threefish(k, tweak, nonce||counter)` where `nonce` is 112 bytes (words 0..13), and `counter` is 128-bit (words 14..15, little-endian).
- **Authentication:** BLAKE3 keyed MAC over `header || ciphertext` (tag at EOF). Constant-time verification.
- **Atomicity:** Temp file → `fsync` temp → `fsync` directory → *rename/replace*.

---

## File format

The encrypted file is laid out as:

```
+------------------ 166 B header ------------------+ +----- ciphertext -----+ +-- tag (32 B) --+
| magic "TF3Fv002" | ver=2 | mode=1 | KDF m/t/p | salt[16] | tweak[16] | nonce[112] |   ENC(data)   |  BLAKE3  |
+--------------------------------------------------+-------------------------+------------------+
```

| Field       | Size | Description                                                      |
|-------------|------|------------------------------------------------------------------|
| magic       | 8    | ASCII `TF3Fv002`                                                 |
| version     | 1    | Format version (2)                                               |
| mode        | 1    | 1 = CTR + Encrypt-then-MAC (BLAKE3)                              |
| KDF params  | 12   | `m_mib`, `t`, `p` (each LE `u32`)                                |
| salt        | 16   | Argon2id salt                                                    |
| tweak       | 16   | Threefish tweak                                                  |
| nonce       | 112  | CTR nonce (14×u64, little-endian)                                |
| ciphertext  | *N*  | Input bytes XOR keystream                                        |
| tag         | 32   | BLAKE3 keyed MAC over header||ciphertext, stored at EOF          |

**Overhead:** 166-byte header + 32-byte tag = **198 bytes** added to the original size.

---

## Tuning (environment variables)

Increase Argon2id cost if your machine has more RAM/CPU; this slows offline attacks while keeping usage simple.

```bash
# defaults: TF_M_MIB=256, TF_T=3, TF_P=1
TF_M_MIB=512 TF_T=4 TF_P=1 threefish-best E big.iso
```

---

## Reliability & atomic replace

- Writes to a temporary file next to the target path.
- `fsync`s the temp file, then the directory, then attempts an atomic rename-replace.
- On Windows, ensure the destination isn’t open in other apps (Notepad, editors, Explorer preview).  
  The tool closes its own handles before replacing and retries briefly to dodge transient AV/indexer locks.

---

## Examples

```bash
# Basic text round-trip (Linux/macOS)
echo hello > hello.txt
./threefish-best E hello.txt
./threefish-best D hello.txt
diff hello.txt <(echo hello)   # should be empty

# Basic text round-trip (Windows PowerShell)
'hello' | Out-File -NoNewline hello.txt
.\threefish-best.exe E .\hello.txt
.\threefish-best.exe D .\hello.txt
Get-Content .\hello.txt
```

---

## Troubleshooting

<details>
<summary><strong>“Access is denied (os error 5)” on Windows</strong></summary>
Another process is holding the file open. Close editors, Explorer preview panes, antivirus scans, etc.  
The tool already closes its own handles before replace and retries with backoff.  
If it still fails, copy the file to a different directory and run again.
</details>

<details>
<summary><strong>“authentication failed: wrong passphrase or corrupted file”</strong></summary>
The keyed BLAKE3 MAC over *header||ciphertext* didn’t match. This happens with a wrong passphrase or file corruption.  
Without the correct passphrase, the data is unrecoverable by design.
</details>

<details>
<summary><strong>“not a TF3Fv002 file / unsupported version”</strong></summary>
The file doesn’t match this format’s magic/version, or was produced by a different tool/version.
</details>

<details>
<summary><strong>“file too small to be valid ciphertext”</strong></summary>
Encrypted files must be at least 198 bytes larger than the original (header+tag).  
Extremely small files may trigger this if truncated.
</details>

---

## Security notes

- Use a strong, unique passphrase. There is no recovery if you forget it.
- This implementation uses well-known primitives via maintained Rust crates, but the codebase itself has not been formally audited.
- Header parameters are authenticated, preventing silent parameter or tweak/nonce tampering.
- Nonce & tweak are per-file random; counter is 128-bit; block reuse across files is avoided.

---

## Project files

**Cargo.toml**

```toml
[package]
name = "threefish-best"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
argon2 = "0.5"
blake3 = "1"
rpassword = "7"
rand = "0.8"
tempfile = "3"
threefish = { version = "0.5", features = ["cipher", "zeroize"] }
zeroize = "1"
subtle = "2"
```

**src/main.rs** — see the source in your repository for the full file.

---

## FAQ

**Q:** Does it support associated data (AD)?  
**A:** Not yet. The current MAC covers the header automatically; AD fields could be added in a future mode.

**Q:** Is it deterministic?  
**A:** No—each file gets fresh random salt/tweak/nonce. If you need deterministic SIV-style mode, it can be added as a new format version.

---

© You. Add a LICENSE file if you plan to share or publish.
