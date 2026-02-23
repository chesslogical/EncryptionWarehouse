# rsafe — Atomic, data-safe password-based file encryption (Rust + libsodium)

`rsafe` is a single-argument CLI that **encrypts or decrypts in-place atomically**. It is designed to be **extremely reliable**: if anything fails, your original file stays intact.

- **One argument only**: pass the file path. `rsafe` reads a magic header to decide whether to **encrypt** (no header) or **decrypt** (header present).
- **Streaming AEAD**: uses libsodium **secretstream XChaCha20-Poly1305**, so each chunk is authenticated and corruption is caught early.
- **Password-based**: prompts for a password (no key files). Per-file **Argon2id** salt + KDF parameters are embedded in the header.
- **True in-place atomic replace**:
  - **Windows**: `ReplaceFileW(REPLACEFILE_WRITE_THROUGH)` with a short retry loop for transient locks (AV, indexers, OneDrive).
  - **POSIX**: write to a temp file in the **same directory**, `fsync`, then `rename` + directory `fsync`.
- **Sidecar lock**: prevents two `rsafe` instances from clobbering each other without locking the target file itself (important on Windows).
- **Data hygiene**: temp file uses restrictive permissions; secrets are **zeroized**; zero-length inputs are handled cleanly.
- **Static libsodium** by default via `libsodium-sys-stable` so end users don’t need a system install.

---

## Quick start

```bash
# build a release binary
cargo build --release
# run (encrypt or decrypt is auto-detected by magic header)
target/release/rsafe path/to/file
```

- **Encrypt**: If the file is plaintext, `rsafe` prompts twice for a password and replaces the file with an encrypted version.
- **Decrypt**: If the file has the `rsafe` header, `rsafe` prompts for the password and replaces it with plaintext.
- **On failure**: The original file remains unchanged.

> Keep backups. Atomic replacement protects against partial writes, not against accidental deletion or losing the only copy of your data.

---

## Build & dependencies

`rsafe` uses Rust 1.70+ (edition 2021). To make the binary easy to distribute, it **vendors and statically links libsodium** by default.

**`Cargo.toml` (core dependencies):**

```toml
[dependencies]
anyhow = "1"
clap = { version = "4.5", features = ["derive"] }
rpassword = "7"
zeroize = "1.7"
tempfile = "3"
fd-lock = "4"
libsodium-rs = "0.1"

# Vendors & statically links libsodium by default
libsodium-sys-stable = "1.22.3"

# New (for production hardening & UX)
filetime = "0.2"     # preserve timestamps
indicatif = "0.17"   # progress bars/spinner

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.52", features = ["Win32_Foundation", "Win32_Storage_FileSystem"] }
```

### Platform notes

- **Windows (MSVC)**
  ```powershell
  cargo build --release
  # verify static sodium (no libsodium.dll should appear)
  dumpbin /DEPENDENTS .\target\release\rsafe.exe
  ```
- **Linux/macOS**
  ```bash
  cargo build --release
  # verify
  ldd target/release/rsafe | grep -i sodium || true  # Linux (should show nothing)
  otool -L target/release/rsafe | grep -i sodium || true  # macOS (should show nothing)
  ```
- **Fully static Linux (optional)**: build for `x86_64-unknown-linux-musl` if you want to avoid glibc dependency.
  ```bash
  rustup target add x86_64-unknown-linux-musl
  cargo build --release --target x86_64-unknown-linux-musl
  ```

---

## Usage

```bash
rsafe <FILE> [FLAGS]
```

- If `<FILE>` is plaintext → **encrypt in place** (asks password; by default asks to confirm).
- If `<FILE>` is an rsafe-encrypted file → **decrypt in place** (asks once).
- The tool writes to a temp file in the same directory and atomically replaces the original only on success.

### Flags

| Flag | Description |
|-----|-------------|
| `--follow-symlink` | Allow operating on a symlink. By default, rsafe **refuses** to touch symlinks to avoid surprises. |
| `--no-confirm` | Skip password confirmation on encrypt (handy for scripts). |
| `--passphrase-file <FILE>` | Read passphrase from a file (first line; trailing newline trimmed). |
| `--progress` | Show a progress bar (encrypt) or spinner (decrypt). |
| `--kdf-target-ms <MS>` | Auto-tune Argon2id **opslimit** to target ~milliseconds on this machine (memlimit stays at default). |
| `-V/--version` | Print version and exit. |
| `-h/--help` | Show help. |

### Examples

```bash
# Encrypt then decrypt back (round trip)
echo 'hello world' > demo.txt
rsafe demo.txt          # prompts twice, encrypts in place
rsafe demo.txt          # prompts once, decrypts in place
```

```powershell
# Windows: verify content hasn't changed after round-trip
Set-Content -NoNewline demo.txt 'hello world'
.\rsafe.exe .\demo.txt
.\rsafe.exe .\demo.txt
CertUtil -hashfile .\demo.txt SHA256
```

---

## Exit codes (stable, for scripting)

| Code | Meaning |
|-----:|---------|
| `0` | Success |
| `1` | Generic failure (uncategorized) |
| `2` | Password mismatch during encrypt (confirmation failed) |
| `3` | Wrong password / decryption failed |
| `4` | Not an rsafe file / bad or unsupported header |
| `5` | File corrupted (framing error, trailing data after FINAL, chunk length out of bounds) |
| `6` | File locked by another rsafe process |
| `7` | Symlink refused (re-run with `--follow-symlink` to allow) |
| `8` | KDF parameters invalid/too large for this machine |
| `9` | I/O error (permission denied, not found, already exists, would block, etc.) |

These codes are returned by the binary and won’t change across releases unless documented.

---

## File format (on-disk)

**Header (fixed size):**

```
MAGIC (8)      = "RSAFEv01"
VERSION (1)    = 1
KDF_ALG (1)    = 1  (Argon2id via libsodium ALG_DEFAULT)
OPSLIMIT (4LE) = libsodium pwhash opslimit (e.g., MODERATE or auto-tuned)
MEMLIMIT (8LE) = libsodium pwhash memlimit in bytes
SALT (16)      = libsodium SALTBYTES
SS_HEADER (24) = secretstream header for XChaCha20-Poly1305
RESERVED (8)   = zeros (future use)
```

**Body (streamed records):**

```
repeat {
  LEN (4LE) | CIPHERTEXT (LEN bytes)
}
# the final record is tagged FINAL by secretstream;
# trailing bytes after FINAL fail decryption
```

- Each record is a libsodium **secretstream** frame (`TAG_MESSAGE` or `TAG_FINAL`) with AEAD authentication.
- The **header bytes are bound as AAD** for every record (integrity belt-and-suspenders).
- Per-chunk authentication detects corruption early; `TAG_FINAL` ensures truncation is detected.
- Zero-length files are emitted as a **single empty FINAL** record.

---

## Security model & defaults

- **Confidentiality & integrity**: XChaCha20-Poly1305 (secretstream) provides AEAD; any modification is detected.
- **Passwords**: KDF = **Argon2id** (`OPSLIMIT_MODERATE`, `MEMLIMIT_MODERATE`) and **per-file 16-byte salt**. Parameters are stored in the header so files remain decryptable even if defaults change later.
  - You can request auto-tuning with `--kdf-target-ms` to match the local machine.
- **Zeroization**: password strings, derived key bytes, and in-memory plaintext buffers are wiped after use.
- **Not hidden**: file size (approx.), modification times, and filename are not hidden. The length-prefix framing leaks chunk sizes (typical for streaming schemes).
- **Out-of-scope**: attacker's live access to your running system, memory forensics, or OS swap/hibernation capturing plaintext; consider OS‑level mitigations for those.

You can raise KDF cost by editing the constants in `main.rs` if you prefer fixed settings:

```rust
const OPSLIMIT: u64 = crypto_pwhash::OPSLIMIT_MODERATE;
const MEMLIMIT: usize = crypto_pwhash::MEMLIMIT_MODERATE;
```

For higher resistance, consider `OPSLIMIT_SENSITIVE` and a larger `MEMLIMIT`—balance with UX and hardware constraints.

---

## Reliability & atomicity

- All work is done in a temp file in the **same directory** as the target (ensures cross‑platform atomic replacement).
- On **Windows**, rsafe uses `ReplaceFileW(REPLACEFILE_WRITE_THROUGH)` and **retries briefly** on `LOCK_VIOLATION`, `SHARING_VIOLATION`, or `ACCESS_DENIED`.
- On **POSIX**, rsafe uses `rename()` and **fsyncs** the directory to durably commit metadata.
- A **sidecar lock file** (`.rsafe.lock.<filename>`) prevents two rsafe processes from racing on the same target without locking the target itself (which would block the replace on Windows).
- **DoS guards**: bounded ciphertext chunk lengths; header KDF params are validated against libsodium “sensitive” ceilings.
- **Orphan cleanup**: old `.rsafe.tmp.*` files older than 24h in the target directory are cleaned up on each run (best-effort).

**If anything fails, the original file remains intact.**

---

## Troubleshooting

- **Windows “The process cannot access the file because another process has locked a portion of the file” (32/33/5)**  
  Another program (editor, AV, indexer, sync client) is holding the file. Close it or wait; rsafe retries for a short period. If it persists, exclude the directory from AV scanning while operating.
- **Windows “The file exists” (80)**  
  Fixed in current implementation by writing to the `NamedTempFile` handle directly.
- **Network / cloud drives**  
  Atomic replace and locking semantics can vary. Prefer local disks for critical operations; let sync tools upload *after* rsafe finishes.
- **Wrong password**  
  Decryption fails with a clear error; the encrypted file remains unchanged.
- **Symlinks refused**  
  Re-run with `--follow-symlink` if you really intend to operate on a symlink.

---

## Testing

```bash
# 1) Round-trip integrity
echo 'hello' > t.txt
rsafe t.txt && rsafe t.txt

# 2) Large files
dd if=/dev/zero of=big.bin bs=1M count=100
rsafe big.bin && rsafe big.bin

# 3) Corruption detection
rsafe t.txt          # encrypt
printf '\x00' | dd of=t.txt bs=1 seek=200 conv=notrunc  # flip a byte somewhere
rsafe t.txt          # should FAIL to decrypt
```

Windows equivalents:

```powershell
Set-Content -NoNewline t.txt 'hello'
.\rsafe.exe .\t.txt; .\rsafe.exe .\t.txt

fsutil file createnew .\big.bin 104857600
.\rsafe.exe .\big.bin; .\rsafe.exe .\big.bin
```

---

## Project layout

Single binary crate with the following major components:

- **Header parsing/encoding** (magic, version, KDF params, salt, secretstream header)
- **Streaming encrypt/decrypt** with framed records (`LEN|CT`) bound to header via AAD
- **Atomic replace** (`ReplaceFileW` or `rename` + directory `fsync`)
- **Sidecar lock** via `fd-lock`
- **Password I/O** via `rpassword`
- **Zeroization** via `zeroize`
- **Progress** via `indicatif`
- **Timestamp preservation** via `filetime`

---

## License

MIT or Apache-2.0 — your choice. Update `Cargo.toml` as you prefer.

---

## Acknowledgements

- The excellent **libsodium** library and its `secretstream` and `pwhash(Argon2id)` APIs.
- The Rust ecosystem crates that make careful systems programming pleasant: `anyhow`, `fd-lock`, `tempfile`, `zeroize`, `indicatif`, `filetime`, and more.
