# sivlock — AES‑256‑GCM‑SIV file encryption (Rust, Windows, auto‑only)

`sivlock` is a small, production‑grade Windows CLI that **encrypts or decrypts a file _in place_** using **AES‑256‑GCM‑SIV** (RFC 8452) with **streaming AEAD** and **Argon2id** key derivation. It writes to a temp file and then **atomically replaces** the original (using `ReplaceFileW` with write‑through), so your file is either the old bytes or the new bytes—never half‑written.

> **Auto‑only UX:** `sivlock <file>`
>
> - If the file begins with the SIVLOCK magic (`AGSV`) and the header looks valid, **decrypt** it in place.
> - Otherwise, **encrypt** it in place.
> - If the file *starts* with `AGSV` but the header is malformed or the size doesn’t match the header, `sivlock` **refuses to encrypt** (prevents accidental double‑encryption of corrupted ciphertext). Use `--force-encrypt` only if you know what you are doing.

---

## Features

- 🔒 **AES‑256‑GCM‑SIV** (nonce‑misuse‑resistant AEAD; better failure mode than GCM).
- 📦 **Streaming AEAD (STREAM/BE32)** — authenticates chunk boundaries; detects truncation/reordering.
- 🧂 **Argon2id** passphrase KDF (tunable memory/time/lanes) or **32‑byte key file**.
- 🧾 **Authenticated header** (keyed BLAKE3) binding the file’s KDF parameters, salt, nonce prefix, chunk size, plaintext length, and optional associated data (AD/label).
- 🧨 **Auto‑only** command: one operation that detects encrypt vs decrypt.
- 🧪 **Hardened auto‑detect**: strict header sanity and full file size consistency check before attempted decrypt.
- 🧱 **Atomic, durable replace** on Windows via `ReplaceFileW` (with write‑through) after `fsync`.
- 🧽 **Zeroizes** sensitive keying material in memory.

> **FIPS note:** AES‑GCM‑SIV is *not* FIPS‑approved today. If you require FIPS 140 validation, use AES‑GCM in a validated module instead.

---

## Build

Prereqs: Rust (stable), Cargo. On Windows, the build pulls `windows-sys` for the atomic replace.

```cmd
git clone <your-fork-or-path>
cd sivlock
cargo build --release
```

The binary will be at:
```
target\release\sivlock.exe
```

---

## Usage (CMD/Batch)

From the directory that contains `sivlock.exe` and your file:

```cmd
:: Auto: encrypt if plaintext; decrypt if SIVLOCK — in place, atomically
sivlock.exe text.txt

:: With 32-byte key file (instead of passphrase prompt)
sivlock.exe text.txt --key-file C:\keys\aead.key

:: Bind a non-secret, authenticated label (AD)
sivlock.exe "My Notes.txt" --ad "client-A"

:: Tuning (encryption only)
sivlock.exe big.bin --kdf-mem-mib 512 --kdf-time 4 --kdf-lanes 2 --chunk-size-log2 22

:: Expert overrides (avoid unless necessary)
sivlock.exe suspicious.bin --force-encrypt   :: treat as plaintext even if it begins with AGSV
sivlock.exe sample.sgsv  --force-decrypt     :: force decryption attempt even if not AGSV
```

### Prompts & exit codes
- Passphrases are **always prompted** (never accepted via CLI/env).
- Success returns **0**. Any error returns a non‑zero exit code (visible as `%ERRORLEVEL%`).

---

## Security design (short version)

- **AEAD mode:** AES‑256‑GCM‑SIV (RFC 8452). Compared with AES‑GCM, accidental nonce reuse degrades more gracefully. You must still treat nonces as unique—`sivlock` generates a random per‑file **nonce prefix**; the streaming layer encodes the counter and “last‑chunk” flag.
- **Streaming construction:** `STREAM` (big‑endian 32‑bit counter). Each chunk is encrypted+authenticated; the **same AAD** (the serialized header) is used for all segments, so **truncation** and **re‑ordering** are detected.
- **KDF:** **Argon2id** with configurable **memory** (MiB), **time** (iterations), **lanes** (parallelism). Defaults: `256 MiB`, `3`, `1`. Output is HKDF‑split into two 32‑byte subkeys: `aead_key` and `header_mac_key`.
- **Header MAC:** BLAKE3 keyed MAC over the entire header (excluding the MAC itself). This authenticates the KDF parameters, salt, nonce prefix, chunk size, plaintext length, and AD.
- **Zeroization:** Key material is wiped from memory when no longer needed.

> **Metadata:** The header is not encrypted. It includes plaintext length, Argon2 parameters, and optional AD. If hiding metadata matters, wrap the file in another container or add application‑level padding before encryption.

---

## File format (on disk)

```
| magic "AGSV" (4) | version (1) | flags (1) | kdf_id (1=Argon2id) (1)
| m_cost_KiB (u32 LE) | t_cost (u32 LE) | lanes (u8)
| salt_len (u8) | salt (salt_len)
| nonce_prefix (7 bytes)               // STREAM uses last 5 bytes as counter+last flag
| chunk_size_log2 (u8)                 // e.g., 20 => 1 MiB chunks
| plaintext_len (u64 LE)
| ad_len (u16 LE) | associated_data (ad_len)
| header_mac (32 bytes)                // BLAKE3 keyed MAC over all header bytes above
| ciphertext chunks (STREAM): Enc_i = AEAD(chunk_i, AAD = header) || tag(16)
```

**Associated Data (AD):** A user‑supplied label that is authenticated but not encrypted.

---

## Hardened auto‑detection

Before auto‑decrypting, `sivlock` validates:

- Magic = `AGSV`; version = `1`; KDF id = `Argon2id`.
- Argon2 lanes in `1..=32`.
- Memory cost is stored as KiB and must be a multiple of `1024`; derived MiB in `1 … 262144` (256 GiB).
- Time cost in `1 … 1000`.
- Salt length: `0` for raw‑key files; otherwise `16 … 64` bytes.
- Chunk size log2 in `10 … 30` (1 KiB … 1 GiB chunks; default 1 MiB).
- AD length ≤ 64 KiB.
- **Total file size exactly equals** `header + 32‑byte MAC + (plaintext_len + chunks*16)` where `chunks = ceil(plaintext_len / chunk_size)`.

If *any* check fails, the tool refuses to encrypt in auto mode and exits with an error that explains what to do next.

---

## Key file (optional)

Instead of a passphrase, you can supply a **raw 32‑byte key file**:

```cmd
sivlock.exe file.txt --key-file C:\keys\aead.key
```

> **Generating a key file:** If you have OpenSSL installed:
> ```cmd
> openssl rand 32 > C:\keys\aead.key
> ```
> If you don’t, just use a passphrase; `sivlock` will derive a strong key with Argon2id.

Keep key files on a secure medium (and back them up). Anyone who obtains the key can decrypt all files sealed with it.

---

## Error messages you may see

- `header authentication failed (wrong password or corrupted file)` — bad passphrase/key, or the file was damaged/tampered.
- `associated data mismatch: the file was sealed with different AD` — you passed `--ad` that doesn’t match the stored label.
- `File begins with 'AGSV' but has an invalid/malformed header or size mismatch.` — ciphertext looks corrupted; auto‑encrypt is refused to avoid double‑encrypting a broken file. Use `--force-encrypt` only if you’re sure.

All writes are atomic: if an error occurs before the final replace, your original file stays untouched.

---

## FAQ

**Q: Is this FIPS‑approved?**  
A: No. AES‑GCM‑SIV isn’t FIPS‑approved. Use AES‑GCM in a validated module if you need FIPS.

**Q: Can I lose data if my PC crashes mid‑write?**  
A: The new data is written to a temp file, `fsync`ed, then `ReplaceFileW` ensures the directory entry switches atomically with write‑through. You’ll end up with either the old or the new file.

**Q: Does AD need to be supplied on decrypt?**  
A: No. The stored header is authenticated either way. If you pass `--ad` during decrypt, it must match or the tool errors early for your safety.

**Q: What about filenames and timestamps?**  
A: The tool doesn’t hide these. If you need to conceal metadata beyond content, use a container (e.g., ZIP with stored name masking) before encryption.

---

## License

Choose what fits your project (e.g., MIT or Apache‑2.0). If you forked this from a template, keep the original license terms.

---

## Acknowledgements

Built on the RustCrypto ecosystem (`aes-gcm-siv`, `aead`, `argon2`, `hkdf`, `sha2`, `blake3`) and Windows’ `ReplaceFileW` for atomic replacement.
