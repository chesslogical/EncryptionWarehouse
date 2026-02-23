

TLDR- its so simple a whale can use it. Just give the file name and it encrypts or decrypts automatically. Key is hard coded at compile time. Static link to libsodium- (a well vetted crypto lib) so you do not have to install libsodium !! 

# safecrypt (Windows CLI)



**Atomic, data-safe, single-argument file encrypt/decrypt** using **XChaCha20‑Poly1305** (libsodium Secretstream).  
Runs on Windows, writes to a temporary file, `fsync`s, then atomically swaps using **`ReplaceFileW(REPLACEFILE_WRITE_THROUGH)`**.  
It **decides automatically** whether to encrypt or decrypt based on a file **magic header**, and it **never double‑encrypts**.

> **Keying model (by design):** The encryption key is **hard‑coded** into the binary as a 32‑byte array.  
> This prevents accidental double-encryption across builds and keeps the CLI to a single argument.  
> Treat the executable as sensitive: anyone with the binary can extract the key and decrypt files produced by it.

---

## Features

- **Single input** (`safecrypt <file>`), no flags to get wrong
- **Atomic in-place replace** via Windows `ReplaceFileW` (+ write-through) for crash safety
- **Streaming AEAD** with libsodium **Secretstream XChaCha20-Poly1305**
- **Automatic mode**: plaintext → **encrypt**, already-encrypted → **decrypt**
- **Magic header** (`XS20` + version) + **Key ID** (BLAKE2b‑derived, 8 bytes) to catch wrong binaries quickly
- **No external Sodium install needed** on Windows: this project uses the Rust crate’s **prebuilt static library**

---

## Quick start

### 1) Install prerequisites

- **Rust (stable)** for Windows (MSVC toolchain) – https://rustup.rs/  
- **Visual Studio C++ Build Tools** (MSVC + Windows SDK) – required by Rust/MSVC and linking

### 2) Set your key (hard‑coded)

Edit `src/main.rs`, replace the 32 bytes in `COMPILETIME_KEY`:

```rust
const COMPILETIME_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, /* ... 28 more ... */, 0x1f
];
```

Generate 32 random bytes (PowerShell):

```powershell
$b = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
($b | ForEach-Object { '0x{0:x2}' -f $_ }) -join ', '
```

> The length is compile‑time enforced. No env vars, no string parsing.

### 3) Build

```powershell
cargo build --release
```

The binary is at `target\release\safecrypt.exe`.

### 4) Use

```powershell
# Encrypts in place (atomic)
.\safecrypt.exe C:\path\to\file.txt

# Run again on the same file -> decrypts back (atomic)
.\safecrypt.exe C:\path\to\file.txt
```

---

## How it decides encrypt vs decrypt

- If a file starts with the magic header `XS20` + version, `safecrypt` **decrypts** it (after verifying the 8‑byte key ID).
- Otherwise, it **encrypts** the file and writes:
  - `MAGIC(4)="XS20" | VERSION(1)=0x01 | KEY_ID(8) | SECRETSTREAM_HEADER(24)`
  - Followed by length‑prefixed Secretstream frames. The final frame carries a **FINAL** tag, so truncation is detected.

Wrong key / wrong binary? You’ll get **“Key mismatch for this file”** and nothing is written.

---

## Static linking: do I need to install libsodium?

**No.** On Windows MSVC, the `libsodium-sys` crate ships a **prebuilt static** Sodium library in the crate. Cargo links it into your `.exe`.  
You don’t install Sodium system‑wide; you just need the **MSVC toolchain** to build/link the Rust project.

**Verify it’s really static** (no `libsodium.dll` dependency):

```powershell
dumpbin /DEPENDENTS .\target\release\safecrypt.exe | Select-String sodium
# (No 'libsodium.dll' should appear.)
```

> If you ever see a dynamic dependency: make sure `SODIUM_SHARED` is **not** set in your environment when building.

---

## Crash‑safety details

1. Write encrypted/decrypted data to a **new temp file** next to the original.
2. `flush` + `fsync` the temp file for durability.
3. Atomically swap with **`ReplaceFileW(..., REPLACEFILE_WRITE_THROUGH)`**, which requests write‑through semantics for the swap.
4. Best‑effort `fsync` the replaced file handle.

If an interruption occurs before the swap, the original file is unchanged (you may see a leftover `.tmp` file).

---

## Troubleshooting

- **“Key mismatch for this file”** – You recompiled with a different `COMPILETIME_KEY` than the one used to encrypt. Use the matching binary.
- **“Not an encrypted file (magic mismatch)”** – You tried to decrypt a plaintext file; run the tool again and it will encrypt.
- **“Authentication failed (corrupted or wrong key)”** – The file is tampered/corrupted or used with the wrong key.
- **`ReplaceFileW` error 32 (sharing violation)** – Another process (AV/backup/indexer) has the file locked. Close apps or retry.
- **Old binary being run** – Ensure you run the fresh build: `.\target\release\safecrypt.exe` or `Get-Command safecrypt` to check the path.

---

# Why this has libsodium “built-in”

Most Windows apps that use libsodium ship a separate DLL or ask you to install libsodium. With Rust, the libsodium-sys crate conveniently vendors a static library for Windows/MSVC, so your final executable doesn’t depend on an external libsodium install. It’s clean and portable—great fit for a single-file CLI like this.




## Known limitations

- **Windows‑only** (uses `ReplaceFileW` and Win32 APIs).  
- **Key is embedded** in the binary by design; keep the executable private.
- No passphrase entry, no key rotation UI (could be added later via a small key‑version byte and multiple embedded keys).
- Metadata/ACLs: `ReplaceFileW` keeps the target filename and typical attributes; special metadata needs aren’t handled explicitly.

---

## License

MIT. See `LICENSE`.

---

## Acknowledgements

- [libsodium](https://libsodium.gitbook.io/doc/) – modern, high‑level crypto primitives.
- Rust crates: `libsodium-sys`, `windows-sys`, `anyhow`, `zeroize`, `hex`.
