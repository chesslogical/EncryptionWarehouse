
<img width="619" height="362" alt="Screenshot 2025-09-03 081117" src="https://github.com/user-attachments/assets/2e9fcbd8-ac93-4112-87e6-e3783a473b33" />



# Safebox v2 — Windows GUI (pure Rust, hard‑coded key)
A compact Windows application for encrypting/decrypting a single file with **one click**.  
Built on the same engine as the CLI version: **atomic, streaming, authenticated** — now with a **file picker** and **drag‑and‑drop**.

> **Highlights:** small window, native file dialog, drag & drop, no console window, hard‑coded master key, atomic in‑place replace, self‑verification, XChaCha20‑Poly1305 (pure Rust).

---

## What this app does
- **Auto‑mode:** give it any file — if it’s plaintext it **encrypts**; if it’s already Safebox (`SBX2`) it **decrypts**.
- **Atomic in‑place:** writes to a temp file in the same directory, `fsync`s, then **atomically renames** over the original.
- **Self‑verification (encrypt):** immediately decrypts the temp file and compares a BLAKE3 hash of plaintext **before** commit.
- **Streaming:** processes files in **64 KiB chunks** (constant, small memory usage).
- **Binary‑safe:** works with **any file type**, including **executables** (`.exe`, `.dll`, `.so`, etc.).
- **No console window:** launches as a regular Windows GUI app.

---

## Security model (hard‑coded key)
- The app uses a **compiled‑in master key** for simplicity. A **default key** is provided in source and **must be changed** for real use.
- Threat model matches your requirement: **attackers don’t have access to the machine that runs the app** or to the master key.
- Caveat: if the binary (or a memory/core dump) leaks, a determined attacker can recover the hard‑coded key. Treat the binary like a secret.

> Hex keys (64 hex characters) are **exactly 32 bytes** (256 bits). Using hex **does not limit key space** vs “binary” — both are full **2²⁵⁶** possibilities when generated uniformly at random.

---

## Build (Windows)
Requirements: [Rust (stable)](https://rustup.rs) and a standard MSVC toolchain.

**`Cargo.toml` (new project named `safebox_gui`)**
```toml
[package]
name = "safebox_gui"
version = "2.2.0"
edition = "2021"

[dependencies]
anyhow = "1"
blake3 = "1"
chacha20poly1305 = "0.10.1"
filetime = "0.2"
fs2 = "0.4"
hex = "0.4"
rand = "0.8"
tempfile = "3"
zeroize = "1"

# GUI
eframe = { version = "0.27", default-features = true }
egui = "0.27"
rfd = "0.14"
```

**`src/main.rs` (single file app)**  
Use the implementation you have from our last step. It includes:
- the attribute `#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]` (no console window)
- a compact window with a **“Select file…”** button and **drag‑and‑drop** anywhere
- the full atomic, self‑verifying engine

Build & run:
```powershell
cargo build --release
.\target\release\safebox_gui.exe
```

---

## Configure the master key (required)
Open `src/main.rs`, locate the constant, and **replace the default** with your own random key:
```rust
const MASTER_KEY_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
```

Generate a key:
- **PowerShell**
  ```powershell
  $b = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
  ($b | ForEach-Object { $_.ToString('x2') }) -join ''
  ```
- **bash (Git Bash / WSL)**  
  ```bash
  openssl rand -hex 32
  ```

> Keep old keys/binaries if you need to decrypt older files later.

---

## How to use
1. Launch `safebox_gui.exe`.  
2. Click **Select file…** _or_ drag a file anywhere into the small window.  
3. The app shows **“Encrypted …”** or **“Decrypted …”** when done. Errors are shown in the window.

> If Windows reports “Access is denied” or similar, another process may be holding the target file open. The app **fails closed**: the original file remains intact.

---

## What happens under the hood
- **Framing & AEAD:** XChaCha20‑Poly1305 with per‑file **subkeys** derived via `BLAKE3.keyed_hash(master_key, salt)`.
- **Header:** `SBX2` magic + algorithm id + salt + nonce‑base.
- **Nonces:** 16‑byte random nonce base + 8‑byte frame counter → 24‑byte XNonce.
- **Frames:** Each 64 KiB chunk becomes an **AEAD‑authenticated frame** with AAD binding `header + frame_type + counter`.
- **Final frame:** A zero‑length authenticated frame guarantees **truncation detection**.
- **Atomicity:** temp file → `fsync` → (encrypt path: **self‑verify**) → **atomic rename** → best‑effort directory sync → restore timestamps & permissions.

### Disk overhead
- Fixed file header: **39 bytes**.  
- Per frame (data + final): **29 bytes** (13‑byte frame header + 16‑byte tag).  
- Total overhead: `39 + (N_data + 1) × 29`, where `N_data = ceil(plaintext / 64 KiB)`.

### Executables & metadata
- **Executables are safe:** bytes are restored **exactly** after decryption (the app verifies this on encrypt).  
- **Metadata preserved:** basic permissions & times.  
- **Not preserved:** extended attributes/ACL details/Windows Alternate Data Streams (ADS). If you rely on these, mirror them yourself around the rename (can be added later).

---

## Troubleshooting
- **Nothing happens or error shown:** Ensure the file path is accessible and not opened exclusively by another process (AV tools, editors, etc.).  
- **Decryption fails / “authentication failed”:** wrong key or corrupted/truncated ciphertext. You must use the **same master key** that encrypted the file.  
- **Leftover `.safebox.*.tmp` file:** safe to delete. It exists if the app was interrupted before the atomic rename.  
- **Leftover `<file>.sbx.lock`:** the RAII lock guard cleans these automatically; if you ever find one, it’s safe to delete when no job is running.

---

## Customization
- **Window size:** change the `size = [420.0, 180.0]` constants in `main()` to your preferred fixed size.  
- **Chunk size:** adjust `CHUNK_SIZE` (default 64 KiB). Larger chunks = higher throughput, slightly more memory.  
- **Key representation:** you can store the key as raw bytes instead of hex (identical strength).  
- **App icon & version info:** add a `windows.rc` or use the `winresource` crate to embed icon/metadata in the EXE.  
- **Installer:** `cargo wix` (MSI) or Inno Setup can package the EXE.

---

## License & warranty
© 2025 Safebox v2 (Windows GUI). Replace the default key before real use.  
Provided “as is” with no warranty. Test in your environment.
