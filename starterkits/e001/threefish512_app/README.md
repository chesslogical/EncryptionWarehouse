# threefish512_app

A small Rust CLI that provides **legit Threefish‑512** file encryption for Windows.  
It encrypts **in place** (atomic replace) using **CTR mode** with authentication via **Skein‑MAC‑512**.  
Large files are handled in **streaming** mode (constant memory, 1 MiB chunks).

> **Why this is legit:** Threefish‑512 is the tweakable block cipher at the core of Skein.  
> This tool uses Threefish‑512 exactly per the Skein v1.3 specification (72 rounds, key schedule with `C240`, rotation tables, UBI for Skein).  
> For file encryption, we combine it with a standard **encrypt‑then‑MAC** design (CTR + Skein‑MAC).

---

## Quick start (Windows)

```powershell
# 1) Build (requires Rust toolchain)
cargo build --release

# 2) Generate a random key file in the folder with your files
.\target\release\threefish512_app.exe gen-key
# -> writes .\key.key   (64 random bytes; keep this safe!)

# 3) Encrypt a file IN PLACE (atomic)
.\target\release\threefish512_app.exe lock .\test.txt

# 4) Decrypt IN PLACE
.\target\release\threefish512_app.exe unlock .\test.txt
```

> The commands **require `key.key` to be present in the same folder** as the target file.  
> If verification fails during `unlock` (wrong key or corruption), **the original file is left unchanged**.

---

## Features

- ✅ **Threefish‑512** core (72 rounds, Skein constants).  
- ✅ **Streaming I/O** – processes large files in constant memory (default 1 MiB chunks).  
- ✅ **Atomic in‑place replace on Windows** using `ReplaceFileW`.  
- ✅ **Authenticated encryption**: CTR for confidentiality + Skein‑MAC‑512 (truncated to 32 bytes) for integrity.  
- ✅ **Key file workflow**: required key is `key.key` (binary), kept next to your files.  
- ✅ **Self‑test** (Skein‑512 vector) to sanity‑check the build.

---

## Install / Build

- Install [Rust](https://www.rust-lang.org/tools/install), then:
  ```powershell
  cargo build --release
  ```
- The binary will be at `target/release/threefish512_app.exe`. Put it in your PATH if you like.

> The **atomic** replace path is Windows‑specific. On non‑Windows platforms the code falls back to a best‑effort rename (not perfectly atomic on all filesystems).

---

## CLI

```
threefish512_app <COMMAND>

Commands:
  lock <PATH>     Atomically encrypt in place (requires key.key in same folder)
  unlock <PATH>   Atomically decrypt in place (requires key.key in same folder)
  gen-key         Create a random key file (default: key.key, 64 bytes)
  self-test       Run Skein‑512‑512 known‑answer test
```

### Examples

```bat
:: Generate a 64‑byte random key
threefish512_app gen-key

:: Encrypt in place
threefish512_app lock "C:\Files\report.docx"

:: Decrypt in place
threefish512_app unlock "C:\Files\report.docx"

:: Overwrite an existing key file with a specific size (dangerous):
threefish512_app gen-key --out key.key --size 64 --force
```

---

## File format (on disk)

For an encrypted file, the content is laid out as:

```
MAGIC (8 bytes) = "TF512v1\0"
SALT  (16 bytes)  random per file
NONCE (16 bytes)  random per file
ORIG_LEN (8 bytes, little‑endian)  original plaintext length

CIPHERTEXT (ORIG_LEN bytes)  produced by Threefish‑512 in CTR mode
TAG (32 bytes)  Skein‑MAC‑512 over (HEADER || CIPHERTEXT), truncated to 32 bytes
```

- **Header** is `MAGIC | SALT | NONCE | ORIG_LEN`.  
- **MAC input** is the concatenation of the **header** and the **ciphertext** (encrypt‑then‑MAC).  
- On **decrypt**, the tag is verified before any replacement of the original file.

---

## Cryptography details

- **Cipher:** Threefish‑512 (block size 512 bits).  
  - Rounds: 72.  
  - Key schedule constant: `C240 = 0x1BD11BDAA9FC1A22`.  
  - Word permutation and rotation tables per Skein v1.3 for `Nw = 8` (512‑bit).  
- **CTR mode:** keystream block = `E_k^t(0^512)` where the **tweak** = `[counter (64) | t1 (64)]` and `t1 = nonce_lo XOR nonce_hi`.  
- **KDF (for per‑file keys):** domain‑separated Skein‑512‑512 on `key.key` + random 128‑bit **salt** → two independent 64‑byte keys:
  - `enc_key = Skein512("TFKDF\0" || salt || key_bytes)`
  - `mac_key = Skein512("TFKDF\x01" || salt || key_bytes)`
- **MAC:** Skein‑MAC‑512 over `header || ciphertext`, truncated to **32 bytes**.  
- **Streaming:** files are processed in 1 MiB chunks (adjustable in source via `CHUNK`).

---

## Security notes

- **Keep `key.key` secret and backed up**. Lose it → data is unrecoverable. Leak it → data is readable.
- The tool uses a **separate random salt and nonce per file**; reusing `key.key` across files is acceptable thanks to the salt‑based KDF.  
  (Still, consider separate `key.key` per dataset if that fits your workflow.)
- CTR + MAC is a standard authenticated‑encryption composition. The program uses **encrypt‑then‑MAC** and verifies the MAC before writing plaintext on decrypt.
- The implementation aims to be clean and correct; it is **not side‑channel hardened**. For highly adversarial environments, consider additional hardening measures.
- Atomic replace relies on **NTFS** semantics. If the process crashes before the replace, your original file remains intact.

---

## Verifying correctness

1. **Self‑test** (Skein‑512 KAT):
   ```powershell
   threefish512_app self-test
   # expected: self-test: OK
   ```
2. **End‑to‑end sanity check**:
   ```powershell
   # make a copy of a file
   copy test.txt test.orig.txt
   # encrypt + decrypt
   threefish512_app lock test.txt
   threefish512_app unlock test.txt
   # compare
   certutil -hashfile test.txt SHA256
   certutil -hashfile test.orig.txt SHA256
   # the two hashes must match
   ```

---

## Troubleshooting

- `required key file not found`  
  Ensure `key.key` is in the **same folder** as the file you lock/unlock.
- `authentication failed (wrong key.key or corrupted file)`  
  - The `key.key` does not match the one used for encryption, or the file is corrupted.
  - The tool **does not** overwrite the original file in this case.
- `bad magic (not TF512v1)`  
  The file is plaintext or from a different tool/format.
- `length mismatch`  
  The header’s `ORIG_LEN` doesn’t match the ciphertext bytes; likely corruption.

---

## Performance

- Streaming in 1 MiB chunks keeps memory usage flat and works well for very large files.
- You can change the chunk size by editing `const CHUNK: usize = 1 << 20;` in `src/main.rs`.

---

## Key management tips

- Generate `key.key` once per folder/dataset and **back it up** (offline storage recommended).  
- `key.key` must be **≥16 bytes**; the default is **64 random bytes**.  
- Do **not** store `key.key` in cloud‑synced folders unless you intend to share decryption capability.

---

## License

Dual‑licensed under **MIT** or **Apache‑2.0** at your option. See `Cargo.toml`.

---

## Acknowledgments

- Bruce Schneier, Niels Ferguson, Stefan Lucks, Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas, Jesse Walker — authors of the Skein/Threefish designs.
- This project re‑implements the Threefish‑512 core and Skein UBI from the specification for educational and practical use.

