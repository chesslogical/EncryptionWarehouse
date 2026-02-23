# 🔐 AES-256-GCM File Encryptor (Zig)

This is a simple, command-line file encryption and decryption tool written in [Zig](https://ziglang.org/), using the AES-256-GCM algorithm from the Zig standard library.

It supports encrypting any file and decrypting it back using a stored key, via a clean CLI interface.

---

## 📦 Features

- Encrypt or decrypt any file using AES-256-GCM
- CLI interface with `enc` / `dec` commands
- Automatically saves and reuses the key via `key.bin`
- Uses authenticated encryption (GCM) to ensure integrity
- Minimal dependencies — only standard library

---

## 🚀 Usage

### 🔧 Build

Make sure you have Zig installed (0.11+ recommended):

```bash
zig build-exe aes.zig
```

### 🔒 Encrypt a File

```bash
./aes enc a.txt b.enc
```

- Encrypts `a.txt`
- Outputs encrypted binary to `b.enc`
- Saves the AES key in `key.bin`

### 🔓 Decrypt a File

```bash
./aes dec b.enc c.txt
```

- Decrypts `b.enc` using the key in `key.bin`
- Writes output to `c.txt` (should match original `a.txt`)

---

## 🧾 File Format

The encrypted file (`b.enc`) is written in the format:

```
|  Nonce (12 bytes) | Tag (16 bytes) | Ciphertext (N bytes) |
```

All data is written as raw binary, not base64.

---

## 🔑 Key Handling

- A random 256-bit key is generated during encryption and saved to `key.bin`
- This key is reused automatically during decryption
- **Important:** Keep `key.bin` safe! If you lose it, you can't decrypt your files.

---

## 🖥️ Terminal Compatibility Note

Some characters like the Unicode arrow `→` may appear as garbage (e.g. `ΓåÆ`) in Windows Command Prompt.

✅ To fix:
- Use `->` instead of `→` for compatibility, or
- Use a UTF-8 capable terminal like Windows Terminal or PowerShell Core

---

## 🛠️ To Do

- [ ] Add password-derived key support (no key.bin)
- [ ] Add optional base64 output mode
- [ ] Add input/output via stdin/stdout
- [ ] Add file existence checks and confirmations

---

## 📘 License

MIT — use it freely, tweak it, break it, just don’t blame me 😄
