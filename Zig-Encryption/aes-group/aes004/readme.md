# 🔐 AES-256-GCM Password-Based File Encryption (Zig)

This is a simple, secure file encryption CLI tool written in [Zig](https://ziglang.org/).  
It uses AES-256-GCM for authenticated encryption, with a key derived from a password using PBKDF2-HMAC-SHA256.

---

## ✅ Features

- 🔒 AES-256-GCM encryption with authentication tag
- 🔑 Key derived from password using PBKDF2-HMAC-SHA256
- 📦 No key file storage — password is all you need
- 🧠 Self-contained, cross-platform, CLI-friendly
- 🧽 Encrypts and decrypts entire files in memory
- 💥 Compatible with Zig `0.15.0-dev+`

---

## 🛠️ Usage

```bash
./aes <enc|dec> <input_file> <output_file> <password>
```

| Argument      | Description                         |
|---------------|-------------------------------------|
| `enc` / `dec` | Mode: encrypt or decrypt            |
| `input_file`  | Path to file to encrypt/decrypt     |
| `output_file` | Path to write encrypted/decrypted   |
| `password`    | Password used to derive the AES key |

---

## 🔒 File Format

Encrypted output is a binary file structured as:

```
| 16 bytes salt | 12 bytes nonce | 16 bytes tag | ciphertext... |
```

- Salt is used to derive the key from your password
- Nonce is used once per encryption
- Tag authenticates the data

---

## 🔧 Compile

```bash
zig build-exe aes.zig -O ReleaseSafe
```

- `-O ReleaseSafe` enables optimizations with safety checks
- Use `-O Debug` while testing if you want full traces

---

## 🔐 Example

```bash
# Encrypt
./aes enc mynotes.txt encrypted.bin correcthorsebatterystaple

# Decrypt
./aes dec encrypted.bin mynotes_decrypted.txt correcthorsebatterystaple
```

⚠️ **You must provide the same password to decrypt!**

---

## 💡 Why This Design?

- No key files = fewer secrets to manage
- Password-derived keys are good for personal or ad-hoc encryption
- Output format stores everything needed to decrypt
- GCM mode ensures both encryption + integrity

---

## 🔍 Security Notes

- Uses PBKDF2 with 100,000 iterations (adjustable)
- HMAC-SHA256 is used as the PRF (per Zig 0.15+ requirements)
- Salt and nonce are randomly generated for each encryption
- All data is held in memory during processing

For high-security apps, consider:
- Adding a password confirmation prompt
- Hiding password input (no echo)
- Using Argon2id instead of PBKDF2

---

## 📘 License

MIT — do what you want with it, just don’t build ransomware 😉

---
