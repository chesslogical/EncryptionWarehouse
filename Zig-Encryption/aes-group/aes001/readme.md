# 🔐 AES-256-GCM File Encryptor (Zig)

This is a simple file encryption and decryption tool written in [Zig](https://ziglang.org/) using the AES-256-GCM algorithm from the standard library.

It reads plaintext from a file (`a.txt`), encrypts it with a randomly generated key and nonce, writes the result to `b.enc`, and then decrypts that back into `c.txt` to verify integrity.

---

## 📦 Features

- 🔒 AES-256-GCM encryption with random key & nonce
- 🧾 Writes encrypted output as: `nonce || tag || ciphertext`
- 🔓 Decrypts and verifies output using authenticated encryption
- 📁 Minimal dependencies — uses only the Zig standard library

---

## 🚀 Build and Run

Make sure you're using Zig version `0.15.0-dev` or later.

```sh
# Compile the program
zig build-exe aes.zig

# Run the binary
./aes
```

---

## 📄 File I/O

- **Input plaintext:** `a.txt`
- **Encrypted output:** `b.enc` (binary format)
- **Decrypted output:** `c.txt` (should match original `a.txt`)

---

## 📂 File Format of `b.enc`

```
|  12 bytes  |  16 bytes  |   N bytes   |
|   Nonce    |    Tag     | Ciphertext  |
```

---

## ⚠️ Notes

- The encryption key and nonce are randomly generated at runtime and not saved. This means:
  - Each run encrypts `a.txt` with a **new key/nonce**.
  - `b.enc` can only be decrypted **within the same run** unless you persist the key/nonce externally.

---

## 🛠️ To Do

- [ ] Add support for CLI arguments
- [ ] Add persistent key storage or password-based key derivation
- [ ] Add test suite for validation
- [ ] Add error logging

---

## 📘 License

MIT License — do whatever you want, just don't blame me 😄
