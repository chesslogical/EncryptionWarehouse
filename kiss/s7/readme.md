# Threefish-1024 Vault

A hardened, password-based file encryption tool written in Rust using Threefish-1024 in CTR mode with authenticated encryption (Encrypt-then-MAC).

This project is designed for:

* Learning advanced cryptography implementation
* Serious private file protection
* Production-grade secure file encryption

---

# 🔐 Security Design

## Cipher

* Threefish-1024 (1024-bit block cipher)
* CTR mode stream construction

## Authentication

* HMAC-SHA512
* Encrypt-then-MAC
* Full header + ciphertext authenticated

## Key Derivation

* Argon2id
* 64 MB memory cost
* 3 iterations
* HKDF-SHA512 key separation

Keys derived:

* 1024-bit encryption key
* 512-bit MAC key

## File Format (Version 2)

```
MAGIC (8 bytes)
SALT (16 bytes)
IV (16 bytes)
CIPHERTEXT (variable)
HMAC TAG (64 bytes)
```

The file format is versioned to allow future upgrades.

---

# 🛡 Security Properties

* Password never appears in CLI history
* Password never stored on disk
* Secrets zeroized from memory
* Constant-memory streaming (multi-GB safe)
* Authentication verified before successful completion
* Counter overflow protection
* Atomic file overwrite

---

# 🚀 Usage

Build:

```
cargo build --release
```

Run:

```
./threefish_encrypt <filename>
```

You will be prompted securely for a password.

Running the tool again on an encrypted file decrypts it automatically.

---

# 📦 Dependencies

* threefish
* argon2
* hkdf
* hmac
* sha2
* zeroize
* rpassword
* clap
* anyhow

---

# ⚙ Argon2 Parameters

Current configuration:

* Memory: 64 MB
* Iterations: 3
* Parallelism: 1
* Variant: Argon2id

These parameters provide strong resistance against GPU and ASIC attacks while remaining usable on modern machines.

You may increase memory cost for higher security.

---

# 📂 Streaming Mode

The tool processes files in 1 MB chunks.

This means:

* No full file loaded into RAM
* Safe for very large files (100GB+)
* Constant memory usage

---

# 🔎 Threat Model

Protects against:

* Offline brute-force attacks (Argon2id)
* File tampering (HMAC-SHA512)
* Bit-flipping attacks
* Partial file corruption

Does NOT protect against:

* Compromised operating system
* Keylogging malware
* Memory scraping attacks on live system

---

# 🧪 Recommended Testing

* Encrypt/decrypt round-trip tests
* Wrong password failure tests
* Tamper detection tests
* Truncated file tests
* Large file testing

---

# 📌 Notes

Threefish is a less commonly deployed cipher compared to AES. It is well analyzed but not standardized in mainstream protocols.

This project is ideal for educational depth and advanced cryptographic exploration.

---

# ⚠ Important

This software has not undergone a formal cryptographic audit.

If protecting extremely sensitive or regulated data, a professional audit is recommended.

---

# License

MIT (or choose your preferred license)
