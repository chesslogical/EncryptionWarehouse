

---

# tf

A minimal, Linux-only file encryption CLI using **Threefish-1024 in CTR mode** with **HMAC-SHA512 (Encrypt-then-MAC)**.

This tool performs **in-place authenticated encryption** of regular files using a required key file in the current working directory.

---

## ⚠️ Design Constraints

* Linux only
* Requires a file named `key.key` in the current working directory
* No password mode
* No key generation
* No interactive prompts
* No symlink following
* Key file must be exactly **128 bytes**
* Key file permissions must be **0600**

---

## Cryptographic Design

* Cipher: Threefish-1024 (CTR mode)
* MAC: HMAC-SHA512
* KDF: HKDF-SHA512
* Construction: Encrypt-then-MAC
* IV: 16 random bytes (per file)
* Authentication covers:

  * IV
  * Frame lengths
  * Ciphertext
* MAC verified before decryption
* Keys are zeroized after use

Each file is structured as:

```
[ 16-byte IV ]
[ 4-byte length ][ ciphertext chunk ]
[ 4-byte length ][ ciphertext chunk ]
...
[ 4-byte zero length ]
[ 64-byte HMAC tag ]
```

---

## Installation

Requires Rust 2024 edition.

```
cargo build --release
```

Binary will be located at:

```
target/release/tf
```

---

## Creating the Key File

You must manually create `key.key` in the directory where you run the tool.

### Generate a secure key:

```
head -c 128 /dev/urandom > key.key
chmod 600 key.key
```

Requirements:

* Exactly 128 bytes
* Permission mode 0600
* Must be a regular file
* Must exist in current working directory

The program will refuse to run otherwise.

---

## Usage

### Encrypt a file (in place)

```
./tf enc filename
```

### Decrypt a file (in place)

```
./tf dec filename
```

Encryption and decryption:

* Write to a temporary file
* `fsync()` the file
* Atomically rename
* `fsync()` the parent directory

---

## Security Properties

✔ Encrypt-then-MAC
✔ Full-file authentication
✔ Constant-time MAC verification
✔ O_NOFOLLOW used for file access
✔ Refuses to encrypt `key.key`
✔ Refuses non-regular files
✔ 0600 permissions enforced
✔ Keys zeroized in memory

---

## Threat Model

Designed for:

* Local file-at-rest protection
* Personal Linux systems
* No network exposure
* No multi-user shared key management

Not designed for:

* Password-based encryption
* Remote adversaries
* High-assurance compliance environments
* Cross-platform portability

---

## Why Threefish?

Threefish-1024:

* Large 1024-bit block size
* ARX design (no S-boxes)
* No AES hardware dependency
* Suitable for custom constructions

This tool uses CTR mode with per-file random IV and HKDF key separation.

---

## Limitations

* No metadata preservation
* No streaming API
* No forward compatibility header
* No versioned file format
* No key rotation system

---

## Disclaimer

This tool is provided as-is.

While it follows sound cryptographic construction principles, it has not been formally audited.

Use at your own risk.

---

