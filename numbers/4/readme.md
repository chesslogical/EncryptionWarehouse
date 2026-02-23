Absolutely — here’s a clean, professional `README.md` you can drop into your project.

---

# README.md

````markdown
# filecrypt

A minimal file encryption CLI written in Rust using Serpent-256 in CTR mode with HMAC-SHA512 authentication.

This tool encrypts files in place using a 256-bit key stored in a local key file.

---

## Features

- Serpent-256 encryption
- CTR mode stream encryption
- HMAC-SHA512 authentication (Encrypt-then-MAC)
- HKDF subkey derivation (separates MAC and encryption keys)
- Random 128-bit IV per file
- Atomic file replacement
- Symlink protection (O_NOFOLLOW)
- Enforces secure key file permissions (0600)

---

## Security Design

Encryption: Serpent-256 in CTR mode  
Authentication: HMAC-SHA512  
Key separation: HKDF-SHA512  

The construction is:

    HKDF(master_key) → enc_key || mac_key
    ciphertext = Serpent-CTR(enc_key)
    tag = HMAC(mac_key, iv || ciphertext)

Authentication is verified before decryption.

If authentication fails, decryption is aborted.

---

## Build

Requires Rust stable.

```bash
cargo build --release
````

Binary will be located at:

```
target/release/filecrypt
```

Optional install:

```bash
sudo cp target/release/filecrypt /usr/local/bin/
```

---

## Key Setup

The program expects a file named:

```
key.key
```

in the current working directory.

Generate a secure 256-bit key:

```bash
head -c 32 /dev/urandom > key.key
chmod 600 key.key
```

Requirements:

* Exactly 32 bytes
* Permissions must be 0600
* If this key is lost, encrypted data is unrecoverable

---

## Usage

Encrypt a file:

```bash
filecrypt enc filename
```

Decrypt a file:

```bash
filecrypt dec filename
```

Encryption and decryption replace the original file atomically.

---

## Example

```bash
echo "hello world" > test.txt

filecrypt enc test.txt
cat test.txt      # shows encrypted binary data

filecrypt dec test.txt
cat test.txt      # shows "hello world"
```

---

## Tamper Detection

If a file is modified after encryption:

```bash
filecrypt dec test.txt
```

Decryption will fail with an authentication error.

No plaintext will be written.

---

## File Format

Encrypted file layout:

```
[16 bytes IV]
[ciphertext]
[64 bytes HMAC tag]
```

* IV size: 128 bits
* Tag size: 512 bits

---

## Limitations

* Replaces files in place
* No password-based key derivation (key file only)
* No secure deletion
* Not designed for network protocols
* Large files are fully loaded into memory during decryption

---

## Warning

This is a local file encryption utility.

Losing `key.key` means permanent data loss.

Keep secure backups of your key.

---

## License

MIT

```

---

If you'd like, I can also:

- Add a more “production-grade” security disclaimer
- Add threat model documentation
- Add benchmarking results
- Make it look more like a polished open-source project page
- Add badges and CI setup

Just tell me the vibe you're going for:
Minimalist, serious crypto tool, or polished GitHub project?
```
