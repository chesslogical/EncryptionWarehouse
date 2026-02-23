# SecureApp

SecureApp is a safety-focused file encryption tool written in Rust.

It provides secure, in-place encryption and decryption using modern authenticated cryptography, strong password hardening, and atomic file replacement to prevent corruption or data loss.

---

## Features

- In-place encryption and decryption
- Atomic file replacement (no partial overwrite corruption)
- Automatic backup + restore on failure
- Temporary file cleanup on errors
- Authenticated encryption (AEAD)
- Full header authentication (magic + version + salt)
- Memory-hard password derivation (Argon2id)
- Password confirmation during encryption
- Chunked processing (large file safe)
- Strict chunk validation
- Password memory zeroization
- No unwraps or panics in crypto path

---

## Usage

```
secureapp E <file>
secureapp D <file>
```

Uppercase required:

- `E` → Encrypt file in place
- `D` → Decrypt file in place

Examples:

```
secureapp E document.pdf
secureapp D document.pdf
```

---

## How It Works

Encryption process:

1. Prompts for password.
2. Requires password confirmation.
3. Creates a temporary file.
4. Encrypts the original file into the temp file.
5. Flushes and finalizes output.
6. Renames the original file to a backup.
7. Atomically replaces the original with the encrypted file.
8. Removes the backup after success.

If any step fails:
- The original file remains intact.
- Temporary files are cleaned up.

Decryption follows the same atomic safety process.

---

## Cryptography

- Cipher: XChaCha20-Poly1305 (AEAD)
- Key derivation: Argon2id
- Argon2 memory cost: 128 MiB
- Argon2 iterations: 4
- Per-file random salt
- Per-chunk nonce derivation
- Full header used as Additional Authenticated Data (AAD)

All encrypted chunks are authenticated.  
Any tampering, corruption, or wrong password causes decryption to fail safely.

---

## Security Design Goals

SecureApp prioritizes:

- Data safety over convenience
- Atomic operations
- Explicit failure handling
- No silent data loss
- Strong password hardening
- Minimal attack surface

---

## Build

Requires stable Rust (1.70+ recommended).

```
cargo build --release
```

Binary will be located at:

```
target/release/secureapp
```

---

## Limitations

- Single-file encryption only
- Password-based encryption only
- No keyfile or public key support (yet)

---

## Future Improvements

- Optional high-security mode (256 MiB Argon2)
- Keyfile support
- Directory mode
- Secure wipe option
- Crash consistency with fsync
- Integration tests

---

## Warning

If you forget your password, your data cannot be recovered.

There is no backdoor.
There is no recovery mechanism.
There is no password reset.

Choose carefully.
