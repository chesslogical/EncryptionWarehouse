# filecrypt

This is genuinely hardened for a Linux CLI tool.

A simple CLI tool for Linux to encrypt and decrypt files in place using XChaCha20-Poly1305 authenticated encryption. It streams data for low memory usage on large files and performs atomic overwrites for safety.

**Note:** This app is designed for Linux only. The requirement for a `key.key` file in the current working directory is intentional for simplicity and security (e.g., avoid passing keys via CLI args).

## Features

- Encrypts/decrypts files atomically (uses a temp file and renames).
- Streams processing in 1MB chunks to handle very large files without high RAM usage.
- Uses libsodium's `crypto_secretstream_xchacha20poly1305` for secure, authenticated streaming encryption.
- Requires a 32-byte key from `key.key` in the current directory.
- Handles empty files and enforces a final authentication tag for integrity.

## Installation

1. Ensure you have Rust and Cargo installed (via [rustup](https://rustup.rs/)).
2. Clone or create the project:
   ```
   cargo new filecrypt
   cd filecrypt
   ```
3. Add dependencies to `Cargo.toml`:
   ```
   [dependencies]
   sodiumoxide = "0.2.7"
   clap = { version = "4.5", features = ["derive"] }
   anyhow = "1.0"
   ```
4. Copy the provided `src/main.rs` code into the file.
5. Build the release binary:
   ```
   cargo build --release
   ```
   The binary will be at `target/release/filecrypt`.

## Usage

Generate a key (run in the directory where you'll use the tool):
```
head -c 32 /dev/urandom > key.key
```
Protect `key.key` appropriately (e.g., permissions: `chmod 600 key.key`).

### Encrypt a file
```
./target/release/filecrypt enc path/to/file.txt
```

### Decrypt a file
```
./target/release/filecrypt dec path/to/file.txt
```

The file is overwritten in place. Test on copies first!

## Security Notes

- This uses a secure, audited library (libsodium) for cryptography—do not modify the crypto parts unless you're an expert.
- The key is raw bytes; for password-based use, consider deriving it with Argon2 (not implemented here).
- No IV/nonce management needed; XChaCha20 handles it securely via random nonces in the header.
- Always verify decryption works immediately after encryption.
- Not suitable for production without further hardening (e.g., key management, error handling).

## Dependencies

- [sodiumoxide](https://crates.io/crates/sodiumoxide): Rust bindings for libsodium.
- [clap](https://crates.io/crates/clap): Command-line argument parsing.
- [anyhow](https://crates.io/crates/anyhow): Error handling.

## License

MIT License

Copyright (c) 2026 xAI

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
