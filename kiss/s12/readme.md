


# serpent2

**Simple, reliable, Linux-only command-line file encryptor using Serpent-256**

A minimal, modern encrypted file container tool that deliberately uses the **Serpent** block cipher (instead of the more common AES or ChaCha).

- Serpent-256 in CBC mode + PKCS#7 padding  
- HMAC-SHA256 authentication (header + ciphertext)  
- Strong Argon2id key derivation (~190 MiB memory, 4 iterations)  
- Interactive password prompt (never visible in process list or history)  
- Atomic file writes with automatic `.bak` backup  
- Memory zeroization of plaintext and keys  

Designed for personal/offline use on Linux systems.

## Features

- **Encryption**: `serpent2 encrypt <file>` → overwrites file with encrypted version  
- **Decryption**: `serpent2 decrypt <file>` → restores original content  
- Always creates a `.bak` backup before overwriting (safety first)  
- Password never passed as argument → uses secure prompt  
- Strong, modern cryptography: Argon2id + Serpent-256 + HMAC-SHA256  
- No external configuration files or dependencies beyond Rust crates  
- Crash-safe writes (tmp file → fsync → atomic rename)  

## Security notes

- Serpent is used correctly: 256-bit key (derived), fresh random IV per file, outer HMAC prevents padding oracle and truncation attacks  
- Argon2id parameters are conservative but still reasonably fast (~0.5–2 seconds on 2025–2026 hardware)  
- Keys and plaintext buffers are zeroized on drop (via `secrecy` crate)  
- In-place overwrite + backup reduces risk of data loss on wrong password or crash  
- **Limitations**: entire file loaded into RAM (not suitable for extremely large files > RAM)  
- **Not audited** — hobby project / for personal fun & learning  

## Installation / Build

```bash
# Clone or extract the project
git clone <your-repo> serpent2
cd serpent2

# Build release binary
cargo build --release

# The binary will be at:
./target/release/serpent2
```

## Usage

```bash
# Encrypt a file
./serpent2 encrypt document.txt
# → will prompt for password twice

# Decrypt it back
./serpent2 decrypt document.txt
# → prompt for the same password

# After either command:
#   - original file is overwritten
#   - backup is created as document.txt.bak
```

Example session:

```
$ ./serpent2 encrypt secret-notes.md
Password: 
Confirm: 
Encrypted → secret-notes.md → secret-notes.md.bak created

$ ./serpent2 decrypt secret-notes.md
Password: 
Decrypted → secret-notes.md → secret-notes.md.bak created
```

## Dependencies (Cargo.toml excerpt)

```toml
[dependencies]
anyhow     = "1.0"
argon2     = "0.5"
cbc        = "0.1"
cipher     = "0.4"
hmac       = "0.12"
hkdf       = "0.12"
rand       = "0.8"
rpassword  = "7.3"
secrecy    = "0.8"
sha2       = "0.10"
serpent    = "0.5.1"
zeroize    = "1.8"
num_cpus   = "1.16"
```

## Why Serpent?

Most modern tools use ChaCha20-Poly1305 or AES-GCM.  
Serpent (one of the AES finalists) is still considered cryptographically strong in 2026, has a 128-bit block size, and is a nice alternative for people who want diversity or just like its design.

## Future ideas (maybe)

- Optional `--no-backup` or `--output <file>` flags  
- Very basic progress messages for large files  
- Optional env-var password fallback (with warning)  
- Streaming mode for huge files  

## License

MIT or Apache-2.0 (your choice)

---

Made for fun & learning — use at your own risk.  
Enjoy Serpent! 🐍🔐
```
