Below is a serious, security-engineer-grade README for your **current XChaCha20-Poly1305 version**.
It mirrors the tone and discipline of the AES version (1) , but accurately reflects the new design.

---

# ai

`ai` is a minimal, single-file XChaCha20-Poly1305 encryptor for Linux.

It performs authenticated encryption of an entire file in memory and atomically replaces the original file. The goal of this project is not feature richness, but correctness, simplicity, and disciplined use of modern AEAD cryptography.

This tool is Linux-only by design. It relies on Linux filesystem semantics (`rename`, `flock`, `mlock`) and does not attempt to be cross-platform. Reducing portability reduces complexity, which reduces risk.

---

## Usage

```
./ai anyfile.txt
```

If the file is not encrypted, it will be encrypted.
If the file is encrypted, it will be decrypted.

The program requires a 32-byte symmetric key stored in a file named:

```
key.key
```

The key file must be located in the same directory as the `ai` binary and the target file.

The tool operates only on files in its current working directory.

---

## Design Philosophy

This project deliberately avoids cleverness.

Cryptographic systems most often fail due to misuse, state complexity, and protocol errors — not because primitives are broken.

The safest strategy for a small encryption utility is:

* Use a well-studied AEAD construction.
* Use it in the simplest possible way.
* Avoid custom framing protocols.
* Avoid streaming unless strictly necessary.
* Avoid multi-layer abstractions.
* Fail closed.

`ai` encrypts the entire file in memory using XChaCha20-Poly1305 and replaces the original file atomically. There is no chunking protocol, no manual MAC composition, and no nonce management beyond per-file randomness.

This simplicity is intentional.

---

## Cryptographic Construction

`ai` uses:

* XChaCha20 stream cipher
* Poly1305 authenticator
* 256-bit symmetric key
* 192-bit (24-byte) nonce generated via the OS CSPRNG (`OsRng`)
* Authenticated encryption with associated data (AEAD)

XChaCha20-Poly1305 is a modern AEAD construction designed to provide strong security even under large-scale random nonce usage.

Each file encryption uses a fresh random 192-bit nonce. The nonce is stored in a small header at the beginning of the file.

The header (version + nonce) is bound as Associated Data (AAD). This ensures:

* The header cannot be modified without detection.
* Version metadata is authenticated.
* Nonce substitution attacks are prevented.

On decryption, the authentication tag is verified before any plaintext is written back to disk. If authentication fails, the operation aborts.

No partial plaintext is ever written if authentication fails.

---

## Why XChaCha20-Poly1305?

XChaCha20-Poly1305 is chosen because:

* It provides a 192-bit nonce, drastically reducing nonce collision probability.
* It is well suited for random nonce generation without coordination.
* It avoids the catastrophic failure properties of nonce reuse seen in GCM.
* It has wide analysis and production usage (e.g., libsodium, WireGuard, Tink).
* It does not rely on AES hardware acceleration.

For whole-file symmetric encryption with random nonces, XChaCha20-Poly1305 is a conservative and modern choice.

---

## Why Not Streaming?

Streaming AEAD introduces:

* Chunk framing logic
* State transitions
* Boundary validation complexity
* Partial write risks
* Larger attack surface

More code surface means more potential bugs.

`ai` reads the entire file into memory, performs one AEAD operation, verifies authentication, and atomically replaces the original file.

This approach:

* Avoids protocol complexity
* Eliminates chunk-boundary edge cases
* Ensures integrity verification before writing plaintext
* Reduces implementation risk

This tool is not intended for extremely large files. It prioritizes correctness over scalability.

---

## Reliability Properties

`ai` is designed to prioritize operational safety:

* Atomic file replacement via `rename`
* Directory fsync after replacement
* File locking (`flock`) to prevent concurrent modification
* Header authenticated as AAD
* Memory locking (`mlock`) for key material
* Zeroization of sensitive buffers
* Strict single-directory operation
* Fail-fast error handling

If decryption fails authentication, the file is not modified.

If encryption fails, the original file remains intact.

---

## Memory Handling

The symmetric key is:

* Loaded from disk
* Locked into RAM using `mlock` (when permitted by system limits)
* Zeroized before program exit

Plaintext buffers are also zeroized after use.

This does not guarantee immunity from memory extraction attacks, but reduces exposure to swap-based leakage and accidental retention.

---

## Threat Model

`ai` is designed to protect against:

* Offline attackers who obtain encrypted files
* Accidental corruption
* Unauthorized ciphertext modification
* Partial write failures during encryption/decryption

`ai` does not protect against:

* A compromised operating system
* A compromised process with memory access
* Key theft
* Malware running as the same user
* Side-channel attacks
* Physical memory extraction
* Swap inspection if `mlock` is disallowed
* Backup systems that captured plaintext before encryption

This is a local file encryption utility, not a hardened key management system.

---

## Key Management

Security depends entirely on the secrecy of the 32-byte symmetric key file.

If the key is lost, encrypted data is unrecoverable.

If the key is copied, encrypted data is compromised.

There is:

* No password-based key derivation
* No recovery mechanism
* No key escrow
* No key exchange
* No rotation system

Key management is external to this tool by design.

---

## File Format

Encrypted files contain:

* 1-byte version identifier
* 24-byte nonce
* AEAD ciphertext (includes Poly1305 authentication tag)

The header (version + nonce) is authenticated as Associated Data.

The tool detects encryption state by inspecting the version byte.

---

## Scope and Non-Goals

This project intentionally does not:

* Support password-based encryption
* Support streaming large files
* Implement key exchange
* Provide multi-user features
* Replace age, gpg, or OpenSSL
* Provide forward secrecy
* Provide deniability
* Provide key management

It is a minimal symmetric file encryptor for Linux.

---

## Security Disclosure

This project has not undergone formal cryptographic audit.

If you discover a vulnerability, please report it responsibly before public disclosure.

No security guarantees are made beyond correct usage of XChaCha20-Poly1305 within the described threat model.

---

## Summary

`ai` is deliberately small and disciplined.

Its security derives from:

* A modern AEAD construction
* Large nonces with safe random generation
* Header authentication
* Atomic file replacement
* Minimal format complexity
* Reduced attack surface
* Fail-closed behavior

It is not ambitious.
It is not feature-rich.

It is intentionally simple.

And that simplicity is its primary security property.
