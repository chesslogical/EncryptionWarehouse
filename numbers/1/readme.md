Here is a serious, honest, security-engineer-grade README.

It avoids hype, explains the design decisions clearly, and sets proper expectations.

usage ./ai anyfile.txt (if the file is not encrypted, it will be encrypted. If the file is encerypted, it will be decrypted. It relies on a 32 byte key called key.key that is in the same dir. 



---

# ai

`ai` is a minimal, single-file AES-256-GCM encryptor for Linux.

It is intentionally small. It performs authenticated encryption of an entire file in memory and atomically replaces the original file. The goal of this project is not feature richness, but correctness, simplicity, and disciplined use of modern AEAD cryptography.

This tool is Linux-only by design. It relies on Linux filesystem semantics and does not attempt to be cross-platform. Reducing portability reduces complexity, which reduces risk.

---

## Design Philosophy

This project deliberately avoids cleverness.

Cryptography fails most often not because primitives are broken, but because they are misused. The safest strategy for a small encryption tool is:

* Use a well-studied AEAD construction.
* Use it in the simplest possible way.
* Minimize state.
* Minimize format complexity.
* Avoid streaming protocols unless absolutely necessary.
* Fail closed.

`ai` encrypts the entire file in memory using AES-256-GCM and replaces the original file atomically. There is no chunking protocol, no custom framing, no hand-rolled MAC, and no nonce bookkeeping system beyond a per-file random nonce.

This simplicity is intentional.

---

## Cryptographic Construction

`ai` uses:

* AES-256 in Galois/Counter Mode (GCM)
* 256-bit symmetric key
* 96-bit nonce generated via the OS CSPRNG (`OsRng`)
* Authenticated encryption with integrity verification

AES-GCM is a NIST-standard AEAD construction and is widely deployed in TLS, SSH, QUIC, and other production systems. It provides both confidentiality and integrity in a single primitive.

Each file encryption uses a fresh random 96-bit nonce. The nonce is stored in a small header at the beginning of the file. On decryption, the authentication tag is verified before any plaintext is written back to disk. If authentication fails, the operation aborts.

No partial plaintext is ever written if authentication fails.

---

## Why AES-256-GCM?

AES-256-GCM is chosen because:

* It is a standard, widely analyzed AEAD mode.
* It is hardware accelerated on modern CPUs (AES-NI).
* It provides authenticated encryption (confidentiality + integrity).
* It is well supported in Rust through mature crates.
* It avoids the need to compose encryption and MAC manually.

AES-256 instead of AES-128 is chosen for conservative security margin. AES-128 is already considered secure, but AES-256 provides additional theoretical margin at negligible performance cost on modern hardware.

For this use case — whole-file symmetric encryption — AES-256-GCM is an appropriate and conservative choice.

---

## Why Not AES-SIV?

AES-SIV (Synthetic IV) is designed to be misuse-resistant, particularly in scenarios where nonce reuse is a realistic risk.

`ai` generates a fresh 96-bit nonce per file using the operating system’s cryptographically secure random number generator. There is no user-controlled nonce input and no deterministic nonce derivation.

Because nonce generation is centralized and automatic, the risk of nonce reuse is already extremely low.

AES-SIV would add complexity and performance cost without meaningfully improving the threat model for this tool. Simplicity and correctness are prioritized over theoretical misuse resistance that does not address a realistic failure mode in this context.

---

## Why Whole-File In-Memory Encryption?

Streaming AEAD implementations introduce:

* Chunk framing logic
* State management
* Boundary error risk
* Partial write complexity
* More code surface

More surface means more potential bugs.

`ai` reads the entire file into memory, encrypts it in one AEAD operation, and atomically replaces the original file.

This approach:

* Avoids protocol complexity
* Eliminates chunk-boundary edge cases
* Ensures integrity is verified before writing decrypted data
* Reduces implementation risk

This tool is not intended for extremely large files. It prioritizes correctness over scalability.

---

## Reliability Properties

`ai` is designed to prioritize operational safety:

* Atomic file replacement using rename semantics
* File locking to prevent concurrent modification
* Authentication verification before writing plaintext
* Zeroization of sensitive buffers
* Minimal file format
* Fail-fast error handling

If decryption fails authentication, the file is not modified.

If encryption fails, the original file remains intact.

---

## Threat Model

`ai` is designed to protect against:

* Offline attackers who obtain a copy of the encrypted file
* Accidental file corruption
* Unauthorized modification of ciphertext
* Partial write failures during encryption/decryption

`ai` does not protect against:

* A compromised operating system
* A compromised process with memory access
* Key theft
* Malware running as the same user
* Side-channel attacks
* Physical memory extraction
* Swap inspection unless mlock is enabled
* Backup systems that captured plaintext before encryption

This is a local file encryption utility, not a hardened key management system.

---

## Key Management

The security of the system depends entirely on the secrecy of the symmetric key file.

If the key is lost, encrypted data is unrecoverable.

If the key is copied, encrypted data is compromised.

There is no password-based key derivation, no key escrow, and no recovery mechanism.

Key protection is the responsibility of the user.

---

## File Format

Encrypted files contain:

* A magic header
* A nonce
* AES-GCM ciphertext including authentication tag

On execution, the tool detects whether the file is encrypted based on the header and either encrypts or decrypts automatically.

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

It is a minimal symmetric file encryptor for Linux.

---

## Security Disclosure

This project has not been formally audited.

If you discover a security issue, please open an issue or contact the maintainer privately before public disclosure.

No security guarantees are made beyond correct usage of AES-256-GCM within the described threat model.

---

## Summary

`ai` is a deliberately small and disciplined encryption tool.

Its security comes from:

* Using a standard AEAD primitive
* Avoiding custom constructions
* Reducing complexity
* Minimizing state
* Failing closed

It is not ambitious. It is not feature-rich.

It is intentionally simple.

And that simplicity is its primary security property.
