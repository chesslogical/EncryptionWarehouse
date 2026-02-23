# s1 


A simple CLI tool for Linux that toggles encryption on files using AES-256-GCM-SIV. It automatically detects if a file is encrypted (based on a magic header) and either encrypts or decrypts it accordingly. Designed for rock-solid reliability and data integrity, processing files entirely in memory (no chunking/streaming) with atomic overwrites, integrity hashes, and metadata preservation.

Important: This tool overwrites files in place. Always back up your data before use—do not encrypt the only copy of important files!



# Features

  Encryption Mode: AES-256-GCM-SIV for authenticated encryption.
  Key Requirement: Uses a fixed 32-byte key from 1.key in the current directory.
  Auto-Detection: Checks for magic header ENC_SIV_ + version byte.
  Integrity Checks: Embeds SHA-256 hash for post-decryption verification.
  Atomic Operations: Uses temporary files for safe overwrites.
  Linux-Only: Relies on Unix-specific metadata handling.
  In-Memory Processing: Loads entire file into RAM for simplicity and reliability (suitable for files that fit in memory).

Crates: aes-gcm-siv, aead, rand, tempfile, anyhow, sha2, zeroize

Build the binary:  cargo build --release

# Usage

Run the tool in the directory containing your file and 1.key.

./s1 <filename>

  If the file is plaintext, it will be encrypted.
  If encrypted, it will be decrypted.
  Output: "ok" on success.


# Generating a Key

Create a secure 32-byte key file:

dd if=/dev/urandom of=1.key bs=32 count=1
chmod 600 1.key  # Recommended for security



# Limitations

  Files must be in the current working directory (no paths allowed).
  Cannot operate on directories, the key file itself, or special dirs like ./...
  No support for very large files (due to in-memory loading).
  No password derivation—uses raw key file for simplicity.


# Security Notes

  Key is zeroized from memory after use.
  Preserves original file permissions and timestamps.
  Detects corruption via AEAD tags and embedded hashes.

If issues arise (e.g., decryption failures), check key validity and file integrity.


# License

 Do as you wish. 










  

