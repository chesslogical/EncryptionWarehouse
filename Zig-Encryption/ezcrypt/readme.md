
# ezcrypt no key or password needed, variables can be changed at compile time. 


Usage: ezcrypt 'filename'

- First run: Encrypts .
- Second run: Decrypts it back to original.

**Warnings:**
- Backup files before use, as operations are in-place.
- Empty files are not processed.
- Decryption requires the same key used for encryption.

## How It Works

1. Reads the entire file into memory.
2. Checks for the magic header.
   - If present: Extracts nonce and tag, decrypts the rest, writes back plaintext.
   - If absent: Generates random nonce, encrypts, prepends header (magic + nonce + tag), writes back.
3. Uses Zig's standard library for crypto (`std.crypto.aead.aes_gcm.Aes256Gcm`).

## Limitations

- File size limited by available memory (reads entire file).
- No support for directories or multiple files.
- Insecure if binary is decompiled (key is embedded).
- Not suitable for very large files or high-security needs.

## License

MIT License. Feel free to use, modify, and distribute.


Copyright (c) 2026 [Your Name or xAI]



