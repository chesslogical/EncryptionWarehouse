# securefile.zig

The first windows zig file encryptor ever known? lol Click on the executable, it opens a file selector- click on the file you want encrypted or decrypted and bam- its done. it needs a key.key (32 byte) in they same dir. It auto encrypts or decrypts. 

A Windows-only Zig application that securely encrypts or decrypts files using AES-256-GCM. It uses the Windows file open dialog to let you select a file, and encrypts or decrypts it in-place based on its header.

## Features

- AES-256-GCM encryption/decryption
- Detects whether a file is already encrypted via a magic header
- Uses Windows GUI (`GetOpenFileNameW`, `MessageBoxW`)
- Works on large files via chunking (1MB chunks)
- Simple `.key` file-based key management

## Usage

### 1. **Build the executable**

```sh
zig build-exe securefile.zig -O ReleaseSafe
```

### 2. **Generate a key**

You must create a 32-byte key file named `key.key` in the same directory:

```sh
zig run -e "std.crypto.random.bytes(&key); std.fs.cwd().createFile('key.key', .{}) catch unreachable;" -fno-link
```

Or manually:

```sh
openssl rand -out key.key 32
```

### 3. **Run the program**

Just run the executable. A file dialog will appear.

```sh
securefile.exe
```

- If the file is **unencrypted**, it will be encrypted.
- If the file is **already encrypted** (header starts with `ZIGC`), it will be decrypted.

You will see a message box on completion.

## File Format

The encrypted file format includes:
- 4-byte magic: `ZIGC`
- 1-byte version
- 4-byte chunk size
- 7 bytes reserved
- Then repeated chunks:
  - 12-byte nonce
  - 16-byte authentication tag
  - 4-byte ciphertext length
  - ciphertext bytes

## Requirements

- Windows
- Zig (master or latest stable recommended)

## License

MIT
