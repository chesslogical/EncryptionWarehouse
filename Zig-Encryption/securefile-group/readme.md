# 🔐 securefile.zig

compiled on zig 0.15.1

A safe, in-place, streaming AES-256-GCM file encryption tool written in pure Zig.  
Automatically detects whether a file is encrypted using a magic `"ZIGC"` header and performs encryption or decryption accordingly.

---

## ✅ Features

- **AES-256-GCM** encryption using Zig's standard library
- **Magic header (`ZIGC`)** auto-detects encrypt/decrypt mode
- **Chunked streaming** (1MB chunks, configurable)
- **In-place processing** via temporary file + atomic rename
- **Key required**: a `key.key` file (must be 32 bytes)
- **Zero dependencies** — pure Zig code
- **Cross-version compatible** — works with all Zig 0.11–0.15

---

## 🚀 Usage

### 1. Build

```sh
zig build-exe securefile.zig -O ReleaseSafe
```

### 2. Create a key

Create a 32-byte key file named `key.key`:

```sh
echo -n "01234567890123456789012345678901" > key.key
```

> ⚠️ Must be exactly 32 bytes! No newline.

### 3. Encrypt a file

```sh
./securefile myfile.txt
```

→ This will overwrite `myfile.txt` with the encrypted version.

### 4. Decrypt the same file

```sh
./securefile myfile.txt
```

→ This will detect it’s encrypted and restore the original plaintext.

---

## 🔍 How It Works

- The app reads the first 4 bytes of the file.
- If they match the magic string `"ZIGC"`, it runs **decryption**.
- Otherwise, it runs **encryption**.
- Writes the result to a temp file (`.securefile.tmp`), then atomically renames it to the original.

---

## 🔐 File Format

Each encrypted file begins with:

| Field        | Size  | Description              |
|--------------|-------|--------------------------|
| Magic        | 4 B   | `"ZIGC"` (ASCII)         |
| Version      | 1 B   | Currently `0x01`         |
| Chunk size   | 4 B   | e.g. `0x00100000` (1MB)  |
| Reserved     | 7 B   | All zero (future use)    |

Each chunk after that:

| Field        | Size            |
|--------------|-----------------|
| Nonce        | 12 bytes        |
| Tag          | 16 bytes        |
| Length       | 4 bytes (u32)   |
| Ciphertext   | `length` bytes  |

---

## ✅ Safety Highlights

- Will **not encrypt a file twice** (auto-detects encrypted files)
- Will **fail** if:
  - Header is corrupted
  - `key.key` is wrong or missing
  - Decryption tag check fails
- Never overwrites input unless the operation fully succeeds

---

## 🔧 Customization Ideas

You can easily extend this project to add:
- Password-based encryption (PBKDF2 or Argon2)
- Command-line flags (`--encrypt`, `--decrypt`, `--out`)
- File integrity verification (checksums)
- Embedded file metadata or timestamps

---

## 🛠 Built With

- Zig `0.11+`
- `std.crypto.aead.aes_gcm.Aes256Gcm`
- `std.fs`, `std.mem`, `std.fmt`, and zero third-party code

---

## ✨ Example Session

```bash
$ echo "Hello World" > hello.txt
$ ./securefile hello.txt
✅ Encryption complete → hello.txt

$ ./securefile hello.txt
✅ Decryption complete → hello.txt

$ cat hello.txt
Hello World
```

---

## 📂 License

MIT — do what you want, just don't double encrypt 😄

---

Happy Ziging! 🔐🦎

