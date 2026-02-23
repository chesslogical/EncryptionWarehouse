# 🔐 AES-256-GCM File Encryptor (Zig)

This is a minimal AES-256-GCM file encryption and decryption tool written in [Zig](https://ziglang.org/), designed for simplicity, control, and portability.

It uses a user-provided 256-bit key file for encryption and decryption — no key is ever generated or written by the app.

---

## ⚙️ Features

- Encrypt or decrypt files using AES-256-GCM (128-bit block, 256-bit key)
- Authenticated encryption with nonce + tag
- Requires you to provide your own key file (must be exactly 32 bytes)
- Minimal dependencies — uses only Zig’s standard library
- Fully CLI-based, cross-platform, and easy to audit

---

## 📦 Usage

```sh
aes <enc|dec> <input_file> <output_file> <key_file>
```

| Argument     | Description                        |
|--------------|------------------------------------|
| `enc`/`dec`  | Encrypt or decrypt                 |
| `input_file` | File to read (plaintext or cipher) |
| `output_file`| File to write (cipher or plain)    |
| `key_file`   | 256-bit key file (must exist)      |

---

### 🔒 Example: Encrypt

```sh
./aes enc message.txt encrypted.bin mykey.bin
```

### 🔓 Example: Decrypt

```sh
./aes dec encrypted.bin output.txt mykey.bin
```

---

## 🔑 Key File

- The `key_file` must exist and contain **exactly 32 bytes**
- The key is not generated or modified by this app
- You can generate a key like this:

### ✅ Option 1: With OpenSSL

```sh
openssl rand -out mykey.bin 32
```

### ✅ Option 2: With Zig

```zig
const std = @import("std");
pub fn main() !void {
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);
    const file = try std.fs.cwd().createFile("mykey.bin", .{});
    defer file.close();
    try file.writeAll(&key);
}
```

---

## 📄 Encrypted File Format

```
|  12 bytes  |  16 bytes  |    N bytes    |
|   Nonce    |    Tag     |  Ciphertext   |
```

All output is written as raw binary (`.bin`), suitable for secure file transport.

---

## 🧪 Compile

Make sure you have Zig installed:

```sh
zig build-exe aes.zig
```

Run:

```sh
./aes enc input.txt out.enc mykey.bin
```

---

## 🛑 Error Behavior

- If key file is missing → error
- If key file is the wrong size → error
- This app never overwrites or creates the key file

---

## 🧠 Why Zig?

- Small, clean, and low-overhead
- No runtime, GC, or surprises
- Great for building secure CLI tools that you can audit line-by-line

---

## 📘 License

MIT — use freely, encrypt responsibly 🔐
