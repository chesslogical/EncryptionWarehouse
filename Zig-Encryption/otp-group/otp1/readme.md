# 🔐 One-Time Pad CLI - Zig

A minimal command-line application written in [Zig](https://ziglang.org/) that performs One-Time Pad (OTP) encryption using XOR. This loads key and file into memory which is fine for a gaming computer with 64gb ddr5. But only use about 1/4 of your avail ram to  be safe!! For example 16 gb of ram, os uses some so you prolly want to stick to not much larger than 4 gb files or so. key takes up 4gb, file takes up 4gb too! 

---

## 📦 Features

- Encrypts a file using a key file via XOR
- Checks that the key is at least as long as the input
- Command-line interface (non-interactive)
- Lightweight and fast — no dependencies

---

## ⚙️ Usage

### 🛠️ Build

Make sure you have Zig installed: https://ziglang.org/download/

```bash
zig build-exe otp.zig
```

This creates a binary `otp` (or `otp.exe` on Windows) in your current directory.

### ▶️ Run

```bash
./otp <input_file> <output_file> <key_file>
```

**Example:**

```bash
./otp secret.txt encrypted.bin otp.key
```

To decrypt, run the exact same command again with:

- `encrypted.bin` as the new input
- `decrypted.txt` as the new output
- `otp.key` must be the same key used for encryption

```bash
./otp encrypted.bin decrypted.txt otp.key
```

---

## 🧪 Notes

- The key file **must** be at least as long as the input file.
- Output file will be overwritten if it exists.
- XOR is symmetrical — encryption and decryption are the same process.

---

## 📁 File Structure

```
.
├── otp.zig       # Main source file
├── a.txt         # Input file (example)
├── key.key       # Key file (example)
├── b.txt         # Output file (example)
```

---

## 🔐 Disclaimer

This is a learning/demo tool. While OTP encryption is theoretically unbreakable, **secure key management and one-time usage** are essential for real-world security.

---

## 🧠 Author

Made with ❤️ in Zig by Ai.

