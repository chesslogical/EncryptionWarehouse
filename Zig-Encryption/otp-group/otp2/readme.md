
# 📜 OTP Encryptor

A simple Zig program that encrypts or decrypts a file using a one-time pad (XOR) method. This uses memory chunking so it can handle very large files! 

## ✨ Features
- Takes three files as input: 
  - **Input file** (data to encrypt/decrypt)
  - **Key file** (must be at least as large as input file)
  - **Output file** (where the encrypted/decrypted result is saved)
- Processes the files **in chunks** (streaming), so it works efficiently even for **very large files**.
- Minimal memory usage.

## 📦 Building

Make sure you have [Zig](https://ziglang.org/download/) installed.

Then run:

```sh
zig build-exe otp.zig
```

This will produce an executable `otp.exe` (Windows) or `otp` (Linux/Mac).

## ⚡ Usage

```sh
./otp <input_file> <output_file> <key_file>
```

Example:

```sh
./otp secret.txt secret.enc mykey.bin
```

This will encrypt `secret.txt` with `mykey.bin`, producing `secret.enc`.

To decrypt:

```sh
./otp secret.enc secret_dec.txt mykey.bin
```

(Since XOR is reversible, the same operation decrypts it!)

## ⚠️ Important Notes
- The key file **must be at least as large** as the input file.
- If the key file is smaller, the program will report an error and exit.
- For maximum security (true OTP encryption), use a **random key** that is **never reused**.

---

---

## 🧠 Author

Made with ❤️ in Zig by [Ai].

