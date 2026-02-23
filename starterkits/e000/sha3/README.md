

<img width="745" height="586" alt="sha" src="https://github.com/user-attachments/assets/7f68cc06-cbef-4c59-986b-b02253113fd2" />






# sha3 — Windows GUI SHA3-512 Hasher (Rust)

A tiny Windows GUI app written in Rust that computes the **SHA3‑512** hash (hex) of your input text.
Built with [`eframe`/`egui`] for a clean native window.

## Features
- Type or paste text; hash is computed over the **exact UTF‑8 bytes**
- **Compute** button and optional **Hash as you type**
- **Uppercase** hex toggle
- **Copy result** button
- **Test with “abc”** button (handy for quick verification)

---

## Requirements
- Windows 10/11 (x64)
- Rust toolchain (latest stable recommended): https://rustup.rs
- On first build, you may need the **Microsoft C++ Build Tools / Windows SDK** (install “Desktop development with C++” in Visual Studio Build Tools) so `winit/eframe` can link Windows system libraries.

## Quick start

```powershell
# from the project root
cargo run
# build an optimized, console-less release exe:
cargo build --release
```

The compiled binary will be at:

```text
target\release\sha3.exe
```

> **Note:** In debug builds you may see a console window; release builds hide it via the
> `windows_subsystem = "windows"` attribute.

---

## Usage

1. Launch `sha3.exe`.
2. Type/paste your input text.
3. Click **Compute** (or enable **Hash as you type**).
4. Use **Uppercase hex** if you prefer capital letters.
5. Click **Copy result** to copy the digest to the clipboard.

### Test vectors

- Input: `abc`
  ```
  b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
  ```
- Input: empty string `""`
  ```
  a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
  ```

These match the SHA‑3 reference test vectors.

---

## Project structure

```text
sha3/
├─ Cargo.toml
├─ README.md
└─ src/
   └─ main.rs
```

- **GUI framework**: `eframe = "0.32"` (bundles `egui`)
- **Hashing**: `sha3` crate, aliased as `sha3_crate` in `Cargo.toml` to avoid a name conflict with this package.

---

## Troubleshooting

- **Link errors or Windows headers not found**: install **Visual Studio Build Tools** with the “Desktop development with C++” workload (includes the Windows 10/11 SDK).
- **Old `eframe`/`egui` causes `winapi` feature errors**: make sure `eframe = "0.32"` (or newer). This project already pins a fixed version.
- **Antivirus flags the EXE**: some AVs are aggressive with fresh Rust builds. Signing the binary or adding an exception typically resolves it.

---

## Customizing

- **Binary hashing**: to hash file contents instead of text, add a “Browse…” file picker and stream bytes into the hasher (`hasher.update(chunk)`).
- **Other SHA variants**: swap `Sha3_512` with `Sha3_256`, `Keccak256`, etc., and adjust labels accordingly.

---

## License
No license is specified. If you plan to distribute this, add a license of your choice to `Cargo.toml` and include a `LICENSE` file.

---

## Credits
- GUI: [`eframe` / `egui`]
- Hashing: RustCrypto’s [`sha3`] crate

[`eframe` / `egui`]: https://github.com/emilk/egui
[`sha3`]: https://github.com/RustCrypto/hashes
