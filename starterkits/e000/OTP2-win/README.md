# otp2 — Windows‑only in‑place XOR transformer (one‑time‑pad style)

`otp2` is a tiny Windows‑only utility that **XOR‑transforms a file in place** using a key file named
`key.key` located **next to the executable**. If the key is truly random, at least as long as the
plaintext, used once, and kept secret, this can function as a *one‑time pad*. If the key is shorter
and wraps, this becomes **repeating‑key XOR** (obfuscation, not cryptography).

> ⚠️ **Security disclaimer**
>
> - Real OTP security requires a key that is: (1) truly random, (2) at least as long as the data, (3) never reused, and
>   (4) kept secret.  
> - If the key is shorter (wrapping), an attacker can recover plaintext via statistical/known‑plaintext attacks.
> - This tool provides *no authentication*. There is no integrity tag or MAC.


## Features

- **Windows‑only**, single‑binary tool (Rust).
- **Strict same‑directory policy**: the executable, the input file, and `key.key` must all live in the **same directory**.
- **Atomic in‑place replace**: writes to a temp file in the same directory, then replaces the original via
  `ReplaceFileW` with `WRITE_THROUGH`.
- **File locking**: exclusive lock on the input; shared lock on the key (via `fs2`).
- **Key wrapping**: if the key is shorter than the input, it wraps automatically.
- **Hygiene**: refuses to operate on the executable or on `key.key`; buffers are zeroized after use.
- **Permissions**: temp file ACL is tightened (gracefully skipped on FAT/exFAT) and read‑only attribute on the
  destination is cleared then restored during replace.


## Requirements

- **Windows** (x64 or ARM64)  
- **Rust** ≥ 1.78 (MSVC toolchain recommended)


## Build

```powershell
# From the project root
cargo build --release
# Output: .\target\release\otp2.exe
```

If you want a statically redistributable exe, use the MSVC toolchain that matches your target environment.


## Quick start

1. Put `otp2.exe` and a `key.key` file in the **same directory** as the file you want to transform.
2. Run the program with the **input file path** (relative paths are resolved relative to the exe’s directory).

```powershell
# Generate 1 MiB of random key material (PowerShell 5+)
$bytes = New-Object byte[] (1MB)
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
[IO.File]::WriteAllBytes("key.key", $bytes)

# Example usage — run from the directory containing otp2.exe, key.key, and the input file
.\otp2.exe .\secret.bin

# Running the tool a second time with the same key restores the original (XOR is its own inverse)
.\otp2.exe .\secret.bin
```

> ℹ️ **Same‑directory rule**  
> This is enforced to avoid cross‑volume renames and to keep atomic replacement and locking simple and reliable.


## Usage

```text
Usage: otp2 <INPUT>

Arguments:
  <INPUT>  INPUT file name (positional). If relative, resolved relative to the executable directory.

Options:
  -h, --help     Print help
  -V, --version  Print version
```

**Behavior:**

- Reads `key.key` next to the executable; errors if missing or empty.
- Streams the file through a 64 KiB buffer, XORing with a wrapping key stream.
- Writes to a temp file (`.otp-tmp-*`), flushes, then **atomically replaces** the input:
  - Uses `ReplaceFileW(WRITE_THROUGH)`.
  - Temporarily clears the **read‑only** attribute on the destination and restores it afterward.
  - Tightens the temp file’s ACL to: `D:P(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)` on NTFS. If the filesystem
    does not support ACLs (FAT/exFAT), this step is **skipped** gracefully.
- **Refuses** to transform `key.key` or the executable itself.
- Operates only on **regular files** (not directories, symlinks, etc.).


## Error cases you may see

- `input file '<path>' does not exist` — wrong name or path.
- `Input file must be in the same directory as the executable` — violates same‑dir rule.
- `refusing to transform 'key.key'` / `refusing to transform the executable itself` — safety guard.
- `key file is empty` — key exists but has zero length.
- `locking input file for exclusive access` — another process holds a lock.
- Windows ACL errors on non‑NTFS filesystems are handled as **no‑ops**; you won’t usually see an error for that.


## How it works (implementation notes)

- **Atomic replace**: The tool writes a complete transformed copy to a temp file in the same directory and calls
  `ReplaceFileW` with `REPLACEFILE_WRITE_THROUGH`. If the process crashes midway, the original file remains intact.
- **Locks**: Uses `fs2` advisory locks to prevent concurrent writers.
- **Zeroization**: Data and key buffers are wiped after each chunk (via `zeroize`).
- **No directory fsync**: On Windows, there is no portable directory fsync; `ReplaceFileW` with write‑through covers durability.


## Limitations & recommendations

- **Not authenticated**: There is no MAC or AEAD; an attacker can flip bits undetected.
- **Key reuse is dangerous**: Never reuse the same key material across different files if you care about secrecy.
- For modern, secure encryption with integrity, consider an AEAD like **ChaCha20‑Poly1305** (a different tool).


## Development

- Lints: the code uses `#![deny(unsafe_code)]` and isolates necessary Windows FFI into small modules with explicit `#[allow(unsafe_code)]`.
- Buffer size is fixed at **64 KiB**; adjust `BUF_CAP` to tune throughput vs. memory.

Run tests (if you add them) with:

```powershell
cargo test
```


## License

Dual‑licensed under **MIT** or **Apache‑2.0**. See `LICENSE-MIT` or `LICENSE-APACHE`.
