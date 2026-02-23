# OTP2 – Simple in‑place OTP‑style XOR Utility

*Version 3.1.0 • MIT OR Apache‑2.0 • Rust 1.78+*

**Binary name:** defaults to `key` in this repo. If you prefer `otp`, see [Binary name](#binary-name).

---

## Contents

- [Overview](#overview)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Key length behavior](#key-length-behavior)
- [Security notes (important)](#security-notes-important)
- [Safety model](#safety-model)
- [Install & build](#install--build)
- [Binary name](#binary-name)
- [Dependencies (and how to slim)](#dependencies-and-how-to-slim)
- [Common errors & fixes](#common-errors--fixes)
- [Troubleshooting](#troubleshooting)
- [How it works (implementation)](#how-it-works-implementation)
- [FAQ](#faq)
- [License](#license)
- [Changelog](#changelog)

---

## Overview

**OTP** is a tiny command‑line tool that XOR‑transforms a file using bytes from `key.key`. It is intentionally simple and hard to misuse:

- Always encrypts **in place** via a safe temporary file + atomic replace.
- **Requires** `key.key` to be present in the *same directory* as the executable and the input file.
- Key bytes **wrap** if shorter than the file; if the key is long enough, it’s *1:1 byte‑for‑byte* with no wrapping.
- XOR is symmetric: running the tool again with the same key restores the original file.

> **Heads up:** XOR with a *repeating* key is not a perfect one‑time pad. For true OTP guarantees, the key must be uniformly random, at least as long as the message, kept secret, and used only once.

---

## Quick start

1. Place `key.exe` (Windows) or `key` (Linux/macOS), your target file (e.g., `example.txt`), and `key.key` in the **same folder**.
2. Open a terminal in that folder.
3. Run:

```bash
# Windows (PowerShell / cmd)
.\key.exe example.txt

# macOS / Linux
./key example.txt

# If you renamed the binary to 'otp':
./otp example.txt
```

This transforms `example.txt` in place using `key.key`. Run the same command again to get the original back. *Optional:* verify with a hash (`shasum` / `certutil -hashfile`) before/after.

---

## Usage

```
Usage: key <INPUT>

Positional arguments:
  INPUT   Path to the file to transform.
          If relative, it is resolved relative to the executable's directory.

Requirements:
  - key.key must exist next to the executable.
  - INPUT must be in the same directory as the executable.
```

*Note:* Relative paths are resolved relative to the executable’s directory, **not** the current working directory. Symlinks are resolved to ensure the files are truly in the same directory.

### Examples

```bash
# Encrypt/decrypt example.txt in place
./key example.txt

# Different folder? Move all three next to each other:
#   C:\secure\key.exe, C:\secure\example.txt, C:\secure\key.key
# then run:
C:\secure> .\key.exe example.txt
```

---

## Key length behavior

- **Key ≥ file size:** reads exactly one key byte for every file byte. No wrap occurs; mapping is strictly byte‑for‑byte.
- **Key shorter than file:** reads until EOF on the key, then seeks back to the start and continues (wrap). This repeats as needed until the file is done.

The logic ensures that chunked I/O is correct: the key file handle’s position is preserved across chunks, and wrapping only occurs when EOF is actually reached.

---

## Security notes (important)

**Do not reuse keys across different files** if you care about confidentiality. Reusing a short (wrapping) key across messages enables classical XOR attacks.

- For true one‑time‑pad properties: generate a *uniformly random* key that is at least as long as the file, use it once, and destroy it afterwards.
- Prefer generating keys with a CSPRNG:
  - *Linux/macOS:* `head -c 1048576 /dev/urandom > key.key` (example: 1 MiB)
  - *Windows PowerShell:*
    ```powershell
    [byte[]]$b = New-Object byte[] 1048576
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    [IO.File]::WriteAllBytes("key.key", $b)
    ```
  - *Cross‑platform (OpenSSL):* `openssl rand -out key.key 1048576`
- Store keys securely; back them up if you might need to decrypt later.

---

## Safety model

- **Same‑directory rule:** executable, input file, and `key.key` must be siblings. Paths are canonicalized to avoid symlink/junction tricks.
- **In‑place via temp + atomic replace:** writes to a temporary file in the same directory, flushes and syncs it, then atomically replaces the original:
  - *Windows:* `ReplaceFileW` with write‑through; destination metadata/ACLs are preserved.
  - *Unix:* same‑dir `rename()` and directory fsync for crash durability.
- **Cleanup on failure:** a guard deletes the temp file if anything fails before replacement.
- **Locks:** input is locked exclusively; key is locked shared; temp output is locked exclusively, limiting races with other processes.
- **Race defense (Unix):** aborts if the input path’s device/inode changes mid‑run (indicates the file was swapped).
- **Non‑regular files:** refuses to transform non‑regular files (e.g., devices, FIFOs). Operates on regular files only.
- **Permissions:** data and key buffers are zeroized after each write. On Unix, the resulting file’s mode is preserved *minus setuid/setgid* for safety. On Windows, read‑only is temporarily cleared and *restored even on failure*.

> **Tip:** While in‑place is convenient, you should still keep a backup or test on a copy first—especially with critical data.

---

## Install & build

### Prerequisites
- Rust 1.78+ (`rustup` recommended)
- Windows, macOS, or Linux

### Build

```bash
git clone <your repo> otp
cd otp
cargo build --release
# Binaries:
#   target/release/key     (macOS/Linux)
#   target/release/key.exe (Windows)
```

### Layout for use

```
# Place these three together:
key[.exe]
example.txt
key.key
```

Then run: `./key example.txt`

---

## Binary name

By default this repo’s package is named `key`, producing a `key`/`key.exe` binary. If you prefer the binary name `otp` without changing the crate name, add this to `Cargo.toml`:

```toml
[[bin]]
name = "otp"
path = "src/main.rs"
```

---

## Dependencies (and how to slim)

| Crate       | Why it’s used                                              | Can I remove it?                                                                 |
|-------------|-------------------------------------------------------------|----------------------------------------------------------------------------------|
| `clap`      | Parses the positional input argument.                       | Possible but not recommended; you’d hand‑roll `std::env::args()`.               |
| `anyhow`    | Friendly errors with context.                               | Optional; replace with `Result<(), Box<dyn Error>>` and manual `map_err`s.      |
| `tempfile`  | Safe temp file in same dir before atomic replace.           | **Keep.** Central to safe in‑place behavior.                                     |
| `fs2`       | File locking to prevent races with other processes.         | Recommended; remove only if you accept race risks and delete lock calls.        |
| `zeroize`   | Zeroes buffers after use.                                   | Optional; drop the `zeroize()` calls if removed.                                 |
| `same‑file` | Robust cross‑platform “same file?” checks (hard‑link safety).| Not recommended; removing weakens safety checks.                                 |
| `winapi`    | ACL tightening + constants for the Windows atomic replace.  | Optional; remove Windows hardening if you don’t need it.                         |

---

## Common errors & fixes

| Message                                                           | Meaning                                                          | Fix                                                                                   |
|-------------------------------------------------------------------|------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| `input file '...' does not exist`                                 | Path typo or wrong folder.                                       | Move the input next to the executable, or fix the filename.                           |
| `Input file must be in the same directory as the executable`      | Same‑dir requirement violated.                                   | Move the file next to the binary.                                                     |
| `refusing to transform 'key.key'`                                 | Safety guard to avoid clobbering the key.                        | Choose a different input file.                                                        |
| `refusing to transform the executable itself`                     | Safety guard to avoid clobbering the program you’re running.     | Choose a different input file.                                                        |
| `refusing to transform non-regular file '...'`                    | The target is not a regular file (e.g., device, FIFO).           | Use a regular file as input.                                                          |
| `key file is empty`                                               | The key file has 0 bytes.                                        | Generate a non‑empty random key (ideally via CSPRNG).                                 |
| `key file became unreadable during processing`                    | Another process truncated/locked the key mid‑run.                | Close other apps, ensure key isn’t modified, and retry.                               |
| `input file was replaced during processing; aborting...` (Unix)   | Detected that the input path started pointing to a different file (race). | Retry after ensuring nothing touches or swaps the file.                      |
| `Access is denied` (Windows, during replace)                      | Another process holds the file, or AV is scanning it.            | Close other apps using the file or exclude the folder and retry.                      |

*Exit status:* returns non‑zero on error.

---

## Troubleshooting

- **Windows: replace failed / access denied** – Make sure no other program is holding the input file open. The tool drops handles and temporarily clears read‑only before replacing (and restores it), but other locks can still block.
- **Antivirus interference** – Some AVs hold temp files briefly. Excluding the folder can help.
- **Network drives / NFS / SMB** – Locking/rename semantics vary and may not be fully atomic. Prefer local disks for reliability.
- **Huge files** – Streams in 64 KiB chunks; RAM use is small and constant.

---

## How it works (implementation)

1. Resolve paths and enforce that executable, input, and `key.key` are siblings (canonicalized).
2. Open input (exclusive lock) and key (shared lock); verify key isn’t empty.
3. Create a temp file in the same directory; on Windows, tighten its ACL.
4. Loop:
   - Read next chunk of data (up to 64 KiB).
   - Fill a key buffer of equal size using `fill_key_slice`: reads from current key position; on EOF, seek to start and continue.
   - XOR the two buffers and write to the temp file, then zeroize both buffers.
5. Flush and `sync_all` the temp file; drop all handles.
6. On Unix, verify the input path still refers to the same file (device+inode). On Windows, temporarily clear read‑only.
7. Atomically replace the input with the temp file (*Windows:* `ReplaceFileW` write‑through; *Unix:* same‑dir `rename()`), then fsync the directory on Unix.

This design ensures byte‑for‑byte correctness even with chunked I/O. If the key is at least as long as the file, the key never wraps and mapping is strictly 1:1.

---

## FAQ

### Is this a “real” one‑time pad?
Only if your key is random, at least as long as the file, used once, and kept secret. If the key is shorter and wraps, it’s repeating‑key XOR—useful, but not information‑theoretically secure.

### Can I pass the key path or use environment variables?
No—by design. Requiring `key.key` next to the executable and input keeps usage predictable on both Windows and Unix‑like systems.

### What happens if I run it twice?
XOR is symmetric: applying the same key again restores the original file.

### Does it change timestamps or permissions?
*Windows:* replacement preserves the destination file’s security and attributes; if the file was read‑only, the tool temporarily clears it and *restores it even on failure*.  
*Unix:* the temp file’s mode is set to match the original *minus setuid/setgid* before the atomic `rename()`. Times/xattrs/ownership are not explicitly preserved.

---

## License

Dual‑licensed under **MIT** or **Apache‑2.0** at your option.

---

## Changelog

- **3.1.0** — RAII read‑only restore on Windows; Unix TOCTOU check (device+inode) before replace; clear setuid/setgid on Unix; refuse non‑regular files; docs updated.
- **0.7.0** — Windows `ReplaceFileW` atomic replace (preserves metadata), Unix directory fsync after rename, temp‑file cleanup guard, hard‑link safety checks, updated PowerShell CSPRNG snippet, clarified docs.
- **0.6.0** — Positional input, always in‑place, requires `key.key`, same‑dir rule, key wrapping, locking, temp+rename, buffer zeroization, Windows ACL hardening.

---

*OTP – simple by default, safe by design.*
