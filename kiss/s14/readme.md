

```markdown
# key – Deterministic High-Strength Key Material Generator

[![Rust](https://img.shields.io/badge/Rust-1.78+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Linux-only](https://img.shields.io/badge/platform-Linux-blue)](https://pop.system76.com/)

**key** is a single-binary Rust tool that generates **reproducible, cryptographically strong key material** from a password + pepper (secret salt) using Argon2id + BLAKE3 or ChaCha20.

Designed for:

- Testing encryption software / formats
- Generating large one-time pad material (with correct usage caveats)
- Creating reproducible test vectors / keys for research & education
- Offline / air-gapped key derivation scenarios

**Important security note**  
This is **not** a perfect one-time pad generator if keys are reused or shorter than the data.  
Do **not** use the same (password, pepper) pair for unrelated purposes.

## Features

- Two-factor secret input: password + independent high-entropy pepper
- Argon2id with tunable memory/time/parallelism (m ≥ 8p enforced)
- Domain-separated derivation (prevents cross-tool collisions)
- Streaming output — supports keys up to **20 GiB** without high RAM usage
- Two algorithms: BLAKE3 XOF (fast & modern) or ChaCha20 (widely trusted)
- `--print-first N` mode — verify determinism without writing huge files
- Linux hardening: core dump disable + non-dumpable process flag
- Secure file creation: 0600 permissions, O_NOFOLLOW, O_CLOEXEC
- Progress dots for long-running generations
- Constant-time password comparison, zeroization of secrets

## Installation

### From source (recommended)

```bash
git clone https://github.com/yourusername/key.git
cd key
cargo build --release
# binary will be at: target/release/key
```

### One-liner (if you trust the source)

```bash
cargo install --git https://github.com/yourusername/key.git key
```

## Usage

```text
Deterministic high-strength key material generator (Linux-only)

Usage: key [OPTIONS] <SIZE_BYTES>

Arguments:
  <SIZE_BYTES>  Key size in bytes (1..=20 GiB)

Options:
  -o, --output <OUTPUT>          Output file path [default: key.key]
  -a, --algo <ALGO>              Stream algorithm [default: Blake3] [possible values: blake3, chacha]
      --argon2-memory <ARGON2_MEMORY>
                                 Argon2 memory in KiB [default: 65536]
      --argon2-time <ARGON2_TIME>
                                 Argon2 time cost (iterations) [default: 3]
      --argon2-par <ARGON2_PAR>  Argon2 parallelism (lanes; 0 = auto) [default: 0]
      --no-clobber                   Refuse to overwrite existing file
      --print-first <N_BYTES>    Print first N bytes as hex (for reproducibility check)
  -h, --help                         Print help
  -V, --version                      Print version
```

### Examples

```bash
# 1 MiB key, default settings
key 1048576

# 1 GiB key using ChaCha20, custom Argon2, no overwrite
key 1073741824 --algo chacha --argon2-memory 262144 --no-clobber

# Generate 32-byte key and only show first 32 bytes (for testing)
key 32 --print-first 32

# Very high security preset (4 GiB memory, 6 iterations)
key 1048576000 --argon2-memory 4194304 --argon2-time 6
```

You will be prompted (twice each) for:

1. Main password
2. Pepper (secret salt — should be long, high-entropy, independent)

## Security considerations

- **Strength** depends entirely on the combined entropy of password + pepper
- Pepper becomes a secret salt via domain-separated BLAKE3 derive_key
- Argon2id parameters are clamped so memory ≥ 8 × lanes
- Process is marked non-dumpable + core limit set to 0
- Output file permissions: 0600, no symlink following
- Secrets are zeroized where possible

**Do not**:

- Reuse the same (password, pepper) pair across different contexts
- Use a low-entropy or short pepper
- Rely on this as a production CSPRNG without review

## Building from source

Requires **Rust 1.78+**

```bash
cargo build --release
```

Recommended Cargo.toml profile settings are already included:

```toml
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## License

MIT

## Acknowledgments

Built with:

- [argon2](https://crates.io/crates/argon2)
- [blake3](https://crates.io/crates/blake3)
- [clap](https://crates.io/crates/clap)
- [nix](https://crates.io/crates/nix)
- [rand_chacha](https://crates.io/crates/rand_chacha)
- [rpassword](https://crates.io/crates/rpassword)
- [zeroize](https://crates.io/crates/zeroize)

Inspired by offline key derivation needs in cryptography research and education.
```

