This is exactly the right use case for **BLAKE3** in XOF mode.

It can:

* deterministically generate **1 byte**
* or **20 GB**
* or effectively unlimited output
* with no repeating pattern
* while streaming (no giant allocations)

This is designed properly.

---

# 🧠 Design

**Inputs**

* `--seed` (32-byte hex master seed)
* `--domain` (string for domain separation)
* `--size` (bytes to generate)
* optional `--offset` (for chunked reproducibility)

**Architecture**

```
subkey = blake3::derive_key("detkey-root", seed)
hasher = blake3::Hasher::new_keyed(&subkey)
hasher.update(domain)
reader = hasher.finalize_xof()
reader.set_position(offset)
stream N bytes to stdout
```

This guarantees:

✔ Deterministic
✔ Domain-separated
✔ No repetition
✔ 64-bit stream position
✔ No large memory allocation
✔ Linux optimized streaming

---

# 📦 Cargo.toml

```toml
[package]
name = "detkey"
version = "1.0.0"
edition = "2021"

[dependencies]
blake3 = "1.5"
clap = { version = "4.5", features = ["derive"] }
hex = "0.4"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

---

# 🧾 main.rs

```rust
use blake3::Hasher;
use clap::Parser;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB streaming chunks

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// 32-byte master seed in hex (64 hex chars)
    #[arg(long)]
    seed: String,

    /// Domain separation label
    #[arg(long)]
    domain: String,

    /// Number of bytes to generate (1 to 20GB+)
    #[arg(long)]
    size: u64,

    /// Optional offset into stream
    #[arg(long, default_value_t = 0)]
    offset: u64,

    /// Optional output file (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.size == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "size must be > 0"));
    }

    // Decode seed
    let seed_bytes = hex::decode(&args.seed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hex seed"))?;

    if seed_bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seed must be exactly 32 bytes (64 hex chars)",
        ));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes);

    // Derive root key
    let root_key = blake3::derive_key("detkey-root", &seed_array);

    // Domain separation
    let mut hasher = Hasher::new_keyed(&root_key);
    hasher.update(args.domain.as_bytes());

    let mut xof = hasher.finalize_xof();
    xof.set_position(args.offset);

    // Output writer
    let writer: Box<dyn Write> = match args.out {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout())),
    };

    stream_bytes(writer, &mut xof, args.size)?;

    Ok(())
}

fn stream_bytes(mut writer: Box<dyn Write>, xof: &mut blake3::OutputReader, mut remaining: u64) -> io::Result<()> {
    let mut buffer = vec![0u8; CHUNK_SIZE];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
        xof.fill(&mut buffer[..to_read]);
        writer.write_all(&buffer[..to_read])?;
        remaining -= to_read as u64;
    }

    writer.flush()?;
    Ok(())
}
```

---

# 🚀 Example Usage

Generate 32 bytes:

```
detkey --seed <64hex> --domain aes-test --size 32 > key.bin
```

Generate 5 GB:

```
detkey --seed <64hex> --domain bigtest --size 5368709120 > stream.bin
```

Generate bytes 10GB–12GB:

```
detkey --seed <64hex> --domain bigtest --size 2147483648 --offset 10737418240 > part.bin
```

---

# 🔒 Security Properties

* 256-bit master seed
* Domain-separated
* No repetition cycle
* 64-bit stream position (18 exabytes before wrap)
* No 20GB allocation
* Fully deterministic
* Pure Rust
* No unsafe
* No C FFI

---

# 🧨 Important

Store your master seed securely.
That seed is the root of everything.

Lose it → you lose determinism.
Leak it → all derived streams are compromised.

---


