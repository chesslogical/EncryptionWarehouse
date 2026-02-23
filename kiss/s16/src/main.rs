use argon2::{Argon2, Params};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use clap::Parser;
use rpassword::read_password;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use zeroize::Zeroize;

//
// ============================================================
// CONFIGURATION SECTION (COMPILE-TIME CONSTANTS)
// ============================================================
//

// Maximum output size (20GB)
const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024;

// Streaming chunk size (1MB)
const CHUNK_SIZE: usize = 1024 * 1024;

// Argon2 tuning parameters
const ARGON2_MEMORY_KIB: u32 = 262_144; // 256MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

// Deterministic salt (change if you want a different domain)
const SALT: &[u8] = b"detkey-v1-domain";

// Optional compile-time pepper (can be empty)
const PEPPER: &[u8] = b"";

//
// ============================================================
// CLI
// ============================================================
//

#[derive(Parser)]
#[command(name = "detkey")]
#[command(about = "Deterministic key generator (length in BYTES only)")]
struct Cli {
    /// Number of bytes to generate (1 to 21474836480). BYTES ONLY.
    #[arg(long, value_parser = clap::value_parser!(u64))]
    length: u64,
}

//
// ============================================================
// MAIN
// ============================================================
//

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    // Validate length
    if cli.length == 0 || cli.length > MAX_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Length must be between 1 and 21474836480 bytes",
        ));
    }

    let path = Path::new("key.key");

    // Refuse overwrite
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "key.key already exists. Refusing to overwrite.",
        ));
    }

    //
    // Password prompt (always double entry)
    //

    println!("Enter password:");
    let mut password1 = read_password()?.into_bytes();

    println!("Confirm password:");
    let mut password2 = read_password()?.into_bytes();

    if password1 != password2 {
        password1.zeroize();
        password2.zeroize();
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passwords do not match",
        ));
    }

    password2.zeroize();

    //
    // Combine password + pepper (deterministic)
    //

    let mut combined = Vec::with_capacity(password1.len() + PEPPER.len());
    combined.extend_from_slice(&password1);
    combined.extend_from_slice(PEPPER);

    password1.zeroize();

    //
    // Argon2id KDF
    //

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut master_key = [0u8; 32];

    argon2
        .hash_password_into(&combined, SALT, &mut master_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    combined.zeroize();

    //
    // Deterministic ChaCha20 stream (nonce = 0)
    //

    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(&master_key.into(), &nonce.into());

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    let mut writer = BufWriter::new(file);
    let mut buffer = vec![0u8; CHUNK_SIZE];

    let mut remaining = cli.length;

    while remaining > 0 {
        let chunk = remaining.min(CHUNK_SIZE as u64) as usize;

        buffer[..chunk].fill(0);
        cipher.apply_keystream(&mut buffer[..chunk]);

        writer.write_all(&buffer[..chunk])?;
        remaining -= chunk as u64;
    }

    writer.flush()?;
    master_key.zeroize();

    println!("Generated {} bytes → key.key", cli.length);

    Ok(())
}
