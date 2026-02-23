// src/bin/keygen.rs
// This app is designed for Linux only.
// Generates all required key files (except OTP) with correct sizes, fails if any exist.
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use dryoc::rng::copy_randombytes;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use zeroize::Zeroize;

const KEYS: [(&str, usize); 6] = [
    ("aes.key", 32),
    ("cha.key", 32),
    ("cam.key", 32),
    ("kuz.key", 32),
    ("serp.key", 32),
    ("tf.key", 128),
];

#[derive(Parser)]
#[command(name = "keygen")]
#[command(about = "Generate all required key files (fails if any exist)")]
struct Cli {}

fn main() -> Result<()> {
    let _ = Cli::parse(); // No args needed

    // Check if any key files already exist
    for (file, _) in KEYS.iter() {
        if std::path::Path::new(file).exists() {
            return Err(anyhow!("Key file {} already exists", file));
        }
    }

    // Generate each key
    for (file, size) in KEYS.iter() {
        gen_key(file, *size)?;
    }

    println!("All key files generated successfully.");
    Ok(())
}

fn gen_key(key_file: &str, keybytes: usize) -> Result<()> {
    let mut key = vec![0u8; keybytes];
    copy_randombytes(&mut key);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key_file)
        .context(format!("Failed to create {}", key_file))?;
    file.write_all(&key)?;

    key.zeroize();
    Ok(())
}