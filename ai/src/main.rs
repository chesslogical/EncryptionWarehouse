// src/main.rs
// This app is designed for Linux only.
// The design choice of requiring the algo.key file in the current working directory for key mode is intentional, but --key-file allows override.
// For password mode (--p), it prompts securely and derives key via Argon2id.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

mod aes;
mod cha;

const CHUNK_SIZE: usize = 1_048_576; // 1MB shared across algos

#[derive(Parser)]
#[command(name = "ai")]
#[command(about = "Simple file encryption CLI using AES-256-GCM-SIV or XChaCha20-Poly1305. Tribute to AI-assisted coding.")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    algo: AlgoCommand,
}

#[derive(Subcommand)]
enum AlgoCommand {
    /// Use AES-256-GCM-SIV
    Aes {
        #[command(subcommand)]
        command: Command,
    },
    /// Use XChaCha20-Poly1305
    Cha {
        #[command(subcommand)]
        command: Command,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt the file in place
    Enc {
        /// File to encrypt
        file: String,
        /// Use password mode (prompts for passphrase)
        #[arg(long, short = 'p')]
        password: bool,
        /// Path to key file (defaults to aes.key or cha.key in CWD; mutually exclusive with --p)
        #[arg(long)]
        key_file: Option<String>,
    },
    /// Decrypt the file in place
    Dec {
        /// File to decrypt
        file: String,
        /// Use password mode (prompts for passphrase)
        #[arg(long, short = 'p')]
        password: bool,
        /// Path to key file (defaults to aes.key or cha.key in CWD; mutually exclusive with --p)
        #[arg(long)]
        key_file: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.algo {
        AlgoCommand::Aes { command } => handle_command(command, "aes")?,
        AlgoCommand::Cha { command } => handle_command(command, "cha")?,
    }
    Ok(())
}

fn handle_command(command: Command, algo: &str) -> Result<()> {
    match command {
        Command::Enc {
            file,
            password,
            key_file,
        } => {
            if algo == "aes" {
                aes::encrypt(&file, password, key_file)?;
            } else {
                cha::encrypt(&file, password, key_file)?;
            }
        }
        Command::Dec {
            file,
            password,
            key_file,
        } => {
            if algo == "aes" {
                aes::decrypt(&file, password, key_file)?;
            } else {
                cha::decrypt(&file, password, key_file)?;
            }
        }
    }
    Ok(())
}

fn get_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!("{}.tmp", path.file_name().unwrap().to_str().unwrap()));
    temp
}

fn atomic_rename(temp_path: &Path, original_path: &Path, parent: &Path) -> Result<()> {
    fs::rename(temp_path, original_path).context("Failed to rename temp to original")?;
    let dir = OpenOptions::new()
        .read(true)
        .open(parent)
        .context("Failed to open parent directory")?;
    dir.sync_all().context("Failed to sync parent directory")?;
    Ok(())
}