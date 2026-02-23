// This app is designed for Linux only.
// The design choice of requiring the key.key file in the current working directory is intentional.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use libc;
use sodiumoxide::crypto::secretstream::{Header, Key, Stream, Tag, ABYTES, HEADERBYTES, KEYBYTES};
use sodiumoxide::utils::memzero;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 1_048_576; // 1MB

#[derive(Parser)]
#[command(name = "filecrypt")]
#[command(about = "Simple file encryption CLI using XChaCha20-Poly1305")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt the file in place
    Enc {
        file: String,
    },
    /// Decrypt the file in place
    Dec {
        file: String,
    },
}

fn main() -> Result<()> {
    if sodiumoxide::init().is_err() {
        return Err(anyhow!("Failed to init sodiumoxide"));
    }

    let cli = Cli::parse();

    let mut key_bytes = fs::read("key.key").context("Failed to read key.key")?;
    if key_bytes.len() != KEYBYTES {
        return Err(anyhow!("key.key must be exactly {} bytes", KEYBYTES));
    }
    let key = Key::from_slice(&key_bytes).unwrap();
    memzero(&mut key_bytes);

    match cli.command {
        Command::Enc { file } => encrypt(&file, &key),
        Command::Dec { file } => decrypt(&file, &key),
    }
}

fn get_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!("{}.tmp", path.file_name().unwrap().to_str().unwrap()));
    temp
}

fn encrypt(file: &str, key: &Key) -> Result<()> {
    let path = Path::new(file);
    let temp_path = get_temp_path(path);

    let result = (|| -> Result<()> {
        let input_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("Failed to open input file")?;

        let metadata = input_file.metadata().context("Failed to get file metadata")?;
        if !metadata.is_file() {
            return Err(anyhow!("Target must be a regular file"));
        }

        let mut input = BufReader::new(input_file);

        let output_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);

        let (mut push_stream, header) = Stream::init_push(key).map_err(|_| anyhow!("Failed to init push stream"))?;
        output.write_all(header.as_ref())?;

        let mut plain = vec![0u8; CHUNK_SIZE];
        loop {
            let n = input.read(&mut plain)?;
            if n == 0 {
                break;
            }

            let ct = push_stream.push(&plain[..n], None, Tag::Message).map_err(|_| anyhow!("Encryption failed"))?;
            let plain_len_bytes = (n as u32).to_le_bytes();
            output.write_all(&plain_len_bytes)?;
            output.write_all(&ct)?;
        }

        // Append final frame
        let final_plain: &[u8] = &[];
        let final_ct = push_stream.push(final_plain, None, Tag::Final).map_err(|_| anyhow!("Encryption failed on final tag"))?;
        let plain_len_bytes = (0u32).to_le_bytes();
        output.write_all(&plain_len_bytes)?;
        output.write_all(&final_ct)?;

        output.flush()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result?;
    fs::rename(temp_path, path).context("Failed to rename temp to original")?;
    Ok(())
}

fn decrypt(file: &str, key: &Key) -> Result<()> {
    let path = Path::new(file);
    let temp_path = get_temp_path(path);

    let result = (|| -> Result<()> {
        let input_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("Failed to open input file")?;

        let metadata = input_file.metadata().context("Failed to get file metadata")?;
        if !metadata.is_file() {
            return Err(anyhow!("Target must be a regular file"));
        }

        let mut input = BufReader::new(input_file);

        let output_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
            .context("Failed to create temp file")?;
        let mut output = BufWriter::new(output_file);

        let mut header_buf = [0u8; HEADERBYTES];
        input.read_exact(&mut header_buf).context("Failed to read header")?;
        let header = Header::from_slice(&header_buf).ok_or(anyhow!("Invalid header"))?;

        let mut pull_stream = Stream::init_pull(&header, key).map_err(|_| anyhow!("Failed to init pull stream"))?;

        let mut ct = vec![0u8; CHUNK_SIZE + ABYTES];
        let mut seen_final = false;
        loop {
            let mut len_buf = [0u8; 4];
            let len_read = input.read(&mut len_buf)?;
            if len_read == 0 {
                break;
            }
            if len_read != 4 {
                return Err(anyhow!("Incomplete length prefix"));
            }
            let plain_len = u32::from_le_bytes(len_buf) as usize;

            if plain_len > CHUNK_SIZE {
                return Err(anyhow!("Frame too large"));
            }

            let ct_len = plain_len + ABYTES;
            if ct_len > ct.len() {
                ct.resize(ct_len, 0);
            }
            input.read_exact(&mut ct[..ct_len]).context("Failed to read ciphertext frame")?;

            let (plain, tag) = pull_stream.pull(&ct[..ct_len], None).map_err(|_| anyhow!("Decryption failed (invalid MAC or data)"))?;

            if plain.len() != plain_len {
                return Err(anyhow!("Length mismatch after decryption"));
            }

            output.write_all(&plain)?;

            if tag == Tag::Final {
                seen_final = true;
                break;
            }
        }

        if !seen_final {
            return Err(anyhow!("Missing final tag (incomplete or invalid encryption)"));
        }

        // Check for trailing data
        let mut buf = [0u8; 1];
        if input.read(&mut buf)? != 0 {
            return Err(anyhow!("Trailing data after final tag"));
        }

        output.flush()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result?;
    fs::rename(temp_path, path).context("Failed to rename temp to original")?;
    Ok(())
}