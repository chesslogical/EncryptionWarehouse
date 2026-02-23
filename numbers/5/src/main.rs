// Linux-only file encryption tool.
// Requires "key.key" in current working directory.
// Key must be exactly 128 bytes and mode 0600.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use cipher::{BlockEncrypt, generic_array::GenericArray};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use libc;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use threefish::Threefish1024;
use zeroize::Zeroize;

const CHUNK_SIZE: usize = 1_048_576;
const DEFAULT_KEY_FILE: &str = "key.key";
const ABYTES: usize = 64;
const HEADERBYTES: usize = 16;
const KEYBYTES: usize = 128;
const MAC_KEYBYTES: usize = 64;
const BLOCK_SIZE: usize = 128;

#[derive(Parser)]
#[command(name = "tf")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Enc { file: String },
    Dec { file: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Enc { file } => {
            let mut key = load_key_from_file(DEFAULT_KEY_FILE)?;
            encrypt(&file, &key)?;
            key.zeroize();
        }
        Command::Dec { file } => {
            let mut key = load_key_from_file(DEFAULT_KEY_FILE)?;
            decrypt(&file, &key)?;
            key.zeroize();
        }
    }

    Ok(())
}

fn get_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    temp
}

fn derive_subkeys(master_key: &[u8]) -> ([u8; MAC_KEYBYTES], [u8; KEYBYTES]) {
    let hk = Hkdf::<Sha512>::new(None, master_key);

    let mut mac_key = [0u8; MAC_KEYBYTES];
    let mut enc_key = [0u8; KEYBYTES];

    hk.expand(b"mac_key", &mut mac_key).unwrap();
    hk.expand(b"enc_key", &mut enc_key).unwrap();

    (mac_key, enc_key)
}

fn encrypt(file: &str, key: &[u8; KEYBYTES]) -> Result<()> {
    let path = Path::new(file);

    if path.file_name().map_or(false, |n| n == DEFAULT_KEY_FILE) {
        return Err(anyhow!("Cannot encrypt the key file"));
    }

    let temp_path = get_temp_path(path);
    let parent = path.parent().unwrap_or(Path::new("."));

    let result = (|| -> Result<()> {
        let input_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;

        if !input_file.metadata()?.is_file() {
            return Err(anyhow!("Target must be regular file"));
        }

        let mut input = BufReader::new(input_file);

        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)?;

        let mut output = BufWriter::new(output_file);

        let mut iv = [0u8; HEADERBYTES];
        OsRng.fill_bytes(&mut iv);
        output.write_all(&iv)?;

        let (mut mac_key, mut enc_key) = derive_subkeys(key);

        let mut mac = Hmac::<Sha512>::new_from_slice(&mac_key)
            .map_err(|_| anyhow!("MAC init failed"))?;

        mac.update(&iv);

        let mut plain = vec![0u8; CHUNK_SIZE];
        let mut block_counter: u64 = 0;

        loop {
            let n = input.read(&mut plain)?;
            if n == 0 {
                break;
            }

            let ct = ctr_process(&enc_key, &iv, &plain[..n], block_counter)?;

            let len_bytes = (n as u32).to_le_bytes();
            output.write_all(&len_bytes)?;
            output.write_all(&ct)?;

            mac.update(&len_bytes);
            mac.update(&ct);

            block_counter += ((n + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        }

        let final_len = 0u32.to_le_bytes();
        output.write_all(&final_len)?;
        mac.update(&final_len);

        let tag = mac.finalize().into_bytes();
        output.write_all(&tag)?;

        plain.zeroize();
        mac_key.zeroize();
        enc_key.zeroize();

        output.flush()?;
        output.get_ref().sync_all()?;

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result?;
    fs::rename(temp_path, path)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()?;

    Ok(())
}

fn decrypt(file: &str, key: &[u8; KEYBYTES]) -> Result<()> {
    let path = Path::new(file);
    let temp_path = get_temp_path(path);
    let parent = path.parent().unwrap_or(Path::new("."));

    let result = (|| -> Result<()> {
        let input_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;

        if !input_file.metadata()?.is_file() {
            return Err(anyhow!("Target must be regular file"));
        }

        let mut input = BufReader::new(input_file);

        let mut iv = [0u8; HEADERBYTES];
        input.read_exact(&mut iv)?;

        let (mut mac_key, mut enc_key) = derive_subkeys(key);

        let mut mac = Hmac::<Sha512>::new_from_slice(&mac_key)
            .map_err(|_| anyhow!("MAC init failed"))?;

        mac.update(&iv);

        let mut seen_final = false;

        loop {
            let mut len_buf = [0u8; 4];
            if input.read(&mut len_buf)? == 0 {
                break;
            }

            let plain_len = u32::from_le_bytes(len_buf) as usize;
            let mut ct = vec![0u8; plain_len];
            input.read_exact(&mut ct)?;

            mac.update(&len_buf);
            mac.update(&ct);

            if plain_len == 0 {
                seen_final = true;
                break;
            }
        }

        if !seen_final {
            return Err(anyhow!("Missing final frame"));
        }

        let mut tag = [0u8; ABYTES];
        input.read_exact(&mut tag)?;
        mac.verify_slice(&tag)
            .map_err(|_| anyhow!("MAC verification failed"))?;

        if input.read(&mut [0u8; 1])? != 0 {
            return Err(anyhow!("Trailing data detected"));
        }

        input.seek(SeekFrom::Start(HEADERBYTES as u64))?;

        let output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&temp_path)?;

        let mut output = BufWriter::new(output_file);
        let mut block_counter = 0u64;

        loop {
            let mut len_buf = [0u8; 4];
            input.read_exact(&mut len_buf)?;

            let plain_len = u32::from_le_bytes(len_buf) as usize;
            if plain_len == 0 {
                break;
            }

            let mut ct = vec![0u8; plain_len];
            input.read_exact(&mut ct)?;

            let plain = ctr_process(&enc_key, &iv, &ct, block_counter)?;
            output.write_all(&plain)?;

            block_counter += ((plain_len + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
        }

        mac_key.zeroize();
        enc_key.zeroize();

        output.flush()?;
        output.get_ref().sync_all()?;

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result?;
    fs::rename(temp_path, path)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()?;

    Ok(())
}

fn ctr_process(
    enc_key: &[u8; KEYBYTES],
    iv: &[u8; HEADERBYTES],
    data: &[u8],
    mut block_counter: u64,
) -> Result<Vec<u8>> {
    let mut output = vec![0u8; data.len()];
    let mut keystream = [0u8; BLOCK_SIZE];

    let mut offset = 0;

    while offset < data.len() {
        let mut tweak = [0u8; 16];
        tweak.copy_from_slice(iv);
        tweak[8..16].copy_from_slice(&block_counter.to_le_bytes());

        let cipher = Threefish1024::new_with_tweak(enc_key, &tweak);

        keystream.fill(0);
        let mut block = GenericArray::from_mut_slice(&mut keystream);
        cipher.encrypt_block(&mut block);

        let remaining = data.len() - offset;
        let to_copy = remaining.min(BLOCK_SIZE);

        for i in 0..to_copy {
            output[offset + i] = data[offset + i] ^ keystream[i];
        }

        offset += to_copy;
        block_counter += 1;
    }

    Ok(output)
}

fn load_key_from_file(key_file: &str) -> Result<[u8; KEYBYTES]> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(key_file)
        .context("Failed to open key.key")?;

    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(anyhow!("Key file must be regular file"));
    }

    if metadata.permissions().mode() != 0o100600 {
        return Err(anyhow!("Key file must have 0600 permissions"));
    }

    let mut reader = BufReader::new(file);
    let mut key = [0u8; KEYBYTES];

    reader.read_exact(&mut key)?;

    if reader.read(&mut [0u8; 1])? != 0 {
        return Err(anyhow!("Key file must be exactly 128 bytes"));
    }

    Ok(key)
}
