use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use serpent::Serpent;

use cipher::{BlockEncrypt, NewBlockCipher};
use cipher::generic_array::GenericArray;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use zeroize::Zeroize;

use rand::rngs::OsRng;
use rand::RngCore;

use libc;

use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{PermissionsExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 1_048_576;
const DEFAULT_KEY_FILE: &str = "key.key";

const ABYTES: usize = 64;
const HEADERBYTES: usize = 16;
const KEYBYTES: usize = 32;
const MAC_KEYBYTES: usize = 64;
const BLOCK_SIZE: usize = 16;

type Key = [u8; KEYBYTES];

#[derive(Parser)]
#[command(name = "filecrypt")]
#[command(about = "Simple file encryption CLI using Serpent-256")]
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

    match &cli.command {
        Command::Enc { file } => {
            let mut key = load_key_from_file(DEFAULT_KEY_FILE)?;
            encrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
        Command::Dec { file } => {
            let mut key = load_key_from_file(DEFAULT_KEY_FILE)?;
            decrypt(file, &key)?;
            key.zeroize();
            Ok(())
        }
    }
}

fn get_temp_path(path: &Path) -> PathBuf {
    let mut temp = path.to_path_buf();
    temp.set_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    temp
}

/* -------------------- HKDF SUBKEYS -------------------- */

fn derive_subkeys(master_key: &[u8]) -> ([u8; MAC_KEYBYTES], [u8; KEYBYTES]) {
    let hk = Hkdf::<Sha512>::new(None, master_key);

    let mut mac_key = [0u8; MAC_KEYBYTES];
    let mut enc_key = [0u8; KEYBYTES];

    hk.expand(b"mac_key", &mut mac_key).unwrap();
    hk.expand(b"enc_key", &mut enc_key).unwrap();

    (mac_key, enc_key)
}

/* ------------------------- ENCRYPT ------------------------- */

fn encrypt(file: &str, key: &Key) -> Result<()> {
    let path = Path::new(file);
    let temp_path = get_temp_path(path);

    let input_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("Failed to open input file")?;

    if !input_file.metadata()?.is_file() {
        return Err(anyhow!("Target must be regular file"));
    }

    let mut input = BufReader::new(input_file);

    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)?;

    let mut output = BufWriter::new(output_file);

    // Generate IV
    let mut iv = [0u8; HEADERBYTES];
    OsRng.fill_bytes(&mut iv);
    output.write_all(&iv)?;

    let (mac_key, enc_key) = derive_subkeys(key);

    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key)?;
    mac.update(&iv);

    let mut plain = vec![0u8; CHUNK_SIZE];
    let mut counter = 0u64;

    loop {
        let n = input.read(&mut plain)?;
        if n == 0 {
            break;
        }

        let ct = ctr_process(&enc_key, &iv, &plain[..n], counter)?;
        output.write_all(&ct)?;
        mac.update(&ct);

        counter += ((n + BLOCK_SIZE - 1) / BLOCK_SIZE) as u64;
    }

    let tag = mac.finalize().into_bytes();
    output.write_all(&tag)?;

    output.flush()?;
    output.get_ref().sync_all()?;

    fs::rename(temp_path, path)?;
    Ok(())
}

/* ------------------------- DECRYPT ------------------------- */

fn decrypt(file: &str, key: &Key) -> Result<()> {
    let path = Path::new(file);
    let temp_path = get_temp_path(path);

    let input_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    let metadata = input_file.metadata()?;
    let file_len = metadata.len() as usize;

    if file_len < HEADERBYTES + ABYTES {
        return Err(anyhow!("File too short"));
    }

    let ct_len = file_len - HEADERBYTES - ABYTES;

    let mut input = BufReader::new(input_file);

    let mut iv = [0u8; HEADERBYTES];
    input.read_exact(&mut iv)?;

    let mut ct = vec![0u8; ct_len];
    input.read_exact(&mut ct)?;

    let mut tag = [0u8; ABYTES];
    input.read_exact(&mut tag)?;

    let (mac_key, enc_key) = derive_subkeys(key);

    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key)?;
    mac.update(&iv);
    mac.update(&ct);
    mac.verify_slice(&tag)?;

    let plain = ctr_process(&enc_key, &iv, &ct, 0)?;

    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)?;

    let mut output = BufWriter::new(output_file);
    output.write_all(&plain)?;
    output.flush()?;
    output.get_ref().sync_all()?;

    fs::rename(temp_path, path)?;
    Ok(())
}

/* ------------------------- CTR MODE ------------------------- */

fn ctr_process(
    enc_key: &[u8],
    iv: &[u8],
    data: &[u8],
    mut counter: u64,
) -> Result<Vec<u8>> {
    let cipher = Serpent::new_from_slice(enc_key)
        .map_err(|_| anyhow!("Cipher init failed"))?;

    let mut output = vec![0u8; data.len()];
    let mut offset = 0;

    while offset < data.len() {
        let mut block = [0u8; BLOCK_SIZE];

        block[..8].copy_from_slice(&iv[..8]);
        block[8..].copy_from_slice(&counter.to_be_bytes());

        let mut block_ga = GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(&mut block_ga);

        let remaining = data.len() - offset;
        let to_copy = remaining.min(BLOCK_SIZE);

        for i in 0..to_copy {
            output[offset + i] = data[offset + i] ^ block[i];
        }

        offset += to_copy;
        counter += 1;
    }

    Ok(output)
}

/* ------------------------- KEY LOAD ------------------------- */

fn load_key_from_file(key_file: &str) -> Result<Key> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(key_file)
        .context("Failed to open key.key")?;

    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(anyhow!("Key file must be regular file"));
    }

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(anyhow!("key.key must have 0600 permissions"));
    }

    let mut key = [0u8; KEYBYTES];
    BufReader::new(file).read_exact(&mut key)?;

    Ok(key)
}
