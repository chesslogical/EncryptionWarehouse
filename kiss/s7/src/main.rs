use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use cipher::{generic_array::GenericArray, BlockEncrypt};
use clap::Parser;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rpassword::prompt_password;
use sha2::Sha512;
use std::fs::{rename, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use threefish::Threefish1024;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const MAGIC: &[u8] = b"TF1024V2";
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const TAG_SIZE: usize = 64;
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB streaming

#[derive(Parser)]
struct Args {
    file: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let password = prompt_password("Enter password: ")?;
    let mut password = password;

    let exe_dir = std::env::current_exe()?
        .parent()
        .context("Cannot determine executable directory")?
        .to_path_buf();

    let file_path = exe_dir.join(&args.file);
    let temp_path = tmp_path(&file_path);

    let mut file = File::open(&file_path)?;
    let mut magic = [0u8; 8];
    let is_encrypted = if file.read_exact(&mut magic).is_ok() && magic == MAGIC {
        true
    } else {
        false
    };

    drop(file);

    if is_encrypted {
        decrypt_stream(&password, &file_path, &temp_path)?;
        println!("File decrypted.");
    } else {
        encrypt_stream(&password, &file_path, &temp_path)?;
        println!("File encrypted.");
    }

    password.zeroize();
    rename(&temp_path, &file_path)?;

    Ok(())
}

fn tmp_path(path: &PathBuf) -> PathBuf {
    path.with_extension("tmp")
}

fn encrypt_stream(password: &str, input: &PathBuf, output: &PathBuf) -> Result<()> {
    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; IV_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    let (mut enc_key, mut mac_key) = derive_keys(password, &salt)?;

    let mut reader = File::open(input)?;
    let mut writer = File::create(output)?;

    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&iv)?;

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)?;
    mac.update(MAGIC);
    mac.update(&salt);
    mac.update(&iv);

    let cipher = Threefish1024::new_with_tweak(&enc_key, &iv);
    let mut counter: u64 = 0;
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        let chunk = &buffer[..read];
        let encrypted = process_chunk(&cipher, chunk, &mut counter)?;

        mac.update(&encrypted);
        writer.write_all(&encrypted)?;
    }

    let tag = mac.finalize().into_bytes();
    writer.write_all(&tag)?;

    enc_key.zeroize();
    mac_key.zeroize();

    Ok(())
}

fn decrypt_stream(password: &str, input: &PathBuf, output: &PathBuf) -> Result<()> {
    let mut reader = File::open(input)?;

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(anyhow!("Invalid file format"));
    }

    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; IV_SIZE];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut iv)?;

    let (mut enc_key, mut mac_key) = derive_keys(password, &salt)?;

    let file_len = reader.metadata()?.len() as usize;
    let header_len = MAGIC.len() + SALT_SIZE + IV_SIZE;
    let ciphertext_len = file_len - header_len - TAG_SIZE;

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key)?;
    mac.update(&magic);
    mac.update(&salt);
    mac.update(&iv);

    let cipher = Threefish1024::new_with_tweak(&enc_key, &iv);
    let mut counter: u64 = 0;
    let mut remaining = ciphertext_len;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut writer = File::create(output)?;

    while remaining > 0 {
        let to_read = remaining.min(CHUNK_SIZE);
        reader.read_exact(&mut buffer[..to_read])?;

        mac.update(&buffer[..to_read]);

        let decrypted =
            process_chunk(&cipher, &buffer[..to_read], &mut counter)?;

        writer.write_all(&decrypted)?;
        remaining -= to_read;
    }

    let mut tag = [0u8; TAG_SIZE];
    reader.read_exact(&mut tag)?;

    mac.verify_slice(&tag)
        .map_err(|_| anyhow!("Authentication failed"))?;

    enc_key.zeroize();
    mac_key.zeroize();

    Ok(())
}

fn derive_keys(password: &str, salt: &[u8]) -> Result<([u8; 128], [u8; 64])> {
    // Strong production parameters:
    // 64 MB memory, 3 iterations, parallelism=1
    let params = Params::new(65536, 3, 1, Some(64))
        .map_err(|e| anyhow!("Argon2 param error: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = [0u8; 64];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut master)
        .map_err(|e| anyhow!("Argon2 failed: {e}"))?;

    let hk = Hkdf::<Sha512>::new(None, &master);

    let mut enc_key = [0u8; 128];
    let mut mac_key = [0u8; 64];

    hk.expand(b"threefish-enc", &mut enc_key)
        .map_err(|_| anyhow!("HKDF enc expand failed"))?;
    hk.expand(b"threefish-mac", &mut mac_key)
        .map_err(|_| anyhow!("HKDF mac expand failed"))?;

    master.zeroize();

    Ok((enc_key, mac_key))
}

fn process_chunk(
    cipher: &Threefish1024,
    data: &[u8],
    counter: &mut u64,
) -> Result<Vec<u8>> {
    let block_size = 128;
    let mut output = vec![0u8; data.len()];
    let blocks = (data.len() + block_size - 1) / block_size;

    for b in 0..blocks {
        let mut block = [0u8; 128];
        block[..8].copy_from_slice(&counter.to_le_bytes());

        let mut ga = GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(&mut ga);

        let start = b * block_size;
        let end = (start + block_size).min(data.len());

        for i in start..end {
            output[i] = data[i] ^ block[i - start];
        }

        *counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("Counter overflow"))?;
    }

    Ok(output)
}
