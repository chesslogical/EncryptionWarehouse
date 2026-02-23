use anyhow::{Context, Result};
use cipher::{BlockEncrypt, generic_array::GenericArray, KeyInit};
use clap::Parser;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha512;
use std::fs::{rename, write, File};
use std::io::Read;

use threefish::Threefish1024;

const MAGIC_HEADER: &[u8] = b"TF1024ENC"; // 9 bytes magic
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const TAG_SIZE: usize = 64; // 512-bit HMAC-SHA512 tag
const HEADER_SIZE: usize = MAGIC_HEADER.len() + SALT_SIZE + IV_SIZE;

#[derive(Parser)]
#[command(name = "threefish_encrypt", about = "CLI for Threefish-1024 file encryption/decryption with auto-detect, in-place overwrite, authentication, and password-based key derivation")]
struct Args {
    /// File name (in same directory as executable)
    file: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    // Get executable directory
    let exe_dir = std::env::current_exe()?
        .parent()
        .context("Failed to get exe dir")?
        .to_path_buf();

    let file_path = exe_dir.join(&args.file);
    let temp_path = exe_dir.join(format!("{}.tmp", file_path.file_name().unwrap().to_str().unwrap()));
    // Read input file
    let mut data = vec![];
    File::open(&file_path)?.read_to_end(&mut data).context("Failed to read file")?;
    let password = rpassword::prompt_password("Enter password: ")?;
    let (output, is_decrypt) = if data.starts_with(MAGIC_HEADER) {
        // Decrypt: Extract salt, IV, ciphertext, tag
        if data.len() < HEADER_SIZE + TAG_SIZE {
            return Err(anyhow::anyhow!("Invalid encrypted file (too short)"));
        }
        let salt: [u8; SALT_SIZE] = data[MAGIC_HEADER.len()..MAGIC_HEADER.len() + SALT_SIZE].try_into()?;
        let iv_array: [u8; IV_SIZE] = data[MAGIC_HEADER.len() + SALT_SIZE..HEADER_SIZE].try_into()?;
        let ciphertext_end = data.len() - TAG_SIZE;
        let ciphertext = &data[HEADER_SIZE..ciphertext_end];
        let tag = &data[ciphertext_end..];
        
        // Derive key from password and salt
        let mut key_bytes = [0u8; 128];
        argon2::Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut key_bytes)?;
        let key_array: [u8; 128] = key_bytes;
        
        // Verify MAC
        let mut mac = <Hmac<Sha512> as KeyInit>::new(GenericArray::from_slice(&key_array));
        mac.update(MAGIC_HEADER);
        mac.update(&salt);
        mac.update(&iv_array);
        mac.update(ciphertext);
        mac.verify_slice(tag).map_err(|_| anyhow::anyhow!("MAC verification failed - file tampered or wrong key/password"))?;
        
        // Decrypt
        (process_ctr(&key_array, &iv_array, ciphertext)?, true)
    } else {
        // Encrypt: Generate random salt and IV, derive key, process, compute MAC, prepend header, append tag
        let mut salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut iv_array = [0u8; IV_SIZE];
        rand::thread_rng().fill_bytes(&mut iv_array);
        
        // Derive key from password and salt
        let mut key_bytes = [0u8; 128];
        argon2::Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut key_bytes)?;
        let key_array: [u8; 128] = key_bytes;
        
        let ciphertext = process_ctr(&key_array, &iv_array, &data)?;
        
        // Compute MAC
        let mut mac = <Hmac<Sha512> as KeyInit>::new(GenericArray::from_slice(&key_array));
        mac.update(MAGIC_HEADER);
        mac.update(&salt);
        mac.update(&iv_array);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();
        
        let mut output = MAGIC_HEADER.to_vec();
        output.extend_from_slice(&salt);
        output.extend_from_slice(&iv_array);
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(&tag);
        (output, false)
    };
    // Write to temp file
    write(&temp_path, &output).context("Failed to write temp file")?;
    // Atomic rename
    rename(&temp_path, &file_path).context("Failed to rename temp file")?;
    println!("File {} successfully {}!", file_path.display(), if is_decrypt { "decrypted" } else { "encrypted" });
    Ok(())
}

fn process_ctr(key_array: &[u8; 128], iv_array: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    // Threefish-1024 instance with key and tweak (IV)
    let cipher = Threefish1024::new_with_tweak(key_array, iv_array);
    // CTR mode: Generate keystream, XOR with data
    let block_size = 128;
    let num_blocks = (data.len() + block_size - 1) / block_size;
    let mut output = vec![0u8; data.len()];
    let mut counter: u64 = 0;
    for i in 0..num_blocks {
        let mut ctr_block = [0u8; 128];
        ctr_block[0..8].copy_from_slice(&counter.to_le_bytes());
        let mut ctr_generic = GenericArray::from_mut_slice(&mut ctr_block);
        <Threefish1024 as BlockEncrypt>::encrypt_block(&cipher, &mut ctr_generic);
        let start = i * block_size;
        let end = std::cmp::min(start + block_size, data.len());
        for j in start..end {
            output[j] = data[j] ^ ctr_block[j - start];
        }
        counter += 1;
    }
    Ok(output)
}