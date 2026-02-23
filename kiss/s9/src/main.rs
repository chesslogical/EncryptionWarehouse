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
const IV_SIZE: usize = 16;
const TAG_SIZE: usize = 64; // 512-bit HMAC-SHA512 tag
const HEADER_SIZE: usize = MAGIC_HEADER.len() + IV_SIZE; // 9 + 16 = 25 bytes

// Hard-coded 128-byte key (1024 bits). Edit this array at compile time to change the key.
// WARNING: For security, generate a random key using a secure method (e.g., openssl rand 128) and paste the hex values here.
// Do not use this default key for real data; it's for demonstration only.
const KEY: [u8; 128] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
];

#[derive(Parser)]
#[command(name = "threefish_encrypt", about = "CLI for Threefish-1024 file encryption/decryption with auto-detect, in-place overwrite, and authentication using hard-coded key")]
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
    let key_array = KEY;
    let (output, is_decrypt) = if data.starts_with(MAGIC_HEADER) {
        // Decrypt: Extract IV, ciphertext, tag
        if data.len() < HEADER_SIZE + TAG_SIZE {
            return Err(anyhow::anyhow!("Invalid encrypted file (too short)"));
        }
        let iv_array: [u8; 16] = data[MAGIC_HEADER.len()..HEADER_SIZE].try_into()?;
        let ciphertext_end = data.len() - TAG_SIZE;
        let ciphertext = &data[HEADER_SIZE..ciphertext_end];
        let tag = &data[ciphertext_end..];
        
        // Verify MAC
        let mut mac = <Hmac<Sha512> as KeyInit>::new(GenericArray::from_slice(&key_array));
        mac.update(MAGIC_HEADER);
        mac.update(&iv_array);
        mac.update(ciphertext);
        mac.verify_slice(tag).map_err(|_| anyhow::anyhow!("MAC verification failed - file tampered or wrong key"))?;
        
        // Decrypt
        (process_ctr(&key_array, &iv_array, ciphertext)?, true)
    } else {
        // Encrypt: Generate random IV, process, compute MAC, prepend header, append tag
        let mut iv_array = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv_array);
        let ciphertext = process_ctr(&key_array, &iv_array, &data)?;
        
        // Compute MAC
        let mut mac = <Hmac<Sha512> as KeyInit>::new(GenericArray::from_slice(&key_array));
        mac.update(MAGIC_HEADER);
        mac.update(&iv_array);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();
        
        let mut output = MAGIC_HEADER.to_vec();
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