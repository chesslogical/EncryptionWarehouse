use anyhow::Result;
use clap::{Parser, Subcommand};
use fs2::FileExt;
use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use rpassword::prompt_password;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{File, OpenOptions, metadata, remove_file};
use std::io::{self, BufReader, BufWriter, Read, Write, Seek, SeekFrom, ErrorKind};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, Payload, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};

const MAGIC: [u8; 4] = [b's', b'e', b'c', b'a'];
const VERSION: u8 = 2;

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;

#[derive(Parser)]
#[command(name = "secureapp")]
struct Args {
    #[command(subcommand)]
    command: Command,

    #[arg(long, default_value_t = 1024)]
    memory: u32,

    #[arg(long, default_value_t = 3)]
    iterations: u32,

    #[arg(long, default_value_t = 4)]
    parallelism: u32,
}

#[derive(Subcommand)]
enum Command {
    Enc(EncArgs),
    Dec(DecArgs),
}

#[derive(Parser)]
struct EncArgs {
    #[arg(short, long)]
    input: Option<String>,

    #[arg(short, long)]
    output: Option<String>,

    #[arg(long)]
    delete: bool,

    #[arg(long)]
    in_place: bool,
}

#[derive(Parser)]
struct DecArgs {
    #[arg(short, long)]
    input: Option<String>,

    #[arg(short, long)]
    output: Option<String>,

    #[arg(long)]
    in_place: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match &args.command {
        Command::Enc(enc) => encrypt(&args, enc)?,
        Command::Dec(dec) => decrypt(&args, dec)?,
    }
    Ok(())
}

fn derive_key(
    pass: &str,
    salt: &[u8],
    memory: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<GenericArray<u8, U32>>> {

    let params = Params::new(memory * 1024, iterations, parallelism, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {:?}", e))?;

    let mut key = GenericArray::<u8, U32>::default();

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {:?}", e))?;

    Ok(Zeroizing::new(key))
}

fn hkdf_expand(
    key: &GenericArray<u8, U32>,
    nonce: &[u8],
) -> GenericArray<u8, U32> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), key);
    let mut okm = GenericArray::<u8, U32>::default();
    hk.expand(b"secureapp payload key", &mut okm).unwrap();
    okm
}

fn encrypt(cli: &Args, args: &EncArgs) -> Result<()> {

    if args.in_place && args.input.is_none() {
        return Err(anyhow::anyhow!("--in-place requires --input"));
    }

    let mut pass = prompt_password("Enter password: ")?;
    let mut confirm = prompt_password("Confirm password: ")?;
    if pass != confirm {
        return Err(anyhow::anyhow!("Passwords don't match"));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut payload_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut payload_nonce);

    let key = derive_key(&pass, &salt, cli.memory, cli.iterations, cli.parallelism)?;
    let payload_key = hkdf_expand(&*key, &payload_nonce);

    pass.zeroize();
    confirm.zeroize();

    let input_path = args.input.as_ref().unwrap();
    let input_file = File::open(input_path)?;
    input_file.lock_exclusive().ok();
    let mut reader = BufReader::new(input_file);

    let final_path = if args.in_place {
        input_path.clone()
    } else if let Some(p) = &args.output {
        p.clone()
    } else {
        return Err(anyhow::anyhow!("Must specify --output or --in-place"));
    };

    let temp_path = format!("{}.tmp", final_path);

    let output_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;

    let mut writer = BufWriter::new(output_file);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&payload_nonce);

    writer.write_all(&header)?;

    let mut index = 0u64;
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 { break; }

        let mut nonce = [0u8; 24];
        nonce[..NONCE_LEN].copy_from_slice(&payload_nonce);
        nonce[NONCE_LEN..].copy_from_slice(&index.to_be_bytes());

        let cipher = XChaCha20Poly1305::new(&payload_key);
        let aad = [&header[..], &index.to_be_bytes()].concat();

        let ciphertext = cipher.encrypt(
            GenericArray::from_slice(&nonce),
            Payload { msg: &buffer[..read], aad: &aad }
        ).map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        writer.write_all(&(read as u32).to_be_bytes())?;
        writer.write_all(&ciphertext)?;

        index += 1;
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    std::fs::rename(&temp_path, &final_path)?;

    sync_parent_dir(&final_path)?;

    if args.delete && !args.in_place {
        secure_delete(Path::new(input_path))?;
    }

    Ok(())
}

fn decrypt(cli: &Args, args: &DecArgs) -> Result<()> {

    if args.in_place && args.input.is_none() {
        return Err(anyhow::anyhow!("--in-place requires --input"));
    }

    let mut pass = prompt_password("Enter password: ")?;

    let input_path = args.input.as_ref().unwrap();
    let input_file = File::open(input_path)?;
    input_file.lock_exclusive().ok();
    let mut reader = BufReader::new(input_file);

    let mut header = vec![0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;

    if &header[..4] != MAGIC {
        return Err(anyhow::anyhow!("Invalid magic"));
    }

    if header[4] != VERSION {
        return Err(anyhow::anyhow!("Unsupported version"));
    }

    let salt = &header[5..5 + SALT_LEN];
    let payload_nonce = &header[5 + SALT_LEN..];

    let key = derive_key(&pass, salt, cli.memory, cli.iterations, cli.parallelism)?;
    let payload_key = hkdf_expand(&*key, payload_nonce);

    pass.zeroize();

    let final_path = if args.in_place {
        input_path.clone()
    } else if let Some(p) = &args.output {
        p.clone()
    } else {
        return Err(anyhow::anyhow!("Must specify --output or --in-place"));
    };

    let temp_path = format!("{}.tmp", final_path);

    let output_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;

    let mut writer = BufWriter::new(output_file);

    let mut index = 0u64;

    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        let mut ct = vec![0u8; chunk_len + TAG_SIZE];
        reader.read_exact(&mut ct)?;

        let mut nonce = [0u8; 24];
        nonce[..NONCE_LEN].copy_from_slice(payload_nonce);
        nonce[NONCE_LEN..].copy_from_slice(&index.to_be_bytes());

        let cipher = XChaCha20Poly1305::new(&payload_key);
        let aad = [&header[..], &index.to_be_bytes()].concat();

        let plaintext = cipher.decrypt(
            GenericArray::from_slice(&nonce),
            Payload { msg: &ct, aad: &aad }
        ).map_err(|_| anyhow::anyhow!("Authentication failed"))?;

        writer.write_all(&plaintext)?;
        index += 1;
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    std::fs::rename(&temp_path, &final_path)?;

    sync_parent_dir(&final_path)?;

    Ok(())
}

fn sync_parent_dir(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };

        let dir = OpenOptions::new().read(true).open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

fn secure_delete(path: &Path) -> io::Result<()> {
    let len = metadata(path)?.len();
    if len == 0 {
        return remove_file(path);
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut buf = vec![0u8; 4096];

    for _ in 0..3 {
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = len;
        while remaining > 0 {
            let size = buf.len().min(remaining as usize);
            OsRng.fill_bytes(&mut buf[..size]);
            file.write_all(&buf[..size])?;
            remaining -= size as u64;
        }
        file.sync_all()?;
    }

    remove_file(path)
}
