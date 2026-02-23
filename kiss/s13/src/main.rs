#![deny(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("This program is Linux-only.");

use std::{
    fs::File,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use nix::libc;
use argon2::{Algorithm, Argon2, Params, Version};
use argon2::Block;
use blake3;
use clap::{Parser, ValueEnum};
use nix::sys::resource::{setrlimit, Resource};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const KEY_MAX_BYTES: u128 = 20 * 1024 * 1024 * 1024;
const IO_BUF_SIZE: usize = 1 << 20;
const DEFAULT_ARGON2_MEMORY: u32 = 64 * 1024; // 64 MiB
const DEFAULT_ARGON2_TIME: u32 = 3;

#[derive(Copy, Clone, ValueEnum, Debug)]
enum StreamAlgo {
    Blake3,
    Chacha,
}

#[derive(Parser, Debug)]
#[command(author, version)]
struct Cli {
    size_bytes: u128,

    #[arg(short, long, default_value = "key.key")]
    output: PathBuf,

    #[arg(short = 'a', long = "algo", value_enum, default_value_t = StreamAlgo::Blake3)]
    algo: StreamAlgo,

    #[arg(long, default_value_t = DEFAULT_ARGON2_MEMORY)]
    argon2_memory: u32,

    #[arg(long, default_value_t = DEFAULT_ARGON2_TIME)]
    argon2_time: u32,

    #[arg(long)]
    no_clobber: bool,
}

fn main() -> io::Result<()> {
    harden_process()?;
    run()
}

fn harden_process() -> io::Result<()> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(())
}

fn run() -> io::Result<()> {
    let args = Cli::parse();

    if args.size_bytes == 0 || args.size_bytes > KEY_MAX_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid key size"));
    }

    let pwd = read_password("Password: ")?;
    let confirm = read_password("Confirm: ")?;

    if pwd.as_bytes().ct_eq(confirm.as_bytes()).unwrap_u8() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Passwords do not match"));
    }

    let pepper = read_password("Second password (pepper): ")?;

    let salt = Zeroizing::new(blake3::derive_key("key/salt/v1", pepper.as_bytes()));

    let mut seed = derive_seed(&pwd, &salt, args.argon2_memory, args.argon2_time)?;

    write_stream(
        &args.output,
        &mut seed,
        args.size_bytes,
        args.algo,
        args.no_clobber,
    )?;

    seed.zeroize();

    Ok(())
}

fn read_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    let p = prompt_password(prompt)?;
    if p.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty password"));
    }
    Ok(Zeroizing::new(p))
}

fn derive_seed(
    password: &Zeroizing<String>,
    salt: &[u8; 32],
    mem: u32,
    time: u32,
) -> io::Result<[u8; 32]> {
    let params = Params::new(mem, time, 1, None)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 32];
    let mut blocks = vec![Block::new(); mem as usize];

    argon2
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut seed, &mut blocks)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    for b in &mut blocks {
        *b = Block::new();
    }

    Ok(seed)
}

fn secure_open(path: &Path, no_clobber: bool) -> io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();

    opts.write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);

    if no_clobber {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }

    opts.open(path)
}

fn write_stream(
    path: &Path,
    seed: &mut [u8; 32],
    size: u128,
    algo: StreamAlgo,
    no_clobber: bool,
) -> io::Result<()> {
    let mut file = secure_open(path, no_clobber)?;
    let mut remaining = size;
    let mut buffer = Zeroizing::new(vec![0u8; IO_BUF_SIZE]);

    match algo {
        StreamAlgo::Blake3 => {
            let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
            while remaining > 0 {
                let n = remaining.min(IO_BUF_SIZE as u128) as usize;
                xof.fill(&mut buffer[..n]);
                file.write_all(&buffer[..n])?;
                remaining -= n as u128;
            }
        }
        StreamAlgo::Chacha => {
            let mut rng = ChaCha20Rng::from_seed(*seed);
            while remaining > 0 {
                let n = remaining.min(IO_BUF_SIZE as u128) as usize;
                rng.fill_bytes(&mut buffer[..n]);
                file.write_all(&buffer[..n])?;
                remaining -= n as u128;
            }
        }
    }

    file.sync_all()?;
    Ok(())
}
