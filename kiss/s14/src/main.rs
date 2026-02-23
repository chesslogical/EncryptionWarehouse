#![deny(unsafe_code)]
#[cfg(not(target_os = "linux"))]
compile_error!("This program is Linux-only.");

use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Instant,
};

use argon2::{Algorithm, Argon2, Params, Version};
use argon2::Block;
use blake3;
use clap::{Parser, ValueEnum};
use nix::{
    libc::{O_CLOEXEC, O_NOFOLLOW},
    sys::{
        prctl::set_dumpable,
        resource::{setrlimit, Resource},
    },
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const KEY_MAX_BYTES: u128 = 20 * 1024 * 1024 * 1024;
const IO_BUF_SIZE: usize = 1 << 20;
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ARGON2_TIME: u32 = 3;
const DEFAULT_ARGON2_PAR: u32 = 0;
const PEPPER_MIN_CHARS: usize = 8;
const DOMAIN_VERSION: &str = "v1";
const MAX_ARGON2_MEMORY_KIB: u32 = 4 * 1024 * 1024;

#[derive(Copy, Clone, ValueEnum, Debug, PartialEq)]
enum StreamAlgo {
    Blake3,
    Chacha,
}

impl std::fmt::Display for StreamAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blake3 => write!(f, "BLAKE3"),
            Self::Chacha => write!(f, "ChaCha20"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Deterministic high-strength key material generator (Linux-only)",
    after_help = "Generates reproducible raw key material using Argon2id + BLAKE3/ChaCha20.\nUse --print-first to verify determinism without writing the full file."
)]
struct Cli {
    #[arg(value_name = "SIZE_BYTES")]
    size_bytes: u128,

    #[arg(short, long, default_value = "key.key")]
    output: PathBuf,

    #[arg(short = 'a', long = "algo", value_enum, default_value_t = StreamAlgo::Blake3)]
    algo: StreamAlgo,

    #[arg(long, default_value_t = DEFAULT_ARGON2_MEMORY_KIB)]
    argon2_memory: u32,

    #[arg(long, default_value_t = DEFAULT_ARGON2_TIME)]
    argon2_time: u32,

    #[arg(long, default_value_t = DEFAULT_ARGON2_PAR)]
    argon2_par: u32,

    #[arg(long)]
    no_clobber: bool,

    #[arg(long = "print-first", value_name = "N_BYTES")]
    print_first: Option<usize>,
}

fn main() -> io::Result<()> {
    harden_process();

    let cli = Cli::parse();

    if cli.size_bytes == 0 || cli.size_bytes > KEY_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SIZE_BYTES must be 1..={KEY_MAX_BYTES}"),
        ));
    }

    if cli.argon2_memory > MAX_ARGON2_MEMORY_KIB {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("argon2-memory exceeds limit ({MAX_ARGON2_MEMORY_KIB} KiB)"),
        ));
    }

    let pwd = read_password("Enter password:     ")?;
    let pwd_confirm = read_password("Confirm password: ")?;
    if pwd.as_bytes().ct_eq(pwd_confirm.as_bytes()).unwrap_u8() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Passwords do not match"));
    }

    let pepper = read_password("Enter pepper (secret salt): ")?;
    let pepper_confirm = read_password("Confirm pepper:             ")?;
    if pepper.as_bytes().ct_eq(pepper_confirm.as_bytes()).unwrap_u8() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Peppers do not match"));
    }

    if pepper.len() < PEPPER_MIN_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Pepper must be at least {PEPPER_MIN_CHARS} characters"),
        ));
    }
    if pepper.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Pepper cannot be only whitespace",
        ));
    }

    let salt = Zeroizing::new(derive_salt_from_pepper(&pepper));

    let par = effective_parallelism(cli.argon2_par, cli.argon2_memory);

    println!(
        "Generating {} bytes using {} / Argon2id(m={} KiB, t={}, p={})",
        cli.size_bytes, cli.algo, cli.argon2_memory, cli.argon2_time, par
    );

    let start = Instant::now();

    let raw_seed = derive_seed(&pwd, &salt, cli.argon2_memory, cli.argon2_time, par)?;

    let stream_seed = derive_stream_seed(&raw_seed, cli.algo, cli.argon2_memory, cli.argon2_time, par);

    if let Some(n) = cli.print_first {
        if n > 0 && n <= 4096 {
            let first = get_first_n_bytes(&stream_seed, cli.algo, n)?;
            println!("\nFirst {} bytes (hex):\n{}", n, hex_dump(&first, 16));
        } else if n > 4096 {
            eprintln!("--print-first limited to 4096 bytes for readability");
        }
    }

    write_stream_to_file(&cli.output, &stream_seed, cli.size_bytes, cli.algo, cli.no_clobber)?;

    println!("Done in {:.2?} → {}", start.elapsed(), cli.output.display());

    Ok(())
}

fn harden_process() {
    // Best-effort hardening — ignore errors in containers etc.
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);
    let _ = set_dumpable(false);  // false = non-dumpable (prevents core dumps)
}

fn effective_parallelism(user: u32, mem_kib: u32) -> u32 {
    let mut par = if user == 0 {
        std::thread::available_parallelism().map_or(4, |n| n.get() as u32)
    } else {
        user.max(1)
    };

    let max_p = (mem_kib / 8).max(1);
    if par > max_p {
        eprintln!("Note: reduced parallelism from {} to {} (m >= 8*p constraint)", par, max_p);
        par = max_p;
    }
    par
}

fn read_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    let pass = prompt_password(prompt)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    if pass.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty password not allowed"));
    }
    Ok(Zeroizing::new(pass))
}

fn derive_salt_from_pepper(pepper: &Zeroizing<String>) -> [u8; 32] {
    blake3::derive_key(
        &format!("key/salt/pepper/{}", DOMAIN_VERSION),
        pepper.as_bytes(),
    )
}

fn derive_stream_seed(
    raw: &[u8; 32],
    algo: StreamAlgo,
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    let ctx = format!(
        "key/stream-seed/{DOMAIN_VERSION}|algo={algo}|argon2(m={mem},t={time},p={par})"
    );
    blake3::derive_key(&ctx, raw)
}

fn derive_seed(
    password: &Zeroizing<String>,
    salt: &Zeroizing<[u8; 32]>,
    mem_kib: u32,
    time: u32,
    par: u32,
) -> io::Result<[u8; 32]> {
    let params = Params::new(mem_kib * 1024, time, par, None)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 32];
    let mut blocks = vec![Block::new(); mem_kib as usize];

    argon2
        .hash_password_into_with_memory(password.as_bytes(), salt.as_ref(), &mut seed, &mut blocks)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    for b in &mut blocks {
        *b = Block::new();
    }

    Ok(seed)
}

fn secure_open(path: &Path, no_clobber: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC);

    if no_clobber {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }

    opts.open(path)
}

fn fsync_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        let dir = File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

fn write_stream_to_file(
    path: &Path,
    seed: &[u8; 32],
    mut remaining: u128,
    algo: StreamAlgo,
    no_clobber: bool,
) -> io::Result<()> {
    let file = secure_open(path, no_clobber)?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, file);

    let mut buf = Zeroizing::new(vec![0u8; IO_BUF_SIZE]);

    let mut chunk_count: u64 = 0;

    match algo {
        StreamAlgo::Blake3 => {
            let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
            while remaining > 0 {
                let n = remaining.min(IO_BUF_SIZE as u128) as usize;
                xof.fill(&mut buf[..n]);
                writer.write_all(&buf[..n])?;
                remaining -= n as u128;
                chunk_count += 1;
                if chunk_count % 10 == 0 {
                    print!(".");
                    let _ = io::stdout().flush();
                }
            }
        }
        StreamAlgo::Chacha => {
            let mut rng = ChaCha20Rng::from_seed(*seed);
            while remaining > 0 {
                let n = remaining.min(IO_BUF_SIZE as u128) as usize;
                rng.fill_bytes(&mut buf[..n]);
                writer.write_all(&buf[..n])?;
                remaining -= n as u128;
                chunk_count += 1;
                if chunk_count % 10 == 0 {
                    print!(".");
                    let _ = io::stdout().flush();
                }
            }
        }
    }

    writer.flush()?;
    let file = writer.into_inner()?;
    file.sync_all()?;
    fsync_parent_dir(path)?;

    if chunk_count > 0 {
        println!();
    }

    Ok(())
}

fn get_first_n_bytes(seed: &[u8; 32], algo: StreamAlgo, n: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    match algo {
        StreamAlgo::Blake3 => {
            let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
            xof.fill(&mut out);
        }
        StreamAlgo::Chacha => {
            let mut rng = ChaCha20Rng::from_seed(*seed);
            rng.fill_bytes(&mut out);
        }
    }
    Ok(out)
}

fn hex_dump(bytes: &[u8], cols: usize) -> String {
    let mut s = String::with_capacity(bytes.len() * 3 + bytes.len() / cols + 1);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            if i % cols == 0 {
                s.push('\n');
            } else {
                s.push(' ');
            }
        }
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}