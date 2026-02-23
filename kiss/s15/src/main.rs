use blake3::Hasher;
use clap::Parser;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB streaming chunks

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// 32-byte master seed in hex (64 hex chars)
    #[arg(long)]
    seed: String,

    /// Domain separation label
    #[arg(long)]
    domain: String,

    /// Number of bytes to generate (1 to 20GB+)
    #[arg(long)]
    size: u64,

    /// Optional offset into stream
    #[arg(long, default_value_t = 0)]
    offset: u64,

    /// Optional output file (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if args.size == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "size must be > 0"));
    }

    // Decode seed
    let seed_bytes = hex::decode(&args.seed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hex seed"))?;

    if seed_bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seed must be exactly 32 bytes (64 hex chars)",
        ));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes);

    // Derive root key
    let root_key = blake3::derive_key("detkey-root", &seed_array);

    // Domain separation
    let mut hasher = Hasher::new_keyed(&root_key);
    hasher.update(args.domain.as_bytes());

    let mut xof = hasher.finalize_xof();
    xof.set_position(args.offset);

    // Output writer
    let writer: Box<dyn Write> = match args.out {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout())),
    };

    stream_bytes(writer, &mut xof, args.size)?;

    Ok(())
}

fn stream_bytes(mut writer: Box<dyn Write>, xof: &mut blake3::OutputReader, mut remaining: u64) -> io::Result<()> {
    let mut buffer = vec![0u8; CHUNK_SIZE];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
        xof.fill(&mut buffer[..to_read]);
        writer.write_all(&buffer[..to_read])?;
        remaining -= to_read as u64;
    }

    writer.flush()?;
    Ok(())
}
