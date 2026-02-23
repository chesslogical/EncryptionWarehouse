use std::error::Error;
use std::fs::{File, OpenOptions, metadata, rename, remove_file};
use std::io::{self, BufReader, BufWriter, Read, Write, Seek, SeekFrom, ErrorKind};
use std::path::Path;
use clap::Parser;
use rpassword::prompt_password;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, Payload, KeyInit}};
use generic_array::{GenericArray, typenum::U32};
use hkdf::Hkdf;
use sha2::Sha256;
use aead::Error as AeadError;

const MAGIC: [u8; 4] = [b's', b'e', b'c', b'a'];
const VERSION: u8 = 1;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 16;

#[derive(Parser)]
#[command(name = "secureapp")]
#[command(about = "Secure file encryption CLI for Linux, rivaling rage and Picocrypt in security and reliability.")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Encrypt a file or stdin
    Enc(EncArgs),
    /// Decrypt a file or stdin
    Dec(DecArgs),
}

#[derive(Parser)]
struct EncArgs {
    #[arg(short, long)]
    input: Option<String>,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(long, help = "Securely delete the input file after encryption")]
    delete: bool,
}

#[derive(Parser)]
struct DecArgs {
    #[arg(short, long)]
    input: Option<String>,
    #[arg(short, long)]
    output: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    match args.command {
        Command::Enc(enc_args) => encrypt(enc_args)?,
        Command::Dec(dec_args) => decrypt(dec_args)?,
    }
    Ok(())
}

fn derive_key(pass: &str, salt: &[u8]) -> Zeroizing<GenericArray<u8, U32>> {
    use argon2::{Argon2, Algorithm, Version, Params};
    let params = Params::new(1024 * 1024, 3, 4, Some(32)).unwrap();
    let mut key = GenericArray::<u8, U32>::default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .unwrap();
    Zeroizing::new(key)
}

fn hkdf_expand(key: &GenericArray<u8, U32>, nonce: &[u8]) -> GenericArray<u8, U32> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), key);
    let mut okm = GenericArray::<u8, U32>::default();
    hk.expand(b"payload", &mut okm).unwrap();
    okm
}

struct StreamEncryptor<W: Write> {
    inner: W,
    buffer: Vec<u8>,
    payload_key: GenericArray<u8, U32>,
    master_nonce: [u8; NONCE_LEN],
    index: u64,
}

impl<W: Write> StreamEncryptor<W> {
    fn new(inner: W, payload_key: GenericArray<u8, U32>, master_nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            payload_key,
            master_nonce,
            index: 0,
        }
    }

    fn finalize(mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let size = self.buffer.len();
            let mut i = self.index;
            i |= 1u64 << 63;
            let mut nonce = [0u8; 24];
            nonce[0..NONCE_LEN].copy_from_slice(&self.master_nonce);
            nonce[NONCE_LEN..].copy_from_slice(&i.to_be_bytes());
            let nonce_ga = GenericArray::from_slice(&nonce);
            let cipher = XChaCha20Poly1305::new(&self.payload_key);
            let payload = Payload { msg: &self.buffer[0..size], aad: b"" };
            let ct_with_tag = cipher.encrypt(nonce_ga, payload).map_err(|_| io::Error::new(ErrorKind::Other, "Encryption failed"))?;
            self.inner.write_all(&ct_with_tag[0..size])?;
            self.inner.write_all(&ct_with_tag[size..])?;
            self.buffer.clear();
            self.index += 1;
        }
        self.inner.flush()
    }
}

impl<W: Write> Write for StreamEncryptor<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= CHUNK_SIZE {
            let size = CHUNK_SIZE;
            let i = self.index;
            let mut nonce = [0u8; 24];
            nonce[0..NONCE_LEN].copy_from_slice(&self.master_nonce);
            nonce[NONCE_LEN..].copy_from_slice(&i.to_be_bytes());
            let nonce_ga = GenericArray::from_slice(&nonce);
            let cipher = XChaCha20Poly1305::new(&self.payload_key);
            let payload = Payload { msg: &self.buffer[0..size], aad: b"" };
            let ct_with_tag = cipher.encrypt(nonce_ga, payload).map_err(|_| io::Error::new(ErrorKind::Other, "Encryption failed"))?;
            self.inner.write_all(&ct_with_tag[0..size])?;
            self.inner.write_all(&ct_with_tag[size..])?;
            self.buffer.drain(0..size);
            self.index += 1;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct StreamDecryptor<R: Read> {
    inner: BufReader<R>,
    dec_buf: Vec<u8>,
    pos: usize,
    payload_key: GenericArray<u8, U32>,
    master_nonce: [u8; NONCE_LEN],
    index: u64,
    final_seen: bool,
}

impl<R: Read> StreamDecryptor<R> {
    fn new(inner: R, payload_key: GenericArray<u8, U32>, master_nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            inner: BufReader::new(inner),
            dec_buf: Vec::new(),
            pos: 0,
            payload_key,
            master_nonce,
            index: 0,
            final_seen: false,
        }
    }
}

impl<R: Read> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.pos < self.dec_buf.len() {
                let to_copy = (buf.len() - filled).min(self.dec_buf.len() - self.pos);
                buf[filled..filled + to_copy].copy_from_slice(&self.dec_buf[self.pos..self.pos + to_copy]);
                self.pos += to_copy;
                filled += to_copy;
                continue;
            }
            if self.final_seen {
                return Ok(filled);
            }
            self.dec_buf.clear();
            self.pos = 0;
            let mut ct = vec![0u8; CHUNK_SIZE];
            let ct_read = self.inner.read(&mut ct)?;
            if ct_read == 0 {
                if self.index == 0 {
                    self.final_seen = true;
                    return Ok(filled);
                } else {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "No final chunk"));
                }
            }
            let mut tag = [0u8; TAG_SIZE];
            let tag_read = self.inner.read(&mut tag)?;
            if tag_read != TAG_SIZE {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "Incomplete tag"));
            }
            let mut ct_with_tag = vec![0u8; ct_read + TAG_SIZE];
            ct_with_tag[0..ct_read].copy_from_slice(&ct[0..ct_read]);
            ct_with_tag[ct_read..].copy_from_slice(&tag);
            if ct_read == 0 {
                return Err(io::Error::new(ErrorKind::InvalidData, "Empty chunk"));
            }
            // Try non-final
            let decrypted = self.try_decrypt(&ct_with_tag, false);
            if let Ok(pt) = decrypted {
                self.dec_buf = pt;
                self.index += 1;
                continue;
            }
            // Try final
            let decrypted = self.try_decrypt(&ct_with_tag, true);
            if let Ok(pt) = decrypted {
                self.dec_buf = pt;
                self.final_seen = true;
                self.index += 1;
                continue;
            }
            return Err(io::Error::new(ErrorKind::InvalidData, "Decryption failed"));
        }
        Ok(filled)
    }
}

impl<R: Read> StreamDecryptor<R> {
    fn try_decrypt(&self, ct_with_tag: &[u8], is_final: bool) -> Result<Vec<u8>, AeadError> {
        let mut i = self.index;
        if is_final {
            i |= 1u64 << 63;
        }
        let mut nonce = [0u8; 24];
        nonce[0..NONCE_LEN].copy_from_slice(&self.master_nonce);
        nonce[NONCE_LEN..].copy_from_slice(&i.to_be_bytes());
        let nonce_ga = GenericArray::from_slice(&nonce);
        let cipher = XChaCha20Poly1305::new(&self.payload_key);
        let payload = Payload { msg: ct_with_tag, aad: b"" };
        cipher.decrypt(nonce_ga, payload)
    }
}

fn encrypt(args: EncArgs) -> Result<(), Box<dyn Error>> {
    let mut pass = prompt_password("Enter password: ")?;
    let mut confirm = prompt_password("Confirm password: ")?;
    if pass != confirm {
        return Err("Passwords don't match".into());
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut payload_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut payload_nonce);
    let key = derive_key(&pass, &salt);
    let payload_key = hkdf_expand(&*key, &payload_nonce);
    pass.zeroize();
    confirm.zeroize();
    let input: Box<dyn Read> = if let Some(inf) = &args.input {
        Box::new(File::open(inf)?)
    } else {
        Box::new(io::stdin())
    };
    let mut reader = BufReader::new(input);
    let (mut header_writer, temp_path): (Box<dyn Write>, Option<String>) = if let Some(outf) = &args.output {
        let tmp = format!("{}.tmp", outf);
        (Box::new(BufWriter::new(File::create(&tmp)?)), Some(tmp))
    } else {
        (Box::new(BufWriter::new(io::stdout())), None)
    };
    header_writer.write_all(&MAGIC)?;
    header_writer.write_all(&[VERSION])?;
    header_writer.write_all(&salt)?;
    header_writer.write_all(&payload_nonce)?;
    header_writer.flush()?;
    let mut encryptor = StreamEncryptor::new(header_writer, payload_key, payload_nonce);
    io::copy(&mut reader, &mut encryptor)?;
    encryptor.finalize()?;
    if let Some(tmp) = temp_path {
        rename(&tmp, args.output.as_ref().unwrap())?;
    }
    if args.delete {
        if let Some(inf) = args.input {
            secure_delete(Path::new(&inf))?;
        }
    }
    Ok(())
}

fn decrypt(args: DecArgs) -> Result<(), Box<dyn Error>> {
    let mut pass = prompt_password("Enter password: ")?;
    let input: Box<dyn Read> = if let Some(inf) = &args.input {
        Box::new(File::open(inf)?)
    } else {
        Box::new(io::stdin())
    };
    let mut reader = BufReader::new(input);
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err("Invalid magic".into());
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver)?;
    if ver[0] != VERSION {
        return Err("Unsupported version".into());
    }
    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;
    let mut payload_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut payload_nonce)?;
    let key = derive_key(&pass, &salt);
    let payload_key = hkdf_expand(&*key, &payload_nonce);
    pass.zeroize();
    let mut decryptor = StreamDecryptor::new(reader, payload_key, payload_nonce);
    let (mut writer, temp_path): (Box<dyn Write>, Option<String>) = if let Some(outf) = &args.output {
        let tmp = format!("{}.tmp", outf);
        (Box::new(BufWriter::new(File::create(&tmp)?)), Some(tmp))
    } else {
        (Box::new(BufWriter::new(io::stdout())), None)
    };
    io::copy(&mut decryptor, &mut writer)?;
    if !decryptor.final_seen {
        return Err("No final chunk found".into());
    }
    if let Some(tmp) = temp_path {
        rename(&tmp, args.output.as_ref().unwrap())?;
    }
    Ok(())
}

fn secure_delete(path: &Path) -> io::Result<()> {
    let len = metadata(path)?.len();
    if len == 0 {
        return remove_file(path);
    }
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let buf_size = 4096;
    let mut buf = vec![0u8; buf_size];
    for _ in 0..3 {
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = len;
        while remaining > 0 {
            let size = buf_size.min(remaining as usize);
            OsRng.fill_bytes(&mut buf[0..size]);
            file.write_all(&buf[0..size])?;
            remaining -= size as u64;
        }
        file.sync_all()?;
    }
    remove_file(path)
}
