// src/main.rs
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

#[cfg(target_family = "unix")]
fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read; // only needed on Unix
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(target_family = "windows")]
mod winrng {
    use std::io;
    use std::os::raw::{c_int, c_uchar, c_uint};
    use std::ptr::null_mut;

    #[link(name = "bcrypt")]
    extern "system" {
        // NTSTATUS BCryptGenRandom(
        //   BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
        fn BCryptGenRandom(
            hAlgorithm: *mut core::ffi::c_void,
            pbBuffer: *mut c_uchar,
            cbBuffer: c_uint,
            dwFlags: c_uint,
        ) -> c_int;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: c_uint = 0x00000002;
    const STATUS_SUCCESS: c_int = 0;

    pub fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                buf.as_mut_ptr(),
                buf.len() as c_uint,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("BCryptGenRandom failed: 0x{status:08x}"),
            ))
        }
    }
}
#[cfg(target_family = "windows")]
fn fill_bytes(buf: &mut [u8]) -> io::Result<()> {
    winrng::fill_bytes(buf)
}

// ---------- tiny encoders (no crates) ----------

fn encode_hex(bytes: &[u8], uppercase: bool) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let table = if uppercase { HEX_UPPER } else { HEX_LOWER };
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(table[(b >> 4) as usize] as char);
        out.push(table[(b & 0x0f) as usize] as char);
    }
    out
}

fn encode_base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((bytes.len() + 2) / 3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

// ---------- minimal arg parsing (no external crates) ----------

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Hex,
    Base64,
    Raw,
}

struct Args {
    length: usize,
    format: Format,
    uppercase: bool,
    out: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = env::args().skip(1);
    let usage = "usage: keymaker <length> [--format hex|base64|raw] [--uppercase] [--out PATH]";

    let length = it
        .next()
        .ok_or(usage)?
        .parse::<usize>()
        .map_err(|_| "length must be a non-negative integer")?;

    let mut format = Format::Hex;
    let mut uppercase = false;
    let mut out: Option<PathBuf> = None;

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--format" => {
                let v = it.next().ok_or("--format requires a value")?;
                format = match v.as_str() {
                    "hex" => Format::Hex,
                    "base64" => Format::Base64,
                    "raw" => Format::Raw,
                    _ => return Err("invalid --format (hex|base64|raw)".into()),
                };
            }
            "--uppercase" => uppercase = true,
            "--out" => {
                let v = it.next().ok_or("--out requires a path")?;
                out = Some(PathBuf::from(v));
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if length == 0 {
        return Err("length must be > 0".into());
    }
    if uppercase && format != Format::Hex {
        return Err("--uppercase only applies to --format hex".into());
    }

    Ok(Args {
        length,
        format,
        uppercase,
        out,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            eprintln!("Try: keymaker 32 --format base64");
            std::process::exit(2);
        }
    };

    let mut buf = vec![0u8; args.length];
    fill_bytes(&mut buf)?;

    match args.format {
        Format::Raw => write_out(&buf, args.out.as_ref())?,
        Format::Hex => {
            let mut s = encode_hex(&buf, args.uppercase);
            s.push('\n');
            write_out(s.as_bytes(), args.out.as_ref())?;
        }
        Format::Base64 => {
            let mut s = encode_base64(&buf);
            s.push('\n');
            write_out(s.as_bytes(), args.out.as_ref())?;
        }
    }

    Ok(())
}

fn write_out(bytes: &[u8], out: Option<&PathBuf>) -> io::Result<()> {
    match out {
        Some(p) => {
            let mut f = File::create(p)?;
            f.write_all(bytes)?;
            f.flush()
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(bytes)?;
            stdout.flush()
        }
    }
}
