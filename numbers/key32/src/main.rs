// This utility is intended for Linux only.

use clap::{Parser, Subcommand};
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(version, about = "File utility for key management")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generates random key files in k/keys
    Make {
        /// Number of key files to generate
        num_files: usize,
    },

    /// Stores all existing key files in numerical order to k/txt/k.txt
    Store,

    /// Restores all lines from k/txt/k.txt to binary key files in k/returned
    Restore,
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Make { num_files } => {
            const BYTE_SIZE: usize = 32;

            if num_files == 0 {
                eprintln!("Error: Number of files must be at least 1.");
                std::process::exit(1);
            }

            let dir = "k/keys";
            if !Path::new(dir).exists() {
                fs::create_dir_all(dir)?;
            }

            // Check for existing files that will be overwritten
            let mut existing_count = 0;
            for i in 1..=num_files {
                let filename = format!("{}/{}.key", dir, i);
                if Path::new(&filename).exists() {
                    existing_count += 1;
                }
            }

            if existing_count > 0 {
                println!("Warning: {} files will be overwritten in the '{}' directory. Continue? (y/n)", existing_count, dir);
                let stdin = io::stdin();
                let mut input = String::new();
                stdin.lock().read_line(&mut input)?;
                let trimmed = input.trim().to_lowercase();
                if trimmed != "y" && trimmed != "yes" {
                    println!("Operation cancelled.");
                    std::process::exit(0);
                }
            }

            let mut rng = rand::thread_rng();

            for i in 1..=num_files {
                let mut key = vec![0u8; BYTE_SIZE];
                rng.fill_bytes(&mut key);

                let filename = format!("{}/{}.key", dir, i);
                let mut file = File::create(&filename)?;
                file.write_all(&key)?;

                println!("Generated: {}", filename);
            }
        }

        Command::Store => {
            let keys_dir = "k/keys";
            if !Path::new(keys_dir).exists() {
                eprintln!("Error: '{}' directory does not exist.", keys_dir);
                std::process::exit(1);
            }

            let mut nums: Vec<usize> = Vec::new();
            for entry in fs::read_dir(keys_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if let Some(filename) = path.file_name() {
                        if let Some(name) = filename.to_str() {
                            if name.ends_with(".key") {
                                if let Ok(num) = name.strip_suffix(".key").unwrap().parse::<usize>() {
                                    nums.push(num);
                                }
                            }
                        }
                    }
                }
            }

            if nums.is_empty() {
                println!("No key files found in '{}'.", keys_dir);
                return Ok(());
            }

            nums.sort();

            let txt_dir = "k/txt";
            if !Path::new(txt_dir).exists() {
                fs::create_dir_all(txt_dir)?;
            }

            let txt_path = format!("{}/k.txt", txt_dir);

            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(&txt_path)?;

            for num in nums {
                let key_file = format!("{}.key", num);
                let key_path = format!("{}/{}", keys_dir, key_file);

                let bytes = fs::read(&key_path)?;

                let numbers: Vec<String> = bytes.iter().map(|&b| b.to_string()).collect();
                let line = numbers.join(" ") + "\n";

                file.write_all(line.as_bytes())?;

                println!("Appended converted key from '{}' to {}", key_file, txt_path);
            }
        }

        Command::Restore => {
            let input_file = "k/txt/k.txt";
            if !Path::new(input_file).exists() {
                eprintln!("Error: '{}' does not exist.", input_file);
                std::process::exit(1);
            }

            let content = fs::read_to_string(input_file)?;
            let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
            if lines.is_empty() {
                eprintln!("Error: '{}' contains no valid lines.", input_file);
                std::process::exit(1);
            }

            let dir = "k/returned";
            if !Path::new(dir).exists() {
                fs::create_dir_all(dir)?;
            }

            // Check for existing files that will be overwritten
            let num_files = lines.len();
            let mut existing_count = 0;
            for i in 1..=num_files {
                let filename = format!("{}/{}.key", dir, i);
                if Path::new(&filename).exists() {
                    existing_count += 1;
                }
            }

            if existing_count > 0 {
                println!("Warning: {} files will be overwritten in the '{}' directory. Continue? (y/n)", existing_count, dir);
                let stdin = io::stdin();
                let mut input = String::new();
                stdin.lock().read_line(&mut input)?;
                let trimmed = input.trim().to_lowercase();
                if trimmed != "y" && trimmed != "yes" {
                    println!("Operation cancelled.");
                    std::process::exit(0);
                }
            }

            for (idx, line) in lines.iter().enumerate() {
                let numbers: Vec<&str> = line.split_whitespace().collect();
                if numbers.len() != 32 {
                    eprintln!("Error: Line {} in '{}' must contain exactly 32 space-separated numbers.", idx + 1, input_file);
                    std::process::exit(1);
                }

                let mut bytes: Vec<u8> = Vec::with_capacity(32);
                for &num_str in &numbers {
                    match num_str.parse::<u8>() {
                        Ok(byte) => bytes.push(byte),
                        Err(_) => {
                            eprintln!("Error: Invalid number '{}' on line {} in '{}'. Must be 0-255.", num_str, idx + 1, input_file);
                            std::process::exit(1);
                        }
                    }
                }

                let output_file = format!("{}/{}.key", dir, idx + 1);
                let mut file = File::create(&output_file)?;
                file.write_all(&bytes)?;

                println!("Converted line {} to '{}'", idx + 1, output_file);
            }
        }
    }

    Ok(())
}