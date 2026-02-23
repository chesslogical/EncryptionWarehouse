# s2 

 
  
   S2 is a simple command-line tool made only for Linux. It automatically toggles encryption on any file you give it. If the file is plain text it encrypts it; if it is already encrypted it decrypts it. The program is built for maximum reliability and data safety. It keeps the entire file in memory (no streaming or chunking), uses atomic overwrites so the file is never left half-written, adds an integrity hash so any corruption or wrong password is instantly detected, and restores the original file permissions and timestamps.
   
   
Important: This tool overwrites the file in place. Always keep a backup of important files. Never encrypt the only copy of anything you care about.

It uses strong AES-256-GCM-SIV encryption. The key is derived from the password you type using Argon2 with a unique random salt for every file. It prints only "ok" when everything succeeds, just like many other modern tools.

To install, clone the repository, then run "cargo build --release". The finished program will be at target/release/s2.

To use it, go to the folder that contains your file and run:
./s2 filename.txt

It will ask "Enter password:" – type your password and press Enter. The same password is used for both encrypting and decrypting.

Limitations: The file must be in the current directory (you cannot use full paths). It does not work on directories or very large files that do not fit comfortably in RAM. It is Linux-only because it uses Unix file metadata features.

Security notes: The password is zeroized from memory immediately after use. Every encrypted file contains a random salt and a SHA-256 integrity hash. If the password is wrong or the file is damaged you will get a clear error instead of corrupted data.
