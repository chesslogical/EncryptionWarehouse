

# detkey 8

A small, deterministic key generation tool.

`detkey` derives a cryptographically strong master key from a password using **Argon2 (Argon2id)**, then expands it into an arbitrary-length deterministic byte stream using **ChaCha20**.

It writes the result to `key.key` in the current directory and refuses to overwrite existing files.

This tool is intentionally:

* Single-purpose
* Deterministic
* Small
* Auditable
* Explicit

---

# What It Does

Given:

* A password (entered twice for safety)
* A requested output length in **bytes**
* Compile-time configuration (salt, pepper, Argon2 cost)

It produces:

* A deterministic byte stream
* From 1 byte up to 20GB
* Written to `key.key`
* Reproducible for the same password + configuration

---

# Why This Design

This tool separates concerns correctly:

1. **Argon2id** is used strictly as a password-based key derivation function (KDF).
2. The derived 32-byte master key is used as the key for ChaCha20.
3. ChaCha20 generates a deterministic stream of bytes.
4. The stream is written in constant memory chunks.

This avoids:

* Misusing password hash functions as large-output generators
* Hand-rolled crypto constructions
* Ambiguous formats or units
* Hidden runtime tuning

---

# Usage

Build:

```bash
cargo build --release
```

Run:

```bash
./target/release/detkey --length 32
```

Example:

```bash
./target/release/detkey --length 1048576
```

Length must be specified in **bytes only**.

The tool will:

1. Prompt for password
2. Prompt for confirmation
3. Refuse to overwrite if `key.key` already exists
4. Generate the requested number of bytes

---

# Determinism

The output is deterministic based on:

* Password
* SALT constant
* PEPPER constant
* Argon2 parameters
* Algorithm version

If all of those remain unchanged, the same password and length will always produce identical output.

Changing any of them will change all outputs.

---

# Configuration (Compile-Time)

At the top of `main.rs`:

```rust
// Argon2 tuning parameters
const ARGON2_MEMORY_KIB: u32 = 262_144; // 256MB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

// Deterministic salt
const SALT: &[u8] = b"detkey-v1-domain";

// Optional compile-time pepper
const PEPPER: &[u8] = b"";
```

## Argon2 Tuning

* `ARGON2_MEMORY_KIB` controls memory hardness.
* `ARGON2_ITERATIONS` controls time cost.
* `ARGON2_PARALLELISM` controls lanes.

Higher values increase brute-force resistance but increase runtime.

These are fixed at compile time to prevent accidental misuse.

---

# Security Model

## What This Tool Is For

* Deterministic API key generation
* Wallet seed material
* Long-form key material
* Reproducible secret expansion
* Air-gapped key generation

## What This Tool Is Not

* Not a file encryptor
* Not a password manager
* Not a secure vault
* Not a randomness generator
* Not forward-secret

It is purely deterministic expansion from a password.

---

# Memory & Performance

* Uses constant memory (1MB streaming buffer)
* Argon2 memory cost currently 256MB
* Output generation scales linearly
* Can generate up to 20GB safely
* Refuses overwrite to avoid accidental destruction

---

# Safety Features

* Password must be entered twice
* Password buffers are zeroized after use
* Master key is zeroized after generation
* `key.key` will never be overwritten
* Length must be explicitly provided
* Bytes only — no ambiguous units

---

# Important Warning

If you change:

* SALT
* PEPPER
* Argon2 parameters
* Algorithm version

Then previously generated keys cannot be reproduced.

Treat configuration as part of the key domain definition.

---

# Example Workflow

Generate 32-byte API key:

```bash
./detkey --length 32
```

Generate 1GB deterministic blob:

```bash
./detkey --length 1073741824
```

---

# Why ChaCha20?

ChaCha20 is a stream cipher specifically designed to generate large amounts of secure pseudorandom data from a fixed key and nonce.

Using it as a deterministic expander is cryptographically sound and avoids misuse of KDF primitives.

---

# Why Argon2id?

Argon2id provides:

* Memory-hard password hashing
* GPU resistance
* Side-channel resistance
* Modern cryptographic design

It protects against brute-force attacks on weak passwords.

---

# Threat Model Notes

* If an attacker knows your configuration and obtains `key.key`, they still cannot derive the password without brute forcing Argon2.
* If your password is weak, no KDF can fully protect you.
* If your machine is compromised, this tool cannot protect secrets in memory.

This tool assumes a trusted local execution environment.

---

# Philosophy

This tool intentionally:

* Does one thing
* Does it correctly
* Avoids complexity
* Avoids runtime tuning
* Avoids format creep
* Avoids silent overwrites

Small crypto tools are easier to audit and reason about.

---


