
# Cryptographic Construction — Solid



XChaCha20-Poly1305 via DryocStream

Per-file random header

Per-file random salt (password mode)

Argon2id via Config::sensitive()

Explicit FINAL tag enforcement

Trailing data rejection

Frame size bounds check

MAC verification on every frame

There is no cryptographic design flaw here.

No nonce reuse.
No truncation attack.
No length confusion attack.
No framing ambiguity.

This is correct.




# ✅ Password Handling — Properly Hardened



Zeroize pw1, pw2, and pw

Zeroize derived pw_bytes

Zeroize key file bytes after read

Use stack-based StackByteArray for keys

That’s a professional-level memory hygiene setup for a CLI tool.

Only unavoidable exposure:

String password exists in heap briefly

Derived key exists until function exit

That’s normal and acceptable.








