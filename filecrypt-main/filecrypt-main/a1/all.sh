#!/bin/bash

# Copy Cargo.toml to all.txt (overwrites if exists)
cat Cargo.toml > all.txt

# Append the source files
cat src/bin/aes.rs >> all.txt
cat src/bin/cha.rs >> all.txt
cat src/bin/tf.rs >> all.txt
cat src/bin/serp.rs >> all.txt
cat src/bin/cam.rs >> all.txt
cat src/bin/kuz.rs >> all.txt
cat src/bin/otp.rs >> all.txt
cat src/bin/otpkg.rs >> all.txt