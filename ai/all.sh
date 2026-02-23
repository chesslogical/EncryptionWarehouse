#!/bin/bash

# Copy Cargo.toml to all.txt (overwrites if exists)
cat Cargo.toml > all.txt

# Append the source files
cat src/main.rs >> all.txt
cat src/aes.rs >> all.txt
cat src/cha.rs >> all.txt
