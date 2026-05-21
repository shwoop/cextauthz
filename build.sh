#!/bin/sh
set -e
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
ls -lh target/wasm32-unknown-unknown/release/cextauthz.wasm
