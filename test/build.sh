#!/usr/bin/env bash
# Build the two static binaries the test image copies in (stormcos test
# standard): rocketsmbd itself (default features, as released) and /test
# (test/src, the suites and their SMB2/3 client).
set -euo pipefail
cd "$(dirname "$0")/.."
target=x86_64-unknown-linux-musl
cargo build --release --locked --target "$target"
# The test crate is its own workspace; start from the server's lockfile so
# both use the same dependency versions.
[ -f test/Cargo.lock ] || cp Cargo.lock test/Cargo.lock
cargo build --release --target "$target" --manifest-path test/Cargo.toml
mkdir -p test/out
cp "${CARGO_TARGET_DIR:-target}/$target/release/rocketsmbd" test/out/rocketsmbd
cp "${CARGO_TARGET_DIR:-test/target}/$target/release/rocketsmbd-test" test/out/test
