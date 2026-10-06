#![no_main]
//! Fuzz the SMB2 wire entry point: NetBIOS-framed message → parse_hdr →
//! compound dispatch → every command's body/offset/length parsing. The body
//! lives in `rocketsmbd::fuzzing` so `cargo test` keeps it compiling.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rocketsmbd::fuzzing::fuzz_process_frame(data));
