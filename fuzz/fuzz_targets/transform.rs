#![no_main]
//! Fuzz the SMB3 TRANSFORM_HEADER: raw decrypt for every cipher, a seal/open
//! round trip, and decrypt-then-dispatch of the sealed input via process_frame.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rocketsmbd::fuzzing::fuzz_transform(data));
