#![no_main]
//! Fuzz SPNEGO/DER security-blob classification (`spnego::classify`), which
//! runs on attacker bytes in every SESSION_SETUP before authentication.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rocketsmbd::fuzzing::fuzz_spnego(data));
