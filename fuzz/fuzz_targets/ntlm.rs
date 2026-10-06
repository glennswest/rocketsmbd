#![no_main]
//! Fuzz the NTLMSSP parser — token location and the AUTHENTICATE field
//! (offset/length) decoding, which run on attacker-controlled bytes during
//! SESSION_SETUP.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| rocketsmbd::fuzzing::fuzz_ntlm(data));
