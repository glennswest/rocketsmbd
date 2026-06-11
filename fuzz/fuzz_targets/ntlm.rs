#![no_main]
//! Fuzz the NTLMSSP parser — token location and the AUTHENTICATE field
//! (offset/length) decoding, which run on attacker-controlled bytes during
//! SESSION_SETUP.
use libfuzzer_sys::fuzz_target;
use rocketsmbd::ntlm;

fuzz_target!(|data: &[u8]| {
    let _ = ntlm::find_token(data);
    let _ = ntlm::classify(data);
    if let Some(a) = ntlm::parse_authenticate(data) {
        let _ = a.is_anonymous();
    }
});
