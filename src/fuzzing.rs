//! Fuzz entry points and the shared test-server constructor.
//!
//! The libFuzzer targets in `fuzz/fuzz_targets/` are one-line wrappers around
//! the `fuzz_*` functions here, so the fuzzed code is compiled (and smoke-run
//! over a small corpus) by every `cargo test` — the targets can no longer drift
//! out of step with the library unnoticed (#50, #51). `test_srv` is the one
//! place that builds a `Srv` for tests and fuzzing: the config comes from TOML,
//! so a new config key with a default never breaks it.
#![doc(hidden)]

use crate::config::{Config, Srv};
use crate::smb2::{self, ChannelState, EncCtx, ProtoConn};
use std::path::Path;

/// A single-worker server with one share `t` at `dir` (writable, guest
/// allowed since no users are defined), no multichannel, no leases.
pub fn test_srv(dir: &Path) -> Srv {
    srv_from_toml(&format!(
        "server_name = \"TESTSRV\"\nworkers = 1\ncore_pinning = false\noplocks = false\n\
         [[share]]\nname = \"t\"\npath = '{}'\n",
        dir.display()
    ))
}

/// Build a `Srv` from config TOML (no interfaces, no mailboxes).
pub fn srv_from_toml(raw: &str) -> Srv {
    let cfg: Config = toml::from_str(raw).expect("test config parses");
    let users = cfg.user_db();
    let allow_guest = cfg.guest_allowed();
    Srv {
        cfg,
        guid: [9; 16],
        max_read: 1 << 20,
        start_ft: 0,
        users,
        allow_guest,
        interfaces: vec![],
        sessions: crate::session::Registry::default(),
        mailboxes: vec![],
        leases: crate::lease::LeaseTable::default(),
    }
}

/// The fuzz server: a read-only share in the temp dir (filesystem side effects
/// stay minimal), one NTLM user, guest allowed, multichannel on.
fn fuzz_srv() -> Srv {
    let dir = std::env::temp_dir().join("rsmbd-fuzz-share");
    let _ = std::fs::create_dir_all(&dir);
    srv_from_toml(&format!(
        "server_name = \"FUZZ\"\nworkers = 1\nallow_guest = true\nmultichannel = true\n\
         core_pinning = false\n\
         [[share]]\nname = \"f\"\npath = '{}'\nread_only = true\n\
         [[user]]\nname = \"u\"\npassword = \"p\"\n",
        dir.display()
    ))
}

thread_local! {
    static FUZZ_SRV: Srv = fuzz_srv();
}

/// SMB2 wire entry: one NetBIOS-stripped frame → parse_hdr → compound
/// dispatch → every command's body parsing. Fresh connection state per input.
pub fn fuzz_process_frame(data: &[u8]) {
    FUZZ_SRV.with(|srv| {
        let mut pc = ProtoConn::new(srv, 0, 0, 0);
        let mut tx = Vec::new();
        let _ = smb2::process_frame(srv, &mut pc, data, &mut tx);
    });
}

/// NTLMSSP token location + AUTHENTICATE field (offset/length) decoding.
#[cfg(feature = "ntlm")]
pub fn fuzz_ntlm(data: &[u8]) {
    let _ = crate::ntlm::find_token(data);
    let _ = crate::ntlm::classify(data);
    if let Some(a) = crate::ntlm::parse_authenticate(data) {
        let _ = a.is_anonymous();
    }
}

/// SPNEGO / DER: SESSION_SETUP security-blob classification (NegTokenInit,
/// NegTokenResp, raw GSS, raw NTLMSSP), run on attacker bytes before any auth.
pub fn fuzz_spnego(data: &[u8]) {
    let inc = crate::spnego::classify(data);
    // The token must be a sub-slice of the input.
    assert!(inc.token.len() <= data.len());
}

const SID: u64 = 0x1000_0000_0000_0001;
const CIPHERS: [u16; 4] = [
    crate::crypto::CIPHER_AES128_CCM,
    crate::crypto::CIPHER_AES128_GCM,
    crate::crypto::CIPHER_AES256_CCM,
    crate::crypto::CIPHER_AES256_GCM,
];

/// SMB3 TRANSFORM_HEADER: (1) raw bytes into `decrypt_transform` for every
/// cipher (header bounds, OriginalMessageSize, tag check); (2) a seal→open
/// round trip; (3) the decrypt-then-act path — the input sealed under a known
/// session key and fed to `process_frame`, so the inner plaintext reaches the
/// dispatcher exactly as an authenticated encrypted client's would.
pub fn fuzz_transform(data: &[u8]) {
    let cipher = CIPHERS[data.first().map(|b| *b as usize % 4).unwrap_or(1)];
    let enc = EncCtx { cipher, c2s: [7; 32], s2c: [7; 32], nonce_ctr: 0 };
    for c in CIPHERS {
        let e = EncCtx { cipher: c, ..enc.clone() };
        let _ = smb2::decrypt_transform(data, &e);
    }
    let mut e = enc.clone();
    let mut sealed = Vec::new();
    smb2::wrap_transform(data, &mut e, SID, &mut sealed);
    let frame = &sealed[4..];
    assert_eq!(smb2::decrypt_transform(frame, &enc).as_deref(), Some(data), "seal/open round trip");

    FUZZ_SRV.with(|srv| {
        let mut pc = ProtoConn::new(srv, 0, 0, 0);
        pc.channels.insert(SID, ChannelState { enc: Some(enc.clone()), ..Default::default() });
        let mut tx = Vec::new();
        let _ = smb2::process_frame(srv, &mut pc, frame, &mut tx);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small deterministic corpus: empty, short, every header-ish prefix,
    /// and pseudo-random buffers. Not a substitute for libFuzzer — it keeps the
    /// targets compiling and catches the shallowest panics on every build.
    fn corpus() -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0xFF; 3]];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let prefixes: [&[u8]; 6] = [
            &[0xFE, b'S', b'M', b'B', 64, 0],
            &[0xFD, b'S', b'M', b'B'],
            &[0xFF, b'S', b'M', b'B'],
            &[0x60, 0x80],
            &[0xA1, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            b"NTLMSSP\0\x03\0\0\0",
        ];
        for p in prefixes {
            for len in [0usize, 8, 64, 200, 1000] {
                let mut b = p.to_vec();
                b.extend((0..len).map(|_| rnd() as u8));
                v.push(b);
            }
        }
        v
    }

    #[test]
    fn fuzz_targets_smoke() {
        for input in corpus() {
            fuzz_process_frame(&input);
            fuzz_spnego(&input);
            fuzz_transform(&input);
            #[cfg(feature = "ntlm")]
            fuzz_ntlm(&input);
        }
    }
}
