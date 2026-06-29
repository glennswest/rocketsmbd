//! rocketsmbd library surface — exposes the protocol/crypto/vfs modules so
//! they can be fuzzed, integration-tested, and reused. The binary
//! (`src/main.rs`) is a thin wrapper; the io_uring reactor is Linux-only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod config;
pub mod crypto;
pub mod lease;
#[macro_use]
pub mod log;
#[cfg(feature = "kerberos")]
pub mod krb5;
pub mod net;
#[cfg(feature = "ntlm")]
pub mod ntlm;
pub mod session;
pub mod smb2;
pub mod spnego;
pub mod status;
pub mod vfs;
pub mod wire;

/// NTLMSSP message signature. Kept always-available (independent of the `ntlm`
/// feature) so SPNEGO classification can recognize — and an NTLM-free build can
/// cleanly reject — NTLMSSP tokens.
pub fn ntlm_sig() -> &'static [u8; 8] {
    b"NTLMSSP\0"
}

#[cfg(target_os = "linux")]
pub mod uring;
