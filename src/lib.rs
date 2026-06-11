//! rocketsmbd library surface — exposes the protocol/crypto/vfs modules so
//! they can be fuzzed, integration-tested, and reused. The binary
//! (`src/main.rs`) is a thin wrapper; the io_uring reactor is Linux-only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod config;
pub mod crypto;
#[macro_use]
pub mod log;
pub mod net;
pub mod ntlm;
pub mod session;
pub mod smb2;
pub mod status;
pub mod vfs;
pub mod wire;

#[cfg(target_os = "linux")]
pub mod uring;
