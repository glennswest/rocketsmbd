# rocketsmbd — Project Context

A from-scratch replacement for smbd in Rust. io_uring end-to-end: accept, recv,
send, file I/O, and zero-copy file→socket via linked splice SQEs. No tokio, no
thread-per-connection — one io_uring reactor per worker thread.

## Version

- Current: **0.1.0** (pre-release, in development)
- Version locations: `Cargo.toml` (`[package] version`), `src/main.rs` (`VERSION` const via `env!("CARGO_PKG_VERSION")` — single source is Cargo.toml)

## Platform & Build

- **Target OS**: Linux only (io_uring). Kernel ≥ 5.15 required; ≥ 6.0 recommended (multishot accept/recv).
- **Dev host**: macOS — cannot run the server locally. Use `cargo check --target aarch64-unknown-linux-musl` (and clippy) for validation; run/integration-test on a Linux host.
- **Release build**: static musl binary → `scratch` container via `podman` (see MikroTik Rose deploy rules in user CLAUDE.md).
- Build check: `cargo check --target aarch64-unknown-linux-musl`

## Architecture

```
main ─ config (TOML) ─ spawn N workers (SO_REUSEPORT)
each worker:
  io_uring ring (SQPOLL optional)
  ├─ multishot accept on :445
  ├─ per-connection: recv (provided buffer ring) → NBT framing → SMB2 dispatch
  ├─ responses: send / send_zc
  └─ READ data path (zero-copy): linked SQE chain
       send(hdr, MSG_MORE) → splice(file → pipe) → splice(pipe → socket)
```

- `src/main.rs` — startup, worker spawn
- `src/config.rs` — TOML config: listen, workers, shares
- `src/uring.rs` — reactor: ring lifecycle, user_data encoding (op | conn id), buffer pool
- `src/conn.rs` — connection state machine, NBT (4-byte length) framing, rx reassembly
- `src/smb2/` — wire protocol: `header.rs`, `negotiate.rs`, `session.rs`, `tree.rs`, `create.rs`, `io.rs` (read/write/flush/close), `dir.rs` (query_directory), `info.rs` (query/set info), `misc.rs` (echo/logoff/disconnect)
- `src/ntlm.rs` — minimal NTLMSSP (guest/anonymous only in phase 1)
- `src/vfs.rs` — share roots, open-handle table (FileId → fd), path sanitation

## Security posture (phase 1)

Guest/anonymous auth only, no signing/encryption enforcement, intended for
trusted LAN use. NTLMv2 + signing is phase 2; do not expose to untrusted networks.

## Work Plan

### Phase 1 — mountable read/write server (v0.1.0)
- [x] Repo bootstrap: docs, scaffold, CI-less build check
- [x] Config + main + worker spawn
- [x] io_uring reactor: multishot accept, recv, send, close; user_data scheme
- [x] NBT framing + connection state machine
- [x] SMB2 header parse/build + error responses
- [x] NEGOTIATE (dialects 2.0.2–3.1.1, negotiate contexts for 3.1.1)
- [x] SESSION_SETUP — NTLMSSP guest/anonymous
- [x] TREE_CONNECT / TREE_DISCONNECT
- [x] CREATE / CLOSE (files + dirs), handle table
- [x] READ — zero-copy splice chain (file→pipe→socket)
- [x] WRITE / FLUSH
- [x] QUERY_DIRECTORY (FileIdBothDirectoryInformation)
- [x] QUERY_INFO (basic/standard/network-open/fs info classes), ECHO, LOGOFF
- [x] cargo check + clippy clean on aarch64/x86_64-unknown-linux-musl
- [ ] Integration test on a Linux box against Linux cifs.ko mount  ← NEXT (needs Linux host)

### Phase 2 — auth & robustness (v0.2.0)
- [ ] NTLMv2 real authentication, user database
- [ ] SMB2 signing (HMAC-SHA256 / AES-CMAC)
- [ ] SET_INFO (rename, delete-on-close, allocation), byte-range locks
- [ ] Oplocks/leases (at least none→break handling correctness)
- [ ] Credit accounting, large MTU, multi-credit reads/writes

### Phase 3 — performance & SMB3 (v0.3.0)
- [ ] SMB3 encryption (AES-128-GCM)
- [ ] Registered buffers + send_zc everywhere applicable
- [ ] SQPOLL mode, NUMA/core pinning
- [ ] Benchmarks vs samba smbd (fio over cifs mount)

## Testing

- `cargo check --target aarch64-unknown-linux-musl` and `--target x86_64-unknown-linux-musl` must pass.
- `cargo clippy --target aarch64-unknown-linux-musl -- -D warnings`
- Unit tests for wire parse/build run on macOS (`cargo test` — protocol code is OS-independent; only uring/reactor is Linux-gated).
- Integration: mount from Linux: `mount -t cifs //host/share /mnt -o guest,vers=3.0`
