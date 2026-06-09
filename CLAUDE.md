# rocketsmbd — Project Context

A from-scratch replacement for smbd in Rust. io_uring end-to-end: accept, recv,
send, file I/O, and zero-copy file→socket via linked splice SQEs. No tokio, no
thread-per-connection — one io_uring reactor per worker thread.

## Version

- Current: **0.2.0** (pre-release, in development)
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
  io_uring ring
  ├─ accept on :445 (oneshot, re-armed; multishot is phase 3)
  ├─ per-connection: recv (per-conn growable buffer) → NBT framing → SMB2 dispatch
  ├─ responses: send (send_zc is phase 3)
  └─ READ data path (zero-copy), one request in flight per connection:
       splice(file → pipe) → send(hdr, MSG_MORE) → splice(pipe → socket)
       (splice-first so the header carries the actual byte count; the pipe is
        sized to the advertised MaxReadSize so the splice never blocks)
```

Phase-1 simplification: one in-flight request per connection (responses are
strictly serialized; client pipelining is absorbed by TCP). True intra-
connection concurrency with credit accounting is phase 3.

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
- [x] NEGOTIATE (dialects 2.0.2–3.0.2; 3.1.1 + preauth integrity is phase 2)
- [x] SESSION_SETUP — NTLMSSP guest/anonymous
- [x] TREE_CONNECT / TREE_DISCONNECT
- [x] CREATE / CLOSE (files + dirs), handle table
- [x] READ — zero-copy splice chain (file→pipe→socket)
- [x] WRITE / FLUSH
- [x] QUERY_DIRECTORY (FileIdBothDirectoryInformation)
- [x] QUERY_INFO (basic/standard/network-open/fs info classes), ECHO, LOGOFF
- [x] SET_INFO (rename, delete-on-close, truncate, basic times)
- [x] IOCTL FSCTL_VALIDATE_NEGOTIATE_INFO
- [x] Wire-level integration test (negotiate→session→tree→create→write→read→dir)
- [x] cargo check + clippy clean on aarch64/x86_64-unknown-linux-musl
- [x] Release build: 772K static ARM64 musl binary; Containerfile (scratch)
- [x] Integration test on Linux (dev.g8.lo, Fedora 43 / kernel 6.17) against cifs.ko:
      mounts with vers=2.1/3.0/3.0.2 (guest), 100MB zero-copy read checksum-verified
      (~500 MB/s), 50MB write verified, mkdir/rename/delete/df all correct

### Phase 1 status: COMPLETE — released as v0.1.0 (2026-06-09)

Build hosts: macOS (cross-check + unit tests), **dev.g8.lo** (root@, Fedora x86_64,
cargo installed) for native Linux builds and cifs.ko integration testing.
Primary deploy target is x86_64; ARM64 retained for MikroTik Rose/mkube.

### Phase 1.5 — write throughput (v0.1.1) — COMPLETE, released 2026-06-09
- [x] Frame batching: drain all complete frames per wakeup, accumulate
      responses in tx, single send; flush tx before a zero-copy READ
- [x] rx read-offset instead of copy_within per frame (compact only pre-recv)
- [x] MaxWrite/MaxTransact 4 MiB; MaxRead kept 1 MiB (readahead parallelism)
- [x] Re-benchmark vs samba: reads 5.8–6.2 GB/s (4.3×), writes ~900 MB/s (1.3×)
- [x] bench/bench.sh + docs/BENCHMARKS.md + docs/ARCHITECTURE.md

**Documentation policy: document as we go.** Every perf-relevant change gets
re-measured with bench/bench.sh and logged in docs/BENCHMARKS.md before
release; architecture changes update docs/ARCHITECTURE.md in the same commit.

### Phase 2 — auth & robustness (v0.2.0) — COMPLETE, released 2026-06-09
- [x] 1. Crypto module (SP800-108 KDF, RC4, HMAC-SHA256/AES-CMAC, NT hash) + vectors
- [x] 2. NTLMv2 verification + [[user]] db (password/nt_hash), allow_guest, KEY_EXCH
- [x] 3. SMB2/3 signing: verify requests, sign all auth'd responses; require_signing
- [x] 4. SMB 3.1.1: SHA-512 preauth integrity context + hash chaining + key derivation
- [x] 5. SPNEGO wrapping + NegTokenInit2 hint (Windows compat)
- [x] 6. IPC$ tree-connect stub (silences cifs IPC warning)
- [x] 7. Credit accounting (window clamp, charge tracking)
- [x] 8. LOCK: byte-range locks via OFD locks, all-or-nothing batch
- [x] 9. CHANGE_NOTIFY: async pend + inotify reactor + cancel/cleanup
- [x] 10. Oplocks/leases: grant-none posture (correct for phase 2)
- [x] 11. Integration verified on dev.g8.lo (cifs + smbclient); bench re-run; docs

Two bugs found and fixed during integration (see CHANGELOG): a use-after-free
crash on disconnect-during-notify (in-flight io_uring ops referenced freed
buffers — now teardown waits for completions), and a 3.1.1 signature
rejection (we only signed when the client set REQUIRED; auth'd sessions must
always sign).

### Phase 3 — performance & SMB3 (v0.3.0)
- [ ] SMB3 encryption (AES-128-GCM)
- [ ] Zero-copy path for signed/encrypted reads (currently buffered)
- [ ] Oplocks/leases with real caching
- [ ] True intra-connection request concurrency (multiple zc reads in flight)
- [ ] Registered buffers + send_zc, multishot accept/recv, SQPOLL mode, core pinning
- [ ] Benchmarks vs samba smbd (fio over cifs mount)

## Testing

- `cargo check --target aarch64-unknown-linux-musl` and `--target x86_64-unknown-linux-musl` must pass.
- `cargo clippy --target aarch64-unknown-linux-musl -- -D warnings`
- Unit tests for wire parse/build run on macOS (`cargo test` — protocol code is OS-independent; only uring/reactor is Linux-gated).
- Integration: mount from Linux: `mount -t cifs //host/share /mnt -o guest,vers=3.0`
