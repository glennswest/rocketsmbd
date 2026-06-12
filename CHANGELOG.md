# Changelog

## [Unreleased]

### 2026-06-11
- **chore:** Bump `toml` 0.8 → 1 to match the version Fedora packages (`rust-toml` 1.1.2) — only `toml::from_str` is used, so the API is unchanged. Removes one of two dependency-version mismatches found while validating an unbundled Fedora build (the remaining one is `io-uring`: Fedora ships 0.6.4, we require 0.7 for `send_zc`).
- **docs:** SMB Direct (RDMA/RoCE) design — `docs/SMBDIRECT.md` (#19): RoCEv2 target, libibverbs+rdma-cm as a second transport wired into io_uring via a CQ event-fd, registered buffers as a hard prerequisite (splice doesn't carry to RDMA), `RDMA_CAPABLE` multichannel advertisement reusing channel binding, NIC-offloaded encryption (MACsec/IPsec-over-RoCE/PSP), and the dynamic-link/feature-flag packaging split.
- **feat:** Cross-worker break **mailbox** (#18) — per-worker `eventfd` + `Mutex<Vec<BreakMsg>>` in the shared `Srv` (`src/lease.rs`), registered in each worker's ring (`OP_WAKE`). Any worker can post a lease/oplock break for a connection owned by another worker and wake it; the owning worker drains the queue in its reactor loop and (in the grant increment) delivers the break via the connection's deferred queue. This is the cross-thread delivery primitive lease breaks require (opens of one file land on different `SO_REUSEPORT` workers); SMB Direct's CQ integration will reuse the same eventfd-in-ring pattern. Unit-tested (post→drain, eventfd counter). No behavior change yet (no breaks are generated until granting is enabled).
- **feat:** Oplock/lease **foundation** (#18) — oplock-level and lease-state constants; CREATE now parses `RequestedOplockLevel` and the `RqLs` lease create context (v1 32-byte / v2 52-byte) into `CreateReq` (unit-tested). Still grants **none** (unchanged, safe): leases are not granted until cross-worker break delivery is built, because a lease without a correct break would let a client serve stale cached data. Design + increment plan in `docs/OPLOCKS.md`.
- **perf:** `send_zc` (MSG_ZEROCOPY) on the buffered send path (#15) — buffered responses ≥ 64 KiB (notably encrypted reads, which can't splice) are sent via `IORING_OP_SEND_ZC`, so the kernel pins the tx pages instead of copying them. Measured (jumbo cross-VM, 4 parallel encrypted streams): **+10% aggregate throughput, −12% server CPU per GiB**. The two-CQE semantics are handled in the reactor: a send completion (`F_MORE`) parks tx in a new `Drain` state and the buffer is only reused/cleared after the buffer-release notification (`F_NOTIF`); both CQEs are counted toward in-flight accounting so teardown waits for the notification (no use-after-free of pinned tx). Probed at startup via `register_probe`; kernels < 5.19 transparently fall back to the copying `Send`.

## [v1.1.0] — 2026-06-11

### Added
- **feat:** **SMB3 encryption (AES-128-GCM)** for SMB 3.1.1 — negotiate the cipher, derive per-channel c2s/s2c keys (SMBC2S/S2CCipherKey), and wrap/unwrap SMB2 TRANSFORM_HEADER frames in `process_frame`. New `encrypt` config (require); client-initiated encryption (cifs `seal`) is honored even when not required. Encrypted reads use the buffered path (an AEAD-sealed frame can't be spliced).
- **test:** Transform roundtrip/tamper unit test; verified end-to-end against Linux cifs.ko (`seal`, md5 integrity) and Windows Server 2025 (`Get-SmbConnection`: Encrypted=True), read+write both directions.

### Notes
- Backward-compatible (SemVer minor): unencrypted sessions are unchanged. Encryption lifts the trusted-LAN limitation — set `encrypt = true` to require it. AES-256-GCM / AES-CCM (SMB 3.0/3.0.2) remain follow-ups.

## [v1.0.0] — 2026-06-11

First stable release. The configuration format and on-wire behavior are now
stable; the 1.x series stays backward-compatible (SemVer).

### Added
- Parser fuzzing (cargo-fuzz) for the SMB2 wire entry point and the NTLMSSP
  parser; both survive millions of executions with zero crashes. Weekly +
  per-push CI fuzz workflow.
- Library crate (lib+bin split) enabling fuzzing, integration tests, and reuse.

### Stable feature set
- SMB 2.0.2 → 3.1.1; NTLMv2 auth + user database; SMB2/3 signing; SMB 3.1.1
  preauth integrity; **SMB3 multichannel**; byte-range locks; CHANGE_NOTIFY;
  zero-copy splice reads (linked io_uring chain); server read-ahead.
- Distro packages (static `.deb`/`.rpm`, x86_64 + aarch64), systemd unit, man
  page; CI (build/test/clippy) + tag-triggered release pipeline.
- Verified interop with Linux cifs.ko and Windows Server 2025 (SMB 3.1.1 +
  signing, read/write).

### Scope & security
- **No SMB3 wire encryption in 1.0** — rocketsmbd is intended for **trusted
  networks**. For untrusted links use a VPN/IPsec until encryption lands in a
  1.x release (#10). Optional `require_signing` enforces signed sessions. See
  SECURITY.md.

## [v0.4.0] — 2026-06-10

### Added
- **feat:** `advertise_only` config — restrict SMB3 multichannel interface advertisement to specific IPs (e.g. a dedicated storage NIC).
- **feat:** Distro packaging — `.deb` + `.rpm` via `cargo-deb`/`cargo-generate-rpm`, systemd unit (`packaging/rocketsmbd.service`), man page (`docs/rocketsmbd.8`), and a tag-triggered GitHub Release workflow that builds x86_64 + aarch64 musl binaries and packages.
- **feat:** GitHub Actions CI (build + test + clippy on x86_64/aarch64 musl).
- **docs:** SECURITY.md, CONTRIBUTING.md, ROADMAP.md, LICENSE (MIT), README badges + quickstart + benchmark table.

### Changed
- **perf:** Full reads (offset+length ≤ file size) submit splice-in → send-header → splice-out as one io_uring IO_LINK chain, cutting two userspace round-trips (and syscalls/CPU) per read. EOF-region reads keep the sequential, partial-safe path. Integrity verified; throughput network-bound on the test fabric (unchanged wire speed) but CPU-per-read drops — matters at 400/800GbE.

### Fixed
- **fix:** Never advertise loopback in FSCTL_QUERY_NETWORK_INTERFACE_INFO (a remote client would try to connect to its own loopback).
- **fix:** Windows `.NET FileStream` interop (#25) — QUERY_INFO **FileStreamInformation** (class 22) now returns the default `::$DATA` stream, and **security-descriptor** queries (info_type 3) return a minimal permissive descriptor instead of NOT_SUPPORTED/ACCESS_DENIED. Verified against a Windows Server 2025 client (SMB 3.1.1 + signing, read+write).

- **feat:** Startup io_uring probe — fail fast with a clear message ("requires kernel ≥ 5.15") instead of cryptic per-worker errors. rocketsmbd is statically linked (no library deps); its only hard dependency is the kernel's io_uring, so the `.deb`/`.rpm` declare no package deps and document the kernel requirement.

### Tested
- **test:** Windows Server 2025 client interop verified (negotiate 3.1.1, NTLMv2, signing, read+write); cross-VM jumbo/multiqueue benchmark; test scripts added under `bench/` and documented in `docs/TESTING.md`.

## [v0.3.0] — 2026-06-10

### Added
- **feat:** SMB3 multichannel — a single client mount stripes one share across multiple connections and worker cores. Cross-connection shared session registry (per-session locks), channel binding (guest + NTLMv2-verified, per-channel 3.1.1 signing keys), `MULTI_CHANNEL` capability, and `FSCTL_QUERY_NETWORK_INTERFACE_INFO` reporting RSS-capable interfaces. `multichannel` config flag.
- **feat:** Server-side read-ahead — `posix_fadvise(POSIX_FADV_SEQUENTIAL)` on file open keeps the kernel prefetching ahead of the splice for cold-storage streaming.

### Changed
- **perf:** Single client mount, 4 channels: **4.7 → 21.1 GB/s (38 → 169 Gbps)** on loopback — 4.5×, past 100GbE. Zero-copy reads on a multichannel mount, 1 GiB checksum verified.
- **perf:** READ holds the session lock only long enough to dup the fd; all read I/O (splice or buffered) runs lock-free, so reads on different channels of one session run in parallel instead of serializing.
- **refactor:** Sessions and open-file handles moved from per-connection state into the shared registry; per-channel signing/preauth stays connection-local (no lock on the sign/verify hot path).

### Fixed
- **fix:** Zero-copy reads dup the file fd so a concurrent CLOSE on another channel can't free it mid-splice; the reactor closes the dup on completion.
- **fix:** Channel binding accepts guest sessions regardless of presented credentials.

### Docs
- **docs:** TUNING.md — read-ahead (client + server), throughput boost roadmap (SQPOLL, registered buffers, send_zc, intra-connection concurrency, SMB Direct), and a Windows Server head-to-head method. BENCHMARKS.md multichannel results.

## [v0.2.0] — 2026-06-09

### Added
- **feat:** NTLMv2 authentication with a user database (`[[user]]` with `password` or `nt_hash`), `allow_guest` policy (defaults to guest-only when no users defined), and NTLMSSP session-key derivation (incl. KEY_EXCH/RC4).
- **feat:** SMB2/3 message signing — HMAC-SHA256 (2.x) and AES-128-CMAC (3.x); requests verified, all responses on authenticated sessions signed; `require_signing` config to reject unsigned requests.
- **feat:** SMB 3.1.1 dialect with preauth integrity (SHA-512 negotiate context + hash chaining) and 3.1.1 signing-key derivation.
- **feat:** SPNEGO wrapping (NegTokenInit2 hint + challenge/accept tokens) for Windows-client compatibility; raw NTLMSSP still accepted.
- **feat:** IPC$ tree-connect stub (ShareType=pipe) — silences the cifs.ko mount-time "failed to connect to IPC" warning.
- **feat:** Byte-range locks (`LOCK`) via Linux OFD locks with all-or-nothing batch semantics; conflicts return STATUS_LOCK_NOT_GRANTED.
- **feat:** Directory change notification (`CHANGE_NOTIFY`) — interim STATUS_PENDING, inotify in the reactor, deferred async responses, CANCEL → STATUS_CANCELLED, handle close → STATUS_NOTIFY_CLEANUP.
- **feat:** Credit accounting (window clamp + charge tracking).
- **feat:** crypto module — SP800-108 KDF, RC4, HMAC-SHA256/AES-CMAC signatures, NT hash; RFC/reference test vectors.

### Fixed
- **fix:** Sign all responses on authenticated sessions, not only when the client set SIGNING_REQUIRED — fixes SMB 3.1.1 signature rejection by smbclient and strict clients.
- **fix:** Defer connection teardown until in-flight io_uring ops complete — prevents a use-after-free (heap corruption crash) of buffers referenced by a parked inotify read when a client disconnects mid-notify.
- **fix:** FSCTL_VALIDATE_NEGOTIATE_INFO echoes the negotiated security mode (incl. SIGNING_REQUIRED) — fixes `require_signing` mounts failing cifs revalidation.
- **fix:** NTLMSSP CHALLENGE advertises the SIGN flag, required by cifs `sec=ntlmsspi`.

### Changed
- **perf:** Signed sessions use the buffered read path (a signature covers the payload, precluding zero-copy splice). Unsigned/guest: read 5.7 GB/s, write 1.0 GB/s. Signed: read 527 MB/s, write 474 MB/s (still ~2× samba unsigned read). See docs/BENCHMARKS.md.

### Verified
- End-to-end on Linux (kernel 6.17) against cifs.ko and smbclient: guest + authenticated mounts; wrong-password rejection; signed (`sec=ntlmsspi`) read/write; SMB 3.1.1; `require_signing` + guest-denied policy; byte-range lock conflict/grant; directory change notification delivery; clean teardown across disconnects.

## [v0.1.1] — 2026-06-09

### Changed
- **perf:** Full-duplex frame batching — drain all complete frames per wakeup, batch responses into one send, rx read-offset instead of per-frame memmove. Sequential write throughput 446 → ~900 MB/s (now 1.3× samba; was 0.7×).
- **perf:** MaxWriteSize/MaxTransactSize raised to 4 MiB; MaxReadSize deliberately kept at 1 MiB — large rsize defeats client readahead parallelism and collapsed reads to 0.67 GB/s (see docs/BENCHMARKS.md tuning findings).

### Added
- **test:** `bench/bench.sh` — repeatable benchmark suite (sequential/parallel/metadata/integrity) for documenting every perf-relevant change.
- **docs:** `docs/ARCHITECTURE.md` (process model, state machines, zero-copy path, layering) and `docs/BENCHMARKS.md` (method, results log, tuning findings).

## [v0.1.0] — 2026-06-09

### Added
- **feat:** io_uring reactor — per-worker rings, SO_REUSEPORT listeners, accept/recv/send state machines, zero-copy READ via splice(file→pipe) + MSG_MORE header + splice(pipe→socket).
- **feat:** SMB2 protocol core — header codec, compound (NextCommand/related) dispatch, NEGOTIATE (2.0.2–3.0.2), SESSION_SETUP (guest NTLMSSP), TREE_CONNECT, CREATE/CLOSE/FLUSH, READ (zero-copy + buffered), WRITE, QUERY_DIRECTORY (6 info classes), QUERY_INFO (file + filesystem), SET_INFO (rename/delete/truncate/times), IOCTL validate-negotiate, ECHO/LOGOFF/TREE_DISCONNECT.
- **feat:** Protocol foundation — wire primitives, NT status mapping, TOML config, minimal NTLMSSP (guest), VFS layer with traversal-safe path resolution and generation-checked handle table.
- **test:** 9 unit/integration tests including a full wire-level session exchange (negotiate→session→tree→create→write→read→query-directory) against a temp share.
- **test:** Verified end-to-end on Linux (kernel 6.17) against cifs.ko: guest mounts with vers=2.1/3.0/3.0.2; 100MB zero-copy read checksum-verified; 50MB write verified; mkdir/rename/delete/df correct.
- **build:** Static musl release builds for x86_64 (primary) and ARM64, Containerfile for scratch image, cross-linker config.
- **chore:** Repo bootstrap — project docs, work plan, scaffold for rocketsmbd, an io_uring-based smbd replacement in Rust.
