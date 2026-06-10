# Changelog

## [Unreleased]
<!-- New unreleased changes go here -->

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
