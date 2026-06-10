# Changelog

## [Unreleased]

### 2026-06-10
- **feat:** `advertise_only` config — restrict SMB3 multichannel interface advertisement to specific IPs (e.g. a dedicated storage NIC).
- **perf:** Full reads (offset+length ≤ file size) submit splice-in → send-header → splice-out as one io_uring IO_LINK chain, cutting two userspace round-trips (and syscalls/CPU) per read. EOF-region reads keep the sequential, partial-safe path. Integrity verified over the linked path; throughput is network-bound on the test fabric so wire speed is unchanged, but CPU-per-read drops (matters at 400/800GbE).
- **fix:** Never advertise loopback in FSCTL_QUERY_NETWORK_INTERFACE_INFO (a remote client would try to connect to its own loopback).

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
