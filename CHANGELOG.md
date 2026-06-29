# Changelog

## [Unreleased]

### 2026-06-29
- **docs(#31):** Turnkey Kerberos (GSS-API/SPNEGO) design + build/test plan — `docs/KERBEROS.md`: library choice (`libgssapi` over MIT/Heimdal, no pure-Rust krb5), SPN/keytab, the off-by-default `kerberos` feature + dynamic-link build profile, GSS session-key→SMB KDF, AD/KDC test matrix.
- **feat(#33,#34):** **Kerberos GSS acceptor** — new `src/krb5.rs` behind the off-by-default `kerberos` feature (links system GSS via `gssapi-sys`; Linux-only dynamic build). `Acceptor` acquires the service credential for `cifs/<host>` from the keytab; `AcceptCtx::step()` drives `gss_accept_sec_context` (multi-leg aware) and, on completion, extracts the SMB session key (the Kerberos sub-session key) via `gss_inquire_sec_context_by_oid(GSS_C_INQ_SSPI_SESSION_KEY)` to feed the existing SP800-108 KDF. Default build is unaffected (feature off — `gssapi-sys` absent from the dep tree); the `--features kerberos` build is compiled/validated on the Linux/AD host (see docs/KERBEROS.md).
- **feat(#31):** **SESSION_SETUP dispatcher + Kerberos handler wired.** `session_setup` is now a non-gated dispatcher that classifies the SPNEGO/raw blob (`spnego::classify`) and routes by mechanism × `auth` policy × built features; the NTLM body is unchanged (renamed `ntlm_session_setup`), so existing NTLM tests verify routing. `kerberos_session_setup` (gated) runs a per-connection GSS acceptor, derives the SMB session key from the Kerberos sub-session key, and sets up signing/encryption. **Verified on a Linux host (dev.g8.lo, Fedora 43):** `cargo build/clippy/test --features kerberos` and `--no-default-features --features kerberos` (Kerberos-only) are clean; the binary links `libgssapi_krb5`. `gssapi-sys` binds only base `gssapi.h`, so the `gss_inquire_sec_context_by_oid` session-key path is declared from `gssapi_ext.h` directly. Live `sec=krb5` interop is the remaining step (#37).
- **feat(#36):** **Auth selector config** — `auth = "kerberos" | "ntlm" | "both"` (default `both`, intersected with built features) plus a `[kerberos]` table (`enabled`, `keytab`, `spn`, `realm`). `AuthMode::allows_ntlm/allows_kerberos` gate which mechanisms are advertised/accepted.
- **feat(#32):** **SPNEGO Kerberos mechtype negotiation.** New always-compiled `src/spnego.rs`: minimal DER reader/writer, the Kerberos (`1.2.840.113554.1.2.2`) + MS-Kerberos + NTLMSSP mech OIDs, a `NegTokenInit2` hint builder that advertises Kerberos-first, inbound classification (SPNEGO `NegTokenInit`/`NegTokenResp`, raw GSS AP-REQ, raw NTLMSSP) returning the mechanism + the GSS token to feed the acceptor, and `NegTokenResp` builders. Pure ASN.1, no external deps — 7 unit tests (advertise order, SPNEGO-wrapped + raw Kerberos, NTLMSSP, response roundtrip, malformed-no-panic). Verified: clippy `-D warnings` clean and `cargo test` green on both feature configs (39 default / 29 `--no-default-features`).
- **feat(#30):** **Optional NTLM / MD4 / RC4 at build time.** New default-on `ntlm` Cargo feature gates the entire NTLM auth path and the only three legacy primitives a FIPS/OpenSSL crypto backend can't provide — MD4 (NT hash), HMAC-MD5 (NTLMv2), and RC4 (NTLMSSP key exchange). `cargo build --no-default-features` drops `md4`/`md-5` from the dependency tree entirely and makes SESSION_SETUP reject every NTLMSSP token with `STATUS_NOT_SUPPORTED` (fail loudly) — the interim state until Kerberos (#31) lands. Prerequisite for a clean OpenSSL/FIPS build (#29). Both feature configs verified: clippy `-D warnings` clean on aarch64+x86_64 musl, `cargo test` 32 passing (ntlm) / 22 passing (no-default-features).
- **docs:** ROADMAP — add a 0.7 Active Directory / Kerberos milestone (GSS/SPNEGO via external lib; #31 + sub-tasks #32–#37).
- **docs:** ROADMAP — add pluggable OpenSSL crypto backend for FIPS (#29) and optional MD4/RC4 build (#30) under 0.6 security.
- **docs:** `docs/TESTING.md` now documents the concurrent-mount stress + 1000-round soak harness (`bench/stress/`) and records the clean soak result (no leak; slope +0.005 kB/round). Committed the soak stats artifact `bench/stress/results/soak-1000-2026-06-16.csv` so `analyze-soak.sh` can be re-run against it.

### 2026-06-16
- **test:** Concurrent-mount stress harness (`bench/stress/`): N privileged podman containers each cifs-mount the server and do md5-verified write/read I/O plus shared-file reads (lease churn). Added a GO-flag **start barrier** so all N clients hold their mounts simultaneously — an N=100 run otherwise only held ~3 concurrent connections because serial container launch outpaced each client's quick I/O. Verified 100/100 pass, server stable, RSS returns to baseline (no per-connection/lease leak), 0 errors.
- **test:** Added a **1000-round soak runner** (`soak.sh`) with per-round CSV stats (`round,epoch,pass,fail,rss_kb,peak_conns,duration_s`) and an analyzer (`analyze-soak.sh`) that reports a leak verdict via least-squares RSS slope + first/last-quartile means. **Full 1000-round soak completed clean** (17.6 h, mean 63.5s/round): 99,999 concurrent md5-verified I/O ops passed, 0 data faults; the single "fail" was a podman launch flake (round 168), not a server fault. Server alive the entire run (one pid, r1→r1000). RSS: 1700→1732 kB, +32 kB total drift in the first ~180 rounds then flat (slope +0.005 kB/round, max 1736 kB @r183) — **no leak** in connection-slot/lease-table/cross-worker-break paths across ~100k mount/teardown cycles.
- **test:** Harden the stress harness to **separate launch failures from I/O-verify failures** — under ~100k container creates in a soak, podman occasionally flakes a `run`; the harness now checks the create exit, retries once, skips `podman wait` for never-created containers, and reports launch-failed separately so a host/podman flake is never misread as a server or data-integrity fault.

## [v1.4.0] — 2026-06-15

### 2026-06-15
- **feat(#27):** **Handle-caching (RH) leases.** When a client requests handle-caching, the server now grants `R|H` (read + handle) instead of read-only, and the lease **persists past CLOSE** — the client keeps its cache/handle to avoid re-opens, and the lease is broken on a later conflicting write or released on connection teardown. Validated end-to-end on cifs.ko *and* Windows: `R|H` granted, the detached lease survives CLOSE, a conflicting write breaks it, and the client re-reads fresh (no stale data). Write-caching (RWH) is still not granted (dirty data needs break-with-ack).


## [v1.3.0] — 2026-06-15

### 2026-06-15
- **feat(#27):** Read-caching leases **enabled by default** (`oplocks=true`). Validated end-to-end against cifs.ko and Windows: clients request a lease, the server grants read-caching, a conflicting write breaks the lease, and the holder re-reads fresh — no stale reads, breaks honored. AES-256-GCM also confirmed against Windows (`Encrypted=True`, cipher 0x4). Write/handle caching remain follow-ups. Set `oplocks=false` to disable.

## [v1.2.0] — 2026-06-14

### 2026-06-14
- **feat(#28):** **AES-256-GCM and AES-CCM (128/256)** for SMB 3.1.1 encryption, alongside AES-128-GCM. Generic SP800-108 KDF derives 16/32-byte keys; the transform codec dispatches per cipher with the right nonce length (GCM 12B, CCM 11B). NEGOTIATE picks the first cipher in the client's preference order that we support; new `prefer_aes256` config selects AES-256 when offered. Validated: cifs `seal` negotiates AES-128-GCM and (with `prefer_aes256`) AES-256-GCM — encrypted reads md5-verified both ways; all four ciphers unit-tested (AEAD + transform roundtrip/tamper). CCM via the `ccm` crate.

### 2026-06-13
- **feat(#18):** Oplock infrastructure — Level II (read-caching) oplock grant, cross-worker break delivery (per-worker eventfd mailbox), `OPLOCK_BREAK` notification builder, and lease-table release on CLOSE *and* connection teardown. Unit + integration tested (grant, cross-worker break delivery, no-crash, no-leak).
- **feat(#18):** **Working read-caching leases** (opt-in `oplocks = true`). Server advertises `CAP_LEASING`; CREATE grants a read-caching lease (echoes the `RqLs` response context, OplockLevel 0xFF), and a conflicting WRITE sends a proper **lease-break** (keyed by LeaseKey) to other clients *after* the write is durable, so their cache invalidates and re-reads the final data. Release on CLOSE and connection teardown. Deterministically validated with cifs.ko: guest + signed sessions, single + multi-holder breaks, 256 MiB read md5, no stale reads, no crash. Read-caching only (the safe subset — no dirty client data); write/handle caching and Windows lease interop are follow-ups, so it stays **default-off** pending Windows validation.
- **fix(#18):** ~~Gate oplock granting behind `oplocks` config (default off).~~ Integration testing revealed that cifs requests *leases* and does **not** invalidate its cache on a legacy oplock-break notification (it expects a lease-break), so granting Level II caused **stale reads** (a held mount served old data after a write). Default-off restores correct grant-none behavior (no caching, always fresh); the grant/break machinery stays live behind the flag until lease-based break lands.
- **feat:** Worker **core pinning** (#17) — `core_pinning` config (default on) pins worker N to core N mod ncpu (`sched_setaffinity`), keeping each ring, its NIC softirqs, and cache on one core under `SO_REUSEPORT`. Validated (read md5 on/off).
- **feat:** Opt-in io_uring **SQPOLL** (#13) — `sqpoll = true` builds the ring with `setup_sqpoll` (1s idle) so submissions need no syscall; falls back to a normal ring if the kernel rejects it. Opt-in (spins a kernel thread per worker; a win only at high IOPS / many channels).

### 2026-06-12
- **fix:** **Guest + SMB3 encryption no longer hangs the mount (#26).** Guest/anonymous sessions carry no session key, so SMB3 cipher keys can't be derived — encryption is invalid for them (matching Windows). Two parts: (1) session-setup now denies a guest/anonymous logon with `STATUS_ACCESS_DENIED` when `encrypt = true` is required, instead of granting a session the client then can't seal; (2) the reactor disconnects on an undecryptable `TRANSFORM` frame (`FrameAction::Close`) rather than silently dropping it — the silent drop left the client waiting forever. Net: `mount -o guest,seal` now fails fast/cleanly instead of hanging; use an authenticated user for encrypted mounts.
- **chore:** Published `rocketsmbd` 1.1.0 to [crates.io](https://crates.io/crates/rocketsmbd) — canonical source for the future unbundled Fedora spec and `cargo install rocketsmbd`. README gains a crates.io badge + install path.
- **packaging:** Fedora package made review-clean — aggregate license `MIT AND BSD-3-Clause AND Unicode-3.0`, 47 `bundled(crate())` Provides, debuginfo subpackage, `rocketsmbd.rpmlintrc`; rpmlint 0/0/0. Submission runbook in `docs/fedora-submission.md` (review bug + sponsor message drafted).

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
