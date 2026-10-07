# rocketsmbd — Project Context

A from-scratch replacement for smbd in Rust. io_uring end-to-end: accept, recv,
send, file I/O, and zero-copy file→socket via linked splice SQEs. No tokio, no
thread-per-connection — one io_uring reactor per worker thread.

## Version

- Current: **1.4.1** (tag on the `release/1.4` maintenance branch, off v1.4.0: the #41 fix only); `main`'s Cargo.toml stays 1.4.0, and its next release is 1.5.0.
  Stable; config/wire-behavior backward-compatible across 1.x.
  `main` carries unreleased work since then: Kerberos (#31–#37), the `auth` key,
  the OpenSSL backend (#29) and optional NTLM (#30). See CHANGELOG `[Unreleased]`.
- Version locations: `Cargo.toml` (`[package] version`), `src/main.rs` (`VERSION` const via `env!("CARGO_PKG_VERSION")` — single source is Cargo.toml)

## Platform & Build

- **Target OS**: Linux only (io_uring). Kernel ≥ 5.15 required; ≥ 6.0 recommended
  (multishot accept + send_zc are probed and used when available; recv is oneshot).
- **Where work happens**: this checkout on stormcentral.g8.lo. **Never build here**
  and never `ssh root@` anywhere. Commit, `git push`, then `sc-build` (runs
  `cargo build && cargo test` on the build box); `sc-build 'cargo clippy --target
  x86_64-unknown-linux-musl -- -D warnings'` etc. for other commands. Scratch
  files go in `tmp/` (gitignored).
- **Cargo features**: `ntlm` (default), `backend-rustcrypto` (default),
  `backend-openssl` (dynamic, FIPS), `kerberos` (dynamic, system GSS). `sc-build deploy/feature-matrix.sh` checks every feature set (#43); releases build the defaults.
- **How it ships**: not GitHub Actions (owner, 2026-10-06): `sc-build 'deploy/release-artifacts.sh vX.Y.Z'`
  (docs/RELEASING.md) builds from the tag static musl
  x86_64 + aarch64 binaries, `.deb` and `.rpm` (config at `/etc/rocketsmbd.toml`,
  systemd unit `packaging/rocketsmbd.service`, man page `docs/rocketsmbd.8`);
  `Containerfile` = `scratch` + static binary, config at
  `/etc/rocketsmbd/rocketsmbd.toml`. Also crates.io, COPR, and the distro
  packaging in `packaging/` (Fedora spec, `debian/`); see docs/UPSTREAM.md.
- **Ports**: SMB on TCP 445 only (`listen`, default `0.0.0.0:445`). No NetBIOS, no
  management/REST API. An opt-in HTTP health endpoint (`health_listen`, off by
  default; `GET /healthz`, src/health.rs) exists for stormd; the stormcos golden uses `127.0.0.1:9104`.
- **Not a stormcos component yet** (#46): `stormcentral component list` has no
  `rocketsmbd`, so there's no golden to request yet. rocketsmbd-operator (`smbop`)
  expects a `rocketsmbd` service golden with the binary at `/usr/sbin/rocketsmbd`,
  config at `/etc/rocketsmbd/rocketsmbd.toml`, and the `ntlm` feature.

## Architecture

```
main ─ config (TOML) ─ spawn N workers (SO_REUSEPORT), pinned to cores
each worker:
  io_uring ring (SQPOLL optional)
  ├─ accept on :445 (multishot on ≥6.0, else oneshot re-armed)
  ├─ per-connection: recv (oneshot, per-conn growable buffer) → NBT framing → SMB2 dispatch
  ├─ responses: send, or send_zc for batches ≥ 64 KiB
  ├─ lease-break mailbox: eventfd polled in the ring (cross-worker breaks)
  └─ READ data path (zero-copy, unsigned standalone reads ≥ 8 KiB):
       splice(file → pipe) → send(hdr, MSG_MORE) → splice(pipe → socket)
       (splice-first so the header carries the actual byte count; the pipe is
        sized to the advertised MaxReadSize so the splice never blocks)
       signed/encrypted/compound/small reads are buffered
```

One tx stream per connection (responses serialized; frame batching absorbs
client pipelining). Intra-connection concurrency was shelved (#12); scale-out is
multichannel. Full detail: docs/ARCHITECTURE.md.

- `src/main.rs` — CLI (`--config`, `--check`, `--version`), startup, worker spawn
- `src/config.rs` — TOML config (all keys + defaults; `deny_unknown_fields`)
- `src/uring.rs` — reactor: ring lifecycle, user_data encoding, accept/recv/send/send_zc, zero-copy read chain
- `src/smb2/mod.rs` — `process_frame`, header codec, compound handling, encryption/signing wrap, unit tests
- `src/smb2/handlers.rs` — command handlers (negotiate, session_setup dispatcher, tree, create, read/write, dir, info, lock, notify, ioctl, leases)
- `src/session.rs` — shared session registry (multichannel) + per-session handle table
- `src/lease.rs` — lease table + per-worker break mailbox
- `src/ntlm.rs` — NTLMv2; `src/spnego.rs` — SPNEGO/DER; `src/krb5.rs` — GSS acceptor + PAC read (`kerberos`)
- `src/authz.rs` — share access lists (TREE_CONNECT); `src/pac.rs` — PAC LOGON_INFO → SIDs
- `src/crypto.rs` — KDF/signing/AEAD API over `crypto_rustcrypto.rs` or `crypto_openssl.rs`
- `src/net.rs` — interface enumeration (multichannel advertisement)
- `src/health.rs` — opt-in HTTP `/healthz` (own std thread)
- `src/vfs.rs` — path sanitation, file ops, handle slab, directory snapshots
- `src/wire.rs`, `src/status.rs`, `src/log.rs` — wire primitives, NTSTATUS codes, logging

## Security posture (1.4)

NTLMv2 (+ Kerberos on `main`, unreleased), SMB2/3 signing, SMB 3.1.1 preauth
integrity, SMB3 encryption (AES-128/256-GCM/CCM). Guest allowed only when no
`[[user]]` exists (or `allow_guest = true`). **Authorization is per share**
(`read_only`, plus on `main` `valid_users`/`invalid_users`/`read_only_users`
with AD groups from the verified PAC, #40, `src/authz.rs` + `src/pac.rs`); I/O
runs as the server's Unix user (per-client identity is #53). Symlinks inside a share are followed even outside it.
No external security review yet (#39) — don't expose 445 to the public internet.
See SECURITY.md.

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

(History: phase 1–5 integration runs were done on dev.g8.lo. Builds now go
through `sc-build` only — see Platform & Build.) Primary deploy target is
x86_64; ARM64 is also released.

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

### Phase 4 — SMB3 encryption (v1.1.0, #10) — COMPLETE
AES-128-GCM for SMB 3.1.1. Lifts the trusted-LAN limitation.
- [x] Crypto: AES-128-GCM seal/open, SMB3 cipher-key derivation, tests
- [x] SMB2 TRANSFORM_HEADER codec (wrap/unwrap, roundtrip test)
- [x] NEGOTIATE advertises AES-128-GCM; SESSION_SETUP derives c2s/s2c keys
- [x] process_frame decrypts inbound / encrypts outbound; encrypted reads buffered
- [x] `encrypt` config (require) + ENCRYPT_DATA flag; signing skipped for
      encrypted msgs but the SS response that enables it is still signed
- [x] Verified: cifs `seal` (md5 integrity) + Windows Server 2025 Encrypted=True
- [x] AES-256-GCM + AES-CCM (128/256) — done (#28); GCM e2e-validated, CCM unit-validated

### Phase 3 — throughput & scale (v0.3.0)
Goal: saturate high-speed NICs (target: fill 100GbE from a single client).
100GbE = 12.5 GB/s; a single TCP/core tops ~45 Gbps (our loopback single-stream
read). Filling the pipe requires spreading across cores = multiple connections.

Network reality (jumbo frames etc.): MTU is an OS/NIC setting, not app-level;
the app already does the things that matter (LARGE_MTU cap, 1 MiB reads/4 MiB
writes, zero-copy splice, TCP_NODELAY). Jumbo frames help real links via fewer
packets; document as a deployment knob (docs/TUNING.md).

Order:
- [x] 1. Measure multi-stream aggregate on loopback: 1 conn ≈ 45 Gbps, 4 conns
      = 100 Gbps (linear SO_REUSEPORT scaling). Single-client gap = multichannel.
- [x] 2. docs/TUNING.md: jumbo frames, TCP buffers, NIC/RSS, multichannel path
- [ ] 3. TCP send/recv buffer headroom on accepted sockets (high-BDP links) — not done (no SO_SNDBUF/SO_RCVBUF set)
- [x] 4. SMB3 multichannel: MULTI_CHANNEL cap, FSCTL_QUERY_NETWORK_INTERFACE_INFO,
      session binding (shared registry, per-channel signing). Single mount
      4.7 → 21.1 GB/s (169 Gbps), 4.5×. — released v0.3.0
- [x]    Server-side read-ahead (POSIX_FADV_SEQUENTIAL); lock-free read I/O.
- [x] 5. send_zc (MSG_ZEROCOPY) for the buffered send path (v1.2.0, #15).
      Registered buffers: not done (#14, waits on #19)
- [x] 6. multishot accept, SQPOLL (opt-in), worker core pinning (v1.2.0).
      Multishot recv: not done (recv stays oneshot)
- [x] 7. Intra-connection request concurrency — shelved after measurement (#12, docs/CONCURRENCY.md)
- [x] 8. SMB3 encryption — done (phase 4). Zero-copy signed/enc reads: infeasible over TCP (#11)
- [x] 9. Leases: R (v1.3.0) + RH (v1.4.0), default on. W deferred (#27); breaks on WRITE, truncate, overwrite, rename, delete (#42, `main`)
- [x] 10. Cross-VM benchmark (Proxmox) + Windows Server interop (docs/BENCHMARKS.md, #21)
- [ ] 11. SMB Direct (RDMA) — designed (docs/SMBDIRECT.md), blocked on hardware (#19)

### Phase 5 — AD / Kerberos / FIPS (on `main`, unreleased) — COMPLETE
- [x] SPNEGO mechtype negotiation (#32), GSS acceptor + keytab (#33), session key → KDF (#34)
- [x] GSS error decoding + clock skew (#35), `auth` + `[kerberos]` config (#36)
- [x] `sec=krb5` e2e vs live KDC, incl. signing + seal (#37, `bench/krb5/e2e.sh`)
- [x] Pluggable crypto backend / OpenSSL for FIPS (#29), optional NTLM (#30)

### Open work (priorities in stormcentral)
- **Where we are (2026-10-06):** #46 waits on the stormcos#149 registration (our side is done). #41 done: v1.4.1 published. #42 done on main; #40 closed; its live AD test is #62 (needs-owner). #39 closed (external review → #63, signing default in 2.0 → #64); #50/#51 closed.
- #41 P1 — **done (2026-10-06).** Shipped config fixed + guard test on main and `release/1.4`; **v1.4.1 published** on GitHub releases (static musl x86_64/aarch64, .deb, .rpm, src.rpm, SHA256SUMS.txt), built from the tag by `deploy/release-artifacts.sh` on a fresh build VM (`SC_BUILD_VM=1`; dev had no free slot). crates.io/COPR/Debian: only if the owner asks.
- #42 P1 lease breaks — **done on `main` (2026-10-06, e6eb9ed)**: truncate, overwrite,
  rename (source + replaced target) and delete now break other keys' leases;
  process_frame test, sc-build 61/61. Not re-run against live cifs/Windows mounts.
- #39 — **closed (2026-10-06).** Self-review (docs/SECURITY-REVIEW.md) + fixes; owner's decisions carried out on `main` (48a3691): guest off by default with Kerberos, `require_signing` unset warns (default true in 2.0 = #64), packaged unit runs as the `rocketsmbd` sysusers user with only CAP_NET_BIND_SERVICE (BREAKING for upgrades: share trees must be accessible to it, README "Service user"). External review before a public offering = #63.
- #40 — **closed (2026-10-06)** per the owner's decision: share access lists + PAC group SIDs on `main`, re-verified on fccbc97. Live AD-group test is #62 (needs-owner: dc1.ad.g8.lo unreachable, AD keytab + test users by gist).
- #53 P2 per-client file identity (idmap + fsuid / io_uring personalities)
- #43 — **closed (2026-10-06):** `sc-build deploy/feature-matrix.sh` = clippy + tests for all six feature sets, musl clippy, aarch64 check, fuzz crate (verified 0adc386 on a build VM). #44 — **closed (2026-10-06):** `test/` = `rocketsmbd-test` (short 6, medium 13, long + waves) verified on build VMs; found + fixed the unsigned LOGOFF reply and send_zc ENOMEM drops. First on-node run via `stormcentral test run` = #66 (blade power-off window); writeback stall finding = #67.
- #46 P1 rocketsmbd as a stormcos service golden for smbop. **rocketsmbd side done (2026-10-06):** opt-in `health_listen` / `GET /healthz` (b09a5f5, docs dbf6d08), unit tests plus a live sc-build run (200 healthy, 503 when a share dir goes, 404/405, bad address fails `--check`). Entry values (port 9104, `/healthz`, placeholder config with `allow_guest = false`) posted on stormcos#149. #46 is queued `--after` stormcos#149. Next step once registered: `stormcentral component build rocketsmbd`, then close #46.
- #47 — **closed (2026-10-06):** SMB1-only clients get SMB1 DialectIndex 0xFFFF and the connection closes (`FrameAction::RespondClose`); SMB2-offering SMB1 negotiates still get the wildcard. Not replayed against the real X9 BMC.
- #38 — **closed (2026-10-06):** multi-leg Kerberos (`GssAcceptCtx` in `ChannelState.krb_pending`); live-KDC test `deploy/krb5-local-test.sh` (single-leg raw/SPNEGO, DCE multi-leg, bad leg) green in all kerberos builds. `bench/krb5/e2e.sh` (root + lab KDC) not re-run.
- #45 P3 — **in progress (2026-10-06):** `[kerberos].realm` now names the acceptor principal (`<spn>@<realm>`, imported as a krb5 principal name; unset = hostbased as before); validation + live-KDC tests in `tests/krb5_live.rs`. Code + docs pushed (19a1ce1); **not yet verified**: sc-build got no slot on dev (exit 75 twice) and build VMs had no ssh route (2026-10-06/07). Next: `sc-build 'deploy/feature-matrix.sh && deploy/krb5-local-test.sh'`, then close #45.
- #22 P3 Fedora review (RHBZ #2488339) — **our side done (2026-10-07):** the review pair is `rocketsmbd-1.4.1-2.fc43.src.rpm` (on the v1.4.1 release) + the spec at `release/1.4` fd892d4; it passes `packaging/verify-srpm.sh` (spec URL == SRPM spec, Source0 == GitHub archive, Provides == vendored, offline rebuild + %check, rpmlint 0/0). Build review SRPMs with `packaging/review-srpm.sh <tag> <spec-commit>`. Waiting on the owner (needs-owner): post the update comment (docs/fedora-submission.md §0) on the bug and get a Rust SIG sponsor. Next spec bump (1.5.0) must regenerate Provides/License (optional openssl/gssapi-sys trees get vendored) — docs/UPSTREAM.md.
- #23 P3 Debian (ITP + debcargo) — **our side done; waiting on the owner (2026-10-07):** `packaging/debian/` fixed and verified in sid by `sc-build 'packaging/debian-build.sh'`: 75 tests pass, lintian 0 errors, `.deb` installs, the user is created (compat 14 for dh_installsysusers), and the config passes `--check`. Owner decides (needs-owner): route (unbundled = RustCrypto port + `rust-ccm`/cmac/md4 via debcargo-conf; vendored = prune vendor + per-crate copyright; or wait), the upload version (1.4.1 vs 1.5.0), then files the ITP and finds a sponsor. docs/UPSTREAM.md "Route".
- #27, #19, #14 P3

## Testing

- Via `sc-build` after pushing: `cargo test` (default), and for feature work
  `sc-build 'cargo test --features kerberos'`,
  `sc-build 'cargo test --no-default-features --features "backend-openssl kerberos"'`.
- `cargo clippy --target x86_64-unknown-linux-musl -- -D warnings`; `cargo check --target aarch64-unknown-linux-musl` (what CI runs).
- Protocol unit tests are OS-independent (drive `process_frame`); only uring/reactor is Linux-gated.
- Integration: `bench/` host scripts (cifs mount, Windows, krb5 e2e, stress/soak) — see docs/TESTING.md.
- Test container (stormcos standard): `test/` → `sc-build 'test/build.sh && ROCKETSMBD_BIN=test/out/rocketsmbd test/out/test <short|medium|long>'`; on nodes via `stormcentral test run rocketsmbd <suite>`.
