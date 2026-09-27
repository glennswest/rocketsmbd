# rocketsmbd Roadmap

What has shipped and what is open. Items link to GitHub issues. Dates are targets, not promises.

## Shipped

- **0.1** — io_uring reactor, zero-copy splice reads, SMB 2.0.2–3.0.2, guest
  read/write. ~4× Samba on reads.
- **0.2** — NTLMv2 auth + user DB, SMB2/3 signing, SMB 3.1.1 preauth
  integrity, SPNEGO, IPC$ stub, byte-range locks, CHANGE_NOTIFY.
- **0.3** — SMB3 **multichannel** (shared session registry, channel binding,
  per-channel signing), server-side read-ahead, lock-free read I/O. Single
  mount 169 Gbps loopback / ~47 Gbps cross-VM jumbo.

- **0.4** — linked io_uring chain for full zero-copy reads, `advertise_only`,
  `.deb`/`.rpm` packages, systemd unit, man page, CI.
- **1.0** (2026-06-11) — stable config + wire behavior; parser fuzzing in CI
  (#20); lib/bin split. Shipped **without** the planned external security
  review, which is now #39.
- **1.1** — SMB3 encryption, AES-128-GCM (#10).
- **1.2** — AES-256-GCM and AES-128/256-CCM (#28); read-caching leases, opt-in
  (#18); send_zc (#15); SQPOLL (#13); multishot accept (#16; recv stays
  oneshot); worker core pinning (#17).
- **1.3** — read-caching leases on by default, validated on Windows (#27).
- **1.4** — handle-caching (RH) leases (#27).
- Packaging: COPR live, crates.io published, Fedora review bug filed (#22).

Investigated and dropped: intra-connection read concurrency (#12, shelved after
measurement) and zero-copy signed/encrypted reads (#11, infeasible over TCP).

## Next release (on `main`, unreleased)

- ✅ Pluggable crypto backend — optional OpenSSL primitives for FIPS
  compliance (#29). `backend-rustcrypto` (default) / `backend-openssl`;
  OpenSSL KATs verified identical to RustCrypto on Linux.
- ✅ Make MD4/RC4 (NTLM legacy primitives) optional at build time, a
  prerequisite for a clean OpenSSL/FIPS build (#30). Default-on `ntlm`
  feature; `--no-default-features` drops md4/md-5 entirely.
- Kerberos (below).

## 0.7 — Active Directory / Kerberos ✅

NTLM-only is not viable long term — Microsoft is aggressively removing NTLM in
favor of Kerberos. Kerberos (GSS-API/SPNEGO) auth via the system GSS library
(no pure-Rust krb5). Tracking issue #31 — **validated end-to-end** against a
live KDC (cifs.ko `sec=krb5`, signing + AES-GCM sealing over the Kerberos
session key). Sub-tasks:

- ✅ SPNEGO mechtype negotiation — advertise + select Kerberos (#32).
- ✅ AP-REQ acceptor + keytab via the system GSS library (#33).
- ✅ GSS session-key → SMB signing/sealing key derivation (#34).
- ✅ Replay cache, clock-skew, and error handling (#35) — multi-leg context
  persistence remains a documented future item (not exercised by real clients).
- ✅ Config to select kerberos / ntlm / both (#36) — composes with #30.
- ✅ AD-join/keytab docs + `sec=krb5` integration tests (#37).

Clean FIPS + AD posture: `--no-default-features --features "backend-openssl
kerberos"` → OpenSSL crypto, Kerberos auth, no NTLM/MD4/RC4 in the binary.

## Open

- External security review (#39).
- Lease breaks on truncate/overwrite/rename (#42); write-caching leases (#27,
  deferred).
- Per-share user/group authorization via the Kerberos PAC, and a SID→uid
  map (#40).
- Multi-leg Kerberos context persistence (#38); honor `[kerberos].realm` (#45).
- CI feature matrix (#43); `rocketsmbd-test` container (#44); shipped-config
  guard test + 1.4.1 (#41).
- Official Fedora (Rust SIG, RHBZ #2488339) and Debian (debcargo) packages
  (#22, #23).

## Beyond

- Registered files + buffers (#14), driven by SMB Direct's needs.
- SMB Direct (RDMA) transport for 400/800GbE (#19) —
  design: [docs/SMBDIRECT.md](docs/SMBDIRECT.md) (RoCEv2 target).
