# Security Policy

rocketsmbd is a network file server — it parses untrusted input from the
network — so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately via GitHub Security Advisories
("Security" tab → "Report a vulnerability") on
<https://github.com/glennswest/rocketsmbd>, or email the maintainer listed in
`Cargo.toml`. Include steps to reproduce, affected versions, and impact. We
aim to acknowledge within a few days.

## Current security posture (pre-1.0)

rocketsmbd is **pre-1.0.** It has grown real authentication, signing, and
encryption, but has not yet had a full external security review. Know the
following before deploying:

- **SMB3 encryption** — AES-128-GCM, AES-256-GCM, and AES-128/256-CCM (SMB
  3.1.1). Set `encrypt = true` to require it, or let clients request it
  (`seal`); `prefer_aes256` selects AES-256 when offered. When not encrypting,
  data is signed (when negotiated) but cleartext on the wire — prefer
  `encrypt = true` on untrusted networks.
- **Signing** — SMB2 HMAC-SHA256 and SMB3 AES-CMAC; SMB 3.1.1 preauth
  integrity (SHA-512). `require_signing = true` enforces it.
- **Authentication** — selectable via `auth` (`ntlm` / `kerberos` / `both`):
  - **Kerberos (GSS-API/SPNEGO)** against a keytab, via the system GSS library
    (MIT/Heimdal) — domain/AD integration. Build with `--features kerberos`.
  - **NTLMv2** against a local user database (the `ntlm` feature, on by
    default; compile out with `--no-default-features`).
  - **Guest/anonymous** when enabled. No account lockout yet.
- **Crypto backend** — pure-Rust (default) or **system OpenSSL**
  (`--features backend-openssl`) for FIPS deployments, where OpenSSL is the
  validated module. A clean FIPS+AD build is
  `--no-default-features --features "backend-openssl kerberos"` — no
  NTLM/MD4/RC4 in the binary.
- **Wire parsers are fuzzed** — `process_frame` (SMB2 entry) and the NTLMSSP
  token parser have libFuzzer targets run in CI (per-push smoke + weekly). Not
  a guarantee, but the attack surface is no longer unexercised.
- **Path safety** — share paths are the jail boundary; `..` traversal and NUL
  bytes are rejected. Symlinks inside a share are followed.
- **Deployment** — a hardened build (Kerberos or NTLMv2 + `require_signing`,
  optionally `encrypt`) is reasonable beyond a trusted LAN, but a full
  security review has not been done; do not expose port 445 to the public
  internet before 1.0.

## Hardening roadmap

A pre-1.0 security review pass is still planned (see `ROADMAP.md`, 1.0).
Done: SMB3 encryption (AES-128/256-GCM/CCM), SMB2/3 signing, Kerberos auth, an
OpenSSL/FIPS crypto-backend option, and fuzzing the frame + NTLMSSP parsers.

## Supported versions

Pre-1.0: only the latest tagged release receives fixes.
