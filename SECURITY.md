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

## Current security posture (1.4)

rocketsmbd is at 1.4. It has real authentication, signing, and encryption, but
1.0 shipped without the planned external security review, and that review
still hasn't been done (#39). Know the following before deploying:

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
  - Kerberos accepts single-leg AP-REQ exchanges only (#38).
- **Authorization is share-level only** — `read_only` per share applies to
  everyone. Any authenticated user (or guest, if allowed) can use every share,
  and all file I/O runs as the server process's Unix user, so on-disk
  permissions don't distinguish clients. Per-share user/group lists and a
  SID→uid map are tracked in #40. Run the server as a dedicated unprivileged
  user that owns only the share trees.
- **Crypto backend** — pure-Rust (default) or **system OpenSSL**
  (`--features backend-openssl`) for FIPS deployments, where OpenSSL is the
  validated module. A FIPS+AD build is
  `--no-default-features --features "backend-openssl kerberos"` — no
  NTLM/MD4/RC4 in the binary. AES-CCM still runs on the RustCrypto `ccm`
  crate in that build, and the RustCrypto crates remain linked (see
  docs/FIPS.md). Release artifacts are the default build only; the Kerberos
  and OpenSSL builds are source builds, and as of v1.4.0 they exist only on
  `main` (unreleased).
- **Wire parsers are fuzzed** — `process_frame` (SMB2 entry) and the NTLMSSP
  token parser have libFuzzer targets run in CI (per-push smoke + weekly). Not
  a guarantee, but the attack surface is no longer unexercised.
- **Path safety** — `..` traversal and NUL bytes in client paths are rejected.
  Symlinks that already exist inside a share are **followed, even if they
  point outside it** (like Samba's `wide links`). Clients can't create
  symlinks over SMB, so only someone with local access to the share tree can
  plant one.
- **Deployment** — a hardened build (Kerberos or NTLMv2 + `require_signing`,
  optionally `encrypt`) is reasonable beyond a trusted LAN, but a full
  security review has not been done; do not expose port 445 to the public
  internet until it has (#39).

## Hardening roadmap

An external security review pass is still planned (#39).
Done: SMB3 encryption (AES-128/256-GCM/CCM), SMB2/3 signing, Kerberos auth, an
OpenSSL/FIPS crypto-backend option, and fuzzing the frame + NTLMSSP parsers.

## Supported versions

Only the latest tagged release receives fixes.
