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

rocketsmbd is **pre-1.0 and not yet hardened for hostile networks.** Know the
following before deploying:

- **No SMB3 encryption yet.** Data is signed (when negotiated) but not
  encrypted on the wire. Use only on trusted networks.
- **Authentication** is NTLMv2 against a local user database, or guest. There
  is no Kerberos, no domain integration, and no account lockout.
- **The SMB2/NTLMSSP wire parsers have not yet been fuzzed.** Treat the
  attack surface as unaudited (see the open hardening issues).
- **Path safety**: share paths are the jail boundary; `..` traversal and NUL
  bytes are rejected. Symlinks inside a share are followed.
- Intended deployment is a **trusted LAN**. Do not expose port 445 to the
  public internet.

## Hardening roadmap

Tracked as issues: SMB3 encryption (AES-128-GCM), fuzzing the frame and
NTLMSSP parsers (`cargo-fuzz`), signing-required-by-default, and a security
review pass before the 1.0 release. See `ROADMAP.md`.

## Supported versions

Pre-1.0: only the latest tagged release receives fixes.
