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

rocketsmbd is at 1.4. It has real authentication, signing, and encryption.
1.0 shipped without the planned external security review. In October 2026 a
self-review covered the auth state machine, crypto use, Kerberos, parsers,
paths, every `unsafe` block, and resource exhaustion; its findings and their
status are in [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md). The fixes
are on `main` (unreleased): releases up to 1.4.1 carry the issues it found,
among them an encrypted session that accepted plaintext requests, a read-only
share writable through another tree's handle, and sessions that were never
freed when their connection dropped. An external review is still to be done
(#39). Know the following before deploying:

- **SMB3 encryption** — AES-128-GCM, AES-256-GCM, and AES-128/256-CCM (SMB
  3.1.1). Set `encrypt = true` to require it, or let clients request it
  (`seal`); `prefer_aes256` selects AES-256 when offered. When not encrypting,
  data is signed (when negotiated) but cleartext on the wire — prefer
  `encrypt = true` on untrusted networks.
- **Signing** — SMB2 HMAC-SHA256 and SMB3 AES-CMAC; SMB 3.1.1 preauth
  integrity (SHA-512). Signing is **off unless the client asks** by default
  (`require_signing` unset or `false`; unset logs a warning, and the default
  becomes `true` in 2.0, #64); without it, an on-path attacker can tamper
  with requests, and NTLM (which has no MIC check here) can be relayed. Set
  `require_signing = true` on anything but a trusted LAN. Each MessageId is
  accepted once per connection, so captured signed or sealed requests can't
  be replayed. With `encrypt`, sessions that can't be sealed are refused and
  an encrypting session takes no plaintext requests; a tampered NEGOTIATE is
  caught by VALIDATE_NEGOTIATE_INFO.
- **Authentication** — selectable via `auth` (`ntlm` / `kerberos` / `both`):
  - **Kerberos (GSS-API/SPNEGO)** against a keytab, via the system GSS library
    (MIT/Heimdal) — domain/AD integration. Build with `--features kerberos`.
  - **NTLMv2** against a local user database (the `ntlm` feature, on by
    default; compile out with `--no-default-features`).
  - **Guest/anonymous** when enabled. Unset, `allow_guest` is true only on a
    server with no `[[user]]` entries and no Kerberos (an enabled `[kerberos]`
    table or `auth = "kerberos"`); releases up to 1.4.1 also allowed guest on
    Kerberos-only configs. An unknown NTLM user is mapped to guest when guest
    is allowed. `invalid_users` never matches a guest, so
    use `valid_users` to keep guests off a share. No account lockout yet.
  - Kerberos accepts single-leg AP-REQ exchanges (cifs.ko, Windows) and
    multi-leg GSS exchanges such as DCE style (#38).
- **Authorization is per share** — `valid_users` / `invalid_users` /
  `read_only_users` decide at TREE_CONNECT who may use a share and who gets it
  read-only, by user, Kerberos principal, or AD group SID from the PAC (#40).
  Only a PAC the GSS library has verified with the service key is used; an
  unverified one is ignored. Without lists, any authenticated user (or guest,
  if allowed) can use the share. All file I/O runs as the server process's
  Unix user, so on-disk permissions don't distinguish clients (per-client
  file identity is #53). Run the server as a dedicated unprivileged user that
  owns only the share trees.
- **Crypto backend** — pure-Rust (default) or **system OpenSSL**
  (`--features backend-openssl`) for FIPS deployments, where OpenSSL is the
  validated module. A FIPS+AD build is
  `--no-default-features --features "backend-openssl kerberos"` — no
  NTLM/MD4/RC4 in the binary. AES-CCM still runs on the RustCrypto `ccm`
  crate in that build, and the RustCrypto crates remain linked (see
  docs/FIPS.md). Release artifacts are the default build only; the Kerberos
  and OpenSSL builds are source builds, and as of v1.4.0 they exist only on
  `main` (unreleased).
- **Wire parsers are fuzzed** — libFuzzer targets for `process_frame` (SMB2
  entry), the NTLMSSP parser, SPNEGO/DER blob classification, and the SMB3
  TRANSFORM header (including decrypt-then-dispatch). Their bodies live in
  the library, and `cargo test` compiles and smoke-runs them, so they can't
  silently stop building again. (The CI Fuzz job needs the two new targets
  added to its matrix, and GitHub Actions is currently disabled on the repo.)
- **Resource limits** — until a session is established, frames are capped at
  128 KiB and a connection may hold 4 half-open session setups. A session
  holds at most 16384 opens and 1024 tree connects, a connection 1024
  pended CHANGE_NOTIFYs, a compound frame 128 members (~8 MiB of responses).
  Sessions, opens and byte-range locks end with their last connection. There
  is no connection cap, handshake/idle timeout or keepalive yet (#55).
- **Path safety** — `..` traversal and NUL bytes in client paths are rejected,
  only regular files and directories are opened, and the share root can't be
  deleted or renamed. A handle works only on the tree it was opened on.
  Symlinks that already exist inside a share are **followed, even if they
  point outside it** (like Samba's `wide links`). Clients can't create
  symlinks over SMB, so only someone with local access to the share tree can
  plant one (`openat2(RESOLVE_BENEATH)` resolution is #56). The packaged
  systemd unit runs as the unprivileged `rocketsmbd` user with only
  `CAP_NET_BIND_SERVICE`, so a planted symlink reaches only what that user
  can (on `main`; releases up to 1.4.1 ran as root with `CAP_DAC_OVERRIDE` —
  see README, "Service user", for the ownership migration).
- **Health endpoint** — off by default. With `health_listen` set, the server
  also accepts plain HTTP on that address (`GET /healthz` only; no auth, no
  share names or paths in the reply, one request at a time with a 2 s timeout
  and a 4 KiB cap). Bind it to loopback or an admin network, never to a
  client-facing interface.
- **Deployment** — a hardened config (Kerberos or NTLMv2, `require_signing =
  true`, `allow_guest = false`, optionally `encrypt = true`, run as a
  dedicated unprivileged user) is reasonable beyond a trusted LAN. An
  external security review has not been done; do not expose port 445 to the
  public internet until it has (#63: before rocketsmbd is offered publicly).

## Hardening roadmap

An external security review is planned before rocketsmbd is offered publicly
(#63); `require_signing` defaults to true in 2.0 (#64). Open follow-ups from
the self-review: connection caps and timeouts (#55), `openat2` path
resolution (#56), lease-table hardening (#57).
Done: SMB3 encryption (AES-128/256-GCM/CCM), SMB2/3 signing, Kerberos auth, an
OpenSSL/FIPS crypto-backend option, fuzzing the frame, NTLMSSP, SPNEGO and
TRANSFORM parsers, and the October 2026 self-review
([docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md)).

## Supported versions

Only the latest tagged release receives fixes.
