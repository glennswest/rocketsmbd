# FIPS / crypto backend

rocketsmbd's FIPS-able SMB2/3 primitives are pluggable (#29). Pick a backend at
build time with Cargo features:

| Feature | Primitives source | Linking | Use case |
|---|---|---|---|
| `backend-rustcrypto` (default) | pure-Rust RustCrypto crates | static (musl `scratch`) | general use; no system crypto |
| `backend-openssl` | system OpenSSL (`libcrypto`) | dynamic | FIPS deployments (OpenSSL is the validated module) |

The backend covers **HMAC-SHA256, SHA-512, AES-CMAC, and AES-GCM** (signing +
SMB3 encryption + the SP800-108 KDF). The public `crypto` API is identical
across backends; the OpenSSL backend is verified to produce byte-identical
output (RFC 4493 CMAC and AEAD known-answer tests pass on both).

## Building the OpenSSL/FIPS profile

Needs `openssl-devel` (Fedora/RHEL) or `libssl-dev` (Debian) at build time:

```sh
# OpenSSL crypto, no NTLM/MD4/RC4 (the clean FIPS build), Kerberos auth:
cargo build --release --no-default-features --features "backend-openssl kerberos"

# OpenSSL crypto but keep NTLM (MD4/MD5/RC4 remain RustCrypto — see below):
cargo build --release --features backend-openssl
```

This is a **dynamically linked** binary (links `libcrypto.so`), so it is not the
static `scratch` container; package it on a glibc base with the system OpenSSL.

## What is *not* on the OpenSSL backend

- **MD4 (NT hash), HMAC-MD5 (NTLMv2), RC4 (NTLMSSP key exchange)** — NTLM-only
  legacy primitives. OpenSSL's FIPS provider does not offer them, so they are
  always RustCrypto and only present with the `ntlm` feature (#30). A FIPS build
  uses `--no-default-features` (no NTLM) + Kerberos (#31) for authentication.
- **AES-CCM** — OpenSSL's one-shot AEAD interface can't satisfy CCM's
  length-prefix requirement, and CCM is rarely negotiated (GCM is the SMB3
  default), so CCM stays on the pure-Rust `ccm` crate even in the OpenSSL
  backend. A strict-FIPS deployment negotiates AES-GCM, which is OpenSSL-backed.

## Summary: the clean FIPS posture

```
--no-default-features --features "backend-openssl kerberos"
```

→ OpenSSL for all crypto on the wire (GCM, signing, KDF), Kerberos for auth, and
no MD4/MD5/RC4/NTLM anywhere in the binary.
