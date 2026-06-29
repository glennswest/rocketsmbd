# Kerberos (GSS-API / SPNEGO) authentication — design & build/test plan

Tracking issue **#31**, sub-tasks **#32–#37**. This is the implementation and
validation plan for Kerberos auth in rocketsmbd. The protocol-level pieces
(SPNEGO mechType negotiation) are unit-testable on any host; the GSS acceptor,
session-key derivation, and end-to-end validation require a Linux host with a
GSS library and a KDC + joined client, and are gated behind the off-by-default
`kerberos` Cargo feature.

> **Why external GSS, not pure-Rust krb5:** explicit reviewer guidance (Simo
> Sorce, ssorce@redhat.com): pure-Rust krb5 implementations are not trustworthy
> for production. We bind a maintained C GSS library (MIT krb5 or Heimdal).

## 1. Library choice

**`libgssapi` crate** (safe bindings over the system GSS-API: MIT krb5
`libgssapi_krb5` or Heimdal). Rationale: covers `gss_accept_sec_context`,
credential/keytab acquisition, context inquiry, and error formatting without us
hand-writing `extern "C"`. Raw `gssapi-sys` FFI is the fallback if we need an
inquire OID the safe crate doesn't expose.

Consequence: linking system GSS means a **dynamically-linked build** — it breaks
the static-musl `scratch` container story. Kerberos builds use a glibc base
(e.g. `gcr.io/distroless/base` or a thin Fedora/Debian layer) with
`krb5-libs` / `libgssapi-krb5` present. This is the same trade-off as the
OpenSSL backend (#29); document both as the "dynamic profile".

## 2. Cargo wiring

```toml
[features]
kerberos = ["dep:libgssapi"]      # default OFF; needs system GSS + dynamic link

[dependencies]
libgssapi = { version = "0.x", optional = true }
```

- Default builds (static musl, what CI on macOS cross-checks) do **not** enable
  `kerberos` and pull no GSS dependency.
- `cargo build --features kerberos` is a **Linux-host** build (needs
  `krb5-devel`/`libkrb5-dev` + `libgssapi-krb5`).
- Composes with `--no-default-features` (#30): `--no-default-features
  --features kerberos` is the NTLM-free, Kerberos-only build — the Phase-3
  end state Microsoft is driving toward.

## 3. Server principal & keytab

- SPN: **`cifs/<fqdn>@REALM`** (cifs is the SMB service class; some clients also
  request `host/<fqdn>`). Register both where practical.
- Keytab: path from config (`kerberos.keytab = "/etc/rocketsmbd.keytab"`), or
  fall back to `KRB5_KTNAME`. The acceptor acquires its credential for the SPN
  from this keytab via `gss_acquire_cred` (or `gss_krb5_import_cred`).
- AD join produces the keytab: `net ads keytab` (Samba) or `ktpass` (Windows) or
  `ipa-getkeytab` (FreeIPA). Document all three in #37's runbook.

## 4. SPNEGO negotiation (#32 — no GSS dependency, unit-testable)

mechType OIDs:

| Mechanism | OID | DER value |
|---|---|---|
| Kerberos 5 | `1.2.840.113554.1.2.2` | `2A 86 48 86 F7 12 01 02 02` |
| MS Kerberos | `1.2.840.48018.1.2.2` | `2A 86 48 82 F7 12 01 02 02` |
| NTLMSSP | `1.3.6.1.4.1.311.2.2.10` | (existing) |

- NEGOTIATE response `NegTokenInit2` lists **Kerberos first, then NTLMSSP** (when
  both features are built) so Kerberos-capable clients prefer it.
- SESSION_SETUP: classify the incoming token —
  - SPNEGO `NegTokenInit` with a `mechToken` under the Kerberos OID → route the
    inner blob (a GSS-API AP-REQ, itself `0x60` / `application 0`) to the GSS
    acceptor.
  - GSS-API framed AP-REQ sent raw (no SPNEGO) → accept directly.
  - NTLMSSP OID / `NTLMSSP\0` signature → existing NTLM path (if built).
- Response wrapping: `NegTokenResp` with `negState` and `supportedMech` =
  Kerberos, `responseToken` = the GSS output token (AP-REP when mutual auth).

This layer is pure ASN.1 over the existing `der()` helper in `ntlm.rs` (move the
shared SPNEGO/DER code to `src/spnego.rs` so it's available without the `ntlm`
feature).

## 5. GSS acceptor (#33)

```
acquire acceptor cred for cifs/<fqdn> from keytab   (once, at startup)
per SESSION_SETUP:
  gss_accept_sec_context(cred, input_token) -> (ctx, output_token, status)
    CONTINUE_NEEDED -> return output_token, MORE_PROCESSING_REQUIRED
    COMPLETE        -> session established; return AP-REP if present, SUCCESS
  on error -> log GSS major/minor, STATUS_LOGON_FAILURE
```

- Multi-leg exchanges (rare for Kerberos AP-REQ, common if the client does
  mutual auth or channel binding) carry the partial GSS context in the
  per-channel `PendingAuth`, like the NTLM challenge does today.
- Extract the authenticated client name (`gss_display_name`) for logging/ACLs.

## 6. Session-key derivation (#34)

- The SMB session key is the **Kerberos sub-session key** from the AP-REQ
  authenticator. Extract via `gss_inquire_sec_context_by_oid` with the
  **`GSS_C_INQ_SSPI_SESSION_KEY`** OID (`1.2.840.113554.1.2.2.5.5`) — MIT and
  Heimdal both expose it; this is what Samba/Windows use for SMB.
- Take the first 16 bytes (or the AES key as provided) as the SMB session key,
  then feed the **existing** SP800-108 KDF (`crypto::kdf128`, MS-SMB2 3.1.4.2)
  to derive signing / encryption / application keys — identical to the NTLM
  path. No new crypto; only the key *source* changes.
- 3.1.1 preauth-integrity hash chaining is unchanged (it hashes the
  SESSION_SETUP messages, mechanism-agnostic).

## 7. Config (#36)

```toml
[kerberos]
enabled = true
keytab  = "/etc/rocketsmbd.keytab"   # or $KRB5_KTNAME
spn     = "cifs/fileserver.example.com"   # optional; default from hostname
realm   = "EXAMPLE.COM"                   # optional; from krb5.conf

# top-level auth selector
auth = "both"   # "kerberos" | "ntlm" | "both" (default preserves NTLM behavior)
```

- `auth = "kerberos"` → advertise/accept only Kerberos; NTLMSSP tokens rejected.
- `auth = "ntlm"` → today's behavior.
- `auth = "both"` → advertise both, Kerberos preferred (NTLM fallback).
- `auth = "kerberos"` with `--no-default-features` = no NTLM code at all.

## 8. Robustness (#35)

- **Replay cache:** rely on the GSS library's rcache (MIT keeps one per
  acceptor). Document the choice; do not roll our own.
- **Clock skew:** GSS returns a clear minor status; surface
  `STATUS_TIME_DIFFERENCE_AT_DC`-class errors and log the skew. AD default
  tolerance is 5 min.
- **Errors:** map common GSS failures (no keytab entry, wrong SPN, expired
  ticket, KDC unreachable) to sane SMB statuses + an actionable log line.

## 9. Build & test matrix (#37 — Linux/AD host)

Environment: reuse the Proxmox test bed. Stand up **one** of:
- Samba AD DC (`samba-tool domain provision`), or
- MIT krb5 KDC (`kdb5_util create`), or
- FreeIPA.

Plus a Linux client (cifs.ko `sec=krb5`) and the existing Windows Server 2025 VM
(domain-joined).

```sh
# build (Linux host with krb5-devel + libgssapi-krb5)
cargo build --release --features kerberos
cargo build --release --no-default-features --features kerberos   # krb-only

# keytab for the SPN
net ads keytab create -U administrator           # or ktpass / ipa-getkeytab
KRB5_KTNAME=/etc/rocketsmbd.keytab rocketsmbd --config ...

# Linux client (after kinit)
kinit alice@EXAMPLE.COM
mount -t cifs //fileserver/data /mnt -o sec=krb5,vers=3.1.1
#   -> verify md5 read/write, signed; smbstatus shows Kerberos

# Windows client (domain-joined)
net use \\fileserver\data
Get-SmbConnection | fl Dialect,Signed,...           # expect Kerberos auth
```

Acceptance: cifs `sec=krb5` and a domain-joined Windows client both authenticate
via Kerberos, with signing (and SMB3 encryption) working over the
Kerberos-established session key. NTLM-free build (`--no-default-features
--features kerberos`) authenticates the same clients with zero NTLM/MD4/RC4 in
the binary.

## 10. Status

- [x] #32 SPNEGO mechtype negotiation — implemented + unit-tested (7 tests)
- [x] #33 GSS acceptor + keytab — implemented; **builds + links `libgssapi_krb5`
      on dev.g8.lo** (Fedora 43). `gssapi-sys` binds only base `gssapi.h`, so the
      session-key symbols from `gssapi_ext.h` are declared directly in `krb5.rs`.
- [x] #34 GSS session-key → SMB KDF — implemented (sub-session key → existing
      SP800-108 KDF); compiles under `--features kerberos`.
- [x] #36 auth selector config (`auth`, `[kerberos]`)
- [x] dispatcher wiring (`session_setup` → mech routing; NTLM path unchanged)
- [ ] #35 replay/skew/errors — GSS rcache relied on; skew/error mapping TODO
- [ ] #37 live `sec=krb5` interop — **blocked on the KDC (krb5.g8.lo)**; runbook
      below, automated by `bench/krb5/e2e.sh`.

Build verified on dev.g8.lo (all four feature combinations clippy-clean):
`cargo build/test --features kerberos` and `--no-default-features --features
kerberos`. Single-leg AP-REQ only so far (the common cifs/Windows case); a
multi-leg GSS exchange is logged + rejected pending per-channel context
persistence (#35).

### e2e runbook (run once krb5.g8.lo is up)

Realm assumed `G8.LO`, KDC `krb5.g8.lo`, server `dev.g8.lo`. `bench/krb5/e2e.sh`
automates this:

```sh
# on krb5.g8.lo (KDC): create the service + a test user
kadmin.local -q "addprinc -randkey cifs/dev.g8.lo@G8.LO"
kadmin.local -q "ktadd -k /tmp/rocketsmbd.keytab cifs/dev.g8.lo@G8.LO"
kadmin.local -q "addprinc -pw testpw alice@G8.LO"
#   copy /tmp/rocketsmbd.keytab to dev.g8.lo:/etc/rocketsmbd.keytab

# on dev.g8.lo (server): krb5.conf points at krb5.g8.lo; then
cat > /etc/rocketsmbd.toml <<EOF
listen = "0.0.0.0:445"
auth = "kerberos"
[kerberos]
keytab = "/etc/rocketsmbd.keytab"
spn = "cifs/dev.g8.lo"
[[share]]
name = "data"
path = "/srv/krbshare"
EOF
rocketsmbd --config /etc/rocketsmbd.toml &

# client (kinit then mount)
kinit alice@G8.LO <<<"testpw"
mount -t cifs //dev.g8.lo/data /mnt -o sec=krb5,vers=3.1.1
#   verify: write+md5 read back, klist shows the cifs/dev.g8.lo ticket
```
