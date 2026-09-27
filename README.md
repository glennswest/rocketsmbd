# rocketsmbd

[![CI](https://github.com/glennswest/rocketsmbd/actions/workflows/ci.yml/badge.svg)](https://github.com/glennswest/rocketsmbd/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rocketsmbd.svg)](https://crates.io/crates/rocketsmbd)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A from-scratch SMB2/SMB3 file server (smbd replacement) written in Rust, built
on **io_uring end-to-end** — accept, receive, send, and file I/O all flow
through a single ring per worker. File reads are served **zero-copy** from page
cache to socket using linked `splice` operations (file → pipe → socket); file
data never enters userspace. A single client mount stripes across cores via
**SMB3 multichannel**.

## Status

**Stable (`1.4`).** Speaks SMB 2.0.2 through 3.1.1 with **NTLMv2 and
Kerberos (GSS-API/SPNEGO) authentication, SMB2/3 signing, SMB 3.1.1 preauth
integrity, SMB3 multichannel, and SMB3 encryption (AES-128/256-GCM,
AES-128/256-CCM)**. Supports a user database, optional guest access,
byte-range locks, and directory change notification. The config format and
on-wire behavior are stable across the 1.x series. The `process_frame` and
NTLMSSP parsers are fuzzed.

Kerberos, the `auth` selector, the OpenSSL crypto backend for FIPS and the
optional-NTLM build are **on `main` but not yet in a release** (see
[CHANGELOG.md](CHANGELOG.md) `[Unreleased]`); v1.4.0 and its packages are
NTLMv2-only. Kerberos is also off in the default build (`--features kerberos`,
see [docs/KERBEROS.md](docs/KERBEROS.md)), as is the OpenSSL backend
(`--features backend-openssl`, see [docs/FIPS.md](docs/FIPS.md)).

**Authorization is share-level only.** Once authenticated, any user can use
every share (`read_only` applies to everyone), and all file I/O runs as the
server's own Unix user. Per-share user/group lists and per-user identity are
tracked in [#40](https://github.com/glennswest/rocketsmbd/issues/40).

**No SMB1.** Every SMB1 NEGOTIATE gets the SMB2 wildcard (0x02FF) reply, and
the dialects the client offers are never checked. A client that speaks
SMB2 upgrades normally. An SMB1-only client (e.g. one that offers only
`NT LM 0.12`, such as some BMCs) can't parse the reply and hangs until it times
out (~20 s), instead of being refused
([#47](https://github.com/glennswest/rocketsmbd/issues/47)).

Set `encrypt = true` to require encryption, or just mount with `seal` (Linux)
/ an encrypted share (Windows) — verified against cifs.ko and Windows Server
2025 (`Encrypted=True`). Ciphers: AES-128/256-GCM and AES-128/256-CCM (set
`prefer_aes256` to favor 256-bit). Read-caching + handle-caching leases are on by
default (`oplocks`; validated against cifs + Windows); SMB Direct (RDMA) is on
the [roadmap](ROADMAP.md). See
[SECURITY.md](SECURITY.md).

## Install

Prebuilt **static** packages (no library dependencies; needs a Linux kernel
with io_uring ≥ 5.15) are attached to each [release](https://github.com/glennswest/rocketsmbd/releases):

```sh
# Fedora / RHEL (x86_64 or aarch64)
sudo dnf install ./rocketsmbd-1.4.0-1.x86_64.rpm
# Debian / Ubuntu
sudo dpkg -i ./rocketsmbd_1.4.0-1_amd64.deb
# then edit /etc/rocketsmbd.toml and:
sudo systemctl enable --now rocketsmbd
```

Or build from source via [crates.io](https://crates.io/crates/rocketsmbd)
(Linux; needs a Rust toolchain):

```sh
cargo install rocketsmbd
```

Fedora users can also `dnf copr enable glennswest/rocketsmbd && dnf install rocketsmbd`.

Distro-upstream packaging (build-from-source `.spec` and `debian/`) and the
Fedora/Debian submission plan are in [docs/UPSTREAM.md](docs/UPSTREAM.md).

## Performance (vs Samba, same host)

| | rocketsmbd | Samba |
|---|---|---|
| 1 GiB sequential read | **5.7–6.2 GB/s** | 1.4 GB/s |
| 512 MiB sequential write | **1.0 GB/s** | 0.64 GB/s |
| single mount, 4 channels (multichannel) | **21 GB/s (169 Gbps), loopback** | n/a |

Full method + cross-VM (real-network) numbers: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
Tuning for 100GbE+: [docs/TUNING.md](docs/TUNING.md).

## Requirements

- Linux kernel ≥ 5.15, with io_uring enabled (checked at startup). ≥ 6.0 is
  recommended: the server then uses multishot accept and `send_zc`
  (MSG_ZEROCOPY) for large buffered sends; older kernels fall back to oneshot
  accept and copying sends.
- Capability to bind port 445 (`CAP_NET_BIND_SERVICE` or root). TCP 445
  (direct TCP, 4-byte length framing) is the only port; there is no NetBIOS
  (139), no RPC or management API, and no SMB Direct (RDMA) transport.

Re-run benchmarks with `bench/bench.sh` (root, Linux, cifs-utils).

## Design

Full write-up: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- **No async runtime.** One reactor thread per worker, each owning its own
  `io_uring` instance and a `SO_REUSEPORT` listener. Completion-driven state
  machines per connection.
- **Zero-copy READ path.** `SMB2 READ` responses are emitted as a linked SQE
  chain: `splice(file → pipe)` → `send(header, MSG_MORE)` →
  `splice(pipe → socket)`. The splice goes first so the header carries the
  actual byte count. The kernel moves page-cache pages directly to the socket.
  Signed or encrypted reads are buffered instead, since the payload has to be
  hashed or sealed.
- **NBT framing** (4-byte direct-TCP length prefix) handled in the receive
  state machine with per-connection buffers that grow to the negotiated
  transact size. Recv is oneshot and re-armed; there are no provided-buffer
  rings or registered buffers ([#14](https://github.com/glennswest/rocketsmbd/issues/14)).
- **Static binary.** The default build (NTLM + RustCrypto) is a single static
  musl binary suitable for a `scratch` container image. The `kerberos` and
  `backend-openssl` builds link system libraries and are dynamic.

## Build

The default build is NTLM + the pure-Rust crypto backend, as a static musl
binary (this is what the release packages and the container ship):

```sh
cargo build --release --target x86_64-unknown-linux-musl    # or aarch64-unknown-linux-musl
cargo test                                                  # protocol unit tests (OS-independent)
```

Cargo features:

| Feature | Default | What it does |
|---|---|---|
| `ntlm` | on | NTLM/NTLMv2 auth (MD4/MD5/RC4). Without it, NTLMSSP session-setup is rejected with `STATUS_NOT_SUPPORTED`. |
| `backend-rustcrypto` | on | Pure-Rust SMB2/3 crypto (static-musl friendly). |
| `backend-openssl` | off | SMB2/3 crypto via system OpenSSL, for FIPS. Dynamically linked. See [docs/FIPS.md](docs/FIPS.md). |
| `kerberos` | off | Kerberos GSS acceptor via the system GSS library (MIT/Heimdal). Dynamically linked, Linux only. See [docs/KERBEROS.md](docs/KERBEROS.md). |

Examples: `cargo build --release --features kerberos` (NTLM + Kerberos);
`cargo build --release --no-default-features --features "backend-openssl kerberos"`
(FIPS, Kerberos only).

### Container

`Containerfile` packages the static musl binary into a `scratch` image. It
reads its config from `/etc/rocketsmbd/rocketsmbd.toml`, so mount that and
your share directories in, and publish port 445:

```sh
cargo build --release --target x86_64-unknown-linux-musl
podman build -t rocketsmbd -f Containerfile .
podman run -d -p 445:445 -v /etc/rocketsmbd:/etc/rocketsmbd:ro -v /srv/data:/srv/data rocketsmbd
```

Only the default (static) build fits `scratch`; Kerberos and OpenSSL builds
need a base image that has their libraries.

## Configuration

TOML, passed with `--config <path>` (default `./rocketsmbd.toml`; packages
install `/etc/rocketsmbd.toml`). `--check` validates the file and exits.
Unknown keys are rejected. A full example is in
[`rocketsmbd.toml.example`](rocketsmbd.toml.example).

| Key | Default | Meaning |
|---|---|---|
| `listen` | `"0.0.0.0:445"` | Bind address (`ip:port`). |
| `workers` | `0` | Worker threads, each with its own io_uring and `SO_REUSEPORT` listener. `0` = one per CPU core. |
| `server_name` | `"ROCKETSMBD"` | Advertised server name; also the default Kerberos SPN host (`cifs/<server_name>`). |
| `log_level` | `1` | `0` = warn, `1` = info, `2` = debug. |
| `allow_guest` | true if there are no `[[user]]` entries, else false | Allow unauthenticated guest sessions. |
| `require_signing` | `false` | Reject unsigned requests on authenticated sessions. |
| `encrypt` | `false` | Require SMB3 encryption for all post-auth traffic. When false, encryption a client asks for (e.g. cifs `seal`) is still honored. |
| `prefer_aes256` | `false` | Pick AES-256 (GCM, then CCM) when offered, instead of the client's order. |
| `multichannel` | `false` | Advertise SMB3 multichannel and accept session binding. |
| `advertise_only` | `[]` | IPs to advertise for multichannel; empty = every non-loopback interface. |
| `core_pinning` | `true` | Pin worker N to core N mod ncpu. |
| `sqpoll` | `false` | io_uring SQPOLL (a busy kernel thread per worker). |
| `oplocks` | `true` | Grant leases: read-caching and handle-caching (R/RH). Write-caching is never granted. |
| `auth` | `"both"` | `"ntlm"`, `"kerberos"` or `"both"` (Kerberos preferred). Intersected with the built features. |
| `[kerberos]` | absent | `enabled` (default true), `keytab` (default `$KRB5_KTNAME` / system keytab), `spn` (default `cifs/<server_name>`), `realm` (currently ignored, #45). Used only in a `kerberos` build. |
| `[[share]]` | at least one required | `name`, `path` (must be an existing directory), `read_only` (default false). `IPC$` is reserved. |
| `[[user]]` | none | `name` plus exactly one of `password` or `nt_hash` (32 hex chars). NTLM users only; Kerberos principals come from the KDC. |

```toml
listen = "0.0.0.0:445"
workers = 0
require_signing = true
multichannel = true

[[share]]
name = "data"
path = "/srv/data"

[[user]]
name = "alice"
password = "secret"        # or: nt_hash = "<32 hex chars>"
```

Run: `rocketsmbd --config /etc/rocketsmbd.toml` (packages install a systemd
unit, `rocketsmbd.service`).

## Mounting

```sh
# Guest (when allowed)
mount -t cifs //server/data /mnt -o guest,vers=3.0

# NTLMv2, signed, SMB 3.1.1
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,sec=ntlmsspi

# Encrypted
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,seal

# Kerberos (kerberos build, needs a ticket: kinit alice@REALM)
mount -t cifs //server.example.com/data /mnt -o sec=krb5,vers=3.1.1

# Multichannel (server has multichannel = true)
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,multichannel,max_channels=4
```

## License

MIT
