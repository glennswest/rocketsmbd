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

**Stable (`1.2`).** Speaks SMB 2.0.2 through 3.1.1 with **NTLMv2
authentication, SMB2/3 signing, SMB 3.1.1 preauth integrity, SMB3
multichannel, and SMB3 encryption (AES-128/256-GCM, AES-CCM)**. Supports a user database,
optional guest access, byte-range locks, and directory change notification.
The config format and on-wire behavior are stable across the 1.x series; wire
parsers are fuzzed.

Set `encrypt = true` to require encryption, or just mount with `seal` (Linux)
/ an encrypted share (Windows) — verified against cifs.ko and Windows Server
2025 (`Encrypted=True`). Ciphers: AES-128/256-GCM and AES-128/256-CCM (set
`prefer_aes256` to favor 256-bit). Read-caching leases are available opt-in
(`oplocks = true`); SMB Direct (RDMA) is on the [roadmap](ROADMAP.md). See
[SECURITY.md](SECURITY.md).

## Install

Prebuilt **static** packages (no library dependencies; needs a Linux kernel
with io_uring ≥ 5.15) are attached to each [release](https://github.com/glennswest/rocketsmbd/releases):

```sh
# Fedora / RHEL (x86_64 or aarch64)
sudo dnf install ./rocketsmbd-1.2.0-1.x86_64.rpm
# Debian / Ubuntu
sudo dpkg -i ./rocketsmbd_1.2.0-1_amd64.deb
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

- Linux kernel ≥ 5.15 (≥ 6.0 recommended for multishot accept/recv)
- Capability to bind port 445 (`CAP_NET_BIND_SERVICE` or root)

Re-run benchmarks with `bench/bench.sh` (root, Linux, cifs-utils).

## Design

Full write-up: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- **No async runtime.** One reactor thread per worker, each owning its own
  `io_uring` instance and a `SO_REUSEPORT` listener. Completion-driven state
  machines per connection.
- **Zero-copy READ path.** `SMB2 READ` responses are emitted as a linked SQE
  chain: `send(header, MSG_MORE)` → `splice(file → pipe)` →
  `splice(pipe → socket)`. The kernel moves page-cache pages directly to the
  socket.
- **NBT framing** (4-byte direct-TCP length prefix) handled in the receive
  state machine with per-connection buffers that grow to the negotiated
  transact size. Provided-buffer rings and multishot recv are phase 3.
- **Static binary.** Builds with musl to a single static binary suitable for a
  `scratch` container image.

## Build

Develop anywhere; compile for Linux:

```sh
cargo check --target aarch64-unknown-linux-musl   # validate
cargo build --release --target aarch64-unknown-linux-musl
```

Protocol-layer unit tests are OS-independent:

```sh
cargo test
```

## Configuration

`rocketsmbd.toml`:

```toml
listen = "0.0.0.0:445"
workers = 0            # 0 = one per CPU core
server_name = "ROCKETSMBD"

require_signing = false   # set true to mandate SMB2 signing
# allow_guest defaults to true only when no [[user]] entries exist

[[share]]
name = "data"
path = "/srv/data"
read_only = false

# Define users to require authentication (presence of any [[user]]
# disables guest unless allow_guest = true is set explicitly).
[[user]]
name = "alice"
password = "secret"        # or: nt_hash = "<32 hex chars>"
```

Run: `rocketsmbd --config /etc/rocketsmbd.toml`

## Mounting

```sh
# Guest (when allowed)
mount -t cifs //server/data /mnt -o guest,vers=3.0

# Authenticated, signed, SMB 3.1.1
mount -t cifs //server/data /mnt -o username=alice,password=secret,vers=3.1.1,sec=ntlmsspi
```

## License

MIT
