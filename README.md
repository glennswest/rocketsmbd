# rocketsmbd

A from-scratch SMB2/SMB3 file server (smbd replacement) written in Rust, built
on **io_uring end-to-end** — accept, receive, send, and file I/O all flow
through a single ring per worker. File reads are served **zero-copy** from page
cache to socket using linked `splice` operations (file → pipe → socket); file
data never enters userspace.

## Status

Pre-release (`0.1.x`). Phase 1 targets a mountable guest read/write server
speaking SMB 2.0.2 through 3.1.1 (no signing/encryption yet). **Do not expose
to untrusted networks.** See `CLAUDE.md` for the full roadmap.

## Requirements

- Linux kernel ≥ 5.15 (≥ 6.0 recommended for multishot accept/recv)
- Capability to bind port 445 (`CAP_NET_BIND_SERVICE` or root)

## Design

- **No async runtime.** One reactor thread per worker, each owning its own
  `io_uring` instance and a `SO_REUSEPORT` listener. Completion-driven state
  machines per connection.
- **Zero-copy READ path.** `SMB2 READ` responses are emitted as a linked SQE
  chain: `send(header, MSG_MORE)` → `splice(file → pipe)` →
  `splice(pipe → socket)`. The kernel moves page-cache pages directly to the
  socket.
- **NBT framing** (4-byte direct-TCP length prefix) handled in the receive
  state machine with provided-buffer rings.
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

[[share]]
name = "data"
path = "/srv/data"
read_only = false
```

Run: `rocketsmbd --config /etc/rocketsmbd.toml`

## Mounting

```sh
mount -t cifs //server/data /mnt -o guest,vers=3.0
```

## License

MIT
