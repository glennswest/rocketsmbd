# Contributing to rocketsmbd

Thanks for your interest! rocketsmbd is a from-scratch SMB2/3 server built on
io_uring. Contributions — bug reports, protocol-correctness fixes,
performance work, packaging, docs — are all welcome.

## Ground rules

- **Linux only at runtime** (io_uring). The protocol layer is OS-independent
  and unit-tests anywhere; the reactor (`src/uring.rs`) is Linux-gated.
- Keep the share-nothing-per-core reactor model intact unless there's a
  measured reason not to. Per-connection state is lock-free; only the shared
  session registry takes locks, and only briefly.
- New wire behavior needs a unit test in `src/smb2/mod.rs` (drive
  `process_frame` and assert on the bytes).
- Run before pushing:
  ```sh
  cargo test
  cargo clippy --target x86_64-unknown-linux-musl -- -D warnings
  cargo check --target aarch64-unknown-linux-musl
  ```
- CI runs build + test + clippy on every PR.

## Building

Develop anywhere; compile for Linux:

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

For real testing you need a Linux host and a cifs client. See `docs/` for the
architecture, benchmark method, and tuning notes.

## Project layout

- `src/wire.rs` — little-endian wire primitives
- `src/smb2/` — protocol: header codec, dispatch, command handlers
- `src/uring.rs` — the io_uring reactor (Linux)
- `src/session.rs` — cross-connection session registry (multichannel)
- `src/crypto.rs`, `src/ntlm.rs` — signing + NTLMv2
- `src/vfs.rs` — filesystem layer, handle table
- `docs/` — ARCHITECTURE.md, BENCHMARKS.md, TUNING.md

## Commit style

Conventional commits (`feat:`, `fix:`, `perf:`, `docs:`, `chore:`). One
logical change per commit. Update `CHANGELOG.md` and the relevant `docs/`.

## Good first issues

Look for the `good-first-issue` label. Packaging (Fedora/Debian), docs, and
additional info-class coverage are approachable starting points.

## Security

Do not file public issues for vulnerabilities — see `SECURITY.md`.
