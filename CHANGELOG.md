# Changelog

## [Unreleased]

### 2026-06-09
- **feat:** io_uring reactor — per-worker rings, SO_REUSEPORT listeners, accept/recv/send state machines, zero-copy READ via splice(file→pipe) + MSG_MORE header + splice(pipe→socket).
- **feat:** SMB2 protocol core — header codec, compound (NextCommand/related) dispatch, NEGOTIATE (2.0.2–3.0.2), SESSION_SETUP (guest NTLMSSP), TREE_CONNECT, CREATE/CLOSE/FLUSH, READ (zero-copy + buffered), WRITE, QUERY_DIRECTORY (6 info classes), QUERY_INFO (file + filesystem), SET_INFO (rename/delete/truncate/times), IOCTL validate-negotiate, ECHO/LOGOFF/TREE_DISCONNECT.
- **feat:** Protocol foundation — wire primitives, NT status mapping, TOML config, minimal NTLMSSP (guest), VFS layer with traversal-safe path resolution and generation-checked handle table.
- **test:** 9 unit/integration tests including a full wire-level session exchange (negotiate→session→tree→create→write→read→query-directory) against a temp share.
- **build:** Static musl release build (772K, ARM64), Containerfile for scratch image, cross-linker config.
- **chore:** Repo bootstrap — project docs, work plan, scaffold for rocketsmbd, an io_uring-based smbd replacement in Rust.
