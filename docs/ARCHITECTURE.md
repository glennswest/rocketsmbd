# Architecture

rocketsmbd is a from-scratch SMB2/3 server built directly on io_uring — no
async runtime, no thread-per-connection. This document describes the design
as implemented; the work plan in `CLAUDE.md` tracks what's next.

## Process model

```
main
 ├─ load TOML config, probe pipe capacity (bounds MaxReadSize)
 └─ spawn N worker threads (default: one per core)
     each worker:
       own io_uring (1024 entries)
       own listening socket (SO_REUSEPORT → kernel load-balances accepts)
       slab of connections, generation-tagged
```

There is no shared state between workers except the read-only `Srv` config.
A connection lives its whole life on one worker — no locks, no cross-thread
wakeups.

## Connection state machines (src/uring.rs)

Each connection runs **full-duplex**: the rx and tx sides operate
independently on the same ring.

**rx side** — a recv is kept posted whenever there is buffer room. The
buffer is a flat `Vec<u8>` with a read offset (`rx_off`) and write watermark
(`rx_len`); consumed frames advance `rx_off`, and the buffer is compacted
only when no recv is in flight (the kernel writes into it concurrently
otherwise). It grows on demand up to MaxTransact + slack (~4.1 MiB).

**tx side** — one transmit stream at a time, in one of two modes:

- `Send` — a batch of buffered responses. The dispatcher appends each
  frame's response (with its NetBIOS prefix) to `tx`; one `send` covers the
  whole batch. Short sends resubmit the remainder.
- `ZcIn → ZcHdr → ZcOut` — the zero-copy READ sequence (below).

**Frame batching** — when the tx side is idle, `drive()` processes *every*
complete frame in the rx buffer (up to a 1 MiB response watermark),
accumulating responses, then submits a single send. This is what makes
pipelined client streams (e.g. cifs writing with 16 credits) fast: requests
that arrived while we were busy are answered in one pass, one syscall-free
ring submission, one TCP burst. See docs/BENCHMARKS.md for the effect
(+2× write throughput).

**user_data encoding** — every SQE carries `(op:8 | conn_idx:24 | gen:16)`.
Generations are bumped when a slot is recycled, so a stale CQE from a dead
connection is recognized and dropped. In-flight ops hold their own kernel
file references, so closing the fd at teardown is safe.

## Zero-copy READ path

A standalone READ ≥ 8 KiB is served without the file data ever entering
userspace:

```
1. splice(file → pipe, len)      repeated until len or EOF   [ZcIn]
2. send(SMB2 header, MSG_MORE)   header built AFTER the splice,
                                 so it carries the true byte count [ZcHdr]
3. splice(pipe → socket, n)      repeated until drained      [ZcOut]
```

Ordering matters: splicing *first* means EOF/short reads are known before
the header is sent, so the header never promises bytes that don't arrive.
The per-connection pipe is sized to the advertised MaxReadSize, so step 1
can never block on a full pipe (which would deadlock — nothing drains it
until step 3). This is also why `MaxReadSize` is bounded by the achievable
pipe capacity probed at startup.

On error or short read below MinimumCount, the pipe is drained synchronously
and an error response is sent instead.

READs inside compound requests or below 8 KiB take a buffered `pread` path.

## SMB2 layer (src/smb2/)

Strictly separated from I/O: `process_frame(srv, conn_state, frame, tx)` is
a pure function from bytes to bytes (plus filesystem side effects), which is
why the whole protocol layer unit-tests on macOS. The reactor only knows
about NetBIOS framing and the `ZcRead` plan escape hatch.

- Compounds: chained requests share a `Chain` (session/tree/last-FileId for
  related ops); responses are 8-aligned with NextCommand patched.
- Sessions are guest-only (phase 1): any NTLMSSP AUTHENTICATE is accepted.
- Credits: granted = clamp(requested, 1, 512); no enforcement yet.
- Dialects 2.0.2, 2.1, 3.0, 3.0.2 (3.1.1 requires preauth integrity —
  phase 2). SMB1 negotiate gets the 0x02FF wildcard response.

## VFS layer (src/vfs.rs)

- Path resolution rejects `..` and NUL; share paths are the jail boundary
  (symlinks inside a share are followed, samba-style).
- Open handles live in a generation-tagged slab per connection; FileIds
  never repeat across a close, so stale client FileIds miss cleanly.
- Directory enumeration snapshots the listing at first QUERY_DIRECTORY and
  serves slices; RESTART_SCANS re-snapshots.

## Limits & known compat warts

- One tx stream per connection: a zero-copy read serializes behind the
  current response batch (flush-then-splice). True concurrent reads per
  connection are phase 3.
- cifs.ko logs `failed to connect to IPC (rc=-2)` at mount because we
  refuse the IPC$ tree connect; harmless (DFS referrals unsupported), an
  IPC$ stub is planned in phase 2.
- No signing/encryption/real auth yet — trusted-LAN only (phase 2).
