# Architecture

rocketsmbd is a from-scratch SMB2/3 server built directly on io_uring — no
async runtime, no thread-per-connection. This document describes the design
as implemented; the work plan in `CLAUDE.md` tracks what's next.

## Process model

```
main
 ├─ load TOML config, probe pipe capacity (bounds MaxReadSize)
 ├─ spawn N worker threads (default: one per core)
     each worker:
       own io_uring (1024 entries; SQPOLL if `sqpoll = true`)
       pinned to core N mod ncpu (`core_pinning`, default on)
       own listening socket (SO_REUSEPORT → kernel load-balances accepts)
       slab of connections, generation-tagged
 └─ health thread, only if `health_listen` is set (src/health.rs)
       plain blocking std::net listener, not an io_uring worker
       GET /healthz → 200 while all workers live and all share paths are dirs, else 503
```

The health endpoint exists for service managers (stormcos's stormd sends an
HTTP liveness probe). Each worker holds a `WorkerGuard` that counts it live
until the thread exits, panics included, so a dead worker turns the probe to 503.
Requests are served one at a time with a 2 s timeout and a 4 KiB cap.

A connection lives its whole life on one worker, and its connection and
protocol state (`Conn`, `ProtoConn`) is touched only by that worker. Workers do
share three things through `Arc<Srv>`:

- the read-only config and share table;
- the **session registry** (`src/session.rs`, `Mutex`). Sessions and their open
  handle tables live here so SMB3 multichannel channels on other workers can
  bind to the same session. A session ends at LOGOFF of its last channel or
  when its last connection closes (`handlers::teardown_conn`, called from the
  reactor's `finalize_close`), which also closes its opens: lease release,
  delete-on-close, and the fd close that drops its byte-range locks. Session
  ids are random;
- the **lease table** (`src/lease.rs`, `Mutex`) keyed by `(share_idx, ino)`, plus
  a per-worker **break mailbox**: an MPSC queue plus an eventfd polled in each
  ring, so a WRITE on worker B can deliver a lease-break to a connection on
  worker A. See docs/OPLOCKS.md.

READ I/O runs without holding the session lock (the fd is dup'd under the
lock, then the read proceeds lock-free), so reads on different channels don't
serialize. Other commands, WRITE included, run under the session lock.

## Connection state machines (src/uring.rs)

Each connection runs **full-duplex**: the rx and tx sides operate
independently on the same ring.

**accept** — multishot accept when the kernel supports `send_zc` (≥ 6.0,
which covers multishot accept's 5.19 floor); otherwise oneshot, re-armed.

**rx side** — a oneshot recv is kept posted whenever there is buffer room. The
buffer is a flat `Vec<u8>` with a read offset (`rx_off`) and write watermark
(`rx_len`); consumed frames advance `rx_off`, and the buffer is compacted
only when no recv is in flight (the kernel writes into it concurrently
otherwise). It grows on demand up to MaxTransact + slack (~4.1 MiB).

**tx side** — one transmit stream at a time, in one of two modes:

- `Send` — a batch of buffered responses. The dispatcher appends each
  frame's response (with its NetBIOS prefix) to `tx`; one `send` covers the
  whole batch. Short sends resubmit the remainder. Batches at or above
  `ZC_SEND_MIN` go out as `send_zc` (MSG_ZEROCOPY) when the kernel supports it;
  the tx buffer is then held until the kernel's buffer-release notification
  (`IORING_CQE_F_NOTIF`) arrives. This matters most for encrypted and signed
  reads, which are buffered.
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

A standalone (non-compound) READ ≥ 8 KiB whose response does not need to be
signed or encrypted is served without the file data ever entering userspace:

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

READs inside compound requests, below 8 KiB, or on signed/encrypted sessions
take a buffered `pread` path: the payload has to be hashed or sealed, so it
can't bypass userspace. Zero-copy for those was investigated and closed as
infeasible over TCP (#11).

## SMB2 layer (src/smb2/)

Strictly separated from I/O: `process_frame(srv, conn_state, frame, tx)` is
a pure function from bytes to bytes (plus filesystem side effects), which is
why the whole protocol layer unit-tests on macOS. The reactor only knows
about NetBIOS framing and the `ZcRead` plan escape hatch.

- Compounds: chained requests share a `Chain` (session/tree/last-FileId for
  related ops); responses are 8-aligned with NextCommand patched.
- SESSION_SETUP is a dispatcher: `spnego::classify` identifies the blob
  (SPNEGO NegTokenInit/Resp, raw Kerberos AP-REQ, raw NTLMSSP) and routes it
  by mechanism × the `auth` policy × the built features. NTLM
  (`ntlm_session_setup`, `src/ntlm.rs`) verifies NTLMv2 against the `[[user]]`
  database, or accepts guest when allowed. Kerberos (`kerberos_session_setup`,
  `src/krb5.rs`, `kerberos` feature) runs one `gss_accept_sec_context` over
  the AP-REQ, and keeps a partial GSS context on the channel between legs
  when GSS asks for more (#38). Either way, the
  session key feeds the SP800-108 KDF for signing and encryption keys.
- Authorization (`src/authz.rs`) runs at TREE_CONNECT: the share's
  `valid_users` / `invalid_users` / `read_only_users` against the session's
  user, Kerberos flag and PAC (`src/pac.rs`, group SIDs). The result is stored
  on the `Tree` (`read_only`), which CREATE, WRITE and SET_INFO check instead
  of the share flag. I/O still runs as the server's Unix user (#53).
- Signing: HMAC-SHA256 (2.x) / AES-CMAC (3.x) verify-and-sign; authenticated
  sessions always sign responses. `require_signing` rejects unsigned requests.
- Encryption: TRANSFORM_HEADER with AES-128/256-GCM/CCM (`prefer_aes256`);
  inbound is decrypted before dispatch and outbound sealed.
- Crypto primitives go through `src/crypto.rs`, backed by `crypto_rustcrypto.rs`
  (default) or `crypto_openssl.rs` (`backend-openssl`; see docs/FIPS.md).
- Credits: each request's charge is consumed, and the grant is
  `clamp(requested, 1, 512 − outstanding)` (a 512-credit window per
  connection).
- Dialects 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 (3.1.1 with SHA-512 preauth integrity
  and the encryption/signing negotiate contexts). SMB1 negotiate gets the
  0x02FF wildcard response whatever dialects it offers
  (`negotiate_resp_smb1_wildcard`). An SMB1-only client can't parse that and
  times out instead of being refused (#47).

## VFS layer (src/vfs.rs)

- Path resolution rejects `..` and NUL; share paths are the jail boundary
  (symlinks inside a share are followed, samba-style).
- Open handles live in a generation-tagged slab per session (shared by the
  session's multichannel channels); FileIds
  never repeat across a close, so stale client FileIds miss cleanly.
- Directory enumeration snapshots the listing at first QUERY_DIRECTORY and
  serves slices; RESTART_SCANS re-snapshots.

## Limits & known compat warts

- One tx stream per connection: a zero-copy read serializes behind the
  current response batch (flush-then-splice). Concurrent reads per connection
  were designed and then shelved after measurement showed the server wasn't
  the bottleneck (#12, docs/CONCURRENCY.md); multichannel is the scaling path.
- IPC$ tree connects get a stub tree (no pipes/RPC); DFS referrals are
  unsupported.
- No registered buffers/files (#14) and no SMB Direct (#19).
- No external security review yet (#39); see SECURITY.md for the deployment
  posture.
