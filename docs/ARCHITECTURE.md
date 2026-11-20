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
share four things through `Arc<Srv>`:

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
  worker A. See docs/OPLOCKS.md;
- the **share-mode table** (`src/sharemode.rs`, `Mutex`) keyed by
  `(st_dev, st_ino)`: every open with data access (read, write, append,
  execute, delete) records its granted access and its ShareAccess, and a
  CREATE that conflicts either way gets STATUS_SHARING_VIOLATION (MS-FSA
  2.1.5.1.2.1). A conflicting OVERWRITE is refused before the file is
  truncated. The record is held by the handle and dropped with it.

Each handle also keeps the access CREATE granted (generic rights mapped,
MAXIMUM_ALLOWED resolved). SET_INFO checks it per class: basic information
needs FILE_WRITE_ATTRIBUTES, rename and disposition need DELETE, end-of-file
and allocation need FILE_WRITE_DATA. FileAccessInformation reports it.

Byte-range locks are OFD locks on the handle's fd, and the handle keeps its
granted SMB locks as a list. As on Windows, an exclusive lock overlaps no
other lock, not even one on the same handle, while shared locks may overlap.
So the fd's kernel lock state is exactly the union of the list. A LOCK
request is either all locks or all unlocks (mixed is INVALID_PARAMETER). A
failed lock request unlocks only the bytes it added that no earlier lock
covers, so locks held before it are untouched. An unlock must name a held
range exactly (else RANGE_NOT_LOCKED).

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
  and the encryption/signing negotiate contexts). An SMB1 NEGOTIATE
  that offers SMB2 gets the 0x02FF wildcard response
  (`negotiate_resp_smb1_wildcard`). One that offers only SMB1 dialects
  (`smb1_negotiate_dialects`) gets an SMB1 reply with DialectIndex 0xFFFF
  (`smb1_negotiate_refuse`). `process_frame` returns
  `FrameAction::RespondClose`, and the reactor sends the reply, reads nothing
  more, and closes the connection once it has gone out (#47).

- IPC$ named pipes (`src/smb2/ipc.rs`, `src/pipe.rs`, #83): CREATE of a pipe
  named in `[ipc] pipes` opens a non-blocking Unix stream socket to `[ipc]
  backend` and writes a preamble (user, PAC SIDs, application key). WRITE,
  READ and FSCTL_PIPE_TRANSCEIVE pass DCE/RPC bytes through. Reads are
  message-mode, cut at `frag_length`. A read with no complete fragment yet
  answers STATUS_PENDING and goes on `ProtoConn::pipe_new`. The reactor then
  arms an io_uring POLL_ADD (`OP_PIPE`) on a dup of the socket, and when it
  fires it calls `ipc::pipe_ready`, which sends the final response (signed or
  sealed) or keeps waiting. CANCEL and CLOSE end a waiting read through
  `pipe_done`, which cancels the poll. Connection teardown cancels every
  armed poll. Pipes live in the session (`SessionInner::pipes`) and close
  with it. Format and rules: docs/IPC-PIPES.md.

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
- IPC$ serves only the named pipes `[ipc]` forwards to an RPC backend
  (below); no RPC is implemented in rocketsmbd itself. DFS referrals are
  unsupported.
- No registered buffers (#14, waits for SMB Direct #19) and no registered
  files (not worth it: the fds are also used by plain syscalls; docs/TUNING.md).
  No SMB Direct (#19).
- No external security review yet (#39); see SECURITY.md for the deployment
  posture.
