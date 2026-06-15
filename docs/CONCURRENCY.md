# Intra-connection read concurrency — design (#12)

**Status: NOT being built — measurement showed no benefit.** The design below
is preserved for reference (and the Stage-1 user_data slot id is kept as
harmless groundwork), but the premise was checked before building and does not
hold for this architecture.

## Why it was shelved (measured 2026-06-15)

Single-channel read on the rig (loopback isolates server from network):

| scenario | throughput | server CPU |
|---|---|---|
| warm (server cache hot) | 6.1–6.4 GB/s | **0.03 s CPU per GiB** (~80% of one core *idle*) |
| cold (page cache dropped) | ~0.50 GB/s | — |
| local disk baseline (cold) | ~0.48 GB/s | — |

- **Warm:** the server spends 0.03 s of CPU to serve a 1 GiB read that takes
  0.17 s — it is *not* the bottleneck. The single-channel cap is the
  client/window/loopback, not the server's one-read-at-a-time processing. You
  can't speed up a server that's already ~80% idle by overlapping fills.
- **Cold:** SMB reads run at **disk speed** (0.50 vs 0.48 GB/s local), and
  `POSIX_FADV_SEQUENTIAL` already has the kernel reading ahead — an app-level
  prefetch is redundant with kernel readahead for sequential reads.

This matches the earlier benchmark conclusion (linked-chain removal "changed
nothing"; single-channel is "network/protocol-bound, not server-bound"), now
confirmed by direct CPU measurement. So the engine below would add a large,
regression-risky rewrite of the core read path for **no measurable gain**. The
right lever for single-client throughput remains **multichannel** (more
connections → more cores/NIC queues), which is already implemented.

Revisit only if a future transport changes the dynamics (e.g. SMB Direct/RDMA,
where the data path and latency profile differ — #19).

---

## (Original design, for reference)

This was to be a high-risk change to the core zero-copy read path, landed
behind tested increments.

## The problem

Today a connection serves **one request in flight**: the reactor processes a
frame, and on a `READ` it runs the whole zero-copy chain
(`splice(file→pipe)` → `send(hdr, MSG_MORE)` → `splice(pipe→socket)`) before
processing the next frame. A client that has pipelined N reads sees them served
strictly serially. Between draining read K to the socket and starting read
K+1's fill, the socket goes idle — a bubble. This caps a single channel
(measured ~21 Gbps single-stream on the jumbo rig, ~45 Gbps loopback), which is
why filling a fast link needs multichannel.

The earlier linked-chain work removed the *userspace* round-trips within one
read but did **not** raise the cap (BENCHMARKS.md): the cap is the
request/response *depth* per channel, i.e. only one read's data is ever being
prepared at a time.

## The key constraint, and the win

On one TCP connection, each SMB2 response (NBT length + message) must be a
**contiguous** byte run — you cannot interleave two responses' bytes. So the
**socket sends must serialize**. But SMB2 does *not* require in-order
responses (the client correlates by MessageId), and crucially the
**`splice(file→pipe)` fills are independent** and can run concurrently.

So the win is **parallel fills, serial drains**: while read K drains
`pipe→socket`, reads K+1..K+d fill their own pipes from the file. When K's
drain finishes, K+1's data is already in its pipe and drains immediately — no
bubble. Depth `d` (a few) hides fill latency behind drain time.

## Design

- A per-connection **read-slot pool** of `d` slots, each owning its own pipe,
  `Zc` state, and response-header buffer. (Today: one `Zc`, one `pipe`,
  header in the shared `tx`.)
- **user_data** gains a slot id in its free low 16 bits:
  `ud(op, idx, gen, slot)`. Splice/send completions route to the right slot's
  `Zc`, removing the single-`conn.zc` collision.
- **Fill side (parallel):** as `drive()` reads pipelined `READ` frames, it
  issues each one's `splice(file→pipe)` into a free slot immediately, up to `d`
  in flight. Non-read frames and buffered responses keep their current path.
- **Drain side (serial):** an ordered queue of slots whose fills have
  completed. The tx engine, when the socket is free, takes the head slot, sends
  its header (`MSG_MORE`) + `splice(pipe→socket)`, and on completion advances to
  the next. Only one drain on the socket at a time.
- **Buffered (non-zc) responses** and the encrypted/compound path keep going
  through `tx`/`Tx::Send`; they interleave with the drain queue at message
  boundaries (never mid-message).

## Staging (each step builds + tests green before the next)

1. **Slot id in user_data** — add the field, thread `slot=0` everywhere. Pure
   plumbing, behavior identical. ✅ safe.
2. **Read-slot pool, depth 1** — move `zc`/`pipe`/header into a 1-element slot
   pool; route by slot id. Behavior identical (still one in flight). Validates
   the structure end-to-end (rig read integrity + throughput unchanged).
3. **Depth ≥ 2, parallel fills** — issue the next pipelined read's fill while
   the current drains; ordered drain queue. Measure throughput + verify
   integrity (md5 over large multi-read transfers, EOF/partial reads, errors).
4. **Tune depth**, ensure pipe-pool memory is bounded (d × max_read), handle
   teardown (close all slot fds/pipes), and the EOF/short-read/error paths per
   slot.

## Risks

- Core read path + the validated linked-chain fast path are touched — heavy
  integrity testing (md5, partial/EOF reads, concurrent writers) at each stage.
- Pipe memory: `d × MaxReadSize` per connection; keep `d` small (e.g. 4) and
  the pipe pool lazy.
- Teardown must drain/close all slots (the existing single-zc dup-fd-close and
  `inflight` accounting generalize per slot).
