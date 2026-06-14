# Oplocks & leases — design

**Status:** foundation landed (constants + create-context/lease parsing,
grant-none unchanged). Granting + breaks are the next increments (#18). This
doc is the implementation contract.

## Why

Oplocks (SMB1-era) and leases (SMB2.1+) let a client **cache** file data and
metadata locally and avoid round-trips. They are the single biggest
*everyday* performance win for real workloads (open/read/close storms, build
trees, roaming profiles) — independent of link speed or fabric, so they help
every deployment, not just the 200G+ segment.

A lease grants caching rights:

| State bit | Meaning |
|---|---|
| `READ_CACHING` (R, 0x1) | cache reads; multiple clients may hold R simultaneously |
| `HANDLE_CACHING` (H, 0x2) | keep the handle open across closes (avoids re-open) |
| `WRITE_CACHING` (W, 0x4) | cache writes; **exclusive** (only one holder) |

Legacy oplock levels map on: `LEVEL_II` ≈ R, `EXCLUSIVE` ≈ R+W,
`BATCH` ≈ R+W+H.

## The safety rule (why grant-none is the safe default)

**A lease without a correct break is a correctness bug, not just a missing
optimization.** If we grant an R lease and a second client writes the file, the
holder must be *broken* down (R→None) before the write is acknowledged, or it
keeps serving stale cached data — silent corruption. Therefore:

> We do not grant any lease/oplock until the break-delivery path is built and
> proven. grant-none (today) is always safe.

## Wire format (parsed today)

- **CREATE request:** `RequestedOplockLevel` byte at body offset 3; if a lease
  is requested it is `0xFF` (`OPLOCK_LEASE`) and the real request is in a
  create context. `CreateContextsOffset/Length` (body offsets 48/52) point at
  the chained context list.
- **`RqLs` context data:** v1 (32 B) = `LeaseKey[16] LeaseState[4]
  LeaseFlags[4] LeaseDuration[8]`; v2 (52 B) adds `ParentLeaseKey[16]
  Epoch[2] Reserved[2]`. `parse_lease_ctx()` walks the chain and returns it.
- **CREATE response (to add):** set the granted `OplockLevel` byte, and for a
  lease echo an `RqLs` response context with the granted `LeaseState`.
- **OPLOCK_BREAK** (cmd `0x12`): both the server→client *Notification* and the
  client→server *Acknowledgement* / server *Response*. Lease breaks use the
  Lease variant (carries the 16-byte LeaseKey + new state); oplock breaks use
  the FileId variant.

## File identity (the lease key on the server side)

Leases are keyed per file, across separate opens and across connections. Use
**`(share_idx, ino)`** — `OpenFile` already carries `share_idx`, and
`vfs::Meta` exposes `ino`. The client's 16-byte `LeaseKey` is *its* handle to
the lease; the server maps `(share_idx, ino) → LeaseState` and remembers which
`LeaseKey` / session holds it.

## The hard part: cross-worker break delivery

This is the crux, and the reason this is multi-increment work.

- Workers are independent threads behind `SO_REUSEPORT`. **Two opens of the
  same file can land on different workers.** A write arriving on worker B may
  need to break a lease held by a connection owned by worker A.
- A `Conn` is owned by its worker's thread (`Worker.conns: Vec<Option<Conn>>`)
  — **not shared**, so worker B cannot touch worker A's `Conn` directly.
- The shared `Srv` (`Arc<Srv>`, incl. the session `Registry`) *is* reachable
  from every worker. That's where the lease table lives.

**Design — a per-worker wakeable break mailbox:**

1. Lease table in `Srv`: `Mutex<HashMap<(u32,u64), Arc<Mutex<LeaseState>>>>`.
   `LeaseState` records granted state, holder `{session_id, worker_id, conn
   slot+gen}`, the client `LeaseKey`, and break-in-progress bookkeeping.
2. Each worker creates an **`eventfd`** and registers it in its ring with
   `POLL_ADD` (same trick the SMB Direct CQ uses). The worker exposes an MPSC
   `Sender<BreakMsg>` in a shared, worker-indexed table in `Srv`.
3. To break a lease held on worker A, the acting worker B: looks up the holder
   in the lease table → pushes a `BreakMsg{conn slot/gen, lease key, new
   state}` to worker A's MPSC → writes A's eventfd (8 bytes).
4. Worker A wakes on the eventfd POLL completion, drains its MPSC, builds the
   **OPLOCK_BREAK Notification**, and pushes it onto the target `Conn`'s
   existing **`deferred`** queue — exactly the path CHANGE_NOTIFY already uses
   to deliver async server→client frames when tx is idle.
5. The acting op (write/conflicting create) either waits for the break-ack
   (returns `STATUS_PENDING` and completes async) or, for a break that doesn't
   need to block, proceeds once the notification is queued, per [MS-SMB2]
   break semantics.

This adds one genuinely new piece of infrastructure — the **per-worker eventfd
mailbox** — which is also exactly what SMB Direct's CQ integration and any
future cross-worker signalling will reuse. Build it once, here.

## Status & key finding (2026-06-13)

Built and tested: connection identity in `ProtoConn`, the `(share_idx,ino)`
lease table, Level II oplock **grant**, cross-worker **break delivery** (the
eventfd mailbox → `build_oplock_break` → deferred queue), and lease release on
**CLOSE and connection teardown**. Unit-tested; cross-worker break delivery
confirmed end-to-end on the rig (no crash, no leak).

**But integration testing found granting is not yet *effective* with cifs, and
is unsafe:** cifs (and Windows) request a **lease** (RqLs), and a lease-based
client does **not** act on a legacy **oplock-break** notification (FileId) — it
waits for a **lease-break** (keyed by LeaseKey, a different 44-byte frame). With
Level II granted, a held cifs mount kept serving **stale** data after another
client's write (server-on-disk and a fresh remount were correct; the cached
handle was not invalidated). That's worse than grant-none.

So granting is **gated behind `oplocks` (default off)**. Default behavior is
grant-none = no client caching = always fresh (verified). To actually realize
the caching win, the remaining work is the **lease path**: emit the granted
`RqLs` response context (OplockLevel `0xFF`), and send a **lease-break**
notification on conflict, broken by LeaseKey, with the ack handling leases
require. The infrastructure (table, mailbox, identity, teardown release) is
reused as-is.

## Increment plan

1. **Foundation (done):** oplock/lease constants; parse `RequestedOplockLevel`
   + `RqLs` (v1/v2) into `CreateReq`; still grant none. No behavior change.
2. **Lease table + identity:** `(share_idx, ino)` table in `Srv`; record holder
   on CREATE; release on CLOSE. Still grant none (table is observational).
3. **Per-worker eventfd mailbox:** eventfd + POLL_ADD per worker; shared
   `Sender` table; a `wake(worker)` helper. Unit-test the wakeup.
4. **Grant R (Level II) + break-on-write:** grant `READ_CACHING` when no
   conflicting holder; on WRITE / conflicting CREATE from another client, send
   a lease break (R→None) via the mailbox; track ack. Most-tested path first
   because R is shared (no exclusivity bugs).
5. **Grant RH, then RW/RWH (exclusive):** handle/write caching with the
   exclusivity invariant; break W→R / RW→R on second opener.
6. **Oplock-break acknowledgement** handler (cmd 0x12 inbound) + the
   wait-for-ack state on the breaking op.
7. **Durable handles (DH2Q)** can reuse the same handle table + lease epoch
   later (separate item).

## Testing

- Unit: `parse_lease_ctx` v1/v2 (landed with the foundation).
- Integration (Linux cifs, two mounts of the same share): client A opens with a
  lease, client B writes → A receives a break, A's cache invalidates, data is
  consistent (md5). cifs exposes lease state via `/proc/fs/cifs/Stats` and
  mount option `nohandlecache`/`handlecache` for H. Windows
  `Get-SmbConnection` / `fsutil` for interop.
- Stress: many openers across all workers to exercise cross-worker delivery.
