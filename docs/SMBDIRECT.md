# SMB Direct (RDMA / RoCE) — design

**Status:** design only (#19). Not implemented. This document scopes the work
so it is shovel-ready and so the architectural constraints are understood
before any code lands.

## Why

For rocketsmbd's high-end target (400/800GbE storage fabrics) RDMA is not a
niche: those deployments already run controlled, homogeneous fabrics —
typically **RoCEv2** on NVIDIA ConnectX-6/7 or BlueField with PFC + ECN/DCQCN,
or InfiniBand. At that scale two walls bite that the TCP path cannot clear:

1. **Single-flow TCP is core-bound** (~45 Gbps/flow). Multichannel spreads
   across cores, but the per-byte TCP/IP + copy cost still caps a host.
2. **Encryption is host-CPU-bound** (AES-GCM ~3–5 GB/s/core); saturating
   200GbE in software needs 6–8 cores doing nothing but crypto.

SMB Direct addresses (1) by moving payload with RDMA Read/Write (no TCP, no
per-packet CPU, true zero-copy NIC→NIC). It addresses (2) when paired with
NIC-offloaded link encryption (see "Encryption" below).

## Transports — pick the fabric, not "RDMA"

| Transport | Wire | Switch requirement | NIC support |
|---|---|---|---|
| InfiniBand | dedicated IB fabric | IB switches | ConnectX (IB mode) |
| **RoCEv2** | Ethernet, UDP/IP encapsulated | **lossless**: PFC + ECN/DCQCN, DCB switches | ConnectX, Intel E810, some Broadcom |
| iWARP | runs over TCP | any Ethernet switch | effectively Chelsio only |

**Primary target: RoCEv2** (what the customer base runs). iWARP is a free
bonus if we use rdma-cm + verbs (it abstracts the transport), and works on
dumb switches, but the NIC install base is tiny. InfiniBand falls out of the
same verbs code path. We program to **libibverbs + rdma-cm**, not to a
specific fabric.

## Protocol: [MS-SMBD]

SMB Direct is the binding that carries SMB2/3 over RDMA. It is a **separate
transport**, layered under the existing SMB2 dispatch:

- **Connection setup** via `rdma-cm` on **TCP port 5445** (the RDMA listener;
  445 stays the TCP listener). After CM connect, an **SMBD Negotiate**
  exchange settles credits, max send/receive sizes, and max
  fragmented/read-write sizes.
- **Two data paths:**
  - **Send/Receive** (two-sided) for SMB2 headers, metadata, and small
    payloads — each SMBD message has a small SMBD header then the SMB2 PDU.
  - **RDMA Read/Write** (one-sided) for bulk READ/WRITE payload. The SMB2
    READ/WRITE carries an **SMB2_BUFFER_DESCRIPTOR_V1** (token = rkey + addr +
    length) describing a registered remote buffer; the peer RDMAs directly
    into/out of it.
- **SMBD credit-based flow control**, separate from and in addition to SMB2
  credits. Both must be accounted.

## How it plugs into what we already have

- **Multichannel advertises it.** `FSCTL_QUERY_NETWORK_INTERFACE_INFO` already
  reports interfaces; we set the **`RDMA_CAPABLE` (0x02)** capability flag on
  RDMA NICs (today we set `RSS_CAPABLE` only). The Windows/cifs client then
  *itself* opens an SMBD channel to that interface and binds it to the session
  — the existing shared session registry + channel-binding code handles the
  bind unchanged.
- **Dispatch is reused.** Once an SMB2 PDU is reassembled off SMBD, it goes
  through the exact same `process_plain` dispatch. SMB Direct is a transport
  swap below the protocol, not a protocol fork.

## Two architectural truths to design around

### 1. RDMA is not an io_uring op — it's a second reactor

RDMA work is submitted/reaped through **libibverbs** (queue pairs, completion
queues), not io_uring. The integration:

- Each worker that owns SMBD connections also owns an **ibverbs completion
  channel**, whose **event fd is registered into the io_uring ring via
  `POLL_ADD`**. When the CQ fd signals, the worker drains the CQ
  (`ibv_poll_cq`) and advances SMBD state machines. So the two reactors
  coexist on one thread; io_uring stays the outer loop.
- Connection setup (rdma-cm) likewise exposes an event fd that we POLL_ADD.
- This keeps the "one thread, one event loop, no locks on the hot path" model.

### 2. splice zero-copy does NOT carry over — registered buffers are a prerequisite

The TCP read fast path is `splice(file→pipe→socket)` — page-cache pages move to
the socket with no userspace copy. RDMA cannot consume a pipe: every buffer it
touches must be a **registered memory region** (`ibv_reg_mr`, pinned, with
lkey/rkey). So:

- Bulk file data must live in **registered buffers** before an RDMA
  Read/Write. Options: register a pool of bulk buffers and `pread` into them
  (one copy, but RDMA then moves them zero-copy off-host), or `O_DIRECT` +
  registered buffers for cold data. Registering page-cache pages directly is
  not generally possible.
- **Therefore "registered buffers" (roadmap #14) is a hard prerequisite for
  SMB Direct, not an independent optimization.** It should land first and be
  reused here.
- Net effect: SMB Direct trades our one *socket-side* copy elimination for a
  *host→NIC* copy elimination — a much bigger win on a 200G+ link, but it does
  not stack with splice; it replaces that path for RDMA channels.

## Encryption over RDMA

The old "SMB encryption disables RDMA" rule (app-layer GCM forces payload back
through the CPU, defeating one-sided RDMA) is lifting in hardware:

- **PSP** (Google's offloaded per-connection encryption for RDMA) on
  ConnectX-7 / BlueField-3.
- **IPsec-over-RoCE** inline offload on ConnectX-6 Dx and later.
- **MACsec** at L2 (line rate on essentially all server NICs ≥ 10G).

Direction: for RDMA channels, prefer **NIC-offloaded link encryption**
(MACsec / IPsec-over-RoCE / PSP) over host AES-GCM, so confidentiality does not
re-impose the CPU wall RDMA exists to avoid. Host SMB3 GCM remains available
but, as on Windows, would force the buffered/Send path and forfeit one-sided
RDMA — document that trade rather than hide it.

## Packaging consequence

libibverbs `dlopen`s provider drivers (rdma-core), so an RDMA-enabled build is
**dynamically linked with an rdma-core dependency** — it cannot be the default
static-musl `scratch`/no-deps binary. Plan:

- Ship SMB Direct behind a Cargo **feature flag** (`rdma`), off by default.
- The default release stays static musl, TCP-only, zero deps.
- A separate `rocketsmbd-rdma` package (glibc, `Requires: rdma-core` /
  `libibverbs`) for fabrics that want it. Hardware-gated at runtime: if no
  RDMA device is present, log and run TCP-only.

## Implementation phases (when picked up)

1. **Prereq:** registered buffer pool (#14) on the TCP path; prove the
   pread→registered-buffer→send shape and the buffer lifecycle.
2. ibverbs/rdma-cm bindings behind the `rdma` feature; CM listener on 5445;
   CQ/CM event fds wired into io_uring via POLL_ADD.
3. SMBD Negotiate + Send/Recv message framing + SMBD credit FC; carry SMB2
   PDUs over Send/Recv only (small I/O correct first, no RDMA R/W yet).
4. RDMA Read/Write for bulk READ/WRITE via SMB2_BUFFER_DESCRIPTOR_V1; register
   bulk buffers; integrity + flow-control tests.
5. Advertise `RDMA_CAPABLE` in the interface FSCTL; verify cifs (`rdma` mount
   option) and Windows bind an SMBD channel to a TCP session.
6. Benchmark on a real RoCEv2 fabric vs TCP multichannel; CPU-per-GiB.
7. Encryption: validate with MACsec/IPsec-over-RoCE offload; document the
   host-GCM-forces-buffered trade.

## Honest assessment

This is the single largest item on the roadmap: a second transport stack
(verbs + rdma-cm + MR management + SMBD framing + a second credit system),
gated on specific hardware, dynamically linked. It is the right endgame for the
400/800GbE segment and the only way to genuinely beat Windows there — but it is
not the throughput strategy for everyone else. The portable TCP path
(multichannel + zero-copy splice + send_zc + the remaining io_uring levers)
remains the default and the priority for the broad install base.
