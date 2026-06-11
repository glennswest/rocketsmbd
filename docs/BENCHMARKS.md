# Benchmarks

Repeatable suite: `bench/bench.sh` (run as root on a Linux host; see header
for usage). Record every run here — newest at the top of each section.
**Every performance-relevant change must be re-measured before release.**

## Method

- Loopback mount on the test host: `mount -t cifs //127.0.0.1/bench ... -o guest,vers=3.0`
- 1 GiB random file, warmed into the server's page cache (measures the SMB
  data path, not the disk)
- Reads: client cache dropped between runs (umount/remount)
- Writes: `dd conv=fsync`, 512 MiB of zeros
- Samba baseline measured on the same host, same share directory, same dd
  commands (samba 4.23.8, default config + guest share)

## Test host

`dev.g8.lo` — Fedora 43, kernel 6.17.1, x86_64, 8 cores.

## Results

### 2026-06-11 — send_zc on the buffered/encrypted send path (#15)

`IORING_OP_SEND_ZC` for buffered responses ≥ 64 KiB (encrypted reads can't
splice, so they take the buffered path). Loopback, authenticated SMB 3.1.1
`seal`, server page cache warm, client cache dropped per run, 256 MiB file:

| | per-run (MB/s) | median |
|---|---|---|
| plain `Send` (copy) | 571, 611, 590, 597 | ~594 |
| **`send_zc` (zero-copy tx)** | 620, 637, 603, 638 | **~628** |

~**6%** single-stream on loopback, no regression (256 MiB md5 verified, plain +
encrypted).

**Jumbo cross-VM (the representative test).** `smbtest-srv`→`smbtest-c1` over
the MTU-9000 internal net, authenticated SMB 3.1.1 `seal`, server cache warm.
Single stream is cipher/core-bound so the gain is small (~615→~630 MB/s), but
under **concurrency** the CPU saved on the send copy turns into throughput:

| 4 parallel encrypted streams (4 GiB total) | aggregate | server CPU | CPU/GiB |
|---|---|---|---|
| plain `Send` | ~1457 MB/s | 6.98 CPU-s | 1.71 s/GiB |
| **`send_zc`** | **~1600 MB/s** | **6.14 CPU-s** | **1.54 s/GiB** |

**+10% aggregate, −12% server CPU per GiB.** That is exactly the point of
send_zc: on a cipher-bound (encrypted) workload, freeing the send-copy CPU
turns directly into more bytes. The bigger the link and channel count, the more
the saved CPU matters. Falls back to copying `Send` on kernels < 5.19 (probed
at startup). **Note:** guest + `seal` hangs (guest sessions have no session key
to derive cipher keys) — pre-existing, tracked separately; use an authenticated
user for encryption.

### 2026-06-11 — SMB3 encryption (AES-128-GCM, v1.1.0)

Jumbo net, single client, sealed (encrypted) reads:

| | throughput |
|---|---|
| unencrypted, zero-copy splice (1 stream) | ~2.6 GB/s |
| **encrypted (AES-128-GCM), 1 stream** | **~0.65 GB/s** |
| encrypted, +aes target-feature build | ~0.70 GB/s (~7%, noise) |

AES-NI + PCLMULQDQ are detected at runtime (hardware crypto already in use).
The drop vs plaintext is the loss of zero-copy (encrypted reads buffer), not
the cipher. Aggregate encrypted throughput scales across cores via
multichannel; `send_zc` (#15) targets the remaining copy. Verified end-to-end
against cifs.ko `seal` (md5 integrity) and Windows Server 2025 (`Encrypted=True`).

### 2026-06-10 — Windows Server 2025 client interop

A real Windows Server 2025 SMB client (`smbtest-win`) against rocketsmbd:

- Negotiated **SMB 3.1.1 with signing** (`Get-SmbConnection`: Dialect 3.1.1,
  Signed=True), NTLMv2 auth — listed the share, read and wrote files. ✔
- `.NET FileStream.OpenRead` initially failed (FileStreamInformation +
  security-descriptor QUERY_INFO unsupported); **fixed in v0.4.0**, now streams.
- Read throughput ~1.8–2.1 Gbps — bound by the `vmbr0` path (MTU 1500,
  single-queue virtio), not the server (same NIC ceiling as the iperf
  finding). Scripts: `bench/win-interop.ps1`, `bench/win-read.ps1`.

### 2026-06-10 — read-path findings (linked zero-copy chain)

Investigated single-channel read headroom: one SMB channel did ~21 Gbps while
raw TCP (iperf3) did ~80 Gbps single-stream on the same jumbo path. Hypothesis
was server-side bubbles between the `splice-in → send-header → splice-out`
round-trips, so the full-read fast path now submits all three as **one
IO_LINK chain**.

Result: throughput unchanged (20.6 vs 21.0 Gbps single channel; 46 vs 47 at 8
readers), which is itself the finding — the single-channel cap is **not**
server round-trips (eliminating them changed nothing) but the SMB
request/response pipelining depth and the network. iperf streams
continuously; SMB is request/response with a bounded outstanding-read window
per channel. Takeaway: per-channel reads are network/protocol-bound, not
server-bound; aggregate scales via channels (multichannel) and faster
fabric. The linked chain is retained anyway — it cuts syscalls/CPU per read
(one submission vs three), which is the scarce resource at 400/800GbE.
Integrity verified (md5 match, server↔client, over the linked path).

### 2026-06-10 — cross-VM, real network (Proxmox)

Dedicated `smbtest` VMs on one Proxmox host (server + client, 8 vCPU each),
Fedora 43. Server `rocketsmbd` guest multichannel, `advertise_only` the test
NIC. Client mounts `vers=3.1.1,multichannel,max_channels=8`, client cache
dropped before each run, distinct 1 GiB files (traffic genuinely on the wire).

**Network matters more than anything here.** Two virtual networks compared:

| | raw TCP (iperf3) | SMB, 8 readers |
|---|---|---|
| `vmbr0`: virtio single-queue, MTU 1500 | 9 Gbps (1 or 8 streams) | 7.7 Gbps |
| `vmbr1`: virtio **multiqueue=8 + MTU 9000** | 80 Gbps (1), 53 (8) | **46.9 Gbps** |

SMB read scaling on the tuned network (jumbo + multiqueue):

| readers (channels filled) | throughput |
|---|---|
| 1 | 21.0 Gbps |
| 2 | 33.6 Gbps |
| 4 | 43.4 Gbps |
| 8 | 46.9 Gbps |

Takeaways:
- The virtual NIC, not the server, is the cross-VM ceiling. Single-queue
  virtio @1500 caps ~9 Gbps; multiqueue + jumbo takes raw TCP to ~80 Gbps
  and SMB to ~47 Gbps (≈88% of the 8-stream iperf3 ceiling).
- 7 extra channels bind over the real network; throughput scales with
  parallel readers up to the network limit.
- Loopback (below) shows 169 Gbps when there's no network limit — the
  architecture isn't the bottleneck. 400/800GbE needs SR-IOV/RDMA hardware.

Test rig (reusable): Proxmox VMs `smbtest-srv` (200, 192.168.8.161 /
10.99.0.10) and `smbtest-c1` (201, .162 / 10.99.0.11). `net0`→`vmbr0` (mgmt),
`net1`→`vmbr1` (internal, MTU 9000), both `queues=8`. Server binary at
`/usr/local/bin/rocketsmbd`, config `/etc/rocketsmbd.toml`, data `/srv/data`.

### 2026-06-10 — SMB3 multichannel (v0.3.0)

Single client mount, loopback, 8 workers, 1 GiB cached file, `max_channels=4`.

| Scenario | 1 mount, 4 parallel readers |
|---|---|
| Before multichannel (one TCP conn) | 4.7 GB/s (38 Gbps) |
| **Guest multichannel, zero-copy** | **21.1 GB/s (169 Gbps)** |

A single mount now stripes across 4 channels → 4 worker cores, a **4.5×**
jump that clears 100GbE. 1 GiB checksum verified over multichannel.
Authenticated multichannel binds correctly (NTLMv2 per channel) but signing
forces the buffered path, so signed throughput is CPU-bound (AES-CMAC),
well below the zero-copy figure — use unsigned for max throughput.

Notes:
- Needs concurrent I/O to show: a single sequential reader rides ~one
  channel (~6 GB/s). Parallel readers / deep client readahead fill all
  channels.
- Loopback is a stand-in; a real 400/800GbE NIC test (cross-VM on Proxmox)
  is the next validation.

### 2026-06-09 — multi-connection scaling (phase 3 baseline)

Loopback, 8 workers, 1 GiB cached file. Establishes that the architecture
scales to line rate across connections (see docs/TUNING.md for analysis).

| Scenario | Conns | Aggregate |
|---|---|---|
| 1 mount, 1 reader | 1 | 6.0 GB/s (48 Gbps) |
| 1 mount, 4 parallel readers | 1 | 4.7 GB/s (38 Gbps) |
| 4 mounts (`nosharesock`), 1 reader each | 4 | **12.5 GB/s (100 Gbps)** |

One TCP connection ≈ one core ≈ ~45 Gbps (zero-copy). Four connections
saturate 100 Gbps. Single-client line rate needs SMB3 multichannel (one
mount → many connections), which is the phase-3 headline.

### 2026-06-09 — v0.2.0 (auth + signing)

Unsigned guest path is unchanged from v0.1.1 (zero-copy splice reads). Signed
sessions take the **buffered** read path — an SMB2 signature covers the
response payload, which is incompatible with splicing file pages straight to
the socket — so signed reads are slower but still ~2× samba's unsigned read.

| Test | rocketsmbd unsigned | rocketsmbd signed | samba (unsigned) |
|---|---|---|---|
| 1 GiB sequential read | **5.7 GB/s** | 527 MB/s | 1.4 GB/s |
| 512 MiB sequential write | **1.0 GB/s** | 474 MB/s | 642 MB/s |

Signing cost is the AES-CMAC over each message plus losing the zero-copy
read path. Restoring zero-copy for signed reads (sign the header with a
trailer-MAC scheme, or AES-GCM transform with `splice`-friendly framing) is
phase 3.

### 2026-06-09 — v0.1.1 (frame batching, 1 MiB rsize / 4 MiB wsize)

| Test | rocketsmbd | samba 4.23 | ratio |
|---|---|---|---|
| 1 GiB sequential read | **5.8–6.2 GB/s** | 1.4 GB/s | **4.3×** |
| 512 MiB sequential write (fsync) | **836–941 MB/s** | 642 MB/s | **1.3×** |

Integrity: 1 GiB read and 128 MiB write verified byte-for-byte (cmp).
4 parallel readers: completed correctly.

### 2026-06-09 — v0.1.0 (one request in flight per connection)

| Test | rocketsmbd | samba 4.23 | ratio |
|---|---|---|---|
| 1 GiB sequential read | 5.8 GB/s | 1.4 GB/s | 4.1× |
| 512 MiB sequential write (fsync) | 446 MB/s | 642 MB/s | **0.7× (slower)** |

## Tuning findings

- **Write throughput is pipelining-bound.** cifs issues streams of `wsize`
  WRITEs; v0.1.0 served them strictly one-at-a-time (recv → pwrite → send →
  next), losing 30% to samba. Batching all complete frames per wakeup into
  one response send (v0.1.1) took writes from 446 → ~900 MB/s.
- **Big rsize hurts reads.** Advertising MaxReadSize = 4 MiB made cifs use
  rsize=4M and collapsed reads to 0.67 GB/s: fewer, larger requests defeat
  client readahead parallelism, and each 4 MiB splice fill+drain runs
  serially. With rsize=1 MiB the client keeps many READs in flight and the
  splice path hits 5.8+ GB/s. Hence `MAX_READ_TARGET = 1 MiB` while
  MaxWriteSize stays 4 MiB (bigger writes = fewer round trips = faster).
- The earlier "0.2 s for 100 MB" sha256 figure was hash-bound, not
  server-bound; use `dd` for throughput numbers.

## Known gaps / next perf work (phase 3)

- True intra-connection request concurrency (multiple zc reads in flight per
  connection; needs a pipe pool and an ordered tx queue)
- Multishot accept/recv, provided buffer rings, send_zc
- File WRITE through the ring (currently synchronous pwrite on the reactor
  thread; page-cache writes are fast, so this is not the current bottleneck)
- Small-file metadata ops benchmark vs samba (added to bench.sh; not yet
  compared)
