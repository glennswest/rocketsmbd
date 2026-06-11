# Tuning for high-speed networks (10/25/40/100GbE)

Short version: rocketsmbd already scales to line rate **across connections**.
The work to fill a fast link from a *single client* is SMB3 multichannel
(in progress). Jumbo frames and TCP tuning are deployment knobs that help at
the margin.

## What the numbers say

Loopback on the dev host (kernel 6.17, 8 cores, 1 GiB cached file):

| Scenario | Connections | Aggregate |
|---|---|---|
| 1 client mount, 1 reader | 1 | 6.0 GB/s (48 Gbps) |
| 1 client mount, 4 parallel readers | 1 | 4.7 GB/s (38 Gbps) |
| 4 mounts (`nosharesock`), 1 reader each | 4 | **12.5 GB/s (100 Gbps)** |

Two takeaways:

1. **One TCP connection ≈ one core ≈ ~45 Gbps**, even with zero-copy. This is
   a fundamental property of TCP, not a server limit — a single flow is
   processed on a single core at both ends.
2. **N connections scale linearly across workers.** Four connections hit
   100 Gbps on loopback. Eight workers on `SO_REUSEPORT` means eight
   independent rings, each pinned to a core by the kernel's accept balancing.

Notice that 4 readers on *one* connection (4.7 GB/s) is *slower* than a single
reader (6.0): they contend on one connection, which today serializes requests
(one in flight). That's the motivation for intra-connection concurrency
(phase 3) and, more importantly, multichannel.

## How to get full line rate today

Until multichannel lands, a single client fills a fast link by using multiple
connections:

```sh
# Force separate TCP connections per mount (don't share the socket):
mount -t cifs //server/data /mnt/a -o guest,vers=3.0,nosharesock
mount -t cifs //server/data /mnt/b -o guest,vers=3.0,nosharesock
# ...striping I/O across /mnt/a, /mnt/b, ... uses multiple server cores.
```

Set `workers` in `rocketsmbd.toml` to the core count (or leave at `0` for
auto). More workers than cores doesn't help; fewer caps aggregate throughput.

## Jumbo frames

Jumbo frames (MTU 9000 vs the 1500 default) are an **OS/NIC setting**, not an
application option — rocketsmbd speaks TCP and the kernel does segmentation.
The server already negotiates everything that matters above the MTU: the
SMB2 LARGE_MTU capability, 1 MiB reads / 4 MiB writes, `TCP_NODELAY`, and
zero-copy `splice` on the read path.

Enable jumbo frames on a real fabric and they help by cutting packet count
~6× (≈8960-byte payloads vs 1448), which lowers per-packet CPU, interrupt
rate, and softirq load — useful headroom at 25GbE and above. Caveats:

- **Every hop must agree**: both NICs and every switch in the path need
  MTU 9000, or you get silent blackholing / PMTU fallback.
- Modern NICs offload most of the per-packet cost anyway (TSO/GSO on TX,
  GRO/LRO on RX), so the win is smaller than it once was — real, but mostly
  as CPU headroom rather than raw throughput.
- **Loopback is already 65536**, so jumbo frames don't change local
  benchmarks; measure on the real NIC.

```sh
ip link set dev <nic> mtu 9000      # both ends; switch ports too
```

## TCP buffers

Linux autotunes socket buffers between `net.ipv4.tcp_rmem` / `tcp_wmem`
limits. On a high bandwidth-delay-product link (fast NIC × non-trivial RTT)
raise the ceilings so autotuning can open the window:

```sh
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728
sysctl -w net.ipv4.tcp_rmem="4096 131072 134217728"
sysctl -w net.ipv4.tcp_wmem="4096 131072 134217728"
```

On loopback (tiny BDP) this is moot; it matters on real links with RTT.

## NIC / system

- **RSS / multiqueue**: ensure the NIC spreads flows across queues/cores
  (`ethtool -L <nic> combined <ncores>`). With multichannel, each SMB
  connection should land on a different queue.
- **IRQ affinity**: pin NIC IRQs across cores (or run `irqbalance`).
- **CPU governor**: `performance` governor for latency-sensitive throughput.
- **Worker pinning**: planned (phase 3) — pin each worker to the core whose
  NIC queue it drains.

## Read-ahead

There are two layers, and we use both:

- **Client read-ahead** (not server-controlled): the cifs/Windows client
  issues reads ahead of the application using `rsize` and its credit window.
  Deeper readahead = more outstanding reads = more channels filled. This is
  what turns multichannel into throughput; a single shallow reader won't.
- **Server read-ahead** (implemented): on opening a file for reading we issue
  `posix_fadvise(POSIX_FADV_SEQUENTIAL)`, which doubles the kernel's readahead
  window and prefetches pages ahead of each splice. For **cold-storage**
  serving (NVMe, not page-cache-warm) this keeps the splice pipe fed so reads
  aren't bound by per-request disk latency. For warmed benchmarks it's a no-op.
  A future refinement is an explicit `readahead(2)`/`IORING_OP_FADVISE` ahead
  of the next splice offset for very large sequential streams.

## What else boosts throughput

Implemented:
- **Multichannel** — N connections per mount across N cores (the big one).
- **Zero-copy reads** — `splice` file→pipe→socket, no userspace copy.
- **Lock-free read I/O** — the session lock is held only to dup the fd, so
  reads on different channels run truly in parallel.
- **Server read-ahead** — `POSIX_FADV_SEQUENTIAL`.
- **send_zc (`MSG_ZEROCOPY`)** on the buffered send path (≥ 64 KiB responses,
  e.g. encrypted reads); kernel pins tx pages instead of copying. Probed at
  startup; copying `Send` on kernels < 5.19. See the bullet below for numbers.
- **Frame batching, TCP_NODELAY, 4 MiB writes, 1 MiB reads** (see other entries).

Planned, in rough value order for 400/800GbE:
- **SQPOLL** — kernel-side submission-queue polling removes a syscall per
  batch; meaningful at high IOPS / many channels.
- **Registered files + registered buffers** (`IORING_REGISTER_*`) — drops
  per-op fd refcount and buffer-pinning overhead on the hot path.
- **Intra-connection read concurrency** — multiple splices in flight per
  connection (pool of pipes) so even one channel exceeds ~45 Gbps and fewer
  channels are needed to fill the link.
- **Worker core-pinning aligned to NIC RSS queues** — each worker drains the
  queue its flows land on; avoids cross-core cache traffic.
- **Signed/encrypted zero-copy** — keep the splice path under signing/GCM via
  a trailer-MAC or offload scheme, so security doesn't force buffered reads.
- **SMB Direct (RDMA)** — the endgame for 100GbE+; Windows uses it to bypass
  TCP/CPU entirely. Large effort (RDMA verbs, separate transport).

## Encryption performance (AES-128-GCM)

The crypto hot path is AES (AES-NI: `AESENC*`) + GHASH (PCLMULQDQ). RustCrypto
detects both at **runtime** (`cpufeatures`), so the shipped generic/musl binary
already uses hardware AES on any capable CPU — no special build needed.

Measured (jumbo net, single encrypted read): **~653 MB/s** runtime-detected vs
**~700 MB/s** built with `-C target-feature=+aes,+pclmulqdq` (~7%, within
noise). The bottleneck is **not the cipher** (AES-NI does multiple GB/s/core)
but the loss of zero-copy: encrypted reads buffer (file → userspace →
encrypt-in-place → send) instead of `splice`. So:

- **AES-NI is already on** — don't compile-pin it for the portable release
  (it would `SIGILL` on pre-2010 CPUs for ~7%). For a host-specific build:
  `RUSTFLAGS="-C target-cpu=native" cargo build --release`.
- **Scale encrypted throughput across cores with multichannel** — each channel
  encrypts on its own core; aggregate scales like plaintext.
- **`send_zc`** (landed, #15) sends buffered responses ≥ 64 KiB via
  `MSG_ZEROCOPY` (the kernel pins tx pages instead of copying). ~6% on a
  loopback single stream; the larger win is CPU saved per send under
  many-channel load, which frees cores for the cipher. Auto-detected; copying
  `Send` on kernels < 5.19.

## Comparison vs other SMB servers

- **vs Samba** (measured, same host): ~4× on unsigned sequential reads
  (5.7 GB/s vs 1.4), ~1.3× on writes. See results above.
- **vs Windows Server SMB3** (reference, not yet measured head-to-head):
  Windows is the multichannel reference implementation and reaches near
  line-rate on 100GbE with RSS multichannel, and beyond with SMB Direct/RDMA.
  Our unsigned multichannel hit 169 Gbps single-mount on loopback, which is
  in the same class for the TCP zero-copy path; the gap at the very top end
  is RDMA (SMB Direct), which we don't implement yet. A real head-to-head
  needs a Windows Server VM on the same fabric — see below.

### Running a Windows Server head-to-head

To compare on equal footing (same client, same NIC/fabric):
1. Stand up a Windows Server eval VM on the Proxmox host (`vmbr0`), enable
   the File Server role, share an NVMe-backed folder.
2. From a Linux client VM, `mount -t cifs` both servers with identical
   `vers=3.1.1,multichannel,max_channels=N` and run the same `fio`/`dd`
   workload against each.
3. Compare aggregate GB/s at matched channel counts; watch server CPU
   (Windows offloads more to the NIC, so CPU-per-GB is the interesting axis).

RDMA-capable NICs would let both use SMB Direct; without RDMA the comparison
is the pure TCP multichannel path, which is where rocketsmbd is strongest.
