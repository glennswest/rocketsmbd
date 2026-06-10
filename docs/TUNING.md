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

## Roadmap to single-client line rate

- **SMB3 multichannel** (in progress): the client opens N connections to one
  share and stripes I/O across them automatically — this is how Windows and
  Samba fill 100GbE from one mount. rocketsmbd advertises the capability,
  reports its interfaces via `FSCTL_QUERY_NETWORK_INTERFACE_INFO`, and accepts
  session binding.
- **Intra-connection concurrency**: pipeline multiple reads in flight on a
  single connection so one connection exceeds the current ~45 Gbps ceiling.
- **send_zc / registered buffers**: lower CPU per byte on the send path,
  freeing cores for more flows.
