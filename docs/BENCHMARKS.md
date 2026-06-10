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
