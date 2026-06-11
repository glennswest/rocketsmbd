# Testing & Benchmarking

How rocketsmbd is tested, the scripts used, and a log of what each test found
(including failures and their fixes). Throughput numbers live in
[BENCHMARKS.md](BENCHMARKS.md); this file is the *method and history*.

## Unit / integration tests (`cargo test`)

22 tests, OS-independent (the protocol layer parses/builds bytes; only the
io_uring reactor is Linux-gated). They drive `process_frame` and assert on the
wire bytes. Highlights:

- Full session exchange: negotiate → session-setup → tree-connect → create →
  write → read → query-directory, against a temp share.
- NTLMv2 auth + signing: challenge/response, wrong-password reject, unsigned-
  request reject, response-signature verify.
- SMB 3.1.1 preauth integrity + signing-key derivation, recomputed
  independently from the transmitted bytes.
- Crypto vectors (HMAC, AES-CMAC, NT hash, KDF), wire round-trips, path
  traversal rejection, handle-table generation safety.

Run: `cargo test` (anywhere); `cargo clippy --target x86_64-unknown-linux-musl
-- -D warnings`.

## Integration scripts (`bench/`)

| Script | What it does |
|---|---|
| `bench.sh` | Full local suite: start server, cifs mount, sequential/parallel/metadata/integrity. |
| `loopback-multichannel.sh` | Guest + authenticated multichannel on loopback, integrity. |
| `cross-vm-read.sh` | Mount over a real NIC, drop client cache, parallel readers on distinct files (traffic genuinely on the wire). |
| `cross-vm-read-cachenone.sh` | Same but `cache=none` — kept as a cautionary example (it cripples readahead; see below). |
| `net-iperf.sh` | Raw TCP ceiling (iperf3) between two hosts — run this first. |
| `win-interop.ps1` | Windows SMB client: `net use`, dir, read, write, `Get-SmbConnection` (dialect/signing). |
| `win-read.ps1` | Windows `.NET` `FileStream` streamed read throughput. |

## Environments

- **Loopback** on a Linux host — server-bound measurement, no network limit.
- **Cross-VM** on Proxmox: dedicated `smbtest-srv`/`smbtest-c1` VMs, 8→32 vCPU,
  32 GB RAM, on an internal **jumbo (MTU 9000) + multiqueue** bridge `vmbr1`.
- **Windows client**: `smbtest-win` (Windows Server 2025) for interop + a real
  Windows SMB client.

## Test log — findings, failures, fixes

### Multichannel scales across cores
4 separate connections hit 100 Gbps on loopback; a single mount with
multichannel hit 169 Gbps (4 channels). One TCP connection ≈ one core ≈
~45 Gbps. → multichannel implemented (v0.3).

### `cache=none` cripples reads (method failure)
`cross-vm-read-cachenone.sh` capped at ~10 Gbps regardless of channels: the
mount option disables client readahead, so reads go synchronous and channels
can't fill. **Fix the test, not the server**: use default caching + drop the
client cache (`echo 3 > /proc/sys/vm/drop_caches`) before reading distinct
files. `cross-vm-read.sh` does this.

### Virtual NIC is the cross-VM ceiling
`net-iperf.sh` showed single-queue virtio @ MTU 1500 caps ~9 Gbps (1 *or* 8
streams). After enabling **multiqueue + jumbo (MTU 9000)** on an internal
bridge, raw TCP hit 80 Gbps (1 stream) and rocketsmbd multichannel hit
~47 Gbps (8 readers, ~88% of the iperf 8-stream ceiling). The server was never
the bottleneck. See TUNING.md.

### Linked zero-copy read chain — no throughput change, lower CPU
Hypothesis: single-channel reads (21 Gbps) lag raw TCP (80) due to server
round-trips. Submitting splice-in → send → splice-out as one IO_LINK chain
changed throughput by ~0% → the cap is SMB request/response pipelining + the
network, not server round-trips. Kept anyway (fewer syscalls/CPU per read).
Integrity verified by md5 (server↔client) over the linked path.

### Windows Server 2025 client interop — verified + a bug fixed
`win-interop.ps1`: a real Windows client negotiated **SMB 3.1.1 with signing**,
authenticated via NTLMv2, listed the share, and **read and wrote** files. ✔

`win-read.ps1` (`.NET FileStream`) initially **failed**:
`"The specified server cannot perform the requested operation."` Reproduced
with `log_level = 2`; the server logged two unsupported QUERY_INFO requests:

- `info_type=1 class=22` = **FileStreamInformation** → returned NOT_SUPPORTED.
- `info_type=3` = **security-descriptor query** → returned ACCESS_DENIED.

**Fix** (v0.4.0): FileStreamInformation now returns the default `::$DATA`
stream entry (none for directories); security queries return a minimal
self-relative descriptor (Administrators owner/group, Everyone-full DACL — we
don't enforce ACLs but clients query the descriptor on open). `.NET FileStream`
now opens and streams correctly. Tracked as a GitHub issue.

### Concurrent multi-stream from Windows
`win-multistream.ps1` runs N read + M write streams from the Windows client
**concurrently** (PowerShell background jobs) against rocketsmbd and reports
aggregate. 4 reads + 4 writes all run and complete together; throughput is
~2–4 Gbps, again the `vmbr0` (MTU 1500, single-queue) ceiling shared across
streams — not the server. (Harness caveat: PowerShell `Receive-Job` only
tallies ~half the streams' byte counts reliably; the streams still all run, so
the real aggregate is roughly 8 GiB / wall-time.) Putting the Windows VM on the
jumbo/multiqueue bridge (virtio-win NIC on `vmbr1`) is the follow-up to scale
it like the Linux client (47 Gbps).

### "1.3 GB/s" explained
A Windows `.NET`/copy read measured ~1.8–2.1 Gbps over `vmbr0` (MTU 1500,
single-queue). That is the **network path**, not the server — the same NIC
ceiling as the iperf finding. On the jumbo/multiqueue bridge the same client
work would scale with the link. Putting the Windows client on the jumbo NIC
(virtio-win driver) is the follow-up.
