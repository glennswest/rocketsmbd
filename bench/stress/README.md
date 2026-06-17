# Concurrent-mount stress test

Launches `N` containers that each `mount -t cifs` the share and do verified I/O
against a running rocketsmbd, to shake out concurrency behavior unit tests
can't: lease-table contention, the cross-worker break mailbox under load,
connection-slot churn, memory scaling, and mount/teardown storms.

## Run (on the server host)

```sh
# 1. rocketsmbd listening on :445 with share "data" (path /srv/stress) and
#    user glenn/testpw123, e.g.:
#      listen="0.0.0.0:445"; oplocks=true
#      [[user]] name="glenn" password="testpw123"
#      [[share]] name="data" path="/srv/stress"
sudo rocketsmbd --config /etc/rocketsmbd.toml &

# 2. fire the fleet (needs podman; root for --privileged cifs mounts)
sudo bench/stress/run-stress.sh 100            # 100 containers, loopback
sudo bench/stress/run-stress.sh 100 192.168.8.150   # remote server
```

Each container (`client.sh`): mounts (`nosharesock` → its own connection),
waits at a **start barrier** (until the launcher drops `GO` on the share) so all
`N` clients hold their mounts at once, then writes a unique random file, reads it
back and **md5-verifies**, reads a shared file each pass (lease grant + break
churn), repeats `ITERS` times (default 3, `SZ`=8 MiB), unmounts. Exit 0 = all
I/O verified.

`run-stress.sh` builds the image once, launches `N` containers, waits for all
`N` connections to be established, releases the barrier, samples server
peak connection count + RSS, then reports `pass/fail` and whether the server is
still alive. Set `BARRIER=0` to skip the barrier (staggered mount/io/unmount).

## What to watch
- All containers exit 0 (no `VERIFY_FAIL`/`MOUNT_FAIL`), server stays alive.
- Server RSS stays bounded across runs (no per-connection / lease-table leak).
- No errors in the server log; teardown leaves no leaked leases (the
  `release_conn` path) or connection slots.

## Soak (`soak.sh`)

`soak.sh [ROUNDS] [N] [SRV] [SHARE_PATH]` loops the round `ROUNDS` times
(default 1000), appending per-round stats to `STATS_CSV`
(`round,epoch_s,pass,fail,rss_kb,peak_conns,duration_s`, default
`/tmp/soak-stats.csv`) and running `analyze-soak.sh` at the end for a leak
verdict (least-squares RSS slope + first/last-quartile means). It aborts if the
server dies and tolerates a lagging container via `BARRIER_PCT` (default 98).

### Result — 1000 × 100 (2026-06-16, dev.g8.lo, kernel 6.17, loopback)

1000 rounds, ~100k concurrent mount/teardown cycles, 17.6 h (mean 63.5s/round):

- **99,999 / 100,000 md5-verified I/O ops passed**; the one miss was a podman
  `run` launch flake (round 168), not a server or data fault.
- Server **alive the whole run** (single pid r1→r1000), zero data corruption.
- RSS 1700→1732 kB: +32 kB in the first ~180 rounds (allocator high-water) then
  flat — slope **+0.005 kB/round**, max 1736 kB. **No leak** in the
  connection-slot, lease-table, or cross-worker break paths.
