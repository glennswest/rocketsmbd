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
