#!/bin/bash
# Concurrent-mount stress test: launch N containers that each mount the share
# and do verified I/O against a running rocketsmbd. Run on the server host
# (clients use --network=host → SRV=127.0.0.1) or point SRV at a remote server.
#
#   run-stress.sh [N] [SRV] [SHARE_PATH]
#     N           number of client containers (default 100)
#     SRV         server address reachable from the containers (default 127.0.0.1)
#     SHARE_PATH  server-side path of the "data" share, for seeding shared.bin
#                 (default /srv/stress; only used when run on the server host)
#
# Assumes rocketsmbd is already listening on SRV:445 with share "data" and user
# glenn/testpw123. Reports pass/fail and samples server CPU/RSS/connections.
set -u
N=${1:-100}
SRV=${2:-127.0.0.1}
SHARE_PATH=${3:-/srv/stress}
HERE=$(cd "$(dirname "$0")" && pwd)

# Seed a shared file every client reads (concurrent lease grants + breaks).
if [ -d "$SHARE_PATH" ]; then
    dd if=/dev/urandom of="$SHARE_PATH/shared.bin" bs=1M count=16 status=none 2>/dev/null || true
fi

echo "==> building client image"
podman build -q -t rsmbd-stress -f "$HERE/Containerfile" "$HERE" >/dev/null

srvpid=$(pgrep -x rocketsmbd | head -1)
echo "==> server pid=$srvpid; launching $N containers against //$SRV/data"
for i in $(seq 1 "$N"); do
    podman run -d --name "rss-$i" --privileged --network=host \
        -e SRV="$SRV" -e SMBUSER=glenn -e SMBPASS=testpw123 -e ID="$i" \
        rsmbd-stress >/dev/null
done

# Sample server while the fleet runs.
if [ -n "$srvpid" ]; then
    conns=$(ss -tn state established "( sport = :445 )" 2>/dev/null | grep -c ':445')
    rss=$(awk '/VmRSS/{print $2" "$3}' /proc/"$srvpid"/status 2>/dev/null)
    echo "==> mid-run: established :445 conns=$conns  server RSS=$rss"
fi

echo "==> waiting for completion"
pass=0
fail=0
for i in $(seq 1 "$N"); do
    code=$(podman wait "rss-$i" 2>/dev/null)
    if [ "$code" = "0" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "  FAIL container $i exit=$code: $(podman logs "rss-$i" 2>&1 | tail -1)"
    fi
done

alive=$([ -n "$srvpid" ] && kill -0 "$srvpid" 2>/dev/null && echo YES || echo NO)
echo "RESULT: $pass passed, $fail failed (of $N); server alive=$alive"

echo "==> cleanup"
podman rm -f $(for i in $(seq 1 "$N"); do echo "rss-$i"; done) >/dev/null 2>&1
