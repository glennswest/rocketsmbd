#!/usr/bin/env bash
# rocketsmbd benchmark suite. Run as root on a Linux host.
#
# Usage:
#   bench/bench.sh [binary] [sharedir] [mountpoint]
#
# Starts the server on 127.0.0.1:445 with a scratch config, mounts it via
# cifs.ko, runs read/write/parallel/metadata benchmarks plus integrity
# checks, prints a results block suitable for docs/BENCHMARKS.md, and cleans
# up. Requires: cifs-utils, a free port 445.
set -u

BIN=${1:-./target/release/rocketsmbd}
SHARE=${2:-/srv/rsmbd-bench}
MNT=${3:-/mnt/rsmbd-bench}
CFG=$(mktemp /tmp/rsmbd-bench-XXXX.toml)
LOG=/tmp/rsmbd-bench.log

cleanup() {
    cd /
    umount "$MNT" 2>/dev/null
    pkill -x rocketsmbd 2>/dev/null
    rm -f "$CFG"
}
trap cleanup EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

[ -x "$BIN" ] || fail "binary $BIN not found (build with: cargo build --release)"
mkdir -p "$SHARE" "$MNT"
ss -tlnp | grep -q ':445 ' && fail "port 445 busy"

cat > "$CFG" <<EOF
listen = "0.0.0.0:445"
workers = 0
log_level = 0
[[share]]
name = "bench"
path = "$SHARE"
EOF

# Test file: 1 GiB of random data, warmed into the server page cache so the
# benchmark measures the SMB data path, not the disk.
if [ ! -f "$SHARE/big.bin" ] || [ "$(stat -c%s "$SHARE/big.bin")" != "1073741824" ]; then
    echo "creating 1GiB test file..."
    dd if=/dev/urandom of="$SHARE/big.bin" bs=1M count=1024 status=none
fi
cat "$SHARE/big.bin" > /dev/null

"$BIN" --config "$CFG" > "$LOG" 2>&1 &
sleep 1
grep -q listening "$LOG" || fail "server did not start: $(cat "$LOG")"

mount -t cifs //127.0.0.1/bench "$MNT" -o guest,vers=3.0 || fail "mount"

echo "== rocketsmbd bench | $(date -u +%F) | $(uname -r) | $(nproc) cores =="
echo "mount: $(grep "$MNT" /proc/mounts | grep -o 'rsize=[0-9]*,wsize=[0-9]*')"

bw() { # label, dd output on stderr
    awk -v l="$1" 'END { print "  " l ": " $(NF-1) " " $NF }'
}

echo "-- sequential read (1 GiB, cold client cache) --"
for i in 1 2; do
    umount "$MNT"; mount -t cifs //127.0.0.1/bench "$MNT" -o guest,vers=3.0
    dd if="$MNT/big.bin" of=/dev/null bs=1M 2>&1 | tail -1 | bw "run$i"
done

echo "-- sequential write (512 MiB, fsync) --"
for i in 1 2; do
    dd if=/dev/zero of="$MNT/w.bin" bs=1M count=512 conv=fsync 2>&1 | tail -1 | bw "run$i"
done
rm -f "$MNT/w.bin"

echo "-- parallel read (4 streams x 1 GiB) --"
umount "$MNT"; mount -t cifs //127.0.0.1/bench "$MNT" -o guest,vers=3.0
START=$(date +%s.%N)
for i in 1 2 3 4; do dd if="$MNT/big.bin" of=/dev/null bs=1M 2>/dev/null & done
wait $(jobs -p | grep -v "$(pgrep -x rocketsmbd)") 2>/dev/null
END=$(date +%s.%N)
echo "  aggregate: $(echo "$START $END" | awk '{printf "%.1f GB/s", 4/($2-$1)}')"

echo "-- small file metadata (create+write+delete 1000 files) --"
mkdir -p "$MNT/meta"
START=$(date +%s.%N)
for i in $(seq 1 1000); do echo x > "$MNT/meta/f$i"; done
for i in $(seq 1 1000); do rm "$MNT/meta/f$i"; done
END=$(date +%s.%N)
rmdir "$MNT/meta"
echo "  2000 ops: $(echo "$START $END" | awk '{printf "%.0f ops/s", 2000/($2-$1)}')"

echo "-- integrity --"
cmp "$SHARE/big.bin" "$MNT/big.bin" && echo "  read: OK"
dd if=/dev/urandom of=/tmp/wi.bin bs=1M count=128 status=none
cp /tmp/wi.bin "$MNT/wi.bin"
cmp /tmp/wi.bin "$SHARE/wi.bin" && echo "  write: OK"
rm -f "$MNT/wi.bin" /tmp/wi.bin

echo "== done =="
