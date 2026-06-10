#!/usr/bin/env bash
set -u
cd /root/rocketsmbd
for m in /mnt/rsmbd /mnt/a /mnt/b /mnt/c /mnt/d; do umount -l $m 2>/dev/null; done
kill -9 $(pgrep -x rocketsmbd) 2>/dev/null; sleep 2
echo "stale procs: $(pgrep -x rocketsmbd | wc -l)"
agg() { # label cfg mountopts
  local label="$1" cfg="$2" opts="$3"
  kill -9 $(pgrep -x rocketsmbd) 2>/dev/null; sleep 1
  nohup ./target/release/rocketsmbd --config $cfg > /tmp/rsmbd.log 2>&1 &
  sleep 1.5
  cat /srv/rsmbd-test/big.bin >/dev/null
  mount -t cifs //127.0.0.1/data /mnt/rsmbd -o $opts || { echo "$label: MOUNT FAIL"; return; }
  local S=$(date +%s.%N)
  for i in 1 2 3 4; do dd if=/mnt/rsmbd/big.bin of=/dev/null bs=1M 2>/dev/null & done; wait
  local E=$(date +%s.%N)
  local bound=$(grep -c "channel bound" /tmp/rsmbd.log)
  echo "$S $E $label $bound" | awk '{printf "%s: %.1f GB/s (%.0f Gbps), channels bound=%s\n", $3, 4/($2-$1), 4*8/($2-$1), $4}'
  cmp -s /srv/rsmbd-test/big.bin /mnt/rsmbd/big.bin && echo "   integrity OK" || echo "   INTEGRITY FAIL"
  umount -l /mnt/rsmbd 2>/dev/null
}
agg "guest-mc-zerocopy" /root/mc.toml      "guest,vers=3.1.1,multichannel,max_channels=4"
agg "auth-mc-signed"    /root/mc-auth.toml "username=glenn,password=testpw123,vers=3.1.1,multichannel,max_channels=4"
kill -9 $(pgrep -x rocketsmbd) 2>/dev/null
