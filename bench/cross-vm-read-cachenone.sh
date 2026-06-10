#!/usr/bin/env bash
set -u
S=192.168.8.150; M=/mnt/r
mkdir -p $M; umount -l $M 2>/dev/null; sleep 1
mount -t cifs //$S/data $M -o guest,vers=3.1.1,multichannel,max_channels=8,cache=none || { echo "MOUNT FAIL"; exit 1; }
sleep 1
echo "mounted: $(grep -o 'vers=3.1.1' /proc/mounts|head -1) $(grep -o 'rsize=[0-9]*' /proc/mounts|head -1)"
echo "extra channels: $(grep -A1 'Extra Channels' /proc/fs/cifs/DebugData 2>/dev/null | grep -o 'Extra Channels: [0-9]*' | head -1)"
run() {
  local n=$1
  local s=$(date +%s.%N)
  for i in $(seq 0 $((n-1))); do dd if=$M/big$i.bin of=/dev/null bs=1M 2>/dev/null & done; wait
  local e=$(date +%s.%N)
  echo "$s $e $n" | awk '{printf "  %d readers: %.1f GB/s (%.0f Gbps)\n", $3, $3/($2-$1), $3*8/($2-$1)}'
}
echo "single stream:"; run 1
echo "parallel:"; run 4; run 8
umount -l $M 2>/dev/null
