#!/bin/bash
# One stress client (runs inside a container): mount the share, then loop
# write-unique → read-back → md5-verify, plus a shared-file read each pass (to
# churn leases/breaks under concurrency). Exit 0 = all I/O verified.
set -u
: "${SRV:?need SRV}" "${SMBUSER:?}" "${SMBPASS:?}" "${ID:?}"
ITERS=${ITERS:-3}
SZ=${SZ:-8} # MiB per file
M=/mnt/smb
mkdir -p "$M"

if ! mount -t cifs "//$SRV/data" "$M" \
    -o "username=$SMBUSER,password=$SMBPASS,vers=3.1.1,nosharesock"; then
    echo "MOUNT_FAIL id=$ID"
    exit 2
fi
trap 'umount "$M" 2>/dev/null' EXIT

# Start barrier: stay mounted but idle until the launcher drops GO on the share,
# so all N clients hold their mounts simultaneously (real concurrency, not a
# staggered sequence of quick mount/io/unmount cycles). Bounded wait.
if [ "${BARRIER:-1}" = "1" ]; then
    for _ in $(seq 1 600); do
        [ -e "$M/GO" ] && break
        sleep 0.1
    done
fi

dd if=/dev/urandom of=/tmp/u bs=1M count="$SZ" status=none
SRC=$(md5sum /tmp/u | cut -d' ' -f1)

for k in $(seq 1 "$ITERS"); do
    f="$M/u-$ID-$k.bin"
    if ! cp /tmp/u "$f"; then
        echo "WRITE_FAIL id=$ID k=$k"
        exit 3
    fi
    GOT=$(md5sum "$f" | cut -d' ' -f1)
    if [ "$SRC" != "$GOT" ]; then
        echo "VERIFY_FAIL id=$ID k=$k src=$SRC got=$GOT"
        exit 4
    fi
    cat "$M/shared.bin" >/dev/null 2>&1 # shared read: lease grant + break churn
    rm -f "$f"
done
echo "OK id=$ID"
exit 0
