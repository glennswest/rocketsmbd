#!/bin/bash
# Kerberos sec=krb5 end-to-end test for rocketsmbd (#37).
#
# Drives: build (--features kerberos) -> run server with a keytab -> kinit ->
# cifs mount -o sec=krb5 -> md5-verified write/read -> teardown. Run on the
# SMB server host (dev.g8.lo) with a reachable KDC (krb5.g8.lo).
#
# Prereqs on the KDC (krb5.g8.lo), once:
#   kadmin.local -q "addprinc -randkey cifs/dev.g8.lo@G8.LO"
#   kadmin.local -q "ktadd -k /tmp/rocketsmbd.keytab cifs/dev.g8.lo@G8.LO"
#   kadmin.local -q "addprinc -pw $USER_PW alice@G8.LO"
#   scp /tmp/rocketsmbd.keytab dev.g8.lo:/etc/rocketsmbd.keytab
#
# Env overrides: REALM, KDC, SPN_HOST, SHARE_DIR, KEYTAB, USER, USER_PW, MNT.
set -euo pipefail

REALM=${REALM:-G8.LO}
SPN_HOST=${SPN_HOST:-$(hostname -f)}
SHARE_DIR=${SHARE_DIR:-/srv/krbshare}
KEYTAB=${KEYTAB:-/etc/rocketsmbd.keytab}
USER=${USER_PRINC:-alice}
USER_PW=${USER_PW:-testpw}
MNT=${MNT:-/mnt/krbtest}
PORT=${PORT:-445}
CFG=$(mktemp /tmp/rocketsmbd-krb.XXXX.toml)
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v kinit >/dev/null || fail "krb5-workstation (kinit) not installed"
[ -f "$KEYTAB" ] || fail "keytab $KEYTAB missing — create it on the KDC (see header)"
klist -k "$KEYTAB" | grep -q "cifs/$SPN_HOST@$REALM" || fail "keytab lacks cifs/$SPN_HOST@$REALM"

echo "== build --features kerberos =="
cargo build --release --features kerberos

mkdir -p "$SHARE_DIR" "$MNT"
cat > "$CFG" <<EOF
listen = "0.0.0.0:$PORT"
auth = "kerberos"
log_level = 1
[kerberos]
keytab = "$KEYTAB"
spn = "cifs/$SPN_HOST"
[[share]]
name = "data"
path = "$SHARE_DIR"
EOF

echo "== start server =="
./target/release/rocketsmbd --config "$CFG" &
SRV=$!
trap 'kill $SRV 2>/dev/null; umount "$MNT" 2>/dev/null; rm -f "$CFG"' EXIT
sleep 1

echo "== kinit $USER@$REALM =="
echo "$USER_PW" | kinit "$USER@$REALM"

echo "== mount -o sec=krb5 =="
mount -t cifs "//$SPN_HOST/data" "$MNT" -o sec=krb5,vers=3.1.1,cruid="$(id -u)"
klist | grep -q "cifs/$SPN_HOST" && echo "  service ticket acquired"

echo "== md5-verified write/read =="
dd if=/dev/urandom of=/tmp/krb-src bs=1M count=64 status=none
cp /tmp/krb-src "$MNT/krb-file"
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
A=$(md5sum < /tmp/krb-src | cut -d' ' -f1)
B=$(md5sum < "$MNT/krb-file" | cut -d' ' -f1)
[ "$A" = "$B" ] || fail "md5 mismatch ($A != $B)"
echo "  md5 OK ($A)"

echo "PASS: sec=krb5 mount + I/O verified against realm $REALM"
