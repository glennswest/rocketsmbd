#!/usr/bin/env bash
# Live Kerberos tests against a private MIT KDC (#38), unprivileged:
#
#   sc-build deploy/krb5-local-test.sh
#
# Builds a throwaway realm under $TMPDIR (KDC on a free high port, database,
# service keytab for cifs/rsmbd.test, user alice with a ticket), then runs
# tests/krb5_live.rs with `--features kerberos` (and the NTLM-free and FIPS
# builds): single-leg AP-REQ, a DCE-style multi-leg exchange, and a broken
# second leg, each through process_frame with a real GSS initiator. Needs
# krb5-server and krb5-workstation (the build box and build VMs have them).
# The KDC is stopped and everything removed on exit.
set -euo pipefail

realm=RSMBD.TEST
host=rsmbd.test
t=$(mktemp -d "${TMPDIR:-/tmp}/krb5test.XXXXXX")
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
kdc_pid=
cleanup() {
    [ -n "$kdc_pid" ] && kill "$kdc_pid" 2>/dev/null || true
    rm -rf "$t"
}
trap cleanup EXIT

export KRB5_CONFIG=$t/krb5.conf KRB5_KDC_PROFILE=$t/kdc.conf
export KRB5CCNAME=FILE:$t/ccache KRB5_KTNAME=$t/service.keytab KRB5RCACHEDIR=$t
cat >"$KRB5_CONFIG" <<CONF
[libdefaults]
    default_realm = $realm
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false
    udp_preference_limit = 1
[realms]
    $realm = {
        kdc = 127.0.0.1:$port
    }
[domain_realm]
    $host = $realm
CONF
cat >"$KRB5_KDC_PROFILE" <<CONF
[kdcdefaults]
    kdc_ports = $port
    kdc_tcp_ports = $port
[realms]
    $realm = {
        database_name = $t/principal
        key_stash_file = $t/stash
        acl_file = $t/kadm5.acl
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
CONF
: >"$t/kadm5.acl"

echo "==> realm $realm, KDC on 127.0.0.1:$port"
kdb5_util create -s -r "$realm" -P "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" >/dev/null
pw=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
kadmin.local -r "$realm" -q "addprinc -randkey cifs/$host" >/dev/null
kadmin.local -r "$realm" -q "ktadd -k $KRB5_KTNAME cifs/$host" >/dev/null
kadmin.local -r "$realm" -q "addprinc -pw $pw alice" >/dev/null
krb5kdc -n -r "$realm" &
kdc_pid=$!
for _ in $(seq 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
    sleep 0.1
done
echo "$pw" | kinit alice >/dev/null
klist | sed -n '1,4p'

fail=0
for flags in "--features kerberos" "--no-default-features --features kerberos" \
             "--no-default-features --features backend-openssl,kerberos"; do
    echo "==> cargo test $flags --test krb5_live"
    # shellcheck disable=SC2086
    out=$(RUST_LOG=debug RSMBD_KRB5_TEST=1 RSMBD_KRB5_HOST=$host cargo test $flags --test krb5_live -- --test-threads=1 2>&1) || fail=1
    grep -E '^test |^test result|panicked|assert|^error' <<<"$out" || echo "$out" | tail -30
done
exit $fail
