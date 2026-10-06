#!/usr/bin/env bash
# Build, lint and test every documented feature set in one go (#43).
#
#   sc-build deploy/feature-matrix.sh
#
# GitHub Actions is not used here (owner's standing practice), so this is
# the "CI" for the non-default builds: run it through sc-build before pushing
# changes to `kerberos`-, `backend-openssl`- or `ntlm`-gated code, and before a
# release. One sc-build slot runs the whole matrix. Needs the krb5 and
# OpenSSL development headers (the build box and build VMs have them).
#
# Each row runs `cargo clippy -- -D warnings` and `cargo test`; the default
# row also does the musl clippy and the aarch64 cross-check the old CI did,
# and the fuzz crate is checked. Every row runs even if an earlier one fails;
# the script exits non-zero if any did.
set -uo pipefail

rows=(
    "default||"
    "no-default-features|--no-default-features|"
    "kerberos|--features kerberos|"
    "kerberos-only|--no-default-features --features kerberos|"
    "openssl|--features backend-openssl|"
    "fips (openssl+kerberos, no NTLM)|--no-default-features --features backend-openssl,kerberos|"
)

declare -a summary
fail=0
step() { # name, command...
    local name=$1
    shift
    if out=$("$@" 2>&1); then
        local tests
        tests=$(grep -E '^test result:' <<<"$out" | awk '{p+=$4; f+=$6} END {if (NR) printf " (%d passed, %d failed)", p, f}')
        summary+=("ok    $name$tests")
    else
        summary+=("FAIL  $name")
        fail=1
        echo "---- $name failed:"
        grep -E '^(error|warning: unused)|^test .* FAILED|panicked|^---- ' <<<"$out" | head -40
    fi
}

for row in "${rows[@]}"; do
    IFS='|' read -r name flags _ <<<"$row"
    read -ra f <<<"$flags"
    echo "==> $name: ${flags:-(default features)}"
    step "$name: clippy" cargo clippy -q "${f[@]}" -- -D warnings
    step "$name: test" cargo test "${f[@]}"
done

echo "==> default: musl + aarch64 + fuzz crate"
step "default: clippy x86_64-musl" cargo clippy -q --target x86_64-unknown-linux-musl -- -D warnings
step "default: check aarch64-musl" cargo check -q --target aarch64-unknown-linux-musl
step "fuzz crate: check" cargo check -q --manifest-path fuzz/Cargo.toml

echo
echo "==== feature matrix"
printf '%s\n' "${summary[@]}"
exit $fail
