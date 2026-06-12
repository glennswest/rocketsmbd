#!/usr/bin/env bash
# Build a self-contained SRPM (source + vendored crates) for COPR or rpmbuild.
# Run from the repo root on a Fedora host with rpm-build, rpmdevtools, cargo.
#   packaging/build-srpm.sh
# Then upload to COPR (see docs/UPSTREAM.md):
#   copr-cli build <user>/rocketsmbd ~/rpmbuild/SRPMS/rocketsmbd-*.src.rpm
set -euo pipefail

V=$(awk -F\" '/^version =/{print $2; exit}' Cargo.toml)
NAME=rocketsmbd
top=$(rpm --eval %_topdir)
mkdir -p "$top/SOURCES" "$top/SPECS"

echo "==> source tarball ($NAME-$V)"
tar caf "$top/SOURCES/$NAME-$V.tar.gz" \
    --exclude=target --exclude=.git --exclude='fuzz/target' \
    --transform "s,^\./,$NAME-$V/," .

echo "==> vendoring crates"
cargo vendor vendor >/dev/null
tar caf "$top/SOURCES/$NAME-$V-vendor.tar.xz" vendor

cp packaging/$NAME.rpmlintrc "$top/SOURCES/"
cp packaging/$NAME.spec "$top/SPECS/"
echo "==> building SRPM"
rpmbuild -bs "$top/SPECS/$NAME.spec"
ls -la "$top"/SRPMS/$NAME-$V-*.src.rpm
