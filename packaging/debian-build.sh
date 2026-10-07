#!/usr/bin/env bash
# Build the Debian source + binary packages from packaging/debian/ the way a
# Debian builder would (#23), in a rootless podman `debian:sid` container:
#   sc-build 'packaging/debian-build.sh [REF]'      # REF defaults to HEAD
# - rocketsmbd_<v>.orig.tar.gz        = `git archive REF`
# - rocketsmbd_<v>.orig-vendor.tar.xz = `cargo vendor` of REF's Cargo.lock
#   (3.0 (quilt) component tarball, unpacked at vendor/)
# - debian/ = this checkout's packaging/debian/
# then dpkg-buildpackage (offline build + cargo test), lintian over the
# .changes, and an install test: the rocketsmbd user exists and the shipped
# /etc/rocketsmbd.toml passes `rocketsmbd --check`.
# Exits non-zero on a build failure, a lintian error, or a failed install test.
set -euo pipefail

ref=${1:-HEAD}
name=rocketsmbd
here=$PWD
work=$here/tmp/debian-build
rm -rf "$work"; mkdir -p "$work"

v=$(git show "$ref:Cargo.toml" | awk -F'"' '/^version =/ && !n++{print $2}')
debv=$(sed -n '1s/^[^(]*(\([^)]*\)).*/\1/p' packaging/debian/changelog)
[ "${debv%-*}" = "$v" ] || { echo "debian/changelog is $debv, Cargo.toml at $ref is $v" >&2; exit 1; }
echo "==> $name $debv from $ref ($(git rev-parse --short "$ref"))"

git archive --prefix="$name-$v/" "$ref" | gzip -9n > "$work/${name}_$v.orig.tar.gz"
tar -xzf "$work/${name}_$v.orig.tar.gz" -C "$work"
src=$work/$name-$v
(cd "$src" && env -u CARGO_TARGET_DIR cargo vendor --locked -q vendor >/dev/null)
tar -C "$src" -cJf "$work/${name}_$v.orig-vendor.tar.xz" vendor
cp -a packaging/debian "$src/debian"
echo "    $(ls "$src/vendor" | wc -l) vendored crates"

# seccomp=unconfined: the test suite exercises io_uring, which container
# seccomp profiles may block; Debian's buildds run on a plain kernel.
podman run --rm --security-opt seccomp=unconfined -v "$work:/w:Z" -w /w \
    -e name="$name" -e v="$v" docker.io/library/debian:sid bash -euo pipefail -c '
echo "==> build dependencies (sid)"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    build-essential debhelper cargo rustc lintian ca-certificates >/dev/null
echo "    $(rustc --version), $(dpkg-query -W -f="debhelper \${Version}" debhelper)"

echo "==> dpkg-buildpackage (offline)"
cd "$name-$v"
dpkg-buildpackage -us -uc > ../build.log 2>&1 || { tail -60 ../build.log; exit 1; }
grep -E "^test result:" ../build.log | sed "s/^/    /"
cd ..
ls -1 *.dsc *.deb *.changes | sed "s/^/    /"

echo "==> lintian"
lintian --info --pedantic --display-experimental *.changes > lintian.txt 2>&1 || true
grep -E "^[EWIPX]: " lintian.txt | sort | uniq | sed "s/^/    /" || echo "    (no tags)"
errors=$(grep -c "^E: " lintian.txt || true)

echo "==> install test"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ./${name}_*_$(dpkg --print-architecture).deb >/dev/null
getent passwd rocketsmbd | sed "s/^/    user: /"
rocketsmbd --version | sed "s/^/    /"
dpkg -L rocketsmbd | grep -E "^/(usr/bin|etc|usr/lib/systemd|usr/lib/sysusers|usr/share/man)/." | sed "s/^/    /"
mkdir -p /srv/share
sed "s#^path = .*#path = \"/srv/share\"#" /etc/rocketsmbd.toml > /tmp/check.toml
rocketsmbd --config /tmp/check.toml --check | sed "s/^/    /"

if [ "$errors" != 0 ]; then echo "FAIL: $errors lintian error(s)"; exit 1; fi
echo "PASS: $name builds, lints without errors, installs"
'
