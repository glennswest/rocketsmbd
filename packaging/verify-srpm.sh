#!/usr/bin/env bash
# Verify a published Fedora review pair (#22): the src.rpm attached to a GitHub
# release and the spec at that tag, as a Package Review reviewer would.
#   packaging/verify-srpm.sh v1.4.1
# 1. the spec at the tag is byte-identical to the spec inside the SRPM
#    (fedora-review's "spec file as given by url is not the same" check);
# 2. the SRPM rebuilds offline (rpmbuild --rebuild, %check runs the tests);
# 3. the bundled(crate()) Provides match the vendored crates in the SRPM;
# 4. rpmlint over SRPM + RPMs with the shipped rpmlintrc (0 errors, 0 warnings).
# Needs rpm-build, cargo, rust, systemd-rpm-macros, curl; rpmlint if present.
# Everything goes under ./tmp (no root, no shared dirs).
set -euo pipefail

tag=${1:?usage: $0 vX.Y.Z}
v=${tag#v}
name=rocketsmbd
work=$PWD/tmp/verify-srpm-$v
rm -rf "$work"; mkdir -p "$work"/{dl,top,spec}
fail=0
step() { echo "==> $*"; }
bad() { echo "FAIL: $*"; fail=1; }

step "download $name-$v SRPM from the $tag release"
srpm_name=$(gh release view "$tag" --repo glennswest/$name --json assets \
    -q '.assets[].name' 2>/dev/null | grep '\.src\.rpm$' | head -1 || true)
[ -n "$srpm_name" ] || srpm_name="$name-$v-1.fc43.src.rpm"
srpm=$work/dl/$srpm_name
curl -fsSL -o "$srpm" \
    "https://github.com/glennswest/$name/releases/download/$tag/$srpm_name"
echo "    $srpm_name ($(stat -c %s "$srpm") bytes)"

step "spec at $tag == spec in the SRPM"
spec_url="https://raw.githubusercontent.com/glennswest/$name/$tag/packaging/$name.spec"
curl -fsSL -o "$work/url.spec" "$spec_url"
# Unpack the whole SRPM (spec, tarballs, rpmlintrc) into spec/.
(cd "$work/spec" && rpm2cpio "$srpm" | cpio -idm --quiet)
ls "$work/spec" | sed 's/^/    srpm: /'
if cmp -s "$work/url.spec" "$work/spec/$name.spec"; then
    echo "    identical ($spec_url)"
else
    bad "spec at $spec_url differs from the SRPM's"
    diff -u "$work/url.spec" "$work/spec/$name.spec" | head -40 || true
fi

step "bundled(crate()) Provides == vendored crates"
tar -tJf "$work/spec/$name-$v-vendor.tar.xz" | awk -F/ 'NF>2 && $3=="Cargo.toml"{print $2}' \
    | while read -r d; do
        toml="$d/Cargo.toml"
        tar -xJOf "$work/spec/$name-$v-vendor.tar.xz" "vendor/$toml" \
            | awk -F'"' '/^\[package\]/{p=1} p&&/^name *=/{n=$2} p&&/^version *=/{print n" = "$2; exit}'
    done | sort > "$work/vendored.txt"
sed -n 's/^Provides: *bundled(crate(\(.*\))) = \(.*\)$/\1 = \2/p' "$work/spec/$name.spec" \
    | sort > "$work/provides.txt"
if cmp -s "$work/vendored.txt" "$work/provides.txt"; then
    echo "    $(wc -l < "$work/provides.txt") crates, all listed"
else
    bad "Provides and vendored crates differ (< vendored, > Provides)"
    diff "$work/vendored.txt" "$work/provides.txt" || true
fi

step "rpmbuild --rebuild (offline, runs %check)"
if rpmbuild --define "_topdir $work/top" --rebuild "$srpm" > "$work/rebuild.log" 2>&1; then
    grep -E '^test result:' "$work/rebuild.log" | sed 's/^/    /'
    ls "$work"/top/RPMS/*/ | sed 's/^/    /'
else
    bad "rpmbuild --rebuild failed (tail of $work/rebuild.log):"
    tail -40 "$work/rebuild.log"
fi

step "rpmlint (SRPM + RPMs, shipped rpmlintrc)"
if command -v rpmlint >/dev/null; then
    rpms=$(find "$work/top/RPMS" -name '*.rpm' 2>/dev/null)
    # shellcheck disable=SC2086
    out=$(rpmlint -r "$work/spec/$name.rpmlintrc" "$srpm" $rpms 2>&1 || true)
    echo "$out" | tail -15 | sed 's/^/    /'
    echo "$out" | grep -qE ' 0 errors, 0 warnings' || bad "rpmlint not clean"
else
    echo "    SKIPPED: rpmlint not installed"
fi

if [ "$fail" = 0 ]; then echo "PASS: $tag SRPM verified"; else echo "FAIL: $tag SRPM"; exit 1; fi
