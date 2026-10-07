#!/usr/bin/env bash
# Verify a Fedora review pair (#22) — a spec URL and an SRPM — as a Package
# Review reviewer (fedora-review) would:
#   packaging/verify-srpm.sh v1.4.1              # the release's SRPM + tag spec
#   packaging/verify-srpm.sh v1.4.1 FILE.src.rpm SPEC_URL
#   packaging/verify-srpm.sh v1.4.1 - SPEC_URL   # newest release SRPM, that spec
# 1. the spec at SPEC_URL is byte-identical to the spec inside the SRPM;
# 2. Source0 in the SRPM is byte-identical to the upstream archive the spec's
#    Source0 URL names (GitHub's tag archive);
# 3. the bundled(crate()) Provides match the vendored crates in Source1
#    (versions compared without +build metadata, as the spec lists them);
# 4. the SRPM rebuilds offline (rpmbuild --rebuild; %check runs the tests);
# 5. rpmlint over SRPM + RPMs with the shipped rpmlintrc: 0 errors, 0 warnings.
# Needs rpm-build, cargo, rust, systemd-rpm-macros, curl, cpio; rpmlint if
# present. Everything goes under ./tmp (no root, no shared dirs).
set -euo pipefail

tag=${1:?usage: $0 vX.Y.Z [FILE.src.rpm SPEC_URL]}
v=${tag#v}
name=rocketsmbd
repo=glennswest/$name
work=$PWD/tmp/verify-srpm-$v
rm -rf "$work"; mkdir -p "$work"/{dl,top,spec}
fail=0
step() { echo "==> $*"; }
bad() { echo "FAIL: $*"; fail=1; }

if [ -n "${2:-}" ] && [ "$2" != - ]; then
    srpm=$(realpath "$2")
    spec_url=${3:?SPEC_URL is required with an SRPM file}
    step "SRPM $(basename "$srpm")"
else
    step "download the $tag release's SRPM"
    srpm_name=$(gh release view "$tag" --repo "$repo" --json assets \
        -q '.assets[].name' 2>/dev/null | grep '\.src\.rpm$' | sort -V | tail -1 || true)
    [ -n "$srpm_name" ] || srpm_name="$name-$v-1.fc43.src.rpm"
    srpm=$work/dl/$srpm_name
    curl -fsSL -o "$srpm" "https://github.com/$repo/releases/download/$tag/$srpm_name"
    spec_url=${3:-https://raw.githubusercontent.com/$repo/$tag/packaging/$name.spec}
fi
echo "    $(basename "$srpm") ($(stat -c %s "$srpm") bytes)"
# Unpack the whole SRPM (spec, tarballs, rpmlintrc, sysusers) into spec/.
(cd "$work/spec" && rpm2cpio "$srpm" | cpio -idm --quiet)
ls "$work/spec" | sed 's/^/    srpm: /'

step "spec at $spec_url == spec in the SRPM"
curl -fsSL -o "$work/url.spec" "$spec_url"
if cmp -s "$work/url.spec" "$work/spec/$name.spec"; then
    echo "    identical"
else
    bad "spec at $spec_url differs from the SRPM's"
    diff -u "$work/url.spec" "$work/spec/$name.spec" | head -40 || true
fi

step "Source0 == upstream archive"
src0_url=$(rpmspec -P "$work/spec/$name.spec" 2>/dev/null | awk '/^Source0:/ && !n++{print $2}')
src0=$work/spec/$(basename "$src0_url")
curl -fsSL -o "$work/dl/upstream.tar.gz" "$src0_url"
if cmp -s "$work/dl/upstream.tar.gz" "$src0"; then
    echo "    identical ($src0_url, sha256 $(sha256sum "$src0" | cut -c1-16)…)"
else
    bad "Source0 in the SRPM is not the upstream archive $src0_url"
fi

step "bundled(crate()) Provides == vendored crates"
vendor=$work/spec/$name-$v-vendor.tar.xz
tar -tJf "$vendor" | awk -F/ 'NF>2 && $3=="Cargo.toml"{print $2}' \
    | while read -r d; do
        tar -xJOf "$vendor" "vendor/$d/Cargo.toml" \
            | awk -F'"' '/^\[package\]/{p=1} p&&/^name *=/{n=$2} p&&!done&&/^version *=/{sub(/\+.*/,"",$2); print n" = "$2; done=1}'
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
# sc-build points CARGO_TARGET_DIR at its own checkout; Koji/mock don't set
# it, and the spec installs from ./target, so build as they would.
if env -u CARGO_TARGET_DIR rpmbuild --define "_topdir $work/top" --rebuild "$srpm" \
        > "$work/rebuild.log" 2>&1; then
    grep -E '^test result:' "$work/rebuild.log" | sed 's/^/    /'
    find "$work/top/RPMS" -name '*.rpm' -printf '    %f\n'
    grep -A3 'RPM build warnings' "$work/rebuild.log" && bad "rpmbuild warnings" || true
else
    bad "rpmbuild --rebuild failed (tail of $work/rebuild.log):"
    tail -40 "$work/rebuild.log"
fi

step "rpmlint (SRPM + RPMs, shipped rpmlintrc)"
if command -v rpmlint >/dev/null; then
    rpms=$(find "$work/top/RPMS" -name '*.rpm' 2>/dev/null)
    # shellcheck disable=SC2086
    out=$(rpmlint -r "$work/spec/$name.rpmlintrc" "$srpm" $rpms 2>&1 || true)
    echo "$out" | grep -E ': [EW]: |packages and' | sed 's/^/    /'
    echo "$out" | grep -qE ' 0 errors, 0 warnings' || bad "rpmlint not clean"
else
    echo "    SKIPPED: rpmlint not installed"
fi

if [ "$fail" = 0 ]; then echo "PASS: $(basename "$srpm") verified"; else echo "FAIL: $(basename "$srpm")"; exit 1; fi
