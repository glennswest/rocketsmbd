#!/usr/bin/env bash
# Build the SRPM for the Fedora review (#22) the way a reviewer expects it, then
# verify it and print it for the caller to publish:
#   sc-build 'packaging/review-srpm.sh v1.4.1 <spec-commit>'
# - Source0 is GitHub's archive of the tag (the spec's Source0 URL), not a
#   tarball of the checkout, so fedora-review's upstream-source check matches;
# - Source1 vendors the crates from that archive's Cargo.lock;
# - the spec, rpmlintrc and sysusers come from <spec-commit> (default: the
#   tag), so a packaging-only fix (Release: N+1) needs no new upstream tag. The
#   spec's review URL is then raw.githubusercontent.com/.../<spec-commit>/...;
# - packaging/verify-srpm.sh checks the result against that spec URL;
# - the SRPM is printed as `@@ARTIFACT <name> <sha256>` + base64 + `@@END`
#   (sc-build keeps nothing; decode as in docs/RELEASING.md) and is uploaded to
#   the tag's GitHub release by the caller.
set -euo pipefail

tag=${1:?usage: $0 vX.Y.Z [spec-commit]}
ref=${2:-$tag}
v=${tag#v}
name=rocketsmbd
repo=glennswest/$name
here=$PWD
work=$here/tmp/review-srpm-$v
rm -rf "$work"; mkdir -p "$work"/{src,top/SOURCES,top/SPECS}

# The spec commit may be on another branch (release/X.Y) than this checkout.
git rev-parse -q --verify "$ref^{commit}" >/dev/null ||
    git fetch -q "https://github.com/$repo.git" "$ref" 2>/dev/null ||
    git fetch -q "https://github.com/$repo.git" "+refs/heads/*:refs/remotes/review/*" "+refs/tags/*:refs/tags/*"
sha=$(git rev-parse "$ref^{commit}")
echo "==> spec from $ref ($sha)"
for f in "$name.spec" "$name.rpmlintrc" "$name.sysusers"; do
    git cat-file -e "$sha:packaging/$f" 2>/dev/null || continue
    dst=$work/top/SOURCES/$f; [ "$f" = "$name.spec" ] && dst=$work/top/SPECS/$f
    git show "$sha:packaging/$f" > "$dst"
done
specv=$(awk '/^Version:/{print $2; exit}' "$work/top/SPECS/$name.spec")
[ "$specv" = "$v" ] || { echo "spec at $ref is Version $specv, tag is $v" >&2; exit 1; }

echo "==> Source0: GitHub archive of $tag"
curl -fsSL -o "$work/top/SOURCES/$name-$v.tar.gz" \
    "https://github.com/$repo/archive/$tag/$name-$v.tar.gz"
tar -xzf "$work/top/SOURCES/$name-$v.tar.gz" -C "$work/src"

echo "==> Source1: vendored crates"
(cd "$work/src/$name-$v" && env -u CARGO_TARGET_DIR cargo vendor --locked -q vendor >/dev/null \
    && tar caf "$work/top/SOURCES/$name-$v-vendor.tar.xz" vendor)

echo "==> SRPM"
rpmbuild -q --define "_topdir $work/top" -bs "$work/top/SPECS/$name.spec"
srpm=$(ls "$work"/top/SRPMS/$name-$v-*.src.rpm)

echo "==> verify"
packaging/verify-srpm.sh "$tag" "$srpm" \
    "https://raw.githubusercontent.com/$repo/$sha/packaging/$name.spec"

n=$(basename "$srpm")
echo "@@ARTIFACT $n $(sha256sum "$srpm" | cut -d' ' -f1)"
base64 -w 76 "$srpm"
echo "@@END $n"
echo "spec URL: https://raw.githubusercontent.com/$repo/$sha/packaging/$name.spec"
