#!/usr/bin/env bash
# Build the release artifacts for a tag through sc-build, and print them.
#
#   sc-build 'deploy/release-artifacts.sh v1.4.1'
#
# GitHub Actions is not used to build releases (owner, 2026-10-06, #41). This
# builds exactly the tagged source — `git archive <tag>`, so commits on the
# branch after the tag (like this script) are not in the artifacts — into:
#   rocketsmbd-x86_64-linux-musl, rocketsmbd-aarch64-linux-musl  (static)
#   rocketsmbd_<v>-1_amd64.deb, rocketsmbd_<v>-1_arm64.deb
#   rocketsmbd-<v>-1.x86_64.rpm, rocketsmbd-<v>-1.aarch64.rpm
#   rocketsmbd-<v>-1.<dist>.src.rpm                             (COPR input)
# the same set release.yml used to produce.
#
# sc-build keeps nothing from a job, so each artifact is printed to stdout as
#   @@ARTIFACT <name> <sha256>
#   <base64 lines>
#   @@END <name>
# and decoded on the calling side (see docs/RELEASING.md).
set -euo pipefail

tag=${1:?usage: deploy/release-artifacts.sh <tag>}
v=${tag#v}
work=${TMPDIR:-/tmp}/release-$v
out=$work/out
rm -rf "$work"
mkdir -p "$work/src" "$out"

# The tag's exact source (sc-build's checkout may be shallow and tag-less).
git rev-parse -q --verify "refs/tags/$tag" >/dev/null ||
    git fetch -q --depth=1 origin "refs/tags/$tag:refs/tags/$tag"
echo "==> building $tag ($(git rev-parse "$tag^{commit}"))"
git archive "$tag" | tar -x -C "$work/src"
cd "$work/src"
got=$(awk -F\" '/^version =/{print $2; exit}' Cargo.toml)
[ "$got" = "$v" ] || { echo "Cargo.toml says $got, tag says $v" >&2; exit 1; }

echo "==> packaging tools"
cargo install -q --locked cargo-deb cargo-generate-rpm
export PATH=$HOME/.cargo/bin:$PATH

# .cargo/config.toml names a dev-host aarch64 musl linker this box lacks; the
# gnu cross gcc links the static musl binary fine (as release.yml did).
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc

for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    arch=${target%%-*}
    echo "==> $target"
    cargo build -q --release --locked --target "$target"
    cargo deb --no-build --target "$target" --output "$out/"
    # Static binary: no library auto-deps (io_uring is checked at runtime).
    cargo generate-rpm --target "$target" --auto-req no -o "$out/"
    cp "target/$target/release/rocketsmbd" "$out/rocketsmbd-$arch-linux-musl"
done

echo "==> checks"
bin=$out/rocketsmbd-x86_64-linux-musl
"$bin" --version
file "$bin" "$out/rocketsmbd-aarch64-linux-musl" | sed "s/, BuildID[^,]*//" || true
# The config the packages install as /etc/rocketsmbd.toml must load (#41);
# point its share at a directory that exists here.
sed "s#^path = .*#path = \"$work\"#" rocketsmbd.toml.example >"$work/check.toml"
"$bin" --config "$work/check.toml" --check
for p in "$out"/*.deb; do dpkg-deb -c "$p" | awk '{print $6}' | grep -q '^\./etc/rocketsmbd.toml$'; done
for p in "$out"/*.rpm; do rpm -qp --configfiles "$p" | grep -qx /etc/rocketsmbd.toml; done

echo "==> src.rpm"
packaging/build-srpm.sh >/dev/null
cp "$(rpm --eval %_topdir)"/SRPMS/rocketsmbd-"$v"-*.src.rpm "$out/"

ls -l "$out"
for f in "$out"/*; do
    n=$(basename "$f")
    echo "@@ARTIFACT $n $(sha256sum "$f" | cut -d' ' -f1)"
    base64 -w 76 "$f"
    echo "@@END $n"
done
