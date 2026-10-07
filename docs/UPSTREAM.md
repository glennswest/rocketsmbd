# Getting rocketsmbd into Fedora and Debian

This is the plan and checklist for upstream distro packaging. It is separate
from the GitHub release artifacts: those are **static musl** binaries + simple
`.deb`/`.rpm` (great for containers / quick installs / MikroTik). Official
distro packages are built **from source** with the distro's Rust toolchain and
follow each distro's guidelines — that's what the files in `packaging/` target.

## Two distribution channels

| Channel | Build | Linking | Audience |
|---|---|---|---|
| GitHub releases (`cargo-deb`/`cargo-generate-rpm`) | musl, prebuilt | static, no deps | quick installs, containers, ARM/MikroTik |
| Fedora / Debian official | from source, distro toolchain | dynamic (glibc) | distro users via `dnf`/`apt` |
| Fedora COPR (interim) | from source | dynamic | early adopters, no review needed |

## Readiness checklist (general)

- [x] OSI license (MIT) + `LICENSE` file
- [x] `README`, `SECURITY.md`, `CONTRIBUTING.md`, `ROADMAP.md`, `CHANGELOG.md`
- [x] Man page (`docs/rocketsmbd.8`), systemd unit, sample config
- [x] CI (build + test + clippy), tagged releases
- [x] No bundled secrets; `.gitignore` clean
- [x] **Parser fuzzing** (cargo-fuzz) — SMB2 + NTLMSSP entry points, in CI (#20)
- [x] **1.0** released (stable config/wire contract; distros are wary of `0.x`
  network daemons) (#24)
- [x] **All direct dependencies packaged in Fedora** as `rust-*-devel` — but
  one (`io-uring`) is too old (0.6.4 vs our required 0.7), so the official
  submission uses the **bundled** spec for now (see Fedora section). The rest
  of the tree resolves unbundled (offline-build verified). `ccm` (added in
  1.4.0 for AES-CCM) has not been re-checked against Fedora's crate set yet.
- Distro packages build the **default features only** (`ntlm`,
  `backend-rustcrypto`), like the GitHub release. The optional `kerberos`
  (`gssapi-sys`) and `backend-openssl` (`openssl`) features aren't in any
  package yet; they're unreleased (on `main`), see docs/KERBEROS.md and docs/FIPS.md.
- [ ] Clear upstream contact / maintainer for the distro bug trackers
- [ ] A **sponsor** in the Fedora `packager` group (the real remaining gate;
  social, not technical — engage the Rust SIG, below)

## Fedora

The Rust SIG packages Rust software with **`rust2rpm`** (generates a spec with
per-crate `BuildRequires`), or — for a leaf application — by **bundling**
vendored crates with `Provides: bundled(crate(NAME)) = VER`.

**Unbundled is blocked on one crate — go bundled for now.** All direct
dependencies *are* packaged in Fedora, but an unbundled build also requires the
**versions** to line up (Fedora ships exactly one version per crate). Verified
on Fedora 43 + rawhide with a fully-offline build against
`/usr/share/cargo/registry`:

| crate | we require | Fedora ships | ok? |
|---|---|---|---|
| toml | `1` (was 0.8) | 1.1.2 | ✅ (bumped to match) |
| aes, aes-gcm, cmac, hmac, sha2, md-5, md4, serde, libc | as-is | match | ✅ |
| ccm | `0.5` (added 1.4.0) | not re-checked | ? |
| **io-uring** | **`0.7`** (need `SendZc`) | **0.6.4** (F43 *and* rawhide) | ❌ |

`io-uring` is the blocker: we depend on 0.7-only API (`send_zc`, #15) and
Fedora is two minor versions behind in both stable and rawhide. Downgrading is
off the table — it would revert the zero-copy send work.

So **the official Fedora submission uses the bundled (vendored) spec**
(`packaging/rocketsmbd.spec`, already COPR-validated) with
`Provides: bundled(crate(NAME)) = VER` and a justification: *the package
requires a newer `io-uring` than Fedora ships and rides current io_uring
features*. Fedora permits bundling for leaf applications with cause; this is a
textbook case. The offline build also confirmed the **rest** of the tree
resolves unbundled, so if/when `rust-io-uring` reaches 0.7 (we can offer to
help bump it) we flip to the unbundled `rust2rpm` spec with a one-line change.

### Review-readiness — done

The bundled spec is **review-clean** (validated on Fedora 43):

- **License** tag is the aggregate of the bundled crates' effective licenses,
  `MIT AND BSD-3-Clause AND Unicode-3.0` (MIT chosen for dual MIT/Apache crates;
  `subtle` forces BSD-3-Clause, `unicode-ident` forces Unicode-3.0). Per-crate
  audited — all three are Fedora-allowed.
- **`Provides: bundled(crate(NAME)) = VER`** for all 47 vendored crates
  (verified emitted by `rpm -q --provides`).
- **`%check`** runs the test suite; **debuginfo** is kept
  (`CARGO_PROFILE_RELEASE_DEBUG=2`/`STRIP=false`) so a proper `-debuginfo`
  subpackage is produced (no unstripped-binary warning).
- **`packaging/rocketsmbd.rpmlintrc`** (shipped as `Source2`) filters only the
  `io_uring` domain-term spelling false-positive and the expected
  vendored-`Source1`-is-not-a-URL note.
- **`rpmlint`** over SRPM + RPM + `-debuginfo` together (how `fedora-review`
  runs it): **0 errors, 0 warnings, 0 badness.**

**Review status (2026-10-07):** Package Review bug filed,
[RHBZ #2488339](https://bugzilla.redhat.com/show_bug.cgi?id=2488339); waiting on
a reviewer + sponsor (the owner's FAS identity; texts in
`docs/fedora-submission.md`). The review pair is the **1.4.1-2** SRPM on the
v1.4.1 release and the spec at the commit it was built from (`release/1.4`,
fd892d4). Verified with `packaging/verify-srpm.sh` on a fresh Fedora 43 VM:
spec URL == SRPM spec, Source0 == GitHub's tag archive, Provides == vendored
crates, offline `rpmbuild --rebuild` + `%check`, rpmlint 0/0 over all four
packages. Build new review SRPMs with `packaging/review-srpm.sh`, never with
`build-srpm.sh`: that one tars the checkout, which can't match the Source0 URL
(the 1.4.1-1 SRPM had that defect, plus two wrong changelog weekdays).

**Next spec update (1.5.0):** `main` adds the systemd sysusers user (#39) and
optional dependencies (`openssl`, `gssapi-sys` and their build trees, e.g.
`bindgen`). `cargo vendor` vendors every crate in `Cargo.lock`, so the
`bundled(crate())` Provides and the `License:` aggregate must be regenerated
from the 1.5.0 vendor tarball (or the vendor tarball filtered to what the
default features build) before the review moves to 1.5.0. verify-srpm.sh fails
on a Provides/vendor mismatch.

Path:
1. **COPR first** (no review, instant `dnf copr enable`): build from the spec
   in `packaging/rocketsmbd.spec`. Gets real users now. (#22)
2. **Official review**: regenerate the spec with `rust2rpm rocketsmbd`, file a
   *Package Review* on Red Hat Bugzilla (component "Package Review"), engage
   the **Fedora Rust SIG** (Matrix `#rust:fedoraproject.org`), find a sponsor,
   iterate to APPROVED, then request the repo + dist-git branch.

`packaging/rocketsmbd.spec` here is **COPR-ready and validated**: it builds
from a source tarball + vendored-crates tarball, offline. `rpmbuild --rebuild`
of the SRPM produces a working `rocketsmbd-VER.fc*.x86_64.rpm` (runs the test
suite in `%check`). For official Fedora review, regenerate per-crate
`BuildRequires` with `rust2rpm` against the packaged crates instead of
vendoring.

### Stand up the COPR (the two commands you run)

The SRPM is built by `packaging/build-srpm.sh` (and attached to GitHub
releases). COPR submission needs **your** Fedora API token (it's tied to your
FAS account — get it from <https://copr.fedorainfracloud.org/api/> and save to
`~/.config/copr`). Then:

```sh
# one-time: create the project (x86_64 + aarch64, recent Fedora + EPEL)
copr-cli create rocketsmbd \
  --chroot fedora-rawhide-x86_64 --chroot fedora-41-x86_64 \
  --chroot fedora-41-aarch64 --chroot epel-9-x86_64 \
  --description "io_uring SMB2/SMB3 file server (zero-copy, multichannel)"

# build (from the SRPM produced by packaging/build-srpm.sh)
copr-cli build rocketsmbd ~/rpmbuild/SRPMS/rocketsmbd-*.src.rpm
```

Users then: `sudo dnf copr enable <you>/rocketsmbd && sudo dnf install rocketsmbd`.

## Debian

The Debian Rust team packages crates via **`debcargo`** as `librust-*-dev`, and
applications with **`dh-cargo`**.

Path:
1. File an **ITP** (Intent To Package) bug against `wnpp`
   (`reportbug wnpp`, severity wishlist, title `ITP: rocketsmbd -- ...`). (#23)
2. Ensure every crate dependency is in Debian (`apt-cache search librust-...`);
   package missing ones via the Rust team / `debcargo`, or vendor.
3. Build with the `debian/` dir here (`dh $@ --buildsystem cargo`).
4. Find a **DD/DM sponsor** to review and upload (mentors.debian.net).

`packaging/debian/` builds and installs in sid (verified 2026-10-07): run
`sc-build 'packaging/debian-build.sh [REF]'`. In a rootless podman `debian:sid`
container it builds the source package as Debian would: `orig.tar.gz` from
`git archive`, crates as a `3.0 (quilt)` component tarball
(`orig-vendor.tar.xz` → `vendor/`), offline `--locked` build, and the test suite
gates the build. It then runs lintian (`--pedantic`) and installs the `.deb`.
Last result on `main` (3372ac9): 75 tests pass; lintian 0 errors; the
`rocketsmbd` user is created by `systemd-sysusers` (debhelper compat 14 runs
`dh_installsysusers`); the shipped `/etc/rocketsmbd.toml` passes `--check`.
Remaining lintian warnings:
- `initial-upload-closes-no-bugs`: needs the ITP bug number in `debian/changelog`.
- `source-contains-prebuilt-windows-binary` (`vendor/libloading/tests/*.dll`):
  `cargo vendor` vendors every crate in `Cargo.lock` (98, including Windows-only
  crates and the optional openssl/gssapi-sys trees), not just what the default
  build links.

**Route — owner's decision (#23).** sid has io-uring 0.7.11, but it is in the
middle of the RustCrypto generation change, so the unbundled dh-cargo route
doesn't resolve today:

| crate | we use | sid |
|---|---|---|
| io-uring | 0.7 | 0.7.11 ✓ |
| aes / aes-gcm | 0.8 / 0.10 | 0.9 / 0.11 |
| hmac | 0.12 | 0.13 |
| sha2 / md-5 | 0.10 | 0.11 |
| cmac / md4 | 0.7 / 0.10 | 0.7.2 / 0.10.2 (old generation) |
| ccm | 0.5 | not in Debian |
| libc, serde, toml | 0.2 / 1 / 1 | ✓ |

1. **Unbundled (dh-cargo, the Rust team's way).** Port rocketsmbd to the new
   RustCrypto generation (aes 0.9, aes-gcm 0.11, hmac 0.13, sha2/md-5 0.11,
   plus the matching cmac/md4/ccm releases). Then get `rust-ccm` packaged and
   `rust-cmac`/`rust-md4` updated through debcargo-conf (Rust team
   contributions). This is the most work, but it is the route Debian reviewers
   accept: ftp-masters generally reject embedded copies of crates Debian already
   ships. The port also keeps Fedora unbundling possible later.
2. **Vendored (what `debian/` does now).** This is the fastest route. It needs
   `vendor/` pruned to what the Linux default build links (no DLLs, no
   Windows/openssl trees), and a per-crate `debian/copyright`. Because almost
   every crate is already in Debian, expect a sponsor or ftp-master to push back.
3. **Wait** until sid's RustCrypto transition settles, then take route 1
   without the cmac/md4 updates.

Also undecided: which upstream version to upload. 1.4.1 is the latest
release; `debian/` assumes the #39 service user, which is only on `main`
(1.5.0).

### ITP bug — ready to file

`reportbug wnpp` (or email `submit@bugs.debian.org`), severity **wishlist**:

```
Subject: ITP: rocketsmbd -- SMB2/SMB3 file server built on Linux io_uring

Package: wnpp
Severity: wishlist
Owner: Glenn West <glennswest@neuralcloudcomputing.com>
X-Debbugs-Cc: debian-devel@lists.debian.org, debian-rust@lists.debian.org

* Package name    : rocketsmbd
  Version         : 1.4.0
  Upstream Author : Glenn West <glennswest@neuralcloudcomputing.com>
* URL             : https://github.com/glennswest/rocketsmbd
* License         : MIT
  Programming Lang: Rust
  Description     : SMB2/SMB3 file server built on Linux io_uring

 A from-scratch SMB2/SMB3 file server in Rust on io_uring: accept, receive,
 send and file I/O flow through one ring per worker, and reads are served
 zero-copy from page cache to socket via splice. SMB 2.0.2-3.1.1 with NTLMv2
 auth, SMB2/3 signing, SMB 3.1.1 preauth, SMB3 multichannel, and SMB3
 encryption (AES-128/256-GCM and -CCM), read/handle-caching leases.
 Wire parsers are fuzzed in CI.

 Packaging via the Debian Rust team (dh-cargo). I am looking for a DD/DM
 sponsor; I'll upload to mentors.debian.net. It is also on crates.io
 (https://crates.io/crates/rocketsmbd) and in a Fedora COPR.
```

After filing, upload the source package to **mentors.debian.net** and request a
sponsor on **debian-mentors@** / the Rust team list.

## Interim: ship a repo now

Until official inclusion, users can install today from:
- The GitHub release `.deb`/`.rpm` (static, no deps) — see README.
- A Fedora **COPR** built from `packaging/rocketsmbd.spec`.
- A Debian repo / `mentors.debian.net` upload built from `packaging/debian/`.

## Status

- GitHub releases: **live** (v1.4.1, x86_64 + aarch64 `.deb`/`.rpm`/binary; SRPM and SHA256SUMS.txt attached), built with `deploy/release-artifacts.sh` via sc-build (docs/RELEASING.md), not GitHub Actions.
- crates.io: **published** (<https://crates.io/crates/rocketsmbd>, v1.4.0).
- Fedora COPR: **live** (<https://copr.fedorainfracloud.org/coprs/glennswest/rocketsmbd/>).
  Official review: the Package Review bug is filed
  (<https://bugzilla.redhat.com/show_bug.cgi?id=2488339>). The package is
  review-clean and passes `fedora-review`; it still needs a Rust SIG sponsor
  (#22, see docs/fedora-submission.md).
- Debian: `packaging/debian/` builds, lints (0 errors) and installs in sid
  (`packaging/debian-build.sh`); ITP drafted above but **not filed yet**; the
  crate route and upload version are the owner's call; needs a DD/DM sponsor (#23).
- 1.0 ✅, fuzzing in CI ✅ — no longer blocking.
