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
  of the tree resolves unbundled (offline-build verified).
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
| aes-gcm, cmac, hmac, sha2, md-5, md4, serde, libc | as-is | match | ✅ |
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

Remaining before filing: run `fedora-review -b <bug>` (full mock build; the
`rpmbuild --rebuild` offline build + `%check` already pass), then file the
Package Review bug and ping the Rust SIG for a sponsor.

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

`packaging/debian/` here is a working skeleton (control, rules, changelog,
copyright, install, manpages). Crate-dependency resolution is the main work.

## Interim: ship a repo now

Until official inclusion, users can install today from:
- The GitHub release `.deb`/`.rpm` (static, no deps) — see README.
- A Fedora **COPR** built from `packaging/rocketsmbd.spec`.
- A Debian repo / `mentors.debian.net` upload built from `packaging/debian/`.

## Status

- GitHub releases: **live** (v0.4.0, x86_64 + aarch64 `.deb`/`.rpm`/binary).
- Fedora COPR: spec ready (`packaging/rocketsmbd.spec`); COPR project TODO (#22).
- Debian: skeleton ready (`packaging/debian/`); ITP + sponsor TODO (#23).
- Blocking for *official* 1.0-quality submission: fuzzing (#20), 1.0 (#24).
