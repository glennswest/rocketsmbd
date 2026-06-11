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
- [x] **All direct dependencies already packaged in Fedora** as `rust-*-devel`
  (io-uring, libc, aes, aes-gcm, cmac, hmac, md-5, md4, sha2, serde, toml) — so
  the **unbundled** build the Rust SIG prefers is feasible *today* with no new
  crate packaging. Decisive enabler.
- [ ] Clear upstream contact / maintainer for the distro bug trackers
- [ ] A **sponsor** in the Fedora `packager` group (the real remaining gate;
  social, not technical — engage the Rust SIG, below)

## Fedora

The Rust SIG packages Rust software with **`rust2rpm`** (generates a spec with
per-crate `BuildRequires`), or — for a leaf application — by **bundling**
vendored crates with `Provides: bundled(crate(NAME)) = VER`.

**We can and should go unbundled.** Verified on Fedora 43: every direct
dependency is already packaged (`rust-io-uring-devel`, `rust-aes-gcm-devel`,
`rust-cmac-devel`, `rust-hmac-devel`, `rust-md-5-devel`, `rust-md4-devel`,
`rust-sha2-devel`, `rust-libc-devel`, `rust-serde-devel`, `rust-toml-devel`),
so a `rust2rpm`-generated spec resolves its `BuildRequires` against system
crates with no vendoring and no bundling exception — the cleanest path through
review. (The vendored `packaging/rocketsmbd.spec` stays for COPR/`rpmbuild
--rebuild` convenience; the official submission uses the unbundled spec.)

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
