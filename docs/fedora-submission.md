# Fedora submission — ready-to-file artifacts

Everything below is drafted for you to paste/run. The package is review-clean
(see `docs/UPSTREAM.md`); what remains needs your Fedora identity.

**Review bug: https://bugzilla.redhat.com/show_bug.cgi?id=2488339** (filed).

URLs the review uses:
- **Spec:** <https://raw.githubusercontent.com/glennswest/rocketsmbd/main/packaging/rocketsmbd.spec>
- **SRPM:** <https://github.com/glennswest/rocketsmbd/releases/download/v1.4.0/rocketsmbd-1.4.0-1.fc43.src.rpm>
- **COPR (already live):** <https://copr.fedorainfracloud.org/coprs/glennswest/rocketsmbd/>

---

## 1. Package Review bug

**One-click pre-filled form** (must be submitted while logged in to
bugzilla.redhat.com as glennswest — the reporter becomes the package
maintainer). Open it, review, and click *Submit Bug*:

<https://bugzilla.redhat.com/enter_bug.cgi?product=Fedora&component=Package%20Review&version=rawhide&bug_severity=medium&short_desc=Review%20Request%3A%20rocketsmbd%20-%20SMB2%2FSMB3%20file%20server%20built%20on%20Linux%20io_uring&comment=Spec%20URL%3A%20https%3A%2F%2Fraw.githubusercontent.com%2Fglennswest%2Frocketsmbd%2Fmain%2Fpackaging%2Frocketsmbd.spec%0ASRPM%20URL%3A%20https%3A%2F%2Fgithub.com%2Fglennswest%2Frocketsmbd%2Freleases%2Fdownload%2Fv1.4.0%2Frocketsmbd-1.4.0-1.fc43.src.rpm%0A%0ADescription%3A%0Arocketsmbd%20is%20a%20from-scratch%20SMB2%2FSMB3%20file%20server%20built%20on%20Linux%20io_uring%3A%20accept%2C%20receive%2C%20send%2C%20and%20file%20I%2FO%20flow%20through%20one%20ring%20per%20worker%2C%20reads%20zero-copy%20via%20splice.%20SMB%202.0.2-3.1.1%2C%20NTLMv2%2C%20SMB2%2F3%20signing%2C%203.1.1%20preauth%2C%20multichannel%2C%20AES-128%2F256-GCM%20and%20AES-CCM%20encryption%2C%20read%2Fhandle-caching%20leases.%20Rust%3B%20parsers%20fuzzed%20in%20CI.%0A%0AFAS%3A%20glennswest%0ACOPR%3A%20https%3A%2F%2Fcopr.fedorainfracloud.org%2Fcoprs%2Fglennswest%2Frocketsmbd%2F%0Acrates.io%3A%20https%3A%2F%2Fcrates.io%2Fcrates%2Frocketsmbd%0A%0ABUNDLING%3A%20vendored%20because%20it%20needs%20io-uring%200.7%20%28IORING_OP_SEND_ZC%29%20and%20Fedora%20ships%200.6.4%20in%20stable%2Brawhide%3B%20every%20other%20dep%20resolves%20unbundled.%2048%20bundled%28crate%28%29%29%20Provides%20listed.%20License%3A%20MIT%20AND%20BSD-3-Clause%20AND%20Unicode-3.0%20%28all%20Fedora-allowed%29.%20fedora-review%20%28rawhide%20mock%29%20passes%3B%20rpmlint%20clean%20with%20shipped%20rpmlintrc.%20First%20package%2C%20seeking%20a%20sponsor.&status_whiteboard=needs-sponsor>

(Full untruncated text below if you prefer to paste manually.) File at product
**Fedora**, component **Package Review**.

**Summary:**

```
Review Request: rocketsmbd - SMB2/SMB3 file server built on Linux io_uring
```

**Description:**

```
Spec URL: https://raw.githubusercontent.com/glennswest/rocketsmbd/main/packaging/rocketsmbd.spec
SRPM URL: https://github.com/glennswest/rocketsmbd/releases/download/v1.4.0/rocketsmbd-1.4.0-1.fc43.src.rpm

Description:
rocketsmbd is a from-scratch SMB2/SMB3 file server built on Linux io_uring:
accept, receive, send, and file I/O all flow through one ring per worker, and
file reads are served zero-copy from the page cache to the socket via splice.
It speaks SMB 2.0.2 through 3.1.1 with NTLMv2 authentication, SMB2/3 signing,
SMB 3.1.1 preauth integrity, SMB3 multichannel, SMB3 encryption (AES-128/256-GCM
and AES-CCM), and read/handle-caching leases. Written in Rust; the wire parsers
are fuzzed in CI.

Fedora Account System (FAS): glennswest
COPR (builds for F41/rawhide/EPEL9, x86_64 + aarch64):
  https://copr.fedorainfracloud.org/coprs/glennswest/rocketsmbd/

Notes for the reviewer:
- This is a leaf APPLICATION (binary), packaged as `rocketsmbd` (not
  `rust-rocketsmbd`).
- BUNDLING: the crate tree is vendored because rocketsmbd requires io-uring 0.7
  (for IORING_OP_SEND_ZC and current io_uring features) while Fedora currently
  ships rust-io-uring 0.6.4 in both stable and rawhide. An offline build against
  /usr/share/cargo/registry confirmed every *other* dependency resolves
  unbundled; when rust-io-uring reaches 0.7 this can move to an unbundled
  rust2rpm spec. I'm happy to help co-maintain/bump rust-io-uring to enable
  that. Per-crate `Provides: bundled(crate(NAME)) = VER` are listed (48 crates).
- LICENSE: the binary's effective license is the AND of the bundled crates'
  licenses, choosing MIT where a crate is dual MIT/Apache (rocketsmbd itself is
  MIT). subtle is BSD-3-Clause; unicode-ident mandates Unicode-3.0. Hence:
    License: MIT AND BSD-3-Clause AND Unicode-3.0
  All three are Fedora-allowed.
- rpmlint over the SRPM + binary RPM + -debuginfo is clean (0 errors, 0
  warnings); the shipped rocketsmbd.rpmlintrc filters only the "io_uring"
  domain-term spelling false-positive and the vendored-Source1-is-not-a-URL note.
- Hard runtime dependency is the kernel's io_uring (5.15+; checked at startup);
  the package is otherwise dependency-light.

This is my first Fedora package — I am seeking a sponsor.
```

After filing, set the bug's `fedora-review` flag to `?` if you can, and add the
`needs-sponsor` Whiteboard keyword.

---

## 2. Rust SIG / sponsor message

Post in Matrix **#rust:fedoraproject.org** (and/or the devel list
`devel@lists.fedoraproject.org`):

```
Hi! I'm submitting my first Fedora package and looking for a reviewer + sponsor.

rocketsmbd — an SMB2/SMB3 file server built from scratch in Rust on io_uring
(zero-copy splice reads, SMB3 multichannel + encryption). 1.0 is out, wire
parsers are fuzzed in CI, and it already builds in COPR for F41/rawhide/EPEL9
(x86_64 + aarch64): https://copr.fedorainfracloud.org/coprs/glennswest/rocketsmbd/

Review bug: https://bugzilla.redhat.com/show_bug.cgi?id=2488339

One thing I'd value SIG guidance on: it's currently bundled because it needs
io-uring 0.7 (IORING_OP_SEND_ZC) and Fedora ships rust-io-uring 0.6.4 in stable
and rawhide. Everything else resolves unbundled. I'd happily help bump
rust-io-uring to 0.7 so this (and others) can go unbundled — pointers welcome.

FAS: glennswest. Thanks!
```

The io-uring-bump offer is deliberate: helping a SIG package is a common fast
path to sponsorship and clears the unbundling blocker for everyone.

### Internal (Red Hat Slack) — short version for a colleague

For DMing a Red Hat colleague who's a Fedora packager/sponsor (target the Rust
SIG — they sponsor Rust packagers and own rust-io-uring):

```
Hey — I'm submitting my first Fedora package and need a reviewer + sponsor into
the packager group. It's rocketsmbd, a from-scratch SMB2/3 server in Rust on
io_uring (zero-copy splice, multichannel, AES-GCM). Already fedora-review clean
and building in COPR (F41/rawhide/EPEL9, x86_64+aarch64).

Review bug: https://bugzilla.redhat.com/show_bug.cgi?id=2488339
COPR: https://copr.fedorainfracloud.org/coprs/glennswest/rocketsmbd/

It's bundled for now only because it needs io-uring 0.7 (SEND_ZC) and Fedora
ships rust-io-uring 0.6.4 — happy to help bump rust-io-uring to 0.7 so it (and
anything else) can go unbundled. Could you review/sponsor, or point me at the
right person? FAS: glennswest. Thanks!
```

---

## 3. Publish the crate to crates.io — DONE

Published: <https://crates.io/crates/rocketsmbd> (v1.4.0). This makes rocketsmbd
the canonical source for a future unbundled rust2rpm spec and enables
`cargo install rocketsmbd`. Future releases: bump the version, then
`cargo publish` (token in the environment as `CARGO_REGISTRY_TOKEN`).

---

## 4. After review approval (mechanical)

```sh
fedpkg request-repo rocketsmbd <REVIEW_BUG_ID>     # creates dist-git
# (a releng admin approves; then:)
fedpkg clone rocketsmbd && cd rocketsmbd
# import the approved SRPM, commit, and build per branch:
fedpkg import ~/rpmbuild/SRPMS/rocketsmbd-1.4.0-1.fc*.src.rpm
fedpkg commit -m "Initial import (#<REVIEW_BUG_ID>)" && fedpkg push
fedpkg build                                       # rawhide (Koji)
# stable branches:
fedpkg switch-branch f41 && git merge rawhide && fedpkg push && fedpkg build
bodhi updates new --type newpackage --notes "Initial Fedora import" rocketsmbd-1.4.0-1.fc41
# optional EPEL:
fedpkg switch-branch epel9 && ... && fedpkg build && bodhi updates new ...
```

rawhide needs no Bodhi update; stable/EPEL branches do.
