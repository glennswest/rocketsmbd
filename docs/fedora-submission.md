# Fedora submission — ready-to-file artifacts

Everything below is drafted for you to paste/run. The package is review-clean
(see `docs/UPSTREAM.md`); what remains needs your Fedora identity.

URLs the review uses:
- **Spec:** <https://raw.githubusercontent.com/glennswest/rocketsmbd/main/packaging/rocketsmbd.spec>
- **SRPM:** <https://github.com/glennswest/rocketsmbd/releases/download/v1.1.0/rocketsmbd-1.1.0-1.fc43.src.rpm>
- **COPR (already live):** <https://copr.fedorainfracloud.org/coprs/glennswest/rocketsmbd/>

---

## 1. Package Review bug

File at Red Hat Bugzilla → product **Fedora**, component **Package Review**
(<https://bugzilla.redhat.com/enter_bug.cgi?product=Fedora&component=Package%20Review>).

**Summary:**

```
Review Request: rocketsmbd - SMB2/SMB3 file server built on Linux io_uring
```

**Description:**

```
Spec URL: https://raw.githubusercontent.com/glennswest/rocketsmbd/main/packaging/rocketsmbd.spec
SRPM URL: https://github.com/glennswest/rocketsmbd/releases/download/v1.1.0/rocketsmbd-1.1.0-1.fc43.src.rpm

Description:
rocketsmbd is a from-scratch SMB2/SMB3 file server built on Linux io_uring:
accept, receive, send, and file I/O all flow through one ring per worker, and
file reads are served zero-copy from the page cache to the socket via splice.
It speaks SMB 2.0.2 through 3.1.1 with NTLMv2 authentication, SMB2/3 signing,
SMB 3.1.1 preauth integrity, SMB3 multichannel, and SMB3 encryption
(AES-128-GCM). Written in Rust; the wire parsers are fuzzed in CI.

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
  that. Per-crate `Provides: bundled(crate(NAME)) = VER` are listed (47 crates).
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

Review bug: <link once filed>

One thing I'd value SIG guidance on: it's currently bundled because it needs
io-uring 0.7 (IORING_OP_SEND_ZC) and Fedora ships rust-io-uring 0.6.4 in stable
and rawhide. Everything else resolves unbundled. I'd happily help bump
rust-io-uring to 0.7 so this (and others) can go unbundled — pointers welcome.

FAS: glennswest. Thanks!
```

The io-uring-bump offer is deliberate: helping a SIG package is a common fast
path to sponsorship and clears the unbundling blocker for everyone.

---

## 3. Publish the crate to crates.io — DONE

Published: <https://crates.io/crates/rocketsmbd> (v1.1.0). This makes rocketsmbd
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
fedpkg import ~/rpmbuild/SRPMS/rocketsmbd-1.1.0-1.fc*.src.rpm
fedpkg commit -m "Initial import (#<REVIEW_BUG_ID>)" && fedpkg push
fedpkg build                                       # rawhide (Koji)
# stable branches:
fedpkg switch-branch f41 && git merge rawhide && fedpkg push && fedpkg build
bodhi updates new --type newpackage --notes "Initial Fedora import" rocketsmbd-1.1.0-1.fc41
# optional EPEL:
fedpkg switch-branch epel9 && ... && fedpkg build && bodhi updates new ...
```

rawhide needs no Bodhi update; stable/EPEL branches do.
