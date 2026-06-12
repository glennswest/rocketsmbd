# Fedora/RHEL spec for rocketsmbd.
#
# This is the BUNDLED (vendored-crates) spec. rocketsmbd requires io-uring 0.7
# (for IORING_OP_SEND_ZC and current io_uring features); Fedora currently ships
# rust-io-uring 0.6.4 in both stable and rawhide, so the dependency tree is
# vendored until rust-io-uring is updated to 0.7. Every *other* dependency is
# available unbundled (verified by an offline build against the system crate
# registry) — when rust-io-uring reaches 0.7 this can switch to a rust2rpm
# unbundled spec.
#
# COPR usage: provide the release tarball as Source0 and a vendored-crates
# tarball as Source1 (packaging/build-srpm.sh produces both).
%global debug_package %{nil}

Name:           rocketsmbd
Version:        1.1.0
Release:        1%{?dist}
Summary:        io_uring SMB2/SMB3 file server (zero-copy, multichannel)

# Effective license of the built binary = AND of all bundled crates' licenses,
# choosing MIT where a crate is dual MIT/Apache-2.0 (rocketsmbd itself is MIT).
# subtle is BSD-3-Clause only; unicode-ident mandates Unicode-3.0.
License:        MIT AND BSD-3-Clause AND Unicode-3.0
URL:            https://github.com/glennswest/rocketsmbd
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

ExclusiveArch:  x86_64 aarch64
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros

# Bundled (vendored) crates — see the header note for why.
Provides:       bundled(crate(aead)) = 0.5.2
Provides:       bundled(crate(aes)) = 0.8.4
Provides:       bundled(crate(aes-gcm)) = 0.10.3
Provides:       bundled(crate(bitflags)) = 2.13.0
Provides:       bundled(crate(block-buffer)) = 0.10.4
Provides:       bundled(crate(cfg-if)) = 1.0.4
Provides:       bundled(crate(cipher)) = 0.4.4
Provides:       bundled(crate(cmac)) = 0.7.2
Provides:       bundled(crate(cpufeatures)) = 0.2.17
Provides:       bundled(crate(crypto-common)) = 0.1.7
Provides:       bundled(crate(ctr)) = 0.9.2
Provides:       bundled(crate(dbl)) = 0.3.2
Provides:       bundled(crate(digest)) = 0.10.7
Provides:       bundled(crate(equivalent)) = 1.0.2
Provides:       bundled(crate(generic-array)) = 0.14.7
Provides:       bundled(crate(getrandom)) = 0.2.17
Provides:       bundled(crate(ghash)) = 0.5.1
Provides:       bundled(crate(hashbrown)) = 0.17.1
Provides:       bundled(crate(hmac)) = 0.12.1
Provides:       bundled(crate(indexmap)) = 2.14.0
Provides:       bundled(crate(inout)) = 0.1.4
Provides:       bundled(crate(io-uring)) = 0.7.12
Provides:       bundled(crate(libc)) = 0.2.186
Provides:       bundled(crate(md-5)) = 0.10.6
Provides:       bundled(crate(md4)) = 0.10.2
Provides:       bundled(crate(opaque-debug)) = 0.3.1
Provides:       bundled(crate(polyval)) = 0.6.2
Provides:       bundled(crate(proc-macro2)) = 1.0.106
Provides:       bundled(crate(quote)) = 1.0.45
Provides:       bundled(crate(rand_core)) = 0.6.4
Provides:       bundled(crate(serde)) = 1.0.228
Provides:       bundled(crate(serde_core)) = 1.0.228
Provides:       bundled(crate(serde_derive)) = 1.0.228
Provides:       bundled(crate(serde_spanned)) = 1.1.1
Provides:       bundled(crate(sha2)) = 0.10.9
Provides:       bundled(crate(subtle)) = 2.6.1
Provides:       bundled(crate(syn)) = 2.0.117
Provides:       bundled(crate(toml)) = 1.1.2
Provides:       bundled(crate(toml_datetime)) = 1.1.1
Provides:       bundled(crate(toml_parser)) = 1.1.2
Provides:       bundled(crate(toml_writer)) = 1.1.1
Provides:       bundled(crate(typenum)) = 1.20.1
Provides:       bundled(crate(unicode-ident)) = 1.0.24
Provides:       bundled(crate(universal-hash)) = 0.5.1
Provides:       bundled(crate(version_check)) = 0.9.5
Provides:       bundled(crate(wasi)) = 0.11.1
Provides:       bundled(crate(winnow)) = 1.0.3

%description
rocketsmbd is a from-scratch SMB2/SMB3 file server built on Linux io_uring:
accept, recv, send, and file I/O flow through one ring per worker, and file
reads are served zero-copy from page cache to socket via splice. Supports
NTLMv2 authentication, SMB2/3 signing, SMB 3.1.1, SMB3 multichannel, and SMB3
encryption (AES-128-GCM).

Requires a Linux kernel with io_uring (5.15+; 6.0+ recommended), checked at
startup.

%prep
%autosetup -n %{name}-%{version}
# Use the bundled vendored crates (offline, reproducible) — avoids depending
# on the rust-packaging macros so this builds on COPR and plain rpmbuild alike.
tar -xf %{SOURCE1}
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF

%build
cargo build --release --offline

%install
install -Dpm0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -Dpm0644 rocketsmbd.toml.example %{buildroot}%{_sysconfdir}/%{name}.toml
install -Dpm0644 packaging/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -Dpm0644 docs/%{name}.8 %{buildroot}%{_mandir}/man8/%{name}.8

%check
cargo test --release --offline

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%license LICENSE
%doc README.md SECURITY.md
%{_bindir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}.toml
%{_unitdir}/%{name}.service
%{_mandir}/man8/%{name}.8*

%changelog
* Fri Jun 12 2026 Glenn West <glennswest@neuralcloudcomputing.com> - 1.1.0-1
- 1.1.0: SMB3 encryption (AES-128-GCM); send_zc on the buffered send path.
- Bundled spec with per-crate bundled() Provides and aggregate license; io-uring
  0.7 is newer than Fedora's 0.6.4, so the tree is vendored until that updates.
* Thu Jun 11 2026 Glenn West <glennswest@neuralcloudcomputing.com> - 1.0.0-1
- 1.0.0 stable: SMB 2.0.2-3.1.1, NTLMv2 auth, SMB2/3 signing, multichannel,
  zero-copy reads. Parsers fuzzed.
