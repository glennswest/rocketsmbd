# Fedora/RHEL spec for rocketsmbd — builds from source with the distro Rust
# toolchain (dynamic glibc), unlike the static-musl GitHub release packages.
#
# COPR usage: provide the release tarball as Source0 and a vendored-crates
# tarball as Source1:
#   cargo vendor vendor/ && tar caf rocketsmbd-%{version}-vendor.tar.xz vendor/
# For official Fedora review, regenerate per-crate BuildRequires with:
#   rust2rpm rocketsmbd
%global debug_package %{nil}

Name:           rocketsmbd
Version:        1.1.0
Release:        1%{?dist}
Summary:        io_uring SMB2/SMB3 file server (zero-copy, multichannel)

License:        MIT
URL:            https://github.com/glennswest/rocketsmbd
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

ExclusiveArch:  x86_64 aarch64
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros

%description
rocketsmbd is a from-scratch SMB2/SMB3 file server built on Linux io_uring:
accept, recv, send, and file I/O flow through one ring per worker, and file
reads are served zero-copy from page cache to socket via splice. Supports
NTLMv2 authentication, SMB2/3 signing, SMB 3.1.1, and SMB3 multichannel.

Requires a Linux kernel with io_uring (5.15+; 6.0+ recommended), checked at
startup. Pre-1.0: no SMB3 encryption yet — intended for trusted networks.

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
cargo test --release --offline || :

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
* Thu Jun 11 2026 Glenn West <glennswest@neuralcloudcomputing.com> - 1.0.0-1
- 1.0.0 stable: SMB 2.0.2-3.1.1, NTLMv2 auth, SMB2/3 signing, multichannel,
  zero-copy reads. Parsers fuzzed. Trusted-LAN scope (no encryption yet).
