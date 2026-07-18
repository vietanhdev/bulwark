# RPM spec for the Bulwark CLI, built on Fedora COPR from the tagged source
# tarball. Only `bulwarkctl` is packaged — the Tauri GUI needs WebKitGTK and is
# distributed as Flatpak/Snap/AppImage instead.
#
# COPR's mock builders have network access, so cargo fetches crates normally (no
# vendoring, unlike the Launchpad PPA whose builders are offline).
Name:           bulwarkctl
Version:        0.8.2
Release:        1%{?dist}
Summary:        Linux host security and misconfiguration scanner (CLI)

License:        Apache-2.0
URL:            https://github.com/vietanhdev/bulwark
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/bulwark-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
# ClamAV powers the optional antivirus scan; everything else works without it, and
# Bulwark detects its absence and prints a distro-aware install hint. dnf installs
# weak deps by default, so a normal install still pulls it in.
Recommends:     clamav

ExclusiveArch:  x86_64

# Disable LTO, which Fedora enables by default. libsqlite3-sys builds SQLite from
# source (the workspace enables its `bundled` feature), so the cc crate would
# compile sqlite3.c into LTO-bytecode objects that the rustc link step cannot
# resolve — failing with "undefined symbol: sqlite3_bind_null" despite bundling
# being active. (The same fix is needed in the AUR PKGBUILD via options=('!lto').)
%global _lto_cflags %{nil}

%description
Bulwark scans a Linux host for security misconfigurations and intrusion
indicators using a native Rust rule engine over declarative YAML rules, and
explains each finding in plain language with a suggested fix.

This package provides the command-line scanner. It audits the local host, or a
remote machine over SSH, with no display session required. It covers SSH/sshd
configuration, account and password policy, systemd units, cron jobs, kernel
sysctls, sensitive file permissions, file-integrity baselines, log analysis, and
AI-assistant artifact checks. Everything runs locally: no network calls, no
telemetry.

%prep
%autosetup -n bulwark-%{version}

%build
# -p bulwarkctl: build only the CLI and its library, never the Tauri GUI member
# (which would need WebKitGTK).
cargo build --release -p bulwarkctl

%install
install -Dpm0755 target/release/bulwarkctl %{buildroot}%{_bindir}/bulwarkctl

# The rule pack is load-bearing, not dressing: on an installed system
# resolve_rules_dir falls back to %{_datadir}/bulwark/rules, so a package without
# it fails on every invocation.
mkdir -p %{buildroot}%{_datadir}/bulwark
cp -r rules decoders log-rules %{buildroot}%{_datadir}/bulwark/
find %{buildroot}%{_datadir}/bulwark -type f -exec chmod 0644 {} +
find %{buildroot}%{_datadir}/bulwark -type d -exec chmod 0755 {} +

%files
%license LICENSE
%doc README.md
%{_bindir}/bulwarkctl
%{_datadir}/bulwark/

%changelog
* Sat Jul 18 2026 Viet Anh Nguyen <vietanh.dev@gmail.com> - 0.8.2-1
- Initial COPR package of the Bulwark CLI.
