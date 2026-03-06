Name:           crypto
Version:        1.0.0
Release:        1%{?dist}
Summary:        OpenSSL-based stdin/stdout crypto program (RSA seal/open and AES-256-CBC)

License:        GPLv3
URL:            https://github.com/shanet/Crypto-Example
# If you create a tarball, set Source0 to it, e.g.:
# Source0:        %{name}-%{version}.tar.gz
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel
# Manpage generator
BuildRequires:  rubygem-ronn

# If you install the built binary and man page, RPM will auto-detect runtime deps
Requires:       openssl-libs

%description
crypto is a small CLI tool demonstrating OpenSSL EVP APIs:
- rsa-enc / rsa-dec: hybrid RSA+AES sealing (EVP_Seal*/EVP_Open*)
- aes-enc / aes-dec: AES-256-CBC with an embedded key+iv container (demo only)

It reads from stdin and writes to stdout, suitable for pipelines.

The code is based on the c++ code of https://github.com/shanet/Crypto-Example

%prep
%autosetup -n crypto-%{version}

%build
# Build binary + man page (Makefile uses ronn for crypto.1)
%make_build all

%install
rm -rf %{buildroot}
# Our Makefile supports DESTDIR and PREFIX
%make_install PREFIX=%{_prefix} DESTDIR=%{buildroot} install

%check
# Basic smoke tests (no network, just local)
printf "test" | %{buildroot}%{_bindir}/crypto aes-enc | %{buildroot}%{_bindir}/crypto aes-dec | grep -qx "test"
printf "hello" | %{buildroot}%{_bindir}/crypto rsa-enc | %{buildroot}%{_bindir}/crypto rsa-dec | grep -qx "hello"

%files
%license LICENSE* COPYING* 2>/dev/null || :
%doc README* 2>/dev/null || :
%{_bindir}/crypto
%{_mandir}/man1/crypto.1*

%changelog
* Tue Mar 03 2026 Gratien Dhaese <gratien.dhaese@gmail.com> - 1.0.0-1
- Initial RPM packaging
