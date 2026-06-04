Name:           crypto
Version:        1.0.0
Release:        1%{?dist}
Summary:        OpenSSL-based stdin/stdout crypto program (RSA seal/open and AES-256-CBC)

License:        GPLv3
URL:            https://github.com/gdha/crypto
# If you create a tarball, set Source0 to it, e.g.:
# Source0:        %{name}-%{version}.tar.gz
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel
# Manpage generator
BuildRequires:  rubygem-ronn-ng

# If you install the built binary and man page, RPM will auto-detect runtime deps
Requires:       openssl-libs

%description
crypto is a small CLI tool demonstrating OpenSSL EVP APIs:
- rsa-enc <pubkey.pem> / rsa-dec <privkey.pem>: hybrid RSA+AES sealing (EVP_Seal*/EVP_Open*)
- aes-keygen <keyfile>: generate a random 48-byte AES key file
- aes-enc <keyfile> / aes-dec <keyfile>: AES-256-CBC; key is never embedded in output

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
# Basic smoke tests using key files (no network, no env vars)
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
CRYPTO=%{buildroot}%{_bindir}/crypto

# AES round-trip
"$CRYPTO" aes-keygen "$TMPDIR/test.key"
RESULT=$(printf 'test' | "$CRYPTO" aes-enc "$TMPDIR/test.key" | "$CRYPTO" aes-dec "$TMPDIR/test.key")
[ "$RESULT" = "test" ]

# RSA round-trip
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMPDIR/private.pem" 2>/dev/null
openssl pkey -in "$TMPDIR/private.pem" -pubout -out "$TMPDIR/public.pem" 2>/dev/null
RESULT=$(printf 'hello' | "$CRYPTO" rsa-enc "$TMPDIR/public.pem" | "$CRYPTO" rsa-dec "$TMPDIR/private.pem")
[ "$RESULT" = "hello" ]

%files
%license LICENSE
%doc README.md
%{_bindir}/crypto
%{_mandir}/man1/crypto.1*

%changelog
* Thu Jun 04 2026 Gratien Dhaese <gratien.dhaese@gmail.com> - 2.0.0-1
- Rewrite to improve security
* Tue Mar 03 2026 Gratien Dhaese <gratien.dhaese@gmail.com> - 1.0.0-1
- Initial RPM packaging
