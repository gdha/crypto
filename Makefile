# Simple Makefile for crypto (C11 + OpenSSL 3.x)
#
# Sources:
#   crypto.c crypto-func.c base64.c
#
# Man page:
#   crypto.1.md  (ronn-flavored Markdown source)
#   crypto.1     (generated roff man page via ronn)
#
# Targets:
#   make            -> build binary + man page (requires ronn)
#   make man        -> build man page only
#   make static     -> build static, stripped binary
#   make install    -> install binary and man page (DESTDIR/PREFIX supported)
#   make clean

name = crypto
specfile = packaging/rpm/$(name).spec
changelog = packaging/debian/changelog

# Version is the single source of truth in crypto.h
version := $(shell grep -m1 'define CRYPTO_VERSION' crypto.h | sed 's/.*"\(.*\)".*/\1/')

distversion = $(version)
rpmrelease =


CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto -lm

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

BIN := crypto
SRCS := crypto.c crypto-func.c base64.c
OBJS := $(SRCS:.c=.o)

MAN_MD := crypto.1.md
MAN_ROFF := crypto.1

.PHONY: all man install clean static test version release

all: $(BIN) man

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

man: $(MAN_ROFF)

# ronn generates crypto.1 from crypto.1.md
$(MAN_ROFF): $(MAN_MD)
	@command -v ronn >/dev/null 2>&1 || { \
		echo "error: ronn not found. Install with: gem install ronn"; \
		exit 1; \
	}
	ronn --roff --pipe < "$(MAN_MD)" > "$(MAN_ROFF)"

install: $(BIN) man
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(BIN)" "$(DESTDIR)$(BINDIR)/$(BIN)"
	install -d "$(DESTDIR)$(MANDIR)/man1"
	install -m 0644 "$(MAN_ROFF)" "$(DESTDIR)$(MANDIR)/man1/$(MAN_ROFF)"

dist: clean dist/$(name)-$(distversion).tar.gz

dist/$(name)-$(distversion).tar.gz:
	@echo "\033[1m== Building archive $(name)-$(distversion) ==\033[0;0m"
	tar -czf dist/$(name)-$(distversion).tar.gz --transform='s,^,$(name)-$(version)/,S' \
	Makefile packaging LICENSE *.c *.h README.md $(name).1.md

rpm: dist
	@echo "\033[1m== Building RPM package $(name)-$(distversion)==\033[0;0m"
	rpmbuild -ta --clean \
		--define "_rpmfilename dist/%%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
		--define "debug_package %{nil}" \
		--define "_rpmdir %(pwd)" dist/$(name)-$(distversion).tar.gz

deb: dist
	@echo "\033[1m== Building DEB package $(name)-$(distversion)==\033[0;0m"
	cp -r packaging/debian/ .
	chmod 755 debian/rules
	fakeroot debian/rules clean
	fakeroot dh_install
	fakeroot debian/rules binary
	fakeroot dh_builddeb --destdir=dist
	-rm -rf debian/


static: $(OBJS)
	$(CC) $(LDFLAGS) -static -Wl,-s -o $(BIN) $(OBJS) $(LDLIBS)

version:
	@echo "$(version)"

# release: propagate CRYPTO_VERSION from crypto.h into the RPM spec and
# Debian changelog so they stay in sync.  Run this after bumping the version
# in crypto.h before cutting a release.
release:
	@echo "\033[1m== Syncing version $(version) into packaging files ==\033[0;0m"
	sed -i 's/^Version:.*/Version:        $(version)/' $(specfile)
	sed -i 's/^Release:.*/Release:        1%{?dist}/' $(specfile)
	@# Prepend a new Debian changelog entry (dch is preferred, but sed keeps
	@# the dependency footprint small)
	@CURDATE=$$(date -R) && \
	{ echo "crypto ($(version)-1) unstable; urgency=medium"; \
	  echo ""; \
	  echo "  * Release $(version)."; \
	  echo ""; \
	  echo " -- Gratien Dhaese <gratien.dhaese@gmail.com>  $$CURDATE"; \
	  echo ""; \
	  cat $(changelog); \
	} > $(changelog).tmp && mv $(changelog).tmp $(changelog)
	@echo "Done. Review packaging/rpm/crypto.spec and packaging/debian/changelog."

clean:
	rm -f $(BIN) $(OBJS) $(MAN_ROFF)

test: $(BIN)
	@echo "\033[1m== Testing crypto ==\033[0;0m"
	@TMPDIR=$$(mktemp -d) && trap 'rm -rf "$$TMPDIR"' EXIT && \
	  AES_KEY="$$TMPDIR/test.key" && \
	  RSA_PRIV="$$TMPDIR/private.pem" && \
	  RSA_PUB="$$TMPDIR/public.pem" && \
	  PLAIN="crypto test string" && \
	  ./$(BIN) aes-keygen "$$AES_KEY" 2>/dev/null && \
	  RESULT=$$(printf '%s' "$$PLAIN" | ./$(BIN) aes-enc "$$AES_KEY" | ./$(BIN) aes-dec "$$AES_KEY") && \
	  [ "$$RESULT" = "$$PLAIN" ] && echo "  PASS  AES round-trip" || { echo "  FAIL  AES round-trip"; exit 1; } && \
	  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$$RSA_PRIV" 2>/dev/null && \
	  openssl pkey -in "$$RSA_PRIV" -pubout -out "$$RSA_PUB" 2>/dev/null && \
	  RESULT=$$(printf '%s' "$$PLAIN" | ./$(BIN) rsa-enc "$$RSA_PUB" | ./$(BIN) rsa-dec "$$RSA_PRIV") && \
	  [ "$$RESULT" = "$$PLAIN" ] && echo "  PASS  RSA round-trip" || { echo "  FAIL  RSA round-trip"; exit 1; }
	@echo
