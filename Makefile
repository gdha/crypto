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
dscfile = packaging/debian/$(name).dsc

version := $(shell awk 'BEGIN { FS=":" } /^Version:/ { print $$2}' $(specfile) | sed -e 's/ //g' -e 's/\$$//')

distversion = $(version)
rpmrelease =


CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

BIN := crypto
SRCS := crypto.c crypto-func.c base64.c
OBJS := $(SRCS:.c=.o)

MAN_MD := crypto.1.md
MAN_ROFF := crypto.1

.PHONY: all man install clean static

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
	Makefile packaging LICENSE $(name).c $(name).1.md

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
	$(CC) $(LDFLAGS) -Wl,-s -o $(BIN) $(OBJS) -Wl,-Bstatic $(LDLIBS) -Wl,-Bdynamic -ldl

clean:
	rm -f $(BIN) $(OBJS) $(MAN_ROFF)

test: $(BIN)
	@echo "\033[1m== Testing crypto ==\033[0;0m"
	printf "test" | ./$(BIN) aes-enc | ./$(BIN) aes-dec
	@echo
