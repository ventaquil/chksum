CARGO := cargo
CP := cp
INSTALL := install
RM := rm
STRIP := strip

DEBUG := 0
DESTDIR ?=
PREFIX ?= /usr/local

.PHONY: default
default: chksum

.PHONY: bench
bench:
	$(CARGO) bench

.PHONY: check
check: test

.PHONY: install
install: $(DESTDIR)$(PREFIX)/bin/chksum $(DESTDIR)$(PREFIX)/share/fish/completions/chksum.fish $(DESTDIR)$(PREFIX)/share/man/man1/chksum.1

.PHONY: uninstall
uninstall:
	$(RM) -f $(DESTDIR)$(PREFIX)/bin/chksum
	$(RM) -f $(DESTDIR)$(PREFIX)/share/fish/completions/chksum.fish
	$(RM) -f $(DESTDIR)$(PREFIX)/share/man/man1/chksum.1

.PHONY: clean
clean: uninstall
	$(CARGO) clean
	$(RM) -f chksum

.PHONY: test
test:
ifeq ($(DEBUG), 0)
	$(CARGO) test --release
else
	$(CARGO) test
endif

ifeq ($(DEBUG), 0)
chksum: target/release/chksum
	$(CP) target/release/chksum chksum
	$(STRIP) chksum
else
chksum: target/debug/chksum
	$(CP) target/debug/chksum chksum
endif

.PHONY: target/debug/chksum
target/debug/chksum:
	$(CARGO) build

.PHONY: target/release/chksum
target/release/chksum:
	$(CARGO) build --release

$(DESTDIR)$(PREFIX):
	$(INSTALL) -m 755 -d $(DESTDIR)$(PREFIX)

$(DESTDIR)$(PREFIX)/bin: $(DESTDIR)$(PREFIX)
	$(INSTALL) -m 755 -d $(DESTDIR)$(PREFIX)/bin

$(DESTDIR)$(PREFIX)/bin/chksum: $(DESTDIR)$(PREFIX)/bin target/release/chksum
	$(INSTALL) -m 755 target/release/chksum $(DESTDIR)$(PREFIX)/bin

$(DESTDIR)$(PREFIX)/share: $(DESTDIR)$(PREFIX)
	$(INSTALL) -m 755 -d $(DESTDIR)$(PREFIX)/share

$(DESTDIR)$(PREFIX)/share/fish: $(DESTDIR)$(PREFIX)/share
	$(INSTALL) -m 755 -d $(DESTDIR)$(PREFIX)/share/fish

$(DESTDIR)$(PREFIX)/share/fish/completions: $(DESTDIR)$(PREFIX)/share/fish
	$(INSTALL) -m 755 -d $(DESTDIR)$(PREFIX)/share/fish/completions

$(DESTDIR)$(PREFIX)/share/fish/completions/chksum.fish: $(DESTDIR)$(PREFIX)/share/fish/completions extra/completions/chksum.fish
	$(INSTALL) -m 755 extra/completions/chksum.fish $(DESTDIR)$(PREFIX)/share/fish/completions

$(DESTDIR)$(PREFIX)/share/man: $(DESTDIR)$(PREFIX)/share
	$(INSTALL) -m 755 -d $(DESTDIR)$(PREFIX)/share/man

$(DESTDIR)$(PREFIX)/share/man/man1: $(DESTDIR)$(PREFIX)/share/man
	$(INSTALL) -m 755 -d $(DESTDIR)$(PREFIX)/share/man/man1

$(DESTDIR)$(PREFIX)/share/man/man1/chksum.1: $(DESTDIR)$(PREFIX)/share/man/man1 docs/man/chksum.1
	$(INSTALL) -m 644 docs/man/chksum.1 $(DESTDIR)$(PREFIX)/share/man/man1
