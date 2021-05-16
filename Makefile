CARGO := cargo
CP := cp
INSTALL := install
RM := rm
STRIP := strip

DEBUG := 0
DESTDIR ?=
PREFIX ?= /usr/local

CARGO_FLAGS ?=
TARGET_CPU ?=
TARGET_FEATURES ?=

RUSTC_FLAGS ?=
ifneq ($(strip $(TARGET_CPU)),)
	RUSTC_FLAGS += -C target-cpu=$(TARGET_CPU)
endif
ifneq ($(strip $(TARGET_FEATURES)),)
	RUSTC_FLAGS += -C target-feature=$(TARGET_FEATURES)
endif

.PHONY: default
default: chksum

.PHONY: bench
bench:
	RUSTFLAGS="$(RUSTC_FLAGS)" $(CARGO) bench $(CARGO_FLAGS)

.PHONY: check
check:
	RUSTFLAGS="$(RUSTC_FLAGS)" $(CARGO) check $(CARGO_FLAGS)

.PHONY: install
install: $(DESTDIR)$(PREFIX)/bin/chksum $(DESTDIR)$(PREFIX)/share/fish/completions/chksum.fish $(DESTDIR)$(PREFIX)/share/man/man1/chksum.1

.PHONY: uninstall
uninstall:
	$(RM) -f $(DESTDIR)$(PREFIX)/bin/chksum
	$(RM) -f $(DESTDIR)$(PREFIX)/share/fish/completions/chksum.fish
	$(RM) -f $(DESTDIR)$(PREFIX)/share/man/man1/chksum.1

.PHONY: clean
clean:
	$(CARGO) clean
	$(RM) -f chksum

.PHONY: test
test:
ifeq ($(DEBUG), 0)
	RUSTFLAGS="$(RUSTC_FLAGS)" $(CARGO) test --release $(CARGO_FLAGS)
else
	RUSTFLAGS="$(RUSTC_FLAGS)" $(CARGO) test $(CARGO_FLAGS)
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
	RUSTFLAGS="$(RUSTC_FLAGS)" $(CARGO) build $(CARGO_FLAGS)

.PHONY: target/release/chksum
target/release/chksum:
	RUSTFLAGS="$(RUSTC_FLAGS)" $(CARGO) build --release $(CARGO_FLAGS)

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
