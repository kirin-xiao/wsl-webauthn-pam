# wsl-webauthn-pam build orchestration.
#
# The real cross-platform, fully-pinned CI lives in .github/workflows/; this
# Makefile is a convenience wrapper for local development and mirrors the same
# release layout.
#
# Windows bridge: prefer a native `cargo.exe` when present on PATH (real MSVC
# build), otherwise cross-compile to a self-contained GNU/LLVM target (see the
# ARCH/GNU_TARGET mapping below; rustup target add <GNU_TARGET>).

CARGO ?= cargo
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

# A single mapping from the host CPU to (a) the release arch label used by
# release.yaml (`x86_64` | `aarch64`) and (b) the matching Windows bridge
# cross-target. Deriving both from one input keeps the tarball name, the bridge
# .exe architecture and the release workflow's naming coherent, and
# `arm64`/`amd64` are normalized so a macOS/ARM spelling cannot leak into an
# artifact name. An unsupported architecture is a hard error (see the checks in
# `bridge`/`release`) instead of a mislabeled x86_64 build.
HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),x86_64)
  ARCH := x86_64
  GNU_TARGET := x86_64-pc-windows-gnu
else ifeq ($(HOST_ARCH),amd64)
  ARCH := x86_64
  GNU_TARGET := x86_64-pc-windows-gnu
else ifeq ($(HOST_ARCH),aarch64)
  ARCH := aarch64
  GNU_TARGET := aarch64-pc-windows-gnullvm
else ifeq ($(HOST_ARCH),arm64)
  ARCH := aarch64
  GNU_TARGET := aarch64-pc-windows-gnullvm
else
  ARCH :=
  GNU_TARGET :=
endif

# The local release layout mirrors release.yaml exactly — the tarball root is a
# single `wsl-webauthn-pam-<version>-<arch>/` directory, and SHA256SUMS covers
# the tarballs (not the files inside them).
PKG_DIR := wsl-webauthn-pam-$(VERSION)-$(ARCH)
STAGE_DIR := build/$(PKG_DIR)
TARBALL := build/$(PKG_DIR).tar.gz

# actionlint is not packaged everywhere; fetch a pinned release into ~/.local/bin.
# The tarball is verified against a per-(os, arch) SHA-256 below, taken from the
# upstream `actionlint_<ver>_checksums.txt`. Bump both the version and the
# matching hashes together (see CONTRIBUTING.md).
ACTIONLINT_VERSION ?= 1.7.12
ACTIONLINT ?= $(HOME)/.local/bin/actionlint

WORKFLOWS := .github/workflows/ci.yaml .github/workflows/release.yaml

.PHONY: all bridge test check fmt clippy deny machete pam-profile crlf lint-actions release clean

# Default: Linux module + CLI (linked against libpam0g-dev) and the Windows exe.
all:
	$(CARGO) build --release --locked -p wsl-webauthn-pam -p wsl-webauthn-cli
	$(MAKE) bridge

# Build WSLWebAuthnBridge.exe. Native cargo.exe first, GNU cross target second.
bridge:
	@if [ -z "$(ARCH)" ]; then \
		echo ">> unsupported host arch '$(HOST_ARCH)' (expected x86_64/amd64/aarch64/arm64)" >&2; \
		exit 1; \
	fi
	@if command -v cargo.exe >/dev/null 2>&1; then \
		echo ">> building bridge with cargo.exe (native MSVC)"; \
		cargo.exe build --release --locked -p wsl-webauthn-bridge; \
	else \
		echo ">> cargo.exe not found; cross-compiling with $(GNU_TARGET)"; \
		$(CARGO) build --release --locked -p wsl-webauthn-bridge --target $(GNU_TARGET); \
	fi

# Tests opt into the module's in-process audit recorder (a runtime switch, not a cargo
# feature) so their synthetic auth lines never reach the real journal. Production never
# calls the switch, so the shipped cdylib always compiles and uses the syslog path.
test:
	$(CARGO) test --workspace --locked

# Local pre-flight: fast local subset of the CI gate (see
# .github/workflows/ci.yaml for the full set), best-effort for tools not installed.
check: fmt clippy test crlf deny machete
	@echo ">> check complete"

fmt:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

deny:
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo-deny check; \
	else \
		echo ">> cargo-deny not installed; skipping (cargo install cargo-deny)"; \
	fi

machete:
	@if command -v cargo-machete >/dev/null 2>&1; then \
		cargo-machete; \
	else \
		echo ">> cargo-machete not installed; skipping (cargo install cargo-machete)"; \
	fi

pam-profile:
	python3 .github/scripts/check-pam-profile.py --self-test
	python3 .github/scripts/check-pam-profile.py --profile pam-config

# No tracked text file may contain CR: a CRLF committed into bootstrap.sh or
# pam-config breaks them on Windows checkouts (autocrlf). `git grep -I` skips
# binaries; the pattern is a literal CR built portably (dash has no $'…').
crlf:
	@if git grep -I -l "$$(printf '\r')" -- . ; then \
		echo ">> CR (CRLF) found in tracked text files above" >&2; \
		exit 1; \
	fi
	@echo ">> no CR in tracked text files"

# Lint the workflow YAML with a pinned actionlint, downloading it if needed.
lint-actions: $(ACTIONLINT)
	$(ACTIONLINT) -color $(WORKFLOWS)

$(ACTIONLINT):
	@mkdir -p $(HOME)/.local/bin
	@set -eu; \
	  case "$$(uname -s)" in Darwin) os=darwin;; *) os=linux;; esac; \
	  case "$$(uname -m)" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo ">> unsupported arch $$(uname -m) for actionlint" >&2; exit 1;; esac; \
	  url="https://github.com/rhysd/actionlint/releases/download/v$(ACTIONLINT_VERSION)/actionlint_$(ACTIONLINT_VERSION)_$${os}_$${a}.tar.gz"; \
	  echo ">> downloading actionlint v$(ACTIONLINT_VERSION) ($${os}/$${a})"; \
	  tmp=$$(mktemp -d); \
	  curl -fsSL "$$url" -o "$$tmp/al.tgz"; \
	  echo ">> verifying actionlint v$(ACTIONLINT_VERSION) ($${os}/$${a}) SHA-256"; \
	  case "$(ACTIONLINT_VERSION)/$${os}/$${a}" in \
	    1.7.12/darwin/amd64) expected=5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644;; \
	    1.7.12/darwin/arm64) expected=aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f;; \
	    1.7.12/linux/amd64)  expected=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8;; \
	    1.7.12/linux/arm64)  expected=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6;; \
	    *) echo ">> no pinned SHA-256 for actionlint $(ACTIONLINT_VERSION) ($${os}/$${a}); refusing to install unverified" >&2; exit 1;; \
	  esac; \
	  actual=$$(sha256sum "$$tmp/al.tgz" | awk '{print $$1}'); \
	  [ "$$actual" = "$$expected" ] || { echo ">> actionlint SHA-256 mismatch: got $$actual, want $$expected" >&2; exit 1; }; \
	  tar -xzf "$$tmp/al.tgz" -C "$$tmp" actionlint; \
	  mv "$$tmp/actionlint" "$(ACTIONLINT)"; \
	  rm -rf "$$tmp"; \
	  "$(ACTIONLINT)" --version

# Assemble the per-arch tarball + top-level SHA256SUMS: the tarball root is the
# single `wsl-webauthn-pam-<version>-<arch>/` directory and SHA256SUMS covers the
# tarballs. `make all` has already built both the Linux module/CLI and the bridge.
release: all
	@if [ -z "$(ARCH)" ]; then \
		echo ">> unsupported host arch '$(HOST_ARCH)' (expected x86_64/amd64/aarch64/arm64)" >&2; \
		exit 1; \
	fi
	@rm -rf $(STAGE_DIR) $(TARBALL)
	@mkdir -p $(STAGE_DIR)
	cp target/release/libpam_wsl_webauthn.so $(STAGE_DIR)/pam_wsl_webauthn.so
	@if [ -f target/$(GNU_TARGET)/release/WSLWebAuthnBridge.exe ]; then \
		cp target/$(GNU_TARGET)/release/WSLWebAuthnBridge.exe $(STAGE_DIR)/; \
	elif [ -f target/release/WSLWebAuthnBridge.exe ]; then \
		cp target/release/WSLWebAuthnBridge.exe $(STAGE_DIR)/; \
	else \
		echo ">> WSLWebAuthnBridge.exe not found; run 'make bridge' first" >&2; exit 1; \
	fi
	cp target/release/wsl-webauthn-pam bootstrap.sh pam-config README.md $(STAGE_DIR)/
	tar -czf $(TARBALL) -C build $(PKG_DIR)
	cd build && sha256sum $(PKG_DIR).tar.gz > SHA256SUMS
	cp bootstrap.sh build/bootstrap.sh
	@echo ">> release assembled: $(TARBALL)"
	@echo ">> checksums:          build/SHA256SUMS"
	@tar -tzf $(TARBALL) | head -1

clean:
	$(CARGO) clean
	rm -rf build
