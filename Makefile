# wsl-webauthn-pam build orchestration (plan §2).
#
# The real cross-platform, fully-pinned CI lives in .github/workflows/; this
# Makefile is a convenience wrapper for local development and mirrors the same
# release layout (plan §11).
#
# Windows bridge: prefer a native `cargo.exe` when present on PATH (real MSVC
# build), otherwise cross-compile with the self-contained
# `x86_64-pc-windows-gnu` target (rustup target add x86_64-pc-windows-gnu).

CARGO ?= cargo
RELEASE_DIR := build/release
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
ARCH := $(shell uname -m)
GNU_TARGET := x86_64-pc-windows-gnu

# actionlint is not packaged everywhere; fetch a pinned release into ~/.local/bin.
ACTIONLINT_VERSION ?= 1.7.12
ACTIONLINT ?= $(HOME)/.local/bin/actionlint

WORKFLOWS := .github/workflows/ci.yaml .github/workflows/release.yaml

.PHONY: all bridge test check fmt clippy deny pam-profile lint-actions release clean

# Default: Linux module + CLI (linked against libpam0g-dev) and the Windows exe.
all:
	$(CARGO) build --release --locked -p wsl-webauthn-pam -p wsl-webauthn-cli
	$(MAKE) bridge

# Build WSLWebAuthnBridge.exe. Native cargo.exe first, gnu cross target second.
bridge:
	@if command -v cargo.exe >/dev/null 2>&1; then \
		echo ">> building bridge with cargo.exe (native MSVC)"; \
		cargo.exe build --release --locked -p wsl-webauthn-bridge; \
	else \
		echo ">> cargo.exe not found; cross-compiling with $(GNU_TARGET)"; \
		$(CARGO) build --release --locked -p wsl-webauthn-bridge --target $(GNU_TARGET); \
	fi

test:
	$(CARGO) test --workspace --locked

# Local pre-flight: everything CI gates on, best-effort for tools not installed.
check: fmt clippy test deny
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

pam-profile:
	python3 .github/scripts/check-pam-profile.py --self-test
	python3 .github/scripts/check-pam-profile.py --profile pam-config

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
	  tar -xzf "$$tmp/al.tgz" -C "$$tmp" actionlint; \
	  mv "$$tmp/actionlint" "$(ACTIONLINT)"; \
	  rm -rf "$$tmp"; \
	  "$(ACTIONLINT)" --version

# Assemble build/release/ + a tarball + SHA256SUMS (plan §11 release layout).
release: all
	@rm -rf $(RELEASE_DIR)
	@mkdir -p $(RELEASE_DIR)
	cp target/release/libpam_wsl_webauthn.so $(RELEASE_DIR)/pam_wsl_webauthn.so
	@if [ -f target/$(GNU_TARGET)/release/WSLWebAuthnBridge.exe ]; then \
		cp target/$(GNU_TARGET)/release/WSLWebAuthnBridge.exe $(RELEASE_DIR)/; \
	elif [ -f target/release/WSLWebAuthnBridge.exe ]; then \
		cp target/release/WSLWebAuthnBridge.exe $(RELEASE_DIR)/; \
	else \
		echo ">> WSLWebAuthnBridge.exe not found; run 'make bridge' first" >&2; exit 1; \
	fi
	cp target/release/wsl-webauthn-pam $(RELEASE_DIR)/
	cp install.sh pam-config README.md $(RELEASE_DIR)/
	cd $(RELEASE_DIR) && sha256sum \
		pam_wsl_webauthn.so WSLWebAuthnBridge.exe wsl-webauthn-pam \
		install.sh pam-config README.md > SHA256SUMS
	tar -czf build/wsl-webauthn-pam-$(VERSION)-$(ARCH).tar.gz -C $(RELEASE_DIR) .
	@echo ">> release assembled: build/wsl-webauthn-pam-$(VERSION)-$(ARCH).tar.gz"

clean:
	$(CARGO) clean
	rm -rf build
