# wsl-webauthn-pam build orchestration (plan §2).
# The real cross-platform CI lives in .github/workflows; this Makefile is a
# convenience wrapper for local development.
#
# Windows bridge: prefer cargo.exe (native MSVC) when present on PATH, else fall
# back to the self-contained x86_64-pc-windows-gnu cross target (plan §11 env).

CARGO ?= cargo
RELEASE_DIR := build/release
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

.PHONY: all bridge test release clean

all:
	$(CARGO) build --release --workspace

# Build WSLWebAuthnBridge.exe. Tries a native Windows cargo.exe first, then the
# gnu cross target (rustup target add x86_64-pc-windows-gnu).
bridge:
	@if command -v cargo.exe >/dev/null 2>&1; then \
		echo ">> building bridge with cargo.exe (native)"; \
		cargo.exe build --release -p wsl-webauthn-bridge; \
	else \
		echo ">> cargo.exe not found; cross-compiling with x86_64-pc-windows-gnu"; \
		$(CARGO) build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu; \
	fi

test:
	$(CARGO) test --workspace

# Assemble a distributable tarball + checksums.
release: all bridge
	@rm -rf $(RELEASE_DIR)
	@mkdir -p $(RELEASE_DIR)
	cp target/release/libpam_wsl_webauthn.so $(RELEASE_DIR)/pam_wsl_webauthn.so
	@if [ -f target/x86_64-pc-windows-gnu/release/WSLWebAuthnBridge.exe ]; then \
		cp target/x86_64-pc-windows-gnu/release/WSLWebAuthnBridge.exe $(RELEASE_DIR)/; \
	else \
		cp target/release/WSLWebAuthnBridge.exe $(RELEASE_DIR)/; \
	fi
	cp target/release/wsl-webauthn-pam $(RELEASE_DIR)/
	cp install.sh pam-config README.md $(RELEASE_DIR)/
	cd $(RELEASE_DIR) && tar -czf ../wsl-webauthn-pam-$(VERSION)-x86_64.tar.gz .
	cd $(RELEASE_DIR) && sha256sum * > SHA256SUMS
	@echo ">> release assembled in $(RELEASE_DIR)"

clean:
	$(CARGO) clean
	rm -rf build
