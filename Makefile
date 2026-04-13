.PHONY: build release test lint fmt check install uninstall clean

# Development build
build:
	cargo build

# Optimized release build
release:
	cargo build --release

# Run all tests
test:
	cargo test

# Run clippy lints (fail on warnings)
lint:
	cargo clippy -- -D warnings

# Check formatting
fmt:
	cargo fmt --check

# Fix formatting
fmt-fix:
	cargo fmt

# Run all checks (what CI runs)
check: fmt lint test

# Install closedshell to ~/.cargo/bin
install:
	cargo install --path crates/closedshell --force
	@echo "Installed closedshell to ~/.cargo/bin"

# Uninstall
uninstall:
	rm -f ~/.cargo/bin/closedshell
	@echo "Removed closedshell from ~/.cargo/bin"

# Clean build artifacts
clean:
	cargo clean
