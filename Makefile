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

# Install cs to ~/.cargo/bin (with closedshell symlink)
install:
	cargo install --path crates/closedshell --force
	ln -sf cs ~/.cargo/bin/closedshell
	@echo "Installed cs to ~/.cargo/bin"

# Uninstall
uninstall:
	rm -f ~/.cargo/bin/cs ~/.cargo/bin/closedshell
	@echo "Removed cs from ~/.cargo/bin"

# Clean build artifacts
clean:
	cargo clean
