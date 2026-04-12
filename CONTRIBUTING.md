# Contributing to ClosedShell

## Getting Started

```bash
git clone https://github.com/andreylukin/closedshell.git
cd closedshell
make build    # dev build
make check    # fmt + lint + test (what CI runs)
```

Requires Rust 1.85+ (edition 2024).

## Making Changes

1. Fork the repo and create a feature branch from `main`
2. Make your changes
3. Run `make check` — this runs formatting, clippy (warnings = errors), and all tests
4. Open a PR against `main`

### Code Style

- **rustfmt** is enforced — run `make fmt-fix` to auto-format
- **clippy** warnings are errors — `make lint` to check
- Keep changes focused. One concern per PR.

### Running Tests

```bash
make test                    # all tests
cargo test -p closedshell-lib  # library tests only
cargo test <test_name>       # single test
```

Some tests require `ANTHROPIC_KEY` to be set and are skipped in CI.

## Templates

Permission templates live in `templates/`. They have their own contribution guidelines — see [templates/CONTRIBUTING.md](templates/CONTRIBUTING.md).

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
