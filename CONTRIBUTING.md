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

## Templates — the easiest way to contribute

Permission templates are YAML files that pre-approve endpoints for specific providers. They don't require any Rust knowledge and are the fastest way to contribute.

**Adding a template for a new provider:**

```bash
cs template init myservice       # scaffold a new template
# edit templates/myservice/full.yaml
cs --yolo -- <command>           # run a YOLO session to capture traffic
cs template generate <session>   # generate template from captured traffic
```

See [templates/CONTRIBUTING.md](templates/CONTRIBUTING.md) for the full format and guidelines.

**Wanted templates:** We'd love community templates for Terraform, Vercel, Netlify, Supabase, npm/PyPI publish, Docker Hub, and any other services agents commonly hit. Check the [issues](https://github.com/andreylukin/closedshell/issues) for specific requests.

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
