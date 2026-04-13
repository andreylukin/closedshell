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

Permission templates are `.csp` files (Cedar-inspired ClosedShell Policy format) that pre-approve endpoints for specific providers. They don't require any Rust knowledge and are the fastest way to contribute. Templates in `templates/` are compiled into the binary at build time.

**Adding a template for a new provider:**

```bash
cs template init myservice              # scaffold
$EDITOR ~/.closedshell/templates/myservice/full.csp
cs template validate myservice/full     # check for errors
cs template check myservice/full "net:GET:api.myservice.com/v1/data"  # test actions
```

Or observe traffic first, then codify:

```bash
cs --yolo -- <command>                  # capture traffic
cs template generate <session-id> --name myservice-full --save
cs template validate myservice/full     # review
```

See [templates/CONTRIBUTING.md](templates/CONTRIBUTING.md) for the full format and guidelines.

**Wanted templates:** We'd love community templates for Terraform, Vercel, Netlify, Supabase, npm/PyPI publish, Docker Hub, and any other services agents commonly hit. Check the [issues](https://github.com/andreylukin/closedshell/issues) for specific requests.

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
