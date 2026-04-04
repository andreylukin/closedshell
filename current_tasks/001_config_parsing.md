# Task: Config Parsing

**Status:** partial (struct + YAML parsing done, needs load_config to resolve ~ paths and merge with CLI flags)

**What to do:**
1. Expand `load_config()` in `crates/closedshell-lib/src/config.rs` to properly resolve `~` in paths
2. Add a `Config::merge_cli_flags()` method that overlays CLI args onto file config (yolo, task, templates, no_motd)
3. Add tests for merge behavior and path resolution
4. Make sure `closedshell.yaml` in current dir takes precedence over `~/.closedshell/config.yaml`

**Tests that must pass:**
- `cargo test -p closedshell-lib config`

**Files:**
- `crates/closedshell-lib/src/config.rs`
