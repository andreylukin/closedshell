#!/usr/bin/env bash
# Run one autoresearch experiment.
# Usage: ./autoresearch/run.sh
set -e

VARIANT="vX-autoresearch"
DEST="crates/closedshell-lib/tests/agent-instructions/${VARIANT}.md"

# Copy current instructions into test directory
cp autoresearch/instructions.md "$DEST"

# Run the test
echo "Running agent instruction tests..."
ANTHROPIC_KEY="${ANTHROPIC_KEY:-$ANTHROPIC_API_KEY}" \
  cargo test -p closedshell-lib --test agent_instructions -- --nocapture > run.log 2>&1

# Show results for our variant
echo ""
echo "=== Results ==="
grep "$VARIANT" run.log | grep -v "Running:"
echo ""
echo "=== Score ==="
grep "score:${VARIANT}" run.log
