#!/bin/sh
# demo-setup.sh — Launches the tmux session for the VHS demo.
# Called by demo.tape before attaching.
set -e

# Clean slate
tmux kill-session -t demo 2>/dev/null || true
rm -rf /private/tmp/closedshell-* 2>/dev/null || true

# Create tmux: left pane = TUI (placeholder), right pane = cs + claude
tmux new-session -s demo -d -x 300 -y 60

# Right pane
tmux split-window -h -t demo

# Left pane narrower (40/60 split)
tmux resize-pane -t demo:0.0 -x 110

# Start cs + claude in headless mode in right pane
tmux send-keys -t demo:0.1 \
  'cs --template anthropic/full -- claude "Use the exa MCP tool to research the best restaurants in NYC and give me a short list"' C-m

# Wait for cs to start and create its tmp dir
sleep 3

# Find session ID and start TUI in left pane
SESSION_ID=$(ls /private/tmp | grep closedshell- | head -1 | sed 's/closedshell-//')
if [ -z "$SESSION_ID" ]; then
  echo "ERROR: no closedshell session found" >&2
  exit 1
fi
tmux send-keys -t demo:0.0 "cs --tui ${SESSION_ID}" C-m
