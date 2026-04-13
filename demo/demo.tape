# ClosedShell Demo — Permission Approval Flow
#
# Shows cs sandboxing Claude Code with --template anthropic/full.
# When Claude tries to call the Exa API (not in the template),
# the TUI prompts for human approval.
#
# Prerequisites:
#   brew install vhs tmux
#   cargo install --path crates/closedshell   (or make install)
#   Claude Code CLI (`claude`) must be installed and authenticated
#
# Run (from repo root):
#   vhs demo/demo.tape

Require tmux

Output demo/demo.gif

Set Shell zsh
Set FontSize 16
Set Width 2400
Set Height 1200
Set Padding 10
Set TypingSpeed 50ms
Set PlaybackSpeed 1.0

# --- Setup: launch tmux + cs + claude + TUI (not recorded) ---
Hide
Type "./demo/demo-setup.sh"
Enter
# Wait for setup script to finish (cs starts, session ID found, TUI launched)
Sleep 6s
Show

# --- Attach to the running tmux session (recording starts here) ---
Type "tmux attach -t demo"
Enter
Sleep 2s

# Both panes are now visible:
#   Left:  cs TUI showing live activity
#   Right: claude running headless with the exa prompt
#
# Switch to TUI (left pane) and go to Approvals tab immediately
# so we're ready when the permission prompt appears.
Ctrl+b
Left
Sleep 500ms
Type "a"
Sleep 1s

# Wait for Claude to hit the Exa API — cs blocks, approval appears in TUI
Sleep 5s

# Keep approving any pending requests every second until the demo ends
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s
Type "y"
Sleep 1s

# --- Done ---
Sleep 3s
