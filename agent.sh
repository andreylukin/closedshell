#!/bin/bash
# Agent loop: spawns Claude Code sessions in wt worktrees.
#
# Usage:
#   ./agent.sh                    # run one agent, one session
#   ./agent.sh 4                  # run 4 agents in parallel
#   ./agent.sh --loop             # one agent, looping
#   ./agent.sh --loop 4           # 4 agents, each looping

set -euo pipefail

LOOP=false
if [[ "${1:-}" == "--loop" ]]; then
    LOOP=true
    shift
fi

NUM_AGENTS=${1:-1}
AGENT_DIR="agent_logs"
mkdir -p "$AGENT_DIR"

run_agent() {
    local agent_id=$1
    local branch="agent-${agent_id}-$(date +%s)"
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local LOGFILE="${AGENT_DIR}/agent_${agent_id}_${TIMESTAMP}.log"

    echo "[agent-${agent_id}] starting on branch ${branch}"

    # wt switch --create creates a worktree on a new branch
    # -x claude runs claude after switching
    # -- passes remaining args to claude
    wt switch --create "$branch" --no-verify -y \
        -x claude -- \
        --dangerously-skip-permissions \
        -p "$(cat AGENT_PROMPT.md)" \
        --model claude-opus-4-6 \
        &> "$LOGFILE" || true

    echo "[agent-${agent_id}] session ended, log: ${LOGFILE}"
}

run_agent_loop() {
    local agent_id=$1
    while true; do
        run_agent "$agent_id"
        sleep 2
    done
}

runner="run_agent"
if $LOOP; then
    runner="run_agent_loop"
fi

if [ "$NUM_AGENTS" -eq 1 ]; then
    $runner 1
else
    for i in $(seq 1 "$NUM_AGENTS"); do
        $runner "$i" &
    done
    wait
fi
