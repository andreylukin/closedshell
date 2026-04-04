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

run_agent() {
    local agent_id=$1
    local branch="agent-${agent_id}-$(date +%s)"

    wt switch --create "$branch" --no-verify -y \
        -x claude -- \
        --dangerously-skip-permissions \
        -p "$(cat AGENT_PROMPT.md)" \
        --model claude-opus-4-6
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
