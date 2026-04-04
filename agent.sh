#!/bin/bash
# Agent loop: spawns Claude Code sessions in wt worktrees.
#
# Usage:
#   ./agent.sh                    # run one agent, one session
#   ./agent.sh 4                  # run 4 agents in parallel
#   ./agent.sh --loop             # one agent, looping
#   ./agent.sh --loop 4           # 4 agents, each looping
#
# Logs: agent_logs/agent_<id>_<timestamp>.log (full claude output)
#        agent_logs/supervisor.log           (high-level events)

set -euo pipefail

LOOP=false
if [[ "${1:-}" == "--loop" ]]; then
    LOOP=true
    shift
fi

NUM_AGENTS=${1:-1}
AGENT_DIR="agent_logs"
mkdir -p "$AGENT_DIR"

SUPERVISOR_LOG="${AGENT_DIR}/supervisor.log"

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" | tee -a "$SUPERVISOR_LOG"
}

run_agent() {
    local agent_id=$1
    local branch="agent-${agent_id}-$(date +%s)"
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local LOGFILE="${AGENT_DIR}/agent_${agent_id}_${TIMESTAMP}.log"

    log "[agent-${agent_id}] starting on branch ${branch} → ${LOGFILE}"

    local start_time=$SECONDS

    wt switch --create "$branch" --no-verify -y \
        -x claude -- \
        --dangerously-skip-permissions \
        -p "$(cat AGENT_PROMPT.md)" \
        --model claude-opus-4-6 \
        2>&1 | tee "$LOGFILE"
    local exit_code=${PIPESTATUS[0]}

    local duration=$(( SECONDS - start_time ))
    local lines=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)

    if [ $exit_code -eq 0 ]; then
        log "[agent-${agent_id}] completed in ${duration}s (${lines} lines output)"
    else
        log "[agent-${agent_id}] exited with code ${exit_code} after ${duration}s (${lines} lines output)"
        # Log last 5 lines of output for quick debugging
        log "[agent-${agent_id}] tail:"
        tail -5 "$LOGFILE" 2>/dev/null | while IFS= read -r line; do
            log "  ${line}"
        done
    fi
}

run_agent_loop() {
    local agent_id=$1
    local session=0
    while true; do
        session=$((session + 1))
        log "[agent-${agent_id}] session ${session}"
        run_agent "$agent_id"
        sleep 2
    done
}

log "supervisor starting: ${NUM_AGENTS} agent(s), loop=${LOOP}"

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
