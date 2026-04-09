# Autoresearch: Agent Instruction Optimization

Adapted from [karpathy/autoresearch](https://github.com/karpathy/autoresearch).

An AI agent autonomously optimizes the instructions we give to sandboxed agents
so they cooperate with ClosedShell's permission system.

## How it works

| autoresearch (original) | ours |
|------------------------|------|
| `train.py` (model code) | `instructions.md` (agent instructions) |
| `val_bpb` (lower = better) | pass rate % (higher = better) |
| 5 min GPU training | ~6 min LLM evaluation |
| `program.md` | `program.md` |

## Quick start

```bash
# 1. Create experiment branch
git checkout -b autoresearch/apr9

# 2. Start your agent in this repo, point it at program.md:
#    "Read autoresearch/program.md and let's kick off a new experiment!"

# 3. The agent will:
#    - Read the files
#    - Establish a baseline score
#    - Loop: modify instructions.md → run tests → keep/discard → repeat
```

## Files

```
autoresearch/
  program.md       — agent instructions (tells the optimizer what to do)
  instructions.md  — the file being optimized (sandboxed agent instructions)
  run.sh           — convenience script to run one experiment
  results.tsv      — experiment log (created by the agent)
  README.md        — this file
```

## Current best: ~80% (12/15)

The best instruction variants (v2-tool-reference, v7-combined) achieve ~80%.
Known hard problems:
- `ask context` when scope changes (0% across all variants)
- Agent lists intended commands alongside `ask plan` 
- Agent mentions "delete" when discussing denied action recovery
