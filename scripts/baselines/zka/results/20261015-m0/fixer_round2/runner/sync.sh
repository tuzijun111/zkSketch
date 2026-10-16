#!/usr/bin/env bash
# Sync the m0-harness worktree (HEAD + uncommitted diff) into the sandbox clone.
set -euo pipefail
WT=/home/binbin/zkSketch/.claude/worktrees/m0-harness
SB=/home/binbin/six-repro-verify/round-shared/home-r3cold/zkSketch
P=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m0fix/wip.patch
git -C $WT diff --binary HEAD > $P
cd $SB
git checkout -q -- . 
git fetch -q /home/binbin/zkSketch m0-harness && git checkout -q -B m0-harness FETCH_HEAD
git status --short
[[ -s $P ]] && git apply $P
git status --short
