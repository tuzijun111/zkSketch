export HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold
export PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"
export PATH="$HOME/.risc0/bin:$PATH"
unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME RUSTFLAGS
export BASELINE_DIR=$HOME/ext-baselines
WT=/home/binbin/zkSketch/.claude/worktrees/m1-gk-matched
SP=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m1
