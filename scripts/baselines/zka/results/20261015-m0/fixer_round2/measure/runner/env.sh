export HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold
export PATH=/usr/local/bin:/usr/bin:/bin
. "$HOME/.cargo/env"
export PATH="$HOME/.risc0/bin:$PATH"
unset CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR RISC0_HOME
export TMPDIR=/tmp
cd $HOME/zkSketch
