#!/usr/bin/env bash
# usage: manifest.sh <M>: write manifest.txt (fields as run_all.sh write_manifest) into the batchscale dir
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/env.sh
M=$1; R=/home/binbin/zkSketch/results/six/batchscale-20261013/m$M
ZKS=$PWD; BASELINE_DIR=$HOME/ext-baselines; RZ_HOME=$HOME/.risc0
pc=$(lscpu -p=SOCKET,CORE 2>/dev/null | grep -v '^#' | sort -u | wc -l)
{
  echo "# six-sketch comparison, batch-size scaling (hll ss gk only); written by the runner, fields as run_all.sh write_manifest"
  echo "mode=batchscale (individual six/*.sh scripts, run_all.sh quick chain replicated)"
  echo "started=$(date -Is)"
  echo "N=$((M * 2)) M=$M T=2 gk_cap=2048 query_points=1,2 aggr_epochs=0,1 cores=32 families=hll,ss,gk"
  echo "zka_roots=noroot zka_cm_ref=0 (no separate CM reference)"
  echo "verify_repeats=5 gate: GATE_WAIT_S=0 GATE_MAX_LOAD=8 GATE_MAX_BUSY=4"
  echo "zksketch=$(git -C "$ZKS" rev-parse HEAD) changed_files=$(git -C "$ZKS" status --porcelain | wc -l) checkout=$ZKS"
  echo "exp_compose_md5=$(md5sum < "$ZKS/target/release/examples/exp_compose" | cut -c1-12)"
  echo "zka=$(git -C "$BASELINE_DIR/zka" rev-parse HEAD) baseline_dir=$BASELINE_DIR"
  echo "host=$(hostname) kernel=$(uname -r) cpu=\"$(lscpu | sed -n 's/^Model name: *//p' | head -1)\" nproc=$(nproc) phys_cores=$pc mem_gib=$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo) / 1024 / 1024 ))"
  echo "rustc=\"$(rustc --version)\" r0vm=\"$(r0vm --version)\" rzup=\"$(rzup --version)\" python=\"$(python3 --version 2>&1)\""
  echo "risc0_toolchains=\"$(find "$RZ_HOME/toolchains" -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null)\""
  echo "mem_available_gib_at_start=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo) load_at_start=\"$(cut -d' ' -f1-3 /proc/loadavg)\""
} > "$R/manifest.txt"
cat "$R/manifest.txt"
