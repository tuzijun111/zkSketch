#!/usr/bin/env bash
# run_ours.sh -- zkSketch's Count-Min leaf at the same small batch sizes as run_zkstream.py.
# One batch (t=1) on one machine runs exec=sim, where total_time_ms is the leaf prove alone.
# Same d, w and AOL keys as the ZoKrates side; pinned to the same 32 hardware threads.
#   MS="16 64 256" REPS=3 scripts/baselines/zkstream/run_ours.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
MS="${MS:-16 64 256}"; REPS="${REPS:-3}"; D="${D:-3}"; W="${W:-1024}"
refuse_if_busy
mkdir -p "$RESULTS"
OUTCSV="$RESULTS/zks_small.csv"
( cd "$ZKS" && cargo build --release --example exp_compose 2>&1 | tail -1 )
BIN="$ZKS/target/release/examples/exp_compose"
# exp_compose rewrites results/env.json; restore it afterwards.
ENVJ="$ZKS/results/env.json"; BAK=""
if [[ -f $ENVJ ]]; then BAK="$(mktemp)"; cp "$ENVJ" "$BAK"; fi
trap '[[ -n $BAK ]] && mv -f "$BAK" "$ENVJ"' EXIT
echo "load1=$(cut -d" " -f1 /proc/loadavg) pin=$PIN_CPUS d=$D w=$W m=[$MS] reps=$REPS -> $OUTCSV"
for m in $MS; do
  for r in $(seq 1 "$REPS"); do
    name="zkstream_ours_d${D}_w${W}_m${m}_r${r}_$$.csv"
    ( cd "$ZKS" && EXP_COMPOSE_FAMILY=cm EXP_D=$D EXP_W=$W EXP_COMPOSE_N=$m EXP_COMPOSE_BATCHES=$m \
        EXP_COMPOSE_MODE=forest EXP_COMPOSE_EXEC=sim EXP_DATASET=aol EXP_COMPOSE_CORES=32 EXP_OUT=$name \
        taskset -c "$PIN_CPUS" "$BIN" >/dev/null 2>&1 )
    src="$ZKS/results/$name"
    [[ -f $src ]] || { echo "run_ours.sh: no output for m=$m rep=$r" >&2; exit 1; }
    [[ -f $OUTCSV ]] || echo "rep,$(head -1 "$src")" > "$OUTCSV"
    echo "$r,$(sed -n 2p "$src")" >> "$OUTCSV"
    awk -F, -v m="$m" -v r="$r" 'NR==1{for(i=1;i<=NF;i++)h[$i]=i}
      NR==2{printf "  m=%-5s rep=%s total_ms=%s verify_ms=%s proof_B=%s rss_MB=%s\n", m, r,
            $h["total_time_ms"], $h["verify_ms"], $h["proof_bytes"], $h["peak_rss_mb"]}' "$src"
    rm -f "$src"
  done
done
echo "done -> $OUTCSV"
