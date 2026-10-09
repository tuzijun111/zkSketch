#!/usr/bin/env bash
# Six-sketch comparison, zk-Analytics side, EXECUTOR ONLY (not timed; cycle counts are
# deterministic): the per-phase profile of the SS and GK aggregation guests at 2,048-record
# epochs (how much of an epoch is their Event read + batch chain), and the SS port's point
# query (`estimate`) next to the `topk --limit 1` query the comparison proves.
#   -> six_zka_prof_ss.csv, six_zka_prof_gk.csv, six_zka_prof.log
# HLL, Bloom and KMV carry the same phase profile in their six_zka_*_exec.csv rows already.
set -uo pipefail
HERE6="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE6/../common.sh"   # BASELINE_DIR, ZKS, RESULTS, PATH
EB=$BASELINE_DIR/build
KEYS=$ZKS/data/aol.keys
OUTD=$RESULTS
unset RISC0_DEV_MODE
SSB=$EB/zka-ss/release/ss
GKB=$EB/zka-gk/release/gk
for b in "$SSB" "$GKB"; do [[ -x $b ]] || { echo "missing $b (run six/build.sh)" >&2; exit 2; }; done
LOG=$OUTD/six_zka_prof.log
C=(--epoch-size 2048 --batch 8 --keys "$KEYS")
echo "# six_zka_prof $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)] executor only, not timed" > "$LOG"
echo "# zka=$(git -C "$ZKA" rev-parse --short=12 HEAD) zkSketch=$(git -C "$ZKS" rev-parse --short=9 HEAD)" >> "$LOG"
"$SSB" --header > "$OUTD/six_zka_prof_ss.csv"
while read -r args; do
  echo "# ss $args" >> "$LOG"
  # shellcheck disable=SC2086
  "$SSB" $args --capacity 1024 "${C[@]}" >> "$OUTD/six_zka_prof_ss.csv" 2>> "$LOG"; echo "# rc=$?" >> "$LOG"
done <<'EOF'
--mode aggr --epoch-index 0 --profile
--mode aggr --epoch-index 7 --profile
--mode query --epochs 1 --query topk --limit 1 --profile
--mode query --epochs 8 --query topk --limit 1 --profile
--mode query --epochs 1 --query estimate --point-rank 1
--mode query --epochs 8 --query estimate --point-rank 1
--mode query --epochs 1 --query estimate --point-rank 1 --profile
--mode query --epochs 8 --query estimate --point-rank 1 --profile
EOF
"$GKB" --header > "$OUTD/six_zka_prof_gk.csv"
for e in 0 7; do
  echo "# gk --mode aggr --epoch-index $e --profile" >> "$LOG"
  "$GKB" --mode aggr --epoch-index "$e" --profile "${C[@]}" >> "$OUTD/six_zka_prof_gk.csv" 2>> "$LOG"
  echo "# rc=$?" >> "$LOG"
done
echo "# end $(date -Is)" >> "$LOG"
