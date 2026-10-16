#!/usr/bin/env bash
# exec1.sh <outdir>: executor evidence for the tuned implementation (sandbox clone).
R="$(cd "$(dirname "$0")" && pwd)"
. "$R/env.sh"
O=$1; mkdir -p "$O"
GKM=$BASELINE_DIR/build/zka-gk-matched/release/gk_matched
KEYS=$HOME/zkSketch/data/aol.keys
C=(--epoch-size 2048 --batch 8 --keys "$KEYS" --s 51)
{
  echo "# exec1 $(date -Is) host=$(hostname) load=[$(cut -d' ' -f1-3 /proc/loadavg)]"
  echo "# zkSketch=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) r0vm=$(r0vm --version) zka=$(git -C $BASELINE_DIR/zka rev-parse --short=12 HEAD)"
  echo "# gk_matched md5=$(md5sum < $GKM | cut -c1-12) keys md5=$(md5sum < $KEYS | cut -c1-12)"
  for g in aggr_gkm querier_gkm; do echo "# elf $g md5=$(md5sum < $BASELINE_DIR/build/zka-gk-matched/riscv-guest/gk-matched-methods/$g/riscv32im-risc0-zkvm-elf/release/$g | cut -c1-12)"; done
} > "$O/exec.log"
run() { local out=$1; shift; echo "# run $* $(date -Is) load1=$(cut -d' ' -f1 /proc/loadavg)" >> "$O/exec.log"; "$GKM" "$@" "${C[@]}" >> "$O/$out" 2>> "$O/exec.log"; echo "# rc=$?" >> "$O/exec.log"; }
for f in check aggr sweep; do "$GKM" --header > "$O/$f.csv"; done
run check.csv --mode check --epochs 4 --capacity 384 --m-sub 128 --impl tuned,fast,fixed_linear
run check.csv --mode check --epochs 2 --capacity 768 --m-sub 512 --impl all
run check.csv --mode check --epochs 2 --capacity 2048 --m-sub 2048 --impl tuned,fast
run check.csv --mode check --epochs 2 --capacity 64 --m-sub 256 --impl tuned
for cfg in "384 128" "768 512"; do set -- $cfg
  for impl in tuned fast; do for e in 0 1; do run aggr.csv --mode aggr --epoch-index $e --root noroot --capacity $1 --m-sub $2 --impl $impl; done; done
done
for e in 0 7; do run aggr.csv --mode aggr --epoch-index $e --root noroot --capacity 2048 --m-sub 2048 --impl tuned; done
for ms in 2048 512 256 128; do run sweep.csv --mode aggr --epoch-index 0 --root noroot --capacity 384 --m-sub $ms --impl tuned; done
# negative controls
for a in "--capacity 16 --m-sub 256" ; do "$GKM" --mode aggr --epoch-index 0 $a --impl tuned "${C[@]}" > /dev/null 2>> "$O/neg.log"; echo "overflow tuned rc=$? (expect 3)" >> "$O/neg.log"; done
echo "# end $(date -Is)" >> "$O/exec.log"
