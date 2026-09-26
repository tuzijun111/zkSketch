#!/usr/bin/env bash
# gen.sh <N> <S> <outdir> [CB] [SPE]
# Instantiates ss_op.zok.tpl (proven) and ss_helper.zok.tpl (witness only) for N
# records per chunk, S SpaceSaving slots, CB-bit counts (default 21) and SPE slots
# packed per committed field element (default 3), by textual constant replacement --
# the way zkStream sizes its circuits (nexmark/zokrates-nexmark/src/zokrates.rs:85-87).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $# -ge 3 && $# -le 5 ]] || { echo "usage: gen.sh <N> <S> <outdir> [CB] [SPE]" >&2; exit 2; }
N=$1 S=$2 OUT=$3 CB=${4:-21} SPE=${5:-3}
(( N >= 1 && S >= 2 )) || { echo "gen.sh: need N >= 1 and S >= 2 (got N=$N S=$S)" >&2; exit 2; }
SW=$((33 + 2 * CB))
(( CB >= 2 && SPE >= 1 && SW * SPE <= 253 )) || { echo "gen.sh: $SPE slots of $SW bits do not fit a field element" >&2; exit 2; }
EB=$((33 + CB)); NP=$(( (S + SPE - 1) / SPE )); NBC=$(( (NP + 4) / 5 )); LC=$((5 * NBC)); NBB=$(( (N + 4) / 5 )); LB=$((5 * NBB))
mkdir -p "$OUT"
for kind in ss_op ss_helper; do
  sed -e "s/__N__/$N/g" -e "s/__S__/$S/g" -e "s/__CB__/$CB/g" -e "s/__EB__/$EB/g" \
      -e "s/__SPE__/$SPE/g" -e "s/__SW__/$SW/g" \
      -e "s/__NBC__/$NBC/g" -e "s/__LC__/$LC/g" -e "s/__NBB__/$NBB/g" -e "s/__LB__/$LB/g" \
      "$HERE/$kind.zok.tpl" > "$OUT/$kind.zok"
done
echo "N=$N S=$S CB=$CB SPE=$SPE SW=$SW EB=$EB NBC=$NBC LC=$LC NBB=$NBB LB=$LB -> $OUT"
