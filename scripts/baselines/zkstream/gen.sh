#!/usr/bin/env bash
# Instantiate cm_op.zok.tpl (proven) and cm_helper.zok.tpl (witness only) for N records, D rows and W columns.
# Usage: gen.sh <N> <D> <W> <outdir>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $# -eq 4 ]] || { echo "usage: gen.sh <N> <D> <W> <outdir>" >&2; exit 2; }
N=$1 D=$2 W=$3 OUT=$4
(( W >= 16 && (W & (W - 1)) == 0 )) || { echo "gen.sh: W must be a power of two >= 16 (got $W)" >&2; exit 2; }
log2() { local v=$1 r=0; while (( v > 1 )); do v=$((v >> 1)); r=$((r + 1)); done; echo "$r"; }
S=$((W / 8)); LOGS=$(log2 "$S"); RB=$(log2 "$W")
(( D * RB <= 254 )) || { echo "gen.sh: D*log2(W) = $((D * RB)) exceeds the 254 hash bits" >&2; exit 2; }
NBC=$(( (D * S + 4) / 5 )); LC=$((5 * NBC)); NBB=$(( (N + 4) / 5 )); LB=$((5 * NBB))
mkdir -p "$OUT"
for kind in cm_op cm_helper; do
  sed -e "s/__N__/$N/g" -e "s/__D__/$D/g" -e "s/__S__/$S/g" -e "s/__LOGS__/$LOGS/g" \
      -e "s/__RB__/$RB/g" -e "s/__NBC__/$NBC/g" -e "s/__LC__/$LC/g" \
      -e "s/__NBB__/$NBB/g" -e "s/__LB__/$LB/g" "$HERE/$kind.zok.tpl" > "$OUT/$kind.zok"
done
echo "N=$N D=$D W=$W S=$S LOGS=$LOGS RB=$RB NBC=$NBC LC=$LC NBB=$NBB LB=$LB -> $OUT"
