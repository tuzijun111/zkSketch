#!/usr/bin/env bash
# Instantiate hll_lib/hll_op/hll_helper.zok.tpl for N records and s registers, P per field element (default min(32, s)).
# Usage: [CK=8] gen.sh <N> <s> <outdir> [P]   (CK: fresh state wires every CK records)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $# -eq 3 || $# -eq 4 ]] || { echo "usage: gen.sh <N> <s> <outdir> [P]" >&2; exit 2; }
N=$1 SREG=$2 OUT=$3
(( SREG >= 16 && (SREG & (SREG - 1)) == 0 )) || { echo "gen.sh: s must be a power of two >= 16 (got $SREG)" >&2; exit 2; }
log2() { local v=$1 r=0; while (( v > 1 )); do v=$((v >> 1)); r=$((r + 1)); done; echo "$r"; }
B=$(log2 "$SREG"); Q=$((64 - B))
P=${4:-$(( SREG < 32 ? SREG : 32 ))}
(( P >= 1 && P <= 32 && P <= SREG && (P & (P - 1)) == 0 )) || { echo "gen.sh: P must be a power of two in [1, min(32, s)] (got $P)" >&2; exit 2; }
CK=${CK:-8}; (( CK >= 1 )) || { echo "gen.sh: CK must be >= 1" >&2; exit 2; }
LOGP=$(log2 "$P"); S=$((SREG / P)); LOGS=$(log2 "$S"); WB=$((6 * P))
NBC=$(( (S + 4) / 5 )); LC=$((5 * NBC)); NBB=$(( (N + 4) / 5 )); LB=$((5 * NBB))
mkdir -p "$OUT"
for kind in hll_lib hll_op hll_helper; do
  sed -e "s/__N__/$N/g" -e "s/__B__/$B/g" -e "s/__Q__/$Q/g" -e "s/__P__/$P/g" \
      -e "s/__LOGP__/$LOGP/g" -e "s/__S__/$S/g" -e "s/__LOGS__/$LOGS/g" -e "s/__WB__/$WB/g" \
      -e "s/__NBC__/$NBC/g" -e "s/__LC__/$LC/g" -e "s/__NBB__/$NBB/g" -e "s/__LB__/$LB/g" -e "s/__CK__/$CK/g" \
      "$HERE/$kind.zok.tpl" > "$OUT/$kind.zok"
done
echo "N=$N s=$SREG B=$B Q=$Q P=$P LOGP=$LOGP S=$S LOGS=$LOGS WB=$WB NBC=$NBC NBB=$NBB CK=$CK -> $OUT"
