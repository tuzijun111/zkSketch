#!/usr/bin/env bash
# gen.sh <K> <S> <E> <NB> <outdir>
# Instantiates gk_op.zok.tpl (proven) and gk_helper.zok.tpl (witness only) for K records
# per chunk, capacity S tuples, eps = 1/E and record counts n < 2^NB, by textual constant
# replacement -- the way zkStream sizes its circuits (nexmark/zokrates-nexmark/src/zokrates.rs:85-87).
#   K, S, E powers of two; S >= 4; E >= 4 (COMPRESS period P = E/2); NB > log2(E).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $# -eq 5 ]] || { echo "usage: gen.sh <K> <S> <E> <NB> <outdir>" >&2; exit 2; }
K=$1 S=$2 E=$3 NB=$4 OUT=$5
pow2() { (( $1 >= 1 && ($1 & ($1 - 1)) == 0 )); }
log2() { local v=$1 r=0; while (( v > 1 )); do v=$((v >> 1)); r=$((r + 1)); done; echo "$r"; }
bitlen() { local v=$1 r=0; while (( v > 0 )); do v=$((v >> 1)); r=$((r + 1)); done; echo "$r"; }
pow2 "$K" || { echo "gen.sh: K must be a power of two (got $K)" >&2; exit 2; }
{ pow2 "$S" && (( S >= 4 )); } || { echo "gen.sh: S must be a power of two >= 4 (got $S)" >&2; exit 2; }
{ pow2 "$E" && (( E >= 4 )); } || { echo "gen.sh: E must be a power of two >= 4 (got $E)" >&2; exit 2; }
EL=$(log2 "$E"); P=$((E / 2))
(( NB > EL && NB <= 40 )) || { echo "gen.sh: need log2(E) < NB <= 40 (got NB=$NB)" >&2; exit 2; }
LOGS=$(log2 "$S")
L=$((NB - EL + 1))            # p = floor(2n/E) < 2^L; every g and Delta <= p < 2^L
WB=$((22 + 2 * L))            # packed tuple word: v (22 bits incl. sentinel bit) | g | Delta
Q=$(bitlen "$L")              # band in [0, L]; 2^Q > L
M=$((NB + EL + 2))            # E * (g* + g + Delta) < 3 E 2^NB <= 2^M
if (( K >= P )); then NC=$((K / P)); RPC=$P; ALB=$((EL - 1)); else NC=1; RPC=$K; ALB=$(log2 "$K"); fi
NBC=$(( (S + 1 + 4) / 5 )); LC=$((5 * NBC)); NBB=$(( (K + 4) / 5 )); LB=$((5 * NBB))
mkdir -p "$OUT"
for kind in gk_op gk_helper; do
  sed -e "s/__K__/$K/g" -e "s/__S__/$S/g" -e "s/__LOGS__/$LOGS/g" -e "s/__S1__/$((S + 1))/g" \
      -e "s/__S2__/$((2 * S))/g" -e "s/__E__/$E/g" -e "s/__EL__/$EL/g" -e "s/__NB__/$NB/g" \
      -e "s/__L__/$L/g" -e "s/__L1__/$((L + 1))/g" -e "s/__L2__/$((2 * L))/g" -e "s/__WB__/$WB/g" \
      -e "s/__Q__/$Q/g" -e "s/__Q1__/$((Q + 1))/g" -e "s/__M__/$M/g" -e "s/__M1__/$((M + 1))/g" \
      -e "s/__NC__/$NC/g" -e "s/__RPC__/$RPC/g" -e "s/__ALB__/$ALB/g" \
      -e "s/__SENTEXP__/$((21 + 2 * L))/g" \
      -e "s/__NBC__/$NBC/g" -e "s/__LC__/$LC/g" -e "s/__NBB__/$NBB/g" -e "s/__LB__/$LB/g" \
      "$HERE/$kind.zok.tpl" > "$OUT/$kind.zok"
  if grep -q '__[A-Z0-9]*__' "$OUT/$kind.zok"; then echo "gen.sh: unreplaced placeholder in $kind.zok" >&2; exit 1; fi
done
echo "K=$K S=$S E=$E NB=$NB P=$P L=$L WB=$WB Q=$Q M=$M NC=$NC RPC=$RPC ALB=$ALB NBC=$NBC NBB=$NBB -> $OUT"
