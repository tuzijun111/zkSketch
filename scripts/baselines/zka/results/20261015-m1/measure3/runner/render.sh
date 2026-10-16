#!/usr/bin/env bash
# render.sh <outdir>: re-render the committed 2026-10-09 set, the M1 smoke set, a config-mismatch copy and
# doctored mixed-port copies with the e9968eb assemble.py / table.py (and the 5f96d1d assemble.py as a control).
R="$(cd "$(dirname "$0")" && pwd)"
. "$R/env.sh"
O=$1; mkdir -p "$O"; cd "$HOME/zkSketch"
SIX=scripts/baselines/zka/six
M1=/home/binbin/zkSketch/scripts/baselines/zka/results/20261015-m1
git show 5f96d1d:$SIX/assemble.py > "$O/assemble_5f96d1d.py"
cp $SIX/table.py "$O/table.py"   # same dir so the old assemble.py runs alongside; table.py unchanged since 5f96d1d
echo "# render $(date -Is) head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) assemble md5=$(md5sum < $SIX/assemble.py | cut -c1-12) table md5=$(md5sum < $SIX/table.py | cut -c1-12)" > "$O/render.log"
# 1. committed set (git-tracked, legacy textbook rows)
python3 -I $SIX/assemble.py scripts/baselines/zka/results data/aol.keys --out "$O/committed.csv" > "$O/committed.assemble.out" 2>&1; echo "committed assemble rc=$?" >> "$O/render.log"
python3 -I $SIX/table.py "$O/committed.csv" --raw scripts/baselines/zka/results > "$O/committed.md" 2> "$O/committed.table.err"; echo "committed table rc=$?" >> "$O/render.log"
# 2. smoke set
mk() { rm -rf "$O/$1"; mkdir -p "$O/$1"; cp "$M1"/harness_smoke/* "$O/$1/"; rm -f "$O/$1/six_sketch_comparison.csv" "$O/$1/six_sketch_table.md"; }
asm() { # asm <name> [assemble.py]
  local d=$O/$1 a=${2:-$SIX/assemble.py}
  python3 -I "$a" "$d" data/aol.keys --zka six_zka --zks six_zksketch --plan "$d/zka_plan.txt" --out "$d/six_sketch_comparison.csv" > "$O/$1.assemble.out" 2>&1
  local rc=$?; echo "$1 assemble($(basename $a)) rc=$rc" >> "$O/render.log"
  if [ $rc = 0 ]; then python3 -I $SIX/table.py "$d/six_sketch_comparison.csv" --zka six_zka > "$O/$1.md" 2> "$O/$1.table.err"; echo "$1 table rc=$?" >> "$O/render.log"; fi
}
dropcol() { # dropcol <csv> : remove the `algorithm` column (the textbook driver writes none)
  python3 -I -c '
import csv,sys
p=sys.argv[1]; rs=list(csv.DictReader(open(p))); h=[k for k in rs[0] if k!="algorithm"]
w=csv.DictWriter(open(p,"w",newline=""),fieldnames=h,lineterminator="\n"); w.writeheader()
[w.writerow({k:r[k] for k in h}) for r in rs]' "$1"; }
mk smoke; asm smoke
# 3. config mismatch: zkSketch GK run claims cap 384
mk mism; sed -i 's/cap512_s51/cap384_s51/g' "$O/mism/six_zksketch_gk.csv"; asm mism
# 4. mixed copies (expect exit 1 with e9968eb; the 5f96d1d script is the control)
mk mixA; dropcol "$O/mixA/six_zka_gk_prove.csv"; asm mixA; cp -r "$O/mixA" "$O/mixA_old"; asm mixA_old "$O/assemble_5f96d1d.py"
mk mixB; dropcol "$O/mixB/six_zka_gk_exec.csv"; asm mixB; cp -r "$O/mixB" "$O/mixB_old"; asm mixB_old "$O/assemble_5f96d1d.py"
mk mixD; cp "$O/mixD/six_zka_gk_prove.csv" "$O/mixD/six_zka_vt_gk_prove.csv"; dropcol "$O/mixD/six_zka_vt_gk_prove.csv"; asm mixD
# 5. all-textbook copy (accepted, labelled textbook)
mk alltb; for f in exec qexec prove; do dropcol "$O/alltb/six_zka_gk_$f.csv"; done; asm alltb
echo "# end $(date -Is)" >> "$O/render.log"
