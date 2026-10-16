. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/m1/env.sh
cd $HOME/zkSketch
export RESULTS=$SP/sbx_smoke SIX_M=256 SIX_T=2 SIX_GK_CAP=512 SIX_QNS=1,2 GATE_WAIT_S=0 TMPDIR=/tmp
rm -rf $RESULTS; Z=scripts/baselines/zka/six
set -x
$Z/run_zka.sh exec || exit 1
python3 -I $Z/jobs.py --keys data/aol.keys --m 256 --t 2 --qns 1,2 --aggr 0,1 --roots noroot --cm-ref 1 --lines > $RESULTS/zka_plan.txt.tmp || exit 1
$Z/run_zks.sh gk || exit 1
mv $RESULTS/zka_plan.txt.tmp $RESULTS/zka_plan.txt   # natively derived (no bloom_absent zkSketch run here)
for n in 1 2; do  # the GK rank value of the plan = what zkSketch probed (QLOG_KEY)
  grep -q "^gk:query:$n:$(sed -n "s/^QLOG_KEY,at_leaf=$n,gk_value=//p" $RESULTS/six_zksketch_gk.log)$" $RESULTS/zka_plan.txt || exit 1
done
mapfile -t Q < <(grep ':query:' $RESULTS/zka_plan.txt)
$Z/run_zka.sh qexec "${Q[@]}" || exit 1
$Z/prof_exec.sh || exit 1
mapfile -t P < <(grep '^gk:' $RESULTS/zka_plan.txt | grep -E 'aggr:0:|query:1:')
$Z/run_zka.sh prove "${P[@]}" || exit 1
python3 -I $Z/assemble.py $RESULTS data/aol.keys --zka six_zka --zks six_zksketch --plan $RESULTS/zka_plan.txt --out $RESULTS/six_sketch_comparison.csv || exit 1
python3 -I $Z/table.py $RESULTS/six_sketch_comparison.csv --zka six_zka > $RESULTS/six_sketch_table.md || exit 1
echo SMOKE_OK
