#!/usr/bin/env bash
# usage: zka_exec.sh <M>: zk-Analytics executor chain of run_all.sh quick for this shape
#   run_zka.sh exec -> jobs.py plan (hll ss gk; derived natively) -> run_zka.sh qexec <planned queries> -> prof_exec.sh
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/env.sh
M=$1
export RESULTS=/home/binbin/zkSketch/results/six/batchscale-20261013/m$M
export SIX_M=$M SIX_T=2 SIX_GK_CAP=2048 GATE_WAIT_S=0 SIX_ZKA_ROOTS=noroot SIX_ZKA_CM_REF=0 EXP_VERIFY_REPEATS=5
S=scripts/baselines/zka/six
st() { local t0=$SECONDS rc; echo "### $(date -Is) step: $*"; "$@"; rc=$?; echo "### rc=$rc seconds=$((SECONDS - t0))"; echo "step rc=$rc seconds=$((SECONDS - t0)) $*" >> "$RESULTS/manifest.txt"; return $rc; }
st $S/run_zka.sh exec || exit 1
echo "### $(date -Is) plan: python3 -I $S/jobs.py --keys data/aol.keys --m $M --t 2 --qns 1,2 --aggr 0,1 --roots noroot --cm-ref 0 --select hll,ss,gk --lines > $RESULTS/zka_plan.txt"
python3 -I $S/jobs.py --keys data/aol.keys --m $M --t 2 --qns 1,2 --aggr 0,1 --roots noroot --cm-ref 0 --select hll,ss,gk --lines > $RESULTS/zka_plan.txt || exit 1
cat $RESULTS/zka_plan.txt
mapfile -t Q < <(grep ':query:' $RESULTS/zka_plan.txt)
st $S/run_zka.sh qexec "${Q[@]}" || exit 1
st $S/prof_exec.sh || exit 1
echo "### $(date -Is) done"
