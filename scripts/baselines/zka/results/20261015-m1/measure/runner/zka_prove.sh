#!/usr/bin/env bash
# zka_prove.sh <label> <cap> <m_sub> [impl] [job]: one real zk-Analytics matched-GK proof at B = 2,048
# (AOL, noroot, epoch 0 unless job given) through six/run_zka.sh prove (ProverOpts::succinct, CPU r0vm;
# rss_tree.sh + the driver's own r0vm sampler), under memsample.py (VmRSS of the whole tree, 0.1 s).
R="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$R")"
LBL=$1; CAP=$2; MS=$3; IMPL=${4:-fast}; JOB=${5:-gk:aggr:0:noroot}
. "$R/env.sh"
D=$S/zka/$LBL; [[ -e $D ]] && { echo "exists: $D"; exit 2; }; mkdir -p "$D"
{
  echo "label=$LBL cap=$CAP m_sub=$MS impl=$IMPL job=$JOB B=2048"
  echo "start=$(date -Is) load=\"$(cut -d' ' -f1-3 /proc/loadavg)\" memavail_gib=$(awk '/MemAvailable/{printf "%.1f", $2/1048576}' /proc/meminfo)"
  echo "head=$(git rev-parse --short=9 HEAD) dirty=$(git status --porcelain | wc -l) r0vm=$(r0vm --version) r0vm_md5=$(md5sum < $(readlink -f $(which r0vm)) | cut -c1-12) gk_matched_md5=$(md5sum < $BASELINE_DIR/build/zka-gk-matched/release/gk_matched | cut -c1-12)"
} > "$D/meta.txt"
RESULTS=$D/out SIX_M=2048 SIX_T=1 SIX_GK_CAP=$CAP SIX_GK_MSUB=$MS SIX_ZKA_GK=matched SIX_ZKA_GK_IMPL=$IMPL GATE_WAIT_S=0 \
  scripts/baselines/zka/six/run_zka.sh prove "$JOB" > "$D/run_zka.stderr" 2>&1 &
PID=$!
( sleep ${RUN_LIMIT_S:-590}; kill -0 $PID 2>/dev/null && { echo "watchdog: run over ${RUN_LIMIT_S:-590} s, stopping it $(date -Is)" >> "$D/meta.txt"; kill -TERM $PID; } ) &
WD=$!
python3 -I -c "import runpy,sys,time; sys.argv=['memsample.py','$PID','$D/mem.csv','0.1']; print(f'MEMSAMPLE_T0_UNIX={time.time():.3f}', flush=True); runpy.run_path('$R/memsample.py', run_name='__main__')" > "$D/memsum.txt" 2>&1 &
SP=$!
wait $PID; RC=$?
wait $SP
kill $WD 2>/dev/null; wait $WD 2>/dev/null
echo "end=$(date -Is) rc=$RC load=\"$(cut -d' ' -f1-3 /proc/loadavg)\"" >> "$D/meta.txt"
gzip -f "$D/mem.csv"
echo "rc=$RC"; head -c 400 "$D/memsum.txt"; echo
