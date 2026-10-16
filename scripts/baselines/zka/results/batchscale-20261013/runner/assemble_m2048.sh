#!/usr/bin/env bash
# M=2048 has no new zk-Analytics proof: assemble with an EXTERNAL calibration from the committed
# 2026-10-09 run (12 aggregation proofs at M=2048), via assemble_cal.py = six/assemble.py + assemble_cal.patch
. /tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad/env.sh
SP=/tmp/claude-1005/-home-binbin-zkSketch/5e529f7b-5eee-44f8-93ee-26cc1c5b0675/scratchpad
D=/home/binbin/zkSketch/results/six/batchscale-20261013/m2048
S=scripts/baselines/zka/six
# calibration = sum(prove_s) / sum(padded_cycles / 2^20) over the 12 aggregation rows of
# scripts/baselines/zka/results/six_zka_{cm,hll,ss,gk,bloom,kmv}_prove.csv (epochs 0 and 7), and the mean
# verify_ms / receipt_bytes of the same 12 receipts
export CAL_K=$(python3 -I - <<'PY'
import csv
rs = [r for f in ['cm','hll','ss','gk','bloom','kmv'] for r in csv.DictReader(open(f'scripts/baselines/zka/results/six_zka_{f}_prove.csv')) if (r.get('step') or r.get('mode')) == 'aggr']
assert len(rs) == 12
print(repr(sum(float(r['prove_s']) for r in rs) / sum(int(r['padded_cycles']) / 2**20 for r in rs)))
PY
)
export CAL_VERIFY_MS=$(python3 -I - <<'PY'
import csv, statistics
rs = [r for f in ['cm','hll','ss','gk','bloom','kmv'] for r in csv.DictReader(open(f'scripts/baselines/zka/results/six_zka_{f}_prove.csv')) if (r.get('step') or r.get('mode')) == 'aggr']
print(repr(statistics.mean(float(r['verify_ms']) for r in rs)))
PY
)
export CAL_RECEIPT_BYTES=$(python3 -I - <<'PY'
import csv, statistics
rs = [r for f in ['cm','hll','ss','gk','bloom','kmv'] for r in csv.DictReader(open(f'scripts/baselines/zka/results/six_zka_{f}_prove.csv')) if (r.get('step') or r.get('mode')) == 'aggr']
print(repr(statistics.mean(int(r['receipt_bytes']) for r in rs)))
PY
)
export CAL_SRC="the 12 aggregation proofs of the committed 2026-10-09 run at M=2048 (scripts/baselines/zka/results; legacy guests; no proof in this directory)"
echo "CAL_K=$CAL_K CAL_VERIFY_MS=$CAL_VERIFY_MS CAL_RECEIPT_BYTES=$CAL_RECEIPT_BYTES"
echo "CAL_SRC=$CAL_SRC"
python3 -I $SP/assemble_cal.py "$D" data/aol.keys --zka six_zka --zks six_zksketch --plan "$D/zka_plan.txt" --out "$D/six_sketch_comparison.csv" || exit 1
python3 -I $S/table.py "$D/six_sketch_comparison.csv" --zka six_zka > "$D/six_sketch_table.md" || exit 1
echo "table -> $D/six_sketch_table.md"
