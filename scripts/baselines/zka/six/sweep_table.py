#!/usr/bin/env python3
"""Cross-size tables of a batch-size sweep (sweep.sh; run with python3 -I).

Usage: sweep_table.py <sweep results dir> [--out-csv F] [--out-md F]

Reads every m<EE>/six_sketch_comparison.csv under the sweep directory (one per batch size
m = 2^EE, written by assemble.py for that size), the zkSketch raw CSVs next to it
(m<EE>/six_zksketch_<fam>.csv: the `variant` column, e.g. bloom_packed / bloom_omc, and the
shape check m, t) and the sweep's manifest.txt (`sizes=`: the planned sizes), and writes
  sweep.csv        one row per family x m: m, zka_prove_s, zks_prove_s, zka_ms_per_record,
                   zks_ms_per_record, speedup (= zka_prove_s / zks_prove_s), zka_verify_ms,
                   zks_verify_ms, zka_proof_bytes, zks_proof_bytes, zka_peak_rss_mb, zks_peak_rss_mb,
                   zks_variant, provenance (+ family, size_dir, zka_variant, zka_system, zks_verify_kind:
                   best = best of the run's EXP_VERIFY_REPEATS calls, first = a single call)
  sweep_table.md   one cross-size table of the prove-time ratio zkA / zkS (sizes x families), then per
                   family a table with m as rows and those metrics as columns, ratios zkA / zkS
Per size the rows are the `update_per_epoch` rows (zkA: the epoch-0 aggregation receipt of the
headline root variant, noroot when present; zkS: the single leaf, k = 1); zkS verify is the
leaf's / root's verify (`update_stream_<T>_epochs`: verify_ms, the best of the run's repeated
calls, else verify_first_ms, the single call of a log without QLOG_ROOTV, marked `1st`), as
table.py's "verify, 1 epoch". The cores and the verify repeats of the conventions line come
from the runs (the zkSketch CSVs' `cores`, the manifest's cores= / verify_repeats=). Missing
sizes or failed rows show '-'; `est` marks a zkA value assemble.py ESTIMATED (not proved);
Bloom rows that ran the omc leaf are marked. Standard library only.
"""
import argparse
import csv
import os
import re
import sys

FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']
NAME = {'cm': 'Count-Min 3x1024', 'hll': 'HLL b=14 †', 'ss': 'SS / MG s=1,024 †', 'gk': 'GK eps=1/51 †',
        'bloom': 'Bloom 7x2^14 †', 'kmv': 'KMV k=1,024 †'}
VORDER = {v: i for i, v in enumerate(['noroot', 'designed', 'legacy', 'buckets1024', 'perkey', 'pertuple'])}
COLS = ['family', 'm', 'zka_prove_s', 'zks_prove_s', 'zka_ms_per_record', 'zks_ms_per_record', 'speedup',
        'zka_verify_ms', 'zks_verify_ms', 'zka_proof_bytes', 'zks_proof_bytes', 'zka_peak_rss_mb',
        'zks_peak_rss_mb', 'zks_variant', 'provenance', 'size_dir', 'zka_variant', 'zka_system', 'zks_verify_kind']

ap = argparse.ArgumentParser(usage='sweep_table.py <sweep results dir> [--out-csv F] [--out-md F]')
ap.add_argument('sweep')
ap.add_argument('--out-csv')
ap.add_argument('--out-md')
A = ap.parse_args()
R = os.path.abspath(A.sweep)
if not os.path.isdir(R):
    sys.exit(f'{R}: no such directory')
OUT_CSV = A.out_csv or os.path.join(R, 'sweep.csv')
OUT_MD = A.out_md or os.path.join(R, 'sweep_table.md')


def num(x):
    try:
        v = float(x)
        return None if v != v else v
    except (TypeError, ValueError):
        return None


def rows(path):
    return list(csv.DictReader(open(path, newline=''))) if os.path.exists(path) else []


# ------------------------------------------------------------------ sizes: the manifest's plan + the m<EE> dirs
sizes = set()
MAN_CORES = None      # the manifest's cores= (SIX_CORES), a fallback for the zkSketch CSVs' cores column
VREPEATS = None       # the manifest's verify_repeats= (EXP_VERIFY_REPEATS of the zkSketch runs)
manifest = os.path.join(R, 'manifest.txt')
if os.path.exists(manifest):
    for line in open(manifest):
        m = re.match(r'^sizes=([0-9,]+)', line)
        if m:
            sizes.update(int(x) for x in m.group(1).split(',') if x)
        m = re.search(r'(?:^|\s)cores=(\d+)(?:\s|$)', line)
        if m and MAN_CORES is None:
            MAN_CORES = int(m.group(1))
        m = re.search(r'(?:^|\s)verify_repeats=(\d+)(?:\s|$)', line)
        if m and VREPEATS is None:
            VREPEATS = int(m.group(1))
for d in os.listdir(R):
    m = re.fullmatch(r'm(\d\d)', d)
    if m and os.path.isdir(os.path.join(R, d)):
        sizes.add(int(m.group(1)))
if not sizes:
    sys.exit(f'{R}: no m<EE> size directory and no sizes= line in manifest.txt (is this a sweep.sh directory?)')
SIZES = sorted(sizes)


def warn(msg):
    print(f'sweep_table.py: {msg}', file=sys.stderr)


# ------------------------------------------------------------------ one size
def headline_variant(za):
    """The zk-Analytics update row of the headline variant: noroot when present, else the first by VORDER."""
    za = sorted(za, key=lambda r: VORDER.get(r.get('variant') or 'legacy', 99))
    return za[0] if za else None


CORES_SEEN = set()    # the `cores` column of every zkSketch CSV read (exp_compose's EXP_COMPOSE_CORES)


def size_rows(E):
    """{family: dict of the sweep.csv columns} of one size (None values where nothing was measured)."""
    m = 1 << E
    d = os.path.join(R, f'm{E:02d}')
    cmp_ = rows(os.path.join(d, 'six_sketch_comparison.csv'))
    present = os.path.isdir(d)
    have = bool(cmp_)
    if present and not have:
        warn(f'm{E:02d}: no six_sketch_comparison.csv (the size did not finish or its assemble failed)')
    elif not present:
        warn(f'm{E:02d}: no directory (planned but not run)')
    out = {}
    for f in FAMS:
        zv = rows(os.path.join(d, f'six_zksketch_{f}.csv'))[:1]
        zvar = (zv[0].get('variant') or '-') if zv else '-'
        if zv:
            zm, zt, st = num(zv[0].get('m')), num(zv[0].get('t')), zv[0].get('status', 'ok')
            if num(zv[0].get('cores')):
                CORES_SEEN.add(int(num(zv[0]['cores'])))
            if zm != m or zt != 1:
                warn(f'm{E:02d} {f}: six_zksketch_{f}.csv has m={zv[0].get("m")} t={zv[0].get("t")}, '
                     f'expected one leaf of {m} records (the sweep shape)')
            if st != 'ok':
                warn(f'm{E:02d} {f}: six_zksketch_{f}.csv status={st} (its row shows -)')
        za = headline_variant([r for r in cmp_ if r['family'] == f and r['system'].startswith('zk-Analytics')
                               and r['run'] == 'main' and r['operation'] == 'update_per_epoch'])
        zs = next((r for r in cmp_ if r['family'] == f and r['system'] == 'zkSketch' and r['run'] == 'main'
                   and r['operation'] == 'update_per_epoch'), None)
        zsr = next((r for r in cmp_ if r['family'] == f and r['system'] == 'zkSketch' and r['run'] == 'main'
                    and re.fullmatch(r'update_stream_\d+_epochs', r['operation'])), None)
        zka_p = num(za['prove_s']) if za else None
        zks_p = num(zs['prove_s']) if zs else None
        zks_v, zks_vk = None, None     # the verify and its kind: best of the repeated calls, or the single first call
        if zsr:
            zks_v, zks_vk = num(zsr.get('verify_ms')), 'best'
            if zks_v is None:
                zks_v, zks_vk = num(zsr.get('verify_first_ms')), 'first'
            if zks_v is None:
                zks_vk = None
        if not have:
            prov = 'size not run' if not present else 'no six_sketch_comparison.csv'
        else:
            prov = (f"zka {za['provenance'] if za else '-: no proved aggregation row'}; "
                    f"zks {zs['provenance'] if zs else '-: no zkSketch row'}")
        out[f] = dict(
            family=f, m=m, size_dir=f'm{E:02d}',
            zka_prove_s=zka_p, zks_prove_s=zks_p,
            zka_ms_per_record=None if zka_p is None else zka_p * 1000 / m,
            zks_ms_per_record=None if zks_p is None else zks_p * 1000 / m,
            speedup=None if zka_p is None or not zks_p else zka_p / zks_p,
            zka_verify_ms=num(za['verify_ms']) if za else None, zks_verify_ms=zks_v,
            zka_proof_bytes=num(za['proof_bytes']) if za else None, zks_proof_bytes=num(zs['proof_bytes']) if zs else None,
            zka_peak_rss_mb=num(za['peak_rss_mb']) if za else None, zks_peak_rss_mb=num(zs['peak_rss_mb']) if zs else None,
            zks_variant=zvar if zs else ('-' if not zv else zvar),
            provenance=prov,
            zka_variant=(za.get('variant') or 'legacy') if za else '-',
            zka_system=za['system'] if za else '-',
            zks_verify_kind=zks_vk,
            _est=bool(za) and 'ESTIMATED' in (za.get('provenance') or ''),
            _zks_note=(zs.get('detail') or '') if zs else '',
        )
    return out


DATA = {E: size_rows(E) for E in SIZES}


# ------------------------------------------------------------------ sweep.csv
def fmtcsv(k, v):
    if v is None:
        return '-'
    if isinstance(v, float):
        if k in ('zka_prove_s', 'zks_prove_s'):
            return f'{v:.6f}'
        if k in ('zka_ms_per_record', 'zks_ms_per_record', 'zka_verify_ms', 'zks_verify_ms', 'speedup'):
            return f'{v:.3f}'
        if k in ('zka_proof_bytes', 'zks_proof_bytes'):
            return f'{v:.0f}'
        return f'{v:.1f}'
    return str(v)


with open(OUT_CSV, 'w', newline='') as fo:
    w = csv.DictWriter(fo, fieldnames=COLS, extrasaction='ignore')
    w.writeheader()
    n = 0
    for f in FAMS:
        for E in SIZES:
            r = DATA[E][f]
            w.writerow({k: fmtcsv(k, r.get(k)) for k in COLS})
            n += 1


# ------------------------------------------------------------------ sweep_table.md
def f1(x, d=1):
    return '-' if x is None else f'{x:,.{d}f}'


def fs(x):  # seconds, adaptive precision (table.py)
    return '-' if x is None else (f'{x:,.3f}' if x < 1 else f'{x:,.2f}' if x < 100 else f'{x:,.1f}')


def kb(x):
    return '-' if x is None else f'{x / 1000:,.1f}'


def gb(x):
    return '-' if x is None else f'{x / 1024:,.2f}'


def ratio(a, b):
    if a is None or b in (None, 0):
        return '-'
    q = a / b
    return f'{q:,.0f}x' if q >= 10 else f'{q:,.1f}x' if q >= 1 else f'{q:,.2f}x'


def est(r):
    return ' est' if r['_est'] else ''


def vfirst(r):  # the zkS verify was a single call (no QLOG_ROOTV in that run's log)
    return ' 1st' if r['zks_verify_kind'] == 'first' else ''


def mlabel(E):
    return f'2^{E} = {1 << E:,}'


L = []
L.append('# Batch-size sweep: zkSketch vs zk-Analytics, one batch of m = 2^E records per size\n')
gk_sys = {DATA[E]['gk']['zka_system'] for E in SIZES} - {'-'}
gk_txt = ('zkSketch\'s own GK rule on both sides (the matched port)' if any('zkSketch GK rule' in s for s in gk_sys)
          else 'textbook Greenwald-Khanna on the zk-Analytics side (a reference, not zkSketch\'s algorithm)'
          if gk_sys else 'no zk-Analytics GK row')
zvars = sorted({DATA[E][f]['zka_variant'] for E in SIZES for f in FAMS} - {'-'}, key=lambda v: VORDER.get(v, 99))
cores_list = sorted(CORES_SEEN) or ([MAN_CORES] if MAN_CORES else [])
if len(cores_list) > 1:
    warn(f'the zkSketch runs used different core counts: {cores_list}')
cores_txt = (' / '.join(str(c) for c in cores_list) if cores_list else 'SIX_CORES (unknown: no zkSketch CSV, no cores= '
             'in manifest.txt)')
rep_txt = f'best of {VREPEATS}' if VREPEATS else 'best of the run\'s EXP_VERIFY_REPEATS (5 by default)'
any_first = any(DATA[E][f]['zks_verify_kind'] == 'first' for E in SIZES for f in FAMS)
first_txt = ('; `1st` = that run\'s log has no QLOG_ROOTV line, so its verify is the one call exp_compose made' if any_first
             else '')
L.append('_Conventions. zkA = zk-Analytics side: ONE aggregation receipt per m-record epoch (epoch 0 proved; root '
         f'variant {", ".join(zvars) or "noroot"}: their guest without the unused per-bucket Merkle root when noroot; '
         '† = our port of the sketch into their RISC Zero pipeline, zk-Analytics ships only Count-Min), no shipped-CM '
         'reference. zkS = zkSketch: ONE leaf per m-record batch (SIX_T = 1, k = 1: the single leaf proof, '
         f'`leafgen_seq_ms`; no composition), a query after it. Both on {cores_txt} cores (SIX_CORES; zkSketch pins '
         'its worker, r0vm takes the same taskset), zero knowledge on (zkSketch pcs=hiding, logup_mask=on; RISC Zero '
         'succinct receipts), AOL keys. prove = that one proof; ms/rec = prove x 1000 / m; verify = in-process calls, '
         f'zkA the best of 5 on the receipt, zkS the {rep_txt} on the leaf (= the forest\'s root at k = 1){first_txt}; '
         'proof = its bytes; peak '
         'RSS = zkA the r0vm process, zkS the procs-engine worker (coordinator and combined peaks: '
         f'm<EE>/six_sketch_comparison.csv). GK: {gk_txt}. Ratios are zkA / zkS: above 1, zkSketch is faster / '
         'smaller / lighter. `est` = a zkA value assemble.py ESTIMATED (not proved in that size); `-` = not run or '
         'failed. zkS variant = the zkSketch circuit of that run; a Bloom row marked (omc) ran the bit-array leaf '
         'because the packed leaf needs 7 x m < 2^16. KB = 10^3 bytes, GB = 2^30 bytes._\n')

# the cross-size table: prove-time ratio per size x family
L.append('**Prove time, zkA / zkS across batch sizes** (one proof of one m-record batch on each side; cells zkA / zkS; '
         'rows m = 2^E)\n')
L.append('| m | ' + ' | '.join(NAME[f] for f in FAMS) + ' |')
L.append('|---' * (len(FAMS) + 1) + '|')
for E in SIZES:
    L.append(f'| {mlabel(E)} | ' + ' | '.join(ratio(DATA[E][f]['zka_prove_s'], DATA[E][f]['zks_prove_s'])
                                                 + est(DATA[E][f]) for f in FAMS) + ' |')
L.append('')
L.append('**Prove time per record, ms** (prove x 1000 / m; cells zkA / zkS)\n')
L.append('| m | ' + ' | '.join(NAME[f] for f in FAMS) + ' |')
L.append('|---' * (len(FAMS) + 1) + '|')
for E in SIZES:
    L.append(f'| {mlabel(E)} | ' + ' | '.join(f"{f1(DATA[E][f]['zka_ms_per_record'], 2)}{est(DATA[E][f])} / "
                                                 f"{f1(DATA[E][f]['zks_ms_per_record'], 2)}" for f in FAMS) + ' |')
L.append('')

HDR = ['m', 'zkA prove (s)', 'zkS prove (s)', 'zkA / zkS', 'zkA ms/rec', 'zkS ms/rec', 'zkA verify (ms)',
       'zkS verify (ms)', 'zkA / zkS', 'zkA proof (KB)', 'zkS proof (KB)', 'zkA / zkS', 'zkA peak RSS (GB)',
       'zkS peak RSS (GB)', 'zkA / zkS', 'zkS variant']
for f in FAMS:
    L.append(f'**{NAME[f]}** (rows m = 2^E; zkA one receipt per batch, zkS one leaf per batch; ratios zkA / zkS)\n')
    L.append('| ' + ' | '.join(HDR) + ' |')
    L.append('|---' * len(HDR) + '|')
    omc = False
    for E in SIZES:
        r = DATA[E][f]
        var = r['zks_variant']
        if f == 'bloom' and var == 'bloom_omc':
            var += ' (omc)'
            omc = True
        L.append('| ' + ' | '.join([
            mlabel(E), fs(r['zka_prove_s']) + est(r), fs(r['zks_prove_s']), ratio(r['zka_prove_s'], r['zks_prove_s']) + est(r),
            f1(r['zka_ms_per_record'], 2) + est(r), f1(r['zks_ms_per_record'], 2),
            f1(r['zka_verify_ms']) + est(r), f1(r['zks_verify_ms']) + vfirst(r),
            ratio(r['zka_verify_ms'], r['zks_verify_ms']) + est(r) + vfirst(r),
            kb(r['zka_proof_bytes']) + est(r), kb(r['zks_proof_bytes']), ratio(r['zka_proof_bytes'], r['zks_proof_bytes']) + est(r),
            gb(r['zka_peak_rss_mb']), gb(r['zks_peak_rss_mb']), ratio(r['zka_peak_rss_mb'], r['zks_peak_rss_mb']),
            var]) + ' |')
    if omc:
        L.append('\n_(omc): the bit-array Bloom leaf (one field element per filter bit, `bloom_omc`), run because the '
                 'packed-byte leaf (`bloom_packed`, 16-bit timestamps) needs 7 x m < 2^16; both prove the same filter '
                 'and give the same answers, their leaf / decode / merge / root VKs differ. Rows of the two variants '
                 'are not one circuit\'s scaling curve._')
    L.append('')
missing = [f'm{E:02d}' for E in SIZES if all(DATA[E][f]['zka_prove_s'] is None and DATA[E][f]['zks_prove_s'] is None
                                             for f in FAMS)]
if missing:
    L.append(f'_Sizes without any result ({", ".join(missing)}): not run, unfinished or failed; see manifest.txt and '
             'sweep.log._\n')
with open(OUT_MD, 'w') as fo:
    fo.write('\n'.join(L) + '\n')
print(f'{n} rows ({len(FAMS)} families x {len(SIZES)} sizes: E = {",".join(map(str, SIZES))}) -> {OUT_CSV}; tables -> {OUT_MD}')
