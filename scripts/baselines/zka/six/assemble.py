#!/usr/bin/env python3
"""Build six_sketch_comparison.csv from the raw files of a six-sketch run (run with python3 -I).
Usage: assemble.py <results dir> <aol.keys> [--zka PFX --zks PFX] [--label L] [--plan FILE] [--extended] [--out CSV]"""
import argparse
import collections
import csv
import os
import re
import statistics
import struct
import subprocess
import sys

ap = argparse.ArgumentParser(usage='assemble.py <results dir> <aol.keys> [--zka PFX --zks PFX] [--label L] '
                                   '[--plan FILE] [--out CSV] [--m M --t T]')
ap.add_argument('results')
ap.add_argument('keys')
ap.add_argument('--zka', default='six_zka')
ap.add_argument('--zks')
ap.add_argument('--label', default='main')
ap.add_argument('--plan')
ap.add_argument('--out')
ap.add_argument('--m', type=int, help='records per epoch, if no zkSketch CSV says (default 2048)')
ap.add_argument('--t', type=int, help='epochs, if no zkSketch CSV says (default 8)')
ap.add_argument('--extended', action='store_true',
                help='append the shape, zkSketch-variant and memory columns (implied by a forest of k > 1 leaves)')
A = ap.parse_args()
R, KEYS = A.results, A.keys
FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']
ZKS_TAGS = {'cm': ['cm'], 'hll': ['hll'], 'ss': ['ss'], 'gk': ['gk'], 'bloom': ['bloom', 'bloom_absent'],
            'kmv': ['kmv']}
# (file prefix, system name, run label, full instrumentation?)
if A.zks:
    ZKA = A.zka
    ZKS_SETS = [(A.zks, 'zkSketch', A.label, True)]
else:
    ZKA = 'six_zka'
    ZKS_SETS = [('six_zksketch_r2', 'zkSketch', 'r2', True),
                ('six_zksketch_zk', 'zkSketch (zk feature)', 'zk', True),
                ('six_zksketch', 'zkSketch', 'r1', False)]
ZKA_VT = f'{ZKA}_vt'
OUT_PATH = A.out or os.path.join(R, 'six_sketch_comparison.csv')


def tracked(path):
    """True if `path` is a file git tracks (the committed reference results)."""
    d, b = os.path.split(os.path.abspath(path))
    try:
        return subprocess.run(['git', '-C', d, 'ls-files', '--error-unmatch', b],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


if tracked(OUT_PATH):
    sys.exit(f'refusing to overwrite the git-tracked {OUT_PATH} (produced by the 6cac471 version of this '
             f'script); pass --out <file> to write elsewhere')


# ------------------------------------------------------------------ readers
def rows(name):
    p = os.path.join(R, name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else []


def num(x):
    try:
        v = float(x)
        return None if v != v else v
    except (TypeError, ValueError):
        return None


def stats(v):
    return min(v), v[0], statistics.median(v)


def and_join(xs):
    xs = [str(x) for x in xs]
    return xs[0] if len(xs) == 1 else ', '.join(xs[:-1]) + ' and ' + xs[-1]


def step_of(r):
    return r.get('step') or r.get('mode')


# ------------------------------------------------------------------ workload shape
def shape_line(pfx, tag):
    """(epoch, leaf, leaves per epoch, epochs) of run_zks.sh's '# shape:' log line, or None."""
    p = os.path.join(R, f'{pfx}_{tag}.log')
    if not os.path.exists(p):
        return None
    m = re.search(r'^# shape: epoch_records=(\d+) leaf_records=(\d+) leaves_per_epoch=(\d+) epochs=(\d+)$',
                  open(p).read(), re.M)
    return tuple(int(x) for x in m.groups()) if m else None


def shape():
    """({family: (records per epoch M, zkSketch leaf records, leaves per epoch k)}, epochs T) from
    the zkSketch CSVs (m = leaf, t = leaves) and their logs' shape lines, else --m/--t, else the
    paper configuration. Runs without the shape line: one leaf per epoch, one (m, t) for all."""
    seen, lines = collections.defaultdict(set), True
    for pfx, _, _, _ in ZKS_SETS:
        for f, tags in ZKS_TAGS.items():
            for tag in tags:
                for r in rows(f'{pfx}_{tag}.csv')[:1]:
                    if num(r.get('m')) and num(r.get('t')):
                        m, t = int(r['m']), int(r['t'])
                        sl = shape_line(pfx, tag)
                        if sl is None:
                            lines, sl = False, (m, m, 1, t)
                        if sl[1] != m or sl[0] != m * sl[2] or t != sl[2] * sl[3]:
                            sys.exit(f'{pfx}_{tag}: shape line epoch/leaf/k/epochs {sl} does not match the CSV\'s '
                                     f'm={m}, t={t}')
                        seen[f].add(sl)
    if not seen:
        m = A.m or 2048
        return {f: (m, m, 1) for f in FAMS}, A.t or 8
    if not lines:
        # one leaf per epoch, as every run before the shape line: one (m, t) for all, as before
        mt = {(s[1], s[2] * s[3]) for ss in seen.values() for s in ss}
        if len(mt) > 1:
            sys.exit(f'zkSketch CSVs disagree on (m, t): {sorted(mt)}')
        m, t = mt.pop()
        if (A.m and A.m != m) or (A.t and A.t != t):
            sys.exit(f'--m/--t ({A.m}, {A.t}) disagree with the zkSketch CSVs ({m}, {t})')
        return {f: (m, m, 1) for f in FAMS}, t
    bad = {f: sorted(ss) for f, ss in seen.items() if len(ss) > 1}
    if bad:
        sys.exit(f'zkSketch runs of one family disagree on epoch/leaf/k/epochs: {bad}')
    one = {f: ss.pop() for f, ss in seen.items()}
    ts = {s[3] for s in one.values()}
    if len(ts) > 1 or (A.t and A.t not in ts):
        sys.exit(f'zkSketch runs disagree on the number of epochs: {sorted(ts)}' + (f' (--t {A.t})' if A.t else ''))
    t = ts.pop()
    epochs = {s[0] for s in one.values()}
    dm = A.m or (epochs.pop() if len(epochs) == 1 else 2048)   # families without a zkSketch run
    return {f: one[f][:3] if f in one else (dm, dm, 1) for f in FAMS}, t


SHAPE, T = shape()
FOREST = any(s[2] > 1 for s in SHAPE.values())
EXT = A.extended or FOREST
NS = list(range(1, T + 1))
for f in FAMS:
    mf, leaf, kf = SHAPE[f]
    for r in rows(f'{ZKA}_{f}_exec.csv'):
        if step_of(r) == 'aggr' and r.get('epoch_records') not in (None, '', '-') and int(r['epoch_records']) != mf:
            sys.exit(f'{ZKA}_{f}_exec.csv: epoch_records={r["epoch_records"]} but the zkSketch run used m={mf}'
                     + (f'-record epochs ({kf} leaves of {leaf})' if kf > 1 else ''))

# ------------------------------------------------------------------ exact answers
raw = open(KEYS, 'rb').read()
keys = list(struct.unpack('<%dI' % (len(raw) // 4), raw))[:max(s[0] for s in SHAPE.values()) * T]


def prefix(f, n):
    """The records of family f's first n epochs."""
    return keys[:n * SHAPE[f][0]]


def hot_key(f, n):
    c = collections.Counter(prefix(f, n))
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def distinct(f, n):
    return len(set(prefix(f, n)))


def rank_le(f, n, v):
    return sum(1 for k in prefix(f, n) if (k & 0x1FFFFF) <= v)


OUT = []
COLS = ['family', 'system', 'run', 'operation', 'n', 'prove_s', 'verify_ms', 'verify_first_ms', 'verify_median_ms',
        'decode_ms', 'proof_bytes', 'peak_rss_mb', 'rss_scope', 'answer', 'exact', 'provenance', 'note', 'detail',
        'variant', 'root_construction']
# --extended (implied by a forest of k > 1 leaves): the family's shape, the zkSketch variant and the memory columns
COLS_EXT = ['epoch_records', 'zks_leaf_records', 'zks_leaves_per_epoch', 'zks_variant', 'zks_gk_rounds', 'zks_shape',
            'coord_peak_rss_mb', 'combined_peak_rss_mb']


def emit(**kw):
    def fmt(v, d):
        return '' if v is None else (f'{v:.{d}f}' if isinstance(v, float) else str(v))
    r = {c: '' for c in COLS + COLS_EXT}
    r['variant'] = r['root_construction'] = r['zks_variant'] = r['zks_gk_rounds'] = r['zks_shape'] = '-'
    for k, v in kw.items():
        if k in ('prove_s',):
            r[k] = fmt(v, 6)
        elif k in ('verify_ms', 'verify_first_ms', 'verify_median_ms', 'decode_ms'):
            r[k] = fmt(v, 3)
        elif k == 'proof_bytes':
            r[k] = fmt(v, 0)
        elif k in ('peak_rss_mb', 'coord_peak_rss_mb', 'combined_peak_rss_mb'):
            r[k] = fmt(v, 1)
        else:
            r[k] = '' if v is None else str(v)
    OUT.append(r)


def note_for(fam, system, arm=''):
    if fam == 'gk' and system.startswith('zk-Analytics'):
        return GK_NOTE
    if fam == 'hll' and system.startswith('zkSketch'):
        if (SHAPE['hll'][0], T) == (2048, 8):
            return ('NOT like-for-like: zkSketch certifies the raw HLL estimator (no small-range / linear-counting '
                    'branch); its answers are 1.9-10x above exact here, outside HLL error bounds')
        return ('NOT like-for-like: zkSketch certifies the raw HLL estimator (no small-range / linear-counting '
                'branch); compare its answer with the exact column')
    if fam == 'ss' and system.startswith('zkSketch'):
        return 'releases the top-1 MG count only (no key); the zk-Analytics port releases the key too'
    if fam == 'ss' and arm == 'ss':   # results of the older SpaceSaving port (../spacesaving)
        return 'SpaceSaving port; topk --limit 1: full sum-and-truncate merge of n x 1,024 entries; releases key, count, error'
    if fam == 'ss':
        return "topk --limit 1: full Misra-Gries merge of the n epochs' entries (at most 1,024 each); releases key and count"
    return ''


# ------------------------------------------------------------------ zk-Analytics side
def zka_answer(f, row):
    res = row.get('answer') or row.get('result') or ''
    if f in ('cm', 'hll', 'kmv'):
        return re.search(r'estimate=(\d+)', res).group(1)
    if f == 'ss':
        m = re.search(r'top=(\d+):(\d+)(?:/e(\d+))?', res)   # SpaceSaving rows carry /e<error>, Misra-Gries rows do not
        return f'key {m.group(1)} count {m.group(2)}' + (f' (error {m.group(3)})' if m.group(3) else '')
    if f == 'gk':
        m = re.search(r'est=(\d+);lo=(\d+);hi=(\d+)', res)
        return f'{m.group(1)} [{m.group(2)}..{m.group(3)}]'
    if f == 'bloom':
        return re.search(r'member=(\w+)', res).group(1)
    return res


def zka_exact(f, r, n):
    """(exact, probe description, op suffix) of a zk-Analytics query row."""
    if f == 'cm':
        k, c = hot_key(f, n)
        m = re.search(r'key=(\d+)', r['exact'])
        assert int(m.group(1)) == k, (f, n)
        return str(c), f'key {k} (heaviest of prefix)', ''
    if f in ('hll', 'kmv'):
        return str(distinct(f, n)), 'distinct count', ''
    if f == 'ss':
        k, c = hot_key(f, n)
        return f'key {k} count {c}', 'top-1 (topk limit 1)', ''
    if f == 'gk':
        v = int(r['_job']['arg'])
        return str(rank_le(f, n, v)), f'rank({v})', ''
    if f == 'bloom':
        pk = int(r['probe_key'])
        ex = str(pk in set(prefix(f, n))).lower()
        return ex, f"key {pk} ({'inserted' if ex == 'true' else 'absent'})", \
            '_inserted' if ex == 'true' else '_absent'
    raise ValueError(f)


# Root variants of the zk-Analytics aggregation guests. Driver rows without a root_variant
# column come from the committed 2026-10-09 guests: `legacy`, with these root constructions.
LEGACY_ROOT = {'cm': 'cm_rows+cm+heap', 'hll': 'none', 'ss': 'samples64', 'gk': 'pertuple', 'bloom': 'none',
               'kmv': 'none'}
VORDER = {v: i for i, v in enumerate(['designed', 'noroot', 'legacy', 'buckets1024', 'perkey', 'pertuple'])}


def row_variant(f, r):
    """(variant, root construction) of a zk-Analytics aggregation row of a driver CSV."""
    v = r.get('root_variant')
    if v in (None, '', '-'):
        return 'legacy', LEGACY_ROOT[f]
    return v, r.get('root_construction') or '-'


def job_variant(j):
    """The root variant of an aggregation job line (its arg; none given = legacy)."""
    return j['arg'] if j.get('arg') not in (None, '', '-') else 'legacy'


def attach_jobs(prefix_, kind='prove', jobs_name=None):
    """{fam: rows of <prefix>_<fam>_<kind>.csv}, each with its job line as row['_job']."""
    jobs = rows(jobs_name or f'{prefix_}_jobs.csv')
    bad = [j['job'] for j in jobs if j.get('rc', '0') != '0']
    if bad:
        print(f'{prefix_} {kind}: skipping {len(bad)} failed job(s): {" ".join(bad)}', file=sys.stderr)
    jobs = [j for j in jobs if j.get('rc', '0') == '0']
    out = {f: rows(f'{prefix_}_{f}_{kind}.csv') for f in FAMS}
    for f in FAMS:
        fj = [j for j in jobs if j['family'] == f]
        if len(fj) != len(out[f]):
            sys.exit(f'{prefix_} {f}: {len(fj)} jobs vs {len(out[f])} {kind} rows')
        for row, j in zip(out[f], fj):
            mode = step_of(row)
            n_or_e = row['epoch_index'] if j['op'] == 'aggr' else row['epochs']
            if mode != j['op'] or n_or_e != j['n_or_epoch']:
                sys.exit(f'{prefix_} {f}: row/job mismatch {mode},{n_or_e} vs {j["op"]},{j["n_or_epoch"]}')
            if j['op'] == 'aggr' and row_variant(f, row)[0] != job_variant(j):
                sys.exit(f'{prefix_} {f}: job {j["job"]} is root variant {job_variant(j)} but its row says '
                         f'{row_variant(f, row)[0]}')
            row['_job'] = j
    return out


def tree_peaks(prefix_):
    """{job: tree_peak_rss_mb} of the RSSTREE lines in <prefix>_<fam>_prove.log (rss_tree.sh labels
    each with its job; the last line of a job wins; logs before the field have none)."""
    out = {}
    for f in FAMS:
        p = os.path.join(R, f'{prefix_}_{f}_prove.log')
        if os.path.exists(p):
            for job, x in re.findall(r'^RSSTREE,([^,]+),main_peak_rss_mb=.*,tree_peak_rss_mb=([\d.]+)$',
                                     open(p).read(), re.M):
                out[job] = float(x)
    return out


def zmem(r, trees):
    """--extended peak columns of a zk-Analytics proof row: its host driver and its whole tree."""
    if r['_est']:
        return {}
    return dict(coord_peak_rss_mb=num(r['_job'].get('main_peak_rss_mb')),
                combined_peak_rss_mb=trees.get(r['_job']['job']))


def zmax(zms, col):
    """The largest value of col over zmem() dicts (the measured proofs), or None."""
    xs = [z[col] for z in zms if z.get(col) is not None]
    return max(xs) if xs else None


ZKA_NAME = {'cm': 'zk-Analytics', **{f: 'zk-Analytics arch. (port †)' for f in FAMS if f != 'cm'}}
# their shipped CM aggregation (variant designed = aggr_cm unchanged): reported as a reference
CM_REF_NOTE = ('reference, not the headline: their shipped CM aggregation (aggr_cm unchanged), incl. the per-row '
               'Merkle roots (row_roots, cm_root, heap_root) that no query guest or verifier reads')


def ref_note(f, var):
    if f == 'gk':
        return GK_NOTE
    return CM_REF_NOTE if (f, var) == ('cm', 'designed') else ''

prove = attach_jobs(ZKA)


def gk_algorithm():
    """('bm2', (capacity, m_sub, s, implementation, steps)) when the zk-Analytics GK rows come from
    the matched port (driver column algorithm=bm2), else ('textbook', None)."""
    src = (rows(f'{ZKA}_gk_exec.csv') + rows(f'{ZKA}_gk_qexec.csv') + prove['gk']
           + rows(f'{ZKA_VT}_gk_prove.csv'))
    rs = [r for r in src if r.get('algorithm')]
    if rs and len(rs) != len(src):
        # the textbook driver writes no `algorithm` column: rows of both ports in one directory
        # (SIX_ZKA_GK changed between run_zka.sh steps) would all be labelled the matched rule
        sys.exit(f'{ZKA} gk: {len(rs)} matched-port rows (algorithm column) and {len(src) - len(rs)} textbook-port '
                 f'rows (none) in one results directory: re-run every run_zka.sh step with one SIX_ZKA_GK')
    algos = {r['algorithm'] for r in rs}
    if len(algos) > 1:
        sys.exit(f'{ZKA} gk: rows of several GK algorithms ({sorted(algos)}) in one results directory')
    if algos == {'bm2'}:
        cfgs = {(r['capacity'], r['m_sub'], r['s'], r['implementation'], r['steps']) for r in rs}
        if len(cfgs) > 1:
            sys.exit(f'{ZKA} gk: rows of several matched-GK configurations {sorted(cfgs)} in one results directory')
        return 'bm2', cfgs.pop()
    return 'textbook', None


GK_ALGO, GK_CFG = gk_algorithm()
if GK_ALGO == 'bm2':
    _cap, _msub, _s, _impl, _steps = GK_CFG
    ZKA_NAME['gk'] = 'zk-Analytics arch. (port †, zkSketch GK rule)'
    GK_NOTE = (f'same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; '
               f'capacity {_cap}, s {_s}, {_steps} step(s) of {_msub} records per epoch (zkSketch leaf size), state '
               f'carried across epochs, guest implementation {_impl}')
    for _pfx, _, _, _ in ZKS_SETS:
        for _r in rows(f'{_pfx}_gk.csv')[:1]:
            _m = re.fullmatch(r'cap(\d+)_s(\d+)', _r.get('shape', ''))
            _zks = (_m.group(1), _r.get('m'), _m.group(2)) if _m else None
            if _zks != (_cap, _msub, _s):
                print(f'WARNING {ZKA} gk: the matched port ran capacity/m_sub/s = {_cap}/{_msub}/{_s} but '
                      f'{_pfx}_gk.csv is shape {_r.get("shape")} with leaf m={_r.get("m")}: NOT the same configuration',
                      file=sys.stderr)
                GK_NOTE += (f'; CONFIG MISMATCH: the zkSketch GK run used {_r.get("shape")} with {_r.get("m")}-record '
                            f'leaves')
elif A.zks:
    GK_NOTE = ("textbook Greenwald-Khanna (summary rebuilt per epoch, query-time merge): NOT zkSketch's algorithm "
               "(its two-sided band-merge batch rule); a reference, not like for like")
else:
    GK_NOTE = ''   # the committed 2026-10-09 set: output unchanged
for f in FAMS:
    for r in prove[f]:
        r['_est'] = False

# --plan: a planned job without a proof gets prove_s = k x its executor's padded cycles / 2^20, where k is
# the seconds per 2^20 padded cycles over this run's proofs; verify_ms and receipt_bytes are the means of those proofs
EST_NOTE = ''
if A.plan:
    plan = [ln.strip() for ln in open(A.plan) if ln.strip() and not ln.startswith('#')]
    measured = [r for f in FAMS for r in prove[f]]
    proved = {r['_job']['job'] for r in measured}
    todo = [j for j in plan if j not in proved]
    if todo:
        if not measured:
            sys.exit('--plan: no measured zk-Analytics proof in this run to compute k from')
        k = sum(num(r['prove_s']) for r in measured) / sum(int(r['padded_cycles']) / 2 ** 20 for r in measured)
        mv = statistics.mean(num(r['verify_ms']) for r in measured)
        mb = statistics.mean(int(r['receipt_bytes']) for r in measured)
        EST_NOTE = (f'FROM CYCLES (padded_cycles x k={k:.3f} s per 2^20 cycles, k from {len(measured)} '
                    f'proof(s) of this run)')
        print(f'k = {k:.3f} s per 2^20 padded cycles from {len(measured)} proof(s) '
              f'({" ".join(sorted(proved))}); {len(todo)} job(s) computed from padded cycles', file=sys.stderr)
        qex = attach_jobs(ZKA, 'qexec', f'{ZKA}_qexec_jobs.csv')
        qex_by_job = {r['_job']['job']: r for f in FAMS for r in qex[f]}
        for job in todo:
            parts = job.split(':', 3)
            f, op, x = parts[0], parts[1], parts[2]
            if op == 'aggr':
                var = parts[3] if len(parts) > 3 else 'legacy'
                src = [r for r in rows(f'{ZKA}_{f}_exec.csv') if step_of(r) == 'aggr' and r['epoch_index'] == x
                       and row_variant(f, r)[0] == var]
                src = src[0] if src else None
            else:
                src = qex_by_job.get(job)
            if src is None:
                sys.exit(f'--plan: no executor row for {job} (run run_zka.sh exec / qexec first; exec runs the '
                         f'root variants of SIX_ZKA_ROOTS, plus designed with SIX_ZKA_CM_REF=1)')
            e = dict(src)
            e['prove_s'] = str(k * int(e['padded_cycles']) / 2 ** 20)
            e['verify_ms'] = str(mv)
            e['receipt_bytes'] = str(round(mb))
            e['_job'] = {'job': job, 'family': f, 'op': op, 'n_or_epoch': x, 'arg': parts[3] if len(parts) > 3 else '-',
                         'gate': '-', 'load1_start': '-', 'busy_cores_start': '-', 'r0vm_peak_rss_mb': ''}
            e['_est'] = True
            e['_est_how'] = (f"NOT proved: prove_s = {e['padded_cycles']} padded cycles / 2^20 x {k:.3f} s; "
                             f"verify_ms and proof_bytes = mean of this run's {len(measured)} measured receipt(s)")
            prove[f].append(e)

# verify-protocol re-proofs: VERIFY_TIMES_MS lines, in job order per family
vt = attach_jobs(ZKA_VT)
for f in FAMS:
    logp = os.path.join(R, f'{ZKA_VT}_{f}_prove.log')
    if not os.path.exists(logp):
        continue
    vts = re.findall(r'VERIFY_TIMES_MS,([\d.;]+),receipt_decode_ms=([\d.]+)', open(logp).read())
    if len(vts) != len(vt[f]):
        sys.exit(f'vt {f}: {len(vts)} VERIFY_TIMES_MS lines vs {len(vt[f])} proved rows')
    for row, (ts, dec) in zip(vt[f], vts):
        times = [float(x) for x in ts.split(';')]
        mn, first, med = stats(times)
        if abs(mn - float(row['verify_ms'])) > 0.002:
            sys.exit(f'vt {f}: min of VERIFY_TIMES_MS {mn} != verify_ms {row["verify_ms"]}')
        row['_vt'] = (mn, first, med, float(dec), times)


def prov(r):
    return EST_NOTE if r['_est'] else 'measured'


def gate_of(r):
    if r['_est']:
        return r['_est_how']
    return (f"verify = best of 5; gate={r['_job']['gate']} load1_start={r['_job']['load1_start']} "
            f"busy_cores_start={r['_job']['busy_cores_start']}")


def check_variants():
    """Per (family, epoch): one state_commit across every executor and proved aggregation row of
    every root variant, each with journal_eq_native and variants_agree true. Rows without the
    columns (the committed 2026-10-09 set) are skipped."""
    commits = collections.defaultdict(set)
    seen = collections.defaultdict(set)
    for f in FAMS:
        src = [('exec', r) for r in rows(f'{ZKA}_{f}_exec.csv')] + [('prove', r) for r in prove[f] if not r['_est']]
        for kind, r in src:
            if step_of(r) != 'aggr' or r.get('state_commit') in (None, '', '-'):
                continue
            v = row_variant(f, r)[0]
            if (r.get('journal_eq_native'), r.get('variants_agree')) != ('true', 'true'):
                sys.exit(f'{ZKA} {f} {kind} epoch {r["epoch_index"]} --root {v}: journal_eq_native='
                         f'{r.get("journal_eq_native")} variants_agree={r.get("variants_agree")}')
            commits[(f, r['epoch_index'])].add(r['state_commit'])
            seen[f].add(v)
    bad = sorted(k for k, c in commits.items() if len(c) > 1)
    if bad:
        sys.exit('root variants disagree on state_commit at (family, epoch) ' + ', '.join(f'({f}, {e})' for f, e in bad))
    if commits:
        print('root variants: one state_commit per (family, epoch) over ' + '; '.join(
            f'{f} {"/".join(sorted(seen[f], key=lambda v: VORDER.get(v, 99)))}' for f in FAMS if seen[f])
            + f' ({len(commits)} epochs)', file=sys.stderr)


check_variants()
TREES, TREES_VT = tree_peaks(ZKA), tree_peaks(ZKA_VT)
zka_aggr_mean, zka_query_mean = {}, {}
for f in FAMS:
    sysname = ZKA_NAME[f]
    ex_all = [r for r in rows(f'{ZKA}_{f}_exec.csv') if step_of(r) == 'aggr']
    aggr_all = [r for r in prove[f] if r['_job']['op'] == 'aggr']
    if not aggr_all:
        print(f'{f}: no proved aggregation rows; update and accept rows skipped', file=sys.stderr)
    variants = sorted({row_variant(f, r)[0] for r in aggr_all}, key=lambda v: VORDER.get(v, 99))
    for var in variants:
        aggr = [r for r in aggr_all if row_variant(f, r)[0] == var]
        con = row_variant(f, aggr[0])[1]
        vk = dict(variant=var, root_construction=con)
        ex = [r for r in ex_all if row_variant(f, r)[0] == var]
        segs = [int(r['segments']) for r in ex]
        cyc = [int(r['user_cycles']) for r in ex]
        zm = [zmem(r, TREES) for r in aggr]
        for r, zr in zip(aggr, zm):
            e = r['epoch_index']
            emit(family=f, system=sysname, run='main', operation=f'update_epoch{e}', prove_s=num(r['prove_s']),
                 verify_ms=num(r['verify_ms']), proof_bytes=int(r['receipt_bytes']),
                 peak_rss_mb=num(r['_job']['r0vm_peak_rss_mb']), rss_scope='' if r['_est'] else 'r0vm process of this proof',
                 answer='-', exact='-', provenance=prov(r), note=ref_note(f, var),
                 detail=f"aggregation guest on epoch {e} ({SHAPE[f][0]} records); {r['segments']} segments; {r['user_cycles']} "
                        f"user cycles; {gate_of(r)}", **vk, **zr)
        zmx = dict(coord_peak_rss_mb=zmax(zm, 'coord_peak_rss_mb'), combined_peak_rss_mb=zmax(zm, 'combined_peak_rss_mb'))
        anyest = any(r['_est'] for r in aggr)
        ps = [num(r['prove_s']) for r in aggr]
        vs = [num(r['verify_ms']) for r in aggr]
        bs = [int(r['receipt_bytes']) for r in aggr]
        rs = [num(r['_job']['r0vm_peak_rss_mb']) for r in aggr if not r['_est']]
        rss = max(rs) if rs else None
        rscope = (f"r0vm process (max of the {len(rs)} {'measured ' if anyest else ''}proofs)" if rs else '')
        mp, mv, mb = sum(ps) / len(ps), sum(vs) / len(vs), sum(bs) / len(bs)
        zka_aggr_mean[(f, var)] = (mp, mv, mb, anyest)
        exd = (f'executor over all {T} epochs: {min(segs)}-{max(segs)} segments, {min(cyc)}-{max(cyc)} user cycles'
               if ex else 'no executor rows')
        emit(family=f, system=sysname, run='main', operation='update_per_epoch', prove_s=mp, verify_ms=mv,
             proof_bytes=round(mb), peak_rss_mb=rss, rss_scope=rscope,
             answer='-', exact='-', provenance='sampled (incl. FROM CYCLES epochs)' if anyest else 'sampled',
             note=ref_note(f, var),
             detail=f"mean of {'proved and FROM CYCLES' if anyest else 'proved'} epochs "
                    f"{and_join(r['epoch_index'] for r in aggr)}; {exd}", **vk, **zmx)
        emit(family=f, system=sysname, run='main', operation='update_per_epoch_amortized', prove_s=mp,
             answer='-', exact='-', provenance='sampled (incl. FROM CYCLES epochs)' if anyest else 'sampled',
             note=ref_note(f, var), detail='no composition on this side: equals update_per_epoch', **vk)
        emit(family=f, system=sysname, run='main', operation=f'update_stream_{T}_epochs', prove_s=T * mp,
             peak_rss_mb=rss, rss_scope=rscope, answer='-', exact='-',
             provenance='computed (incl. FROM CYCLES epochs)' if anyest else 'computed', note=ref_note(f, var),
             detail=f'{T} x sampled per-epoch prove time; {T} receipts are kept (no composition)', **vk, **zmx)
    qrows = {}
    for r in [r for r in prove[f] if r['_job']['op'] == 'query']:
        n = int(r['epochs'])
        exact, probe, suf = zka_exact(f, r, n)
        qrows[(n, suf)] = r
        emit(family=f, system=sysname, run='main', operation=f'query_n{n}{suf}', n=n, prove_s=num(r['prove_s']),
             verify_ms=num(r['verify_ms']), proof_bytes=int(r['receipt_bytes']),
             peak_rss_mb=num(r['_job']['r0vm_peak_rss_mb']), rss_scope='' if r['_est'] else 'r0vm process of this proof',
             answer=zka_answer(f, r), exact=exact, provenance=prov(r), note=note_for(f, sysname, r.get('arm', '')),
             detail=f"query guest over {n} epoch states; {probe}; {r['segments']} segments; {r['user_cycles']} user "
                    f"cycles; {gate_of(r)}", **zmem(r, TREES))
    if not qrows or not variants:
        continue
    sufs = sorted({s for (_, s) in qrows})
    qv = [num(r['verify_ms']) for r in qrows.values()]
    qb = [int(r['receipt_bytes']) for r in qrows.values()]
    zka_query_mean[f] = (sum(qv) / len(qv), sum(qb) / len(qb))
    for var in variants:
        mp, mv, mb, aest = zka_aggr_mean[(f, var)]
        con = row_variant(f, next(r for r in aggr_all if row_variant(f, r)[0] == var))[1]
        for suf in sufs:
            for n in NS:
                r = qrows.get((n, suf))
                if r:
                    v, b, how = num(r['verify_ms']), int(r['receipt_bytes']), \
                        'query receipt FROM CYCLES' if r['_est'] else 'query receipt measured'
                else:
                    v, b = zka_query_mean[f]
                    how = (f'query receipt at n={n} not proved: mean of the {len(qv)} measured query receipts '
                           f'({v:.3f} ms, {b:.0f} B)')
                est = aest or (r is not None and r['_est'])
                parts = ['incl. FROM CYCLES receipts'] if est else []
                if r is None and A.zks:   # (the committed 2026-10-09 set: provenance as before)
                    parts.append(f'query receipt at n={n} not proved: SAMPLED, the mean of the measured ones')
                emit(family=f, system=sysname, run='main', operation=f'accept_n{n}{suf}', n=n,
                     verify_ms=n * mv + v, proof_bytes=round(n * mb + b), answer='', exact='',
                     provenance='computed' + (f' ({"; ".join(parts)})' if parts else ''), note=ref_note(f, var),
                     detail=f'verifier work to accept the answer, best-of-5 per receipt: {n} aggregation receipts '
                            f'(sampled mean {mv:.3f} ms, {mb:.0f} B each) + 1 query receipt ({how})',
                     variant=var, root_construction=con)
for f in FAMS:
    sysname = ZKA_NAME[f]
    # verify-protocol re-proofs
    for r in vt[f]:
        if '_vt' not in r:
            continue
        mn, first, med, dec, times = r['_vt']
        j = r['_job']
        vk = {}
        if j['op'] == 'aggr':
            op, ans, ex = f"verify_protocol_update_epoch{r['epoch_index']}", '-', '-'
            vk = dict(zip(('variant', 'root_construction'), row_variant(f, r)))
        else:
            n = int(r['epochs'])
            exact, probe, suf = zka_exact(f, r, n)
            op, ans, ex = f'verify_protocol_query_n{n}{suf}', zka_answer(f, r), exact
        emit(family=f, system=sysname, run='vt', operation=op, n='' if j['op'] == 'aggr' else r['epochs'],
             prove_s=num(r['prove_s']), verify_ms=mn, verify_first_ms=first, verify_median_ms=med, decode_ms=dec,
             proof_bytes=int(r['receipt_bytes']), peak_rss_mb=num(j['r0vm_peak_rss_mb']),
             coord_peak_rss_mb=num(j.get('main_peak_rss_mb')), combined_peak_rss_mb=TREES_VT.get(j['job']),
             rss_scope='r0vm process of this proof', answer=ans, exact=ex, provenance='measured (re-proof)',
             detail=f"re-proof for the verify protocol: all 5 in-process verify calls {';'.join(f'{x:.3f}' for x in times)} ms; "
                    f"decode = bincode deserialisation of the receipt; gate={j['gate']} load1_start={j['load1_start']} "
                    f"busy_cores_start={j['busy_cores_start']}", **vk)


# ------------------------------------------------------------------ zkSketch side
def parse_zks_log(log):
    q = {int(m.group(1)): m.groupdict() for m in re.finditer(
        r'QLOG_QUERY,at_leaf=(\d+),prove_ms=(?P<prove>[\d.]+),witness_ms=[\d.]+,verify_ms=(?P<verify>[\d.]+),'
        r'proof_bytes=(?P<bytes>\d+),answer=(?P<answer>\d+)', log)}
    kk = {int(m.group(1)): m.group(2) for m in re.finditer(r'QLOG_KEY,at_leaf=(\d+),(\S+)', log)}
    b = {int(m.group(1)): m.groupdict() for m in re.finditer(
        r'QLOG_BIND,at_leaf=(\d+),ctx_proofs=(?P<ctx>\d+),intervals=(?P<iv>[^,]+),interval_bytes=(?P<ib>[^,]+),'
        r'bind_ms=(?P<ms>[\d.]+)', log)}
    vq = {int(m.group(1)): [float(x) for x in m.group(2).split(';')] for m in re.finditer(
        r'QLOG_VERIFY,at_leaf=(\d+),decode_verify_ms=([\d.;]+)', log)}
    bv = {}
    for m in re.finditer(r'QLOG_BINDV,at_leaf=(\d+),decode_ms=([\d.|]+),verify_ms=([\d.;|]+),check_ms=([\d.]+)', log):
        bv[int(m.group(1))] = dict(dec=[float(x) for x in m.group(2).split('|')],
                                   ver=[[float(y) for y in x.split(';')] for x in m.group(3).split('|')],
                                   check=float(m.group(4)))
    mem = {int(m.group(1)): float(m.group(2)) for m in re.finditer(
        r'QLOG_MEM,at_leaf=(\d+),query_hwm_mb=([\d.]+)', log)}
    memstart = {int(m.group(1)): (m.group(2), float(m.group(3))) for m in re.finditer(
        r'QLOG_MEMSTART,at_leaf=(\d+),hwm_reset=(\w+),rss_start_mb=([\d.]+)', log)}
    phase = {m.group(1): (float(m.group(2)), float(m.group(3))) for m in re.finditer(
        r'QLOG_PHASE,after=(\w+),coord_hwm_mb=([\d.]+),coord_rss_mb=([\d.]+)', log)}
    vk = re.findall(r'auditor: VK derived from public parameters in ([\d.]+)s', log)
    rs = re.search(r'RSSTREE,\S+,main_peak_rss_mb=([\d.]+),r0vm_peak_rss_mb=[\d.]+,desc_peak_rss_mb=([\d.]+)', log)
    tr = re.search(r'^RSSTREE,.*,tree_peak_rss_mb=([\d.]+)$', log, re.M)
    return q, kk, b, vq, bv, mem, memstart, phase, vk, (float(rs.group(1)), float(rs.group(2))), \
        (float(tr.group(1)) if tr else None)


def zks_answer(f, n, ans, key):
    """(answer, exact, probe, op suffix) of zkSketch's query after n epochs (leaf n x k)."""
    if f == 'cm':
        kv = int(key.split('=')[1])
        return str(ans), str(collections.Counter(prefix(f, n))[kv]), f'key {kv} (hot = heaviest of prefix)', ''
    if f == 'hll':
        return f'{ans / 256:.1f}', str(distinct(f, n)), f'raw HLL estimator, fixed point {ans}/2^8, no small-range correction', ''
    if f == 'kmv':
        return str(ans), str(distinct(f, n)), 'distinct count (27-bit hash)', ''
    if f == 'ss':
        k, c = hot_key(f, n)
        return f'count {ans} (no key)', f'key {k} count {c}', 'top-1 mass (c=1), MG under-estimate', ''
    if f == 'gk':
        v = int(key.split('=')[1])
        return str(ans), str(rank_le(f, n, v)), f'rank({v}) (hot value)', ''
    if f == 'bloom':
        kv = int(key.split('=')[1])
        ex = str(kv in set(prefix(f, n))).lower()
        return ('true' if ans == 1 else 'false'), ex, f"key {kv} ({'inserted' if ex == 'true' else 'absent'})", \
            '_inserted' if ex == 'true' else '_absent'
    raise ValueError(f)


PHASES = []  # (set, tag, phase dict, vk secs, rsstree)
MISSING = []
for pfx, sysname, run, full in ZKS_SETS:
    runs = rows(f'{pfx}_runs.csv')
    for f in FAMS:
        mf, leaf, k = SHAPE[f]   # epoch records, leaf records, leaves per epoch (k = 1: a leaf is an epoch)
        for tag in ZKS_TAGS[f]:
            rr = rows(f'{pfx}_{tag}.csv')
            if not rr:
                MISSING.append(f'{pfx}_{tag}')
                continue
            row = rr[0]
            if row.get('status', 'ok') != 'ok':
                sys.exit(f'{pfx}_{tag}.csv: status={row.get("status")} (the run failed; see {pfx}_{tag}.log)')
            log = open(os.path.join(R, f'{pfx}_{tag}.log')).read()
            q, kk, b, vq, bv, mem, memstart, phase, vk, (main_rss, worker_rss), tree_rss = parse_zks_log(log)
            # --extended columns of every zkSketch row of this run
            zx = dict(zks_variant=row.get('variant') or '-', zks_gk_rounds=row.get('gk_rounds') or '-',
                      zks_shape=row.get('shape') or '-')
            zmem_ = dict(coord_peak_rss_mb=main_rss, combined_peak_rss_mb=tree_rss)
            # the per-query log lines must add up to the CSV's summed query_* columns
            for col, vals in (('query_prove_ms', [float(v['prove']) for v in q.values()]),
                              ('query_verify_ms', [float(v['verify']) for v in q.values()]),
                              ('query_proof_bytes', [float(v['bytes']) for v in q.values()]),
                              ('query_bind_ms', [float(v['ms']) for v in b.values()])):
                if len(vals) != int(row['n_queries']) or abs(sum(vals) - float(row[col])) > 0.01 + 1e-6 * sum(vals):
                    sys.exit(f'{pfx}_{tag}: QLOG lines do not add up to {col} ({sum(vals)} vs {row[col]})')
            hwm_ok = {}
            if full:
                for n in q:
                    # first decode verify == the CSV's; bind_ms == sum(decode + first verify per part) + checks
                    if abs(vq[n][0] - float(q[n]['verify'])) > 0.002:
                        sys.exit(f'{pfx}_{tag}: QLOG_VERIFY first != QLOG_QUERY verify at {n}')
                    want = sum(d + v[0] for d, v in zip(bv[n]['dec'], bv[n]['ver'])) + bv[n]['check']
                    if abs(want - float(b[n]['ms'])) > 0.005 * len(bv[n]['dec']) + 0.002:
                        sys.exit(f'{pfx}_{tag}: QLOG_BINDV parts do not add up to bind_ms at {n} ({want} vs {b[n]["ms"]})')
                    hwm_ok[n] = memstart[n][0] == 'true'
                    if not hwm_ok[n]:
                        print(f'{pfx}_{tag}: VmHWM reset failed at n={n} (/proc/self/clear_refs not writable); '
                              f'its query peak RSS is left blank', file=sys.stderr)
                PHASES.append((pfx, tag, phase, vk, (main_rss, worker_rss)))
            t = int(row['t'])   # leaves
            te = t // k         # epochs
            g = ([x for x in runs if x['tag'] == tag] or [{}])[-1]
            gate = (f"gate={g.get('gate', '?')} load1_start={g.get('load1_start', '?')} "
                    f"busy_cores_start={g.get('busy_cores_start', '?')} "
                    f"commit={row['commit']} features={g.get('features', 'default')}")
            if tag == ZKS_TAGS[f][0] and k == 1:
                emit(family=f, system=sysname, run=run, operation='update_per_epoch',
                     prove_s=float(row['leafgen_seq_ms']) / t / 1000, proof_bytes=int(b[1]['ib']),
                     peak_rss_mb=worker_rss, rss_scope='procs-engine worker (RSSTREE sampler)', answer='-', exact='-',
                     provenance='computed',
                     detail=f"EXCLUDING composition: leafgen_seq_ms/t = {row['leafgen_seq_ms']}/{t} (sum of the {t} "
                            f"measured leaf proofs); proof_bytes = leaf-1 proof as shipped for query binding; "
                            f"exp_compose's own worker peak_rss_mb = {row['peak_rss_mb']}; {gate}", **zx, **zmem_)
                emit(family=f, system=sysname, run=run, operation='update_per_epoch_amortized',
                     prove_s=float(row['total_time_ms']) / t / 1000, answer='-', exact='-', provenance='computed',
                     detail=f"INCLUDING composition: total_time_ms/t = {row['total_time_ms']}/{t} ({t} leaves + "
                            f"{row['merges_local']} merges, 1 machine x {row['cores']} cores)", **zx)
            elif tag == ZKS_TAGS[f][0]:
                # one epoch = k leaves + (k - 1) merges: the measured total when the run is one epoch,
                # else k x leaf_s + (k - 1) x merge_s
                tot = float(row['total_time_ms']) / 1000
                leaf_s = float(row['leafgen_seq_ms']) / t / 1000
                merge_s = (tot - leaf_s * t) / (t - 1)
                how = ('the measured total_time_ms: this forest is one epoch' if te == 1 else
                       f'k x leaf_s + (k - 1) x merge_s = {k} x {leaf_s:.3f} + {k - 1} x {merge_s:.3f} s')
                emit(family=f, system=sysname, run=run, operation='update_per_epoch',
                     prove_s=tot if te == 1 else k * leaf_s + (k - 1) * merge_s,
                     proof_bytes=sum(int(x) for x in b[k]['ib'].split(';')),
                     peak_rss_mb=worker_rss, rss_scope='procs-engine worker (RSSTREE sampler)', answer='-', exact='-',
                     provenance='measured' if te == 1 else 'computed',
                     detail=f"ONE EPOCH = {k} leaves of {leaf} records + {k - 1} merges: {how}; leaf_s = "
                            f"leafgen_seq_ms/t = {row['leafgen_seq_ms']}/{t} ms, merge_s = (total_time_ms - "
                            f"leafgen_seq_ms)/(t - 1) = ({row['total_time_ms']} - {row['leafgen_seq_ms']})/{t - 1} ms "
                            f"(the merges plus the run's other prover work: worker spawn, circuit build, per-leaf "
                            f"verify){'' if te == 1 else f'; EXCLUDING the {te - 1} merge(s) across epochs'}; "
                            f"proof_bytes = the live peak(s) after leaf {k} ({b[k]['ib']}), the epoch's proof as "
                            f"shipped for query binding; exp_compose's own worker peak_rss_mb = {row['peak_rss_mb']}; "
                            f"{gate}", **zx, **zmem_)
                emit(family=f, system=sysname, run=run, operation='update_per_epoch_amortized',
                     prove_s=tot / te, answer='-', exact='-', provenance='computed',
                     detail=f"INCLUDING composition: total_time_ms/T = {row['total_time_ms']}/{te} ({t} leaves of "
                            f"{leaf} records + {row['merges_local']} merges, 1 machine x {row['cores']} cores)", **zx)
            if tag == ZKS_TAGS[f][0]:
                # root verify: newer logs carry QLOG_ROOTV (best of EXP_VERIFY_REPEATS calls = the CSV's
                # verify_ms, plus the first call); older ones only the CSV's single call
                rv = re.search(r'QLOG_ROOTV,repeats=(\d+),first_ms=([\d.]+),best_ms=([\d.]+)', log)
                if rv and abs(float(rv.group(3)) - float(row['verify_ms'])) > 0.002:
                    sys.exit(f'{pfx}_{tag}: QLOG_ROOTV best_ms != the CSV verify_ms')
                root_v = dict(verify_ms=float(rv.group(3)), verify_first_ms=float(rv.group(2))) if rv \
                    else dict(verify_first_ms=float(row['verify_ms']))
                emit(family=f, system=sysname, run=run, operation=f'update_stream_{te}_epochs',
                     prove_s=float(row['total_time_ms']) / 1000, **root_v,
                     proof_bytes=int(row['proof_bytes']), peak_rss_mb=worker_rss, **zx, **zmem_,
                     rss_scope='procs-engine worker (RSSTREE sampler)', answer='-', exact='-', provenance='measured',
                     detail=f"forest, 1 machine x {row['cores']} cores: {t} leaves"
                            f"{f' of {leaf} records ({k} per epoch)' if k > 1 else ''} + {row['merges_local']} merges (merge_ms "
                            f"{row['merge_ms']}, local_fold_ms {row['local_fold_ms']}); one O(1) root ("
                            f"{f'verify_ms = best of {rv.group(1)} calls, verify_first_ms = the first' if rv else 'single verify verify_first_ms'}"
                            f", proof_bytes); {gate}")
            for n in NS:
                j = n * k   # zkSketch's leaf at the end of epoch n
                if j not in q:
                    continue
                qq, bb = q[j], b[j]
                answer, exact, probe, suf = zks_answer(f, n, int(qq['answer']), kk.get(j, ''))
                op = f'query_n{n}{suf}'
                ib = [int(x) for x in bb['ib'].split(';')]
                ver = f"t'={n}" if k == 1 else f"t'={j} (after leaf {j} = epoch {n})"
                if full:
                    mn, first, med = stats(vq[j])
                    emit(family=f, system=sysname, run=run, operation=op, n=n, prove_s=float(qq['prove']) / 1000,
                         verify_ms=mn, verify_first_ms=first, verify_median_ms=med, proof_bytes=int(qq['bytes']),
                         peak_rss_mb=mem[j] if hwm_ok[j] else None,
                         rss_scope='coordinator VmHWM reset at query start (this query only)' if hwm_ok[j] else
                         'not measured (VmHWM reset failed)',
                         answer=answer, exact=exact, provenance='measured', note=note_for(f, sysname),
                         detail=f"decode proof at version {ver}; {probe}; prove = witness + prove; verify calls "
                                f"{';'.join(f'{x:.3f}' for x in vq[j])} ms; rss_start {memstart[j][1]} MB; {gate}", **zx)
                    parts = bv[j]
                    pmin = sum(min(v) for v in parts['ver'])
                    pfirst = sum(v[0] for v in parts['ver'])
                    pmed = sum(statistics.median(v) for v in parts['ver'])
                    emit(family=f, system=sysname, run=run, operation=op.replace('query', 'accept'), n=n,
                         verify_ms=pmin + parts['check'] + mn, verify_first_ms=pfirst + parts['check'] + first,
                         verify_median_ms=pmed + parts['check'] + med, decode_ms=sum(parts['dec']),
                         proof_bytes=sum(ib) + int(qq['bytes']), answer='', exact='', **zx,
                         provenance='computed (sum of measured parts)',
                         detail=f"{bb['ctx']} live peak(s) [{bb['iv']}] verified against pinned VKs (per part, best "
                                f"of 5: {'+'.join(f'{min(v):.3f}' for v in parts['ver'])} ms) + statement checks "
                                f"{parts['check']:.3f} ms + query proof (best of 5 {mn:.3f} ms); postcard decode "
                                f"{'+'.join(f'{d:.3f}' for d in parts['dec'])} ms excluded; bytes = peak proof(s) "
                                f"{bb['ib']} + query proof")
                else:
                    emit(family=f, system=sysname, run=run, operation=op, n=n, prove_s=float(qq['prove']) / 1000,
                         verify_first_ms=float(qq['verify']), proof_bytes=int(qq['bytes']), answer=answer,
                         exact=exact, provenance='measured (repeat run r1)', note=note_for(f, sysname),
                         detail=f"first run (r1), single verify only; {probe}; {gate}", **zx)

if A.zks:
    for f in FAMS:
        if not prove[f]:
            print(f'{ZKA}: no zk-Analytics rows for {f}', file=sys.stderr)
    if MISSING:
        print(f'no zkSketch CSV for: {" ".join(MISSING)}', file=sys.stderr)

order = {f: i for i, f in enumerate(FAMS)}
sys_order = {'zk-Analytics': 0, 'zk-Analytics arch. (port †)': 0, 'zk-Analytics arch. (port †, zkSketch GK rule)': 0,
             'zkSketch': 1, 'zkSketch (zk feature)': 2}
run_order = {'main': 0, 'vt': 1, 'r2': 0, 'zk': 0, 'r1': 3}
# Rows of one variant stay together (update rows first, then accept rows per variant); with a
# single variant (the committed set: legacy update / accept rows, '-' query rows) this is the
# previous order.
OUT.sort(key=lambda r: (order[r['family']], sys_order[r['system']], run_order.get(r['run'], 0),
                        r['operation'].split('_')[0] != 'update', VORDER.get(r['variant'], 99),
                        r['operation'].split('_')[0], int(r['n'] or 0), r['operation']))
# The HLL note's "N-Mx above exact": the committed set keeps its text; a new run at the paper
# shape (2048, 8), or an --extended one, gets the ratios of its own answers
HLL_RAW = ('NOT like-for-like: zkSketch certifies the raw HLL estimator (no small-range / linear-counting '
           'branch); ')
if A.zks and ((SHAPE['hll'][0], T) == (2048, 8) or EXT):
    for key in {(r['system'], r['run']) for r in OUT if r['family'] == 'hll' and r['system'].startswith('zkSketch')}:
        qs = [r for r in OUT if (r['system'], r['run']) == key and r['family'] == 'hll'
              and r['operation'].startswith('query_n') and num(r['exact'])]
        xs = [num(r['answer']) / num(r['exact']) for r in qs if num(r['answer']) is not None]
        if not xs:
            continue
        lo, hi = min(xs), max(xs)
        # HLL's standard error at b = 14 is 1.04 / 2^7 = 0.8%: outside its bounds well before 5% off
        txt = HLL_RAW + (f'its answers are {lo:.1f}-{hi:.1f}x the exact count here (n = {qs[0]["n"]}..{qs[-1]["n"]}), '
                         f'outside HLL error bounds' if lo > 1.05 or hi < 0.95 else
                         'compare its answer with the exact column')
        for r in qs:
            r['note'] = txt
for r in OUT:   # the family's shape on every row (--extended)
    r['epoch_records'], r['zks_leaf_records'], r['zks_leaves_per_epoch'] = SHAPE[r['family']]
w = csv.DictWriter(open(OUT_PATH, 'w', newline=''), fieldnames=COLS + (COLS_EXT if EXT else []),
                   extrasaction='ignore')
w.writeheader()
w.writerows(OUT)
print(f'{len(OUT)} rows -> {OUT_PATH}')
for pfx, tag, phase, vk, (mr, wr) in PHASES:
    print(f'PHASE {pfx}_{tag}: ' + ' '.join(f'{k}=hwm {v[0]:.0f}/rss {v[1]:.0f} MB' for k, v in phase.items())
          + f" vk_derive_s={','.join(vk)} RSSTREE main={mr:.0f} worker={wr:.0f}", file=sys.stderr)
