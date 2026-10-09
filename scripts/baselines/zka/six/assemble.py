#!/usr/bin/env python3
"""Assemble six_sketch_comparison.csv from the raw six_* files (run with python3 -I).

Usage: assemble.py <results dir> <aol.keys>

Inputs (all in <results dir>):
  six_zka_<fam>_exec.csv     executor rows, all 8 aggregation epochs (bloom/kmv: + query executes)
  six_zka_<fam>_prove.csv    proved rows (aggregation epochs 0 and 7; queries n = 1, 2, 4, 8)
  six_zka_jobs.csv           one line per proved job, in the same order (gate, load, r0vm peak RSS)
  six_zksketch_<tag>.csv     exp_compose CSV row (one per run)
  six_zksketch_<tag>.log     the run's stderr/stdout incl. QLOG_* per-query lines and RSSTREE
Exact answers are recomputed here from the same 16,384 AOL records.
"""
import collections
import csv
import os
import re
import struct
import sys

R, KEYS = sys.argv[1], sys.argv[2]
M, T = 2048, 8
NS = [1, 2, 4, 8]
FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']

# ------------------------------------------------------------------ exact answers
raw = open(KEYS, 'rb').read()
keys = list(struct.unpack('<%dI' % (len(raw) // 4), raw))[:M * T]


def prefix(n):
    return keys[:n * M]


def hot_key(n):
    c = collections.Counter(prefix(n))
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def distinct(n):
    return len(set(prefix(n)))


def rank_le(n, v):
    return sum(1 for k in prefix(n) if (k & 0x1FFFFF) <= v)


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


jobs = rows('six_zka_jobs.csv')
prove = {f: rows(f'six_zka_{f}_prove.csv') for f in FAMS}
# attach each proved row to its job line (same order per family; checked)
for f in FAMS:
    fj = [j for j in jobs if j['family'] == f]
    if len(fj) != len(prove[f]):
        sys.exit(f'{f}: {len(fj)} jobs vs {len(prove[f])} proved rows')
    for row, j in zip(prove[f], fj):
        mode = row.get('step') or row.get('mode')
        n_or_e = row['epoch_index'] if j['op'] == 'aggr' else row['epochs']
        if mode != j['op'] or n_or_e != j['n_or_epoch']:
            sys.exit(f'{f}: row/job mismatch {mode},{n_or_e} vs {j["op"]},{j["n_or_epoch"]}')
        row['_job'] = j

OUT = []


def emit(fam, system, op, n, prove_s, verify_ms, proof_bytes, rss, answer, exact, prov, detail):
    def fmt(v, d):
        return '' if v is None else (f'{v:.{d}f}' if isinstance(v, float) else str(v))
    OUT.append(dict(family=fam, system=system, operation=op, n=n, prove_s=fmt(prove_s, 6),
                    verify_ms=fmt(verify_ms, 3), proof_bytes=fmt(proof_bytes, 0),
                    peak_rss_mb=fmt(rss, 1), answer=answer, exact=exact, provenance=prov, detail=detail))


def zka_answer(f, row):
    res = row.get('answer') or row.get('result') or ''
    if f == 'cm':
        return re.search(r'estimate=(\d+)', res).group(1)
    if f in ('hll', 'kmv'):
        return re.search(r'estimate=(\d+)', res).group(1)
    if f == 'ss':
        m = re.search(r'top=(\d+):(\d+)/e(\d+)', res)
        return f'key {m.group(1)} count {m.group(2)} (error {m.group(3)})'
    if f == 'gk':
        m = re.search(r'est=(\d+);lo=(\d+);hi=(\d+)', res)
        return f'{m.group(1)} [{m.group(2)}..{m.group(3)}]'
    if f == 'bloom':
        return re.search(r'member=(\w+)', res).group(1)
    return res


ZKA_NAME = {'cm': 'zk-Analytics', 'hll': 'zk-Analytics arch. (port †)', 'ss': 'zk-Analytics arch. (port †)',
            'gk': 'zk-Analytics arch. (port †)', 'bloom': 'zk-Analytics arch. (port †)',
            'kmv': 'zk-Analytics arch. (port †)'}

zka_aggr_mean = {}
for f in FAMS:
    sysname = ZKA_NAME[f]
    ex = [r for r in rows(f'six_zka_{f}_exec.csv') if (r.get('step') or r.get('mode')) == 'aggr']
    segs = [int(r['segments']) for r in ex]
    cyc = [int(r['user_cycles']) for r in ex]
    aggr = [r for r in prove[f] if r['_job']['op'] == 'aggr']
    for r in aggr:
        e = r['epoch_index']
        emit(f, sysname, f'update_epoch{e}', '', num(r['prove_s']), num(r['verify_ms']), int(r['receipt_bytes']),
             num(r['_job']['r0vm_peak_rss_mb']), '-', '-', 'measured',
             f"aggregation guest on epoch {e} ({M} records); {r['segments']} segments; {r['user_cycles']} user cycles; "
             f"gate={r['_job']['gate']} load1_start={r['_job']['load1_start']}")
    if not aggr:
        print(f'{f}: no proved aggregation rows yet; skipped', file=sys.stderr)
        continue
    ps = [num(r['prove_s']) for r in aggr]
    vs = [num(r['verify_ms']) for r in aggr]
    bs = [int(r['receipt_bytes']) for r in aggr]
    rs = [num(r['_job']['r0vm_peak_rss_mb']) for r in aggr]
    mp, mv, mb = sum(ps) / len(ps), sum(vs) / len(vs), sum(bs) / len(bs)
    zka_aggr_mean[f] = (mp, mv, mb)
    emit(f, sysname, 'update_per_epoch', '', mp, mv, round(mb), max(rs), '-', '-', 'sampled',
         f'mean of proved epochs 0 and 7; executor over all 8 epochs: {min(segs)}-{max(segs)} segments, '
         f'{min(cyc)}-{max(cyc)} user cycles')
    emit(f, sysname, 'update_stream_8_epochs', '', 8 * mp, None, None, max(rs), '-', '-', 'derived',
         '8 x sampled per-epoch prove time; 8 receipts are kept (no composition)')
    for r in [r for r in prove[f] if r['_job']['op'] == 'query']:
        n = int(r['epochs'])
        probe = ''
        if f == 'cm':
            k, c = hot_key(n)
            exact = str(c)
            m = re.search(r'key=(\d+)', r['exact'])
            assert int(m.group(1)) == k, (f, n)
            probe = f'key {k} (heaviest of prefix)'
        elif f in ('hll', 'kmv'):
            exact = str(distinct(n))
        elif f == 'ss':
            k, c = hot_key(n)
            exact = f'key {k} count {c}'
            probe = 'top-1 (topk limit 1)'
        elif f == 'gk':
            v = int(r['_job']['arg'])
            exact = str(rank_le(n, v))
            probe = f'rank({v})'
        elif f == 'bloom':
            pk = int(r['probe_key'])
            exact = str(pk in set(prefix(n))).lower()
            probe = f"key {pk} ({'inserted' if exact == 'true' else 'absent'})"
        op = f'query_n{n}' + ('' if f != 'bloom' else ('_inserted' if exact == 'true' else '_absent'))
        emit(f, sysname, op, n, num(r['prove_s']), num(r['verify_ms']), int(r['receipt_bytes']),
             num(r['_job']['r0vm_peak_rss_mb']), zka_answer(f, r), exact, 'measured',
             f"query guest over {n} epoch states; {probe}; {r['segments']} segments; {r['user_cycles']} user cycles; "
             f"gate={r['_job']['gate']} load1_start={r['_job']['load1_start']}")
        emit(f, sysname, op.replace('query', 'accept'), n, None, n * mv + num(r['verify_ms']),
             round(n * mb + int(r['receipt_bytes'])), None, '', '', 'derived',
             f'verifier work to accept the answer: {n} aggregation receipts (sampled mean verify {mv:.3f} ms, '
             f'{mb:.0f} B each) + 1 query receipt (measured)')

# ------------------------------------------------------------------ zkSketch
ZKS_TAGS = {'cm': ['cm'], 'hll': ['hll'], 'ss': ['ss'], 'gk': ['gk'], 'bloom': ['bloom', 'bloom_absent'],
            'kmv': ['kmv']}
for f in FAMS:
    for tag in ZKS_TAGS[f]:
        rr = rows(f'six_zksketch_{tag}.csv')
        if not rr:
            continue
        row = rr[0]
        logp = os.path.join(R, f'six_zksketch_{tag}.log')
        log = open(logp).read()
        q = {int(m.group(1)): m.groupdict() for m in re.finditer(
            r'QLOG_QUERY,at_leaf=(\d+),prove_ms=(?P<prove>[\d.]+),witness_ms=[\d.]+,verify_ms=(?P<verify>[\d.]+),'
            r'proof_bytes=(?P<bytes>\d+),answer=(?P<answer>\d+)', log)}
        kk = {int(m.group(1)): m.group(2) for m in re.finditer(r'QLOG_KEY,at_leaf=(\d+),(\S+)', log)}
        b = {int(m.group(1)): m.groupdict() for m in re.finditer(
            r'QLOG_BIND,at_leaf=(\d+),ctx_proofs=(?P<ctx>\d+),intervals=(?P<iv>[^,]+),interval_bytes=(?P<ib>[^,]+),'
            r'bind_ms=(?P<ms>[\d.]+)', log)}
        # the per-query log lines must add up to the CSV's summed query_* columns
        for col, vals in (('query_prove_ms', [float(v['prove']) for v in q.values()]),
                          ('query_verify_ms', [float(v['verify']) for v in q.values()]),
                          ('query_proof_bytes', [float(v['bytes']) for v in q.values()]),
                          ('query_bind_ms', [float(v['ms']) for v in b.values()])):
            if len(vals) != int(row['n_queries']) or abs(sum(vals) - float(row[col])) > 0.01 + 1e-6 * sum(vals):
                sys.exit(f'{tag}: QLOG lines do not add up to {col} ({sum(vals)} vs {row[col]})')
        rs = re.search(r'RSSTREE,\S+,main_peak_rss_mb=([\d.]+),r0vm_peak_rss_mb=[\d.]+,desc_peak_rss_mb=([\d.]+)', log)
        main_rss, worker_rss = float(rs.group(1)), float(rs.group(2))
        t = int(row['t'])
        leaf_bytes = int(b[1]['ib'])
        notes = os.path.join(R, 'six_zksketch_runs.csv')
        g = [x for x in rows('six_zksketch_runs.csv') if x['tag'] == tag][0]
        gate = f"gate={g['gate']} load1_start={g['load1_start']} commit={row['commit']}"
        if tag == ZKS_TAGS[f][0]:
            emit(f, 'zkSketch', 'update_per_epoch', '', float(row['leafgen_seq_ms']) / t / 1000, None, leaf_bytes,
                 float(row['peak_rss_mb']), '-', '-', 'derived',
                 f"leafgen_seq_ms/t = {row['leafgen_seq_ms']}/{t} (sum of the {t} measured leaf proofs); "
                 f'proof_bytes = leaf-1 proof as shipped for query binding; {gate}')
            emit(f, 'zkSketch', 'update_stream_8_epochs', '', float(row['total_time_ms']) / 1000,
                 float(row['verify_ms']), int(row['proof_bytes']), float(row['peak_rss_mb']), '-', '-', 'measured',
                 f"forest, 1 machine x 32 cores: {t} leaves + {row['merges_local']} merges (merge_ms {row['merge_ms']}, "
                 f"local_fold_ms {row['local_fold_ms']}); one O(1) root (verify_ms, proof_bytes); {gate}")
        for n in NS:
            if n not in q:
                continue
            qq, bb = q[n], b[n]
            ans = int(qq['answer'])
            key = kk.get(n, '')
            if f == 'cm':
                kv = int(key.split('=')[1])
                c = collections.Counter(prefix(n))[kv]
                exact, answer, probe = str(c), str(ans), f'key {kv} (hot = heaviest of prefix)'
            elif f == 'hll':
                exact, answer, probe = str(distinct(n)), f'{ans / 256:.1f}', \
                    f'raw HLL estimator, fixed point answer {ans}/2^8, no small-range correction'
            elif f == 'kmv':
                exact, answer, probe = str(distinct(n)), str(ans), 'distinct count (27-bit hash)'
            elif f == 'ss':
                k, c = hot_key(n)
                exact, answer, probe = f'key {k} count {c}', f'count {ans} (no key)', 'top-1 mass (c=1), MG under-estimate'
            elif f == 'gk':
                v = int(key.split('=')[1])
                exact, answer, probe = str(rank_le(n, v)), str(ans), f'rank({v}) (hot value)'
            elif f == 'bloom':
                kv = int(key.split('=')[1])
                exact = str(kv in set(prefix(n))).lower()
                answer = 'true' if ans == 1 else 'false'
                probe = f"key {kv} ({'inserted' if exact == 'true' else 'absent'})"
            op = f'query_n{n}' + ('' if f != 'bloom' else ('_inserted' if exact == 'true' else '_absent'))
            emit(f, 'zkSketch', op, n, float(qq['prove']) / 1000, float(qq['verify']), int(qq['bytes']), main_rss,
                 answer, exact, 'measured',
                 f'decode proof at version t\'={n}; {probe}; prove = witness + prove; rss = coordinator peak '
                 f'(whole run: auditor VK derivation + all {t} queries + binding); {gate}')
            ib = [int(x) for x in bb['ib'].split(';')]
            emit(f, 'zkSketch', op.replace('query', 'accept'), n, None, float(bb['ms']) + float(qq['verify']),
                 sum(ib) + int(qq['bytes']), None, '', '', 'measured',
                 f"query_bind_ms {bb['ms']} (pinned verify of {bb['ctx']} live peak(s) [{bb['iv']}] + log checks) "
                 f"+ query verify {qq['verify']} ms; bytes = peak proof(s) {bb['ib']} + query proof")

cols = ['family', 'system', 'operation', 'n', 'prove_s', 'verify_ms', 'proof_bytes', 'peak_rss_mb', 'answer', 'exact',
        'provenance', 'detail']
order = {f: i for i, f in enumerate(FAMS)}
OUT.sort(key=lambda r: (order[r['family']], r['system'] != 'zkSketch', r['operation'].split('_')[0] != 'update',
                        int(r['n'] or 0), r['operation']))
w = csv.DictWriter(open(os.path.join(R, 'six_sketch_comparison.csv'), 'w', newline=''), fieldnames=cols)
w.writeheader()
w.writerows(OUT)
print(f'{len(OUT)} rows')
