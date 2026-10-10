#!/usr/bin/env python3
"""Print the README's markdown tables from six_sketch_comparison.csv (python3 -I table.py <csv>).

zkA = zk-Analytics side, zkS = zkSketch default build (run r2; the `zk` feature was then off),
zkS-zk = zkSketch built with `--features zk` (HidingFriPcs) BEFORE the LogUp-mask forks: its
revealed LogUp sums are unmasked, so it is not zero-knowledge either, and the masked build costs
more (src/config.rs, "Cost of the masks"). KB / MB = 10^3 / 10^6 bytes; GB (memory) = 2^30 bytes.
"""
import csv
import statistics
import sys

rows = list(csv.DictReader(open(sys.argv[1])))
FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']
NAME = {'cm': 'Count-Min 3x1024', 'hll': 'HLL b=14 † ‡', 'ss': 'SS / MG s=1,024 † §', 'gk': 'GK eps=1/51 †',
        'bloom': 'Bloom 7x2^14 †', 'kmv': 'KMV k=1,024 †'}
ZKS, ZK = ('zkSketch', 'r2'), ('zkSketch (zk feature)', 'zk')


def get(fam, who, op):
    for r in rows:
        if r['family'] != fam or r['operation'] != op:
            continue
        if who == 'zka' and r['system'].startswith('zk-Analytics') and r['run'] == 'main':
            return r
        if who == 'vt' and r['system'].startswith('zk-Analytics') and r['run'] == 'vt':
            return r
        if who == 'zks' and (r['system'], r['run']) == ZKS:
            return r
        if who == 'zk' and (r['system'], r['run']) == ZK:
            return r
        if who == 'r1' and r['system'] == 'zkSketch' and r['run'] == 'r1':
            return r
    return None


def v(r, col):
    return None if r is None or r[col] in ('', None) else float(r[col])


def f(x, d=1):
    return '-' if x is None else f'{x:,.{d}f}'


def fs(x):  # seconds, adaptive precision
    return '-' if x is None else (f'{x:,.3f}' if x < 1 else f'{x:,.2f}' if x < 100 else f'{x:,.1f}')


def kb(x):
    return '-' if x is None else f'{x / 1000:,.0f}'


def gb(x):
    return '-' if x is None else f'{x / 1024:,.1f}'


def ratio(a, b):
    if a is None or b in (None, 0):
        return '-'
    q = a / b
    return f'{q:,.0f}x' if q >= 10 else f'{q:,.1f}x' if q >= 1 else f'{q:,.2f}x'


def sufs(fam):
    return ['_inserted', '_absent'] if fam == 'bloom' else ['']


def label(fam, suf):
    return NAME[fam] + (f' ({suf[1:]} key)' if suf else '')


print('**Update side.** One epoch = one batch of 2,048 records. Ratios are zkA / zkS. zkA prove per epoch is the '
      'mean of proved epochs 0 and 7 (sampled); zkA 8 epochs = 8 x that mean (derived). zkS "8 batches" is '
      'measured and includes the 7 forest merges; "leaf alone" is leafgen_seq_ms / 8 and EXCLUDES composition.\n')
print('| sketch | zkA 8 epochs (s) | zkS 8 batches incl. merges (s) | ratio | zkS-zk 8 batches (s) | ratio | '
      'zkA / epoch (s) | zkS leaf alone (s) | ratio | zkS-zk leaf alone (s) | ratio | '
      'peak RSS GB: zkA r0vm / zkS worker / zkS-zk worker |')
print('|---|---|---|---|---|---|---|---|---|---|---|---|')
for fam in FAMS:
    a8, b8, z8 = (v(get(fam, w, 'update_stream_8_epochs'), 'prove_s') for w in ('zka', 'zks', 'zk'))
    a1, b1, z1 = (v(get(fam, w, 'update_per_epoch'), 'prove_s') for w in ('zka', 'zks', 'zk'))
    ra, rb, rz = (v(get(fam, w, 'update_per_epoch'), 'peak_rss_mb') for w in ('zka', 'zks', 'zk'))
    print(f'| {NAME[fam]} | {f(a8, 0)} | {fs(b8)} | {ratio(a8, b8)} | {fs(z8)} | {ratio(a8, z8)} | {fs(a1)} | '
          f'{fs(b1)} | {ratio(a1, b1)} | {fs(z1)} | {ratio(a1, z1)} | {gb(ra)} / {gb(rb)} / {gb(rz)} |')

print('\n**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.\n')
print('| sketch | zkA receipt / epoch | zkA 8 receipts | zkS root | zkS-zk root | zkS root verify, single call (ms) | '
      'zkS-zk root verify (ms) |')
print('|---|---|---|---|---|---|---|')
for fam in FAMS:
    ab = v(get(fam, 'zka', 'update_per_epoch'), 'proof_bytes')
    sb, zb = (v(get(fam, w, 'update_stream_8_epochs'), 'proof_bytes') for w in ('zks', 'zk'))
    sv, zv = (v(get(fam, w, 'update_stream_8_epochs'), 'verify_first_ms') for w in ('zks', 'zk'))
    print(f'| {NAME[fam]} | {kb(ab)} | {kb(8 * ab if ab else None)} | {kb(sb)} | {kb(zb)} | {f(sv)} | {f(zv)} |')

print('\n**Query proving time** (s; the query proof alone; cells are zkA / zkS / zkS-zk; ‡ and § see notes)\n')
print('| sketch | n=1 | n=2 | n=4 | n=8 | zkA / zkS at n=1 | at n=8 | zkA / zkS-zk at n=1 | at n=8 |')
print('|---|---|---|---|---|---|---|---|---|')
for fam in FAMS:
    for suf in sufs(fam):
        cells = []
        for n in (1, 2, 4, 8):
            a, b, z = (v(get(fam, w, f'query_n{n}{suf}'), 'prove_s') for w in ('zka', 'zks', 'zk'))
            cells.append(f'{fs(a)} / {fs(b)} / {fs(z)}')
        a1, b1, z1 = (v(get(fam, w, f'query_n1{suf}'), 'prove_s') for w in ('zka', 'zks', 'zk'))
        a8, b8, z8 = (v(get(fam, w, f'query_n8{suf}'), 'prove_s') for w in ('zka', 'zks', 'zk'))
        print(f"| {label(fam, suf)} | {' | '.join(cells)} | {ratio(a1, b1)} | {ratio(a8, b8)} | {ratio(a1, z1)} | "
              f"{ratio(a8, z8)} |")

print('\n**zkSketch query proving at the other n** (s; zkS / zkS-zk; zkA did not prove these n)\n')
print('| sketch | n=3 | n=5 | n=6 | n=7 |')
print('|---|---|---|---|---|')
for fam in FAMS:
    for suf in sufs(fam):
        cells = []
        for n in (3, 5, 6, 7):
            b, z = (v(get(fam, w, f'query_n{n}{suf}'), 'prove_s') for w in ('zks', 'zk'))
            cells.append(f'{fs(b)} / {fs(z)}')
        print(f"| {label(fam, suf)} | {' | '.join(cells)} |")

PEAKS = {n: bin(n).count('1') for n in range(1, 9)}
for who, title in (('zks', 'zkSketch default build'), ('zk', 'zkSketch `--features zk`')):
    for col, unit, fmt, what in (('verify_ms', 'ms', lambda x: f(x), 'Verifier work to accept one answer at n'),
                                 ('proof_bytes', 'KB', kb, 'Bytes the verifier receives for one answer at n')):
        extra = ('best of 5 calls per proof on both sides; deserialisation excluded on both sides'
                 if col == 'verify_ms' else 'KB = 10^3 bytes')
        print(f'\n**{what}, zkA vs {title}** ({unit}; {extra}; cells zkA / zkS; zkA = n aggregation receipts + 1 query '
              f'receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the '
              f'smaller side)\n')
        print('| sketch | ' + ' | '.join(f'n={n} ({PEAKS[n]} peak{"s" if PEAKS[n] > 1 else ""})' for n in range(1, 9))
              + ' |')
        print('|---' * 9 + '|')
        for fam in FAMS:
            for suf in sufs(fam):
                cells = []
                for n in range(1, 9):
                    a, b = v(get(fam, 'zka', f'accept_n{n}{suf}'), col), v(get(fam, who, f'accept_n{n}{suf}'), col)
                    if a is None or b is None:
                        cells.append('-')
                    elif a < b:
                        cells.append(f'**{fmt(a)}** / {fmt(b)}')
                    else:
                        cells.append(f'{fmt(a)} / **{fmt(b)}**')
                print(f"| {label(fam, suf)} | {' | '.join(cells)} |")

print('\n**Verify protocol, one proof** (ms; in-process, right after proving; first call / median of 5 / best of 5; '
      'decode = deserialisation, not in any verify column)\n')
print('| sketch | zkA query receipt n=1 (re-proof) | zkA decode (bincode) | zkS query proof n=1 | '
      'zkS leaf-1 peak (accept n=1) | zkS decode (postcard), leaf-1 | zkS-zk query proof n=1 |')
print('|---|---|---|---|---|---|---|')
for fam in FAMS:
    suf = '_inserted' if fam == 'bloom' else ''
    a = get(fam, 'vt', f'verify_protocol_query_n1{suf}')
    b, z = get(fam, 'zks', f'query_n1{suf}'), get(fam, 'zk', f'query_n1{suf}')
    acc = get(fam, 'zks', f'accept_n1{suf}')

    def trip(r):
        return '-' if r is None else f"{f(v(r, 'verify_first_ms'))} / {f(v(r, 'verify_median_ms'))} / {f(v(r, 'verify_ms'))}"
    leaf = '-'
    if acc and b:
        leaf = (f"{f(v(acc, 'verify_first_ms') - v(b, 'verify_first_ms'))} / "
                f"{f(v(acc, 'verify_median_ms') - v(b, 'verify_median_ms'))} / "
                f"{f(v(acc, 'verify_ms') - v(b, 'verify_ms'))}")
    print(f"| {NAME[fam]} | {trip(a)} | {f(v(a, 'decode_ms'), 2) if a else '-'} | {trip(b)} | {leaf} | "
          f"{f(v(acc, 'decode_ms'), 2) if acc else '-'} | {trip(z)} |")
agg = [r for r in rows if r['run'] == 'vt' and r['operation'].startswith('verify_protocol_update')]
for r in agg:
    print(f"\n(zkA aggregation receipt, {r['family']} {r['operation'][16:]}, re-proof: first {f(v(r, 'verify_first_ms'))} / "
          f"median {f(v(r, 'verify_median_ms'))} / best {f(v(r, 'verify_ms'))} ms; bincode decode {f(v(r, 'decode_ms'), 2)} ms)")

print('\n**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the '
      'coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the '
      'process already held)\n')
print('| sketch | zkA n=1 | zkA n=2 | zkA n=4 | zkA n=8 | zkS n=1 / n=8 (max over n=1..8) | zkS-zk n=1 / n=8 (max) |')
print('|---|---|---|---|---|---|---|')
for fam in FAMS:
    suf = '_inserted' if fam == 'bloom' else ''
    a = [gb(v(get(fam, 'zka', f'query_n{n}{suf}'), 'peak_rss_mb')) for n in (1, 2, 4, 8)]

    def zz(who):
        xs = [v(get(fam, who, f'query_n{n}{suf}'), 'peak_rss_mb') for n in range(1, 9)]
        xs = [x for x in xs if x is not None]
        if not xs:
            return '-'
        return f"{gb(v(get(fam, who, f'query_n1{suf}'), 'peak_rss_mb'))} / {gb(v(get(fam, who, f'query_n8{suf}'), 'peak_rss_mb'))} ({gb(max(xs))})"
    print(f"| {NAME[fam]} | {' | '.join(a)} | {zz('zks')} | {zz('zk')} |")

print('\n**Answers vs exact** (same 16,384 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw '
      'estimator, outside HLL error bounds)\n')
print('| sketch | n | zk-Analytics answer | zkSketch answer | zkSketch-zk answer | exact |')
print('|---|---|---|---|---|---|')
for fam in FAMS:
    for suf in sufs(fam):
        for n in (1, 2, 4, 8):
            a, b, z = (get(fam, w, f'query_n{n}{suf}') for w in ('zka', 'zks', 'zk'))
            ex = (b or a or {}).get('exact', '-')
            print(f"| {label(fam, suf)} | {n} | {a['answer'] if a else '-'} | {b['answer'] if b else '-'} | "
                  f"{z['answer'] if z else '-'} | {ex} |")

print('\n**Repeatability, zkSketch default build: run r1 (first run) vs r2 (primary)**\n')
print('| sketch | 8 batches r1 / r2 (s) | leaf alone r1 / r2 (s) | query prove n=1..8 summed r1 / r2 (s) |')
print('|---|---|---|---|')
for fam in FAMS:
    s1, s2 = v(get(fam, 'r1', 'update_stream_8_epochs'), 'prove_s'), v(get(fam, 'zks', 'update_stream_8_epochs'), 'prove_s')
    l1, l2 = v(get(fam, 'r1', 'update_per_epoch'), 'prove_s'), v(get(fam, 'zks', 'update_per_epoch'), 'prove_s')
    suf = '_inserted' if fam == 'bloom' else ''
    q1 = sum(v(get(fam, 'r1', f'query_n{n}{suf}'), 'prove_s') or 0 for n in range(1, 9))
    q2 = sum(v(get(fam, 'zks', f'query_n{n}{suf}'), 'prove_s') or 0 for n in range(1, 9))
    print(f'| {NAME[fam]} | {fs(s1)} / {fs(s2)} | {fs(l1)} / {fs(l2)} | {fs(q1)} / {fs(q2)} |')

# ------------------------------------------------------------------ framework share (zk-Analytics side)
import os
import re
RD = os.path.dirname(os.path.abspath(sys.argv[1]))


def rd(name):
    p = os.path.join(RD, name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else []


def phase_split(fam):
    """(user cycles, read, chain, update-or-sketch work) of aggregation epoch 0, or None."""
    if fam in ('hll', 'bloom', 'kmv'):
        for r in rd(f'six_zka_{fam}_exec.csv'):
            if (r.get('step') or r.get('mode')) == 'aggr' and r['epoch_index'] == '0':
                ph = dict(kv.split('=') for kv in r['prof'].split(';'))
                return int(r['user_cycles']), int(ph['read']), int(ph['chain']), 'measured (profiling marks)'
    if fam == 'ss':
        for r in rd('six_zka_prof_ss.csv'):
            if r['mode'] == 'aggr' and r['epoch_index'] == '0':
                ph = {k: int(v.split('(')[0]) for k, v in (kv.split('=') for kv in r['phases'].split(';'))}
                return int(r['user_cycles']), ph['read'], ph['chain'], 'measured (profiling twin aggr_ss_prof)'
    if fam == 'gk':
        for r in rd('six_zka_prof_gk.csv'):
            if r['mode'] == 'aggr' and r['epoch_index'] == '0':
                ph = dict(kv.split('=') for kv in re.search(r'PHASES (.*?)(,|$)', r['result']).group(1).split())
                return int(r['user_cycles']), int(ph['input_read']), int(ph['chain_verify']), \
                    'measured (profiling twin aggr_gk_prof)'
    return None


print('\n**zk-Analytics aggregation guest, epoch 0 (2,048 records): their ingest vs the rest** (user cycles; '
      'MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment '
      'rounding; it is NOT a measurement)\n')
print('| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest '
      'prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |')
print('|---|---|---|---|---|---|---|---|---|')
for fam in FAMS:
    sp = phase_split(fam)
    a1 = v(get(fam, 'zka', 'update_per_epoch'), 'prove_s')
    b1 = v(get(fam, 'zks', 'update_per_epoch'), 'prove_s')
    bam = v(get(fam, 'zks', 'update_per_epoch_amortized'), 'prove_s')
    if sp is None:
        ex = [r for r in rd(f'six_zka_{fam}_exec.csv') if (r.get('step') or r.get('mode')) == 'aggr' and r['epoch_index'] == '0']
        uc = int(ex[0]['user_cycles']) if ex else None
        print(f"| {NAME[fam]} | {uc:,} | not profiled | not profiled | - | their shipped guest has no profiling twin | "
              f"- | - | - |")
        continue
    uc, rdc, ch, src = sp
    share = (rdc + ch) / uc
    mod = a1 * (1 - share) if a1 else None
    print(f'| {NAME[fam]} | {uc:,} | {rdc:,} | {ch:,} | {100 * share:.1f}% | {src} | {fs(mod)} | {ratio(mod, b1)} | '
          f'{ratio(mod, bam)} |')
