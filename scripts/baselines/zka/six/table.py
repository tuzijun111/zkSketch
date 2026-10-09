#!/usr/bin/env python3
"""Print the README's markdown tables from six_sketch_comparison.csv (python3 -I table.py <csv>)."""
import csv
import sys

rows = list(csv.DictReader(open(sys.argv[1])))
FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']
NAME = {'cm': 'Count-Min 3x1024', 'hll': 'HLL b=14 †', 'ss': 'SS / MG s=1,024 †', 'gk': 'GK eps=1/51 †',
        'bloom': 'Bloom 7x2^14 †', 'kmv': 'KMV k=1,024 †'}
NAME_ZKS = dict(NAME, hll='HLL b=14', ss='SS / MG s=1,024', gk='GK eps=1/51', bloom='Bloom 7x2^14', kmv='KMV k=1,024')


def get(fam, system_is_zks, op):
    for r in rows:
        if r['family'] == fam and (r['system'] == 'zkSketch') == system_is_zks and r['operation'] == op:
            return r
    return None


def f(v, d=1):
    return '-' if v in (None, '') else f'{float(v):,.{d}f}'


def kb(v):
    return '-' if v in (None, '') else f'{float(v) / 1000:,.0f} KB'


def gb(v):
    return '-' if v in (None, '') else f'{float(v) / 1024:,.1f} GB'


def ratio(a, b):
    try:
        return f'{float(a) / float(b):,.0f}x' if float(a) / float(b) >= 10 else f'{float(a) / float(b):,.1f}x'
    except (TypeError, ValueError, ZeroDivisionError):
        return '-'


print('**Update side** (one epoch = one batch of 2,048 records)\n')
print('| sketch | zk-Analytics prove / epoch (s) | zkSketch prove / leaf (s) | ratio | zk-Analytics 8 epochs (s) | '
      'zkSketch 8 batches incl. merges (s) | ratio | zk-Analytics receipt / epoch | zkSketch root proof | '
      'peak RSS zk-Analytics (r0vm) | peak RSS zkSketch (worker) |')
print('|---|---|---|---|---|---|---|---|---|---|---|')
for fam in FAMS:
    a, b = get(fam, False, 'update_per_epoch'), get(fam, True, 'update_per_epoch')
    a8, b8 = get(fam, False, 'update_stream_8_epochs'), get(fam, True, 'update_stream_8_epochs')
    e0, e7 = get(fam, False, 'update_epoch0'), get(fam, False, 'update_epoch7')
    if not (a and b):
        continue
    e0s, e7s = (f(e0['prove_s']) if e0 else '-'), (f(e7['prove_s']) if e7 else '-')
    print(f"| {NAME[fam]} | {f(a['prove_s'])} (e0 {e0s}, e7 {e7s}) | {f(b['prove_s'], 2)} | "
          f"{ratio(a['prove_s'], b['prove_s'])} | {f(a8['prove_s'], 0)} | {f(b8['prove_s'], 1)} | "
          f"{ratio(a8['prove_s'], b8['prove_s'])} | {kb(a['proof_bytes'])} x 8 kept | {kb(b8['proof_bytes'])} (one root) | "
          f"{gb(a['peak_rss_mb'])} | {gb(b8['peak_rss_mb'])} |")

for title, op, col, fmt in [('**Query proving time** (s; the query proof alone)', 'query', 'prove_s',
                             lambda v: f(v, 3) if v not in (None, '') and float(v) < 1 else f(v, 2)),
                            ('**Verifier work to accept one answer at n** (ms; zk-Analytics: n aggregation receipts + '
                             '1 query receipt; zkSketch: the live forest peak(s) + 1 query proof)', 'accept', 'verify_ms',
                             lambda v: f(v, 1)),
                            ('**Bytes the verifier receives for one answer at n** (zk-Analytics: n + 1 receipts; '
                             'zkSketch: peak proof(s) + query proof)', 'accept', 'proof_bytes', kb)]:
    print(f'\n{title}\n')
    print('| sketch | n=1 zkA | n=1 zkS | n=2 zkA | n=2 zkS | n=4 zkA | n=4 zkS | n=8 zkA | n=8 zkS | ratio at n=8 |')
    print('|---|---|---|---|---|---|---|---|---|---|')
    for fam in FAMS:
        suffixes = ['_inserted', '_absent'] if fam == 'bloom' else ['']
        for suf in suffixes:
            cells = []
            last = None
            for n in (1, 2, 4, 8):
                a, b = get(fam, False, f'{op}_n{n}{suf}'), get(fam, True, f'{op}_n{n}{suf}')
                cells += [fmt(a[col]) if a else '-', fmt(b[col]) if b else '-']
                last = (a[col] if a else None, b[col] if b else None)
            label = NAME[fam] + (f' ({suf[1:]} key)' if suf else '')
            print(f"| {label} | {' | '.join(cells)} | {ratio(*last)} |")

print('\n**Peak RSS while proving one query** (zk-Analytics: r0vm of that proof; zkSketch: the coordinator over the '
      'whole run, see caveats)\n')
print('| sketch | n=1 zkA | n=2 zkA | n=4 zkA | n=8 zkA | zkSketch coordinator |')
print('|---|---|---|---|---|---|')
for fam in FAMS:
    suf = '_inserted' if fam == 'bloom' else ''
    cells = [gb(get(fam, False, f'query_n{n}{suf}')['peak_rss_mb']) if get(fam, False, f'query_n{n}{suf}') else '-'
             for n in (1, 2, 4, 8)]
    z = get(fam, True, f'query_n1{suf}')
    print(f"| {NAME[fam]} | {' | '.join(cells)} | {gb(z['peak_rss_mb']) if z else '-'} |")

print('\n**Answers vs exact** (same 16,384 AOL records; exact computed natively)\n')
print('| sketch | n | zk-Analytics answer | zkSketch answer | exact |')
print('|---|---|---|---|---|')
for fam in FAMS:
    suffixes = ['_inserted', '_absent'] if fam == 'bloom' else ['']
    for suf in suffixes:
        for n in (1, 2, 4, 8):
            a, b = get(fam, False, f'query_n{n}{suf}'), get(fam, True, f'query_n{n}{suf}')
            ex = (a or b or {}).get('exact', '-')
            if fam == 'ss' and b:
                ex = b['exact']
            label = NAME[fam] + (f' ({suf[1:]} key)' if suf else '')
            print(f"| {label} | {n} | {a['answer'] if a else '-'} | {b['answer'] if b else '-'} | {ex} |")
