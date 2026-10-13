#!/usr/bin/env python3
"""Print the README's markdown tables from six_sketch_comparison.csv.

Usage: python3 -I table.py <six_sketch_comparison.csv> [--zka PFX] [--raw DIR]

The epochs T, records per epoch M, the proved epochs and the query points n are read from
the CSV, so any run shape works. The last table also reads the zk-Analytics executor /
profile CSVs <PFX>_<fam>_exec.csv and <PFX>_prof_{ss,gk}.csv (--zka, default six_zka) from
--raw DIR (default: the CSV's directory).

Committed 2026-10-09 set (it has zkSketch rows of run r2): zkA = zk-Analytics side, zkS =
zkSketch default build of that day (run r2; the `zk` feature was then off), zkS-zk = zkSketch
built with `--features zk` (HidingFriPcs) BEFORE the LogUp-mask forks: its revealed LogUp sums
are unmasked, so it is not zero-knowledge either, and the masked build costs more
(src/config.rs, "Cost of the masks").
A new run (`run_all.sh`): zkS = that run's zkSketch build (the line above the tables says
which; the default build is zero-knowledge: pcs=hiding, logup_mask=on). Cells marked `est`
are ESTIMATED zk-Analytics prove times (not proved in that run; see the CSV's provenance).
KB / MB = 10^3 / 10^6 bytes; GB (memory) = 2^30 bytes.

Root variants of the zk-Analytics aggregation proofs (the CSV's `variant` column; a CSV
without it is the legacy variant): with one variant the tables show `zkA`; with several (a
new run: designed and noroot) every update-side and accept table shows one zkA column per
variant (`zkA designed`, `zkA noroot`) next to zkSketch, with a ratio against each. Query
proofs do not depend on the variant. The first table, "Update proofs side by side", puts
proving time, verification time, proof size and peak memory of the update proofs together;
the last one lists each variant's root construction and executor cycles.
The committed 2026-10-09 set is the `legacy` variant (CM their shipped roots, SS samples
pattern with 64 buckets, GK per-tuple root, HLL / Bloom / KMV none). For it the tables of
the previous version are printed unchanged; added are the variant note at the top, the
"Update proofs side by side" table and the root-variant table at the end.
"""
import argparse
import csv
import os
import re
import statistics
import sys

ap = argparse.ArgumentParser()
ap.add_argument('csv')
ap.add_argument('--zka', default='six_zka')
ap.add_argument('--raw')
A = ap.parse_args()
rows = list(csv.DictReader(open(A.csv)))
if rows and 'run' not in rows[0]:
    sys.exit(f'{A.csv}: no "run" column: written by assemble.py as of 6cac471 (like the committed '
             f'scripts/baselines/zka/results/six_sketch_comparison.csv). Re-assemble its directory: '
             f'assemble.py <dir> data/aol.keys --out <file>, then table.py <file> --raw <dir>; or print it '
             f'with that version: git show 6cac471:scripts/baselines/zka/six/table.py')
FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']
NAME = {'cm': 'Count-Min 3x1024', 'hll': 'HLL b=14 † ‡', 'ss': 'SS / MG s=1,024 † §', 'gk': 'GK eps=1/51 †',
        'bloom': 'Bloom 7x2^14 †', 'kmv': 'KMV k=1,024 †'}
LEGACY = any((r['system'], r['run']) == ('zkSketch', 'r2') for r in rows)
if LEGACY:
    ZKS = ('zkSketch', 'r2')
else:
    ZKS = next(((r['system'], r['run']) for r in rows if r['system'] == 'zkSketch'), ('zkSketch', 'main'))
ZK = ('zkSketch (zk feature)', 'zk')
HAS_ZK = LEGACY or any((r['system'], r['run']) == ZK for r in rows)
HAS_VT = LEGACY or any(r['run'] == 'vt' for r in rows)
HAS_R1 = LEGACY or any(r['run'] == 'r1' for r in rows)
HAS_VARCOL = bool(rows) and 'variant' in rows[0]
VORDER = {v: i for i, v in enumerate(['designed', 'noroot', 'legacy', 'buckets1024', 'perkey', 'pertuple'])}
# root construction of the legacy guests (a CSV without the variant columns)
LEGACY_ROOT = {'cm': 'cm_rows+cm+heap', 'hll': 'none', 'ss': 'samples64', 'gk': 'pertuple', 'bloom': 'none',
               'kmv': 'none'}
VNOTE = {'designed': 'with the per-bucket Merkle root zk-Analytics builds in every aggregation proof',
         'noroot': 'the same guests without that root, apples-to-apples with zkSketch (the headline)',
         'legacy': 'the guests of the committed 2026-10-09 run'}


def var_of(r):
    """A row's root variant ('-' = none: query rows and zkSketch rows)."""
    return (r.get('variant') or '-') if HAS_VARCOL else 'legacy'


def zka_row(r):
    return r['system'].startswith('zk-Analytics') and r['run'] == 'main'


def vsort(vs):
    return sorted(vs, key=lambda x: (VORDER.get(x, 99), x))


ZV = vsort({var_of(r) for r in rows if zka_row(r) and r['operation'] == 'update_per_epoch'}) \
    or vsort({var_of(r) for r in rows if zka_row(r) and var_of(r) != '-'}) or ['legacy']
MULTI = len(ZV) > 1


def zl(var):  # column label of a zk-Analytics variant
    return f'zkA {var}' if MULTI else 'zkA'


def rl(var, zks_label):  # label of a ratio column
    return f'{var} / {zks_label}' if MULTI else 'ratio'


def construction(fam, var):
    for r in rows:
        if r['family'] == fam and zka_row(r) and r['operation'] == 'update_per_epoch' and var_of(r) == var:
            return r.get('root_construction') or LEGACY_ROOT[fam]
    return LEGACY_ROOT[fam] if var == 'legacy' else 'not run'


# run shape, from the rows
TS = sorted({int(m.group(1)) for r in rows for m in [re.match(r'update_stream_(\d+)_epochs$', r['operation'])] if m})
T = TS[-1] if TS else 8
MS = sorted({int(m.group(1)) for r in rows if zka_row(r)
             for m in [re.search(r'on epoch \d+ \((\d+) records\)', r['detail'])] if m})
M = MS[-1] if MS else 2048
AE = sorted({int(r['operation'][len('update_epoch'):]) for r in rows
             if zka_row(r) and re.fullmatch(r'update_epoch\d+', r['operation'])})
QNS = sorted({int(r['n']) for r in rows if zka_row(r) and r['operation'].startswith('query_n')}) \
    or [1 << i for i in range(T.bit_length()) if 1 << i <= T]  # no zkA query rows: the run's own query points
NALL = list(range(1, T + 1))
OTHER = [n for n in NALL if n not in QNS]
OP_STREAM = f'update_stream_{T}_epochs'


def and_join(xs):
    xs = [str(x) for x in xs]
    return 'none' if not xs else xs[0] if len(xs) == 1 else ', '.join(xs[:-1]) + ' and ' + xs[-1]


def get(fam, who, op, var=None):
    """The row of (family, side, operation); var = the zk-Analytics root variant of an update /
    accept row (None: any, for the variant-independent query rows and zkSketch)."""
    for r in rows:
        if r['family'] != fam or r['operation'] != op:
            continue
        if var is not None and var_of(r) != var:
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


def E(r):  # ' est' when the row's value is (partly) an estimate
    return ' est' if r is not None and 'ESTIMATED' in r['provenance'] else ''


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


def table(header):
    print('| ' + ' | '.join(header) + ' |')
    print('|---' * len(header) + '|')


def line(cells):
    print('| ' + ' | '.join(cells) + ' |')


if not LEGACY:
    feats = sorted({m.group(1) for r in rows if (r['system'], r['run']) == ZKS
                    for m in [re.search(r'features=(\S+)', r['detail'])] if m})
    est = sorted({m.group(1) for r in rows for m in [re.search(r'ESTIMATED \((.*?)\)$', r['provenance'])] if m})
    print(f'_Run: {M * T:,} AOL records = {T} epochs x {M:,}; zk-Analytics proved epochs {and_join(AE)} and '
          f'queries at n = {", ".join(map(str, QNS))}; zkSketch features: {", ".join(feats) or "?"}._\n')
    if est:
        print(f'_`est` = ESTIMATED zk-Analytics prove time, NOT proved in this run: {est[0]}. Verify time and bytes '
              f'of an estimated receipt are the mean of the measured ones; ratios built on an estimate are marked '
              f'too._\n')

# ------------------------------------------------------------------ root variants
SHORT = {'cm': 'CM', 'hll': 'HLL', 'ss': 'SS', 'gk': 'GK', 'bloom': 'Bloom', 'kmv': 'KMV'}


def vdesc(var):
    return (f'{VNOTE.get(var, "a sensitivity variant")}; root: '
            + ', '.join(f'{SHORT[fam]} {construction(fam, var)}' for fam in FAMS))


ROOTS_TXT = '; '.join(f'{zl(var)} = {vdesc(var)}' for var in ZV)
if MULTI:
    print('_**zk-Analytics root variants.** Every zk-Analytics summary type builds, inside each epoch\'s aggregation '
          'proof, a Merkle root over its buckets next to the flat SHA-256 state commitment that the epoch chain and '
          'the query guests use; no query guest or verifier reads that root, and zkSketch publishes none. '
          f'{ROOTS_TXT} (root constructions: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + '
          'cm_root + heap_root; samples64 / buckets64 = their samples pattern with 64 buckets; none = no root). '
          'Query proofs read no root: they are the same for every variant._\n')
else:
    print(f'_zk-Analytics aggregation guests (zkA): root variant {ZV[0]}, {vdesc(ZV[0])}._\n')

# zkSketch sets of the side-by-side table: zkS-zk only when the CSV has its rows
SYSZ = [('zks', 'zkS')] + ([('zk', 'zkS-zk')] if any((r['system'], r['run']) == ZK for r in rows) else [])

def root_verify(r):  # zkS root verify: best of EXP_VERIFY_REPEATS calls (QLOG_ROOTV runs), else the single call
    x = v(r, 'verify_ms')
    return x if x is not None else v(r, 'verify_first_ms')


ROOTV_BEST = any(v(get(fam, 'zks', OP_STREAM), 'verify_ms') is not None for fam in FAMS)

# ------------------------------------------------------------------ update proofs, the four metrics
print(f'**Update proofs side by side: proving time, verification time, proof size, peak memory** (one epoch = '
      f'one batch of {M:,} records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the '
      f'mean of proved epochs {and_join(AE)} (sampled), "{T} epochs" = {T} x that (derived); verify = best of 5 '
      f'calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf '
      f'proof alone (leafgen_seq_ms / {T}, EXCLUDING composition; its proof = the leaf-1 proof), "{T} epochs" = the '
      f'whole forest incl. its {T - 1} merge{"" if T == 2 else "s"} (measured), which ends in ONE root proof: '
      f'"verify" is that root, {"best of 5 calls (as zkA)" if ROOTV_BEST else "single call"}, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for '
      f'every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)\n')
METRICS = [  # label, zkA op, zkA col, zkA multiplier, zkS op, zkS col, format
    ('prove, 1 epoch (s)', 'update_per_epoch', 'prove_s', 1, 'update_per_epoch', 'prove_s', fs),
    (f'prove, {T} epochs (s)', OP_STREAM, 'prove_s', 1, OP_STREAM, 'prove_s', fs),
    ('verify, 1 epoch (ms)', 'update_per_epoch', 'verify_ms', 1, OP_STREAM, 'root_verify', f),
    (f'verify, {T} epochs (ms)', 'update_per_epoch', 'verify_ms', T, OP_STREAM, 'root_verify', f),
    ('proof, 1 epoch (KB)', 'update_per_epoch', 'proof_bytes', 1, 'update_per_epoch', 'proof_bytes', kb),
    (f'proof, {T} epochs (KB)', 'update_per_epoch', 'proof_bytes', T, OP_STREAM, 'proof_bytes', kb),
    ('peak RSS (GB)', 'update_per_epoch', 'peak_rss_mb', 1, 'update_per_epoch', 'peak_rss_mb', gb),
]
table(['sketch', 'metric'] + [zl(var) for var in ZV] + [lab for _, lab in SYSZ]
      + [f'{zl(var)} / {lab}' for _, lab in SYSZ for var in ZV])
for fam in FAMS:
    for mlab, aop, acol, amul, sop, scol, fmt in METRICS:
        ra = {var: get(fam, 'zka', aop, var) for var in ZV}
        av = {var: (None if v(ra[var], acol) is None else amul * v(ra[var], acol)) for var in ZV}
        sv = {who: (root_verify(get(fam, who, sop)) if scol == 'root_verify' else v(get(fam, who, sop), scol))
              for who, _ in SYSZ}
        def est(x, r):  # the est mark only on a value that exists; peak RSS is always that of measured proofs
            return E(r) if x is not None and acol != 'peak_rss_mb' else ''
        line([NAME[fam], mlab] + [fmt(av[var]) + est(av[var], ra[var]) for var in ZV] + [fmt(sv[who]) for who, _ in SYSZ]
             + [ratio(av[var], sv[who]) + est(av[var] if sv[who] else None, ra[var]) for who, _ in SYSZ for var in ZV])

zk_txt = ' / zkS-zk worker' if HAS_ZK else ''
print(f'\n**Update side.** One epoch = one batch of {M:,} records. Ratios are zkA / zkS. zkA prove per epoch is the '
      f'mean of proved epochs {and_join(AE)} (sampled); zkA {T} epochs = {T} x that mean (derived). zkS "{T} batches" is '
      f'measured and includes the {T - 1} forest merge{"" if T == 2 else "s"}; "leaf alone" is leafgen_seq_ms / {T} and '
      f'EXCLUDES composition.\n')
hdr = ['sketch'] + [f'{zl(var)} {T} epochs (s)' for var in ZV] + [f'zkS {T} batches incl. merges (s)'] \
    + [rl(var, 'zkS') for var in ZV]
if HAS_ZK:
    hdr += [f'zkS-zk {T} batches (s)'] + [rl(var, 'zkS-zk') for var in ZV]
hdr += [f'{zl(var)} / epoch (s)' for var in ZV] + ['zkS leaf alone (s)'] + [rl(var, 'zkS') for var in ZV]
if HAS_ZK:
    hdr += ['zkS-zk leaf alone (s)'] + [rl(var, 'zkS-zk') for var in ZV]
hdr += ['peak RSS GB: ' + ' / '.join([f'{zl(var)} r0vm' for var in ZV]) + f' / zkS worker{zk_txt}']
table(hdr)
for fam in FAMS:
    ra8 = {var: get(fam, 'zka', OP_STREAM, var) for var in ZV}
    ra1 = {var: get(fam, 'zka', 'update_per_epoch', var) for var in ZV}
    rb8, rz8 = (get(fam, w, OP_STREAM) for w in ('zks', 'zk'))
    rb1, rz1 = (get(fam, w, 'update_per_epoch') for w in ('zks', 'zk'))
    a8 = {var: v(ra8[var], 'prove_s') for var in ZV}
    a1 = {var: v(ra1[var], 'prove_s') for var in ZV}
    b8, z8 = (v(x, 'prove_s') for x in (rb8, rz8))
    b1, z1 = (v(x, 'prove_s') for x in (rb1, rz1))
    rb, rz = (v(x, 'peak_rss_mb') for x in (rb1, rz1))
    c = [NAME[fam]] + [f(a8[var], 0) + E(ra8[var]) for var in ZV] + [fs(b8)] \
        + [ratio(a8[var], b8) + E(ra8[var]) for var in ZV]
    if HAS_ZK:
        c += [fs(z8)] + [ratio(a8[var], z8) + E(ra8[var]) for var in ZV]
    c += [fs(a1[var]) + E(ra1[var]) for var in ZV] + [fs(b1)] + [ratio(a1[var], b1) + E(ra1[var]) for var in ZV]
    if HAS_ZK:
        c += [fs(z1)] + [ratio(a1[var], z1) + E(ra1[var]) for var in ZV]
    c += [' / '.join([gb(v(ra1[var], 'peak_rss_mb')) for var in ZV] + [gb(rb)] + ([gb(rz)] if HAS_ZK else []))]
    line(c)

print('\n**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.\n')
hdr = ['sketch'] + [x for var in ZV for x in (f'{zl(var)} receipt / epoch', f'{zl(var)} {T} receipts')] + ['zkS root'] \
    + (['zkS-zk root'] if HAS_ZK else []) + [f'zkS root verify, {"best of 5" if ROOTV_BEST else "single call"} (ms)'] \
    + (['zkS-zk root verify (ms)'] if HAS_ZK else [])
table(hdr)
for fam in FAMS:
    c = [NAME[fam]]
    for var in ZV:
        ra = get(fam, 'zka', 'update_per_epoch', var)
        ab = v(ra, 'proof_bytes')
        c += [kb(ab) + E(ra), kb(T * ab if ab else None) + E(ra)]
    sb, zb = (v(get(fam, w, OP_STREAM), 'proof_bytes') for w in ('zks', 'zk'))
    sv, zv = (root_verify(get(fam, w, OP_STREAM)) for w in ('zks', 'zk'))
    c += [kb(sb)] + ([kb(zb)] if HAS_ZK else []) + [f(sv)] + ([f(zv)] if HAS_ZK else [])
    line(c)

nl, nh = QNS[0], QNS[-1]
QNOTE = '; the same for every zkA root variant: query guests read no root' if ZV != ['legacy'] else ''
print(f"\n**Query proving time** (s; the query proof alone; cells are zkA / zkS{' / zkS-zk' if HAS_ZK else ''}; "
      f"‡ and § see notes{QNOTE})\n")
table(['sketch'] + [f'n={n}' for n in QNS] + [f'zkA / zkS at n={nl}', f'at n={nh}']
      + ([f'zkA / zkS-zk at n={nl}', f'at n={nh}'] if HAS_ZK else []))
for fam in FAMS:
    for suf in sufs(fam):
        cells = []
        for n in QNS:
            r = get(fam, 'zka', f'query_n{n}{suf}')
            a, b, z = (v(get(fam, w, f'query_n{n}{suf}'), 'prove_s') for w in ('zka', 'zks', 'zk'))
            cells.append(f'{fs(a)}{E(r)} / {fs(b)}' + (f' / {fs(z)}' if HAS_ZK else ''))
        rl, rh = get(fam, 'zka', f'query_n{nl}{suf}'), get(fam, 'zka', f'query_n{nh}{suf}')
        a1, b1, z1 = (v(get(fam, w, f'query_n{nl}{suf}'), 'prove_s') for w in ('zka', 'zks', 'zk'))
        a8, b8, z8 = (v(get(fam, w, f'query_n{nh}{suf}'), 'prove_s') for w in ('zka', 'zks', 'zk'))
        c = [label(fam, suf)] + cells + [ratio(a1, b1) + E(rl), ratio(a8, b8) + E(rh)]
        if HAS_ZK:
            c += [ratio(a1, z1) + E(rl), ratio(a8, z8) + E(rh)]
        line(c)

if OTHER:
    print(f"\n**zkSketch query proving at the other n** (s; zkS{' / zkS-zk' if HAS_ZK else ''}; zkA did not prove "
          f"these n)\n")
    table(['sketch'] + [f'n={n}' for n in OTHER])
    for fam in FAMS:
        for suf in sufs(fam):
            cells = []
            for n in OTHER:
                b, z = (v(get(fam, w, f'query_n{n}{suf}'), 'prove_s') for w in ('zks', 'zk'))
                cells.append(f'{fs(b)}' + (f' / {fs(z)}' if HAS_ZK else ''))
            line([label(fam, suf)] + cells)

PEAKS = {n: bin(n).count('1') for n in NALL}
WHO = [('zks', 'zkSketch default build' if LEGACY else 'zkSketch')]
if HAS_ZK:
    WHO.append(('zk', 'zkSketch `--features zk`'))
for who, title in WHO:
    for col, unit, fmt, what in (('verify_ms', 'ms', lambda x: f(x), 'Verifier work to accept one answer at n'),
                                 ('proof_bytes', 'KB', kb, 'Bytes the verifier receives for one answer at n')):
        extra = ('best of 5 calls per proof on both sides; deserialisation excluded on both sides'
                 if col == 'verify_ms' else 'KB = 10^3 bytes')
        print(f'\n**{what}, zkA vs {title}** ({unit}; {extra}; cells {" / ".join(zl(var) for var in ZV)} / zkS; zkA = '
              f'n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of '
              f'measured parts; **bold** = the smaller side)\n')
        table(['sketch'] + [f'n={n} ({PEAKS[n]} peak{"s" if PEAKS[n] > 1 else ""})' for n in NALL])
        for fam in FAMS:
            for suf in sufs(fam):
                cells = []
                for n in NALL:
                    ra = [get(fam, 'zka', f'accept_n{n}{suf}', var) for var in ZV]
                    xs = [v(r, col) for r in ra] + [v(get(fam, who, f'accept_n{n}{suf}'), col)]
                    if any(x is None for x in xs):
                        cells.append('-')
                        continue
                    lo = max(i for i, x in enumerate(xs) if x == min(xs))  # a tie goes to zkS
                    cells.append(' / '.join((f'**{fmt(x)}**' if i == lo else fmt(x)) + (E(ra[i]) if i < len(ra) else '')
                                            for i, x in enumerate(xs)))
                line([label(fam, suf)] + cells)

if HAS_VT:
    print('\n**Verify protocol, one proof** (ms; in-process, right after proving; first call / median of 5 / best of 5; '
          'decode = deserialisation, not in any verify column)\n')
    table(['sketch', 'zkA query receipt n=1 (re-proof)', 'zkA decode (bincode)', 'zkS query proof n=1',
           'zkS leaf-1 peak (accept n=1)', 'zkS decode (postcard), leaf-1'] + (['zkS-zk query proof n=1'] if HAS_ZK else []))
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
        line([NAME[fam], trip(a), f(v(a, 'decode_ms'), 2) if a else '-', trip(b), leaf,
              f(v(acc, 'decode_ms'), 2) if acc else '-'] + ([trip(z)] if HAS_ZK else []))
    agg = [r for r in rows if r['run'] == 'vt' and r['operation'].startswith('verify_protocol_update')]
    for r in agg:
        print(f"\n(zkA aggregation receipt, {r['family']} {r['operation'][16:]}, re-proof: first {f(v(r, 'verify_first_ms'))} / "
              f"median {f(v(r, 'verify_median_ms'))} / best {f(v(r, 'verify_ms'))} ms; bincode decode {f(v(r, 'decode_ms'), 2)} ms)")

print('\n**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the '
      'coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the '
      f'process already held{QNOTE})\n')
table(['sketch'] + [f'zkA n={n}' for n in QNS] + [f'zkS n=1 / n={T} (max over n=1..{T})']
      + ([f'zkS-zk n=1 / n={T} (max)'] if HAS_ZK else []))
for fam in FAMS:
    suf = '_inserted' if fam == 'bloom' else ''
    a = [gb(v(get(fam, 'zka', f'query_n{n}{suf}'), 'peak_rss_mb')) for n in QNS]

    def zz(who):
        xs = [v(get(fam, who, f'query_n{n}{suf}'), 'peak_rss_mb') for n in NALL]
        xs = [x for x in xs if x is not None]
        if not xs:
            return '-'
        return f"{gb(v(get(fam, who, f'query_n1{suf}'), 'peak_rss_mb'))} / {gb(v(get(fam, who, f'query_n{T}{suf}'), 'peak_rss_mb'))} ({gb(max(xs))})"
    line([NAME[fam]] + a + [zz('zks')] + ([zz('zk')] if HAS_ZK else []))

print(f'\n**Answers vs exact** (same {M * T:,} AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw '
      'estimator, outside HLL error bounds)\n')
table(['sketch', 'n', 'zk-Analytics answer', 'zkSketch answer'] + (['zkSketch-zk answer'] if HAS_ZK else []) + ['exact'])
for fam in FAMS:
    for suf in sufs(fam):
        for n in QNS:
            a, b, z = (get(fam, w, f'query_n{n}{suf}') for w in ('zka', 'zks', 'zk'))
            ex = (b or a or {}).get('exact', '-')
            line([label(fam, suf), str(n), a['answer'] if a else '-', b['answer'] if b else '-']
                 + ([z['answer'] if z else '-'] if HAS_ZK else []) + [ex])

if HAS_R1:
    print('\n**Repeatability, zkSketch default build: run r1 (first run) vs r2 (primary)**\n')
    table(['sketch', f'{T} batches r1 / r2 (s)', 'leaf alone r1 / r2 (s)', f'query prove n=1..{T} summed r1 / r2 (s)'])
    for fam in FAMS:
        s1, s2 = v(get(fam, 'r1', OP_STREAM), 'prove_s'), v(get(fam, 'zks', OP_STREAM), 'prove_s')
        l1, l2 = v(get(fam, 'r1', 'update_per_epoch'), 'prove_s'), v(get(fam, 'zks', 'update_per_epoch'), 'prove_s')
        suf = '_inserted' if fam == 'bloom' else ''
        q1 = sum(v(get(fam, 'r1', f'query_n{n}{suf}'), 'prove_s') or 0 for n in NALL)
        q2 = sum(v(get(fam, 'zks', f'query_n{n}{suf}'), 'prove_s') or 0 for n in NALL)
        line([NAME[fam], f'{fs(s1)} / {fs(s2)}', f'{fs(l1)} / {fs(l2)}', f'{fs(q1)} / {fs(q2)}'])

# ------------------------------------------------------------------ framework share (zk-Analytics side)
RD = A.raw or os.path.dirname(os.path.abspath(A.csv))
ZP = A.zka


def rd(name):
    p = os.path.join(RD, name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else []


def raw_var(r):
    """The root variant of a driver CSV row (no root_variant column: the legacy guests)."""
    x = r.get('root_variant')
    return 'legacy' if x in (None, '', '-') else x


def exec_e0(fam, var):
    """The executor row of aggregation epoch 0 under root variant var, or None."""
    for r in rd(f'{ZP}_{fam}_exec.csv'):
        if (r.get('step') or r.get('mode')) == 'aggr' and r['epoch_index'] == '0' and raw_var(r) == var:
            return r
    return None


def phase_split(fam, var):
    """(user cycles, read, chain, source) of aggregation epoch 0 under root variant var, or None.
    HLL / Bloom / KMV: the profiling marks of that variant's guest. SS / GK: the legacy profiling
    twins (prof_exec.sh); for another variant, their read and chain cycles (the same code in
    every variant) over that variant's executor user cycles."""
    if fam in ('hll', 'bloom', 'kmv'):
        r = exec_e0(fam, var)
        if r is not None and '=' in r.get('prof', ''):
            ph = dict(kv.split('=') for kv in r['prof'].split(';'))
            return int(r['user_cycles']), int(ph['read']), int(ph['chain']), 'measured (profiling marks)'
        return None
    sp = None
    if fam == 'ss':
        for r in rd(f'{ZP}_prof_ss.csv'):
            if r['mode'] == 'aggr' and r['epoch_index'] == '0':
                ph = {k: int(v.split('(')[0]) for k, v in (kv.split('=') for kv in r['phases'].split(';'))}
                sp = int(r['user_cycles']), ph['read'], ph['chain'], 'measured (profiling twin aggr_ss_prof)'
                break
    if fam == 'gk':
        for r in rd(f'{ZP}_prof_gk.csv'):
            if r['mode'] == 'aggr' and r['epoch_index'] == '0':
                ph = dict(kv.split('=') for kv in re.search(r'PHASES (.*?)(,|$)', r['result']).group(1).split())
                sp = int(r['user_cycles']), int(ph['input_read']), int(ph['chain_verify']), \
                    'measured (profiling twin aggr_gk_prof)'
                break
    if sp is None or var == 'legacy':
        return sp
    ex = exec_e0(fam, var)
    if ex is None:
        return None
    return int(ex['user_cycles']), sp[1], sp[2], (f'read + chain: legacy profiling twin aggr_{fam}_prof; user cycles: '
                                                  f'this variant (executor)')


print(f'\n**zk-Analytics aggregation guest, epoch 0 ({M:,} records): their ingest vs the rest** (user cycles; '
      'MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment '
      'rounding; it is NOT a measurement)\n')
table(['sketch', 'user cycles', 'Event read', 'batch-chain check', 'read + chain share', 'source',
       'MODELED non-ingest prove / epoch (s)', 'vs zkS leaf alone', 'vs zkS amortized'])
for fam in FAMS:
    for var in ZV:
        name = NAME[fam] + (f' ({var})' if MULTI else '')
        sp = phase_split(fam, var)
        ra1 = get(fam, 'zka', 'update_per_epoch', var)
        a1 = v(ra1, 'prove_s')
        b1 = v(get(fam, 'zks', 'update_per_epoch'), 'prove_s')
        bam = v(get(fam, 'zks', 'update_per_epoch_amortized'), 'prove_s')
        if sp is None:
            ex = exec_e0(fam, var)
            uc = f"{int(ex['user_cycles']):,}" if ex else '-'
            why = ('the noroot copy of their guest has no profiling twin' if fam == 'cm' and var == 'noroot' else
                   'their shipped guest has no profiling twin' if fam == 'cm' else
                   'no six_zka_prof_* rows in this results directory' if LEGACY else f'no {ZP}_prof_* / exec CSV')
            line([name, uc, 'not profiled', 'not profiled', '-', why, '-', '-', '-'])
            continue
        uc, rdc, ch, src = sp
        share = (rdc + ch) / uc
        mod = a1 * (1 - share) if a1 else None
        line([name, f'{uc:,}', f'{rdc:,}', f'{ch:,}', f'{100 * share:.1f}%', src, fs(mod) + E(ra1),
              ratio(mod, b1) + E(ra1), ratio(mod, bam) + E(ra1)])

# ------------------------------------------------------------------ root variants (executor)
VX = vsort({raw_var(r) for fam in FAMS for r in rd(f'{ZP}_{fam}_exec.csv')
            if (r.get('step') or r.get('mode')) == 'aggr'} | set(ZV))
WORK = 'designed' in VX and 'noroot' in VX
print(f'\n**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 ({M:,} records): '
      'user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state '
      'commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, '
      'samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no '
      'root' + ('; root work = designed - noroot, the cost of the root nothing reads' if WORK else '') + ')\n')
table(['sketch'] + [x for var in VX for x in (f'{var}: root', f'{var}: user cycles (segments)')]
      + (['root work (cycles)', 'share of designed'] if WORK else []))
for fam in FAMS:
    c, uc = [NAME[fam]], {}
    for var in VX:
        ex = exec_e0(fam, var)
        con = (ex.get('root_construction') if ex and ex.get('root_construction') not in (None, '', '-') else
               LEGACY_ROOT[fam] if var == 'legacy' else '-')
        if ex is not None:
            uc[var] = int(ex['user_cycles'])
        c += [con if ex else '-', f"{uc[var]:,} ({ex['segments']})" if ex else '-']
    if WORK:
        d, n0 = uc.get('designed'), uc.get('noroot')
        c += ['-', '-'] if d is None or n0 is None else [f'{d - n0:,}', f'{100 * (d - n0) / d:.1f}%']
    line(c)
