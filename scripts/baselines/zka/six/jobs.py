#!/usr/bin/env python3
"""Plan the zk-Analytics prove jobs of the six-sketch comparison (run with python3 -I).

Usage:
  jobs.py --keys <aol.keys> --m M --t T [--aggr 0,7] [--qns 1,2,4,8] [--roots noroot] [--cm-ref 1]
          [--logs DIR [--prefix six_zksketch]] [--select SEL,...] [--lines]

A job is `<fam>:aggr:<epoch>:<variant>` or `<fam>:query:<n>[:<arg>]` (the argument syntax
of `run_zka.sh prove`; there an aggregation job without a variant means legacy). The plan
lists, in this order: the aggregation jobs of every family (cm hll ss gk bloom kmv; per
family each epoch of --aggr, per epoch each root variant of --roots), then the queries of
cm, hll, gk, bloom (inserted key), bloom (absent key), kmv and ss at every n in --qns, then
(--cm-ref 1) their shipped CM aggregation as a REFERENCE, `cm:aggr:<e>:designed` at each
epoch of --aggr, unless --roots already has designed or legacy (both are their unchanged
aggr_cm). The reference comes last, so a run stopped early still has the headline.
Query proofs do not depend on the root variant (query guests read no root), so each query
is planned once. Defaults: --aggr 0,T-1, --qns = the powers of two <= T, --roots noroot
(the headline) and --cm-ref 1, i.e. 2 x 6 = 12 aggregation + 28 query + 2 CM reference = 42
jobs at T = 8 (40 with --cm-ref 0; 52 with --roots designed,noroot, the reference then being
the designed CM jobs; 40 with --roots legacy, the plan of the committed 2026-10-09 run).

Two query arguments must equal what zkSketch probed at n, so both sides answer the
same query:
  GK rank value     the most frequent 21-bit value (key & 0x1FFFFF) of the first n*M
                    records, ties to the smaller value (zkSketch EXP_QUERY_KEY_MODE=hot)
  Bloom absent key  splitmix64(n ^ 0xD1B54A32D192ED03) & 0xFFFFFFFF, re-hashed with
                    splitmix64(c) & 0xFFFFFFFF (up to 128 times) while c is in the
                    prefix (zkSketch EXP_QUERY_KEY_MODE=absent)
(src/experiments/stream_compose.rs, select_query_key). With --logs they are READ from
the QLOG_KEY lines of <prefix>_gk.log and <prefix>_bloom_absent.log in DIR (zkSketch's
own record of what it probed) and cross-checked against the derivation above, if
--keys is given (exit 1 on any difference). Without --logs they are derived.
The inserted Bloom key needs no argument: `first` is the first record of batch n on
both sides.

--select keeps only the jobs equal to a selector or starting with '<selector>:', e.g.
`cm:aggr:0:noroot,kmv:aggr:0:noroot,gk:query:1,bloom:query:1:key` (`cm:aggr:0` selects
every planned variant of that epoch, the CM reference included); a selector that matches no
job is reported on stderr, and no match at all is an error. Output: one line, jobs separated by spaces (--lines: one job per line).
"""
import argparse
import collections
import os
import re
import struct
import sys

FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']
ROOTS = ['designed', 'noroot', 'legacy']
PAD = 0xFFFFFFFF
MASK64 = (1 << 64) - 1


def splitmix64(x):
    z = (x + 0x9E3779B97F4A7C15) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return z ^ (z >> 31)


def derive(keys_path, m, ns):
    """{n: (gk value, bloom absent key)} by zkSketch's select_query_key rule."""
    need = max(ns) * m
    raw = open(keys_path, 'rb').read()
    if len(raw) // 4 < need:
        sys.exit(f'{keys_path}: {len(raw) // 4} keys, need {need}')
    keys = struct.unpack('<%dI' % need, raw[:4 * need])
    out = {}
    for n in ns:
        pre = [k for k in keys[:n * m] if k != PAD]
        gk = collections.Counter(k & 0x1FFFFF for k in pre)
        gv = min(gk.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        present = set(pre)
        cand = splitmix64(n ^ 0xD1B54A32D192ED03) & 0xFFFFFFFF
        for _ in range(128):
            if cand not in present:
                break
            cand = splitmix64(cand) & 0xFFFFFFFF
        out[n] = (gv, cand)
    return out


def from_logs(d, prefix, ns):
    """{n: (gk value, bloom absent key)} from the QLOG_KEY lines of zkSketch's logs."""
    def grab(tag, field):
        p = os.path.join(d, f'{prefix}_{tag}.log')
        if not os.path.exists(p):
            sys.exit(f'missing {p} (run the zkSketch side first: run_zks.sh {tag})')
        got = {int(a): int(b) for a, b in
               re.findall(r'^QLOG_KEY,at_leaf=(\d+),' + field + r'=(\d+)$', open(p).read(), re.M)}
        missing = [n for n in ns if n not in got]
        if missing:
            sys.exit(f'{p}: no QLOG_KEY {field} line for n = {missing} (did that run finish?)')
        return got
    gk, ab = grab('gk', 'gk_value'), grab('bloom_absent', 'bloom_key')
    return {n: (gk[n], ab[n]) for n in ns}


def ints(s):
    return [int(x) for x in s.split(',') if x != '']


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--keys')
    ap.add_argument('--m', type=int, default=2048)
    ap.add_argument('--t', type=int, default=8)
    ap.add_argument('--aggr')
    ap.add_argument('--qns')
    ap.add_argument('--roots', default='noroot')
    ap.add_argument('--cm-ref', choices=['0', '1'], default='1')
    ap.add_argument('--logs')
    ap.add_argument('--prefix', default='six_zksketch')
    ap.add_argument('--select', default='')
    ap.add_argument('--lines', action='store_true')
    a = ap.parse_args()
    t = a.t
    aggr = ints(a.aggr) if a.aggr else sorted({0, t - 1})
    qns = ints(a.qns) if a.qns else [1 << i for i in range(t.bit_length()) if (1 << i) <= t]
    roots = [v for v in a.roots.split(',') if v]
    if t < 1 or not qns or any(not 1 <= n <= t for n in qns) or any(not 0 <= e < t for e in aggr):
        sys.exit(f'bad plan: t={t} aggr={aggr} qns={qns}')
    if not roots or any(v not in ROOTS for v in roots) or len(set(roots)) != len(roots):
        sys.exit(f'bad --roots {a.roots}: a comma list of distinct {", ".join(ROOTS)}')
    if a.logs:
        args = from_logs(a.logs, a.prefix, qns)
        if a.keys:
            nat = derive(a.keys, a.m, qns)
            bad = [n for n in qns if nat[n] != args[n]]
            if bad:
                sys.exit('zkSketch logs and the native derivation disagree at n = '
                         + ', '.join(f'{n} (log gk/absent {args[n]}, derived {nat[n]})' for n in bad)
                         + f'; check --m (M={a.m}) and the keys file')
    elif a.keys:
        args = derive(a.keys, a.m, qns)
    else:
        sys.exit('need --logs and/or --keys')
    jobs = [f'{f}:aggr:{e}:{v}' for f in FAMS for e in aggr for v in roots]
    jobs += [f'cm:query:{n}' for n in qns] + [f'hll:query:{n}' for n in qns]
    jobs += [f'gk:query:{n}:{args[n][0]}' for n in qns]
    jobs += [f'bloom:query:{n}:first' for n in qns] + [f'bloom:query:{n}:key:{args[n][1]}' for n in qns]
    jobs += [f'kmv:query:{n}' for n in qns] + [f'ss:query:{n}' for n in qns]
    if a.cm_ref == '1' and 'designed' not in roots and 'legacy' not in roots:
        jobs += [f'cm:aggr:{e}:designed' for e in aggr]   # their shipped CM, the reference
    sel = [s for s in a.select.split(',') if s]
    if sel:
        def hit(j, s):
            return j == s or j.startswith(s + ':')
        for s in sel:
            if not any(hit(j, s) for j in jobs):
                print(f'jobs.py: --select {s} matches no planned job (roots {",".join(roots)}, '
                      f'cm-ref {a.cm_ref})', file=sys.stderr)
        jobs = [j for j in jobs if any(hit(j, s) for s in sel)]
        if not jobs:
            sys.exit(f'--select {a.select}: no job matches')
    print(('\n' if a.lines else ' ').join(jobs))


if __name__ == '__main__':
    main()
