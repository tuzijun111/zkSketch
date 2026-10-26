#!/usr/bin/env python3
"""Model the query-rate experiment of the six-sketch comparison (run with python3 -I).

Usage: queryrate_model.py <results dir> [--out-csv F] [--out-md F]

Input: a directory written by queryrate.sh --
  manifest.txt                       N=, Q=, cores=, Eq=, Tq=, ... (key=value tokens)
  qr_zks_<group>_q<Q>.csv            zkSketch exp_compose rows (one per family) of the run at Q
                                     (Q = 0: the query-free baseline); group a = cm,hll,bloom,
                                     b = ss,kmv, c = gk
  zka_epoch_E<Q>/six_zka_<fam>_exec.csv   zk-Analytics executor row of epoch 0 at E = Q records
  zka_epoch_E<Q>/six_zka_<fam>_prove.csv  its real aggregation proof, when proved
  zka_query_E<Eq>_T<Tq>/six_zka_<fam>_qexec.csv  query executor rows at n = 1, 2, 4, ... epochs
  zka_query_E<Eq>_T<Tq>/six_zka_<fam>_prove.csv  real query proofs at the calibration points n
Output: queryrate.csv (one row per family x Q, every quantity plus a provenance string) and
queryrate_table.md (per Q a table, families as rows, under a header that states the model).

The model of the zk-Analytics side (it answers a query only at an epoch end, by a query
proof that merges the n epoch summaries published so far):
  k      = sum(prove_s) / sum(padded_cycles / 2^20) over ALL real zk-Analytics proofs of the
           run (epoch and query proofs): seconds per 2^20 padded cycles
  A(Q)   = the real aggregation proof's prove_s at E = Q when proved, else
           padded_cycles(epoch 0 at E = Q) / 2^20 x k ('estimated')
  q(n)   = a + b n, least squares over the measured n of the query executor rows, each
           valued padded_cycles / 2^20 x k (the real proofs at the calibration points are
           reported next to them with their relative error); b >= 0. It is measured at
           Eq-record epochs (the directory name) and used for every Q: the KMV summary (and
           the older SpaceSaving port's) holds min(distinct keys, capacity) entries, the
           Misra-Gries port's at most that many, fewer after its decrement steps, so q(n)
           depends on the epoch size (disclosed in the header and per Q)
  T      = floor(N / Q) queries = epochs, U = N - T updates
  total  = T x A(Q) + a T + b T (T + 1) / 2 seconds ('extrapolated' when T exceeds the
           largest measured n); amortized = total / U x 1000 ms per update
zkSketch: measured. Its total = total_time_ms (the update makespan, incl. the leaves
sealed early and padded at the queries) + query_prove_ms (the sum over the queries);
amortized = total / (n - n_queries) x 1000 ms per update record.
Standard library only.
"""
import argparse
import csv
import glob
import os
import re
import sys

FAMS = ['cm', 'hll', 'ss', 'gk', 'bloom', 'kmv']
GROUP = {'cm': 'a', 'hll': 'a', 'bloom': 'a', 'ss': 'b', 'kmv': 'b', 'gk': 'c'}
LABEL = {'cm': 'Count-Min', 'hll': 'HLL', 'ss': 'MG', 'gk': 'GK', 'bloom': 'Bloom', 'kmv': 'KMV'}
SEG = float(1 << 20)
# AOL: the distinct keys of a stream prefix exceed the KMV (and SpaceSaving) capacity 1,024 from
# about 2,048 records on (1,234 distinct in the first 2,048 keys, 607 in the first 1,000, 2,372 in
# 4,096). A Misra-Gries summary does not saturate this way: each decrement step releases every
# count-1 counter, so its size varies with the epoch (e.g. 356-492 entries at 2,048 records).
AOL_SAT_E = 2048


def warn(msg):
    print('queryrate_model.py: ' + msg, file=sys.stderr)


def fnum(s):
    """float of a CSV cell, None for '', '-', 'NaN' and the like."""
    try:
        v = float(s)
    except (TypeError, ValueError):
        return None
    return None if v != v else v


def rows(path):
    if not os.path.isfile(path):
        return []
    with open(path, newline='') as f:
        return [r for r in csv.DictReader(f) if r]


def step_of(r):  # the drivers write 'mode' (cm, hll, ss, gk) or 'step' (bloom, kmv)
    return r.get('step') or r.get('mode') or ''


def read_manifest(d):
    out = {}
    p = os.path.join(d, 'manifest.txt')
    if not os.path.isfile(p):
        return out
    for line in open(p):
        if line.startswith('step ') or line.startswith('#'):
            continue
        for m in re.finditer(r'(\w+)=("[^"]*"|\S+)', line):
            out.setdefault(m.group(1), m.group(2).strip('"'))
    return out


def fmt(x, nd=1, dash='-'):
    if x is None:
        return dash
    if isinstance(x, str):
        return x
    if nd == 0:
        return f'{x:,.0f}'
    return f'{x:,.{nd}f}'


def hm(s):  # seconds -> "1 h 02 min" / "12.3 min" / "45 s"
    if s is None:
        return '-'
    if s >= 3600:
        return f'{int(s // 3600)} h {int(s % 3600 // 60):02d} min'
    if s >= 60:
        return f'{s / 60:.1f} min'
    return f'{s:.0f} s'


def lsq(points):
    """least squares a + b n over (n, y); b clamped at 0. Returns (a, b, note)."""
    if not points:
        return None, None, 'no measured n'
    if len(points) == 1:
        return points[0][1], 0.0, 'one measured n: b = 0'
    nx = len(points)
    mx = sum(p[0] for p in points) / nx
    my = sum(p[1] for p in points) / nx
    sxx = sum((p[0] - mx) ** 2 for p in points)
    sxy = sum((p[0] - mx) * (p[1] - my) for p in points)
    b = sxy / sxx if sxx > 0 else 0.0
    note = ''
    if b < 0:
        b, note = 0.0, 'fitted b < 0, clamped to 0'
    a = my - b * mx
    return a, b, note


def load_zks(d):
    """{(fam, Q): row} of the zkSketch runs; Q from the file names."""
    out = {}
    for p in sorted(glob.glob(os.path.join(d, 'qr_zks_*_q*.csv'))):
        m = re.search(r'qr_zks_([a-z]+)_q(\d+)\.csv$', p)
        if not m:
            continue
        q = int(m.group(2))
        for r in rows(p):
            fam = r.get('family', '')
            if fam in FAMS:
                r['_file'] = os.path.basename(p)
                if (fam, q) in out:
                    warn(f'{p}: a second row for {fam} (keeping the first)')
                    continue
                out[(fam, q)] = r
    return out


def calibrate(d):
    """k = sum(prove_s) / sum(padded_cycles / 2^20) over every real proof of the run."""
    s_sum = c_sum = 0.0
    jobs = []
    for p in sorted(glob.glob(os.path.join(d, 'zka_*', 'six_zka_*_prove.csv'))):
        for r in rows(p):
            s, c = fnum(r.get('prove_s')), fnum(r.get('padded_cycles'))
            if s is None or c is None or s <= 0 or c <= 0:
                continue
            s_sum += s
            c_sum += c / SEG
            st = step_of(r)
            jobs.append(f"{os.path.basename(os.path.dirname(p))}:{r.get('family', '?')}:{st}:"
                        f"{r.get('epoch_index') if st == 'aggr' else 'n=' + str(r.get('epochs'))}")
    if c_sum <= 0:
        return None, 0, []
    return s_sum / c_sum, len(jobs), jobs


def epoch_cost(d, fam, q, k):
    """A(Q) of one family: (seconds, cycles, source) with source measured | estimated | None."""
    sub = os.path.join(d, f'zka_epoch_E{q}')
    aggr = [r for r in rows(os.path.join(sub, f'six_zka_{fam}_prove.csv'))
            if step_of(r) == 'aggr' and r.get('epoch_index') == '0' and fnum(r.get('prove_s'))]
    aggr = [r for r in aggr if r.get('root_variant', 'noroot') in ('noroot', '', '-')]
    if aggr:
        r = aggr[0]
        return fnum(r['prove_s']), fnum(r.get('padded_cycles')), 'measured'
    ex = [r for r in rows(os.path.join(sub, f'six_zka_{fam}_exec.csv'))
          if step_of(r) == 'aggr' and r.get('epoch_index') == '0'
          and r.get('root_variant', 'noroot') in ('noroot', '', '-')]
    if ex:
        c = fnum(ex[0].get('padded_cycles'))
        if c is not None and k is not None:
            return c / SEG * k, c, 'estimated'
        return None, c, None
    return None, None, None


def pick_bloom(rs):
    """one qexec / prove row per n for Bloom: the inserted-key probe, when both were run."""
    first = [r for r in rs if r.get('probe_mode') == 'first']
    if first:
        return first
    ins = [r for r in rs if 'in_stream=true' in (r.get('exact') or '') or 'member=true' in (r.get('answer') or '')]
    return ins or rs


def query_cost(d, fam, k):
    """q(n) of one family: {'n': {n: (cycles, est_s, real_s)}, 'a', 'b', 'note', 'dir'}."""
    dirs = sorted(glob.glob(os.path.join(d, 'zka_query_E*_T*')))
    out = {'n': {}, 'a': None, 'b': None, 'note': 'no zka_query_E*_T* directory', 'dir': None, 'arm': None}
    if not dirs:
        return out
    sub = dirs[0]
    out['dir'] = os.path.basename(sub)
    if len(dirs) > 1:
        warn(f'several query-cost directories, using {sub}')
    qx = [r for r in rows(os.path.join(sub, f'six_zka_{fam}_qexec.csv')) if step_of(r) == 'query']
    pr = [r for r in rows(os.path.join(sub, f'six_zka_{fam}_prove.csv')) if step_of(r) == 'query']
    if fam == 'bloom':
        qx, pr = pick_bloom(qx), pick_bloom(pr)
    # family ss: 'mg' = the Misra-Gries port (../mg), 'ss' = the older SpaceSaving port
    out['arm'] = next((r.get('arm') for r in qx + pr if r.get('arm')), None)
    real = {}
    for r in pr:
        n, s = fnum(r.get('epochs')), fnum(r.get('prove_s'))
        if n and s and int(n) not in real:
            real[int(n)] = (s, fnum(r.get('padded_cycles')))
    for r in qx:
        n, c = fnum(r.get('epochs')), fnum(r.get('padded_cycles'))
        if not n or c is None or int(n) in out['n']:
            continue
        est = c / SEG * k if k is not None else None
        out['n'][int(n)] = (c, est, real.get(int(n), (None, None))[0])
    for n, (s, c) in real.items():   # a proof at an n without an executor row
        if n not in out['n'] and c is not None:
            out['n'][n] = (c, c / SEG * k if k is not None else None, s)
    pts = [(n, v[1]) for n, v in sorted(out['n'].items()) if v[1] is not None]
    out['a'], out['b'], out['note'] = lsq(pts)
    if not out['n']:
        out['note'] = f'no query executor rows in {out["dir"]}'
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('results')
    ap.add_argument('--out-csv')
    ap.add_argument('--out-md')
    a = ap.parse_args()
    d = os.path.abspath(a.results)
    if not os.path.isdir(d):
        sys.exit(f'{d}: no such directory')
    out_csv = a.out_csv or os.path.join(d, 'queryrate.csv')
    out_md = a.out_md or os.path.join(d, 'queryrate_table.md')
    man = read_manifest(d)
    zks = load_zks(d)
    k, nk, kjobs = calibrate(d)
    if k is None:
        warn('no real zk-Analytics proof in the run: every zk-Analytics quantity is unavailable')
    else:
        print(f'calibration: k = {k:.3f} s per 2^20 padded cycles from {nk} proof(s)')

    # Q values: zkSketch runs and zk-Analytics epoch directories; 0 = the baseline
    qs = {q for (_, q) in zks}
    for p in glob.glob(os.path.join(d, 'zka_epoch_E*')):
        m = re.search(r'zka_epoch_E(\d+)$', p)
        if m and os.path.isdir(p):
            qs.add(int(m.group(1)))
    qs = sorted(qs)
    if not qs:
        sys.exit(f'{d}: no qr_zks_*_q*.csv and no zka_epoch_E* directory')
    n_total = None
    if man.get('N', '').isdigit():
        n_total = int(man['N'])
    else:
        for r in zks.values():
            if fnum(r.get('n')):
                n_total = int(fnum(r['n']))
                break
    if n_total is None:
        sys.exit('N unknown: no N= in manifest.txt and no zkSketch row')

    qcost = {f: query_cost(d, f, k) for f in FAMS}
    n_max = {f: (max(qcost[f]['n']) if qcost[f]['n'] else None) for f in FAMS}
    # the epoch size the query cost was measured at (from the directory name, else the manifest)
    eq = None
    if qcost['cm']['dir']:
        m = re.search(r'zka_query_E(\d+)_T(\d+)$', qcost['cm']['dir'])
        eq = int(m.group(1)) if m else None
    if eq is None and man.get('Eq', '').isdigit():
        eq = int(man['Eq'])
    # the proof system zkSketch's rows report (the zk build: pcs=hiding, logup_mask=on, commit=hiding)
    pcs = sorted({r.get('pcs') or '?' for r in zks.values()}) or ['?']
    lmask = sorted({r.get('logup_mask') or '?' for r in zks.values()}) or ['?']
    cmode = sorted({r.get('commit') or '?' for r in zks.values()}) or ['?']
    zks_zk = pcs == ['hiding'] and lmask == ['on'] and cmode == ['hiding']
    if zks and not zks_zk:
        warn(f"zkSketch rows are NOT all from the zk build: pcs={pcs} logup_mask={lmask} commit={cmode}")

    cols = ['family', 'q', 'n_total', 'zka_epochs_T', 'updates_U',
            'zka_A_s', 'zka_A_source', 'zka_A_padded_cycles',
            'zka_q_a_s', 'zka_q_b_s', 'zka_q_n_measured', 'zka_q_n_max', 'zka_q_epoch_records', 'zka_query_sum_s',
            'zka_total_s', 'zka_total_flag', 'zka_ms_per_update',
            'zks_group', 'zks_leaf_m', 'zks_t_leaves', 'zks_n_queries', 'zks_update_makespan_s',
            'zks_query_sum_s', 'zks_total_s', 'zks_ratio_vs_q0', 'zks_ms_per_update',
            'zks_split_leaves', 'zks_pad_records', 'zks_pad_fraction', 'zks_variant', 'zks_status',
            'zks_pcs', 'zks_logup_mask', 'zks_commit',
            'ratio_zka_over_zks', 'calib_k_s_per_2e20', 'calib_n_proofs', 'provenance']
    recs = []
    base = {}   # fam -> Q=0 update makespan (s)
    for f in FAMS:
        r = zks.get((f, 0))
        if r and fnum(r.get('total_time_ms')) is not None:
            base[f] = fnum(r['total_time_ms']) / 1000.0
    for q in qs:
        for f in FAMS:
            rec = {c: '' for c in cols}
            rec.update(family=f, q=q, n_total=n_total, zks_group=GROUP[f],
                       calib_k_s_per_2e20=fmt(k, 4) if k is not None else '', calib_n_proofs=nk)
            prov = []
            # zkSketch
            r = zks.get((f, q))
            if r:
                tt, qp = fnum(r.get('total_time_ms')), fnum(r.get('query_prove_ms')) or 0.0
                n, nq = fnum(r.get('n')), fnum(r.get('n_queries')) or 0.0
                t, m = fnum(r.get('t')), fnum(r.get('m'))
                sl, pr = fnum(r.get('query_split_leaves')), fnum(r.get('query_pad_records'))
                rec.update(zks_leaf_m=int(m) if m else '', zks_t_leaves=int(t) if t else '',
                           zks_n_queries=int(nq), zks_variant=r.get('variant', ''),
                           zks_status=r.get('status', ''), zks_pcs=r.get('pcs', ''),
                           zks_logup_mask=r.get('logup_mask', ''), zks_commit=r.get('commit', ''),
                           zks_split_leaves=int(sl) if sl is not None else '',
                           zks_pad_records=int(pr) if pr is not None else '')
                if tt is not None:
                    tot = (tt + qp) / 1000.0
                    rec.update(zks_update_makespan_s=f'{tt / 1000.0:.3f}', zks_query_sum_s=f'{qp / 1000.0:.3f}',
                               zks_total_s=f'{tot:.3f}')
                    if n and n - nq > 0:
                        rec['zks_ms_per_update'] = f'{tot / (n - nq) * 1000.0:.4f}'
                    if f in base and base[f] > 0:
                        rec['zks_ratio_vs_q0'] = f'{tot / base[f]:.3f}'
                    if t and m and pr is not None:
                        rec['zks_pad_fraction'] = f'{pr / (t * m):.4f}'
                    rec['_zks_total'] = tot
                prov.append(f"zkS measured ({r['_file']}, status {r.get('status', '?')})")
            else:
                prov.append('zkS: no run' if q else 'zkS: no baseline run')
            # zk-Analytics
            if q > 0:
                T = n_total // q
                U = n_total - T
                rec.update(zka_epochs_T=T, updates_U=U)
                A, Ac, Asrc = epoch_cost(d, f, q, k)
                rec.update(zka_A_padded_cycles=int(Ac) if Ac else '', zka_A_source=Asrc or 'n/a')
                qc = qcost[f]
                rec['zka_q_epoch_records'] = eq if eq is not None else ''
                if qc['n']:
                    ns = sorted(qc['n'])
                    rec.update(zka_q_n_measured='|'.join(str(x) for x in ns), zka_q_n_max=ns[-1])
                if A is not None:
                    rec['zka_A_s'] = f'{A:.3f}'
                    prov.append(f'zkA A(Q) {Asrc} (zka_epoch_E{q})')
                else:
                    prov.append(f'zkA A(Q) unavailable (zka_epoch_E{q}: {"no executor row" if Ac is None else "no calibration"})')
                if qc['a'] is not None:
                    rec.update(zka_q_a_s=f'{qc["a"]:.3f}', zka_q_b_s=f'{qc["b"]:.4f}')
                    prov.append(f"zkA q(n) fit over n = {rec['zka_q_n_measured'].replace('|', ',')} "
                                f"({qc['dir']}, executor cycles x k){'; ' + qc['note'] if qc['note'] else ''}")
                    if f == 'ss' and eq is not None and eq != q and qc.get('arm') != 'ss':
                        prov.append(f'q(n) measured at {eq:,}-record epochs, not {q:,}: the {LABEL[f]} summary holds at most '
                                    f'min(distinct keys, capacity) entries, fewer after its decrement steps, so its size and '
                                    f'query cost vary with the epoch rather than growing with its length')
                    elif f in ('ss', 'kmv') and eq is not None and eq != q:
                        prov.append(f'q(n) measured at {eq:,}-record epochs, not {q:,}: the {LABEL[f]} summary holds '
                                    f'min(distinct keys, capacity) entries, so its query cost is '
                                    + ('overstated (conservative)' if eq > q else
                                       'the saturated one (AOL: full from about %s records on)' % f'{AOL_SAT_E:,}' if eq >= AOL_SAT_E else
                                       'understated (the Eq summaries were not full)'))
                else:
                    prov.append(f"zkA q(n) unavailable ({qc['note']})")
                if A is not None and qc['a'] is not None:
                    qsum = qc['a'] * T + qc['b'] * T * (T + 1) / 2.0
                    tot = T * A + qsum
                    flag = 'extrapolated' if (n_max[f] is None or T > n_max[f]) else 'within'
                    rec.update(zka_query_sum_s=f'{qsum:.3f}', zka_total_s=f'{tot:.3f}', zka_total_flag=flag,
                               zka_ms_per_update=f'{tot / U * 1000.0:.4f}' if U > 0 else '')
                    rec['_zka_total'] = tot
                    prov.append(f'T = {T} epochs {flag} the measured n'
                                + (f' (max {n_max[f]})' if n_max[f] else ''))
                    if '_zks_total' in rec and rec['_zks_total'] > 0:
                        rec['ratio_zka_over_zks'] = f'{tot / rec["_zks_total"]:.2f}'
            rec['provenance'] = '; '.join(prov)
            recs.append(rec)

    with open(out_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for rec in recs:
            w.writerow(rec)

    # ---------------------------------------------------------------- markdown
    by = {(r['family'], r['q']): r for r in recs}
    L = []
    cores = man.get('cores') or man.get('nproc') or '?'
    qlist = ', '.join(f'{q:,}' for q in qs if q)
    L.append('# Query rate: one query every Q stream positions, zkSketch measured, zk-Analytics modeled')
    L.append('')
    zk_note = ('zero-knowledge on both sides' if zks_zk else
               'zkSketch rows NOT all from the zk build' if zks else 'no zkSketch rows')
    L.append(f"_Run: N = {n_total:,} stream positions (AOL keys), a query every Q positions for Q = {qlist or 'none'} "
             f"plus the query-free baseline Q = 0; zkSketch cores {cores}; {zk_note} "
             f"(zkSketch rows: pcs={','.join(pcs)}, logup_mask={','.join(lmask)}, commit={','.join(cmode)}; "
             f"zk-Analytics RISC Zero succinct receipts); "
             f"zkSketch leaves: CM / HLL / Bloom {man.get('leaf_a', '1024')}, MG / KMV {man.get('leaf_b', '4096')}, "
             f"GK {man.get('leaf_c', '512')} (capacity {man.get('gk_cap', '768')}); zkSketch {man.get('zksketch', '?')[:9]}, "
             f"zk-Analytics {man.get('zka', '?')[:7]}; {man.get('started', '')}._")
    L.append('')
    L.append('**The zk-Analytics side is a MODEL built from measured parts, not a run.** zk-Analytics answers a query only '
             'at an epoch end, by a query proof that merges the n epoch summaries published so far, so a query every Q '
             'positions means epochs of Q records and N / Q query proofs whose cost grows with n. Its total for a Q is')
    L.append('')
    L.append('    total(Q) = T x A(Q) + a T + b T (T + 1) / 2   seconds,   T = floor(N / Q) queries = epochs, U = N - T updates')
    L.append('')
    L.append('with these assumptions: (1) epochs of exactly Q records, every epoch at the cost of epoch 0 at E = Q '
             '(A(Q): the real aggregation proof when it was proved, else its executor padded cycles / 2^20 x k, marked '
             'estimated); the stream tail after the last query is not proved; (2) the query proof cost is linear in the '
             'number n of merged epoch summaries, q(n) = a + b n, fitted by least squares over the measured n of the '
             f"query executor run (Eq = {eq if eq is not None else '?'}-record epochs, n up to {man.get('Tq', '?')}), each valued "
             'padded cycles / 2^20 x k, and EXTRAPOLATED beyond the largest measured n (rows say so); the KMV summaries '
             '(and those of the older SpaceSaving port) hold min(distinct keys, capacity 1,024) entries, so their q(n) depends '
             f"on the epoch size and is the one of Eq = {eq if eq is not None else '?'}-record epochs for every Q (on AOL they are "
             f'saturated from about {AOL_SAT_E:,} records on: an Eq at or above that carries over to every Q >= Eq and overstates '
             'them slightly at Q < Eq; an Eq below it understates them at larger Q); the Misra-Gries summaries hold at most '
             'that many entries, fewer after each decrement step, so their size varies with the epoch and the Eq-epoch q(n) '
             'is used for every Q as measured; CM / HLL / Bloom summaries have a fixed size, the GK band-merge '
             'state is capacity-bounded and stays small); (3) k = s per 2^20 '
             'padded cycles is one rate for every guest, calibrated over all real proofs of this run; (4) both sides on '
             f'the same {cores} cores, ZK on, one proof at a time; (5) the T periods of Q positions hold Q - 1 updates and '
             'one query each, charged as an epoch of Q records: the last update of each period is counted in the next '
             'epoch (one record per epoch more than the stream carries). zkSketch is measured: its total = the update '
             'makespan (the forest over the leaves, incl. the leaves sealed early and padded at each query) + the sum of '
             'its query proofs; its queries are proved on the coordinator after the update makespan.')
    L.append('')
    if k is not None:
        L.append(f'**Calibration.** k = {k:.3f} s per 2^20 padded cycles over {nk} real zk-Analytics proof(s) of this run '
                 f'({", ".join(kjobs)}).')
    else:
        L.append('**Calibration.** No real zk-Analytics proof in this run: no zk-Analytics quantity could be derived.')
    L.append('')
    # A(E)
    L.append('**zk-Analytics epoch proof A(E)** (epoch 0 at E records, noroot; estimated = padded cycles / 2^20 x k)')
    L.append('')
    L.append('| sketch | ' + ' | '.join(f'E = {q:,}' for q in qs if q) + ' |')
    L.append('|---|' + '---|' * len([q for q in qs if q]))
    for f in FAMS:
        cells = []
        for q in qs:
            if not q:
                continue
            r = by[(f, q)]
            cyc = r['zka_A_padded_cycles']   # '' when the proof row carries no padded_cycles
            if r['zka_A_s']:
                cells.append(f"{fmt(float(r['zka_A_s']), 1)} s ({r['zka_A_source']}"
                             + (f'; {int(cyc) / SEG:.1f} x 2^20 cycles)' if cyc != '' else ')'))
            elif cyc != '':
                cells.append(f"- ({int(cyc) / SEG:.1f} x 2^20 cycles, no calibration)")
            else:
                cells.append('-')
        L.append(f'| {LABEL[f]} | ' + ' | '.join(cells) + ' |')
    L.append('')
    # q(n)
    L.append('**zk-Analytics query proof q(n)** (n merged epoch summaries; est = executor padded cycles / 2^20 x k; '
             'real = the proof at the calibration points, with (est - real) / real)')
    L.append('')
    L.append('| sketch | per n: est s [real s, rel. err] | fit q(n) = a + b n (s) | note |')
    L.append('|---|---|---|---|')
    for f in FAMS:
        qc = qcost[f]
        cells = []
        for n, (c, est, real) in sorted(qc['n'].items()):
            s = f'n={n}: {fmt(est, 1)}'
            if real is not None:
                err = f', {(est - real) / real * 100:+.0f}%' if est is not None else ''
                s += f' [{real:.1f}{err}]'
            cells.append(s)
        fit = f"{qc['a']:.2f} + {qc['b']:.3f} n" if qc['a'] is not None else '-'
        L.append(f"| {LABEL[f]} | {'; '.join(cells) or '-'} | {fit} | {qc['note'] or ''} |")
    L.append('')
    # baseline
    if 0 in qs:
        L.append('**Q = 0, the query-free baseline (zkSketch only)**')
        L.append('')
        L.append('| sketch | leaf | leaves | update makespan (s) | ms per update record | status |')
        L.append('|---|---|---|---|---|---|')
        for f in FAMS:
            r = by[(f, 0)]
            L.append(f"| {LABEL[f]} | {r['zks_leaf_m'] or '-'} | {r['zks_t_leaves'] or '-'} | "
                     f"{fmt(fnum(r['zks_update_makespan_s']), 1)} | {fmt(fnum(r['zks_ms_per_update']), 2)} | {r['zks_status'] or 'no run'} |")
        L.append('')
    for q in qs:
        if not q:
            continue
        T = n_total // q
        eq_note = ''
        if eq is not None and eq != q:
            sat = ('conservative for zkA' if eq > q else
                   'saturated summaries, carries over' if eq >= AOL_SAT_E else 'understated for zkA')
            if qcost['ss'].get('arm') == 'ss':   # older SpaceSaving port: saturates like KMV
                eq_note = f'; SpaceSaving / KMV q(n) is the one of {eq:,}-record epochs: {sat}'
            else:
                eq_note = (f'; MG / KMV q(n) is the one of {eq:,}-record epochs (KMV: {sat}; MG: its size varies '
                           f'with the decrement steps)')
        L.append(f'**Q = {q:,}: T = {T:,} queries / epochs, U = {n_total - T:,} updates** '
                 '(zkA = zk-Analytics, modeled; zkS = zkSketch, measured; ratio = zkA / zkS, above 1 zkSketch is faster; '
                 f'zkS pad fraction = padded record slots / proved record slots; x Q=0 = zkS total over the baseline makespan{eq_note})')
        L.append('')
        L.append('| sketch | zkA epochs T | A(Q) (s) | q(n) = a + b n (s) [measured n] | zkA queries (s) | zkA total (h) | '
                 'zkA ms/update | zkS update makespan (s) | zkS queries (s) | zkS total (s) | zkS ms/update | zkS leaves (padded) | '
                 'zkS pad fraction | x Q=0 | zkA / zkS |')
        L.append('|---|' + '---|' * 14)
        for f in FAMS:
            r = by[(f, q)]
            A = f"{fmt(fnum(r['zka_A_s']), 1)}{' est' if r['zka_A_source'] == 'estimated' else ''}" if r['zka_A_s'] else '-'
            fit = (f"{float(r['zka_q_a_s']):.1f} + {float(r['zka_q_b_s']):.2f} n [{r['zka_q_n_measured'].replace('|', ',')}]"
                   if r['zka_q_a_s'] else '-')
            tot = fnum(r['zka_total_s'])
            tot_s = (f"{tot / 3600:.2f}{' extrap.' if r['zka_total_flag'] == 'extrapolated' else ''}" if tot is not None else '-')
            leaves = f"{r['zks_t_leaves']} ({r['zks_split_leaves']})" if r['zks_t_leaves'] != '' else '-'
            ratio = f"{float(r['ratio_zka_over_zks']):,.0f}x" if r['ratio_zka_over_zks'] else '-'
            L.append(f"| {LABEL[f]} | {r['zka_epochs_T']} | {A} | {fit} | {fmt(fnum(r['zka_query_sum_s']), 0)} | {tot_s} | "
                     f"{fmt(fnum(r['zka_ms_per_update']), 1)} | {fmt(fnum(r['zks_update_makespan_s']), 1)} | "
                     f"{fmt(fnum(r['zks_query_sum_s']), 1)} | {fmt(fnum(r['zks_total_s']), 1)} | {fmt(fnum(r['zks_ms_per_update']), 2)} | "
                     f"{leaves} | {fmt(fnum(r['zks_pad_fraction']), 3)} | {fmt(fnum(r['zks_ratio_vs_q0']), 2)} | {ratio} |")
        L.append('')
    L.append(f'_Columns and provenance per row: {os.path.basename(out_csv)}._')
    with open(out_md, 'w') as f:
        f.write('\n'.join(L) + '\n')
    print(f'queryrate_model.py: {len(recs)} rows -> {out_csv}; tables -> {out_md}')


if __name__ == '__main__':
    main()
