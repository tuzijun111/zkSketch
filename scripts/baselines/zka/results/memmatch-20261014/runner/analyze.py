# Builds memmatch_runs.csv (one row per zkSketch run) and memmatch_estimates.csv (per family at B) from
# /home/binbin/zkSketch/results/six/memmatch-20261014. Budget 8,192 MiB (VmHWM / 1024, from rss_tree.sh).
import csv, glob, os, re, sys
R = '/home/binbin/zkSketch/results/six/memmatch-20261014'
OUT = sys.argv[1]
BUDGET = 8192.0
K1, K2 = 30.073281609195405, 31.77   # s per 2^20 padded cycles (2026-10-09 mean of 12 proofs; 2026-10-13 HLL 8,192)
rows = []
for d in sorted(glob.glob(R + '/*')):
    name = os.path.basename(d)
    if name.startswith('zka-'): continue
    for f in glob.glob(d + '/six_zksketch_*.csv'):
        if f.endswith('_runs.csv'): continue
        log = f[:-4] + '.log'
        L = open(log).read()
        rss = re.search(r'RSSTREE,\S+?,main_peak_rss_mb=([0-9.]+),r0vm_peak_rss_mb=[0-9.]+,desc_peak_rss_mb=([0-9.]+),wall_s=([0-9.]+)', L)
        vk = re.search(r'VK derived from public parameters in ([0-9.]+)s', L)
        prequery = re.findall(r'QLOG_PHASE,after=before_query_phase,coord_hwm_mb=([0-9.]+)', L)
        qmax = [float(x) for x in re.findall(r'QLOG_MEM,at_leaf=\d+,query_hwm_mb=([0-9.]+)', L)]
        for r in csv.DictReader(open(f)):
            st = r['status']; t = int(r['t']); m = int(r['m'])
            worker = float(rss.group(2)); coord = float(rss.group(1))
            ok = st == 'ok'
            row = dict(dir=name, family=r['family'], shape=r['shape'], mode=r['mode'], m_leaf=m, t=t, n=r['n'], status=st,
                       worker_mib=worker, coordinator_mib=coord,
                       coord_before_queries_mib=float(prequery[0]) if prequery else '',
                       coord_max_query_hwm_mib=max(qmax) if qmax else '',
                       within_8gib=((worker <= BUDGET and coord <= BUDGET) if ok else ''), wall_s=float(rss.group(3)),
                       vk_derive_s=float(vk.group(1)) if vk else '')
            if ok:
                tot = float(r['total_time_ms']) / 1e3; seq = float(r['leafgen_seq_ms']) / 1e3
                mg = int(r['merges_local']) + int(r['merges_cross'])
                row.update(total_s=round(tot, 3), leaf_s=round(seq / t, 3),
                           merge_s=round((tot - seq) / (t - 1), 3) if t > 1 else '',
                           fold_per_merge_s=round(float(r['local_fold_ms']) / 1e3 / mg, 3) if mg else '',
                           merges=mg, root_verify_ms=r['verify_ms'], query_prove_s_avg=round(float(r['query_prove_ms_avg']) / 1e3, 3))
            rows.append(row)
cols = ['dir','family','shape','mode','m_leaf','t','n','status','leaf_s','merge_s','fold_per_merge_s','merges','total_s','worker_mib','coordinator_mib',
        'coord_before_queries_mib','coord_max_query_hwm_mib','within_8gib','wall_s','vk_derive_s','root_verify_ms','query_prove_s_avg']
with open(OUT + '/memmatch_runs.csv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=cols, extrasaction='ignore'); w.writeheader()
    for r in rows: w.writerow(r)
by = {r['dir']: r for r in rows}
# zk-Analytics executor (noroot, CM also designed) at B
zka = {}
for M in (16384, 2048):
    for fam in ['cm','hll','ss','gk','bloom','kmv']:
        for r in csv.DictReader(open(f'{R}/zka-m{M}/six_zka_{fam}_exec.csv')):
            if (r.get('step') or r.get('mode')) != 'aggr': continue
            zka[(fam, M, r['root_variant'])] = (int(r['user_cycles']), int(r['segments']), int(r['padded_cycles']))
# per family: B, chosen forest dir (measured at B unless est), T=2 dir for the formula, monolithic dir
plan = [
  # fam, zfam, B, forest dir at B (or None), leaf/merge source for formula, k, mono dir
  ('cm',    'cm',    16384, 'cm-m1024-t16',        'cm-m1024-t16',        16, 'cm-m16384-t1'),
  ('hll',   'hll',   16384, 'hll-m1024-t16',       'hll-m1024',           16, 'hll-m16384-t1'),
  ('ss',    'ss',    16384, 'ss-m4096-t4',         'ss-m4096',             4, 'ss-m16384-t1'),
  ('gk',    'gk',     2048, 'gk-m512-cap64-t4',    'gk-m512-cap64-t4',     4, 'gk-m2048-cap64-t1'),
  ('gk_cap384', 'gk', 2048, 'gk-m128-cap384-t16',  'gk-m128-cap384-t16',  16, 'gk-m2048-cap2048-t1'),
  ('bloom', 'bloom', 16384, None,                  'bloom-m256-t16',      64, 'bloom-m16384-t1'),
  ('kmv',   'kmv',   16384, 'kmv-m4096-t4',        'kmv-m4096',            4, 'kmv-m16384-t1'),
]
est = []
for fam, zf, B, fdir, sdir, k, mdir in plan:
    u, seg, pc = zka[(zf, B, 'noroot')]
    z1, z2 = pc / 2**20 * K1, pc / 2**20 * K2
    s = by[sdir]
    formula = k * s['leaf_s'] + (k - 1) * s['merge_s']
    if fdir:
        f = by[fdir]; zks = f['total_s']; zsrc = f'measured ({fdir}: {f["t"]} leaves + {f["merges"]} merges)'
        wmem, cmem = f['worker_mib'], f['coordinator_mib']
    else:
        zks = formula; zsrc = f'ESTIMATED k*leaf_s + (k-1)*merge_s from {sdir}'
        wmem, cmem = 'est ~9600', by[sdir]['coordinator_mib']
    mo = by[mdir]
    e = dict(family=fam, B=B, m_leaf=s['m_leaf'], k=k, zks_forest_s=round(zks, 2), zks_forest_src=zsrc,
             formula_s=round(formula, 2), formula_src=f'{k} x {s["leaf_s"]} + {k-1} x {s["merge_s"]} ({sdir})',
             forest_worker_mib=wmem, forest_coordinator_mib=cmem,
             mono_dir=mdir, mono_leaf_s=mo['leaf_s'], mono_total_s=mo['total_s'], mono_worker_mib=mo['worker_mib'], mono_coordinator_mib=mo['coordinator_mib'],
             zka_user_cycles=u, zka_segments=seg, zka_padded_cycles=pc, zka_est_s_k3007=round(z1, 1), zka_est_s_k3177=round(z2, 1),
             speedup_forest_k3007=round(z1 / zks, 1), speedup_forest_k3177=round(z2 / zks, 1),
             speedup_mono_total_k3007=round(z1 / mo['total_s'], 1), speedup_mono_total_k3177=round(z2 / mo['total_s'], 1),
             speedup_mono_leaf_k3007=round(z1 / mo['leaf_s'], 1))
    est.append(e)
u, seg, pc = zka[('cm', 16384, 'designed')]
est.append(dict(family='cm_designed_ref', B=16384, zka_user_cycles=u, zka_segments=seg, zka_padded_cycles=pc,
                zka_est_s_k3007=round(pc/2**20*K1, 1), zka_est_s_k3177=round(pc/2**20*K2, 1),
                zks_forest_s=by['cm-m1024-t16']['total_s'], speedup_forest_k3007=round(pc/2**20*K1/by['cm-m1024-t16']['total_s'], 1),
                speedup_forest_k3177=round(pc/2**20*K2/by['cm-m1024-t16']['total_s'], 1)))
ecols = list(est[0].keys())
with open(OUT + '/memmatch_estimates.csv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=ecols, extrasaction='ignore'); w.writeheader()
    for e in est: w.writerow(e)
for r in rows:
    print(f"{r['dir']:22s} {r['family']:5s} {r['shape']:13s} {r['mode']:6s} m={r['m_leaf']:>5} t={r['t']:>2} {r['status']:5s} leaf={r.get('leaf_s','')!s:>7} merge={r.get('merge_s','')!s:>6} fold={r.get('fold_per_merge_s','')!s:>6} total={r.get('total_s','')!s:>7} W={r['worker_mib']:>8} C={r['coordinator_mib']:>8} preQ={r['coord_before_queries_mib']!s:>8} {'OK' if r['within_8gib'] else 'OVER'}")
print()
for e in est: print(e)
