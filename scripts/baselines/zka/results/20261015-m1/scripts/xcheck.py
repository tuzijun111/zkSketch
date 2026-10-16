"""Cross-check: zkSketch exp_compose GK query answers (QLOG lines of committed / memmatch runs)
vs the matched zk-Analytics query guest's answers (driver CSV rows). Usage:
xcheck.py <repo_results_dir> <query8.csv> <check_AB.csv> <check_D.csv>"""
import csv, re, sys, os
R, q8, cAB, cD = sys.argv[1:5]
def qlog(path):
    t = open(path).read()
    keys = dict(re.findall(r'QLOG_KEY,at_leaf=(\d+),gk_value=(\d+)', t))
    ans = dict(re.findall(r'QLOG_QUERY,at_leaf=(\d+),prove_ms=[^,]*,witness_ms=[^,]*,verify_ms=[^,]*,proof_bytes=[^,]*,answer=(\d+)', t))
    return {int(k): (int(keys[k]), int(v)) for k, v in ans.items()}
def est(row):
    m = re.search(r'rank\((\d+)\) est=(\d+)', row['result'])
    return int(m.group(1)), int(m.group(2))
ok = True
print('# zkSketch exp_compose GK answers vs the matched zk-Analytics query guest (rank(v) after n x 2,048 AOL records)')
print('source,config(capacity/leaf m),n,leaf,v,zkSketch_exp_compose_answer,zka_matched_answer,equal')
rows = {}
for p in (cAB, cD):
    for r in csv.DictReader(open(p)):
        if r['implementation'] == 'fast':
            rows[(r['capacity'], r['m_sub'], int(r['epoch_index']) + 1)] = est(r)
for r in csv.DictReader(open(q8)):
    rows[(r['capacity'], r['m_sub'], int(r['epochs']))] = est(r)
runs = [('memmatch-20261014/runs/gk-m128-cap384-t16/six_zksketch_gk.log', '384', '128', 16, ('384', '128')),
        ('memmatch-20261014/runs/gk-m512-cap128-t4/six_zksketch_gk.log', '128', '512', 4, ('128', '512')),
        ('memmatch-20261014/runs/gk-m512-cap64-t4/six_zksketch_gk.log', '64', '512', 4, ('64', '512')),
        ('memmatch-20261014/runs/gk-m2048-cap2048-t1/six_zksketch_gk.log', '2048', '2048', 1, ('2048', '2048')),
        ('six_zksketch_r2_gk.log', '2048', '2048', 1, ('2048', '2048')),
        ('six_zksketch_gk.log', '2048', '2048', 1, ('2048', '2048'))]
for path, cap, m, per, key in runs:
    q = qlog(os.path.join(R, path))
    for leaf in sorted(q):
        if leaf % per:
            continue
        n = leaf // per
        if key + (n,) not in rows:
            continue
        v, a = q[leaf]
        zv, za = rows[key + (n,)]
        eq = (v, a) == (zv, za)
        ok &= eq
        print(f'{path},{cap}/{m} (zka {key[0]}/{key[1]}),{n},{leaf},{v},{a},{za},{str(eq).lower()}')
print('# all equal:', ok)
sys.exit(0 if ok else 1)
