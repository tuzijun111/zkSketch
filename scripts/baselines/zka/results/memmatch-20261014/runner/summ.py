import csv, glob, os, re, sys
root = '/home/binbin/zkSketch/results/six/memmatch-20261014'
dirs = sys.argv[1:] or sorted(glob.glob(root + '/*'))
for d in dirs:
    d = d if d.startswith('/') else os.path.join(root, d)
    for f in sorted(glob.glob(d + '/six_zksketch_*.csv')):
        if f.endswith('_runs.csv'): continue
        for r in csv.DictReader(open(f)):
            t = int(r['t']); tot = float(r['total_time_ms']); seq = float(r['leafgen_seq_ms'])
            ml = int(r['merges_local']) + int(r['merges_cross'])
            log = f[:-4] + '.log'
            rss = vk = ''
            for line in open(log):
                if line.startswith('RSSTREE'): rss = line.strip()
                m = re.search(r'VK derived from public parameters in ([0-9.]+)s', line)
                if m: vk = m.group(1)
            mm = re.search(r'main_peak_rss_mb=([0-9.]+).*desc_peak_rss_mb=([0-9.]+).*wall_s=([0-9.]+)', rss)
            print(f"{os.path.basename(d):22s} {r['family']:5s} {r['shape']:14s} m={r['m']:>5s} t={t} status={r['status']} "
                  f"leaf_s={seq/t/1000:.2f} merge(tot-seq)/(t-1)={(tot-seq)/max(t-1,1)/1000:.2f} fold/merge={float(r['local_fold_ms'])/max(ml,1)/1000:.2f} merges={ml} "
                  f"total={tot/1000:.2f} worker={mm.group(2) if mm else '?'} coord={mm.group(1) if mm else '?'} wall={mm.group(3) if mm else '?'} vk_s={vk} q_avg_s={float(r['query_prove_ms_avg'])/1000:.2f}")
