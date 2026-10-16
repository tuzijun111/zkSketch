#!/usr/bin/env python3
"""answers.py <run_dir>...: per run, the answers, md5 of the QLOG_KEY lines and of the answers, the number of
QLOG_BIND / QLOG_BINDV lines and the CSV status; then whether all runs of one family agree."""
import glob, hashlib, os, re, sys, csv
fam = {}
for d in sys.argv[1:]:
    log = glob.glob(os.path.join(d, "out", "six_zksketch_*.log"))[0]
    txt = open(log).read()
    keys = "\n".join(re.findall(r"^QLOG_KEY,.*$", txt, re.M))
    ans = re.findall(r"^QLOG_QUERY,at_leaf=(\d+),.*?answer=([^,\s]+)", txt, re.M)
    a = " ".join(f"{i}:{v}" for i, v in ans)
    binds = len(re.findall(r"^QLOG_BIND,", txt, re.M)); bindv = len(re.findall(r"^QLOG_BINDV,", txt, re.M))
    c = [p for p in glob.glob(os.path.join(d, "out", "six_zksketch_*.csv")) if not p.endswith("_runs.csv")][0]
    st = next(csv.DictReader(open(c)))["status"]
    km = hashlib.md5(keys.encode()).hexdigest()[:8]; am = hashlib.md5(a.encode()).hexdigest()[:8]
    f = os.path.basename(d).split("_")[0]
    fam.setdefault(f, set()).add((km, am))
    print(f"{os.path.basename(d):10s} n_ans={len(ans)} keys_md5={km} answers_md5={am} bind={binds} bindv={bindv} status={st} answers=[{' '.join(v for _, v in ans)}]")
for f, s in fam.items():
    print(f"{f}: {'IDENTICAL across runs' if len(s) == 1 else 'DIFFER'} {sorted(s)}")
