#!/usr/bin/env python3
"""loadwin.py <load.csv> <run_dir>...: per run window (meta.txt start..end), mean/max 1-min load and the busy
cores used by other users (others) and by this uid (me), from loadsample.py."""
import csv, datetime, os, re, sys, statistics as st
rows = [r for r in csv.DictReader(open(sys.argv[1]))]
def ts(s): return datetime.datetime.fromisoformat(s).timestamp()
print("| run | window | load1 mean / max | busy cores, others: mean / max | busy cores, ours: mean |")
print("|---|---|---|---|---|")
for d in sys.argv[2:]:
    m = open(os.path.join(d, "meta.txt")).read()
    a = ts(re.search(r"start=(\S+)", m).group(1)); b = ts(re.search(r"end=(\S+)", m).group(1))
    sel = [r for r in rows if a <= float(r["unix_s"]) <= b]
    l = [float(r["load1"]) for r in sel]; o = [float(r["busy_cores_others"]) for r in sel]; me = [float(r["busy_cores_me"]) for r in sel]
    print(f"| {os.path.basename(d)} | {datetime.datetime.fromtimestamp(a).strftime('%H:%M:%S')}-{datetime.datetime.fromtimestamp(b).strftime('%H:%M:%S')} | {st.mean(l):.1f} / {max(l):.1f} | {st.mean(o):.2f} / {max(o):.2f} | {st.mean(me):.1f} |")
