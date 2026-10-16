#!/usr/bin/env python3
"""gate.py wait <load.csv> <max_wait_s> | window <load.csv> <start_iso> <end_iso>
wait:   block until the last QUIET_N samples (5 s each) of loadsample.py's CSV all show other users' busy
        cores < QUIET_MAX (defaults 12 samples = 60 s, < 6 cores); print the wait; exit 3 on timeout.
window: mean / max of other users' busy cores and of the 1-min load over [start, end]."""
import csv, datetime, os, sys, time
N = int(os.environ.get("QUIET_N", "12")); MX = float(os.environ.get("QUIET_MAX", "6"))
def rows(p):
    try: return list(csv.DictReader(open(p)))
    except Exception: return []
if sys.argv[1] == "wait":
    p, mw = sys.argv[2], float(sys.argv[3]); t0 = time.time()
    while True:
        r = rows(p)[-N:]
        if len(r) == N and all(float(x["busy_cores_others"]) < MX for x in r) and time.time() - float(r[-1]["unix_s"]) < 15:
            print(f"GATE quiet waited_s={time.time()-t0:.0f} others_last={[round(float(x['busy_cores_others']),1) for x in r]}"); sys.exit(0)
        if time.time() - t0 > mw:
            print(f"GATE timeout waited_s={time.time()-t0:.0f}"); sys.exit(3)
        time.sleep(10)
else:
    p = sys.argv[2]
    ts = lambda s: datetime.datetime.fromisoformat(s).timestamp()
    a, b = ts(sys.argv[3]), ts(sys.argv[4])
    sel = [x for x in rows(p) if a <= float(x["unix_s"]) <= b]
    if not sel: print("WINDOW n=0"); sys.exit(0)
    o = [float(x["busy_cores_others"]) for x in sel]; l = [float(x["load1"]) for x in sel]; m = [float(x["busy_cores_me"]) for x in sel]
    print(f"WINDOW n={len(sel)} others_mean={sum(o)/len(o):.2f} others_max={max(o):.2f} load1_mean={sum(l)/len(l):.1f} load1_max={max(l):.1f} me_mean={sum(m)/len(m):.1f}")
