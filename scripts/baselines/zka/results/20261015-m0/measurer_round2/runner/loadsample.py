#!/usr/bin/env python3
"""loadsample.py <out.csv> <stopfile> [interval_s]: every interval, busy cores used by this uid vs other uids
(from /proc/<pid>/stat utime+stime deltas) plus the 1-min load average. Stops when <stopfile> exists."""
import os, sys, time
out, stop = sys.argv[1], sys.argv[2]
dt = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
me = os.getuid(); hz = os.sysconf("SC_CLK_TCK")
def snap():
    d = {}
    for p in os.listdir("/proc"):
        if not p.isdigit(): continue
        try:
            st = os.stat(f"/proc/{p}")
            with open(f"/proc/{p}/stat") as f: s = f.read()
            fl = s[s.rfind(")") + 2:].split()
            d[int(p)] = (st.st_uid, int(fl[11]) + int(fl[12]))
        except Exception: pass
    return d
prev, tp = snap(), time.time()
with open(out, "w") as f:
    f.write("unix_s,iso,load1,busy_cores_me,busy_cores_others\n")
    while not os.path.exists(stop):
        time.sleep(dt)
        cur, tc = snap(), time.time()
        mine = oth = 0
        for pid, (uid, j) in cur.items():
            j0 = prev.get(pid, (uid, j if pid not in prev else 0))[1] if pid in prev else 0
            dj = j - j0 if pid in prev else 0  # new processes: count from next interval
            if uid == me: mine += dj
            else: oth += dj
        el = (tc - tp) * hz
        l1 = open("/proc/loadavg").read().split()[0]
        f.write(f"{tc:.1f},{time.strftime('%H:%M:%S')},{l1},{mine/el:.2f},{oth/el:.2f}\n"); f.flush()
        prev, tp = cur, tc
