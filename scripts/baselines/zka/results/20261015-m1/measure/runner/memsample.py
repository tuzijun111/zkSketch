#!/usr/bin/env python3
"""Sample VmRSS of a process tree at the same instants; report the peak SUM.

usage: memsample.py <root_pid> <out.csv> [interval_s]
Runs until root_pid exits. CSV rows: t_s,sum_mb,<pid:comm:rss_mb>...
Prints a SUMMARY line: peak sum, its time and per-process components, and
per-process VmHWM (last seen) / max sampled VmRSS.
"""
import os
import sys
import time


def children(pid):
    out = []
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            try:
                with open(f"/proc/{pid}/task/{tid}/children") as f:
                    out.extend(int(x) for x in f.read().split())
            except OSError:
                pass
    except OSError:
        pass
    return out


def tree(root):
    seen, stack = [], [root]
    while stack:
        p = stack.pop()
        seen.append(p)
        stack.extend(children(p))
    return seen


def status(pid):
    d = {}
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("Name", "VmRSS", "VmHWM", "RssAnon", "RssFile", "RssShmem"):
                    d[k] = v.strip()
    except OSError:
        return None
    return d


def kb(v):
    try:
        return int(v.split()[0])
    except Exception:
        return 0


def main():
    root = int(sys.argv[1])
    out = sys.argv[2]
    dt = float(sys.argv[3]) if len(sys.argv) > 3 else 0.1
    t0 = time.time()
    peak = (0, 0.0, {})
    maxrss, hwm, names = {}, {}, {}
    with open(out, "w") as f:
        f.write("t_s,sum_mb,sum_anon_mb,procs\n")
        while os.path.exists(f"/proc/{root}"):
            now = time.time() - t0
            tot = 0
            anon = 0
            comp = {}
            for p in tree(root):
                st = status(p)
                if not st:
                    continue
                r = kb(st.get("VmRSS", "0"))
                if r == 0:
                    continue
                tot += r
                anon += kb(st.get("RssAnon", "0"))
                comp[p] = r
                names[p] = st.get("Name", "?")
                maxrss[p] = max(maxrss.get(p, 0), r)
                hwm[p] = max(hwm.get(p, 0), kb(st.get("VmHWM", "0")))
            if tot > peak[0]:
                peak = (tot, now, dict(comp))
            f.write(
                f"{now:.2f},{tot/1024:.1f},{anon/1024:.1f},"
                + ";".join(f"{p}:{names[p]}:{r/1024:.0f}" for p, r in comp.items())
                + "\n"
            )
            time.sleep(dt)
    comps = " ".join(f"{p}({names.get(p,'?')})={r/1024:.0f}" for p, r in peak[2].items())
    per = " ".join(
        f"{p}({names.get(p,'?')}):maxrss={maxrss[p]/1024:.0f},hwm={hwm[p]/1024:.0f}" for p in maxrss
    )
    print(
        f"MEMSAMPLE SUMMARY peak_sum_mb={peak[0]/1024:.0f} at_t={peak[1]:.1f}s [{comps}] | per-process {per}",
        flush=True,
    )


if __name__ == "__main__":
    main()
