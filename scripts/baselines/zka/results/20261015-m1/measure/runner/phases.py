#!/usr/bin/env python3
"""phases.py <run_dir>...: split a memsample.py trace by exp_compose QLOG_PHASE unix_ms marks.

Combined = coordinator (exp_compose) + procs worker (zks_dc_exe_*) + its helpers (rustc), i.e. the
exp_compose process tree; 'tree' additionally counts the run_zks.sh / rss_tree.sh shells.
Phases: vk     = exp_compose start -> auditor_new (QueryAudit::new: decode + prefix VKs)
        worker = auditor_new -> root_received (leaves + merges)
        post   = root_received -> before_query_phase (A: audit, then Exit; B: Exit, then audit)
          of which audit = (A) root_received -> audit_done, (B) workers_exited -> audit_done
                   exit  = (A) audit_done -> before_query_phase, (B) root_received -> workers_exited
        query  = before_query_phase -> queries_done
        tail   = queries_done -> exp_compose exit
"""
import csv, glob, json, os, re, sys

KEEP = re.compile(r"^(exp_compose|zks_dc_exe.*|rustc|numactl|taskset)$")

def load(d):
    log = glob.glob(os.path.join(d, "out", "six_zksketch_*.log"))[0]
    txt = open(log).read()
    marks = {}
    for m in re.finditer(r"QLOG_PHASE,after=(\w+),coord_hwm_mb=([\d.]+),coord_rss_mb=([\d.]+),unix_ms=(\d+)", txt):
        marks[m.group(1)] = (int(m.group(4)) / 1000.0, float(m.group(2)), float(m.group(3)))
    t0 = float(re.search(r"MEMSAMPLE_T0_UNIX=([\d.]+)", open(os.path.join(d, "memsum.txt")).read()).group(1))
    rows = []
    with open(os.path.join(d, "mem.csv")) as f:
        r = csv.reader(f); next(r)
        for row in r:
            t = t0 + float(row[0])
            coord = work = other = shells = 0.0
            for p in row[3].split(";") if len(row) > 3 and row[3] else []:
                pid, comm, mb = p.split(":")
                mb = float(mb)
                if comm == "exp_compose": coord += mb
                elif comm.startswith("zks_dc_exe"): work += mb
                elif KEEP.match(comm): other += mb
                else: shells += mb
            rows.append((t, coord, work, other, shells))
    return txt, marks, rows

def phase_stats(rows, a, b):
    sel = [r for r in rows if a <= r[0] < b]
    if not sel: return None
    comb = max(sel, key=lambda r: r[1] + r[2] + r[3])
    return dict(dur_s=b - a, peak_comb=comb[1] + comb[2] + comb[3], at_coord=comb[1], at_worker=comb[2],
                peak_coord=max(r[1] for r in sel), peak_worker=max(r[2] for r in sel),
                peak_tree=max(sum(r[1:]) for r in sel))

def analyse(d):
    txt, mk, rows = load(d)
    alive = [r for r in rows if r[1] > 0]
    start, end = alive[0][0], alive[-1][0] + 0.1
    ab = "B" if "workers_exited" in mk else "A"
    t = {k: v[0] for k, v in mk.items()}
    ph = [("vk", start, t["auditor_new"]), ("worker", t["auditor_new"], t["root_received"])]
    if ab == "B":
        ph += [("exit", t["root_received"], t["workers_exited"]), ("audit", t["workers_exited"], t["audit_done"]),
               ("post_audit", t["audit_done"], t["before_query_phase"])]
    else:
        ph += [("audit", t["root_received"], t["audit_done"]), ("exit", t["audit_done"], t["before_query_phase"])]
    ph += [("query", t["before_query_phase"], t["queries_done"]), ("tail", t["queries_done"], end), ("whole", start, end)]
    out = {"run": os.path.basename(d), "ab": ab, "phases": {}}
    for name, a, b in ph:
        out["phases"][name] = phase_stats(rows, a, b)
    csvp = glob.glob(os.path.join(d, "out", "six_zksketch_*.csv"))
    csvp = [p for p in csvp if not p.endswith("_runs.csv")][0]
    row = next(csv.DictReader(open(csvp)))
    out["csv"] = {k: row[k] for k in ("total_time_ms", "leafgen_seq_ms", "local_fold_ms", "merge_total_ms", "verify_ms", "peak_rss_mb",
                                       "query_prove_ms", "query_bind_ms", "proof_bytes", "status")}
    out["answers"] = re.findall(r"QLOG_QUERY,at_leaf=(\d+),.*?answer=([^,\s]+)", txt)
    out["keys"] = re.findall(r"QLOG_KEY,at_leaf=(\d+),(\S+)", txt)
    vk = re.search(r"VK derived from public parameters in ([\d.]+)s", txt)
    out["vk_derive_s"] = float(vk.group(1)) if vk else None
    rss = re.search(r"RSSTREE,\S+?,main_peak_rss_mb=([\d.]+),r0vm_peak_rss_mb=[\d.]+,desc_peak_rss_mb=([\d.]+),wall_s=([\d.]+)", txt)
    out["rsstree"] = dict(main=float(rss.group(1)), desc=float(rss.group(2)), wall=float(rss.group(3))) if rss else None
    w = re.findall(r"QLOG_WORKER,(.*)", txt)
    out["worker_line"] = w
    out["memsum"] = [l for l in open(os.path.join(d, "memsum.txt")) if l.startswith("MEMSAMPLE SUMMARY")]
    out["meta"] = open(os.path.join(d, "meta.txt")).read()
    out["marks"] = {k: [round(v[0] - start, 2), v[1], v[2]] for k, v in mk.items()}
    return out

if __name__ == "__main__":
    for d in sys.argv[1:]:
        o = analyse(d)
        print(f"== {o['run']} ({o['ab']})")
        print(o["meta"].strip())
        print("csv:", o["csv"], "vk_derive_s:", o["vk_derive_s"], "rsstree:", o["rsstree"])
        print("worker:", o["worker_line"])
        print("marks (s from exp_compose start, coord_hwm, coord_rss):", o["marks"])
        for k, v in o["phases"].items():
            if v: print(f"  {k:10s} dur={v['dur_s']:7.1f}s peak_comb={v['peak_comb']:7.0f} (coord {v['at_coord']:.0f} + worker {v['at_worker']:.0f}) peak_coord={v['peak_coord']:.0f} peak_worker={v['peak_worker']:.0f} peak_tree={v['peak_tree']:.0f}")
            else: print(f"  {k:10s} (no samples)")
        print("answers:", " ".join(f"{a}:{b}" for a, b in o["answers"]))
        print("".join(o["memsum"]).strip())
        json.dump(o, open(os.path.join(d, "phases.json"), "w"), indent=1)
