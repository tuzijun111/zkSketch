#!/usr/bin/env python3
"""means.py <runs_dir>: per family and A/B, mean (and per-run) time and combined peak for each phase."""
import json, os, statistics as st, sys
D = sys.argv[1]; R = {}
for n in sorted(os.listdir(D)):
    p = os.path.join(D, n, "phases.json")
    if os.path.exists(p): R[n] = json.load(open(p))
def val(o, k):
    ph, c = o["phases"], o["csv"]
    return {"vk_s": ph["vk"]["dur_s"], "vk_peak": ph["vk"]["peak_comb"],
            "make_s": float(c["total_time_ms"]) / 1e3, "leaves_s": float(c["leafgen_seq_ms"]) / 1e3, "merges_s": float(c["local_fold_ms"]) / 1e3,
            "worker_s": ph["worker"]["dur_s"], "worker_peak": ph["worker"]["peak_comb"], "worker_at_coord": ph["worker"]["at_coord"], "worker_at_worker": ph["worker"]["at_worker"],
            "audit_s": ph["audit"]["dur_s"], "audit_peak": ph["audit"]["peak_comb"], "audit_at_coord": ph["audit"]["at_coord"], "audit_at_worker": ph["audit"]["at_worker"],
            "exit_s": (o["marks"]["workers_exited"][0] - o["marks"]["root_received"][0]) if "workers_exited" in o["marks"] else (o["marks"]["before_query_phase"][0] - o["marks"]["audit_done"][0]),
            "query_s": ph["query"]["dur_s"], "query_peak": ph["query"]["peak_comb"],
            "audq_s": ph["audit"]["dur_s"] + ph["query"]["dur_s"],
            "whole_peak": ph["whole"]["peak_comb"], "whole_tree": ph["whole"]["peak_tree"], "wall_s": o["rsstree"]["wall"],
            "qprove_s": float(c["query_prove_ms"]) / 1e3}[k]
keys = ["vk_s", "vk_peak", "make_s", "leaves_s", "merges_s", "worker_s", "worker_peak", "worker_at_coord", "worker_at_worker", "audit_s", "audit_peak",
        "audit_at_coord", "audit_at_worker", "exit_s", "query_s", "query_peak", "audq_s", "qprove_s", "whole_peak", "whole_tree", "wall_s"]
out = {}
for fam in ("gk", "bloom"):
    for ab in ("A", "B"):
        rs = [o for n, o in R.items() if n.startswith(fam + "_" + ab)]
        if not rs: continue
        out[f"{fam}_{ab}"] = {k: {"mean": st.mean(val(o, k) for o in rs), "runs": [round(val(o, k), 1) for o in rs]} for k in keys}
        print(f"== {fam} {ab} ({len(rs)} runs: {', '.join(o['run'] for o in rs)})")
        for k in keys:
            v = out[f"{fam}_{ab}"][k]; print(f"  {k:18s} mean={v['mean']:9.1f}  runs={v['runs']}")
json.dump(out, open(os.path.join(os.path.dirname(D.rstrip('/')), "means.json"), "w"), indent=1)
