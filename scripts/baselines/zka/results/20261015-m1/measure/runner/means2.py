#!/usr/bin/env python3
"""means2.py <runs_dir>: per shape (gkA / gk768 / bloom) and build (scalar / avx2), the per-run and mean
update makespan (total_time_ms), leaves (leafgen_seq_ms), merges (local_fold_ms), per-leaf / per-merge times,
combined peaks per phase (from phases.json), answers, and the AVX2 factor (scalar mean / avx2 mean)."""
import json, os, re, statistics as st, sys
D = sys.argv[1]; R = {}
for n in sorted(os.listdir(D)):
    p = os.path.join(D, n, "phases.json")
    if os.path.exists(p) and not n.startswith("CONTAM"): R[n] = json.load(open(p))
def nleaves(o):
    m = re.search(r"\bT=(\d+)", o["meta"]); return int(m.group(1))
def merges(o):
    w = o["worker_line"][0] if o["worker_line"] else ""
    m = re.search(r"hits=(\d+);misses=(\d+)", w)
    return (int(m.group(1)) + int(m.group(2))) if m else None
def val(o):
    ph, c = o["phases"], o["csv"]
    T = nleaves(o); nm = merges(o)
    v = dict(make_s=float(c["total_time_ms"]) / 1e3, leaves_s=float(c["leafgen_seq_ms"]) / 1e3, merges_s=float(c["local_fold_ms"]) / 1e3,
             vk_s=ph["vk"]["dur_s"], vk_peak=ph["vk"]["peak_comb"], worker_s=ph["worker"]["dur_s"], worker_peak=ph["worker"]["peak_comb"],
             worker_at_coord=ph["worker"]["at_coord"], worker_at_worker=ph["worker"]["at_worker"],
             audit_s=ph["audit"]["dur_s"], audit_peak=ph["audit"]["peak_comb"], query_s=ph["query"]["dur_s"], query_peak=ph["query"]["peak_comb"],
             whole_peak=ph["whole"]["peak_comb"], whole_tree=ph["whole"]["peak_tree"], wall_s=o["rsstree"]["wall"],
             qprove_s=float(c["query_prove_ms"]) / 1e3, verify_ms=float(c["verify_ms"]), proof_bytes=float(c["proof_bytes"]))
    v["per_leaf_s"] = v["leaves_s"] / T
    v["per_merge_s"] = v["merges_s"] / nm if nm else float("nan")
    v["n_merges"] = nm or 0
    return v
keys = ["make_s", "leaves_s", "merges_s", "per_leaf_s", "per_merge_s", "n_merges", "vk_s", "vk_peak", "worker_s", "worker_peak", "worker_at_coord", "worker_at_worker",
        "audit_s", "audit_peak", "query_s", "query_peak", "qprove_s", "whole_peak", "whole_tree", "wall_s", "verify_ms", "proof_bytes"]
out = {}
for shape in ("gkA", "gk768", "gk768x4", "bloom"):
    for b in ("scalar", "avx2"):
        rs = [(n, o) for n, o in R.items() if n.startswith(f"{shape}_{b}_")]
        if not rs: continue
        vals = [val(o) for _, o in rs]
        out[f"{shape}_{b}"] = {k: {"mean": st.mean(v[k] for v in vals), "runs": [round(v[k], 2) for v in vals]} for k in keys}
        out[f"{shape}_{b}"]["answers"] = [" ".join(f"{a}:{x}" for a, x in o["answers"]) for _, o in rs]
        out[f"{shape}_{b}"]["names"] = [n for n, _ in rs]
        print(f"== {shape} {b} ({len(rs)} runs: {', '.join(n for n, _ in rs)})")
        for k in keys:
            v = out[f"{shape}_{b}"][k]; print(f"  {k:18s} mean={v['mean']:10.2f}  runs={v['runs']}")
    if f"{shape}_scalar" in out and f"{shape}_avx2" in out:
        for k in ("make_s", "leaves_s", "merges_s", "per_leaf_s", "per_merge_s", "vk_s", "audit_s", "query_s", "wall_s"):
            s, a = out[f"{shape}_scalar"][k]["mean"], out[f"{shape}_avx2"][k]["mean"]
            if a: print(f"  AVX2 factor {shape} {k}: {s / a:.3f} ({s:.1f} / {a:.1f})")
        sa = set(out[f"{shape}_scalar"]["answers"]) | set(out[f"{shape}_avx2"]["answers"])
        print(f"  answers identical across all {shape} runs: {len(sa) == 1}")
json.dump(out, open(os.path.join(os.path.dirname(D.rstrip('/')), "means2.json"), "w"), indent=1)
