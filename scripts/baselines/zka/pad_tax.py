#!/usr/bin/env python3
"""Pad records and split leaves of zkSketch's query schedule (build_query_schedule_batches),
by replaying its loop and in closed form. Usage: python3 pad_tax.py"""
import sys

def sim(N, m, Q):
    """Literal replay of the Rust loop."""
    batches = 0; query_at = []; pads = 0; splits = 0; cur = 0
    def seal():
        nonlocal batches, pads, splits, cur
        if cur == 0: return
        p = m - cur
        if p > 0:
            pads += p; splits += 1
        batches += 1; cur = 0
    for pos in range(1, N+1):
        if Q > 0 and pos % Q == 0:
            seal(); query_at.append(batches)
        else:
            cur += 1
            if cur == m: seal()
    seal()
    return batches, len(query_at), pads, splits

def closed_form(N, m, Q):
    """O(1) formula. nq = floor(N/Q); each query seals a run of Q-1 updates
    (cur is empty only when (Q-1) % m == 0), then the tail is pad-sealed."""
    nq = N // Q
    per = (m - ((Q-1) % m)) % m          # pads charged at each query point
    tail = N - nq*Q                      # updates after the last query
    tailpad = (m - (tail % m)) % m
    pads = nq*per + tailpad
    splits = nq*(1 if per else 0) + (1 if tailpad else 0)
    # leaves = ceil-ish; derive from sim-equivalent accounting
    return nq, pads, splits, per

if __name__ == "__main__":
    print("# validation against the recorded run "
          "(results/s3_mixed_q100000.csv: n=1048576 m=16384 Q=100000 "
          "-> n_queries=10 query_pad_records=147466 query_split_leaves=11)")
    for (N,m,Q) in [(1048576,16384,100000),(1048576,16384,1000000),
                    (1048576,16384,10000),(1048576,16384,1000)]:
        t,nq,p,s = sim(N,m,Q)
        cnq,cp,cs,per = closed_form(N,m,Q)
        print(f"N={N} m={m} Q={Q:>7} -> sim: t={t} nq={nq} pad={p} split={s} "
              f"| closed: nq={cnq} pad={cp} split={cs} (per-query {per})")
    print()
    print("# zero-pad rule: (Q-1) % m == 0  =>  every query lands on a batch boundary")
    for Q in [16385, 32769, 8193]:
        t,nq,p,s = sim(131072,16384,Q)
        print(f"N=131072 m=16384 Q={Q:>6} -> t={t} nq={nq} pad={p} split={s}")

def qctx(t, qevery):
    """query_ctx_verifies per composition mode, from
    `aggregate_queries` in src/experiments/stream_compose.rs.  Purely STRUCTURAL —
    no proving needed to predict it.
      per_batch -> t'      chain -> 1      forest -> popcount(t')"""
    qs = [i for i in range(1, t+1) if i % qevery == 0]
    return {"n_queries": len(qs),
            "per_batch": sum(qs),
            "chain": len(qs),
            "forest": sum(bin(i).count("1") for i in qs)}
