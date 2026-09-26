#!/usr/bin/env python3
"""Accuracy side-check for the HLL baseline (native, numpy; no zkVM).

1. Independent re-implementation of the guest's HLL (FNV-1a over the 15-byte
   make_key_id(0, key), seeded splitmix64 finaliser, index = low 14 bits,
   rank = 1 + leading zeros of the other 50 bits, textbook estimator with linear
   counting). For the seed the guest uses (their CM row-0 seed 0x6d0f27bd) it must
   reproduce the committed estimate of every query row in zka_hll_exec.csv exactly;
   the script exits non-zero otherwise.
2. The same estimate under 9 other seeds, to show how much of the observed error is
   the draw of one hash function (HLL standard error 1.04/sqrt(2^14) = 0.81%).

Usage: seed_spread.py [--keys data/aol.keys] [--exec-csv results/zka_hll_exec.csv]
                      [--out results/zka_hll_seed_spread.csv]
"""
import argparse, csv, math, os, sys
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ZKS = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
P, M = 14, 1 << 14
EPOCH = 16384
GUEST_SEED = 0x6D0F27BD
SEEDS = [GUEST_SEED, 0x9E3779B9, 0x94D049BB, 1, 2, 3, 0xDEADBEEF, 12345, 777, 4242]
U = np.uint64


def fnv1a_key_id(keys):
    # key_id = 3 zero bytes | source_id 0 (4 bytes BE) | key (8 bytes BE); FNV-1a 64
    h = np.full(keys.shape, 0xCBF29CE484222325, dtype=U)
    with np.errstate(over="ignore"):
        for _ in range(7):
            h ^= U(0)
            h *= U(0x100000001B3)
        for i in range(8):
            h ^= (keys >> U(8 * (7 - i))) & U(0xFF)
            h *= U(0x100000001B3)
    return h


def splitmix(x, seed):
    with np.errstate(over="ignore"):
        x = x ^ U((seed << 32) | seed)
        x ^= x >> U(30); x *= U(0xBF58476D1CE4E5B9)
        x ^= x >> U(27); x *= U(0x94D049BB133111EB)
        x ^= x >> U(31)
    return x


def estimate(h):
    idx = (h & U(M - 1)).astype(np.int64)
    w = h >> U(P)
    bitlen = np.zeros(h.shape, dtype=np.int64)
    for k in range(64 - P):  # exact bit length of w (< 2^50)
        bitlen += ((w >> U(k)) > 0)
    rank = (64 - P) - bitlen + 1
    regs = np.zeros(M, dtype=np.int64)
    np.maximum.at(regs, idx, rank)
    # exact sum_j 2^(51 - M[j]) like the guest, then one float conversion
    hist = np.bincount(regs, minlength=64 - P + 2)
    s = sum(int(c) << (64 - P + 1 - r) for r, c in enumerate(hist))
    z = float(s) / float(1 << (64 - P + 1))
    raw = 0.7213 / (1.0 + 1.079 / M) * M * M / z
    v = int(hist[0])
    est = M * math.log(M / v) if (raw <= 2.5 * M and v != 0) else raw
    return int(math.floor(est + 0.5))  # guest: libm::round (half away from zero; est > 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys", default=os.path.join(ZKS, "data", "aol.keys"))
    ap.add_argument("--exec-csv", default=os.path.join(HERE, "..", "results", "zka_hll_exec.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "..", "results", "zka_hll_seed_spread.csv"))
    a = ap.parse_args()
    keys = np.fromfile(a.keys, dtype="<u4").astype(U)
    f = fnv1a_key_id(keys)

    committed = {}
    with open(a.exec_csv) as fh:
        for r in csv.DictReader(fh):
            if r["mode"] == "query":
                est = int(r["result"].split(";")[0].split("=")[1])
                committed.setdefault(int(r["epochs"]), set()).add(est)

    rows, bad = [], 0
    for n in sorted(committed) or [1, 4, 16, 64]:
        pref = keys[: n * EPOCH]
        exact = len(np.unique(pref))
        errs = []
        for seed in SEEDS:
            e = estimate(splitmix(f[: n * EPOCH], seed))
            err = (e - exact) / exact
            errs.append(err)
            match = ""
            if seed == GUEST_SEED:
                ok = committed.get(n) == {e}
                bad += not ok
                match = "guest_match=" + ("yes" if ok else f"NO(guest={committed.get(n)})")
            rows.append([n, hex(seed), exact, e, f"{err:.6f}", match])
        sd = float(np.std(errs, ddof=1))
        print(f"n={n:2d} exact={exact:7d} guest-seed err={errs[0]*100:+.2f}%  "
              f"10 seeds: min {min(errs)*100:+.2f}% max {max(errs)*100:+.2f}% "
              f"mean {np.mean(errs)*100:+.2f}% sd {sd*100:.2f}%  (theory 0.81%)")
    with open(a.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["epochs", "seed", "exact_distinct", "estimate", "rel_err", "note"])
        w.writerows(rows)
    print(f"wrote {a.out}")
    if bad:
        print(f"MISMATCH: {bad} guest estimate(s) not reproduced", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
