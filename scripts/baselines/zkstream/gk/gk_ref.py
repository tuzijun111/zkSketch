#!/usr/bin/env python3
"""Native textbook Greenwald-Khanna (SIGMOD'01; COMPRESS stops at i = 1, as RefGk in ../../zka/gk/core/src/lib.rs)
and the packed state of gk_op.zok. Run as a script for a self-test against the circuit's fixed-shape COMPRESS.
"""
import random
import struct
import sys
from pathlib import Path

VALUE_MASK = 0x1FFFFF
SENT_V = 1 << 21


def band(delta, p):
    """BAND(Delta, p), p = floor(2 eps n): 0 if Delta == p, else the smallest a >= 1 with
    p - Delta < 2^a + (p mod 2^a) (GK'01 Sec 3.1 band_a)."""
    assert 0 <= delta <= p
    if delta == p:
        return 0
    x, a = p - delta, 1
    while True:
        m = 1 << a
        if x < m + (p & (m - 1)):
            return a
        a += 1


class GK:
    """Textbook GK for eps = 1/E (E even), COMPRESS period P = floor(1/(2 eps)) = E/2."""

    def __init__(self, E):
        assert E % 2 == 0 and E >= 4
        self.E, self.P, self.n, self.t = E, E // 2, 0, []
        self.stats = dict(compress=0, merges=0, desc_blocks=0, max_len=0, max_len_before_insert=0)

    def two_eps_n(self):
        return 2 * self.n // self.E

    def observe(self, v):
        """Returns the insert position (index in the post-COMPRESS list) -- the op's hint."""
        if self.n % self.P == 0:
            self.compress()
        self.stats["max_len_before_insert"] = max(self.stats["max_len_before_insert"], len(self.t))
        pos = next((i for i, x in enumerate(self.t) if v < x[0]), len(self.t))
        d = 0 if pos == 0 or pos == len(self.t) else self.two_eps_n()
        self.t.insert(pos, [v, 1, d])
        self.n += 1
        self.stats["max_len"] = max(self.stats["max_len"], len(self.t))
        return pos

    def compress(self):
        self.stats["compress"] += 1
        t = self.t
        if len(t) < 2:
            return
        p = self.two_eps_n()
        i = len(t) - 2
        while i >= 1:
            bi, bn = band(t[i][2], p), band(t[i + 1][2], p)
            j = i
            while j > 0 and band(t[j - 1][2], p) < bi:
                j -= 1
            assert j >= 1, "t_0 inside a descendant block"
            gstar = sum(x[1] for x in t[j:i + 1])
            if bi <= bn and self.E * (gstar + t[i + 1][1] + t[i + 1][2]) < 2 * self.n:
                t[i + 1][1] += gstar
                del t[j:i + 1]
                self.stats["merges"] += 1
                self.stats["desc_blocks"] += int(i > j)
                i = j - 1
            else:
                i -= 1

    def check_invariants(self, seen_sorted):
        """GK invariants against the exact multiset of values seen so far."""
        t, n = self.t, self.n
        assert sum(x[1] for x in t) == n
        assert all(t[i][0] <= t[i + 1][0] for i in range(len(t) - 1))
        if n:
            assert t[0] == [seen_sorted[0], 1, 0] and t[-1][0] == seen_sorted[-1] and t[-1][2] == 0
        rmin = 0
        for v, g, d in t:
            rmin += g
            # rank(v) window: rmin <= r(v) <= rmin + d for some occurrence of v
            lo = sum(1 for x in seen_sorted if x < v) + 1
            hi = sum(1 for x in seen_sorted if x <= v)
            assert lo <= rmin + d and rmin <= hi, (v, g, d, rmin, lo, hi)
            assert g + d <= 2 * n / self.E + 1


def read_keys(path, n, offset=0):
    data = Path(path).read_bytes()[4 * offset: 4 * (offset + n)]
    if len(data) < 4 * n:
        sys.exit(f"{path} holds fewer than {offset + n} keys")
    return list(struct.unpack(f"<{n}I", data))


def geometry(S, E, NB):
    """Constants of gen.sh (kept in sync by run_gk.py's check against the generated file)."""
    EL = E.bit_length() - 1
    L = NB - EL + 1
    return dict(L=L, WB=22 + 2 * L, P=E // 2, EL=EL)


def pack(t, S, L):
    """Packed state words: v * 2^(2L) + g * 2^L + Delta, sentinel 2^21 * 2^(2L) above s."""
    if len(t) > S:
        raise OverflowError(f"{len(t)} tuples > capacity {S}")
    words = []
    for v, g, d in t:
        assert 0 <= v < SENT_V and 0 < g < (1 << L) and 0 <= d < (1 << L), (v, g, d, L)
        words.append((v << (2 * L)) | (g << L) | d)
    return words + [SENT_V << (2 * L)] * (S - len(t))


# ---------------------------------------------------------------------------------------
# Self-test: the circuit's fixed-shape COMPRESS, step for step, against the reference.
# ---------------------------------------------------------------------------------------

def _therm(delta, p, L):
    pb = [(p >> a) & 1 for a in range(L)]
    db = [(delta >> a) & 1 for a in range(L)]
    x = y = 0
    xs, ys = [0] * L, [0] * L
    for a in range(L - 1, -1, -1):
        pr = pb[a] * db[a]
        ym = y * (db[a] - pr)
        x, y = x + y - ym, ym + (1 - x - y) * (pb[a] - pr)
        xs[a], ys[a] = x, y
    out, nz = [], 0
    for a in range(L):
        out.append(xs[a] + ys[a] * (1 - nz))
        nz = nz + db[a] - nz * db[a]
    return out + [0]


def _compact_network(words, keep, dcount, S, L):
    """Mirror of gk_op.zok.tpl:compress pass (5): LSB-first shifts, each kept tuple carrying its
    remaining shift r = d >> b, moving left by 2^b iff r is odd."""
    LOGS = S.bit_length() - 1
    ww, occ, rs = list(words) + [0] * S, list(keep) + [0] * S, list(dcount) + [0] * S
    for b in range(LOGS):
        sh = 1 << b
        assert all(0 <= rs[x] < (1 << (LOGS - b)) for x in range(S))
        mv = [occ[x] * (rs[x] & 1) for x in range(S)] + [0] * S
        rr = [rs[x] >> 1 for x in range(S)] + [0] * S
        nocc, nww, nrs = [0] * (2 * S), [0] * (2 * S), [0] * (2 * S)
        for x in range(S):
            st, inc = occ[x] - mv[x], mv[x + sh]
            assert st + inc <= 1, "collision"
            nocc[x], nww[x], nrs[x] = st + inc, st * ww[x] + inc * ww[x + sh], st * rr[x] + inc * rr[x + sh]
        occ, ww, rs = nocc, nww, nrs
    return [ww[x] if occ[x] else SENT_V << (2 * L) for x in range(S)]


def _compress_fixed(words, n, E, S, L):
    """Mirror of gk_op.zok.tpl:compress on packed words (same passes, same formulas)."""
    p = 2 * n // E
    valid = [0 if (w >> (2 * L)) & SENT_V else 1 for w in words] + [0]
    g = [(w >> L) & ((1 << L) - 1) for w in words]
    dl = [w & ((1 << L) - 1) for w in words]
    th = [_therm(dl[j], p, L) for j in range(S)]
    bd = [sum(x) for x in th]
    gs, acc = [0] * S, [0] * (L + 1)
    for j in range(S):
        gs[j] = g[j] + sum((th[j][b - 1] - th[j][b]) * acc[b] for b in range(1, L + 1))
        for b in range(1, L + 1):
            acc[b] = (1 - th[j][b - 1]) * (acc[b] + g[j])
    rg = rd = rb = indel = thr = 0
    kp, mgs = [0] * S, [0] * S
    for j in range(S - 1, 0, -1):
        last = valid[j] * (1 - valid[j + 1])
        desc = indel * int(bd[j] < thr)
        cand = valid[j] - last - desc
        mg = cand * int(bd[j] <= rb) * int(E * (gs[j] + rg + rd) < 2 * n)
        nr = last + cand - mg
        rg = rg + nr * (g[j] - rg) + mg * gs[j]
        rd = rd + nr * (dl[j] - rd)
        rb = rb + nr * (bd[j] - rb)
        indel, thr = mg + desc, thr + mg * (bd[j] - thr)
        kp[j], mgs[j] = nr, mg * gs[j]
    kp[0] = valid[0]
    assert indel * int(bd[0] < thr) == 0
    carry, ww, dcount, dd = 0, [], 0, []
    for j in range(S):
        ww.append(words[j] + kp[j] * carry * (1 << L))
        carry = (1 - kp[j]) * (carry + mgs[j])
        dd.append(dcount)
        dcount += valid[j] - kp[j]
    out = [SENT_V << (2 * L)] * S
    for j in range(S):
        if kp[j]:
            out[j - dd[j]] = ww[j]          # the specification of the compaction ...
    assert out == _compact_network(ww, kp, dd, S, L)   # ... equals the circuit's network
    return out


def selftest():
    for p in range(0, 300):
        for d in range(p + 1):
            assert sum(_therm(d, p, 9)) == band(d, p)
    print("band automaton == BAND(Delta, p) for p < 300")
    here = Path(__file__).resolve()
    keys = read_keys(here.parents[4] / "data" / "aol.keys", 4096)
    aol = [k & VALUE_MASK for k in keys]
    rnd = random.Random(7)
    streams = [("aol", aol[:1024]), ("aol2", aol[2048:4096])]
    for s in range(4):
        streams.append((f"uniform{s}", [rnd.randrange(SENT_V) for _ in range(800)]))
        streams.append((f"fewdistinct{s}", [rnd.randrange(20) for _ in range(800)]))
    streams += [("increasing", list(range(800))), ("decreasing", list(range(800, 0, -1)))]
    S, NB = 128, 13
    for E in (8, 16):
        L = geometry(S, E, NB)["L"]
        for name, st in streams:
            gk = GK(E)
            words = pack([], S, L)
            seen = []
            for i, v in enumerate(st):
                if gk.n % gk.P == 0:
                    words = _compress_fixed(words, gk.n, E, S, L)
                pos = gk.observe(v)
                w = pack(gk.t, S, L)
                # replay the insert on the fixed-shape words
                vals = [x >> (2 * L) for x in words]
                assert pos == sum(1 for x in vals if x <= v)
                assert w == [x for x in words[:pos]] + [w[pos]] + words[pos:S - 1], (name, i)
                words = w
                seen.append(v)
                if i % 97 == 0 or i + 1 == len(st):
                    gk.check_invariants(sorted(seen))
            print(f"E={E:<3} {name:<14} n={gk.n} tuples={len(gk.t)} {gk.stats}")
    print("fixed-shape COMPRESS == textbook reference on every step")


if __name__ == "__main__":
    selftest()
