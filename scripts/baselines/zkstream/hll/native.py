#!/usr/bin/env python3
"""Native reference for hll_op.zok.tpl: Poseidon (bit-exact with the ZoKrates 0.8.8 stdlib), register map, packed
state, commitments and the HLL estimate. Run directly for a self-test of the Poseidon port.
"""
import os
import re
from pathlib import Path

P_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617
LANE_BITS = 6  # register width; ranks are <= 65-b <= 61 for b >= 4

STDLIB = Path(os.environ.get("ZOK_STDLIB", Path(os.environ.get("BASELINE_DIR", Path.home() / "ext-baselines")) / "zok" / "stdlib"))


# ---------------------------------------------------------------- constants parser
def _parse_zok_array(text, pos):
    """Parse a ZoKrates array literal starting at text[pos] == '['.
    Supports numbers, nested arrays, spreads (...[x; n]) and repeats ([x; n])."""
    ws = re.compile(r"\s*")

    def skip(p):
        return ws.match(text, p).end()

    def value(p):
        p = skip(p)
        if text[p] == "[":
            return array(p)
        m = re.compile(r"\d+").match(text, p)
        if not m:
            raise ValueError(f"unexpected token at {p}: {text[p:p + 30]!r}")
        return int(m.group(0)), m.end()

    def array(p):
        assert text[p] == "["
        p = skip(p + 1)
        # repeat form [v; n]
        save = p
        try:
            v, q = value(p)
            q = skip(q)
            if text[q] == ";":
                q = skip(q + 1)
                m = re.compile(r"\d+").match(text, q)
                n = int(m.group(0))
                q = skip(m.end())
                assert text[q] == "]"
                return [v] * n, q + 1
        except (ValueError, AssertionError, IndexError):
            pass
        p = save
        out = []
        while True:
            p = skip(p)
            if text[p] == "]":
                return out, p + 1
            if text.startswith("...", p):
                v, p = value(p + 3)
                out.extend(v)
            else:
                v, p = value(p)
                out.append(v)
            p = skip(p)
            if text[p] == ",":
                p += 1

    return array(pos)


def _load_constants():
    src = (STDLIB / "hashes" / "poseidon" / "constants.zok").read_text()
    src = re.sub(r"//[^\n]*", "", src)
    c_at = src.index("[", src.index("POSEIDON_C"))
    m_at = src.index("[", src.index("POSEIDON_M"))
    C, _ = _parse_zok_array(src, c_at)
    M, _ = _parse_zok_array(src, m_at)
    assert len(C) == 6 and all(len(r) == 497 for r in C), "POSEIDON_C shape"
    assert len(M) == 6 and all(len(r) == 7 and all(len(x) == 7 for x in r) for r in M), "POSEIDON_M shape"
    return C, M


_C, _M = _load_constants()
_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63]


def poseidon(inputs):
    """ZoKrates stdlib poseidon::<N>(inputs), 1 <= N <= 6."""
    n = len(inputs)
    assert 0 < n <= 6
    t = n + 1
    f, p = 8, _ROUNDS_P[t - 2]
    c, m = _C[t - 2], _M[t - 2]
    state = [0] + [x % P_BN254 for x in inputs]
    for r in range(f + p):
        state = [(state[i] + c[r * t + i]) % P_BN254 for i in range(t)]
        full = r < f // 2 or r >= f // 2 + p
        state = [pow(x, 5, P_BN254) if (i == 0 or full) else x for i, x in enumerate(state)]
        state = [sum(state[j] * m[i][j] for j in range(t)) % P_BN254 for i in range(t)]
    return state[0]


# ---------------------------------------------------------------- operator semantics
def geometry(s, lanes=None):
    """Register count s = 2^b -> (b, P lanes per word, S words, Q rank-window bits)."""
    b = s.bit_length() - 1
    assert s == 1 << b and b >= 4, "s must be a power of two >= 16"
    P = lanes if lanes else min(32, s)
    assert P & (P - 1) == 0 and 1 <= P <= min(32, s)
    return b, P, s // P, 64 - b


def constraints(k, s, P=None, ck=8):
    """Exact R1CS size of hll_op.zok (ZoKrates 0.8.8, bn128); fit.py compares it with every compile.
    426 + 1: Poseidon-1 salt heads, the three equality checks and one == 1; 678 per
    5-word commitment block pair (2 x 354, minus 3 per zero-padded lane saved in each
    first round, folded into 6*S); 339 per digest block (+3 per record, same padding
    effect); per record 764 (Poseidon-3 of the key, strict 254-bit unpack, rank window,
    7-bit compare, lane weight) + 2S (slot mux read + one-hot write) + Q (leading-zero
    prefix products) + 7(P-1) + log2 P (6P-bit word unpack, lane mux); and S per wire
    refresh, ceil(k/CK) of them."""
    b, P, S, Q = geometry(s, P)
    nbc, nbb = (S + 4) // 5, (k + 4) // 5
    return (427 + 678 * nbc + 6 * S + 339 * nbb + S * (-(-k // ck))
            + k * (764 + 2 * S + Q + 7 * (P - 1) + (P.bit_length() - 1)))


def route(key, b):
    """Record -> (register index, rank). h = Poseidon(key, 0); idx = low b bits of h;
    rank = 1 + leading zeros of the next Q = 64-b bits (bit b+Q-1 read first)."""
    h = poseidon([key, 0])
    idx = h & ((1 << b) - 1)
    q = 64 - b
    window = (h >> b) & ((1 << q) - 1)
    rank = q + 1 - window.bit_length()  # 1 + clz over a q-bit window; q+1 when all zero
    return idx, rank


def update(regs, keys, b):
    regs = list(regs)
    for key in keys:
        i, r = route(key, b)
        if r > regs[i]:
            regs[i] = r
    return regs


def pack(regs, P):
    """Registers -> words; register i is lane i % P of word i // P (6 bits per lane)."""
    S = len(regs) // P
    return [sum(regs[w * P + l] << (LANE_BITS * l) for l in range(P)) for w in range(S)]


def unpack(words, P):
    mask = (1 << LANE_BITS) - 1
    return [(w >> (LANE_BITS * l)) & mask for w in words for l in range(P)]


def commit(words, salt):
    """Salted Poseidon chain over the words in blocks of 5 (same idiom as cm_op)."""
    flat = list(words) + [0] * ((-len(words)) % 5)
    h = poseidon([salt])
    for i in range(0, len(flat), 5):
        h = poseidon([h] + flat[i:i + 5])
    return h


def digest(keys):
    flat = list(keys) + [0] * ((-len(keys)) % 5)
    h = 0
    for i in range(0, len(flat), 5):
        h = poseidon([h] + flat[i:i + 5])
    return h


def estimate(regs):
    """Raw HLL estimate with the small-range (linear counting) correction."""
    import math
    m = len(regs)
    alpha = {16: 0.673, 32: 0.697, 64: 0.709}.get(m, 0.7213 / (1 + 1.079 / m))
    e = alpha * m * m / sum(2.0 ** -r for r in regs)
    zeros = regs.count(0)
    if e <= 2.5 * m and zeros:
        e = m * math.log(m / zeros)
    return e


if __name__ == "__main__":
    # circomlib / ZoKrates stdlib test vectors (stdlib tests/tests/hashes/poseidon)
    vec = {
        (1,): 18586133768512220936620570745912940619677854269274689475585506675881198879027,
        (1, 2): 7853200120776062878684798364095072458815029376092732009249414926327459813530,
        (1, 2, 3, 4): 18821383157269793795438455681495246036402687001665670618754263018637548127333,
    }
    for k, v in vec.items():
        got = poseidon(list(k))
        print(f"poseidon{k} {'OK' if got == v else 'MISMATCH ' + str(got)}")
