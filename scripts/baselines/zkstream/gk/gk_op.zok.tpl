// Greenwald-Khanna update operator in zkStream's stateful-operator shape (zkStream Sec 4.4):
// open a salted commitment to the summary, apply one chunk of records with the TEXTBOOK
// per-record GK update (SIGMOD'01: COMPRESS every floor(1/(2 eps)) records, then INSERT),
// emit the commitment to the updated summary. OUR circuit in zkStream's toolchain, not
// zkStream code. Replay only: no batch certificate, no multiset/permutation argument.
//
// State: record count n and S tuple slots, sorted by v, each packed into one field element
//   word = v * 2^(2L) + g * 2^L + Delta        (v: 22 bits, g and Delta: L bits each)
// Empty slots hold the sentinel word 2^21 * 2^(2L) (v = 2^21 > every value, g = Delta = 0),
// so slots 0..s-1 are the summary and s..S-1 are sentinels. t_0 is the running minimum and
// t_{s-1} the running maximum (both kept by COMPRESS, as the paper's Sec 2.1 requires).
// Records: 32-bit keys bound to a public batch digest; value v = key & 0x1FFFFF.
// Prover hints: one one-hot insert position per record, fully checked (v_{pos-1} <= v < v_pos).
// COMPRESS takes no hints: bands, descendant blocks, merge decisions and the compaction of
// the kept tuples are all recomputed in fixed-shape passes over the S slots.
// Commitment idiom = zkStream's salted Poseidon output hash (q4a.poseidon.zok producer,
// q4b.poseidon.zok:28-32 consumer). Constants are rewritten textually by gen.sh, as zkStream
// does (zokrates.rs:85-87).
import "hashes/poseidon/poseidon" as poseidon;
import "utils/pack/bool/unpack" as unpack;
import "utils/pack/bool/pack" as pack;
const u32 K = __K__;
const u32 S = __S__;
const u32 LOGS = __LOGS__;
const u32 S2 = __S2__;
const field EF = __E__;
const u32 EL = __EL__;
const u32 NB = __NB__;
const u32 L = __L__;
const u32 L1 = __L1__;
const u32 WB = __WB__;
const u32 Q1 = __Q1__;
const u32 M1 = __M1__;
const u32 NC = __NC__;
const u32 RPC = __RPC__;
const u32 ALB = __ALB__;
const u32 NBC = __NBC__;
const u32 LC = __LC__;
const u32 NBB = __NBB__;
const u32 LB = __LB__;
const field TWOL = 2**__L__;
const field TWO2L = 2**__L2__;
const field TWOQ = 2**__Q__;
const field TWOM = 2**__M__;
const field SENTW = 2**__SENTEXP__;

// x in [0, 2^N). The explicit re-pack keeps the constraints: an unpack whose bits are never
// read is removed by the ZoKrates 0.8.8 optimiser (a bare unpack is NOT a range check).
def range_check<N>(field x) -> bool {
    bool[N] b = unpack::<N>(x);
    assert(pack(b) == x);
    return true;
}

def commit(field n, field[S] w, field salt) -> field {
    field[LC] mut flat = [0; LC];
    flat[0] = n;
    for u32 j in 0..S { flat[j + 1] = w[j]; }
    field mut h = poseidon([salt]);
    for u32 b in 0..NBC { h = poseidon([h, flat[5*b], flat[5*b+1], flat[5*b+2], flat[5*b+3], flat[5*b+4]]); }
    return h;
}

def digest(field[K] keys) -> field {
    field[LB] mut flat = [0; LB];
    for u32 i in 0..K { flat[i] = keys[i]; }
    field mut h = 0;
    for u32 b in 0..NBB { h = poseidon([h, flat[5*b], flat[5*b+1], flat[5*b+2], flat[5*b+3], flat[5*b+4]]); }
    return h;
}

// Textbook COMPRESS (GK'01 Fig. 2, loop i = s-2 .. 1 so that t_0 stays the minimum) at count n,
// p = floor(2 eps n); the caller derives p from the bits of n. en = 0 returns w unchanged.
// Compile-time note: ZoKrates 0.8.8 copies a whole array on every element assignment, so
// the passes keep only 1-D arrays of S slots (no per-slot 2-D tables).
def compress(field[S] w, field n, field p, field en) -> field[S] {
    bool[L] pb = unpack::<L>(p);
    field[S2] mut valid = [0; S2];
    field[S] mut g = [0; S];
    field[S] mut dl = [0; S];
    field[S] mut band = [0; S];
    field[S] mut gs = [0; S];
    field[L1] mut acc = [0; L1];
    // (1) unpack every slot; BAND(Delta, p) as a thermometer th[a] = [band > a].
    // band > a  <=>  ceil(Delta / 2^a) < floor(p / 2^a); an MSB-first automaton tracks
    // min(floor(p/2^a) - floor(Delta/2^a), 2) and nz tracks [Delta mod 2^a != 0].
    // (2) in the same left-to-right loop: g*_j = g_j + sum of g over the maximal run directly
    // left of j with band < band_j (t_j and its descendants); acc[b] = that sum for threshold b.
    for u32 j in 0..S {
        bool[WB] b = unpack::<WB>(w[j]);
        valid[j] = b[0] ? 0 : 1;
        field mut gg = 0;
        field mut dd = 0;
        for u32 a in 0..L {
            gg = gg + (b[21 + L - a] ? 2**a : 0);
            dd = dd + (b[WB - 1 - a] ? 2**a : 0);
        }
        g[j] = gg;
        dl[j] = dd;
        field mut x = 0;
        field mut y = 0;
        field[L] mut xs = [0; L];
        field[L] mut ys = [0; L];
        for u32 aa in 0..L {
            u32 a = L - 1 - aa;
            field pa = pb[L - 1 - a] ? 1 : 0;
            field da = b[WB - 1 - a] ? 1 : 0;
            field pr = pa * da;
            field ym = y * (da - pr);
            field x2 = x + y - ym;
            field y2 = ym + (1 - x - y) * (pa - pr);
            x = x2;
            y = y2;
            xs[a] = x;
            ys[a] = y;
        }
        field[L1] mut th = [0; L1];
        field mut nz = 0;
        field mut bd = 0;
        for u32 a in 0..L {
            field o = xs[a] + ys[a] * (1 - nz);
            th[a] = o;
            bd = bd + o;
            field da = b[WB - 1 - a] ? 1 : 0;
            nz = if a + 1 < L { nz + da - nz * da } else { nz };
        }
        band[j] = bd;
        field mut s = gg;
        for u32 bb in 1..L1 { s = s + (th[bb - 1] - th[bb]) * acc[bb]; }
        gs[j] = s;
        for u32 bb in 1..L1 { acc[bb] = (1 - th[bb - 1]) * (acc[bb] + gg); }
    }
    // (3) the textbook right-to-left pass, i = s-2 .. 1, as a fixed scan over slots S-1 .. 1.
    // Right neighbour (rg, rd, rb) = nearest kept tuple to the right, with merged g's.
    // A merge of t_j deletes t_j and its descendant block, which the scan meets next:
    // indel/thr mark "inside the block of the last merged tuple, band < thr".
    field mut rg = 0;
    field mut rd = 0;
    field mut rb = 0;
    field mut indel = 0;
    field mut thr = 0;
    field[S] mut kp = [0; S];
    field[S] mut mgs = [0; S];
    for u32 jj in 0..S - 1 {
        u32 j = S - 1 - jj;
        field vj = valid[j];
        field last = vj * (1 - valid[j + 1]);
        bool[Q1] c1 = unpack::<Q1>(thr - band[j] - 1 + TWOQ);
        field desc = indel * (c1[0] ? 1 : 0);
        field cand = vj - last - desc;
        bool[Q1] c2 = unpack::<Q1>(rb - band[j] + TWOQ);
        bool[M1] c3 = unpack::<M1>(2 * n - 1 - EF * (gs[j] + rg + rd) + TWOM);
        field m1 = cand * (c2[0] ? 1 : 0);
        field mg = m1 * (c3[0] ? 1 : 0);
        field nr = last + cand - mg;
        field mgsj = mg * gs[j];
        rg = rg + nr * (g[j] - rg) + mgsj;
        rd = rd + nr * (dl[j] - rd);
        rb = rb + nr * (band[j] - rb);
        indel = mg + desc;
        thr = thr + mg * (band[j] - thr);
        kp[j] = nr;
        mgs[j] = mgsj;
    }
    kp[0] = valid[0];
    // t_0 is never inside a deleted block (the textbook loop must end at i = 0).
    bool[Q1] c0 = unpack::<Q1>(thr - band[0] - 1 + TWOQ);
    assert(indel * (c0[0] ? 1 : 0) == 0);
    // (4) write the merged g's into their kept right neighbours, left to right; rs[j] = number
    // of deleted slots left of j = how far a kept tuple j moves left.
    field mut carry = 0;
    field[S2] mut ww = [0; S2];
    field[S2] mut occ = [0; S2];
    field[S2] mut rs = [0; S2];
    field mut dcount = 0;
    for u32 j in 0..S {
        field add = kp[j] * carry;
        ww[j] = w[j] + add * TWOL;
        carry = (1 - kp[j]) * (carry + mgs[j]);
        occ[j] = kp[j];
        rs[j] = dcount;
        dcount = dcount + valid[j] - kp[j];
    }
    // (5) order-preserving compaction, LSB first: at stage b every kept tuple carries its
    // remaining shift r = d >> b (< 2^(LOGS-b)) and moves left by 2^b iff r is odd
    // (collision-free because d is monotone along the kept tuples).
    for u32 b in 0..LOGS {
        u32 sh = 1 << b;
        field[S2] mut mv = [0; S2];
        field[S2] mut rr = [0; S2];
        for u32 x in 0..S {
            bool[LOGS - b] rbits = unpack(rs[x]);
            mv[x] = occ[x] * (rbits[LOGS - b - 1] ? 1 : 0);
            field mut half = 0;
            for u32 i in 1..LOGS - b { half = half + (rbits[LOGS - b - 1 - i] ? 2**(i - 1) : 0); }
            rr[x] = half;
        }
        field[S2] mut nocc = [0; S2];
        field[S2] mut nww = [0; S2];
        field[S2] mut nrs = [0; S2];
        for u32 x in 0..S {
            field st = occ[x] - mv[x];
            field inc = mv[x + sh];
            nocc[x] = st + inc;
            nww[x] = st * ww[x] + inc * ww[x + sh];
            nrs[x] = st * rr[x] + inc * rr[x + sh];
        }
        occ = nocc;
        ww = nww;
        rs = nrs;
    }
    field[S] mut res = [0; S];
    for u32 x in 0..S { res[x] = w[x] + en * (SENTW + occ[x] * (ww[x] - SENTW) - w[x]); }
    return res;
}

// Textbook INSERT of key's value v at the prover-supplied one-hot position oh (checked:
// v_{pos-1} <= v < v_pos, sentinels above s), Delta = floor(2 eps n) = dnew, or 0 for a
// new minimum or maximum. Shifts the slots >= pos up by one; asserts no overflow.
def insert(field[S] w, field key, bool[S] oh, field dnew) -> field[S] {
    assert(w[S - 1] == SENTW);
    bool[32] kb = unpack::<32>(key);
    field mut v = 0;
    for u32 a in 0..21 { v = v + (kb[31 - a] ? 2**a : 0); }
    field mut cnt = 0;
    field mut hi = 0;
    for u32 j in 0..S {
        cnt = cnt + (oh[j] ? 1 : 0);
        hi = hi + (oh[j] ? w[j] : 0);
    }
    assert(cnt == 1);
    field mut lo = 0;
    for u32 j in 0..S - 1 { lo = lo + (oh[j + 1] ? w[j] : 0); }
    // v(lo) <= v  <=>  lo < (v+1) 2^(2L);   v < v(hi)  <=>  hi >= (v+1) 2^(2L)
    // ZoKrates 0.8.8 drops an unpack whose bits are never read, so every pure range check
    // re-packs its bits and asserts equality (range_check below).
    assert(range_check::<WB>((v + 1) * TWO2L - 1 - lo));
    assert(range_check::<WB>(hi - (v + 1) * TWO2L));
    field ismax = hi == SENTW ? 1 : 0;
    field e0 = oh[0] ? 1 : 0;
    field dn = ((1 - e0) * (1 - ismax)) * dnew;
    field neww = v * TWO2L + TWOL + dn;
    field[S] mut out = [0; S];
    out[0] = w[0] + e0 * (neww - w[0]);
    field mut ge = e0;
    for u32 j in 1..S {
        field e = oh[j] ? 1 : 0;
        ge = ge + e;
        out[j] = w[j] + ge * (w[j - 1] - w[j]) + e * (neww - w[j - 1]);
    }
    return out;
}

def main(field com_in, field batch_com, private field salt_in, private field n_in, private field[S] w_in, private field[K] keys, private bool[K][S] oh, private field salt_out) -> field {
    assert(commit(n_in, w_in, salt_in) == com_in);
    assert(digest(keys) == batch_com);
    bool[NB] nb = unpack::<NB>(n_in);
    // chunks hold K records, so n_in is a multiple of 2^ALB = min(K, E/2)
    for u32 a in 0..ALB { assert(!nb[NB - 1 - a]); }
    field mut p0 = 0;
    for u32 a in EL - 1..NB { p0 = p0 + (nb[NB - 1 - a] ? 2**(a - EL + 1) : 0); }
    // COMPRESS runs before a record iff n = 0 mod E/2. With K >= E/2 that is every E/2
    // records from the chunk start (en = 1); with K < E/2 only at record 0 and only
    // when n_in = 0 mod E/2.
    field mut en = 1;
    for u32 a in ALB..EL - 1 { en = en * (nb[NB - 1 - a] ? 0 : 1); }
    field[S] mut w = w_in;
    field mut n = n_in;
    field mut pc = p0;
    for u32 c in 0..NC {
        w = compress(w, n, pc, en);
        for u32 r in 0..RPC {
            w = insert(w, keys[c * RPC + r], oh[c * RPC + r], pc);
            n = n + 1;
        }
        pc = pc + 1;
    }
    assert(range_check::<NB>(n));
    return commit(n, w, salt_out);
}
