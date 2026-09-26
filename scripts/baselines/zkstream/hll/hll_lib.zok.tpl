// Shared body of hll_op.zok (proven) and hll_helper.zok (witness only): constants,
// the salted state commitment, the batch digest and the per-record HLL update.
// See hll_op.zok.tpl for the design. Instantiated by gen.sh.
import "hashes/poseidon/poseidon" as poseidon;
import "utils/pack/bool/unpack" as unpack;
const u32 N = __N__;
const u32 B = __B__;
const u32 Q = __Q__;
const u32 P = __P__;
const u32 LOGP = __LOGP__;
const u32 S = __S__;
const u32 LOGS = __LOGS__;
const u32 WB = __WB__;
const u32 NBC = __NBC__;
const u32 LC = __LC__;
const u32 NBB = __NBB__;
const u32 LB = __LB__;
const u32 CK = __CK__;

def commit(field[S] t, field salt) -> field {
    field[LC] mut flat = [0; LC];
    for u32 i in 0..S { flat[i] = t[i]; }
    field mut h = poseidon([salt]);
    for u32 b in 0..NBC { h = poseidon([h, flat[5*b], flat[5*b+1], flat[5*b+2], flat[5*b+3], flat[5*b+4]]); }
    return h;
}

def digest(field[N] keys) -> field {
    field[LB] mut flat = [0; LB];
    for u32 i in 0..N { flat[i] = keys[i]; }
    field mut h = 0;
    for u32 b in 0..NBB { h = poseidon([h, flat[5*b], flat[5*b+1], flat[5*b+2], flat[5*b+3], flat[5*b+4]]); }
    return h;
}

// One textbook HLL update. bits[253 - i] is bit i (LSB first) of h.
// `one` is a private input fixed to 1 by the operator; with `mat` set, each updated word
// is multiplied by it, which makes the compiler allocate a fresh wire per word instead
// of carrying w_in + (sum of all earlier writes) as an ever longer linear combination
// into every later read (that made compile memory and constraint density grow as k^2).
def update(field[S] w, field key, field one, bool mat) -> field[S] {
    field h = poseidon([key, 0]);
    bool[254] bits = unpack::<254>(h);
    // read the word: mux tree over slot bits LOGP..B-1, lowest slot bit first
    field[S] mut m = w;
    for u32 l in 0..LOGS {
        field sb = bits[253 - LOGP - l] ? 1 : 0;
        u32 sz = S >> (l + 1);
        for u32 j in 0..sz { m[j] = m[2*j] + sb * (m[2*j+1] - m[2*j]); }
    }
    bool[WB] wb = unpack::<WB>(m[0]);
    // lane values (6 bits each, lane l at weight 2^(6l)), then mux over lane bits 0..LOGP-1
    field[P] mut lv = [0; P];
    for u32 l in 0..P {
        field mut v = 0;
        field mut pw = 1;
        for u32 t in 0..6 {
            v = v + (wb[WB - 1 - 6*l - t] ? pw : 0);
            pw = pw * 2;
        }
        lv[l] = v;
    }
    for u32 l in 0..LOGP {
        field lb = bits[253 - l] ? 1 : 0;
        u32 sz = P >> (l + 1);
        for u32 j in 0..sz { lv[j] = lv[2*j] + lb * (lv[2*j+1] - lv[2*j]); }
    }
    field cur = lv[0];
    // rank = 1 + leading zeros of bits B+Q-1 .. B
    field mut z = 1;
    field mut rank = 1;
    for u32 i in 0..Q {
        z = z * (bits[253 - (B + Q - 1 - i)] ? 0 : 1);
        rank = rank + z;
    }
    // max: rank <= Q+1 <= 61 and cur <= 63, so rank - cur + 63 is in [1, 124]
    bool[7] cb = unpack::<7>(rank - cur + 63);
    field delta = (cb[0] ? 1 : 0) * (rank - cur);
    // lane weight 2^(6*lane) from the lane bits
    field mut lw = 1;
    field mut fac = 64;
    for u32 l in 0..LOGP {
        lw = lw * (bits[253 - l] ? fac : 1);
        fac = fac * fac;
    }
    // write: one-hot slot decoder rooted at delta*2^(6*lane), highest slot bit first
    field[S] mut oh = [0; S];
    oh[0] = lw * delta;
    for u32 l in 0..LOGS {
        field sb = bits[253 - LOGP - (LOGS - 1 - l)] ? 1 : 0;
        u32 sz = 1 << l;
        for u32 jj in 0..sz {
            u32 j = sz - 1 - jj;
            field hi = oh[j] * sb;
            oh[2*j+1] = hi;
            oh[2*j] = oh[j] - hi;
        }
    }
    field[S] mut out = w;
    for u32 j in 0..S { out[j] = mat ? (w[j] + oh[j]) * one : w[j] + oh[j]; }
    return out;
}
