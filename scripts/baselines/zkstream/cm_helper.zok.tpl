// WITNESS HELPER for cm_op.zok -- run through compute-witness only, never set up or proven.
// open a salted commitment to the table, apply one chunk of records, emit the
// commitment to the updated table. OUR circuit, following their design; not zkStream code.
//
// Encoding ("packed8"): D rows x S = W/8 slots; each slot packs 8 lanes of 21-bit
// counters (8*21 = 168 < 254 bits), so a counter overflows past 2^21-1 hits.
// Column (log2 W bits) = slot (LOGS bits, in-place tree decoder) + lane (3 bits,
// weight 2^(21*lane)). Records are bound to a public batch digest, like zkSketch's
// batch commitment. Commitment idiom = zkStream's salted Poseidon output hash
// (q4a.poseidon.zok producer, q4b.poseidon.zok:28-32 consumer).
// Constants are rewritten textually by gen.sh, as zkStream does (zokrates.rs:85-87).
import "hashes/poseidon/poseidon" as poseidon;
import "utils/pack/bool/unpack" as unpack;
const u32 N = __N__;
const u32 D = __D__;
const u32 S = __S__;
const u32 LOGS = __LOGS__;
const u32 RB = __RB__;
const u32 NBC = __NBC__;
const u32 LC = __LC__;
const u32 NBB = __NBB__;
const u32 LB = __LB__;

def commit(field[D][S] t, field salt) -> field {
    field[LC] mut flat = [0; LC];
    for u32 r in 0..D { for u32 s in 0..S { flat[r*S+s] = t[r][s]; } }
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

def main(field[D][S] t_in, field[N] keys, field salt_in, field salt_out) -> (field, field, field[D][S], field) {
    field com_in = commit(t_in, salt_in);
    field batch_com = digest(keys);
    field[D][S] mut t = t_in;
    for u32 i in 0..N {
        field h = poseidon([keys[i], 0]);
        bool[254] bits = unpack::<254>(h);
        for u32 r in 0..D {
            field[S] mut oh = [0; S];
            oh[0] = 1;
            for u32 l in 0..LOGS {
                u32 sz = 1 << l;
                for u32 jj in 0..sz {
                    u32 j = sz - 1 - jj;
                    field hi = oh[j] * (bits[253 - r*RB - l] ? 1 : 0);
                    oh[2*j+1] = hi;
                    oh[2*j] = oh[j] - hi;
                }
            }
            field f0 = 1 + (bits[253 - r*RB - LOGS] ? 1 : 0) * (2**21 - 1);
            field f1 = 1 + (bits[253 - r*RB - LOGS - 1] ? 1 : 0) * (2**42 - 1);
            field f2 = 1 + (bits[253 - r*RB - LOGS - 2] ? 1 : 0) * (2**84 - 1);
            field wgt = f0 * f1 * f2;
            for u32 s in 0..S { t[r][s] = t[r][s] + oh[s] * wgt; }
        }
    }
    return (com_in, batch_com, t, commit(t, salt_out));
}
