// WITNESS HELPER for gk_op.zok -- run through compute-witness only, never set up or proven.
// Gives the driver the three public values of one chunk without reimplementing BN254
// Poseidon: com_in = commit(n_in, w_in, salt_in), batch_com = digest(keys) and
// com_out = commit(n_out, w_out, salt_out), where (n_out, w_out) is the next summary
// computed by the driver's NATIVE textbook GK. The proven operator recomputes that summary
// in-circuit, so its output must equal this com_out: every chunk checks circuit == native.
// Same packed state layout, commitment and digest as gk_op.zok.tpl.
import "hashes/poseidon/poseidon" as poseidon;
const u32 K = __K__;
const u32 S = __S__;
const u32 NBC = __NBC__;
const u32 LC = __LC__;
const u32 NBB = __NBB__;
const u32 LB = __LB__;

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

def main(field n_in, field[S] w_in, field[K] keys, field salt_in, field n_out, field[S] w_out, field salt_out) -> (field, field, field) {
    return (commit(n_in, w_in, salt_in), digest(keys), commit(n_out, w_out, salt_out));
}
