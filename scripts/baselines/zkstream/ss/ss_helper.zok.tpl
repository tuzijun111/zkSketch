// WITNESS HELPER for ss_op.zok -- run through compute-witness only, never set up or proven.
// Returns (com_in, batch_com, com_out) for a state transition that the driver's native
// SpaceSaving reference computed, so the driver need not reimplement BN254 Poseidon.
// The commitment and digest functions are copied verbatim from ss_op.zok.tpl. The
// driver then runs ss_op on the same inputs and requires its output (the commitment
// to the state the CIRCUIT computed) to equal this com_out, which cross-checks the
// native reference against the circuit's textbook update.
import "hashes/poseidon/poseidon" as poseidon;
const u32 N = __N__;
const u32 S = __S__;
const u32 CB = __CB__;
const u32 EB = __EB__;
const u32 SPE = __SPE__;
const u32 SW = __SW__;
const u32 NBC = __NBC__;
const u32 LC = __LC__;
const u32 NBB = __NBB__;
const u32 LB = __LB__;

def commit(field[S] k, field[S] c, field[S] e, field salt) -> field {
    field[LC] mut flat = [0; LC];
    for u32 i in 0..S { flat[i / SPE] = flat[i / SPE] + (k[i] + c[i] * 2**33 + e[i] * 2**EB) * 2**(SW * (i % SPE)); }
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

def main(field[S] k_in, field[S] c_in, field[S] e_in, field[N] keys, field salt_in, field[S] k_out, field[S] c_out, field[S] e_out, field salt_out) -> (field, field, field) {
    return (commit(k_in, c_in, e_in, salt_in), digest(keys), commit(k_out, c_out, e_out, salt_out));
}
