// WITNESS HELPER for hll_op.zok -- run through compute-witness only, never set up or proven.
// Imports the same commit/digest/update functions as the operator (hll_lib.zok), so the state it returns is
// exactly the one hll_op.zok computes; it turns the operator's asserts into outputs:
// (com_in, batch_com, next packed state, com_out). The driver uses it only to obtain the
// public statement for the proven operator and cross-checks it against native.py.
from "./hll_lib" import N, S, CK, commit, digest, update;

def main(field[S] w_in, field[N] keys, field salt_in, field salt_out, field one) -> (field, field, field[S], field) {
    field com_in = commit(w_in, salt_in);
    field batch_com = digest(keys);
    field[S] mut w = w_in;
    for u32 i in 0..N { w = update(w, keys[i], one, (i + 1) % CK == 0 || i + 1 == N); }
    return (com_in, batch_com, w, commit(w, salt_out));
}
