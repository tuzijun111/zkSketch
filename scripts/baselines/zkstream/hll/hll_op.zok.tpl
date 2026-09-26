// HyperLogLog update operator in zkStream's stateful-operator shape (zkStream Sec 4.4):
// open a salted commitment to the register array, apply one chunk of records with the
// textbook per-record HLL update, and check the commitment to the updated array.
// OUR circuit, following zkStream's design ("replay"); not zkStream code.
//
// Per record: h = Poseidon(key, 0) with a strict 254-bit unpack; register index = low B
// bits of h; rank = 1 + leading zeros of the next Q = 64-B bits (a 64-bit HLL hash
// word); R[idx] = max(R[idx], rank).
// State encoding: S = s/P words, each packing P registers of 6 bits (lane l of word w is
// register w*P + l; 6*P <= 192 bits, so a word has one bit decomposition).
// Update, per record: read the word with a mux tree over the slot bits, unpack it,
// read the lane with a mux tree over the lane bits, compare rank with the register
// (7-bit range decomposition), and add delta*2^(6*lane) to the selected word through a
// one-hot slot decoder whose root carries that value. Records are bound to a public
// batch digest. Commitment idiom = zkStream's salted Poseidon output hash
// (q4a.poseidon.zok producer, q4b.poseidon.zok:28-32 consumer). Public statement:
// (com_in, batch_com, com_out). Every CK-th updated state (and the last) is re-allocated
// as fresh wires (see hll_lib.zok.tpl), so constraint density stays bounded. Constants
// are rewritten textually by gen.sh, as zkStream does
// (nexmark/zokrates-nexmark/src/zokrates.rs:85-87).
from "./hll_lib" import N, S, CK, commit, digest, update;

def main(field com_in, field batch_com, field com_out, private field salt_in, private field[S] w_in, private field[N] keys, private field salt_out, private field one) {
    assert(one == 1);
    assert(commit(w_in, salt_in) == com_in);
    assert(digest(keys) == batch_com);
    field[S] mut w = w_in;
    for u32 i in 0..N { w = update(w, keys[i], one, (i + 1) % CK == 0 || i + 1 == N); }
    assert(commit(w, salt_out) == com_out);
    return;
}
