// SpaceSaving update operator in zkStream's stateful-operator shape (zkStream Sec 4.4,
// "replay"): open a salted commitment to the S counters, bind the chunk's records to a
// public batch digest, apply the TEXTBOOK SpaceSaving update record by record, emit the
// salted commitment to the updated counters. OUR circuit in zkStream's toolchain
// (ZoKrates 0.8.8, Groth16/BN254); not zkStream code.
//
// State: S slots (key, count, error). A stored key is key+1, so 0 marks an empty slot
// (empty <=> key 0, count 0, error 0); occupied slots have count >= 1.
// Per record x (v = x+1), with a prover-supplied one-hot slot selector sel (a hint the
// circuit fully checks):
//   z_i  = (K_i == v)       exact equality scan over all S keys, hit = sum z_i
//   sel  one-hot            sel_i in {0,1}, sum sel_i = 1
//   hit  => sel = z         z_i = 1 forces sel_i = 1: the key's own slot, no other slot equal
//   miss => key absent everywhere (every z_i = 0), and sel is a minimum-count slot:
//           C_i - C_j in [0, 2^CB) for every slot i. A free slot has count 0, so while
//           one exists this selects a free slot ("insert, count 1, error 0" = "replace
//           min, count min+1, error min"). Any minimum is accepted, as in the textbook
//           algorithm; the driver's prover picks the lowest index.
//   update: C_j += 1 (hit: +1; miss: min+1); miss: K_j = v, E_j = C_j(old).
// Counts stay below 2^CB (CB = 21 covers a 2^20-record stream, as zkSketch's SS does).
//
// Encoding: a slot is the SW-bit word K + C*2^33 + E*2^(33+CB) (SW = 75 at CB=21), and SPE
// slots share one field element for the commitment (SPE = 3: 225 bits < 254), so each
// Poseidon call absorbs 5*SPE slots. Opening range-checks ALL three limbs of every slot
// (K 33 bits, C and E CB bits each; E <= C always), so a packed element is < 2^(SW*SPE) < p
// and its decomposition is unique. (Leaving any limb unchecked lets it absorb an
// arbitrary change to the others mod p -- the driver's tamper case alias_error_absorbs_count.)
// Commitment idiom = zkStream's salted Poseidon output hash (q4a.poseidon.zok producer,
// q4b.poseidon.zok:28-32 consumer, shared.zok:224-230 hashOutputPoseidon).
// Constants are rewritten textually by gen.sh, as zkStream does (zokrates.rs:85-87).
import "hashes/poseidon/poseidon" as poseidon;
import "utils/pack/bool/unpack" as unpack;
import "utils/pack/bool/pack" as pack;
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
// ZoKrates inlines every linear combination, so an s-term running sum costs O(s^2)
// compile memory (and a k-record running update O(k) terms per use). Multiplying by the
// private input `one` (asserted == 1) every BS slots / MB records keeps them short.
// Cost: 5*ceil(s/BS) constraints per record + 2*s per MB records.
const u32 BS = 64;
const u32 MB = 16;

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

def main(field com_in, field batch_com, private field salt_in, private field[S] k_in, private field[S] c_in, private field[S] e_in, private field[N] keys, private field[N][S] sel, private field salt_out, private field one) -> field {
    assert(one == 1);
    // commit-in: canonical opening (K < 2^33, C < 2^CB, E < 2^CB) of the packed slots.
    // ZoKrates drops an unpack whose bits are never read, so the opened values are the
    // recomposed bits (strict: fewer than 254 bits, no wrap-around).
    field[S] mut K = [0; S];
    field[S] mut C = [0; S];
    field[S] mut E = [0; S];
    for u32 i in 0..S {
        K[i] = pack(unpack::<33>(k_in[i]));
        C[i] = pack(unpack::<CB>(c_in[i]));
        E[i] = pack(unpack::<CB>(e_in[i]));
    }
    assert(commit(K, C, E, salt_in) == com_in);
    assert(digest(keys) == batch_com);
    for u32 r in 0..N {
        field v = keys[r] + 1;
        field mut hit = 0;
        field mut ssum = 0;
        field mut kj = 0;
        field mut cj = 0;
        field mut ej = 0;
        for u32 i in 0..S {
            field z = K[i] == v ? 1 : 0;
            field si = sel[r][i];
            assert(si * si == si);
            assert(z * si == z);
            hit = hit + z;
            ssum = ssum + si;
            kj = kj + si * K[i];
            cj = cj + si * C[i];
            ej = ej + si * E[i];
            bool cut = i % BS == BS - 1;
            hit = if cut { hit * one } else { hit };
            ssum = if cut { ssum * one } else { ssum };
            kj = if cut { kj * one } else { kj };
            cj = if cut { cj * one } else { cj };
            ej = if cut { ej * one } else { ej };
        }
        assert(ssum == 1);
        // miss: C_j is a minimum. hit: the reference is 0 and the checks are vacuous.
        // The new count is rebuilt from the range-checked difference d = C_i - cref, which
        // keeps d's bits live without an extra equality constraint. cref, de and dk are
        // products, so ZoKrates keeps each as one variable instead of inlining an s-term
        // linear combination into all s slot updates (dk = v - kj is 0 on a hit anyway).
        field cref = (1 - hit) * cj;
        field de = (1 - hit) * (cj - ej);
        field dk = (1 - hit) * (v - kj);
        for u32 i in 0..S {
            field d = pack(unpack::<CB>(C[i] - cref));
            C[i] = d + cref + sel[r][i];
            E[i] = E[i] + sel[r][i] * de;
            K[i] = K[i] + sel[r][i] * dk;
            bool cutr = r % MB == MB - 1;
            E[i] = if cutr { E[i] * one } else { E[i] };
            K[i] = if cutr { K[i] * one } else { K[i] };
        }
    }
    return commit(K, C, E, salt_out);
}
