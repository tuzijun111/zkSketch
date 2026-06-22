//! **HyperLogLog sparse-rebind leaf with a Merkle-root state commitment**
//! (plonky3 / STARK) — the §5.2 sparse-opening commit applied to HLL.
//!
//! HLL's register array `m = 2^b` grows with the accuracy target (≈2¹⁴ for ~1%
//! error), like Count-Min's width `w`. The flat HLL circuit
//! ([`super::hll_final_full`]) re-hashes all `m` registers per epoch (`Θ(m)`)
//! and scatters every record over every register (`O(m·batch)`). Here `Com(S)`
//! is a **Merkle root** over the `m` registers, and a batch touches only the
//! `T ≤ min(batch, m)` distinct registers its keys route to — so the rebind is
//! `Θ(T·log m)`, **independent of `m`**.
//!
//! It is structurally the single-tree Count-Min Merkle leaf
//! ([`super::countmin_merkle`] at `d = 1`), with two HLL-specific changes:
//! - the cell "value" is the **derived rank** `ρ = 1 + trailing_zeros(digest[1])`
//!   (re-derived in-circuit, so the prover can neither pick the register nor
//!   inflate ρ), not a supplied count; and
//! - the per-register aggregation is a **max** — `new = max(old, {ρ routed})`,
//!   enforced by a product-of-differences + range gadget — instead of a sum.
//!
//! Register routing (`idx = digest[0] mod m`) and ρ derivation come from the
//! first hash output half `c0 = decompose(hashed[0])` (`digest[i] = c0[i]`),
//! matching [`super::hll_final_full`]. The flat HLL circuit remains the baseline.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Range-check window for the rank/register comparisons. `ρ ≤ Val::bits()+1`
/// and registers hold a rank, so both stay well under `2^RANK_BITS`.
const RANK_BITS: usize = 8;

fn val_bits() -> usize {
    Val::bits()
}

// ─── Parameters ────────────────────────────────────────────────────────────

/// Shape of a sparse-rebind HLL leaf: `m = 2^b` registers, `batch` records per
/// epoch, capacity `t_max` for distinct touched registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HllMerkleParams {
    /// Register-index bits; `m = 2^b` registers.
    pub b: usize,
    /// Records per epoch.
    pub batch: usize,
    /// Compile-time bound on distinct touched registers (`1 ≤ t_max ≤ m`).
    pub t_max: usize,
}

impl HllMerkleParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }
    pub fn validate(&self) {
        assert!(self.b >= 1 && self.b <= 16, "b in [1,16]; got {}", self.b);
        assert!(self.batch >= 1, "batch must be positive");
        assert!(self.t_max >= 1 && self.t_max <= self.m(), "t_max in [1, m]");
    }
    /// Merkle tree height = `b`.
    pub fn height(&self) -> usize {
        self.b
    }
}

// ─── Native hashing (must match the in-circuit gadget bit-for-bit) ──────────

fn leaf_digest(v: u64) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let input = [Val::from_u64(v), Val::ZERO, Val::ZERO, Val::ZERO];
    hasher.hash_iter(input.iter().copied())
}

fn node_digest(left: &[Val; 8], right: &[Val; 8]) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let input: Vec<Val> = left.iter().chain(right.iter()).copied().collect();
    hasher.hash_iter(input.iter().copied())
}

/// Merkle root over `m` register cells.
pub fn merkle_root(cells: &[u64]) -> [Val; 8] {
    assert!(cells.len().is_power_of_two() && !cells.is_empty());
    let mut level: Vec<[Val; 8]> = cells.iter().map(|&c| leaf_digest(c)).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| node_digest(&p[0], &p[1])).collect();
    }
    level[0]
}

fn merkle_siblings(cells: &[u64], pos: usize) -> Vec<[Val; 8]> {
    let height = cells.len().trailing_zeros() as usize;
    let mut level: Vec<[Val; 8]> = cells.iter().map(|&c| leaf_digest(c)).collect();
    let mut idx = pos;
    let mut sibs = Vec::with_capacity(height);
    for _ in 0..height {
        sibs.push(level[idx ^ 1]);
        idx >>= 1;
        level = level.chunks(2).map(|p| node_digest(&p[0], &p[1])).collect();
    }
    sibs
}

/// Native register routing: `idx = digest[0] mod m`, `ρ = 1 +
/// trailing_zeros(digest[1])` over the `val_bits()` window — mirrors the
/// in-circuit derivation (digest = `MyHash([key, 0, 0, 0])`).
pub fn route(key: u64, m: usize) -> (usize, u32) {
    let digest = leaf_digest(key); // = MyHash([key,0,0,0])
    let idx = (<Val as PrimeField64>::as_canonical_u64(&digest[0]) % m as u64) as usize;
    let tail = <Val as PrimeField64>::as_canonical_u64(&digest[1]);
    let nbits = val_bits() as u32;
    let mut tz = 0u32;
    while tz < nbits && (tail >> tz) & 1 == 0 {
        tz += 1;
    }
    (idx, tz + 1)
}

fn pack_digest(d: &[Val; 8]) -> [Challenge; 2] {
    [
        Challenge::from_basis_coefficients_slice(&d[0..4]).expect("4 coeffs"),
        Challenge::from_basis_coefficients_slice(&d[4..8]).expect("4 coeffs"),
    ]
}

// ─── Public proof type ──────────────────────────────────────────────────────

pub struct HllMerkleProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: CountMinCommit,
    pub final_: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub params: HllMerkleParams,
}

impl HllMerkleProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

// ─── Prover ──────────────────────────────────────────────────────────────────

/// Prove one HLL sparse-rebind epoch over an `m`-register array. `initial` is
/// the `m` register values; `keys` is `params.batch` record keys.
pub fn prove_hll_merkle_leaf(
    params: HllMerkleParams,
    initial: Vec<u64>,
    keys: Vec<u64>,
) -> HllMerkleProof {
    params.validate();
    let HllMerkleParams { batch: m_batch, t_max, .. } = params;
    let m = params.m();
    assert_eq!(initial.len(), m, "initial registers != m");
    assert_eq!(keys.len(), m_batch, "keys length != batch");
    let h = params.height();
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

    // ─── Native side: route + max-fold into the distinct touched registers ───
    let mut cells: Vec<u64> = initial.clone();
    let mut op_pos: Vec<usize> = Vec::new();
    let mut record_op = vec![0usize; m_batch];
    let mut rho = vec![0u32; m_batch];
    for (k, &key) in keys.iter().enumerate() {
        let (idx, r) = route(key, m);
        rho[k] = r;
        let c = op_pos.iter().position(|&q| q == idx).unwrap_or_else(|| {
            op_pos.push(idx);
            op_pos.len() - 1
        });
        record_op[k] = c;
    }
    assert!(op_pos.len() <= t_max, "touched registers {} exceed t_max {}", op_pos.len(), t_max);

    let init_root = merkle_root(&cells);
    let mut op_old = vec![0u64; t_max];
    let mut op_new = vec![0u64; t_max];
    let mut op_active = vec![0u64; t_max];
    let mut op_used_pos = vec![0usize; t_max];
    let mut op_siblings: Vec<Vec<[Val; 8]>> = Vec::with_capacity(t_max);
    let mut snap: Vec<u64> = cells.clone();
    for c in 0..t_max {
        let (pos, active) = if c < op_pos.len() { (op_pos[c], 1u64) } else { (0usize, 0u64) };
        let routed_max = keys
            .iter()
            .enumerate()
            .filter(|(k, _)| active == 1 && record_op[*k] == c)
            .map(|(k, _)| rho[k] as u64)
            .max()
            .unwrap_or(0);
        op_used_pos[c] = pos;
        op_old[c] = cells[pos];
        op_new[c] = cells[pos].max(routed_max);
        op_active[c] = active;
        op_siblings.push(merkle_siblings(&snap, pos));
        snap[pos] = op_new[c];
        cells[pos] = op_new[c];
    }
    let final_root = *([merkle_root(&cells)].last().unwrap());

    // Batch commitment over the keys (one Challenge each).
    let batch_commit: [Val; 8] = {
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = keys
            .iter()
            .flat_map(|&k| [Val::from_u64(k), Val::ZERO, Val::ZERO, Val::ZERO])
            .collect();
        hasher.hash_iter(flat.iter().copied())
    };

    // ─── Build circuit ───────────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    let init_root_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_root_lo" } else { "init_root_hi" })
    });
    let final_root_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_root_lo" } else { "final_root_hi" })
    });
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let pow2: Vec<ExprId> =
        (0..h).map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j")).collect();

    // Private witnesses (allocation order MUST match the value push order).
    let key_coeff: Vec<ExprId> = (0..m_batch).map(|_| b.alloc_private_input("key_coeff")).collect();
    let keys_t: Vec<ExprId> = (0..m_batch)
        .map(|k| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero, zero, zero])
                .expect("recompose key")
        })
        .collect();
    let key_h0: Vec<ExprId> = (0..m_batch).map(|_| b.alloc_private_input("key_h0")).collect();
    let key_h1: Vec<ExprId> = (0..m_batch).map(|_| b.alloc_private_input("key_h1")).collect();
    let sel: Vec<Vec<ExprId>> = (0..m_batch)
        .map(|_| (0..t_max).map(|_| b.alloc_private_input("sel")).collect())
        .collect();
    let op_old_w: Vec<ExprId> = (0..t_max).map(|_| b.alloc_private_input("op_old")).collect();
    let op_new_w: Vec<ExprId> = (0..t_max).map(|_| b.alloc_private_input("op_new")).collect();
    let op_active_w: Vec<ExprId> = (0..t_max).map(|_| b.alloc_private_input("op_active")).collect();
    let op_pos_bits: Vec<Vec<ExprId>> = (0..t_max)
        .map(|_| (0..h).map(|_| b.alloc_private_input("op_pos_bit")).collect())
        .collect();
    let op_sib: Vec<Vec<[ExprId; 2]>> = (0..t_max)
        .map(|_| {
            (0..h)
                .map(|_| [b.alloc_private_input("sib_lo"), b.alloc_private_input("sib_hi")])
                .collect()
        })
        .collect();

    // ── S1: batch commitment over keys ───────────────────────────────────────
    let hb = b.add_hash_slice(&cfg, &keys_t, true).expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_commit_pis[i]);
    }

    // op_active boolean + per-op register position from its bits.
    let mut op_pos_val: Vec<ExprId> = Vec::with_capacity(t_max);
    for c in 0..t_max {
        let am1 = b.sub(op_active_w[c], one);
        let chk = b.mul(op_active_w[c], am1);
        b.connect(chk, zero);
        let mut p = zero;
        for j in 0..h {
            let bm1 = b.sub(op_pos_bits[c][j], one);
            let bchk = b.mul(op_pos_bits[c][j], bm1);
            b.connect(bchk, zero);
            p = b.mul_add(op_pos_bits[c][j], pow2[j], p);
        }
        op_pos_val.push(p);
    }

    // ── S2: per record, derive (idx, ρ) from the key hash; route via one-hot ─
    let mut rho_c: Vec<ExprId> = Vec::with_capacity(m_batch);
    for k in 0..m_batch {
        let hashed = b.add_hash_slice(&cfg, &[keys_t[k]], true).expect("hash key");
        b.connect(hashed[0], key_h0[k]);
        b.connect(hashed[1], key_h1[k]);
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(key_h0[k]).expect("decompose h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(key_h1[k]).expect("decompose h1");
        // idx = digest[0] mod m = bottom b bits of c0[0].
        let idx_bits = b.decompose_to_bits::<Val>(c0[0], val_bits()).expect("bits digest0");
        let mut idx = zero;
        for j in 0..h {
            idx = b.mul_add(idx_bits[j], pow2[j], idx);
        }
        // ρ = 1 + trailing_zeros(digest[1]) = 1 + Σ_k ∏_{i≤k}(1 − bit_i) over c0[1].
        let dbits = b.decompose_to_bits::<Val>(c0[1], val_bits()).expect("bits digest1");
        let mut acc_zero = b.sub(one, dbits[0]);
        let mut tz = acc_zero;
        for k2 in 1..val_bits() {
            let omb = b.sub(one, dbits[k2]);
            acc_zero = b.mul(acc_zero, omb);
            tz = b.add(tz, acc_zero);
        }
        rho_c.push(b.add(tz, one));
        // Consume the remaining decompose coeffs (every coeff must flow through
        // an ALU lhs — decompose_to_bits does).
        for idx2 in 2..4 {
            let _ = b.decompose_to_bits::<Val>(c0[idx2], val_bits()).expect("consume c0");
        }
        for idx2 in 0..4 {
            let _ = b.decompose_to_bits::<Val>(c1[idx2], val_bits()).expect("consume c1");
        }
        // sel[k] one-hot; route pos + active.
        let mut sum = zero;
        let mut routed_pos = zero;
        let mut routed_active = zero;
        for c in 0..t_max {
            let s = sel[k][c];
            let sm1 = b.sub(s, one);
            let chk = b.mul(s, sm1);
            b.connect(chk, zero);
            sum = b.add(sum, s);
            routed_pos = b.mul_add(s, op_pos_val[c], routed_pos);
            routed_active = b.mul_add(s, op_active_w[c], routed_active);
        }
        b.connect(sum, one);
        b.connect(routed_pos, idx);
        b.connect(routed_active, one);
    }

    // ── S3: per-op max — new = max(old, {ρ_k routed}) (product-of-differences) ─
    for c in 0..t_max {
        // new ≥ old.
        let d0 = b.sub(op_new_w[c], op_old_w[c]);
        let _ = b.decompose_to_bits::<Val>(d0, RANK_BITS).expect("new>=old");
        let mut prod = d0;
        for k in 0..m_batch {
            // cand_k = old + sel·(ρ_k − old)  (= ρ_k if routed, else old).
            let rho_minus_old = b.sub(rho_c[k], op_old_w[c]);
            let scaled = b.mul(sel[k][c], rho_minus_old);
            let cand = b.add(op_old_w[c], scaled);
            let diff = b.sub(op_new_w[c], cand);
            let _ = b.decompose_to_bits::<Val>(diff, RANK_BITS).expect("new>=cand");
            prod = b.mul(prod, diff);
        }
        b.connect(prod, zero); // new is one of {old} ∪ {ρ_k routed}
    }

    // ── S5: Merkle update chain (thread NPO roots; sub-trick across ops) ─────
    let mut prev_root: [ExprId; 2] = init_root_pis;
    for c in 0..t_max {
        let old_root = climb_merkle_path(&mut b, &cfg, op_old_w[c], &op_pos_bits[c], &op_sib[c]);
        if c == 0 {
            b.connect(old_root[0], prev_root[0]);
            b.connect(old_root[1], prev_root[1]);
        } else {
            for l in 0..2 {
                let diff = b.sub(old_root[l], prev_root[l]);
                b.connect(diff, zero);
            }
        }
        let new_root = climb_merkle_path(&mut b, &cfg, op_new_w[c], &op_pos_bits[c], &op_sib[c]);
        prev_root = new_root;
    }
    b.connect(prev_root[0], final_root_pis[0]);
    b.connect(prev_root[1], final_root_pis[1]);

    let circuit = b.build().expect("build hll merkle leaf circuit");

    // ─── Pack public + private values (same order as allocation) ─────────────
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&pack_digest(&init_root));
    public_inputs.extend_from_slice(&pack_digest(&final_root));
    public_inputs.extend_from_slice(&pack_digest(&batch_commit));

    let mut private_inputs: Vec<Challenge> = Vec::new();
    for &k in &keys {
        private_inputs.push(Challenge::from_u64(k)); // key_coeff
    }
    {
        let hasher = MyHash::new(make_perm());
        let digs: Vec<[Challenge; 2]> = keys
            .iter()
            .map(|&k| {
                let input = [Val::from_u64(k), Val::ZERO, Val::ZERO, Val::ZERO];
                pack_digest(&hasher.hash_iter(input.iter().copied()))
            })
            .collect();
        for d in &digs {
            private_inputs.push(d[0]); // key_h0 block
        }
        for d in &digs {
            private_inputs.push(d[1]); // key_h1 block
        }
    }
    for k in 0..m_batch {
        for c in 0..t_max {
            private_inputs.push(if record_op[k] == c { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    for c in 0..t_max {
        private_inputs.push(Challenge::from_u64(op_old[c]));
    }
    for c in 0..t_max {
        private_inputs.push(Challenge::from_u64(op_new[c]));
    }
    for c in 0..t_max {
        private_inputs.push(Challenge::from_u64(op_active[c]));
    }
    for c in 0..t_max {
        for j in 0..h {
            let bit = (op_used_pos[c] >> j) & 1;
            private_inputs.push(if bit == 1 { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    for c in 0..t_max {
        for j in 0..h {
            let [lo, hi] = pack_digest(&op_siblings[c][j]);
            private_inputs.push(lo);
            private_inputs.push(hi);
        }
    }

    // ─── Run + prove ─────────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run hll merkle circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false)];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (hll merkle)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&dd| dd + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove hll merkle");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify hll merkle leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&dd| 1u64 << dd).sum(),
    });

    let _ = pack_commit_to_challenge;

    HllMerkleProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: CountMinCommit(init_root),
        final_: CountMinCommit(final_root),
        batch_commit: CountMinCommit(batch_commit),
        params,
    }
}

// ─── In-circuit Merkle path gadget (identical to countmin_merkle) ────────────

fn climb_merkle_path(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    leaf_val: ExprId,
    pos_bits: &[ExprId],
    siblings: &[[ExprId; 2]],
) -> [ExprId; 2] {
    let leaf_d = b.add_hash_slice(cfg, &[leaf_val], true).expect("leaf hash");
    let mut cur: [ExprId; 2] = [leaf_d[0], leaf_d[1]];
    for (level, sib) in siblings.iter().enumerate() {
        let bit = pos_bits[level];
        let mut lo = [cur[0]; 2];
        let mut hi = [cur[0]; 2];
        for limb in 0..2 {
            let d = b.sub(cur[limb], sib[limb]);
            let bit_d = b.mul(bit, d);
            lo[limb] = b.sub(cur[limb], bit_d);
            hi[limb] = b.mul_add(bit, d, sib[limb]);
        }
        let parent = b.add_hash_slice(cfg, &[lo[0], lo[1], hi[0], hi[1]], true).expect("node hash");
        cur = [parent[0], parent[1]];
    }
    cur
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn native_apply(initial: &[u64], keys: &[u64], m: usize) -> Vec<u64> {
        let mut c = initial.to_vec();
        for &key in keys {
            let (idx, r) = route(key, m);
            if r as u64 > c[idx] {
                c[idx] = r as u64;
            }
        }
        c
    }

    #[test]
    fn hll_merkle_round_trip() {
        let params = HllMerkleParams { b: 6, batch: 4, t_max: 4 };
        let m = 1 << 6;
        let initial = vec![0u64; m];
        let keys = vec![7u64, 11, 7, 3];
        let proof = prove_hll_merkle_leaf(params, initial.clone(), keys.clone());
        assert_eq!(proof.final_.0, merkle_root(&native_apply(&initial, &keys, m)));
        assert_eq!(proof.initial.0, merkle_root(&initial));
    }

    /// Large register array, tiny batch: cost Θ(t_max·log m), not Θ(m).
    #[test]
    fn hll_merkle_large_state_small_patch() {
        let params = HllMerkleParams { b: 10, batch: 4, t_max: 4 };
        let m = 1 << 10;
        let initial = vec![0u64; m];
        let keys = vec![123u64, 777, 123, 9];
        let proof = prove_hll_merkle_leaf(params, initial.clone(), keys.clone());
        assert_eq!(proof.final_.0, merkle_root(&native_apply(&initial, &keys, m)));
    }

    /// Cost study: prove cost ~log(m) at fixed t_max, vs the flat HLL's Θ(m).
    #[test]
    #[ignore]
    fn hll_sparse_cost_is_sublinear() {
        use crate::recursion::recursive::timing;
        println!();
        println!("hll_merkle — sparse-rebind cost vs. register count m (t_max=4, batch=4)");
        println!("========================================================================");
        for &bb in &[4usize, 8, 12, 16] {
            let m = 1usize << bb;
            let params = HllMerkleParams { b: bb, batch: 4, t_max: 4 };
            let initial = vec![0u64; m];
            let keys: Vec<u64> = [1u64, 2, 3, 4].iter().map(|&k| k.wrapping_mul(0x9E37_79B9)).collect();
            let _ = prove_hll_merkle_leaf(params, initial, keys);
            let t = timing::take();
            println!("  m=2^{bb:<2} ({m:<6}) trace_rows={:<9} prove={:>9.2?}", t.trace_rows, t.prove);
        }
    }
}
