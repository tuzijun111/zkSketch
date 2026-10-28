//! One-hot HyperLogLog update leaf; register index and rank are computed in-circuit from Poseidon(key).

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;

use crate::config::{C, D, F};
use crate::recursion::Node;
use crate::sketch::hyperloglog::{hash_register, HllState, HllUpdate, RHO_WINDOW};

/// Register width in bits. For `b >= 2`, leading-runs are `<= 63`, so 6 bits suffice.
pub const REGISTER_WIDTH: usize = 6;

/// Per-leaf shape: `m = 2^b` registers, `batch` records per epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HllLeafParams {
    pub b: usize,
    pub batch: usize,
}

impl HllLeafParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }
    pub fn validate(&self) {
        assert!(self.b >= 2, "b must be >= 2");
        assert!(self.batch >= 1, "batch must be positive");
    }
}

impl Default for HllLeafParams {
    fn default() -> Self {
        Self { b: 3, batch: 2 }
    }
}

struct HllTargets {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    /// Raw keys per record — **private**, opened from `batch_commit`; `(idx, ρ)`
    /// are derived from each key in-circuit.
    keys: Vec<Target>,
    init_regs: Vec<Target>,
    final_regs: Vec<Target>,
    /// `selectors[k][r]`.
    selectors: Vec<Vec<Target>>,
}

/// A built, reusable HLL leaf circuit.
pub struct HllLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: HllTargets,
    pub params: HllLeafParams,
}

fn virtual_hash(b: &mut CircuitBuilder<F, D>) -> HashOutTarget {
    HashOutTarget { elements: core::array::from_fn(|_| b.add_virtual_target()) }
}

/// Canonical little-endian 64-bit decomposition of a Goldilocks element.
///
/// `split_le(_, 64)` alone is **ambiguous near the field wraparound**: when
/// `x < 2^64 − p` (≈ `2^32`), both `x` and `x + p` are valid 64-bit residues with
/// different low bits, which would let a grinding prover pick between two register
/// routings. Goldilocks `p − 1 = 0xFFFFFFFF_00000000`, so a 64-bit value is
/// canonical (`< p`) unless its high 32 bits are all 1 **and** some low 32 bit is
/// set; we forbid exactly that, pinning the unique canonical bits.
fn canonical_bits_64(b: &mut CircuitBuilder<F, D>, x: Target) -> Vec<BoolTarget> {
    let bits = b.split_le(x, 64);
    let one = b.one();
    let zero = b.zero();
    let mut all_hi = one; // 1 iff bits[32..64] are all 1
    for bit in bits.iter().skip(32) {
        all_hi = b.mul(all_hi, bit.target);
    }
    let mut none_lo = one; // 1 iff bits[0..32] are all 0
    for bit in bits.iter().take(32) {
        let omb = b.sub(one, bit.target);
        none_lo = b.mul(none_lo, omb);
    }
    let any_lo = b.sub(one, none_lo);
    let bad = b.mul(all_hi, any_lo); // (all high ones) AND (some low one) ⇒ ≥ p
    b.connect(bad, zero);
    bits
}

/// Build the HLL update circuit for the given shape.
pub fn build_hll_leaf(params: HllLeafParams) -> HllLeaf {
    params.validate();
    let m = params.m();
    let batch = params.batch;
    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());

    // ---- Public inputs: (Com(S_{t-1}), Com(S_t), Com(B_t)) ----
    // Same `[initial | final]` 8-element prefix as every other leaf, so
    // `crate::recursion::merge` treats all families uniformly; `batch_commit`
    // follows, matching the CM/SS/GK leaves and zk1.tex's leaf interface
    // `(r_t, Com(S_{t-1}), Com(B_t), Com(S_t))`.
    let init_commit = virtual_hash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = virtual_hash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = virtual_hash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Private witness: batch keys (opened from Com(B_t)), registers ----
    // Only the raw keys are witnessed; the (register index, leading-run) are
    // DERIVED in-circuit from each key (the S2 routing), so the committed batch
    // fully determines the update — matching the plonky3 `hll_final_full`.
    let keys = b.add_virtual_targets(batch);
    let init_regs = b.add_virtual_targets(m);
    let final_regs = b.add_virtual_targets(m);
    let mut selectors = Vec::with_capacity(batch);
    for _ in 0..batch {
        selectors.push(b.add_virtual_targets(m));
    }

    // ---- Constraint 1: open the batch (over keys) + bind the state commitments ----
    let hb = b.hash_n_to_hash_no_pad::<PoseidonHash>(keys.clone());
    for i in 0..4 {
        b.connect(hb.elements[i], batch_commit.elements[i]);
    }
    let hi = b.hash_n_to_hash_no_pad::<PoseidonHash>(init_regs.clone());
    for i in 0..4 {
        b.connect(hi.elements[i], init_commit.elements[i]);
    }
    let hf = b.hash_n_to_hash_no_pad::<PoseidonHash>(final_regs.clone());
    for i in 0..4 {
        b.connect(hf.elements[i], final_commit.elements[i]);
    }

    let one = b.one();
    let zero = b.zero();
    let rconsts: Vec<Target> = (0..m).map(|r| b.constant(F::from_canonical_u64(r as u64))).collect();
    let pow2b: Vec<Target> = (0..params.b).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();

    // ---- Constraint 2: derive (idx, ρ) from each key in-circuit, bind selector ----
    // `digest = Poseidon(key)`; `idx = digest[0] mod 2^b` (low b bits);
    // `ρ = 1 + trailing_zeros(digest[1])` over `RHO_WINDOW` bits via a running
    // product. Mirrors `sketch::hyperloglog::hash_register` exactly.
    let mut lrs = Vec::with_capacity(batch);
    for k in 0..batch {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![keys[k]]);
        let d0_bits = canonical_bits_64(&mut b, digest.elements[0]);
        let mut idx_t = zero;
        for j in 0..params.b {
            idx_t = b.mul_add(d0_bits[j].target, pow2b[j], idx_t);
        }
        // selector one-hot, picking the derived register `idx_t`.
        for r in 0..m {
            let s = selectors[k][r];
            let sm1 = b.sub(s, one);
            let prod = b.mul(s, sm1);
            b.connect(prod, zero); // boolean
        }
        let mut sum = selectors[k][0];
        for r in 1..m {
            sum = b.add(sum, selectors[k][r]);
        }
        b.connect(sum, one); // one-hot
        let mut weighted = zero;
        for r in 0..m {
            weighted = b.mul_add(selectors[k][r], rconsts[r], weighted);
        }
        b.connect(weighted, idx_t); // selected register == derived idx
        // ρ = 1 + trailing_zeros(digest[1]) over the low RHO_WINDOW bits.
        let d1_bits = canonical_bits_64(&mut b, digest.elements[1]);
        let mut prod = one;
        let mut tz = zero;
        for bit in d1_bits.iter().take(RHO_WINDOW) {
            let omb = b.sub(one, bit.target);
            prod = b.mul(prod, omb); // ∏_{j<=i}(1 - bit_j)
            tz = b.add(tz, prod);
        }
        lrs.push(b.add(one, tz));
    }

    // ---- Constraint 3: per-register max (product-of-differences + range) ----
    for r in 0..m {
        // Factor for the "keep initial" candidate, and range-check final >= initial.
        let mut prod = b.sub(final_regs[r], init_regs[r]);
        let _ = b.split_le(prod, REGISTER_WIDTH);
        for k in 0..batch {
            // candidate_k = initial[r] + selector[k][r] * (ρ_k - initial[r])
            let lr_minus_init = b.sub(lrs[k], init_regs[r]);
            let scaled = b.mul(selectors[k][r], lr_minus_init);
            let cand = b.add(init_regs[r], scaled);
            let diff = b.sub(final_regs[r], cand);
            let _ = b.split_le(diff, REGISTER_WIDTH); // final >= candidate_k
            prod = b.mul(prod, diff);
        }
        b.connect(prod, zero); // final[r] is one of the candidates
    }

    let data = Arc::new(crate::config::build_circuit(b));
    HllLeaf {
        data,
        t: HllTargets { init_commit, final_commit, batch_commit, keys, init_regs, final_regs, selectors },
        params,
    }
}

impl HllLeaf {
    /// Prove one HLL epoch. `index` is the 1-based leaf position.
    pub fn prove(&self, initial: &HllState, batch: &[HllUpdate], index: u64) -> Result<Node> {
        self.prove_timed(initial, batch, index).map(|(n, _, _)| n)
    }

    /// Like [`prove`](Self::prove) but also returns `(witness_gen, prove)`
    /// durations — the EVAL_SPEC §1 phase split.
    pub fn prove_timed(
        &self,
        initial: &HllState,
        batch: &[HllUpdate],
        index: u64,
    ) -> Result<(Node, std::time::Duration, std::time::Duration)> {
        let t_w = std::time::Instant::now();
        assert_eq!(batch.len(), self.params.batch, "batch length mismatch");
        assert_eq!(initial.b, self.params.b, "state.b mismatch");

        let mut final_state = initial.clone();
        for u in batch {
            final_state.update(u);
        }
        let init_commit = initial.commit();
        let final_commit = final_state.commit();

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        // Com(B_t) over the raw keys (idx/ρ are derived in-circuit from each key).
        let keys_f: Vec<F> = batch.iter().map(|u| F::from_canonical_u64(u.key)).collect();
        let batch_commit = PoseidonHash::hash_no_pad(&keys_f);
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;
        for (t, v) in self.t.keys.iter().zip(&keys_f) {
            pw.set_target(*t, *v)?;
        }
        for (t, v) in self.t.init_regs.iter().zip(initial.cells()) {
            pw.set_target(*t, v)?;
        }
        for (t, v) in self.t.final_regs.iter().zip(final_state.cells()) {
            pw.set_target(*t, v)?;
        }
        for (k, u) in batch.iter().enumerate() {
            let (idx, _) = hash_register(self.params.b, u.key);
            for r in 0..self.params.m() {
                let v = if r == idx { F::ONE } else { F::ZERO };
                pw.set_target(self.t.selectors[k][r], v)?;
            }
        }

        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self.data.prove(pw)?;
        let prove = t_p.elapsed();
        Ok((Node::leaf(self.data.clone(), proof, init_commit, final_commit, index), witness, prove))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};
    use crate::sketch::hyperloglog::HllParams;

    #[test]
    fn hll_leaf_round_trip() -> Result<()> {
        let leaf = build_hll_leaf(HllLeafParams::default());
        let initial = HllState::new(&HllParams { b: 3 });
        let batch = vec![HllUpdate { key: 42 }, HllUpdate { key: 1337 }];
        let node = leaf.prove(&initial, &batch, 1)?;
        let mut expected = initial.clone();
        for u in &batch {
            expected.update(u);
        }
        assert_eq!(node.final_, expected.commit());
        verify_node(&node)
    }

    #[test]
    fn hll_leaf_rejects_wrong_register_routing() {
        // The register a key routes to is derived from the committed key
        // in-circuit; a witness that points the selector at the wrong register
        // must be rejected (the `weighted == idx_t` binding fails).
        let params = HllLeafParams { b: 3, batch: 1 };
        let leaf = build_hll_leaf(params);
        let m = params.m();
        let key = 42u64;
        let (idx, _) = hash_register(params.b, key);
        let initial = HllState::new(&HllParams { b: params.b });
        let mut final_state = initial.clone();
        final_state.update(&HllUpdate { key });

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(leaf.t.init_commit, initial.commit()).unwrap();
        pw.set_hash_target(leaf.t.final_commit, final_state.commit()).unwrap();
        let keys_f = vec![F::from_canonical_u64(key)];
        pw.set_hash_target(leaf.t.batch_commit, PoseidonHash::hash_no_pad(&keys_f)).unwrap();
        pw.set_target(leaf.t.keys[0], F::from_canonical_u64(key)).unwrap();
        for (t, v) in leaf.t.init_regs.iter().zip(initial.cells()) {
            pw.set_target(*t, v).unwrap();
        }
        for (t, v) in leaf.t.final_regs.iter().zip(final_state.cells()) {
            pw.set_target(*t, v).unwrap();
        }
        // Point the selector at the WRONG register (idx+1), not the derived idx.
        let wrong = (idx + 1) % m;
        for r in 0..m {
            let v = if r == wrong { F::ONE } else { F::ZERO };
            pw.set_target(leaf.t.selectors[0][r], v).unwrap();
        }
        assert!(leaf.data.prove(pw).is_err(), "wrong register routing must be rejected");
    }

    #[test]
    fn hll_two_leaf_recursive_merge() -> Result<()> {
        let leaf = build_hll_leaf(HllLeafParams::default());
        let s0 = HllState::new(&HllParams { b: 3 });
        let b1 = vec![HllUpdate { key: 42 }, HllUpdate { key: 1337 }];
        let n1 = leaf.prove(&s0, &b1, 1)?;
        let mut s1 = s0.clone();
        for u in &b1 {
            s1.update(u);
        }
        let b2 = vec![HllUpdate { key: 9 }, HllUpdate { key: 42 }];
        let n2 = leaf.prove(&s1, &b2, 2)?;
        let root = merge(&n1, &n2)?; // same sketch-agnostic merge as Count-Min
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }
}
