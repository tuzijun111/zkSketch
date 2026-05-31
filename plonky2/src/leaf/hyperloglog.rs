//! In-circuit HyperLogLog update leaf (paper §5.3, sound max-correctness) for plonky2.
//!
//! Port of `../src/recursion/recursive/hll_leaf.rs`. Proves one epoch:
//! committed initial registers + a batch of `(idx, leading_run)` selections yield
//! the committed final registers, with `final[r] = max(initial[r], selected runs)`.
//!
//! ## Public inputs (in order)
//! 1. `initial_commit[0..4]`, 2. `final_commit[0..4]`, 3. per record: `key`, `idx`, `lr`.
//! (Same `[initial | final]` prefix as the Count-Min leaf, so [`crate::recursion::merge`]
//! treats both uniformly.)
//!
//! ## Max via product-of-differences + range checks
//! For each register `r` let the candidate set be `{initial[r]} ∪ {lr_k : selector[k][r]=1}`.
//! - `Π (final[r] - candidate) == 0`  ⇒  `final[r]` equals **some** candidate.
//! - each `final[r] - candidate` is range-checked to `[0, 2^REGISTER_WIDTH)` (via `split_le`)
//!   ⇒  `final[r] ≥ every` candidate.
//! Together ⇒ `final[r] = max(candidates)`.

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};

use crate::config::{C, D, F};
use crate::recursion::Node;
use crate::sketch::hyperloglog::{hash_register, HllState, HllUpdate};

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
    /// `(key, idx, lr)` per record.
    records: Vec<(Target, Target, Target)>,
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

/// Build the HLL update circuit for the given shape.
pub fn build_hll_leaf(params: HllLeafParams) -> HllLeaf {
    params.validate();
    let m = params.m();
    let batch = params.batch;
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // ---- Public inputs ----
    let init_commit = virtual_hash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = virtual_hash(&mut b);
    b.register_public_inputs(&final_commit.elements);

    let mut records = Vec::with_capacity(batch);
    for _ in 0..batch {
        let key = b.add_virtual_target();
        let idx = b.add_virtual_target();
        let lr = b.add_virtual_target();
        b.register_public_input(key);
        b.register_public_input(idx);
        b.register_public_input(lr);
        records.push((key, idx, lr));
    }

    // ---- Private witness ----
    let init_regs = b.add_virtual_targets(m);
    let final_regs = b.add_virtual_targets(m);
    let mut selectors = Vec::with_capacity(batch);
    for _ in 0..batch {
        selectors.push(b.add_virtual_targets(m));
    }

    // ---- Constraint 1: hash binds ----
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

    // ---- Constraint 2: selector validity ----
    for k in 0..batch {
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
            let term = b.mul(selectors[k][r], rconsts[r]);
            weighted = b.add(weighted, term);
        }
        b.connect(weighted, records[k].1); // == idx_k
    }

    // ---- Constraint 3: per-register max (product-of-differences + range) ----
    for r in 0..m {
        // Factor for the "keep initial" candidate, and range-check final >= initial.
        let mut prod = b.sub(final_regs[r], init_regs[r]);
        let _ = b.split_le(prod, REGISTER_WIDTH);
        for k in 0..batch {
            // candidate_k = initial[r] + selector[k][r] * (lr_k - initial[r])
            let lr_minus_init = b.sub(records[k].2, init_regs[r]);
            let scaled = b.mul(selectors[k][r], lr_minus_init);
            let cand = b.add(init_regs[r], scaled);
            let diff = b.sub(final_regs[r], cand);
            let _ = b.split_le(diff, REGISTER_WIDTH); // final >= candidate_k
            prod = b.mul(prod, diff);
        }
        b.connect(prod, zero); // final[r] is one of the candidates
    }

    let data = Arc::new(b.build::<C>());
    HllLeaf {
        data,
        t: HllTargets { init_commit, final_commit, records, init_regs, final_regs, selectors },
        params,
    }
}

impl HllLeaf {
    /// Prove one HLL epoch. `index` is the 1-based leaf position.
    pub fn prove(&self, initial: &HllState, batch: &[HllUpdate], index: u64) -> Result<Node> {
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
        for (k, u) in batch.iter().enumerate() {
            let (idx, lr) = hash_register(self.params.b, u.key);
            pw.set_target(self.t.records[k].0, F::from_canonical_u64(u.key))?;
            pw.set_target(self.t.records[k].1, F::from_canonical_u64(idx as u64))?;
            pw.set_target(self.t.records[k].2, F::from_canonical_u64(lr))?;
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

        let proof = self.data.prove(pw)?;
        Ok(Node::leaf(self.data.clone(), proof, init_commit, final_commit, index))
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
