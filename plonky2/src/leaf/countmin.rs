//! In-circuit Count-Min update leaf (paper §5.1 strawman) for plonky2.
//!
//! Port of `../src/recursion/recursive/countmin_leaf.rs`. Each leaf
//! proves one epoch: starting from a committed `d×w` state, applying `batch`
//! records yields the committed final state.
//!
//! ## Public inputs (in order)
//! 1. `initial_commit[0..4]` — Poseidon digest of the pre-update state.
//! 2. `final_commit[0..4]`   — Poseidon digest of the post-update state.
//! 3. per record `k`: `key_k`, `value_k`, `pos_k[0..d]` (the public hash columns).
//!
//! Keeping `initial_commit` at PI `[0..4]` and `final_commit` at `[4..8]` lets the
//! sketch-agnostic [`crate::recursion::merge`] read boundaries uniformly.
//!
//! ## Constraints
//! 1. `hash(initial_cells) == initial_commit`, `hash(final_cells) == final_commit`.
//! 2. per `(k, r)`: `selector` is boolean, `Σ_j selector = 1`, `Σ_j j·selector = pos_k[r]`.
//! 3. per cell `(i, j)`: `final[i,j] = initial[i,j] + Σ_k selector[k][i][j] · value_k`.

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
use crate::sketch::countmin::{hash_cell, CountMinState, CountMinUpdate};

/// Per-leaf shape: `d` rows, `w` columns, `batch` records per epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmLeafParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmLeafParams {
    pub fn validate(&self) {
        assert!(self.d >= 1 && self.w >= 1 && self.batch >= 1, "params must be positive");
    }
}

impl Default for CmLeafParams {
    fn default() -> Self {
        Self { d: 2, w: 4, batch: 2 }
    }
}

struct CmTargets {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    /// `(key, value, pos[0..d])` per record.
    records: Vec<(Target, Target, Vec<Target>)>,
    init_cells: Vec<Target>,
    final_cells: Vec<Target>,
    /// `selectors[k][r][j]`.
    selectors: Vec<Vec<Vec<Target>>>,
}

/// A built, reusable Count-Min leaf circuit. Build once per `(d, w, batch)`;
/// prove many epochs against it (they share one `CircuitData`, so their proofs
/// merge cheaply).
pub struct CountMinLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: CmTargets,
    pub params: CmLeafParams,
}

fn virtual_hash(b: &mut CircuitBuilder<F, D>) -> HashOutTarget {
    HashOutTarget { elements: core::array::from_fn(|_| b.add_virtual_target()) }
}

/// Build the Count-Min update circuit for the given shape.
pub fn build_countmin_leaf(params: CmLeafParams) -> CountMinLeaf {
    params.validate();
    let CmLeafParams { d, w, batch: m } = params;
    let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // ---- Public inputs ----
    let init_commit = virtual_hash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = virtual_hash(&mut b);
    b.register_public_inputs(&final_commit.elements);

    let mut records = Vec::with_capacity(m);
    for _ in 0..m {
        let key = b.add_virtual_target();
        let value = b.add_virtual_target();
        b.register_public_input(key);
        b.register_public_input(value);
        let mut pos = Vec::with_capacity(d);
        for _ in 0..d {
            let p = b.add_virtual_target();
            b.register_public_input(p);
            pos.push(p);
        }
        records.push((key, value, pos));
    }

    // ---- Private witness ----
    let init_cells = b.add_virtual_targets(d * w);
    let final_cells = b.add_virtual_targets(d * w);
    let mut selectors = Vec::with_capacity(m);
    for _ in 0..m {
        let mut per_row = Vec::with_capacity(d);
        for _ in 0..d {
            per_row.push(b.add_virtual_targets(w));
        }
        selectors.push(per_row);
    }

    // ---- Constraint 1: hash binds ----
    let hi = b.hash_n_to_hash_no_pad::<PoseidonHash>(init_cells.clone());
    for i in 0..4 {
        b.connect(hi.elements[i], init_commit.elements[i]);
    }
    let hf = b.hash_n_to_hash_no_pad::<PoseidonHash>(final_cells.clone());
    for i in 0..4 {
        b.connect(hf.elements[i], final_commit.elements[i]);
    }

    let one = b.one();
    let zero = b.zero();
    let jconsts: Vec<Target> = (0..w).map(|j| b.constant(F::from_canonical_u64(j as u64))).collect();

    // ---- Constraint 2: selector validity ----
    for k in 0..m {
        for r in 0..d {
            // boolean: s*(s-1) == 0
            for j in 0..w {
                let s = selectors[k][r][j];
                let sm1 = b.sub(s, one);
                let prod = b.mul(s, sm1);
                b.connect(prod, zero);
            }
            // one-hot: Σ_j s == 1
            let mut sum = selectors[k][r][0];
            for j in 1..w {
                sum = b.add(sum, selectors[k][r][j]);
            }
            b.connect(sum, one);
            // position: Σ_j j·s == pos_k[r]
            let mut weighted = zero;
            for j in 0..w {
                let term = b.mul(selectors[k][r][j], jconsts[j]);
                weighted = b.add(weighted, term);
            }
            b.connect(weighted, records[k].2[r]);
        }
    }

    // ---- Constraint 3: state transition ----
    for i in 0..d {
        for j in 0..w {
            let idx = i * w + j;
            let mut acc = init_cells[idx];
            for k in 0..m {
                let term = b.mul(selectors[k][i][j], records[k].1);
                acc = b.add(acc, term);
            }
            b.connect(acc, final_cells[idx]);
        }
    }

    let data = Arc::new(b.build::<C>());
    CountMinLeaf {
        data,
        t: CmTargets { init_commit, final_commit, records, init_cells, final_cells, selectors },
        params,
    }
}

impl CountMinLeaf {
    /// Prove one epoch: `initial` --(`batch`)--> final, exposing both commits.
    /// `index` is the 1-based leaf position (bound into the chain digest).
    pub fn prove(
        &self,
        initial: &CountMinState,
        batch: &[CountMinUpdate],
        index: u64,
    ) -> Result<Node> {
        assert_eq!(batch.len(), self.params.batch, "batch length mismatch");
        assert_eq!(initial.d, self.params.d, "state.d mismatch");
        assert_eq!(initial.w, self.params.w, "state.w mismatch");

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
            pw.set_target(self.t.records[k].0, F::from_canonical_u64(u.key))?;
            pw.set_target(self.t.records[k].1, F::from_canonical_u64(u.value))?;
            for r in 0..self.params.d {
                let pos = hash_cell(r, u.key, self.params.w);
                pw.set_target(self.t.records[k].2[r], F::from_canonical_u64(pos as u64))?;
            }
        }
        for (t, v) in self.t.init_cells.iter().zip(initial.cells()) {
            pw.set_target(*t, v)?;
        }
        for (t, v) in self.t.final_cells.iter().zip(final_state.cells()) {
            pw.set_target(*t, v)?;
        }
        for (k, u) in batch.iter().enumerate() {
            for r in 0..self.params.d {
                let pos = hash_cell(r, u.key, self.params.w);
                for j in 0..self.params.w {
                    let v = if j == pos { F::ONE } else { F::ZERO };
                    pw.set_target(self.t.selectors[k][r][j], v)?;
                }
            }
        }

        let proof = self.data.prove(pw)?;
        Ok(Node::leaf(self.data.clone(), proof, init_commit, final_commit, index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::verify_node;
    use crate::sketch::countmin::CountMinParams;

    #[test]
    fn countmin_leaf_round_trip() -> Result<()> {
        let params = CmLeafParams::default();
        let leaf = build_countmin_leaf(params);
        let initial = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let node = leaf.prove(&initial, &batch, 1)?;

        let mut expected = initial.clone();
        for u in &batch {
            expected.update(u);
        }
        assert_eq!(node.final_, expected.commit());
        assert_eq!(node.initial, initial.commit());
        verify_node(&node)
    }

    #[test]
    fn countmin_leaf_at_4_4_4() -> Result<()> {
        let params = CmLeafParams { d: 4, w: 4, batch: 4 };
        let leaf = build_countmin_leaf(params);
        let initial = CountMinState::new(&CountMinParams { d: 4, w: 4 });
        let batch: Vec<CountMinUpdate> = (0..4)
            .map(|i| CountMinUpdate { key: i * 11 + 1, value: i + 1 })
            .collect();
        let node = leaf.prove(&initial, &batch, 1)?;
        let mut expected = initial.clone();
        for u in &batch {
            expected.update(u);
        }
        assert_eq!(node.final_, expected.commit());
        verify_node(&node)
    }
}
