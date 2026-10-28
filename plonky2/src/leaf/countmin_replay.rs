//! Count-Min `replay` leaf: hash and route every record in-circuit, flat Poseidon commit of all d·w cells.

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;

use crate::config::{C, D, F};
use crate::leaf::countmin_final::{apply_update_prf, hash_cell_prf};
use crate::recursion::Node;
use crate::sketch::countmin::{commit_batch, CountMinState, CountMinUpdate};

/// Circuit shape: `d` rows of `w` counters, `batch` records per epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmReplayParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmReplayParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    pub fn validate(&self) {
        assert!((1..=4).contains(&self.d), "d must be in 1..=4 (PRF digest width)");
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two >= 2");
        assert!(self.batch >= 1, "batch >= 1");
        let sel_cells = self.batch.saturating_mul(self.d).saturating_mul(self.w);
        let max_sel = std::env::var("COUNTMIN_MAX_SEL_CELLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(16_000_000);
        assert!(
            sel_cells <= max_sel,
            "selector budget exceeded: batch·d·w = {sel_cells} > {max_sel} \
             (raise COUNTMIN_MAX_SEL_CELLS for heavy runs)"
        );
    }
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    key: Vec<Target>,
    val: Vec<Target>,
    init_cells: Vec<Target>,
    final_cells: Vec<Target>,
    /// `sel[k][r][j]` — one-hot over `w` cells for record `k` in row `r`.
    sel: Vec<Vec<Vec<Target>>>,
}

/// A built, reusable replay (flat-commit) Count-Min leaf circuit.
pub struct CountMinReplayLeaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: CmReplayParams,
}

fn vhash(b: &mut CircuitBuilder<F, D>) -> HashOutTarget {
    HashOutTarget { elements: core::array::from_fn(|_| b.add_virtual_target()) }
}

/// Build the replay-update Count-Min circuit for the given shape.
pub fn build_countmin_replay_leaf(params: CmReplayParams) -> CountMinReplayLeaf {
    params.validate();
    let CmReplayParams { d, w, batch: m } = params;
    let num_cells = d * w;
    let w_log2 = w.trailing_zeros() as usize;

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());

    // ---- Public inputs: commits only (keys/values stay private) ----
    let init_commit = vhash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);

    // ---- Private witness ----
    let key = b.add_virtual_targets(m);
    let val = b.add_virtual_targets(m);
    let init_cells = b.add_virtual_targets(num_cells);
    let final_cells = b.add_virtual_targets(num_cells);
    let mut sel = Vec::with_capacity(m);
    for _ in 0..m {
        let mut per_row = Vec::with_capacity(d);
        for _ in 0..d {
            per_row.push(b.add_virtual_targets(w));
        }
        sel.push(per_row);
    }

    let one = b.one();
    let zero = b.zero();
    let pow2: Vec<Target> = (0..w_log2).map(|j| b.constant(F::from_canonical_u64(1u64 << j))).collect();
    let jconsts: Vec<Target> = (0..w).map(|j| b.constant(F::from_canonical_u64(j as u64))).collect();

    // ---- C1: flat state commitments ----
    let hi = b.hash_n_to_hash_no_pad::<PoseidonHash>(init_cells.clone());
    for i in 0..4 {
        b.connect(hi.elements[i], init_commit.elements[i]);
    }
    let hf = b.hash_n_to_hash_no_pad::<PoseidonHash>(final_cells.clone());
    for i in 0..4 {
        b.connect(hf.elements[i], final_commit.elements[i]);
    }

    // ---- C2: batch commitment over interleaved (key, value) ----
    let mut batch_pre: Vec<Target> = Vec::with_capacity(2 * m);
    for k in 0..m {
        batch_pre.push(key[k]);
        batch_pre.push(val[k]);
    }
    let hb = b.hash_n_to_hash_no_pad::<PoseidonHash>(batch_pre);
    for i in 0..4 {
        b.connect(hb.elements[i], batch_commit.elements[i]);
    }

    // ---- C3: per-record PRF — pos_r = Poseidon(key)[r] mod w, in-circuit ----
    // The prover cannot choose the cell: it is the hash of the (private) key.
    for k in 0..m {
        let digest = b.hash_n_to_hash_no_pad::<PoseidonHash>(vec![key[k]]);
        for r in 0..d {
            // pos = low w_log2 bits of digest[r].
            let bits = b.split_le(digest.elements[r], 64);
            let mut pos = b.mul(bits[0].target, pow2[0]);
            for jb in 1..w_log2 {
                let term = b.mul(bits[jb].target, pow2[jb]);
                pos = b.add(pos, term);
            }
            // Selector validity for (record k, row r): boolean, one-hot, weighted
            // index equal to the derived position.
            let s = &sel[k][r];
            let mut sum = s[0];
            let mut weighted = b.mul(s[0], jconsts[0]);
            let sm0 = b.sub(s[0], one);
            let chk0 = b.mul(s[0], sm0);
            b.connect(chk0, zero);
            for j in 1..w {
                let sm1 = b.sub(s[j], one);
                let chk = b.mul(s[j], sm1);
                b.connect(chk, zero);
                sum = b.add(sum, s[j]);
                let term = b.mul(s[j], jconsts[j]);
                weighted = b.add(weighted, term);
            }
            b.connect(sum, one);
            b.connect(weighted, pos);
        }
    }

    // ---- C4: flat state transition — final[i·w+j] = init[...] + Σ_k sel·value ----
    for i in 0..d {
        for j in 0..w {
            let idx = i * w + j;
            let mut acc = init_cells[idx];
            for k in 0..m {
                let term = b.mul(sel[k][i][j], val[k]);
                acc = b.add(acc, term);
            }
            b.connect(acc, final_cells[idx]);
        }
    }

    let data = Arc::new(crate::config::build_circuit(b));
    CountMinReplayLeaf {
        data,
        t: Tgt { init_commit, final_commit, batch_commit, key, val, init_cells, final_cells, sel },
        params,
    }
}

impl CountMinReplayLeaf {
    /// Prove one replay epoch: `initial` --(`batch`)--> final, exposing both
    /// state commits and the batch commit. `index` is the 1-based leaf position.
    pub fn prove(
        &self,
        initial: &CountMinState,
        batch: &[CountMinUpdate],
        index: u64,
    ) -> Result<Node> {
        let CmReplayParams { d, w, batch: m } = self.params;
        assert_eq!(batch.len(), m, "batch length mismatch");
        assert_eq!(initial.d, d, "state.d mismatch");
        assert_eq!(initial.w, w, "state.w mismatch");

        // Native side: replay with the PRF hash family.
        let mut final_state = initial.clone();
        for u in batch {
            apply_update_prf(&mut final_state, u);
        }
        let init_commit = initial.commit();
        let final_commit = final_state.commit();
        let batch_commit = commit_batch(batch);

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;
        for (k, u) in batch.iter().enumerate() {
            pw.set_target(self.t.key[k], F::from_canonical_u64(u.key))?;
            pw.set_target(self.t.val[k], F::from_canonical_u64(u.value))?;
        }
        for (t, v) in self.t.init_cells.iter().zip(initial.cells()) {
            pw.set_target(*t, v)?;
        }
        for (t, v) in self.t.final_cells.iter().zip(final_state.cells()) {
            pw.set_target(*t, v)?;
        }
        for (k, u) in batch.iter().enumerate() {
            for r in 0..d {
                let pos = hash_cell_prf(r, u.key, w);
                for j in 0..w {
                    let v = if j == pos { F::ONE } else { F::ZERO };
                    pw.set_target(self.t.sel[k][r][j], v)?;
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
    use crate::recursion::{merge, verify_node};
    use crate::sketch::countmin::CountMinParams;

    fn state(d: usize, w: usize, fill: impl Fn(usize, usize) -> u64) -> CountMinState {
        let counters = (0..d).map(|i| (0..w).map(|j| fill(i, j)).collect()).collect();
        CountMinState { counters, d, w }
    }

    /// Round-trip: the proof's commits equal the native flat commits of the
    /// PRF-replayed state.
    fn check(node: &Node, initial: &CountMinState, batch: &[CountMinUpdate]) {
        let mut s = initial.clone();
        for u in batch {
            apply_update_prf(&mut s, u);
        }
        assert_eq!(node.final_, s.commit(), "final commit");
        assert_eq!(node.initial, initial.commit(), "initial commit");
    }

    #[test]
    fn replay_min_round_trip() -> Result<()> {
        let params = CmReplayParams { d: 1, w: 8, batch: 2 };
        let leaf = build_countmin_replay_leaf(params);
        let initial = state(1, 8, |_, j| (j * 2 + 1) as u64);
        let batch = vec![CountMinUpdate { key: 5, value: 1 }, CountMinUpdate { key: 9, value: 1 }];
        let node = leaf.prove(&initial, &batch, 1)?;
        check(&node, &initial, &batch);
        verify_node(&node)
    }

    #[test]
    fn replay_d_rows_round_trip() -> Result<()> {
        let params = CmReplayParams { d: 4, w: 16, batch: 4 };
        let leaf = build_countmin_replay_leaf(params);
        let initial = CountMinState::new(&CountMinParams { d: 4, w: 16 });
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let node = leaf.prove(&initial, &batch, 1)?;
        check(&node, &initial, &batch);
        verify_node(&node)
    }

    /// Two adjacent replay epochs thread by boundary and recursively merge.
    #[test]
    fn replay_two_leaf_merge() -> Result<()> {
        let params = CmReplayParams { d: 2, w: 8, batch: 2 };
        let leaf = build_countmin_replay_leaf(params);
        let s0 = CountMinState::new(&CountMinParams { d: 2, w: 8 });
        let batch1 = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }];
        let n1 = leaf.prove(&s0, &batch1, 1)?;
        let mut s1 = s0.clone();
        for u in &batch1 {
            apply_update_prf(&mut s1, u);
        }
        let batch2 = vec![CountMinUpdate { key: 7, value: 1 }, CountMinUpdate { key: 13, value: 9 }];
        let n2 = leaf.prove(&s1, &batch2, 2)?;
        let root = merge(&n1, &n2)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }
}
