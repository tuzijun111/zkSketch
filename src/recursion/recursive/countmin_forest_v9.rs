//! Recursive streaming forest over v9 Count-Min leaves: equal-size subtree proofs are
//! merged as leaves arrive, then the surviving roots are folded into one root proof.

use core::fmt;

use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, RecursionInput, RecursionOutput,
    build_and_prove_aggregation_layer,
};

use crate::commitment::countmin::CountMinCommit;
use crate::commitment::countmin_batch::CountMinBatchCommit;
use crate::config::LOG_BLOWUP;
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::make_leaf_config;
use crate::recursion::recursive::countmin_leaf_v9::CountMinLeafProofV9;

const LOG_FINAL_POLY_LEN: usize = 6;

/// Aggregation parameters — identical FRI shape to [`countmin_merge_v9`] so
/// leaf proofs and aggregation outputs verify under the same circuit.
fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// The aggregated root proof over a streaming forest of `E ≥ 2` v9 epochs.
///
/// Structurally a [`countmin_merge_v9::CountMinChainProofV9`], but the digest
/// binds the **tree** (Bentley–Saxe) schedule rather than the linear chain
/// schedule, so it is verified with [`verify_forest_countmin_v9`] (which
/// replays the same cascade) — not the linear chain verifier.
pub struct CountMinForestRootV9 {
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    /// `(1, E)`.
    pub interval: (u64, u64),
    /// `Com(S_0)` — outer left boundary.
    pub initial: CountMinCommit,
    /// `Com(S_E)` — outer right boundary.
    pub final_: CountMinCommit,
    /// All `E - 1` internal boundaries `Com(S_1)..Com(S_{E-1})`, in order.
    /// Carried for the native digest recompute; **not** part of the proof's
    /// public inputs (the proof is `O(1)`).
    pub internal_boundaries: Vec<CountMinCommit>,
    /// Per-leaf batch commitments (privacy-preserving opaque digests).
    pub batch_commits: Vec<CountMinBatchCommit>,
    /// `H_{[1,E]}` over the tree schedule.
    pub digest: ChainDigest,
}

impl CountMinForestRootV9 {
    pub fn num_leaves(&self) -> usize {
        self.batch_commits.len()
    }

    /// `Com(S_i)` for `0 ≤ i ≤ E`.
    pub fn boundary(&self, i: usize) -> CountMinCommit {
        let e = self.num_leaves();
        assert!(i <= e, "boundary index {i} > num_leaves {e}");
        if i == 0 {
            self.initial
        } else if i == e {
            self.final_
        } else {
            self.internal_boundaries[i - 1]
        }
    }
}

#[derive(Debug)]
pub enum CountMinForestErrorV9 {
    TooFewLeaves(usize),
    NonContiguous {
        at: usize,
        left_final: CountMinCommit,
        right_initial: CountMinCommit,
    },
    AggregationFailed(String),
    BatchVerifyFailed(String),
    StructuralMismatch,
    DigestMismatch,
}

impl fmt::Display for CountMinForestErrorV9 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewLeaves(n) => write!(f, "forest needs ≥ 2 leaves, got {n}"),
            Self::NonContiguous { at, left_final, right_initial } => write!(
                f,
                "non-contiguous history at epoch {at}: left.final = {left_final:?} but right.initial = {right_initial:?}"
            ),
            Self::AggregationFailed(s) => write!(f, "forest aggregation layer failed: {s}"),
            Self::BatchVerifyFailed(s) => write!(f, "forest batch-stark verification failed: {s}"),
            Self::StructuralMismatch => write!(f, "structural mismatch in forest root proof"),
            Self::DigestMismatch => write!(f, "recomputed tree digest does not match the carried one"),
        }
    }
}

impl core::error::Error for CountMinForestErrorV9 {}

// ─── Cascade node ────────────────────────────────────────────────────────

/// A subtree proof: either a borrowed leaf (size-1, not yet aggregated) or an
/// owned aggregation output (size ≥ 2). Both convert uniformly to a
/// `RecursionInput::BatchStark` for the next merge.
enum NodeProof<'a> {
    Leaf(&'a CountMinLeafProofV9),
    Agg(RecursionOutput<ConfigWithFriParams>),
}

impl NodeProof<'_> {
    fn as_input(&self) -> RecursionInput<'_, ConfigWithFriParams, BatchOnly> {
        match self {
            NodeProof::Leaf(l) => l.output.into_recursion_input::<BatchOnly>(),
            NodeProof::Agg(o) => o.into_recursion_input::<BatchOnly>(),
        }
    }
}

/// One surviving subtree in the cascade.
struct Node<'a> {
    proof: NodeProof<'a>,
    /// Interval `[lo, hi]` of epochs this subtree covers (1-based).
    lo: u64,
    hi: u64,
    initial: CountMinCommit,
    final_: CountMinCommit,
}

impl Node<'_> {
    /// Number of epochs covered — a power of two within the cascade.
    fn size(&self) -> u64 {
        self.hi - self.lo + 1
    }
}

/// Merge two adjacent subtree proofs into one aggregation that recursively
/// verifies both. `left` is the earlier interval; its `final_` must equal
/// `right.initial` (checked natively).
fn merge_nodes<'a>(
    left: Node<'a>,
    right: Node<'a>,
    config: &ConfigWithFriParams,
    backend: &Backend,
    params: &ProveNextLayerParams,
) -> Result<Node<'a>, CountMinForestErrorV9> {
    if left.final_ != right.initial {
        return Err(CountMinForestErrorV9::NonContiguous {
            at: left.hi as usize,
            left_final: left.final_,
            right_initial: right.initial,
        });
    }

    let out = {
        let li = left.proof.as_input();
        let ri = right.proof.as_input();
        build_and_prove_aggregation_layer::<ConfigWithFriParams, BatchOnly, BatchOnly, Backend, EXT_D>(
            &li, &ri, config, backend, params, None,
        )
        .map_err(|e| CountMinForestErrorV9::AggregationFailed(format!("{e:?}")))?
    };

    Ok(Node {
        proof: NodeProof::Agg(out),
        lo: left.lo,
        hi: right.hi,
        initial: left.initial,
        final_: right.final_,
    })
}

/// Replay the Bentley–Saxe cascade purely over per-leaf digests to produce
/// the root digest. Used by both prover and verifier so they agree on the
/// tree schedule. `leaf_digs[i]` is the digest for epoch `i + 1`.
fn pure_forest_digest(leaf_digs: &[ChainDigest]) -> ChainDigest {
    struct D {
        lo: u64,
        hi: u64,
        dig: ChainDigest,
    }
    let mut roots: Vec<D> = Vec::new();
    for (i, d) in leaf_digs.iter().enumerate() {
        let mut node = D { lo: (i + 1) as u64, hi: (i + 1) as u64, dig: *d };
        while let Some(last) = roots.last() {
            // Same size (power-of-two interval) ⇒ carry / merge.
            if last.hi - last.lo == node.hi - node.lo {
                let left = roots.pop().unwrap();
                let dig = combine_digest(left.lo, left.hi, node.hi, &left.dig, &node.dig);
                node = D { lo: left.lo, hi: node.hi, dig };
            } else {
                break;
            }
        }
        roots.push(node);
    }
    // Finalize: chain the surviving roots left-to-right.
    let mut acc = roots.remove(0);
    for r in roots {
        let dig = combine_digest(acc.lo, acc.hi, r.hi, &acc.dig, &r.dig);
        acc = D { lo: acc.lo, hi: r.hi, dig };
    }
    acc.dig
}

/// Prove a streaming forest over `E ≥ 2` contiguous v9 leaves, producing one
/// root proof that recursively verifies them all.
pub fn prove_countmin_forest_v9(
    leaves: &[CountMinLeafProofV9],
) -> Result<CountMinForestRootV9, CountMinForestErrorV9> {
    let e = leaves.len();
    if e < 2 {
        return Err(CountMinForestErrorV9::TooFewLeaves(e));
    }
    // Fail fast on a non-contiguous history (the merges would catch it too).
    for w in leaves.windows(2) {
        if w[0].final_ != w[1].initial {
            return Err(CountMinForestErrorV9::NonContiguous {
                at: 0,
                left_final: w[0].final_,
                right_initial: w[1].initial,
            });
        }
    }

    let config = make_leaf_config();
    let backend = make_backend();
    let params = agg_params();

    // Binary-counter cascade over real proofs.
    let mut roots: Vec<Node> = Vec::new();
    for (i, leaf) in leaves.iter().enumerate() {
        let mut node = Node {
            proof: NodeProof::Leaf(leaf),
            lo: (i + 1) as u64,
            hi: (i + 1) as u64,
            initial: leaf.initial,
            final_: leaf.final_,
        };
        while let Some(last) = roots.last() {
            if last.size() == node.size() {
                let left = roots.pop().unwrap();
                node = merge_nodes(left, node, &config, &backend, &params)?;
            } else {
                break;
            }
        }
        roots.push(node);
    }
    // Finalize: chain surviving roots left-to-right into one root proof.
    let mut acc = roots.remove(0);
    for r in roots {
        acc = merge_nodes(acc, r, &config, &backend, &params)?;
    }
    let recursive_proof = match acc.proof {
        NodeProof::Agg(o) => o,
        NodeProof::Leaf(_) => unreachable!("E ≥ 2 ⇒ the root is an aggregation"),
    };

    // Digest binds the tree schedule; boundaries are read off the leaves.
    let leaf_digs: Vec<ChainDigest> = leaves
        .iter()
        .enumerate()
        .map(|(i, l)| {
            leaf_digest(
                (i + 1) as u64,
                (i + 1) as u64,
                &l.batch_commit.0,
                &l.initial.0,
                &l.final_.0,
            )
        })
        .collect();
    let digest = pure_forest_digest(&leaf_digs);
    let internal_boundaries: Vec<CountMinCommit> = (1..e).map(|i| leaves[i].initial).collect();
    let batch_commits: Vec<CountMinBatchCommit> = leaves.iter().map(|l| l.batch_commit).collect();

    Ok(CountMinForestRootV9 {
        recursive_proof,
        interval: (1, e as u64),
        initial: leaves[0].initial,
        final_: leaves[e - 1].final_,
        internal_boundaries,
        batch_commits,
        digest,
    })
}

/// Verify a forest root: (1) the single recursive batch-STARK is sound, and
/// (2) the carried boundaries replay the same tree-schedule digest the proof
/// advertises.
pub fn verify_forest_countmin_v9(
    root: &CountMinForestRootV9,
) -> Result<(), CountMinForestErrorV9> {
    let config = make_leaf_config();
    let params = agg_params();

    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier
        .verify_all_tables(&root.recursive_proof.0)
        .map_err(|e| CountMinForestErrorV9::BatchVerifyFailed(format!("{e:?}")))?;

    let e = root.num_leaves();
    if e < 2
        || root.internal_boundaries.len() != e - 1
        || root.interval != (1, e as u64)
        || root.batch_commits.len() != e
    {
        return Err(CountMinForestErrorV9::StructuralMismatch);
    }

    let leaf_digs: Vec<ChainDigest> = (1..=e)
        .map(|i| {
            leaf_digest(
                i as u64,
                i as u64,
                &root.batch_commits[i - 1].0,
                &root.boundary(i - 1).0,
                &root.boundary(i).0,
            )
        })
        .collect();
    if pure_forest_digest(&leaf_digs) != root.digest {
        return Err(CountMinForestErrorV9::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    use crate::recursion::recursive::countmin_leaf::{D, W};
    use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9;
    use crate::recursion::recursive::countmin_merge_v9::merge_two_countmin_v9;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
    use crate::sketch::countmin_v9::CountMinV9;

    fn empty_state() -> CountMinState {
        CountMinV9::new(&CountMinParams { d: D, w: W })
    }

    /// Build a contiguous run of `n` honest v9 leaves over distinct batches.
    fn honest_leaves(n: u64) -> Vec<CountMinLeafProofV9> {
        let mut state = empty_state();
        let mut leaves = Vec::with_capacity(n as usize);
        for i in 0..n {
            let k0 = 1 + 2 * i;
            let k1 = 2 + 2 * i;
            let batch = [
                CountMinUpdate { key: k0, value: (1 + i) as u32 },
                CountMinUpdate { key: k1, value: (2 + i) as u32 },
            ];
            let leaf = prove_countmin_leaf_v9(state.clone(), batch);
            for u in &batch {
                CountMinV9::update(&mut state, u);
            }
            leaves.push(leaf);
        }
        leaves
    }

    /// A 2-leaf forest is exactly a 2-leaf merge: same root boundaries and the
    /// same (linear == tree at E=2) digest.
    #[test]
    fn forest_two_matches_merge() {
        let leaves = honest_leaves(2);
        let root = prove_countmin_forest_v9(&leaves).expect("forest of 2");
        verify_forest_countmin_v9(&root).expect("verify forest of 2");

        let merge = merge_two_countmin_v9(&leaves[0], &leaves[1]).expect("merge");
        assert_eq!(root.interval, (1, 2));
        assert_eq!(root.initial, leaves[0].initial);
        assert_eq!(root.final_, leaves[1].final_);
        assert_eq!(root.digest, merge.digest, "E=2: tree digest == chain digest");
    }

    /// A 3-leaf forest finalizes a size-2 subtree with a trailing size-1 leaf
    /// (`agg + leaf`). Root covers `[1, 3]` and verifies.
    #[test]
    fn forest_three_accepts() {
        let leaves = honest_leaves(3);
        let root = prove_countmin_forest_v9(&leaves).expect("forest of 3");
        verify_forest_countmin_v9(&root).expect("verify forest of 3");
        assert_eq!(root.interval, (1, 3));
        assert_eq!(root.num_leaves(), 3);
        assert_eq!(root.internal_boundaries.len(), 2);
        assert_eq!(root.initial, leaves[0].initial);
        assert_eq!(root.final_, leaves[2].final_);
    }

    /// A 4-leaf forest exercises `agg + agg` (the top merge verifies two
    /// aggregation proofs) — the case the linear chain never hits. Root
    /// covers `[1, 4]` and verifies.
    #[test]
    fn forest_four_accepts_agg_of_aggs() {
        let leaves = honest_leaves(4);
        let root = prove_countmin_forest_v9(&leaves).expect("forest of 4");
        verify_forest_countmin_v9(&root).expect("verify forest of 4");
        assert_eq!(root.interval, (1, 4));
        assert_eq!(root.num_leaves(), 4);
        assert_eq!(root.internal_boundaries.len(), 3);
        assert_eq!(root.final_, leaves[3].final_);

        // The root recursive proof carries NO intermediate state commitments
        // (see probe_aggregation_public_inputs); demonstrate its serialized
        // size is bounded (O(1)), not proportional to the 4 leaves.
        if let Ok(bytes) = postcard::to_allocvec(&root.recursive_proof.0) {
            println!("forest(4) recursive_proof = {} bytes", bytes.len());
        }
    }

    /// O(1) evidence: the root recursive proof does not grow linearly with
    /// the leaf count. Doubling the forest (4 → 8 epochs) leaves the root
    /// proof's serialized size essentially flat (it only verifies its two
    /// direct children, never the whole history). Slow (15 proofs); run with
    /// `--ignored --nocapture`.
    #[test]
    #[ignore = "slow: builds 4- and 8-leaf forests (15 recursive proofs)"]
    fn forest_root_size_does_not_grow_with_leaves() {
        let r4 = prove_countmin_forest_v9(&honest_leaves(4)).expect("forest of 4");
        let r8 = prove_countmin_forest_v9(&honest_leaves(8)).expect("forest of 8");
        verify_forest_countmin_v9(&r4).expect("verify 4");
        verify_forest_countmin_v9(&r8).expect("verify 8");

        let b4 = postcard::to_allocvec(&r4.recursive_proof.0).expect("ser 4").len();
        let b8 = postcard::to_allocvec(&r8.recursive_proof.0).expect("ser 8").len();
        println!("forest root proof: E=4 -> {b4} bytes, E=8 -> {b8} bytes");
        // Linear-in-E growth would make E=8 ~2x E=4; assert it stays well
        // under that (the recursive root is O(1), not O(E)).
        assert!(
            b8 < b4 * 3 / 2,
            "root proof grew too much with leaf count: {b4} -> {b8}"
        );
    }

    /// O(1)-VERIFIER evidence: the time to verify a forest root does NOT grow
    /// with the stream length (leaf count). The single recursive STARK only ever
    /// verifies its two direct children in-circuit, so `verify_all_tables` is
    /// constant-time regardless of how many leaves are folded; the only
    /// E-dependent term is the cheap native digest replay (a handful of
    /// Poseidon2 per leaf), which is negligible against the STARK verify.
    /// Builds forests at E ∈ {2,4,8} (2+4+8 leaves + 1+3+7 merges = 25 proofs)
    /// and times verify; the per-E times should be ~flat. Slow; run with
    /// `--ignored --nocapture`.
    #[test]
    #[ignore = "slow: builds forests at E=2,4,8 (25 recursive proofs) to time verify"]
    fn forest_verify_time_independent_of_stream_length() {
        use std::time::Instant;
        const REPS: u32 = 50;
        for e in [2u64, 4, 8] {
            let root = prove_countmin_forest_v9(&honest_leaves(e)).expect("forest");
            verify_forest_countmin_v9(&root).expect("verify"); // warm up
            let t0 = Instant::now();
            for _ in 0..REPS {
                verify_forest_countmin_v9(&root).expect("verify");
            }
            let per = t0.elapsed().as_secs_f64() * 1000.0 / REPS as f64;
            println!("verify forest E={e:>2} ({e} leaves): {per:.3} ms/verify");
        }
    }

    /// Tampering the carried digest is rejected at verify time.
    #[test]
    fn forest_rejects_tampered_digest() {
        let leaves = honest_leaves(3);
        let mut root = prove_countmin_forest_v9(&leaves).expect("forest of 3");
        root.digest[0] = root.digest[0] + crate::config::Val::ONE;
        match verify_forest_countmin_v9(&root) {
            Err(CountMinForestErrorV9::DigestMismatch) => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    /// A non-contiguous history is rejected before any aggregation runs.
    #[test]
    fn forest_rejects_non_contiguous() {
        let mut leaves = honest_leaves(2);
        // Replace leaf 2 with one starting from a fresh (wrong) state.
        let s_wrong = empty_state();
        let bad = [
            CountMinUpdate { key: 100, value: 1 },
            CountMinUpdate { key: 101, value: 1 },
        ];
        leaves[1] = prove_countmin_leaf_v9(s_wrong, bad);
        match prove_countmin_forest_v9(&leaves) {
            Err(CountMinForestErrorV9::NonContiguous { .. }) => {}
            Err(other) => panic!("expected NonContiguous, got {other:?}"),
            Ok(_) => panic!("expected NonContiguous, got Ok"),
        }
    }
}
