//! Root VKs of boundary-bound forests, computed from public parameters only (forest
//! shape and a no-op leaf), so the auditor never takes the VK from the proof.

use std::collections::HashMap;

use p3_circuit_prover::{AirVariant, BatchStarkProof, RowCounts, TablePacking};
use p3_field::PrimeField64;
use p3_uni_stark::{StarkGenericConfig, Val};
use serde::{Deserialize, Serialize};

// ─── Tree shapes ─────────────────────────────────────────────────────────────

/// The binary merge tree a composer builds over its leaves. Leaves are
/// interchangeable for VK purposes (all leaves of one deployment run the same
/// circuit), so a shape records only the tree structure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ForestShape {
    Leaf,
    Merge(Box<ForestShape>, Box<ForestShape>),
}

impl ForestShape {
    pub fn merge(left: ForestShape, right: ForestShape) -> Self {
        Self::Merge(Box::new(left), Box::new(right))
    }

    pub fn num_leaves(&self) -> usize {
        match self {
            Self::Leaf => 1,
            Self::Merge(l, r) => l.num_leaves() + r.num_leaves(),
        }
    }

    pub fn num_merges(&self) -> usize {
        self.num_leaves() - 1
    }

    /// The tree [`super::expose_forest::prove_forest_over`] builds over `t`
    /// leaves: a binary-counter cascade (merge equal-size peaks), then the
    /// surviving peaks chained left to right. `t = 1` is the lone leaf (the
    /// single-leaf case of the dist workers' identical in-slice cascade).
    pub fn forest(t: usize) -> Self {
        assert!(t >= 1, "a forest needs at least one leaf");
        let mut peaks: Vec<(u64, ForestShape)> = Vec::new();
        for _ in 0..t {
            let mut node = (1u64, ForestShape::Leaf);
            while peaks.last().is_some_and(|(sz, _)| *sz == node.0) {
                let (_, left) = peaks.pop().unwrap();
                node = (node.0 * 2, ForestShape::merge(left, node.1));
            }
            peaks.push(node);
        }
        let mut acc = peaks.remove(0).1;
        for (_, r) in peaks {
            acc = ForestShape::merge(acc, r);
        }
        acc
    }

    /// The left-leaning chain [`super::expose_forest::prove_chain_over`]
    /// (and the dist chain) folds: `merge(merge(merge(l1, l2), l3), ...)`.
    pub fn chain(t: usize) -> Self {
        assert!(t >= 1, "a chain needs at least one leaf");
        let mut acc = ForestShape::Leaf;
        for _ in 1..t {
            acc = ForestShape::merge(acc, ForestShape::Leaf);
        }
        acc
    }

    /// The multi-machine forest of `experiments::dist_compose` (forest mode):
    /// `t` leaves are cut into `machines` contiguous slices
    /// (`ceil(t / machines)` leaves each, empty tails dropped), each slice is
    /// folded with [`Self::forest`], then the slice roots are combined by
    /// stride-doubling reduction rounds (receiver `k` merges sender
    /// `k + stride`).
    pub fn dist_forest(t: usize, machines: usize) -> Self {
        assert!(t >= 1, "a forest needs at least one leaf");
        let per = t.div_ceil(machines.max(1));
        let mut roots: Vec<Option<ForestShape>> = (0..machines.max(1))
            .map(|i| (i * per, ((i + 1) * per).min(t)))
            .filter(|(a, b)| a < b)
            .map(|(a, b)| Some(ForestShape::forest(b - a)))
            .collect();
        let live = roots.len();
        let mut stride = 1usize;
        while stride < live {
            let pairs: Vec<(usize, usize)> = (0..live)
                .step_by(2 * stride)
                .filter_map(|k| (k + stride < live).then_some((k, k + stride)))
                .collect();
            if pairs.is_empty() {
                break;
            }
            for (recv, send) in pairs {
                let left = roots[recv].take().expect("receiver root");
                let right = roots[send].take().expect("sender root");
                roots[recv] = Some(ForestShape::merge(left, right));
            }
            stride *= 2;
        }
        roots[0].take().expect("machine 0 holds the whole-stream root")
    }
}

// ─── Proof metadata pin ──────────────────────────────────────────────────────

/// One non-primitive table's manifest entry, minus its public VALUES (those
/// are the statement — e.g. the exposed `(Com_before, Com_after)` — and are
/// checked against the expected boundary separately); their COUNT is pinned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpoShape {
    pub op_type: String,
    pub rows: usize,
    pub lanes: usize,
    pub air_variant: AirVariant,
    pub public_values_len: usize,
}

/// Everything the native verifier (`BatchStarkProver::verify_all_tables` in the
/// fork) reads from the proof besides the opened values: it rebuilds the table
/// AIRs from `table_packing`, `rows`, `ext_degree`/`w_binomial`, the
/// non-primitive manifest, and trusts `degree_bits` and the preprocessed
/// layout carried in `stark_common`. Pinning these alongside the preprocessed
/// commitment means none of them is taken on the prover's word (cf. upstream
/// `CircuitVerifier::validate_metadata`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundProofShape {
    pub table_packing: TablePacking,
    pub rows: RowCounts,
    pub alu_variant: AirVariant,
    pub ext_degree: usize,
    pub w_binomial: Option<u64>,
    pub alu_quintic_trinomial: bool,
    pub degree_bits: Vec<usize>,
    pub non_primitives: Vec<NpoShape>,
    /// Per instance `(matrix_index, width, degree_bits)` of its preprocessed
    /// matrix, and the matrix→instance map (`None` = no preprocessed data).
    pub preprocessed: Option<(Vec<Option<(usize, usize, usize)>>, Vec<usize>)>,
    pub opened_instances: usize,
}

/// Read a proof's [`BoundProofShape`].
pub fn bound_proof_shape<SC>(proof: &BatchStarkProof<SC>) -> BoundProofShape
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField64,
{
    BoundProofShape {
        table_packing: proof.table_packing.clone(),
        rows: proof.rows,
        alu_variant: proof.alu_variant,
        ext_degree: proof.ext_degree,
        w_binomial: proof.w_binomial.map(|w| w.as_canonical_u64()),
        alu_quintic_trinomial: proof.alu_quintic_trinomial,
        degree_bits: proof.proof.degree_bits.clone(),
        non_primitives: proof
            .non_primitives
            .iter()
            .map(|e| NpoShape {
                op_type: e.op_type.as_str().to_string(),
                rows: e.rows,
                lanes: e.lanes,
                air_variant: e.air_variant,
                public_values_len: e.public_values.len(),
            })
            .collect(),
        preprocessed: proof.stark_common.preprocessed.as_ref().map(|g| {
            (
                g.instances
                    .iter()
                    .map(|m| m.as_ref().map(|m| (m.matrix_index, m.width, m.degree_bits)))
                    .collect(),
                g.matrix_to_instance.clone(),
            )
        }),
        opened_instances: proof.proof.opened_values.instances.len(),
    }
}

/// A trusted root verification key: the preprocessed commitment (in
/// `vk_pin_values` order) plus, optionally, the proof metadata to pin.
/// Serializable, so an auditor can hold it as a file (e.g. postcard).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootVk<C> {
    pub commitment: Vec<C>,
    pub shape: Option<BoundProofShape>,
}

impl<C> RootVk<C> {
    /// A commitment-only pin (metadata still taken from the proof).
    pub fn commitment_only(commitment: Vec<C>) -> Self {
        Self { commitment, shape: None }
    }
}

// ─── Experiment-harness policy (`EXP_ROOT_VK`) ───────────────────────────────

/// Where an experiment harness's auditor takes the trusted root VK from
/// (environment variable `EXP_ROOT_VK`). Fails closed: the default derives the
/// VK from public parameters, and the vacuous self-pin needs an explicit
/// opt-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpRootVk {
    /// Unset, empty or `derive` (the default): derive the root VK from public
    /// parameters only (a no-op leaf plus the run's merge-tree shape) and
    /// verify the root against it. A derivation failure aborts the run. Where
    /// the auditor receives LEAF proofs directly (per-batch mode, or a
    /// one-batch stream) the trusted VK is the leaf VK (the no-op leaf's own),
    /// and each leaf is verified against it
    /// (`expose_forest::verify_leaves_against_log`).
    Derive,
    /// `self`: the LEGACY (pre-H2) self-pin — the VK is read from the received
    /// root itself, so the pin is vacuous; per-batch and lone-leaf proofs are
    /// not re-verified by the auditor (the provers' self-verify is reported).
    /// Kept only as an explicit opt-in for side-by-side timing runs; announced
    /// on stderr by [`warn_self_pinned_legacy`]. The batch-log check that
    /// still runs under it authenticates nothing.
    SelfPinnedLegacy,
    /// Anything else: a path to a postcard-encoded [`RootVk`] (supported by
    /// `experiments::dist_compose`, where one run has one root shape).
    File(std::path::PathBuf),
}

/// Parse `EXP_ROOT_VK` (see [`ExpRootVk`]).
pub fn exp_root_vk() -> ExpRootVk {
    match std::env::var("EXP_ROOT_VK").ok().as_deref().map(str::trim) {
        None | Some("") | Some("derive") => ExpRootVk::Derive,
        Some("self") => ExpRootVk::SelfPinnedLegacy,
        Some(path) => ExpRootVk::File(std::path::PathBuf::from(path)),
    }
}

/// Loud stderr notice for the opt-in legacy self-pin (`EXP_ROOT_VK=self`).
///
/// It covers every artifact the auditor receives: the composed root, and the
/// leaf proofs of the per-batch mode and of a one-batch stream (which under
/// `self` are not re-verified by the auditor at all; the reported verify time
/// is the provers' own self-verify). Without the pin the batch-log check is
/// worthless: a proof of ANY circuit that merely exposes the log's statement
/// passes it.
pub fn warn_self_pinned_legacy(context: &str) {
    eprintln!(
        "\n!!! WARNING ({context}): EXP_ROOT_VK=self — the root / leaf VK is SELF-PINNED \
         from the received proof (legacy, vacuous pin: a forged or wrong-shape proof is NOT \
         rejected by the VK check; per-batch and lone-leaf proofs are not re-verified by the \
         auditor at all). The statement / batch-log check is then WORTHLESS: any circuit \
         that exposes the log's values passes it. Only for side-by-side timing; unset \
         EXP_ROOT_VK (or set EXP_ROOT_VK=derive) for a trusted, derived VK. !!!\n"
    );
}

// ─── Derivation ──────────────────────────────────────────────────────────────

/// A proof's VK as the commitment OBJECT (what a parent merge bakes in).
pub type VkCommitment<SC> = p3_batch_stark::Commitment<SC>;

type MergeProver<SC> =
    Box<dyn Fn(&BatchStarkProof<SC>, &BatchStarkProof<SC>) -> BatchStarkProof<SC> + Send + Sync>;
type MergeVkWith<SC> = Box<
    dyn Fn(
        &BatchStarkProof<SC>,
        &VkCommitment<SC>,
        &BatchStarkProof<SC>,
        &VkCommitment<SC>,
    ) -> VkCommitment<SC>
        + Send
        + Sync,
>;
type CommitValues<SC, C> = Box<dyn Fn(&VkCommitment<SC>) -> Vec<C> + Send + Sync>;

/// Derives root VKs of arbitrary [`ForestShape`]s from one no-op dummy leaf.
///
/// Distinct subtree shapes are interned (hash-consed) and, per distinct
/// shape, one DUMMY proof and the REAL VK are memoised, so deriving the forest
/// root for `t` leaves proves only `O(log t)` dummy merges (the chain
/// `t - 1`); [`Self::root_commitment_unproved`] skips proving the root dummy.
///
/// The dummies are proofs of the **twin** merge circuit
/// (`expose_forest::MergeMode::Twin`): the real Interval atom enforces index
/// adjacency (`left.hi + 1 == right.lo`), so a dummy subtree cannot be merged
/// with ITSELF; the twin is the same circuit with the adjacency gap
/// `right.lo - left.hi` connected to `0` instead of `1` (same op list and
/// constant count, hence the same proof
/// shape and metadata, but a different VK). The REAL VK of a merge node is
/// then computed without proving, by building the real merge circuit over
/// the children's dummy proofs (shape only) with the children's real VKs
/// substituted (`merge_vk_with`); the real VK of the leaf is the no-op
/// leaf's own. The root's metadata is read off the root dummy. Under the
/// Boundary layout the twin is the real merge and this is exactly the
/// pre-B6(b) derivation.
///
/// The field backend (BabyBear or Goldilocks) is plugged in through three
/// functions: prove a twin merge, compute a real merge VK from child shapes
/// and VKs, and read a VK's field values.
pub struct ShapeVkDeriver<SC: StarkGenericConfig, C> {
    prove_twin_merge: MergeProver<SC>,
    merge_vk_with: MergeVkWith<SC>,
    commit_values: CommitValues<SC, C>,
    /// Interned shapes: id -> children ids (`None` = the leaf, id 0).
    nodes: Vec<Option<(usize, usize)>>,
    ids: HashMap<(usize, usize), usize>,
    /// Memoised dummy (twin) proof per interned shape id.
    proofs: Vec<Option<BatchStarkProof<SC>>>,
    /// Memoised REAL VK per interned shape id.
    vks: Vec<Option<VkCommitment<SC>>>,
    dummy_merges: usize,
}

impl<SC, C> ShapeVkDeriver<SC, C>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField64,
{
    /// `noop_leaf` must be a proof of the deployment's leaf circuit whose
    /// exposed initial and final boundaries are equal (the caller checks
    /// this; a non-contiguous leaf makes the first dummy merge unprovable).
    pub fn new(
        noop_leaf: BatchStarkProof<SC>,
        prove_twin_merge: MergeProver<SC>,
        merge_vk_with: MergeVkWith<SC>,
        commit_values: CommitValues<SC, C>,
    ) -> Self {
        let leaf_vk = noop_leaf
            .stark_common
            .preprocessed
            .as_ref()
            .expect("a bound leaf proof carries a preprocessed commitment")
            .commitment
            .clone();
        Self {
            prove_twin_merge,
            merge_vk_with,
            commit_values,
            nodes: vec![None],
            ids: HashMap::new(),
            proofs: vec![Some(noop_leaf)],
            vks: vec![Some(leaf_vk)],
            dummy_merges: 0,
        }
    }

    /// Number of dummy merge proofs generated so far (the derivation's cost).
    pub fn dummy_merges(&self) -> usize {
        self.dummy_merges
    }

    fn intern(&mut self, shape: &ForestShape) -> usize {
        match shape {
            ForestShape::Leaf => 0,
            ForestShape::Merge(l, r) => {
                let key = (self.intern(l), self.intern(r));
                if let Some(&id) = self.ids.get(&key) {
                    return id;
                }
                let id = self.nodes.len();
                self.nodes.push(Some(key));
                self.proofs.push(None);
                self.vks.push(None);
                self.ids.insert(key, id);
                id
            }
        }
    }

    /// The real VK of interned merge shape `(l, r)` (children ensured).
    fn real_merge_vk(&self, l: usize, r: usize) -> VkCommitment<SC> {
        (self.merge_vk_with)(
            self.proofs[l].as_ref().expect("left dummy"),
            self.vks[l].as_ref().expect("left VK"),
            self.proofs[r].as_ref().expect("right dummy"),
            self.vks[r].as_ref().expect("right VK"),
        )
    }

    /// Ensure the dummy proof AND the real VK of interned shape `id` are
    /// memoised.
    fn ensure(&mut self, id: usize) {
        if self.proofs[id].is_some() && self.vks[id].is_some() {
            return;
        }
        let (l, r) = self.nodes[id].expect("the leaf proof is memoised at construction");
        self.ensure(l);
        self.ensure(r);
        if self.vks[id].is_none() {
            self.vks[id] = Some(self.real_merge_vk(l, r));
        }
        if self.proofs[id].is_none() {
            let merged = (self.prove_twin_merge)(
                self.proofs[l].as_ref().expect("left child"),
                self.proofs[r].as_ref().expect("right child"),
            );
            self.dummy_merges += 1;
            self.proofs[id] = Some(merged);
        }
    }

    /// The dummy (twin) proof of `shape`'s root, proving it if needed. Its
    /// SHAPE equals the real root's; under the Interval layout its VK does
    /// not (see the type docs).
    pub fn dummy_proof(&mut self, shape: &ForestShape) -> &BatchStarkProof<SC> {
        let id = self.intern(shape);
        self.ensure(id);
        self.proofs[id].as_ref().expect("ensured")
    }

    /// Full trusted root VK of `shape`: the real root commitment plus the
    /// metadata read off the root dummy.
    pub fn root_vk(&mut self, shape: &ForestShape) -> RootVk<C> {
        let id = self.intern(shape);
        self.ensure(id);
        let proof = self.proofs[id].as_ref().expect("ensured");
        RootVk {
            commitment: (self.commit_values)(self.vks[id].as_ref().expect("ensured")),
            shape: Some(bound_proof_shape(proof)),
        }
    }

    /// The root's preprocessed commitment computed from its circuit alone —
    /// the root merge is built over dummy children but never run or proved.
    pub fn root_commitment_unproved(&mut self, shape: &ForestShape) -> Vec<C> {
        let id = self.intern(shape);
        let vk = match self.nodes[id] {
            None => self.vks[0].clone().expect("leaf VK"),
            Some((l, r)) => {
                self.ensure(l);
                self.ensure(r);
                self.real_merge_vk(l, r)
            }
        };
        (self.commit_values)(&vk)
    }
}

#[cfg(test)]
mod tests {
    use super::ForestShape;

    #[test]
    fn forest_shapes_match_cascade() {
        use ForestShape::Leaf;
        let m = ForestShape::merge;
        assert_eq!(ForestShape::forest(1), Leaf);
        assert_eq!(ForestShape::forest(2), m(Leaf, Leaf));
        assert_eq!(ForestShape::forest(3), m(m(Leaf, Leaf), Leaf));
        assert_eq!(ForestShape::forest(4), m(m(Leaf, Leaf), m(Leaf, Leaf)));
        // 7 = 4 + 2 + 1: peaks chained left to right.
        let p4 = m(m(Leaf, Leaf), m(Leaf, Leaf));
        assert_eq!(ForestShape::forest(7), m(m(p4, m(Leaf, Leaf)), Leaf));
        assert_eq!(ForestShape::chain(3), m(m(Leaf, Leaf), Leaf));
        for t in 1..40 {
            assert_eq!(ForestShape::forest(t).num_leaves(), t);
            assert_eq!(ForestShape::chain(t).num_leaves(), t);
            for machines in 1..9 {
                assert_eq!(ForestShape::dist_forest(t, machines).num_leaves(), t, "t={t} M={machines}");
            }
        }
        // One machine = the plain forest; t <= machines = one leaf per slice
        // reduced by stride doubling (a balanced tree for powers of two).
        assert_eq!(ForestShape::dist_forest(6, 1), ForestShape::forest(6));
        assert_eq!(ForestShape::dist_forest(4, 4), ForestShape::forest(4));
        // 5 leaves on 2 machines: slices of 3 and 2.
        assert_eq!(
            ForestShape::dist_forest(5, 2),
            m(ForestShape::forest(3), ForestShape::forest(2))
        );
    }
}
