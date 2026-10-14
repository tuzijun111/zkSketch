//! In-circuit **boundary-bound** recursive streaming forest, via the Expose NPO.
//!
//! [`countmin_forest_v9`](super::countmin_forest_v9) already folds the
//! intermediates away (O(1) root, no `Com(S_i)` exposed) but binds the *outer*
//! boundaries natively. This module closes that gap: each leaf surfaces its
//! `(Com_before, Com_after)` via the Expose NPO, and each merge
//!
//! 1. recursively verifies both children in-circuit,
//! 2. reads the children's surfaced boundaries as `air_public_targets`,
//! 3. binds `left.final == right.initial` **in-circuit** (`connect`),
//! 4. re-exposes only `(left.initial, right.final)` via its *own* Expose NPO.
//!
//! Composed in a Bentley–Saxe cascade, the single root proof's public values
//! are exactly `(Com(S_0), Com(S_E))` — bound to the verified leaves, with the
//! intermediates neither exposed nor natively trusted.
//!
//! The leaf here ([`prove_boundary_leaf`]) is a *minimal* leaf that exposes a
//! claimed `(initial, final)` boundary — it demonstrates the binding mechanism
//! independent of any sketch's internal update logic. Any real leaf (e.g. the
//! v9 Count-Min leaf) participates by adding the same `add_expose` of its
//! boundary commitments; the merge/forest below compose it unchanged.
//!
//! ## Interval statement (revision B6(b))
//!
//! The `(initial, final)` statement above (the **Boundary** layout) certifies
//! only that SOME batch sequence maps `S_0` to `S_E`. Leaves built with
//! `Expose::Interval` (see [`crate::recursion::recursive::statement`]) expose
//! `(init, final, idx = (t, t), H = Poseidon2(TAG_LEAF, t, Com(B_t)))`, and the
//! merge atom is layout-dispatched: over Interval children it additionally
//! enforces `right.lo - left.hi == 1` in-circuit and exposes
//! `(left.init, right.final, (left.lo, right.hi), Poseidon2([TAG_MERGE, i, h, j], H_L, H_R))`.
//! The auditor ([`verify_bound_stark_proof_against_log`]) pins the root VK,
//! verifies the STARK, and checks the root statement against the public batch
//! log under the declared bracketing. Boundary-layout children still get the
//! pre-B6(b) merge circuit op for op (side-by-side runs, the toy leaves).

use std::rc::Rc;

use p3_batch_stark::common::GlobalPreprocessed;
use p3_batch_stark::{CommonData, Commitment, ProverData};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::generate_expose_trace;
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    common::get_airs_and_degrees_with_prep,
};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::pcs::MerkleCapTargets;
use p3_recursion::{
    AggregationPrepCache, BatchOnly, PcsRecursionBackend, Poseidon2Config, ProveNextLayerParams,
    RecursionInput, RecursionOutput, Recursive, Target, VerifierCircuitResult,
    prove_aggregation_layer,
};
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::countmin::CountMinCommit;
use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, DIGEST_ELEMS, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::{make_leaf_config, pack_commit_to_challenge};
use crate::recursion::recursive::root_vk::{
    BoundProofShape, ForestShape, RootVk, ShapeVkDeriver, bound_proof_shape,
};
use crate::recursion::recursive::statement::{
    BatchLog, Expose, Layout, Statement, TAG_MERGE, check_leaf_statements_against_log,
    check_prefix_statements, check_root_statement, hash_bb, parse_statement,
};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Number of base-field elements per commitment (`CountMinCommit` is `[Val; 8]`).
const COMMIT_LEN: usize = 8;

fn agg_params() -> ProveNextLayerParams {
    ProveNextLayerParams {
        table_packing: TablePacking::new(2, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP),
        constraint_profile: ConstraintProfile::Standard,
    }
}

/// The observation-ordered field values of a bound proof's **preprocessed
/// commitment** — its verification key (VK). The recursion backend bakes each
/// child's VK into its parent merge's preprocessed trace as constants (so the
/// merge's own VK depends on its children's); the auditor pins the *root*
/// proof's VK to a trusted copy of these values (see [`verify_bound_stark_proof`]),
/// which transitively anchors the whole tree. The VK is a deterministic,
/// transparent function of the circuit alone (its op list, including constant
/// values) — for real sketch leaves, whose boundaries are witnesses, it is
/// independent of the data — so it is a legitimate public parameter, not a
/// trusted setup; [`derive_forest_root_vk`] recomputes it from public
/// parameters only.
pub fn vk_pin_values(proof: &BatchStarkProof<ConfigWithFriParams>) -> Vec<Challenge> {
    common_vk_pin_values(&proof.stark_common)
}

/// [`vk_pin_values`] of the proofs a circuit's prover data produces, read
/// from that [`CommonData`] (e.g. a prebuilt leaf's) without proving anything.
pub fn common_vk_pin_values(common: &CommonData<ConfigWithFriParams>) -> Vec<Challenge> {
    let commitment = &common
        .preprocessed
        .as_ref()
        .expect("a boundary-bound proof carries a preprocessed commitment")
        .commitment;
    <MerkleCapTargets<Val, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(commitment)
}

/// Build a `RecursionInput::BatchStark` that carries the proof's per-table
/// public values (so surfaced Expose values reach the next layer's
/// `air_public_targets`). The stock `RecursionOutput::into_recursion_input`
/// empties them; this reconstructs them from the proof: primitive tables
/// contribute nothing, each non-primitive table contributes its recorded
/// `public_values`.
pub fn recursion_input_with_public_values(
    output: &RecursionOutput<ConfigWithFriParams>,
) -> RecursionInput<'_, ConfigWithFriParams, BatchOnly> {
    recursion_input_from_proof(&output.0)
}

/// [`recursion_input_with_public_values`] from a bare proof. Everything the
/// next layer's verifier circuit needs lives in the `BatchStarkProof` itself
/// (`proof`, `stark_common`, the non-primitives' recorded `public_values`) —
/// the `Rc<CircuitProverData>` half of a `RecursionOutput` is never consumed.
/// This is what makes proofs **portable across machines**: a merge node can
/// deserialize a peer's proof bytes and fold them without any local circuit
/// state from the producing process. (Wire-crossing proofs additionally need
/// their `CommonData` rebuilt — see [`rebuilt_common_for`].)
pub fn recursion_input_from_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> RecursionInput<'_, ConfigWithFriParams, BatchOnly> {
    recursion_input_with_common(proof, &proof.stark_common)
}

/// [`recursion_input_from_proof`] with an explicit [`CommonData`] — the
/// deserialized-proof path, where `proof.stark_common` lost its lookups on
/// the wire and a rebuilt copy must be supplied.
pub fn recursion_input_with_common<'a>(
    proof: &'a BatchStarkProof<ConfigWithFriParams>,
    common: &'a CommonData<ConfigWithFriParams>,
) -> RecursionInput<'a, ConfigWithFriParams, BatchOnly> {
    let n_instances = proof.proof.opened_values.instances.len();
    let n_non_prim = proof.non_primitives.len();
    let n_prim = n_instances - n_non_prim;

    let mut table_public_inputs: Vec<Vec<Val>> = vec![Vec::new(); n_prim];
    for entry in &proof.non_primitives {
        table_public_inputs.push(entry.public_values.clone());
    }

    RecursionInput::BatchStark { proof, common_data: common, table_public_inputs }
}

/// Rebuild a wire-crossing proof's [`CommonData`], or `None` when the proof's
/// own `stark_common` is intact (in-process proofs). Serialization
/// intentionally drops the lookup contexts (`serde_stark_common` in the
/// fork), so a deserialized proof carries an empty `lookups` and would fail
/// the recursive verifier's shape check; the fork's
/// `BatchStarkProver::rebuild_common_data` re-derives them from AIRs
/// reconstructed out of proof metadata. Every non-primitive any zkSketch
/// proof can carry is registered (aggregation trio + the sketch leaves'
/// permute/range), so leaves and merge roots both rebuild.
pub fn rebuilt_common_for(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> Option<CommonData<ConfigWithFriParams>> {
    let n_instances = proof.proof.opened_values.instances.len();
    if proof.stark_common.lookups.len() == n_instances {
        return None;
    }
    let mut prover = BatchStarkProver::new(make_leaf_config());
    prover.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    prover.register_expose_table::<EXT_D>();
    prover.register_permute_table::<EXT_D>();
    prover.register_range_table::<EXT_D>();
    Some(prover.rebuild_common_data(proof).expect("rebuild common data for deserialized proof"))
}

/// Prove a minimal leaf that exposes the given Challenge values via the Expose
/// NPO (each becomes `D` surfaced base public values).
pub fn prove_exposing_leaf(values: &[Challenge]) -> RecursionOutput<ConfigWithFriParams> {
    let config = make_leaf_config();

    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_expose(generate_expose_trace::<Val, Challenge>);
    let wires: Vec<_> = values.iter().map(|&v| b.alloc_const(v, "exposed")).collect();
    b.add_expose(&wires).expect("add_expose");
    let circuit = b.build().expect("build exposing leaf");

    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).expect("set_public_inputs");
        runner.run().expect("run exposing circuit")
    };

    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![p3_circuit_prover::expose_preprocessor::<Val>()];
    let air_builders = p3_circuit_prover::expose_air_builders::<ConfigWithFriParams, EXT_D>();

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, EXT_D>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (exposing leaf)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_expose_table::<EXT_D>();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (exposing leaf)");
    prover.verify_all_tables(&proof).expect("self-verify exposing leaf");

    RecursionOutput(proof, Rc::new(circuit_prover_data))
}

/// Prove a boundary leaf: surface `(initial, final)` commitments via Expose.
/// Each commitment packs into `DIGEST_PACKING = 2` Challenge wires, so the
/// leaf exposes 4 wires → 16 surfaced base values laid out as
/// `[initial[0..8], final[0..8]]`.
pub fn prove_boundary_leaf(
    initial: CountMinCommit,
    final_: CountMinCommit,
) -> RecursionOutput<ConfigWithFriParams> {
    let iv = pack_commit_to_challenge(&initial);
    let fv = pack_commit_to_challenge(&final_);
    prove_exposing_leaf(&[iv[0], iv[1], fv[0], fv[1]])
}

/// The exposed statement targets of a verified child: the (unique) non-empty
/// per-instance `air_public_targets` entry, and its [`Layout`] —
/// `Boundary`: `[initial[0..8], final[0..8]]` (16 base-field targets);
/// `Interval`: additionally `[idx (lo, hi, 0, 0), H[0..8]]` (28 targets).
fn statement_targets(
    result: &impl VerifierCircuitResult<ConfigWithFriParams, BatchOnly>,
) -> (Layout, Vec<Target>) {
    let all = result.air_public_targets();
    all.into_iter()
        .find_map(|t| Layout::of_len(t.len(), COMMIT_LEN, EXT_D).map(|l| (l, t)))
        .expect("verified child must surface a 16-element (Boundary) or 28-element (Interval) statement")
}

/// The exposed public values of a proof's Expose table (the unique
/// non-primitive whose public-value count matches a statement layout).
fn exposed_values(proof: &BatchStarkProof<ConfigWithFriParams>) -> &[Val] {
    proof
        .non_primitives
        .iter()
        .map(|e| e.public_values.as_slice())
        .find(|v| Layout::of_len(v.len(), COMMIT_LEN, EXT_D).is_some())
        .expect("proof must surface a 16-element (Boundary) or 28-element (Interval) statement")
}

/// Read the `(initial, final)` commitments a proof surfaced via its Expose
/// table (the first `2 * COMMIT_LEN` values of either layout).
pub fn read_exposed_boundary(
    output: &RecursionOutput<ConfigWithFriParams>,
) -> (CountMinCommit, CountMinCommit) {
    read_exposed_boundary_proof(&output.0)
}

/// [`read_exposed_boundary`] from a bare proof (e.g. one deserialized from a
/// peer machine's bytes).
pub fn read_exposed_boundary_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
) -> (CountMinCommit, CountMinCommit) {
    let pv = exposed_values(proof);
    let mut initial = [Val::ZERO; COMMIT_LEN];
    let mut final_ = [Val::ZERO; COMMIT_LEN];
    initial.copy_from_slice(&pv[0..COMMIT_LEN]);
    final_.copy_from_slice(&pv[COMMIT_LEN..2 * COMMIT_LEN]);
    (CountMinCommit(initial), CountMinCommit(final_))
}

/// The full statement a proof surfaced (either layout; see
/// [`crate::recursion::recursive::statement`]).
pub fn read_exposed_statement(proof: &BatchStarkProof<ConfigWithFriParams>) -> Statement<Val> {
    parse_statement(exposed_values(proof), COMMIT_LEN, EXT_D).expect("statement layout")
}

/// In-circuit hiding merge of two adjacent children: verify both, bind
/// `left.final == right.initial` in-circuit, and re-expose only
/// `(left.initial, right.final)`. The returned proof surfaces exactly the
/// outer boundary `(Com_before, Com_after)`.
pub fn prove_hiding_merge(
    left: &RecursionOutput<ConfigWithFriParams>,
    right: &RecursionOutput<ConfigWithFriParams>,
) -> RecursionOutput<ConfigWithFriParams> {
    prove_hiding_merge_proofs(&left.0, &right.0)
}

/// [`prove_hiding_merge`] over bare proofs. The merge circuit consumes only
/// the children's `BatchStarkProof`s (see [`recursion_input_from_proof`]), so
/// either child may have been produced by a **different process/machine** and
/// deserialized from wire bytes — the enabling property for distributed
/// composition (each machine folds its own slice, then subtree roots cross
/// machines as serialized proofs).
pub fn prove_hiding_merge_proofs(
    left: &BatchStarkProof<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
) -> RecursionOutput<ConfigWithFriParams> {
    let config = make_leaf_config();
    let backend = make_backend();
    let params = agg_params();

    // Deserialized children carry no lookup contexts — rebuild before wiring
    // the verifier circuits (in-process children skip this, `None`).
    let left_common = rebuilt_common_for(left);
    let right_common = rebuilt_common_for(right);
    let left_input =
        recursion_input_with_common(left, left_common.as_ref().unwrap_or(&left.stark_common));
    let right_input =
        recursion_input_with_common(right, right_common.as_ref().unwrap_or(&right.stark_common));

    let (circuit, left_result, right_result) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real);

    prove_aggregation_layer::<ConfigWithFriParams, BatchOnly, BatchOnly, Backend, EXT_D>(
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &circuit,
        &config,
        &backend,
        &params,
        None,
    )
    .expect("prove hiding merge")
}

// ─── Harness memory/time switches (M0) ───────────────────────────────────────
//
// Each defaults to the new behaviour; the "off" value restores the pre-M0
// behaviour exactly (side-by-side runs). None changes a circuit, a VK or a
// proof statement: they only decide what the PROVER keeps in memory.

/// `EXP_FOREST_RETAIN_PREP=1`: the pre-M0 behaviour, where every live peak of
/// a [`ForestCascade`] (and the procs worker's chain prefix and slice root)
/// keeps its whole [`RecursionOutput`], i.e. the merge circuit's
/// `Rc<CircuitProverData>` (about 1 GB per merge under ZK) next to the proof.
/// Default (unset or anything else): keep the bare [`BatchStarkProof`] only
/// ([`PeakProof::Bare`]); a merge reads nothing else.
pub fn forest_retain_prep() -> bool {
    std::env::var("EXP_FOREST_RETAIN_PREP").is_ok_and(|v| v.trim() == "1")
}

/// `EXP_MERGE_CACHE=0`: no [`MergeCache`] in [`ForestCascade::new`] (the
/// pre-M0 behaviour: every merge rebuilds its circuit, AIRs and preprocessed
/// commitment). Default: a cache of `EXP_MERGE_CACHE_ENTRIES` entries
/// (default 1; `0` also disables it).
pub fn merge_cache_from_env() -> Option<MergeCache> {
    if std::env::var("EXP_MERGE_CACHE").is_ok_and(|v| v.trim() == "0") {
        return None;
    }
    let cap = std::env::var("EXP_MERGE_CACHE_ENTRIES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(1);
    (cap > 0).then(|| MergeCache::new(cap))
}

/// A proof kept by the prover between merges: a forest peak, the chain's
/// running prefix, a slice root.
///
/// `Bare` (the default) is the proof alone, which is everything a later merge,
/// a query certificate or the wire ever reads ([`recursion_input_from_proof`]).
/// `Retained` is the pre-M0 [`RecursionOutput`], which also pins the producing
/// circuit's prover data (`EXP_FOREST_RETAIN_PREP=1`).
pub enum PeakProof {
    Bare(BatchStarkProof<ConfigWithFriParams>),
    Retained(RecursionOutput<ConfigWithFriParams>),
}

impl PeakProof {
    /// Keep `output` whole (`retain_prep`) or drop its prover data now.
    pub fn keep(output: RecursionOutput<ConfigWithFriParams>, retain_prep: bool) -> Self {
        if retain_prep { Self::Retained(output) } else { Self::Bare(output.0) }
    }

    pub fn proof(&self) -> &BatchStarkProof<ConfigWithFriParams> {
        match self {
            Self::Bare(p) => p,
            Self::Retained(o) => &o.0,
        }
    }

    /// Whether this value still pins a circuit's prover data.
    pub fn holds_prover_data(&self) -> bool {
        matches!(self, Self::Retained(_))
    }

    pub fn into_proof(self) -> BatchStarkProof<ConfigWithFriParams> {
        match self {
            Self::Bare(p) => p,
            Self::Retained(o) => o.0,
        }
    }

    /// The whole [`RecursionOutput`], when it was retained.
    pub fn into_output(self) -> Option<RecursionOutput<ConfigWithFriParams>> {
        match self {
            Self::Bare(_) => None,
            Self::Retained(o) => Some(o),
        }
    }
}

/// One child of a cached merge, as the merge circuit sees it: its VK (baked
/// into the merge circuit as constants), its proof shape (which fixes the
/// verifier circuit's structure) and whether its `CommonData` had to be
/// rebuilt (a deserialized child).
#[derive(Clone, Debug, PartialEq)]
struct MergeChildKey {
    vk: Vec<Challenge>,
    shape: BoundProofShape,
    rebuilt_common: bool,
}

/// What a built hiding-merge circuit depends on (besides the fixed config and
/// backend): both children's [`MergeChildKey`] and the [`MergeMode`].
#[derive(Clone, Debug, PartialEq)]
pub struct MergeCacheKey {
    left: MergeChildKey,
    right: MergeChildKey,
    mode: MergeMode,
}

impl MergeCacheKey {
    fn new(
        left: &BatchStarkProof<ConfigWithFriParams>,
        left_rebuilt: bool,
        right: &BatchStarkProof<ConfigWithFriParams>,
        right_rebuilt: bool,
        mode: MergeMode,
    ) -> Self {
        let child = |p: &BatchStarkProof<ConfigWithFriParams>, rebuilt_common: bool| MergeChildKey {
            vk: vk_pin_values(p),
            shape: bound_proof_shape(p),
            rebuilt_common,
        };
        Self { left: child(left, left_rebuilt), right: child(right, right_rebuilt), mode }
    }

    /// The key of the REAL merge of `left` and `right`.
    pub fn of(
        left: &BatchStarkProof<ConfigWithFriParams>,
        right: &BatchStarkProof<ConfigWithFriParams>,
    ) -> Self {
        let rebuilt = |p: &BatchStarkProof<ConfigWithFriParams>| {
            p.stark_common.lookups.len() != p.proof.opened_values.instances.len()
        };
        Self::new(left, rebuilt(left), right, rebuilt(right), MergeMode::Real)
    }
}

struct MergeCacheEntry {
    key: MergeCacheKey,
    /// Eviction rank: the merged subtree's leaf count (smaller subtrees merge
    /// more often, so they are kept first).
    rank: u64,
    last_used: u64,
    circuit: p3_circuit::Circuit<Challenge>,
    left_result: MergeVerifierResult,
    right_result: MergeVerifierResult,
    /// The fork's slot: the circuit's prover data (AIRs + preprocessed
    /// commitment) and its prover. The fork compares the fingerprint of the
    /// circuit it is handed with the one stored here, but a hit always hands
    /// it [`Self::circuit`], from which this slot was built, so that check
    /// cannot fail here: whether a hit is the right circuit rests on
    /// [`MergeCacheKey`] alone.
    prep: Option<AggregationPrepCache<ConfigWithFriParams>>,
}

/// **PROVER-SIDE** cache of built hiding-merge circuits (`EXP_MERGE_CACHE`).
///
/// A merge's circuit depends only on its children's VKs and proof shapes
/// (plus the merge mode, the config and the backend, which are fixed), never
/// on their data: the verifier circuit reads each child proof through public
/// and private inputs set at run time. So every merge of a forest level after
/// the first can reuse the level's circuit, its verifier results and the
/// fork's [`AggregationPrepCache`] (the AIRs and the preprocessed commitment),
/// about 1.1 s per merge. The key is [`MergeCacheKey`] (both children's VK
/// values and [`BoundProofShape`], whether their common data was rebuilt, and
/// the mode), and it is the only guard: on a hit the fork's circuit
/// fingerprint is computed from the cached circuit itself, so it is not a
/// second, independent check (the tests pin every hit to the merge VK derived
/// without the cache, [`hiding_merge_vk`] / [`root_vk_deriver`]).
///
/// It never feeds the auditor: VKs are always derived independently from
/// public parameters ([`root_vk_deriver`]), so a mis-keyed entry could only
/// produce a proof that fails verification. ZK is unaffected: the cached
/// prover's mask RNG advances from proof to proof (and `ZkRng` reseeds from
/// the OS on clone).
///
/// An entry holds a merge's prover data (0.4-1.1 GB under ZK, measured) and
/// keeps it resident through every later leaf proof and uncached merge
/// ([`Self::holds_prover_data`]), so the cache is bounded: at most
/// `capacity` entries, ranked by the merged subtree's leaf count. A new circuit is admitted while there is room, or in place of
/// the largest-rank entry (the least recently used among equals) when its own
/// rank is not larger; otherwise the merge is proved uncached. With one
/// entry, a Bentley–Saxe cascade keeps its two-leaf merge circuit, which
/// serves `T/2 - 1` of its `T - 1` merges.
pub struct MergeCache {
    capacity: usize,
    entries: Vec<MergeCacheEntry>,
    clock: u64,
    hits: u64,
    misses: u64,
}

impl MergeCache {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, entries: Vec::new(), clock: 0, hits: 0, misses: 0 }
    }

    /// Merges that reused a cached circuit.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Merges that built their circuit.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether an entry pins a merge circuit's prover data (the fork's
    /// [`AggregationPrepCache`]: AIRs, preprocessed commitment, prover).
    pub fn holds_prover_data(&self) -> bool {
        self.entries.iter().any(|e| e.prep.is_some())
    }

    /// Whether the real merge of `left` and `right` would reuse a cached circuit.
    pub fn contains(
        &self,
        left: &BatchStarkProof<ConfigWithFriParams>,
        right: &BatchStarkProof<ConfigWithFriParams>,
    ) -> bool {
        let key = MergeCacheKey::of(left, right);
        self.entries.iter().any(|e| e.key == key)
    }

    /// Admission of a new entry of `rank`: `None` = do not cache it;
    /// `Some(victim)` = cache it, after evicting `victim` if any.
    fn admission(&self, rank: u64) -> Option<Option<usize>> {
        if self.entries.len() < self.capacity {
            return Some(None);
        }
        let victim = self
            .entries
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.rank.cmp(&b.rank).then(b.last_used.cmp(&a.last_used)))
            .map(|(i, e)| (i, e.rank))?;
        (rank <= victim.1).then_some(Some(victim.0))
    }

    /// [`prove_hiding_merge_proofs`] through the cache: the same circuit,
    /// hence the same VK and statement, for the same children. `rank` is the
    /// merged subtree's leaf count (the eviction order).
    pub fn merge(
        &mut self,
        left: &BatchStarkProof<ConfigWithFriParams>,
        right: &BatchStarkProof<ConfigWithFriParams>,
        rank: u64,
    ) -> RecursionOutput<ConfigWithFriParams> {
        let config = make_leaf_config();
        let backend = make_backend();
        let params = agg_params();
        let left_common = rebuilt_common_for(left);
        let right_common = rebuilt_common_for(right);
        let left_input =
            recursion_input_with_common(left, left_common.as_ref().unwrap_or(&left.stark_common));
        let right_input =
            recursion_input_with_common(right, right_common.as_ref().unwrap_or(&right.stark_common));
        let key = MergeCacheKey::new(
            left,
            left_common.is_some(),
            right,
            right_common.is_some(),
            MergeMode::Real,
        );
        let prove = |circuit: &p3_circuit::Circuit<Challenge>,
                     left_result: &MergeVerifierResult,
                     right_result: &MergeVerifierResult,
                     prep: Option<&mut Option<AggregationPrepCache<ConfigWithFriParams>>>| {
            prove_aggregation_layer::<ConfigWithFriParams, BatchOnly, BatchOnly, Backend, EXT_D>(
                &left_input,
                &right_input,
                left_result,
                right_result,
                circuit,
                &config,
                &backend,
                &params,
                prep,
            )
            .expect("prove hiding merge")
        };
        self.clock += 1;
        if let Some(e) = self.entries.iter_mut().find(|e| e.key == key) {
            self.hits += 1;
            e.last_used = self.clock;
            return prove(&e.circuit, &e.left_result, &e.right_result, Some(&mut e.prep));
        }
        self.misses += 1;
        let (circuit, left_result, right_result) =
            build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real);
        let Some(victim) = self.admission(rank) else {
            return prove(&circuit, &left_result, &right_result, None);
        };
        if let Some(i) = victim {
            self.entries.swap_remove(i);
        }
        let mut prep = None;
        let out = prove(&circuit, &left_result, &right_result, Some(&mut prep));
        self.entries.push(MergeCacheEntry {
            key,
            rank,
            last_used: self.clock,
            circuit,
            left_result,
            right_result,
            prep,
        });
        out
    }
}

/// DERIVATION ONLY: prove the **twin** of the hiding merge over `left` and
/// `right` (see [`MergeMode::Twin`]). The twin accepts a child merged with
/// ITSELF, which the real Interval merge (index adjacency) rejects, so
/// [`ShapeVkDeriver`] can keep one memoised dummy proof per subtree shape. A
/// twin proof never verifies under a real VK (its circuit differs), so it is
/// useless to a prover; the deriver only reads its proof SHAPE.
fn prove_twin_merge_proofs(
    left: &BatchStarkProof<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
) -> BatchStarkProof<ConfigWithFriParams> {
    let config = make_leaf_config();
    let backend = make_backend();
    let params = agg_params();
    let left_input = recursion_input_from_proof(left);
    let right_input = recursion_input_from_proof(right);
    let (circuit, left_result, right_result) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Twin);
    prove_aggregation_layer::<ConfigWithFriParams, BatchOnly, BatchOnly, Backend, EXT_D>(
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &circuit,
        &config,
        &backend,
        &params,
        None,
    )
    .expect("prove twin merge (VK derivation)")
    .0
}

/// Test hook: a twin merge proof, for the attack test that submits one as a
/// root (`interval_tests::twin_merge_root_rejected_by_root_vk`).
#[cfg(test)]
pub(crate) fn prove_twin_merge_for_test(
    left: &BatchStarkProof<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
) -> BatchStarkProof<ConfigWithFriParams> {
    prove_twin_merge_proofs(left, right)
}

type MergeVerifierResult =
    <Backend as PcsRecursionBackend<ConfigWithFriParams, BatchOnly, EXT_D>>::VerifierResult;

/// Which merge circuit [`build_hiding_merge_circuit`] emits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MergeMode {
    /// The composition atom.
    Real,
    /// VK-derivation twin (Interval layout only): identical op list and
    /// constant set, except that the index-adjacency gap `right.lo - left.hi`
    /// is connected to the constant `0` instead of `1`, so a no-op leaf's
    /// dummy subtree (`lo == hi`) merges with itself. Same trace shape as
    /// the real atom, different VK. Under the Boundary layout the twin IS
    /// the real merge.
    Twin,
}

/// The hiding-merge circuit over two children (shared by
/// [`prove_hiding_merge_proofs`] and [`hiding_merge_vk`]): verify both children
/// in-circuit, bind `left.final == right.initial`, re-expose the outer
/// boundary. Its structure depends only on the children's proof shape and VKs.
///
/// The children's statement [`Layout`] selects the atom:
/// * `Boundary` (pre-B6(b), unchanged op for op): re-expose
///   `(left.initial, right.final)`.
/// * `Interval`: additionally assert `left.hi + 1 == right.lo` and expose
///   `(left.initial, right.final, (left.lo, right.hi, 0, 0), H)` with
///   `H = Poseidon2([TAG_MERGE, i, h, j], H_L, H_R)`.
fn build_hiding_merge_circuit(
    left_input: &RecursionInput<'_, ConfigWithFriParams, BatchOnly>,
    right_input: &RecursionInput<'_, ConfigWithFriParams, BatchOnly>,
    config: &ConfigWithFriParams,
    backend: &Backend,
    mode: MergeMode,
) -> (p3_circuit::Circuit<Challenge>, MergeVerifierResult, MergeVerifierResult) {
    // Assemble a custom aggregation circuit: verify both children, then bind +
    // re-expose their boundaries.
    let mut cb = CircuitBuilder::<Challenge>::new();
    cb.enable_expose(generate_expose_trace::<Val, Challenge>);
    // `prepare_circuit` enables the verifier's NPOs (challenger perm, recompose,
    // poseidon2); recompose is reused below to repack the outer boundary.
    PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::prepare_circuit(
        backend, config, &mut cb,
    )
    .expect("prepare merge circuit");

    let left_result = PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::build_verifier_circuit(
        backend, left_input, config, &mut cb,
    )
    .expect("verify left child");
    let right_result = PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::build_verifier_circuit(
        backend, right_input, config, &mut cb,
    )
    .expect("verify right child");

    // VK anchor: each verified child's preprocessed commitment (its VK) is baked
    // into this merge's circuit as constants by the recursion backend
    // (`Comm::new_const`, via `CommonDataTargets::new`), rather than left as a free
    // public input. That makes this merge's own preprocessed trace — hence its VK —
    // depend on its children's VKs, so the auditor's single trusted root-VK pin
    // ([`verify_bound_stark_proof`]) transitively anchors every child in the tree.
    // Without it a malicious prover could feed a forged child (e.g. an Expose table
    // with `is_real = 0`, decoupling the surfaced boundary from any witness) and
    // re-expose an arbitrary `(Com_before, Com_after)`.

    // [left.initial 0..8, left.final 8..16 (, idx 16..20, H 20..28)]
    let (left_layout, lb) = statement_targets(&left_result);
    let (right_layout, rb) = statement_targets(&right_result);
    assert_eq!(
        left_layout, right_layout,
        "hiding merge: children expose different statement layouts"
    );

    // (3) Contiguity, in-circuit: left.final == right.initial (8 base elements).
    // Assert via subtraction (`connect(sub(a,b), zero)`) rather than connecting
    // the two verification-created targets directly — a direct connect would
    // double-create on the WitnessChecks bus; the sub *reads* both operands so
    // the bus balances.
    let zero = cb.alloc_const(Challenge::ZERO, "zero");
    for k in 0..COMMIT_LEN {
        let diff = cb.sub(lb[COMMIT_LEN + k], rb[k]);
        cb.connect(diff, zero);
    }

    // Interval layout: index adjacency `right.lo - left.hi == 1` (the twin
    // asserts `== 0`), with the same sub/connect-to-constant discipline. Both
    // constants are allocated in both modes and the op list is identical (one
    // ALU sub; an `x + 0` would be folded away), so the twin has exactly the
    // real atom's trace shape.
    //
    // The adjacency is a FIELD equation: a BabyBear leaf pins `t` only below
    // p, so it wraps (leaves at `t = p - 1` and `t = 0` merge; see
    // `interval_tests::index_wrap_merges_in_circuit_but_root_rejected`). An
    // intermediate `(lo, hi)` is meaningful only under a root the auditor
    // accepted with `lo == 1`, `hi == T < p` and the recomputed digest
    // (`statement::check_root_statement`), which rule wrapped trees out.
    if left_layout == Layout::Interval {
        let one = cb.alloc_const(Challenge::ONE, "one");
        let step = if mode == MergeMode::Twin { zero } else { one };
        let (lo, hi) = (2 * COMMIT_LEN, 2 * COMMIT_LEN + 1);
        let gap = cb.sub(rb[lo], lb[hi]);
        cb.connect(gap, step);
    }

    // (4) Repack the outer boundary into 2+2 Challenge wires (each wire = 4
    // base coeffs) so the re-exposed representation stays O(1) — without the
    // repack, the surfaced values would blow up D× per layer.
    let out_init_lo = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&lb[0..4])
        .expect("recompose init_lo");
    let out_init_hi = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&lb[4..8])
        .expect("recompose init_hi");
    let out_final_lo = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&rb[COMMIT_LEN..COMMIT_LEN + 4])
        .expect("recompose final_lo");
    let out_final_hi = cb
        .recompose_base_coeffs_to_ext_via_alu::<Val>(&rb[COMMIT_LEN + 4..COMMIT_LEN + 8])
        .expect("recompose final_hi");

    match left_layout {
        Layout::Boundary => {
            cb.add_expose(&[out_init_lo, out_init_hi, out_final_lo, out_final_hi])
                .expect("re-expose outer boundary");
        }
        Layout::Interval => {
            let (lo, hi, h) = (2 * COMMIT_LEN, 2 * COMMIT_LEN + 1, 2 * COMMIT_LEN + EXT_D);
            // Parent interval [i, j] = [left.lo, right.hi]; split h = left.hi.
            let out_idx = cb
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[lb[lo], rb[hi], zero, zero])
                .expect("recompose idx");
            let tag = cb.alloc_const(Challenge::from(Val::from_u64(TAG_MERGE)), "tag_merge");
            let tag_idx = cb
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[tag, lb[lo], lb[hi], rb[hi]])
                .expect("recompose (tag, i, h, j)");
            let mut inputs = vec![tag_idx];
            for (targets, off) in [(&lb, h), (&lb, h + 4), (&rb, h), (&rb, h + 4)] {
                inputs.push(
                    cb.recompose_base_coeffs_to_ext_via_alu::<Val>(&targets[off..off + 4])
                        .expect("recompose child digest"),
                );
            }
            let digest = cb
                .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &inputs, true)
                .expect("merge digest");
            let mut exposed = vec![out_init_lo, out_init_hi, out_final_lo, out_final_hi, out_idx];
            exposed.extend_from_slice(&digest);
            cb.add_expose(&exposed).expect("re-expose interval statement");
        }
    }

    let circuit = cb.build().expect("build hiding-merge circuit");
    (circuit, left_result, right_result)
}

/// The VK (preprocessed commitment, [`vk_pin_values`] order) of the
/// aggregation-layer proof `prove_aggregation_layer` would produce for
/// `circuit` — computed exactly as that function prepares its prover data,
/// without running or proving the circuit.
fn aggregation_circuit_vk(
    circuit: &p3_circuit::Circuit<Challenge>,
    config: &ConfigWithFriParams,
    backend: &Backend,
) -> Vec<Challenge> {
    commitment_values(&aggregation_circuit_commitment(circuit, config, backend))
}

/// The preprocessed commitment object (the VK) behind [`aggregation_circuit_vk`].
fn aggregation_circuit_commitment(
    circuit: &p3_circuit::Circuit<Challenge>,
    config: &ConfigWithFriParams,
    backend: &Backend,
) -> Commitment<ConfigWithFriParams> {
    let params = agg_params();
    let preprocessors =
        PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::non_primitive_preprocessors(backend);
    let air_builders =
        PcsRecursionBackend::<ConfigWithFriParams, BatchOnly, EXT_D>::non_primitive_air_builders(backend);
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, EXT_D>(
            circuit,
            &params.table_packing,
            &preprocessors,
            &air_builders,
            params.constraint_profile,
        )
        .expect("get_airs_and_degrees_with_prep (merge VK)");
    // E-0 table probe (read-only; a no-op unless armed). The merge proof
    // (`prove_aggregation_layer`) builds the same AIRs from the same circuit.
    crate::experiments::table_probe::record_merge(
        &params.table_packing,
        &airs_degrees,
        &non_primitive_columns,
        &primitive_columns,
    );
    crate::experiments::table_probe::maybe_stop();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
    prover_data
        .common
        .preprocessed
        .as_ref()
        .expect("a merge circuit has preprocessed columns")
        .commitment
        .clone()
}

/// [`vk_pin_values`] order of a preprocessed commitment object.
fn commitment_values(commitment: &Commitment<ConfigWithFriParams>) -> Vec<Challenge> {
    <MerkleCapTargets<Val, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(commitment)
}

/// A copy of `common` whose preprocessed commitment (the VK the parent merge
/// bakes in) is replaced by `vk`; layout metadata and lookups unchanged.
fn common_with_vk(
    common: &CommonData<ConfigWithFriParams>,
    vk: &Commitment<ConfigWithFriParams>,
) -> CommonData<ConfigWithFriParams> {
    let pre = common.preprocessed.as_ref().expect("a bound proof has preprocessed columns");
    CommonData::new(
        Some(GlobalPreprocessed {
            commitment: vk.clone(),
            instances: pre.instances.clone(),
            matrix_to_instance: pre.matrix_to_instance.clone(),
        }),
        common.lookups.clone(),
    )
}

/// DERIVATION: the VK (commitment object) of the REAL merge over children of
/// the given proof shapes and VKs, without proving anything. `left` / `right`
/// supply only the proof SHAPE (they may be twin dummies, see
/// [`MergeMode::Twin`]); `left_vk` / `right_vk` are the real children's VKs,
/// substituted for the dummies' own before the merge circuit bakes them in.
fn hiding_merge_vk_with(
    left: &BatchStarkProof<ConfigWithFriParams>,
    left_vk: &Commitment<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
    right_vk: &Commitment<ConfigWithFriParams>,
) -> Commitment<ConfigWithFriParams> {
    let config = make_leaf_config();
    let backend = make_backend();
    let left_common = common_with_vk(
        rebuilt_common_for(left).as_ref().unwrap_or(&left.stark_common),
        left_vk,
    );
    let right_common = common_with_vk(
        rebuilt_common_for(right).as_ref().unwrap_or(&right.stark_common),
        right_vk,
    );
    let left_input = recursion_input_with_common(left, &left_common);
    let right_input = recursion_input_with_common(right, &right_common);
    let (circuit, _, _) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real);
    aggregation_circuit_commitment(&circuit, &config, &backend)
}

/// VK of `merge(left, right)` **without proving it**: builds the hiding-merge
/// circuit over the two children and commits to its preprocessed trace. Equal
/// to `vk_pin_values(&prove_hiding_merge_proofs(left, right).0)`; the children
/// contribute only their proof shape and VKs, never their data (see
/// [`crate::recursion::recursive::root_vk`]).
pub fn hiding_merge_vk(
    left: &BatchStarkProof<ConfigWithFriParams>,
    right: &BatchStarkProof<ConfigWithFriParams>,
) -> Vec<Challenge> {
    let config = make_leaf_config();
    let backend = make_backend();
    let left_common = rebuilt_common_for(left);
    let right_common = rebuilt_common_for(right);
    let left_input =
        recursion_input_with_common(left, left_common.as_ref().unwrap_or(&left.stark_common));
    let right_input =
        recursion_input_with_common(right, right_common.as_ref().unwrap_or(&right.stark_common));
    let (circuit, _, _) =
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real);
    aggregation_circuit_vk(&circuit, &config, &backend)
}

/// A VK deriver for boundary-bound forests over the leaf circuit of
/// `noop_leaf` (see [`ShapeVkDeriver`]). `noop_leaf` must expose equal initial
/// and final boundaries — a proof over the family's provable no-op records,
/// from any public state — so it can stand in for every leaf of every subtree.
///
/// Interval layout: the real atom's index adjacency forbids merging a dummy
/// subtree with itself, so the deriver proves the [`MergeMode::Twin`] of each
/// distinct subtree shape once (proof shape and metadata) and computes the
/// REAL merge VKs by building the real circuit over those shapes with the
/// real child VKs substituted ([`hiding_merge_vk_with`]); still `O(log t)`
/// dummy merges for the forest. Under the Boundary layout the twin is the
/// real merge, so this is exactly the pre-B6(b) derivation.
pub fn root_vk_deriver(
    noop_leaf: BatchStarkProof<ConfigWithFriParams>,
) -> ShapeVkDeriver<ConfigWithFriParams, Challenge> {
    let (initial, final_) = read_exposed_boundary_proof(&noop_leaf);
    assert_eq!(initial, final_, "the VK-derivation leaf must be a no-op (initial == final boundary)");
    if let Some(iv) = read_exposed_statement(&noop_leaf).interval {
        assert_eq!(iv.lo, iv.hi, "the VK-derivation leaf must cover one batch (lo == hi)");
    }
    ShapeVkDeriver::new(
        noop_leaf,
        Box::new(prove_twin_merge_proofs),
        Box::new(hiding_merge_vk_with),
        Box::new(commitment_values),
    )
}

/// Trusted root VK (commitment + metadata) of the [`prove_forest_over`] root
/// over `t` leaves of `noop_leaf`'s circuit, from public parameters only.
pub fn derive_forest_root_vk(
    noop_leaf: BatchStarkProof<ConfigWithFriParams>,
    t: usize,
) -> RootVk<Challenge> {
    root_vk_deriver(noop_leaf).root_vk(&ForestShape::forest(t))
}

/// Trusted root VK of the [`prove_chain_over`] root over `t` leaves.
pub fn derive_chain_root_vk(
    noop_leaf: BatchStarkProof<ConfigWithFriParams>,
    t: usize,
) -> RootVk<Challenge> {
    root_vk_deriver(noop_leaf).root_vk(&ForestShape::chain(t))
}

/// Verify a boundary-bound root proof against an **externally supplied**
/// trusted root VK — e.g. one from [`derive_forest_root_vk`], never one read
/// from `output` itself. Pins the preprocessed commitment and, when
/// `expected_root_vk.shape` is set, the proof metadata the native verifier
/// would otherwise take from the proof ([`BoundProofShape`](crate::recursion::recursive::root_vk::BoundProofShape)); then verifies
/// the STARK tables. The boundary is read separately via
/// [`read_exposed_boundary`] (it is bound in-circuit). Panics on any mismatch.
///
/// This checks the proof, NOT which batches it covers: an auditor holding
/// the public batch log uses [`verify_bound_proof_against_log`] (the
/// harnesses' default path), which additionally checks the Interval
/// statement against the log.
pub fn verify_bound_proof(
    output: &RecursionOutput<ConfigWithFriParams>,
    expected_root_vk: &RootVk<Challenge>,
) {
    verify_bound_stark_proof_pinned(&output.0, expected_root_vk);
}

/// LEGACY (pre-H2) behaviour of `verify_bound_proof`, kept for side-by-side
/// use: the "trusted" root VK is read from the proof being verified, so the
/// root-VK pin is vacuous — it only checks the STARK tables. Use
/// [`verify_bound_proof`] with a derived VK to actually anchor the root.
pub fn verify_bound_proof_self_pinned_legacy(output: &RecursionOutput<ConfigWithFriParams>) {
    let expected = vk_pin_values(&output.0);
    verify_bound_stark_proof(&output.0, &expected);
}

/// [`verify_bound_stark_proof`] plus the metadata pin: the proof's
/// [`BoundProofShape`](crate::recursion::recursive::root_vk::BoundProofShape) must equal `expected.shape` when that is set.
pub fn verify_bound_stark_proof_pinned(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    expected: &RootVk<Challenge>,
) {
    if let Some(shape) = &expected.shape {
        assert!(
            &bound_proof_shape(proof) == shape,
            "root proof metadata mismatch: the proof's table packing / row counts / \
             non-primitive manifest / degree bits / preprocessed layout differ from the \
             trusted root VK"
        );
    }
    verify_bound_stark_proof(proof, &expected.commitment);
}

/// [`verify_bound_stark_proof_pinned`] returning the failure instead of
/// panicking (the query-time prefix auditor checks proofs a verifier
/// received, which may be malformed).
pub fn try_verify_bound_stark_proof_pinned(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    expected: &RootVk<Challenge>,
) -> Result<(), String> {
    if let Some(shape) = &expected.shape {
        if &bound_proof_shape(proof) != shape {
            return Err("merge proof metadata (table packing / rows / non-primitive manifest / \
                        degree bits / preprocessed layout) differs from the trusted VK"
                .into());
        }
    }
    if vk_pin_values(proof) != expected.commitment {
        return Err("merge VK mismatch: the proof's preprocessed commitment is not the trusted \
                    one for its bracketing (a forged or wrong-shape proof)"
            .into());
    }
    let config = make_leaf_config();
    let params = agg_params();
    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier.register_expose_table::<EXT_D>();
    verifier.verify_all_tables(proof).map_err(|e| format!("merge STARK rejected: {e:?}"))
}

/// Verify a boundary-bound proof against a **trusted root verification key**
/// (`expected_root_vk`, in [`vk_pin_values`] order) — the auditor path for a
/// root that arrived as serialized bytes from another machine.
///
/// The VK is a deterministic, transparent public-profile parameter the auditor
/// holds independently; it is **not** read from the (untrusted) proof. This
/// top-level pin, together with the in-circuit child-VK pins each merge applies
/// ([`pin_child_vk`]), forces the whole proof tree to be structurally honest:
/// the root VK transitively encodes every subtree's VK, so a forged leaf or
/// merge (whose VK differs) cannot appear anywhere in the tree. Panics on a VK
/// mismatch or a STARK-table failure.
pub fn verify_bound_stark_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    expected_root_vk: &[Challenge],
) {
    // (P2) Root VK anchor.
    let got = vk_pin_values(proof);
    assert!(
        got == expected_root_vk,
        "root VK mismatch: the proof's preprocessed commitment does not match the trusted \
         verification key (a forged or wrong-shape root proof)"
    );
    let config = make_leaf_config();
    let params = agg_params();
    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier.register_expose_table::<EXT_D>();
    verifier.verify_all_tables(proof).expect("verify bound proof");
}

/// Check a (verified) root's exposed statement against the public batch log
/// and the composition shape (see
/// [`crate::recursion::recursive::statement::check_root_statement`]):
/// Interval layout, `lo == 1`, `hi == T`, `init == Com(S_0)`,
/// `final == Com(S_T)` and `H == H_expected(shape, Com(B_1..B_T))`.
pub fn check_root_against_log(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    log: &BatchLog<Val>,
    shape: &ForestShape,
) -> Result<(), String> {
    check_root_statement(&read_exposed_statement(proof), log, shape, &hash_bb, EXT_D)
}

/// **The auditor's default path (B6(b))**: pin the root VK and metadata to the
/// trusted `expected_root_vk` (derived from public parameters for `shape`),
/// verify the STARK, then check the root statement against the public batch
/// log ([`check_root_against_log`]). Panics on any mismatch.
pub fn verify_bound_stark_proof_against_log(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    expected_root_vk: &RootVk<Challenge>,
    log: &BatchLog<Val>,
    shape: &ForestShape,
) {
    verify_bound_stark_proof_pinned(proof, expected_root_vk);
    if let Err(e) = check_root_against_log(proof, log, shape) {
        panic!("root statement rejected against the batch log: {e}");
    }
}

/// [`verify_bound_stark_proof_against_log`] on a [`RecursionOutput`].
pub fn verify_bound_proof_against_log(
    output: &RecursionOutput<ConfigWithFriParams>,
    expected_root_vk: &RootVk<Challenge>,
    log: &BatchLog<Val>,
    shape: &ForestShape,
) {
    verify_bound_stark_proof_against_log(&output.0, expected_root_vk, log, shape);
}

// ─── Standalone LEAF verification (per-batch mode, lone leaf `t == 1`) ──────
//
// A leaf proof that reaches the auditor directly (the per-batch mode's `t`
// proofs, or the lone "root" of a one-batch stream) is NOT covered by the
// root-VK pin above, and a plain `verify_all_tables` reads the verification key
// from the proof itself, so on its own it accepts a proof of ANY circuit that
// merely exposes the right statement (e.g. `prove_exposing_leaf`). The leaf is
// therefore pinned exactly like a root: its preprocessed commitment and proof
// metadata must equal a trusted leaf VK derived from public parameters (a
// no-op leaf, `noop_leaf.rs`), and the STARK is checked by a verifier that is
// configured from public parameters, not from the proof.

/// Verifier of a standalone BabyBear sketch-LEAF proof, configured from public
/// parameters only: [`make_leaf_config`] plus the union of the tables the
/// BabyBear leaf circuits register (Poseidon2 D = 4 W16, Recompose, Permute,
/// Range, Expose). The fork's verifier looks each non-primitive table up by the
/// op type listed in the proof's manifest, and rebuilds the primitive AIRs from
/// the proof's table packing and row counts; the trusted leaf VK pins all of
/// these ([`verify_leaf_proof_pinned`]), so a table the leaf does not use is
/// never consulted and one verifier serves every family.
pub fn leaf_verifier() -> BatchStarkProver<ConfigWithFriParams> {
    let mut v = BatchStarkProver::new(make_leaf_config())
        .with_table_packing(TablePacking::new(1, 1).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP));
    v.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    v.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    v.register_permute_table::<EXT_D>();
    v.register_range_table::<EXT_D>();
    v.register_expose_table::<EXT_D>();
    v
}

/// The trusted VK (preprocessed commitment + proof metadata) of a leaf
/// circuit, read off a proof of that circuit over PUBLIC, data-free input — a
/// no-op leaf (see [`crate::recursion::recursive::noop_leaf`]) — never off the
/// proof being verified. Leaf circuits take the sketch data and the batch index
/// only as witnesses, so every real leaf of the same public parameters has
/// this VK (the harness tests exercise real leaves against it).
pub fn leaf_vk(noop_leaf: &BatchStarkProof<ConfigWithFriParams>) -> RootVk<Challenge> {
    RootVk { commitment: vk_pin_values(noop_leaf), shape: Some(bound_proof_shape(noop_leaf)) }
}

/// **Pinned verification of a standalone leaf proof**: the proof metadata must
/// equal `leaf_vk.shape` (when set), its preprocessed commitment must equal
/// `leaf_vk.commitment`, and the STARK must verify under [`leaf_verifier`]
/// with the field metadata checked against BabyBear's quartic extension
/// (`verify_all_tables_for_field`). A proof of a different circuit — another
/// family, other parameters, another binding or statement layout, or a toy
/// that only exposes chosen values — is rejected.
pub fn verify_leaf_proof_pinned(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    leaf_vk: &RootVk<Challenge>,
) -> Result<(), String> {
    pin_and_verify_leaf(&leaf_verifier(), proof, leaf_vk)
}

fn pin_and_verify_leaf(
    verifier: &BatchStarkProver<ConfigWithFriParams>,
    proof: &BatchStarkProof<ConfigWithFriParams>,
    leaf_vk: &RootVk<Challenge>,
) -> Result<(), String> {
    if let Some(shape) = &leaf_vk.shape {
        if &bound_proof_shape(proof) != shape {
            return Err("leaf proof metadata (table packing / rows / non-primitive manifest / \
                        degree bits / preprocessed layout) differs from the trusted leaf VK"
                .into());
        }
    }
    if vk_pin_values(proof) != leaf_vk.commitment {
        return Err("leaf VK mismatch: the proof's preprocessed commitment is not the trusted \
                    leaf circuit's (a proof of a different circuit)"
            .into());
    }
    verifier
        .verify_all_tables_for_field::<Challenge>(proof)
        .map_err(|e| format!("leaf STARK rejected: {e:?}"))
}

/// **The auditor's path for leaf proofs that reach it directly** (per-batch
/// mode: all `T` leaves; chain/forest with `T == 1`: the lone leaf). Each proof
/// is verified with [`verify_leaf_proof_pinned`] against the trusted `leaf_vk`,
/// then their exposed statements are checked against the log
/// ([`check_leaf_statements_against_log`](crate::recursion::recursive::statement::check_leaf_statements_against_log)):
/// the boundary chain `Com(S_0) → … → Com(S_T)`, and under the Interval
/// layout each leaf's `(t, t, H(TAG_LEAF, t, Com(B_t)))`.
pub fn verify_leaves_against_log(
    proofs: &[&BatchStarkProof<ConfigWithFriParams>],
    leaf_vk: &RootVk<Challenge>,
    log: &BatchLog<Val>,
    layout: Expose,
) -> Result<(), String> {
    let verifier = leaf_verifier();
    for (i, p) in proofs.iter().enumerate() {
        pin_and_verify_leaf(&verifier, p, leaf_vk).map_err(|e| format!("leaf {}: {e}", i + 1))?;
    }
    check_leaves_against_log(proofs, log, layout)
}

/// Statement-only half of [`verify_leaves_against_log`] (no STARK, no VK):
/// what the auditor can still check under the explicit, warned
/// `EXP_ROOT_VK=self` opt-in. On its own it authenticates nothing — any
/// circuit can expose these values.
pub fn check_leaves_against_log(
    proofs: &[&BatchStarkProof<ConfigWithFriParams>],
    log: &BatchLog<Val>,
    layout: Expose,
) -> Result<(), String> {
    let stmts: Vec<Statement<Val>> = proofs.iter().map(|p| read_exposed_statement(p)).collect();
    check_leaf_statements_against_log(&stmts, log, layout, &hash_bb, EXT_D)
}

/// The published log of a BabyBear stream: `Com(S_0)`, `Com(S_T)` and the
/// ordered batch commitments.
pub fn batch_log(
    init: &[Val; COMMIT_LEN],
    final_: &[Val; COMMIT_LEN],
    batch_commits: &[[Val; COMMIT_LEN]],
) -> BatchLog<Val> {
    BatchLog {
        init: init.to_vec(),
        final_: final_.to_vec(),
        batch_commits: batch_commits.iter().map(|c| c.to_vec()).collect(),
    }
}

/// Bentley–Saxe cascade over boundary leaves, producing one root proof whose
/// surfaced public values are exactly `(Com(S_0), Com(S_E))`, bound in-circuit.
/// `commits` is the boundary chain `[Com(S_0), Com(S_1), ..., Com(S_E)]`
/// (`E + 1` entries); leaf `i` exposes `(commits[i], commits[i+1])`.
pub fn prove_bound_forest(commits: &[CountMinCommit]) -> RecursionOutput<ConfigWithFriParams> {
    assert!(commits.len() >= 3, "need >= 2 leaves (>= 3 boundary commits)");
    let leaves: Vec<_> = (0..commits.len() - 1)
        .map(|i| prove_boundary_leaf(commits[i], commits[i + 1]))
        .collect();
    prove_forest_over(leaves)
}

/// Bentley–Saxe cascade over **any** boundary-exposing leaves (boundary leaves
/// or real Count-Min v9-exposed leaves — see
/// `prove_countmin_leaf_v9_exposed_with_params`). Adjacent leaves must form a
/// contiguous boundary chain; the hiding merge enforces it in-circuit. The
/// returned root surfaces exactly `(Com(S_0), Com(S_E))`.
///
/// It returns the root's whole [`RecursionOutput`], so it folds through a
/// [`ForestCascade::retaining`] cascade (the pre-M0 fold, independent of the
/// `EXP_FOREST_RETAIN_PREP` / `EXP_MERGE_CACHE` switches).
pub fn prove_forest_over(
    leaves: Vec<RecursionOutput<ConfigWithFriParams>>,
) -> RecursionOutput<ConfigWithFriParams> {
    assert!(leaves.len() >= 2, "need >= 2 leaves");
    let mut forest = ForestCascade::retaining(1);
    for leaf in leaves {
        forest.push(leaf);
    }
    forest.finalize().0.into_output().expect("a retaining cascade keeps the root's output")
}

/// The **online** proof forest (Bentley–Saxe cascade), one leaf at a time:
/// [`Self::push`] appends a leaf as a new size-one peak and merges the two
/// rightmost peaks while their sizes are equal (a binary-counter carry), so
/// after `t` leaves the live peaks are one perfect composition tree per set
/// bit of `t`, tiling `[first_index, first_index + t - 1]` left to right.
/// [`Self::peaks`] exposes them (what a verifier checks at query time,
/// [`PrefixAuditor`]); [`Self::finalize`] composes them left to right into
/// the root. [`prove_forest_over`] and the distributed workers fold through
/// this type, so the bracketing is [`ForestShape::forest`].
///
/// Memory (M0): by default a peak is a bare proof ([`PeakProof::Bare`]): a
/// merge reads only its children's proofs, so the merge circuit's prover
/// data is dropped as soon as the merge returns; `EXP_FOREST_RETAIN_PREP=1`
/// keeps whole [`RecursionOutput`]s as before. Merges go through a
/// [`MergeCache`] unless `EXP_MERGE_CACHE=0`; its entries are the only
/// prover data a bare cascade keeps ([`Self::holds_prover_data`] counts
/// them, [`Self::peaks_hold_prover_data`] does not). Neither changes a
/// proof's circuit, VK or statement.
pub struct ForestCascade {
    first_index: u64,
    /// `(size, proof)`, left to right.
    peaks: Vec<(u64, PeakProof)>,
    retain_prep: bool,
    cache: Option<MergeCache>,
}

impl ForestCascade {
    /// An empty forest whose first leaf will be batch `first_index` (1-based),
    /// under the environment's switches ([`forest_retain_prep`],
    /// [`merge_cache_from_env`]).
    pub fn new(first_index: u64) -> Self {
        Self::with_options(first_index, forest_retain_prep(), merge_cache_from_env())
    }

    /// The pre-M0 cascade: whole [`RecursionOutput`] peaks, no merge cache.
    pub fn retaining(first_index: u64) -> Self {
        Self::with_options(first_index, true, None)
    }

    /// Explicit switches: keep each peak's prover data (`retain_prep`), and
    /// the merge cache to prove through (`None`: every merge builds its
    /// circuit).
    pub fn with_options(first_index: u64, retain_prep: bool, cache: Option<MergeCache>) -> Self {
        Self { first_index, peaks: Vec::new(), retain_prep, cache }
    }

    /// Number of leaves pushed so far.
    pub fn len(&self) -> u64 {
        self.peaks.iter().map(|(sz, _)| sz).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.peaks.is_empty()
    }

    /// Whether any live peak still pins a circuit's prover data (only under
    /// `retain_prep`).
    pub fn peaks_hold_prover_data(&self) -> bool {
        self.peaks.iter().any(|(_, p)| p.holds_prover_data())
    }

    /// Whether the cascade pins any circuit's prover data: a retained peak, or
    /// a [`MergeCache`] entry (at most its capacity, by design).
    pub fn holds_prover_data(&self) -> bool {
        self.peaks_hold_prover_data()
            || self.cache.as_ref().is_some_and(MergeCache::holds_prover_data)
    }

    /// The merge cache, if any (hit / miss counters).
    pub fn merge_cache(&self) -> Option<&MergeCache> {
        self.cache.as_ref()
    }

    /// One merge of `left` and `right` into a subtree of `size` leaves.
    fn merge(
        &mut self,
        left: &BatchStarkProof<ConfigWithFriParams>,
        right: &BatchStarkProof<ConfigWithFriParams>,
        size: u64,
    ) -> RecursionOutput<ConfigWithFriParams> {
        match &mut self.cache {
            Some(cache) => cache.merge(left, right, size),
            None => prove_hiding_merge_proofs(left, right),
        }
    }

    /// Append the next leaf and run the composition cascade; returns the
    /// number of merges it took.
    pub fn push(&mut self, leaf: RecursionOutput<ConfigWithFriParams>) -> u32 {
        let mut node = (1u64, PeakProof::keep(leaf, self.retain_prep));
        let mut merges = 0u32;
        while self.peaks.last().is_some_and(|(sz, _)| *sz == node.0) {
            let (_, left) = self.peaks.pop().unwrap();
            let size = node.0 * 2;
            let merged = self.merge(left.proof(), node.1.proof(), size);
            node = (size, PeakProof::keep(merged, self.retain_prep));
            merges += 1;
        }
        self.peaks.push(node);
        merges
    }

    /// The live peaks as `(lo, hi, proof)`, left to right (each a perfect
    /// tree, bracketing `ForestShape::forest(hi - lo + 1)`).
    pub fn peaks(&self) -> Vec<(u64, u64, &BatchStarkProof<ConfigWithFriParams>)> {
        let mut lo = self.first_index;
        self.peaks
            .iter()
            .map(|(sz, p)| {
                let part = (lo, lo + sz - 1, p.proof());
                lo += sz;
                part
            })
            .collect()
    }

    /// Compose the surviving peaks left to right into the root (the forest's
    /// finalization); returns it with the number of merges. A one-leaf forest
    /// returns the lone leaf. The root is kept like a peak (bare unless
    /// `retain_prep`).
    pub fn finalize(self) -> (PeakProof, u32) {
        let (root, merges, _) = self.finalize_with_stats();
        (root, merges)
    }

    /// [`Self::finalize`], also returning the merge cache's final `(hits,
    /// misses)`, the finalization's own merges included (`None`: no cache).
    pub fn finalize_with_stats(mut self) -> (PeakProof, u32, Option<(u64, u64)>) {
        assert!(!self.peaks.is_empty(), "finalize an empty forest");
        let peaks = std::mem::take(&mut self.peaks);
        let mut peaks = peaks.into_iter();
        let (mut size, mut acc) = peaks.next().expect("non-empty");
        let mut merges = 0u32;
        for (sz, r) in peaks {
            size += sz;
            let merged = self.merge(acc.proof(), r.proof(), size);
            acc = PeakProof::keep(merged, self.retain_prep);
            merges += 1;
        }
        let stats = self.cache.as_ref().map(|c| (c.hits(), c.misses()));
        (acc, merges, stats)
    }
}

// ─── Query-time prefix certification (Property 3) ───────────────────────────
//
// A query proof exposes `(Com(S), q, answer)`. The verifier accepts the answer
// only once `Com(S)` is certified as the state at the query's version `t`: by
// the interval proofs live at `t` (the forest's peaks, the chain's current
// fold, or the per-batch leaves), each pinned to the VK of its bracketing,
// STARK-verified, and their statements tiling `[1, t]` against the log, the
// last one's final commitment being `Com(S_t)`.

/// The verifier's half of Property 3 at query time: trusted VKs per
/// bracketing, derived from public parameters only (a no-op leaf, as for the
/// root), and the pinned verification of each interval proof.
pub struct PrefixAuditor {
    deriver: ShapeVkDeriver<ConfigWithFriParams, Challenge>,
    vks: std::collections::HashMap<ForestShape, RootVk<Challenge>>,
    leaf_verifier: BatchStarkProver<ConfigWithFriParams>,
}

impl PrefixAuditor {
    /// `noop_leaf`: a proof of the deployment's leaf circuit over public no-op
    /// records (see [`root_vk_deriver`]).
    pub fn new(noop_leaf: BatchStarkProof<ConfigWithFriParams>) -> Self {
        Self {
            deriver: root_vk_deriver(noop_leaf),
            vks: std::collections::HashMap::new(),
            leaf_verifier: leaf_verifier(),
        }
    }

    /// The trusted VK of `shape`, derived on first use (a one-time setup per
    /// bracketing; callers that time verification derive it beforehand).
    pub fn vk(&mut self, shape: &ForestShape) -> &RootVk<Challenge> {
        if !self.vks.contains_key(shape) {
            let vk = self.deriver.root_vk(shape);
            self.vks.insert(shape.clone(), vk);
        }
        &self.vks[shape]
    }

    /// Pin `proof` to the trusted VK of `shape` and STARK-verify it: a lone
    /// leaf (`ForestShape::Leaf`) with the leaf verifier, a composition with
    /// the aggregation verifier. Returns its exposed statement.
    pub fn verify_interval(
        &mut self,
        proof: &BatchStarkProof<ConfigWithFriParams>,
        shape: &ForestShape,
    ) -> Result<Statement<Val>, String> {
        self.vk(shape);
        let vk = &self.vks[shape];
        match shape {
            ForestShape::Leaf => pin_and_verify_leaf(&self.leaf_verifier, proof, vk)?,
            ForestShape::Merge(..) => try_verify_bound_stark_proof_pinned(proof, vk)?,
        }
        Ok(read_exposed_statement(proof))
    }

    /// Certify version `t`: verify every part ([`Self::verify_interval`]),
    /// then check that their statements tile `[1, t]` against `log`
    /// ([`check_prefix_statements`]). Returns the certified `Com(S_t)`.
    pub fn certify_prefix(
        &mut self,
        parts: &[(&BatchStarkProof<ConfigWithFriParams>, ForestShape)],
        log: &BatchLog<Val>,
        t: usize,
    ) -> Result<Vec<Val>, String> {
        let mut stmts = Vec::with_capacity(parts.len());
        for (k, (proof, shape)) in parts.iter().enumerate() {
            stmts.push(self.verify_interval(proof, shape).map_err(|e| format!("part {}: {e}", k + 1))?);
        }
        let refs: Vec<(&Statement<Val>, &ForestShape)> =
            stmts.iter().zip(parts.iter().map(|(_, sh)| sh)).collect();
        check_prefix_statements(&refs, log, t, &hash_bb, EXT_D)
    }
}

/// Left-leaning **linear chain** fold over any boundary-exposing leaves — the
/// family-agnostic analog of `countmin_chain_v9::prove_countmin_chain_v9`, but
/// consuming the same exposed `RecursionOutput` leaves as [`prove_forest_over`].
/// Folds `Π^(t) = merge(Π^(t-1), leaf_t)` strictly left-to-right (`O(t)` depth,
/// vs the tree's `O(log t)`), so it is the sequential comparison baseline for the
/// streaming forest. Same in-circuit child verification + boundary binding per
/// merge as the tree; the returned root surfaces exactly `(Com(S_0), Com(S_E))`
/// and verifies with [`verify_bound_proof`].
pub fn prove_chain_over(
    leaves: Vec<RecursionOutput<ConfigWithFriParams>>,
) -> RecursionOutput<ConfigWithFriParams> {
    assert!(leaves.len() >= 2, "need >= 2 leaves");
    let mut iter = leaves.into_iter();
    let mut acc = iter.next().unwrap();
    for leaf in iter {
        acc = prove_hiding_merge(&acc, &leaf);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_recursion::{build_aggregation_layer_circuit, build_and_prove_aggregation_layer};

    /// AUDIT EXPERIMENT: does a const VALUE land in the VK (preprocessed
    /// commitment), or only in the main-trace commitment? Two structurally
    /// identical exposing leaves that differ ONLY in their exposed (const)
    /// values. If the VKs are equal while the trace commitments differ, then
    /// const values are NOT part of the VK -> baking a child commitment as a
    /// const does not make the child's commitment VALUE part of the parent VK.
    ///
    /// HISTORY: this is the original audit test, unchanged except for the
    /// rename and `#[ignore]`. It passed at fork rev 19dcb37 (bug present:
    /// `AUDIT VK_EQUAL=true`) and FAILS once ConstAir binds constant values
    /// into its preprocessed trace (the constfix port of upstream 2db3735),
    /// because the VKs then differ. The live regression test is
    /// [`audit_const_value_binds_vk`] below.
    #[test]
    #[ignore = "pre-fix behaviour (fork 19dcb37): asserts const values are NOT in the VK; fails with the ConstAir value-binding fix"]
    fn audit_const_value_independence_of_vk_pre_fix() {
        use p3_field::PrimeCharacteristicRing;
        let a = prove_exposing_leaf(&[
            Challenge::from(Val::from_u32(0x1111_1111)),
            Challenge::from(Val::from_u32(0x2222_2222)),
        ]);
        let b = prove_exposing_leaf(&[
            Challenge::from(Val::from_u32(0x3333_3333)),
            Challenge::from(Val::from_u32(0x4444_4444)),
        ]);
        let vk_a = vk_pin_values(&a.0);
        let vk_b = vk_pin_values(&b.0);
        let trace = |p: &BatchStarkProof<ConfigWithFriParams>| {
            <MerkleCapTargets<Val, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(
                &p.proof.commitments.main,
            )
        };
        let tr_a = trace(&a.0);
        let tr_b = trace(&b.0);
        println!("AUDIT VK_EQUAL={}", vk_a == vk_b);
        println!("AUDIT TRACE_EQUAL={}", tr_a == tr_b);
        assert_ne!(tr_a, tr_b, "sanity: different const values must change the main-trace commitment");
        // The load-bearing observation for the audit:
        assert_eq!(
            vk_a, vk_b,
            "AUDIT: const values do NOT affect the VK (preprocessed commitment)"
        );
    }

    /// REGRESSION (constant binding): two structurally identical exposing
    /// leaves that differ ONLY in their `alloc_const` values must have
    /// DIFFERENT VKs (preprocessed commitments). This is the inverse of
    /// [`audit_const_value_independence_of_vk_pre_fix`]: with ConstAir's value
    /// columns in the preprocessed trace, a constant's value is part of the
    /// circuit's verification key, so a prover cannot swap a constant and
    /// still present the honest VK.
    #[test]
    fn audit_const_value_binds_vk() {
        use p3_field::PrimeCharacteristicRing;
        let a = prove_exposing_leaf(&[
            Challenge::from(Val::from_u32(0x1111_1111)),
            Challenge::from(Val::from_u32(0x2222_2222)),
        ]);
        let b = prove_exposing_leaf(&[
            Challenge::from(Val::from_u32(0x3333_3333)),
            Challenge::from(Val::from_u32(0x4444_4444)),
        ]);
        let vk_a = vk_pin_values(&a.0);
        let vk_b = vk_pin_values(&b.0);
        let trace = |p: &BatchStarkProof<ConfigWithFriParams>| {
            <MerkleCapTargets<Val, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(
                &p.proof.commitments.main,
            )
        };
        println!("AUDIT VK_EQUAL={}", vk_a == vk_b);
        println!("AUDIT TRACE_EQUAL={}", trace(&a.0) == trace(&b.0));
        assert_ne!(
            trace(&a.0),
            trace(&b.0),
            "sanity: different const values must change the main-trace commitment"
        );
        assert_ne!(
            vk_a, vk_b,
            "REGRESSION: const values must be bound into the VK (preprocessed commitment)"
        );
    }

    /// VALIDATION GATE: a value exposed via the Expose NPO surfaces as the
    /// aggregation's public input (unlike a primitive `public_input`) AND the
    /// aggregation verifies. Confirms the `public_values → air_public_targets
    /// → recursion` pathway works.
    #[test]
    fn expose_value_surfaces_through_aggregation() {
        let v0 = Challenge::from(Val::from_u32(0x1234_5678));
        let v1 = Challenge::from(Val::from_u32(0x0BAD_F00D));
        let left = prove_exposing_leaf(&[v0, v1]);
        let right = prove_exposing_leaf(&[v0, v1]);

        let config = make_leaf_config();
        let backend = make_backend();
        let left_input = recursion_input_with_public_values(&left);
        let right_input = recursion_input_with_public_values(&right);

        let (_circuit, (lr, _rr)) = build_aggregation_layer_circuit::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            EXT_D,
        >(&left_input, &right_input, &config, &backend)
        .expect("build aggregation circuit");
        let lpis = lr.pack_public_inputs(&left_input).expect("left pis");
        assert!(lpis.contains(&v0) && lpis.contains(&v1), "exposed values must surface");

        let params = agg_params();
        let out = build_and_prove_aggregation_layer::<
            ConfigWithFriParams,
            BatchOnly,
            BatchOnly,
            Backend,
            EXT_D,
        >(&left_input, &right_input, &config, &backend, &params, None)
        .expect("aggregate exposing leaves");
        verify_bound_proof_self_pinned_legacy(&out);
    }

    /// Deterministic synthetic boundary commitment for state index `k`.
    fn commit(k: u64) -> CountMinCommit {
        CountMinCommit(std::array::from_fn(|i| {
            Val::from_u64(k.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64) + 1)
        }))
    }

    /// 2-leaf hiding merge: the merged proof surfaces ONLY the outer boundary
    /// (Com(S_0), Com(S_2)) — bound in-circuit — and verifies.
    #[test]
    fn hiding_merge_exposes_only_outer_boundary() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        // Trusted VK from the merge circuit alone (built, never run/proved).
        let expected = RootVk::commitment_only(hiding_merge_vk(&l0.0, &l1.0));
        let merged = prove_hiding_merge(&l0, &l1);
        verify_bound_proof(&merged, &expected);

        let (initial, final_) = read_exposed_boundary(&merged);
        assert_eq!(initial, commit(0), "outer initial = Com(S_0)");
        assert_eq!(final_, commit(2), "outer final = Com(S_2)");
    }

    /// A boundary break is rejected in-circuit (the `connect` is unsatisfiable),
    /// so the merge prover fails — contiguity is enforced by the proof, not a
    /// native check.
    #[test]
    #[should_panic]
    fn hiding_merge_rejects_boundary_break() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        // l1 starts from commit(99), not commit(1) — non-contiguous.
        let l1 = prove_boundary_leaf(commit(99), commit(2));
        let _ = prove_hiding_merge(&l0, &l1);
    }

    /// VK ANCHOR (accept): the honest root verifies against its own trusted VK.
    #[test]
    fn root_vk_pin_accepts_correct_vk() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let merged = prove_hiding_merge(&l0, &l1);
        let root_vk = vk_pin_values(&merged.0);
        verify_bound_stark_proof(&merged.0, &root_vk); // must not panic
    }

    /// VK ANCHOR (reject): the auditor's trusted root-VK pin rejects a proof
    /// whose preprocessed commitment does not equal the expected verification
    /// key — a forged or wrong-circuit root. A leaf's VK differs from a merge's,
    /// so verifying a merge proof against a leaf VK must be rejected. This is the
    /// single trusted check that, together with each merge baking its children's
    /// VKs into its own preprocessed trace, transitively anchors the whole tree.
    #[test]
    #[should_panic(expected = "root VK mismatch")]
    fn root_vk_pin_rejects_wrong_vk() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let merged = prove_hiding_merge(&l0, &l1);
        let leaf_vk = vk_pin_values(&l0.0); // a leaf VK != the merge (root) VK
        verify_bound_stark_proof(&merged.0, &leaf_vk);
    }

    /// VK ANCHOR (distinctness): the verification keys of the distinct circuit
    /// types in a forest are all different — a leaf, a one-level merge (over two
    /// leaves), and a two-level merge (over two one-level merges). This is a
    /// necessary property for the root-VK pin to distinguish circuits.
    ///
    /// The *baking* property itself — that a merge's VK now depends on its
    /// children's VKs (via `Comm::new_const`, versus the pre-fix bug where child
    /// VKs were free public inputs outside the parent's preprocessed) — was
    /// confirmed empirically against the pre-fix commitments: the leaf VK is
    /// unchanged (a leaf verifies no children) while every merge VK changed once
    /// its children's commitments became preprocessed constants.
    #[test]
    fn merge_vk_depends_on_children() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let l2 = prove_boundary_leaf(commit(2), commit(3));
        let l3 = prove_boundary_leaf(commit(3), commit(4));
        let leaf_vk = vk_pin_values(&l0.0);
        let m01 = prove_hiding_merge(&l0, &l1); // level-1: children are leaves
        let m23 = prove_hiding_merge(&l2, &l3);
        let root = prove_hiding_merge(&m01, &m23); // level-2: children are merges
        let m01_vk = vk_pin_values(&m01.0);
        let root_vk = vk_pin_values(&root.0);
        assert_ne!(leaf_vk, m01_vk, "leaf VK must differ from a merge VK");
        assert_ne!(m01_vk, root_vk, "a level-2 merge VK must differ from level-1");
    }

    /// REAL Count-Min bound forest: two v9-exposed CM leaves (proving actual
    /// sketch updates) composed via the hiding merge. The root surfaces ONLY
    /// the real outer boundary (Com(S_0), Com(S_2)) — bound in-circuit.
    #[test]
    fn real_v9_bound_forest_exposes_outer_boundary() {
        use crate::commitment::countmin::commit_countmin;
        use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, D, W};
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_v9::CountMinV9;

        let params = CountMinLeafParams::default(); // (d, w, batch) = (2, 4, 2)
        let mut s = CountMinV9::new(&CountMinParams { d: D, w: W });
        let c0 = commit_countmin(&s);

        let b1 = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let leaf1 = prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b1.clone());
        for u in &b1 {
            CountMinV9::update(&mut s, u);
        }

        let b2 = vec![
            CountMinUpdate { key: 13, value: 2 },
            CountMinUpdate { key: 7, value: 4 },
        ];
        let leaf2 = prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b2.clone());
        for u in &b2 {
            CountMinV9::update(&mut s, u);
        }
        let c2 = commit_countmin(&s);

        // Sanity: the leaves expose their real commitments.
        assert_eq!(read_exposed_boundary(&leaf1.output).0, c0);

        // Trusted root VK derived from public parameters only (a no-op
        // leaf over the empty state), never read from the root proof.
        let root_vk = derive_forest_root_vk(crate::recursion::recursive::noop_leaf::cm_v9_noop_leaf(params), 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial, c0, "root initial = real Com(S_0)");
        assert_eq!(final_, c2, "root final = real Com(S_2)");
    }

    /// REAL HyperLogLog bound forest: two `hll_final_full` exposed leaves
    /// (real §A update circuit) composed via the hiding merge; root surfaces
    /// only the real (Com(S_0), Com(S_2)), bound in-circuit.
    #[test]
    fn real_hll_bound_forest_exposes_outer_boundary() {
        use crate::sketch::hll_final_full::{
            HllFullParams, HllFullState, HllFullUpdate, apply_batch, commit_hll_state,
            prove_hll_full_exposed,
        };
        let params = HllFullParams { b: 4, batch: 2 };
        let s0 = HllFullState::empty(params);
        let b1 = vec![HllFullUpdate::real(7), HllFullUpdate::real(11)];
        let leaf1 = prove_hll_full_exposed(params, s0.clone(), b1.clone());
        let s1 = apply_batch(&s0, &b1);
        let b2 = vec![HllFullUpdate::real(13), HllFullUpdate::real(7)];
        let leaf2 = prove_hll_full_exposed(params, s1.clone(), b2.clone());
        let s2 = apply_batch(&s1, &b2);

        // Trusted root VK derived from public parameters only (a no-op
        // leaf over the empty state), never read from the root proof.
        let root_vk = derive_forest_root_vk(crate::recursion::recursive::noop_leaf::hll_full_noop_leaf(params), 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_hll_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_hll_state(&s2).0, "root final = real Com(S_2)");
    }

    /// REAL SpaceSaving bound forest: two `ss_final_full` exposed leaves.
    #[test]
    fn real_ss_bound_forest_exposes_outer_boundary() {
        use crate::sketch::ss_final_full::{
            SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full, commit_ss_state,
            prove_ss_full_exposed,
        };
        let params = SsFullParams { capacity: 4, batch: 2 };
        let s0 = SsFullState::empty(params);
        let b1 = vec![SsFullUpdate::real(7, 1), SsFullUpdate::real(11, 1)];
        let leaf1 = prove_ss_full_exposed(params, s0.clone(), b1.clone());
        let (s1, _) = apply_batch_ss_full(&s0, &b1);
        let b2 = vec![SsFullUpdate::real(13, 1), SsFullUpdate::real(7, 1)];
        let leaf2 = prove_ss_full_exposed(params, s1.clone(), b2.clone());
        let (s2, _) = apply_batch_ss_full(&s1, &b2);

        // Trusted root VK derived from public parameters only (a no-op
        // leaf over the empty state), never read from the root proof.
        let root_vk = derive_forest_root_vk(crate::recursion::recursive::noop_leaf::ss_full_noop_leaf(params), 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_ss_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_ss_state(&s2).0, "root final = real Com(S_2)");
    }

    /// REAL Greenwald--Khanna bound forest: two `gk_final_full` exposed leaves.
    #[test]
    fn real_gk_bound_forest_exposes_outer_boundary() {
        use crate::sketch::gk_final_full::{
            GKFullParams, GKFullState, GKFullUpdate, apply_batch_full, commit_gk_state,
            prove_gk_full_exposed,
        };
        let params = GKFullParams { capacity: 4, batch: 2 };
        let s0 = GKFullState::empty(params);
        let b1 = vec![GKFullUpdate::real(10), GKFullUpdate::real(11)];
        let leaf1 = prove_gk_full_exposed(params, s0.clone(), b1.clone());
        let (s1, _) = apply_batch_full(&s0, &b1);
        let b2 = vec![GKFullUpdate::real(20), GKFullUpdate::real(21)];
        let leaf2 = prove_gk_full_exposed(params, s1.clone(), b2.clone());
        let (s2, _) = apply_batch_full(&s1, &b2);

        // Trusted root VK derived from public parameters only (a no-op
        // leaf over the empty state), never read from the root proof.
        let root_vk = derive_forest_root_vk(crate::recursion::recursive::noop_leaf::gk_full_noop_leaf(params), 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_gk_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_gk_state(&s2).0, "root final = real Com(S_2)");
    }

    /// Two-sided band-merge (bandmerge2) leaf, boundary-exposed via the NEW
    /// `prove_gkb2_exposed`: the generic forest fold composes two real gk2 leaves
    /// and surfaces the outer boundary — confirms the added Expose wiring is
    /// sound and the gk2 leaf is foldable by the family-agnostic path.
    #[test]
    fn real_gk2_bandmerge_bound_forest_exposes_outer_boundary() {
        use crate::sketch::gk_bandmerge::{
            apply_batch2, commit_gk2_state, prove_gkb2_exposed, Gk2State, GkbParams,
        };
        let params = GkbParams { capacity: 4, batch: 2, s: 2 };
        let s0 = Gk2State::empty(params);
        let b1 = vec![10u32, 11];
        let leaf1 = prove_gkb2_exposed(params, s0.clone(), b1.clone());
        let s1 = apply_batch2(&s0, &b1);
        let b2 = vec![20u32, 21];
        let leaf2 = prove_gkb2_exposed(params, s1.clone(), b2.clone());
        let s2 = apply_batch2(&s1, &b2);

        // Trusted root VK derived from public parameters only (a no-op
        // leaf over the empty state), never read from the root proof.
        let root_vk = derive_forest_root_vk(crate::recursion::recursive::noop_leaf::gk2_noop_leaf(params), 2);
        let root = prove_forest_over(vec![leaf1.output, leaf2.output]);
        verify_bound_proof(&root, &root_vk);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial.0, commit_gk2_state(&s0).0, "root initial = real Com(S_0)");
        assert_eq!(final_.0, commit_gk2_state(&s2).0, "root final = real Com(S_2)");
    }

    /// WIRE-MERGEABILITY GATE (distributed composition): proofs round-trip
    /// through postcard serialization and merge as bare `BatchStarkProof`s —
    /// no `CircuitProverData` from the producing context. This is exactly what
    /// a multi-machine deployment does: leaves/subtree roots cross machines as
    /// bytes and the receiving machine folds them. A regression here breaks
    /// `experiments::dist_compose`.
    #[test]
    fn merge_from_deserialized_proof_bytes() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));

        // Simulate the machine boundary: serialize, drop the originals'
        // prover halves, deserialize on "the other side".
        let b0 = postcard::to_allocvec(&l0.0).expect("serialize left");
        let b1 = postcard::to_allocvec(&l1.0).expect("serialize right");
        // Trusted VK computed from the IN-PROCESS children: the merge circuit
        // over wire children (lookups rebuilt) must be the same circuit.
        let expected = RootVk::commitment_only(hiding_merge_vk(&l0.0, &l1.0));
        drop((l0, l1));
        let p0: BatchStarkProof<ConfigWithFriParams> =
            postcard::from_bytes(&b0).expect("deserialize left");
        let p1: BatchStarkProof<ConfigWithFriParams> =
            postcard::from_bytes(&b1).expect("deserialize right");

        let merged = prove_hiding_merge_proofs(&p0, &p1);
        assert_eq!(
            hiding_merge_vk(&p0, &p1),
            expected.commitment,
            "merge VK over deserialized children == over in-process children"
        );
        verify_bound_proof(&merged, &expected);
        let (initial, final_) = read_exposed_boundary(&merged);
        assert_eq!(initial, commit(0), "outer initial survives the wire");
        assert_eq!(final_, commit(2), "outer final survives the wire");

        // Second hop: the merged root itself round-trips and re-merges (the
        // forest's cross-machine reduction rounds fold fold-outputs).
        let rb = postcard::to_allocvec(&merged.0).expect("serialize root");
        let rp: BatchStarkProof<ConfigWithFriParams> =
            postcard::from_bytes(&rb).expect("deserialize root");
        let l2 = prove_boundary_leaf(commit(2), commit(3));
        let l3 = prove_boundary_leaf(commit(3), commit(4));
        let right = prove_hiding_merge(&l2, &l3);
        let root_vk = RootVk::commitment_only(hiding_merge_vk(&merged.0, &right.0));
        let root = prove_hiding_merge_proofs(&rp, &right.0);
        verify_bound_proof(&root, &root_vk);
        let (ri, rf) = read_exposed_boundary(&root);
        assert_eq!((ri, rf), (commit(0), commit(4)), "fold-of-folds over the wire");
    }

    /// 4-leaf bound forest (exercises `agg + agg`): the single root proof
    /// surfaces ONLY (Com(S_0), Com(S_4)), bound in-circuit, and verifies.
    #[test]
    fn bound_forest_four_exposes_only_outer() {
        let commits: Vec<_> = (0..=4).map(commit).collect();
        let root = prove_bound_forest(&commits);
        // Toy leaves carry their boundary as constants (data-dependent VKs by
        // design), so there is no public-parameter VK to derive here.
        verify_bound_proof_self_pinned_legacy(&root);
        let (initial, final_) = read_exposed_boundary(&root);
        assert_eq!(initial, commit(0), "root initial = Com(S_0)");
        assert_eq!(final_, commit(4), "root final = Com(S_4)");
    }

    /// AUDIT PROBE (bypass hunter): a leaf's VK (preprocessed commitment) is
    /// INVARIANT to the `alloc_const` values it exposes.
    ///
    /// HISTORY: original probe, unchanged except for the rename and
    /// `#[ignore]`. It held at fork rev 19dcb37 (the bug) and fails with the
    /// ConstAir value-binding fix; see
    /// [`probe_leaf_vk_binds_exposed_const_value`].
    #[test]
    #[ignore = "pre-fix behaviour (fork 19dcb37): asserts the toy leaf VK ignores its const values; fails with the ConstAir value-binding fix"]
    fn probe_leaf_vk_ignores_exposed_const_value_pre_fix() {
        let a = prove_boundary_leaf(commit(0), commit(1));
        let b = prove_boundary_leaf(commit(40), commit(41));
        let vk_a = vk_pin_values(&a.0);
        let vk_b = vk_pin_values(&b.0);
        assert_ne!(read_exposed_boundary(&a), read_exposed_boundary(&b));
        assert_eq!(vk_a, vk_b, "leaf VK must be independent of the exposed const values");
    }

    /// REGRESSION: the toy boundary leaf exposes `alloc_const` values, so with
    /// the ConstAir value-binding fix its VK depends on the boundary it
    /// exposes (by design: the boundary IS its constant).
    #[test]
    fn probe_leaf_vk_binds_exposed_const_value() {
        let a = prove_boundary_leaf(commit(0), commit(1));
        let b = prove_boundary_leaf(commit(40), commit(41));
        assert_ne!(read_exposed_boundary(&a), read_exposed_boundary(&b));
        assert_ne!(
            vk_pin_values(&a.0),
            vk_pin_values(&b.0),
            "the toy leaf's VK must bind the const values it exposes"
        );
    }

    // ─── Constant-forgery PoC (fork constfix prototype) ─────────────────────
    //
    // At fork rev 19dcb37 ConstAir's preprocessed trace held only
    // [multiplicity, witness_idx]; the constant VALUE sent on the WitnessChecks
    // bus came from the prover-chosen main trace. A prover could therefore
    // build the trace of a circuit whose constants differ from the honest
    // circuit's, prove it with the HONEST prover data, and obtain a proof that
    // carries the honest VK and verifies. The tests below mount that attack on
    // the exposing leaf and through the hiding merge + root-VK pin; they print
    // the outcome and require rejection.

    /// The exposing-leaf circuit over `values` — identical to the circuit
    /// [`prove_exposing_leaf`] builds.
    fn exposing_leaf_circuit(values: &[Challenge]) -> p3_circuit::Circuit<Challenge> {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let wires: Vec<_> = values.iter().map(|&v| b.alloc_const(v, "exposed")).collect();
        b.add_expose(&wires).expect("add_expose");
        b.build().expect("build exposing leaf")
    }

    fn exposing_leaf_packing() -> TablePacking {
        TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP)
    }

    /// Prover data (hence VK) of the exposing-leaf circuit — same packing,
    /// preprocessors and AIR builders as [`prove_exposing_leaf`].
    fn exposing_leaf_prover_data(
        circuit: &p3_circuit::Circuit<Challenge>,
    ) -> CircuitProverData<ConfigWithFriParams> {
        let config = make_leaf_config();
        let preprocessors = vec![p3_circuit_prover::expose_preprocessor::<Val>()];
        let air_builders = p3_circuit_prover::expose_air_builders::<ConfigWithFriParams, EXT_D>();
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, EXT_D>(
                circuit,
                &exposing_leaf_packing(),
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .expect("get_airs_and_degrees_with_prep (exposing leaf)");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns)
    }

    /// ATTACK: run the exposing-leaf circuit whose constants are `forged`, and
    /// prove its trace against the prover data (VK) of the honest circuit whose
    /// constants are `honest`. The resulting proof is NOT self-verified.
    fn forge_exposing_leaf(
        honest: &[Challenge],
        forged: &[Challenge],
    ) -> RecursionOutput<ConfigWithFriParams> {
        let honest_circuit = exposing_leaf_circuit(honest);
        let forged_circuit = exposing_leaf_circuit(forged);
        let honest_data = exposing_leaf_prover_data(&honest_circuit);
        let traces = {
            let mut runner = forged_circuit.runner();
            runner.set_public_inputs(&[]).expect("set_public_inputs");
            runner.run().expect("run forged exposing circuit")
        };
        let mut prover =
            BatchStarkProver::new(make_leaf_config()).with_table_packing(exposing_leaf_packing());
        prover.register_expose_table::<EXT_D>();
        let proof = prover
            .prove_all_tables(&traces, &honest_data)
            .expect("prove_all_tables (forged exposing leaf)");
        RecursionOutput(proof, Rc::new(honest_data))
    }

    fn boundary_values(initial: CountMinCommit, final_: CountMinCommit) -> Vec<Challenge> {
        let iv = pack_commit_to_challenge(&initial);
        let fv = pack_commit_to_challenge(&final_);
        vec![iv[0], iv[1], fv[0], fv[1]]
    }

    /// Runs `f`, turning a panic into `Err(message)`.
    fn outcome<T>(f: impl FnOnce() -> T) -> Result<T, String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|p| {
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".into())
        })
    }

    /// PoC (leaf level): a leaf proof whose exposed `initial` boundary was
    /// swapped (commit(0) -> commit(99)) and proved against the honest leaf's
    /// prover data carries the honest leaf VK. The auditor path
    /// ([`verify_bound_stark_proof`] pinned to the honest leaf VK) must reject it.
    /// At 19dcb37 it is ACCEPTED (this test fails there).
    #[test]
    fn forged_const_leaf_rejected_under_honest_vk() {
        let honest_leaf = prove_boundary_leaf(commit(0), commit(1));
        let honest_vk = vk_pin_values(&honest_leaf.0);
        verify_bound_stark_proof(&honest_leaf.0, &honest_vk); // sanity: honest leaf passes

        let forged = forge_exposing_leaf(
            &boundary_values(commit(0), commit(1)),
            &boundary_values(commit(99), commit(1)),
        );
        assert_eq!(
            vk_pin_values(&forged.0),
            honest_vk,
            "the forged proof carries the honest leaf VK (it was proved with the honest prover data)"
        );
        assert_eq!(
            read_exposed_boundary(&forged).0,
            commit(99),
            "the forged proof surfaces the forged initial boundary"
        );
        let res = outcome(|| verify_bound_stark_proof(&forged.0, &honest_vk));
        match &res {
            Ok(()) => println!("POC FORGED_LEAF=ACCEPTED (forged initial boundary verified under the honest VK)"),
            Err(e) => println!("POC FORGED_LEAF=REJECTED ({e})"),
        }
        assert!(res.is_err(), "a leaf with a forged constant must be rejected under the honest VK");
    }

    /// PoC (end to end): the forged left leaf (claims `initial = commit(99)`,
    /// honest VK) is folded with an honest right leaf by the hiding merge, and
    /// the root is checked by the auditor against the TRUSTED root VK of the
    /// honest forest. At 19dcb37 the whole pipeline accepts and the root
    /// surfaces `(commit(99), commit(2))` (this test fails there); with the fix
    /// the forged child cannot be verified in-circuit, so no root is produced.
    #[test]
    fn forged_const_leaf_cannot_reach_pinned_root() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let honest_root = prove_hiding_merge(&l0, &l1);
        let trusted_root_vk = vk_pin_values(&honest_root.0);
        verify_bound_stark_proof(&honest_root.0, &trusted_root_vk);

        let res = outcome(|| {
            let forged_l0 = forge_exposing_leaf(
                &boundary_values(commit(0), commit(1)),
                &boundary_values(commit(99), commit(1)),
            );
            let root = prove_hiding_merge(&forged_l0, &l1);
            verify_bound_stark_proof(&root.0, &trusted_root_vk);
            read_exposed_boundary(&root)
        });
        match &res {
            Ok((i, f)) => println!(
                "POC E2E=ACCEPTED root_initial_is_forged={} root_final_is_honest={}",
                *i == commit(99),
                *f == commit(2)
            ),
            Err(e) => println!("POC E2E=REJECTED ({})", e.lines().next().unwrap_or("")),
        }
        assert!(
            res.is_err(),
            "a forged-constant leaf must not reach a root that passes the trusted root-VK pin"
        );
    }

    /// FINDING 2 support: values surfaced through ExposeAir ARE bound for the
    /// native verifier (unlike `alloc_public_input` values, which live only in
    /// PublicAir's main trace). Tampering with one surfaced public value of an
    /// honest proof must make `verify_bound_stark_proof` (VK pinned) fail.
    #[test]
    fn exposed_public_values_are_bound_natively() {
        let mut leaf = prove_boundary_leaf(commit(0), commit(1));
        let vk = vk_pin_values(&leaf.0);
        verify_bound_stark_proof(&leaf.0, &vk);
        let entry = leaf
            .0
            .non_primitives
            .iter_mut()
            .find(|e| e.public_values.len() == 2 * COMMIT_LEN)
            .expect("expose entry");
        entry.public_values[3] += Val::ONE;
        let res = outcome(|| verify_bound_stark_proof(&leaf.0, &vk));
        println!(
            "EXPOSE_PV_TAMPER={}",
            match &res {
                Ok(()) => "ACCEPTED".to_string(),
                Err(e) => format!("REJECTED ({})", e.lines().next().unwrap_or("")),
            }
        );
        assert!(res.is_err(), "a tampered exposed public value must be rejected");
    }

    /// With the fix the in-circuit child-VK pin (`Comm::new_const`) binds the
    /// child VK VALUES: two merges whose (structurally identical) children
    /// differ only in constant values — hence, post-fix, in VK — get different
    /// merge VKs. At 19dcb37 both the leaf VKs and the merge VKs are equal.
    #[test]
    fn merge_vk_binds_child_vk_values() {
        let a0 = prove_boundary_leaf(commit(0), commit(1));
        let a1 = prove_boundary_leaf(commit(1), commit(2));
        let b0 = prove_boundary_leaf(commit(10), commit(11));
        let b1 = prove_boundary_leaf(commit(11), commit(12));
        let leaf_vks_equal = vk_pin_values(&a0.0) == vk_pin_values(&b0.0);
        let ma = prove_hiding_merge(&a0, &a1);
        let mb = prove_hiding_merge(&b0, &b1);
        let merge_vks_equal = vk_pin_values(&ma.0) == vk_pin_values(&mb.0);
        println!("CHILDVK leaf_vks_equal={leaf_vks_equal} merge_vks_equal={merge_vks_equal}");
        assert!(!leaf_vks_equal, "post-fix the toy leaf VKs differ (they bind their constants)");
        assert!(!merge_vks_equal, "post-fix a merge VK must depend on its children's VK values");
    }

    /// With the fix every `alloc_const` value enters the VK, so a
    /// data-dependent constant in a real leaf would make its VK (and hence
    /// every ancestor merge's VK) data-dependent. Asserts, per family, that
    /// four leaves over different data/states share ONE VK, that the two roots
    /// share ONE VK, and that both equal the VK DERIVED from public parameters
    /// only (a no-op leaf, [`root_vk_deriver`]) — commitment and metadata.
    ///
    /// HISTORY: the root VKs were only printed while the merge-circuit build
    /// was nondeterministic (global-bus checks emitted in `HashMap` order in
    /// the fork's recursive verifier); fixed in the determinism fork branch
    /// (recursion: emit global-bus cumulative-sum checks in first-seen order),
    /// so they are asserted now.
    fn assert_data_independent_vks(
        family: &str,
        forest_a: Vec<RecursionOutput<ConfigWithFriParams>>,
        forest_b: Vec<RecursionOutput<ConfigWithFriParams>>,
        noop_leaf: BatchStarkProof<ConfigWithFriParams>,
    ) {
        assert_eq!(forest_a.len(), forest_b.len());
        let leaf_vks: Vec<_> =
            forest_a.iter().chain(forest_b.iter()).map(|l| vk_pin_values(&l.0)).collect();
        let leaves_equal = leaf_vks.windows(2).all(|w| w[0] == w[1]);
        let noop_leaf_vk = vk_pin_values(&noop_leaf);
        let shape = ForestShape::forest(forest_a.len());
        let mut deriver = root_vk_deriver(noop_leaf);
        let derived = deriver.root_vk(&shape);
        let derived_unproved = deriver.root_commitment_unproved(&shape);
        let ra = prove_forest_over(forest_a);
        let rb = prove_forest_over(forest_b);
        let (vk_a, vk_b) = (vk_pin_values(&ra.0), vk_pin_values(&rb.0));
        println!(
            "DATAVK {family}: leaf_vks_equal={leaves_equal} noop_leaf_vk_equal={} root_vks_equal={} \
             derived_root_vk_equal={} derived_unproved_equal={} derived_shape_equal={}",
            noop_leaf_vk == leaf_vks[0],
            vk_a == vk_b,
            derived.commitment == vk_a,
            derived_unproved == vk_a,
            derived.shape.as_ref() == Some(&bound_proof_shape(&ra.0)),
        );
        assert!(leaves_equal, "{family}: leaf VK must not depend on the sketch data");
        assert_eq!(noop_leaf_vk, leaf_vks[0], "{family}: no-op leaf VK == real leaf VK");
        assert_eq!(vk_a, vk_b, "{family}: root VK must not depend on the sketch data");
        assert_eq!(derived.commitment, vk_a, "{family}: derived root VK == real root VK");
        assert_eq!(derived_unproved, vk_a, "{family}: unproved root VK == real root VK");
        assert_eq!(
            derived.shape.as_ref(),
            Some(&bound_proof_shape(&ra.0)),
            "{family}: derived root metadata == real root metadata"
        );
        assert_eq!(bound_proof_shape(&ra.0), bound_proof_shape(&rb.0));
        verify_bound_proof(&ra, &derived);
        verify_bound_proof(&rb, &derived);
    }

    /// The hiding-merge circuit exactly as [`prove_hiding_merge_proofs`] builds
    /// it (before proving) — the shared [`build_hiding_merge_circuit`].
    fn hiding_merge_circuit(
        left: &BatchStarkProof<ConfigWithFriParams>,
        right: &BatchStarkProof<ConfigWithFriParams>,
    ) -> p3_circuit::Circuit<Challenge> {
        let config = make_leaf_config();
        let backend = make_backend();
        let left_input = recursion_input_from_proof(left);
        let right_input = recursion_input_from_proof(right);
        build_hiding_merge_circuit(&left_input, &right_input, &config, &backend, MergeMode::Real).0
    }

    /// DIAGNOSTIC: why do real-forest root VKs depend on the data? Prints each
    /// leaf's table heights (the in-circuit verifier bakes each child's degree
    /// bits in as `alloc_const`) and diffs the Const ops of the two merge
    /// circuits.
    fn diag_forest_pair(
        family: &str,
        a: &[RecursionOutput<ConfigWithFriParams>],
        b: &[RecursionOutput<ConfigWithFriParams>],
    ) {
        for (tag, leaves) in [("A", a), ("B", b)] {
            for (i, l) in leaves.iter().enumerate() {
                let np: Vec<_> = l.0.non_primitives.iter().map(|e| (e.op_type.clone(), e.rows)).collect();
                println!(
                    "DIAG {family} {tag}{i}: degree_bits={:?} rows={:?} npo_rows={np:?}",
                    l.0.proof.degree_bits, l.0.rows
                );
            }
        }
        let ca = hiding_merge_circuit(&a[0].0, &a[1].0);
        let cb = hiding_merge_circuit(&b[0].0, &b[1].0);
        let consts = |c: &p3_circuit::Circuit<Challenge>| -> Vec<Challenge> {
            c.ops
                .iter()
                .filter_map(|op| match op {
                    p3_circuit::ops::Op::Const { val, .. } => Some(*val),
                    _ => None,
                })
                .collect()
        };
        let (ka, kb) = (consts(&ca), consts(&cb));
        println!(
            "DIAG {family} merge: n_ops A={} B={} n_const A={} B={}",
            ca.ops.len(),
            cb.ops.len(),
            ka.len(),
            kb.len()
        );
        let mut shown = 0;
        for (i, (x, y)) in ka.iter().zip(kb.iter()).enumerate() {
            if x != y && shown < 12 {
                println!("DIAG {family} merge const[{i}]: A={x:?} B={y:?}");
                shown += 1;
            }
        }
        let ndiff = ka.iter().zip(kb.iter()).filter(|(x, y)| x != y).count();
        println!("DIAG {family} merge: {ndiff} differing const values (positionwise)");
        let pa = ca.generate_preprocessed_columns::<EXT_D>().unwrap();
        let pb = cb.generate_preprocessed_columns::<EXT_D>().unwrap();
        for (i, (x, y)) in pa.primitive.iter().zip(pb.primitive.iter()).enumerate() {
            let pos: Vec<usize> =
                x.iter().zip(y.iter()).enumerate().filter(|(_, (u, v))| u != v).map(|(j, _)| j).collect();
            println!(
                "DIAG {family} merge prep primitive[{i}]: len A={} B={} ndiff={} first={:?}",
                x.len(),
                y.len(),
                pos.len(),
                &pos[..pos.len().min(8)]
            );
        }
        let mut keys: Vec<_> = pa.non_primitive.keys().cloned().collect();
        keys.sort_by_key(|k| format!("{k:?}"));
        for k in keys {
            let eq = pa.non_primitive.get(&k) == pb.non_primitive.get(&k);
            println!("DIAG {family} merge prep npo {k:?}: equal={eq}");
        }
        println!(
            "DIAG {family} merge prep ext_reads_equal={} dup_npo_outputs_equal={}",
            pa.ext_reads == pb.ext_reads,
            pa.dup_npo_outputs == pb.dup_npo_outputs
        );
        let ra = prove_hiding_merge_proofs(&a[0].0, &a[1].0);
        let rb = prove_hiding_merge_proofs(&b[0].0, &b[1].0);
        let ra2 = prove_hiding_merge_proofs(&a[0].0, &a[1].0);
        println!(
            "DIAG {family} root VK: A==B {}  A==A(re-merge same children) {}",
            vk_pin_values(&ra.0) == vk_pin_values(&rb.0),
            vk_pin_values(&ra.0) == vk_pin_values(&ra2.0)
        );
        for (tag, r) in [("A", &ra), ("A'", &ra2), ("B", &rb)] {
            let prep = r.0.stark_common.preprocessed.as_ref().unwrap();
            let metas: Vec<_> = prep
                .instances
                .iter()
                .map(|m| m.as_ref().map(|m| (m.matrix_index, m.width, m.degree_bits)))
                .collect();
            let np: Vec<_> = r.0.non_primitives.iter().map(|e| (e.op_type.clone(), e.rows, e.lanes)).collect();
            println!(
                "DIAG {family} root {tag}: degree_bits={:?} rows={:?} prep_metas={metas:?} npo={np:?}",
                r.0.proof.degree_bits, r.0.rows
            );
        }
    }

    /// Rebuild the hiding-merge circuit over the SAME children `rebuilds`
    /// times and require an identical op list each time; returns the op count.
    fn assert_merge_circuit_build_deterministic(
        tag: &str,
        left: &BatchStarkProof<ConfigWithFriParams>,
        right: &BatchStarkProof<ConfigWithFriParams>,
        rebuilds: usize,
    ) -> usize {
        let base = hiding_merge_circuit(left, right);
        for trial in 0..rebuilds {
            let c = hiding_merge_circuit(left, right);
            let first_diff = base.ops.iter().zip(c.ops.iter()).position(|(a, b)| a != b);
            let n_diff = base.ops.iter().zip(c.ops.iter()).filter(|(a, b)| a != b).count();
            println!(
                "DETERMINISM {tag} trial {trial}: n_ops {} vs {} first_differing_op={first_diff:?} \
                 n_differing_ops={n_diff}",
                base.ops.len(),
                c.ops.len()
            );
            if let Some(i) = first_diff {
                let fmt = |o: &p3_circuit::ops::Op<Challenge>| {
                    format!("{o:?}").chars().take(220).collect::<String>()
                };
                println!("DETERMINISM   base op[{i}] = {}", fmt(&base.ops[i]));
                println!("DETERMINISM   this op[{i}] = {}", fmt(&c.ops[i]));
            }
            assert_eq!(c.ops.len(), base.ops.len(), "{tag}: op count changed on rebuild {trial}");
            assert_eq!(first_diff, None, "{tag}: op order changed on rebuild {trial}");
        }
        base.ops.len()
    }

    /// REGRESSION (root-VK determinism): rebuilding a hiding merge over the
    /// SAME children must give the same circuit and hence the same root VK.
    ///
    /// HISTORY: this was an `#[ignore]`d diagnostic. At fork 19dcb37 and the
    /// constfix port, about half of all rebuilds over two real v9 children
    /// moved one block of 26 ALU ops (e.g. an `Add` with `out: WitnessId(0)`
    /// at op ~110k or ~223k), so the root VK differed between builds, while
    /// toy children were stable. Root cause: the fork's recursive batch-STARK
    /// verifier emitted one global-bus cumulative-sum check per bus while
    /// iterating a randomly seeded `HashMap` (toy leaves have a single global
    /// bus; v9 leaves and every merge have several). Fixed on the fork's
    /// `determinism` branch by emitting the checks in first-seen bus order.
    ///
    /// Covers: toy leaves (1 global bus), real v9 leaves (the observed case),
    /// and a level-2 merge whose children are merges (Poseidon2 / recompose /
    /// expose buses) — circuit op lists over several rebuilds, then the VK
    /// both from the unproved circuit and from two independently proved roots.
    #[test]
    fn diag_merge_circuit_build_determinism() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        assert_merge_circuit_build_deterministic("toy", &l0.0, &l1.0, 3);

        // Real v9 leaves (two global buses per child).
        use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, D, W};
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_v9::CountMinV9;
        let params = CountMinLeafParams::default();
        let mut s = CountMinV9::new(&CountMinParams { d: D, w: W });
        let mut leaves = Vec::new();
        for bt in [[(7u64, 3u32), (11, 5)], [(13, 2), (7, 4)]] {
            let b: Vec<_> = bt.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect();
            leaves.push(prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b.clone()).output);
            for u in &b {
                CountMinV9::update(&mut s, u);
            }
        }
        assert_merge_circuit_build_deterministic("v9", &leaves[0].0, &leaves[1].0, 6);
        let vk_unproved = hiding_merge_vk(&leaves[0].0, &leaves[1].0);
        assert_eq!(vk_unproved, hiding_merge_vk(&leaves[0].0, &leaves[1].0), "v9: unproved VK");
        let v1 = prove_hiding_merge(&leaves[0], &leaves[1]);
        let v2 = prove_hiding_merge(&leaves[0], &leaves[1]);
        println!(
            "DETERMINISM v9 root VK: re-merge equal={} unproved==proved {}",
            vk_pin_values(&v1.0) == vk_pin_values(&v2.0),
            vk_unproved == vk_pin_values(&v1.0)
        );
        assert_eq!(vk_pin_values(&v1.0), vk_pin_values(&v2.0), "v9: root VK across re-merges");
        assert_eq!(vk_unproved, vk_pin_values(&v1.0), "v9: unproved VK == proved root VK");

        // Level 2: children are merges (several global buses each).
        let l2 = prove_boundary_leaf(commit(2), commit(3));
        let l3 = prove_boundary_leaf(commit(3), commit(4));
        let m01 = prove_hiding_merge(&l0, &l1);
        let m23 = prove_hiding_merge(&l2, &l3);
        assert_merge_circuit_build_deterministic("level2", &m01.0, &m23.0, 4);
        let r1 = prove_hiding_merge(&m01, &m23);
        let r2 = prove_hiding_merge(&m01, &m23);
        assert_eq!(vk_pin_values(&r1.0), vk_pin_values(&r2.0), "level2: root VK across re-merges");
        assert_eq!(hiding_merge_vk(&m01.0, &m23.0), vk_pin_values(&r1.0), "level2: unproved VK");
    }

    #[test]
    #[ignore = "diagnostic: run explicitly"]
    fn diag_real_forest_root_vk_data_dependence() {
        use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, D, W};
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_v9::CountMinV9;
        let params = CountMinLeafParams::default();
        let v9 = |batches: [[(u64, u32); 2]; 2]| {
            let mut s = CountMinV9::new(&CountMinParams { d: D, w: W });
            let mut leaves = Vec::new();
            for bt in batches {
                let b: Vec<_> =
                    bt.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect();
                leaves.push(prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b.clone()).output);
                for u in &b {
                    CountMinV9::update(&mut s, u);
                }
            }
            leaves
        };
        diag_forest_pair(
            "v9",
            &v9([[(7, 3), (11, 5)], [(13, 2), (7, 4)]]),
            &v9([[(1000, 9), (2024, 1)], [(5, 17), (99_999, 2)]]),
        );

        use crate::sketch::ss_final_full::{
            SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full, prove_ss_full_exposed,
        };
        let sp = SsFullParams { capacity: 4, batch: 2 };
        let ss = |ups: [[(u64, u64); 2]; 2]| {
            let mut s = SsFullState::empty(sp);
            let mut leaves = Vec::new();
            for us in ups {
                let b: Vec<_> = us.iter().map(|&(k, c)| SsFullUpdate::real(k as _, c as _)).collect();
                leaves.push(prove_ss_full_exposed(sp, s.clone(), b.clone()).output);
                s = apply_batch_ss_full(&s, &b).0;
            }
            leaves
        };
        diag_forest_pair(
            "ss",
            &ss([[(7, 1), (11, 1)], [(13, 1), (7, 1)]]),
            &ss([[(500, 1), (3, 1)], [(3, 1), (900, 1)]]),
        );

        use crate::sketch::gk_final_full::{
            GKFullParams, GKFullState, GKFullUpdate, apply_batch_full, prove_gk_full_exposed,
        };
        let gp = GKFullParams { capacity: 4, batch: 2 };
        let gk = |vals: [[u64; 2]; 2]| {
            let mut s = GKFullState::empty(gp);
            let mut leaves = Vec::new();
            for vs in vals {
                let b: Vec<_> = vs.iter().map(|&v| GKFullUpdate::real(v as _)).collect();
                leaves.push(prove_gk_full_exposed(gp, s.clone(), b.clone()).output);
                s = apply_batch_full(&s, &b).0;
            }
            leaves
        };
        diag_forest_pair("gk", &gk([[10, 11], [20, 21]]), &gk([[5, 300], [7, 1000]]));

        use crate::sketch::gk_bandmerge::{Gk2State, GkbParams, apply_batch2, prove_gkb2_exposed};
        let g2p = GkbParams { capacity: 4, batch: 2, s: 2 };
        let gk2 = |vals: [[u32; 2]; 2]| {
            let mut s = Gk2State::empty(g2p);
            let mut leaves = Vec::new();
            for vs in vals {
                let b = vs.to_vec();
                leaves.push(prove_gkb2_exposed(g2p, s.clone(), b.clone()).output);
                s = apply_batch2(&s, &b);
            }
            leaves
        };
        diag_forest_pair("gk2", &gk2([[10, 11], [20, 21]]), &gk2([[5, 300], [7, 1000]]));
    }

    /// MEASUREMENT (constfix before/after): prove time, verify time, proof size
    /// and ConstAir shape of the `countmin_omc` leaf (prebuilt circuit,
    /// per-epoch prove) plus one toy hiding merge. Run the same binary built
    /// against fork 19dcb37 and against the constfix port, e.g.
    /// `CONSTFIX_REPS=15 <test-bin> measure_constfix_cost --ignored --nocapture --test-threads 1`.
    #[test]
    #[ignore = "measurement: run explicitly"]
    fn measure_constfix_cost() {
        use std::time::Instant;

        use crate::experiments::{ms, proof_size};
        use crate::recursion::recursive::timing;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf};
        use crate::sketch::countmin_v9::CountMinV9;

        let reps: usize =
            std::env::var("CONSTFIX_REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(15);
        let med = |v: &mut Vec<f64>| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let shape = |p: &BatchStarkProof<ConfigWithFriParams>| {
            let prep = p.stark_common.preprocessed.as_ref().unwrap();
            let c = prep.instances[0].as_ref().map(|m| (m.width, m.degree_bits));
            let total_w: usize = prep.instances.iter().flatten().map(|m| m.width).sum();
            (format!("{:?}", p.rows), c, total_w)
        };
        for (d, w, m) in [(2usize, 4usize, 2usize), (4, 64, 16), (7, 128, 128)] {
            let params = CmOmcParams { d, w, batch: m };
            let t0 = Instant::now();
            let mut leaf = build_countmin_omc_leaf(params, false);
            let setup_ms = ms(t0.elapsed());
            let state = CountMinV9::new(&CountMinParams { d, w });
            let batch: Vec<CountMinUpdate> = (0..m)
                .map(|i| CountMinUpdate {
                    key: (i as u64).wrapping_mul(0xABCD_1234) ^ 0x7,
                    value: 1 + (i as u32 % 5),
                })
                .collect();
            let (mut pv, mut vv) = (Vec::new(), Vec::new());
            let mut last = None;
            for _ in 0..reps {
                let p = leaf.prove_epoch(state.clone(), batch.clone());
                let t = timing::take();
                pv.push(ms(t.prove));
                vv.push(ms(t.verify));
                last = Some(p);
            }
            let p = last.unwrap();
            let (rows, c, total_w) = shape(&p.output.0);
            let pmin = pv.iter().cloned().fold(f64::INFINITY, f64::min);
            println!(
                "MEASURE cm_omc d={d} w={w} m={m} reps={reps}: setup_ms={setup_ms:.1} prove_ms_med={:.2} \
                 prove_ms_min={pmin:.2} verify_ms_med={:.2} proof_bytes={} rows(const,public,alu)={rows} \
                 const_prep(width,log_h)={c:?} total_prep_width={total_w}",
                med(&mut pv),
                med(&mut vv),
                p.proof_size()
            );
        }

        // One toy hiding merge (the recursion layer verifies each child's
        // wider ConstAir preprocessed rows in-circuit).
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let mreps = reps.min(7);
        let mut mv = Vec::new();
        let mut last = None;
        for _ in 0..mreps {
            let t0 = Instant::now();
            let r = prove_hiding_merge(&l0, &l1);
            mv.push(ms(t0.elapsed()));
            last = Some(r);
        }
        let r = last.unwrap();
        let (rows, c, total_w) = shape(&r.0);
        println!(
            "MEASURE toy_merge reps={mreps}: build+prove_ms_med={:.1} proof_bytes={} leaf_proof_bytes={} \
             rows(const,public,alu)={rows} const_prep(width,log_h)={c:?} total_prep_width={total_w}",
            med(&mut mv),
            proof_size(&r.0),
            proof_size(&l0.0)
        );
    }

    /// DERIVATION (Task H2): the root VKs of real forests equal the VKs
    /// derived from public parameters only — a no-op leaf plus the tree shape
    /// ([`root_vk_deriver`]) — for `t = 2, 3, 4` leaves, over the forest
    /// cascade and the left-leaning chain. Checks commitment AND metadata, the
    /// unproved root commitment, and that each real root verifies against its
    /// derived VK while a wrong-size derived VK is rejected.
    fn assert_derived_root_vks_match(
        family: &str,
        leaves: Vec<RecursionOutput<ConfigWithFriParams>>,
        noop_leaf: BatchStarkProof<ConfigWithFriParams>,
    ) {
        assert_eq!(leaves.len(), 4);
        let leaf_vk = vk_pin_values(&leaves[0].0);
        assert!(leaves.iter().all(|l| vk_pin_values(&l.0) == leaf_vk), "{family}: leaf VKs");
        assert_eq!(vk_pin_values(&noop_leaf), leaf_vk, "{family}: no-op leaf VK == real leaf VK");
        let mut deriver = root_vk_deriver(noop_leaf);

        // Real roots (sharing the m12 subtree): forest(2), forest(3) = chain(3),
        // chain(4) exactly as `prove_chain_over` folds, then forest(4) via
        // `prove_forest_over` itself.
        let m12 = prove_hiding_merge(&leaves[0], &leaves[1]);
        let m123 = prove_hiding_merge(&m12, &leaves[2]);
        let chain4 = prove_hiding_merge(&m123, &leaves[3]);
        let mut real = vec![
            ("forest2", ForestShape::forest(2), m12),
            ("forest3", ForestShape::forest(3), m123),
            ("chain4", ForestShape::chain(4), chain4),
        ];
        real.push(("forest4", ForestShape::forest(4), prove_forest_over(leaves)));

        let mut derived_vks = Vec::new();
        for (tag, shape, root) in &real {
            let derived = deriver.root_vk(shape);
            let unproved = deriver.root_commitment_unproved(shape);
            let got = vk_pin_values(&root.0);
            let shape_eq = derived.shape.as_ref() == Some(&bound_proof_shape(&root.0));
            println!(
                "DERIVE {family} {tag}: derived_vk_equal={} unproved_equal={} shape_equal={shape_eq}",
                derived.commitment == got,
                unproved == got
            );
            assert_eq!(derived.commitment, got, "{family} {tag}: derived root VK == real");
            assert_eq!(unproved, got, "{family} {tag}: unproved root VK == real");
            assert!(shape_eq, "{family} {tag}: derived metadata == real metadata");
            verify_bound_proof(root, &derived);
            derived_vks.push(derived);
        }
        println!("DERIVE {family}: dummy merges proved = {}", deriver.dummy_merges());
        // forest(4) and chain(4) are different circuits; each pin rejects the other.
        assert_ne!(derived_vks[2].commitment, derived_vks[3].commitment);
        let res = outcome(|| verify_bound_proof(&real[3].2, &derived_vks[2]));
        assert!(res.is_err(), "{family}: a forest(4) root must not verify under the chain(4) VK");
    }

    #[test]
    fn derived_root_vks_match_real_cm_v9() {
        use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, D, W};
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
        use crate::recursion::recursive::noop_leaf::cm_v9_noop_leaf;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_v9::CountMinV9;

        let params = CountMinLeafParams::default();
        let mut s = CountMinV9::new(&CountMinParams { d: D, w: W });
        let mut leaves = Vec::new();
        for bt in [[(7u64, 3u32), (11, 5)], [(13, 2), (7, 4)], [(99, 1), (5, 8)], [(7, 2), (1234, 6)]] {
            let b: Vec<_> = bt.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect();
            leaves.push(prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b.clone()).output);
            for u in &b {
                CountMinV9::update(&mut s, u);
            }
        }
        assert_derived_root_vks_match("cm_v9", leaves, cm_v9_noop_leaf(params));
    }

    #[test]
    fn derived_root_vks_match_real_cm_omc() {
        use crate::recursion::recursive::noop_leaf::cm_omc_noop_leaf;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf, countmin_omc_advance};
        use crate::sketch::countmin_v9::CountMinV9;

        let params = CmOmcParams { d: 2, w: 4, batch: 2 };
        let mut leaf = build_countmin_omc_leaf(params, true);
        // Leaf VK from the prebuilt circuit's prover data alone (no proof).
        let built_vk = leaf.vk_pin_values();
        let mut s = CountMinV9::new(&CountMinParams { d: params.d, w: params.w });
        let mut leaves = Vec::new();
        for bt in [[(7u64, 3u32), (11, 5)], [(13, 2), (7, 4)], [(99, 1), (5, 8)], [(7, 2), (1234, 6)]] {
            let b: Vec<_> = bt.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect();
            leaves.push(leaf.prove_epoch(s.clone(), b.clone()).output);
            countmin_omc_advance(&mut s, &b);
        }
        assert_eq!(vk_pin_values(&leaves[0].0), built_vk, "omc: prebuilt-circuit VK == proof VK");
        assert_derived_root_vks_match("cm_omc", leaves, cm_omc_noop_leaf(params));
    }

    #[test]
    fn derived_root_vks_match_real_hll() {
        use crate::recursion::recursive::noop_leaf::hll_full_noop_leaf;
        use crate::sketch::hll_final_full::{
            HllFullParams, HllFullState, HllFullUpdate, apply_batch, prove_hll_full_exposed,
        };
        let params = HllFullParams { b: 4, batch: 2 };
        let mut s = HllFullState::empty(params);
        let mut leaves = Vec::new();
        for ks in [[7u64, 11], [13, 7], [123_456, 9], [42, 77_777]] {
            let b: Vec<_> = ks.iter().map(|&k| HllFullUpdate::real(k)).collect();
            leaves.push(prove_hll_full_exposed(params, s.clone(), b.clone()).output);
            s = apply_batch(&s, &b);
        }
        assert_derived_root_vks_match("hll", leaves, hll_full_noop_leaf(params));
    }

    /// METADATA PIN: a root whose metadata (here: the table packing the native
    /// verifier rebuilds its AIRs from) differs from the trusted root VK's is
    /// rejected by the pin itself, before any STARK verification.
    #[test]
    fn root_metadata_pin_rejects_tampered_metadata() {
        let l0 = prove_boundary_leaf(commit(0), commit(1));
        let l1 = prove_boundary_leaf(commit(1), commit(2));
        let mut merged = prove_hiding_merge(&l0, &l1);
        let pinned = RootVk {
            commitment: hiding_merge_vk(&l0.0, &l1.0),
            shape: Some(bound_proof_shape(&merged.0)),
        };
        verify_bound_proof(&merged, &pinned);
        merged.0.table_packing =
            TablePacking::new(1, 1).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let res = outcome(|| verify_bound_stark_proof_pinned(&merged.0, &pinned));
        println!("METADATA_TAMPER={res:?}");
        assert!(
            res.as_ref().is_err_and(|e| e.contains("root proof metadata mismatch")),
            "the metadata pin must reject a proof with altered table packing"
        );
    }

    #[test]
    fn real_v9_vks_are_data_independent() {
        use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, D, W};
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_v9::CountMinV9;

        let params = CountMinLeafParams::default();
        let forest = |batches: [[(u64, u32); 2]; 2]| {
            let mut s = CountMinV9::new(&CountMinParams { d: D, w: W });
            let mut leaves = Vec::new();
            for bt in batches {
                let b: Vec<_> =
                    bt.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect();
                leaves.push(prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b.clone()).output);
                for u in &b {
                    CountMinV9::update(&mut s, u);
                }
            }
            leaves
        };
        assert_data_independent_vks(
            "v9",
            forest([[(7, 3), (11, 5)], [(13, 2), (7, 4)]]),
            forest([[(1000, 9), (2024, 1)], [(5, 17), (99_999, 2)]]),
            crate::recursion::recursive::noop_leaf::cm_v9_noop_leaf(params),
        );
    }

    #[test]
    fn real_hll_vks_are_data_independent() {
        use crate::sketch::hll_final_full::{
            HllFullParams, HllFullState, HllFullUpdate, apply_batch, prove_hll_full_exposed,
        };
        let params = HllFullParams { b: 4, batch: 2 };
        let forest = |keys: [[u64; 2]; 2]| {
            let mut s = HllFullState::empty(params);
            let mut leaves = Vec::new();
            for ks in keys {
                let b: Vec<_> = ks.iter().map(|&k| HllFullUpdate::real(k)).collect();
                leaves.push(prove_hll_full_exposed(params, s.clone(), b.clone()).output);
                s = apply_batch(&s, &b);
            }
            leaves
        };
        assert_data_independent_vks(
            "hll",
            forest([[7, 11], [13, 7]]),
            forest([[123_456, 9], [42, 77_777]]),
            crate::recursion::recursive::noop_leaf::hll_full_noop_leaf(params),
        );
    }

    #[test]
    fn real_ss_vks_are_data_independent() {
        use crate::sketch::ss_final_full::{
            SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full, prove_ss_full_exposed,
        };
        let params = SsFullParams { capacity: 4, batch: 2 };
        let forest = |ups: [[(u64, u64); 2]; 2]| {
            let mut s = SsFullState::empty(params);
            let mut leaves = Vec::new();
            for us in ups {
                let b: Vec<_> = us.iter().map(|&(k, c)| SsFullUpdate::real(k as _, c as _)).collect();
                leaves.push(prove_ss_full_exposed(params, s.clone(), b.clone()).output);
                s = apply_batch_ss_full(&s, &b).0;
            }
            leaves
        };
        assert_data_independent_vks(
            "ss",
            forest([[(7, 1), (11, 1)], [(13, 1), (7, 1)]]),
            forest([[(500, 1), (3, 1)], [(3, 1), (900, 1)]]),
            crate::recursion::recursive::noop_leaf::ss_full_noop_leaf(params),
        );
    }

    #[test]
    fn real_gk_vks_are_data_independent() {
        use crate::sketch::gk_final_full::{
            GKFullParams, GKFullState, GKFullUpdate, apply_batch_full, prove_gk_full_exposed,
        };
        let params = GKFullParams { capacity: 4, batch: 2 };
        let forest = |vals: [[u64; 2]; 2]| {
            let mut s = GKFullState::empty(params);
            let mut leaves = Vec::new();
            for vs in vals {
                let b: Vec<_> = vs.iter().map(|&v| GKFullUpdate::real(v as _)).collect();
                leaves.push(prove_gk_full_exposed(params, s.clone(), b.clone()).output);
                s = apply_batch_full(&s, &b).0;
            }
            leaves
        };
        assert_data_independent_vks(
            "gk",
            forest([[10, 11], [20, 21]]),
            forest([[5, 300], [7, 1000]]),
            crate::recursion::recursive::noop_leaf::gk_full_noop_leaf(params),
        );
    }

    #[test]
    fn real_gk2_vks_are_data_independent() {
        use crate::sketch::gk_bandmerge::{Gk2State, GkbParams, apply_batch2, prove_gkb2_exposed};
        let params = GkbParams { capacity: 4, batch: 2, s: 2 };
        let forest = |vals: [[u32; 2]; 2]| {
            let mut s = Gk2State::empty(params);
            let mut leaves = Vec::new();
            for vs in vals {
                let b = vs.to_vec();
                leaves.push(prove_gkb2_exposed(params, s.clone(), b.clone()).output);
                s = apply_batch2(&s, &b);
            }
            leaves
        };
        assert_data_independent_vks(
            "gk2",
            forest([[10, 11], [20, 21]]),
            forest([[5, 300], [7, 1000]]),
            crate::recursion::recursive::noop_leaf::gk2_noop_leaf(params),
        );
    }

    // ─── Adversarial root-VK checks (adopted from the H2 review) ────────────

    /// `n` real Count-Min v9 exposed leaves over a fixed boundary chain, their
    /// params, and the chain's commitments `[Com(S_0), .., Com(S_n)]`.
    fn real_v9_leaves(
        n: usize,
    ) -> (
        crate::recursion::recursive::countmin_leaf::CountMinLeafParams,
        Vec<RecursionOutput<ConfigWithFriParams>>,
        Vec<CountMinCommit>,
    ) {
        use crate::commitment::countmin::commit_countmin;
        use crate::recursion::recursive::countmin_leaf::{CountMinLeafParams, D, W};
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_exposed_with_params;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
        use crate::sketch::countmin_v9::CountMinV9;
        let params = CountMinLeafParams::default();
        let mut s = CountMinV9::new(&CountMinParams { d: D, w: W });
        let mut commits = vec![commit_countmin(&s)];
        let mut leaves = Vec::new();
        let bts = [[(7u64, 3u32), (11, 5)], [(13, 2), (7, 4)], [(99, 1), (5, 8)], [(7, 2), (1234, 6)]];
        for bt in bts.iter().take(n) {
            let b: Vec<_> = bt.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect();
            leaves.push(prove_countmin_leaf_v9_exposed_with_params(params, s.clone(), b.clone()).output);
            for u in &b {
                CountMinV9::update(&mut s, u);
            }
            commits.push(commit_countmin(&s));
        }
        (params, leaves, commits)
    }

    /// Splice attack: a real v9 leaf (`S_0 -> S_1`) merged with a TOY boundary
    /// leaf that claims `S_1 -> forged`. The legacy self-pin cannot tell (its
    /// VK comes from the root itself); the derived pin must reject, both with
    /// the metadata and with the commitment alone.
    #[test]
    fn splice_toy_leaf_into_real_forest() {
        let (params, leaves, commits) = real_v9_leaves(1);
        let forged = commit(999);
        let toy = prove_boundary_leaf(commits[1], forged);
        let root = prove_hiding_merge(&leaves[0], &toy);
        let (ri, rf) = read_exposed_boundary(&root);
        println!(
            "splice root boundary: initial_is_real_S0={} final_is_forged={}",
            ri == commits[0],
            rf == forged
        );
        let legacy = outcome(|| verify_bound_proof_self_pinned_legacy(&root));
        println!(
            "splice LEGACY self-pin: {}",
            if legacy.is_ok() { "ACCEPTED".to_string() } else { format!("REJECTED {legacy:?}") }
        );
        let derived =
            derive_forest_root_vk(crate::recursion::recursive::noop_leaf::cm_v9_noop_leaf(params), 2);
        let full = outcome(|| verify_bound_proof(&root, &derived));
        println!(
            "splice DERIVED full pin: {:?}",
            full.as_ref().map_err(|e| e.lines().next().unwrap_or("").to_string())
        );
        let conly =
            outcome(|| verify_bound_proof(&root, &RootVk::commitment_only(derived.commitment.clone())));
        println!(
            "splice DERIVED commitment-only pin: {:?}",
            conly.as_ref().map_err(|e| e.lines().next().unwrap_or("").to_string())
        );
        println!("splice shapes_equal={}", derived.shape.as_ref() == Some(&bound_proof_shape(&root.0)));
        assert!(full.is_err());
        assert!(conly.as_ref().is_err_and(|e| e.contains("root VK mismatch")));
    }

    /// A `forest(4)` root under a `chain(4)` VK: the rejection must come from
    /// the commitment pin (commitment-only, and with the forest's metadata).
    #[test]
    fn commitment_pin_rejects_other_shape() {
        let (params, leaves, _) = real_v9_leaves(4);
        let mut deriver =
            root_vk_deriver(crate::recursion::recursive::noop_leaf::cm_v9_noop_leaf(params));
        let f4 = deriver.root_vk(&ForestShape::forest(4));
        let c4 = deriver.root_vk(&ForestShape::chain(4));
        println!(
            "f4/c4 shapes_equal={} commitments_equal={} dummy_merges={}",
            f4.shape == c4.shape,
            f4.commitment == c4.commitment,
            deriver.dummy_merges()
        );
        let root = prove_forest_over(leaves);
        verify_bound_proof(&root, &f4);
        let full = outcome(|| verify_bound_proof(&root, &c4));
        println!(
            "f4-under-c4 full: {:?}",
            full.as_ref().map_err(|e| e.lines().next().unwrap_or("").to_string())
        );
        let conly =
            outcome(|| verify_bound_proof(&root, &RootVk::commitment_only(c4.commitment.clone())));
        println!(
            "f4-under-c4 commitment-only: {:?}",
            conly.as_ref().map_err(|e| e.lines().next().unwrap_or("").to_string())
        );
        assert!(conly.as_ref().is_err_and(|e| e.contains("root VK mismatch")));
        // Mixed: c4 commitment + f4 metadata (the metadata pin passes), so the
        // commitment check must fire.
        let mixed = outcome(|| {
            verify_bound_proof(&root, &RootVk { commitment: c4.commitment.clone(), shape: f4.shape.clone() })
        });
        assert!(mixed.as_ref().is_err_and(|e| e.contains("root VK mismatch")));
    }

    // ─── M0 harness switches: merge cache ───────────────────────────────────

    /// A toy leaf exposing the Interval statement
    /// `(Com_k, Com_{k'}, (t, t), H)` with `H = (salt, salt + 1, …)`: its VK
    /// depends on every exposed value (constants are in the VK), its proof
    /// shape on none of them.
    fn toy_interval_leaf(t: u64, init: u64, fin: u64, salt: u64) -> RecursionOutput<ConfigWithFriParams> {
        use p3_field::BasedVectorSpace;
        let mut v: Vec<Val> = commit(init).0.to_vec();
        v.extend_from_slice(&commit(fin).0);
        v.extend([Val::from_u64(t), Val::from_u64(t), Val::ZERO, Val::ZERO]);
        v.extend((0..COMMIT_LEN as u64).map(|i| Val::from_u64(salt + i)));
        let chals: Vec<Challenge> = v
            .chunks(EXT_D)
            .map(|c| Challenge::from_basis_coefficients_slice(c).expect("D coefficients"))
            .collect();
        prove_exposing_leaf(&chals)
    }

    /// M0 (`EXP_MERGE_CACHE`): children of the SAME proof shape but another
    /// VK miss the cache (the key carries the VK values, not just the shape),
    /// children of the cached VK and shape hit it, and every merge, cached or
    /// not, natively verifies against the merge VK derived without proving
    /// ([`hiding_merge_vk`]); the two VKs differ.
    #[test]
    fn m0_merge_cache_misses_same_shape_other_vk() {
        let a1 = toy_interval_leaf(1, 0, 1, 100);
        let a2 = toy_interval_leaf(2, 1, 2, 200);
        let b1 = toy_interval_leaf(1, 0, 5, 300);
        let b2 = toy_interval_leaf(2, 5, 6, 400);
        for (a, b) in [(&a1, &b1), (&a2, &b2)] {
            assert_eq!(bound_proof_shape(&a.0), bound_proof_shape(&b.0), "same proof shape");
            assert_ne!(vk_pin_values(&a.0), vk_pin_values(&b.0), "different VK");
        }
        let vk_a = hiding_merge_vk(&a1.0, &a2.0);
        let vk_b = hiding_merge_vk(&b1.0, &b2.0);
        assert_ne!(vk_a, vk_b, "the merge VK bakes the children's VKs");
        let check = |out: &RecursionOutput<ConfigWithFriParams>, vk: &[Challenge]| {
            try_verify_bound_stark_proof_pinned(&out.0, &RootVk::commitment_only(vk.to_vec()))
                .expect("cache merge verifies natively against the derived VK");
        };

        let mut cache = MergeCache::new(2);
        let ma = cache.merge(&a1.0, &a2.0, 2);
        assert_eq!((cache.hits(), cache.misses(), cache.len()), (0, 1, 1));
        check(&ma, &vk_a);
        assert!(cache.contains(&a1.0, &a2.0));
        assert!(!cache.contains(&b1.0, &b2.0), "same shape, other VK: no entry");
        let mb = cache.merge(&b1.0, &b2.0, 2);
        assert_eq!((cache.hits(), cache.misses(), cache.len()), (0, 2, 2), "forced miss");
        check(&mb, &vk_b);
        let ma2 = cache.merge(&a1.0, &a2.0, 2);
        assert_eq!((cache.hits(), cache.misses()), (1, 2), "the first entry still hits");
        check(&ma2, &vk_a);
        assert_eq!(bound_proof_shape(&ma2.0), bound_proof_shape(&ma.0));
        assert_eq!(read_exposed_statement(&ma2.0), read_exposed_statement(&ma.0));
        // ZK: the cached prover draws fresh masks for every proof.
        #[cfg(feature = "zk")]
        assert_ne!(
            postcard::to_allocvec(&ma2.0).unwrap(),
            postcard::to_allocvec(&ma.0).unwrap(),
            "a cache hit must not replay the masks of the proof that filled the entry"
        );
    }

    /// M0: the cache's admission keeps the smallest subtrees. With one entry,
    /// a larger-rank circuit is proved uncached (the entry survives); an
    /// equal-rank one replaces it. Pure bookkeeping over toy leaves.
    #[test]
    fn m0_merge_cache_admission_keeps_small_subtrees() {
        let a1 = toy_interval_leaf(1, 0, 1, 100);
        let a2 = toy_interval_leaf(2, 1, 2, 200);
        let b1 = toy_interval_leaf(1, 0, 5, 300);
        let b2 = toy_interval_leaf(2, 5, 6, 400);
        let mut cache = MergeCache::new(1);
        let _ = cache.merge(&a1.0, &a2.0, 2);
        let _ = cache.merge(&b1.0, &b2.0, 4); // larger rank: not admitted
        assert!(cache.contains(&a1.0, &a2.0) && !cache.contains(&b1.0, &b2.0));
        let _ = cache.merge(&b1.0, &b2.0, 2); // equal rank: replaces the entry
        assert!(!cache.contains(&a1.0, &a2.0) && cache.contains(&b1.0, &b2.0));
        assert_eq!((cache.hits(), cache.misses(), cache.len()), (0, 3, 1));
    }
}
