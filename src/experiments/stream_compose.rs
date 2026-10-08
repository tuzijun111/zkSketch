//! **Multi-family streaming proof composition** (paper §Streaming Proof
//! Composition, generalised beyond Count-Min).
//!
//! Benchmarks the three composition modes — **per-batch proof chain**, the
//! **recursive linear chain**, and the **streaming forest** — over a stream of
//! `t = ⌈N/m⌉` transition leaves, for five sketch families each pinned to one
//! leaf variant:
//!
//! | family | variant           | leaf prover (exposed)          |
//! |--------|-------------------|--------------------------------|
//! | cm     | omc               | `prove_countmin_omc_exposed`   |
//! | hll    | omc               | `prove_hll_omc_exposed`        |
//! | ss     | certified         | `prove_ss_full_exposed`        |
//! | gk     | bandmerge2        | `prove_gkb2_exposed`           |
//! | bloom  | omc               | `build_bloom_omc_leaf_expose`  |
//!
//! (The first four are the measured families; the Bloom filter, a generality
//! instance of the timestamped OR rebind, runs through the same harness.)
//!
//! All five leaves surface their `(Com(S_{i-1}), Com(S_i))` boundary via the
//! Expose NPO, so the **family-agnostic** folds
//! ([`prove_forest_over`](crate::recursion::recursive::expose_forest::prove_forest_over)
//! Bentley–Saxe tree, [`prove_chain_over`](crate::recursion::recursive::expose_forest::prove_chain_over)
//! left-leaning linear) compose any of
//! them and bind `left.final == right.initial` in-circuit. The per-batch mode
//! folds nothing — it stores the `t` leaf proofs to a folder and the verifier
//! holds all of them.
//!
//! **Statement (B6(b)).** By default the leaves are built with the Interval
//! statement (`statement::composition_expose()`): leaf `t` also exposes
//! `(t, t)` and `H = Poseidon2(TAG_LEAF, t, Com(B_t))`, the merges enforce index
//! adjacency and fold the digests, and the auditor checks the root against
//! the public batch log (`Com(S_0)`, `Com(S_T)` and every `Com(B_t)`, computed
//! natively from the batches: `dist_compose::stream_batch_log`) under the
//! fold's bracketing. Where the auditor holds LEAF proofs directly (per_batch,
//! and the lone leaf of a one-batch stream) it pins each one to the leaf VK
//! derived from public parameters, STARK-verifies it, and checks its statement
//! against its log entry and the boundary chain; the reported verify time is
//! that audit. `ZKSKETCH_STATEMENT=boundary` (or `ZKSKETCH_BINDING=legacy`)
//! selects the pre-B6(b) Boundary layout for side-by-side runs, with a loud
//! warning that the batch log is then NOT checked.
//!
//! ## Mixed updates + queries (`query_at`)
//!
//! With a non-empty `query_at` schedule (1-based batch indices), a **query
//! leaf** (the family's `src/decode/*` circuit: cm point count, hll
//! cardinality, ss top-1 mass, gk rank, bloom membership) is proved after each listed batch
//! against the state at that point. Queries at ARBITRARY stream positions
//! (the paper's operation-stream model: a query OCCUPIES a position, so `n`
//! points carry `n − ⌊n/Q⌋` update records) are supported by building the
//! batch list with [`build_query_schedule_batches`]:
//! a query landing mid-batch seals the batch early and pads its tail with the
//! family's provable no-op records ([`PAD_KEY`]), so `Com(S_u)` becomes a real
//! batch-boundary commitment at the exact query position. The query circuit
//! re-hashes the state and exposes `(Com(S_{t'}), q, answer)`. The auditor
//! ([`QueryAudit`]) pins every query proof to the decode circuit's VK derived
//! from public parameters, then binds its `Com(S_{t'})` to the certified
//! history (Property 3) with the interval proofs live at `t'`: all `t'` leaves
//! (per_batch), the current fold `Π_[1,t']` (chain), or the `popcount(t')`
//! Bentley–Saxe peaks (forest; under the procs engine with `M` machines, the
//! earlier slices' roots plus the query slice's peaks). Each is pinned to the
//! VK of its bracketing and STARK-verified, their statements must tile
//! `[1, t']` against the batch log, and the last one's final commitment must
//! equal the query's — interior boundaries are hidden by the final root, so
//! mid-stream queries verify against the composition state at query time, not
//! the end-of-stream root. Query costs are reported separately (`query_*`
//! fields): `query_ctx_verifies` counts the certificate's proofs and
//! `query_bind_ms` the measured binding cost.
//!
//! ## Cores and machines
//!
//! Every mode honours a **cores** budget: the whole measurement runs inside a
//! `cores`-thread rayon pool, so each leaf/merge proof uses exactly that many
//! cores (the per-machine budget). The `per_batch` and `forest` modes
//! additionally honour a **machines** count `M`: leaves are independent, so `M`
//! machines prove them in parallel. Recursion proofs are `!Send`
//! (`Rc<CircuitProverData>`) and cannot be combined across threads, so we do NOT
//! fake a parallel fold; instead the parallel leaf-gen wall-clock is the
//! **work-partition makespan** — the `t` leaves are split into `M` contiguous
//! segments and `leafgen = max` over segments of the segment's real per-leaf
//! prove times (measured at the machine's core budget). The recursive fold then
//! runs sequentially on one machine (the `O(log t)` depth tail the paper's
//! `O(t/M + log t)` predicts), yielding one real `O(1)` root whose size and
//! verify time are reported. `chain` is inherently sequential (each fold needs
//! its predecessor), so it ignores `machines`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use rayon::ThreadPoolBuilder;

use crate::config::Val;
use crate::decode::bloom::{bloom_decode_vk, bloom_query_input, prove_bloom_query};
use crate::decode::countmin::{prove_cm_decode, CmDecodeParams};
use crate::decode::gk_bandmerge::{prove_gk2_decode, Gkb2DecodeParams};
use crate::decode::hyperloglog::{prove_hll_decode_omc, HllDecodeParams};
use crate::decode::spacesaving::{prove_ss_decode, SsDecodeParams};
use crate::decode::countmin::cm_decode_vk;
use crate::decode::gk_bandmerge::gk2_decode_vk;
use crate::decode::hyperloglog::hll_omc_decode_vk;
use crate::decode::spacesaving::ss_decode_vk;
use crate::decode::{
    check_query_statement, verify_decode_proof, DecodeProof, DecodeVk, QueryStatement,
    ReleasePolicy,
};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::config::D as EXT_D;
use crate::recursion::recursive::expose_forest::{
    ForestCascade, PrefixAuditor, check_leaves_against_log, check_root_against_log,
    prove_hiding_merge, read_exposed_statement, verify_bound_proof, verify_bound_proof_against_log,
    verify_bound_proof_self_pinned_legacy, verify_leaves_against_log,
};
use crate::recursion::recursive::root_vk::{
    exp_root_vk, warn_self_pinned_legacy, ExpRootVk, ForestShape, RootVk,
};
use crate::recursion::recursive::statement::{
    check_prefix_statements, composition_expose, hash_bb, warn_boundary_layout, BatchLog, Expose,
    Statement,
};
use crate::recursion::recursive::timing;
use crate::sketch::bind::{default_binding, Binding};
use p3_recursion::RecursionOutput;

use crate::sketch::bloom_omc::{
    bloom_empty, bloom_insert, build_bloom_omc_leaf_expose, commit_bloom, BloomOmcParams,
};
use crate::sketch::countmin::CountMinUpdate;
use crate::sketch::countmin_omc::{build_countmin_omc_leaf_expose, countmin_omc_advance, CmOmcParams};
use crate::sketch::gk_bandmerge::{
    apply_batch2, build_gkb2_leaf_expose, commit_gk2_state, Gk2State, GkbParams,
};
use crate::sketch::hll_omc::{
    build_hll_omc_leaf_expose, commit_hll_omc, hll_omc_advance, hll_omc_empty, HllOmcParams,
};
use crate::sketch::ss_final_full::{
    apply_batch_ss_full, build_ss_full_leaf_expose, commit_ss_state, SsFullParams, SsFullState,
    SsFullUpdate,
};

use super::families::cm_empty;
use super::metrics::{bench, read_vmrss_kb, BenchCfg, RunOutcome};
use super::proof_size;

use crate::commitment::countmin::commit_countmin;

/// The (family, variant) leaf types the composition benchmark folds: the four
/// measured families, their Goldilocks variants, and the Bloom filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamFamily {
    /// Count-Min, offline-memory-checking rebind (`prove_countmin_omc_exposed`).
    CmOmc,
    /// HyperLogLog, offline-memory-checking rebind (`prove_hll_omc_exposed`).
    HllOmc,
    /// SpaceSaving, certified full top-s leaf (`prove_ss_full_exposed`).
    SsCertified,
    /// Greenwald–Khanna, two-sided band-merge (`prove_gkb2_exposed`).
    GkBandmerge2,
    /// SpaceSaving certified leaf on the **Goldilocks** field (D=2, `ss_final_full_gl`).
    /// Parallel to [`Self::SsCertified`]; runs the Goldilocks recursion config.
    SsCertifiedGl,
    /// Greenwald–Khanna band-merge on the **Goldilocks** field (`gk_bandmerge_gl`).
    GkBandmerge2Gl,
    /// HyperLogLog omc leaf on the **Goldilocks** field (D=2, `hll_omc_gl`).
    /// Parallel to [`Self::HllOmc`]; runs the Goldilocks recursion config.
    /// NOTE: the Goldilocks routing hash differs from BabyBear's, so `hll_gl`
    /// register arrays are a distinct (statistically equivalent) HLL instance.
    HllOmcGl,
    /// Count-Min omc leaf on the **Goldilocks** field (D=2, `countmin_omc_gl`).
    /// Parallel to [`Self::CmOmc`]; same field caveat as [`Self::HllOmcGl`]
    /// (the Goldilocks PRF row hash is a distinct Count-Min instance).
    CmOmcGl,
    /// Partitioned Bloom filter, timestamped offline-memory-checking rebind of
    /// an OR update (`build_bloom_omc_leaf_expose`), `k` slices of
    /// `2^log_w` bits ([`StreamShape::bloom_k`] / [`StreamShape::bloom_log_w`]).
    /// BabyBear only: there is no Goldilocks Bloom leaf.
    BloomOmc,
}

impl StreamFamily {
    /// Parse a `family` token; the variant is fixed per family. The `_gl` tokens
    /// select the Goldilocks-field leaves (BabyBear stays the default for the
    /// non-suffixed tokens).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cm" | "cm_omc" | "countmin" => Some(Self::CmOmc),
            "hll" | "hll_omc" | "hyperloglog" => Some(Self::HllOmc),
            "ss" | "ss_certified" | "spacesaving" => Some(Self::SsCertified),
            "gk" | "gk_bandmerge2" | "bandmerge2" | "greenwald_khanna" => Some(Self::GkBandmerge2),
            "ss_gl" | "ss_certified_gl" | "spacesaving_gl" => Some(Self::SsCertifiedGl),
            "gk_gl" | "gk_bandmerge2_gl" | "bandmerge2_gl" => Some(Self::GkBandmerge2Gl),
            "hll_gl" | "hll_omc_gl" | "hyperloglog_gl" => Some(Self::HllOmcGl),
            "cm_gl" | "cm_omc_gl" | "countmin_gl" => Some(Self::CmOmcGl),
            "bloom" | "bloom_omc" | "bloomfilter" | "bloom_filter" => Some(Self::BloomOmc),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::CmOmc => "cm_omc",
            Self::HllOmc => "hll_omc",
            Self::SsCertified => "ss_certified",
            Self::GkBandmerge2 => "gk_bandmerge2",
            Self::SsCertifiedGl => "ss_certified_gl",
            Self::GkBandmerge2Gl => "gk_bandmerge2_gl",
            Self::HllOmcGl => "hll_omc_gl",
            Self::CmOmcGl => "cm_omc_gl",
            Self::BloomOmc => "bloom_omc",
        }
    }
    pub fn family(self) -> &'static str {
        match self {
            Self::CmOmc => "cm",
            Self::HllOmc => "hll",
            Self::SsCertified => "ss",
            Self::GkBandmerge2 => "gk",
            // Distinct family labels so the CSV self-identifies the Goldilocks rows
            // (there is no per-run `field` column; downstream plots split on this).
            Self::SsCertifiedGl => "ss_gl",
            Self::GkBandmerge2Gl => "gk_gl",
            Self::HllOmcGl => "hll_gl",
            Self::CmOmcGl => "cm_gl",
            Self::BloomOmc => "bloom",
        }
    }
    /// The base field of this family's recursion config.
    pub fn field(self) -> &'static str {
        match self {
            Self::SsCertifiedGl | Self::GkBandmerge2Gl | Self::HllOmcGl | Self::CmOmcGl => {
                "Goldilocks"
            }
            _ => "BabyBear",
        }
    }
    /// Whether this family runs the Goldilocks (`_gl`) recursion path.
    pub fn is_gl(self) -> bool {
        matches!(
            self,
            Self::SsCertifiedGl | Self::GkBandmerge2Gl | Self::HllOmcGl | Self::CmOmcGl
        )
    }
    /// The underlying (field-agnostic) sketch family, for sharing plaintext
    /// state/record-mapping machinery between the BabyBear and Goldilocks paths.
    pub fn base_family(self) -> Self {
        match self {
            Self::SsCertifiedGl => Self::SsCertified,
            Self::GkBandmerge2Gl => Self::GkBandmerge2,
            Self::HllOmcGl => Self::HllOmc,
            Self::CmOmcGl => Self::CmOmc,
            other => other,
        }
    }
}

/// The three composition modes of §Streaming Proof Composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMode {
    /// One independent proof per batch, NO fold; proofs stored to a folder.
    PerBatch,
    /// Recursive linear chain `Π^(t) = merge(Π^(t-1), π_t)` (`O(t)` depth).
    Chain,
    /// Streaming forest — Bentley–Saxe tree fold (`O(log t)` depth).
    Forest,
}

impl StreamMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "per_batch" | "perbatch" | "per-batch" | "flat" => Some(Self::PerBatch),
            "chain" | "linear" => Some(Self::Chain),
            // `recursive` accepted as a back-compat alias for the renamed forest.
            "forest" | "recursive" | "tree" => Some(Self::Forest),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::PerBatch => "per_batch",
            Self::Chain => "chain",
            Self::Forest => "forest",
        }
    }
}

/// Sketch shape — only the fields relevant to the chosen family are used.
#[derive(Clone, Copy, Debug)]
pub struct StreamShape {
    /// Count-Min depth.
    pub d: usize,
    /// Count-Min width.
    pub w: usize,
    /// HLL register-index bits (`m = 2^b` registers).
    pub b: usize,
    /// SS / GK summary capacity `s'`.
    pub capacity: usize,
    /// GK accuracy parameter `s = 1/ε`.
    pub gk_s: u64,
    /// Bloom filter: number of slices = hash positions per key (`1..=8`).
    pub bloom_k: usize,
    /// Bloom filter: bits per slice `W = 2^bloom_log_w` (`7..=20`).
    pub bloom_log_w: usize,
}

impl StreamShape {
    /// The Bloom leaf / query parameters at batch size `m`. Panics on a bad
    /// `(k, log_w)`; a runner that takes the shape from configuration calls
    /// [`Self::check_bloom`] first so the reason is reported, not swallowed by
    /// its panic guard.
    pub fn bloom_params(&self, m: usize) -> BloomOmcParams {
        self.check_bloom(m).unwrap_or_else(|e| panic!("{e}"))
    }

    /// [`Self::bloom_params`] without the panic: the parameters, or why
    /// `(bloom_k, bloom_log_w, m)` is not a valid Bloom leaf shape.
    pub fn check_bloom(&self, m: usize) -> Result<BloomOmcParams, String> {
        let p = BloomOmcParams { k: self.bloom_k, log_w: self.bloom_log_w, batch: m };
        p.check()?;
        Ok(p)
    }
}

/// One measured composition cell.
#[derive(Clone, Debug)]
pub struct ComposeCell {
    /// Whole-stream prove time = `leafgen + merge` (leafgen = parallel makespan).
    pub total_time_ms: f64,
    /// Parallel leaf-gen: the `M`-machine work-partition makespan (= sequential
    /// sum when `machines = 1`).
    pub leafgen_ms: f64,
    /// Sequential leaf-gen (Σ per-leaf), for reference / speedup denominator.
    pub leafgen_seq_ms: f64,
    /// Recursive fold time (0 for per_batch).
    pub merge_ms: f64,
    /// Verifier cost: Σ leaf verifies + links (per_batch), or the single root
    /// verify (chain/forest).
    pub verify_ms: f64,
    /// Verifier-facing artifact bytes: Σ leaf proofs (per_batch, `Θ(t)`) or the
    /// single root proof (chain/forest, `O(1)`).
    pub proof_bytes: u64,
    pub peak_rss_mb: f64,
    /// Mixed workload: number of interleaved query events (0 = updates only).
    pub n_queries: usize,
    /// Σ query-leaf prove time over all query events.
    pub query_prove_ms: f64,
    /// Σ query-leaf self-verify time over all query events.
    pub query_verify_ms: f64,
    /// Σ query-leaf proof bytes over all query events.
    pub query_proof_bytes: u64,
    /// Σ over query events of the number of COMPOSITION proofs the verifier must
    /// check at query time to trust the bound state commitment `Com(S_{t'})`:
    /// `t'` leaf proofs (per_batch), the 1 current fold (chain), or the
    /// `popcount(t')` Bentley–Saxe peaks (forest). With the prefix binding on
    /// (the default) this is the number of proofs the auditor actually
    /// verified for each answer ([`QueryAudit`]); under the legacy opt-ins it
    /// is the structural count.
    pub query_ctx_verifies: u64,
    /// Σ over query events of the measured cost of binding the answer's
    /// `Com(S_{t'})` to the certified history: pinned STARK verification of
    /// every proof in its prefix certificate plus the statement checks
    /// against the log ([`QueryAudit::bind`]). `None` when the binding is off
    /// (legacy opt-ins), so the answers are NOT tied to the certified history.
    pub query_bind_ms: Option<f64>,
}

/// A boundary-exposing leaf proof plus the Send metrics we keep off-thread.
struct LeafArt {
    output: RecursionOutput<ConfigWithFriParams>,
    initial: [Val; 8],
    final_: [Val; 8],
    prove_ms: f64,
    verify_ms: f64,
}

/// One interleaved query event's Send metrics (the query proof itself is
/// dropped — only its cost, size and verified statement are kept).
pub(crate) struct QueryArt {
    /// Number of leaves covered when the query fired (`t'`, 1-based).
    pub(crate) at_leaf: usize,
    prove_ms: f64,
    /// The auditor's pinned verification of the query proof
    /// ([`verify_decode_proof`]); the prover's self-verify under the legacy
    /// opt-ins.
    verify_ms: f64,
    proof_bytes: u64,
    /// The `(Com(S), q, answer)` the pinned verifier read off the query proof
    /// (`None` under the legacy opt-ins).
    statement: Option<QueryStatement>,
    /// Set once [`QueryAudit::bind`] has certified `statement.commit` as
    /// `Com(S_{t'})`.
    bind: Option<QueryBind>,
}

/// The outcome of binding one answer to the certified history.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryBind {
    /// Interval proofs in the answer's prefix certificate.
    pub(crate) ctx_proofs: u64,
    /// Stateless verifier cost: Σ pinned verify time of those proofs + the
    /// statement checks against the log.
    pub(crate) ms: f64,
}

/// Where one part of a prefix certificate lives: an in-memory proof (the
/// single-process engine) or the serialized bytes a worker shipped (procs).
pub(crate) enum CtxProof<'a> {
    Proof(&'a p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>),
    Bytes(&'a [u8]),
}

/// One part of a prefix certificate: the interval `[lo, hi]` it covers, the
/// bracketing it was folded under, and the proof.
pub(crate) type CtxPart<'a> = (u64, u64, ForestShape, CtxProof<'a>);

/// The verifier side of the mixed workload (Property 3): the trusted VK of
/// the family's query circuit and a [`PrefixAuditor`] (trusted VKs per
/// bracketing), all derived from public parameters. Every query proof is
/// pinned to the decode VK ([`record_query`]), and its exposed `Com(S)` must
/// equal the `Com(S_{t'})` certified by the interval proofs live at its
/// version ([`Self::bind`]): the forest's peaks, the chain's current fold, or
/// the per-batch leaves.
///
/// Each distinct interval proof is verified once and its time memoised: a
/// stateless verifier answering one query pays the sum over that query's
/// certificate, which is what [`QueryBind::ms`] reports, without the harness
/// re-verifying a peak that several queries share.
pub(crate) struct QueryAudit {
    pub(crate) decode_vk: DecodeVk,
    prefix: PrefixAuditor,
    memo: HashMap<(u64, u64, ForestShape), (f64, Statement<Val>)>,
}

impl QueryAudit {
    /// The family's auditor, or `None` under the legacy opt-ins that cannot
    /// bind an answer (`ZKSKETCH_BINDING=legacy`: the decoders expose
    /// nothing; `ZKSKETCH_STATEMENT=boundary`: no interval to tile;
    /// `EXP_ROOT_VK=self`: no trusted VKs), with a loud warning.
    pub(crate) fn new(family: StreamFamily, shape: &StreamShape, m: usize) -> Option<Self> {
        let why = if default_binding() == Binding::Legacy {
            Some("ZKSKETCH_BINDING=legacy (the decoders expose no statement)")
        } else if composition_expose() != Expose::Interval {
            Some("ZKSKETCH_STATEMENT=boundary (no interval statement to tile [1, t'])")
        } else if exp_root_vk() == ExpRootVk::SelfPinnedLegacy {
            Some("EXP_ROOT_VK=self (no VK derived from public parameters)")
        } else if family.is_gl() {
            Some("a Goldilocks family (no query path)")
        } else {
            None
        };
        if let Some(why) = why {
            eprintln!(
                "\n!!! WARNING: query answers are NOT bound to the certified history under {why}:\n\
                 !!!   no prefix certificate is verified; query_bind_ms is reported as 'unbound'.\n"
            );
            return None;
        }
        let decode_vk = match family {
            StreamFamily::CmOmc => cm_decode_vk(
                CmDecodeParams { d: shape.d, w: shape.w, release: ReleasePolicy::Identity },
                default_binding(),
            ),
            StreamFamily::HllOmc => hll_omc_decode_vk(
                HllDecodeParams { b: shape.b, release: ReleasePolicy::Identity },
                default_binding(),
            ),
            StreamFamily::SsCertified => ss_decode_vk(
                SsDecodeParams { capacity: shape.capacity, c: 1, release: ReleasePolicy::Identity },
                default_binding(),
            ),
            StreamFamily::GkBandmerge2 => gk2_decode_vk(
                Gkb2DecodeParams { capacity: shape.capacity, release: ReleasePolicy::Identity },
                default_binding(),
            ),
            // The membership circuit has one (bound) construction; it does
            // not depend on the binding, nor on the batch size.
            StreamFamily::BloomOmc => bloom_decode_vk(shape.bloom_params(m)),
            _ => unreachable!("Goldilocks families are rejected above"),
        };
        let noop = super::dist_compose::prove_noop_leaf(family, shape, m);
        Some(Self { decode_vk, prefix: PrefixAuditor::new(noop), memo: HashMap::new() })
    }

    /// Bind query `q` (its version `q.at_leaf`) to the certified history with
    /// the prefix certificate `parts`: verify each part under the trusted VK
    /// of its bracketing (memoised; the one-time VK derivation is outside the
    /// timing), check that the statements tile `[1, t']` against `log`, and
    /// require the query proof's exposed `Com(S)` to equal the certified
    /// `Com(S_{t'})`. Fails closed.
    pub(crate) fn bind(
        &mut self,
        q: &mut QueryArt,
        parts: &[CtxPart<'_>],
        log: &BatchLog<Val>,
    ) -> Result<(), String> {
        let stmt = q.statement.ok_or("the query proof exposes no statement")?;
        let mut ms = 0.0f64;
        let mut stmts: Vec<Statement<Val>> = Vec::with_capacity(parts.len());
        for (k, (lo, hi, shape, src)) in parts.iter().enumerate() {
            let key = (*lo, *hi, shape.clone());
            if !self.memo.contains_key(&key) {
                self.prefix.vk(shape);
                let t0 = std::time::Instant::now();
                let owned: p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>;
                let proof = match src {
                    CtxProof::Proof(p) => *p,
                    CtxProof::Bytes(b) => {
                        owned = postcard::from_bytes(b)
                            .map_err(|e| format!("part {} [{lo}, {hi}]: decode: {e}", k + 1))?;
                        &owned
                    }
                };
                let st = self
                    .prefix
                    .verify_interval(proof, shape)
                    .map_err(|e| format!("part {} [{lo}, {hi}]: {e}", k + 1))?;
                self.memo.insert(key.clone(), (t0.elapsed().as_secs_f64() * 1000.0, st));
            }
            let (part_ms, st) = &self.memo[&key];
            ms += part_ms;
            stmts.push(st.clone());
        }
        let t0 = std::time::Instant::now();
        let refs: Vec<(&Statement<Val>, &ForestShape)> =
            stmts.iter().zip(parts.iter().map(|(_, _, sh, _)| sh)).collect();
        let certified = check_prefix_statements(&refs, log, q.at_leaf, &hash_bb, EXT_D)?;
        if certified != stmt.commit.to_vec() {
            return Err(format!(
                "the query proof's Com(S) is not the certified Com(S_{}) of the history",
                q.at_leaf
            ));
        }
        ms += t0.elapsed().as_secs_f64() * 1000.0;
        q.bind = Some(QueryBind { ctx_proofs: parts.len() as u64, ms });
        Ok(())
    }
}

/// Bind every query whose version is `g` (in the single-process engine's
/// folds, right after leaf `g`): `parts` builds `g`'s prefix certificate,
/// only when some query is due. Returns the wall time spent, which the caller
/// keeps out of its fold timing. No-op without an auditor.
fn bind_due<'a>(
    audit: &mut Option<QueryAudit>,
    arts: &mut [QueryArt],
    g: usize,
    parts: impl FnOnce() -> Vec<CtxPart<'a>>,
    log: &BatchLog<Val>,
) -> f64 {
    let Some(audit) = audit.as_mut() else { return 0.0 };
    if !arts.iter().any(|q| q.at_leaf == g) {
        return 0.0;
    }
    let t0 = std::time::Instant::now();
    let parts = parts();
    for q in arts.iter_mut().filter(|q| q.at_leaf == g) {
        audit
            .bind(q, &parts, log)
            .unwrap_or_else(|e| panic!("query at t'={g} not bound to the certified history: {e}"));
    }
    t0.elapsed().as_secs_f64() * 1000.0
}

/// The procs engine's prefix certificates, assembled by the coordinator from
/// what the workers shipped: per query version `g`, the parts `(lo, hi,
/// bracketing)` in order, and each distinct part's serialized proof.
#[derive(Default)]
pub(crate) struct ContextStore {
    pub(crate) parts: BTreeMap<usize, Vec<(u64, u64, ForestShape)>>,
    bytes: HashMap<(u64, u64, ForestShape), Vec<u8>>,
}

impl ContextStore {
    /// Store the proof of one interval (a worker ships each peak once).
    /// Rejects a second, different proof for the same interval.
    pub(crate) fn insert(
        &mut self,
        key: (u64, u64, ForestShape),
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        match self.bytes.get(&key) {
            Some(old) if *old != bytes => {
                Err(format!("two different proofs shipped for interval [{}, {}]", key.0, key.1))
            }
            Some(_) => Ok(()),
            None => {
                self.bytes.insert(key, bytes);
                Ok(())
            }
        }
    }

    pub(crate) fn has(&self, key: &(u64, u64, ForestShape)) -> bool {
        self.bytes.contains_key(key)
    }

    /// Bind every query in `arts` with its stored certificate.
    pub(crate) fn bind_all(
        &self,
        audit: &mut QueryAudit,
        arts: &mut [QueryArt],
        log: &BatchLog<Val>,
    ) -> Result<(), String> {
        for q in arts.iter_mut() {
            let list = self
                .parts
                .get(&q.at_leaf)
                .ok_or_else(|| format!("no prefix certificate shipped for t'={}", q.at_leaf))?;
            let parts: Vec<CtxPart<'_>> = list
                .iter()
                .map(|(lo, hi, sh)| {
                    let b = self
                        .bytes
                        .get(&(*lo, *hi, sh.clone()))
                        .ok_or_else(|| format!("interval [{lo}, {hi}] was never shipped"))?;
                    Ok((*lo, *hi, sh.clone(), CtxProof::Bytes(b.as_slice())))
                })
                .collect::<Result<_, String>>()?;
            audit
                .bind(q, &parts, log)
                .map_err(|e| format!("query at t'={}: {e}", q.at_leaf))?;
        }
        Ok(())
    }
}

/// Record one query event: take the decode prover's timings, check the
/// prover-side consistency (the state the query circuit hashed must be
/// exactly the leaf-boundary commitment at `t'`), and, with a trusted
/// `decode_vk`, have the auditor verify the query proof pinned to it and
/// check the exposed query and answer ([`verify_decode_proof`], timed as the
/// query verify); the exposed `Com(S)` is kept for [`QueryAudit::bind`],
/// which ties it to the certified history. `leaf_final` is a PROVER-side
/// value, never what binds the answer. Without a VK (legacy opt-ins) the
/// exposure is checked against the native replay only and the prover's
/// self-verify time is reported.
/// `query` is the keyed families' query as the decoder exposes it
/// ([`cm_query`] for a cm key, [`scalar_query`] for ss `c` / gk value);
/// `None` for hll (cardinality, no query).
fn record_query(
    queries: &mut Vec<QueryArt>,
    at_leaf: usize,
    dp: &DecodeProof,
    native_commit: [Val; 8],
    leaf_final: [Val; 8],
    query: Option<[Val; 4]>,
    decode_vk: Option<&DecodeVk>,
) {
    let tm = timing::take();
    assert_eq!(
        native_commit, leaf_final,
        "query state commitment must equal the leaf boundary at t'={at_leaf}"
    );
    let (verify_ms, statement) = match decode_vk {
        Some(vk) => {
            let t0 = std::time::Instant::now();
            let st = verify_decode_proof(&dp.output.0, vk)
                .unwrap_or_else(|e| panic!("query proof at t'={at_leaf}: {e}"));
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            use p3_field::PrimeCharacteristicRing;
            let want_q = query.unwrap_or([Val::ZERO; 4]);
            assert_eq!(st.query, want_q, "query proof at t'={at_leaf}: exposed query");
            let want = QueryStatement::with_query(st.commit, want_q, dp.answer);
            assert_eq!(st.answer, want.answer, "query proof at t'={at_leaf}: exposed answer");
            (ms, Some(st))
        }
        None => {
            check_query_exposure(dp, leaf_final, query, at_leaf);
            (tm.verify.as_secs_f64() * 1000.0, None)
        }
    };
    queries.push(QueryArt {
        at_leaf,
        prove_ms: (tm.witness + tm.prove).as_secs_f64() * 1000.0,
        verify_ms,
        proof_bytes: dp.proof_size() as u64,
        statement,
        bind: None,
    });
}

/// Property 3 at the harness level: the query proof must EXPOSE the
/// leaf-boundary commitment at `t'`, the query that was asked and the answer
/// it reports (`(Com(S), q, answer)`, 16 values; hll `(Com(S), answer)`, 12),
/// so a verifier reading only the proof learns what was certified. Fails
/// closed. Skipped under `ZKSKETCH_BINDING=legacy`, whose pre-fix decoders
/// expose nothing (the Legacy warning is printed when it is selected).
fn check_query_exposure(dp: &DecodeProof, commit: [Val; 8], query: Option<[Val; 4]>, at_leaf: usize) {
    if default_binding() == Binding::Legacy {
        return;
    }
    match query {
        Some(q) => check_query_statement(&dp.output.0, &QueryStatement::with_query(commit, q, dp.answer))
            .unwrap_or_else(|e| panic!("query proof at t'={at_leaf}: {e}")),
        None => {
            let pv = dp
                .output
                .0
                .non_primitives
                .iter()
                .map(|e| &e.public_values)
                .find(|v| v.len() == 12)
                .unwrap_or_else(|| panic!("hll query proof at t'={at_leaf} exposes no (Com(S), answer)"));
            assert_eq!(&pv[..8], &commit[..], "hll query proof at t'={at_leaf}: exposed Com(S)");
            use p3_field::PrimeCharacteristicRing;
            assert_eq!(pv[8], Val::from_u64(dp.answer), "hll query proof at t'={at_leaf}: exposed answer");
            assert!(pv[9..].iter().all(|v| *v == Val::ZERO), "hll answer must be a base element");
        }
    }
}

/// The exposed query of a scalar-query decoder (ss `c`, gk value): `(q, 0, 0, 0)`.
fn scalar_query(q: u64) -> [Val; 4] {
    use p3_field::PrimeCharacteristicRing;
    QueryStatement::new([Val::ZERO; 8], q, 0).query
}

/// The exposed query of the Count-Min decoder for `key` under the process
/// default binding: the exact 16-bit limbs (`Semantic`/`Bound`), or
/// `(key mod p, 0, 0, 0)` (`Legacy`).
fn cm_query(key: u64) -> [Val; 4] {
    crate::sketch::countmin_final::key_hash_input(key, default_binding())
}

/// The exposed query of the Bloom membership decoder for `key`: the active
/// record `[k0, k1, k2, k3 + 2^16]` (exact 16-bit limbs plus the `act` bit;
/// the decoder has no Legacy variant).
fn bloom_query(key: u64) -> [Val; 4] {
    bloom_query_input(key)
}

/// How the probe key for a **keyed** decode query is chosen at each query event.
/// Only the keyed families use it — cm (point-count), gk (rank) and bloom
/// (membership); hll (cardinality) and ss (top-1) take no probe key and ignore
/// the mode.
///
/// `First` is the baseline (the batch's first key, matching the original
/// behaviour); the others sample against the multiset of keys seen so far,
/// mirroring the discipline S³'s harness uses (query targets drawn from the
/// observed stream rather than an arbitrary constant). All modes are
/// deterministic in the query index, so a run is reproducible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QueryKeyMode {
    /// The batch's first key — the original, degenerate baseline. Keep for
    /// side-by-side comparison.
    First,
    /// A key sampled from the keys seen so far, weighted by occurrence (S³'s
    /// `selectRandomIndices` behaviour: guaranteed present, frequency-weighted).
    UniformStream,
    /// The most-frequent key seen so far (ties → smallest key). Stresses the
    /// heavy-hitter path (a meaningful point/rank target for cm/gk).
    Hot,
    /// A deterministic in-domain key NOT in the stream — a point query on a true
    /// zero (cm) / the rank of an unseen value (gk); exercises the soundness of
    /// answering for absent keys.
    Absent,
}

impl QueryKeyMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "first" | "" => Some(Self::First),
            "uniform_stream" | "uniform" | "stream" => Some(Self::UniformStream),
            "hot" => Some(Self::Hot),
            "absent" | "cold" | "zero" => Some(Self::Absent),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::First => "first",
            Self::UniformStream => "uniform_stream",
            Self::Hot => "hot",
            Self::Absent => "absent",
        }
    }
}

/// splitmix64 — a tiny deterministic PRNG (no `rand` dependency, and stable
/// across runs so every query-key mode is reproducible).
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Pick the probe key for a keyed decode query under `mode`. `freq` is the
/// multiset of keys/values seen through the current batch (inclusive); `first`
/// is the batch's first key (the `First` baseline and the empty-`freq`
/// fallback); `seed` (the query index `t'`) varies the sampler per query yet
/// keeps it reproducible; `domain_mask` bounds the `Absent` candidate to the
/// family's key/value domain (cm keys 32-bit, gk values 21-bit).
fn select_query_key(
    mode: QueryKeyMode,
    freq: &BTreeMap<u64, u64>,
    first: u64,
    seed: u64,
    domain_mask: u64,
) -> u64 {
    match mode {
        QueryKeyMode::First => first,
        QueryKeyMode::Hot => freq
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, _)| *k)
            .unwrap_or(first),
        QueryKeyMode::UniformStream => {
            let total: u64 = freq.values().sum();
            if total == 0 {
                return first;
            }
            let mut r = splitmix64(seed) % total;
            for (k, c) in freq {
                if r < *c {
                    return *k;
                }
                r -= *c;
            }
            first
        }
        QueryKeyMode::Absent => {
            let mut cand = splitmix64(seed ^ 0xD1B5_4A32_D192_ED03) & domain_mask;
            for _ in 0..128 {
                if !freq.contains_key(&cand) {
                    return cand;
                }
                cand = splitmix64(cand) & domain_mask;
            }
            cand
        }
    }
}

/// Pad sentinel for **split batches** (mid-batch queries). A query may land at
/// any update position `u`; the harness seals the current batch early and pads
/// the tail to the fixed batch size `m` with provable NO-OP records, so the
/// circuit shape stays uniform and `Com(S_u)` becomes a real batch-boundary
/// commitment the query can bind. Pad slots carry this sentinel in the wire
/// batches; real keys equal to it are remapped to `PAD_KEY - 1` at batch build
/// (a 2^-32 distortion, disclosed). HLL never carries the sentinel — its pads
/// repeat a real key of the same batch (the `max` update is idempotent).
pub const PAD_KEY: u32 = u32::MAX;

// ─── The canonical per-family record mappings ────────────────────────────
// Shared by the sim engine, the procs witness pass + workers, and the query
// replay — a divergence would break the in-circuit boundary bind. Each maps a
// `PAD_KEY` slot to that family's provable no-op:
//   cm  → `value = 0` update (`new = old + 0`; value is a committed input)
//   ss  → the circuit-native `SsFullUpdate::dummy()` (key-0 sentinel lane)
//   gk  → stripped (a short batch: `fresh_tuples` pads with `E_MAX` dummies
//         natively and `n` advances by the real count only)
//   hll → no sentinel (pads are repeated real keys; `max` is idempotent)
//   bloom → stripped (a short batch: the leaf fills its free record slots
//           with the canonical `act = 0` dummy, which ORs in nothing)

pub fn cm_updates_of(batch: &[u32]) -> Vec<CountMinUpdate> {
    batch
        .iter()
        .map(|&k| {
            if k == PAD_KEY {
                CountMinUpdate { key: 0, value: 0 }
            } else {
                CountMinUpdate { key: k as u64, value: 1 }
            }
        })
        .collect()
}

pub fn ss_updates_of(batch: &[u32]) -> Vec<SsFullUpdate> {
    batch
        .iter()
        .map(|&k| {
            if k == PAD_KEY {
                SsFullUpdate::dummy()
            } else {
                // SS binds keys to `[0, 2^29)` (union-sort diff range-check);
                // low bit forced 1 so no real key collides with the 0 dummy.
                SsFullUpdate::real(((k & 0x1FFF_FFFF) | 1) as u64, 1)
            }
        })
        .collect()
}

pub fn gk_vals_of(batch: &[u32]) -> Vec<u32> {
    // GK is over values masked to 21 bits (< E_MAX). PAD_KEY slots are
    // stripped: `prove_gkb2` accepts short batches (`len <= m`) and pads the
    // fresh-tuple rows with `(E_MAX,0,0,0)` dummies itself.
    batch.iter().filter(|&&k| k != PAD_KEY).map(|&k| k & 0x001F_FFFF).collect()
}

pub fn hll_keys_of(batch: &[u32]) -> Vec<u64> {
    batch.iter().map(|&k| k as u64).collect()
}

/// Bloom records of a wire batch: the real keys, in order. `PAD_KEY` slots
/// are stripped, so the leaf (and the batch commitment,
/// [`crate::sketch::bloom_omc::bloom_batch_commit`]) fills them with the
/// canonical dummy record (`act = 0`, all-zero limbs), a provable no-op.
pub fn bloom_keys_of(batch: &[u32]) -> Vec<u64> {
    batch.iter().filter(|&&k| k != PAD_KEY).map(|&k| k as u64).collect()
}

/// Build the batch list for a **mixed workload over an operation stream**:
/// the stream is `n` OPERATIONS (the paper's streaming model), and a query
/// OCCUPIES a stream position — with `query_every = Q`, every `Q`-th position
/// (`Q, 2Q, …`) is a query and all other positions are updates, so `n` stream
/// points carry `n − ⌊n/Q⌋` update records (e.g. 100 points with `Q = 10` ⇒
/// 10 queries + 90 updates). Queries consume no data record; updates draw the
/// next key from `base`.
///
/// Updates are cut into batches of exactly `m`; a query landing mid-batch
/// seals the batch EARLY, padding its tail with the family's no-op records, so
/// the query binds a real batch-boundary commitment at its exact stream
/// position (the query grid is not restricted to multiples of `m`). The stream
/// tail (if it ends mid-batch) is pad-sealed too (no phantom records).
///
/// Returns `(batches, query_at, pad_records, split_leaves)`: `query_at` holds
/// the 1-based leaf indices whose final boundary each query binds,
/// `pad_records` counts total pad slots, and `split_leaves` counts the padded
/// (early-sealed or tail) batches — the honest "query at any point" premium.
pub fn build_query_schedule_batches(
    base: &[u32],
    n: usize,
    m: usize,
    query_every: usize,
    family: StreamFamily,
) -> (Vec<Vec<u32>>, Vec<usize>, usize, usize) {
    assert!(n >= 1 && m >= 1 && !base.is_empty(), "need records, a batch size and keys");
    let q = query_every;
    // Q = 1 would make EVERY position a query (zero updates) — meaningless.
    assert!(q != 1, "query_every = 1 leaves no update positions in the operation stream");
    let mut batches: Vec<Vec<u32>> = Vec::new();
    let mut query_at: Vec<usize> = Vec::new();
    let mut pad_records = 0usize;
    let mut split_leaves = 0usize;
    let mut cur: Vec<u32> = Vec::with_capacity(m);
    let mut next_key = 0usize;
    let mut seal = |cur: &mut Vec<u32>,
                    batches: &mut Vec<Vec<u32>>,
                    pad_records: &mut usize,
                    split_leaves: &mut usize| {
        if cur.is_empty() {
            return;
        }
        let pads = m - cur.len();
        if pads > 0 {
            // HLL pads repeat the batch's first (real) key — `max` idempotence
            // makes a repeat a provable no-op; the others carry the sentinel.
            let pad_val =
                if family.base_family() == StreamFamily::HllOmc { cur[0] } else { PAD_KEY };
            cur.resize(m, pad_val);
            *pad_records += pads;
            *split_leaves += 1;
        }
        batches.push(std::mem::take(cur));
    };
    for p in 1..=n {
        if q > 0 && p % q == 0 {
            // This stream position IS the query (it consumes the position, not
            // a record). Seal what accumulated (with Q ≥ 2 there is at least
            // one update since the last query, so `cur` is only empty right
            // after a natural batch boundary — then the query binds that
            // boundary directly, no split needed).
            seal(&mut cur, &mut batches, &mut pad_records, &mut split_leaves);
            query_at.push(batches.len());
        } else {
            // Update position: draw the next record. Real keys never carry the
            // pad sentinel (2^-32 remap, disclosed).
            let mut k = base[next_key % base.len()];
            next_key += 1;
            if k == PAD_KEY {
                k = PAD_KEY - 1;
            }
            cur.push(k);
            if cur.len() == m {
                seal(&mut cur, &mut batches, &mut pad_records, &mut split_leaves);
            }
        }
    }
    // Stream tail: pad-seal the remainder (no query, no phantom records).
    seal(&mut cur, &mut batches, &mut pad_records, &mut split_leaves);
    (batches, query_at, pad_records, split_leaves)
}

/// Aggregated mixed-workload query metrics for one cell (shared by both the sim
/// engine and the procs engine so the two report identical semantics).
#[derive(Clone, Copy, Debug, Default)]
pub struct QueryAgg {
    pub n_queries: usize,
    pub query_prove_ms: f64,
    pub query_verify_ms: f64,
    pub query_proof_bytes: u64,
    /// Σ over query events of the COMPOSITION proofs a verifier checks at query
    /// time to trust `Com(S_{t'})`: `t'` (per_batch), `1` (chain), `popcount(t')`
    /// Bentley–Saxe peaks (forest).
    pub query_ctx_verifies: u64,
    /// Σ measured binding cost ([`QueryBind::ms`]); `None` when unbound.
    pub query_bind_ms: Option<f64>,
}

/// Fold the raw per-event query artifacts into the reported metrics. Bound
/// queries report the certificate sizes the auditor verified; unbound ones
/// (legacy opt-ins) the structural per-mode count.
pub(crate) fn aggregate_queries(query_arts: &[QueryArt], mode: StreamMode) -> QueryAgg {
    let bound = query_arts.iter().filter(|q| q.bind.is_some()).count();
    assert!(
        bound == 0 || bound == query_arts.len(),
        "{bound} of {} queries bound: the binding must cover every query or none",
        query_arts.len()
    );
    let bound = bound > 0;
    QueryAgg {
        n_queries: query_arts.len(),
        query_prove_ms: query_arts.iter().map(|q| q.prove_ms).sum(),
        query_verify_ms: query_arts.iter().map(|q| q.verify_ms).sum(),
        query_proof_bytes: query_arts.iter().map(|q| q.proof_bytes).sum(),
        query_ctx_verifies: query_arts
            .iter()
            .map(|q| match (q.bind, mode) {
                (Some(b), _) => b.ctx_proofs,
                (None, StreamMode::PerBatch) => q.at_leaf as u64,
                (None, StreamMode::Chain) => 1u64,
                (None, StreamMode::Forest) => q.at_leaf.count_ones() as u64,
            })
            .sum(),
        query_bind_ms: bound.then(|| query_arts.iter().filter_map(|q| q.bind).map(|b| b.ms).sum()),
    }
}

/// Prove ONLY the interleaved query leaves via a plaintext replay — no update
/// leaf is proved here. Used by the **procs** engine, where the workers prove
/// the update leaves distributedly; this recomputes the plaintext state (the
/// same deterministic advance the coordinator's witness pass runs) and proves
/// one decode query after each `query_at`-listed batch. Mirrors `prove_leaves`'
/// query logic exactly (same `query_key_mode` probes, same per-family circuits).
///
/// The replay is the PROVER's: it needs the state to answer. The answer is
/// tied to the update proofs by the auditor, not by this replay: each query
/// proof is pinned to `decode_vk` ([`record_query`]) and its exposed `Com(S)`
/// is later bound by [`ContextStore::bind_all`] to the `Com(S_{t'})` that the
/// interval proofs the workers shipped certify ([`QueryAudit::bind`]).
fn prove_queries_only(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
    decode_vk: Option<&DecodeVk>,
) -> Vec<QueryArt> {
    let mut queries: Vec<QueryArt> = Vec::new();
    if query_at.is_empty() {
        return queries;
    }
    // Discard any timing accumulated before the first query so it times cleanly.
    let _ = timing::take();
    let qset: BTreeSet<usize> = query_at.iter().copied().collect();
    let query_due = |bi: usize| qset.contains(&(bi + 1));
    let track_freq = query_key_mode != QueryKeyMode::First;

    match family {
        StreamFamily::CmOmc => {
            let StreamShape { d, w, .. } = shape;
            let mut state = cm_empty(d, w);
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                // The omc leaf's native update (default binding), which the
                // default-binding decoder below also routes by.
                countmin_omc_advance(&mut state, &cm_updates_of(batch));
                if track_freq {
                    for &k in batch {
                        if k != PAD_KEY {
                            *freq.entry(k as u64).or_insert(0) += 1;
                        }
                    }
                }
                if query_due(bi) {
                    let key =
                        select_query_key(query_key_mode, &freq, batch[0] as u64, (bi + 1) as u64, 0xFFFF_FFFF);
                    let dp = prove_cm_decode(
                        CmDecodeParams { d, w, release: ReleasePolicy::Identity },
                        state.clone(),
                        key,
                    );
                    let commit = commit_countmin(&state).0;
                    record_query(&mut queries, bi + 1, &dp, commit, commit, Some(cm_query(key)), decode_vk);
                }
            }
        }
        StreamFamily::HllOmc => {
            let StreamShape { b, .. } = shape;
            let m_reg = 1usize << b;
            let mut regs = hll_omc_empty(b);
            for (bi, batch) in batches.iter().enumerate() {
                hll_omc_advance(&mut regs, &hll_keys_of(batch), m_reg);
                if query_due(bi) {
                    let dp = prove_hll_decode_omc(
                        HllDecodeParams { b, release: ReleasePolicy::Identity },
                        regs.clone(),
                        0,
                    );
                    let commit = commit_hll_omc(&regs, b);
                    record_query(&mut queries, bi + 1, &dp, commit, commit, None, decode_vk);
                }
            }
        }
        StreamFamily::SsCertified => {
            let StreamShape { capacity, .. } = shape;
            let m = batches[0].len();
            let params = SsFullParams { capacity, batch: m };
            let mut state = SsFullState::empty(params);
            for (bi, batch) in batches.iter().enumerate() {
                state = apply_batch_ss_full(&state, &ss_updates_of(batch)).0;
                if query_due(bi) {
                    let dp = prove_ss_decode(
                        SsDecodeParams { capacity, c: 1, release: ReleasePolicy::Identity },
                        state.clone(),
                        1,
                    );
                    let commit = commit_ss_state(&state).0;
                    record_query(&mut queries, bi + 1, &dp, commit, commit, Some(scalar_query(1)), decode_vk);
                }
            }
        }
        StreamFamily::GkBandmerge2 => {
            let StreamShape { capacity, gk_s, .. } = shape;
            let m = batches[0].len();
            let params = GkbParams { capacity, batch: m, s: gk_s };
            let mut state = Gk2State::empty(params);
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                let vals = gk_vals_of(batch);
                state = apply_batch2(&state, &vals);
                if track_freq {
                    for &v in &vals {
                        *freq.entry(v as u64).or_insert(0) += 1;
                    }
                }
                if query_due(bi) {
                    let qval = select_query_key(
                        query_key_mode,
                        &freq,
                        (batch[0] & 0x001F_FFFF) as u64,
                        (bi + 1) as u64,
                        0x001F_FFFF,
                    ) as u32;
                    let dp = prove_gk2_decode(
                        Gkb2DecodeParams { capacity, release: ReleasePolicy::Identity },
                        state.clone(),
                        qval,
                    );
                    let commit = commit_gk2_state(&state).0;
                    record_query(&mut queries, bi + 1, &dp, commit, commit, Some(scalar_query(qval as u64)), decode_vk);
                }
            }
        }
        StreamFamily::BloomOmc => {
            let params = shape.bloom_params(batches[0].len());
            let mut bits = bloom_empty(&params);
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                let keys = bloom_keys_of(batch);
                bloom_insert(&mut bits, &params, &keys);
                if track_freq {
                    for &k in &keys {
                        *freq.entry(k).or_insert(0) += 1;
                    }
                }
                if query_due(bi) {
                    let key =
                        select_query_key(query_key_mode, &freq, batch[0] as u64, (bi + 1) as u64, 0xFFFF_FFFF);
                    let dp = prove_bloom_query(params, &bits, key);
                    let commit = commit_bloom(&bits);
                    record_query(&mut queries, bi + 1, &dp, commit, commit, Some(bloom_query(key)), decode_vk);
                }
            }
        }
        StreamFamily::SsCertifiedGl
        | StreamFamily::GkBandmerge2Gl
        | StreamFamily::HllOmcGl
        | StreamFamily::CmOmcGl => {
            // The Goldilocks (`_gl`) families run only the distributed forest
            // path (`dist_compose::worker_main_gl`); per-batch query replay is
            // BabyBear-only. Use the non-`_gl` token for query experiments.
            panic!("query replay is not supported for the Goldilocks (_gl) families");
        }
    }
    queries
}

/// Measure the mixed-workload query phase for the **procs** engine: a plaintext
/// replay that proves each interleaved decode query on the coordinator, timed
/// inside a `cores`-thread pool (one machine's budget). The update leaves are
/// proved by the workers, so this covers only the query side; its cost lands in
/// the `query_*` columns, separate from the distributed update makespan.
///
/// With `bind = Some((audit, store, log))` (the procs coordinators' default),
/// every query proof is pinned to the auditor's decode VK and its answer is
/// bound to the certified history with the prefix certificates the workers
/// shipped ([`ContextStore::bind_all`]), inside the same pool. Without it the
/// answers are unbound (legacy opt-ins, and the engine-free unit test).
#[allow(clippy::too_many_arguments)]
pub fn measure_queries_dist(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
    bind: Option<(&mut QueryAudit, &ContextStore, &BatchLog<Val>)>,
) -> Result<QueryAgg, String> {
    if query_at.is_empty() || batches.is_empty() {
        return Ok(QueryAgg::default());
    }
    let pool = ThreadPoolBuilder::new()
        .num_threads(cores.max(1))
        .build()
        .expect("query pool");
    pool.install(|| {
        match bind {
            Some((audit, store, log)) => {
                let mut arts = prove_queries_only(
                    family,
                    shape,
                    batches,
                    query_at,
                    query_key_mode,
                    Some(&audit.decode_vk),
                );
                store.bind_all(audit, &mut arts, log)?;
                Ok(aggregate_queries(&arts, mode))
            }
            None => {
                let arts = prove_queries_only(family, shape, batches, query_at, query_key_mode, None);
                Ok(aggregate_queries(&arts, mode))
            }
        }
    })
}

/// Prove the `t` exposed, boundary-chained leaves for `family` at `shape`,
/// returning them (leaves stay on the calling thread — they are `!Send`) plus
/// the canonical empty-state commitment `Com(S_0)` for the per-batch anchor and
/// the interleaved query events (empty when `query_at` is empty).
///
/// Mixed workload: after each batch whose 1-based index is listed in
/// `query_at`, a **query leaf** (the family's decode circuit, `src/decode/*`) is proved
/// against the state at that point — it re-hashes the state in-circuit and
/// binds the SAME commitment the update leaf just exposed as its `final_`
/// boundary (asserted here), so a verifier holding the composition proof(s) at
/// `t'` can check the answer against `Com(S_{t'})`. The keyed probes (cm point
/// count, gk rank) target the key chosen by `query_key_mode` (default `First` =
/// the batch's first key), as does bloom membership; hll = cardinality and
/// ss = top-1 heavy-hitter mass are keyless and ignore the mode.
fn prove_leaves(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
    decode_vk: Option<&DecodeVk>,
) -> (Vec<LeafArt>, [Val; 8], Vec<QueryArt>) {
    let m = batches[0].len();
    let mut leaves: Vec<LeafArt> = Vec::with_capacity(batches.len());
    let mut queries: Vec<QueryArt> = Vec::new();
    let qset: BTreeSet<usize> = query_at.iter().copied().collect();
    let query_due = |bi: usize| qset.contains(&(bi + 1));
    // Maintain the running key/value multiset only when a keyed sampler needs it
    // (cm/gk under a non-`First` mode); `First` and hll/ss never touch it.
    let track_freq = !qset.is_empty() && query_key_mode != QueryKeyMode::First;
    // Capture each leaf's real self-timing right after proving.
    let mut push = |output: RecursionOutput<ConfigWithFriParams>, initial: [Val; 8], final_: [Val; 8]| {
        let tm = timing::take();
        leaves.push(LeafArt {
            output,
            initial,
            final_,
            prove_ms: (tm.witness + tm.prove).as_secs_f64() * 1000.0,
            verify_ms: tm.verify.as_secs_f64() * 1000.0,
        });
    };

    let empty_commit = match family {
        StreamFamily::CmOmc => {
            let StreamShape { d, w, .. } = shape;
            let mut state = cm_empty(d, w);
            let e = commit_countmin(&state).0;
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                let ups = cm_updates_of(batch);
                let leaf = build_countmin_omc_leaf_expose(
                    CmOmcParams { d, w, batch: m },
                    composition_expose(),
                    default_binding(),
                )
                .prove_epoch_at(bi as u64 + 1, state.clone(), ups.clone());
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                countmin_omc_advance(&mut state, &ups);
                if track_freq {
                    for &k in batch {
                        if k != PAD_KEY {
                            *freq.entry(k as u64).or_insert(0) += 1;
                        }
                    }
                }
                if query_due(bi) {
                    // Point-count query. Probe key chosen by `query_key_mode`
                    // (default = the batch's first key). The cm decode circuit
                    // takes any power-of-two w (cost ∝ d·w one-hot cells).
                    let key = select_query_key(
                        query_key_mode,
                        &freq,
                        batch[0] as u64,
                        (bi + 1) as u64,
                        0xFFFF_FFFF,
                    );
                    let dp = prove_cm_decode(
                        CmDecodeParams { d, w, release: ReleasePolicy::Identity },
                        state.clone(),
                        key,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_countmin(&state).0, leaf_final, Some(cm_query(key)), decode_vk);
                }
            }
            e
        }
        StreamFamily::HllOmc => {
            let StreamShape { b, .. } = shape;
            let m_reg = 1usize << b;
            let mut regs = hll_omc_empty(b);
            let e = commit_hll_omc(&regs, b);
            for (bi, batch) in batches.iter().enumerate() {
                let keys = hll_keys_of(batch);
                let leaf = build_hll_omc_leaf_expose(
                    HllOmcParams { b, batch: m },
                    composition_expose(),
                    default_binding(),
                )
                .prove_epoch_at(bi as u64 + 1, regs.clone(), keys.clone());
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                hll_omc_advance(&mut regs, &keys, m_reg);
                if query_due(bi) {
                    // Cardinality query (no probe key).
                    let dp = prove_hll_decode_omc(
                        HllDecodeParams { b, release: ReleasePolicy::Identity },
                        regs.clone(),
                        0,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_hll_omc(&regs, b), leaf_final, None, decode_vk);
                }
            }
            e
        }
        StreamFamily::SsCertified => {
            let StreamShape { capacity, .. } = shape;
            let params = SsFullParams { capacity, batch: m };
            let mut state = SsFullState::empty(params);
            let e = commit_ss_state(&state).0;
            for (bi, batch) in batches.iter().enumerate() {
                // Key mask (29-bit, low bit 1) + PAD_KEY→dummy live in the
                // canonical `ss_updates_of` mapping.
                let ups = ss_updates_of(batch);
                let leaf = build_ss_full_leaf_expose(params, composition_expose())
                    .prove_epoch_at(bi as u64 + 1, state.clone(), ups.clone());
                let leaf_final = leaf.final_.0;
                push(leaf.output, leaf.initial.0, leaf_final);
                state = apply_batch_ss_full(&state, &ups).0;
                if query_due(bi) {
                    // Top-1 heavy-hitter mass query.
                    let dp = prove_ss_decode(
                        SsDecodeParams { capacity, c: 1, release: ReleasePolicy::Identity },
                        state.clone(),
                        1,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_ss_state(&state).0, leaf_final, Some(scalar_query(1)), decode_vk);
                }
            }
            e
        }
        StreamFamily::GkBandmerge2 => {
            let StreamShape { capacity, gk_s, .. } = shape;
            let params = GkbParams { capacity, batch: m, s: gk_s };
            let mut state = Gk2State::empty(params);
            let e = commit_gk2_state(&state).0;
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                // 21-bit value mask (< E_MAX) + PAD_KEY stripping live in the
                // canonical `gk_vals_of` mapping (short batches are legal — the
                // leaf pads its fresh-tuple rows with E_MAX dummies itself).
                let vals = gk_vals_of(batch);
                let leaf = build_gkb2_leaf_expose(params, composition_expose())
                    .prove_epoch_at(bi as u64 + 1, state.clone(), vals.clone());
                let leaf_final = leaf.final_.0;
                push(leaf.output, leaf.initial.0, leaf_final);
                state = apply_batch2(&state, &vals);
                if track_freq {
                    for &v in &vals {
                        *freq.entry(v as u64).or_insert(0) += 1;
                    }
                }
                if query_due(bi) {
                    // Rank query. Probe value chosen by `query_key_mode` (default
                    // = the batch's first masked value), bounded to the 21-bit
                    // GK value domain.
                    let qval = select_query_key(
                        query_key_mode,
                        &freq,
                        (batch[0] & 0x001F_FFFF) as u64,
                        (bi + 1) as u64,
                        0x001F_FFFF,
                    ) as u32;
                    let dp = prove_gk2_decode(
                        Gkb2DecodeParams { capacity, release: ReleasePolicy::Identity },
                        state.clone(),
                        qval,
                    );
                    record_query(&mut queries, bi + 1, &dp, commit_gk2_state(&state).0, leaf_final, Some(scalar_query(qval as u64)), decode_vk);
                }
            }
            e
        }
        StreamFamily::BloomOmc => {
            let params = shape.bloom_params(m);
            let mut bits = bloom_empty(&params);
            let e = commit_bloom(&bits);
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                // PAD_KEY slots stripped into the leaf's canonical dummies
                // (the canonical `bloom_keys_of` mapping).
                let keys = bloom_keys_of(batch);
                let leaf = build_bloom_omc_leaf_expose(params, composition_expose())
                    .prove_epoch_at(bi as u64 + 1, &bits, &keys);
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                bloom_insert(&mut bits, &params, &keys);
                if track_freq {
                    for &k in &keys {
                        *freq.entry(k).or_insert(0) += 1;
                    }
                }
                if query_due(bi) {
                    // Membership query. Probe key chosen by `query_key_mode`
                    // (default = the batch's first key); `absent` may hit a
                    // false positive, which the proof certifies as such.
                    let key = select_query_key(
                        query_key_mode,
                        &freq,
                        batch[0] as u64,
                        (bi + 1) as u64,
                        0xFFFF_FFFF,
                    );
                    let dp = prove_bloom_query(params, &bits, key);
                    record_query(&mut queries, bi + 1, &dp, commit_bloom(&bits), leaf_final, Some(bloom_query(key)), decode_vk);
                }
            }
            e
        }
        StreamFamily::SsCertifiedGl
        | StreamFamily::GkBandmerge2Gl
        | StreamFamily::HllOmcGl
        | StreamFamily::CmOmcGl => {
            // The single-process `sim` engine is monomorphized to BabyBear. The
            // Goldilocks families run through the distributed engine only
            // (`dist_compose::measure_compose_dist_gl`), selected when machines >= 2
            // or EXP_COMPOSE_EXEC=procs.
            panic!(
                "the Goldilocks (_gl) families require the distributed engine \
                 (set EXP_COMPOSE_EXEC=procs or EXP_COMPOSE_MACHINES>=2)"
            )
        }
    };

    (leaves, empty_commit, queries)
}

/// `M`-machine work-partition makespan of `per_leaf` prove times: split the
/// leaves into `M` contiguous segments and take the max segment sum. Models `M`
/// machines each proving a disjoint contiguous range at the machine's core
/// budget. `machines <= 1` ⇒ the sequential sum.
fn makespan(per_leaf: &[f64], machines: usize) -> f64 {
    let t = per_leaf.len();
    if machines <= 1 || t == 0 {
        return per_leaf.iter().sum();
    }
    let per = t.div_ceil(machines);
    let mut worst = 0.0f64;
    let mut i = 0;
    while i < t {
        let end = (i + per).min(t);
        worst = worst.max(per_leaf[i..end].iter().sum());
        i = end;
    }
    worst
}

/// The trusted VK the auditor verifies the stream's artifact against, derived
/// from public parameters only (a no-op leaf of the family's leaf circuit,
/// via `dist_compose`) — the default:
///
/// * chain / forest with `t >= 2`: the ROOT VK of the fold's tree shape
///   (`dist_compose::derive_dist_root_vk` with one machine);
/// * per_batch, and chain / forest with `t == 1` (the artifact is then a lone
///   leaf proof): the LEAF VK (`dist_compose::derive_dist_leaf_vk`), against
///   which every leaf the auditor holds is pinned and STARK-verified
///   (`expose_forest::verify_leaves_against_log`).
///
/// `None` only for the explicit `EXP_ROOT_VK=self` legacy opt-in (warned: the
/// root is self-pinned and leaf proofs are not re-verified), and for a
/// Goldilocks family, which this engine rejects in `prove_leaves`.
fn compose_trusted_vk(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
    mode: StreamMode,
    t: usize,
) -> Option<RootVk<crate::config::Challenge>> {
    if family.is_gl() {
        return None;
    }
    let leaf_artifact = mode == StreamMode::PerBatch || t < 2;
    match exp_root_vk() {
        ExpRootVk::Derive => Some(if leaf_artifact {
            super::dist_compose::derive_dist_leaf_vk(family, shape, m)
        } else {
            super::dist_compose::derive_dist_root_vk(family, shape, m, mode, t, 1)
        }),
        ExpRootVk::SelfPinnedLegacy => {
            warn_self_pinned_legacy("stream_compose");
            None
        }
        ExpRootVk::File(path) => panic!(
            "EXP_ROOT_VK={}: a root-VK file is only supported by dist_compose; \
             use EXP_ROOT_VK=derive (default) or EXP_ROOT_VK=self",
            path.display()
        ),
    }
}

/// The per_batch / lone-leaf auditor of the sim engine: with a trusted leaf
/// VK, pin + STARK-verify every leaf and check the statements against `log`
/// (timed; returns ms). Without one (legacy `EXP_ROOT_VK=self` only), check
/// the statements alone — which authenticates nothing — and report the
/// provers' self-verify total `self_verify_ms`, as before the pin existed.
fn audit_leaves(
    leaves: &[&p3_circuit_prover::BatchStarkProof<ConfigWithFriParams>],
    leaf_vk: Option<&RootVk<crate::config::Challenge>>,
    log: &BatchLog<Val>,
    layout: Expose,
    self_verify_ms: f64,
) -> f64 {
    match leaf_vk {
        Some(vk) => {
            let tv = std::time::Instant::now();
            if let Err(e) = verify_leaves_against_log(leaves, vk, log, layout) {
                panic!("leaf audit: {e}");
            }
            tv.elapsed().as_secs_f64() * 1000.0
        }
        None => {
            if let Err(e) = check_leaves_against_log(leaves, log, layout) {
                panic!("leaf statements vs log: {e}");
            }
            self_verify_ms
        }
    }
}

/// Measure one `(family, shape, mode, cores, machines)` composition cell over
/// `batches` (raw dataset keys, all of length `m`). The whole measurement runs
/// inside a `cores`-thread pool so each proof uses that many cores. `proof_dir`
/// is the folder the per-batch mode stores its `t` proofs under (ignored by the
/// composed modes). A non-empty `query_at` (1-based batch indices; see
/// [`build_query_schedule_batches`] for arbitrary stream positions) interleaves
/// one query leaf after each listed batch (mixed updates+queries workload); its
/// costs are reported in the separate `query_*` fields, NOT folded into the
/// update-side totals.
#[allow(clippy::too_many_arguments)]
pub fn measure_compose(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    machines: usize,
    proof_dir: &Path,
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
) -> ComposeCell {
    assert!(!batches.is_empty(), "need at least one batch");
    let m = batches[0].len();
    assert!(batches.iter().all(|b| b.len() == m), "all batches must share length m");

    let pool = ThreadPoolBuilder::new()
        .num_threads(cores.max(1))
        .build()
        .expect("compose leaf pool");

    // One measured pass, inside the core-limited pool. bench() wraps it with the
    // RSS sampler; the closure returns only Send metrics (proofs are dropped
    // inside it), so !Send never crosses the pool boundary.
    // Sequential leaf-gen (Σ per-leaf) written out at full f64 precision — a
    // reference / speedup denominator, captured via a mutable rather than
    // squeezed through the u64 RunOutcome fields (trials = 1, set once).
    // Query-event aggregates are captured the same way (trials = 1, set once).
    let mut leafgen_seq_out = 0.0f64;
    let mut q_out = QueryAgg::default();
    let agg = pool.install(|| {
        // Auditor's trusted root VK: derived from public parameters before (and
        // outside) the measured pass; never read from the root it verifies.
        let root_vk = compose_trusted_vk(family, &shape, m, mode, batches.len());
        // Mixed workload: the query-side auditor (decode VK + prefix
        // auditor), likewise derived from public parameters up front.
        let mut audit =
            if query_at.is_empty() { None } else { QueryAudit::new(family, &shape, m) };
        bench(BenchCfg { warmup: 0, trials: 1 }, || {
            let (leaves, empty_commit, mut query_arts) = prove_leaves(
                family,
                shape,
                batches,
                query_at,
                query_key_mode,
                audit.as_ref().map(|a| &a.decode_vk),
            );
            let prove_ms: Vec<f64> = leaves.iter().map(|l| l.prove_ms).collect();
            let leafgen_seq: f64 = prove_ms.iter().sum();
            leafgen_seq_out = leafgen_seq;

            let outcome = match mode {
                StreamMode::PerBatch => {
                    // Store each leaf proof to the folder (fresh per run); the
                    // verifier holds all t (Θ(t) size + verify).
                    let _ = std::fs::remove_dir_all(proof_dir);
                    std::fs::create_dir_all(proof_dir).expect("create per-batch proof dir");
                    let mut total_bytes = 0u64;
                    let mut self_verify = 0.0f64;
                    for (i, l) in leaves.iter().enumerate() {
                        let bytes =
                            postcard::to_allocvec(&l.output.0).expect("serialize leaf proof");
                        total_bytes += bytes.len() as u64;
                        std::fs::write(proof_dir.join(format!("leaf_{i:04}.bin")), &bytes)
                            .expect("write leaf proof");
                        self_verify += l.verify_ms;
                    }
                    // The prover's native anchor and boundary links (its own
                    // Com(S_i) values) — a consistency assert of the harness,
                    // not an audit: the auditor below reads the boundaries
                    // from the verified proofs instead.
                    let mut ok = leaves[0].initial == empty_commit;
                    for pair in leaves.windows(2) {
                        ok &= pair[0].final_ == pair[1].initial;
                    }
                    assert!(ok, "per-batch chain boundary/anchor check failed");
                    // Auditor: every leaf is pinned to the trusted LEAF VK
                    // (derived from public parameters, outside this pass),
                    // STARK-verified, and its exposed statement checked
                    // against the public batch log (Com(S_0) -> ... -> Com(S_T)
                    // chain; Interval: (t, t, H(TAG_LEAF, t, Com(B_t)))).
                    // Timed as the per-batch verify (the paper's Θ(t) cost).
                    let layout = composition_expose();
                    if layout != Expose::Interval {
                        warn_boundary_layout("stream_compose per-batch");
                    }
                    let log = super::dist_compose::stream_batch_log(family, &shape, m, batches);
                    let proofs: Vec<_> = leaves.iter().map(|l| &l.output.0).collect();
                    let total_verify =
                        audit_leaves(&proofs, root_vk.as_ref(), &log, layout, self_verify);
                    // Mixed workload: a query at t' is certified by leaves 1..t'.
                    for g in query_arts.iter().map(|q| q.at_leaf).collect::<BTreeSet<_>>() {
                        bind_due(&mut audit, &mut query_arts, g, || {
                            (1..=g)
                                .map(|k| {
                                    let p = CtxProof::Proof(&leaves[k - 1].output.0);
                                    (k as u64, k as u64, ForestShape::Leaf, p)
                                })
                                .collect()
                        }, &log);
                    }

                    // machines: parallel independent leaf proving (no fold).
                    let leafgen = makespan(&prove_ms, machines);
                    RunOutcome {
                        witness_gen: Duration::from_secs_f64(leafgen / 1000.0),
                        prove: Duration::ZERO, // no fold
                        verify: Duration::from_secs_f64(total_verify / 1000.0),
                        proof_size_bytes: total_bytes,
                        trace_rows: 0,
                        num_columns: 0,
                    }
                }
                StreamMode::Chain | StreamMode::Forest => {
                    // A single leaf has nothing to compose; the artifact is
                    // the lone leaf proof. Its proof carries the sketch's
                    // tables (Permute, Range...), which the aggregation
                    // verifier (`verify_bound_proof*`) does not register, so
                    // for t == 1 the auditor verifies it as a LEAF: pinned to
                    // the trusted leaf VK, STARK-verified, statement vs the
                    // log ([`audit_leaves`]).
                    let single_leaf = leaves.len() < 2;
                    let single_verify_ms = leaves[0].verify_ms;
                    let outputs: Vec<RecursionOutput<ConfigWithFriParams>> =
                        leaves.into_iter().map(|l| l.output).collect();
                    // The public batch log (Com(S_0), Com(S_T), Com(B_1..B_T)),
                    // computed natively from the batches.
                    let log = super::dist_compose::stream_batch_log(family, &shape, m, batches);
                    // Real recursive fold → one O(1) root. Timed as merge.
                    // Mixed workload: right after leaf t' the interval proofs
                    // live at t' (the chain's fold Π_[1,t'] or the forest's
                    // peaks) certify each query at t' ([`bind_due`]); that
                    // time is kept out of the merge timing.
                    let t0 = std::time::Instant::now();
                    let mut bind_wall = 0.0f64;
                    let mut outputs = outputs.into_iter();
                    let first = outputs.next().expect(">=1 leaf");
                    let root = match mode {
                        StreamMode::Chain => {
                            let mut acc = first;
                            bind_wall += bind_due(&mut audit, &mut query_arts, 1, || {
                                vec![(1, 1, ForestShape::Leaf, CtxProof::Proof(&acc.0))]
                            }, &log);
                            for (k, leaf) in outputs.enumerate() {
                                let g = k + 2;
                                acc = prove_hiding_merge(&acc, &leaf);
                                bind_wall += bind_due(&mut audit, &mut query_arts, g, || {
                                    let sh = ForestShape::chain(g);
                                    vec![(1, g as u64, sh, CtxProof::Proof(&acc.0))]
                                }, &log);
                            }
                            acc
                        }
                        _ => {
                            let mut forest = ForestCascade::new(1);
                            let mut push_and_bind = |leaf, g: usize, forest: &mut ForestCascade| {
                                forest.push(leaf);
                                bind_due(&mut audit, &mut query_arts, g, || {
                                    forest
                                        .peaks()
                                        .into_iter()
                                        .map(|(lo, hi, p)| {
                                            let sh = ForestShape::forest((hi - lo + 1) as usize);
                                            (lo, hi, sh, CtxProof::Proof(&p.0))
                                        })
                                        .collect()
                                }, &log)
                            };
                            bind_wall += push_and_bind(first, 1, &mut forest);
                            for (k, leaf) in outputs.enumerate() {
                                bind_wall += push_and_bind(leaf, k + 2, &mut forest);
                            }
                            forest.finalize().0
                        }
                    };
                    let merge_ms = t0.elapsed().as_secs_f64() * 1000.0 - bind_wall;
                    let bytes = proof_size(&root.0) as u64;
                    let tree = match mode {
                        StreamMode::Chain => ForestShape::chain(batches.len()),
                        _ => ForestShape::forest(batches.len()),
                    };
                    let layout = composition_expose();
                    let interval = layout == Expose::Interval;
                    if !interval {
                        warn_boundary_layout("stream_compose");
                    }
                    // Verifier: one succinct check of the merged root (t == 1:
                    // the lone leaf, audited as a leaf; see above).
                    let verify_ms = if single_leaf {
                        audit_leaves(&[&root.0], root_vk.as_ref(), &log, layout, single_verify_ms)
                    } else {
                        let tv = std::time::Instant::now();
                        // Pinned to the derived root VK (fails closed on a
                        // mismatch); only the explicit `EXP_ROOT_VK=self`
                        // opt-in self-pins (a fixed-size equality either way,
                        // so the timing is comparable). Interval layout
                        // (default): the root statement is then checked against
                        // the batch log (O(T) native hashes, inside the timing).
                        match (&root_vk, interval) {
                            (Some(vk), true) => verify_bound_proof_against_log(&root, vk, &log, &tree),
                            (Some(vk), false) => verify_bound_proof(&root, vk),
                            (None, true) => {
                                verify_bound_proof_self_pinned_legacy(&root);
                                if let Err(e) = check_root_against_log(&root.0, &log, &tree) {
                                    panic!("root statement vs log: {e}");
                                }
                            }
                            (None, false) => verify_bound_proof_self_pinned_legacy(&root),
                        }
                        if !interval {
                            // Boundary layout: the root's (init, final) must
                            // still be the log's (Com(S_0), Com(S_T)).
                            let st = read_exposed_statement(&root.0);
                            assert!(
                                st.init == log.init && st.final_ == log.final_,
                                "root boundary != the log's (Com(S_0), Com(S_T))"
                            );
                        }
                        tv.elapsed().as_secs_f64() * 1000.0
                    };
                    // Chain is sequential (fold depends on predecessor); forest
                    // parallelises leaf-gen across machines.
                    let leafgen = match mode {
                        StreamMode::Forest => makespan(&prove_ms, machines),
                        _ => leafgen_seq,
                    };
                    RunOutcome {
                        witness_gen: Duration::from_secs_f64(leafgen / 1000.0),
                        prove: Duration::from_secs_f64(merge_ms / 1000.0),
                        verify: Duration::from_secs_f64(verify_ms / 1000.0),
                        proof_size_bytes: bytes,
                        trace_rows: 0,
                        num_columns: 0,
                    }
                }
            };
            // Mixed-workload aggregates (same fold the procs engine uses).
            q_out = aggregate_queries(&query_arts, mode);
            outcome
        })
    });

    let peak = if agg.peak_rss_mb_median > 0.0 {
        agg.peak_rss_mb_median
    } else {
        read_vmrss_kb().map(|kb| kb as f64 / 1024.0).unwrap_or(0.0)
    };

    ComposeCell {
        total_time_ms: agg.prove_total_ms_median,
        leafgen_ms: agg.witness_gen_ms_median,
        leafgen_seq_ms: leafgen_seq_out,
        merge_ms: agg.prove_ms_median,
        verify_ms: agg.verify_ms_median,
        proof_bytes: agg.proof_size_bytes,
        peak_rss_mb: peak,
        n_queries: q_out.n_queries,
        query_prove_ms: q_out.query_prove_ms,
        query_verify_ms: q_out.query_verify_ms,
        query_proof_bytes: q_out.query_proof_bytes,
        query_ctx_verifies: q_out.query_ctx_verifies,
        query_bind_ms: q_out.query_bind_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> StreamShape {
        StreamShape { d: 4, w: 8, b: 4, capacity: 4, gk_s: 2, bloom_k: 3, bloom_log_w: 7 }
    }

    /// The query-key sampler is deterministic and honours each mode: `First`
    /// returns the batch's first key untouched; `Hot` returns the most-frequent
    /// key (ties → smallest); `UniformStream` returns a key that is present in
    /// the multiset; `Absent` returns an in-domain key that is NOT present.
    #[test]
    fn query_key_modes_select_correctly() {
        assert_eq!(QueryKeyMode::parse("first"), Some(QueryKeyMode::First));
        assert_eq!(QueryKeyMode::parse("UNIFORM"), Some(QueryKeyMode::UniformStream));
        assert_eq!(QueryKeyMode::parse("Hot"), Some(QueryKeyMode::Hot));
        assert_eq!(QueryKeyMode::parse("absent"), Some(QueryKeyMode::Absent));
        assert_eq!(QueryKeyMode::parse("bogus"), None);

        // Multiset {7:3, 42:1, 99:2} — 7 is hot, all three are "present".
        let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
        freq.insert(7, 3);
        freq.insert(42, 1);
        freq.insert(99, 2);
        let mask = 0xFFFF_FFFF;

        assert_eq!(select_query_key(QueryKeyMode::First, &freq, 123, 1, mask), 123);
        assert_eq!(select_query_key(QueryKeyMode::Hot, &freq, 123, 1, mask), 7);
        for seed in 0..32u64 {
            let k = select_query_key(QueryKeyMode::UniformStream, &freq, 123, seed, mask);
            assert!(freq.contains_key(&k), "uniform_stream key {k} must be in the stream");
            let a = select_query_key(QueryKeyMode::Absent, &freq, 123, seed, mask);
            assert!(!freq.contains_key(&a), "absent key {a} must NOT be in the stream");
            assert_eq!(a & mask, a, "absent key {a} must stay in domain");
        }
        // Deterministic: same seed → same key.
        assert_eq!(
            select_query_key(QueryKeyMode::UniformStream, &freq, 123, 5, mask),
            select_query_key(QueryKeyMode::UniformStream, &freq, 123, 5, mask),
        );
        // Empty multiset falls back to `first` for the sampled modes.
        let empty: BTreeMap<u64, u64> = BTreeMap::new();
        assert_eq!(select_query_key(QueryKeyMode::UniformStream, &empty, 123, 1, mask), 123);
        assert_eq!(select_query_key(QueryKeyMode::Hot, &empty, 123, 1, mask), 123);
    }

    /// The procs-engine query phase (`measure_queries_dist`, coordinator-side,
    /// no worker processes) proves each interleaved query for real and reports
    /// the same per-mode verifier-context count as the sim engine.
    #[test]
    fn measure_queries_dist_matches_modes() {
        // Two batches, one query per batch ⇒ 2 query events at t'=1,2.
        let batches: Vec<Vec<u32>> = vec![(1..=4).collect(), (5..=8).collect()];
        let run = |mode, query_at: &[usize]| {
            measure_queries_dist(
                StreamFamily::CmOmc, shape(), &batches, mode, 1, query_at, QueryKeyMode::First, None,
            )
            .expect("unbound query phase")
        };
        // forest ctx = popcount(1)+popcount(2) = 1+1 = 2.
        let f = run(StreamMode::Forest, &[1, 2]);
        assert_eq!(f.n_queries, 2, "one query per batch");
        assert!(f.query_prove_ms > 0.0 && f.query_proof_bytes > 0, "real query proof");
        assert_eq!(f.query_ctx_verifies, 2, "forest ctx = Σ popcount(t')");
        // per_batch ctx = 1+2 = 3 ; chain ctx = 1+1 = 2.
        assert_eq!(run(StreamMode::PerBatch, &[1, 2]).query_ctx_verifies, 3, "per_batch ctx = Σ t'");
        assert_eq!(run(StreamMode::Chain, &[1, 2]).query_ctx_verifies, 2, "chain ctx = 1/query");
        // Updates-only ⇒ no query phase.
        assert_eq!(run(StreamMode::Forest, &[]).n_queries, 0, "empty schedule → no queries");
    }

    /// Two batches, every family/mode — proves the leaves chain (a broken
    /// boundary would panic the fold's in-circuit bind), the three modes run,
    /// and per_batch stores one file per batch with a Θ(t) artifact.
    #[test]
    fn all_families_all_modes_smoke() {
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
            StreamFamily::BloomOmc,
        ] {
            for mode in [StreamMode::PerBatch, StreamMode::Chain, StreamMode::Forest] {
                let dir = std::env::temp_dir()
                    .join(format!("zksketch_compose_{}_{}", family.label(), mode.label()));
                let _ = std::fs::remove_dir_all(&dir);
                let cell =
                    measure_compose(family, shape(), &batches, mode, 1, 1, &dir, &[], QueryKeyMode::First);
                assert!(
                    cell.total_time_ms > 0.0,
                    "measured ({family:?}, {mode:?})"
                );
                assert!(cell.proof_bytes > 0, "artifact ({family:?}, {mode:?})");
                assert_eq!(cell.n_queries, 0, "updates-only run has no queries");
                if mode == StreamMode::PerBatch {
                    let files = std::fs::read_dir(&dir).map(|it| it.count()).unwrap_or(0);
                    assert_eq!(files, 2, "one proof/batch ({family:?})");
                    assert_eq!(cell.merge_ms, 0.0, "per_batch no fold ({family:?})");
                }
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }

    /// Mixed updates+queries: every batch is followed by a query leaf. Checks
    /// the query events fire, carry real costs, bind the leaf boundary (a
    /// mismatch would panic `record_query`'s assert), and every answer is
    /// bound to the certified history with the certificate a verifier holds at
    /// t' — forest peaks = popcount(t'), per_batch = t' leaves, chain = 1 fold
    /// — at a measured cost.
    #[test]
    fn mixed_queries_smoke() {
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
            StreamFamily::BloomOmc,
        ] {
            let dir = std::env::temp_dir().join(format!("zksketch_mixed_{}", family.label()));
            let _ = std::fs::remove_dir_all(&dir);
            let cell = measure_compose(
                family, shape(), &batches, StreamMode::Forest, 1, 1, &dir, &[1, 2],
                QueryKeyMode::First,
            );
            assert_eq!(cell.n_queries, 2, "one query per batch ({family:?})");
            assert!(cell.query_prove_ms > 0.0, "query prove timed ({family:?})");
            assert!(cell.query_proof_bytes > 0, "query artifact ({family:?})");
            // Forest peaks at t'=1 and t'=2: popcount(1)+popcount(2) = 1+1.
            assert_eq!(cell.query_ctx_verifies, 2, "forest peaks ctx ({family:?})");
            assert!(cell.query_bind_ms.is_some_and(|ms| ms > 0.0), "answers bound ({family:?})");
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Mode-dependent ctx on one family: per_batch = 1+2, chain = 1+1.
        let dir = std::env::temp_dir().join("zksketch_mixed_ctx");
        let cell = measure_compose(
            StreamFamily::CmOmc, shape(), &batches, StreamMode::PerBatch, 1, 1, &dir, &[1, 2],
            QueryKeyMode::First,
        );
        assert_eq!(cell.query_ctx_verifies, 3, "per_batch ctx = t' sum");
        assert!(cell.query_bind_ms.is_some(), "per_batch answers bound");
        let cell = measure_compose(
            StreamFamily::CmOmc, shape(), &batches, StreamMode::Chain, 1, 1, &dir, &[1, 2],
            QueryKeyMode::First,
        );
        assert_eq!(cell.query_ctx_verifies, 2, "chain ctx = 1 per query");
        assert!(cell.query_bind_ms.is_some(), "chain answers bound");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `build_query_schedule_batches` follows the OPERATION-STREAM model: every
    /// Q-th stream position IS a query (it occupies the position, consuming no
    /// record), the rest are updates; mid-batch queries seal early with the
    /// family's no-op pads (sentinel / repeated key), with honest accounting.
    #[test]
    fn query_schedule_builder_cuts_and_pads() {
        let base: Vec<u32> = (1..=10).collect();
        // n=10 OPERATIONS, m=4, Q=3 → queries at positions 3,6,9; updates at
        // 1,2,4,5,7,8,10 = 7 records (keys 1..7): 10 points = 3 queries + 7
        // updates. Batches: [1,2,P,P] [3,4,P,P] [5,6,P,P] [7,P,P,P].
        let (b, qat, pads, splits) =
            build_query_schedule_batches(&base, 10, 4, 3, StreamFamily::CmOmc);
        assert_eq!(b.len(), 4);
        assert!(b.iter().all(|x| x.len() == 4), "uniform batch length m");
        assert_eq!(qat, vec![1, 2, 3], "queries bind leaves 1..3");
        assert_eq!(pads, 2 + 2 + 2 + 3, "7 update records over 4 batches of 4");
        assert_eq!(splits, 4);
        assert_eq!(&b[0][..2], &[1, 2]);
        assert_eq!(b[0][2], PAD_KEY);
        assert_eq!(b[3], vec![7, PAD_KEY, PAD_KEY, PAD_KEY]);
        // HLL pads repeat the batch's first real key instead of the sentinel.
        let (bh, ..) = build_query_schedule_batches(&base, 10, 4, 3, StreamFamily::HllOmc);
        assert_eq!(bh[0], vec![1, 2, 1, 1]);
        assert_eq!(bh[3], vec![7, 7, 7, 7]);
        // A query right after a natural batch boundary binds that boundary
        // directly — no split, no pads: Q=5 over n=10 → updates 1..4 fill leaf
        // 1, query at p=5 binds it; updates 6..9 (keys 5..8) fill leaf 2,
        // query at p=10 binds it.
        let (b2, qat2, pads2, splits2) =
            build_query_schedule_batches(&base, 10, 4, 5, StreamFamily::CmOmc);
        assert_eq!((b2.len(), qat2, pads2, splits2), (2, vec![1, 2], 0, 0));
        assert_eq!(b2[1], vec![5, 6, 7, 8]);
        // Real keys equal to the sentinel are remapped.
        let (b3, ..) =
            build_query_schedule_batches(&[PAD_KEY, 5, 6, 7], 4, 4, 0, StreamFamily::CmOmc);
        assert_eq!(b3[0][0], PAD_KEY - 1);
    }

    /// Mid-batch queries via split+pad batches, EVERY family: the padded leaf
    /// must land exactly on the native state of the real records (pads provably
    /// no-ops) — `record_query`'s boundary assert panics on any drift — and the
    /// query binds that mid-stream commitment.
    #[test]
    fn mixed_queries_at_update_positions_all_families() {
        let base: Vec<u32> = (1..=10).map(|k| k * 7 + 1).collect();
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
            StreamFamily::BloomOmc,
        ] {
            // n=10 stream positions, Q=3, m=4 ⇒ queries occupy positions
            // 3,6,9 (7 update records) ⇒ leaves [2r+2p][2r+2p][2r+2p][1r+3p],
            // queries after leaves 1..3 — every queried boundary is mid-batch.
            let (batches, query_at, pads, splits) =
                build_query_schedule_batches(&base, 10, 4, 3, family);
            assert_eq!((query_at.as_slice(), pads > 0, splits), (&[1, 2, 3][..], true, 4));
            let dir =
                std::env::temp_dir().join(format!("zksketch_split_{}", family.label()));
            let _ = std::fs::remove_dir_all(&dir);
            let cell = measure_compose(
                family, shape(), &batches, StreamMode::Forest, 1, 1, &dir, &query_at,
                QueryKeyMode::First,
            );
            assert_eq!(cell.n_queries, 3, "3 mid-batch queries ({family:?})");
            assert!(cell.query_prove_ms > 0.0, "real query proofs ({family:?})");
            // Peaks at t' = 1, 2, 3: 1 + 1 + 2 proofs, all verified.
            assert_eq!(cell.query_ctx_verifies, 4, "forest peaks ctx ({family:?})");
            assert!(cell.query_bind_ms.is_some(), "mid-batch answers bound ({family:?})");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A single-leaf (t=1) stream: chain/forest have nothing to compose, so the
    /// "root" is the lone leaf. Regression for the case where verifying that raw
    /// leaf via the aggregation verifier (which lacks the Permute table) would
    /// panic — t=1 must fall back to the leaf's own self-verify.
    #[test]
    fn single_leaf_chain_forest_no_panic() {
        let batches: Vec<Vec<u32>> = vec![(0..4).map(|j| (j + 1) as u32).collect()];
        let dir = std::env::temp_dir().join("zksketch_compose_t1");
        for mode in [StreamMode::Chain, StreamMode::Forest] {
            let cell = measure_compose(StreamFamily::CmOmc, shape(), &batches, mode, 1, 1, &dir, &[], QueryKeyMode::First);
            assert!(cell.total_time_ms > 0.0, "t=1 measured ({mode:?})");
            assert!(cell.proof_bytes > 0, "t=1 artifact ({mode:?})");
            // No real fold — the "root" is the lone leaf (sub-ms to select).
            assert!(cell.merge_ms < 10.0, "t=1 has no real merge ({mode:?})");
            assert!(cell.verify_ms > 0.0, "t=1: the auditor verifies the lone leaf ({mode:?})");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Child half of [`boundary_layout_harness_paths`]: a no-op unless the
    /// parent re-runs this test binary with `ZKSKETCH_STATEMENT_CHILD` set.
    #[test]
    fn boundary_layout_child() {
        if std::env::var_os("ZKSKETCH_STATEMENT_CHILD").is_none() {
            return;
        }
        assert_eq!(composition_expose(), Expose::Boundary, "ZKSKETCH_STATEMENT=boundary");
        let dir = std::env::temp_dir().join(format!("zksketch_boundary_child_{}", std::process::id()));
        let two: Vec<Vec<u32>> = (0..2u32).map(|i| (1..=4).map(|k| k * 7 + i * 13).collect()).collect();
        for (batches, modes) in [
            (&two[..], &[StreamMode::PerBatch, StreamMode::Chain, StreamMode::Forest][..]),
            (&two[..1], &[StreamMode::Forest][..]),
        ] {
            for &mode in modes {
                let cell = measure_compose(
                    StreamFamily::CmOmc,
                    shape(),
                    batches,
                    mode,
                    1,
                    1,
                    &dir,
                    &[],
                    QueryKeyMode::First,
                );
                assert!(cell.proof_bytes > 0 && cell.verify_ms > 0.0, "{mode:?} t={}", batches.len());
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        println!("CHILD_BOUNDARY_OK");
    }

    /// The side-by-side Boundary layout through the sim harness, in a child
    /// process so the parallel test run's environment is untouched:
    /// `ZKSKETCH_STATEMENT=boundary` builds the pre-B6(b) leaves and merges,
    /// prints the loud Boundary warning, and every mode (per_batch, chain,
    /// forest, and the lone leaf) still verifies under the derived root / leaf
    /// VK and the log's `(Com(S_0), Com(S_T))`.
    #[test]
    fn boundary_layout_harness_paths() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let out = std::process::Command::new(&exe)
            .args(["--exact", "experiments::stream_compose::tests::boundary_layout_child", "--nocapture"])
            .args(["--test-threads", "1"])
            .env("ZKSKETCH_STATEMENT_CHILD", "1")
            .env("ZKSKETCH_STATEMENT", "boundary")
            .env_remove("ZKSKETCH_BINDING")
            .output()
            .expect("spawn child test");
        let text =
            format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "boundary child failed:\n{text}");
        assert!(text.contains("CHILD_BOUNDARY_OK"), "{text}");
        assert!(text.contains("composition layout = Boundary"), "the Boundary warning is printed:\n{text}");
    }

    /// The sim engine's leaf audit ([`audit_leaves`]: per_batch, and the lone
    /// leaf of a one-batch stream). With the leaf VK the harness derives
    /// ([`compose_trusted_vk`]) the honest leaf passes and THE REVIEWED
    /// ATTACK — a toy circuit exposing leaf 1's honest statement — is rejected;
    /// the pre-fix statement-only path (still what the legacy
    /// `EXP_ROOT_VK=self` opt-in runs) accepts it.
    #[test]
    fn sim_leaf_audit_rejects_foreign_circuit() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        use p3_field::BasedVectorSpace;
        let (sh, m) = (shape(), 4usize);
        let batches: Vec<Vec<u32>> = vec![(1..=4).collect()];
        for mode in [StreamMode::PerBatch, StreamMode::Forest] {
            assert!(compose_trusted_vk(StreamFamily::CmOmc, &sh, m, mode, 1).is_some(), "{mode:?}: leaf VK");
        }
        let vk = compose_trusted_vk(StreamFamily::CmOmc, &sh, m, StreamMode::PerBatch, 3)
            .expect("derived leaf VK");
        let (leaves, _, _) = prove_leaves(StreamFamily::CmOmc, sh, &batches, &[], QueryKeyMode::First, None);
        let log = super::super::dist_compose::stream_batch_log(StreamFamily::CmOmc, &sh, m, &batches);
        let layout = composition_expose();
        assert!(audit_leaves(&[&leaves[0].output.0], Some(&vk), &log, layout, -1.0) >= 0.0);
        let cs: Vec<crate::config::Challenge> = read_exposed_statement(&leaves[0].output.0)
            .values()
            .chunks(4)
            .map(|c| crate::config::Challenge::from_basis_coefficients_slice(c).unwrap())
            .collect();
        let toy = crate::recursion::recursive::expose_forest::prove_exposing_leaf(&cs);
        assert_eq!(audit_leaves(&[&toy.0], None, &log, layout, -1.0), -1.0, "pre-fix path accepts");
        let r = crate::sketch::forge::catch_msg(|| audit_leaves(&[&toy.0], Some(&vk), &log, layout, -1.0));
        println!("B6B sim leaf audit toy: {r:?}");
        assert!(r.is_err_and(|e| e.contains("leaf audit")));
    }

    /// The binding fails closed, for Count-Min and the Bloom filter: a query
    /// answered against the state at t' is rejected with the certificate of
    /// t'-1 (stale peaks), with a certificate over a different batch log, and
    /// when its exposed Com(S) is not the certified one. Without an auditor
    /// (legacy opt-ins) nothing is bound.
    #[test]
    fn query_binding_rejects_mismatched_certificates() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        let (sh, m) = (shape(), 4usize);
        for fam in [StreamFamily::CmOmc, StreamFamily::BloomOmc] {
            let batches: Vec<Vec<u32>> =
                (0..3u32).map(|i| (1..=4).map(|k| k * 5 + i * 11).collect()).collect();
            let Some(mut audit) = QueryAudit::new(fam, &sh, m) else {
                eprintln!("skipped: binding off under a legacy opt-in");
                return;
            };
            let (leaves, _, arts) =
                prove_leaves(fam, sh, &batches, &[2, 3], QueryKeyMode::First, Some(&audit.decode_vk));
            let log = super::super::dist_compose::stream_batch_log(fam, &sh, m, &batches);
            let other: Vec<Vec<u32>> = batches.iter().rev().cloned().collect();
            let other_log = super::super::dist_compose::stream_batch_log(fam, &sh, m, &other);
            let leaf = |k: usize| (k as u64, k as u64, ForestShape::Leaf, CtxProof::Proof(&leaves[k - 1].output.0));
            let fresh = |a: &QueryArt| QueryArt {
                at_leaf: a.at_leaf,
                prove_ms: 0.0,
                verify_ms: 0.0,
                proof_bytes: 0,
                statement: a.statement,
                bind: None,
            };
            // Honest: query at t'=2 with leaves 1..2 (per-batch certificate).
            let mut q2 = fresh(&arts[0]);
            assert_eq!(q2.at_leaf, 2);
            audit.bind(&mut q2, &[leaf(1), leaf(2)], &log).expect("honest certificate");
            assert_eq!(q2.bind.map(|b| b.ctx_proofs), Some(2), "{fam:?}");
            // Stale: the query at t'=3 with the certificate of t'=2.
            let mut q3 = fresh(&arts[1]);
            let e = audit.bind(&mut q3, &[leaf(1), leaf(2)], &log).unwrap_err();
            assert!(e.contains("certify [1, 2]"), "{fam:?}: {e}");
            // The query at t'=2 answered against S_2 but offered leaves 1..3.
            let mut q2b = fresh(&arts[0]);
            assert!(audit.bind(&mut q2b, &[leaf(1), leaf(2), leaf(3)], &log).is_err(), "{fam:?}: past t'");
            // A log with other batches: the leaves' digests no longer match.
            let mut q2c = fresh(&arts[0]);
            let e = audit.bind(&mut q2c, &[leaf(1), leaf(2)], &other_log).unwrap_err();
            assert!(e.contains("digest") || e.contains("Com(S_0)"), "{fam:?}: {e}");
            // The query proof's Com(S) is not the certified one (S_3 vs S_2).
            let mut q3b = fresh(&arts[1]);
            q3b.at_leaf = 2;
            let e = audit.bind(&mut q3b, &[leaf(1), leaf(2)], &log).unwrap_err();
            assert!(e.contains("not the certified"), "{fam:?}: {e}");
            // Nothing exposed (legacy decoder): nothing to bind.
            let mut q0 = fresh(&arts[0]);
            q0.statement = None;
            assert!(audit.bind(&mut q0, &[leaf(1), leaf(2)], &log).is_err(), "{fam:?}");
        }
    }

    /// The procs engine's query replay ([`prove_queries_only`], no update
    /// leaf) and the sim engine's interleaved queries ([`prove_leaves`]) pin
    /// to the same Bloom decode VK and expose the SAME statements
    /// `(Com(S_{t'}), record(key), answer)` for every query-key mode, and the
    /// replay's answers bind to the certified history with the leaves' prefix
    /// certificate (what the coordinator assembles from the workers' bytes).
    #[test]
    fn bloom_query_replay_matches_sim_and_binds() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        let (sh, m, fam) = (shape(), 4usize, StreamFamily::BloomOmc);
        let Some(mut audit) = QueryAudit::new(fam, &sh, m) else {
            eprintln!("skipped: binding off under a legacy opt-in");
            return;
        };
        let base: Vec<u32> = (1..=10).map(|k| k * 7 + 1).collect();
        let (batches, query_at, _, _) = build_query_schedule_batches(&base, 10, 4, 3, fam);
        let log = super::super::dist_compose::stream_batch_log(fam, &sh, m, &batches);
        for mode in [QueryKeyMode::First, QueryKeyMode::UniformStream, QueryKeyMode::Absent] {
            let (leaves, _, sim) =
                prove_leaves(fam, sh, &batches, &query_at, mode, Some(&audit.decode_vk));
            let mut replay =
                prove_queries_only(fam, sh, &batches, &query_at, mode, Some(&audit.decode_vk));
            assert_eq!(replay.len(), query_at.len(), "{mode:?}");
            for (a, b) in sim.iter().zip(&replay) {
                assert_eq!((a.at_leaf, a.statement), (b.at_leaf, b.statement), "{mode:?}");
            }
            for q in replay.iter_mut() {
                let parts: Vec<CtxPart<'_>> = (1..=q.at_leaf)
                    .map(|k| (k as u64, k as u64, ForestShape::Leaf, CtxProof::Proof(&leaves[k - 1].output.0)))
                    .collect();
                audit.bind(q, &parts, &log).expect("replayed answer binds");
            }
            if mode == QueryKeyMode::First {
                // The first key of every batch is a member: no false negative.
                use p3_field::PrimeCharacteristicRing;
                let one = crate::decode::QueryStatement::new([Val::ZERO; 8], 0, 1).answer;
                assert!(replay.iter().all(|q| q.statement.unwrap().answer == one));
            }
        }
    }
}
