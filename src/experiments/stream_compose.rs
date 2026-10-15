//! **Multi-family streaming proof composition** (paper §Streaming Proof
//! Composition, generalised beyond Count-Min).
//!
//! Benchmarks the three composition modes — **per-batch proof chain**, the
//! **recursive linear chain**, and the **streaming forest** — over a stream of
//! `t = ⌈N/m⌉` transition leaves, for six sketch families each pinned to one
//! leaf variant:
//!
//! | family | variant           | leaf prover (exposed)          |
//! |--------|-------------------|--------------------------------|
//! | cm     | omc               | `prove_countmin_omc_exposed`   |
//! | hll    | omc               | `prove_hll_omc_exposed`        |
//! | ss     | certified         | `prove_ss_full_exposed`        |
//! | gk     | bandmerge2        | `prove_gkb2_exposed`           |
//! | bloom  | omc               | `build_bloom_omc_leaf_expose`  |
//! | bloom  | packed (B1, M2)   | `build_bloom_packed_leaf_commit` |
//! | kmv    | kmv (bottom-`k`)  | `build_kmv_leaf_commit`        |
//!
//! (The first four are the measured families; the Bloom filter, a generality
//! instance of the timestamped OR rebind, and the KMV / bottom-`k`
//! distinct-count sketch, a verified sorted reduction, run through the same
//! harness.)
//!
//! All six leaves surface their `(Com(S_{i-1}), Com(S_i))` boundary via the
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
//! the public batch log (`Com(S_0)`, `Com(S_T)` and every `Com(B_t)`, which
//! the PROVER publishes: `dist_compose::publish_batch_log`) under the fold's
//! bracketing. Where the auditor holds LEAF proofs directly (per_batch,
//! and the lone leaf of a one-batch stream) it pins each one to the leaf VK
//! derived from public parameters, STARK-verifies it, and checks its statement
//! against its log entry and the boundary chain; the reported verify time is
//! that audit. `ZKSKETCH_STATEMENT=boundary` (or `ZKSKETCH_BINDING=legacy`)
//! selects the pre-B6(b) Boundary layout for side-by-side runs, with a loud
//! warning that the batch log is then NOT checked.
//!
//! **Hiding commitments (B2).** Every measurement takes the run's
//! [`ProverCommit`] (read once by the runner: `ZKSKETCH_COMMIT`, default
//! `hiding`, plus the salt seed). Under `Hiding` each leaf `t` (every batch,
//! query-sealed and padded ones included) is built with the family's
//! `*_commit` builder and proved with `prove_epoch_commit(t, .., openings of
//! leaf t)`; a query at version `t'` opens `Com(S_{t'}; ρ^S_{t'})` with the
//! same randomizer leaf `t'` closed its state with, so its exposed commitment
//! is leaf `t'`'s final. The published log is built prover-side, and the
//! auditor ([`super::audit`]) sees only the log, the proofs and public
//! parameters. `ZKSKETCH_COMMIT=plain` is the pre-B2 path byte for byte.
//!
//! ## Mixed updates + queries (`query_at`)
//!
//! With a non-empty `query_at` schedule (1-based batch indices), a **query
//! leaf** (the family's `src/decode/*` circuit: cm point count, hll
//! cardinality, ss top-1 mass, gk rank, bloom membership, kmv distinct
//! count) is proved after each listed batch
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use rayon::ThreadPoolBuilder;

use crate::commitment::hiding::{CommitFamily, CommitMode, SaltBb};
use crate::config::Val;
use crate::decode::bloom::{bloom_query_input, prove_bloom_query, prove_bloom_query_commit};
use crate::decode::bloom_packed::prove_bloom_packed_query_commit;
use crate::decode::countmin::{prove_cm_decode, prove_cm_decode_commit, CmDecodeParams};
use crate::decode::gk_bandmerge::{prove_gk2_decode, prove_gk2_decode_commit, Gkb2DecodeParams};
use crate::decode::hyperloglog::{
    prove_hll_decode_omc, prove_hll_decode_omc_commit, HllDecodeParams,
};
use crate::decode::kmv::{prove_kmv_decode_commit, prove_kmv_decode_with, KmvDecodeParams};
use crate::decode::spacesaving::{prove_ss_decode, prove_ss_decode_commit, SsDecodeParams};
use crate::decode::{verify_decode_proof, DecodeProof, DecodeVk, QueryStatement, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::{prove_hiding_merge, ForestCascade};
use crate::recursion::recursive::root_vk::ForestShape;
use crate::recursion::recursive::statement::{
    composition_expose, warn_boundary_layout, BatchLog, Expose,
};
use crate::recursion::recursive::timing;
use crate::sketch::bind::default_binding;
use p3_recursion::RecursionOutput;

use crate::sketch::bloom_omc::{
    bloom_empty, bloom_insert, build_bloom_omc_leaf_commit, commit_bloom, commit_bloom_with,
    BloomOmcParams,
};
use crate::sketch::bloom_packed::{
    build_bloom_packed_leaf_commit, commit_packed_with, packed_empty, packed_insert, BloomPackedParams,
};
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_omc::{build_countmin_omc_leaf_commit, countmin_omc_advance, CmOmcParams};
use crate::sketch::gk_bandmerge::{
    apply_batch2, build_gkb2_leaf_rounds, commit_gk2_state, commit_gk2_state_with, Gk2State, GkRounds,
    GkbParams,
};
use crate::sketch::hll_omc::{
    build_hll_omc_leaf_commit, commit_hll_omc, commit_hll_omc_with, hll_omc_advance, hll_omc_empty,
    HllOmcParams,
};
use crate::sketch::kmv::{
    build_kmv_leaf_commit, commit_kmv_state, commit_kmv_state_with, kmv_advance, KmvParams,
    KmvState,
};
use crate::sketch::ss_final_full::{
    apply_batch_ss_full, build_ss_full_leaf_commit, commit_ss_state, commit_ss_state_with,
    SsFullParams, SsFullState, SsFullUpdate,
};

use super::audit::{audit_leaves, audit_root, check_query_exposure, compose_trusted_vk, PublicParams};
// The query-side auditor lives in `audit.rs` (whose source-level test keeps
// every prover secret out of it); re-exported under the paths the engines use.
pub(crate) use super::audit::{ContextStore, CtxPart, CtxProof, QueryAudit, QueryBind};
use super::families::cm_empty;
use super::metrics::{bench, read_vmrss_kb, BenchCfg, RunOutcome};
use super::proof_size;
use super::prover_commit::ProverCommit;

use crate::commitment::countmin::{commit_countmin, commit_countmin_with};

/// The (family, variant) leaf types the composition benchmark folds: the four
/// measured families, their Goldilocks variants, the Bloom filter and the
/// KMV / bottom-`k` sketch.
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
    /// The SAME partitioned Bloom filter with its state packed 8 bits per
    /// byte (design B1, milestone M2; `crate::sketch::bloom_packed`):
    /// per-access timestamped memory checking over bytes, split-at-bit OR,
    /// commitment family 7. Bit-for-bit the filter and the answers of
    /// [`Self::BloomOmc`], with its own leaf / decode / merge / root VKs.
    /// Selected by the token `bloom_packed`, or by `bloom` under
    /// `EXP_BLOOM_VARIANT=packed` ([`bloom_variant_from_env`]).
    BloomPacked,
    /// KMV / bottom-`k` distinct counting (`crate::sketch::kmv`): the `k`
    /// smallest distinct 27-bit key hashes, a verified sorted reduction of
    /// `S_{t-1} ⊎ B_t` ([`StreamShape::kmv_k`]); its query is the
    /// distinct-count estimate (`crate::decode::kmv`). BabyBear only: there
    /// is no Goldilocks KMV leaf.
    KmvSketch,
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
            "bloom_packed" | "bloompacked" | "bloom_b1" => Some(Self::BloomPacked),
            "kmv" | "kmv_sketch" | "bottom_k" | "bottomk" => Some(Self::KmvSketch),
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
            Self::BloomPacked => "bloom_packed",
            Self::KmvSketch => "kmv",
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
            Self::BloomPacked => "bloom",
            Self::KmvSketch => "kmv",
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

/// The Bloom leaf the harness's `bloom` family token selects while the M2
/// packed leaf is under review: the bit-array `omc` leaf.
pub const HARNESS_DEFAULT_BLOOM_VARIANT: StreamFamily = StreamFamily::BloomOmc;

/// The Bloom leaf variant a `bloom` family token selects:
/// `EXP_BLOOM_VARIANT=omc|packed` (unset or empty =
/// [`HARNESS_DEFAULT_BLOOM_VARIANT`]). The explicit tokens `bloom_omc` and
/// `bloom_packed` ignore it. A PUBLIC parameter (the two variants prove the
/// same filter under different leaf, decode and root VKs and commitment
/// families); the CSV `variant` column records it. A bad value panics.
pub fn bloom_variant_from_env() -> StreamFamily {
    match std::env::var("EXP_BLOOM_VARIANT") {
        Err(_) => HARNESS_DEFAULT_BLOOM_VARIANT,
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "" => HARNESS_DEFAULT_BLOOM_VARIANT,
            "omc" | "bits" => StreamFamily::BloomOmc,
            "packed" | "b1" | "bytes" => StreamFamily::BloomPacked,
            other => panic!("EXP_BLOOM_VARIANT={other}: omc | packed"),
        },
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// KMV: capacity `k` = the number of smallest distinct hash values kept
    /// (a multiple of 4 in `4..=2^15`, `k + m < 2^24`).
    pub kmv_k: usize,
    /// GK band-merge: how the leaf certifies its fusion rounds
    /// ([`GkRounds`], `EXP_GK_ROUNDS`). A PUBLIC parameter: the two variants
    /// prove the same batch rule under different leaf (hence merge and root)
    /// VKs, so the workers, the no-op VK-derivation leaf and the auditor all
    /// build the leaf from this field.
    pub gk_rounds: GkRounds,
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

    /// The packed Bloom leaf / query parameters at batch size `m` (the same
    /// `(bloom_k, bloom_log_w)` filter as [`Self::bloom_params`]). Panics on a
    /// bad shape; see [`Self::check_bloom_packed`].
    pub fn bloom_packed_params(&self, m: usize) -> BloomPackedParams {
        self.check_bloom_packed(m).unwrap_or_else(|e| panic!("{e}"))
    }

    /// [`Self::bloom_packed_params`] without the panic (adds the packed
    /// leaf's `k·m < 2^16` timestamp bound to the bit-array leaf's checks).
    pub fn check_bloom_packed(&self, m: usize) -> Result<BloomPackedParams, String> {
        let p = BloomPackedParams { k: self.bloom_k, log_w: self.bloom_log_w, batch: m };
        p.check()?;
        Ok(p)
    }

    /// The KMV leaf parameters at batch size `m`. Panics on a bad `(k, m)`;
    /// a runner that takes the shape from configuration calls
    /// [`Self::check_kmv`] first so the reason is reported.
    pub fn kmv_params(&self, m: usize) -> KmvParams {
        self.check_kmv(m).unwrap_or_else(|e| panic!("{e}"))
    }

    /// [`Self::kmv_params`] without the panic: the parameters, or why
    /// `(kmv_k, m)` is not a valid KMV leaf shape.
    pub fn check_kmv(&self, m: usize) -> Result<KmvParams, String> {
        let p = KmvParams { k: self.kmv_k, batch: m };
        p.check()?;
        Ok(p)
    }

    /// The KMV distinct-count decoder parameters (identity release).
    pub fn kmv_decode_params(&self) -> KmvDecodeParams {
        KmvDecodeParams { k: self.kmv_k, release: ReleasePolicy::Identity }
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

/// `EXP_QUERY_LOG=1`: print one stderr line per query event (`QLOG_KEY` probe
/// key, `QLOG_QUERY` decode prove/verify/bytes/answer, `QLOG_BIND` prefix
/// certificate and binding cost), the per-query detail the CSV only sums.
/// Logging only: no proof, timing window or CSV column changes.
pub(crate) fn qlog_on() -> bool {
    std::env::var("EXP_QUERY_LOG").map(|v| v == "1").unwrap_or(false)
}

/// `EXP_VERIFY_REPEATS=R` (read only under `EXP_QUERY_LOG=1`; default 1):
/// after the timed first verification of a query proof or of a prefix
/// certificate part (the value the CSV reports, unchanged), verify the same
/// proof `R - 1` more times and log every time (`QLOG_VERIFY`, `QLOG_BINDV`),
/// so a min / median of `R` warm runs can be compared with a baseline that
/// reports one. Outside every timed window of the CSV.
pub(crate) fn qlog_verify_repeats() -> usize {
    if !qlog_on() {
        return 1;
    }
    std::env::var("EXP_VERIFY_REPEATS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&r| r >= 1)
        .unwrap_or(1)
}

/// `(VmHWM, VmRSS)` of this process in MB (0 when unreadable).
pub(crate) fn qlog_mem_mb() -> (f64, f64) {
    let (mut hwm, mut rss) = (0.0, 0.0);
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            let kb = |rest: &str| {
                rest.split_whitespace().next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) as f64
                    / 1024.0
            };
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                hwm = kb(rest);
            } else if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss = kb(rest);
            }
        }
    }
    (hwm, rss)
}

/// Reset this process's peak-RSS high-water mark (`VmHWM`) to its current RSS
/// (Linux `/proc/self/clear_refs` value 5), so the next [`qlog_mem_mb`] reads
/// the peak of the work in between. Best effort, logging only.
pub(crate) fn qlog_reset_hwm() -> bool {
    std::fs::write("/proc/self/clear_refs", "5").is_ok()
}

/// `a;b;c` with 3 decimals.
pub(crate) fn qlog_join(v: &[f64]) -> String {
    v.iter().map(|x| format!("{x:.3}")).collect::<Vec<_>>().join(";")
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
    pub(crate) statement: Option<QueryStatement>,
    /// Set once [`QueryAudit::bind`] has certified `statement.commit` as
    /// `Com(S_{t'})`.
    pub(crate) bind: Option<QueryBind>,
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

/// Record one query event: take the decode prover's timings, check the
/// prover-side consistency (the state the query circuit hashed must be
/// exactly the leaf-boundary commitment at `t'`; under `Hiding` both are
/// `Com(S_{t'}; ρ^S_{t'})`, the decoder having opened the state with the same
/// randomizer leaf `t'` closed it with), and, with a trusted `decode_vk` (the
/// decoder of the run's commitment mode), have the auditor verify the query
/// proof pinned to it and check the exposed query and answer
/// ([`verify_decode_proof`], timed as the query verify); the exposed `Com(S)`
/// is kept for [`QueryAudit::bind`], which ties it to the certified history.
/// `leaf_final` is a PROVER-side value, never what binds the answer. Without
/// a VK (legacy opt-ins) the exposure is checked against the native replay
/// only ([`check_query_exposure`]) and the prover's self-verify time is
/// reported.
/// `query` is the keyed families' query as the decoder exposes it
/// ([`cm_query`] for a cm key, [`scalar_query`] for ss `c` / gk value,
/// [`bloom_query`] for a Bloom key); `None` for hll (cardinality) and kmv
/// (distinct count), which take no query.
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
    let prove_ms = (tm.witness + tm.prove).as_secs_f64() * 1000.0;
    let proof_bytes = dp.proof_size() as u64;
    if qlog_on() {
        eprintln!(
            "QLOG_QUERY,at_leaf={at_leaf},prove_ms={prove_ms:.3},witness_ms={:.3},verify_ms={verify_ms:.3},proof_bytes={proof_bytes},answer={}",
            tm.witness.as_secs_f64() * 1000.0,
            dp.answer
        );
        // Peak RSS since the reset in `prove_query_at`: witness + prove + the
        // first verify of this one query.
        let (hwm, rss) = qlog_mem_mb();
        eprintln!("QLOG_MEM,at_leaf={at_leaf},query_hwm_mb={hwm:.1},rss_end_mb={rss:.1}");
        // Warm repeats of the same pinned verification (not in the CSV).
        if let Some(vk) = decode_vk {
            let mut times = vec![verify_ms];
            for _ in 1..qlog_verify_repeats() {
                let t0 = std::time::Instant::now();
                verify_decode_proof(&dp.output.0, vk)
                    .unwrap_or_else(|e| panic!("query proof at t'={at_leaf} (repeat): {e}"));
                times.push(t0.elapsed().as_secs_f64() * 1000.0);
            }
            eprintln!("QLOG_VERIFY,at_leaf={at_leaf},decode_verify_ms={}", qlog_join(&times));
        }
    }
    queries.push(QueryArt { at_leaf, prove_ms, verify_ms, proof_bytes, statement, bind: None });
}

/// **PROVER side.** One query proof at version `t` (1-based leaf index;
/// `0` = the genesis state) plus the native commitment it opens: `Plain` is
/// the pre-B2 decoder and `commit_*` call; `Hiding` opens `Com(S_t; ρ^S_t)`
/// with the run's randomizer `commit.state_salt(family, t)` (the public zero
/// at `t = 0` only), i.e. exactly the value leaf `t` exposed as its final.
enum QueryState<'a> {
    Cm(&'a CountMinState, u64),
    Hll(&'a [u64], usize),
    Ss(&'a SsFullState, usize),
    Gk(&'a Gk2State, u32),
    /// The filter bits, its shape (`batch` ignored) and the probe key.
    Bloom(&'a [u8], BloomOmcParams, u64),
    /// The packed filter's bytes, its shape (`batch` ignored) and the key.
    BloomPacked(&'a [u8], BloomPackedParams, u64),
    /// The KMV state (its capacity is `state.k`); keyless.
    Kmv(&'a KmvState),
}

fn prove_query_at(
    q: QueryState<'_>,
    t: usize,
    commit: &ProverCommit,
) -> (DecodeProof, [Val; 8]) {
    // The previous query's freed memory goes back to the OS first
    // (`EXP_MALLOC_TRIM`; outside the query's own timing).
    super::metrics::trim_heap();
    let mode = commit.mode();
    let id = ReleasePolicy::Identity;
    if qlog_on() {
        let key = match &q {
            QueryState::Cm(_, k) => format!("cm_key={k}"),
            QueryState::Gk(_, v) => format!("gk_value={v}"),
            QueryState::Bloom(_, _, k) | QueryState::BloomPacked(_, _, k) => format!("bloom_key={k}"),
            QueryState::Ss(_, c) => format!("ss_c={c}"),
            QueryState::Hll(_, b) => format!("hll_b={b}"),
            QueryState::Kmv(s) => format!("kmv_k={}", s.k),
        };
        eprintln!("QLOG_KEY,at_leaf={t},{key}");
        // Peak RSS of this query alone: reset the high-water mark here; read
        // back in `record_query` (`QLOG_MEM`).
        let reset = qlog_reset_hwm();
        let (_, rss) = qlog_mem_mb();
        eprintln!("QLOG_MEMSTART,at_leaf={t},hwm_reset={reset},rss_start_mb={rss:.1}");
    }
    // The version's randomizer. Under `Hiding` only the genesis state (t = 0)
    // opens with the public zero; a zero salt at t ≥ 1 would publish the
    // guess-checkable `Com(S_t; 0)`, so refuse it here (an honest PRF output
    // is zero with probability ~2^-371). Version 0 is the public EMPTY
    // sketch: a query there must open exactly the genesis anchor, so any
    // other state at t = 0 (which would publish its own `Com(S; 0)`) is
    // refused too. `is_genesis` compares the state's commitment with the
    // empty sketch's; it runs only at t = 0 (never reached by the harness
    // schedules, whose queries follow a batch).
    let salt_of = |fam: CommitFamily, is_genesis: &dyn Fn() -> bool| -> SaltBb {
        let salt = commit.state_salt(fam, t as u64);
        if mode.is_hiding() {
            if t == 0 {
                assert!(
                    is_genesis(),
                    "hiding query at version 0 opens the public zero randomizer: only the genesis (empty) state may"
                );
            } else {
                assert!(
                    !salt.is_zero(),
                    "hiding query at version {t}: needs the version's secret randomizer, not the public zero"
                );
            }
        }
        salt
    };
    match q {
        QueryState::Cm(state, key) => {
            let params = CmDecodeParams { d: state.params.d, w: state.params.w, release: id };
            match mode {
                CommitMode::Plain => (prove_cm_decode(params, state.clone(), key), commit_countmin(state).0),
                CommitMode::Hiding => {
                    let salt = salt_of(CommitFamily::CountMin, &|| {
                        commit_countmin(state).0 == commit_countmin(&cm_empty(params.d, params.w)).0
                    });
                    (
                        prove_cm_decode_commit(params, state.clone(), key, default_binding(), mode, &salt),
                        commit_countmin_with(state, mode, &salt).0,
                    )
                }
            }
        }
        QueryState::Hll(regs, b) => {
            let params = HllDecodeParams { b, release: id };
            match mode {
                CommitMode::Plain => (prove_hll_decode_omc(params, regs.to_vec(), 0), commit_hll_omc(regs, b)),
                CommitMode::Hiding => {
                    let salt = salt_of(CommitFamily::HyperLogLog, &|| {
                        commit_hll_omc(regs, b) == commit_hll_omc(&hll_omc_empty(b), b)
                    });
                    (
                        prove_hll_decode_omc_commit(params, regs.to_vec(), 0, default_binding(), mode, &salt),
                        commit_hll_omc_with(regs, b, mode, &salt),
                    )
                }
            }
        }
        QueryState::Ss(state, c) => {
            let params = SsDecodeParams { capacity: state.params.capacity, c, release: id };
            match mode {
                CommitMode::Plain => (prove_ss_decode(params, state.clone(), c), commit_ss_state(state).0),
                CommitMode::Hiding => {
                    let salt = salt_of(CommitFamily::SpaceSaving, &|| {
                        commit_ss_state(state).0 == commit_ss_state(&SsFullState::empty(state.params)).0
                    });
                    (
                        prove_ss_decode_commit(params, state.clone(), c, default_binding(), mode, &salt),
                        commit_ss_state_with(state, mode, &salt).0,
                    )
                }
            }
        }
        QueryState::Gk(state, qval) => {
            let params = Gkb2DecodeParams { capacity: state.params.capacity, release: id };
            match mode {
                CommitMode::Plain => (prove_gk2_decode(params, state.clone(), qval), commit_gk2_state(state).0),
                CommitMode::Hiding => {
                    let salt = salt_of(CommitFamily::GreenwaldKhanna, &|| {
                        commit_gk2_state(state).0 == commit_gk2_state(&Gk2State::empty(state.params)).0
                    });
                    (
                        prove_gk2_decode_commit(params, state.clone(), qval, default_binding(), mode, &salt),
                        commit_gk2_state_with(state, mode, &salt).0,
                    )
                }
            }
        }
        QueryState::Bloom(bits, params, key) => match mode {
            CommitMode::Plain => (prove_bloom_query(params, bits, key), commit_bloom(bits)),
            CommitMode::Hiding => {
                let salt = salt_of(CommitFamily::Bloom, &|| bits.iter().all(|&x| x == 0));
                (
                    prove_bloom_query_commit(params, bits, key, mode, &salt),
                    commit_bloom_with(bits, mode, &salt),
                )
            }
        },
        QueryState::BloomPacked(words, params, key) => {
            // Plain: the salt is ignored (the plain commitment).
            let salt = if mode.is_hiding() {
                salt_of(CommitFamily::BloomPacked, &|| words.iter().all(|&x| x == 0))
            } else {
                SaltBb::ZERO
            };
            (
                prove_bloom_packed_query_commit(params, words, key, mode, &salt),
                commit_packed_with(&params, words, mode, &salt),
            )
        }
        QueryState::Kmv(state) => {
            let params = KmvDecodeParams { k: state.k, release: id };
            match mode {
                CommitMode::Plain => {
                    (prove_kmv_decode_with(params, state, default_binding()), commit_kmv_state(state))
                }
                CommitMode::Hiding => {
                    let salt = salt_of(CommitFamily::Kmv, &|| state.vals.is_empty());
                    (
                        prove_kmv_decode_commit(params, state, default_binding(), mode, &salt),
                        commit_kmv_state_with(state, mode, &salt),
                    )
                }
            }
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
/// (membership); hll (cardinality), ss (top-1) and kmv (distinct count) take
/// no probe key and ignore the mode.
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
//   kmv → the canonical dummy record IN PLACE (`None`: `act = 0`, all-zero
//         limbs), which enters the sorted union as the never-kept sentinel

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

/// KMV records of a wire batch, slot for slot: a real key `Some(k)`, and a
/// `PAD_KEY` slot the canonical dummy record `None` (`act = 0`, all-zero
/// limbs: it enters the sorted union as the sentinel `(0, 0)` and is never
/// kept, a provable no-op). The leaf, the batch commitment
/// ([`crate::sketch::kmv::kmv_batch_commit`]) and the native replay
/// ([`kmv_advance_records`]) all take exactly this sequence.
pub fn kmv_records_of(batch: &[u32]) -> Vec<Option<u64>> {
    batch.iter().map(|&k| (k != PAD_KEY).then_some(k as u64)).collect()
}

/// The native KMV batch rule over a record sequence (dummies contribute
/// nothing): `bottom_k(S ∪ {h(x) : x a real record})`.
pub fn kmv_advance_records(state: &KmvState, records: &[Option<u64>]) -> KmvState {
    let keys: Vec<u64> = records.iter().flatten().copied().collect();
    kmv_advance(state, &keys)
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
/// The replay is the PROVER's: it needs the state to answer. Each query at
/// version `t'` is proved with the run's commitment context ([`prove_query_at`]:
/// under `Hiding` it opens `Com(S_{t'}; ρ^S_{t'})`), and `record_query`
/// checks, prover side, that the replay's commitment equals
/// `leaf_finals[t' - 1]`, the final commitment the workers' leaf proof for
/// batch `t'` exposed (reported over the socket,
/// `dist_compose::FromWorker::LeafFinal`), so a query opening another
/// version's randomizer or another state fails the cell. The answer is tied
/// to the update proofs by the AUDITOR, not by this replay: each query proof
/// is pinned to `decode_vk` (the decoder of the run's commitment mode,
/// [`record_query`]) and its exposed `Com(S)` is later bound by
/// [`ContextStore::bind_all`] to the `Com(S_{t'})` that the interval proofs
/// the workers shipped certify ([`QueryAudit::bind`]) against the published
/// batch log.
fn prove_queries_only(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
    commit: &ProverCommit,
    leaf_finals: &[[Val; 8]],
    decode_vk: Option<&DecodeVk>,
) -> Vec<QueryArt> {
    let mut queries: Vec<QueryArt> = Vec::new();
    if query_at.is_empty() {
        return queries;
    }
    assert_eq!(leaf_finals.len(), batches.len(), "one reported leaf final per batch");
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
                    let (dp, c) = prove_query_at(QueryState::Cm(&state, key), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_finals[bi], Some(cm_query(key)), decode_vk);
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
                    let (dp, c) = prove_query_at(QueryState::Hll(&regs, b), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_finals[bi], None, decode_vk);
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
                    let (dp, c) = prove_query_at(QueryState::Ss(&state, 1), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_finals[bi], Some(scalar_query(1)), decode_vk);
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
                    let (dp, c) = prove_query_at(QueryState::Gk(&state, qval), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_finals[bi], Some(scalar_query(qval as u64)), decode_vk);
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
                    let (dp, c) = prove_query_at(QueryState::Bloom(&bits, params, key), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_finals[bi], Some(bloom_query(key)), decode_vk);
                }
            }
        }
        StreamFamily::BloomPacked => {
            let params = shape.bloom_packed_params(batches[0].len());
            let mut words = packed_empty(&params);
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                let keys = bloom_keys_of(batch);
                packed_insert(&mut words, &params, &keys);
                if track_freq {
                    for &k in &keys {
                        *freq.entry(k).or_insert(0) += 1;
                    }
                }
                if query_due(bi) {
                    let key =
                        select_query_key(query_key_mode, &freq, batch[0] as u64, (bi + 1) as u64, 0xFFFF_FFFF);
                    let (dp, c) = prove_query_at(QueryState::BloomPacked(&words, params, key), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_finals[bi], Some(bloom_query(key)), decode_vk);
                }
            }
        }
        StreamFamily::KmvSketch => {
            let params = shape.kmv_params(batches[0].len());
            let mut state = KmvState::empty(params.k);
            for (bi, batch) in batches.iter().enumerate() {
                state = kmv_advance_records(&state, &kmv_records_of(batch));
                if query_due(bi) {
                    // Distinct-count query (no probe key).
                    let (dp, c) = prove_query_at(QueryState::Kmv(&state), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_finals[bi], None, decode_vk);
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
/// `leaf_finals[t - 1]` is the final commitment leaf `t`'s proof exposed (as
/// its worker reported it); each query at version `t'` must open exactly
/// `leaf_finals[t' - 1]` (a prover-side check; a mismatch fails the cell).
///
/// With `bind = Some((audit, store, log))` (the procs coordinators' default),
/// every query proof is pinned to the auditor's decode VK (of the run's
/// commitment mode) and its answer is bound to the certified history with
/// the prefix certificates the workers shipped ([`ContextStore::bind_all`])
/// against `log`, the batch log the auditor holds (under `Hiding` the one
/// the prover published), inside the same pool. Without it the answers are
/// unbound (legacy opt-ins, and the engine-free unit test).
#[allow(clippy::too_many_arguments)]
pub(crate) fn measure_queries_dist(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
    commit: &ProverCommit,
    leaf_finals: &[[Val; 8]],
    bind: Option<(&mut QueryAudit, &ContextStore, &BatchLog<Val>)>,
) -> Result<QueryAgg, String> {
    if query_at.is_empty() || batches.is_empty() {
        return Ok(QueryAgg::default());
    }
    let pool = ThreadPoolBuilder::new()
        .num_threads(cores.max(1))
        .build()
        .expect("query pool");
    let out = pool.install(|| {
        match bind {
            Some((audit, store, log)) => {
                let mut arts = prove_queries_only(
                    family,
                    shape,
                    batches,
                    query_at,
                    query_key_mode,
                    commit,
                    leaf_finals,
                    Some(&audit.decode_vk),
                );
                store.bind_all(audit, &mut arts, log)?;
                Ok(aggregate_queries(&arts, mode))
            }
            None => {
                let arts = prove_queries_only(
                    family,
                    shape,
                    batches,
                    query_at,
                    query_key_mode,
                    commit,
                    leaf_finals,
                    None,
                );
                Ok(aggregate_queries(&arts, mode))
            }
        }
    });
    super::metrics::trim_heap(); // `EXP_MALLOC_TRIM`
    out
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
/// the batch's first key), as does bloom membership; hll = cardinality,
/// ss = top-1 heavy-hitter mass and kmv = distinct count are keyless and
/// ignore the mode.
fn prove_leaves(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
    commit: &ProverCommit,
    decode_vk: Option<&DecodeVk>,
) -> (Vec<LeafArt>, [Val; 8], Vec<QueryArt>) {
    let m = batches[0].len();
    // Every batch is a REAL leaf (including query-sealed / split / padded
    // ones): under `Hiding` it opens with the prover's honest openings of
    // its global index `t` (`Openings::for_leaf(seed, family, t)`), never
    // the public-zero no-op path; `Plain` keeps `prove_epoch_at`.
    let mode = commit.mode();
    let cf = family.commit_family();
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
            let e = commit_countmin_with(&state, mode, &SaltBb::ZERO).0;
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                let ups = cm_updates_of(batch);
                let t = bi as u64 + 1;
                let mut l = build_countmin_omc_leaf_commit(
                    CmOmcParams { d, w, batch: m },
                    composition_expose(),
                    default_binding(),
                    mode,
                );
                let leaf = if commit.is_hiding() {
                    l.prove_epoch_commit(t, state.clone(), ups.clone(), &commit.openings(cf, t))
                } else {
                    l.prove_epoch_at(t, state.clone(), ups.clone())
                };
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
                    let (dp, c) = prove_query_at(QueryState::Cm(&state, key), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_final, Some(cm_query(key)), decode_vk);
                }
            }
            e
        }
        StreamFamily::HllOmc => {
            let StreamShape { b, .. } = shape;
            let m_reg = 1usize << b;
            let mut regs = hll_omc_empty(b);
            let e = commit_hll_omc_with(&regs, b, mode, &SaltBb::ZERO);
            for (bi, batch) in batches.iter().enumerate() {
                let keys = hll_keys_of(batch);
                let t = bi as u64 + 1;
                let mut l = build_hll_omc_leaf_commit(
                    HllOmcParams { b, batch: m },
                    composition_expose(),
                    default_binding(),
                    mode,
                );
                let leaf = if commit.is_hiding() {
                    l.prove_epoch_commit(t, regs.clone(), keys.clone(), &commit.openings(cf, t))
                } else {
                    l.prove_epoch_at(t, regs.clone(), keys.clone())
                };
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                hll_omc_advance(&mut regs, &keys, m_reg);
                if query_due(bi) {
                    // Cardinality query (no probe key).
                    let (dp, c) = prove_query_at(QueryState::Hll(&regs, b), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_final, None, decode_vk);
                }
            }
            e
        }
        StreamFamily::SsCertified => {
            let StreamShape { capacity, .. } = shape;
            let params = SsFullParams { capacity, batch: m };
            let mut state = SsFullState::empty(params);
            let e = commit_ss_state_with(&state, mode, &SaltBb::ZERO).0;
            for (bi, batch) in batches.iter().enumerate() {
                // Key mask (29-bit, low bit 1) + PAD_KEY→dummy live in the
                // canonical `ss_updates_of` mapping.
                let ups = ss_updates_of(batch);
                let t = bi as u64 + 1;
                let mut l = build_ss_full_leaf_commit(params, composition_expose(), mode);
                let leaf = if commit.is_hiding() {
                    l.prove_epoch_commit(t, state.clone(), ups.clone(), &commit.openings(cf, t))
                } else {
                    l.prove_epoch_at(t, state.clone(), ups.clone())
                };
                let leaf_final = leaf.final_.0;
                push(leaf.output, leaf.initial.0, leaf_final);
                state = apply_batch_ss_full(&state, &ups).0;
                if query_due(bi) {
                    // Top-1 heavy-hitter mass query.
                    let (dp, c) = prove_query_at(QueryState::Ss(&state, 1), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_final, Some(scalar_query(1)), decode_vk);
                }
            }
            e
        }
        StreamFamily::GkBandmerge2 => {
            let StreamShape { capacity, gk_s, .. } = shape;
            let params = GkbParams { capacity, batch: m, s: gk_s };
            let mut state = Gk2State::empty(params);
            let e = commit_gk2_state_with(&state, mode, &SaltBb::ZERO).0;
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                // 21-bit value mask (< E_MAX) + PAD_KEY stripping live in the
                // canonical `gk_vals_of` mapping (short batches are legal — the
                // leaf pads its fresh-tuple rows with E_MAX dummies itself).
                let vals = gk_vals_of(batch);
                let t = bi as u64 + 1;
                let mut l = build_gkb2_leaf_rounds(
                    params,
                    composition_expose(),
                    default_binding(),
                    mode,
                    shape.gk_rounds,
                );
                let leaf = if commit.is_hiding() {
                    l.prove_epoch_commit(t, state.clone(), vals.clone(), &commit.openings(cf, t))
                } else {
                    l.prove_epoch_at(t, state.clone(), vals.clone())
                };
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
                    let (dp, c) = prove_query_at(QueryState::Gk(&state, qval), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_final, Some(scalar_query(qval as u64)), decode_vk);
                }
            }
            e
        }
        StreamFamily::BloomOmc => {
            let params = shape.bloom_params(m);
            let mut bits = bloom_empty(&params);
            let e = commit_bloom_with(&bits, mode, &SaltBb::ZERO);
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                // PAD_KEY slots stripped into the leaf's canonical dummies
                // (the canonical `bloom_keys_of` mapping).
                let keys = bloom_keys_of(batch);
                let t = bi as u64 + 1;
                let mut l = build_bloom_omc_leaf_commit(params, composition_expose(), mode);
                let leaf = if commit.is_hiding() {
                    l.prove_epoch_commit(t, &bits, &keys, &commit.openings(cf, t))
                } else {
                    l.prove_epoch_at(t, &bits, &keys)
                };
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
                    let (dp, c) = prove_query_at(QueryState::Bloom(&bits, params, key), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_final, Some(bloom_query(key)), decode_vk);
                }
            }
            e
        }
        StreamFamily::BloomPacked => {
            let params = shape.bloom_packed_params(m);
            let mut words = packed_empty(&params);
            let e = commit_packed_with(&params, &words, mode, &SaltBb::ZERO);
            let mut freq: BTreeMap<u64, u64> = BTreeMap::new();
            for (bi, batch) in batches.iter().enumerate() {
                // The same record mapping as the bit-array leaf.
                let keys = bloom_keys_of(batch);
                let t = bi as u64 + 1;
                let mut l = build_bloom_packed_leaf_commit(params, composition_expose(), mode);
                let leaf = if commit.is_hiding() {
                    l.prove_epoch_commit(t, &words, &keys, &commit.openings(cf, t))
                } else {
                    l.prove_epoch_at(t, &words, &keys)
                };
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                packed_insert(&mut words, &params, &keys);
                if track_freq {
                    for &k in &keys {
                        *freq.entry(k).or_insert(0) += 1;
                    }
                }
                if query_due(bi) {
                    let key = select_query_key(
                        query_key_mode,
                        &freq,
                        batch[0] as u64,
                        (bi + 1) as u64,
                        0xFFFF_FFFF,
                    );
                    let (dp, c) = prove_query_at(QueryState::BloomPacked(&words, params, key), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_final, Some(bloom_query(key)), decode_vk);
                }
            }
            e
        }
        StreamFamily::KmvSketch => {
            let params = shape.kmv_params(m);
            let mut state = KmvState::empty(params.k);
            let e = commit_kmv_state_with(&state, mode, &SaltBb::ZERO);
            for (bi, batch) in batches.iter().enumerate() {
                // PAD_KEY slots become the canonical dummy record in place
                // (the canonical `kmv_records_of` mapping).
                let records = kmv_records_of(batch);
                let t = bi as u64 + 1;
                let mut l = build_kmv_leaf_commit(params, composition_expose(), default_binding(), mode);
                let leaf = if commit.is_hiding() {
                    l.prove_records_commit(t, state.clone(), records.clone(), &commit.openings(cf, t))
                } else {
                    l.prove_records_at(t, state.clone(), records.clone())
                };
                let leaf_final = leaf.final_commit;
                push(leaf.output, leaf.initial_commit, leaf_final);
                state = kmv_advance_records(&state, &records);
                if query_due(bi) {
                    // Distinct-count query (no probe key).
                    let (dp, c) = prove_query_at(QueryState::Kmv(&state), bi + 1, commit);
                    record_query(&mut queries, bi + 1, &dp, c, leaf_final, None, decode_vk);
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

// The auditor's trusted-VK derivation and its leaf / root checks live in
// [`super::audit`] (public inputs only: the published log, the proofs and
// [`PublicParams`]).

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
    commit: &ProverCommit,
) -> ComposeCell {
    assert!(!batches.is_empty(), "need at least one batch");
    let m = batches[0].len();
    assert!(batches.iter().all(|b| b.len() == m), "all batches must share length m");
    // What the auditor knows: public parameters (incl. the commitment mode),
    // never the prover's seed.
    let pp = PublicParams { family, shape, m, commit_mode: commit.mode() };

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
        let root_vk = compose_trusted_vk(&pp, mode, batches.len());
        // Mixed workload: the query-side auditor (the decode VK of the run's
        // commitment mode + the prefix auditor), likewise derived from public
        // parameters up front.
        let mut audit = if query_at.is_empty() {
            None
        } else {
            QueryAudit::new(family, &shape, m, commit.mode())
        };
        bench(BenchCfg { warmup: 0, trials: 1 }, || {
            let (leaves, empty_commit, mut query_arts) = prove_leaves(
                family,
                shape,
                batches,
                query_at,
                query_key_mode,
                commit,
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
                    // PROVER side: the published batch log (with the seed's
                    // randomizers under `Hiding`).
                    let log = super::dist_compose::publish_batch_log(family, &shape, m, batches, commit);
                    // AUDITOR (public inputs only): the genesis anchor, then
                    // every leaf pinned to the trusted LEAF VK (derived from
                    // public parameters, outside this pass), STARK-verified,
                    // and its exposed statement checked against the published
                    // batch log (Com(S_0) -> ... -> Com(S_T) chain; Interval:
                    // (t, t, H(TAG_LEAF, t, Com(B_t)))). Timed as the
                    // per-batch verify (the paper's Θ(t) cost).
                    let layout = composition_expose();
                    if layout != Expose::Interval {
                        warn_boundary_layout("stream_compose per-batch");
                    }
                    let proofs: Vec<_> = leaves.iter().map(|l| &l.output.0).collect();
                    let total_verify =
                        audit_leaves(&pp, &proofs, root_vk.as_ref(), &log, layout, self_verify);
                    // Mixed workload: a query at t' is certified by leaves 1..t',
                    // checked against the published log.
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
                    // PROVER side: the published batch log (Com(S_0),
                    // Com(S_T), Com(B_1..B_T); the seed's randomizers under
                    // `Hiding`). The bracketing the fold used is public. The
                    // query binding below checks each prefix certificate
                    // against this same published log.
                    let log = super::dist_compose::publish_batch_log(family, &shape, m, batches, commit);
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
                            // The single-process (sim) engine keeps the
                            // pre-M0 fold: its root must stay a whole
                            // `RecursionOutput` (`audit_root`), and every leaf
                            // is held in memory anyway.
                            let mut forest = ForestCascade::retaining(1);
                            let mut push_and_bind = |leaf, g: usize, forest: &mut ForestCascade| {
                                forest.push(leaf);
                                bind_due(&mut audit, &mut query_arts, g, || {
                                    forest
                                        .peaks()
                                        .into_iter()
                                        .map(|(lo, hi, p)| {
                                            let sh = ForestShape::forest((hi - lo + 1) as usize);
                                            (lo, hi, sh, CtxProof::Proof(p))
                                        })
                                        .collect()
                                }, &log)
                            };
                            bind_wall += push_and_bind(first, 1, &mut forest);
                            for (k, leaf) in outputs.enumerate() {
                                bind_wall += push_and_bind(leaf, k + 2, &mut forest);
                            }
                            forest
                                .finalize()
                                .0
                                .into_output()
                                .expect("a retaining cascade keeps the root's output")
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
                    // AUDITOR (public inputs only): one succinct check of the
                    // merged root, pinned to the derived root VK and bound to
                    // the published log ([`audit_root`]; t == 1: the lone
                    // leaf, audited as a leaf; see above).
                    let verify_ms = if single_leaf {
                        audit_leaves(&pp, &[&root.0], root_vk.as_ref(), &log, layout, single_verify_ms)
                    } else {
                        audit_root(&pp, &root, root_vk.as_ref(), &log, &tree, layout)
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
    use crate::commitment::hiding::SaltSeed;
    use crate::recursion::recursive::expose_forest::{prove_chain_over, read_exposed_statement};

    fn shape() -> StreamShape {
        StreamShape {
            d: 4,
            w: 8,
            b: 4,
            capacity: 4,
            gk_s: 2,
            bloom_k: 3,
            bloom_log_w: 7,
            kmv_k: 4,
            gk_rounds: GkRounds::SortedCopy,
        }
    }

    const FAMILIES: [StreamFamily; 6] = [
        StreamFamily::CmOmc,
        StreamFamily::HllOmc,
        StreamFamily::SsCertified,
        StreamFamily::GkBandmerge2,
        StreamFamily::BloomOmc,
        StreamFamily::KmvSketch,
    ];

    /// Both commitment contexts: `Plain` (pre-B2) and `Hiding` under a
    /// fixed, public test seed.
    fn both_modes() -> [ProverCommit; 2] {
        [ProverCommit::plain(), ProverCommit::hiding(SaltSeed::for_tests(3))]
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
    /// the same per-mode verifier-context count as the sim engine, under both
    /// commitment modes. The leaf finals it binds each query to are the real
    /// leaves' exposed finals (here from the sim engine's leaves; the procs
    /// coordinator gets them from its workers' `LeafFinal` reports).
    #[test]
    fn measure_queries_dist_matches_modes() {
        // Two batches, one query per batch ⇒ 2 query events at t'=1,2.
        let batches: Vec<Vec<u32>> = vec![(1..=4).collect(), (5..=8).collect()];
        for commit in both_modes() {
            let (leaves, _, _) = prove_leaves(
                StreamFamily::CmOmc, shape(), &batches, &[], QueryKeyMode::First, &commit, None,
            );
            let finals: Vec<[Val; 8]> = leaves.iter().map(|l| l.final_).collect();
            let run = |mode, query_at: &[usize]| {
                measure_queries_dist(
                    StreamFamily::CmOmc, shape(), &batches, mode, 1, query_at, QueryKeyMode::First,
                    &commit, &finals, None,
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
    }

    /// Two batches, every family/mode, under both commitment modes — proves
    /// the leaves chain (a broken boundary would panic the fold's in-circuit
    /// bind), the three modes run and the auditor accepts each artifact
    /// against the prover's published log (per_batch: every leaf pinned to the
    /// derived leaf VK; chain / forest: the root pinned to the derived root
    /// VK), and per_batch stores one file per batch with a Θ(t) artifact.
    /// The `Hiding` pass is the B2 end-to-end run of the sim engine for every
    /// BabyBear family.
    #[test]
    fn all_families_all_modes_smoke() {
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        for commit in both_modes() {
            for family in FAMILIES {
                for mode in [StreamMode::PerBatch, StreamMode::Chain, StreamMode::Forest] {
                    let dir = std::env::temp_dir().join(format!(
                        "zksketch_compose_{}_{}_{}",
                        family.label(),
                        mode.label(),
                        commit.label()
                    ));
                    let _ = std::fs::remove_dir_all(&dir);
                    let cell = measure_compose(
                        family, shape(), &batches, mode, 1, 1, &dir, &[], QueryKeyMode::First, &commit,
                    );
                    let what = format!("({family:?}, {mode:?}, {})", commit.label());
                    assert!(cell.total_time_ms > 0.0, "measured {what}");
                    assert!(cell.proof_bytes > 0, "artifact {what}");
                    assert!(cell.verify_ms > 0.0, "the auditor verified {what}");
                    assert_eq!(cell.n_queries, 0, "updates-only run has no queries");
                    if mode == StreamMode::PerBatch {
                        let files = std::fs::read_dir(&dir).map(|it| it.count()).unwrap_or(0);
                        assert_eq!(files, 2, "one proof/batch {what}");
                        assert_eq!(cell.merge_ms, 0.0, "per_batch no fold {what}");
                    }
                    let _ = std::fs::remove_dir_all(&dir);
                }
            }
        }
    }

    /// Mixed updates+queries under both commitment modes: every batch is
    /// followed by a query leaf. Checks the query events fire, carry real
    /// costs, bind the leaf boundary (a mismatch would panic `record_query`'s
    /// assert; under `Hiding` the decoder opens `Com(S_t'; ρ^S_t')` and must
    /// expose exactly leaf `t'`'s final), and every answer is bound to the
    /// certified history with the certificate a verifier holds at t' — forest
    /// peaks = popcount(t'), per_batch = t' leaves, chain = 1 fold — at a
    /// measured cost, against the published (under `Hiding`, salted) log.
    #[test]
    fn mixed_queries_smoke() {
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        for commit in both_modes() {
            let tag = commit.label();
            for family in FAMILIES {
                let dir = std::env::temp_dir().join(format!("zksketch_mixed_{}_{tag}", family.label()));
                let _ = std::fs::remove_dir_all(&dir);
                let cell = measure_compose(
                    family, shape(), &batches, StreamMode::Forest, 1, 1, &dir, &[1, 2],
                    QueryKeyMode::First, &commit,
                );
                assert_eq!(cell.n_queries, 2, "one query per batch ({family:?}, {tag})");
                assert!(cell.query_prove_ms > 0.0, "query prove timed ({family:?}, {tag})");
                assert!(cell.query_proof_bytes > 0, "query artifact ({family:?}, {tag})");
                // Forest peaks at t'=1 and t'=2: popcount(1)+popcount(2) = 1+1.
                assert_eq!(cell.query_ctx_verifies, 2, "forest peaks ctx ({family:?}, {tag})");
                assert!(
                    cell.query_bind_ms.is_some_and(|ms| ms > 0.0),
                    "answers bound ({family:?}, {tag})"
                );
                let _ = std::fs::remove_dir_all(&dir);
            }
            // Mode-dependent ctx on one family: per_batch = 1+2, chain = 1+1.
            let dir = std::env::temp_dir().join(format!("zksketch_mixed_ctx_{tag}"));
            let cell = measure_compose(
                StreamFamily::CmOmc, shape(), &batches, StreamMode::PerBatch, 1, 1, &dir, &[1, 2],
                QueryKeyMode::First, &commit,
            );
            assert_eq!(cell.query_ctx_verifies, 3, "per_batch ctx = t' sum");
            assert!(cell.query_bind_ms.is_some(), "per_batch answers bound ({tag})");
            let cell = measure_compose(
                StreamFamily::CmOmc, shape(), &batches, StreamMode::Chain, 1, 1, &dir, &[1, 2],
                QueryKeyMode::First, &commit,
            );
            assert_eq!(cell.query_ctx_verifies, 2, "chain ctx = 1 per query");
            assert!(cell.query_bind_ms.is_some(), "chain answers bound ({tag})");
            let _ = std::fs::remove_dir_all(&dir);
        }
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


    /// Mid-batch queries via split+pad batches, EVERY family, under both
    /// commitment modes: the padded leaf must land exactly on the native
    /// state of the real records (pads provably no-ops) — `record_query`'s
    /// boundary assert panics on any drift — and the query binds that
    /// mid-stream commitment. Under `Hiding` the early-sealed and padded
    /// batches are REAL leaves opened with their version's randomizers (the
    /// public-zero no-op path would refuse them), and every query opens its
    /// version's `Com(S_t'; ρ^S_t')`.
    #[test]
    fn mixed_queries_at_update_positions_all_families() {
        let base: Vec<u32> = (1..=10).map(|k| k * 7 + 1).collect();
        for commit in both_modes() {
            for family in FAMILIES {
                // n=10 stream positions, Q=3, m=4 ⇒ queries occupy positions
                // 3,6,9 (7 update records) ⇒ leaves [2r+2p][2r+2p][2r+2p][1r+3p],
                // queries after leaves 1..3 — every queried boundary is mid-batch.
                let (batches, query_at, pads, splits) =
                    build_query_schedule_batches(&base, 10, 4, 3, family);
                assert_eq!((query_at.as_slice(), pads > 0, splits), (&[1, 2, 3][..], true, 4));
                let dir = std::env::temp_dir()
                    .join(format!("zksketch_split_{}_{}", family.label(), commit.label()));
                let _ = std::fs::remove_dir_all(&dir);
                let cell = measure_compose(
                    family, shape(), &batches, StreamMode::Forest, 1, 1, &dir, &query_at,
                    QueryKeyMode::First, &commit,
                );
                let what = format!("({family:?}, {})", commit.label());
                assert_eq!(cell.n_queries, 3, "3 mid-batch queries {what}");
                assert!(cell.query_prove_ms > 0.0, "real query proofs {what}");
                // Peaks at t' = 1, 2, 3: 1 + 1 + 2 proofs, all verified.
                assert_eq!(cell.query_ctx_verifies, 4, "forest peaks ctx {what}");
                assert!(cell.query_bind_ms.is_some(), "mid-batch answers bound {what}");
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }

    /// B2 query binding, per family: under `Hiding` a query at version `t`
    /// exposes exactly hiding leaf `t`'s final `Com(S_t; ρ^S_t)` (the
    /// auditor's [`check_query_exposure`] against the leaf's exposed value
    /// passes), which is NOT the `Plain` commitment of the same state; a
    /// query opened with another version's randomizer exposes a different
    /// commitment and is rejected against leaf `t`'s final.
    #[test]
    fn hiding_query_exposes_the_leaf_final() {
        let hid = ProverCommit::hiding(SaltSeed::for_tests(3));
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 11) as u32).collect()).collect();
        for family in FAMILIES {
            // Leaves 1..2 under Hiding; the query at t' = 2.
            let (leaves, _, queries) =
                prove_leaves(family, shape(), &batches, &[2], QueryKeyMode::First, &hid, None);
            assert_eq!(queries.len(), 1, "{family:?}");
            let leaf_final = leaves[1].final_;
            let sh = shape();
            // Replay the state at t' = 2 and prove the query at version 2
            // (honest) and at version 1's randomizer (dishonest).
            let q = |t: usize| -> (DecodeProof, [Val; 8], [Val; 8], Option<[Val; 4]>) {
                match family {
                    StreamFamily::CmOmc => {
                        let mut st = cm_empty(sh.d, sh.w);
                        for b in &batches {
                            countmin_omc_advance(&mut st, &cm_updates_of(b));
                        }
                        let key = batches[1][0] as u64;
                        let (dp, c) = prove_query_at(QueryState::Cm(&st, key), t, &hid);
                        (dp, c, commit_countmin(&st).0, Some(cm_query(key)))
                    }
                    StreamFamily::HllOmc => {
                        let mut regs = hll_omc_empty(sh.b);
                        for b in &batches {
                            hll_omc_advance(&mut regs, &hll_keys_of(b), 1 << sh.b);
                        }
                        let (dp, c) = prove_query_at(QueryState::Hll(&regs, sh.b), t, &hid);
                        (dp, c, commit_hll_omc(&regs, sh.b), None)
                    }
                    StreamFamily::SsCertified => {
                        let mut st = SsFullState::empty(SsFullParams { capacity: sh.capacity, batch: 4 });
                        for b in &batches {
                            st = apply_batch_ss_full(&st, &ss_updates_of(b)).0;
                        }
                        let (dp, c) = prove_query_at(QueryState::Ss(&st, 1), t, &hid);
                        (dp, c, commit_ss_state(&st).0, Some(scalar_query(1)))
                    }
                    StreamFamily::BloomOmc => {
                        let params = sh.bloom_params(4);
                        let mut bits = bloom_empty(&params);
                        for b in &batches {
                            bloom_insert(&mut bits, &params, &bloom_keys_of(b));
                        }
                        let key = batches[1][0] as u64;
                        let (dp, c) = prove_query_at(QueryState::Bloom(&bits, params, key), t, &hid);
                        (dp, c, commit_bloom(&bits), Some(bloom_query(key)))
                    }
                    StreamFamily::KmvSketch => {
                        let mut st = KmvState::empty(sh.kmv_k);
                        for b in &batches {
                            st = kmv_advance_records(&st, &kmv_records_of(b));
                        }
                        let (dp, c) = prove_query_at(QueryState::Kmv(&st), t, &hid);
                        (dp, c, commit_kmv_state(&st), None)
                    }
                    _ => {
                        let mut st = Gk2State::empty(GkbParams { capacity: sh.capacity, batch: 4, s: sh.gk_s });
                        for b in &batches {
                            st = apply_batch2(&st, &gk_vals_of(b));
                        }
                        let qv = batches[1][0] & 0x001F_FFFF;
                        let (dp, c) = prove_query_at(QueryState::Gk(&st, qv), t, &hid);
                        (dp, c, commit_gk2_state(&st).0, Some(scalar_query(qv as u64)))
                    }
                }
            };
            let (dp, c, plain, query) = q(2);
            assert_eq!(c, leaf_final, "{family:?}: the query opens leaf 2's final");
            assert_ne!(c, plain, "{family:?}: the exposed commitment is the hiding one");
            check_query_exposure(&dp, leaf_final, query, 2);
            let (dp1, c1, _, query1) = q(1);
            assert_ne!(c1, leaf_final, "{family:?}: another version's randomizer");
            let r = crate::sketch::forge::catch_msg(|| check_query_exposure(&dp1, leaf_final, query1, 2));
            assert!(r.is_err(), "{family:?}: a query under the wrong randomizer is rejected");
        }
    }

    /// Version 0 is the public EMPTY sketch, opened with the public zero
    /// randomizer: a hiding query at `t = 0` must open exactly the genesis
    /// anchor `Com(S_0; 0)`, so it is refused (before any proving) on any
    /// other state, which would otherwise publish that state's guessable
    /// `Com(S; 0)`. On the empty state it is honest and exposes the anchor
    /// (checked on the families whose decoders take an empty state: cm, hll).
    #[test]
    fn hiding_query_at_version_zero_opens_only_the_genesis_state() {
        let hid = ProverCommit::hiding(SaltSeed::for_tests(4));
        let sh = shape();
        let batch: Vec<u32> = (1..=4).map(|k| k * 5 + 3).collect();
        let refused = |what: &str, r: Result<(DecodeProof, [Val; 8]), String>| match r {
            Ok(_) => panic!("{what}: a hiding query at version 0 on a non-genesis state was accepted"),
            Err(e) => assert!(e.contains("version 0"), "{what}: refused by the genesis guard, got: {e}"),
        };
        let mut cm = cm_empty(sh.d, sh.w);
        countmin_omc_advance(&mut cm, &cm_updates_of(&batch));
        refused("cm", crate::sketch::forge::catch_msg(|| prove_query_at(QueryState::Cm(&cm, 8), 0, &hid)));
        let mut regs = hll_omc_empty(sh.b);
        hll_omc_advance(&mut regs, &hll_keys_of(&batch), 1 << sh.b);
        refused("hll", crate::sketch::forge::catch_msg(|| prove_query_at(QueryState::Hll(&regs, sh.b), 0, &hid)));
        let ss0 = SsFullState::empty(SsFullParams { capacity: sh.capacity, batch: 4 });
        let ss = apply_batch_ss_full(&ss0, &ss_updates_of(&batch)).0;
        refused("ss", crate::sketch::forge::catch_msg(|| prove_query_at(QueryState::Ss(&ss, 1), 0, &hid)));
        let gk0 = Gk2State::empty(GkbParams { capacity: sh.capacity, batch: 4, s: sh.gk_s });
        let gk = apply_batch2(&gk0, &gk_vals_of(&batch));
        refused("gk", crate::sketch::forge::catch_msg(|| prove_query_at(QueryState::Gk(&gk, 8), 0, &hid)));
        // The genesis state itself: the query exposes the public anchor.
        let empty_cm = cm_empty(sh.d, sh.w);
        let (dp, c) = prove_query_at(QueryState::Cm(&empty_cm, 8), 0, &hid);
        assert_eq!(c, commit_countmin_with(&empty_cm, CommitMode::Hiding, &SaltBb::ZERO).0, "cm genesis anchor");
        check_query_exposure(&dp, c, Some(cm_query(8)), 0);
        let empty_regs = hll_omc_empty(sh.b);
        let (dp, c) = prove_query_at(QueryState::Hll(&empty_regs, sh.b), 0, &hid);
        assert_eq!(c, commit_hll_omc_with(&empty_regs, sh.b, CommitMode::Hiding, &SaltBb::ZERO), "hll genesis anchor");
        check_query_exposure(&dp, c, None, 0);
        // Plain has no randomizers: a version-0 query is not restricted.
        let (_, c) = prove_query_at(QueryState::Cm(&cm, 8), 0, &ProverCommit::plain());
        assert_eq!(c, commit_countmin(&cm).0, "plain query at version 0");
    }

    /// A single-leaf (t=1) stream: chain/forest have nothing to compose, so the
    /// "root" is the lone leaf. Regression for the case where verifying that raw
    /// leaf via the aggregation verifier (which lacks the Permute table) would
    /// panic — t=1 must fall back to the leaf's own self-verify. Both modes.
    #[test]
    fn single_leaf_chain_forest_no_panic() {
        let batches: Vec<Vec<u32>> = vec![(0..4).map(|j| (j + 1) as u32).collect()];
        for commit in both_modes() {
            let dir = std::env::temp_dir().join(format!("zksketch_compose_t1_{}", commit.label()));
            for mode in [StreamMode::Chain, StreamMode::Forest] {
                let cell = measure_compose(
                    StreamFamily::CmOmc, shape(), &batches, mode, 1, 1, &dir, &[], QueryKeyMode::First, &commit,
                );
                assert!(cell.total_time_ms > 0.0, "t=1 measured ({mode:?})");
                assert!(cell.proof_bytes > 0, "t=1 artifact ({mode:?})");
                // No real fold — the "root" is the lone leaf (sub-ms to select).
                assert!(cell.merge_ms < 10.0, "t=1 has no real merge ({mode:?})");
                assert!(cell.verify_ms > 0.0, "t=1: the auditor verifies the lone leaf ({mode:?})");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
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
        for commit in both_modes() {
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
                        &commit,
                    );
                    assert!(
                        cell.proof_bytes > 0 && cell.verify_ms > 0.0,
                        "{mode:?} t={} {}",
                        batches.len(),
                        commit.label()
                    );
                }
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
    /// VK and the log's `(Com(S_0), Com(S_T))`, under both commitment modes.
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
    /// leaf of a one-batch stream), under both commitment modes. With the
    /// leaf VK the harness derives ([`compose_trusted_vk`]) the honest leaf
    /// passes and THE REVIEWED ATTACK — a toy circuit exposing leaf 1's
    /// honest statement — is rejected; the pre-fix statement-only path (still
    /// what the legacy `EXP_ROOT_VK=self` opt-in runs) accepts it.
    #[test]
    fn sim_leaf_audit_rejects_foreign_circuit() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        use p3_field::BasedVectorSpace;
        let (sh, m) = (shape(), 4usize);
        let batches: Vec<Vec<u32>> = vec![(1..=4).collect()];
        for commit in both_modes() {
            let pp = PublicParams { family: StreamFamily::CmOmc, shape: sh, m, commit_mode: commit.mode() };
            for mode in [StreamMode::PerBatch, StreamMode::Forest] {
                assert!(compose_trusted_vk(&pp, mode, 1).is_some(), "{mode:?}: leaf VK");
            }
            let vk = compose_trusted_vk(&pp, StreamMode::PerBatch, 3).expect("derived leaf VK");
            let (leaves, _, _) =
                prove_leaves(StreamFamily::CmOmc, sh, &batches, &[], QueryKeyMode::First, &commit, None);
            let log = super::super::dist_compose::publish_batch_log(StreamFamily::CmOmc, &sh, m, &batches, &commit);
            let layout = composition_expose();
            assert!(audit_leaves(&pp, &[&leaves[0].output.0], Some(&vk), &log, layout, -1.0) >= 0.0);
            let cs: Vec<crate::config::Challenge> = read_exposed_statement(&leaves[0].output.0)
                .values()
                .chunks(4)
                .map(|c| crate::config::Challenge::from_basis_coefficients_slice(c).unwrap())
                .collect();
            let toy = crate::recursion::recursive::expose_forest::prove_exposing_leaf(&cs);
            assert_eq!(audit_leaves(&pp, &[&toy.0], None, &log, layout, -1.0), -1.0, "pre-fix path accepts");
            let r = crate::sketch::forge::catch_msg(|| audit_leaves(&pp, &[&toy.0], Some(&vk), &log, layout, -1.0));
            println!("B6B sim leaf audit toy ({}): {r:?}", commit.label());
            assert!(r.is_err_and(|e| e.contains("leaf audit")));
        }
    }

    /// Under `Hiding` the sim engine's auditor rejects the honest proofs
    /// against a log the prover would have published under ANOTHER seed (the
    /// genesis anchor matches, `Com(S_T)` and every `Com(B_t)` do not), for
    /// the root (chain) and the per_batch leaves, and accepts the honest log.
    #[test]
    fn sim_auditor_rejects_a_log_from_another_seed() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        let (sh, m) = (shape(), 4usize);
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        let (hid, other) = (ProverCommit::hiding(SaltSeed::for_tests(3)), ProverCommit::hiding(SaltSeed::for_tests(4)));
        let family = StreamFamily::HllOmc;
        let pp = PublicParams { family, shape: sh, m, commit_mode: CommitMode::Hiding };
        let (leaves, _, _) = prove_leaves(family, sh, &batches, &[], QueryKeyMode::First, &hid, None);
        let honest = super::super::dist_compose::publish_batch_log(family, &sh, m, &batches, &hid);
        let wrong = super::super::dist_compose::publish_batch_log(family, &sh, m, &batches, &other);
        assert_eq!(honest.init, wrong.init);
        let layout = composition_expose();
        let leaf_vk = compose_trusted_vk(&pp, StreamMode::PerBatch, 2).expect("leaf VK");
        let proofs: Vec<_> = leaves.iter().map(|l| &l.output.0).collect();
        assert!(audit_leaves(&pp, &proofs, Some(&leaf_vk), &honest, layout, -1.0) >= 0.0);
        let r = crate::sketch::forge::catch_msg(|| audit_leaves(&pp, &proofs, Some(&leaf_vk), &wrong, layout, -1.0));
        assert!(r.is_err(), "per_batch leaves vs another seed's log: {r:?}");
        let outputs: Vec<_> = leaves.into_iter().map(|l| l.output).collect();
        let root = prove_chain_over(outputs);
        let root_vk = compose_trusted_vk(&pp, StreamMode::Chain, 2).expect("root VK");
        let tree = ForestShape::chain(2);
        assert!(audit_root(&pp, &root, Some(&root_vk), &honest, &tree, layout) >= 0.0);
        let r = crate::sketch::forge::catch_msg(|| audit_root(&pp, &root, Some(&root_vk), &wrong, &tree, layout));
        println!("B2 sim root vs other-seed log: {r:?}");
        assert!(r.is_err(), "chain root vs another seed's log");
    }

    /// The binding fails closed, for Count-Min, the Bloom filter and the
    /// KMV sketch (its keyless 12-value statement), under both commitment
    /// modes: a query answered against the state at t' is
    /// rejected with the certificate of t'-1 (stale peaks), with a certificate
    /// over a different batch log, and when its exposed Com(S) is not the
    /// certified one. The log is the one the prover publishes (under `Hiding`
    /// the salted `Com(B_t)` / `Com(S_T)`; the auditor never recomputes them).
    /// Without an auditor (legacy opt-ins) nothing is bound.
    #[test]
    fn query_binding_rejects_mismatched_certificates() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        let (sh, m) = (shape(), 4usize);
        for commit in both_modes() {
            let tag = commit.label();
            for fam in [StreamFamily::CmOmc, StreamFamily::BloomOmc, StreamFamily::BloomPacked, StreamFamily::KmvSketch] {
                let batches: Vec<Vec<u32>> =
                    (0..3u32).map(|i| (1..=4).map(|k| k * 5 + i * 11).collect()).collect();
                let Some(mut audit) = QueryAudit::new(fam, &sh, m, commit.mode()) else {
                    eprintln!("skipped: binding off under a legacy opt-in");
                    return;
                };
                let (leaves, _, arts) = prove_leaves(
                    fam, sh, &batches, &[2, 3], QueryKeyMode::First, &commit, Some(&audit.decode_vk),
                );
                let log = super::super::dist_compose::publish_batch_log(fam, &sh, m, &batches, &commit);
                let other: Vec<Vec<u32>> = batches.iter().rev().cloned().collect();
                let other_log = super::super::dist_compose::publish_batch_log(fam, &sh, m, &other, &commit);
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
                assert_eq!(q2.bind.map(|b| b.ctx_proofs), Some(2), "{fam:?} {tag}");
                // A DIFFERENT proof offered for an interval already verified
                // is verified on its own, not served the memoised statement:
                // leaf 2's (valid) proof as the part [1, 1] certifies [2, 2],
                // and junk bytes there fail to decode.
                let swapped = (1u64, 1u64, ForestShape::Leaf, CtxProof::Proof(&leaves[1].output.0));
                let mut q2s = fresh(&arts[0]);
                assert!(
                    audit.bind(&mut q2s, &[swapped, leaf(2)], &log).is_err(),
                    "{fam:?} {tag}: a substituted proof for a memoised interval"
                );
                let junk = vec![0u8; 16];
                let mut q2j = fresh(&arts[0]);
                let junk_part = (1, 1, ForestShape::Leaf, CtxProof::Bytes(&junk));
                let e = audit.bind(&mut q2j, &[junk_part, leaf(2)], &log).unwrap_err();
                assert!(e.contains("decode"), "{fam:?} {tag}: {e}");
                let mut q2h = fresh(&arts[0]);
                audit
                    .bind(&mut q2h, &[leaf(1), leaf(2)], &log)
                    .expect("honest certificate, memoised");
                // Stale: the query at t'=3 with the certificate of t'=2.
                let mut q3 = fresh(&arts[1]);
                let e = audit.bind(&mut q3, &[leaf(1), leaf(2)], &log).unwrap_err();
                assert!(e.contains("certify [1, 2]"), "{fam:?} {tag}: {e}");
                // The query at t'=2 answered against S_2 but offered leaves 1..3.
                let mut q2b = fresh(&arts[0]);
                assert!(
                    audit.bind(&mut q2b, &[leaf(1), leaf(2), leaf(3)], &log).is_err(),
                    "{fam:?} {tag}: past t'"
                );
                // A log with other batches: the leaves' digests no longer match.
                let mut q2c = fresh(&arts[0]);
                let e = audit.bind(&mut q2c, &[leaf(1), leaf(2)], &other_log).unwrap_err();
                assert!(e.contains("digest") || e.contains("Com(S_0)"), "{fam:?} {tag}: {e}");
                // The query proof's Com(S) is not the certified one (S_3 vs S_2).
                let mut q3b = fresh(&arts[1]);
                q3b.at_leaf = 2;
                let e = audit.bind(&mut q3b, &[leaf(1), leaf(2)], &log).unwrap_err();
                assert!(e.contains("not the certified"), "{fam:?} {tag}: {e}");
                // Nothing exposed (legacy decoder): nothing to bind.
                let mut q0 = fresh(&arts[0]);
                q0.statement = None;
                assert!(audit.bind(&mut q0, &[leaf(1), leaf(2)], &log).is_err(), "{fam:?} {tag}");
            }
        }
    }

    /// Query binding under `Hiding` for every BabyBear family: the hiding
    /// query proofs are pinned to the HIDING decode VK (derived from public
    /// parameters: the empty state under the public zero salt), which differs
    /// from the plain decoder's, so a hiding query proof fails the plain VK
    /// and a plain one fails the hiding VK; each answer binds to the
    /// certificate against the log the prover published, and is rejected
    /// against a log published under another seed (same genesis anchor, other
    /// `Com(B_t)`) and against the plain log of the same stream.
    #[test]
    fn hiding_query_binding_uses_the_published_log_and_the_hiding_vk() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        let (sh, m) = (shape(), 4usize);
        let hid = ProverCommit::hiding(SaltSeed::for_tests(5));
        let other = ProverCommit::hiding(SaltSeed::for_tests(6));
        let plain = ProverCommit::plain();
        let batches: Vec<Vec<u32>> =
            (0..2u32).map(|i| (1..=4).map(|k| k * 3 + i * 17).collect()).collect();
        for fam in FAMILIES {
            let (Some(mut audit), Some(plain_audit)) = (
                QueryAudit::new(fam, &sh, m, CommitMode::Hiding),
                QueryAudit::new(fam, &sh, m, CommitMode::Plain),
            ) else {
                eprintln!("skipped: binding off under a legacy opt-in");
                return;
            };
            assert_ne!(
                audit.decode_vk.commitment, plain_audit.decode_vk.commitment,
                "{fam:?}: the hiding decoder is another circuit"
            );
            let (leaves, _, arts) =
                prove_leaves(fam, sh, &batches, &[2], QueryKeyMode::First, &hid, Some(&audit.decode_vk));
            let (_, _, plain_arts) = prove_leaves(
                fam, sh, &batches, &[2], QueryKeyMode::First, &plain, Some(&plain_audit.decode_vk),
            );
            // The exposed commitments differ: hiding Com(S_2; ρ) vs plain Com(S_2).
            assert_ne!(
                arts[0].statement.map(|s| s.commit),
                plain_arts[0].statement.map(|s| s.commit),
                "{fam:?}: the hiding query exposes the salted commitment"
            );
            let honest = super::super::dist_compose::publish_batch_log(fam, &sh, m, &batches, &hid);
            let wrong = super::super::dist_compose::publish_batch_log(fam, &sh, m, &batches, &other);
            let plain_log = super::super::dist_compose::publish_batch_log(fam, &sh, m, &batches, &plain);
            assert_eq!(honest.init, wrong.init, "{fam:?}: one public genesis anchor per mode");
            let parts = || -> Vec<CtxPart<'_>> {
                (1..=2)
                    .map(|k| (k as u64, k as u64, ForestShape::Leaf, CtxProof::Proof(&leaves[k - 1].output.0)))
                    .collect()
            };
            let fresh = |a: &QueryArt| QueryArt {
                at_leaf: a.at_leaf,
                prove_ms: 0.0,
                verify_ms: 0.0,
                proof_bytes: 0,
                statement: a.statement,
                bind: None,
            };
            let mut q = fresh(&arts[0]);
            audit.bind(&mut q, &parts(), &honest).expect("hiding answer binds to the published log");
            // A log anchored anywhere but the public genesis is refused.
            let inflated = BatchLog { init: plain_log.init.clone(), ..honest.clone() };
            let mut q = fresh(&arts[0]);
            let e = audit.bind(&mut q, &parts(), &inflated).unwrap_err();
            assert!(e.contains("genesis anchor"), "{fam:?}: {e}");
            for (what, lg) in [("another seed's log", &wrong), ("the plain log", &plain_log)] {
                let mut q = fresh(&arts[0]);
                assert!(audit.bind(&mut q, &parts(), lg).is_err(), "{fam:?}: bound against {what}");
            }
            // Cross-mode pinning fails closed both ways (`record_query`
            // verifies every query proof against the VK it is handed).
            let r = crate::sketch::forge::catch_msg(|| {
                prove_leaves(fam, sh, &batches, &[2], QueryKeyMode::First, &hid, Some(&plain_audit.decode_vk))
                    .2
                    .len()
            });
            assert!(r.is_err(), "{fam:?}: a hiding query proof passed the plain decode VK");
            let r = crate::sketch::forge::catch_msg(|| {
                prove_leaves(fam, sh, &batches, &[2], QueryKeyMode::First, &plain, Some(&audit.decode_vk))
                    .2
                    .len()
            });
            assert!(r.is_err(), "{fam:?}: a plain query proof passed the hiding decode VK");
        }
    }

    /// The procs engine's query replay ([`prove_queries_only`], no update
    /// leaf) and the sim engine's interleaved queries ([`prove_leaves`]) pin
    /// to the same Bloom decode VK and expose the SAME statements
    /// `(Com(S_{t'}), record(key), answer)` for every query-key mode, under
    /// both commitment modes, and the replay's answers bind to the certified
    /// history with the leaves' prefix certificate (what the coordinator
    /// assembles from the workers' bytes) against the published log.
    #[test]
    fn bloom_query_replay_matches_sim_and_binds() {
        bloom_query_replay_matches_sim_and_binds_in(StreamFamily::BloomOmc);
    }

    /// [`bloom_query_replay_matches_sim_and_binds`] for the packed-byte leaf
    /// (M2).
    #[test]
    fn bloom_packed_query_replay_matches_sim_and_binds() {
        bloom_query_replay_matches_sim_and_binds_in(StreamFamily::BloomPacked);
    }

    /// M2: the packed and bit-array Bloom variants answer EVERY query of the
    /// same stream identically (same filter), for every query-key mode,
    /// while their exposed commitments differ (different state encodings and
    /// commitment families).
    #[test]
    fn bloom_variants_answer_identically() {
        use p3_field::PrimeCharacteristicRing;
        let sh = shape();
        let base: Vec<u32> = (1..=40).map(|k| k * 7919 + 13).collect();
        let commit = ProverCommit::plain();
        let vk_omc = crate::decode::bloom::bloom_decode_vk_commit(sh.bloom_params(4), CommitMode::Plain);
        let vk_packed =
            crate::decode::bloom_packed::bloom_packed_decode_vk_commit(sh.bloom_packed_params(4), CommitMode::Plain);
        let (mut ones, mut zeros) = (0, 0);
        for mode in [QueryKeyMode::First, QueryKeyMode::UniformStream, QueryKeyMode::Absent, QueryKeyMode::Hot] {
            let run = |fam: StreamFamily, vk: &DecodeVk| {
                let (batches, query_at, _, _) = build_query_schedule_batches(&base, 30, 4, 4, fam);
                prove_leaves(fam, sh, &batches, &query_at, mode, &commit, Some(vk)).2
            };
            let (a, b) = (run(StreamFamily::BloomOmc, &vk_omc), run(StreamFamily::BloomPacked, &vk_packed));
            assert_eq!(a.len(), b.len());
            assert!(!a.is_empty());
            for (qa, qb) in a.iter().zip(&b) {
                let (sa, sb) = (qa.statement.expect("pinned"), qb.statement.expect("pinned"));
                assert_eq!(qa.at_leaf, qb.at_leaf, "{mode:?}");
                assert_eq!(sa.query, sb.query, "{mode:?}: the same probe key");
                assert_eq!(sa.answer, sb.answer, "{mode:?} at leaf {}: the same answer", qa.at_leaf);
                assert_ne!(sa.commit, sb.commit, "different state commitments");
                if sa.answer[0] == Val::ONE { ones += 1 } else { zeros += 1 }
            }
        }
        assert!(ones > 0 && zeros > 0, "members and non-members both probed ({ones} / {zeros})");
    }

    fn bloom_query_replay_matches_sim_and_binds_in(fam: StreamFamily) {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        let (sh, m) = (shape(), 4usize);
        for commit in both_modes() {
            let Some(mut audit) = QueryAudit::new(fam, &sh, m, commit.mode()) else {
                eprintln!("skipped: binding off under a legacy opt-in");
                return;
            };
            let base: Vec<u32> = (1..=10).map(|k| k * 7 + 1).collect();
            let (batches, query_at, _, _) = build_query_schedule_batches(&base, 10, 4, 3, fam);
            let log = super::super::dist_compose::publish_batch_log(fam, &sh, m, &batches, &commit);
            for mode in [QueryKeyMode::First, QueryKeyMode::UniformStream, QueryKeyMode::Absent] {
                let (leaves, _, sim) =
                    prove_leaves(fam, sh, &batches, &query_at, mode, &commit, Some(&audit.decode_vk));
                let finals: Vec<[Val; 8]> = leaves.iter().map(|l| l.final_).collect();
                let mut replay = prove_queries_only(
                    fam, sh, &batches, &query_at, mode, &commit, &finals, Some(&audit.decode_vk),
                );
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

    /// The KMV family end to end in the harness, under both commitment
    /// modes: the procs engine's query replay ([`prove_queries_only`]) and the
    /// sim engine's interleaved queries ([`prove_leaves`]) over the
    /// operation-stream schedule (split and padded leaves: `PAD_KEY` slots
    /// become in-place dummy records) pin to the same KMV decode VK and expose
    /// the SAME keyless statements `(Com(S_{t'}), answer)`, with the answer
    /// the native distinct-count estimate of the replayed state (exact below
    /// capacity); the replay's answers bind to the leaves' prefix certificate
    /// against the published log. A hiding query at version 0 opens only the
    /// genesis (empty) state.
    #[test]
    fn kmv_query_replay_matches_sim_and_binds() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        use p3_field::PrimeCharacteristicRing;
        let (sh, m, fam) = (shape(), 4usize, StreamFamily::KmvSketch);
        // 13 operations, a query every 3rd: 9 update records, distinct keys
        // with repeats, past capacity k = 4.
        let base: Vec<u32> = [3u32, 5, 3, 8, 13, 21, 5, 34, 55, 3].to_vec();
        for commit in both_modes() {
            let Some(mut audit) = QueryAudit::new(fam, &sh, m, commit.mode()) else {
                eprintln!("skipped: binding off under a legacy opt-in");
                return;
            };
            let (batches, query_at, pads, _) = build_query_schedule_batches(&base, 13, m, 3, fam);
            assert!(pads > 0, "the schedule splits and pads leaves");
            let log = super::super::dist_compose::publish_batch_log(fam, &sh, m, &batches, &commit);
            let (leaves, _, sim) =
                prove_leaves(fam, sh, &batches, &query_at, QueryKeyMode::UniformStream, &commit, Some(&audit.decode_vk));
            let finals: Vec<[Val; 8]> = leaves.iter().map(|l| l.final_).collect();
            let mut replay = prove_queries_only(
                fam, sh, &batches, &query_at, QueryKeyMode::UniformStream, &commit, &finals, Some(&audit.decode_vk),
            );
            assert_eq!(replay.len(), query_at.len());
            let mut st = KmvState::empty(sh.kmv_k);
            let mut applied = 0usize;
            for (a, b) in sim.iter().zip(&replay) {
                assert_eq!((a.at_leaf, a.statement), (b.at_leaf, b.statement), "{}", commit.label());
                while applied < a.at_leaf {
                    st = kmv_advance_records(&st, &kmv_records_of(&batches[applied]));
                    applied += 1;
                }
                let s = b.statement.expect("bound statement");
                assert_eq!(s.query, [Val::ZERO; 4], "keyless");
                assert_eq!(s.answer[0], Val::from_u64(crate::sketch::kmv::kmv_estimate(&st)));
                assert_eq!(s.commit, finals[a.at_leaf - 1], "the query opens leaf t''s final");
            }
            for q in replay.iter_mut() {
                let parts: Vec<CtxPart<'_>> = (1..=q.at_leaf)
                    .map(|k| (k as u64, k as u64, ForestShape::Leaf, CtxProof::Proof(&leaves[k - 1].output.0)))
                    .collect();
                audit.bind(q, &parts, &log).expect("replayed answer binds");
            }
        }
        // Version 0 under Hiding: the empty state opens the genesis anchor;
        // any other state is refused before proving.
        let hid = ProverCommit::hiding(SaltSeed::for_tests(4));
        let empty = KmvState::empty(sh.kmv_k);
        let (dp, c) = prove_query_at(QueryState::Kmv(&empty), 0, &hid);
        assert_eq!(c, commit_kmv_state_with(&empty, CommitMode::Hiding, &SaltBb::ZERO), "kmv genesis anchor");
        check_query_exposure(&dp, c, None, 0);
        let full = kmv_advance(&empty, &[1, 2, 3, 4, 5]);
        let r = crate::sketch::forge::catch_msg(|| prove_query_at(QueryState::Kmv(&full), 0, &hid));
        assert!(r.is_err_and(|e| e.contains("version 0")), "a non-genesis state at version 0");
    }
}
