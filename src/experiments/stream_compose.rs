//! **Multi-family streaming proof composition** (paper §Streaming Proof
//! Composition, generalised beyond Count-Min).
//!
//! Benchmarks the three composition modes — **per-batch proof chain**, the
//! **recursive linear chain**, and the **streaming forest** — over a stream of
//! `t = ⌈N/m⌉` transition leaves, for four sketch families each pinned to one
//! leaf variant:
//!
//! | family | variant           | leaf prover (exposed)          |
//! |--------|-------------------|--------------------------------|
//! | cm     | omc               | `prove_countmin_omc_exposed`   |
//! | hll    | omc               | `prove_hll_omc_exposed`        |
//! | ss     | certified         | `prove_ss_full_exposed`        |
//! | gk     | bandmerge2        | `prove_gkb2_exposed`           |
//!
//! All four leaves surface their `(Com(S_{i-1}), Com(S_i))` boundary via the
//! Expose NPO, so the **family-agnostic** folds
//! ([`prove_forest_over`](crate::recursion::recursive::expose_forest::prove_forest_over)
//! Bentley–Saxe tree, [`prove_chain_over`] left-leaning linear) compose any of
//! them and bind `left.final == right.initial` in-circuit. The per-batch mode
//! folds nothing — it stores the `t` leaf proofs to a folder and the verifier
//! holds all of them.
//!
//! ## Mixed updates + queries (`query_at`)
//!
//! With a non-empty `query_at` schedule (1-based batch indices), a **query
//! leaf** (the family's `src/decode/*` circuit: cm point count, hll
//! cardinality, ss top-1 mass, gk rank) is proved after each listed batch
//! against the state at that point. Queries at ARBITRARY stream positions
//! (the paper's operation-stream model: a query OCCUPIES a position, so `n`
//! points carry `n − ⌊n/Q⌋` update records) are supported by building the
//! batch list with [`build_query_schedule_batches`]:
//! a query landing mid-batch seals the batch early and pads its tail with the
//! family's provable no-op records ([`PAD_KEY`]), so `Com(S_u)` becomes a real
//! batch-boundary commitment at the exact query position. The query circuit
//! re-hashes the state and binds the same `Com(S_{t'})` the update leaf just
//! exposed (asserted by the harness), so the verifier checks the answer against
//! the composition proof(s) live at `t'`: all `t'` leaves (per_batch), the
//! current fold (chain), or the `popcount(t')` Bentley–Saxe peaks (forest).
//! Query costs are reported separately (`query_*` fields) and the per-mode
//! verifier context is the structural `query_ctx_verifies` count — interior
//! boundaries are hidden by the final root, so mid-stream queries verify
//! against the composition state at query time, not the end-of-stream root.
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

use crate::config::Val;
use crate::decode::countmin::{prove_cm_decode, CmDecodeParams};
use crate::decode::gk_bandmerge::{prove_gk2_decode, Gkb2DecodeParams};
use crate::decode::hyperloglog::{prove_hll_decode_omc, HllDecodeParams};
use crate::decode::spacesaving::{prove_ss_decode, SsDecodeParams};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::{
    prove_chain_over, prove_forest_over, verify_bound_proof,
};
use crate::recursion::recursive::timing;
use p3_recursion::RecursionOutput;

use crate::sketch::countmin::CountMinUpdate;
use crate::sketch::countmin_final::apply_update_prf;
use crate::sketch::countmin_omc::{prove_countmin_omc_exposed, CmOmcParams};
use crate::sketch::gk_bandmerge::{
    apply_batch2, commit_gk2_state, prove_gkb2_exposed, Gk2State, GkbParams,
};
use crate::sketch::hll_omc::{
    commit_hll_omc, hll_omc_advance, hll_omc_empty, prove_hll_omc_exposed, HllOmcParams,
};
use crate::sketch::ss_final_full::{
    apply_batch_ss_full, commit_ss_state, prove_ss_full_exposed, SsFullParams, SsFullState,
    SsFullUpdate,
};

use super::families::cm_empty;
use super::metrics::{bench, read_vmrss_kb, BenchCfg, RunOutcome};
use super::proof_size;

use crate::commitment::countmin::commit_countmin;

/// The four (family, variant) leaf types the composition benchmark folds.
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
    /// `popcount(t')` Bentley–Saxe peaks (forest). Structural count — the folds
    /// exist at query time in a live stream; this harness does not re-time them.
    pub query_ctx_verifies: u64,
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
/// dropped — only its cost and size are kept).
struct QueryArt {
    /// Number of leaves covered when the query fired (`t'`, 1-based).
    at_leaf: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: u64,
}

/// Record one query event: take the decode prover's self-timings, check the
/// harness-level binding (the state the query circuit hashed must be exactly
/// the leaf-boundary commitment at `t'` — the decode proof binds it in-circuit
/// via public inputs, this asserts the two sides agree), and keep the metrics.
fn record_query(
    queries: &mut Vec<QueryArt>,
    at_leaf: usize,
    dp: &DecodeProof,
    native_commit: [Val; 8],
    leaf_final: [Val; 8],
) {
    let tm = timing::take();
    assert_eq!(
        native_commit, leaf_final,
        "query state commitment must equal the leaf boundary at t'={at_leaf}"
    );
    queries.push(QueryArt {
        at_leaf,
        prove_ms: (tm.witness + tm.prove).as_secs_f64() * 1000.0,
        verify_ms: tm.verify.as_secs_f64() * 1000.0,
        proof_bytes: dp.proof_size() as u64,
    });
}

/// How the probe key for a **keyed** decode query is chosen at each query event.
/// Only the keyed families use it — cm (point-count) and gk (rank); hll
/// (cardinality) and ss (top-1) take no probe key and ignore the mode.
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
}

/// Fold the raw per-event query artifacts into the reported metrics; the
/// verifier-context count is per composition mode.
fn aggregate_queries(query_arts: &[QueryArt], mode: StreamMode) -> QueryAgg {
    QueryAgg {
        n_queries: query_arts.len(),
        query_prove_ms: query_arts.iter().map(|q| q.prove_ms).sum(),
        query_verify_ms: query_arts.iter().map(|q| q.verify_ms).sum(),
        query_proof_bytes: query_arts.iter().map(|q| q.proof_bytes).sum(),
        query_ctx_verifies: query_arts
            .iter()
            .map(|q| match mode {
                StreamMode::PerBatch => q.at_leaf as u64,
                StreamMode::Chain => 1u64,
                StreamMode::Forest => q.at_leaf.count_ones() as u64,
            })
            .sum(),
    }
}

/// Prove ONLY the interleaved query leaves via a plaintext replay — no update
/// leaf is proved here. Used by the **procs** engine, where the workers prove
/// the update leaves distributedly; this recomputes the plaintext state (the
/// same deterministic advance the coordinator's witness pass runs) and proves
/// one decode query after each `query_at`-listed batch. Mirrors `prove_leaves`'
/// query logic exactly (same `query_key_mode` probes, same per-family circuits).
///
/// The query decode circuit binds its in-circuit state hash to `Com(S_{t'})`;
/// because that state is the identical canonical replay the workers' update
/// leaves expose as their boundary, the answer is bound to the composition
/// proof at `t'` transitively (there is no separate leaf here to assert against,
/// so `record_query`'s check is against the freshly recomputed commit itself).
fn prove_queries_only(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
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
                for u in &cm_updates_of(batch) {
                    apply_update_prf(&mut state, u);
                }
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
                    record_query(&mut queries, bi + 1, &dp, commit, commit);
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
                    record_query(&mut queries, bi + 1, &dp, commit, commit);
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
                    record_query(&mut queries, bi + 1, &dp, commit, commit);
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
                    record_query(&mut queries, bi + 1, &dp, commit, commit);
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
pub fn measure_queries_dist(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
) -> QueryAgg {
    if query_at.is_empty() || batches.is_empty() {
        return QueryAgg::default();
    }
    let pool = ThreadPoolBuilder::new()
        .num_threads(cores.max(1))
        .build()
        .expect("query pool");
    pool.install(|| {
        let arts = prove_queries_only(family, shape, batches, query_at, query_key_mode);
        aggregate_queries(&arts, mode)
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
/// the batch's first key); hll = cardinality and ss = top-1 heavy-hitter mass
/// are keyless and ignore the mode.
fn prove_leaves(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
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
                let leaf = prove_countmin_omc_exposed(
                    CmOmcParams { d, w, batch: m },
                    state.clone(),
                    ups.clone(),
                );
                let leaf_final = leaf.final_commit.0;
                push(leaf.output, leaf.initial_commit.0, leaf_final);
                for u in &ups {
                    apply_update_prf(&mut state, u);
                }
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
                    record_query(&mut queries, bi + 1, &dp, commit_countmin(&state).0, leaf_final);
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
                let leaf = prove_hll_omc_exposed(
                    HllOmcParams { b, batch: m },
                    regs.clone(),
                    keys.clone(),
                );
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
                    record_query(&mut queries, bi + 1, &dp, commit_hll_omc(&regs, b), leaf_final);
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
                let leaf = prove_ss_full_exposed(params, state.clone(), ups.clone());
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
                    record_query(&mut queries, bi + 1, &dp, commit_ss_state(&state).0, leaf_final);
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
                let leaf = prove_gkb2_exposed(params, state.clone(), vals.clone());
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
                    record_query(&mut queries, bi + 1, &dp, commit_gk2_state(&state).0, leaf_final);
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
        bench(BenchCfg { warmup: 0, trials: 1 }, || {
            let (leaves, empty_commit, query_arts) =
                prove_leaves(family, shape, batches, query_at, query_key_mode);
            let prove_ms: Vec<f64> = leaves.iter().map(|l| l.prove_ms).collect();
            let leafgen_seq: f64 = prove_ms.iter().sum();
            leafgen_seq_out = leafgen_seq;
            // Mixed-workload aggregates (same fold the procs engine uses).
            q_out = aggregate_queries(&query_arts, mode);

            match mode {
                StreamMode::PerBatch => {
                    // Store each leaf proof to the folder (fresh per run); the
                    // verifier holds all t (Θ(t) size + verify).
                    let _ = std::fs::remove_dir_all(proof_dir);
                    std::fs::create_dir_all(proof_dir).expect("create per-batch proof dir");
                    let mut total_bytes = 0u64;
                    let mut total_verify = 0.0f64;
                    for (i, l) in leaves.iter().enumerate() {
                        let bytes =
                            postcard::to_allocvec(&l.output.0).expect("serialize leaf proof");
                        total_bytes += bytes.len() as u64;
                        std::fs::write(proof_dir.join(format!("leaf_{i:04}.bin")), &bytes)
                            .expect("write leaf proof");
                        total_verify += l.verify_ms;
                    }
                    // Verifier's chain links: anchor (π₁.initial == Com(S₀)) +
                    // (t-1) boundary equalities. Native compares — negligible but
                    // real (the paper's Θ(t) link cost).
                    let mut ok = leaves[0].initial == empty_commit;
                    for pair in leaves.windows(2) {
                        ok &= pair[0].final_ == pair[1].initial;
                    }
                    assert!(ok, "per-batch chain boundary/anchor check failed");

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
                    // A single leaf has nothing to compose. Its proof still
                    // carries the sketch's Permute table, which the aggregation
                    // verifier (`verify_bound_proof`) does not register — so for
                    // t == 1 we report the leaf's own self-verify (run at prove
                    // time) rather than re-verifying the raw leaf.
                    let single_leaf = leaves.len() < 2;
                    let single_verify_ms = leaves[0].verify_ms;
                    let outputs: Vec<RecursionOutput<ConfigWithFriParams>> =
                        leaves.into_iter().map(|l| l.output).collect();
                    // Real recursive fold → one O(1) root. Timed as merge.
                    let t0 = std::time::Instant::now();
                    let root = if !single_leaf {
                        match mode {
                            StreamMode::Chain => prove_chain_over(outputs),
                            _ => prove_forest_over(outputs),
                        }
                    } else {
                        outputs.into_iter().next().expect(">=1 leaf")
                    };
                    let merge_ms = t0.elapsed().as_secs_f64() * 1000.0;
                    let bytes = proof_size(&root.0) as u64;
                    // Verifier: one succinct check of the merged root (t == 1 uses
                    // the leaf's self-verify, see above).
                    let verify_ms = if single_leaf {
                        single_verify_ms
                    } else {
                        let tv = std::time::Instant::now();
                        verify_bound_proof(&root);
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
            }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> StreamShape {
        StreamShape { d: 4, w: 8, b: 4, capacity: 4, gk_s: 2 }
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
                StreamFamily::CmOmc, shape(), &batches, mode, 1, query_at, QueryKeyMode::First,
            )
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
    /// mismatch would panic `record_query`'s assert), and the per-mode verifier
    /// context counts are the structural values: forest peaks = popcount(t'),
    /// per_batch = t', chain = 1.
    #[test]
    fn mixed_queries_smoke() {
        let batches: Vec<Vec<u32>> =
            (0..2).map(|i| (0..4).map(|j| (i * 4 + j + 1) as u32).collect()).collect();
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
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
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Mode-dependent ctx on one family: per_batch = 1+2, chain = 1+1.
        let dir = std::env::temp_dir().join("zksketch_mixed_ctx");
        let cell = measure_compose(
            StreamFamily::CmOmc, shape(), &batches, StreamMode::PerBatch, 1, 1, &dir, &[1, 2],
            QueryKeyMode::First,
        );
        assert_eq!(cell.query_ctx_verifies, 3, "per_batch ctx = t' sum");
        let cell = measure_compose(
            StreamFamily::CmOmc, shape(), &batches, StreamMode::Chain, 1, 1, &dir, &[1, 2],
            QueryKeyMode::First,
        );
        assert_eq!(cell.query_ctx_verifies, 2, "chain ctx = 1 per query");
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
            assert!(cell.verify_ms > 0.0, "t=1 uses the leaf self-verify ({mode:?})");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
