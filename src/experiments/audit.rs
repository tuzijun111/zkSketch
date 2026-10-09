//! **The AUDITOR side of the composition harness** (B6(b) statement checks,
//! B2 hiding commitments).
//!
//! Every function here consumes only what a verifier holds: the PUBLISHED
//! batch log ([`BatchLog`]: `Com(S_0)`, `Com(S_T)`, every `Com(B_t)`), the
//! received proofs, a trusted VK, and public parameters ([`PublicParams`]:
//! the family, its shape and batch size, and the commitment MODE, which is
//! public because it changes every VK). Nothing here takes, derives or reads
//! the prover's salt seed or a per-version randomizer: the log is produced
//! PROVER-side (`dist_compose::publish_batch_log` and its Goldilocks twin),
//! and the auditor compares commitment values without ever opening one. A
//! source-level test (`tests::auditor_source_names_no_prover_secret`) keeps
//! the prover-side seed types and randomizer derivations out of this file.
//! That includes the query side (Property 3): [`QueryAudit`] (decode and
//! prefix VKs from public parameters, prefix certificates tiled against the
//! log) and [`ContextStore`] (the certificates the procs workers shipped).
//!
//! The one commitment the auditor recomputes is the genesis anchor
//! `Com(S_0)`: `S_0` is the public empty sketch and its randomizer is the
//! public zero, so [`genesis_commit_bb`] / [`genesis_commit_gl`] rebuild it
//! from public parameters and [`check_log_genesis_bb`] /
//! [`check_log_genesis_gl`] hold the published log to it (before the timed
//! verify, like the VK derivation: a one-time, per-deployment check).
//! `Com(S_T)` and every `Com(B_t)` are taken from the published log.

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::time::Instant;

use p3_circuit_prover::BatchStarkProof;
use p3_recursion::RecursionOutput;

use crate::commitment::countmin::commit_countmin_with;
use crate::commitment::hiding::{CommitMode, SaltBb, SaltGl};
use crate::config::Val;
use crate::decode::bloom::bloom_decode_vk_commit;
use crate::decode::countmin::{cm_decode_vk_commit, CmDecodeParams};
use crate::decode::gk_bandmerge::{gk2_decode_vk_commit, Gkb2DecodeParams};
use crate::decode::hyperloglog::{hll_omc_decode_vk_commit, HllDecodeParams};
use crate::decode::kmv::kmv_decode_vk_commit;
use crate::decode::spacesaving::{ss_decode_vk_commit, SsDecodeParams};
use crate::decode::{check_query_statement, DecodeProof, DecodeVk, QueryStatement, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::config::D as EXT_D;
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl;
use crate::recursion::recursive::expose_forest::{
    check_leaves_against_log, check_root_against_log, read_exposed_statement, verify_bound_proof,
    verify_bound_proof_against_log, verify_bound_proof_self_pinned_legacy,
    verify_bound_stark_proof_against_log, verify_bound_stark_proof_pinned,
    verify_leaves_against_log, vk_pin_values, PrefixAuditor,
};
use crate::recursion::recursive::root_vk::{
    exp_root_vk, warn_self_pinned_legacy, ExpRootVk, ForestShape, RootVk,
};
use crate::recursion::recursive::statement::{
    check_prefix_statements, composition_expose, hash_bb, BatchLog, Expose, Statement,
};
use crate::sketch::bind::{default_binding, Binding};
use crate::sketch::gk_bandmerge::{commit_gk2_state_with, Gk2State, GkbParams};
use crate::sketch::hll_omc::{commit_hll_omc_with, hll_omc_empty};
use crate::sketch::ss_final_full::{commit_ss_state_with, SsFullParams, SsFullState};

use super::dist_compose::{
    derive_dist_leaf_vk, derive_dist_leaf_vk_gl, derive_dist_root_vk, derive_dist_root_vk_gl,
    dist_tree_shape, resolve_root_vk, resolve_trusted_vk,
};
use super::families::cm_empty;
use super::stream_compose::{QueryArt, StreamFamily, StreamMode, StreamShape};

type Proof = BatchStarkProof<ConfigWithFriParams>;
type ProofGl = BatchStarkProof<ConfigWithFriParamsGl>;
type GlVal = crate::config_gl::Val;

/// What the auditor knows about a stream besides the log: public parameters
/// only.
#[derive(Clone, Copy, Debug)]
pub struct PublicParams {
    pub family: StreamFamily,
    pub shape: StreamShape,
    /// Batch size (every leaf's record count).
    pub m: usize,
    /// Whether the deployment's commitments are hiding (public: the leaf and
    /// decoder circuits, hence their VKs, differ between the modes).
    pub commit_mode: CommitMode,
}

// ─── The genesis anchor ─────────────────────────────────────────────────────

/// `Com(S_0)` of a BabyBear stream's genesis history, from public parameters
/// alone: the family's empty sketch under the public zero randomizer (under
/// `Plain`, the pre-B2 commitment of the empty sketch).
pub fn genesis_commit_bb(pp: &PublicParams) -> [Val; 8] {
    let (mode, zero) = (pp.commit_mode, &SaltBb::ZERO);
    let s = &pp.shape;
    match pp.family {
        StreamFamily::CmOmc => commit_countmin_with(&cm_empty(s.d, s.w), mode, zero).0,
        StreamFamily::HllOmc => commit_hll_omc_with(&hll_omc_empty(s.b), s.b, mode, zero),
        StreamFamily::SsCertified => commit_ss_state_with(
            &SsFullState::empty(SsFullParams { capacity: s.capacity, batch: pp.m }),
            mode,
            zero,
        )
        .0,
        StreamFamily::GkBandmerge2 => commit_gk2_state_with(
            &Gk2State::empty(GkbParams { capacity: s.capacity, batch: pp.m, s: s.gk_s }),
            mode,
            zero,
        )
        .0,
        StreamFamily::BloomOmc => {
            use crate::sketch::bloom_omc::{bloom_empty, commit_bloom_with};
            commit_bloom_with(&bloom_empty(&s.bloom_params(pp.m)), mode, zero)
        }
        StreamFamily::KmvSketch => {
            use crate::sketch::kmv::{commit_kmv_state_with, KmvState};
            commit_kmv_state_with(&KmvState::empty(s.kmv_params(pp.m).k), mode, zero)
        }
        other => panic!("{other:?} is a Goldilocks family: use genesis_commit_gl"),
    }
}

/// Goldilocks twin of [`genesis_commit_bb`].
pub fn genesis_commit_gl(pp: &PublicParams) -> [GlVal; 4] {
    use crate::sketch::countmin_omc_gl::{cm_gl_empty, commit_countmin_with as cm_commit};
    use crate::sketch::gk_bandmerge_gl::{
        commit_gk2_state_with as gk_commit, Gk2State as Gk2StateGl, GkbParams as GkbParamsGl,
    };
    use crate::sketch::hll_omc_gl::{commit_hll_omc_with as hll_commit, hll_omc_empty as hll_empty};
    use crate::sketch::ss_final_full_gl::{
        commit_ss_state_with as ss_commit, SsFullParams as SsFullParamsGl,
        SsFullState as SsFullStateGl,
    };
    let (mode, zero) = (pp.commit_mode, &SaltGl::ZERO);
    let s = &pp.shape;
    match pp.family {
        StreamFamily::CmOmcGl => cm_commit(&cm_gl_empty(s.d, s.w), mode, zero).0,
        StreamFamily::HllOmcGl => hll_commit(&hll_empty(s.b), s.b, mode, zero),
        StreamFamily::SsCertifiedGl => ss_commit(
            &SsFullStateGl::empty(SsFullParamsGl { capacity: s.capacity, batch: pp.m }),
            mode,
            zero,
        )
        .0,
        StreamFamily::GkBandmerge2Gl => gk_commit(
            &Gk2StateGl::empty(GkbParamsGl { capacity: s.capacity, batch: pp.m, s: s.gk_s }),
            mode,
            zero,
        )
        .0,
        other => panic!("{other:?} is a BabyBear family: use genesis_commit_bb"),
    }
}

/// The published log must open with the genesis anchor the auditor
/// recomputes itself ([`genesis_commit_bb`]); a log anchored anywhere else
/// (another start state, a non-zero `ρ_0`) is rejected.
pub fn check_log_genesis_bb(pp: &PublicParams, log: &BatchLog<Val>) -> Result<(), String> {
    if log.init[..] != genesis_commit_bb(pp)[..] {
        return Err("log Com(S_0) != the genesis anchor recomputed from public parameters".into());
    }
    Ok(())
}

/// Goldilocks twin of [`check_log_genesis_bb`].
pub fn check_log_genesis_gl(pp: &PublicParams, log: &BatchLog<GlVal>) -> Result<(), String> {
    if log.init[..] != genesis_commit_gl(pp)[..] {
        return Err("log Com(S_0) != the genesis anchor recomputed from public parameters".into());
    }
    Ok(())
}

// ─── Distributed engine (`dist_compose`): proofs arrive as wire bytes ────────

/// The auditor's check of LEAF proofs it receives directly, as postcard bytes
/// (per_batch: all `t` leaves; chain/forest with `t == 1`: the lone leaf).
///
/// The genesis anchor is checked first ([`check_log_genesis_bb`]). Default
/// (`EXP_ROOT_VK` unset / `derive`, or a VK file): the trusted leaf VK is
/// resolved OUTSIDE the timed verify (`dist_compose::derive_dist_leaf_vk`, a
/// no-op leaf of the public parameters), the bytes are decoded, and then
/// every leaf is pinned to it, STARK-verified, and its statement checked
/// against `log` ([`verify_leaves_against_log`]); returns the measured verify
/// time in ms. Legacy `EXP_ROOT_VK=self` (warned): the leaves are only
/// decoded and their statements checked, which authenticates nothing, and
/// the workers' self-verify total `self_verify_ms` is reported, exactly as
/// before the pin existed.
pub(crate) fn audit_leaf_bytes(
    pp: &PublicParams,
    bytes: &[&[u8]],
    log: &BatchLog<Val>,
    layout: Expose,
    self_verify_ms: f64,
) -> Result<f64, String> {
    check_log_genesis_bb(pp, log)?;
    let vk = resolve_trusted_vk(|| derive_dist_leaf_vk(pp.family, &pp.shape, pp.m, pp.commit_mode))?;
    let proofs: Vec<Proof> = bytes
        .iter()
        .map(|b| postcard::from_bytes(b))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("leaf decode: {e}"))?;
    let refs: Vec<&Proof> = proofs.iter().collect();
    match &vk {
        Some(vk) => {
            let v0 = Instant::now();
            verify_leaves_against_log(&refs, vk, log, layout)
                .map_err(|e| format!("leaf audit: {e}"))?;
            Ok(v0.elapsed().as_secs_f64() * 1000.0)
        }
        None => {
            check_leaves_against_log(&refs, log, layout)
                .map_err(|e| format!("leaf statements vs log: {e}"))?;
            Ok(self_verify_ms)
        }
    }
}

/// Goldilocks analog of [`audit_leaf_bytes`].
pub(crate) fn audit_leaf_bytes_gl(
    pp: &PublicParams,
    bytes: &[&[u8]],
    log: &BatchLog<GlVal>,
    layout: Expose,
    self_verify_ms: f64,
) -> Result<f64, String> {
    use crate::recursion::recursive::expose_forest_gl as efg;
    check_log_genesis_gl(pp, log)?;
    let vk =
        resolve_trusted_vk(|| derive_dist_leaf_vk_gl(pp.family, &pp.shape, pp.m, pp.commit_mode))?;
    let proofs: Vec<ProofGl> = bytes
        .iter()
        .map(|b| postcard::from_bytes(b))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("leaf decode: {e}"))?;
    let refs: Vec<&ProofGl> = proofs.iter().collect();
    match &vk {
        Some(vk) => {
            let v0 = Instant::now();
            efg::verify_leaves_against_log(&refs, vk, log, layout)
                .map_err(|e| format!("leaf audit: {e}"))?;
            Ok(v0.elapsed().as_secs_f64() * 1000.0)
        }
        None => {
            efg::check_leaves_against_log(&refs, log, layout)
                .map_err(|e| format!("leaf statements vs log: {e}"))?;
            Ok(self_verify_ms)
        }
    }
}

/// The auditor's check of the composed artifact of a chain/forest run: the
/// root proof bytes (or, for a one-batch stream, the lone leaf, audited like
/// a per_batch leaf by [`audit_leaf_bytes`]). The root VK (commitment +
/// metadata) is pinned to a trusted copy (`EXP_ROOT_VK`, derived from public
/// parameters by default) resolved outside the timed verify; under the
/// Interval layout the root statement is then checked against the log
/// (`lo = 1`, `hi = T`, `Com(S_0)`, `Com(S_T)`, the ordered-batch digest
/// recomputed natively under the run's bracketing: `O(T)` hashes, inside the
/// timing). Under the Boundary layout the root's `(init, final)` must equal
/// the log's `(Com(S_0), Com(S_T))`. Panics on a rejected root (as the
/// pre-B2 auditor did); returns the verify time in ms.
#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_root_bytes(
    pp: &PublicParams,
    bytes: &[u8],
    log: &BatchLog<Val>,
    stream_mode: StreamMode,
    t: usize,
    machines: usize,
    layout: Expose,
    leaf_verify_ms: f64,
) -> Result<f64, String> {
    check_log_genesis_bb(pp, log)?;
    let proof: Proof = postcard::from_bytes(bytes).map_err(|e| format!("root decode: {e}"))?;
    if t == 1 {
        // A one-batch stream: the "root" is the lone LEAF proof. The
        // aggregation verifier cannot check it (it lacks the sketch's
        // tables), so it is verified like a per_batch leaf.
        return audit_leaf_bytes(pp, &[bytes], log, layout, leaf_verify_ms);
    }
    let st = read_exposed_statement(&proof);
    if st.init != log.init || st.final_ != log.final_ {
        return Err("root boundary != the log's (Com(S_0), Com(S_T))".into());
    }
    let tree = dist_tree_shape(stream_mode, t, machines);
    let expected_root_vk = resolve_root_vk(
        || vk_pin_values(&proof),
        || derive_dist_root_vk(pp.family, &pp.shape, pp.m, stream_mode, t, machines, pp.commit_mode),
    )?;
    let v0 = Instant::now();
    if layout == Expose::Interval {
        verify_bound_stark_proof_against_log(&proof, &expected_root_vk, log, &tree);
    } else {
        verify_bound_stark_proof_pinned(&proof, &expected_root_vk);
    }
    Ok(v0.elapsed().as_secs_f64() * 1000.0)
}

/// Goldilocks analog of [`audit_root_bytes`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_root_bytes_gl(
    pp: &PublicParams,
    bytes: &[u8],
    log: &BatchLog<GlVal>,
    stream_mode: StreamMode,
    t: usize,
    machines: usize,
    layout: Expose,
    leaf_verify_ms: f64,
) -> Result<f64, String> {
    use crate::recursion::recursive::expose_forest_gl as efg;
    check_log_genesis_gl(pp, log)?;
    let proof: ProofGl = postcard::from_bytes(bytes).map_err(|e| format!("root decode: {e}"))?;
    if t == 1 {
        return audit_leaf_bytes_gl(pp, &[bytes], log, layout, leaf_verify_ms);
    }
    let st = efg::read_exposed_statement(&proof);
    if st.init != log.init || st.final_ != log.final_ {
        return Err("root boundary != the log's (Com(S_0), Com(S_T))".into());
    }
    let tree = dist_tree_shape(stream_mode, t, machines);
    let expected_root_vk = resolve_root_vk(
        || efg::vk_pin_values(&proof),
        || {
            derive_dist_root_vk_gl(pp.family, &pp.shape, pp.m, stream_mode, t, machines, pp.commit_mode)
        },
    )?;
    let v0 = Instant::now();
    if layout == Expose::Interval {
        efg::verify_bound_stark_proof_against_log(&proof, &expected_root_vk, log, &tree);
    } else {
        efg::verify_bound_stark_proof_pinned(&proof, &expected_root_vk);
    }
    Ok(v0.elapsed().as_secs_f64() * 1000.0)
}

// ─── Single-process engine (`stream_compose`): proofs arrive in memory ───────

/// The trusted VK the auditor verifies a sim-engine stream's artifact
/// against, derived from public parameters only (a no-op leaf of the
/// family's leaf circuit under `pp.commit_mode`, via `dist_compose`) — the
/// default:
///
/// * chain / forest with `t >= 2`: the ROOT VK of the fold's tree shape
///   (`dist_compose::derive_dist_root_vk` with one machine);
/// * per_batch, and chain / forest with `t == 1` (the artifact is then a lone
///   leaf proof): the LEAF VK (`dist_compose::derive_dist_leaf_vk`), against
///   which every leaf the auditor holds is pinned and STARK-verified
///   ([`verify_leaves_against_log`]).
///
/// `None` only for the explicit `EXP_ROOT_VK=self` legacy opt-in (warned: the
/// root is self-pinned and leaf proofs are not re-verified), and for a
/// Goldilocks family, which the sim engine rejects.
pub(crate) fn compose_trusted_vk(
    pp: &PublicParams,
    stream_mode: StreamMode,
    t: usize,
) -> Option<RootVk<crate::config::Challenge>> {
    if pp.family.is_gl() {
        return None;
    }
    let leaf_artifact = stream_mode == StreamMode::PerBatch || t < 2;
    match exp_root_vk() {
        ExpRootVk::Derive => Some(if leaf_artifact {
            derive_dist_leaf_vk(pp.family, &pp.shape, pp.m, pp.commit_mode)
        } else {
            derive_dist_root_vk(pp.family, &pp.shape, pp.m, stream_mode, t, 1, pp.commit_mode)
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

/// The per_batch / lone-leaf auditor of the sim engine: the genesis anchor
/// check, then, with a trusted leaf VK, pin + STARK-verify every leaf and
/// check the statements against `log` (timed; returns ms). Without one
/// (legacy `EXP_ROOT_VK=self` only), check the statements alone — which
/// authenticates nothing — and report the provers' self-verify total
/// `self_verify_ms`, as before the pin existed. Panics on a rejection.
pub(crate) fn audit_leaves(
    pp: &PublicParams,
    leaves: &[&Proof],
    leaf_vk: Option<&RootVk<crate::config::Challenge>>,
    log: &BatchLog<Val>,
    layout: Expose,
    self_verify_ms: f64,
) -> f64 {
    if let Err(e) = check_log_genesis_bb(pp, log) {
        panic!("batch log: {e}");
    }
    match leaf_vk {
        Some(vk) => {
            let tv = Instant::now();
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

/// The sim engine's root auditor (chain/forest, `t >= 2`): the genesis anchor
/// check, then one succinct check of the merged root, pinned to the derived
/// root VK (fails closed on a mismatch); only the explicit `EXP_ROOT_VK=self`
/// opt-in self-pins (a fixed-size equality either way, so the timing is
/// comparable). Interval layout (default): the root statement is checked
/// against the log (`O(T)` native hashes, inside the timing). Boundary
/// layout: the root's `(init, final)` must still be the log's
/// `(Com(S_0), Com(S_T))`. Panics on a rejection; returns ms.
pub(crate) fn audit_root(
    pp: &PublicParams,
    root: &RecursionOutput<ConfigWithFriParams>,
    root_vk: Option<&RootVk<crate::config::Challenge>>,
    log: &BatchLog<Val>,
    tree: &ForestShape,
    layout: Expose,
) -> f64 {
    if let Err(e) = check_log_genesis_bb(pp, log) {
        panic!("batch log: {e}");
    }
    let interval = layout == Expose::Interval;
    let tv = Instant::now();
    match (root_vk, interval) {
        (Some(vk), true) => verify_bound_proof_against_log(root, vk, log, tree),
        (Some(vk), false) => verify_bound_proof(root, vk),
        (None, true) => {
            verify_bound_proof_self_pinned_legacy(root);
            if let Err(e) = check_root_against_log(&root.0, log, tree) {
                panic!("root statement vs log: {e}");
            }
        }
        (None, false) => verify_bound_proof_self_pinned_legacy(root),
    }
    if !interval {
        let st = read_exposed_statement(&root.0);
        assert!(
            st.init == log.init && st.final_ == log.final_,
            "root boundary != the log's (Com(S_0), Com(S_T))"
        );
    }
    tv.elapsed().as_secs_f64() * 1000.0
}

// ─── Queries ────────────────────────────────────────────────────────────────

/// Property 3 at the harness level: the query proof must EXPOSE `commit`
/// (the published `Com(S_{t'})` it answers against: leaf `t'`'s final), the
/// query that was asked and the answer it reports (`(Com(S), q, answer)`, 16
/// values; the keyless hll / kmv `(Com(S), answer)`, 12), so a verifier
/// reading only the proof learns what was certified. Fails closed (panics).
/// Skipped under `ZKSKETCH_BINDING=legacy`, whose pre-fix decoders expose
/// nothing (the Legacy warning is printed when it is selected).
pub fn check_query_exposure(
    dp: &DecodeProof,
    commit: [Val; 8],
    query: Option<[Val; 4]>,
    at_leaf: usize,
) {
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
                .unwrap_or_else(|| panic!("keyless (hll/kmv) query proof at t'={at_leaf} exposes no (Com(S), answer)"));
            assert_eq!(&pv[..8], &commit[..], "keyless (hll/kmv) query proof at t'={at_leaf}: exposed Com(S)");
            use p3_field::PrimeCharacteristicRing;
            assert_eq!(pv[8], Val::from_u64(dp.answer), "keyless (hll/kmv) query proof at t'={at_leaf}: exposed answer");
            assert!(pv[9..].iter().all(|v| *v == Val::ZERO), "keyless (hll/kmv) answer must be a base element");
        }
    }
}

// ─── Query binding (Property 3) ─────────────────────────────────────────────
//
// The auditor of the mixed workload: decode VKs and prefix VKs derived from
// public parameters, prefix certificates verified and tiled against the log
// the auditor holds (the prover-published one under `Hiding`).

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
    Proof(&'a Proof),
    Bytes(&'a [u8]),
}

/// One part of a prefix certificate: the interval `[lo, hi]` it covers, the
/// bracketing it was folded under, and the proof.
pub(crate) type CtxPart<'a> = (u64, u64, ForestShape, CtxProof<'a>);

/// The verifier side of the mixed workload (Property 3): the trusted VK of
/// the family's query circuit and a [`PrefixAuditor`] (trusted VKs per
/// bracketing), all derived from public parameters (the family, its shape,
/// the batch size and the commitment MODE, which is public because the
/// hiding leaf and decoder circuits differ from the plain ones; never the
/// prover's seed). Every query proof is pinned to the decode VK of that mode
/// (`stream_compose::record_query`), and its exposed `Com(S)` must equal the `Com(S_{t'})`
/// certified by the interval proofs live at its version ([`Self::bind`]):
/// the forest's peaks, the chain's current fold, or the per-batch leaves,
/// tiled against the batch log the auditor holds (under `Hiding`, the
/// salted log the prover published; it never recomputes a salted
/// commitment).
///
/// Each distinct interval proof is verified once and its time memoised: a
/// stateless verifier answering one query pays the sum over that query's
/// certificate, which is what [`QueryBind::ms`] reports, without the harness
/// re-verifying a peak that several queries share. The memo is keyed by the
/// interval, its bracketing AND a fingerprint of the proof bytes, so a
/// different proof offered later for an interval already seen is verified
/// on its own (never served the earlier proof's statement). The query-side
/// auditor lives in this file so that the source-level isolation test
/// (`tests::auditor_source_names_no_prover_secret`) covers it.
pub(crate) struct QueryAudit {
    pub(crate) decode_vk: DecodeVk,
    prefix: PrefixAuditor,
    /// `Com(S_0)` recomputed from public parameters (the empty sketch under
    /// the public zero randomizer, [`genesis_commit_bb`]): the
    /// one commitment this auditor computes itself. Every log it binds
    /// against must open with it.
    genesis: [Val; 8],
    /// Verified parts: `(lo, hi, bracketing, proof fingerprint)` to the
    /// verify time and the statement read off the proof.
    memo: HashMap<(u64, u64, ForestShape, u64), (f64, Statement<Val>)>,
    /// Per-auditor random SipHash key of the proof fingerprints, so a prover
    /// cannot aim a different proof at the fingerprint of a verified one.
    /// (Even a collision would only serve a statement that WAS verified for
    /// that interval and bracketing.)
    fingerprint: RandomState,
}

impl QueryAudit {
    /// The family's auditor, or `None` under the legacy opt-ins that cannot
    /// bind an answer (`ZKSKETCH_BINDING=legacy`: the decoders expose
    /// nothing; `ZKSKETCH_STATEMENT=boundary`: no interval to tile;
    /// `EXP_ROOT_VK=self`: no trusted VKs), with a loud warning.
    /// `commit_mode` selects the decode and leaf circuits whose VKs are
    /// derived (each from the empty state / the no-op leaf with the public
    /// zero salt; a salt is a witness, so the VK pins every proof of the
    /// mode).
    pub(crate) fn new(
        family: StreamFamily,
        shape: &StreamShape,
        m: usize,
        commit_mode: CommitMode,
    ) -> Option<Self> {
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
        let id = ReleasePolicy::Identity;
        let decode_vk = match family {
            StreamFamily::CmOmc => cm_decode_vk_commit(
                CmDecodeParams { d: shape.d, w: shape.w, release: id },
                default_binding(),
                commit_mode,
            ),
            StreamFamily::HllOmc => hll_omc_decode_vk_commit(
                HllDecodeParams { b: shape.b, release: id },
                default_binding(),
                commit_mode,
            ),
            StreamFamily::SsCertified => ss_decode_vk_commit(
                SsDecodeParams { capacity: shape.capacity, c: 1, release: id },
                default_binding(),
                commit_mode,
            ),
            StreamFamily::GkBandmerge2 => gk2_decode_vk_commit(
                Gkb2DecodeParams { capacity: shape.capacity, release: id },
                default_binding(),
                commit_mode,
            ),
            // The membership circuit has one (bound) construction; it does
            // not depend on the binding, nor on the batch size.
            StreamFamily::BloomOmc => bloom_decode_vk_commit(shape.bloom_params(m), commit_mode),
            // The distinct-count decoder depends on `k` only (not on the
            // batch size); `Legacy` builds the Semantic decoder.
            StreamFamily::KmvSketch => {
                kmv_decode_vk_commit(shape.kmv_decode_params(), default_binding(), commit_mode)
            }
            _ => unreachable!("Goldilocks families are rejected above"),
        };
        let noop = super::dist_compose::prove_noop_leaf(family, shape, m, commit_mode);
        let genesis = genesis_commit_bb(&PublicParams { family, shape: *shape, m, commit_mode });
        Some(Self {
            decode_vk,
            prefix: PrefixAuditor::new(noop),
            genesis,
            memo: HashMap::new(),
            fingerprint: RandomState::new(),
        })
    }

    /// Fingerprint of a part's proof bytes (an in-memory proof is serialized
    /// exactly as a worker ships it).
    fn fingerprint(&self, src: &CtxProof<'_>) -> Result<u64, String> {
        Ok(match src {
            CtxProof::Bytes(b) => self.fingerprint.hash_one(b),
            CtxProof::Proof(p) => {
                let b = postcard::to_allocvec(*p).map_err(|e| format!("serialize: {e}"))?;
                self.fingerprint.hash_one(b.as_slice())
            }
        })
    }

    /// Bind query `q` (its version `q.at_leaf`) to the certified history with
    /// the prefix certificate `parts`: verify each part under the trusted VK
    /// of its bracketing (memoised per proof, so only an identical proof of
    /// the same interval reuses an earlier verification; the one-time VK
    /// derivation and the fingerprint are outside the timing), check that
    /// `log` opens with the genesis anchor recomputed from public parameters
    /// and that the statements tile `[1, t']` against it, and require the
    /// query proof's exposed `Com(S)` to equal the certified `Com(S_{t'})`.
    /// Fails closed.
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
            let fp =
                self.fingerprint(src).map_err(|e| format!("part {} [{lo}, {hi}]: {e}", k + 1))?;
            let key = (*lo, *hi, shape.clone(), fp);
            if !self.memo.contains_key(&key) {
                self.prefix.vk(shape);
                let t0 = std::time::Instant::now();
                let owned: Proof;
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
        if log.init[..] != self.genesis[..] {
            return Err("log Com(S_0) != the genesis anchor recomputed from public parameters".into());
        }
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

#[cfg(test)]
mod tests {
    /// The audit path's isolation, at the source level: outside this test
    /// module, `audit.rs` never names the prover-side seed or context types,
    /// the randomizer derivations or the leaf openings, so no auditor entry
    /// point can reach the prover's secret (they take the published log,
    /// proofs and [`PublicParams`] only).
    #[test]
    fn auditor_source_names_no_prover_secret() {
        let src = include_str!("audit.rs");
        let body = src.split("#[cfg(test)]").next().expect("source before the tests");
        for banned in [
            "SaltSeed",
            "ProverCommit",
            "prover_commit",
            "rho_state",
            "rho_batch",
            "Openings",
            "for_leaf",
            "SALT_SEED",
            "state_salt",
            "batch_salt",
            "os_random",
        ] {
            assert!(!body.contains(banned), "the auditor module names `{banned}`");
        }
    }
}
