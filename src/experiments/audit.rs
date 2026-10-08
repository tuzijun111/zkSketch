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
//!
//! The one commitment the auditor recomputes is the genesis anchor
//! `Com(S_0)`: `S_0` is the public empty sketch and its randomizer is the
//! public zero, so [`genesis_commit_bb`] / [`genesis_commit_gl`] rebuild it
//! from public parameters and [`check_log_genesis_bb`] /
//! [`check_log_genesis_gl`] hold the published log to it (before the timed
//! verify, like the VK derivation: a one-time, per-deployment check).
//! `Com(S_T)` and every `Com(B_t)` are taken from the published log.

use std::time::Instant;

use p3_circuit_prover::BatchStarkProof;
use p3_recursion::RecursionOutput;

use crate::commitment::countmin::commit_countmin_with;
use crate::commitment::hiding::{CommitMode, SaltBb, SaltGl};
use crate::config::Val;
use crate::decode::{check_query_statement, DecodeProof, QueryStatement};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl;
use crate::recursion::recursive::expose_forest::{
    check_leaves_against_log, check_root_against_log, read_exposed_statement, verify_bound_proof,
    verify_bound_proof_against_log, verify_bound_proof_self_pinned_legacy,
    verify_bound_stark_proof_against_log, verify_bound_stark_proof_pinned,
    verify_leaves_against_log, vk_pin_values,
};
use crate::recursion::recursive::root_vk::{
    exp_root_vk, warn_self_pinned_legacy, ExpRootVk, ForestShape, RootVk,
};
use crate::recursion::recursive::statement::{BatchLog, Expose};
use crate::sketch::bind::{default_binding, Binding};
use crate::sketch::gk_bandmerge::{commit_gk2_state_with, Gk2State, GkbParams};
use crate::sketch::hll_omc::{commit_hll_omc_with, hll_omc_empty};
use crate::sketch::ss_final_full::{commit_ss_state_with, SsFullParams, SsFullState};

use super::dist_compose::{
    derive_dist_leaf_vk, derive_dist_leaf_vk_gl, derive_dist_root_vk, derive_dist_root_vk_gl,
    dist_tree_shape, resolve_root_vk, resolve_trusted_vk,
};
use super::families::cm_empty;
use super::stream_compose::{StreamFamily, StreamMode, StreamShape};

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
/// values; hll `(Com(S), answer)`, 12), so a verifier reading only the proof
/// learns what was certified. Fails closed (panics). Skipped under
/// `ZKSKETCH_BINDING=legacy`, whose pre-fix decoders expose nothing (the
/// Legacy warning is printed when it is selected).
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
                .unwrap_or_else(|| panic!("hll query proof at t'={at_leaf} exposes no (Com(S), answer)"));
            assert_eq!(&pv[..8], &commit[..], "hll query proof at t'={at_leaf}: exposed Com(S)");
            use p3_field::PrimeCharacteristicRing;
            assert_eq!(pv[8], Val::from_u64(dp.answer), "hll query proof at t'={at_leaf}: exposed answer");
            assert!(pv[9..].iter().all(|v| *v == Val::ZERO), "hll answer must be a base element");
        }
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
