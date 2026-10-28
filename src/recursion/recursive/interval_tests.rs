//! End-to-end tests of the Interval statement on real leaves. Batch-log attacks run against
//! both auditors: the old boundary-only one accepts them, the interval one rejects them.

use p3_circuit_prover::BatchStarkProof;
use p3_recursion::RecursionOutput;

use crate::config::Val;
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::{
    batch_log, check_root_against_log, prove_chain_over, prove_forest_over, prove_hiding_merge,
    prove_hiding_merge_proofs, read_exposed_boundary_proof, read_exposed_statement, root_vk_deriver,
    verify_bound_stark_proof_against_log, verify_bound_stark_proof_pinned,
};
use crate::recursion::recursive::root_vk::{ForestShape, RootVk};
use crate::recursion::recursive::statement::{BatchLog, Expose};
use crate::sketch::bind::Binding;

type Out = RecursionOutput<ConfigWithFriParams>;
type Proof = BatchStarkProof<ConfigWithFriParams>;

/// Runs `f`, turning a panic into `Err(first line of the message)`.
fn outcome<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    })
}

/// The pre-B6(b) auditor: derived root-VK pin + STARK + `init/final` vs log.
fn legacy_auditor(root: &Proof, vk: &RootVk<crate::config::Challenge>, log: &BatchLog<Val>) -> Result<(), String> {
    outcome(|| verify_bound_stark_proof_pinned(root, vk))?;
    let (i, f) = read_exposed_boundary_proof(root);
    if i.0.to_vec() != log.init {
        return Err("init != Com(S_0)".into());
    }
    if f.0.to_vec() != log.final_ {
        return Err("final != Com(S_T)".into());
    }
    Ok(())
}

/// The B6(b) auditor (default path).
fn new_auditor(
    root: &Proof,
    vk: &RootVk<crate::config::Challenge>,
    log: &BatchLog<Val>,
    shape: &ForestShape,
) -> Result<(), String> {
    outcome(|| verify_bound_stark_proof_against_log(root, vk, log, shape))
}

// ─── Count-Min omc ───────────────────────────────────────────────────────────

mod cm {
    use super::*;
    use crate::commitment::countmin::commit_countmin;
    use crate::recursion::recursive::noop_leaf::cm_omc_noop_leaf_expose;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
    use crate::sketch::countmin_omc::{
        CmOmcLeafCircuit, CmOmcParams, build_countmin_omc_leaf_expose,
        countmin_omc_advance_with, countmin_omc_batch_commit_with,
    };
    use crate::sketch::countmin_v9::CountMinV9;

    pub const P: CmOmcParams = CmOmcParams { d: 2, w: 4, batch: 2 };

    pub fn empty() -> CountMinState {
        CountMinV9::new(&CountMinParams { d: P.d, w: P.w })
    }

    pub fn batch(pairs: &[(u64, u32)]) -> Vec<CountMinUpdate> {
        pairs.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect()
    }

    /// `s` advanced by `b` under the omc leaf's `Semantic` native model (the
    /// binding [`leaf_circuit`] uses).
    pub fn apply(s: &CountMinState, b: &[CountMinUpdate]) -> CountMinState {
        let mut s = s.clone();
        countmin_omc_advance_with(&mut s, b, Binding::Semantic);
        s
    }

    pub fn leaf_circuit() -> CmOmcLeafCircuit {
        build_countmin_omc_leaf_expose(P, Expose::Interval, Binding::Semantic)
    }

    /// Prove `batches[k]` as leaf `indices[k]`, chaining the state from `s0`.
    /// Returns the leaves and the final state.
    pub fn leaves_at(
        leaf: &mut CmOmcLeafCircuit,
        s0: &CountMinState,
        batches: &[Vec<CountMinUpdate>],
        indices: &[u64],
    ) -> (Vec<Out>, CountMinState) {
        let mut s = s0.clone();
        let mut out = Vec::new();
        for (b, &t) in batches.iter().zip(indices) {
            out.push(leaf.prove_epoch_at(t, s.clone(), b.clone()).output);
            countmin_omc_advance_with(&mut s, b, leaf.binding());
        }
        (out, s)
    }

    pub fn log(s0: &CountMinState, s_t: &CountMinState, batches: &[Vec<CountMinUpdate>]) -> BatchLog<Val> {
        let commits: Vec<[Val; 8]> =
            batches.iter().map(|b| countmin_omc_batch_commit_with(b, Binding::Semantic)).collect();
        batch_log(&commit_countmin(s0).0, &commit_countmin(s_t).0, &commits)
    }

    pub fn honest_batches() -> Vec<Vec<CountMinUpdate>> {
        vec![
            batch(&[(7, 3), (11, 5)]),
            batch(&[(13, 2), (7, 4)]),
            batch(&[(99, 1), (5, 8)]),
            batch(&[(7, 2), (1234, 6)]),
        ]
    }

    pub fn noop() -> Proof {
        cm_omc_noop_leaf_expose(P, Expose::Interval, Binding::Semantic)
    }
}

/// Every CM omc Interval leaf exposes `(Com(S_{t-1}), Com(S_t), (t, t), H)`
/// with `H` equal to the NATIVE leaf digest of `(t, Com(B_t))`: the in-circuit
/// sponge and the native `MyHash` agree, and `t` is the prover's index.
#[test]
fn cm_leaf_statement_matches_native_digest() {
    use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
    let bs = cm::honest_batches();
    // Every binding: Semantic (default), Bound (zero-IV sponge, Range pin of
    // t) and Legacy (plain sponge, bit pin of t) all yield the native digest.
    for binding in [Binding::Semantic, Binding::Bound, Binding::Legacy] {
        let mut leaf = crate::sketch::countmin_omc::build_countmin_omc_leaf_expose(
            cm::P,
            Expose::Interval,
            binding,
        );
        let (leaves, _) = cm::leaves_at(&mut leaf, &cm::empty(), &bs[..2], &[1, 2]);
        for (k, l) in leaves.iter().enumerate() {
            let st = read_exposed_statement(&l.0);
            let iv = st.interval.expect("interval layout");
            let t = (k + 1) as u64;
            assert_eq!((iv.lo, iv.hi), (Val::new(t as u32), Val::new(t as u32)));
            assert!(iv.idx_pad.iter().all(|&x| x == Val::new(0)));
            let bc = crate::sketch::countmin_omc::countmin_omc_batch_commit_with(&bs[k], binding);
            assert_eq!(iv.digest, leaf_digest(&hash_bb, 4, t, &bc), "{binding:?} leaf {t}: H == native");
        }
    }
}

/// The leaf's batch index is a witness: an Interval leaf proved at `t = 7`
/// has the same VK as one proved at `t = 1` (so one no-op leaf serves the
/// derivation), and its exposed `idx` is `(7, 7)`.
#[test]
fn cm_leaf_vk_independent_of_batch_index() {
    use crate::recursion::recursive::expose_forest::vk_pin_values;
    let mut leaf = cm::leaf_circuit();
    let b = cm::honest_batches()[0].clone();
    let a = leaf.prove_epoch_at(1, cm::empty(), b.clone()).output;
    let c = leaf.prove_epoch_at(7, cm::empty(), b).output;
    assert_eq!(vk_pin_values(&a.0), vk_pin_values(&c.0));
    let iv = read_exposed_statement(&c.0).interval.unwrap();
    assert_eq!((iv.lo, iv.hi), (Val::new(7), Val::new(7)));
}

/// (e) HONEST, Count-Min: forest(3) (= chain(3) = dist_forest(3, 2) as a
/// shape), forest(4) and chain(4) roots, each verified end to end against the
/// log-recomputed digest and the VK derived from public parameters only; the
/// dist(3, 2) root is folded exactly as `dist_compose` does (machine 0 folds
/// leaves 1-2 in place, machine 1 ships leaf 3 as postcard bytes, machine 0
/// merges the deserialized proof). Also: derived == real root VK and
/// metadata, and a correct root is rejected under another shape's log check.
#[test]
fn cm_honest_forest_chain_dist_verify_against_log() {
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches();
    let s0 = cm::empty();
    let (l4, s4) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3, 4]);
    let s3 = cm::apply(&cm::apply(&cm::apply(&s0, &bs[0]), &bs[1]), &bs[2]);
    let log3 = cm::log(&s0, &s3, &bs[..3]);
    let log4 = cm::log(&s0, &s4, &bs);

    let mut deriver = root_vk_deriver(cm::noop());

    // forest(3)
    let m12 = prove_hiding_merge(&l4[0], &l4[1]);
    let f3 = prove_hiding_merge(&m12, &l4[2]);
    let vk_f3 = deriver.root_vk(&ForestShape::forest(3));
    assert_eq!(vk_f3.commitment, crate::recursion::recursive::expose_forest::vk_pin_values(&f3.0));
    assert_eq!(vk_f3.shape.as_ref(), Some(&crate::recursion::recursive::root_vk::bound_proof_shape(&f3.0)));
    verify_bound_stark_proof_against_log(&f3.0, &vk_f3, &log3, &ForestShape::forest(3));

    // dist_forest(3, 2): slice roots cross the "machine boundary" as bytes.
    let dist_shape = ForestShape::dist_forest(3, 2);
    assert_eq!(dist_shape, ForestShape::forest(3));
    let slice1: Proof = postcard::from_bytes(&postcard::to_allocvec(&l4[2].0).unwrap()).unwrap();
    let slice0: Proof = postcard::from_bytes(&postcard::to_allocvec(&m12.0).unwrap()).unwrap();
    let dist_root = prove_hiding_merge_proofs(&slice0, &slice1);
    let dist_root: Proof =
        postcard::from_bytes(&postcard::to_allocvec(&dist_root.0).unwrap()).unwrap();
    let vk_d = deriver.root_vk(&dist_shape);
    verify_bound_stark_proof_against_log(&dist_root, &vk_d, &log3, &dist_shape);

    // chain(3) is the same tree as forest(3): the chain VK and log check agree.
    verify_bound_stark_proof_against_log(
        &f3.0,
        &deriver.root_vk(&ForestShape::chain(3)),
        &log3,
        &ForestShape::chain(3),
    );

    // chain(4) = merge(forest(3), l4), folded by hand over the shared m12/f3.
    let c4 = prove_hiding_merge(&f3, &l4[3]);
    let vk_c4 = deriver.root_vk(&ForestShape::chain(4));
    assert_eq!(vk_c4.commitment, crate::recursion::recursive::expose_forest::vk_pin_values(&c4.0));
    verify_bound_stark_proof_against_log(&c4.0, &vk_c4, &log4, &ForestShape::chain(4));

    // forest(4) through the harness fold itself (consumes the leaves).
    let f4 = prove_forest_over(l4);
    let vk_f4 = deriver.root_vk(&ForestShape::forest(4));
    assert_eq!(vk_f4.commitment, crate::recursion::recursive::expose_forest::vk_pin_values(&f4.0));
    verify_bound_stark_proof_against_log(&f4.0, &vk_f4, &log4, &ForestShape::forest(4));

    // The digest alone distinguishes the bracketing (independently of the VK).
    let e = check_root_against_log(&f4.0, &log4, &ForestShape::chain(4));
    assert!(e.is_err_and(|e| e.contains("digest")), "forest(4) root under a chain(4) log check");
    // And the VK pin does too.
    assert!(new_auditor(&f4.0, &vk_c4, &log4, &ForestShape::forest(4)).is_err());
    println!(
        "B6B cm honest: forest3 / dist(3,2) / chain3 / chain4 / forest4 accepted; dummy merges = {}",
        deriver.dummy_merges()
    );
}

/// `prove_chain_over` over Interval leaves (the harness's chain fold).
#[test]
fn cm_honest_chain_fold_verifies_against_log() {
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches();
    let s0 = cm::empty();
    let (l3, s3) = cm::leaves_at(&mut leaf, &s0, &bs[..3], &[1, 2, 3]);
    let log3 = cm::log(&s0, &s3, &bs[..3]);
    let root = prove_chain_over(l3);
    let vk = root_vk_deriver(cm::noop()).root_vk(&ForestShape::chain(3));
    verify_bound_stark_proof_against_log(&root.0, &vk, &log3, &ForestShape::chain(3));
    assert!(legacy_auditor(&root.0, &vk, &log3).is_ok());
}

/// Property 3 at query time (the prefix certificate): after each leaf, the
/// forest's live peaks, checked by the [`PrefixAuditor`] (VK derived per
/// bracketing from a no-op leaf, pinned STARK verification, statements tiling
/// `[1, t']` against the log), certify exactly `Com(S_{t'})`; so do the
/// per-batch leaves and the chain's running fold. Rejected: the previous
/// version's peaks offered for `t'`, a proof claimed under another
/// bracketing, a leaf spliced from another stream whose boundary states match
/// (only `Com(B_2)` differs), and a toy proof exposing the honest statement.
///
/// [`PrefixAuditor`]: crate::recursion::recursive::expose_forest::PrefixAuditor
#[test]
fn cm_query_prefix_certified_by_live_peaks() {
    use crate::recursion::recursive::expose_forest::{
        ForestCascade, PrefixAuditor, prove_exposing_leaf,
    };
    use p3_field::BasedVectorSpace;
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches();
    let s0 = cm::empty();
    let (l4, s4) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3, 4]);
    let log = cm::log(&s0, &s4, &bs);
    let state_at =
        |k: usize| cm_commit(&bs[..k].iter().fold(s0.clone(), |s, b| cm::apply(&s, b)));
    let copy = |p: &Proof| -> Proof {
        postcard::from_bytes(&postcard::to_allocvec(p).unwrap()).unwrap()
    };
    fn refs(parts: &[(Proof, ForestShape)]) -> Vec<(&Proof, ForestShape)> {
        parts.iter().map(|(p, sh)| (p, sh.clone())).collect()
    }
    let mut auditor = PrefixAuditor::new(cm::noop());
    let leaf_copies: Vec<(Proof, ForestShape)> =
        l4.iter().map(|o| (copy(&o.0), ForestShape::Leaf)).collect();

    let mut forest = ForestCascade::new(1);
    let mut prev: Option<Vec<(Proof, ForestShape)>> = None;
    for (k, l) in l4.into_iter().enumerate() {
        let t = k + 1;
        forest.push(l);
        let peaks: Vec<(Proof, ForestShape)> = forest
            .peaks()
            .iter()
            .map(|(lo, hi, p)| (copy(p), ForestShape::forest((hi - lo + 1) as usize)))
            .collect();
        assert_eq!(peaks.len(), t.count_ones() as usize, "one peak per set bit of t'");
        assert_eq!(auditor.certify_prefix(&refs(&peaks), &log, t), Ok(state_at(t)), "peaks at t'={t}");
        assert_eq!(
            auditor.certify_prefix(&refs(&leaf_copies[..t]), &log, t),
            Ok(state_at(t)),
            "per-batch leaves at t'={t}"
        );
        if let Some(p) = &prev {
            let e = auditor.certify_prefix(&refs(p), &log, t);
            assert!(e.as_ref().is_err_and(|e| e.contains("certify [1,")), "stale peaks at t'={t}: {e:?}");
        }
        prev = Some(peaks);
    }
    // t' = 4: the one peak is forest(4); under chain(4) its VK is wrong.
    let p4 = prev.unwrap();
    let e = auditor.certify_prefix(&[(&p4[0].0, ForestShape::chain(4))], &log, 4);
    assert!(e.as_ref().is_err_and(|e| e.contains("VK")), "{e:?}");
    // A size-2 peak claimed as a lone leaf fails the leaf pin.
    let (l2, _) = cm::leaves_at(&mut leaf, &s0, &bs[..2], &[1, 2]);
    let m12 = copy(&prove_hiding_merge(&l2[0], &l2[1]).0);
    let e = auditor.certify_prefix(&[(&m12, ForestShape::Leaf)], &log, 2);
    assert!(e.is_err(), "merge proof under the leaf VK");

    // Splice: leaf 2 of a stream Y whose batch 2 is B_2 reordered (same
    // states, different Com(B_2)).
    let y_batches = vec![bs[0].clone(), rev(&bs[1])];
    let (y, _) = cm::leaves_at(&mut leaf, &s0, &y_batches, &[1, 2]);
    let spliced = vec![(copy(&leaf_copies[0].0), ForestShape::Leaf), (copy(&y[1].0), ForestShape::Leaf)];
    let e = auditor.certify_prefix(&refs(&spliced), &log, 2);
    assert!(e.as_ref().is_err_and(|e| e.contains("digest")), "{e:?}");

    // A toy circuit exposing leaf 1's honest statement values.
    let vals = read_exposed_statement(&leaf_copies[0].0).values();
    let chals: Vec<crate::config::Challenge> = vals
        .chunks(4)
        .map(|c| crate::config::Challenge::from_basis_coefficients_slice(c).unwrap())
        .collect();
    let toy = prove_exposing_leaf(&chals);
    assert_eq!(read_exposed_statement(&toy.0), read_exposed_statement(&leaf_copies[0].0));
    let e = auditor.certify_prefix(&[(&toy.0, ForestShape::Leaf)], &log, 1);
    assert!(e.is_err(), "the toy proof is not the leaf circuit");

    // The chain's running fold Π_[1,4] certifies version 4 under chain(4).
    let (l4b, _) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3, 4]);
    let c4 = prove_chain_over(l4b);
    assert_eq!(auditor.certify_prefix(&[(&c4.0, ForestShape::chain(4))], &log, 4), Ok(state_at(4)));
    assert!(auditor.certify_prefix(&[(&c4.0, ForestShape::forest(4))], &log, 4).is_err());
}

// ─── Attacks: Count-Min omc ──────────────────────────────────────────────────

fn rev(b: &[crate::sketch::countmin::CountMinUpdate]) -> Vec<crate::sketch::countmin::CountMinUpdate> {
    b.iter().rev().copied().collect()
}

/// A no-op Count-Min batch (value-0 updates): the state does not move, so two
/// such leaves chain in either order and only the INDEX statement can tell
/// them apart.
fn cm_zero_batch(k: u64) -> Vec<crate::sketch::countmin::CountMinUpdate> {
    cm::batch(&[(k, 0), (k + 1, 0)])
}

fn cm_commit(s: &crate::sketch::countmin::CountMinState) -> Vec<Val> {
    crate::commitment::countmin::commit_countmin(s).0.to_vec()
}

/// (a) SUBSTITUTE a leaf proved over a different batch than the log's.
/// (a1) `B'_2` has different records; the prover posts the resulting
///      `Com(S'_3)` as the final (the log's batch commitments stay honest).
/// (a2) `B'_2` = `B_2` with its records reordered: every state commitment,
///      including the final, is the HONEST one, only `Com(B_2)` differs.
/// Both roots pass the pre-B6(b) auditor; the digest check rejects both.
#[test]
fn cm_attack_substituted_batch_rejected() {
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches()[..3].to_vec();
    let s0 = cm::empty();
    let s3 = bs.iter().fold(s0.clone(), |s, b| cm::apply(&s, b));
    let honest = cm::log(&s0, &s3, &bs);
    let shape = ForestShape::forest(3);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);

    // Control: the honest root passes both auditors.
    let (hl, _) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3]);
    let hroot = prove_forest_over(hl);
    assert!(legacy_auditor(&hroot.0, &vk, &honest).is_ok());
    assert!(new_auditor(&hroot.0, &vk, &honest, &shape).is_ok());

    // (a1)
    let mut forged = bs.clone();
    forged[1] = cm::batch(&[(500, 9), (7, 1)]);
    let (fl, s3f) = cm::leaves_at(&mut leaf, &s0, &forged, &[1, 2, 3]);
    assert_ne!(cm_commit(&s3f), cm_commit(&s3));
    let root = prove_forest_over(fl);
    let posted = BatchLog { final_: cm_commit(&s3f), ..honest.clone() };
    let legacy = legacy_auditor(&root.0, &vk, &posted);
    let new = new_auditor(&root.0, &vk, &posted, &shape);
    println!("B6B (a1) substituted batch: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok(), "the pre-B6(b) auditor accepts the substituted history");
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");

    // (a2)
    let mut reordered = bs.clone();
    reordered[1] = rev(&bs[1]);
    assert_ne!(reordered[1], bs[1]);
    let (rl, s3r) = cm::leaves_at(&mut leaf, &s0, &reordered, &[1, 2, 3]);
    assert_eq!(cm_commit(&s3r), cm_commit(&s3), "Count-Min is order-insensitive: same final state");
    let root = prove_forest_over(rl);
    let legacy = legacy_auditor(&root.0, &vk, &honest);
    let new = new_auditor(&root.0, &vk, &honest, &shape);
    println!("B6B (a2) same-state substituted batch: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok());
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");
}

/// (b) SWAP two adjacent batches.
/// (b1) Batches proved in the order `B_2, B_1, B_3` at indices 1, 2, 3:
///      Count-Min commutes, so every posted state commitment is honest; only
///      the digest rejects.
/// (b2) Two leaf PROOFS swapped in the tree (index 2 left of index 1) over
///      state-neutral batches: the merge's in-circuit index adjacency makes
///      the merge unprovable. Control: the same swap under the Boundary
///      layout (pre-B6(b)) merges fine.
#[test]
fn cm_attack_swapped_batches_rejected() {
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches()[..3].to_vec();
    let s0 = cm::empty();
    let s3 = bs.iter().fold(s0.clone(), |s, b| cm::apply(&s, b));
    let honest = cm::log(&s0, &s3, &bs);
    let shape = ForestShape::forest(3);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);

    // (b1)
    let swapped = vec![bs[1].clone(), bs[0].clone(), bs[2].clone()];
    let (sl, s3s) = cm::leaves_at(&mut leaf, &s0, &swapped, &[1, 2, 3]);
    assert_eq!(cm_commit(&s3s), cm_commit(&s3));
    let root = prove_forest_over(sl);
    let legacy = legacy_auditor(&root.0, &vk, &honest);
    let new = new_auditor(&root.0, &vk, &honest, &shape);
    println!("B6B (b1) swapped batches: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok());
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");

    // (b2)
    let z1 = leaf.prove_epoch_at(1, s0.clone(), cm_zero_batch(1)).output;
    let z2 = leaf.prove_epoch_at(2, s0.clone(), cm_zero_batch(3)).output;
    assert!(outcome(|| prove_hiding_merge(&z1, &z2)).is_ok(), "control: in-order merge");
    let swapped = outcome(|| prove_hiding_merge(&z2, &z1));
    println!("B6B (b2) swapped leaf proofs (interval): {:?}", swapped.as_ref().map(|_| "MERGED"));
    assert!(swapped.is_err(), "index adjacency must make the swapped merge unprovable");
    let mut bleaf = crate::sketch::countmin_omc::build_countmin_omc_leaf_expose(
        cm::P,
        Expose::Boundary,
        Binding::Semantic,
    );
    let b1 = bleaf.prove_epoch(s0.clone(), cm_zero_batch(1)).output;
    let b2 = bleaf.prove_epoch(s0.clone(), cm_zero_batch(3)).output;
    assert!(
        outcome(|| prove_hiding_merge(&b2, &b1)).is_ok(),
        "control: the Boundary layout (pre-B6(b)) merges the swapped leaves"
    );
}

/// (c) DROP / DUPLICATE a batch.
/// (c1) `B_2` dropped and `B_1` duplicated to keep `T = 3` (indices 1, 2, 3);
///      the prover posts the resulting final: pre-B6(b) auditor accepts,
///      digest rejects.
/// (c2) `B_2` dropped leaving an index gap (leaf 3 proved from `S_1`): the
///      states chain but the merge is unprovable (adjacency).
/// (c3) the same leaf PROOF used twice: unprovable merge (adjacency), while
///      the Boundary layout merges it.
#[test]
fn cm_attack_dropped_or_duplicated_batch_rejected() {
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches()[..3].to_vec();
    let s0 = cm::empty();
    let s3 = bs.iter().fold(s0.clone(), |s, b| cm::apply(&s, b));
    let honest = cm::log(&s0, &s3, &bs);
    let shape = ForestShape::forest(3);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);

    // (c1)
    let dup = vec![bs[0].clone(), bs[0].clone(), bs[2].clone()];
    let (dl, s3d) = cm::leaves_at(&mut leaf, &s0, &dup, &[1, 2, 3]);
    let root = prove_forest_over(dl);
    let posted = BatchLog { final_: cm_commit(&s3d), ..honest.clone() };
    let legacy = legacy_auditor(&root.0, &vk, &posted);
    let new = new_auditor(&root.0, &vk, &posted, &shape);
    println!("B6B (c1) dropped+duplicated batch: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok());
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");

    // (c2)
    let s1 = cm::apply(&s0, &bs[0]);
    let l1 = leaf.prove_epoch_at(1, s0.clone(), bs[0].clone()).output;
    let l3 = leaf.prove_epoch_at(3, s1.clone(), bs[2].clone()).output;
    let gap = outcome(|| prove_hiding_merge(&l1, &l3));
    println!("B6B (c2) index gap: {:?}", gap.as_ref().map(|_| "MERGED"));
    assert!(gap.is_err(), "an index gap must make the merge unprovable");

    // (c3)
    let z1 = leaf.prove_epoch_at(1, s0.clone(), cm_zero_batch(1)).output;
    let dupm = outcome(|| prove_hiding_merge(&z1, &z1));
    println!("B6B (c3) duplicated leaf proof: {:?}", dupm.as_ref().map(|_| "MERGED"));
    assert!(dupm.is_err(), "a leaf merged with itself must be unprovable");
    let mut bleaf = crate::sketch::countmin_omc::build_countmin_omc_leaf_expose(
        cm::P,
        Expose::Boundary,
        Binding::Semantic,
    );
    let b1 = bleaf.prove_epoch(s0.clone(), cm_zero_batch(1)).output;
    assert!(
        outcome(|| prove_hiding_merge(&b1, &b1)).is_ok(),
        "control: the Boundary layout (pre-B6(b)) merges a leaf with itself"
    );
}

/// (d) SPLICE a leaf from ANOTHER stream whose boundary states match: stream
/// Y starts from the same `S_0`, has the same first batch, and a second batch
/// with `B_2`'s records reordered, so Y's leaf 2 goes `S_1 -> S_2` exactly as
/// X's does. X's root with Y's leaf-2 proof spliced in passes the pre-B6(b)
/// auditor on X's honest log; the digest rejects it. A leaf of Y over the SAME
/// batch and states but at index 7 cannot be merged at position 2 at all.
#[test]
fn cm_attack_spliced_leaf_from_other_stream_rejected() {
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches()[..3].to_vec();
    let s0 = cm::empty();
    let s3 = bs.iter().fold(s0.clone(), |s, b| cm::apply(&s, b));
    let honest = cm::log(&s0, &s3, &bs);
    let shape = ForestShape::forest(3);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);

    let (x, _) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3]);
    let y_batches = vec![bs[0].clone(), rev(&bs[1])];
    let (mut y, _) = cm::leaves_at(&mut leaf, &s0, &y_batches, &[1, 2]);
    let y2 = y.pop().unwrap();
    assert_eq!(
        read_exposed_boundary_proof(&y2.0),
        read_exposed_boundary_proof(&x[1].0),
        "Y's leaf 2 has X's boundary states"
    );
    let m = prove_hiding_merge(&x[0], &y2);
    let root = prove_hiding_merge(&m, &x[2]);
    let legacy = legacy_auditor(&root.0, &vk, &honest);
    let new = new_auditor(&root.0, &vk, &honest, &shape);
    println!("B6B (d) spliced leaf: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok());
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");

    let s1 = cm::apply(&s0, &bs[0]);
    let y7 = leaf.prove_epoch_at(7, s1, bs[1].clone()).output;
    assert!(outcome(|| prove_hiding_merge(&x[0], &y7)).is_err(), "wrong-index splice is unprovable");
}

/// Tampering with the root's exposed statement values is rejected by the
/// STARK verifier itself (Expose values are bound), and the log check
/// rejects a root whose `T`, `S_0` or `S_T` disagree with the log.
#[test]
fn cm_root_statement_fields_are_checked() {
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches()[..2].to_vec();
    let s0 = cm::empty();
    let (ls, s2) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2]);
    let honest = cm::log(&s0, &s2, &bs);
    let shape = ForestShape::forest(2);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);
    let mut root = prove_forest_over(ls);
    assert!(new_auditor(&root.0, &vk, &honest, &shape).is_ok());

    let wrong_s0 = BatchLog { init: vec![Val::new(1); 8], ..honest.clone() };
    assert!(new_auditor(&root.0, &vk, &wrong_s0, &shape).is_err_and(|e| e.contains("Com(S_0)")));
    let wrong_st = BatchLog { final_: vec![Val::new(1); 8], ..honest.clone() };
    assert!(new_auditor(&root.0, &vk, &wrong_st, &shape).is_err_and(|e| e.contains("Com(S_T)")));
    let longer = BatchLog {
        batch_commits: [honest.batch_commits.clone(), vec![vec![Val::new(0); 8]]].concat(),
        ..honest.clone()
    };
    assert!(
        check_root_against_log(&root.0, &longer, &ForestShape::forest(3))
            .is_err_and(|e| e.contains("idx_hi"))
    );

    let entry = root.0.non_primitives.iter_mut().find(|e| e.public_values.len() == 28).unwrap();
    entry.public_values[17] = Val::new(3);
    assert!(
        outcome(|| verify_bound_stark_proof_pinned(&root.0, &vk)).is_err(),
        "a tampered exposed idx must fail the STARK"
    );
}

// ─── Cost of the Interval statement (measurement) ───────────────────────────

/// `(Σ 2^degree_bits over all tables, primitive RowCounts, NPO (op, rows),
/// proof bytes)` of a proof.
fn proof_cost(p: &Proof) -> (u64, String, String, usize) {
    let total: u64 = p.proof.degree_bits.iter().map(|&d| 1u64 << d).sum();
    let npo: Vec<String> =
        p.non_primitives.iter().map(|e| format!("{}:{}", e.op_type.as_str(), e.rows)).collect();
    (total, format!("{:?}", p.rows), npo.join(","), crate::experiments::proof_size(p))
}

/// MEASUREMENT (B6(b) cost): per leaf and per merge, Boundary vs Interval
/// statement, at small shapes — CM omc (d, w, m) = (2, 4, 2) and (4, 64, 16)
/// and SS (capacity 4, batch 2). Prints padded trace rows (Σ 2^degree_bits),
/// primitive row counts, NPO rows, proof bytes, and one prove wall time.
/// `cargo test --release --lib measure_interval_statement_cost -- --ignored --nocapture --test-threads 1`
#[test]
#[ignore = "measurement: run explicitly"]
fn measure_interval_statement_cost() {
    use std::time::Instant;
    let s0 = cm::empty();
    for (d, w, m) in [(2usize, 4usize, 2usize), (4, 64, 16)] {
        let p = crate::sketch::countmin_omc::CmOmcParams { d, w, batch: m };
        let st0 = {
            use crate::sketch::Sketch;
            crate::sketch::countmin_v9::CountMinV9::new(&crate::sketch::countmin::CountMinParams { d, w })
        };
        let _ = &s0;
        let b1: Vec<_> = (0..m).map(|i| crate::sketch::countmin::CountMinUpdate { key: 7 + 13 * i as u64, value: 1 + i as u32 % 3 }).collect();
        let b2: Vec<_> = (0..m).map(|i| crate::sketch::countmin::CountMinUpdate { key: 1000 + 17 * i as u64, value: 2 }).collect();
        let st1 = {
            let mut s = st0.clone();
            for u in &b1 {
                crate::sketch::countmin_final::apply_update_prf_with(&mut s, u, Binding::Semantic);
            }
            s
        };
        for expose in [Expose::Boundary, Expose::Interval] {
            let mut leaf = crate::sketch::countmin_omc::build_countmin_omc_leaf_expose(p, expose, Binding::Semantic);
            let t0 = Instant::now();
            let l1 = leaf.prove_epoch_at(1, st0.clone(), b1.clone()).output;
            let leaf_ms = t0.elapsed().as_secs_f64() * 1e3;
            let l2 = leaf.prove_epoch_at(2, st1.clone(), b2.clone()).output;
            let (lr, lrows, lnpo, lbytes) = proof_cost(&l1.0);
            println!(
                "MEASURE cm_omc d={d} w={w} m={m} {expose:?} LEAF: trace_rows={lr} table_rows_sum={} prim_rows={lrows} npo=[{lnpo}] proof_bytes={lbytes} prove_ms={leaf_ms:.0}",
                leaf.trace_rows()
            );
            let t0 = Instant::now();
            let m1 = prove_hiding_merge(&l1, &l2);
            let merge_ms = t0.elapsed().as_secs_f64() * 1e3;
            let (mr, mrows, mnpo, mbytes) = proof_cost(&m1.0);
            println!(
                "MEASURE cm_omc d={d} w={w} m={m} {expose:?} MERGE(leaf,leaf): trace_rows={mr} prim_rows={mrows} npo=[{mnpo}] proof_bytes={mbytes} build+prove_ms={merge_ms:.0}"
            );
            // Level 2: merge of two merges (index-shifted second pair).
            let st2 = {
                let mut s = st1.clone();
                for u in &b2 {
                    crate::sketch::countmin_final::apply_update_prf_with(&mut s, u, Binding::Semantic);
                }
                s
            };
            let l3 = leaf.prove_epoch_at(3, st2.clone(), b1.clone()).output;
            let st3 = {
                let mut s = st2.clone();
                for u in &b1 {
                    crate::sketch::countmin_final::apply_update_prf_with(&mut s, u, Binding::Semantic);
                }
                s
            };
            let l4 = leaf.prove_epoch_at(4, st3, b2.clone()).output;
            let m2 = prove_hiding_merge(&l3, &l4);
            let t0 = Instant::now();
            let root = prove_hiding_merge(&m1, &m2);
            let root_ms = t0.elapsed().as_secs_f64() * 1e3;
            let (rr, rrows, rnpo, rbytes) = proof_cost(&root.0);
            println!(
                "MEASURE cm_omc d={d} w={w} m={m} {expose:?} MERGE(merge,merge): trace_rows={rr} prim_rows={rrows} npo=[{rnpo}] proof_bytes={rbytes} build+prove_ms={root_ms:.0}"
            );
            let t0 = Instant::now();
            crate::recursion::recursive::expose_forest::verify_bound_stark_proof(
                &root.0,
                &crate::recursion::recursive::expose_forest::vk_pin_values(&root.0),
            );
            println!(
                "MEASURE cm_omc d={d} w={w} m={m} {expose:?} ROOT verify_ms={:.1}",
                t0.elapsed().as_secs_f64() * 1e3
            );
        }
    }
    // SpaceSaving leaf (Pattern B).
    for expose in [Expose::Boundary, Expose::Interval] {
        let mut leaf = crate::sketch::ss_final_full::build_ss_full_leaf_expose(ss::P, expose);
        let bs = ss::honest_batches();
        let t0 = Instant::now();
        let l1 = leaf.prove_epoch_at(1, ss::empty(), bs[0].clone()).output;
        let leaf_ms = t0.elapsed().as_secs_f64() * 1e3;
        let (lr, lrows, lnpo, lbytes) = proof_cost(&l1.0);
        println!(
            "MEASURE ss_full cap=4 m=2 {expose:?} LEAF: trace_rows={lr} prim_rows={lrows} npo=[{lnpo}] proof_bytes={lbytes} prove_ms={leaf_ms:.0}"
        );
    }
}

// ─── Every other BabyBear leaf with an Interval statement ────────────────────

/// Two Interval leaves → forest(2) root; the VK derived from the family's
/// Interval no-op leaf equals the real root VK (commitment and metadata), the
/// root verifies against the log, and a log listing the two batches in the
/// opposite order is rejected by the digest.
fn assert_family_interval_forest2(
    family: &str,
    leaves: Vec<Out>,
    noop: Proof,
    log: BatchLog<Val>,
) {
    use crate::recursion::recursive::expose_forest::vk_pin_values;
    use crate::recursion::recursive::root_vk::bound_proof_shape;
    let shape = ForestShape::forest(2);
    let vk = root_vk_deriver(noop).root_vk(&shape);
    let root = prove_forest_over(leaves);
    assert_eq!(vk.commitment, vk_pin_values(&root.0), "{family}: derived root VK == real");
    assert_eq!(vk.shape, Some(bound_proof_shape(&root.0)), "{family}: derived metadata == real");
    verify_bound_stark_proof_against_log(&root.0, &vk, &log, &shape);
    let mut swapped = log.clone();
    swapped.batch_commits.swap(0, 1);
    let r = check_root_against_log(&root.0, &swapped, &shape);
    println!("B6B {family}: honest forest(2) accepted; swapped log -> {r:?}");
    assert!(r.is_err_and(|e| e.contains("digest")), "{family}: swapped log must be rejected");
}

#[test]
fn hll_omc_and_gk2_interval_forest2() {
    use crate::recursion::recursive::noop_leaf::{gk2_noop_leaf_expose, hll_omc_noop_leaf_expose};
    // HyperLogLog omc.
    {
        use crate::sketch::hll_omc::{
            HllOmcParams, build_hll_omc_leaf_expose, commit_hll_omc, hll_omc_advance_with,
            hll_omc_batch_commit_with, hll_omc_empty,
        };
        let p = HllOmcParams { b: 4, batch: 2 };
        let mut leaf = build_hll_omc_leaf_expose(p, Expose::Interval, Binding::Semantic);
        let bs = [vec![7u64, 11], vec![13, 7]];
        let mut regs = hll_omc_empty(p.b);
        let s0 = commit_hll_omc(&regs, p.b);
        let mut outs = Vec::new();
        for (i, ks) in bs.iter().enumerate() {
            outs.push(leaf.prove_epoch_at(i as u64 + 1, regs.clone(), ks.clone()).output);
            hll_omc_advance_with(&mut regs, ks, p.m(), Binding::Semantic);
        }
        let commits: Vec<[Val; 8]> =
            bs.iter().map(|k| hll_omc_batch_commit_with(k, Binding::Semantic)).collect();
        let log = batch_log(&s0, &commit_hll_omc(&regs, p.b), &commits);
        assert_family_interval_forest2(
            "hll_omc",
            outs,
            hll_omc_noop_leaf_expose(p, Expose::Interval, Binding::Semantic),
            log,
        );
    }
    // Greenwald-Khanna band-merge (Pattern B). Com(B_t) binds n_prev.
    {
        use crate::sketch::gk_bandmerge::{
            Gk2State, GkbParams, apply_batch2, build_gkb2_leaf_expose, commit_gk2_batch,
            commit_gk2_state,
        };
        let p = GkbParams { capacity: 4, batch: 2, s: 2 };
        let mut leaf = build_gkb2_leaf_expose(p, Expose::Interval);
        let bs = [vec![10u32, 11], vec![20, 21]];
        let mut s = Gk2State::empty(p);
        let s0 = commit_gk2_state(&s).0;
        let mut outs = Vec::new();
        let mut commits = Vec::new();
        for (i, vs) in bs.iter().enumerate() {
            commits.push(commit_gk2_batch(vs, p.batch, s.n).0);
            outs.push(leaf.prove_epoch_at(i as u64 + 1, s.clone(), vs.clone()).output);
            s = apply_batch2(&s, vs);
        }
        let log = batch_log(&s0, &commit_gk2_state(&s).0, &commits);
        assert_family_interval_forest2("gk_bandmerge2", outs, gk2_noop_leaf_expose(p, Expose::Interval), log);
    }
}

/// Bloom-filter `omc` (an OR update with the timestamped rebind): two
/// Interval leaves → forest(2). The root VK derived from the Bloom Interval
/// no-op leaf (empty filter, all-dummy batch) equals the real root's, the
/// honest root verifies against the log, and the reversed log is rejected
/// ([`assert_family_interval_forest2`]). A substituted batch is rejected by
/// the digest:
/// (a1) `B'_2` with other keys, posted with its own final commitment;
/// (a2) `B'_2` = `B_2` with its records reordered: OR is order-insensitive,
///      so every posted state commitment is the HONEST one and only
///      `Com(B'_2) != Com(B_2)` differs.
/// Both substituted roots pass the pre-B6(b) auditor; the digest check
/// rejects both, while (control) the reordered root verifies against its own
/// log.
#[test]
fn bloom_omc_interval_forest2() {
    use crate::recursion::recursive::noop_leaf::bloom_omc_noop_leaf_expose;
    use crate::sketch::bloom_omc::{
        BloomOmcLeafCircuit, BloomOmcParams, bloom_batch_commit, bloom_empty, bloom_insert,
        build_bloom_omc_leaf_expose, commit_bloom,
    };
    let p = BloomOmcParams { k: 3, log_w: 7, batch: 4 };
    /// Prove `bs` from the empty filter at indices 1, 2, …; returns the leaves,
    /// the final filter and the log.
    fn run(leaf: &mut BloomOmcLeafCircuit, p: &BloomOmcParams, bs: &[Vec<u64>]) -> (Vec<Out>, BatchLog<Val>) {
        let s0 = bloom_empty(p);
        let mut bits = s0.clone();
        let mut outs = Vec::new();
        for (i, ks) in bs.iter().enumerate() {
            outs.push(leaf.prove_epoch_at(i as u64 + 1, &bits, ks).output);
            bloom_insert(&mut bits, p, ks);
        }
        let commits: Vec<[Val; 8]> = bs.iter().map(|ks| bloom_batch_commit(p.batch, ks)).collect();
        (outs, batch_log(&commit_bloom(&s0), &commit_bloom(&bits), &commits))
    }
    let mut leaf = build_bloom_omc_leaf_expose(p, Expose::Interval);
    // Batch 1 leaves one dummy slot; batch 2 re-inserts key 7.
    let bs = vec![vec![7u64, 11, 1 << 40], vec![13, 7, 99, 2]];
    let (outs, log) = run(&mut leaf, &p, &bs);
    assert_family_interval_forest2(
        "bloom_omc",
        outs,
        bloom_omc_noop_leaf_expose(p, Expose::Interval),
        log.clone(),
    );
    let shape = ForestShape::forest(2);
    let vk = root_vk_deriver(bloom_omc_noop_leaf_expose(p, Expose::Interval)).root_vk(&shape);

    // (a1)
    let forged = vec![bs[0].clone(), vec![500, 501]];
    let (fl, flog) = run(&mut leaf, &p, &forged);
    assert_ne!(flog.final_, log.final_);
    let root = prove_forest_over(fl);
    let posted = BatchLog { final_: flog.final_.clone(), ..log.clone() };
    let legacy = legacy_auditor(&root.0, &vk, &posted);
    let new = new_auditor(&root.0, &vk, &posted, &shape);
    println!("B6B bloom (a1) substituted batch: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok(), "the pre-B6(b) auditor accepts the substituted history");
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");

    // (a2)
    let reordered = vec![bs[0].clone(), bs[1].iter().rev().copied().collect::<Vec<_>>()];
    let (rl, rlog) = run(&mut leaf, &p, &reordered);
    assert_eq!(rlog.final_, log.final_, "OR is order-insensitive: same final state");
    assert_ne!(rlog.batch_commits[1], log.batch_commits[1]);
    let root = prove_forest_over(rl);
    let legacy = legacy_auditor(&root.0, &vk, &log);
    let new = new_auditor(&root.0, &vk, &log, &shape);
    println!("B6B bloom (a2) same-state substituted batch: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok());
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");
    assert!(new_auditor(&root.0, &vk, &rlog, &shape).is_ok(), "control: its own log");
}

#[test]
fn test_only_leaves_interval_forest2() {
    use crate::commitment::countmin::commit_countmin;
    use crate::commitment::countmin_batch::commit_batch;
    use crate::recursion::recursive::noop_leaf::{
        cm_v9_noop_leaf_interval, gk_full_noop_leaf_interval, hll_full_noop_leaf_interval,
    };
    use crate::sketch::countmin::CountMinUpdate;
    // hll_final_full.
    {
        use crate::sketch::hll_final_full::{
            HllFullParams, HllFullState, HllFullUpdate, apply_batch, commit_hll_batch,
            commit_hll_state, prove_hll_full_interval,
        };
        let p = HllFullParams { b: 4, batch: 2 };
        let bs = [vec![HllFullUpdate::real(7), HllFullUpdate::real(11)], vec![HllFullUpdate::real(13), HllFullUpdate::real(7)]];
        let mut s = HllFullState::empty(p);
        let s0 = commit_hll_state(&s).0;
        let mut outs = Vec::new();
        for (i, b) in bs.iter().enumerate() {
            outs.push(prove_hll_full_interval(p, i as u64 + 1, s.clone(), b.clone()).output);
            s = apply_batch(&s, b);
        }
        let commits: Vec<[Val; 8]> = bs.iter().map(|b| commit_hll_batch(b).0).collect();
        let log = batch_log(&s0, &commit_hll_state(&s).0, &commits);
        assert_family_interval_forest2("hll_final_full", outs, hll_full_noop_leaf_interval(p), log);
    }
    // gk_final_full.
    {
        use crate::sketch::gk_final_full::{
            GKFullParams, GKFullState, GKFullUpdate, apply_batch_full, commit_gk_batch,
            commit_gk_state, prove_gk_full_interval,
        };
        let p = GKFullParams { capacity: 4, batch: 2 };
        let bs = [vec![GKFullUpdate::real(10), GKFullUpdate::real(11)], vec![GKFullUpdate::real(20), GKFullUpdate::real(21)]];
        let mut s = GKFullState::empty(p);
        let s0 = commit_gk_state(&s).0;
        let mut outs = Vec::new();
        for (i, b) in bs.iter().enumerate() {
            outs.push(prove_gk_full_interval(p, i as u64 + 1, s.clone(), b.clone()).output);
            s = apply_batch_full(&s, b).0;
        }
        let commits: Vec<[Val; 8]> = bs.iter().map(|b| commit_gk_batch(b).0).collect();
        let log = batch_log(&s0, &commit_gk_state(&s).0, &commits);
        assert_family_interval_forest2("gk_final_full", outs, gk_full_noop_leaf_interval(p), log);
    }
    // countmin_leaf_v9.
    {
        use crate::recursion::recursive::countmin_leaf::CountMinLeafParams;
        use crate::recursion::recursive::countmin_leaf_v9::prove_countmin_leaf_v9_interval_with_params;
        use crate::sketch::Sketch;
        use crate::sketch::countmin::CountMinParams;
        use crate::sketch::countmin_v9::CountMinV9;
        let p = CountMinLeafParams::default();
        let bs = [cm::batch(&[(7, 3), (11, 5)]), cm::batch(&[(13, 2), (7, 4)])];
        let mut s = CountMinV9::new(&CountMinParams { d: p.d, w: p.w });
        let s0 = commit_countmin(&s).0;
        let mut outs = Vec::new();
        for (i, b) in bs.iter().enumerate() {
            outs.push(prove_countmin_leaf_v9_interval_with_params(p, i as u64 + 1, s.clone(), b.clone()).output);
            for u in b {
                CountMinV9::update(&mut s, u);
            }
        }
        let commits: Vec<[Val; 8]> = bs.iter().map(|b| commit_batch(b).0).collect();
        let log = batch_log(&s0, &commit_countmin(&s).0, &commits);
        assert_family_interval_forest2("countmin_leaf_v9", outs, cm_v9_noop_leaf_interval(p), log);
    }
    // countmin_final (one_hot) and c_merkle — the e6 variants.
    {
        use crate::sketch::countmin_final::{CountMinFinalParams, prove_countmin_final_interval};
        let p = CountMinFinalParams { d: 2, w: 4, batch: 2 };
        let bs = [cm::batch(&[(7, 3), (11, 5)]), cm::batch(&[(13, 2), (7, 4)])];
        let s0 = cm::empty();
        let mut s = s0.clone();
        let mut outs = Vec::new();
        for (i, b) in bs.iter().enumerate() {
            outs.push(prove_countmin_final_interval(p, i as u64 + 1, s.clone(), b.clone()).output);
            s = cm::apply(&s, b);
        }
        let commits: Vec<[Val; 8]> = bs.iter().map(|b| commit_batch(b).0).collect();
        let log = batch_log(&commit_countmin(&s0).0, &commit_countmin(&s).0, &commits);
        let noop = prove_countmin_final_interval(p, 1, s0.clone(), vec![CountMinUpdate { key: 0, value: 0 }; 2]).output.0;
        assert_family_interval_forest2("countmin_final", outs, noop, log);
    }
    {
        use crate::commitment::CountMinCommit;
        use crate::sketch::countmin_c_merkle::{
            CountMinCMerkleParams, countmin_c_merkle_batch_commit, prove_countmin_c_merkle_interval,
        };
        use crate::sketch::countmin_merkle::{combined_commit, merkle_root_mode};
        let combined = |s: &crate::sketch::countmin::CountMinState| -> [Val; 8] {
            let roots: Vec<CountMinCommit> = s
                .counters
                .iter()
                .map(|row| CountMinCommit(merkle_root_mode(&row.iter().map(|&c| c as u64).collect::<Vec<_>>(), false)))
                .collect();
            combined_commit(&roots).0
        };
        let p = CountMinCMerkleParams { d: 2, w: 4, batch: 2, t_max: 2, compress: false, group_by: false };
        let bs = [cm::batch(&[(7, 3), (11, 5)]), cm::batch(&[(13, 2), (7, 4)])];
        let s0 = cm::empty();
        let mut s = s0.clone();
        let mut outs = Vec::new();
        for (i, b) in bs.iter().enumerate() {
            outs.push(prove_countmin_c_merkle_interval(p, i as u64 + 1, s.clone(), b.clone()).output);
            s = cm::apply(&s, b);
        }
        let commits: Vec<[Val; 8]> = bs.iter().map(|b| countmin_c_merkle_batch_commit(b)).collect();
        let log = batch_log(&combined(&s0), &combined(&s), &commits);
        let noop = prove_countmin_c_merkle_interval(p, 1, s0.clone(), vec![CountMinUpdate { key: 0, value: 0 }; 2]).output.0;
        assert_family_interval_forest2("c_merkle", outs, noop, log);
    }
}

// ─── Goldilocks (D = 2) ──────────────────────────────────────────────────────

/// (e) + (a) on the GOLDILOCKS atom: CM `omc_gl` Interval leaves; the
/// forest(3) root verifies against the log-recomputed digest and the derived
/// VK (derived == real); a leaf proved over a substituted batch (prover posts
/// the resulting final) passes the pre-B6(b) checks and fails the digest.
#[test]
fn gl_cm_honest_and_substituted_batch() {
    use crate::recursion::recursive::expose_forest_gl as fgl;
    use crate::sketch::countmin::CountMinUpdate;
    use crate::sketch::countmin_omc_gl::{
        CmOmcParams, apply_update_prf_with, build_countmin_omc_leaf_expose, cm_gl_empty,
        commit_batch_with, commit_countmin,
    };
    let params = CmOmcParams { d: 2, w: 4, batch: 2 };
    let mut leaf = build_countmin_omc_leaf_expose(params, Expose::Interval, Binding::Semantic);
    let noop = leaf
        .prove_epoch_at(1, cm_gl_empty(2, 4), vec![CountMinUpdate { key: 0, value: 0 }; 2])
        .output
        .0;
    let shape = ForestShape::forest(3);
    let vk = fgl::root_vk_deriver(noop).root_vk(&shape);
    let b = |p: &[(u64, u32)]| -> Vec<CountMinUpdate> {
        p.iter().map(|&(key, value)| CountMinUpdate { key, value }).collect()
    };
    let run = |leaf: &mut crate::sketch::countmin_omc_gl::CmOmcLeafCircuit,
               bs: &[Vec<CountMinUpdate>]| {
        let mut s = cm_gl_empty(2, 4);
        let mut outs = Vec::new();
        for (i, bt) in bs.iter().enumerate() {
            outs.push(leaf.prove_epoch_at(i as u64 + 1, s.clone(), bt.clone()).output);
            for u in bt {
                apply_update_prf_with(&mut s, u, Binding::Semantic);
            }
        }
        (outs, s)
    };
    let bs = vec![b(&[(7, 3), (11, 5)]), b(&[(13, 2), (7, 1)]), b(&[(99, 1), (5, 8)])];
    let commits: Vec<[crate::config_gl::Val; 4]> =
        bs.iter().map(|x| commit_batch_with(x, Binding::Semantic).0).collect();
    let (outs, s3) = run(&mut leaf, &bs);
    let log = fgl::batch_log(&commit_countmin(&cm_gl_empty(2, 4)).0, &commit_countmin(&s3).0, &commits);
    let root = fgl::prove_forest_over(outs);
    assert_eq!(vk.commitment, fgl::vk_pin_values(&root.0), "GL derived root VK == real");
    fgl::verify_bound_stark_proof_against_log(&root.0, &vk, &log, &shape);

    let mut forged = bs.clone();
    forged[1] = b(&[(500, 9), (7, 1)]);
    let (fouts, s3f) = run(&mut leaf, &forged);
    let froot = fgl::prove_forest_over(fouts);
    let posted = BatchLog { final_: commit_countmin(&s3f).0.to_vec(), ..log.clone() };
    let legacy = outcome(|| fgl::verify_bound_stark_proof_pinned(&froot.0, &vk));
    let (fi, ff) = fgl::read_exposed_boundary_proof(&froot.0);
    assert!(legacy.is_ok() && fi.0.to_vec() == posted.init && ff.0.to_vec() == posted.final_);
    let new = outcome(|| fgl::verify_bound_stark_proof_against_log(&froot.0, &vk, &posted, &shape));
    println!("B6B gl (a) substituted batch: legacy=Ok new={new:?}");
    assert!(new.is_err_and(|e| e.contains("digest")));
}

// ─── SpaceSaving (Pattern B) ─────────────────────────────────────────────────

mod ss {
    use super::*;
    use crate::recursion::recursive::noop_leaf::ss_full_noop_leaf_expose;
    use crate::sketch::ss_final_full::{
        SsFullLeafCircuit, SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full,
        build_ss_full_leaf_expose, commit_ss_batch, commit_ss_state,
    };

    pub const P: SsFullParams = SsFullParams { capacity: 4, batch: 2 };

    pub fn batch(pairs: &[(u64, u32)]) -> Vec<SsFullUpdate> {
        pairs.iter().map(|&(k, v)| SsFullUpdate::real(k, v)).collect()
    }

    pub fn honest_batches() -> Vec<Vec<SsFullUpdate>> {
        vec![batch(&[(7, 1), (11, 1)]), batch(&[(13, 1), (7, 1)]), batch(&[(21, 1), (7, 1)])]
    }

    pub fn leaves_at(
        leaf: &mut SsFullLeafCircuit,
        s0: &SsFullState,
        batches: &[Vec<SsFullUpdate>],
        indices: &[u64],
    ) -> (Vec<Out>, SsFullState) {
        let mut s = s0.clone();
        let mut out = Vec::new();
        for (b, &t) in batches.iter().zip(indices) {
            out.push(leaf.prove_epoch_at(t, s.clone(), b.clone()).output);
            s = apply_batch_ss_full(&s, b).0;
        }
        (out, s)
    }

    pub fn commit(s: &SsFullState) -> Vec<Val> {
        commit_ss_state(s).0.to_vec()
    }

    pub fn log(s0: &SsFullState, s_t: &SsFullState, batches: &[Vec<SsFullUpdate>]) -> BatchLog<Val> {
        let commits: Vec<[Val; 8]> = batches.iter().map(|b| commit_ss_batch(b).0).collect();
        batch_log(&commit_ss_state(s0).0, &commit_ss_state(s_t).0, &commits)
    }

    pub fn leaf_circuit() -> SsFullLeafCircuit {
        build_ss_full_leaf_expose(P, Expose::Interval)
    }

    pub fn noop() -> Proof {
        ss_full_noop_leaf_expose(P, Expose::Interval)
    }

    pub fn empty() -> SsFullState {
        SsFullState::empty(P)
    }
}

/// (e) HONEST, SpaceSaving: the dist(3, 2) root (= forest(3) = chain(3) as a
/// shape; slice 1 crosses the machine boundary as postcard bytes) verified end
/// to end against the log and the derived VK. (a) + (b) on this Pattern-B
/// family: a substituted batch and two swapped batches, with the prover
/// posting the resulting final, pass the pre-B6(b) auditor and fail the
/// digest check.
#[test]
fn ss_honest_and_attacks() {
    let mut leaf = ss::leaf_circuit();
    let bs = ss::honest_batches();
    let s0 = ss::empty();
    let shape = ForestShape::forest(3);
    assert_eq!(shape, ForestShape::dist_forest(3, 2));
    let vk = root_vk_deriver(ss::noop()).root_vk(&shape);

    let (hl, s3) = ss::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3]);
    let honest = ss::log(&s0, &s3, &bs);
    let mut hl = hl.into_iter();
    let (l1, l2, l3) = (hl.next().unwrap(), hl.next().unwrap(), hl.next().unwrap());
    let slice0 = prove_hiding_merge(&l1, &l2);
    let wire: Proof = postcard::from_bytes(&postcard::to_allocvec(&l3.0).unwrap()).unwrap();
    let root = prove_hiding_merge_proofs(&slice0.0, &wire);
    assert_eq!(vk.commitment, crate::recursion::recursive::expose_forest::vk_pin_values(&root.0));
    verify_bound_stark_proof_against_log(&root.0, &vk, &honest, &shape);
    assert!(legacy_auditor(&root.0, &vk, &honest).is_ok());

    // (a) substituted batch 2.
    let mut forged = bs.clone();
    forged[1] = ss::batch(&[(99, 1), (98, 1)]);
    let (fl, s3f) = ss::leaves_at(&mut leaf, &s0, &forged, &[1, 2, 3]);
    let froot = prove_forest_over(fl);
    let posted = BatchLog { final_: ss::commit(&s3f), ..honest.clone() };
    let legacy = legacy_auditor(&froot.0, &vk, &posted);
    let new = new_auditor(&froot.0, &vk, &posted, &shape);
    println!("B6B ss (a) substituted batch: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok());
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");

    // (b) batches 1 and 2 swapped (indices stay 1, 2, 3).
    let swapped = vec![bs[1].clone(), bs[0].clone(), bs[2].clone()];
    let (sl, s3s) = ss::leaves_at(&mut leaf, &s0, &swapped, &[1, 2, 3]);
    let sroot = prove_forest_over(sl);
    let posted = BatchLog { final_: ss::commit(&s3s), ..honest.clone() };
    let legacy = legacy_auditor(&sroot.0, &vk, &posted);
    let new = new_auditor(&sroot.0, &vk, &posted, &shape);
    println!("B6B ss (b) swapped batches: legacy={legacy:?} new={new:?}");
    assert!(legacy.is_ok());
    assert!(new.as_ref().is_err_and(|e| e.contains("digest")), "{new:?}");
}

// ─── Standalone leaves: the leaf-VK pin (per-batch mode, lone leaf) ──────────
//
// A leaf proof that reaches the auditor directly (per-batch mode; the lone
// leaf of a one-batch stream) is not covered by any root-VK pin. Before the
// fix those paths checked only the leaf's EXPOSED statement (plus the
// prover's own self-verify, whose VK is read from the proof), so a proof of
// any circuit exposing the right values passed. Each attack below runs that
// pre-fix check (`check_leaves_against_log` / `check_root_against_log` over
// `ForestShape::Leaf`, and the self-pinned STARK verify) and asserts it
// ACCEPTS; the pinned leaf verifier (`verify_leaves_against_log` with the leaf
// VK derived from the family's no-op leaf) must REJECT.

mod leaf_pin {
    use super::*;
    use crate::config::Challenge;
    use crate::recursion::recursive::expose_forest::{leaf_vk, prove_exposing_leaf};
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

    /// A TOY BabyBear circuit (constants only, no sketch logic) exposing the
    /// base values `v` in the leaf's Expose layout.
    pub fn toy(v: &[Val]) -> Out {
        let cs: Vec<Challenge> =
            v.chunks(4).map(|c| Challenge::from_basis_coefficients_slice(c).unwrap()).collect();
        prove_exposing_leaf(&cs)
    }

    pub fn toy_mimic(p: &Proof) -> Out {
        toy(&read_exposed_statement(p).values())
    }

    pub fn vk() -> RootVk<Challenge> {
        leaf_vk(&cm::noop())
    }

    pub fn bump(v: &[Val], k: usize) -> Vec<Val> {
        let mut v = v.to_vec();
        v[k] += Val::ONE;
        v
    }
}

/// THE REVIEWED ATTACK (lone leaf, `T = 1`): a toy circuit exposes
/// `(Com(S_0), FORGED Com(S_1), (1, 1), H(TAG_LEAF, 1, Com(B_1)))` — key 7
/// counted 1000 times where the batch counted it once. The pre-fix lone-leaf
/// path (self-verify + statement vs the log of a follower that takes the
/// posted final) ACCEPTS it; the pinned leaf verifier REJECTS it. A toy
/// exposing the HONEST statement (a non-proof of the transition) is likewise
/// accepted by the statement check and rejected by the pin. Control: the real
/// leaf of the same batch verifies against the derived leaf VK.
#[test]
fn leaf_pin_attack_lone_leaf_foreign_circuit() {
    use p3_field::PrimeCharacteristicRing;
    use crate::commitment::countmin::commit_countmin;
    use crate::recursion::recursive::expose_forest::{
        check_leaves_against_log, verify_bound_proof_self_pinned_legacy, verify_leaves_against_log,
        vk_pin_values,
    };
    use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
    use crate::sketch::countmin_omc::countmin_omc_batch_commit_with;
    let vk = leaf_pin::vk();
    let s0 = cm::empty();
    let b1 = cm::batch(&[(7, 1), (11, 1)]);
    let bc = countmin_omc_batch_commit_with(&b1, Binding::Semantic);
    let init = commit_countmin(&s0).0;
    let honest_final = commit_countmin(&cm::apply(&s0, &b1)).0;
    let forged_final = commit_countmin(&cm::apply(&s0, &cm::batch(&[(7, 1000), (11, 1)]))).0;
    assert_ne!(honest_final, forged_final);
    let h = leaf_digest(&hash_bb, 4, 1, &bc);

    // Control: the real leaf of batch 1 verifies against the derived leaf VK.
    let real = cm::leaf_circuit().prove_epoch_at(1, s0.clone(), b1.clone()).output;
    let honest_log = batch_log(&init, &honest_final, &[bc]);
    assert_eq!(verify_leaves_against_log(&[&real.0], &vk, &honest_log, Expose::Interval), Ok(()));
    assert_eq!(vk.commitment, vk_pin_values(&real.0), "the derived leaf VK is the real leaf's");

    for (what, fin) in [("forged Com(S_1)", forged_final), ("honest statement", honest_final)] {
        let mut v = init.to_vec();
        v.extend_from_slice(&fin);
        v.extend_from_slice(&[Val::from_u64(1), Val::from_u64(1), Val::from_u64(0), Val::from_u64(0)]);
        v.extend_from_slice(&h);
        let toy = leaf_pin::toy(&v);
        let log = batch_log(&init, &fin, &[bc]);
        // Pre-fix path: the STARK verifies under its own VK, and every
        // statement check passes.
        assert!(outcome(|| verify_bound_proof_self_pinned_legacy(&toy)).is_ok());
        assert_eq!(check_root_against_log(&toy.0, &log, &ForestShape::Leaf), Ok(()));
        assert_eq!(check_leaves_against_log(&[&toy.0], &log, Expose::Interval), Ok(()));
        // Fixed path: rejected by the leaf pin (first by the metadata pin;
        // the commitment pin alone rejects it too).
        let new = verify_leaves_against_log(&[&toy.0], &vk, &log, Expose::Interval);
        println!("B6B leaf pin, lone leaf ({what}): pre-fix=Ok new={new:?}");
        assert!(new.as_ref().is_err_and(|e| e.contains("leaf 1")), "{new:?}");
        let commit_only = RootVk::commitment_only(vk.commitment.clone());
        let r = verify_leaves_against_log(&[&toy.0], &commit_only, &log, Expose::Interval);
        assert!(r.as_ref().is_err_and(|e| e.contains("VK mismatch")), "{r:?}");
    }
    // The real leaf also passes the commitment-only pin (control).
    let commit_only = RootVk::commitment_only(vk.commitment.clone());
    assert_eq!(verify_leaves_against_log(&[&real.0], &commit_only, &honest_log, Expose::Interval), Ok(()));
}

/// THE REVIEWED ATTACK (per-batch mode, `T = 3`): the honest per-batch
/// artifact verifies against the derived leaf VK; replacing leaf 2 with a
/// toy that mimics its exposed statement, or leaves 2 and 3 with toys that
/// forge `S_2`, `S_3` (the log follower takes the posted final), passes the
/// pre-fix statement checks and is rejected by the pin at leaf 2. A real leaf
/// placed at the wrong position is rejected by the statement check.
#[test]
fn leaf_pin_attack_per_batch_foreign_circuit() {
    use p3_field::PrimeCharacteristicRing;
    use crate::commitment::countmin::commit_countmin;
    use crate::recursion::recursive::expose_forest::{check_leaves_against_log, verify_leaves_against_log};
    use crate::recursion::recursive::statement::{hash_bb, leaf_digest};
    use crate::sketch::countmin_omc::countmin_omc_batch_commit_with;
    let vk = leaf_pin::vk();
    let bs: Vec<_> = cm::honest_batches().into_iter().take(3).collect();
    let s0 = cm::empty();
    let mut leaf = cm::leaf_circuit();
    let (ls, s3) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3]);
    let log = cm::log(&s0, &s3, &bs);
    let refs: Vec<&Proof> = ls.iter().map(|l| &l.0).collect();
    assert_eq!(verify_leaves_against_log(&refs, &vk, &log, Expose::Interval), Ok(()), "honest");

    // (1) Leaf 2 replaced by a toy mimicking its honest statement.
    let t2 = leaf_pin::toy_mimic(&ls[1].0);
    let mixed = [&ls[0].0, &t2.0, &ls[2].0];
    assert_eq!(check_leaves_against_log(&mixed, &log, Expose::Interval), Ok(()), "pre-fix accepts");
    let new = verify_leaves_against_log(&mixed, &vk, &log, Expose::Interval);
    println!("B6B leaf pin, per-batch mimic leaf 2: pre-fix=Ok new={new:?}");
    assert!(new.as_ref().is_err_and(|e| e.contains("leaf 2")), "{new:?}");

    // (2) Leaves 2 and 3 replaced by toys that forge S_2 and S_3.
    let s1 = cm::apply(&s0, &bs[0]);
    let f2 = commit_countmin(&cm::apply(&s1, &cm::batch(&[(7, 1000), (13, 2)]))).0;
    let f3 = commit_countmin(&cm::apply(&s1, &cm::batch(&[(7, 2000), (13, 2)]))).0;
    let stmt = |t: u64, i: &[Val], f: &[Val]| -> Out {
        let mut v = i.to_vec();
        v.extend_from_slice(f);
        v.extend_from_slice(&[Val::from_u64(t), Val::from_u64(t), Val::from_u64(0), Val::from_u64(0)]);
        v.extend_from_slice(&leaf_digest(
            &hash_bb,
            4,
            t,
            &countmin_omc_batch_commit_with(&bs[t as usize - 1], Binding::Semantic),
        ));
        leaf_pin::toy(&v)
    };
    let toy2 = stmt(2, &commit_countmin(&s1).0, &f2);
    let toy3 = stmt(3, &f2, &f3);
    let posted = BatchLog { final_: f3.to_vec(), ..log.clone() };
    let forged = [&ls[0].0, &toy2.0, &toy3.0];
    assert_eq!(check_leaves_against_log(&forged, &posted, Expose::Interval), Ok(()), "pre-fix accepts");
    let new = verify_leaves_against_log(&forged, &vk, &posted, Expose::Interval);
    println!("B6B leaf pin, per-batch forged S_2/S_3: pre-fix=Ok new={new:?}");
    assert!(new.as_ref().is_err_and(|e| e.contains("leaf 2")), "{new:?}");

    // (3) Real leaves in the wrong positions: pinned and STARK-valid, but the
    // statement check rejects them (index / digest / boundary).
    let swapped = [&ls[1].0, &ls[0].0, &ls[2].0];
    let r = verify_leaves_against_log(&swapped, &vk, &log, Expose::Interval);
    println!("B6B leaf pin, per-batch real leaves swapped: {r:?}");
    assert!(r.is_err());
}

/// The pin rejects REAL, self-verifying leaf proofs of every other circuit:
/// the same family and parameters under the unsound Legacy binding (whose
/// exposed statement is IDENTICAL, so the pre-fix statement check accepts it),
/// the Boundary layout, other parameters, and another family.
#[test]
fn leaf_pin_rejects_other_real_circuits() {
    use crate::recursion::recursive::expose_forest::{
        check_leaves_against_log, verify_leaf_proof_pinned, verify_leaves_against_log,
    };
    use crate::sketch::Sketch;
    use crate::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf_expose};
    let vk = leaf_pin::vk();
    let s0 = cm::empty();
    let b1 = cm::batch(&[(7, 3), (11, 5)]);
    let log = cm::log(&s0, &cm::apply(&s0, &b1), &[b1.clone()]);
    let semantic = cm::leaf_circuit().prove_epoch_at(1, s0.clone(), b1.clone()).output;
    assert_eq!(verify_leaf_proof_pinned(&semantic.0, &vk), Ok(()), "control");

    let legacy = build_countmin_omc_leaf_expose(cm::P, Expose::Interval, Binding::Legacy)
        .prove_epoch_at(1, s0.clone(), b1.clone())
        .output;
    // The Legacy leaf commits the batch as `[key_lo, key_hi, value, 0]`, the
    // Semantic one as exact key limbs (`commit_batch_limbs`), so their leaf
    // digests differ and the Semantic log already rejects the Legacy leaf.
    // Against a log with the Legacy encoding, the Legacy leaf's statement
    // matches, the pre-fix statement check accepts it, and only the VK pin
    // rejects it.
    let (st_legacy, st_semantic) = (read_exposed_statement(&legacy.0), read_exposed_statement(&semantic.0));
    assert_eq!(st_legacy.init, st_semantic.init);
    assert_ne!(st_legacy.interval, st_semantic.interval, "Com(B_t) layouts differ");
    assert!(check_leaves_against_log(&[&legacy.0], &log, Expose::Interval).is_err(), "Semantic log");
    let log_legacy = {
        use crate::commitment::countmin::commit_countmin;
        use crate::sketch::countmin_omc::{countmin_omc_advance_with, countmin_omc_batch_commit_with};
        let mut s1 = s0.clone();
        countmin_omc_advance_with(&mut s1, &b1, Binding::Legacy);
        batch_log(
            &commit_countmin(&s0).0,
            &commit_countmin(&s1).0,
            &[countmin_omc_batch_commit_with(&b1, Binding::Legacy)],
        )
    };
    assert_eq!(check_leaves_against_log(&[&legacy.0], &log_legacy, Expose::Interval), Ok(()), "pre-fix accepts");
    let r = verify_leaves_against_log(&[&legacy.0], &vk, &log_legacy, Expose::Interval);
    println!("B6B leaf pin, Legacy-binding leaf: {r:?}");
    assert!(r.is_err());
    let commit_only = RootVk::commitment_only(vk.commitment.clone());
    let r = verify_leaves_against_log(&[&legacy.0], &commit_only, &log_legacy, Expose::Interval);
    assert!(r.as_ref().is_err_and(|e| e.contains("VK mismatch")), "{r:?}");

    let boundary = build_countmin_omc_leaf_expose(cm::P, Expose::Boundary, Binding::Semantic)
        .prove_epoch_at(1, s0.clone(), b1.clone())
        .output;
    assert!(verify_leaf_proof_pinned(&boundary.0, &vk).is_err(), "Boundary-layout leaf");

    let p8 = CmOmcParams { d: 2, w: 8, batch: 2 };
    let s0_8 = crate::sketch::countmin_v9::CountMinV9::new(&crate::sketch::countmin::CountMinParams {
        d: 2,
        w: 8,
    });
    let other_params = build_countmin_omc_leaf_expose(p8, Expose::Interval, Binding::Semantic)
        .prove_epoch_at(1, s0_8, b1.clone())
        .output;
    assert!(verify_leaf_proof_pinned(&other_params.0, &vk).is_err(), "other parameters");

    let hp = crate::sketch::hll_omc::HllOmcParams { b: 4, batch: 2 };
    let hll = crate::sketch::hll_omc::build_hll_omc_leaf_expose(hp, Expose::Interval, Binding::Semantic)
        .prove_epoch_at(1, crate::sketch::hll_omc::hll_omc_empty(4), vec![7, 11])
        .output;
    assert!(verify_leaf_proof_pinned(&hll.0, &vk).is_err(), "another family");
}

/// The pinned verifier's STARK check binds the exposed values: altering any
/// exposed coordinate of an honest leaf (init, final, index, digest) fails;
/// an untouched copy verifies (control of the tamper plumbing).
#[test]
fn leaf_pin_detects_tampered_exposed_values() {
    use crate::recursion::recursive::expose_forest::verify_leaf_proof_pinned;
    let vk = leaf_pin::vk();
    let real = cm::leaf_circuit().prove_epoch_at(3, cm::empty(), cm::batch(&[(7, 3), (11, 5)])).output;
    let copy = |p: &Proof| -> Proof { postcard::from_bytes(&postcard::to_allocvec(p).unwrap()).unwrap() };
    assert_eq!(verify_leaf_proof_pinned(&copy(&real.0), &vk), Ok(()), "control: untouched copy");
    for (slot, what) in [(0usize, "init"), (8, "final"), (16, "idx lo"), (17, "idx hi"), (20, "digest")] {
        let mut forged = copy(&real.0);
        let e = forged
            .non_primitives
            .iter_mut()
            .find(|e| e.public_values.len() == 28)
            .expect("Interval statement");
        e.public_values = leaf_pin::bump(&e.public_values, slot);
        let r = verify_leaf_proof_pinned(&forged, &vk);
        println!("B6B leaf pin, tampered {what}: {r:?}");
        assert!(r.is_err(), "a tampered exposed {what} must fail");
    }
}

/// Goldilocks: the lone-leaf attack on the GL atom. A GL toy mimicking the
/// honest CM `omc_gl` leaf statement passes the pre-fix checks and is rejected
/// by the GL leaf pin; the real leaf verifies.
#[test]
fn gl_leaf_pin_attack_foreign_circuit() {
    use crate::recursion::recursive::expose_forest_gl as fgl;
    use crate::sketch::countmin::CountMinUpdate;
    use crate::sketch::countmin_omc_gl::{
        CmOmcParams, apply_update_prf_with, build_countmin_omc_leaf_expose, cm_gl_empty,
        commit_batch_with, commit_countmin,
    };
    use p3_field::BasedVectorSpace;
    let params = CmOmcParams { d: 2, w: 4, batch: 2 };
    let mut leaf = build_countmin_omc_leaf_expose(params, Expose::Interval, Binding::Semantic);
    let noop = leaf
        .prove_epoch_at(1, cm_gl_empty(2, 4), vec![CountMinUpdate { key: 0, value: 0 }; 2])
        .output
        .0;
    let vk = fgl::leaf_vk(&noop);
    let b1 = vec![CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }];
    let s0 = cm_gl_empty(2, 4);
    let mut s1 = s0.clone();
    for u in &b1 {
        apply_update_prf_with(&mut s1, u, Binding::Semantic);
    }
    let real = leaf.prove_epoch_at(1, s0.clone(), b1.clone()).output;
    let log = fgl::batch_log(
        &commit_countmin(&s0).0,
        &commit_countmin(&s1).0,
        &[commit_batch_with(&b1, Binding::Semantic).0],
    );
    assert_eq!(fgl::verify_leaves_against_log(&[&real.0], &vk, &log, Expose::Interval), Ok(()));
    let v = fgl::read_exposed_statement(&real.0).values();
    assert_eq!(v.len(), 14);
    let cs: Vec<crate::config_gl::Challenge> = v
        .chunks(2)
        .map(|c| crate::config_gl::Challenge::from_basis_coefficients_slice(c).unwrap())
        .collect();
    let toy = fgl::prove_exposing_leaf(&cs);
    assert_eq!(fgl::check_root_against_log(&toy.0, &log, &ForestShape::Leaf), Ok(()), "pre-fix accepts");
    assert_eq!(fgl::check_leaves_against_log(&[&toy.0], &log, Expose::Interval), Ok(()));
    let new = fgl::verify_leaves_against_log(&[&toy.0], &vk, &log, Expose::Interval);
    println!("B6B gl leaf pin, lone leaf mimic: pre-fix=Ok new={new:?}");
    assert!(new.is_err_and(|e| e.contains("leaf 1")));
}

/// The index adjacency is a FIELD equation. On BabyBear, leaves proved at
/// `t = p - 1` and `t = 0` MERGE under the real atom, and the root passes the
/// derived root-VK pin and the STARK (and the pre-B6(b) boundary auditor);
/// the auditor rejects it on `lo != 1`, and its digest cannot match the log's
/// either. So intermediate `(lo, hi)` are meaningful only under an accepted
/// root (documented at the adjacency constraint).
#[test]
fn index_wrap_merges_in_circuit_but_root_rejected() {
    use p3_field::PrimeCharacteristicRing;
    use crate::recursion::recursive::statement::{expected_interval, hash_bb};
    use p3_field::PrimeField64;
    let p_minus_1 = <Val as PrimeField64>::ORDER_U64 - 1;
    let mut leaf = cm::leaf_circuit();
    let bs: Vec<_> = cm::honest_batches().into_iter().take(2).collect();
    let s0 = cm::empty();
    let (ls, s2) = cm::leaves_at(&mut leaf, &s0, &bs, &[p_minus_1, 0]);
    let st1 = read_exposed_statement(&ls[0].0).interval.unwrap();
    assert_eq!(st1.lo, Val::from_u64(p_minus_1));
    let root = outcome(|| prove_hiding_merge(&ls[0], &ls[1])).expect("the wrapped merge is provable");
    let shape = ForestShape::forest(2);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);
    let log = cm::log(&s0, &s2, &bs);
    assert!(legacy_auditor(&root.0, &vk, &log).is_ok(), "VK pin + STARK + boundary accept");
    let r = new_auditor(&root.0, &vk, &log, &shape);
    println!("B6B index wrap (p-1, 0): merge provable, auditor -> {r:?}");
    assert!(r.is_err_and(|e| e.contains("idx_lo")));
    let (_, _, expect) = expected_interval(&hash_bb, 4, &shape, 1, &log.batch_commits);
    assert_ne!(read_exposed_statement(&root.0).interval.unwrap().digest, expect, "digest differs too");
}

/// A multi-machine bracketing that DIFFERS from the plain forest:
/// `dist_forest(6, 2) = merge(forest(3), forest(3)) != forest(6)`. The dist
/// root (each slice folded as a worker folds it, the second slice root
/// shipped as wire bytes) has the derived VK and metadata and verifies against
/// the log under its own bracketing; a `forest(6)` auditor rejects it (its
/// root-VK pin: metadata / commitment), and so does the `forest(6)` digest.
#[test]
fn cm_dist_forest_6_2_bracketing() {
    use crate::recursion::recursive::expose_forest::vk_pin_values;
    use crate::recursion::recursive::root_vk::bound_proof_shape;
    let mut bs = cm::honest_batches();
    bs.push(cm::batch(&[(42, 1), (43, 2)]));
    bs.push(cm::batch(&[(7, 9), (44, 1)]));
    let s0 = cm::empty();
    let mut leaf = cm::leaf_circuit();
    let (ls, s6) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3, 4, 5, 6]);
    let log = cm::log(&s0, &s6, &bs);
    let mut ls = ls.into_iter();
    let slice0 = prove_forest_over(ls.by_ref().take(3).collect());
    let slice1 = prove_forest_over(ls.collect());
    let wire: Proof = postcard::from_bytes(&postcard::to_allocvec(&slice1.0).unwrap()).unwrap();
    let root = prove_hiding_merge_proofs(&slice0.0, &wire);
    let dist = ForestShape::dist_forest(6, 2);
    assert_ne!(dist, ForestShape::forest(6));
    let mut deriver = root_vk_deriver(cm::noop());
    let vk = deriver.root_vk(&dist);
    assert_eq!(vk.commitment, vk_pin_values(&root.0), "derived dist(6,2) root VK == real");
    assert_eq!(vk.shape, Some(bound_proof_shape(&root.0)), "derived metadata == real");
    assert_eq!(new_auditor(&root.0, &vk, &log, &dist), Ok(()));
    let f6 = deriver.root_vk(&ForestShape::forest(6));
    assert_ne!(f6.commitment, vk.commitment);
    let r = new_auditor(&root.0, &f6, &log, &ForestShape::forest(6));
    println!("B6B dist(6,2) root under a forest(6) auditor: {r:?}");
    assert!(r.is_err_and(|e| e.contains("metadata mismatch") || e.contains("VK mismatch")));
    let d = check_root_against_log(&root.0, &log, &ForestShape::forest(6));
    assert!(d.is_err_and(|e| e.contains("digest")));
}

/// The derivation TWIN (adjacency gap connected to 0) is provable over a
/// no-op leaf merged with ITSELF and has exactly the derived root metadata,
/// so a prover could try to submit it as the `forest(2)` root of a log with
/// two identical no-op batches. The derived root VK rejects it (commitment
/// pin); the honest `forest(2)` root over the same two batches is accepted.
#[test]
fn twin_merge_root_rejected_by_root_vk() {
    use crate::recursion::recursive::expose_forest::prove_twin_merge_for_test;
    use crate::recursion::recursive::root_vk::bound_proof_shape;
    let s0 = cm::empty();
    let noop = cm::batch(&[(7, 0), (11, 0)]);
    let mut leaf = cm::leaf_circuit();
    let (ls, s2) = cm::leaves_at(&mut leaf, &s0, &[noop.clone(), noop.clone()], &[1, 2]);
    let shape = ForestShape::forest(2);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);
    let log = cm::log(&s0, &s2, &[noop.clone(), noop]);
    let twin = prove_twin_merge_for_test(&ls[0].0, &ls[0].0);
    assert_eq!(Some(bound_proof_shape(&twin)), vk.shape, "the twin has the derived metadata");
    let r = new_auditor(&twin, &vk, &log, &shape);
    println!("B6B twin root as forest(2) root: {r:?}");
    assert!(r.is_err_and(|e| e.contains("root VK mismatch")));
    let honest = prove_hiding_merge(&ls[0], &ls[1]);
    assert_eq!(new_auditor(&honest.0, &vk, &log, &shape), Ok(()), "control");
}

// ─── M0 harness switches: bare peaks and the merge cache ────────────────────

/// M0 (`EXP_FOREST_RETAIN_PREP`, `EXP_MERGE_CACHE`): a cascade over 4 no-op
/// Count-Min leaves (one shared leaf circuit, batches of `value = 0` records),
/// in three configurations:
/// - **bare peaks, no merge cache**: the cascade holds NO prover data, by
///   type: every peak is a `&BatchStarkProof` (`peaks()`),
///   `holds_prover_data()` (peaks and cache) is false after every push, the
///   cascade never keeps a reference to the leaf circuit's prover data (its
///   `Rc` count drops back as each leaf is pushed), and the root comes back as
///   `PeakProof::Bare`;
/// - **bare peaks, one-entry merge cache** (the M0 default): the peaks hold
///   none (`peaks_hold_prover_data()` false after every push, no leaf-prep
///   handle), and the only prover data the cascade keeps is the cache's one
///   entry, from the first merge on (`holds_prover_data()` true exactly when
///   the cache is non-empty); the second level-1 merge (`[3, 4]`) was a cache
///   hit;
/// - **the pre-M0 cascade** (`ForestCascade::retaining`): its peaks do hold it.
///
/// All three roots have the same VK, metadata and statement, and each
/// verifies against the root VK derived from public parameters and the batch
/// log.
#[test]
fn m0_cascade_over_noop_leaves_holds_no_prover_data() {
    use std::rc::Rc;

    use crate::recursion::recursive::expose_forest::{
        ForestCascade, MergeCache, PeakProof, vk_pin_values,
    };
    use crate::recursion::recursive::root_vk::bound_proof_shape;
    let s0 = cm::empty();
    let noop = cm::batch(&[(7, 0), (11, 0)]);
    let batches = vec![noop.clone(); 4];
    let mut leaf = cm::leaf_circuit();
    let log = cm::log(&s0, &s0, &batches);
    let shape = ForestShape::forest(4);
    let vk = root_vk_deriver(cm::noop()).root_vk(&shape);

    // Per push: (peaks hold prover data, the cascade as a whole holds some,
    // cache entries); then the root and the cache's (hits, misses).
    type Held = Vec<(bool, bool, usize)>;
    let run = |mut forest: ForestCascade, leaf: &mut crate::sketch::countmin_omc::CmOmcLeafCircuit| {
        let (outs, _) = cm::leaves_at(leaf, &s0, &batches, &[1, 2, 3, 4]);
        let n = outs.len();
        let mut held_log: Held = Vec::new();
        for (k, out) in outs.into_iter().enumerate() {
            let prep = Rc::downgrade(&out.1);
            forest.push(out);
            // Handles outside the cascade: the leaf circuit's own and the
            // outputs not pushed yet. Bare: the cascade holds none (a cache
            // entry is a MERGE circuit's prover data, never a leaf's).
            // Retaining: a lone leaf peak (t = 1, 3) holds one.
            let held = prep.strong_count() - (1 + n - (k + 1));
            let peaks: Vec<(u64, u64, &Proof)> = forest.peaks();
            assert_eq!(peaks.len(), (k + 1).count_ones() as usize);
            let entries = forest.merge_cache().map_or(0, |c| c.len());
            println!(
                "M0 push t={} leaf_prep_handles_in_cascade={held} peaks_hold_prover_data={} \
                 holds_prover_data={} cache_entries={entries}",
                k + 1,
                forest.peaks_hold_prover_data(),
                forest.holds_prover_data(),
            );
            assert_eq!(held, usize::from(forest.peaks_hold_prover_data() && (k + 1) % 2 == 1));
            held_log.push((forest.peaks_hold_prover_data(), forest.holds_prover_data(), entries));
        }
        let (root, merges, stats) = forest.finalize_with_stats();
        assert_eq!(merges, 0, "t = 4 is one perfect tree");
        (root, held_log, stats)
    };

    // Bare peaks, no cache: nothing at all, after every push.
    let (bare, held, stats) = run(ForestCascade::with_options(1, false, None), &mut leaf);
    assert!(held.iter().all(|h| *h == (false, false, 0)), "bare cascade holds no prover data: {held:?}");
    assert!(matches!(bare, PeakProof::Bare(_)), "bare root");
    assert_eq!(stats, None);

    // Bare peaks + the default one-entry cache: only the cache's entry, from
    // the first merge (t = 2) on.
    let (cached, held, stats) =
        run(ForestCascade::with_options(1, false, Some(MergeCache::new(1))), &mut leaf);
    let expect: Held = vec![(false, false, 0), (false, true, 1), (false, true, 1), (false, true, 1)];
    assert_eq!(held, expect, "peaks bare; the cascade's prover data is the one cache entry");
    assert!(matches!(cached, PeakProof::Bare(_)), "bare root");
    assert_eq!(stats, Some((1, 2)), "merge [3, 4] reused the [1, 2] circuit");

    // The pre-M0 cascade: the peaks keep the merges' prover data.
    let (old, held_old, stats_old) = run(ForestCascade::retaining(1), &mut leaf);
    assert!(held_old.iter().all(|h| h.0 && h.1 && h.2 == 0), "pre-M0 peaks hold it: {held_old:?}");
    assert!(matches!(old, PeakProof::Retained(_)));
    assert_eq!(stats_old, None);

    for root in [&bare, &cached] {
        assert_eq!(vk_pin_values(root.proof()), vk_pin_values(old.proof()), "same root VK");
        assert_eq!(bound_proof_shape(root.proof()), bound_proof_shape(old.proof()));
        assert_eq!(read_exposed_statement(root.proof()), read_exposed_statement(old.proof()));
    }
    for root in [&bare, &cached, &old] {
        assert_eq!(new_auditor(root.proof(), &vk, &log, &shape), Ok(()));
    }
}

/// M0 (`EXP_MERGE_CACHE`): every CACHE-HIT merge natively verifies against
/// the VK the auditor derives from public parameters. Real Count-Min leaves
/// (honest, different batches): `[1, 2]` fills the one-entry cache, `[3, 4]`
/// hits it twice (two proofs with fresh masks under ZK). The hits are
/// pinned to the derived `forest(2)` VK and metadata and STARK-verified
/// natively, and the auditor's prefix check certifies `Com(S_4)` from
/// `[1, 2]` + `[3, 4]` against the log; the root merged from them verifies
/// against the derived `forest(4)` VK.
#[test]
fn m0_merge_cache_hits_verify_against_derived_vk() {
    use crate::recursion::recursive::expose_forest::{MergeCache, PrefixAuditor};
    let mut leaf = cm::leaf_circuit();
    let bs = cm::honest_batches();
    let s0 = cm::empty();
    let (l, s4) = cm::leaves_at(&mut leaf, &s0, &bs, &[1, 2, 3, 4]);
    let log = cm::log(&s0, &s4, &bs);
    let mut deriver = root_vk_deriver(cm::noop());
    let vk2 = deriver.root_vk(&ForestShape::forest(2));
    let vk4 = deriver.root_vk(&ForestShape::forest(4));

    let mut cache = MergeCache::new(1);
    let m12 = cache.merge(&l[0].0, &l[1].0, 2);
    assert_eq!((cache.hits(), cache.misses()), (0, 1));
    assert!(cache.contains(&l[2].0, &l[3].0), "same circuit, other data");
    let m34 = cache.merge(&l[2].0, &l[3].0, 2);
    let m34b = cache.merge(&l[2].0, &l[3].0, 2);
    assert_eq!((cache.hits(), cache.misses()), (2, 1));
    for (name, m) in [("[1,2] (miss)", &m12), ("[3,4] (hit)", &m34), ("[3,4] (hit, again)", &m34b)] {
        assert_eq!(
            outcome(|| verify_bound_stark_proof_pinned(&m.0, &vk2)),
            Ok(()),
            "{name} under the derived forest(2) VK"
        );
    }
    #[cfg(feature = "zk")]
    assert_ne!(
        postcard::to_allocvec(&m34.0).unwrap(),
        postcard::to_allocvec(&m34b.0).unwrap(),
        "two hits must not share masks"
    );
    let state_at_4 = cm_commit(&s4);
    let mut auditor = PrefixAuditor::new(cm::noop());
    for m34 in [&m34, &m34b] {
        let parts = [(&m12.0, ForestShape::forest(2)), (&m34.0, ForestShape::forest(2))];
        assert_eq!(auditor.certify_prefix(&parts, &log, 4), Ok(state_at_4.clone()));
    }
    let root = cache.merge(&m12.0, &m34.0, 4);
    assert_eq!(new_auditor(&root.0, &vk4, &log, &ForestShape::forest(4)), Ok(()));
}
