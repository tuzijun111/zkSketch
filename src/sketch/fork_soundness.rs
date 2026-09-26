//! Regression tests for three soundness gaps in the pinned Plonky3-recursion fork
//! (`July620/Plonky3_RangeAir` @ `19dcb37`). Each test builds a toy circuit, runs it
//! honestly, then FORGES the trace (rewriting every value that depends on the forged one so
//! that only the gap is exercised), proves against the HONEST circuit's prover data, and
//! verifies with `verify_all_tables`.
//!
//! These started as proof-of-concept tests that asserted the forgery was ACCEPTED (the
//! `poc_*` tests of the Bloom-filter leaf). Here they assert it is REJECTED, so they only
//! pass against a fork carrying the fixes:
//!
//! 1. **Constants bound.** `ConstAir` kept constant VALUES in the main trace with only
//!    `(multiplicity, index)` preprocessed and no constraint, so a prover could replace a
//!    constant consistently across its uses. Fixed by committing the value in the
//!    preprocessed row `[mult, idx, value[0..D)]` and constraining `main == preprocessed`.
//! 2. **Poseidon2 zero IV.** In the D > 1 (non-compact) layout, input limbs without a CTL on
//!    a `new_start` row (the capacity, and rate limbs a partial first chunk leaves unfilled)
//!    were unconstrained, so the IV was prover-chosen. Fixed by asserting them zero.
//! 3. **Unaligned `add_range_bits`.** For `n % 8 != 0` the top byte was looked up only as
//!    `byte·2^(8−r)`, which in a prime field admits `byte = v·2^-(8−r)`: no bound at all for
//!    `n < 8`, and `x < 2^n + 2^(8⌈n/8⌉−8)` for `n ≥ 9`. Fixed by also looking up the
//!    unshifted top byte.
//!
//! A forged proof counts as rejected when the prover returns an error, the prover panics
//! (e.g. while building a lookup table from an out-of-range value), or verification fails;
//! [`Verdict::Rejected`] records which. The controls re-run the repo-side mitigations
//! (`range_exact`, `hash_slice_bound`) that predate the fork fixes.
//!
//! [`known_gap_unpinned_verifier_accepts_a_forged_vk`] documents what the fork fixes do NOT
//! cover: `verify_all_tables` reads the preprocessed commitment (VK) from the proof, so a
//! prover that also swaps in the forged circuit's own prover data is accepted unless the
//! caller pins the VK.

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    ExposeTrace, NpoTypeId, Poseidon2Config, Poseidon2PermCall, Poseidon2Trace, RangeTrace,
    generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder, ExprId, Op};
use p3_circuit_prover::batch_stark_prover::{
    expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4, poseidon2_preprocessor,
    range_air_builders, range_preprocessor, recompose_air_builders, recompose_preprocessor,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_symmetric::{CryptographicHasher, Permutation};
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::make_leaf_config;

const LOG_FINAL_POLY_LEN: usize = 6;
const EXT_D: usize = 4;

type Preprocessors = Vec<Box<dyn NpoPreprocessor<Val>>>;
type AirBuilders = Vec<Box<dyn NpoAirBuilder<ConfigWithFriParams, EXT_D>>>;

fn table_packing() -> TablePacking {
    TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP)
}

/// Prover data (hence the preprocessed commitment, i.e. the VK) of `circuit`.
fn prover_data(
    circuit: &Circuit<Challenge>,
    preprocessors: &Preprocessors,
    air_builders: &AirBuilders,
) -> CircuitProverData<ConfigWithFriParams> {
    let config = make_leaf_config();
    let (airs_degrees, pc, npc) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, EXT_D>(
            circuit,
            &table_packing(),
            preprocessors,
            air_builders,
            ConstraintProfile::Standard,
        )
        .expect("preprocess");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    CircuitProverData::new(pd, pc, npc)
}

/// Outcome of proving and verifying a (possibly forged) trace.
enum Verdict {
    Accepted(Box<BatchStarkProof<ConfigWithFriParams>>),
    Rejected(String),
}

impl Verdict {
    fn is_accepted(&self) -> bool {
        matches!(self, Verdict::Accepted(_))
    }

    /// The first exposed op's public values (base coefficients).
    fn exposed(&self) -> Vec<Val> {
        match self {
            Verdict::Accepted(proof) => proof
                .non_primitives
                .iter()
                .find(|e| e.op_type == NpoTypeId::expose())
                .expect("expose table")
                .public_values
                .clone(),
            Verdict::Rejected(why) => panic!("expected an accepted proof, got: {why}"),
        }
    }

    fn describe(&self) -> String {
        match self {
            Verdict::Accepted(_) => "ACCEPTED".into(),
            Verdict::Rejected(why) => format!("rejected ({why})"),
        }
    }
}

/// Prove `traces` against `cpd` and verify with `verify_all_tables`.
fn prove_and_verify(
    traces: &Traces<Challenge>,
    cpd: &CircuitProverData<ConfigWithFriParams>,
    register: impl Fn(&mut BatchStarkProver<ConfigWithFriParams>),
) -> Verdict {
    let mut prover = BatchStarkProver::new(make_leaf_config()).with_table_packing(table_packing());
    register(&mut prover);
    let run = catch_unwind(AssertUnwindSafe(|| {
        let proof = prover
            .prove_all_tables(traces, cpd)
            .map_err(|e| format!("prove error: {e:?}"))?;
        prover
            .verify_all_tables(&proof)
            .map_err(|e| format!("verify error: {e:?}"))?;
        Ok::<_, String>(proof)
    }));
    match run {
        Ok(Ok(proof)) => Verdict::Accepted(Box::new(proof)),
        Ok(Err(why)) => Verdict::Rejected(why),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".into());
            Verdict::Rejected(format!("prover panicked: {msg}"))
        }
    }
}

/// Rewrite every expose-op input value whose witness is `wid` to `new` (all `D` coefficients).
fn patch_exposed(traces: &mut Traces<Challenge>, wid_new: &[(p3_circuit::WitnessId, Challenge)]) {
    let eid = NpoTypeId::expose();
    let mut ex: ExposeTrace<Val> = traces
        .non_primitive_trace::<ExposeTrace<Val>>(&eid)
        .expect("expose trace")
        .clone();
    for op in ex.operations.iter_mut() {
        for (pos, wid) in op.input_wids.iter().enumerate() {
            for (w, new) in wid_new {
                if wid == w {
                    let c = <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(new);
                    op.input_values[EXT_D * pos..EXT_D * pos + EXT_D].copy_from_slice(c);
                }
            }
        }
    }
    traces.non_primitive_traces.insert(eid, Box::new(ex));
}

// ─── Gap 1: constant values ──────────────────────────────────────────────

/// `y = x + K` with the constant `K = 5`, `(x, y)` exposed.
fn const_circuit() -> Circuit<Challenge> {
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_expose(generate_expose_trace::<Val, Challenge>);
    let xpub = b.alloc_public_input("x");
    let kc = b.alloc_const(Challenge::from_u64(5), "K");
    let y = b.add(xpub, kc);
    b.add_expose(&[xpub, y]).unwrap();
    b.tag(kc, "K").unwrap();
    b.tag(y, "y").unwrap();
    b.build().unwrap()
}

fn const_tables() -> (Preprocessors, AirBuilders) {
    (
        vec![expose_preprocessor::<Val>()],
        expose_air_builders::<ConfigWithFriParams, EXT_D>(),
    )
}

/// Run `circuit` on `x = 1`, optionally FORGE the Const table's value of `K` to 7 (patching
/// the ALU row and the exposed `y = 8`), and prove against the honest circuit's prover data.
fn const_value_forgery(forge: bool) -> Verdict {
    let circuit = const_circuit();
    let (pre, airs) = const_tables();
    let cpd = prover_data(&circuit, &pre, &airs);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[Challenge::from_u64(1)]).unwrap();
    let mut traces = runner.run().expect("honest run");
    if forge {
        let k_wid = traces.tag_to_witness["K"];
        let y_wid = traces.tag_to_witness["y"];
        let (k_new, y_new) = (Challenge::from_u64(7), Challenge::from_u64(8));
        for (i, wid) in traces.const_trace.index.iter().enumerate() {
            if *wid == k_wid {
                traces.const_trace.values[i] = k_new;
            }
        }
        for (row, idx) in traces.alu_trace.indices.iter().enumerate() {
            for slot in 0..4 {
                if idx[slot] == k_wid {
                    traces.alu_trace.values[row][slot] = k_new;
                }
                if idx[slot] == y_wid {
                    traces.alu_trace.values[row][slot] = y_new;
                }
            }
        }
        patch_exposed(&mut traces, &[(y_wid, y_new)]);
    }
    prove_and_verify(&traces, &cpd, |p| p.register_expose_table::<EXT_D>())
}

/// Was `poc_const_values_are_prover_chosen`: a proof of `y = x + 5` exposing `x = 1, y = 8`
/// verified. Now the forged constant value contradicts the committed preprocessed value.
#[test]
fn const_value_forgery_is_rejected() {
    let honest = const_value_forgery(false);
    assert_eq!(
        honest.exposed()[..8],
        [Val::ONE, Val::ZERO, Val::ZERO, Val::ZERO, Val::from_u64(6), Val::ZERO, Val::ZERO, Val::ZERO],
        "honest run must verify and expose (x, y) = (1, 6)"
    );
    let forged = const_value_forgery(true);
    eprintln!("forged constant K = 7: {}", forged.describe());
    assert!(
        !forged.is_accepted(),
        "a trace with a forged constant value must be rejected"
    );
}

/// KNOWN GAP (not fixed by the fork patch): `verify_all_tables` takes the preprocessed
/// commitment from `proof.stark_common`. A prover that builds the FORGED circuit (`K = 7`)
/// and proves with that circuit's own prover data gets a proof `verify_all_tables` accepts;
/// only a caller that pins the honest circuit's commitment can reject it. This test asserts
/// the gap (acceptance by the unpinned verifier) and that pinning closes it: it must flip
/// once `verify_all_tables` takes an expected VK.
#[test]
fn known_gap_unpinned_verifier_accepts_a_forged_vk() {
    let circuit = const_circuit();
    let mut forged = circuit.clone();
    let mut swapped = 0;
    for op in forged.ops.iter_mut() {
        if let Op::Const { val, .. } = op
            && *val == Challenge::from_u64(5)
        {
            *val = Challenge::from_u64(7);
            swapped += 1;
        }
    }
    assert_eq!(swapped, 1, "exactly one Const op carries K");
    let (pre, airs) = const_tables();
    let honest_vk = prover_data(&circuit, &pre, &airs)
        .common_data()
        .preprocessed
        .as_ref()
        .expect("preprocessed")
        .commitment
        .clone();
    let forged_cpd = prover_data(&forged, &pre, &airs);
    let mut runner = forged.runner();
    runner.set_public_inputs(&[Challenge::from_u64(1)]).unwrap();
    let traces = runner.run().expect("forged-circuit run");
    let verdict = prove_and_verify(&traces, &forged_cpd, |p| {
        p.register_expose_table::<EXT_D>()
    });
    assert!(
        verdict.is_accepted(),
        "unpinned verify_all_tables accepts a proof under the forged circuit's VK \
         (if this fails, the verifier now pins the VK: flip this test)"
    );
    assert_eq!(verdict.exposed()[4], Val::from_u64(8), "exposes y = x + 7");
    let Verdict::Accepted(proof) = verdict else { unreachable!() };
    let proof_vk = &proof.stark_common.preprocessed.as_ref().unwrap().commitment;
    assert_ne!(
        *proof_vk, honest_vk,
        "the forged circuit has a different VK, so a verifier that pins the honest VK rejects it"
    );
}

// ─── Gap 2: Poseidon2 IV (D = 4) ─────────────────────────────────────────

/// Sponge hash equal to `add_hash_slice(cfg, inputs, true)` except that EVERY input limb of
/// the first (`new_start`) row is CTL-bound (unfilled rate limbs and the capacity are fed the
/// zero constant). The repo-side mitigation for gap 2 (copied from the Bloom-filter leaf).
fn hash_slice_bound(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    inputs: &[ExprId],
    zero: ExprId,
) -> Vec<ExprId> {
    assert!(!inputs.is_empty());
    let width_ext = cfg.width_ext();
    let rate_ext = cfg.rate_ext();
    let chunks: Vec<&[ExprId]> = inputs.chunks(rate_ext).collect();
    let last = chunks.len() - 1;
    let mut outputs: Vec<Option<ExprId>> = Vec::new();
    for (i, ch) in chunks.iter().enumerate() {
        let first = i == 0;
        let call_inputs: Vec<Option<ExprId>> = (0..width_ext)
            .map(|j| {
                if j < ch.len() {
                    Some(ch[j])
                } else if first {
                    Some(zero)
                } else {
                    None
                }
            })
            .collect();
        let (_, outs) = b
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: *cfg,
                new_start: first,
                merkle_path: false,
                mmcs_bit: None,
                inputs: call_inputs,
                out_ctl: vec![i == last; rate_ext],
                return_all_outputs: false,
                mmcs_index_sum: None,
            })
            .expect("poseidon2 perm");
        outputs = outs;
    }
    outputs
        .into_iter()
        .take(rate_ext)
        .map(|o| o.expect("rate output"))
        .collect()
}

/// Hash one exposed Challenge `x` (4 values → one Poseidon2 row) and expose `(x, digest)`,
/// via plain `add_hash_slice` or via [`hash_slice_bound`]. With `forge = Some(i)`, add 1 to
/// input value `i` of that row (8, 9: capacity limb 2; 4..8: the unfilled rate limb 1),
/// recompute the permutation and patch the exposed digest. Returns the verdict and, when
/// accepted, the exposed digest.
fn poseidon_iv_forgery(bound: bool, forge: Option<usize>) -> (Verdict, Option<[Val; 8]>) {
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_expose(generate_expose_trace::<Val, Challenge>);
    let xpub = b.alloc_public_input("x");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let h = if bound {
        hash_slice_bound(&mut b, &cfg, &[xpub], zero)
    } else {
        b.add_hash_slice(&cfg, &[xpub], true).unwrap()
    };
    b.add_expose(&[xpub, h[0], h[1]]).unwrap();
    b.tag(h[0], "h0").unwrap();
    b.tag(h[1], "h1").unwrap();
    let circuit = b.build().unwrap();

    let pre: Preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
        expose_preprocessor::<Val>(),
    ];
    let mut airs: AirBuilders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    airs.extend(recompose_air_builders::<ConfigWithFriParams, EXT_D>(1, false));
    airs.extend(expose_air_builders::<ConfigWithFriParams, EXT_D>());
    let cpd = prover_data(&circuit, &pre, &airs);

    let xs = [1u64, 2, 3, 4].map(Val::from_u64);
    let x = Challenge::from_basis_coefficients_slice(&xs).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[x]).unwrap();
    let mut traces = runner.run().expect("honest run");

    if let Some(at) = forge {
        let pid = NpoTypeId::poseidon2_perm(cfg);
        let mut pt: Poseidon2Trace<Val> = traces
            .non_primitive_trace::<Poseidon2Trace<Val>>(&pid)
            .expect("poseidon2 trace")
            .clone();
        assert_eq!(pt.operations.len(), 1, "one permutation row");
        let row = &mut pt.operations[0];
        assert_eq!(row.input_values[at], Val::ZERO, "forged limb holds the zero IV");
        row.input_values[at] += Val::ONE;
        let mut state: [Val; 16] = row.input_values.clone().try_into().unwrap();
        make_perm().permute_mut(&mut state);
        traces.non_primitive_traces.insert(pid, Box::new(pt));
        let h0 = traces.tag_to_witness["h0"];
        let h1 = traces.tag_to_witness["h1"];
        let d0 = Challenge::from_basis_coefficients_slice(&state[0..4]).unwrap();
        let d1 = Challenge::from_basis_coefficients_slice(&state[4..8]).unwrap();
        patch_exposed(&mut traces, &[(h0, d0), (h1, d1)]);
    }

    let verdict = prove_and_verify(&traces, &cpd, |p| {
        p.register_poseidon2_table::<EXT_D>(cfg);
        p.register_recompose_table::<EXT_D>(false);
        p.register_expose_table::<EXT_D>();
    });
    let digest = verdict
        .is_accepted()
        .then(|| std::array::from_fn(|i| verdict.exposed()[4 + i]));
    (verdict, digest)
}

fn native_digest() -> [Val; 8] {
    MyHash::new(make_perm()).hash_iter([1u64, 2, 3, 4].map(Val::from_u64))
}

/// Was `poc_poseidon_d4_free_capacity`: with plain `add_hash_slice` a proof verified while
/// exposing a "digest" of `x` that is not `MyHash(x)` (capacity limb 2 forged).
#[test]
fn poseidon_d4_free_capacity_forgery_is_rejected() {
    let (honest, digest) = poseidon_iv_forgery(false, None);
    assert!(honest.is_accepted(), "honest run must verify: {}", honest.describe());
    assert_eq!(digest, Some(native_digest()), "honest digest must equal MyHash");
    let (forged, _) = poseidon_iv_forgery(false, Some(8));
    eprintln!("forged Poseidon2 capacity: {}", forged.describe());
    assert!(
        !forged.is_accepted(),
        "a sponge chain start with a nonzero, non-CTL capacity must be rejected"
    );
}

/// Same, forging the rate limb the one-element first chunk leaves unfilled (limb 1).
#[test]
fn poseidon_d4_free_unfilled_rate_limb_forgery_is_rejected() {
    let (forged, _) = poseidon_iv_forgery(false, Some(5));
    eprintln!("forged Poseidon2 unfilled rate limb: {}", forged.describe());
    assert!(
        !forged.is_accepted(),
        "a sponge chain start with a nonzero, non-CTL rate limb must be rejected"
    );
}

/// Control (was `control_bound_sponge_rejects_capacity_forgery`): the repo-side
/// [`hash_slice_bound`] still matches `MyHash` and still rejects the forgery.
#[test]
fn control_bound_sponge_rejects_capacity_forgery() {
    let (honest, digest) = poseidon_iv_forgery(true, None);
    assert!(honest.is_accepted(), "bound sponge must verify: {}", honest.describe());
    assert_eq!(digest, Some(native_digest()), "bound sponge must equal MyHash");
    let (forged, _) = poseidon_iv_forgery(true, Some(8));
    assert!(
        !forged.is_accepted(),
        "capacity forgery must be rejected by the bound sponge"
    );
}

// ─── Gap 3: unaligned add_range_bits ─────────────────────────────────────

/// Exact `x ∈ [0, 2^n)` (`1 ≤ n ≤ 24`) from byte-aligned `add_range_bits` only: `x` and
/// `x + (2^{n8} − 2^n)` both in `[0, 2^{n8})`, `n8 = 8⌈n/8⌉`. The repo-side mitigation for
/// gap 3 (copied from the Bloom-filter leaf).
fn range_exact(b: &mut CircuitBuilder<Challenge>, x: ExprId, n: usize) {
    assert!((1..=24).contains(&n));
    let n8 = n.div_ceil(8) * 8;
    b.add_range_bits::<Val>(x, n8).expect("range_exact aligned");
    if n8 != n {
        let off = b.alloc_const(
            Challenge::from_u64((1u64 << n8) - (1u64 << n)),
            "range_exact_off",
        );
        let y = b.add(x, off);
        b.add_range_bits::<Val>(y, n8).expect("range_exact shifted");
    }
}

/// Range-check the exposed public `x` to `n` bits (fork `add_range_bits` or [`range_exact`]),
/// run honestly on `x_honest`, then (if `remap` is non-empty) FORGE by rewriting every trace
/// value in the ALU, Public and Range tables (and the exposed `x`) through `remap`, which
/// lists `(honest value, forged value)` for every wire derived from `x`.
fn range_bits_forgery(exact: bool, n: usize, x_honest: u64, remap: &[(Val, Val)]) -> Verdict {
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_range(generate_range_trace::<Val, Challenge>);
    b.enable_expose(generate_expose_trace::<Val, Challenge>);
    let xpub = b.alloc_public_input("x");
    b.add_expose(&[xpub]).unwrap();
    if exact {
        range_exact(&mut b, xpub, n);
    } else {
        b.add_range_bits::<Val>(xpub, n).unwrap();
    }
    b.tag(xpub, "x").unwrap();
    let circuit = b.build().unwrap();
    let pre: Preprocessors = vec![range_preprocessor::<Val>(), expose_preprocessor::<Val>()];
    let mut airs: AirBuilders = range_air_builders::<ConfigWithFriParams, EXT_D>(1);
    airs.extend(expose_air_builders::<ConfigWithFriParams, EXT_D>());
    let cpd = prover_data(&circuit, &pre, &airs);

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[Challenge::from_u64(x_honest)])
        .unwrap();
    let mut traces = runner.run().expect("honest run");

    if !remap.is_empty() {
        let map = |v: Challenge| -> Challenge {
            for &(h, f) in remap {
                if v == Challenge::from(h) {
                    return Challenge::from(f);
                }
            }
            v
        };
        for row in traces.alu_trace.values.iter_mut() {
            for slot in row.iter_mut() {
                *slot = map(*slot);
            }
        }
        for v in traces.public_trace.values.iter_mut() {
            *v = map(*v);
        }
        let rid = NpoTypeId::range();
        let mut rt: RangeTrace<Val> = traces
            .non_primitive_trace::<RangeTrace<Val>>(&rid)
            .expect("range trace")
            .clone();
        for op in rt.operations.iter_mut() {
            for v in op.input_values.chunks_mut(EXT_D) {
                for &(h, f) in remap {
                    if v[0] == h && v[1..].iter().all(|c| *c == Val::ZERO) {
                        v[0] = f;
                        break;
                    }
                }
            }
        }
        traces.non_primitive_traces.insert(rid, Box::new(rt));
        let x_forged = remap[0].1;
        let x_wid = traces.tag_to_witness["x"];
        patch_exposed(&mut traces, &[(x_wid, Challenge::from(x_forged))]);
    }

    prove_and_verify(&traces, &cpd, |p| {
        p.register_range_table::<EXT_D>();
        p.register_expose_table::<EXT_D>();
    })
}

/// `n = 4`, honest `x = 3` (byte 3, shifted byte 48); forged `x = 16^{-1} mod p` (byte
/// `16^{-1}`, shifted byte 1).
fn remap_n4() -> Vec<(Val, Val)> {
    let x_forged = Val::from_u64(16).inverse();
    vec![(Val::from_u64(3), x_forged), (Val::from_u64(48), Val::ONE)]
}

/// Was `poc_add_range_bits_unaligned_is_not_a_range_check`: `add_range_bits(x, 4)` accepted
/// `x = 16^{-1} mod p` (≈ 0.94·p).
#[test]
fn add_range_bits_unaligned_small_n_forgery_is_rejected() {
    let honest = range_bits_forgery(false, 4, 3, &[]);
    assert_eq!(honest.exposed()[0], Val::from_u64(3), "honest run must verify");
    let forged = range_bits_forgery(false, 4, 3, &remap_n4());
    eprintln!("add_range_bits(x, 4), x = 16^-1: {}", forged.describe());
    assert!(
        !forged.is_accepted(),
        "add_range_bits(x, 4) must reject x = 16^-1 mod p"
    );
}

/// `n = 12` (`k = 2`, `r = 4`): the unfixed check proved only `x < 2^12 + 2^8`. Honest
/// `x = 4000` (bytes 160, 15; shifted top byte 240); forged `x = 4101 ≥ 2^12` as bytes
/// `21 + 256·(255·16^{-1})`: `21 < 256`, and the shifted top byte is `255 < 256`.
#[test]
fn add_range_bits_unaligned_large_n_forgery_is_rejected() {
    let honest = range_bits_forgery(false, 12, 4000, &[]);
    assert_eq!(honest.exposed()[0], Val::from_u64(4000), "honest run must verify");
    let b1_forged = Val::from_u64(255) * Val::from_u64(16).inverse();
    assert_eq!(
        Val::from_u64(21) + Val::from_u64(256) * b1_forged,
        Val::from_u64(4101),
        "forged bytes recompose to 4101"
    );
    let remap = [
        (Val::from_u64(4000), Val::from_u64(4101)),
        (Val::from_u64(160), Val::from_u64(21)),
        (Val::from_u64(15), b1_forged),
        (Val::from_u64(240), Val::from_u64(255)),
    ];
    let forged = range_bits_forgery(false, 12, 4000, &remap);
    eprintln!("add_range_bits(x, 12), x = 4101: {}", forged.describe());
    assert!(
        !forged.is_accepted(),
        "add_range_bits(x, 12) must reject x = 4101 >= 2^12"
    );
}

/// Control (was `control_range_exact_rejects_unaligned_forgery`): [`range_exact`] (two
/// byte-aligned checks) still rejects `x = 16^{-1}` for `n = 4`. The shifted wire is
/// `y = x + (2^8 − 2^4) = x + 240`, honest 243. (The original PoC remapped `251 → x + 248`,
/// a value that never occurs, so its forged trace broke the `y = x + 240` ALU row and was
/// rejected for that reason rather than by the range check.)
#[test]
fn control_range_exact_rejects_unaligned_forgery() {
    let honest = range_bits_forgery(true, 4, 3, &[]);
    assert_eq!(honest.exposed()[0], Val::from_u64(3), "honest run must verify");
    let x_forged = Val::from_u64(16).inverse();
    let remap = [
        (Val::from_u64(3), x_forged),
        (Val::from_u64(243), x_forged + Val::from_u64(240)),
    ];
    let forged = range_bits_forgery(true, 4, 3, &remap);
    assert!(!forged.is_accepted(), "range_exact must reject x = 16^-1");
}

/// Honest boundary values still pass the fixed unaligned check (`2^n − 1` for several `n`,
/// including the widths the repo uses: 6, 22, 27, 29).
#[test]
fn add_range_bits_unaligned_accepts_max_value() {
    for n in [4usize, 6, 12, 22, 27, 29] {
        let x = (1u64 << n) - 1;
        let verdict = range_bits_forgery(false, n, x, &[]);
        assert!(
            verdict.is_accepted(),
            "add_range_bits(2^{n} - 1, {n}) must verify: {}",
            verdict.describe()
        );
        assert_eq!(verdict.exposed()[0].as_canonical_u64(), x);
    }
}
