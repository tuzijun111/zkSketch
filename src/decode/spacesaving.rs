//! SpaceSaving **top-`c` query** decode circuit (E3, plonky3/STARK).
//!
//! Implements the paper's *SpaceSaving Top-`c` Query Circuit* (zk1.tex
//! §SpaceSaving Query Circuit). A top-`c` query returns the first `c` active
//! rows of the committed summary under the declared count/key order; \sys
//! answers queries against the closed (committed) state `S_t`. This is the
//! STARK-backend counterpart of the plonky2 `decode::spacesaving` relation.
//!
//! The committed state is an [`SsFullState`] (the same row table the
//! `ss_final_full` update circuit recommits). Its rows are kept in
//! `(active asc, count asc)` order (dummies first, then actives by **ascending**
//! count), so the **top heavy hitters** (highest counts) are the *last* active
//! rows. Each row packs into one `Challenge` as the 4 base coefficients
//! `[key_lo, key_hi, count, active]`, and `commit_ss_state` is the flat
//! Poseidon2 over those rows; `pack_cells` here reproduces that exact
//! flattening so the in-circuit `add_hash_slice` binds the opened cells to the
//! published digest.
//!
//! ### Verification target (paper)
//!
//! Public input is the query size `c`. With `#active = #{active rows}` and
//! `k = min(c, #active)`, the released result table `res` is the first `k`
//! rows of `S_t` under the declared (top-count-first) order, with canonical
//! dummy rows beyond position `k`. For the identity release policy the circuit
//! binds the published answer to `res` (here: the released top-`c` mass
//! `Σ res[z].count`, a deterministic function of the fully-pinned `res`).
//!
//! ### Checks
//!
//! 1. **State opening** — re-hash the `capacity` packed rows, bind to the
//!    committed digest (the `Θ(s)` cost).
//! 2. **Active-prefix structure** — active flags are monotone (here a
//!    contiguous *suffix*: dummies first, actives last).
//! 3. **Distinct-key** — adjacent active rows carry distinct keys (the
//!    grouped summary has no duplicate retained keys); witnessed inverse.
//! 4. **Sortedness** — counts are non-decreasing along the stored order
//!    (range-checked adjacent diff); equivalently the top heavy hitters are
//!    the trailing rows.
//! 5. **Top-`c` selection** — a monotone 0/1 selector `sel` marks exactly
//!    `k = min(c, #active)` rows as released: a *suffix* of the row array
//!    (the highest-count actives), each selected row active, and
//!    `Σ sel = min(c, #active)`.
//! 6. **Release binding** — for identity release `answer = Σ sel·count`
//!    (the released top-`c` mass); for `Threshold(θ)` the mass is gated by
//!    `mass ≥ θ` (same `≥` semantics as the other decode leaves).
//!
//! Scope: keys must fit in one BabyBear limb (`key_hi = 0`, `key < 2^31`),
//! matching `ss_final_full`. Counts/mass fit in `DIFF_BITS − 1` bits at
//! prototype scale. The query size `c` is a verifier-supplied public input.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_range_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        range_air_builders, range_preprocessor, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::decode::{DecodeProof, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::ss_final_full::{SsFullState, commit_ss_state};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Range-check window for non-negative diffs (count sortedness, the `c −
/// Σsel ≥ 0` selection bound, and the threshold gate). Counts/`c`/mass fit in
/// `DIFF_BITS − 1` bits at prototype scale; a "negative" diff wraps past `2^p`
/// and overflows the check (sound `>= 0`).
const DIFF_BITS: usize = 22;

#[derive(Copy, Clone, Debug)]
pub struct SsDecodeParams {
    pub capacity: usize,
    /// Query size `c` — release the top-`c` heavy hitters by count.
    pub c: usize,
    pub release: ReleasePolicy,
}

impl SsDecodeParams {
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity must be positive, got {}", self.capacity);
        assert!(self.c >= 1, "query size c must be positive, got {}", self.c);
    }
}

/// Pack a SpaceSaving state's rows into Challenge elements (one row / Challenge,
/// 4 base coeffs `[key_lo, key_hi, count, active]`), matching
/// `commit_ss_state`'s flattening and the committed digest.
fn pack_cells(state: &SsFullState) -> Vec<Challenge> {
    state
        .rows
        .iter()
        .map(|r| {
            let lo = (r.key & 0xFFFF_FFFF) as u32;
            let hi = (r.key >> 32) as u32;
            let coeffs =
                [Val::from_u32(lo), Val::from_u32(hi), Val::from_u32(r.count), Val::from_u32(r.active)];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

/// Native top-`c` selection over a stored SpaceSaving state.
///
/// The state rows are in `(active asc, count asc)` order, so the top heavy
/// hitters by count are the trailing rows. Returns, for each row index, a 0/1
/// selector marking the released top-`min(c, #active)` rows (a suffix of the
/// row array), together with the released mass `Σ selected count`.
fn native_select(state: &SsFullState, c: usize) -> (Vec<u32>, u64) {
    let cap = state.rows.len();
    let n_active = state.rows.iter().filter(|r| r.active == 1).count();
    let k = c.min(n_active);
    // Select the trailing `k` rows (the highest-count actives). Because the
    // active rows form the suffix and are count-ascending, the last `k` rows
    // are exactly the top-`k` heavy hitters.
    let mut sel = vec![0u32; cap];
    for r in (0..cap).rev().take(k) {
        sel[r] = 1;
    }
    let mass: u64 = (0..cap).filter(|&r| sel[r] == 1).map(|r| state.rows[r].count as u64).sum();
    (sel, mass)
}

/// Prove a SpaceSaving top-`c` query decode. Returns a [`DecodeProof`]; the
/// prover self-verifies and records the witness/prove/verify split via
/// [`crate::recursion::recursive::timing`]. The `answer` is the released
/// top-`c` mass (the identity image of the `res` table) under the release
/// policy.
pub fn prove_ss_decode(params: SsDecodeParams, state: SsFullState, c: usize) -> DecodeProof {
    params.validate();
    assert_eq!(c, params.c, "c argument must match params.c");
    let SsDecodeParams { capacity: cap, c: _c, release } = params;
    assert_eq!(state.rows.len(), cap, "state capacity must match params");

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_ss_state(&state);
    let (sel_native, mass) = native_select(&state, c);
    let answer = release.apply(mass);

    // ─── Build circuit ───────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);

    // PIs: committed state, query size c, released answer.
    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let c_pi = b.alloc_public_input("c");
    let answer_pi = b.alloc_public_input("answer");

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let neg_one = b.alloc_const(-Challenge::ONE, "neg_one");

    // Private witnesses.
    let cells_packed: Vec<ExprId> =
        (0..cap).map(|_| b.alloc_private_input("cell_packed")).collect();
    // sel[r] ∈ {0,1}: the top-c selector (released-row indicator).
    let sel: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("sel")).collect();
    // key_inv[r]: inverse of (key[r+1] − key[r]) for the distinct-key check.
    let key_inv: Vec<ExprId> = (0..cap.saturating_sub(1)).map(|_| b.alloc_private_input("key_inv")).collect();
    let flag = if matches!(release, ReleasePolicy::Threshold(_)) {
        Some(b.alloc_private_input("flag"))
    } else {
        None
    };

    // ── Check 1: open the committed state ──
    let digest = b
        .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
        .expect("hash cells");
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }
    // Decompose each packed row into [key_lo, key_hi, count, active]. Every
    // decompose output that we constrain must flow through an ALU op as the
    // LHS at least once (WitnessChecks discipline), or the prover panics with
    // "GlobalCumulativeMismatch: WitnessChecks". We put each cell coeff FIRST
    // in the muls that consume it below.
    let fields: Vec<Vec<ExprId>> = cells_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose row"))
        .collect();

    // Every decompose coeff is a HINT: it gets its WitnessChecks bus creator
    // ONLY from its first use as an ALU `a`-operand (lhs); used only as a `b`
    // (rhs) it is never created, and used as BOTH operands of one op (e.g.
    // `mul(coeff, coeff)`) it is double-created. Either way the global LogUp
    // bus unbalances (GlobalCumulativeMismatch). So we lift each coeff to a
    // bus-safe ALU copy `coeff·1` exactly once (created cleanly as the `a`-
    // operand, `one` being a const) and build EVERY downstream relation on
    // those copies. `key_hi` is additionally pinned to 0 (single-limb keys).
    let klo: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][0], one)).collect();
    let cnt: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][2], one)).collect();
    let act: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][3], one)).collect();
    for r in 0..cap {
        let key_hi_l = b.mul(fields[r][1], one);
        b.connect(key_hi_l, zero);
    }

    // WitnessChecks bus note (applies to every boolean check below): an ALU op
    // that reads the SAME witness on both the `a` and `b` lanes (e.g.
    // `mul(x, x)`) double-counts it on the global LogUp bus and unbalances it
    // (GlobalCumulativeMismatch). So every `x·x` is written as `x·(x − 1) = 0`
    // with a fresh `x − 1` sub output, reading `x` once per op.

    // ── Check 2: active-prefix structure (active monotone non-decreasing) ──
    // Stored order puts dummies first, actives last → actives form a suffix.
    // active ∈ {0,1} and active[r] ≤ active[r+1].
    for r in 0..cap {
        // active ∈ {0,1}: act·(act − 1) = 0 (distinct operands; see note).
        let a = act[r];
        let a_m1 = b.sub(a, one);
        let bchk = b.mul(a, a_m1);
        b.connect(bchk, zero);
    }
    for r in 0..cap - 1 {
        // active[r+1] − active[r] ∈ {0,1}  ⇒ monotone non-decreasing.
        let neg_ar = b.mul(act[r], neg_one);
        let d = b.add(act[r + 1], neg_ar);
        let one_minus = b.sub(one, d); // const lhs → forward
        let prod = b.mul(d, one_minus);
        b.connect(prod, zero);
    }

    // ── Check 4: sortedness — counts non-decreasing along the stored order ──
    // count[r+1] − count[r] ≥ 0, range-checked (dummies have count 0 so the
    // dummy→active boundary is also non-negative; no gating needed).
    for r in 0..cap - 1 {
        let neg_cr = b.mul(cnt[r], neg_one);
        let cdiff = b.add(cnt[r + 1], neg_cr); // count[r+1] − count[r]
        let _ = b.add_range_bits::<Val>(cdiff, DIFF_BITS).expect("count sortedness");
    }

    // ── Check 3: distinct-key on adjacent ACTIVE rows ──
    // If active[r]·active[r+1] = 1 then key[r+1] ≠ key[r]. With kdiff =
    // key[r+1] − key[r] and witnessed inverse `key_inv[r]`, force
    //   active[r]·active[r+1]·(1 − kdiff·inv) = 0.
    // (When both active, the only way the product vanishes is kdiff·inv = 1,
    // i.e. kdiff ≠ 0.)
    for r in 0..cap - 1 {
        let neg_klo = b.mul(klo[r], neg_one);
        let kdiff = b.add(klo[r + 1], neg_klo); // key_lo[r+1] − key_lo[r]
        let kd_inv = b.mul(kdiff, key_inv[r]);
        let one_minus = b.sub(one, kd_inv); // 1 − kdiff·inv
        let both_active = b.mul(act[r], act[r + 1]);
        let dchk = b.mul(both_active, one_minus);
        b.connect(dchk, zero);
    }

    // ── Check 5: top-c selection ──
    // sel[r] ∈ {0,1}; sel monotone non-decreasing (a suffix); sel ≤ active;
    // Σ sel = min(c, #active).
    //
    // `sel[r]` is a private input. Its mandatory bus creator must come from a
    // SINGLE ALU use as the `a`-operand (lhs). We lift each `sel[r]` to a
    // bus-safe ALU copy `sv[r] = sel[r]·1` (created cleanly as the `a`-operand,
    // `one` being a const), then build the relation on `sv`.
    let sv: Vec<ExprId> = (0..cap).map(|r| b.mul(sel[r], one)).collect();
    for r in 0..cap {
        let s = sv[r];
        // sv ∈ {0,1}: sv·(sv − 1) = 0 (distinct operands; see note).
        let s_m1 = b.sub(s, one);
        let bchk = b.mul(s, s_m1);
        b.connect(bchk, zero);
        // sel ≤ active: sv·(1 − active) = 0 (no selecting a dummy).
        let one_minus_a = b.sub(one, act[r]); // const lhs → forward
        let sel_outside = b.mul(s, one_minus_a);
        b.connect(sel_outside, zero);
    }
    // sv monotone non-decreasing: sv[r+1] − sv[r] ∈ {0,1}.
    for r in 0..cap - 1 {
        let neg_sr = b.mul(sv[r], neg_one);
        let d = b.add(sv[r + 1], neg_sr);
        let one_minus = b.sub(one, d);
        let prod = b.mul(d, one_minus);
        b.connect(prod, zero);
    }
    // n_active = Σ active[r]; sum_sel = Σ sv[r].
    let mut n_active_e = b.mul(act[0], one);
    for r in 1..cap {
        let t = b.mul(act[r], one);
        n_active_e = b.add(n_active_e, t);
    }
    let mut sum_sel_e = b.mul(sv[0], one);
    for r in 1..cap {
        let t = b.mul(sv[r], one);
        sum_sel_e = b.add(sum_sel_e, t);
    }
    // Σ sel = min(c, #active):
    //   c − Σsel ≥ 0   (range-checked; needs sum_sel as a forward `a`-operand)
    //   (c − Σsel)·(#active − Σsel) = 0   (one bound is tight)
    // Combined with sel ≤ active (⇒ Σsel ≤ #active), this pins Σsel = min.
    let neg_sum_sel = b.mul(sum_sel_e, neg_one);
    let c_minus_sel = b.add(c_pi, neg_sum_sel); // c − Σsel  (forward)
    let _ = b.add_range_bits::<Val>(c_minus_sel, DIFF_BITS).expect("c − Σsel ≥ 0");
    let act_minus_sel = b.add(n_active_e, neg_sum_sel); // #active − Σsel (forward)
    let prod = b.mul(c_minus_sel, act_minus_sel);
    b.connect(prod, zero);

    // ── released mass = Σ sel·count ──
    let mut mass_e = b.mul(cnt[0], sv[0]); // count copy FIRST
    for r in 1..cap {
        let t = b.mul(cnt[r], sv[r]);
        mass_e = b.add(mass_e, t);
    }
    // Decompose the mass to base coeffs so the release range checks are sound,
    // pinning the high coeffs to zero (single-limb mass at prototype scale).
    let massc = b.decompose_ext_to_base_coeffs::<Val>(mass_e).expect("decompose mass");
    let mass_b = massc[0];
    b.connect(massc[1], zero);
    b.connect(massc[2], zero);
    b.connect(massc[3], zero);

    // ── Check 6: release policy → answer ──
    match release {
        ReleasePolicy::Identity => {
            // mass coeff FIRST (LHS) so this decompose output gets a bus creator.
            let released = b.mul(mass_b, one);
            b.connect(released, answer_pi);
        }
        ReleasePolicy::Threshold(t) => {
            let fl = flag.unwrap();
            let mass_v = b.mul(mass_b, one);
            let neg_theta = b.alloc_const(-Challenge::from_u64(t), "neg_theta");
            let theta_m1 = b.alloc_const(Challenge::from_u64(t) - Challenge::ONE, "theta_m1");
            // fl ∈ {0,1}: fl·(fl−1) = 0. `sub(fl, one)` keeps fl as a fresh,
            // undefined private input → fl gets its bus creator here.
            let fm1 = b.sub(fl, one);
            let bchk = b.mul(fl, fm1);
            b.connect(bchk, zero);
            // chosen = fl·(mass−θ) + (1−fl)·(θ−1−mass) ≥ 0  ⇔  fl = [mass ≥ θ].
            let mass_minus_t = b.add(mass_v, neg_theta); // mass − θ (forward)
            let neg_mass = b.mul(mass_v, neg_one); // −mass
            let t_minus_mass_m1 = b.add(neg_mass, theta_m1); // (θ−1) − mass (forward)
            let nf = b.sub(one, fl); // 1 − fl (const lhs → forward)
            let a = b.mul(fl, mass_minus_t);
            let nft = b.mul(nf, t_minus_mass_m1);
            let chosen = b.add(a, nft);
            let _ = b.add_range_bits::<Val>(chosen, DIFF_BITS).expect("chosen >= 0");
            let released = b.mul(fl, mass_v);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build ss decode circuit");

    // ─── Pack public + private values ────────────────────────────────────
    let commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit.0));
    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&commit_packed);
    public_inputs.push(Challenge::from_u64(c as u64));
    public_inputs.push(Challenge::from_u64(answer));

    let mut private_inputs: Vec<Challenge> = pack_cells(&state);
    // sel
    for r in 0..cap {
        private_inputs.push(if sel_native[r] == 1 { Challenge::ONE } else { Challenge::ZERO });
    }
    // key_inv[r]: inverse of (key_lo[r+1] − key_lo[r]) when non-zero, else 0.
    for r in 0..cap.saturating_sub(1) {
        let lo = |k: u64| (k & 0xFFFF_FFFF) as u32;
        let d = Challenge::from_u64(lo(state.rows[r + 1].key) as u64)
            - Challenge::from_u64(lo(state.rows[r].key) as u64);
        private_inputs.push(if d == Challenge::ZERO { Challenge::ZERO } else { d.inverse() });
    }
    // flag (threshold only)
    if flag.is_some() {
        let t = if let ReleasePolicy::Threshold(t) = release { t } else { 0 };
        private_inputs.push(if mass >= t { Challenge::ONE } else { Challenge::ZERO });
    }

    // ─── Run + prove ─────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run ss decode circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false), range_preprocessor::<Val>()];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (ss decode)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_range_table::<4>();
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove ss decode");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify ss decode");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    DecodeProof { output: RecursionOutput(proof, Rc::new(circuit_prover_data)), answer }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::ss_final_full::{SsFullParams, apply_batch_ss_full, SsFullState, SsFullUpdate};

    /// Build a SpaceSaving state from a few updates via the native top-`s`
    /// pipeline. Distinct keys 101..104 with weights 1..4 (capacity 4, batch 4),
    /// so the stored rows are `[dummy?... , w=1, w=2, w=3, w=4]` ascending.
    fn state() -> SsFullState {
        let params = SsFullParams { capacity: 4, batch: 4 };
        let s0 = SsFullState::empty(params);
        let batch = vec![
            SsFullUpdate::real(101, 1),
            SsFullUpdate::real(102, 2),
            SsFullUpdate::real(103, 3),
            SsFullUpdate::real(104, 4),
        ];
        apply_batch_ss_full(&s0, &batch).0
    }

    /// Native top-`c` mass: sum of the `min(c, #active)` highest counts.
    fn native_topc_mass(st: &SsFullState, c: usize) -> u64 {
        let mut counts: Vec<u64> = st.rows.iter().filter(|r| r.active == 1).map(|r| r.count as u64).collect();
        counts.sort_unstable_by(|a, b| b.cmp(a)); // descending
        counts.into_iter().take(c).sum()
    }

    #[test]
    fn ss_decode_topc_all() {
        // c ≥ #active ⇒ releases the full mass (1+2+3+4 = 10).
        let st = state();
        assert_eq!(st.active_count(), 4);
        let native = native_topc_mass(&st, 4);
        assert_eq!(native, 10);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 4, release: ReleasePolicy::Identity },
            st,
            4,
        );
        assert_eq!(p.answer, native, "top-c mass matches native");
    }

    #[test]
    fn ss_decode_topc_larger_than_active() {
        // c > #active ⇒ k = #active, still the full mass.
        let st = state();
        let native = native_topc_mass(&st, 10);
        assert_eq!(native, 10);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 10, release: ReleasePolicy::Identity },
            st,
            10,
        );
        assert_eq!(p.answer, native);
    }

    #[test]
    fn ss_decode_top2() {
        // Top-2 heavy hitters: weights 4 + 3 = 7.
        let st = state();
        let native = native_topc_mass(&st, 2);
        assert_eq!(native, 7);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Identity },
            st,
            2,
        );
        assert_eq!(p.answer, native, "top-2 mass = 4 + 3");
    }

    #[test]
    fn ss_decode_top1() {
        // Top-1 heavy hitter: weight 4.
        let st = state();
        let native = native_topc_mass(&st, 1);
        assert_eq!(native, 4);
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 1, release: ReleasePolicy::Identity },
            st,
            1,
        );
        assert_eq!(p.answer, native, "top-1 mass = 4");
    }

    #[test]
    fn ss_decode_threshold_suppresses() {
        // Top-1 mass = 4 < θ = 1000 ⇒ suppressed to 0.
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 1, release: ReleasePolicy::Threshold(1000) },
            state(),
            1,
        );
        assert_eq!(p.answer, 0, "mass below θ ⇒ released 0");
    }

    #[test]
    fn ss_decode_threshold_passes() {
        // Top-2 mass = 7 ≥ θ = 5 ⇒ released raw.
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(5) },
            state(),
            2,
        );
        assert_eq!(p.answer, 7, "mass 7 ≥ θ=5 ⇒ released raw");
    }

    /// Boundary: mass == θ must be released (the `≥` semantics).
    #[test]
    fn ss_decode_threshold_boundary() {
        let p = prove_ss_decode(
            SsDecodeParams { capacity: 4, c: 2, release: ReleasePolicy::Threshold(7) },
            state(),
            2,
        );
        assert_eq!(p.answer, 7, "mass 7 == θ=7 ⇒ released raw");
    }

    /// Soundness: a tampered answer public input must be rejected by the
    /// in-circuit relation (running the circuit fails the constraints).
    #[test]
    fn ss_decode_rejects_wrong_answer() {
        let st = state();
        let cap = 4usize;
        let c = 2usize;
        let commit = commit_ss_state(&st);
        let (sel_native, _mass) = native_select(&st, c);

        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = CircuitBuilder::<Challenge>::new();
            b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
                generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
                default_babybear_poseidon2_16(),
            );
            b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
            b.enable_range(generate_range_trace::<Val, Challenge>);
            let commit_pis: [ExprId; DIGEST_PACKING] =
                std::array::from_fn(|_| b.alloc_public_input("c"));
            let c_pi = b.alloc_public_input("c");
            let answer_pi = b.alloc_public_input("answer");
            let one = b.alloc_const(Challenge::ONE, "one");
            let zero = b.alloc_const(Challenge::ZERO, "zero");
            let neg_one = b.alloc_const(-Challenge::ONE, "neg_one");
            let cells_packed: Vec<ExprId> =
                (0..cap).map(|_| b.alloc_private_input("cell")).collect();
            let sel: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input("sel")).collect();
            let key_inv: Vec<ExprId> =
                (0..cap - 1).map(|_| b.alloc_private_input("key_inv")).collect();
            let digest = b
                .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &cells_packed, true)
                .unwrap();
            for i in 0..DIGEST_PACKING {
                b.connect(digest[i], commit_pis[i]);
            }
            let fields: Vec<Vec<ExprId>> = cells_packed
                .iter()
                .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
                .collect();
            for r in 0..cap {
                let key_hi_l = b.mul(fields[r][1], one);
                b.connect(key_hi_l, zero);
            }
            let klo: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][0], one)).collect();
            let cnt: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][2], one)).collect();
            let act: Vec<ExprId> = (0..cap).map(|r| b.mul(fields[r][3], one)).collect();
            for r in 0..cap {
                let a = act[r];
                let a_m1 = b.sub(a, one);
                let bchk = b.mul(a, a_m1);
                b.connect(bchk, zero);
            }
            for r in 0..cap - 1 {
                let neg_ar = b.mul(act[r], neg_one);
                let d = b.add(act[r + 1], neg_ar);
                let one_minus = b.sub(one, d);
                let prod = b.mul(d, one_minus);
                b.connect(prod, zero);
            }
            for r in 0..cap - 1 {
                let neg_cr = b.mul(cnt[r], neg_one);
                let cdiff = b.add(cnt[r + 1], neg_cr);
                let _ = b.add_range_bits::<Val>(cdiff, DIFF_BITS).unwrap();
            }
            for r in 0..cap - 1 {
                let neg_klo = b.mul(klo[r], neg_one);
                let kdiff = b.add(klo[r + 1], neg_klo);
                let kd_inv = b.mul(kdiff, key_inv[r]);
                let one_minus = b.sub(one, kd_inv);
                let both_active = b.mul(act[r], act[r + 1]);
                let dchk = b.mul(both_active, one_minus);
                b.connect(dchk, zero);
            }
            let sv: Vec<ExprId> = (0..cap).map(|r| b.mul(sel[r], one)).collect();
            for r in 0..cap {
                let s = sv[r];
                let s_m1 = b.sub(s, one);
                let bchk = b.mul(s, s_m1);
                b.connect(bchk, zero);
                let one_minus_a = b.sub(one, act[r]);
                let sel_outside = b.mul(s, one_minus_a);
                b.connect(sel_outside, zero);
            }
            for r in 0..cap - 1 {
                let neg_sr = b.mul(sv[r], neg_one);
                let d = b.add(sv[r + 1], neg_sr);
                let one_minus = b.sub(one, d);
                let prod = b.mul(d, one_minus);
                b.connect(prod, zero);
            }
            let mut n_active_e = b.mul(act[0], one);
            for r in 1..cap {
                let t = b.mul(act[r], one);
                n_active_e = b.add(n_active_e, t);
            }
            let mut sum_sel_e = b.mul(sv[0], one);
            for r in 1..cap {
                let t = b.mul(sv[r], one);
                sum_sel_e = b.add(sum_sel_e, t);
            }
            let neg_sum_sel = b.mul(sum_sel_e, neg_one);
            let c_minus_sel = b.add(c_pi, neg_sum_sel);
            let _ = b.add_range_bits::<Val>(c_minus_sel, DIFF_BITS).unwrap();
            let act_minus_sel = b.add(n_active_e, neg_sum_sel);
            let prod = b.mul(c_minus_sel, act_minus_sel);
            b.connect(prod, zero);
            let mut mass_e = b.mul(cnt[0], sv[0]);
            for r in 1..cap {
                let t = b.mul(cnt[r], sv[r]);
                mass_e = b.add(mass_e, t);
            }
            let massc = b.decompose_ext_to_base_coeffs::<Val>(mass_e).unwrap();
            let mass_b = massc[0];
            b.connect(massc[1], zero);
            b.connect(massc[2], zero);
            b.connect(massc[3], zero);
            let released = b.mul(mass_b, one);
            b.connect(released, answer_pi);
            let circuit = b.build().unwrap();

            let commit_packed =
                pack_commit_to_challenge(&crate::commitment::CountMinCommit(commit.0));
            let mut public_inputs: Vec<Challenge> = Vec::new();
            public_inputs.extend_from_slice(&commit_packed);
            public_inputs.push(Challenge::from_u64(c as u64));
            public_inputs.push(Challenge::from_u64(999)); // WRONG answer (true is 7)
            let mut private_inputs: Vec<Challenge> = pack_cells(&st);
            for r in 0..cap {
                private_inputs
                    .push(if sel_native[r] == 1 { Challenge::ONE } else { Challenge::ZERO });
            }
            for r in 0..cap - 1 {
                let lo = |k: u64| (k & 0xFFFF_FFFF) as u32;
                let d = Challenge::from_u64(lo(st.rows[r + 1].key) as u64)
                    - Challenge::from_u64(lo(st.rows[r].key) as u64);
                private_inputs
                    .push(if d == Challenge::ZERO { Challenge::ZERO } else { d.inverse() });
            }
            let mut runner = circuit.runner();
            runner.set_public_inputs(&public_inputs).unwrap();
            runner.set_private_inputs(&private_inputs).unwrap();
            runner.run().expect("run must fail on wrong answer");
        }));
        assert!(bad.is_err(), "wrong answer must be rejected by the relation");
    }
}
