//! **Complete HyperLogLog update circuit** (paper Appendix F, Pattern A
//! max) — the optimized counterpart to the [`crate::sketch::hll_final`]
//! baseline, mirroring how [`crate::sketch::gk_final_full`] completes
//! [`crate::sketch::gk_final`].
//!
//! Where `hll_final` only certified the Poseidon2 commits + active flags +
//! per-register monotonicity (Steps 2–5 deferred), this module enforces
//! the distinctive HLL update semantics in-circuit:
//!
//! 1. **Bind** state arrays + batch to their commitments (Poseidon2).
//! 2. **Generate register contributions** — each active batch record's key
//!    is hashed in-circuit (`add_hash_slice`), and the register index is
//!    routed as `reg = digest mod m` (bottom `b` bits of the first digest
//!    limb). This is the anti-forgery property that matters most: the
//!    prover **cannot choose which register** a key lands in.
//! 3.–4. **Group by register + aggregate by max** and **5. apply the
//!    sparse max-patch** — realized together as a register-wise scatter:
//!    one-hot selectors route each contribution to its register, a running
//!    `max` folds the contributions, and the new register is
//!    `N[b] = max(O[b], batch_max[b])`. Every `max` is a gated
//!    range-checked comparator. So the new state is verified to be the
//!    canonical HLL max-patch — closing the baseline's "any monotone
//!    replacement" soundness gap.
//! 6. **Metadata** via `params.validate()`.
//!
//! ### ρ is derived and bound in-circuit (no free-witness gap)
//!
//! The rank `ρ_j` is **re-derived from the hash digest inside the
//! circuit** and bound to the prover's witness (Stage 2b), so a malicious
//! prover can neither pick the register (routing is verified) nor inflate
//! ρ (it equals `1 + trailing_zeros(digest[1])` by constraint). We use
//! **trailing zeros** rather than the textbook leading-ones because it's a
//! clean running-product over the digest bits
//! (`a_k = ∏_{i≤k}(1−bit_i)`, `ρ = 1 + Σ_k a_k`) — and it is an equally
//! valid hash-derived geometric rank (`P(ρ=k) ≈ 2^{-k}`), so HLL's
//! estimator is unchanged. This makes HLL as sound as the SS/GK full
//! circuits (no documented honest-prover gap on the update relation).
//!
//! ### Cost note
//!
//! The register-wise scatter uses `O(m · batch)` one-hot selectors +
//! `max` gates (the unoptimized but fully-verifying form). The paper's
//! Step 3–4 sort-then-segment-max (and Opt A "hash once per distinct key")
//! would cut this to `O((m+batch)·log)` and `O(distinct)` hashes; that's
//! the same sort-group lever count-min's `v9h` uses. Kept simple here
//! (small `m`); documented as the optimization path.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4, poseidon2_preprocessor,
        recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};

const LOG_FINAL_POLY_LEN: usize = 6;

/// Bit-width for the `max` gated-diff range checks. `ρ` and register
/// values live in `[0, lr_max] ⊂ [0, 64)`, so an 8-bit window covers every
/// difference; a "negative" diff wraps past `2^8` and overflows the check.
const DIFF_BITS: usize = 8;

// ─── Types ─────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllFullParams {
    /// Register-index bits; `m = 2^b` registers.
    pub b: usize,
    pub batch: usize,
}

impl HllFullParams {
    pub fn m(&self) -> usize {
        1usize << self.b
    }
    pub fn lr_max(&self) -> u32 {
        (64 - self.b + 1) as u32
    }
    pub fn validate(&self) {
        // b∈[2,16] matches the merkle leaf's range so the flat-vs-sparse
        // comparison can run head-to-head at the same sketch sizes (up to
        // m=2^16). The flat circuit is *logically* correct for any b≤~30
        // (routing = digest mod 2^b; ρ is derived over 31 bits so it stays in
        // [1,32] independent of b); the practical ceiling is the O(m·batch)
        // trace vs BabyBear's 2^27 FRI domain — points that exceed it surface as
        // a capacity panic, which the e1 runner catches via `bench_guarded`.
        assert!(self.b >= 2 && self.b <= 16, "b in [2,16]; got {}", self.b);
        assert!(self.batch >= 2 && self.batch % 2 == 0, "batch even ≥ 2");
        // Flat O(m·batch) selector budget — the dominant cost. Each cell expands
        // to ~32 trace rows, so the trace hits BabyBear's 2^27 FRI domain near
        // m·batch ≈ 4.2M, and RAM grows fast (m·batch=262k ≈ 35 GB measured).
        // The default lets the full b≤14 sweep through; raise it on a bigger box,
        // lower it to skip sooner on a small one. Mirrors Count-Min's
        // COUNTMIN_MAX_SEL_CELLS; the e1 runner turns this panic into a
        // `too_large` skip via `bench_guarded`.
        let sel_cells = self.m().saturating_mul(self.batch);
        let max_sel = std::env::var("HLL_FULL_MAX_SEL_CELLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(4_194_304);
        assert!(
            sel_cells <= max_sel,
            "HLL selector budget exceeded: m·batch = {sel_cells} > {max_sel} (b={}, batch={}). \
             Use the sparse merkle variant, or raise HLL_FULL_MAX_SEL_CELLS (heavy RAM/time).",
            self.b, self.batch
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HllFullState {
    pub registers: Vec<u32>,
    pub params: HllFullParams,
}

impl HllFullState {
    pub fn empty(params: HllFullParams) -> Self {
        Self { registers: vec![0u32; params.m()], params }
    }
    pub fn touched(&self) -> usize {
        self.registers.iter().filter(|&&r| r > 0).count()
    }
    pub fn estimate(&self) -> f64 {
        let m = self.params.m() as f64;
        let alpha = match self.params.m() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let z: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        alpha * m * m / z
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct HllFullUpdate {
    pub key: u64,
    pub active: u32,
}

impl HllFullUpdate {
    pub const fn real(key: u64) -> Self {
        Self { key, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, active: 0 }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllFullStateCommit(pub [Val; 8]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HllFullBatchCommit(pub [Val; 8]);

pub struct HllFullLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: HllFullStateCommit,
    pub final_: HllFullStateCommit,
    pub batch_commit: HllFullBatchCommit,
    pub params: HllFullParams,
}

pub struct HllFullProof {
    pub proof: HllFullLeafProof,
    pub final_state: HllFullState,
}

impl HllFullProof {
    pub fn estimate(&self) -> f64 {
        self.final_state.estimate()
    }
}

// ─── Hash family — Poseidon2 PRF (native; matches the in-circuit routing) ──

/// Number of bits `decompose_to_bits` unpacks a BabyBear value into; the
/// ρ trailing-zeros window matches this exactly (native ↔ in-circuit).
fn val_bits() -> usize {
    <Val as Field>::bits()
}

/// Hash the **exact 4-tuple the circuit hashes** — `(key_lo, key_hi,
/// active, 0)` (= the committed `batch_packed` row) — and return
/// `(register, ρ, digest)`.
///
/// - Register = `digest[0] mod m` (the in-circuit `bottom-b-bits` routing
///   reconstructs it).
/// - **ρ = 1 + trailing_zeros(digest[1])** over the `val_bits()`-bit
///   window. This is a hash-derived geometric rank (`P(ρ=k) ≈ 2^{-k}`,
///   exactly what HLL needs) — but unlike a leading-ones priority encoder,
///   trailing zeros are a clean running-product over the bits, so the
///   circuit **re-derives and binds ρ** (Stage 2b) instead of trusting a
///   free witness. `ρ ∈ [1, val_bits()+1] ⊂ [1, 32]`, well under `lr_max`,
///   so no clamp is needed.
///
/// Including `active` in the hashed input keeps the native and in-circuit
/// hashes identical (a dummy's contribution is gated to 0 downstream).
pub fn hash_record(key: u64, active: u32, params: HllFullParams) -> (usize, u32, [Val; 8]) {
    let hasher = MyHash::new(make_perm());
    let (lo, hi) = ((key & 0xFFFF_FFFF) as u32, (key >> 32) as u32);
    let input = [Val::from_u32(lo), Val::from_u32(hi), Val::from_u32(active), Val::ZERO];
    let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
    let m = params.m() as u64;
    let idx = (<Val as p3_field::PrimeField64>::as_canonical_u64(&digest[0]) % m) as usize;
    // Trailing-zero count of digest[1] over the val_bits() window (matches
    // the in-circuit running-product gadget exactly).
    let tail = <Val as p3_field::PrimeField64>::as_canonical_u64(&digest[1]);
    let nbits = val_bits() as u32;
    let mut tz = 0u32;
    while tz < nbits && (tail >> tz) & 1 == 0 {
        tz += 1;
    }
    let rho = tz + 1;
    (idx, rho, digest)
}

pub fn apply_update(state: &mut HllFullState, u: &HllFullUpdate) {
    if u.active == 0 {
        return;
    }
    let (idx, rho, _) = hash_record(u.key, 1, state.params);
    if rho > state.registers[idx] {
        state.registers[idx] = rho;
    }
}

pub fn apply_batch(state: &HllFullState, batch: &[HllFullUpdate]) -> HllFullState {
    let mut s = state.clone();
    for u in batch {
        apply_update(&mut s, u);
    }
    s
}

// ─── Native packing ────────────────────────────────────────────────────────

fn pack_state_to_challenge(state: &HllFullState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    state
        .registers
        .iter()
        .map(|&r| {
            let coeffs = [Val::from_u32(r), Val::ZERO, Val::ZERO, Val::ONE];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn pack_batch_to_challenge(batch: &[HllFullUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    batch
        .iter()
        .map(|u| {
            let (lo, hi) = ((u.key & 0xFFFF_FFFF) as u32, (u.key >> 32) as u32);
            let coeffs = [Val::from_u32(lo), Val::from_u32(hi), Val::from_u32(u.active), Val::ZERO];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn flat_state_vals(state: &HllFullState) -> Vec<Val> {
    state
        .registers
        .iter()
        .flat_map(|&r| [Val::from_u32(r), Val::ZERO, Val::ZERO, Val::ONE])
        .collect()
}

fn flat_batch_vals(batch: &[HllFullUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            let (lo, hi) = ((u.key & 0xFFFF_FFFF) as u32, (u.key >> 32) as u32);
            [Val::from_u32(lo), Val::from_u32(hi), Val::from_u32(u.active), Val::ZERO]
        })
        .collect()
}

pub fn commit_hll_state(state: &HllFullState) -> HllFullStateCommit {
    let hasher = MyHash::new(make_perm());
    HllFullStateCommit(hasher.hash_iter(flat_state_vals(state)))
}

pub fn commit_hll_batch(batch: &[HllFullUpdate]) -> HllFullBatchCommit {
    let hasher = MyHash::new(make_perm());
    HllFullBatchCommit(hasher.hash_iter(flat_batch_vals(batch)))
}

// ─── Test-only soundness hook ──────────────────────────────────────────────
// When set, the prover bumps the new state's first register so it no longer
// equals the verified max-patch — exercises whether the max + connect
// constraints reject it.
#[cfg(test)]
thread_local! {
    static TAMPER_FINAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    // When set, the prover inflates the first record's ρ witness — must be
    // rejected by the in-circuit ρ-derivation binding (Stage 2b).
    static TAMPER_RHO: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// Benchmark hook (NOT test-gated — used by Experiment E9): when set, the prover
// performs a SECOND Poseidon2 hash per record (its output fully consumed),
// modelling the paper's pre-optimisation "two separate hashes" HLL baseline.
// The default single wide-output hash (one call, two lanes c0[0]=index,
// c0[1]=ρ) is the §App-F optimisation; the prove-time delta between the two is
// the measured saving. See [`prove_hll_full_two_hashes`].
thread_local! {
    static HLL_TWO_HASHES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ─── Prover ────────────────────────────────────────────────────────────────

pub fn prove_hll_full(
    params: HllFullParams,
    initial_state: HllFullState,
    batch: Vec<HllFullUpdate>,
) -> HllFullLeafProof {
    prove_hll_full_inner(params, initial_state, batch, false)
}

/// Like [`prove_hll_full`] but also surfaces the `(initial, final)` boundary via
/// the Expose NPO, for the in-circuit boundary-bound forest. Baselines stable:
/// the unexposed entry point is unchanged.
pub fn prove_hll_full_exposed(
    params: HllFullParams,
    initial_state: HllFullState,
    batch: Vec<HllFullUpdate>,
) -> HllFullLeafProof {
    prove_hll_full_inner(params, initial_state, batch, true)
}

fn prove_hll_full_inner(
    params: HllFullParams,
    initial_state: HllFullState,
    batch: Vec<HllFullUpdate>,
    expose_boundary: bool,
) -> HllFullLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);

    let m = params.m();
    let mb = params.batch;
    let blog2 = params.b;

    // ─── Native side ────────────────────────────────────────────────────
    let final_state = apply_batch(&initial_state, &batch);
    let initial_commit = commit_hll_state(&initial_state);
    let final_commit = commit_hll_state(&final_state);
    let batch_commit = commit_hll_batch(&batch);

    // Per-record (register, ρ) and the scatter witnesses.
    let mut rec_reg = vec![0usize; mb];
    let mut rec_rho = vec![0u32; mb];
    let mut rec_active = vec![0u32; mb];
    for (j, u) in batch.iter().enumerate() {
        // Hash the exact committed 4-tuple (key, key, active, 0).
        let (idx, rho, _) = hash_record(u.key, u.active, params);
        rec_reg[j] = idx;
        // ρ is the hash-derived rank for EVERY record (the circuit binds it
        // in Stage 2b regardless of active); the `active` gating happens on
        // the *contribution*, not on ρ itself.
        rec_rho[j] = rho;
        rec_active[j] = u.active;
    }

    // Per-register running max over routed contributions + the final
    // patch max. We record the compare bits so the circuit can replay.
    // contribution[b][j] = (reg==b && active) ? ρ : 0.
    // batchmax[b] = running max over j; new[b] = max(old[b], batchmax[b]).
    let mut sel = vec![vec![0u32; mb]; m]; // sel[b][j]
    let mut ge_bm = vec![vec![0u32; mb]; m]; // running-max compare bits
    let mut ge_patch = vec![0u32; m];
    let mut batchmax = vec![0u32; m];
    for b_reg in 0..m {
        let mut acc = 0u32;
        for j in 0..mb {
            sel[b_reg][j] = if rec_reg[j] == b_reg { 1 } else { 0 };
            // Contribution is gated by `active`: a dummy routes to its
            // register but contributes 0 (its ρ is bound but unused).
            let contribution = if rec_reg[j] == b_reg && rec_active[j] == 1 {
                rec_rho[j]
            } else {
                0
            };
            // max(acc, contribution): ge = [contribution >= acc].
            let ge = if contribution >= acc { 1 } else { 0 };
            ge_bm[b_reg][j] = ge;
            acc = acc.max(contribution);
        }
        batchmax[b_reg] = acc;
        let o = initial_state.registers[b_reg];
        ge_patch[b_reg] = if batchmax[b_reg] >= o { 1 } else { 0 };
    }
    // Sanity: new = max(old, batchmax).
    for b_reg in 0..m {
        let expect = initial_state.registers[b_reg].max(batchmax[b_reg]);
        debug_assert_eq!(final_state.registers[b_reg], expect);
    }

    // ─── Build circuit ──────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    if expose_boundary {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let init_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    if expose_boundary {
        b.add_expose(&[init_pis[0], init_pis[1], final_pis[0], final_pis[1]])
            .expect("add_expose boundary");
    }
    let batch_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    // pow2 consts for the bottom-b bit reconstruction of the register id.
    let pow2: Vec<ExprId> = (0..blog2)
        .map(|i| b.alloc_const(Challenge::from_u64(1u64 << i), "pow2"))
        .collect();
    // register-index constants 0..m.
    let reg_const: Vec<ExprId> =
        (0..m).map(|i| b.alloc_const(Challenge::from_u64(i as u64), "reg")).collect();

    // Private inputs (alloc order MUST match the packing below):
    //   init, final, batch, h0, h1, rho, sel(b-major), ge_bm(b-major), ge_patch.
    let init_packed: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("init_packed")).collect();
    let final_packed: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("final_packed")).collect();
    let batch_packed: Vec<ExprId> = (0..mb).map(|_| b.alloc_private_input("batch_packed")).collect();
    let h0: Vec<ExprId> = (0..mb).map(|_| b.alloc_private_input("h0")).collect();
    let h1: Vec<ExprId> = (0..mb).map(|_| b.alloc_private_input("h1")).collect();
    let rho: Vec<ExprId> = (0..mb).map(|_| b.alloc_private_input("rho")).collect();
    let sel_w: Vec<ExprId> =
        (0..m * mb).map(|_| b.alloc_private_input("sel")).collect();
    let ge_bm_w: Vec<ExprId> =
        (0..m * mb).map(|_| b.alloc_private_input("ge_bm")).collect();
    let ge_patch_w: Vec<ExprId> =
        (0..m).map(|_| b.alloc_private_input("ge_patch")).collect();

    // ─── Stage 1: commit bindings ───────────────────────────────────────
    let hi = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &init_packed, true).expect("h init");
    for i in 0..DIGEST_PACKING {
        b.connect(hi[i], init_pis[i]);
    }
    let hf = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true).expect("h final");
    for i in 0..DIGEST_PACKING {
        b.connect(hf[i], final_pis[i]);
    }
    let hb = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true).expect("h batch");
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_pis[i]);
    }

    // ─── Stage 2: decompose state + batch ───────────────────────────────
    let init_fields: Vec<Vec<ExprId>> =
        init_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d i")).collect();
    let final_fields: Vec<Vec<ExprId>> =
        final_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d f")).collect();
    let batch_fields: Vec<Vec<ExprId>> =
        batch_packed.iter().map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("d b")).collect();

    let bool_check = |b: &mut CircuitBuilder<Challenge>, a: ExprId| {
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    };

    // State registers carry a forced active=1 in field [3]; batch active in [2].
    for r in 0..m {
        bool_check(&mut b, init_fields[r][3]);
        bool_check(&mut b, final_fields[r][3]);
        // registers' fields [1],[2] must be zero (canonical packing).
        b.connect(init_fields[r][1], zero);
        b.connect(init_fields[r][2], zero);
        b.connect(final_fields[r][1], zero);
        b.connect(final_fields[r][2], zero);
    }
    for j in 0..mb {
        bool_check(&mut b, batch_fields[j][2]);
    }

    // ─── Stage 2b: hash each record → register index (in-circuit) ───────
    // reg_idx[j] = bottom-b bits of digest[0] = digest[0] mod m.
    let mut reg_idx: Vec<ExprId> = Vec::with_capacity(mb);
    for j in 0..mb {
        let hashed = b
            .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &[batch_packed[j]], true)
            .expect("hash record key");
        b.connect(hashed[0], h0[j]);
        b.connect(hashed[1], h1[j]);
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0[j]).expect("d h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1[j]).expect("d h1");
        // Route the register from digest limb c0[0].
        let bits = b.decompose_to_bits::<Val>(c0[0], Val::bits()).expect("bits digest0");
        let mut rsum = b.mul(bits[0], pow2[0]);
        for k in 1..blog2 {
            let t = b.mul(bits[k], pow2[k]);
            rsum = b.add(rsum, t);
        }
        reg_idx.push(rsum);

        // ── Derive ρ_j = 1 + trailing_zeros(digest[1]) IN-CIRCUIT and bind
        //    it to the supplied `rho[j]` witness. This closes the soundness
        //    gap where ρ was a free (only range-checked) witness — a
        //    malicious prover could otherwise inflate the cardinality.
        //    `digest[1]` is the SECOND coefficient of the FIRST digest
        //    Challenge, i.e. `c0[1]` (the two output Challenges decompose as
        //    c0=[d0,d1,d2,d3], c1=[d4,d5,d6,d7]).
        //    a_k = ∏_{i≤k}(1−bit_i) = "bits[0..=k] all zero"; tz = Σ_k a_k;
        //    ρ = tz + 1. (bottom-up running product = trailing zeros.)
        let dbits = b.decompose_to_bits::<Val>(c0[1], Val::bits()).expect("bits digest1");
        let nbits = Val::bits();
        let mut acc_zero = b.sub(one, dbits[0]); // a_0 = 1 − bit_0
        let mut tz = acc_zero; // Σ a_k, starts at a_0
        for k in 1..nbits {
            let one_minus_bit = b.sub(one, dbits[k]);
            // a_k = a_{k-1} · (1 − bit_k)   (acc_zero lhs → bus creator)
            acc_zero = b.mul(acc_zero, one_minus_bit);
            tz = b.add(tz, acc_zero);
        }
        let rho_circuit = b.add(tz, one); // ρ = tz + 1
        b.connect(rho[j], rho_circuit);

        // Consume the remaining digest limbs so every hash output is read
        // (WitnessChecks discipline). Used so far: c0[0] (routing), c0[1]
        // (ρ). Remaining: c0[2], c0[3], c1[0..4].
        let _ = b.decompose_to_bits::<Val>(c0[2], Val::bits()).expect("consume c0[2]");
        let _ = b.decompose_to_bits::<Val>(c0[3], Val::bits()).expect("consume c0[3]");
        for k in 0..4 {
            let _ = b.decompose_to_bits::<Val>(c1[k], Val::bits()).expect("consume c1");
        }

        // Wide-output ablation BASELINE (Experiment E9): a SECOND Poseidon2 hash
        // per record, output fully consumed — the pre-optimisation "two separate
        // hashes" cost. The default path skips this (single wide hash above).
        if HLL_TWO_HASHES.with(|c| c.get()) {
            let extra = b
                .add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &[batch_packed[j]], true)
                .expect("baseline second hash");
            let e0 = b.decompose_ext_to_base_coeffs::<Val>(extra[0]).expect("d e0");
            let e1c = b.decompose_ext_to_base_coeffs::<Val>(extra[1]).expect("d e1");
            for k in 0..4 {
                let _ = b.decompose_to_bits::<Val>(e0[k], Val::bits()).expect("consume e0");
                let _ = b.decompose_to_bits::<Val>(e1c[k], Val::bits()).expect("consume e1");
            }
        }
    }

    // ─── Stage 3–5: register-wise max-patch via one-hot scatter ─────────
    // gated_max(x, y, ge) = x + ge·(y−x), with ge∈{0,1} and the gated
    // diffs range-checked so ge correctly selects the larger.
    let gated_max =
        |b: &mut CircuitBuilder<Challenge>, x: ExprId, y: ExprId, ge: ExprId| -> ExprId {
            let gem1 = b.sub(ge, one);
            let bp = b.mul(ge, gem1);
            b.connect(bp, zero);
            let y_minus_x = b.sub(y, x);
            let x_minus_y = b.sub(x, y);
            // ge·(y−x) ≥ 0  (ge lhs → bus creator)
            let g1 = b.mul(ge, y_minus_x);
            let _ = b.decompose_to_bits::<Val>(g1, DIFF_BITS).expect("max diff hi");
            // (1−ge)·(x−y) ≥ 0
            let omg = b.sub(one, ge);
            let g2 = b.mul(omg, x_minus_y);
            let _ = b.decompose_to_bits::<Val>(g2, DIFF_BITS).expect("max diff lo");
            b.add(x, g1)
        };

    for b_reg in 0..m {
        // batchmax via running max over routed contributions.
        let mut acc = zero;
        for j in 0..mb {
            let s = sel_w[b_reg * mb + j];
            // sel ∈ {0,1}
            bool_check(&mut b, s);
            // one-hot routing: sel·(reg_idx[j] − b) = 0.
            let diff = b.sub(reg_idx[j], reg_const[b_reg]);
            let route = b.mul(s, diff);
            b.connect(route, zero);
            // contribution = sel · ρ · active  (sel lhs → creator-friendly).
            let sa = b.mul(s, batch_fields[j][2]);
            let contribution = b.mul(sa, rho[j]);
            let ge = ge_bm_w[b_reg * mb + j];
            acc = gated_max(&mut b, acc, contribution, ge);
        }
        // new[b] = max(old[b], batchmax[b]).
        let new_b = gated_max(&mut b, init_fields[b_reg][0], acc, ge_patch_w[b_reg]);
        b.connect(final_fields[b_reg][0], new_b);
    }

    // one-hot completeness: Σ_b sel[b][j] = 1 for every record (each key
    // routes to exactly one register).
    for j in 0..mb {
        let mut s = sel_w[j]; // b=0
        for b_reg in 1..m {
            s = b.add(s, sel_w[b_reg * mb + j]);
        }
        b.connect(s, one);
    }

    let circuit = b.build().expect("build hll_full circuit");

    // ─── Pack public + private ──────────────────────────────────────────
    let init_commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(initial_commit.0));
    let final_commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(final_commit.0));
    let batch_commit_packed = pack_commit_to_challenge(&crate::commitment::CountMinCommit(batch_commit.0));

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&init_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);

    // Hash digests (native) over the exact committed 4-tuple, to bind the
    // in-circuit hash outputs.
    let mut h0_vals: Vec<Challenge> = Vec::with_capacity(mb);
    let mut h1_vals: Vec<Challenge> = Vec::with_capacity(mb);
    {
        use p3_field::BasedVectorSpace;
        for u in &batch {
            let (_idx, _rho, digest) = hash_record(u.key, u.active, params);
            h0_vals.push(Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("h0"));
            h1_vals.push(Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("h1"));
        }
    }

    #[allow(unused_mut)]
    let mut final_state_for_pack = final_state.clone();
    #[cfg(test)]
    if TAMPER_FINAL.with(|c| c.get()) {
        final_state_for_pack.registers[0] = final_state_for_pack.registers[0].wrapping_add(1);
    }

    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_state_to_challenge(&initial_state));
    private_inputs.extend_from_slice(&pack_state_to_challenge(&final_state_for_pack));
    private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
    private_inputs.extend_from_slice(&h0_vals);
    private_inputs.extend_from_slice(&h1_vals);
    for (jr, &r) in rec_rho.iter().enumerate() {
        #[allow(unused_mut)]
        let mut v = Challenge::from_u64(r as u64);
        // [test-only] inflate ρ[0] to confirm Stage 2b's in-circuit ρ
        // derivation binds it (and rejects a forged rank).
        #[cfg(test)]
        if jr == 0 && TAMPER_RHO.with(|c| c.get()) {
            v += Challenge::ONE;
        }
        let _ = jr;
        private_inputs.push(v);
    }
    // sel (b-major), ge_bm (b-major), ge_patch.
    for b_reg in 0..m {
        for j in 0..mb {
            private_inputs.push(if sel[b_reg][j] == 1 { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    for b_reg in 0..m {
        for j in 0..mb {
            private_inputs.push(if ge_bm[b_reg][j] == 1 { Challenge::ONE } else { Challenge::ZERO });
        }
    }
    for b_reg in 0..m {
        private_inputs.push(if ge_patch[b_reg] == 1 { Challenge::ONE } else { Challenge::ZERO });
    }

    // ─── Run + prove ────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run hll_full circuit")
    };
    let __witness = __t_w.elapsed(); // witness_gen = trace generation only

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false)];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    if expose_boundary {
        preprocessors.push(expose_preprocessor::<Val>());
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
    }

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (hll_full)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    if expose_boundary {
        prover.register_expose_table::<4>();
    }
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove_all_tables (hll_full)");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify hll_full leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&d| 1u64 << d).sum(),
    });

    let _ = blog2;
    HllFullLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

/// **Wide-output ablation baseline** (Experiment E9 / Appendix F): proves the
/// exact same HLL leaf as [`prove_hll_full`] but with TWO Poseidon2 hashes per
/// record instead of the default single wide-output hash. The proof and final
/// state are identical; only the per-record hash invocation count (and hence
/// prove time) differs, so timing both quantifies the wide-output saving as a
/// **measured** number rather than an analytical 2×.
pub fn prove_hll_full_two_hashes(
    params: HllFullParams,
    initial_state: HllFullState,
    batch: Vec<HllFullUpdate>,
) -> HllFullLeafProof {
    HLL_TWO_HASHES.with(|c| c.set(true));
    let proof = prove_hll_full(params, initial_state, batch);
    HLL_TWO_HASHES.with(|c| c.set(false));
    proof
}

pub fn generate_proof(params: HllFullParams, updates: Vec<HllFullUpdate>) -> HllFullProof {
    params.validate();
    assert_eq!(updates.len(), params.batch);
    let initial_state = HllFullState::empty(params);
    let final_state = apply_batch(&initial_state, &updates);
    let proof = prove_hll_full(params, initial_state, updates);
    HllFullProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_padded_batch(params: HllFullParams, active_count: usize) -> Vec<HllFullUpdate> {
        assert!(active_count <= params.batch);
        let salt = (params.m() * params.batch) as u64;
        (0..params.batch)
            .map(|i| {
                if i < active_count {
                    HllFullUpdate::real((i as u64).wrapping_mul(0x9E37_79B9) ^ salt)
                } else {
                    HllFullUpdate::dummy()
                }
            })
            .collect()
    }

    fn resolve_threads() -> (Option<usize>, String) {
        let n: Option<usize> = std::env::var("V3_SWEEP_THREADS").ok().and_then(|s| s.parse().ok());
        let label = match n {
            Some(k) => format!("V3_SWEEP_THREADS={k}"),
            None => format!("Rayon default pool ({} threads)", rayon::current_num_threads()),
        };
        (n, label)
    }

    fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
        match n {
            None => f(),
            Some(k) => rayon::ThreadPoolBuilder::new()
                .num_threads(k)
                .thread_name(|i| format!("hll-full-bench-{i}"))
                .build()
                .expect("pool")
                .install(f),
        }
    }

    #[test]
    fn hll_full_round_trip() {
        let params = HllFullParams { b: 4, batch: 2 };
        let updates = vec![HllFullUpdate::real(7), HllFullUpdate::real(11)];
        let result = generate_proof(params, updates);
        assert_eq!(commit_hll_state(&result.final_state).0, result.proof.final_.0);
    }

    /// Wide-output ablation (E9): the two-hashes-per-record baseline must
    /// prove (its second hash balances the WitnessChecks bus and self-verifies)
    /// and yield the IDENTICAL final-state commitment as the default single
    /// wide-output hash — i.e. it's a faithful cost baseline, not a different
    /// circuit relation.
    #[test]
    fn hll_full_two_hashes_matches_wide() {
        let params = HllFullParams { b: 4, batch: 4 };
        let updates = vec![
            HllFullUpdate::real(7),
            HllFullUpdate::real(11),
            HllFullUpdate::real(20240101),
            HllFullUpdate::real(99),
        ];
        let wide = prove_hll_full(params, HllFullState::empty(params), updates.clone());
        let two = prove_hll_full_two_hashes(params, HllFullState::empty(params), updates);
        // Same boundary commitments (both prove the same transition).
        assert_eq!(wide.initial.0, two.initial.0);
        assert_eq!(wide.final_.0, two.final_.0);
        assert_eq!(wide.batch_commit.0, two.batch_commit.0);
    }

    /// In-circuit max-patch: two keys landing in distinct registers both
    /// raise their registers; the proof certifies `N = max(O, batch)`.
    #[test]
    fn hll_full_in_circuit_max_patch() {
        let params = HllFullParams { b: 4, batch: 4 };
        let updates = gen_padded_batch(params, 4);
        // Native truth.
        let s0 = HllFullState::empty(params);
        let s1 = apply_batch(&s0, &updates);
        let touched = s1.touched();
        assert!(touched >= 1, "at least one register touched");
        let result = generate_proof(params, updates);
        assert_eq!(commit_hll_state(&result.final_state).0, result.proof.final_.0);
        // Every final register is ≥ initial (max is monotone).
        for (o, n) in s0.registers.iter().zip(result.final_state.registers.iter()) {
            assert!(n >= o);
        }
    }

    /// Idempotence/max: re-applying the same keys to a non-empty state
    /// leaves registers unchanged (max with an equal-or-smaller value), and
    /// the leaf still verifies the max-patch.
    #[test]
    fn hll_full_max_keeps_larger() {
        let params = HllFullParams { b: 4, batch: 2 };
        let updates = vec![HllFullUpdate::real(123), HllFullUpdate::real(123)];
        let s0 = HllFullState::empty(params);
        let s1 = apply_batch(&s0, &updates);
        // Apply the same batch again starting from s1 → no change.
        let s2 = apply_batch(&s1, &updates);
        assert_eq!(s1.registers, s2.registers, "max is idempotent on a settled register");
        // The in-circuit proof over (s1 → s2) verifies the no-op max-patch.
        let leaf = prove_hll_full(params, s1.clone(), updates);
        assert_eq!(commit_hll_state(&s1).0, leaf.final_.0);
    }

    /// Soundness: a tampered new state (one register bumped off the true
    /// max-patch) must be rejected by the max + connect constraints.
    #[test]
    fn hll_full_soundness_rejects_bad_state() {
        let params = HllFullParams { b: 4, batch: 2 };
        let updates = vec![HllFullUpdate::real(7), HllFullUpdate::real(11)];

        TAMPER_FINAL.with(|c| c.set(false));
        let _ok = generate_proof(params, updates.clone());

        TAMPER_FINAL.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates)
        }));
        TAMPER_FINAL.with(|c| c.set(false));
        assert!(bad.is_err(), "tampered final state accepted — max-patch unsound");
    }

    /// Soundness: ρ is bound to the hash digest in-circuit (Stage 2b), so
    /// inflating a record's ρ witness must be rejected. This is the gap
    /// the fix closed — previously ρ was a free, only-range-checked
    /// witness a prover could use to forge the cardinality.
    #[test]
    fn hll_full_rho_binding_rejects_inflated_rho() {
        let params = HllFullParams { b: 4, batch: 2 };
        let updates = vec![HllFullUpdate::real(7), HllFullUpdate::real(11)];

        TAMPER_RHO.with(|c| c.set(false));
        let _ok = generate_proof(params, updates.clone());

        TAMPER_RHO.with(|c| c.set(true));
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_proof(params, updates)
        }));
        TAMPER_RHO.with(|c| c.set(false));
        assert!(bad.is_err(), "inflated ρ accepted — Stage 2b ρ-derivation binding unsound");
    }

    #[test]
    #[ignore]
    fn hll_full_proving_time_with_different_active_counts() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        // Small m to keep the O(m·batch) scatter tractable.
        let params = HllFullParams { b: 6, batch: 32 };
        println!();
        println!("hll_final_full — proving time vs. active-count density");
        println!("  threads: {threads_label}");
        println!("  b={} (m={}), batch={}", params.b, params.m(), params.batch);
        for &active in &[32usize, 16, 8, 4, 1] {
            let updates = gen_padded_batch(params, active);
            let elapsed = with_pool(threads, move || {
                let t = Instant::now();
                let _ = generate_proof(params, updates);
                t.elapsed()
            });
            println!("  active={active:>3} (of {:>3})   prove {elapsed:>10.2?}", params.batch);
        }
    }

    #[test]
    #[ignore]
    fn hll_full_generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = HllFullParams { b: 6, batch: 32 };
        let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("mkdir");
        println!();
        println!("hll_final_full — generate two proofs + store to disk");
        println!("  threads: {threads_label}");
        with_pool(threads, move || {
            let s0 = HllFullState::empty(params);
            let b1 = gen_padded_batch(params, 20);
            let t1 = Instant::now();
            let l1 = prove_hll_full(params, s0.clone(), b1.clone());
            let l1t = t1.elapsed();
            let p1 = postcard::to_allocvec(&l1.output.0).expect("ser p1");
            fs::write(out_dir.join("hll_full_proof1.bin"), &p1).expect("w p1");
            let s1 = apply_batch(&s0, &b1);
            let b2 = gen_padded_batch(params, 12);
            let t2 = Instant::now();
            let l2 = prove_hll_full(params, s1, b2);
            let l2t = t2.elapsed();
            let p2 = postcard::to_allocvec(&l2.output.0).expect("ser p2");
            fs::write(out_dir.join("hll_full_proof2.bin"), &p2).expect("w p2");
            println!("  leaf 1 prove: {l1t:>10.2?}  size {} bytes", p1.len());
            println!("  leaf 2 prove: {l2t:>10.2?}  size {} bytes", p2.len());
            let mut meta = String::new();
            meta.push_str("# hll_final_full proofs — App F max-patch, full pipeline\n");
            meta.push_str("# Certifies: commits; in-circuit register routing (digest mod m);\n");
            meta.push_str("# register-wise max-patch N[b]=max(O[b], max routed rho) via one-hot\n");
            meta.push_str("# scatter + gated-max comparators. rho leading-ones derivation is the\n");
            meta.push_str("# documented honest-prover gap (range-checked, not re-derived).\n");
            fs::write(out_dir.join("hll_full_proofs.meta.txt"), &meta).expect("w meta");
        });
    }
}
