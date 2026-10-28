//! Structural SpaceSaving leaf (baseline): binds the commitments and checks active flags
//! and mass conservation only.

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
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
const ROW_FIELDS: usize = 4;

// ─── Types ───────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SsFinalRow {
    pub key: u64,
    pub count: u32,
    /// 1 if this row holds a real heavy-hitter candidate; 0 if padding.
    pub active: u32,
}

impl SsFinalRow {
    pub const fn real(key: u64, count: u32) -> Self {
        Self { key, count, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, count: 0, active: 0 }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct SsFinalUpdate {
    pub key: u64,
    pub value: u32,
    pub active: u32,
}

impl SsFinalUpdate {
    pub const fn real(key: u64, value: u32) -> Self {
        Self { key, value, active: 1 }
    }
    pub const fn dummy() -> Self {
        Self { key: 0, value: 0, active: 0 }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsFinalParams {
    /// Public capacity of the heavy-hitter summary.
    pub capacity: usize,
    /// Public batch capacity.
    pub batch: usize,
}

impl SsFinalParams {
    pub fn state_packing(&self) -> usize {
        self.capacity
    }

    pub fn batch_packing(&self) -> usize {
        self.batch
    }

    pub fn validate(&self) {
        assert!(self.capacity >= 2, "capacity must be ≥ 2");
        assert!(self.capacity % 2 == 0, "capacity must be even (Poseidon2 alignment)");
        assert!(self.batch >= 1, "batch must be ≥ 1");
        assert!(self.batch % 2 == 0, "batch must be even (Poseidon2 alignment)");
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsFinalState {
    pub rows: Vec<SsFinalRow>,
    pub params: SsFinalParams,
}

impl SsFinalState {
    pub fn empty(params: SsFinalParams) -> Self {
        Self {
            rows: vec![SsFinalRow::dummy(); params.capacity],
            params,
        }
    }

    pub fn active_count(&self) -> usize {
        self.rows.iter().filter(|r| r.active == 1).count()
    }

    pub fn total_mass(&self) -> u64 {
        self.rows
            .iter()
            .filter(|r| r.active == 1)
            .map(|r| r.count as u64)
            .sum()
    }

    /// Point-frequency query: returns the count of the row matching `key`,
    /// or 0 if no active row matches (an over-estimate by SpaceSaving
    /// design — never under-estimates a true heavy hitter).
    pub fn frequency(&self, key: u64) -> u32 {
        self.rows
            .iter()
            .find(|r| r.active == 1 && r.key == key)
            .map(|r| r.count)
            .unwrap_or(0)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsFinalStateCommit(pub [Val; 8]);
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SsFinalBatchCommit(pub [Val; 8]);

pub struct SsFinalLeafProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial: SsFinalStateCommit,
    pub final_: SsFinalStateCommit,
    pub batch_commit: SsFinalBatchCommit,
    pub params: SsFinalParams,
}

pub struct SsFinalProof {
    pub proof: SsFinalLeafProof,
    pub final_state: SsFinalState,
}

impl SsFinalProof {
    pub fn frequency(&self, key: u64) -> u32 {
        self.final_state.frequency(key)
    }
}

// ─── Native helpers ──────────────────────────────────────────────────────

fn pack_state_to_challenge(state: &SsFinalState) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    state
        .rows
        .iter()
        .map(|r| {
            let key_lo = (r.key & 0xFFFF_FFFF) as u32;
            let key_hi = (r.key >> 32) as u32;
            let coeffs = [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(r.count),
                Val::from_u32(r.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn pack_batch_to_challenge(batch: &[SsFinalUpdate]) -> Vec<Challenge> {
    use p3_field::BasedVectorSpace;
    batch
        .iter()
        .map(|u| {
            let key_lo = (u.key & 0xFFFF_FFFF) as u32;
            let key_hi = (u.key >> 32) as u32;
            let coeffs = [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(u.value),
                Val::from_u32(u.active),
            ];
            Challenge::from_basis_coefficients_slice(&coeffs).expect("4 base coeffs")
        })
        .collect()
}

fn flat_state_vals(state: &SsFinalState) -> Vec<Val> {
    state
        .rows
        .iter()
        .flat_map(|r| {
            let key_lo = (r.key & 0xFFFF_FFFF) as u32;
            let key_hi = (r.key >> 32) as u32;
            [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(r.count),
                Val::from_u32(r.active),
            ]
        })
        .collect()
}

fn flat_batch_vals(batch: &[SsFinalUpdate]) -> Vec<Val> {
    batch
        .iter()
        .flat_map(|u| {
            let key_lo = (u.key & 0xFFFF_FFFF) as u32;
            let key_hi = (u.key >> 32) as u32;
            [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(u.value),
                Val::from_u32(u.active),
            ]
        })
        .collect()
}

pub fn commit_ss_state(state: &SsFinalState) -> SsFinalStateCommit {
    let hasher = MyHash::new(make_perm());
    let flat = flat_state_vals(state);
    let digest: [Val; 8] = hasher.hash_iter(flat);
    SsFinalStateCommit(digest)
}

pub fn commit_ss_batch(batch: &[SsFinalUpdate]) -> SsFinalBatchCommit {
    let hasher = MyHash::new(make_perm());
    let flat = flat_batch_vals(batch);
    let digest: [Val; 8] = hasher.hash_iter(flat);
    SsFinalBatchCommit(digest)
}

/// SpaceSaving Misra-Gries update with `value`-weighted increments.
///
/// 1. If `u.active == 0`: no-op (padding row).
/// 2. If a matching active row exists: increment its count by `u.value`.
/// 3. Else if any row has `active = 0`: write `(key, value, 1)` there.
/// 4. Else (full, no match): find the active row with smallest count,
///    overwrite with `(key, min_count + value)` (the canonical
///    SpaceSaving eviction; the discarded row's count becomes the new
///    row's error bound, which we don't track separately here).
pub fn apply_update(state: &mut SsFinalState, u: &SsFinalUpdate) {
    if u.active == 0 {
        return;
    }
    // 2: existing-key increment.
    for r in state.rows.iter_mut() {
        if r.active == 1 && r.key == u.key {
            r.count = r.count.saturating_add(u.value);
            return;
        }
    }
    // 3: free slot.
    if let Some(slot) = state.rows.iter_mut().find(|r| r.active == 0) {
        *slot = SsFinalRow { key: u.key, count: u.value, active: 1 };
        return;
    }
    // 4: evict minimum.
    let (min_idx, _) = state
        .rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.active == 1)
        .min_by_key(|(_, r)| r.count)
        .expect("table is full but no active row?");
    let min_count = state.rows[min_idx].count;
    state.rows[min_idx] = SsFinalRow {
        key: u.key,
        count: min_count.saturating_add(u.value),
        active: 1,
    };
}

// ─── Prover ──────────────────────────────────────────────────────────────

pub fn prove_ss_final(
    params: SsFinalParams,
    initial_state: SsFinalState,
    batch: Vec<SsFinalUpdate>,
) -> SsFinalLeafProof {
    params.validate();
    assert_eq!(initial_state.params, params);
    assert_eq!(batch.len(), params.batch);

    let cap = params.capacity;
    let m = params.batch;
    let state_packing = params.state_packing();
    let batch_packing = params.batch_packing();

    let mut final_state = initial_state.clone();
    for u in &batch {
        apply_update(&mut final_state, u);
    }
    let initial_commit = commit_ss_state(&initial_state);
    let final_commit = commit_ss_state(&final_state);
    let batch_commit = commit_ss_batch(&batch);

    // Sanity (native).
    let init_mass = initial_state.total_mass();
    let batch_mass: u64 = batch
        .iter()
        .map(|u| u.value as u64 * u.active as u64)
        .sum();
    let final_mass = final_state.total_mass();
    assert_eq!(
        final_mass,
        init_mass + batch_mass,
        "native SpaceSaving: mass conservation violated"
    );

    // ─── Build the circuit ──────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

    let init_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "init_commit_lo" } else { "init_commit_hi" })
    });
    let final_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "final_commit_lo" } else { "final_commit_hi" })
    });
    let batch_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");

    let init_packed: Vec<ExprId> = (0..state_packing)
        .map(|_| b.alloc_private_input("init_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..state_packing)
        .map(|_| b.alloc_private_input("final_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..batch_packing)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();

    // ─── Stage 1: Commit bindings ───────────────────────────────────────
    let h_init = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &init_packed, true)
        .expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(h_init[i], init_pis[i]);
    }
    let h_final = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &final_packed, true)
        .expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(h_final[i], final_pis[i]);
    }
    let h_batch = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(h_batch[i], batch_pis[i]);
    }

    // ─── Stage 2: Decompose ─────────────────────────────────────────────
    // State row: (key_lo, key_hi, count, active) — fields 0..4.
    // Batch row: (key_lo, key_hi, value, active) — same layout.
    let init_fields: Vec<Vec<ExprId>> = init_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose init"))
        .collect();
    let final_fields: Vec<Vec<ExprId>> = final_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose final"))
        .collect();
    let batch_fields: Vec<Vec<ExprId>> = batch_packed
        .iter()
        .map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).expect("decompose batch"))
        .collect();

    // ─── Stage 3: Boolean active flags ──────────────────────────────────
    for r in 0..cap {
        let a = init_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);

        let a = final_fields[r][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }
    for j in 0..m {
        let a = batch_fields[j][3];
        let am1 = b.sub(a, one);
        let prod = b.mul(a, am1);
        b.connect(prod, zero);
    }

    // ─── Stage 4: Active-flag monotonicity on the new state ─────────────
    // active[r+1] ≤ active[r]: actives first, padding tail.
    for r in 0..cap - 1 {
        let curr = final_fields[r][3];
        let next = final_fields[r + 1][3];
        let diff = b.sub(curr, next);
        let one_minus_diff = b.sub(one, diff);
        let prod = b.mul(diff, one_minus_diff);
        b.connect(prod, zero);
    }

    // ─── Stage 5: Mass conservation ─────────────────────────────────────
    // Σ(final.count · final.active) = Σ(init.count · init.active)
    //                              + Σ(batch.value · batch.active)
    let mut init_mass_expr = b.mul(init_fields[0][2], init_fields[0][3]);
    for r in 1..cap {
        let term = b.mul(init_fields[r][2], init_fields[r][3]);
        init_mass_expr = b.add(init_mass_expr, term);
    }
    let mut final_mass_expr = b.mul(final_fields[0][2], final_fields[0][3]);
    for r in 1..cap {
        let term = b.mul(final_fields[r][2], final_fields[r][3]);
        final_mass_expr = b.add(final_mass_expr, term);
    }
    let mut batch_mass_expr = b.mul(batch_fields[0][2], batch_fields[0][3]);
    for j in 1..m {
        let term = b.mul(batch_fields[j][2], batch_fields[j][3]);
        batch_mass_expr = b.add(batch_mass_expr, term);
    }
    let init_plus_batch = b.add(init_mass_expr, batch_mass_expr);
    b.connect(final_mass_expr, init_plus_batch);

    let circuit = b.build().expect("build ss_final circuit");

    // ─── Pack inputs ────────────────────────────────────────────────────
    let init_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(initial_commit.0),
    );
    let final_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(final_commit.0),
    );
    let batch_commit_packed = pack_commit_to_challenge(
        &crate::commitment::CountMinCommit(batch_commit.0),
    );

    let mut public_inputs: Vec<Challenge> = Vec::new();
    public_inputs.extend_from_slice(&init_commit_packed);
    public_inputs.extend_from_slice(&final_commit_packed);
    public_inputs.extend_from_slice(&batch_commit_packed);

    let mut private_inputs: Vec<Challenge> = Vec::new();
    private_inputs.extend_from_slice(&pack_state_to_challenge(&initial_state));
    private_inputs.extend_from_slice(&pack_state_to_challenge(&final_state));
    private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));

    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run ss_final circuit")
    };

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (ss_final)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("prove_all_tables (ss_final)");
    prover.verify_all_tables(&proof).expect("self-verify ss_final leaf");

    let _ = ROW_FIELDS; // keep constant for documentation; not used directly

    SsFinalLeafProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial: initial_commit,
        final_: final_commit,
        batch_commit,
        params,
    }
}

pub fn generate_proof(
    params: SsFinalParams,
    updates: Vec<SsFinalUpdate>,
) -> SsFinalProof {
    params.validate();
    assert_eq!(updates.len(), params.batch);
    let initial_state = SsFinalState::empty(params);
    let mut final_state = initial_state.clone();
    for u in &updates {
        apply_update(&mut final_state, u);
    }
    let proof = prove_ss_final(params, initial_state, updates);
    SsFinalProof { proof, final_state }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_padded_batch(params: SsFinalParams, active_count: usize) -> Vec<SsFinalUpdate> {
        assert!(active_count <= params.batch);
        let salt = (params.capacity * params.batch) as u64;
        (0..params.batch)
            .map(|i| {
                if i < active_count {
                    // Cycle through `min(active_count, capacity)` distinct keys
                    // so the in-circuit mass-conservation check exercises both
                    // the "free slot" and "increment existing" branches.
                    let key_idx = (i % params.capacity) as u64;
                    SsFinalUpdate::real(
                        key_idx.wrapping_mul(0x9E37_79B9) ^ salt,
                        1,
                    )
                } else {
                    SsFinalUpdate::dummy()
                }
            })
            .collect()
    }

    fn resolve_threads() -> (Option<usize>, String) {
        let n: Option<usize> = std::env::var("V3_SWEEP_THREADS")
            .ok()
            .and_then(|s| s.parse().ok());
        let label = match n {
            Some(k) => format!("V3_SWEEP_THREADS={k}"),
            None => format!("Rayon default pool ({} threads)", rayon::current_num_threads()),
        };
        (n, label)
    }

    fn with_pool<F: FnOnce() -> T + Send, T: Send>(n: Option<usize>, f: F) -> T {
        match n {
            None => f(),
            Some(k) => {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(k)
                    .thread_name(|i| format!("ss-final-bench-{i}"))
                    .build()
                    .expect("build rayon thread pool");
                pool.install(f)
            }
        }
    }

    #[test]
    fn ss_generate_proof_round_trip() {
        let params = SsFinalParams { capacity: 4, batch: 2 };
        let updates = vec![SsFinalUpdate::real(7, 3), SsFinalUpdate::real(11, 5)];
        let result = generate_proof(params, updates);
        assert_eq!(commit_ss_state(&result.final_state).0, result.proof.final_.0);
        // Two inserts, no eviction → mass = 3 + 5 = 8.
        assert_eq!(result.final_state.total_mass(), 8);
        assert_eq!(result.frequency(7), 3);
        assert_eq!(result.frequency(11), 5);
        assert_eq!(result.frequency(999_999), 0);
    }

    /// **Test 1 — proving time vs. active-count density.**
    #[test]
    #[ignore]
    fn ss_proving_time_with_different_active_counts() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = SsFinalParams { capacity: 32, batch: 100 };

        println!();
        println!("ss_final — proving time vs. active-count density");
        println!("==================================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();

        for &active in &[100usize, 50, 30, 10, 5, 1] {
            let updates = gen_padded_batch(params, active);
            let elapsed = with_pool(threads, move || {
                let t = Instant::now();
                let _ = generate_proof(params, updates);
                t.elapsed()
            });
            println!(
                "  active={:>3} (of {:>3})   prove {:>10.2?}",
                active, params.batch, elapsed
            );
        }
    }

    /// **Test 2 — proving time to merge two leaves.**
    #[test]
    #[ignore]
    fn ss_proving_time_merge_two_leaves() {
        use std::time::Instant;
        let (threads, threads_label) = resolve_threads();
        let params = SsFinalParams { capacity: 32, batch: 100 };

        println!();
        println!("ss_final — merge proving-time check");
        println!("=====================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();

        let (l1_time, l2_time) = with_pool(threads, move || {
            let s0 = SsFinalState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_ss_final(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();

            let mut s1 = s0;
            for u in &b1 {
                apply_update(&mut s1, u);
            }
            assert_eq!(commit_ss_state(&s1).0, l1.final_.0);

            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let _l2 = prove_ss_final(params, s1, b2);
            (l1_time, t2.elapsed())
        });

        println!("  leaf 1 prove:       {l1_time:>10.2?}");
        println!("  leaf 2 prove:       {l2_time:>10.2?}");
        println!("  ────────────────────────────────");
        println!("  total wall-clock:   {:>10.2?}", l1_time + l2_time);
        println!();
        println!("  (Sequential merge via recursive aggregation deferred.)");
    }

    /// **Test 3 — generate two proofs and persist to `src/proofs/`.**
    #[test]
    #[ignore]
    fn ss_generate_and_store_proof() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::Instant;

        let (threads, threads_label) = resolve_threads();
        let params = SsFinalParams { capacity: 32, batch: 100 };

        let crate_root = env!("CARGO_MANIFEST_DIR");
        let out_dir = PathBuf::from(crate_root).join("src/proofs");
        fs::create_dir_all(&out_dir).expect("create src/proofs directory");

        println!();
        println!("ss_final — generate two proofs + store to disk");
        println!("================================================");
        println!("  threads: {threads_label}");
        println!("  capacity={}, batch={}", params.capacity, params.batch);
        println!();

        with_pool(threads, move || {
            let s0 = SsFinalState::empty(params);
            let b1 = gen_padded_batch(params, 60);
            let t1 = Instant::now();
            let l1 = prove_ss_final(params, s0.clone(), b1.clone());
            let l1_time = t1.elapsed();
            let proof1_bytes = postcard::to_allocvec(&l1.output.0).expect("serialize p1");
            let proof1_path = out_dir.join("ss_proof1.bin");
            fs::write(&proof1_path, &proof1_bytes).expect("write p1");
            write_ss_meta(&out_dir.join("ss_proof1.meta.txt"), "ss_proof1.bin", &params, &l1, proof1_bytes.len());

            let mut s1 = s0;
            for u in &b1 { apply_update(&mut s1, u); }
            let b2 = gen_padded_batch(params, 40);
            let t2 = Instant::now();
            let l2 = prove_ss_final(params, s1, b2);
            let l2_time = t2.elapsed();
            let proof2_bytes = postcard::to_allocvec(&l2.output.0).expect("serialize p2");
            let proof2_path = out_dir.join("ss_proof2.bin");
            fs::write(&proof2_path, &proof2_bytes).expect("write p2");
            write_ss_meta(&out_dir.join("ss_proof2.meta.txt"), "ss_proof2.bin", &params, &l2, proof2_bytes.len());

            println!("  leaf 1 prove time:  {l1_time:>10.2?}");
            println!("  proof 1 size:       {:>10} bytes", proof1_bytes.len());
            println!("  leaf 2 prove time:  {l2_time:>10.2?}");
            println!("  proof 2 size:       {:>10} bytes", proof2_bytes.len());
            println!();
            println!("  proofs persisted to: {}", out_dir.display());
        });
    }

    fn write_ss_meta(
        path: &std::path::Path,
        bin: &str,
        params: &SsFinalParams,
        leaf: &SsFinalLeafProof,
        size: usize,
    ) {
        use std::fs;
        let mut meta = String::new();
        meta.push_str("# SpaceSaving final-design proof — sidecar metadata\n");
        meta.push_str(&format!("# Paired with `{bin}`.\n\n"));
        meta.push_str(&format!("params.capacity = {}\n", params.capacity));
        meta.push_str(&format!("params.batch    = {}\n\n", params.batch));
        meta.push_str(&format!("initial_commit  = {:?}\n", leaf.initial.0));
        meta.push_str(&format!("final_commit    = {:?}\n", leaf.final_.0));
        meta.push_str(&format!("batch_commit    = {:?}\n\n", leaf.batch_commit.0));
        meta.push_str(&format!("proof_size_bytes = {size}\n"));
        fs::write(path, &meta).expect("write meta");
    }
}
