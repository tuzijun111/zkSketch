//! **Count-Min `c_merkle` leaf — CERTIFIED distinct-key update + MERKLE
//! sparse-rebind state commitment** (plonky3 / STARK).
//!
//! This is the head-to-head partner of [`super::countmin_merkle`]. Both commit
//! the state with the same per-row **Merkle root** and rebind it with the same
//! `Θ(t_max·d·log w)` sparse update chain — so the COMMITMENT is identical.
//! What differs is the **update method**:
//!
//! - [`super::countmin_merkle`] (the `merkle` variant) is **replay-style**: it
//!   hashes and routes **every one of the `batch` records** individually
//!   (`add_hash_slice` per record), so the in-circuit PRF cost is `Θ(batch·d)`.
//! - This leaf (the `c_merkle` variant) is **certified-style**: it proves the
//!   batch opens from `Com(B_t)`, then routes each `(record, row)` tuple to the
//!   per-row Merkle ops; collisions are re-aggregated at the **cell** level by
//!   the routing, so the per-row final roots equal the additive Count-Min state.
//!
//! Following the updated paper design (zk1.tex §"Pattern A", Steps 1–5), the
//! data-dependent **key-grouping** step is dropped: the PRF runs once per
//! record (`Θ(batch·d)`), and there is no `distinct_bound` compaction. The
//! batch-binding stage is lifted from [`super::countmin_final`]; the rebind
//! (op routing, `climb_merkle_path`, per-row root chain) is reused from
//! [`super::countmin_merkle`].
//!
//! ## Where the two pipelines meet (the seam)
//!
//! The PRF yields, per record `k` and row `i`, the cell position
//! `pos_i[k] = Poseidon2(key_k)[i] mod w` and the record value `value_k`.
//! These `(row, position, value)` tuples are **routed** to the per-row Merkle
//! ops exactly as the `merkle` leaf routes its records: a one-hot selector
//! sends each `(i, k)` to the op at `pos_i[k]`, the op increment is
//! `Σ_k sel·value_k`, and the op is rebound through the Merkle update chain.
//! Routing re-aggregates collisions at the **cell** level, so the per-row roots
//! are correct regardless of duplicate keys.
//!
//! ## Soundness posture
//!
//! Identical to [`super::countmin_final`] for the update relation (same
//! per-record → group-by-counter shape) and to [`super::countmin_merkle`] for
//! the rebind (same path gadget). Scope: **plonky3 only** for v1; a
//! Goldilocks/plonky2 port is deferred. The existing `merkle` and `certified`
//! leaves are left untouched as side-by-side baselines.

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
    common::{CircuitTableAir, get_airs_and_degrees_with_prep},
};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::statement::{self, Expose, IndexPin};
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_merkle::{
    RowPlan, build_row_plan_mode, climb_merkle_path, climb_merkle_path_compress, pack_digest,
};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Range-check window for the aggregate counters (matches `countmin_merkle`).
const COUNT_BITS: usize = 24;

// ─── Parameters ────────────────────────────────────────────────────────────

/// Shape of a `c_merkle` leaf: a `merkle`-leaf shape (`d` rows of `w` counters,
/// `batch` records, per-row touched-cell capacity `t_max`). The PRF runs once
/// per record (`batch·d` times) — there is no key-grouping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountMinCMerkleParams {
    /// Number of sketch rows (independent Merkle trees). `1 ≤ d ≤ 8`.
    pub d: usize,
    /// Counters per row. A power of two `≥ 2`.
    pub w: usize,
    /// Records per epoch. The PRF gadget runs `batch · d` times (once per
    /// record, no pre-grouping by key).
    pub batch: usize,
    /// Compile-time bound on distinct touched cells **per row** (`1 ≤ t_max ≤ w`).
    pub t_max: usize,
    /// Merkle internal-node combiner for the rebind.
    ///
    /// - `false` (the `merkle` baseline): the padding-free sponge
    ///   ([`super::countmin_merkle::node_digest`] /
    ///   [`super::countmin_merkle::climb_merkle_path`]) — 2 Poseidon2
    ///   permutations per binary node, plus per-level bit-select ALU ops.
    /// - `true` (the `merkle_fast` variant): a single 2:1 Poseidon2 compression
    ///   in Merkle mode ([`super::countmin_merkle::node_digest_compress`] /
    ///   [`super::countmin_merkle::climb_merkle_path_compress`]) — 1
    ///   permutation per node, and the AIR does the swap for free (no
    ///   per-level bit-select ALU ops).
    ///
    /// The leaf digest (sponge), batch binding, routing, op chain, and commitment
    /// SHAPE (the `d`-tuple of per-row roots) are identical in both modes. The
    /// two roots are NOT interchangeable across modes (different node combiner).
    pub compress: bool,
    /// Selects the **routing** method for the Step-5 rebind — optimization (ii).
    ///
    /// - `false` (the `merkle`/`merkle_fast` baselines): each `(record, row)`
    ///   tuple is routed to one of `t_max` per-row Merkle op slots via a one-hot
    ///   selector `sel[i][k][c]` of size `m·t_max·d ≈ m²·d`. This ALU routing
    ///   dominates at large batch.
    /// - `true` (the `merkle_gb` variant): the selector matrix is replaced by a
    ///   **group-by-counter** (`O(m·d)`) feeding a SINGLE GLOBAL sorted Merkle
    ///   op-chain. The `m·d` `(combined = i·w + pos_i[k], value_k)` entries are
    ///   sorted by `combined` with ONE PermuteAir; an adjacent-equality +
    ///   running-sum group-by totals each touched cell at its segment end; and
    ///   every sorted position climbs the per-row tree (oblivious null climbs at
    ///   non-segment-ends). Each row contributes exactly `m` entries, so the `d`
    ///   blocks occupy fixed sorted positions `[i·m, (i+1)·m)` and the per-row
    ///   root chain threads through compile-time block boundaries. Routing cost
    ///   drops from `m²·d` to `O(m·d)`. Always paired with `compress: true`.
    ///
    /// The commitment SHAPE (the `d`-tuple of per-row roots) and the final-root
    /// semantics are IDENTICAL to `merkle_fast` — `merkle_gb`'s roots equal
    /// `merkle_fast`'s for the same input (same MyCompress nodes), so it is a
    /// drop-in semantically-equivalent rebind that only changes the routing.
    pub group_by: bool,
}

impl CountMinCMerkleParams {
    pub fn validate(&self) {
        assert!(self.d >= 1 && self.d <= 8, "d must be in 1..=8, got {}", self.d);
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two ≥ 2");
        assert!(self.batch >= 1, "batch must be positive");
        assert!(self.t_max >= 1 && self.t_max <= self.w, "t_max in [1, w]");
        if self.group_by {
            assert!(self.compress, "group_by (merkle_gb) requires compress=true");
        }
    }
    /// Per-row Merkle tree height = `log2(w)` (also the number of position bits).
    pub fn height(&self) -> usize {
        self.w.trailing_zeros() as usize
    }
}

// ─── Public proof type ──────────────────────────────────────────────────────

/// A self-verified `c_merkle` leaf proof. Same shape as
/// [`super::countmin_merkle::CountMinMerkleProof`] (the commitment is the
/// `d`-tuple of per-row Merkle roots).
pub struct CountMinCMerkleProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_roots: Vec<CountMinCommit>,
    pub final_roots: Vec<CountMinCommit>,
    pub batch_commit: CountMinCommit,
    pub params: CountMinCMerkleParams,
}

impl CountMinCMerkleProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

// ─── Prover ──────────────────────────────────────────────────────────────────

/// Prove one `c_merkle` epoch: per-record PRF + Merkle sparse rebind over a
/// `d × w` Count-Min state (Pattern A — no key-grouping).
///
/// # Panics
/// - `params.validate()` failures.
/// - `initial.params != (d, w)` or `batch.len() != params.batch`.
/// - more than `t_max` distinct touched cells in some row.
/// Combine the `d` per-row Merkle root PIs into a single `combined_commit`
/// digest **in-circuit** — a Poseidon2 hash of the `d` roots (or the root itself
/// when `d == 1`), matching the native
/// [`combined_commit`](super::countmin_merkle::combined_commit). Each root PI is
/// `[lo, hi]` (the `[Val; 8]` root packed as 2 Challenge wires), and flattening
/// them reproduces the native `roots.flat_map(|r| r.0)` Val order, so the
/// in-circuit hash equals the native digest.
///
/// Rate-alignment invariant: `add_hash_slice` matches the native padding-free
/// sponge only when the input length is a multiple of the sponge rate. Here the
/// input is `d · DIGEST_PACKING` Challenge wires, and for `BABY_BEAR_D4_W16` the
/// extension rate equals `DIGEST_PACKING` (= 2), so each root is one full rate
/// block and the total is always rate-aligned for any `d`. If `DIGEST_PACKING`
/// or the config's rate ever diverge, a partial final block would silently
/// differ from native — hence the debug-assert.
fn combine_roots_in_circuit(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    roots: &[[ExprId; DIGEST_PACKING]],
) -> [ExprId; DIGEST_PACKING] {
    if roots.len() == 1 {
        return roots[0];
    }
    // Correctness rests on each root being exactly one sponge-rate block
    // (DIGEST_PACKING == extension rate == 2 for BABY_BEAR_D4_W16); fires if a
    // future change breaks that alignment so native/in-circuit could diverge.
    debug_assert_eq!(DIGEST_PACKING, 2, "combine_roots_in_circuit assumes DIGEST_PACKING == sponge rate (2)");
    let flat: Vec<ExprId> = roots.iter().flatten().copied().collect();
    let h = b.add_hash_slice(cfg, &flat, true).expect("hash per-row roots → combined commit");
    [h[0], h[1]]
}

pub fn prove_countmin_c_merkle_leaf(
    params: CountMinCMerkleParams,
    initial: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinCMerkleProof {
    prove_countmin_c_merkle_leaf_impl(params, initial, batch, Expose::None, 1)
}

/// Like [`prove_countmin_c_merkle_leaf`] but additionally surfaces the boundary
/// commitment `combined_commit(per-row roots)` — computed **in-circuit** (a
/// Poseidon2 hash of the `d` root PIs; the root itself when `d == 1`) — via the
/// Expose NPO, so the leaf can be folded by the in-circuit boundary-bound forest
/// ([`crate::recursion::recursive::expose_forest::prove_forest_over`]). Requires
/// `group_by == false` (the `merkle_gb` routing path has no exposing variant).
pub fn prove_countmin_c_merkle_exposed(
    params: CountMinCMerkleParams,
    initial: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinCMerkleProof {
    assert!(!params.group_by, "boundary-exposing c_merkle requires group_by == false");
    prove_countmin_c_merkle_leaf_impl(params, initial, batch, Expose::Boundary, 1)
}

/// Like [`prove_countmin_c_merkle_exposed`] but with the **Interval**
/// statement for batch `t` (1-based): exposes
/// `(combined_init, combined_final, (t, t, 0, 0), Poseidon2(TAG_LEAF, t, Com(B_t)))`
/// with the in-circuit batch digest (see
/// [`crate::recursion::recursive::statement`]).
pub fn prove_countmin_c_merkle_interval(
    params: CountMinCMerkleParams,
    t: u64,
    initial: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinCMerkleProof {
    assert!(!params.group_by, "boundary-exposing c_merkle requires group_by == false");
    prove_countmin_c_merkle_leaf_impl(params, initial, batch, Expose::Interval, t)
}

/// The batch commitment `Com(B_t)` the c_merkle leaf binds in-circuit (the
/// sponge over interleaved `(key, value)`): what the public log publishes.
pub fn countmin_c_merkle_batch_commit(batch: &[CountMinUpdate]) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let flat: Vec<Val> = batch
        .iter()
        .flat_map(|u| {
            [
                Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO,
                Val::from_u32(u.value), Val::ZERO, Val::ZERO, Val::ZERO,
            ]
        })
        .collect();
    hasher.hash_iter(flat.iter().copied())
}

fn prove_countmin_c_merkle_leaf_impl(
    params: CountMinCMerkleParams,
    initial: CountMinState,
    batch: Vec<CountMinUpdate>,
    expose: Expose,
    t: u64,
) -> CountMinCMerkleProof {
    let expose_boundary = expose == Expose::Boundary;
    params.validate();
    let CountMinCMerkleParams { d, w, batch: m, t_max, compress, group_by } = params;
    assert_eq!(initial.params.d, d, "state.d / params.d mismatch");
    assert_eq!(initial.params.w, w, "state.w / params.w mismatch");
    assert_eq!(batch.len(), m, "batch.len() != params.batch");
    // Optimization (ii): the group-by routing path (merkle_gb). Same final-root
    // semantics, different routing (O(m·d) group-by instead of m²·d selectors).
    // (The exposing variant forbids group_by, so expose_boundary is false here.)
    if group_by {
        return prove_countmin_c_merkle_gb_leaf(params, initial, batch);
    }
    let h = params.height(); // = w_log2
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

    // ─── Native side ─────────────────────────────────────────────────────────
    // Reduced (mod p) keys: the Merkle commitment + PRF both reduce keys to a
    // BabyBear Val, so the whole pipeline works on `key mod p` as a single base
    // element (no key_lo/key_hi split — simpler than countmin_final).
    let red_key: Vec<u64> =
        batch.iter().map(|u| Val::from_u64(u.key).as_canonical_u64()).collect();

    // Per-row Merkle plans, driven directly by the `m` records (no
    // key-grouping). Count-Min is additive, so routing each record to its
    // hashed cell and summing collisions at the cell level reaches the same
    // per-row final cells. The build uses the reduced keys so the plan's cell
    // positions match the in-circuit PRF (which hashes `key mod p`).
    let records_reduced: Vec<CountMinUpdate> = (0..m)
        .map(|k| CountMinUpdate { key: red_key[k], value: batch[k].value })
        .collect();
    let plans: Vec<RowPlan> = (0..d)
        .map(|i| {
            let cells_in: Vec<u64> = initial.counters[i].iter().map(|&c| c as u64).collect();
            build_row_plan_mode(i, &cells_in, &records_reduced, w, t_max, compress)
        })
        .collect();

    // Batch commitment over interleaved (key, value) — matches `countmin_merkle`
    // so the two leaves' batch commits are directly comparable.
    let batch_commit: [Val; 8] = {
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = batch
            .iter()
            .flat_map(|u| {
                [
                    Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO,
                    Val::from_u32(u.value), Val::ZERO, Val::ZERO, Val::ZERO,
                ]
            })
            .collect();
        hasher.hash_iter(flat.iter().copied())
    };

    // ─── Build circuit ───────────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    if expose.exposes() {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }
    // No PermuteAir: the key-grouping (key-sort + compaction) stages are
    // dropped (Pattern A — hash per record, route to per-row Merkle ops).

    // Public inputs: per-row init roots, per-row final roots, batch commit.
    let init_root_pis: Vec<[ExprId; DIGEST_PACKING]> = (0..d)
        .map(|_| std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_root_lo" } else { "init_root_hi" })))
        .collect();
    let final_root_pis: Vec<[ExprId; DIGEST_PACKING]> = (0..d)
        .map(|_| std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_root_lo" } else { "final_root_hi" })))
        .collect();
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Boundary exposing: surface combined_commit(per-row roots) for the initial
    // and final states via the Expose NPO, computed IN-CIRCUIT (so it equals the
    // native combined_commit). The root PIs are connected to the climbed roots
    // below; the hash gate reads those PI values. Consumed by the in-circuit
    // boundary-bound forest (`expose_forest`).
    if expose_boundary {
        let combined_init = combine_roots_in_circuit(&mut b, &cfg, &init_root_pis);
        let combined_final = combine_roots_in_circuit(&mut b, &cfg, &final_root_pis);
        b.add_expose(&[combined_init[0], combined_init[1], combined_final[0], combined_final[1]])
            .expect("add_expose boundary");
    }
    // Interval layout: the same in-circuit combined roots, exposed together
    // with the batch index and digest once the batch digest exists (S1).
    let interval_boundary = expose.is_interval().then(|| {
        (
            combine_roots_in_circuit(&mut b, &cfg, &init_root_pis),
            combine_roots_in_circuit(&mut b, &cfg, &final_root_pis),
        )
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    // Note: c_merkle routes by the within-row position `pos` directly (no
    // `combined = i·w + pos` cell index), so it needs no `w`/`row_i` consts.
    // The key-grouping payload shift is gone (no key-sort/compaction PermuteAir).
    let pow2: Vec<ExprId> =
        (0..h).map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j")).collect();

    // ── Private witnesses (allocation order MUST match the value-push order) ──
    // key fed only to hashes → recompose it so it gets a WitnessChecks creator.
    let key_coeff: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_coeff")).collect();
    let values: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("value")).collect();
    let h_digest: Vec<(ExprId, ExprId)> = (0..m)
        .map(|_| (b.alloc_private_input("h_digest_0"), b.alloc_private_input("h_digest_1")))
        .collect();
    // Merkle op witnesses (per row). `sel[i][k][c]` routes record k to op c.
    let sel: Vec<Vec<Vec<ExprId>>> = (0..d)
        .map(|_| (0..m).map(|_| (0..t_max).map(|_| b.alloc_private_input("sel")).collect()).collect())
        .collect();
    let op_old_w: Vec<Vec<ExprId>> =
        (0..d).map(|_| (0..t_max).map(|_| b.alloc_private_input("op_old")).collect()).collect();
    let op_new_w: Vec<Vec<ExprId>> =
        (0..d).map(|_| (0..t_max).map(|_| b.alloc_private_input("op_new")).collect()).collect();
    let op_active_w: Vec<Vec<ExprId>> =
        (0..d).map(|_| (0..t_max).map(|_| b.alloc_private_input("op_active")).collect()).collect();
    let op_pos_bits: Vec<Vec<Vec<ExprId>>> = (0..d)
        .map(|_| (0..t_max).map(|_| (0..h).map(|_| b.alloc_private_input("op_pos_bit")).collect()).collect())
        .collect();
    let op_sib: Vec<Vec<Vec<[ExprId; 2]>>> = (0..d)
        .map(|_| {
            (0..t_max)
                .map(|_| {
                    (0..h)
                        .map(|_| [b.alloc_private_input("sib_lo"), b.alloc_private_input("sib_hi")])
                        .collect()
                })
                .collect()
        })
        .collect();

    // keys[k] = recompose(key_coeff[k] = key mod p).
    let keys: Vec<ExprId> = (0..m)
        .map(|k| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero, zero, zero])
                .expect("recompose key")
        })
        .collect();

    // ── S1: open the batch commitment over interleaved (key, value) ──────────
    let mut batch_pre: Vec<ExprId> = Vec::with_capacity(2 * m);
    for k in 0..m {
        batch_pre.push(keys[k]);
        batch_pre.push(values[k]);
    }
    let hb = b.add_hash_slice(&cfg, &batch_pre, true).expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_commit_pis[i]);
    }
    // Interval statement (B6(b)): batch index t (last public input,
    // bit-pinned: no Range table here) and H = Poseidon2(TAG_LEAF, t, hb).
    if let Some((combined_init, combined_final)) = interval_boundary {
        let _t = statement::expose_leaf_interval::<Val, Challenge>(
            &mut b,
            &cfg,
            &combined_init,
            &combined_final,
            &hb,
            zero,
            crate::sketch::bind::Binding::Semantic,
            IndexPin::Bits,
        );
    }

    // ── Stage F: PRF hash gadget OVER EVERY RECORD (no key-grouping) ─────────
    // Yields pos_val[i][k] = Poseidon2(keys[k])[i] mod w (bottom log2(w) bits).
    // One hash per record (Θ(batch·d)); duplicate keys are re-merged at the
    // cell level by the routing + per-op aggregation below.
    let mut pos_val: Vec<Vec<ExprId>> = vec![Vec::with_capacity(m); d];
    for k in 0..m {
        let hashed = b.add_hash_slice(&cfg, &[keys[k]], true).expect("hash keys[k]");
        let (h0, h1) = h_digest[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        let coeffs_0 = b.decompose_ext_to_base_coeffs::<Val>(h0).expect("decompose h0");
        let coeffs_1 = b.decompose_ext_to_base_coeffs::<Val>(h1).expect("decompose h1");
        let h_vals: [ExprId; 8] = [
            coeffs_0[0], coeffs_0[1], coeffs_0[2], coeffs_0[3],
            coeffs_1[0], coeffs_1[1], coeffs_1[2], coeffs_1[3],
        ];
        for i in 0..d {
            let bits = b.decompose_to_bits::<Val>(h_vals[i], Val::bits()).expect("decompose h_val");
            let mut pos = b.mul(bits[0], pow2[0]);
            for jb in 1..h {
                let term = b.mul(bits[jb], pow2[jb]);
                pos = b.add(pos, term);
            }
            pos_val[i].push(pos);
        }
        // Consume unused digest Vals (bus balance), matching countmin_final.
        for kk in d..8 {
            let _ = b.decompose_to_bits::<Val>(h_vals[kk], Val::bits()).expect("decompose unused h_val");
        }
    }

    // ── Per-op position value (from op_pos_bits) + op_active boolean check ────
    let mut op_pos_value: Vec<Vec<ExprId>> = Vec::with_capacity(d);
    for i in 0..d {
        let mut row_vals = Vec::with_capacity(t_max);
        for c in 0..t_max {
            let am1 = b.sub(op_active_w[i][c], one);
            let chk = b.mul(op_active_w[i][c], am1);
            b.connect(chk, zero);
            let mut p = zero;
            for j in 0..h {
                let bm1 = b.sub(op_pos_bits[i][c][j], one);
                let bchk = b.mul(op_pos_bits[i][c][j], bm1);
                b.connect(bchk, zero);
                p = b.mul_add(op_pos_bits[i][c][j], pow2[j], p);
            }
            row_vals.push(p);
        }
        op_pos_value.push(row_vals);
    }

    // ── Routing: send each (row i, record k) to the op at pos_val[i][k] ──────
    for i in 0..d {
        for k in 0..m {
            let mut sum = zero;
            let mut routed_pos = zero;
            let mut routed_active = zero;
            for c in 0..t_max {
                let s = sel[i][k][c];
                let sm1 = b.sub(s, one);
                let chk = b.mul(s, sm1);
                b.connect(chk, zero);
                sum = b.add(sum, s);
                routed_pos = b.mul_add(s, op_pos_value[i][c], routed_pos);
                routed_active = b.mul_add(s, op_active_w[i][c], routed_active);
            }
            b.connect(sum, one);
            b.connect(routed_pos, pos_val[i][k]);
            b.connect(routed_active, one);
        }
    }

    // ── Aggregate: op increment = Σ_k sel·value_k; new = old + inc ───────────
    for i in 0..d {
        for c in 0..t_max {
            let mut inc = zero;
            for k in 0..m {
                inc = b.mul_add(sel[i][k][c], values[k], inc);
            }
            let expect_new = b.add(op_old_w[i][c], inc);
            b.connect(op_new_w[i][c], expect_new);
            let _ = b.decompose_to_bits::<Val>(op_new_w[i][c], COUNT_BITS).expect("op_new ≥ 0");
            let _ = b.decompose_to_bits::<Val>(op_old_w[i][c], COUNT_BITS).expect("op_old ≥ 0");
        }
    }

    // ── Rebind: per-row Merkle update chain r_0=init → r_t_max=final ──────────
    // `compress` selects the per-level combiner: the sponge `climb_merkle_path`
    // (baseline) or the single-perm Merkle-mode `climb_merkle_path_compress`
    // (`merkle_fast`). Both have the same signature and consume the SAME CTL
    // sibling `ExprId`s (`op_sib`), so the rest of the chain is identical.
    let climb = |b: &mut CircuitBuilder<Challenge>,
                 leaf_val: ExprId,
                 pos_bits: &[ExprId],
                 siblings: &[[ExprId; 2]]| -> [ExprId; 2] {
        if compress {
            climb_merkle_path_compress(b, &cfg, leaf_val, pos_bits, siblings)
        } else {
            climb_merkle_path(b, &cfg, leaf_val, pos_bits, siblings)
        }
    };
    for i in 0..d {
        let mut prev_root: [ExprId; 2] = init_root_pis[i];
        for c in 0..t_max {
            let old_root = climb(&mut b, op_old_w[i][c], &op_pos_bits[i][c], &op_sib[i][c]);
            if c == 0 {
                b.connect(old_root[0], prev_root[0]);
                b.connect(old_root[1], prev_root[1]);
            } else {
                for l in 0..2 {
                    let diff = b.sub(old_root[l], prev_root[l]);
                    b.connect(diff, zero);
                }
            }
            let new_root = climb(&mut b, op_new_w[i][c], &op_pos_bits[i][c], &op_sib[i][c]);
            prev_root = new_root;
        }
        b.connect(prev_root[0], final_root_pis[i][0]);
        b.connect(prev_root[1], final_root_pis[i][1]);
    }

    let circuit = b.build().expect("build cm c_merkle leaf circuit");

    // ─── Pack public + private values (same order as allocation) ─────────────
    let mut public_inputs: Vec<Challenge> = Vec::new();
    for plan in &plans {
        public_inputs.extend_from_slice(&pack_digest(&plan.init_root));
    }
    for plan in &plans {
        public_inputs.extend_from_slice(&pack_digest(&plan.final_root));
    }
    public_inputs.extend_from_slice(&pack_digest(&batch_commit));
    if expose.is_interval() {
        public_inputs.push(Challenge::from_u64(t));
    }

    let mut private_inputs: Vec<Challenge> = Vec::new();
    // key_coeff (= key mod p), values.
    for &rk in &red_key {
        private_inputs.push(Challenge::from_u64(rk));
    }
    for u in &batch {
        private_inputs.push(Challenge::from_u32(u.value));
    }
    // h_digest (two Challenges per RECORD).
    {
        use p3_field::BasedVectorSpace;
        let hasher = MyHash::new(make_perm());
        for &rk in &red_key {
            let input = [Val::from_u64(rk), Val::ZERO, Val::ZERO, Val::ZERO];
            let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
            private_inputs
                .push(Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs"));
            private_inputs
                .push(Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs"));
        }
    }
    // sel[i][k][c] — record k routes to op c in row i.
    for i in 0..d {
        for k in 0..m {
            for c in 0..t_max {
                private_inputs.push(if plans[i].record_op[k] == c {
                    Challenge::ONE
                } else {
                    Challenge::ZERO
                });
            }
        }
    }
    // op_old, op_new, op_active.
    for i in 0..d {
        for c in 0..t_max {
            private_inputs.push(Challenge::from_u64(plans[i].op_old[c]));
        }
    }
    for i in 0..d {
        for c in 0..t_max {
            private_inputs.push(Challenge::from_u64(plans[i].op_new[c]));
        }
    }
    for i in 0..d {
        for c in 0..t_max {
            private_inputs.push(Challenge::from_u64(plans[i].op_active[c]));
        }
    }
    // op_pos_bits[i][c][j].
    for i in 0..d {
        for c in 0..t_max {
            for j in 0..h {
                let bit = (plans[i].op_used_pos[c] >> j) & 1;
                private_inputs.push(if bit == 1 { Challenge::ONE } else { Challenge::ZERO });
            }
        }
    }
    // op_sib[i][c][j] = (lo, hi).
    for i in 0..d {
        for c in 0..t_max {
            for j in 0..h {
                let [lo, hi] = pack_digest(&plans[i].op_siblings[c][j]);
                private_inputs.push(lo);
                private_inputs.push(hi);
            }
        }
    }

    // ─── Run + prove ─────────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run cm c_merkle circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    if expose.exposes() {
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
        .expect("get_airs_and_degrees_with_prep (cm c_merkle)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&dd| dd + config.is_zk()).collect();
    // STEP-1 GATE INSTRUMENTATION (env CM_TABLE_DEBUG=1): print the per-table
    // heights so we can see whether the ALU table dominates and scales with w.
    // Each row of `airs` is a CircuitTableAir variant; Dynamic = the
    // poseidon2/recompose sub-tables (in air_builders order: poseidon2 then
    // recompose). Total = Σ 2^ext_degree should equal the reported trace_rows.
    if std::env::var("CM_TABLE_DEBUG").is_ok() {
        let mut dyn_n = 0usize;
        let mut total: u64 = 0;
        let variant = if compress { "merkle_fast" } else { "merkle" };
        eprintln!(
            "[CM_TABLE_DEBUG] c_merkle[{variant}] d={d} w={w} m={m} t_max={t_max} h={h} — per-table heights:"
        );
        for (air, &ed) in airs.iter().zip(ext_degrees.iter()) {
            let rows: u64 = 1u64 << ed;
            total += rows;
            let label = match air {
                CircuitTableAir::Const(_) => "Const".to_string(),
                CircuitTableAir::Public(_) => "Public".to_string(),
                CircuitTableAir::Alu(_) => "ALU".to_string(),
                CircuitTableAir::Dynamic(_) => {
                    let n = dyn_n;
                    dyn_n += 1;
                    format!("Dynamic#{n} (poseidon2|recompose)")
                }
            };
            eprintln!("    {label:<32} log2={ed:>2}  rows={rows}");
        }
        eprintln!("    {:<32} {:>10}  rows={total}", "TOTAL", "");
    }
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    if expose.exposes() {
        prover.register_expose_table::<4>();
    }
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove cm c_merkle");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify cm c_merkle leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&dd| 1u64 << dd).sum(),
    });

    let _ = pack_commit_to_challenge;

    CountMinCMerkleProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial_roots: plans.iter().map(|p| CountMinCommit(p.init_root)).collect(),
        final_roots: plans.iter().map(|p| CountMinCommit(p.final_root)).collect(),
        batch_commit: CountMinCommit(batch_commit),
        params,
    }
}

// ─── Optimization (ii): group-by routing + global sorted Merkle op-chain ─────

/// Prove one `merkle_gb` epoch (optimization (ii)): replace the `m·t_max·d`
/// selector-routing matrix with an `O(m·d)` group-by-counter feeding a SINGLE
/// GLOBAL sorted Merkle op-chain.
///
/// ## Design (mirrors `countmin_memcheck` / `countmin_omc` for the front half)
///
/// 1. **U_ctr + sort.** For each record `k` (m) and row `i` (d), one entry
///    `(combined = i·w + pos_i[k], value_k)`; `n_ctr = m·d`. ONE PermuteAir
///    sorts by `combined` → `(combined_sorted, val_sorted)`.
/// 2. **Group-by.** `eq_tag` (adjacent equality via `inv_diff`), running sum
///    `acc`, segment-end flag `a_active`.
/// 3. **Block partition + range check.** Each row hits each cell exactly once,
///    so each row contributes exactly `m` entries; sorted by `combined`, block
///    `i = r/m` is a COMPILE-TIME CONSTANT. `pos_r = combined_sorted[r] − i·w`
///    is range-checked into `[0, w)` (bit-decompose to `h` bits + reconstruct)
///    — this BINDS each sorted entry to its block. Global sortedness (gap ≥ 0,
///    top bits zero) is enforced as in `countmin_memcheck`.
/// 4. **Global sorted Merkle op-chain (oblivious).** For each `r`, let `i = r/m`.
///    `inc[r] = a_active[r]·acc[r]`; `op_new[r] = op_old[r] + inc[r]`. Climb the
///    per-row tree (compress gadget) with `op_old[r]` opening against the running
///    block root, then `op_new[r]` → next running root, SHARED siblings + the
///    `pos_r` bits from step 3. The block root is threaded by the const block
///    boundaries: `r % m == 0` ⇒ start from `init_root_pis[i]`; `r % m == m-1` ⇒
///    connect to `final_root_pis[i]`. Non-segment-ends climb too (null climb,
///    inc=0) for obliviousness.
fn prove_countmin_c_merkle_gb_leaf(
    params: CountMinCMerkleParams,
    initial: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinCMerkleProof {
    use crate::sketch::countmin_final::hash_cell_prf;
    use crate::sketch::countmin_merkle::{merkle_root_mode, merkle_siblings_mode};
    use p3_circuit::ops::generate_permute_trace;
    use p3_circuit_prover::batch_stark_prover::{permute_air_builders, permute_preprocessor};

    let CountMinCMerkleParams { d, w, batch: m, t_max: _, compress: _, group_by: _ } = params;
    let h = params.height(); // = w_log2
    let n_ctr = m * d;
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    // The combined index lives in [0, d·w); its sortedness gap range-check width.
    let addr_bits = {
        let n = d * w;
        (usize::BITS - (n.saturating_sub(1)).leading_zeros()).max(1) as usize
    };

    // ─── Native side ─────────────────────────────────────────────────────────
    // Reduced (mod p) keys: the Merkle commitment + PRF both reduce keys to a
    // BabyBear Val (matches the existing c_merkle leaf).
    let red_key: Vec<u64> =
        batch.iter().map(|u| Val::from_u64(u.key).as_canonical_u64()).collect();

    // Batch commitment over interleaved (key, value) — identical to the baseline.
    let batch_commit: [Val; 8] = {
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = batch
            .iter()
            .flat_map(|u| {
                [
                    Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO,
                    Val::from_u32(u.value), Val::ZERO, Val::ZERO, Val::ZERO,
                ]
            })
            .collect();
        hasher.hash_iter(flat.iter().copied())
    };

    // U_ctr: one (combined, value) entry per (record, row). Native unsorted order
    // is (record-major, row-minor): entry index = k*d + i.
    let mut u_ctr: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        for i in 0..d {
            let bucket = hash_cell_prf(i, red_key[k], w);
            let combined = (i * w + bucket) as u64;
            u_ctr.push((combined, batch[k].value));
        }
    }
    // Stable sort by `combined` (ties keep record order — irrelevant to the
    // running sum, which is commutative within a cell).
    let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr.iter().enumerate().collect();
    indexed.sort_by_key(|(_, (combined, _))| *combined);
    let sigma_ctr: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
    let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
    let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

    // Group-by-counter: adjacent equality, running sum, segment-end flags.
    let mut tag_native: Vec<u32> = vec![0; n_ctr];
    for r in 1..n_ctr {
        if combined_sorted_native[r] == combined_sorted_native[r - 1] {
            tag_native[r] = 1;
        }
    }
    let mut acc_native: Vec<u64> = vec![0; n_ctr];
    if n_ctr > 0 {
        acc_native[0] = val_sorted_native[0] as u64;
        for r in 1..n_ctr {
            acc_native[r] = if tag_native[r] == 1 {
                acc_native[r - 1] + val_sorted_native[r] as u64
            } else {
                val_sorted_native[r] as u64
            };
        }
    }
    let mut a_active_native: Vec<u32> = vec![0; n_ctr];
    for r in 0..n_ctr {
        let ends = if r == n_ctr - 1 { true } else { tag_native[r + 1] == 0 };
        a_active_native[r] = u32::from(ends);
    }

    // Per-row block partition (block i = sorted positions [i*m, (i+1)*m)):
    // validate against the per-row additive Count-Min, and build the per-position
    // op_old/op_new/pos/siblings + per-block init/final roots for the op-chain.
    // SANITY: each block must hold exactly the entries combined ∈ [i*w, (i+1)*w).
    let mut op_old_native: Vec<u64> = vec![0; n_ctr];
    let mut op_new_native: Vec<u64> = vec![0; n_ctr];
    let mut pos_native: Vec<usize> = vec![0; n_ctr];
    let mut sib_native: Vec<Vec<[Val; 8]>> = Vec::with_capacity(n_ctr);
    sib_native.resize(n_ctr, Vec::new());
    let mut init_root_native: Vec<[Val; 8]> = Vec::with_capacity(d);
    let mut final_root_native: Vec<[Val; 8]> = Vec::with_capacity(d);
    for i in 0..d {
        let cells: Vec<u64> = initial.counters[i].iter().map(|&c| c as u64).collect();
        init_root_native.push(merkle_root_mode(&cells, true));
        let mut snap: Vec<u64> = cells.clone();
        for r in (i * m)..((i + 1) * m) {
            // Block boundary range-check (native invariant): the entry's combined
            // index lies in row i's range.
            let combined = combined_sorted_native[r];
            assert!(
                combined >= (i * w) as u64 && combined < ((i + 1) * w) as u64,
                "block partition broken: r={r} combined={combined} not in row {i} range \
                 [{},{}) — each row must contribute exactly m sorted entries",
                i * w,
                (i + 1) * w
            );
            let pos = (combined - (i * w) as u64) as usize;
            pos_native[r] = pos;
            // op_old = snapshot value (= initial value; pos is written only at the
            // cell's segment-end, which has not run yet at any read of this run).
            op_old_native[r] = snap[pos];
            // Siblings against the running snapshot (oblivious: EVERY position
            // opens a path).
            sib_native[r] = merkle_siblings_mode(&snap, pos, true);
            let inc = (a_active_native[r] as u64) * acc_native[r];
            op_new_native[r] = op_old_native[r] + inc;
            // Apply the write at the segment-end (inc>0); null climbs leave snap.
            if a_active_native[r] == 1 {
                snap[pos] = op_new_native[r];
            }
        }
        final_root_native.push(merkle_root_mode(&snap, true));
    }

    // ─── Build circuit ───────────────────────────────────────────────────────
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);

    // Public inputs: per-row init roots, per-row final roots, batch commit.
    let init_root_pis: Vec<[ExprId; DIGEST_PACKING]> = (0..d)
        .map(|_| std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_root_lo" } else { "init_root_hi" })))
        .collect();
    let final_root_pis: Vec<[ExprId; DIGEST_PACKING]> = (0..d)
        .map(|_| std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_root_lo" } else { "final_root_hi" })))
        .collect();
    let batch_commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "batch_commit_lo" } else { "batch_commit_hi" })
    });

    // Constants.
    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    // 2^j for the largest of {h (pos range check), addr_bits (sortedness)}.
    let pow2: Vec<ExprId> = (0..h.max(addr_bits))
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();
    // Per-row i·w constant (used to recover pos_r within its const block).
    let row_w_const: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64((i * w) as u64), "row_i_w"))
        .collect();

    // ── Private witnesses (allocation order MUST match the value-push order) ──
    // key fed only to hashes → recompose for a WitnessChecks creator.
    let key_coeff: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_coeff")).collect();
    let values: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("value")).collect();
    let h_digest: Vec<(ExprId, ExprId)> = (0..m)
        .map(|_| (b.alloc_private_input("h_digest_0"), b.alloc_private_input("h_digest_1")))
        .collect();
    // Sorted view + group-by hints.
    let combined_sorted: Vec<ExprId> =
        (0..n_ctr).map(|_| b.alloc_private_input("combined_sorted")).collect();
    let val_sorted: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("val_sorted")).collect();
    let eq_tag: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("eq_tag")).collect();
    let inv_diff: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("inv_diff")).collect();
    // Op-chain witnesses (one per sorted position).
    let op_old_w: Vec<ExprId> = (0..n_ctr).map(|_| b.alloc_private_input("op_old")).collect();
    let op_sib: Vec<Vec<[ExprId; 2]>> = (0..n_ctr)
        .map(|_| {
            (0..h)
                .map(|_| [b.alloc_private_input("sib_lo"), b.alloc_private_input("sib_hi")])
                .collect()
        })
        .collect();

    // keys[k] = recompose(key_coeff[k] = key mod p).
    let keys: Vec<ExprId> = (0..m)
        .map(|k| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero, zero, zero])
                .expect("recompose key")
        })
        .collect();

    // ── S1: open the batch commitment over interleaved (key, value) ──────────
    let mut batch_pre: Vec<ExprId> = Vec::with_capacity(2 * m);
    for k in 0..m {
        batch_pre.push(keys[k]);
        batch_pre.push(values[k]);
    }
    let hb = b.add_hash_slice(&cfg, &batch_pre, true).expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(hb[i], batch_commit_pis[i]);
    }

    // ── Stage F: PRF hash over EVERY record → payload entries ────────────────
    // payload[k*d + i] = combined·SHIFT + value (recover from the sort). We avoid
    // a separate SHIFT by sorting on `combined` directly with the value carried;
    // to keep ONE permute we encode (combined, value) into one Challenge via the
    // recompose ALU (combined in coeff 0, value in coeff 1), mirroring the
    // (combined·SHIFT + value) trick but with a clean base-coeff packing.
    let mut payload: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let hashed = b.add_hash_slice(&cfg, &[keys[k]], true).expect("hash keys[k]");
        let (hd0, hd1) = h_digest[k];
        b.connect(hashed[0], hd0);
        b.connect(hashed[1], hd1);
        let coeffs_0 = b.decompose_ext_to_base_coeffs::<Val>(hd0).expect("decompose h0");
        let coeffs_1 = b.decompose_ext_to_base_coeffs::<Val>(hd1).expect("decompose h1");
        let h_vals: [ExprId; 8] = [
            coeffs_0[0], coeffs_0[1], coeffs_0[2], coeffs_0[3],
            coeffs_1[0], coeffs_1[1], coeffs_1[2], coeffs_1[3],
        ];
        for i in 0..d {
            let bits = b.decompose_to_bits::<Val>(h_vals[i], Val::bits()).expect("decompose h_val");
            let mut pos = b.mul(bits[0], pow2[0]);
            for jb in 1..h {
                let term = b.mul(bits[jb], pow2[jb]);
                pos = b.add(pos, term);
            }
            // combined = i·w + pos  (i is a const for this entry).
            let combined = b.add(row_w_const[i], pos);
            // Pack (combined, value) into one Challenge: coeff0=combined,
            // coeff1=value. The recompose ALU gives it a bus creator.
            let entry = b
                .recompose_base_coeffs_to_ext_via_alu::<Val>(&[combined, values[k], zero, zero])
                .expect("recompose payload entry");
            payload.push(entry);
        }
        // Consume unused digest Vals (bus balance), matching the baseline.
        for kk in d..8 {
            let _ = b.decompose_to_bits::<Val>(h_vals[kk], Val::bits()).expect("decompose unused h_val");
        }
    }

    // ── Sort (the ONLY PermuteAir): payload → sorted; recover (combined,val) ──
    let payload_sorted = b.add_permute(&payload, sigma_ctr.clone()).expect("add_permute (counter sort)");
    for r in 0..n_ctr {
        // recompose(combined_sorted, val_sorted, 0, 0) must equal the permuted
        // payload entry — binds combined_sorted/val_sorted to the sorted view.
        let recovered = b
            .recompose_base_coeffs_to_ext_via_alu::<Val>(&[combined_sorted[r], val_sorted[r], zero, zero])
            .expect("recompose sorted entry");
        b.connect(recovered, payload_sorted[r]);
    }

    // ── Group-by: adjacent equality + running sum + segment-end flags ────────
    b.connect(eq_tag[0], zero);
    b.connect(inv_diff[0], zero);
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r - 1], combined_sorted[r]);
        let lhs1 = b.mul(eq_tag[r], diff);
        b.connect(lhs1, zero);
        let one_minus_tag = b.sub(one, eq_tag[r]);
        let diff_inv = b.mul(diff, inv_diff[r]);
        let one_minus_diff_inv = b.sub(one, diff_inv);
        let lhs2 = b.mul(one_minus_tag, one_minus_diff_inv);
        b.connect(lhs2, zero);
    }

    // ── Sortedness range-check (global): gap ∈ [0, 2^addr_bits) ──────────────
    // A decrease wraps to ≈ p (sets a high bit) and is rejected — so the prover
    // cannot reorder entries to break the block partition. (Same gate as
    // countmin_memcheck.)
    for r in 1..n_ctr {
        let gap = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        let gap_bits = b.decompose_to_bits::<Val>(gap, Val::bits()).expect("decompose sort gap");
        for &bit in gap_bits.iter().skip(addr_bits) {
            b.connect(bit, zero);
        }
    }

    // ── Block partition + pos range-check: pos_r = combined_sorted[r] − i·w ∈ [0,w)
    // Bit-decompose pos_r to exactly h bits and reconstruct == pos_r. This binds
    // the entry to its const block: a row-1 entry mis-sorted into block 0 has
    // combined ≥ w ⇒ pos_r ≥ w ⇒ the h-bit reconstruction cannot equal pos_r.
    // The pos bits double as the Merkle path direction bits.
    let mut pos_bits_all: Vec<Vec<ExprId>> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let i = r / m; // COMPILE-TIME CONSTANT block index.
        let pos_expr = b.sub(combined_sorted[r], row_w_const[i]);
        let bits = b.decompose_to_bits::<Val>(pos_expr, Val::bits()).expect("decompose pos");
        // Reconstruct from the low h bits and force every higher bit to zero
        // (pos < w = 2^h).
        let mut recon = b.mul(bits[0], pow2[0]);
        for j in 1..h {
            recon = b.mul_add(bits[j], pow2[j], recon);
        }
        b.connect(recon, pos_expr);
        for &bit in bits.iter().skip(h) {
            b.connect(bit, zero);
        }
        pos_bits_all.push(bits[0..h].to_vec());
    }

    // ── Running sum acc + segment-end flag a_active (as ExprId) ──────────────
    let mut acc: Vec<ExprId> = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        let new_acc = b.add(val_sorted[r], carried);
        acc.push(new_acc);
    }
    let mut a_active: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let active = if r == n_ctr - 1 { one } else { b.sub(one, eq_tag[r + 1]) };
        a_active.push(active);
    }

    // ── inc[r] = a_active·acc; op_new = op_old + inc; range-check both ≥ 0 ────
    let mut op_new_w: Vec<ExprId> = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        let inc = b.mul(a_active[r], acc[r]);
        let new_v = b.add(op_old_w[r], inc);
        op_new_w.push(new_v);
        let _ = b.decompose_to_bits::<Val>(op_new_w[r], COUNT_BITS).expect("op_new ≥ 0");
        let _ = b.decompose_to_bits::<Val>(op_old_w[r], COUNT_BITS).expect("op_old ≥ 0");
    }

    // ── Global sorted Merkle op-chain (compress climb, oblivious) ────────────
    // Block i occupies sorted positions [i·m, (i+1)·m); the running root threads
    // through the COMPILE-TIME block boundaries.
    for i in 0..d {
        let mut prev_root: [ExprId; 2] = init_root_pis[i];
        for in_block in 0..m {
            let r = i * m + in_block;
            // Old value opens against the running block root.
            let old_root =
                climb_merkle_path_compress(&mut b, &cfg, op_old_w[r], &pos_bits_all[r], &op_sib[r]);
            if in_block == 0 {
                b.connect(old_root[0], prev_root[0]);
                b.connect(old_root[1], prev_root[1]);
            } else {
                for l in 0..2 {
                    let diff = b.sub(old_root[l], prev_root[l]);
                    b.connect(diff, zero);
                }
            }
            // New value's climb is the next running block root (null climb when
            // inc=0 ⇒ op_new==op_old ⇒ root unchanged, but SAME fixed work).
            let new_root =
                climb_merkle_path_compress(&mut b, &cfg, op_new_w[r], &pos_bits_all[r], &op_sib[r]);
            prev_root = new_root;
        }
        b.connect(prev_root[0], final_root_pis[i][0]);
        b.connect(prev_root[1], final_root_pis[i][1]);
    }

    let circuit = b.build().expect("build cm c_merkle_gb leaf circuit");

    // ─── Pack public + private values (same order as allocation) ─────────────
    let mut public_inputs: Vec<Challenge> = Vec::new();
    for root in &init_root_native {
        public_inputs.extend_from_slice(&pack_digest(root));
    }
    for root in &final_root_native {
        public_inputs.extend_from_slice(&pack_digest(root));
    }
    public_inputs.extend_from_slice(&pack_digest(&batch_commit));

    let mut private_inputs: Vec<Challenge> = Vec::new();
    // key_coeff (= key mod p), values.
    for &rk in &red_key {
        private_inputs.push(Challenge::from_u64(rk));
    }
    for u in &batch {
        private_inputs.push(Challenge::from_u32(u.value));
    }
    // h_digest (two Challenges per RECORD).
    {
        use p3_field::BasedVectorSpace;
        let hasher = MyHash::new(make_perm());
        for &rk in &red_key {
            let input = [Val::from_u64(rk), Val::ZERO, Val::ZERO, Val::ZERO];
            let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
            private_inputs
                .push(Challenge::from_basis_coefficients_slice(&digest[0..4]).expect("4 coeffs"));
            private_inputs
                .push(Challenge::from_basis_coefficients_slice(&digest[4..8]).expect("4 coeffs"));
        }
    }
    // combined_sorted, val_sorted, eq_tag, inv_diff.
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(combined_sorted_native[r]));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u32(val_sorted_native[r]));
    }
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(tag_native[r] as u64));
    }
    for r in 0..n_ctr {
        let inv = if r == 0 || combined_sorted_native[r - 1] == combined_sorted_native[r] {
            Challenge::ZERO
        } else {
            let diff = Challenge::from_u64(combined_sorted_native[r - 1])
                - Challenge::from_u64(combined_sorted_native[r]);
            diff.try_inverse().expect("nonzero diff inverts")
        };
        private_inputs.push(inv);
    }
    // op_old (one per sorted position).
    for r in 0..n_ctr {
        private_inputs.push(Challenge::from_u64(op_old_native[r]));
    }
    // op_sib[r][j] = (lo, hi).
    for r in 0..n_ctr {
        for j in 0..h {
            let [lo, hi] = pack_digest(&sib_native[r][j]);
            private_inputs.push(lo);
            private_inputs.push(hi);
        }
    }

    // ─── Run + prove ─────────────────────────────────────────────────────────
    let __t_w = std::time::Instant::now();
    let traces = {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
        runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
        runner.run().expect("run cm c_merkle_gb circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (cm c_merkle_gb)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&dd| dd + config.is_zk()).collect();
    // STEP-2 GATE INSTRUMENTATION (env CM_TABLE_DEBUG=1): per-table heights for
    // the group-by routing variant (label merkle_gb). Compare ALU growth in m vs.
    // merkle_fast's m²·d selector routing.
    if std::env::var("CM_TABLE_DEBUG").is_ok() {
        let mut dyn_n = 0usize;
        let mut total: u64 = 0;
        eprintln!(
            "[CM_TABLE_DEBUG] c_merkle[merkle_gb] d={d} w={w} m={m} n_ctr={n_ctr} h={h} addr_bits={addr_bits} — per-table heights:"
        );
        for (air, &ed) in airs.iter().zip(ext_degrees.iter()) {
            let rows: u64 = 1u64 << ed;
            total += rows;
            let label = match air {
                CircuitTableAir::Const(_) => "Const".to_string(),
                CircuitTableAir::Public(_) => "Public".to_string(),
                CircuitTableAir::Alu(_) => "ALU".to_string(),
                CircuitTableAir::Dynamic(_) => {
                    let n = dyn_n;
                    dyn_n += 1;
                    format!("Dynamic#{n} (poseidon2|recompose|permute)")
                }
            };
            eprintln!("    {label:<40} log2={ed:>2}  rows={rows}");
        }
        eprintln!("    {:<40} {:>10}  rows={total}", "TOTAL", "");
    }
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    let __t_p = std::time::Instant::now();
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove cm c_merkle_gb");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify cm c_merkle_gb leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&dd| 1u64 << dd).sum(),
    });

    let _ = pack_commit_to_challenge;

    CountMinCMerkleProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial_roots: init_root_native.iter().map(|r| CountMinCommit(*r)).collect(),
        final_roots: final_root_native.iter().map(|r| CountMinCommit(*r)).collect(),
        batch_commit: CountMinCommit(batch_commit),
        params,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::countmin::CountMinParams;
    use crate::sketch::countmin_final::hash_cell_prf;
    use crate::sketch::countmin_merkle::merkle_root_mode;

    /// Native d×w state evolution under the PRF row hash, returning per-row
    /// updated cells (to compare against the proof's row roots).
    fn native_rows(initial: &CountMinState, batch: &[CountMinUpdate]) -> Vec<Vec<u64>> {
        let (d, w) = (initial.params.d, initial.params.w);
        let mut rows: Vec<Vec<u64>> =
            initial.counters.iter().map(|r| r.iter().map(|&c| c as u64).collect()).collect();
        for u in batch {
            for i in 0..d {
                rows[i][hash_cell_prf(i, u.key, w)] += u.value as u64;
            }
        }
        rows
    }

    fn state(d: usize, w: usize, fill: impl Fn(usize, usize) -> u32) -> CountMinState {
        let counters = (0..d).map(|i| (0..w).map(|j| fill(i, j)).collect()).collect();
        CountMinState { counters, params: CountMinParams { d, w } }
    }

    fn check(proof: &CountMinCMerkleProof, initial: &CountMinState, batch: &[CountMinUpdate]) {
        check_mode(proof, initial, batch, false);
    }

    /// Verify the proof's per-row roots against the natively-computed Merkle
    /// roots using the `compress` mode that built the proof (sponge vs. the
    /// single-perm compression). The proof already self-verified inside the
    /// prover; this confirms the EXPOSED roots equal the additive Count-Min
    /// state under the selected node combiner.
    fn check_mode(
        proof: &CountMinCMerkleProof,
        initial: &CountMinState,
        batch: &[CountMinUpdate],
        compress: bool,
    ) {
        let rows = native_rows(initial, batch);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(proof.final_roots[i].0, merkle_root_mode(row, compress), "row {i} final root");
            assert_eq!(
                proof.initial_roots[i].0,
                merkle_root_mode(
                    &initial.counters[i].iter().map(|&c| c as u64).collect::<Vec<_>>(),
                    compress
                ),
                "row {i} initial root"
            );
        }
    }

    /// Minimal: one row, two records that REPEAT the same key. The per-record
    /// routing must re-merge both into the same cell (collision aggregation).
    #[test]
    fn c_merkle_min() {
        let params = CountMinCMerkleParams { d: 1, w: 16, batch: 2, t_max: 2, compress: false, group_by: false };
        let initial = state(1, 16, |_, j| (j * 3 + 1) as u32);
        let batch = vec![
            CountMinUpdate { key: 5, value: 1 },
            CountMinUpdate { key: 5, value: 1 },
        ];
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }

    /// d rows, repeated keys (4 records, 3 distinct keys). Exercises the
    /// per-record → per-cell re-aggregation: the repeated key's two records
    /// route to the same op and are summed.
    #[test]
    fn c_merkle_d_rows_distinct() {
        let params = CountMinCMerkleParams { d: 4, w: 16, batch: 4, t_max: 4, compress: false, group_by: false };
        let initial = state(4, 16, |_, _| 0);
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }

    /// Large width, repeated keys: rebind is Θ(t_max·d·log w); the PRF runs
    /// once per record (Θ(batch·d)) and collisions re-merge at the cell level.
    #[test]
    fn c_merkle_large_state_small_distinct() {
        let params = CountMinCMerkleParams { d: 4, w: 64, batch: 6, t_max: 4, compress: false, group_by: false };
        let initial = state(4, 64, |i, j| ((i * 7 + j) % 5) as u32);
        let batch: Vec<CountMinUpdate> = [123u64, 777, 123, 9, 777, 123]
            .iter()
            .map(|&k| CountMinUpdate { key: k, value: 2 })
            .collect();
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }

    /// **Tamper test.** A proof's per-row final roots are bound to the batch
    /// it was built for. Building the same shape over a DIFFERENT batch yields
    /// different final roots — a verifier checking the first leaf's public
    /// roots would reject the second proof (the Merkle rebind binds the
    /// committed state to the routed increments).
    #[test]
    fn c_merkle_tamper_rejected() {
        let params = CountMinCMerkleParams { d: 4, w: 16, batch: 4, t_max: 4, compress: false, group_by: false };
        let initial = state(4, 16, |_, _| 0);
        let honest_batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let tampered_batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 9 }).collect();

        let honest = prove_countmin_c_merkle_leaf(params, initial.clone(), honest_batch.clone());
        check(&honest, &initial, &honest_batch);
        let tampered = prove_countmin_c_merkle_leaf(params, initial.clone(), tampered_batch.clone());

        // Different batch values ⇒ different per-row final roots: the honest
        // leaf's public roots cannot be satisfied by the tampered increments.
        let any_diff = (0..params.d)
            .any(|i| honest.final_roots[i].0 != tampered.final_roots[i].0);
        assert!(any_diff, "tampering batch values must change the final roots");
    }

    // ── merkle_fast (compress: true) — same coverage as the sponge baseline ──

    /// `merkle_fast` minimal: one row, two records repeating a key. Routing must
    /// re-merge both into one cell; the compress climb must self-verify and the
    /// roots must equal the compress-mode native tree.
    #[test]
    fn c_merkle_fast_min() {
        let params = CountMinCMerkleParams { d: 1, w: 16, batch: 2, t_max: 2, compress: true, group_by: false };
        let initial = state(1, 16, |_, j| (j * 3 + 1) as u32);
        let batch = vec![
            CountMinUpdate { key: 5, value: 1 },
            CountMinUpdate { key: 5, value: 1 },
        ];
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check_mode(&proof, &initial, &batch, true);
    }

    /// `merkle_fast` d rows, repeated keys — the real Count-Min shape under the
    /// single-perm compression rebind.
    #[test]
    fn c_merkle_fast_d_rows_distinct() {
        let params = CountMinCMerkleParams { d: 4, w: 16, batch: 4, t_max: 4, compress: true, group_by: false };
        let initial = state(4, 16, |_, _| 0);
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check_mode(&proof, &initial, &batch, true);
    }

    /// `merkle_fast` large width, small distinct: Θ(t_max·d·log w) rebind with
    /// the compression node combiner.
    #[test]
    fn c_merkle_fast_large_state_small_distinct() {
        let params = CountMinCMerkleParams { d: 4, w: 64, batch: 6, t_max: 4, compress: true, group_by: false };
        let initial = state(4, 64, |i, j| ((i * 7 + j) % 5) as u32);
        let batch: Vec<CountMinUpdate> = [123u64, 777, 123, 9, 777, 123]
            .iter()
            .map(|&k| CountMinUpdate { key: k, value: 2 })
            .collect();
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check_mode(&proof, &initial, &batch, true);
    }

    /// `merkle_fast` tamper: tampering the batch values changes the compress-mode
    /// final roots, so the honest leaf's public roots reject the tampered proof.
    #[test]
    fn c_merkle_fast_tamper_rejected() {
        let params = CountMinCMerkleParams { d: 4, w: 16, batch: 4, t_max: 4, compress: true, group_by: false };
        let initial = state(4, 16, |_, _| 0);
        let honest_batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let tampered_batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 9 }).collect();

        let honest = prove_countmin_c_merkle_leaf(params, initial.clone(), honest_batch.clone());
        check_mode(&honest, &initial, &honest_batch, true);
        let tampered = prove_countmin_c_merkle_leaf(params, initial.clone(), tampered_batch.clone());

        let any_diff = (0..params.d)
            .any(|i| honest.final_roots[i].0 != tampered.final_roots[i].0);
        assert!(any_diff, "tampering batch values must change the merkle_fast final roots");
    }

    /// The two modes commit DIFFERENT roots for the same epoch (different node
    /// combiner), so a verifier pinned to one mode rejects the other. Confirms
    /// the variants are distinct, not accidentally identical.
    #[test]
    fn c_merkle_modes_produce_distinct_roots() {
        let base = CountMinCMerkleParams { d: 4, w: 16, batch: 4, t_max: 4, compress: false, group_by: false };
        let fast = CountMinCMerkleParams { compress: true, ..base };
        let initial = state(4, 16, |_, _| 0);
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let p_base = prove_countmin_c_merkle_leaf(base, initial.clone(), batch.clone());
        let p_fast = prove_countmin_c_merkle_leaf(fast, initial.clone(), batch.clone());
        check_mode(&p_base, &initial, &batch, false);
        check_mode(&p_fast, &initial, &batch, true);
        // Same batch commitment (binding the records is mode-independent)…
        assert_eq!(p_base.batch_commit.0, p_fast.batch_commit.0);
        // …but the per-row roots differ (sponge vs. compression node combiner).
        let any_diff =
            (0..base.d).any(|i| p_base.final_roots[i].0 != p_fast.final_roots[i].0);
        assert!(any_diff, "sponge and compress modes must commit different roots");
    }

    // ── merkle_gb (optimization (ii): group-by routing + global op-chain) ────

    /// `merkle_gb` minimal: one row, two records repeating a key. The group-by
    /// must re-merge both into one cell (collision summed); roots equal the
    /// compress-mode native tree.
    #[test]
    fn c_merkle_gb_min() {
        let params = CountMinCMerkleParams { d: 1, w: 16, batch: 2, t_max: 2, compress: true, group_by: true };
        let initial = state(1, 16, |_, j| (j * 3 + 1) as u32);
        let batch = vec![
            CountMinUpdate { key: 5, value: 1 },
            CountMinUpdate { key: 5, value: 1 },
        ];
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check_mode(&proof, &initial, &batch, true);
    }

    /// `merkle_gb` d rows, repeated keys — the real Count-Min shape. The global
    /// sorted op-chain threads d fixed blocks; the group-by sums collisions.
    #[test]
    fn c_merkle_gb_d_rows_distinct() {
        let params = CountMinCMerkleParams { d: 4, w: 16, batch: 4, t_max: 4, compress: true, group_by: true };
        let initial = state(4, 16, |_, _| 0);
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check_mode(&proof, &initial, &batch, true);
    }

    /// `merkle_gb` over a NON-TRIVIAL initial state + larger width. Confirms the
    /// op_old binding (= the committed initial cell value) and the per-block root
    /// threading against a non-empty starting tree.
    #[test]
    fn c_merkle_gb_large_state_nontrivial_init() {
        let params = CountMinCMerkleParams { d: 4, w: 64, batch: 6, t_max: 4, compress: true, group_by: true };
        let initial = state(4, 64, |i, j| ((i * 7 + j) % 5) as u32);
        let batch: Vec<CountMinUpdate> = [123u64, 777, 123, 9, 777, 123]
            .iter()
            .map(|&k| CountMinUpdate { key: k, value: 2 })
            .collect();
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check_mode(&proof, &initial, &batch, true);
    }

    /// `merkle_gb` REPEATED-KEYS collision test: many records collapse into a few
    /// cells; the running sum must total each cell's contribution exactly. The
    /// `check_mode` against the additive Count-Min validates the summation.
    #[test]
    fn c_merkle_gb_repeated_keys_summed() {
        let params = CountMinCMerkleParams { d: 2, w: 16, batch: 8, t_max: 8, compress: true, group_by: true };
        let initial = state(2, 16, |_, j| (j as u32) % 3);
        // Three distinct keys, each repeated; values vary to catch mis-summing.
        let batch: Vec<CountMinUpdate> = [
            (7u64, 1), (11, 2), (7, 3), (7, 4), (11, 5), (3, 6), (7, 7), (11, 8),
        ]
        .iter()
        .map(|&(k, v)| CountMinUpdate { key: k, value: v })
        .collect();
        let proof = prove_countmin_c_merkle_leaf(params, initial.clone(), batch.clone());
        check_mode(&proof, &initial, &batch, true);
    }

    /// **Tamper.** Tampering a batch value changes the compress-mode final roots,
    /// so an honest leaf's public roots reject the tampered `merkle_gb` proof.
    #[test]
    fn c_merkle_gb_tamper_rejected() {
        let params = CountMinCMerkleParams { d: 4, w: 16, batch: 4, t_max: 4, compress: true, group_by: true };
        let initial = state(4, 16, |_, _| 0);
        let honest_batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let tampered_batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 9 }).collect();

        let honest = prove_countmin_c_merkle_leaf(params, initial.clone(), honest_batch.clone());
        check_mode(&honest, &initial, &honest_batch, true);
        let tampered = prove_countmin_c_merkle_leaf(params, initial.clone(), tampered_batch.clone());

        let any_diff = (0..params.d)
            .any(|i| honest.final_roots[i].0 != tampered.final_roots[i].0);
        assert!(any_diff, "tampering batch values must change the merkle_gb final roots");
    }

    /// **THE EQUIVALENCE GATE.** `merkle_gb` (group-by routing) must commit the
    /// IDENTICAL per-row roots as `merkle_fast` (selector routing) for the same
    /// input — both use MyCompress nodes, so the rebind is a function of the
    /// state alone. Equal roots prove the group-by routing is semantically
    /// equivalent to the selector routing (only the in-circuit routing differs).
    /// The batch commitment is also identical (binding is routing-independent).
    #[test]
    fn c_merkle_gb_equals_merkle_fast_commitment() {
        let fast = CountMinCMerkleParams { d: 4, w: 16, batch: 6, t_max: 6, compress: true, group_by: false };
        let gb = CountMinCMerkleParams { group_by: true, ..fast };
        // Non-trivial initial state + repeated keys (exercise collision summing).
        let initial = state(4, 16, |i, j| ((i * 5 + j * 2) % 4) as u32);
        let batch: Vec<CountMinUpdate> = [
            (7u64, 3), (11, 1), (7, 2), (29, 4), (11, 5), (7, 1),
        ]
        .iter()
        .map(|&(k, v)| CountMinUpdate { key: k, value: v })
        .collect();
        let p_fast = prove_countmin_c_merkle_leaf(fast, initial.clone(), batch.clone());
        let p_gb = prove_countmin_c_merkle_leaf(gb, initial.clone(), batch.clone());
        check_mode(&p_fast, &initial, &batch, true);
        check_mode(&p_gb, &initial, &batch, true);
        // Same batch commitment.
        assert_eq!(p_fast.batch_commit.0, p_gb.batch_commit.0, "batch commit must match");
        // IDENTICAL per-row init AND final roots — the equivalence claim.
        for i in 0..fast.d {
            assert_eq!(
                p_fast.initial_roots[i].0, p_gb.initial_roots[i].0,
                "row {i} init root must match merkle_fast"
            );
            assert_eq!(
                p_fast.final_roots[i].0, p_gb.final_roots[i].0,
                "row {i} final root must match merkle_fast (group-by ≡ selector routing)"
            );
        }
    }
}
