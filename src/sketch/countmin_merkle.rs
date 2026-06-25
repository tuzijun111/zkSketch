//! **Count-Min sparse-rebind leaf with Merkle-root state commitments**
//! (plonky3 / STARK) — the §5.2 RQ2-c "sparse-opening commit" repair.
//!
//! The canonical flat-commit update leaf ([`super::countmin_final`]) and the
//! strawman leaf ([`crate::recursion::recursive::countmin_leaf`]) both commit
//! the state with a **flat** Poseidon2 sponge over all `d·w` cells, so every
//! rebind re-hashes the whole sketch and costs `Θ(d·w)`. Here each of the `d`
//! rows is committed by a **Merkle root** over its `w` cells, and the rebind
//! opens only the touched cells via a per-row **Merkle update chain**: thread
//! the row's root `r_0 = Com(row_{t-1}) → … → r_T = Com(row_t)` through
//! `t_max` single-leaf ops, each verifying the **old** value against `r_{c-1}`
//! and the **new** value against `r_c` along the **same** sibling path.
//! Untouched cells never appear (they carry through the shared siblings), so a
//! rebind is `Θ(T·log w)` per row — `Θ(distinct·d·log w)` overall, **independent
//! of `w`**. The flat-commit leaves remain the baseline for comparison.
//!
//! ## d rows, d independent trees
//! A Count-Min sketch has `d` rows of `w` counters with independent row hashes
//! `h_i(key) = Poseidon2(key)[i] mod w`. Each row is its own perfect binary
//! Merkle tree of `w` leaves (`w` is a power of two), with its own root pair of
//! public inputs. A record touches one cell per row (`d` cells total); the
//! per-row op lists and update chains are otherwise identical to a single row.
//! `Com(S)` is therefore the `d`-tuple of row roots (each `[Val; 8]`).
//!
//! ## Soundness sketch
//! - **Batch opened (S1):** `Com(B_t)` (a Poseidon2 sponge over the
//!   `(key, value)` records) binds the witnessed records.
//! - **Routing (S2):** each record's per-row cell `pos_i = Poseidon2(key)[i] mod
//!   w` is derived in-circuit; a one-hot selector maps each `(record, row)` to
//!   an *active* patch op whose position equals that `pos_i`.
//! - **Aggregate (S3):** `new_c = old_c + Σ_{records→c} value`.
//! - **Rebind (S5):** the in-circuit Merkle path gadget ties `old_c`/`new_c`
//!   to `r_{c-1}`/`r_c` along one shared path, per row; untouched cells are
//!   unchanged because only the touched leaf moves.
//!
//! ## The in-circuit Merkle gadget
//! Built from `add_hash_slice` (= the canonical `MyHash` sponge, so the native
//! [`merkle_root`] matches bit-for-bit). See [`climb_merkle_path`].

use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, Poseidon2PermCall, generate_poseidon2_trace, generate_recompose_trace,
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
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::hash_cell_prf;

const LOG_FINAL_POLY_LEN: usize = 6;
/// Range-check window for the aggregate counters. Counts fit comfortably below
/// `2^p` at prototype scale; a sound non-wrap check.
const COUNT_BITS: usize = 24;

// ─── Parameters ────────────────────────────────────────────────────────────

/// Shape of a sparse-rebind Count-Min leaf: `d` rows of `w` counters, `batch`
/// records per epoch, capacity `t_max` for distinct touched cells **per row**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountMinMerkleParams {
    /// Number of sketch rows (independent Merkle trees). `1 ≤ d ≤ 8` (the PRF
    /// digest has 8 `Val` elements; row `i` muxes to the i-th).
    pub d: usize,
    /// Counters per row. A power of two `≥ 2` (each row tree is perfect).
    pub w: usize,
    /// Records per epoch.
    pub batch: usize,
    /// Compile-time bound on distinct touched cells **per row** (`1 ≤ t_max ≤ w`).
    pub t_max: usize,
}

impl CountMinMerkleParams {
    pub fn validate(&self) {
        assert!(self.d >= 1 && self.d <= 8, "d must be in 1..=8, got {}", self.d);
        assert!(self.w.is_power_of_two() && self.w >= 2, "w must be a power of two ≥ 2");
        assert!(self.batch >= 1, "batch must be positive");
        assert!(self.t_max >= 1 && self.t_max <= self.w, "t_max in [1, w]");
    }
    /// Per-row Merkle tree height = `log2(w)`.
    pub fn height(&self) -> usize {
        self.w.trailing_zeros() as usize
    }
}

// ─── Native hashing (must match the in-circuit gadget bit-for-bit) ──────────

/// Native leaf digest of a cell value: `MyHash(v, 0, 0, 0)` → `[Val; 8]`.
/// Mirrors the in-circuit `add_hash_slice(cfg, &[v_challenge], true)`.
pub fn leaf_digest(v: u64) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let input = [Val::from_u64(v), Val::ZERO, Val::ZERO, Val::ZERO];
    hasher.hash_iter(input.iter().copied())
}

/// Native node digest of two child digests `[Val; 8]` (left then right).
/// Mirrors `add_hash_slice(cfg, &[l0, l1, r0, r1], true)`.
pub fn node_digest(left: &[Val; 8], right: &[Val; 8]) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let input: Vec<Val> = left.iter().chain(right.iter()).copied().collect();
    hasher.hash_iter(input.iter().copied())
}

/// Native node digest in **compress** mode: a single 2:1 Poseidon2
/// `MyCompress = TruncatedPermutation<Perm, 2, 8, 16>::compress([left, right])`.
/// This is the native counterpart of the Merkle-mode `add_poseidon2_perm` op
/// used by [`climb_merkle_path_compress`] — ONE permutation per internal node
/// (vs. the padding-free sponge's two in [`node_digest`]).
pub fn node_digest_compress(left: &[Val; 8], right: &[Val; 8]) -> [Val; 8] {
    use p3_symmetric::PseudoCompressionFunction;
    let c = crate::config::MyCompress::new(make_perm());
    c.compress([*left, *right])
}

/// Native climb step in compress mode: combine the current digest with its
/// sibling, ordered by the direction bit. `bit == 1` means the current node is
/// the RIGHT child (sibling on the left), matching the in-circuit
/// `apply_merkle_swap` (which swaps rate↔capacity iff bit==1). Equals the
/// parent's `node_digest_compress([left, right])` because the swap reproduces
/// the child order.
pub fn node_climb_compress(cur: &[Val; 8], sib: &[Val; 8], bit: bool) -> [Val; 8] {
    if bit { node_digest_compress(sib, cur) } else { node_digest_compress(cur, sib) }
}

/// Merkle root over a row of `w` counter cells. `cells[i]` is a single-cell
/// leaf; the tree is a perfect binary tree of `height = log2(w)` levels.
///
/// `compress` selects the internal-node combiner: `false` = the padding-free
/// sponge ([`node_digest`], the `merkle` baseline); `true` = the single-perm
/// 2:1 compression ([`node_digest_compress`], the `merkle_fast` variant). The
/// LEAF combiner ([`leaf_digest`]) is the sponge in both modes.
pub fn merkle_root_mode(cells: &[u64], compress: bool) -> [Val; 8] {
    assert!(cells.len().is_power_of_two() && !cells.is_empty());
    let combine = |l: &[Val; 8], r: &[Val; 8]| {
        if compress { node_digest_compress(l, r) } else { node_digest(l, r) }
    };
    let mut level: Vec<[Val; 8]> = cells.iter().map(|&c| leaf_digest(c)).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|pair| combine(&pair[0], &pair[1])).collect();
    }
    level[0]
}

/// Merkle root over a row of `w` counter cells (sponge baseline). Equivalent to
/// [`merkle_root_mode`] with `compress = false`.
pub fn merkle_root(cells: &[u64]) -> [Val; 8] {
    merkle_root_mode(cells, false)
}

/// Sibling digests along the path from `pos` to the root, level 0 (leaves)
/// first. Length `= height`. `compress` selects the internal-node combiner
/// (see [`merkle_root_mode`]).
pub(crate) fn merkle_siblings_mode(cells: &[u64], pos: usize, compress: bool) -> Vec<[Val; 8]> {
    let combine = |l: &[Val; 8], r: &[Val; 8]| {
        if compress { node_digest_compress(l, r) } else { node_digest(l, r) }
    };
    let height = cells.len().trailing_zeros() as usize;
    let mut level: Vec<[Val; 8]> = cells.iter().map(|&c| leaf_digest(c)).collect();
    let mut idx = pos;
    let mut sibs = Vec::with_capacity(height);
    for _ in 0..height {
        let sib = idx ^ 1;
        sibs.push(level[sib]);
        idx >>= 1;
        level = level.chunks(2).map(|pair| combine(&pair[0], &pair[1])).collect();
    }
    sibs
}

/// Combine `d` per-row roots into one state commitment: the single root when
/// `d = 1`, else `Poseidon2(r_0 ‖ … ‖ r_{d-1})`. This is the boundary id the
/// recursive merge ([`crate::recursion::recursive::countmin_merge_merkle`])
/// folds into its chain digest.
pub fn combined_commit(roots: &[CountMinCommit]) -> CountMinCommit {
    if roots.len() == 1 {
        return roots[0];
    }
    let hasher = MyHash::new(make_perm());
    let flat: Vec<Val> = roots.iter().flat_map(|r| r.0).collect();
    CountMinCommit(hasher.hash_iter(flat.iter().copied()))
}

/// Pack an 8-Val digest into 2 Challenges (the DIGEST_PACKING shape).
pub(crate) fn pack_digest(d: &[Val; 8]) -> [Challenge; 2] {
    [
        Challenge::from_basis_coefficients_slice(&d[0..4]).expect("4 coeffs"),
        Challenge::from_basis_coefficients_slice(&d[4..8]).expect("4 coeffs"),
    ]
}

// ─── Public proof type ──────────────────────────────────────────────────────

/// A self-verified sparse-rebind leaf proof. `output` is the batch-STARK proof;
/// `initial_roots`/`final_roots` are the `d` per-row Merkle-root state
/// commitments it binds (`Com(S)` is the tuple of row roots).
pub struct CountMinMerkleProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_roots: Vec<CountMinCommit>,
    pub final_roots: Vec<CountMinCommit>,
    pub batch_commit: CountMinCommit,
    pub params: CountMinMerkleParams,
}

impl CountMinMerkleProof {
    /// Serialized proof size in bytes (postcard, matching the E-suite metric).
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

// ─── Native per-row update plan ─────────────────────────────────────────────

/// Per-row witnessed op data: distinct touched cells (first-touch order),
/// per-op (old, new, active, position, sibling path), and the intermediate
/// roots `r_0=init … r_t_max=final`.
pub(crate) struct RowPlan {
    pub(crate) record_op: Vec<usize>,  // m: which op each record routes to in this row
    pub(crate) op_old: Vec<u64>,       // t_max
    pub(crate) op_new: Vec<u64>,       // t_max
    pub(crate) op_active: Vec<u64>,    // t_max
    pub(crate) op_used_pos: Vec<usize>,// t_max
    pub(crate) op_siblings: Vec<Vec<[Val; 8]>>, // t_max × height
    pub(crate) init_root: [Val; 8],
    pub(crate) final_root: [Val; 8],
}

/// Build a per-row update plan with the sponge Merkle combiner (the baseline).
/// Equivalent to [`build_row_plan_mode`] with `compress = false`.
pub(crate) fn build_row_plan(
    row: usize,
    cells_in: &[u64],
    batch: &[CountMinUpdate],
    w: usize,
    t_max: usize,
) -> RowPlan {
    build_row_plan_mode(row, cells_in, batch, w, t_max, false)
}

/// Build a per-row update plan. `compress` selects the internal-node combiner
/// for the native roots/siblings: `false` = sponge ([`node_digest`], the
/// `merkle` baseline), `true` = single-perm compression
/// ([`node_digest_compress`], the `merkle_fast` variant). The routing,
/// op-chain, and position logic are identical in both modes; only the native
/// `init_root`/`final_root`/`op_siblings` digests differ.
pub(crate) fn build_row_plan_mode(
    row: usize,
    cells_in: &[u64],
    batch: &[CountMinUpdate],
    w: usize,
    t_max: usize,
    compress: bool,
) -> RowPlan {
    let m = batch.len();
    let mut cells: Vec<u64> = cells_in.to_vec();
    // Route records to distinct touched cells (first-touch order).
    let mut op_pos: Vec<usize> = Vec::new();
    let mut record_op = vec![0usize; m];
    for (k, u) in batch.iter().enumerate() {
        let p = hash_cell_prf(row, u.key, w);
        let c = op_pos.iter().position(|&q| q == p).unwrap_or_else(|| {
            op_pos.push(p);
            op_pos.len() - 1
        });
        record_op[k] = c;
    }
    assert!(
        op_pos.len() <= t_max,
        "row {row}: touched cells {} exceed t_max {}",
        op_pos.len(),
        t_max
    );

    let init_root = merkle_root_mode(&cells, compress);
    let mut op_old = vec![0u64; t_max];
    let mut op_new = vec![0u64; t_max];
    let mut op_active = vec![0u64; t_max];
    let mut op_used_pos = vec![0usize; t_max];
    let mut op_siblings: Vec<Vec<[Val; 8]>> = Vec::with_capacity(t_max);
    let mut snap: Vec<u64> = cells.clone();
    for c in 0..t_max {
        let (pos, inc, active) = if c < op_pos.len() {
            let pos = op_pos[c];
            let inc: u64 = batch
                .iter()
                .enumerate()
                .filter(|(k, _)| record_op[*k] == c)
                .map(|(_, u)| u.value as u64)
                .sum();
            (pos, inc, 1u64)
        } else {
            (0usize, 0u64, 0u64)
        };
        op_used_pos[c] = pos;
        op_old[c] = cells[pos];
        op_new[c] = cells[pos] + inc;
        op_active[c] = active;
        op_siblings.push(merkle_siblings_mode(&snap, pos, compress));
        snap[pos] = op_new[c];
        cells[pos] = op_new[c];
    }
    let final_root = merkle_root_mode(&cells, compress);

    RowPlan { record_op, op_old, op_new, op_active, op_used_pos, op_siblings, init_root, final_root }
}

// ─── Prover ──────────────────────────────────────────────────────────────────

/// Prove one sparse-rebind epoch over a `d × w` Count-Min state.
///
/// `initial` is the starting state; `batch` is `params.batch` records. The
/// number of distinct touched cells in any row must be `≤ params.t_max`.
/// Records the witness/prove/verify split via
/// [`crate::recursion::recursive::timing`].
///
/// # Panics
/// - `params.validate()` failures.
/// - `initial.params != (params.d, params.w)` or `batch.len() != params.batch`.
/// - more than `params.t_max` distinct touched cells in some row.
pub fn prove_countmin_merkle_leaf(
    params: CountMinMerkleParams,
    initial: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinMerkleProof {
    params.validate();
    let CountMinMerkleParams { d, w, batch: m, t_max } = params;
    assert_eq!(initial.params.d, d, "state.d / params.d mismatch");
    assert_eq!(initial.params.w, w, "state.w / params.w mismatch");
    assert_eq!(batch.len(), m, "batch.len() != params.batch");
    let h = params.height();
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;

    // ─── Native side: per-row update plans ───────────────────────────────────
    let plans: Vec<RowPlan> = (0..d)
        .map(|i| {
            let cells_in: Vec<u64> = initial.counters[i].iter().map(|&c| c as u64).collect();
            build_row_plan(i, &cells_in, &batch, w, t_max)
        })
        .collect();

    // Batch commitment over interleaved (key, value) — each field absorbed as
    // one Challenge (payload in coeff 0), matching the in-circuit `add_hash_slice`.
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
    let pow2: Vec<ExprId> =
        (0..h).map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j")).collect();

    // ── Private witnesses (allocation order MUST match the value-push order) ──
    // The key is fed only to Poseidon2 absorbs; build it from a base coefficient
    // via `recompose_base_coeffs_to_ext_via_alu` so it gets a WitnessChecks bus
    // creator (a raw private input fed only to a hash would have none).
    let key_coeff: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_coeff")).collect();
    let keys: Vec<ExprId> = (0..m)
        .map(|k| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_coeff[k], zero, zero, zero])
                .expect("recompose key")
        })
        .collect();
    let values: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("value")).collect();
    // h0/h1: the two-Challenge digest of each key, bound to the in-circuit hash.
    let key_h0: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_h0")).collect();
    let key_h1: Vec<ExprId> = (0..m).map(|_| b.alloc_private_input("key_h1")).collect();
    // Per-row: sel[i][k][c], op_old/new/active[i][c], pos_bits[i][c][j], sib[i][c][j].
    let sel: Vec<Vec<Vec<ExprId>>> = (0..d)
        .map(|_| (0..m).map(|_| (0..t_max).map(|_| b.alloc_private_input("sel")).collect()).collect())
        .collect();
    let op_old_w: Vec<Vec<ExprId>> = (0..d)
        .map(|_| (0..t_max).map(|_| b.alloc_private_input("op_old")).collect())
        .collect();
    let op_new_w: Vec<Vec<ExprId>> = (0..d)
        .map(|_| (0..t_max).map(|_| b.alloc_private_input("op_new")).collect())
        .collect();
    let op_active_w: Vec<Vec<ExprId>> = (0..d)
        .map(|_| (0..t_max).map(|_| b.alloc_private_input("op_active")).collect())
        .collect();
    let op_pos_bits: Vec<Vec<Vec<ExprId>>> = (0..d)
        .map(|_| {
            (0..t_max)
                .map(|_| (0..h).map(|_| b.alloc_private_input("op_pos_bit")).collect())
                .collect()
        })
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

    // op_active boolean + per-op position value from its bits (per row).
    let mut op_pos_val: Vec<Vec<ExprId>> = Vec::with_capacity(d);
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
        op_pos_val.push(row_vals);
    }

    // ── S2: derive each record's per-row cell pos = Poseidon2(key)[i] mod w ───
    for k in 0..m {
        let hashed = b.add_hash_slice(&cfg, &[keys[k]], true).expect("hash key");
        b.connect(hashed[0], key_h0[k]);
        b.connect(hashed[1], key_h1[k]);
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(key_h0[k]).expect("decompose h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(key_h1[k]).expect("decompose h1");
        // Digest element `i` is coeff `i` of (c0 ++ c1). Decompose every element
        // to bits (creator + range check); rows 0..d also extract a position.
        for elem in 0..8 {
            let coeff = if elem < 4 { c0[elem] } else { c1[elem - 4] };
            let bits = b.decompose_to_bits::<Val>(coeff, Val::bits()).expect("bits");
            if elem < d {
                let mut pos = zero;
                for j in 0..h {
                    pos = b.mul_add(bits[j], pow2[j], pos);
                }
                // Route record k in row `elem`: one-hot sel over ops.
                let mut sum = zero;
                let mut routed_pos = zero;
                let mut routed_active = zero;
                for c in 0..t_max {
                    let s = sel[elem][k][c];
                    let sm1 = b.sub(s, one);
                    let chk = b.mul(s, sm1);
                    b.connect(chk, zero);
                    sum = b.add(sum, s);
                    routed_pos = b.mul_add(s, op_pos_val[elem][c], routed_pos);
                    routed_active = b.mul_add(s, op_active_w[elem][c], routed_active);
                }
                b.connect(sum, one);
                b.connect(routed_pos, pos);
                b.connect(routed_active, one);
            }
        }
    }

    // ── S3: per-op increment = Σ routed values; new = old + increment ────────
    for i in 0..d {
        for c in 0..t_max {
            let mut inc = zero;
            for k in 0..m {
                inc = b.mul_add(sel[i][k][c], values[k], inc);
            }
            let expect_new = b.add(op_old_w[i][c], inc);
            // `op_new_w` is created on the bus by this connect to the ALU output.
            b.connect(op_new_w[i][c], expect_new);
            let _ = b.decompose_to_bits::<Val>(op_new_w[i][c], COUNT_BITS).expect("op_new >= 0");
            let _ = b.decompose_to_bits::<Val>(op_old_w[i][c], COUNT_BITS).expect("op_old >= 0");
        }
    }

    // ── S5: per-row Merkle update chain r_0=init → r_t_max=final ──────────────
    // Thread roots as NPO `ExprId`s (no private-input intermediate roots). The
    // OLD value opens to the incoming root; the NEW value's climb is the next
    // incoming root. Equality against a *previous op's* root (itself an NPO
    // output) is asserted via subtraction — connecting two NPO outputs is
    // unbalanced on the WitnessChecks bus, but connecting an NPO output to a
    // public input (the init/final roots) is fine.
    for i in 0..d {
        let mut prev_root: [ExprId; 2] = init_root_pis[i];
        for c in 0..t_max {
            let old_root = climb_merkle_path(&mut b, &cfg, op_old_w[i][c], &op_pos_bits[i][c], &op_sib[i][c]);
            if c == 0 {
                b.connect(old_root[0], prev_root[0]);
                b.connect(old_root[1], prev_root[1]);
            } else {
                for l in 0..2 {
                    let diff = b.sub(old_root[l], prev_root[l]);
                    b.connect(diff, zero);
                }
            }
            let new_root = climb_merkle_path(&mut b, &cfg, op_new_w[i][c], &op_pos_bits[i][c], &op_sib[i][c]);
            prev_root = new_root;
        }
        b.connect(prev_root[0], final_root_pis[i][0]);
        b.connect(prev_root[1], final_root_pis[i][1]);
    }

    let circuit = b.build().expect("build cm merkle leaf circuit");

    // ─── Pack public + private values (same order as allocation) ─────────────
    let mut public_inputs: Vec<Challenge> = Vec::new();
    for plan in &plans {
        public_inputs.extend_from_slice(&pack_digest(&plan.init_root));
    }
    for plan in &plans {
        public_inputs.extend_from_slice(&pack_digest(&plan.final_root));
    }
    public_inputs.extend_from_slice(&pack_digest(&batch_commit));

    let mut private_inputs: Vec<Challenge> = Vec::new();
    // key_coeff (= key mod p), values.
    for u in &batch {
        private_inputs.push(Challenge::from_u64(u.key));
    }
    for u in &batch {
        private_inputs.push(Challenge::from_u32(u.value));
    }
    // key_h0 block then key_h1 block.
    {
        let hasher = MyHash::new(make_perm());
        let digests: Vec<[Challenge; 2]> = batch
            .iter()
            .map(|u| {
                let input = [Val::from_u64(u.key), Val::ZERO, Val::ZERO, Val::ZERO];
                let digest: [Val; 8] = hasher.hash_iter(input.iter().copied());
                pack_digest(&digest)
            })
            .collect();
        for dgt in &digests {
            private_inputs.push(dgt[0]);
        }
        for dgt in &digests {
            private_inputs.push(dgt[1]);
        }
    }
    // sel[i][k][c].
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
    // op_old[i][c], op_new[i][c], op_active[i][c].
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
        runner.run().expect("run cm merkle circuit")
    };
    let __witness = __t_w.elapsed();

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let preprocessors =
        vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false)];
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
        .expect("get_airs_and_degrees_with_prep (cm merkle)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&dd| dd + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    let __t_p = std::time::Instant::now();
    let proof =
        prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove cm merkle");
    let __prove = __t_p.elapsed();
    let __t_v = std::time::Instant::now();
    prover.verify_all_tables(&proof).expect("self-verify cm merkle leaf");
    crate::recursion::recursive::timing::record(crate::recursion::recursive::timing::LeafTiming {
        witness: __witness,
        prove: __prove,
        verify: __t_v.elapsed(),
        trace_rows: ext_degrees.iter().map(|&dd| 1u64 << dd).sum(),
    });

    let _ = pack_commit_to_challenge;

    CountMinMerkleProof {
        output: RecursionOutput(proof, Rc::new(circuit_prover_data)),
        initial_roots: plans.iter().map(|p| CountMinCommit(p.init_root)).collect(),
        final_roots: plans.iter().map(|p| CountMinCommit(p.final_root)).collect(),
        batch_commit: CountMinCommit(batch_commit),
        params,
    }
}

// ─── In-circuit Merkle path gadget ──────────────────────────────────────────

/// Climb the Merkle path from a cell value to the root and RETURN the computed
/// root digest (2 Challenges). `cur` starts as the leaf digest and climbs: at
/// each level the (current, sibling) pair is bit-swapped into (lo, hi) order and
/// re-hashed. The bit-select is written so the *sibling* private input is bus-
/// created: `d = sub(cur, sib)` uses the already-created `cur` (an NPO output)
/// as the minuend, so `sib` is operand `a` (its creator) and the result is also
/// created (the output `cur` is already defined). Both children differ only by
/// `d`: `lo = cur − bit·d` (= cur + bit·(sib−cur)), `hi = sib + bit·d`.
pub(crate) fn climb_merkle_path(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    leaf_val: ExprId,
    pos_bits: &[ExprId],
    siblings: &[[ExprId; 2]],
) -> [ExprId; 2] {
    let leaf_d = b.add_hash_slice(cfg, &[leaf_val], true).expect("leaf hash");
    let mut cur: [ExprId; 2] = [leaf_d[0], leaf_d[1]];
    for (level, sib) in siblings.iter().enumerate() {
        let bit = pos_bits[level];
        let mut lo = [cur[0]; 2];
        let mut hi = [cur[0]; 2];
        for limb in 0..2 {
            let d = b.sub(cur[limb], sib[limb]); // cur − sib
            let bit_d = b.mul(bit, d); // bit·d
            lo[limb] = b.sub(cur[limb], bit_d); // cur − bit·d
            hi[limb] = b.mul_add(bit, d, sib[limb]); // sib + bit·d
        }
        let parent = b
            .add_hash_slice(cfg, &[lo[0], lo[1], hi[0], hi[1]], true)
            .expect("node hash");
        cur = [parent[0], parent[1]];
    }
    cur
}

/// Climb the Merkle path in **compress** mode and RETURN the computed root
/// digest (2 Challenges). Drop-in replacement for [`climb_merkle_path`] with
/// the same signature; the leaf digest is still the sponge
/// (`add_hash_slice(&[leaf_val])`), but each internal node is a SINGLE
/// Poseidon2 permutation in Merkle mode (`add_poseidon2_perm`), not the
/// two-permutation sponge.
///
/// Per level, given `running` (current digest, rate) and `sib` (sibling
/// digest, capacity), the Merkle-mode AIR fills capacity with the CTL-bound
/// sibling, swaps rate↔capacity iff `bit == 1` (FREE — no per-level bit-select
/// ALU ops), then permutes; the rate output is the parent digest. This:
/// 1. removes the per-level `sub`/`mul`/`mul_add` bit-select ALU work, and
/// 2. uses 1 permutation/level instead of 2.
///
/// Soundness: `sib` is the SAME CTL-bound `ExprId` the sponge climb consumes
/// (kept as a private CTL input, NOT moved to perm-private-data), so the two
/// climbs share the sibling binding. The 2 rate outputs are CTL-verified
/// (`out_ctl = [true, true]`) = the parent digest threaded into the next level.
/// `bit` must already be boolean-checked by the caller.
///
/// Native match: equals [`node_climb_compress`] = `MyCompress::compress` of
/// `(cur, sib)` ordered by `bit` (bit==1 ⇒ current is the right child), so a
/// tree built with [`merkle_root_mode`]`(.., true)` reconstructs bit-for-bit.
pub(crate) fn climb_merkle_path_compress(
    b: &mut CircuitBuilder<Challenge>,
    cfg: &Poseidon2Config,
    leaf_val: ExprId,
    pos_bits: &[ExprId],
    siblings: &[[ExprId; 2]],
) -> [ExprId; 2] {
    let leaf_d = b.add_hash_slice(cfg, &[leaf_val], true).expect("leaf hash");
    let mut cur: [ExprId; 2] = [leaf_d[0], leaf_d[1]];
    for (level, sib) in siblings.iter().enumerate() {
        let bit = pos_bits[level];
        // rate = running digest, capacity = sibling digest; all CTL-bound. The
        // AIR swaps rate↔capacity by `bit` (free) before permuting.
        let call = Poseidon2PermCall {
            config: Poseidon2Config::BABY_BEAR_D4_W16,
            new_start: true, // each level is an independent permutation; thread `cur` explicitly
            merkle_path: true,
            mmcs_bit: Some(bit),
            inputs: vec![Some(cur[0]), Some(cur[1]), Some(sib[0]), Some(sib[1])],
            out_ctl: vec![true, true], // rate outputs CTL-verified = parent digest
            return_all_outputs: false,
            mmcs_index_sum: None,
        };
        let (_op_id, outputs) =
            b.add_poseidon2_perm(&call).expect("merkle compress level");
        cur = [
            outputs[0].expect("compress rate0"),
            outputs[1].expect("compress rate1"),
        ];
    }
    cur
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::countmin::CountMinParams;

    /// Native d×w state evolution under `apply_update_prf` semantics, returning
    /// the per-row updated cells (for comparing against the proof's row roots).
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

    fn check(proof: &CountMinMerkleProof, initial: &CountMinState, batch: &[CountMinUpdate]) {
        let rows = native_rows(initial, batch);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(proof.final_roots[i].0, merkle_root(row), "row {i} final root");
            assert_eq!(
                proof.initial_roots[i].0,
                merkle_root(&initial.counters[i].iter().map(|&c| c as u64).collect::<Vec<_>>()),
                "row {i} initial root"
            );
        }
    }

    /// Native sanity: a node digest of two leaf digests matches re-hashing the
    /// concatenated child Vals.
    #[test]
    fn native_node_matches_concat() {
        let l = leaf_digest(3);
        let r = leaf_digest(7);
        let n = node_digest(&l, &r);
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = l.iter().chain(r.iter()).copied().collect();
        let expect: [Val; 8] = hasher.hash_iter(flat.iter().copied());
        assert_eq!(n, expect);
    }

    /// Native sanity: the compress-mode node combiner is a single
    /// `MyCompress::compress`, and the climb step orders children by the bit.
    #[test]
    fn native_compress_node_and_climb() {
        let l = leaf_digest(3);
        let r = leaf_digest(7);
        // climb with bit=0: current=l is left child, sibling=r on the right.
        assert_eq!(node_climb_compress(&l, &r, false), node_digest_compress(&l, &r));
        // climb with bit=1: current=l is right child, sibling=r on the left.
        assert_eq!(node_climb_compress(&l, &r, true), node_digest_compress(&r, &l));
        // compress is NOT the sponge node digest (different node combiner).
        assert_ne!(node_digest_compress(&l, &r), node_digest(&l, &r));
    }

    /// **Standalone gadget de-risk** (run BEFORE integration): build a tiny
    /// circuit that sponges a leaf value, climbs `h` levels with
    /// [`climb_merkle_path_compress`] against CTL sibling private-inputs + bit
    /// private-inputs, connects the final running digest to a public-input root
    /// computed NATIVELY via [`leaf_digest`] + [`node_climb_compress`], then
    /// proves + self-verifies. If native != in-circuit, self-verify FAILS.
    ///
    /// This isolates the native-match / swap-convention risk of the new gadget
    /// from the full `c_merkle` leaf integration.
    fn gadget_climb_compress_once(leaf_val: u64, pos: usize, h: usize, sib_cells: &[u64]) {
        use p3_baby_bear::default_babybear_poseidon2_16;
        use p3_batch_stark::ProverData;
        use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
        use p3_circuit::CircuitBuilder;
        use p3_circuit_prover::{
            BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
            batch_stark_prover::{
                poseidon2_air_builders_d4, poseidon2_preprocessor, recompose_air_builders,
                recompose_preprocessor,
            },
            common::get_airs_and_degrees_with_prep,
        };
        use p3_poseidon2_circuit_air::BabyBearD4Width16;
        use p3_uni_stark::StarkGenericConfig;

        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        assert_eq!(sib_cells.len(), h, "one sibling digest per level");

        // ── Native expected root: leaf sponge, then climb compress per level ──
        let mut native_cur = leaf_digest(leaf_val);
        for level in 0..h {
            let bit = (pos >> level) & 1 == 1;
            let sib = leaf_digest(sib_cells[level]); // sibling = a leaf digest
            native_cur = node_climb_compress(&native_cur, &sib, bit);
        }
        let root_pi_vals = pack_digest(&native_cur);

        // ── Build the circuit ────────────────────────────────────────────────
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);

        let root_pis: [ExprId; 2] = std::array::from_fn(|i| {
            b.alloc_public_input(if i == 0 { "root_lo" } else { "root_hi" })
        });
        let zero = b.alloc_const(Challenge::ZERO, "zero");

        // leaf value fed only to a hash → recompose it for a bus creator.
        let leaf_coeff = b.alloc_private_input("leaf_coeff");
        let leaf_x = b
            .recompose_base_coeffs_to_ext_via_alu::<Val>(&[leaf_coeff, zero, zero, zero])
            .expect("recompose leaf");

        // direction bits (boolean-checked) + sibling CTL private inputs.
        let pos_bits: Vec<ExprId> = (0..h).map(|_| b.alloc_private_input("bit")).collect();
        let one = b.alloc_const(Challenge::ONE, "one");
        for &bit in &pos_bits {
            let bm1 = b.sub(bit, one);
            let chk = b.mul(bit, bm1);
            b.connect(chk, zero);
        }
        let siblings: Vec<[ExprId; 2]> = (0..h)
            .map(|_| [b.alloc_private_input("sib_lo"), b.alloc_private_input("sib_hi")])
            .collect();

        let root = climb_merkle_path_compress(&mut b, &cfg, leaf_x, &pos_bits, &siblings);
        b.connect(root[0], root_pis[0]);
        b.connect(root[1], root_pis[1]);

        let circuit = b.build().expect("build gadget circuit");

        // ── Public + private values (allocation order) ───────────────────────
        let public_inputs: Vec<Challenge> = root_pi_vals.to_vec();
        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.push(Challenge::from_u64(leaf_val)); // leaf_coeff
        for level in 0..h {
            let bit = (pos >> level) & 1;
            private_inputs.push(if bit == 1 { Challenge::ONE } else { Challenge::ZERO });
        }
        for level in 0..h {
            let [lo, hi] = pack_digest(&leaf_digest(sib_cells[level]));
            private_inputs.push(lo);
            private_inputs.push(hi);
        }

        // ── Run + prove + self-verify ────────────────────────────────────────
        let traces = {
            let mut runner = circuit.runner();
            runner.set_public_inputs(&public_inputs).expect("set_public_inputs");
            runner.set_private_inputs(&private_inputs).expect("set_private_inputs");
            runner.run().expect("run gadget circuit")
        };

        let config = make_leaf_config();
        let table_packing =
            TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let preprocessors =
            vec![poseidon2_preprocessor::<Val>(), recompose_preprocessor::<Val>(false)];
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
            .expect("get_airs_and_degrees_with_prep (gadget)");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext_degrees: Vec<usize> = degrees.iter().map(|&dd| dd + config.is_zk()).collect();
        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let circuit_prover_data =
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

        let mut prover =
            BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
        prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
        let proof =
            prover.prove_all_tables(&traces, &circuit_prover_data).expect("prove gadget");
        prover.verify_all_tables(&proof).expect("self-verify gadget (native match)");
    }

    /// Gadget de-risk across several positions/heights. Self-verify passing
    /// proves the in-circuit compress climb matches the native one bit-for-bit.
    #[test]
    fn climb_compress_gadget_matches_native() {
        // h=2 levels, leaf at each position 0..4 with distinct siblings.
        for pos in 0..4usize {
            gadget_climb_compress_once(42, pos, 2, &[7, 13]);
        }
        // h=3 levels, exercise the high bit (bit=1 at top).
        gadget_climb_compress_once(100, 0b101, 3, &[3, 9, 21]);
        gadget_climb_compress_once(100, 0b010, 3, &[3, 9, 21]);
    }

    /// Minimal repro: single row, single op, one Merkle level.
    #[test]
    fn merkle_min() {
        let params = CountMinMerkleParams { d: 1, w: 16, batch: 1, t_max: 1 };
        let initial = state(1, 16, |_, j| (j * 3 + 1) as u32);
        let batch = vec![CountMinUpdate { key: 1, value: 1 }];
        let proof = prove_countmin_merkle_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }

    /// d rows, multi-op: the real Count-Min shape. Each key touches one cell per
    /// row; per-row trees are updated independently.
    #[test]
    fn merkle_d_rows_round_trip() {
        let params = CountMinMerkleParams { d: 4, w: 16, batch: 4, t_max: 4 };
        let initial = state(4, 16, |_, _| 0);
        let batch: Vec<CountMinUpdate> =
            [7u64, 11, 7, 3].iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
        let proof = prove_countmin_merkle_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }

    /// Large width, tiny batch: still touches ≤ t_max cells per row — the point
    /// of the sparse rebind (cost Θ(t_max·d·log w), not Θ(d·w)).
    #[test]
    fn merkle_large_state_small_patch() {
        let params = CountMinMerkleParams { d: 4, w: 64, batch: 4, t_max: 4 };
        let initial = state(4, 64, |i, j| ((i * 7 + j) % 5) as u32);
        let batch: Vec<CountMinUpdate> =
            [123u64, 777, 123, 9].iter().map(|&k| CountMinUpdate { key: k, value: 2 }).collect();
        let proof = prove_countmin_merkle_leaf(params, initial.clone(), batch.clone());
        check(&proof, &initial, &batch);
    }

    /// Cost study: at fixed (d, t_max), prove time / trace rows grow ~log(w)
    /// (the per-row Merkle height), NOT linearly in w. The flat-commit circuit
    /// is Θ(d·w) and OOMs past w≈1024; the sparse rebind proves w=2^16 cheaply.
    #[test]
    #[ignore]
    fn sparse_cost_is_sublinear() {
        use crate::recursion::recursive::timing;
        println!();
        println!("countmin_merkle — sparse-rebind cost vs. width w (d=4, t_max=4, batch=4)");
        println!("  (cost ~ d·t_max·log2(w); the flat circuit is Θ(d·w) and OOMs ≳ w=1024)");
        println!("========================================================================");
        for &w in &[16usize, 256, 4096, 65536] {
            let params = CountMinMerkleParams { d: 4, w, batch: 4, t_max: 4 };
            let initial = state(4, w, |_, _| 0);
            let batch: Vec<CountMinUpdate> = [1u64, 2, 3, 4]
                .iter()
                .map(|&k| CountMinUpdate { key: k.wrapping_mul(0x9E37_79B9), value: 1 })
                .collect();
            let _ = prove_countmin_merkle_leaf(params, initial, batch);
            let t = timing::take();
            println!(
                "  w={:<6} height={:<2} trace_rows={:<9} prove={:>9.2?}",
                w,
                params.height(),
                t.trace_rows,
                t.prove
            );
        }
    }
}
