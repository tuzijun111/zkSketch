//! **Goldilocks (D=2) offline-memory-checking Count-Min leaf** — the
//! selectable Goldilocks counterpart of [`super::countmin_omc`], mirroring how
//! [`super::hll_omc_gl`] / [`super::ss_final_full_gl`] / [`super::gk_bandmerge_gl`]
//! shadow their BabyBear originals. The BabyBear module stays byte-for-byte
//! untouched; this file only adds the `cm_gl` option.
//!
//! Same `M_old ⊎ W == M_new ⊎ R` check as the BabyBear leaf (see
//! [`super::countmin_omc`]'s header). The port-relevant differences:
//!
//! - **Config**: `crate::config_gl` (Goldilocks, D=2, width-8 Poseidon2,
//!   digest 4) via `GOLDILOCKS_D2_W8`; `::<2>` / `_d2` registration forms.
//! - **Cell packing**: 2 counters per `Challenge` (D=2) instead of 4.
//! - **Single-limb key**: Goldilocks holds the whole u64 key in ONE base
//!   element (no `key_lo`/`key_hi` split), so a batch record packs as
//!   `[key, value]` in one Challenge (the BabyBear batch row is
//!   `[key_lo, key_hi, value, 0]`). The batch commitment therefore hashes a
//!   different (2-element) flat stream — commitments are field-specific.
//! - **PRF routing**: the key digest is 4 Goldilocks coefficients instead of
//!   8 BabyBear ones, but the PRF family still needs up to 8 row streams
//!   (`d ≤ 8`). Row `i` draws its bucket from the 32-bit HALF-coefficient
//!   `i`: `bucket_i = ((digest[i/2] >> 32·(i mod 2)) mod 2^32) mod w`
//!   ([`hash_cell_prf`]) — in-circuit, bits `[32·(i mod 2), 32·(i mod 2) +
//!   log2 w)` of coefficient `i/2`'s 64-bit decomposition. Distinct rows use
//!   disjoint bit ranges, preserving the 8-stream PRF shape. NOTE: this is a
//!   DIFFERENT hash family from BabyBear's, so `cm_gl` sketch states are a
//!   distinct (statistically equivalent) Count-Min instance — chains/forests
//!   must not mix fields.
//! - **Multiset encoding**: BabyBear packs `(addr, val, tag, 0)` into one
//!   D=4 challenge. D=2 has two coords and CM counter values are unbounded
//!   by design (no range checks on committed cells — exactly BabyBear's
//!   contract), so the dummy-separating tag moves to the ADDRESS coordinate:
//!   `enc(a, v) = recompose([2a+1, v])`; the value coordinate stays RAW.
//!   `recompose` is injective in `(2a+1, v)`, so distinct real elements never
//!   collide. Caveat vs BabyBear's dedicated constant tag coordinate: `2a+1`
//!   is nonzero only for `a ≠ (p−1)/2`, so real/dummy disjointness is
//!   conditional on the address witness — adversarial review found no
//!   standalone exploit (a `(p−1)/2` address cannot satisfy gap-sortedness
//!   next to canonical neighbors without collapsing into the shared split
//!   gap below), but it is defense-in-depth BabyBear has and this encoding
//!   lacks. On Goldilocks the payload packing `addr·2^SHIFT + val` cannot
//!   wrap for any admissible shape (`< 2^55 ≪ p`), unlike BabyBear where it
//!   exceeds `p` at the deployed `d·w`.
//!
//! ### KNOWN SHARED SOUNDNESS GAP (inherited from [`super::countmin_omc`])
//!
//! The sorted-view split `combined_sorted[r]·2^SHIFT + val_sorted[r] ==
//! payload_sorted[r]` is ONE in-field equation in TWO free witnesses:
//! `val_sorted` is never range-checked and `combined_sorted[0]` has no
//! absolute bound (only gaps are checked). A malicious prover can therefore
//! trade value bits against address bits in the split — redirecting an
//! increment to a different (gap-consistent) cell with an attacker-chosen
//! magnitude — and certify a final commitment that is not the honest
//! Count-Min fold. The BabyBear original has the IDENTICAL structure
//! (`countmin_omc.rs` Stage G), so this port is soundness-envelope-matched
//! to it (deliberately: the leaf is a same-arithmetization field-comparison
//! artifact). The fix — range-check `val_sorted[r] < 2^SHIFT_VAL_BITS` and
//! `combined_sorted[r] < 2^addr_bits` at every row — costs ~(SHIFT_VAL_BITS
//! + addr_bits) bit witnesses per counter-touch row in BOTH files and is
//! tracked as a separate work item.

use std::collections::HashMap;
use std::rc::Rc;

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    GoldilocksD2Width8, Poseidon2Config, generate_expose_trace, generate_permute_trace,
    generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d2, poseidon2_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::config_gl::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl as ConfigWithFriParams;
use crate::recursion::recursive::leaf_gl::{
    DIGEST_PACKING, GlCommit, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::Sketch;
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_v9::CountMinV9;

const LOG_FINAL_POLY_LEN: usize = 6;
const SHIFT_VAL_BITS: u64 = 20;
const SHIFT_VAL: u64 = 1u64 << SHIFT_VAL_BITS;

fn val_bits() -> usize {
    Val::bits()
}

thread_local! {
    /// When set, the prover commits to a CORRUPTED final state (one cell
    /// bumped) while the patch/multiset are built from the honest one, so
    /// `M_old ⊎ W = M_new ⊎ R` fails and the self-verify rejects. Drives
    /// [`tests::tamper_rejected`].
    static TAMPER_FINAL_CELL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Goldilocks PRF row hash: row `i` reads the 32-bit half-coefficient `i` of
/// `MyHash([key, 0])` (digest = 4 Goldilocks elements = 8 halves), reduced
/// mod `w`. Mirrors the in-circuit derivation bit-for-bit (`w` is a power of
/// two, so `mod w` = the bottom `log2 w` bits of the half).
pub fn hash_cell_prf(row: usize, key: u64, w: usize) -> usize {
    assert!(row < 8, "PRF hash family supports row < 8; got {row}");
    assert!(w > 0, "width w must be positive");
    let input = [Val::from_u64(key), Val::ZERO];
    let hasher = MyHash::new(make_perm());
    let digest: [Val; 4] = hasher.hash_iter(input.iter().copied());
    let h: u64 = <Val as PrimeField64>::as_canonical_u64(&digest[row / 2]);
    let half = (h >> (32 * (row % 2))) & 0xFFFF_FFFF;
    (half as usize) % w
}

/// Apply one [`CountMinUpdate`] with the GOLDILOCKS PRF row hash — the
/// canonical native update for the `cm_gl` leaf (distinct instance from the
/// BabyBear `apply_update_prf`).
pub fn apply_update_prf(state: &mut CountMinState, u: &CountMinUpdate) {
    for i in 0..state.params.d {
        let j = hash_cell_prf(i, u.key, state.params.w);
        state.counters[i][j] = state.counters[i][j].saturating_add(u.value);
    }
}

/// Empty Count-Min state (shared field-independent `CountMinState`).
pub fn cm_gl_empty(d: usize, w: usize) -> CountMinState {
    CountMinV9::new(&CountMinParams { d, w })
}

/// `Com(S)` for a Count-Min state under the Goldilocks hash — the flat
/// Poseidon2 digest over the `d·w` counters the leaf recomputes in-circuit.
pub fn commit_countmin(state: &CountMinState) -> GlCommit {
    let hasher = MyHash::new(make_perm());
    let flat = state.counters.iter().flatten().map(|&c| Val::from_u32(c));
    GlCommit(hasher.hash_iter(flat))
}

/// Batch commitment: flat `[key, value]` per record (2 Goldilocks elements =
/// one D=2 Challenge, matching the in-circuit `batch_packed` absorb).
pub fn commit_batch(records: &[CountMinUpdate]) -> GlCommit {
    let hasher = MyHash::new(make_perm());
    let flat = records
        .iter()
        .flat_map(|r| [Val::from_u64(r.key), Val::from_u32(r.value)]);
    GlCommit(hasher.hash_iter(flat))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmOmcParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
}

impl CmOmcParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    fn addr_bits(&self) -> usize {
        let n = self.num_cells();
        (usize::BITS - n.saturating_sub(1).leading_zeros()).max(1) as usize
    }
    pub fn validate(&self) {
        assert!(
            self.d >= 1 && self.d <= 8,
            "d must be in 1..=8, got {}",
            self.d
        );
        assert!(
            self.w.is_power_of_two() && self.w >= 2,
            "w must be a power of two ≥ 2, got {}",
            self.w
        );
        assert!(
            self.w.trailing_zeros() <= 32,
            "w must fit a 32-bit half-coefficient PRF stream, got {}",
            self.w
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.num_cells() % 2 == 0,
            "d·w must be a multiple of 2 (Challenge packing, D=2)"
        );
    }
}

/// A self-verified Goldilocks `omc` Count-Min leaf proof. Commitments are the
/// dense Goldilocks digests on both ends, so this chains against a real
/// committed prior state.
pub struct CountMinOmcProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: GlCommit,
    pub final_commit: GlCommit,
    pub batch_commit: GlCommit,
    pub params: CmOmcParams,
}

impl CountMinOmcProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// Pack the counters 2-per-Challenge (D=2) — the coefficient stream the
/// in-circuit `add_hash_slice` absorbs equals the flat stream
/// [`commit_countmin`] hashes natively.
fn pack_cells_to_challenge(state: &CountMinState) -> Vec<Challenge> {
    let flat: Vec<Val> = state
        .counters
        .iter()
        .flatten()
        .map(|&c| Val::from_u32(c))
        .collect();
    flat.chunks(2)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("2 base coeffs"))
        .collect()
}

/// Pack the batch records 1-per-Challenge: `[key, value]`.
fn pack_batch_to_challenge(batch: &[CountMinUpdate]) -> Vec<Challenge> {
    batch
        .iter()
        .map(|r| {
            Challenge::from_basis_coefficients_slice(&[
                Val::from_u64(r.key),
                Val::from_u32(r.value),
            ])
            .expect("2 base coeffs")
        })
        .collect()
}

/// Prove one count-min epoch from an arbitrary committed `initial_state`
/// via the `M_old ⊎ W = M_new ⊎ R` multiset rebind.
pub fn prove_countmin_omc(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, false)
}

/// Like [`prove_countmin_omc`] but surfaces the `(initial, final)` boundary
/// commitments via the **Expose NPO** so the leaf can be folded by the
/// in-circuit boundary-bound Goldilocks forest.
pub fn prove_countmin_omc_exposed(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcProof {
    prove_countmin_omc_impl(params, initial_state, batch, true)
}

/// A built, reusable Goldilocks `omc` Count-Min leaf: the circuit graph, its
/// prover data, and a registered prover. Build once per
/// `(params, expose_boundary)` and call [`Self::prove_epoch`] per batch.
pub struct CmOmcLeafCircuit {
    params: CmOmcParams,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
}

/// Build the reusable Goldilocks `omc` Count-Min leaf circuit for a shape.
pub fn build_countmin_omc_leaf(params: CmOmcParams, expose_boundary: bool) -> CmOmcLeafCircuit {
    params.validate();
    let CmOmcParams { d, w, batch: m } = params;
    let num_cells = params.num_cells();
    let cell_packing = num_cells / 2;
    let n_ctr = m * d;
    let w_log2 = w.trailing_zeros() as usize;
    let addr_bits = params.addr_bits();
    let l = num_cells + n_ctr; // multiset side length

    // ─── Circuit ─────────────────────────────────────────────────────────
    let cfg = Poseidon2Config::GOLDILOCKS_D2_W8;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        make_perm(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    if expose_boundary {
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
    }

    let init_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "init_lo" } else { "init_hi" }));
    let final_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "final_lo" } else { "final_hi" }));
    if expose_boundary {
        b.add_expose(&[
            init_commit_pis[0],
            init_commit_pis[1],
            final_commit_pis[0],
            final_commit_pis[1],
        ])
        .expect("add_expose boundary");
    }
    let batch_commit_pis: [ExprId; DIGEST_PACKING] =
        std::array::from_fn(|i| b.alloc_public_input(if i == 0 { "batch_lo" } else { "batch_hi" }));

    let one = b.alloc_const(Challenge::ONE, "one");
    let zero = b.alloc_const(Challenge::ZERO, "zero");
    let two = b.alloc_const(Challenge::from_u64(2), "two");
    let w_const = b.alloc_const(Challenge::from_u64(w as u64), "w");
    let shift_val_const = b.alloc_const(Challenge::from_u64(SHIFT_VAL), "shift_val");
    let row_consts: Vec<ExprId> = (0..d)
        .map(|i| b.alloc_const(Challenge::from_u64(i as u64), "row_i"))
        .collect();
    let cell_idx_consts: Vec<ExprId> = (0..num_cells)
        .map(|idx| b.alloc_const(Challenge::from_u64(idx as u64), "cell_idx"))
        .collect();
    let pow2_consts: Vec<ExprId> = (0..w_log2)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();

    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();
    let mut key_w = Vec::with_capacity(m);
    let mut value_w = Vec::with_capacity(m);
    for _ in 0..m {
        key_w.push(b.alloc_private_input("key"));
        value_w.push(b.alloc_private_input("value"));
    }
    let combined_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("combined_sorted"))
        .collect();
    let val_sorted: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("val_sorted"))
        .collect();
    let eq_tag: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("eq_tag"))
        .collect();
    let inv_diff: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("inv_diff"))
        .collect();
    let op_old: Vec<ExprId> = (0..n_ctr)
        .map(|_| b.alloc_private_input("op_old"))
        .collect();

    // Stage A — bind both states + batch to commitments.
    let digest_init = b
        .add_hash_slice(&cfg, &initial_packed, true)
        .expect("hash init");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_init[i], init_commit_pis[i]);
    }
    let digest_final = b
        .add_hash_slice(&cfg, &final_packed, true)
        .expect("hash final");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_final[i], final_commit_pis[i]);
    }
    let digest_batch = b
        .add_hash_slice(&cfg, &batch_packed, true)
        .expect("hash batch");
    for i in 0..DIGEST_PACKING {
        b.connect(digest_batch[i], batch_commit_pis[i]);
    }
    let o_cells: Vec<ExprId> = initial_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    let n_cells: Vec<ExprId> = final_packed
        .iter()
        .flat_map(|&p| b.decompose_ext_to_base_coeffs::<Val>(p).unwrap())
        .collect();
    for k in 0..m {
        let coeffs = b
            .decompose_ext_to_base_coeffs::<Val>(batch_packed[k])
            .expect("decompose batch");
        b.connect(coeffs[0], key_w[k]);
        b.connect(coeffs[1], value_w[k]);
    }
    // Single-limb key → hash-input Challenge [key, 0].
    let key_field: Vec<ExprId> = (0..m)
        .map(|k| {
            b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[key_w[k], zero])
                .expect("recompose key")
        })
        .collect();

    // Stage F — per-record PRF hash → payload. Row `i` draws its bucket from
    // the 32-bit half `i` of the 64-bit digest coefficients (see the module
    // header): bits [32·(i mod 2), 32·(i mod 2) + w_log2) of coeff i/2.
    let mut h_w = Vec::with_capacity(m);
    for _ in 0..m {
        h_w.push((b.alloc_private_input("h0"), b.alloc_private_input("h1")));
    }
    let mut payload = Vec::with_capacity(n_ctr);
    for k in 0..m {
        let hashed = b
            .add_hash_slice(&cfg, &[key_field[k]], true)
            .expect("hash key");
        let (h0, h1) = h_w[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0).expect("d h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1).expect("d h1");
        let hv = [c0[0], c0[1], c1[0], c1[1]];
        // Decompose all 4 coefficients once (also satisfies the consume rule
        // for the unused halves/coeffs at d < 8).
        let hv_bits: Vec<Vec<ExprId>> = hv
            .iter()
            .map(|&coeff| {
                b.decompose_to_bits::<Val>(coeff, val_bits())
                    .expect("bits digest coeff")
            })
            .collect();
        for i in 0..d {
            let bits = &hv_bits[i / 2];
            let off = 32 * (i % 2);
            let mut pos = b.mul(bits[off], pow2_consts[0]);
            for jb in 1..w_log2 {
                let t = b.mul(bits[off + jb], pow2_consts[jb]);
                pos = b.add(pos, t);
            }
            let rw = b.mul(row_consts[i], w_const);
            let comb = b.add(rw, pos);
            let cs = b.mul(comb, shift_val_const);
            payload.push(b.add(cs, value_w[k]));
        }
    }

    // Stage G — counter sort.
    // Placeholder identity permutation — `prove_epoch` swaps in the real
    // per-batch sigma via `update_permute_witnesses` before each run.
    let payload_sorted = b
        .add_permute(&payload, (0..n_ctr).collect::<Vec<_>>())
        .expect("permute ctr");
    for r in 0..n_ctr {
        let cs = b.mul(combined_sorted[r], shift_val_const);
        let rec = b.add(cs, val_sorted[r]);
        b.connect(rec, payload_sorted[r]);
    }

    // Stage H — adjacency / running sum / sortedness / segment flags.
    b.connect(eq_tag[0], zero);
    b.connect(inv_diff[0], zero);
    for r in 1..n_ctr {
        let diff = b.sub(combined_sorted[r - 1], combined_sorted[r]);
        let l1 = b.mul(eq_tag[r], diff);
        b.connect(l1, zero);
        let omt = b.sub(one, eq_tag[r]);
        let di = b.mul(diff, inv_diff[r]);
        let omdi = b.sub(one, di);
        let l2 = b.mul(omt, omdi);
        b.connect(l2, zero);
        // sortedness: gap ∈ [0, 2^addr_bits) (canonical 1-entry-per-address).
        // Full-width window + zero-forced high bits keeps it canonical.
        let gap = b.sub(combined_sorted[r], combined_sorted[r - 1]);
        let gb = b
            .decompose_to_bits::<Val>(gap, val_bits())
            .expect("gap bits");
        for &bit in gb.iter().skip(addr_bits) {
            b.connect(bit, zero);
        }
    }
    let mut acc = Vec::with_capacity(n_ctr);
    acc.push(val_sorted[0]);
    for r in 1..n_ctr {
        let carried = b.mul(eq_tag[r], acc[r - 1]);
        acc.push(b.add(val_sorted[r], carried));
    }
    let mut a_active = Vec::with_capacity(n_ctr);
    for r in 0..n_ctr {
        a_active.push(if r == n_ctr - 1 {
            one
        } else {
            b.sub(one, eq_tag[r + 1])
        });
    }

    // ─── Build the multiset sides and check M_old ⊎ W == M_new ⊎ R ───────
    // enc(a, v) = recompose([2a+1, v]) — the odd-address tag keeps real
    // elements disjoint from the zero dummies of inactive W/R rows (addresses
    // are canonical small integers; the value coordinate stays RAW, matching
    // the BabyBear contract of no range assumptions on committed cells).
    let enc = |b: &mut CircuitBuilder<Challenge>, a: ExprId, v: ExprId| -> ExprId {
        let ta = b.mul_add(a, two, one); // 2·a + 1
        b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[ta, v])
            .expect("enc")
    };
    let mut input: Vec<ExprId> = Vec::with_capacity(l);
    let mut target: Vec<ExprId> = Vec::with_capacity(l);
    for a in 0..num_cells {
        input.push(enc(&mut b, cell_idx_consts[a], o_cells[a]));
        target.push(enc(&mut b, cell_idx_consts[a], n_cells[a]));
    }
    for r in 0..n_ctr {
        let n_z = b.add(op_old[r], acc[r]); // N_z = O_z + Δ
        let enc_w = enc(&mut b, combined_sorted[r], n_z);
        let w_elem = b.mul(a_active[r], enc_w); // active → enc, inactive → 0
        input.push(w_elem);
        let enc_r = enc(&mut b, combined_sorted[r], op_old[r]);
        let r_elem = b.mul(a_active[r], enc_r);
        target.push(r_elem);
    }
    let permuted = b
        .add_permute(&input, (0..l).collect::<Vec<_>>())
        .expect("permute mset");
    for r in 0..l {
        b.connect(permuted[r], target[r]);
    }

    let circuit = b.build().expect("build countmin_omc_gl circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d2::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 2>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 2>(1));
    if expose_boundary {
        preprocessors.push(expose_preprocessor::<Val>());
        air_builders.extend(expose_air_builders::<ConfigWithFriParams, 2>());
    }

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 2>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("get_airs_and_degrees_with_prep (omc_gl)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8);
    prover.register_recompose_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8.d() != 2);
    prover.register_permute_table::<2>();
    if expose_boundary {
        prover.register_expose_table::<2>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();

    CmOmcLeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
    }
}

impl CmOmcLeafCircuit {
    /// Prove one epoch on the prebuilt circuit.
    pub fn prove_epoch(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcProof {
        let params = self.params;
        assert_eq!(initial_state.params.d, params.d);
        assert_eq!(initial_state.params.w, params.w);
        assert_eq!(batch.len(), params.batch, "batch.len() != params.batch");

        let CmOmcParams { d, w, batch: m } = params;
        let num_cells = params.num_cells();
        let n_ctr = m * d;
        let l = num_cells + n_ctr; // multiset side length

        // ─── Native side ─────────────────────────────────────────────────────
        let mut final_state = initial_state.clone();
        for u in &batch {
            apply_update_prf(&mut final_state, u);
        }
        // Optionally corrupt the COMMITTED final state for the tamper test (the
        // patch is still built from the honest evolution below).
        let mut committed_final = final_state.clone();
        if TAMPER_FINAL_CELL.with(|f| f.get()) {
            committed_final.counters[0][0] = committed_final.counters[0][0].wrapping_add(1);
        }
        let initial_commit = commit_countmin(&initial_state);
        let final_commit = commit_countmin(&committed_final);
        let batch_commit = commit_batch(&batch);

        // U_ctr (per record, no key-grouping) + counter sort.
        let mut u_ctr_data: Vec<(u64, u32)> = Vec::with_capacity(n_ctr);
        for u in &batch {
            for i in 0..d {
                let bucket = hash_cell_prf(i, u.key, w);
                u_ctr_data.push(((i * w + bucket) as u64, u.value));
            }
        }
        let mut indexed: Vec<(usize, &(u64, u32))> = u_ctr_data.iter().enumerate().collect();
        indexed.sort_by_key(|(_, (combined, _))| *combined);
        let sigma_ctr: Vec<usize> = indexed.iter().map(|(i, _)| *i).collect();
        let combined_sorted_native: Vec<u64> = indexed.iter().map(|(_, (c, _))| *c).collect();
        let val_sorted_native: Vec<u32> = indexed.iter().map(|(_, (_, v))| *v).collect();

        let mut tag_native: Vec<u32> = vec![0; n_ctr];
        for r in 1..n_ctr {
            if combined_sorted_native[r] == combined_sorted_native[r - 1] {
                tag_native[r] = 1;
            }
        }
        let mut acc_native: Vec<u32> = vec![0; n_ctr];
        if n_ctr > 0 {
            acc_native[0] = val_sorted_native[0];
            for r in 1..n_ctr {
                acc_native[r] = if tag_native[r] == 1 {
                    acc_native[r - 1].saturating_add(val_sorted_native[r])
                } else {
                    val_sorted_native[r]
                };
            }
        }
        let mut a_active_native: Vec<u32> = vec![0; n_ctr];
        for r in 0..n_ctr {
            let ends = if r == n_ctr - 1 {
                true
            } else {
                tag_native[r + 1] == 0
            };
            a_active_native[r] = u32::from(ends);
        }
        // Old value at each row's address (from the HONEST initial state).
        let op_old_native: Vec<u32> = (0..n_ctr)
            .map(|r| {
                let a = combined_sorted_native[r] as usize;
                initial_state.counters[a / w][a % w]
            })
            .collect();

        // Native multiset elements. None = zero dummy (inactive W/R row); a real
        // element is keyed by (addr, value), carried in-circuit as [2a+1, v].
        let o_cells_native: Vec<u32> = initial_state.counters.iter().flatten().copied().collect();
        let n_cells_native: Vec<u32> = committed_final.counters.iter().flatten().copied().collect();
        let mut input_native: Vec<Option<(u64, u64)>> = Vec::with_capacity(l);
        let mut target_native: Vec<Option<(u64, u64)>> = Vec::with_capacity(l);
        for a in 0..num_cells {
            input_native.push(Some((a as u64, o_cells_native[a] as u64)));
            target_native.push(Some((a as u64, n_cells_native[a] as u64)));
        }
        for r in 0..n_ctr {
            if a_active_native[r] == 1 {
                let addr = combined_sorted_native[r];
                let o = op_old_native[r] as u64;
                let n = o + acc_native[r] as u64;
                input_native.push(Some((addr, n))); // W
                target_native.push(Some((addr, o))); // R
            } else {
                input_native.push(None);
                target_native.push(None);
            }
        }
        // Build sigma s.t. input[sigma[r]] == target[r] (multiset matching).
        let mut buckets: HashMap<Option<(u64, u64)>, Vec<usize>> = HashMap::new();
        for (i, v) in input_native.iter().enumerate() {
            buckets.entry(*v).or_default().push(i);
        }
        let sigma_mset: Vec<usize> = target_native
            .iter()
            .map(|t| {
                buckets
                    .get_mut(t)
                    .and_then(|v| v.pop())
                    .expect("honest multiset matching exists")
            })
            .collect();

        // Swap the real per-batch permutation hints into the prebuilt graph
        // (op order: counter-sort permute, then multiset permute).
        self.circuit
            .update_permute_witnesses(&[sigma_ctr, sigma_mset])
            .expect("update permute witnesses (countmin_omc_gl)");

        // ─── Public + private values ─────────────────────────────────────────
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&batch_commit));

        let mut private_inputs: Vec<Challenge> = Vec::new();
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&initial_state));
        private_inputs.extend_from_slice(&pack_cells_to_challenge(&committed_final));
        private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
        for u in &batch {
            private_inputs.push(Challenge::from_u64(u.key));
            private_inputs.push(Challenge::from_u32(u.value));
        }
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
                (Challenge::from_u64(combined_sorted_native[r - 1])
                    - Challenge::from_u64(combined_sorted_native[r]))
                .try_inverse()
                .expect("nonzero diff inverts")
            };
            private_inputs.push(inv);
        }
        for r in 0..n_ctr {
            private_inputs.push(Challenge::from_u32(op_old_native[r]));
        }
        {
            let hasher = MyHash::new(make_perm());
            for u in &batch {
                let input = [Val::from_u64(u.key), Val::ZERO];
                let digest: [Val; 4] = hasher.hash_iter(input.iter().copied());
                private_inputs.push(
                    Challenge::from_basis_coefficients_slice(&digest[0..2]).expect("2 coeffs"),
                );
                private_inputs.push(
                    Challenge::from_basis_coefficients_slice(&digest[2..4]).expect("2 coeffs"),
                );
            }
        }

        // ─── Run + prove ─────────────────────────────────────────────────────
        let __t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&public_inputs).expect("set pubs");
            runner
                .set_private_inputs(&private_inputs)
                .expect("set privs");
            runner.run().expect("run countmin_omc_gl")
        };
        let __witness = __t_w.elapsed();

        let __t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (omc_gl)");
        let __prove = __t_p.elapsed();
        let __t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify countmin_omc_gl leaf");
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness: __witness,
                prove: __prove,
                verify: __t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        CountMinOmcProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit,
            final_commit,
            batch_commit,
            params,
        }
    }
}

fn prove_countmin_omc_impl(
    params: CmOmcParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
    expose_boundary: bool,
) -> CountMinOmcProof {
    build_countmin_omc_leaf(params, expose_boundary).prove_epoch(initial_state, batch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip against a **non-empty** prior state: the touched old values
    /// are reconciled against a real committed `M_old`, and the certified
    /// final commitment must equal the natively-applied (GL-PRF) Count-Min.
    #[test]
    fn omc_round_trip_nonempty_prior() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        // Seed a non-trivial prior state with a real prior batch.
        let mut prior = cm_gl_empty(2, 4);
        for u in &[
            CountMinUpdate { key: 3, value: 4 },
            CountMinUpdate { key: 9, value: 2 },
        ] {
            apply_update_prf(&mut prior, u);
        }
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 9, value: 5 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior.clone(), updates);
        assert_eq!(r.initial_commit, commit_countmin(&prior));
        assert_eq!(r.final_commit, commit_countmin(&expect_final));
        assert_ne!(r.initial_commit, r.final_commit);
    }

    /// Exposed-boundary smoke: the forest folds this leaf shape, so the Expose
    /// NPO registration must prove and self-verify.
    #[test]
    fn omc_exposed_smoke() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        let prior = cm_gl_empty(2, 4);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc_exposed(params, prior, updates);
        assert_eq!(r.final_commit, commit_countmin(&expect_final));
    }

    /// **Tamper.** Commit a corrupted final state (one cell bumped) while the
    /// patch is built from the honest evolution: an untouched cell disagrees
    /// across `M_old`/`M_new`, so the multiset equality fails and self-verify
    /// rejects.
    #[test]
    fn tamper_rejected() {
        let params = CmOmcParams {
            d: 2,
            w: 4,
            batch: 2,
        };
        let prior = cm_gl_empty(2, 4);
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
        ];
        let _ok = prove_countmin_omc(params, prior.clone(), updates.clone());

        TAMPER_FINAL_CELL.with(|f| f.set(true));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prove_countmin_omc(params, prior.clone(), updates.clone());
        }));
        std::panic::set_hook(prev);
        TAMPER_FINAL_CELL.with(|f| f.set(false));
        assert!(
            res.is_err(),
            "corrupted final state must break the multiset equality"
        );
    }

    /// Repeated keys across a non-empty prior: the running sum folds the
    /// duplicates into one read/write pair, reconciled against the prior.
    /// `d=7` also exercises the half-coefficient PRF streams past coeff 3.
    #[test]
    fn omc_repeated_keys_nonempty() {
        let params = CmOmcParams {
            d: 7,
            w: 8,
            batch: 4,
        };
        let mut prior = cm_gl_empty(7, 8);
        apply_update_prf(&mut prior, &CountMinUpdate { key: 7, value: 10 });
        let updates = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let mut expect_final = prior.clone();
        for u in &updates {
            apply_update_prf(&mut expect_final, u);
        }
        let r = prove_countmin_omc(params, prior, updates);
        assert_eq!(r.final_commit, commit_countmin(&expect_final));
    }
}
