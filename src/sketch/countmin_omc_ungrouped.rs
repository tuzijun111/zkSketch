//! Count-Min `omc` leaf without the counter sort: each access emits its own read/write pair
//! with a free read value. Sound for additive updates only.

use std::collections::HashMap;
use std::rc::Rc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_permute_trace, generate_poseidon2_trace,
    generate_range_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking,
    batch_stark_prover::{
        expose_air_builders, expose_preprocessor, permute_air_builders, permute_preprocessor,
        poseidon2_air_builders_d4, poseidon2_preprocessor, range_air_builders, range_preprocessor,
        recompose_air_builders, recompose_preprocessor,
    },
    common::get_airs_and_degrees_with_prep,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::RecursionOutput;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::StarkGenericConfig;

use crate::commitment::CountMinCommit;
use crate::commitment::countmin::commit_countmin;
use crate::commitment::countmin_batch::commit_batch;
use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::{
    DIGEST_PACKING, make_leaf_config, pack_commit_to_challenge,
};
use crate::sketch::countmin::{CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::{apply_update_prf, hash_cell_prf};

const LOG_FINAL_POLY_LEN: usize = 6;
/// Range-check width for the free read values `r_z`. Its job is to force `r_z`
/// into the base field (so `enc` stays injective); 31 bits (`= Val::bits()`) admits every canonical
/// BabyBear value, so it imposes no bound on honest counters.
const R_BITS: usize = 31;

// ─── Test-only knobs (tamper injection / disabling a check) ─────────────────

/// Adversarial witness modifications used by the tamper tests. Each one keeps
/// the circuit identical and only changes the prover's witness / committed
/// final state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[allow(dead_code)]
enum Tamper {
    #[default]
    None,
    /// Commit a final state with one UNTOUCHED cell bumped by +1.
    BumpUntouched,
    /// Commit a final state where one touched cell is reverted to its old
    /// value (claim "no change"), honest reads.
    RevertTouched,
    /// Commit a final state that omits the LAST record's increment on all `d`
    /// of its cells, honest reads (so every claimed value still occurs on the
    /// write side and only the LogUp balance can catch it).
    DropLastRecord,
    /// Supply the non-canonical decomposition `x + p` for (record `k`, row
    /// `i`) and commit the state that results from the shifted routing.
    NonCanonical { k: usize, i: usize },
    /// Give access `z` an extension-valued read `r_z = r0 + r3·X³` that
    /// re-routes it to cell `c` (through `X^4 = W`), and commit the re-routed state.
    RExtension { z: usize, c: usize },
    /// Inflate a touched cell by +1 by exploiting the FREE reads (the freedom
    /// this leaf hands the prover). Accesses `z1 < z2` hit the same cell and
    /// `v_{z2} = 0`; with `c` the honest value before `z1`, set
    /// `r_{z1} = r_{z2} = c + 1` (so `z1` writes `c + 1 + v_{z1}` and `z2`
    /// writes `c + 1`), continue honestly, and commit the inflated cell.
    /// Every claimed value then occurs on the input side, so the
    /// non-bijective hint lets the trace generator finish and only the LogUp
    /// multiplicities (element `c` is written but never read) can reject.
    InflateViaReads { z1: usize, z2: usize },
}

#[derive(Copy, Clone, Debug, Default)]
struct Knobs {
    tamper: Tamper,
    /// Build without the canonical-bits constraint.
    skip_canonical: bool,
    /// Build without the `r_z` range check.
    skip_r_range: bool,
    /// Cost-accounting only: decompose the `8 − d` unused digest coefficients
    /// to 31 bits exactly as `countmin_omc` does, so op counts can separate
    /// "ungrouping" from "dropping omc's unused decompositions".
    decompose_unused: bool,
}

#[cfg(test)]
thread_local! {
    static KNOBS: std::cell::Cell<Knobs> = const { std::cell::Cell::new(Knobs {
        tamper: Tamper::None,
        skip_canonical: false,
        skip_r_range: false,
        decompose_unused: false,
    }) };
}

fn knobs() -> Knobs {
    #[cfg(test)]
    {
        KNOBS.with(|k| k.get())
    }
    #[cfg(not(test))]
    {
        Knobs::default()
    }
}

// ─── Params / proof / leaf types ────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmOmcUngroupedParams {
    pub d: usize,
    pub w: usize,
    pub batch: usize,
    /// `false`: build `enc(a,v)` with the same 4-`mul_add` recompose gadget as
    /// `countmin_omc` (apples-to-apples). `true`: build the SAME extension
    /// element as `v·X + (a + X²)` in 1 ALU row for the dense side (constant
    /// `a + X²`) and 1 row per read/write (`write = read + v·X`).
    /// Independent of ungrouping: the same gadget would shrink
    /// `countmin_omc`'s dense side (`6·dw` → `2·dw` ALU ops) equally, so an
    /// `ungrouped + affine` vs `countmin_omc` comparison mixes two changes.
    pub affine_enc: bool,
}

impl CmOmcUngroupedParams {
    pub fn num_cells(&self) -> usize {
        self.d * self.w
    }
    pub fn num_accesses(&self) -> usize {
        self.batch * self.d
    }
    pub fn validate(&self) {
        assert!(
            self.d >= 1 && self.d <= 8,
            "d must be in 1..=8, got {}",
            self.d
        );
        assert!(
            self.w.is_power_of_two() && self.w >= 2 && self.w <= (1 << 27),
            "w must be a power of two in [2, 2^27], got {}",
            self.w
        );
        assert!(self.batch >= 1, "batch must be ≥ 1, got {}", self.batch);
        assert!(
            self.num_cells().is_multiple_of(4),
            "d·w must be a multiple of 4 (Challenge packing)"
        );
        // Each multiset side has L = dw + md elements; LogUp equality
        // is exact multiset equality only while every multiplicity is < p.
        let l = (self.num_cells() as u128) + (self.num_accesses() as u128);
        assert!(
            l < p_u64() as u128,
            "multiset side length dw + md = {l} must be < p"
        );
    }
}

pub struct CountMinOmcUngroupedProof {
    pub output: RecursionOutput<ConfigWithFriParams>,
    pub initial_commit: CountMinCommit,
    pub final_commit: CountMinCommit,
    pub batch_commit: CountMinCommit,
    pub params: CmOmcUngroupedParams,
}

impl CountMinOmcUngroupedProof {
    pub fn proof_size(&self) -> usize {
        crate::experiments::proof_size(&self.output.0)
    }
}

/// A built, reusable leaf (graph + prover data), mirroring
/// [`super::countmin_omc::CmOmcLeafCircuit`]. Only the multiset Permute op's
/// trace hint changes per batch.
pub struct CmOmcUngroupedLeafCircuit {
    params: CmOmcUngroupedParams,
    circuit: p3_circuit::Circuit<Challenge>,
    prover: BatchStarkProver<ConfigWithFriParams>,
    circuit_prover_data: Rc<CircuitProverData<ConfigWithFriParams>>,
    trace_rows: u64,
    log_heights: Vec<usize>,
}

impl CmOmcUngroupedLeafCircuit {
    /// `Σ 2^{log_height}` over all tables (same metric as `countmin_omc`).
    /// Power-of-two padded: it jumps ~2× when one table crosses a boundary,
    /// so compare variants by unpadded ALU ops, not by one padded point.
    pub fn trace_rows(&self) -> u64 {
        self.trace_rows
    }
    /// Per-table log2 heights (incl. the zk `+is_zk` bump), in AIR order:
    /// `[const, public, alu, <npo tables in builder order>]`.
    pub fn log_heights(&self) -> &[usize] {
        &self.log_heights
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn val_bits() -> usize {
    Val::bits()
}

/// Local copy of `hll_omc.rs`'s canonical-bits gadget (swap for Track A's
/// shared helper at merge).
///
/// Assert the LSB-first boolean `bits` (length `Val::bits()`) encode a
/// CANONICAL field value (`< p`), rejecting the alternate `x + p`
/// decomposition. Both supported fields have the form `p = 2^n − 2^m + 1`, so
/// `V ≥ p` iff the top `n−m` bits are all 1 AND the low `m` bits are nonzero;
/// assert the negation as `(∏_{i≥m} bit_i) · (Σ_{i<m} bit_i·2^i) == 0`.
/// `pow2_lo[i] = 2^i` for `i < m` (`m == pow2_lo.len()`).
fn assert_canonical_bits(
    b: &mut CircuitBuilder<Challenge>,
    bits: &[ExprId],
    pow2_lo: &[ExprId],
    one: ExprId,
    zero: ExprId,
) {
    let m = pow2_lo.len();
    let n = bits.len();
    let mut hi_and = one;
    for &bit in &bits[m..n] {
        hi_and = b.mul(hi_and, bit);
    }
    let mut lo = zero;
    for i in 0..m {
        lo = b.mul_add(bits[i], pow2_lo[i], lo);
    }
    let prod = b.mul(hi_and, lo);
    b.connect(prod, zero);
}

/// Low-bit count `m` of the canonical gadget: `p = 2^n − 2^m + 1`.
fn canon_low_bits() -> usize {
    let pm1 = <Val as PrimeField64>::as_canonical_u64(&(Val::ZERO - Val::ONE));
    let m = pm1.trailing_zeros() as usize;
    let n = val_bits();
    let expected = ((1u64 << (n - m)) - 1) << m;
    assert_eq!(
        pm1, expected,
        "canonical gadget requires the field modulus to have the form p = 2^n − 2^m + 1"
    );
    m
}

fn p_u64() -> u64 {
    <Val as PrimeField64>::as_canonical_u64(&(Val::ZERO - Val::ONE)) + 1
}

/// The extension generator `X` (basis element 1) and `W = X^4`.
fn ext_x() -> Challenge {
    Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::ZERO, Val::ZERO])
        .expect("4 coeffs")
}

/// `enc(a, v) = a + v·X + X²` for base `a` and extension `v` (native mirror
/// of both in-circuit gadgets; for base `v` its coordinates are `(a, v, 1, 0)`).
fn enc_native(a: u64, v: Challenge) -> Challenge {
    let base = Challenge::from_basis_coefficients_slice(&[
        Val::from_u64(a),
        Val::ZERO,
        Val::ONE,
        Val::ZERO,
    ])
    .expect("4 coeffs");
    base + v * ext_x()
}

fn pack_cells(flat: &[Val]) -> Vec<Challenge> {
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

fn pack_batch_to_challenge(batch: &[CountMinUpdate]) -> Vec<Challenge> {
    let flat: Vec<Val> = batch
        .iter()
        .flat_map(|r| {
            let key_lo = (r.key & 0xFFFF_FFFF) as u32;
            let key_hi = (r.key >> 32) as u32;
            [
                Val::from_u32(key_lo),
                Val::from_u32(key_hi),
                Val::from_u32(r.value),
                Val::ZERO,
            ]
        })
        .collect();
    flat.chunks(4)
        .map(|chunk| Challenge::from_basis_coefficients_slice(chunk).expect("4 base coeffs"))
        .collect()
}

fn key_digest(key: u64) -> [Val; 8] {
    let hasher = MyHash::new(make_perm());
    let input = [Val::from_u64(key), Val::ZERO, Val::ZERO, Val::ZERO];
    hasher.hash_iter(input.iter().copied())
}

/// Build `sigma` with `input[sigma[r]] == target[r]`. With `allow_reuse`
/// (tamper tests only) a target whose matching input is exhausted reuses any
/// input of equal value, or index 0 if none exists — i.e. a NON-bijective
/// hint, so the trace generator can still run and the rejection (if any) must
/// come from the proof system rather than from the native side.
fn build_sigma(input: &[Challenge], target: &[Challenge], allow_reuse: bool) -> Vec<usize> {
    let mut buckets: HashMap<Challenge, Vec<usize>> = HashMap::new();
    for (i, v) in input.iter().enumerate() {
        buckets.entry(*v).or_default().push(i);
    }
    let any_of: HashMap<Challenge, usize> =
        buckets.iter().map(|(v, ix)| (*v, ix[0])).collect();
    target
        .iter()
        .map(|t| match buckets.get_mut(t).and_then(|v| v.pop()) {
            Some(i) => i,
            None => {
                assert!(allow_reuse, "honest multiset matching exists");
                any_of.get(t).copied().unwrap_or(0)
            }
        })
        .collect()
}

// ─── Circuit ────────────────────────────────────────────────────────────────

/// Build the reusable ungrouped `omc` Count-Min leaf circuit for a shape.
pub fn build_countmin_omc_ungrouped_leaf(
    params: CmOmcUngroupedParams,
    expose_boundary: bool,
) -> CmOmcUngroupedLeafCircuit {
    params.validate();
    let kn = knobs();
    let CmOmcUngroupedParams {
        d,
        w,
        batch: m,
        affine_enc,
    } = params;
    let num_cells = params.num_cells();
    let cell_packing = num_cells / 4;
    let n_acc = params.num_accesses();
    let w_log2 = w.trailing_zeros() as usize;
    let nb = val_bits();
    let l = num_cells + n_acc; // multiset side length

    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_permute(generate_permute_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
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
    let two_pow_32_const = b.alloc_const(Challenge::from_u64(1u64 << 32), "2^32");
    let pow2_all: Vec<ExprId> = (0..nb)
        .map(|j| b.alloc_const(Challenge::from_u64(1u64 << j), "2^j"))
        .collect();
    let canon_m = canon_low_bits();
    let canon_pow2: Vec<ExprId> = pow2_all[..canon_m].to_vec();
    // Row base address i·w (pure base-field address; used by the recompose
    // gadget) and i·w + X² (the affine gadget folds the tag into the address).
    let x2 = ext_x() * ext_x();
    let row_base: Vec<ExprId> = (0..d)
        .map(|i| {
            let c = if affine_enc {
                Challenge::from_u64((i * w) as u64) + x2
            } else {
                Challenge::from_u64((i * w) as u64)
            };
            b.alloc_const(c, "row_base")
        })
        .collect();
    let x_const = b.alloc_const(ext_x(), "X");

    // ── Private inputs (allocation order == value push order) ─────────────
    let initial_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("init_cell_packed"))
        .collect();
    let final_packed: Vec<ExprId> = (0..cell_packing)
        .map(|_| b.alloc_private_input("final_cell_packed"))
        .collect();
    let batch_packed: Vec<ExprId> = (0..m)
        .map(|_| b.alloc_private_input("batch_packed"))
        .collect();
    let mut key_lo = Vec::with_capacity(m);
    let mut key_hi = Vec::with_capacity(m);
    let mut value_w = Vec::with_capacity(m);
    for _ in 0..m {
        key_lo.push(b.alloc_private_input("key_lo"));
        key_hi.push(b.alloc_private_input("key_hi"));
        value_w.push(b.alloc_private_input("value"));
    }
    let h_w: Vec<(ExprId, ExprId)> = (0..m)
        .map(|_| (b.alloc_private_input("h0"), b.alloc_private_input("h1")))
        .collect();
    // bits[z][j]: bit j of digest coefficient i for access z = k·d + i.
    let bits_w: Vec<Vec<ExprId>> = (0..n_acc)
        .map(|_| (0..nb).map(|_| b.alloc_private_input("bucket_bit")).collect())
        .collect();
    let r_w: Vec<ExprId> = (0..n_acc)
        .map(|_| b.alloc_private_input("r_read"))
        .collect();

    // ── Stage A — bind both states + batch to their commitments ──────────
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
        b.connect(coeffs[0], key_lo[k]);
        b.connect(coeffs[1], key_hi[k]);
        b.connect(coeffs[2], value_w[k]);
        b.connect(coeffs[3], zero);
    }

    // ── Stage F — per record: hash → canonical bucket bits → d accesses ──
    // For each access z = (k, i): the address a_z and the read/write elements.
    let mut w_elems: Vec<ExprId> = Vec::with_capacity(n_acc);
    let mut r_elems: Vec<ExprId> = Vec::with_capacity(n_acc);
    for k in 0..m {
        let hi = b.mul(key_hi[k], two_pow_32_const);
        let key_field = b.add(key_lo[k], hi);
        let hashed = b
            .add_hash_slice(&cfg, &[key_field], true)
            .expect("hash key");
        let (h0, h1) = h_w[k];
        b.connect(hashed[0], h0);
        b.connect(hashed[1], h1);
        let c0 = b.decompose_ext_to_base_coeffs::<Val>(h0).expect("d h0");
        let c1 = b.decompose_ext_to_base_coeffs::<Val>(h1).expect("d h1");
        let hv = [c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2], c1[3]];
        for i in 0..d {
            let z = k * d + i;
            let bits = &bits_w[z];
            // Same constraints as `decompose_to_bits(hv[i], 31)`: boolean bits
            // whose Σ 2^j reconstructs the digest coefficient.
            let mut recon = zero;
            for j in 0..nb {
                b.assert_bool(bits[j]);
                recon = b.mul_add(bits[j], pow2_all[j], recon);
            }
            b.connect(recon, hv[i]);
            if !kn.skip_canonical {
                assert_canonical_bits(&mut b, bits, &canon_pow2, one, zero);
            }
            // a_z = i·w + Σ_{j<log w} bit_j·2^j   (affine: + X² folded in).
            let mut addr = row_base[i];
            for j in 0..w_log2 {
                addr = b.mul_add(bits[j], pow2_all[j], addr);
            }
            // r_z ∈ base field: byte-table range check to 31 bits.
            if !kn.skip_r_range {
                b.add_range_bits::<Val>(r_w[z], R_BITS)
                    .expect("r_z range");
            }
            let (re, we) = if affine_enc {
                // read = r·X + (a + X²); write = read + v·X.
                let re = b.mul_add(r_w[z], x_const, addr);
                let we = b.mul_add(value_w[k], x_const, re);
                (re, we)
            } else {
                let nz = b.add(r_w[z], value_w[k]);
                let re = b
                    .recompose_base_coeffs_to_ext_via_alu::<Val>(&[addr, r_w[z], one, zero])
                    .expect("enc read");
                let we = b
                    .recompose_base_coeffs_to_ext_via_alu::<Val>(&[addr, nz, one, zero])
                    .expect("enc write");
                (re, we)
            };
            r_elems.push(re);
            w_elems.push(we);
        }
        // Consume the unused digest coefficients through one ALU lhs each, as
        // in hll_omc. This only gives each hint coefficient a `WitnessChecks`
        // creator (so the bus balances); it pins nothing — in this backend
        // the coefficients are not bound to the packed digest at all. Test
        // knob `decompose_unused` instead mirrors the `Legacy` path of
        // `countmin_omc` (a full 31-bit `decompose_to_bits` of each unused
        // coefficient) to measure that confound in op counts.
        for &c in &hv[d..8] {
            if kn.decompose_unused {
                let _ = b
                    .decompose_to_bits::<Val>(c, Val::bits())
                    .expect("bits unused (omc mirror)");
            } else {
                let _ = b.mul(c, c);
            }
        }
    }

    // ── Multiset: M_old ⊎ W == M_new ⊎ R ─────────────────────────────────
    let mut input: Vec<ExprId> = Vec::with_capacity(l);
    let mut target: Vec<ExprId> = Vec::with_capacity(l);
    if affine_enc {
        for a in 0..num_cells {
            let ka = b.alloc_const(
                Challenge::from_u64(a as u64) + x2,
                "cell_addr_tag",
            );
            input.push(b.mul_add(o_cells[a], x_const, ka));
            target.push(b.mul_add(n_cells[a], x_const, ka));
        }
    } else {
        for a in 0..num_cells {
            let ca = b.alloc_const(Challenge::from_u64(a as u64), "cell_idx");
            input.push(
                b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[ca, o_cells[a], one, zero])
                    .expect("enc old"),
            );
            target.push(
                b.recompose_base_coeffs_to_ext_via_alu::<Val>(&[ca, n_cells[a], one, zero])
                    .expect("enc new"),
            );
        }
    }
    input.extend_from_slice(&w_elems);
    target.extend_from_slice(&r_elems);
    // Placeholder identity permutation; `prove_epoch` swaps in the real hint.
    let permuted = b
        .add_permute(&input, (0..l).collect::<Vec<_>>())
        .expect("permute mset");
    for r in 0..l {
        b.connect(permuted[r], target[r]);
    }

    let circuit = b.build().expect("build countmin_omc_ungrouped circuit");

    let config = make_leaf_config();
    let table_packing = TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
    let mut preprocessors = vec![
        poseidon2_preprocessor::<Val>(),
        recompose_preprocessor::<Val>(false),
    ];
    preprocessors.push(permute_preprocessor::<Val>());
    preprocessors.push(range_preprocessor::<Val>());
    let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
    air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
    air_builders.extend(permute_air_builders::<ConfigWithFriParams, 4>(1));
    air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
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
        .expect("get_airs_and_degrees_with_prep (omc_ungrouped)");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.d() != 4);
    prover.register_permute_table::<4>();
    prover.register_range_table::<4>();
    if expose_boundary {
        prover.register_expose_table::<4>();
    }
    let trace_rows: u64 = ext_degrees.iter().map(|&d| 1u64 << d).sum();

    CmOmcUngroupedLeafCircuit {
        params,
        circuit,
        prover,
        circuit_prover_data: Rc::new(circuit_prover_data),
        trace_rows,
        log_heights: ext_degrees,
    }
}

// ─── Native witness ─────────────────────────────────────────────────────────

/// Native per-access witness: `(address, value, r_z)` in access order plus the
/// 31-bit integer the prover's bucket bits encode, and the resulting final
/// cells. Honest unless a test knob is set.
struct NativeWitness {
    bits_int: Vec<u64>,
    r: Vec<Challenge>,
    final_cells: Vec<Val>,
    addr: Vec<u64>,
    value: Vec<Val>,
    allow_reuse: bool,
}

fn native_witness(
    params: CmOmcUngroupedParams,
    initial: &CountMinState,
    batch: &[CountMinUpdate],
    tamper: Tamper,
) -> NativeWitness {
    let CmOmcUngroupedParams { d, w, .. } = params;
    let p = p_u64();
    let n_acc = params.num_accesses();
    let mut bits_int = Vec::with_capacity(n_acc);
    let mut addr = Vec::with_capacity(n_acc);
    let mut value = Vec::with_capacity(n_acc);
    for (k, u) in batch.iter().enumerate() {
        let dg = key_digest(u.key);
        for i in 0..d {
            let hvi = <Val as PrimeField64>::as_canonical_u64(&dg[i]);
            let mut x = hvi;
            if tamper == (Tamper::NonCanonical { k, i }) {
                x = hvi + p;
                assert!(
                    x < (1u64 << val_bits()),
                    "non-canonical tamper needs digest coeff < 2^31 − p"
                );
            }
            bits_int.push(x);
            addr.push((i * w) as u64 + (x % w as u64));
            value.push(Val::from_u32(u.value));
            debug_assert!(
                !matches!(tamper, Tamper::None)
                    || (x % w as u64) as usize
                        == hash_cell_prf(
                            i,
                            <Val as PrimeField64>::as_canonical_u64(&Val::from_u64(u.key)),
                            w
                        )
            );
        }
    }
    // Effective address each access acts on (differs from `addr` only for the
    // r-extension re-route).
    let mut eff = addr.clone();
    let mut r3 = vec![Val::ZERO; n_acc];
    if let Tamper::RExtension { z, c } = tamper {
        let x4 = ext_x() * ext_x() * ext_x() * ext_x();
        let wv = <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&x4)[0];
        r3[z] = (Val::from_u64(c as u64) - Val::from_u64(addr[z])) * wv.inverse();
        eff[z] = c as u64;
    }
    // Running values in stream order.
    let mut cur: Vec<Val> = initial
        .counters
        .iter()
        .flatten()
        .map(|&c| Val::from_u32(c))
        .collect();
    let old = cur.clone();
    let mut r = Vec::with_capacity(n_acc);
    let mut inflate_c: Option<Val> = None;
    for z in 0..n_acc {
        let a = eff[z] as usize;
        let mut r0 = cur[a];
        let mut advance = true;
        if let Tamper::InflateViaReads { z1, z2 } = tamper {
            assert!(z1 < z2 && addr[z1] == addr[z2] && value[z2] == Val::ZERO);
            if z == z1 {
                inflate_c = Some(cur[a]);
                r0 = cur[a] + Val::ONE;
            } else if z == z2 {
                r0 = inflate_c.expect("z1 before z2") + Val::ONE;
                advance = false; // v = 0: the running value is unchanged
            }
        }
        let rz = Challenge::from_basis_coefficients_slice(&[r0, Val::ZERO, Val::ZERO, r3[z]])
            .expect("4 coeffs");
        r.push(rz);
        if advance {
            cur[a] = r0 + value[z];
        }
    }
    let mut final_cells = cur;
    let mut allow_reuse = false;
    match tamper {
        Tamper::BumpUntouched => {
            let touched: std::collections::HashSet<u64> = eff.iter().copied().collect();
            let u = (0..final_cells.len())
                .find(|a| !touched.contains(&(*a as u64)))
                .expect("an untouched cell exists");
            final_cells[u] += Val::ONE;
            allow_reuse = true;
        }
        Tamper::RevertTouched => {
            let a = eff[0] as usize;
            final_cells[a] = old[a];
            allow_reuse = true;
        }
        Tamper::DropLastRecord => {
            for z in n_acc - d..n_acc {
                let a = eff[z] as usize;
                final_cells[a] -= value[z];
            }
            allow_reuse = true;
        }
        Tamper::InflateViaReads { .. } => {
            allow_reuse = true;
        }
        _ => {}
    }
    NativeWitness {
        bits_int,
        r,
        final_cells,
        addr,
        value,
        allow_reuse,
    }
}

fn state_from_cells(d: usize, w: usize, cells: &[Val]) -> CountMinState {
    use crate::sketch::countmin::CountMinParams;
    let counters: Vec<Vec<u32>> = (0..d)
        .map(|i| {
            (0..w)
                .map(|b| <Val as PrimeField64>::as_canonical_u64(&cells[i * w + b]) as u32)
                .collect()
        })
        .collect();
    CountMinState {
        counters,
        params: CountMinParams { d, w },
    }
}

impl CmOmcUngroupedLeafCircuit {
    /// Prove one epoch on the prebuilt circuit from an arbitrary committed
    /// `initial_state`.
    pub fn prove_epoch(
        &mut self,
        initial_state: CountMinState,
        batch: Vec<CountMinUpdate>,
    ) -> CountMinOmcUngroupedProof {
        let params = self.params;
        assert_eq!(initial_state.params.d, params.d);
        assert_eq!(initial_state.params.w, params.w);
        assert_eq!(batch.len(), params.batch, "batch.len() != params.batch");
        let CmOmcUngroupedParams { d, w, .. } = params;
        let num_cells = params.num_cells();
        let n_acc = params.num_accesses();
        let nb = val_bits();
        let tamper = knobs().tamper;

        // ─── Native side ─────────────────────────────────────────────────────
        let nw = native_witness(params, &initial_state, &batch, tamper);
        let committed_final = state_from_cells(d, w, &nw.final_cells);
        if tamper == Tamper::None {
            // The certified relation equals the natively-applied Count-Min.
            let mut expect = initial_state.clone();
            for u in &batch {
                apply_update_prf(&mut expect, u);
            }
            assert_eq!(
                expect.counters, committed_final.counters,
                "field replay diverged from native u32 Count-Min (counter ≥ p?)"
            );
        }
        let initial_commit = commit_countmin(&initial_state);
        let final_commit = commit_countmin(&committed_final);
        let batch_commit = commit_batch(&batch);

        // Multiset hint (same element values in both enc modes).
        let o_flat: Vec<Val> = initial_state
            .counters
            .iter()
            .flatten()
            .map(|&c| Val::from_u32(c))
            .collect();
        let mut input_n: Vec<Challenge> = Vec::with_capacity(num_cells + n_acc);
        let mut target_n: Vec<Challenge> = Vec::with_capacity(num_cells + n_acc);
        for a in 0..num_cells {
            input_n.push(enc_native(a as u64, o_flat[a].into()));
            target_n.push(enc_native(a as u64, nw.final_cells[a].into()));
        }
        for z in 0..n_acc {
            let v: Challenge = nw.value[z].into();
            input_n.push(enc_native(nw.addr[z], nw.r[z] + v));
            target_n.push(enc_native(nw.addr[z], nw.r[z]));
        }
        let sigma = build_sigma(&input_n, &target_n, nw.allow_reuse);
        self.circuit
            .update_permute_witnesses(&[sigma])
            .expect("update permute witnesses (countmin_omc_ungrouped)");

        // ─── Public + private values (order == allocation order) ─────────────
        let mut public_inputs: Vec<Challenge> = Vec::new();
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&initial_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&final_commit));
        public_inputs.extend_from_slice(&pack_commit_to_challenge(&CountMinCommit(batch_commit.0)));

        let mut private_inputs: Vec<Challenge> =
            Vec::with_capacity(2 * num_cells / 4 + 6 * batch.len() + n_acc * (nb + 1));
        private_inputs.extend_from_slice(&pack_cells(&o_flat));
        let n_flat: Vec<Val> = committed_final
            .counters
            .iter()
            .flatten()
            .map(|&c| Val::from_u32(c))
            .collect();
        private_inputs.extend_from_slice(&pack_cells(&n_flat));
        private_inputs.extend_from_slice(&pack_batch_to_challenge(&batch));
        for u in &batch {
            private_inputs.push(Challenge::from_u32((u.key & 0xFFFF_FFFF) as u32));
            private_inputs.push(Challenge::from_u32((u.key >> 32) as u32));
            private_inputs.push(Challenge::from_u32(u.value));
        }
        for u in &batch {
            let dg = key_digest(u.key);
            private_inputs
                .push(Challenge::from_basis_coefficients_slice(&dg[0..4]).expect("4 coeffs"));
            private_inputs
                .push(Challenge::from_basis_coefficients_slice(&dg[4..8]).expect("4 coeffs"));
        }
        for z in 0..n_acc {
            let x = nw.bits_int[z];
            for j in 0..nb {
                private_inputs.push(Challenge::from_u64((x >> j) & 1));
            }
        }
        private_inputs.extend_from_slice(&nw.r);

        // ─── Run + prove ─────────────────────────────────────────────────────
        let t_w = std::time::Instant::now();
        let traces = {
            let mut runner = self.circuit.runner();
            runner.set_public_inputs(&public_inputs).expect("set pubs");
            runner
                .set_private_inputs(&private_inputs)
                .expect("set privs");
            runner.run().expect("run countmin_omc_ungrouped")
        };
        let witness = t_w.elapsed();
        let t_p = std::time::Instant::now();
        let proof = self
            .prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("prove_all_tables (omc_ungrouped)");
        let prove = t_p.elapsed();
        let t_v = std::time::Instant::now();
        self.prover
            .verify_all_tables(&proof)
            .expect("self-verify countmin_omc_ungrouped leaf");
        crate::recursion::recursive::timing::record(
            crate::recursion::recursive::timing::LeafTiming {
                witness,
                prove,
                verify: t_v.elapsed(),
                trace_rows: self.trace_rows,
            },
        );

        CountMinOmcUngroupedProof {
            output: RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)),
            initial_commit,
            final_commit,
            batch_commit: CountMinCommit(batch_commit.0),
            params,
        }
    }
}

/// Prove one epoch (builds the leaf, then proves).
pub fn prove_countmin_omc_ungrouped(
    params: CmOmcUngroupedParams,
    initial_state: CountMinState,
    batch: Vec<CountMinUpdate>,
) -> CountMinOmcUngroupedProof {
    build_countmin_omc_ungrouped_leaf(params, false).prove_epoch(initial_state, batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::Sketch;
    use crate::sketch::countmin::CountMinParams;
    use crate::sketch::countmin_v9::CountMinV9;

    fn empty(d: usize, w: usize) -> CountMinState {
        CountMinV9::new(&CountMinParams { d, w })
    }

    fn seeded_prior(d: usize, w: usize, n: u64) -> CountMinState {
        let mut prior = empty(d, w);
        for k in 0..n {
            apply_update_prf(
                &mut prior,
                &CountMinUpdate {
                    key: k.wrapping_mul(0x9E37_79B9) ^ 0x55,
                    value: 1 + (k as u32 % 4),
                },
            );
        }
        prior
    }

    fn batch_of(m: usize, seed: u64) -> Vec<CountMinUpdate> {
        (0..m)
            .map(|i| CountMinUpdate {
                key: (i as u64).wrapping_mul(0xABCD_1234) ^ seed,
                value: 1 + (i as u32 % 5),
            })
            .collect()
    }

    fn native_final(prior: &CountMinState, batch: &[CountMinUpdate]) -> CountMinState {
        let mut s = prior.clone();
        for u in batch {
            apply_update_prf(&mut s, u);
        }
        s
    }

    fn with_knobs<T>(k: Knobs, f: impl FnOnce() -> T) -> T {
        let prev = KNOBS.with(|c| c.replace(k));
        let out = f();
        KNOBS.with(|c| c.set(prev));
        out
    }

    thread_local! {
        static SILENCE_PANICS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    static FILTER_HOOK: std::sync::Once = std::sync::Once::new();

    /// `catch_unwind` without printing the (expected) panic. The process-wide
    /// hook is installed ONCE and consults a thread-local flag, so parallel
    /// tests never swap each other's hooks (the previous take/set-hook pair
    /// raced under `--test-threads > 1`).
    fn silently<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> std::thread::Result<T> {
        FILTER_HOOK.call_once(|| {
            let default = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if !SILENCE_PANICS.with(|s| s.get()) {
                    default(info);
                }
            }));
        });
        let prev = SILENCE_PANICS.with(|s| s.replace(true));
        let r = std::panic::catch_unwind(f);
        SILENCE_PANICS.with(|s| s.set(prev));
        r
    }

    /// Run `f` expecting a panic; returns the panic message.
    fn expect_reject(k: Knobs, f: impl FnOnce() + std::panic::UnwindSafe) -> String {
        let prev = KNOBS.with(|c| c.replace(k));
        let res = silently(f);
        KNOBS.with(|c| c.set(prev));
        match res {
            Ok(()) => panic!("tampered witness was ACCEPTED (knobs {k:?})"),
            Err(e) => e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".into()),
        }
    }

    /// Which layer rejected: the trace generator (a connect/ALU conflict — the
    /// supplied witness violates a constraint) or the proof system (prove /
    /// verify, e.g. an unbalanced LogUp bus).
    fn layer(msg: &str) -> &'static str {
        if msg.contains("run countmin_omc_ungrouped") {
            RUNNER
        } else if msg.contains("prove_all_tables") || msg.contains("self-verify") {
            "STARK prove/verify"
        } else {
            "other"
        }
    }
    const RUNNER: &str = "runner (constraint violated by the supplied witness)";

    /// A runner-level rejection must be the witness generator refusing a
    /// value that conflicts with a constraint (not some unrelated panic).
    fn assert_runner_conflict(what: &str, msg: &str) {
        assert_eq!(layer(msg), RUNNER, "{what}: unexpected rejection layer: {msg}");
        assert!(
            msg.contains("WitnessConflict"),
            "{what}: runner rejected for a reason other than a witness conflict: {msg}"
        );
    }

    // ── Native model ───────────────────────────────────────────────────────

    /// The native field replay (stream-order reads) equals the native u32
    /// Count-Min, and the honest multiset sides are equal as multisets.
    #[test]
    fn native_model_matches_countmin_and_balances() {
        for &(d, w, m) in &[(1usize, 4usize, 3usize), (3, 8, 16), (4, 16, 40), (7, 32, 64)] {
            let params = CmOmcUngroupedParams {
                d,
                w,
                batch: m,
                affine_enc: false,
            };
            let prior = seeded_prior(d, w, 17);
            let batch = batch_of(m, 0x7);
            let nw = native_witness(params, &prior, &batch, Tamper::None);
            let got = state_from_cells(d, w, &nw.final_cells);
            assert_eq!(got.counters, native_final(&prior, &batch).counters);
            // multiset balance (bijective sigma exists)
            let o: Vec<Val> = prior.counters.iter().flatten().map(|&c| Val::from_u32(c)).collect();
            let mut inp = Vec::new();
            let mut tgt = Vec::new();
            for a in 0..d * w {
                inp.push(enc_native(a as u64, o[a].into()));
                tgt.push(enc_native(a as u64, nw.final_cells[a].into()));
            }
            for z in 0..m * d {
                let v: Challenge = nw.value[z].into();
                inp.push(enc_native(nw.addr[z], nw.r[z] + v));
                tgt.push(enc_native(nw.addr[z], nw.r[z]));
            }
            let s = build_sigma(&inp, &tgt, false);
            let mut seen = vec![false; s.len()];
            for &i in &s {
                assert!(!seen[i], "sigma must be a bijection");
                seen[i] = true;
            }
        }
    }

    /// Multiset equality of `(addr, value)` pairs (sort + compare).
    fn mset_eq(mut a: Vec<(u64, u64)>, mut b: Vec<(u64, u64)>) -> bool {
        a.sort_unstable();
        b.sort_unstable();
        a == b
    }

    /// **Exhaustive check of the soundness claim**, independent of the
    /// honest witness: over a small domain, enumerate EVERY choice of the free
    /// reads `r` and EVERY claimed final value `N`, and check that
    /// `M_old ⊎ W == M_new ⊎ R` (on `(address, value)` pairs) holds only if
    /// `N[a] = O[a] + Σ_{a_z=a} v_z` for every address — and that it holds
    /// for at least one choice of reads (completeness).
    ///
    /// Case 1: one address, three accesses. Case 2: two addresses, two
    /// accesses, every address pattern (so values cannot be traded across
    /// addresses). Case 3 (non-additive update): the same search for a
    /// non-additive update `write = max(r, v)` DOES find a multiset-balanced
    /// wrong `N` — which is why max/OR/min/replace need a timestamp.
    #[test]
    fn native_multiset_forces_additive_sum_exhaustive() {
        // Case 1: one address, accesses v = (v1, v2, v3).
        let (vmax, rmax) = (3u64, 10u64);
        for o in 0..3u64 {
            for v1 in 0..vmax {
                for v2 in 0..vmax {
                    for v3 in 0..vmax {
                        let vs = [v1, v2, v3];
                        let want = o + v1 + v2 + v3;
                        let mut complete = false;
                        for r1 in 0..rmax {
                            for r2 in 0..rmax {
                                for r3 in 0..rmax {
                                    let rs = [r1, r2, r3];
                                    let mut inp = vec![(0, o)];
                                    let mut tgt = vec![];
                                    for j in 0..3 {
                                        inp.push((0, rs[j] + vs[j]));
                                        tgt.push((0, rs[j]));
                                    }
                                    for n in 0..rmax + vmax * 3 {
                                        let mut t = tgt.clone();
                                        t.push((0, n));
                                        if mset_eq(inp.clone(), t) {
                                            assert_eq!(n, want, "O={o} v={vs:?} r={rs:?}");
                                            complete = true;
                                        }
                                    }
                                }
                            }
                        }
                        assert!(complete, "honest reads must balance (O={o} v={vs:?})");
                    }
                }
            }
        }
        // Case 2: two addresses, two accesses at addresses (a1, a2).
        let (vmax, rmax) = (3u64, 7u64);
        for (a1, a2) in [(0u64, 0u64), (0, 1), (1, 0), (1, 1)] {
            for o0 in 0..2u64 {
                for o1 in 0..2u64 {
                    for v1 in 0..vmax {
                        for v2 in 0..vmax {
                            let mut want = [o0, o1];
                            want[a1 as usize] += v1;
                            want[a2 as usize] += v2;
                            let mut complete = false;
                            for r1 in 0..rmax {
                                for r2 in 0..rmax {
                                    let inp = vec![(0, o0), (1, o1), (a1, r1 + v1), (a2, r2 + v2)];
                                    for n0 in 0..rmax + 2 * vmax {
                                        for n1 in 0..rmax + 2 * vmax {
                                            let tgt = vec![(0, n0), (1, n1), (a1, r1), (a2, r2)];
                                            if mset_eq(inp.clone(), tgt) {
                                                assert_eq!([n0, n1], want);
                                                complete = true;
                                            }
                                        }
                                    }
                                }
                            }
                            assert!(complete);
                        }
                    }
                }
            }
        }
        // Case 3: non-additive (max) update is NOT pinned without timestamps.
        let mut counterexample = None;
        'search: for o in 0..3u64 {
            for v in 1..4u64 {
                for r in 0..8u64 {
                    for n in 0..8u64 {
                        let inp = vec![(0, o), (0, r.max(v))];
                        let tgt = vec![(0, n), (0, r)];
                        if mset_eq(inp, tgt) && n != o.max(v) {
                            counterexample = Some((o, v, r, n));
                            break 'search;
                        }
                    }
                }
            }
        }
        let (o, v, r, n) = counterexample.expect("max update admits a wrong balanced N");
        println!("max-update counterexample: O={o} v={v} read r={r} ⇒ accepted N={n} ≠ {}", o.max(v));
    }

    // ── Honest round-trips (real STARK prove + verify) ─────────────────────

    fn round_trip(d: usize, w: usize, m: usize, affine_enc: bool, prior: CountMinState) {
        let params = CmOmcUngroupedParams {
            d,
            w,
            batch: m,
            affine_enc,
        };
        let batch = batch_of(m, 0x7 ^ (d as u64) << 8);
        let expect = native_final(&prior, &batch);
        let r = prove_countmin_omc_ungrouped(params, prior.clone(), batch);
        assert_eq!(r.initial_commit.0, commit_countmin(&prior).0);
        assert_eq!(r.final_commit.0, commit_countmin(&expect).0);
    }

    #[test]
    fn round_trip_small_nonempty_prior() {
        round_trip(2, 4, 2, false, seeded_prior(2, 4, 2));
        round_trip(2, 4, 2, true, seeded_prior(2, 4, 2));
    }

    #[test]
    fn round_trip_repeated_keys() {
        // Same key repeated → the same d cells are hit several times in one
        // batch (the chain r_{z_1} → … in stream order), plus a zero-value
        // padding record.
        let params = CmOmcUngroupedParams {
            d: 4,
            w: 8,
            batch: 5,
            affine_enc: false,
        };
        let mut prior = empty(4, 8);
        apply_update_prf(&mut prior, &CountMinUpdate { key: 7, value: 10 });
        let batch = vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 7, value: 2 },
            CountMinUpdate { key: 0, value: 0 },
            CountMinUpdate { key: 7, value: 1 },
        ];
        let expect = native_final(&prior, &batch);
        for affine in [false, true] {
            let r = prove_countmin_omc_ungrouped(
                CmOmcUngroupedParams {
                    affine_enc: affine,
                    ..params
                },
                prior.clone(),
                batch.clone(),
            );
            assert_eq!(r.final_commit.0, commit_countmin(&expect).0);
        }
    }

    #[test]
    fn round_trip_shapes() {
        round_trip(3, 64, 32, false, seeded_prior(3, 64, 40));
        round_trip(3, 64, 32, true, seeded_prior(3, 64, 40));
        round_trip(7, 128, 64, true, seeded_prior(7, 128, 60));
        round_trip(1, 4, 16, false, empty(1, 4));
    }

    /// A built leaf is reusable across epochs (only the permute hint changes).
    #[test]
    fn reuse_leaf_across_epochs() {
        let params = CmOmcUngroupedParams {
            d: 3,
            w: 16,
            batch: 8,
            affine_enc: true,
        };
        let mut leaf = build_countmin_omc_ungrouped_leaf(params, false);
        let mut state = seeded_prior(3, 16, 5);
        for e in 0..3u64 {
            let batch = batch_of(8, 0x100 + e);
            let next = native_final(&state, &batch);
            let r = leaf.prove_epoch(state.clone(), batch);
            assert_eq!(r.initial_commit.0, commit_countmin(&state).0);
            assert_eq!(r.final_commit.0, commit_countmin(&next).0);
            state = next;
        }
    }

    // ── Tamper tests ───────────────────────────────────────────────────────

    fn tamper_params(affine: bool) -> (CmOmcUngroupedParams, CountMinState, Vec<CountMinUpdate>) {
        let params = CmOmcUngroupedParams {
            d: 3,
            w: 16,
            batch: 6,
            affine_enc: affine,
        };
        (params, seeded_prior(3, 16, 7), batch_of(6, 0x5a))
    }

    /// Wrong final counter (a): an untouched cell bumped by +1.
    ///
    /// Rejected by the trace generator: the only input-side element at an
    /// untouched address `u` is `enc(u, O[u])` (no access writes there), so
    /// the claimed `enc(u, O[u] + 1)` has no match, the non-bijective hint
    /// falls back to input 0, and `connect(permuted[r], target[r])` conflicts.
    /// A witness-path STARK-level variant cannot be set up for this tamper;
    /// a trace-forging adversary is not covered by this test (see
    /// `tamper_inflate_via_free_reads_rejected_by_stark` for the STARK-level
    /// "wrong counter" case that the free reads could otherwise enable).
    #[test]
    fn tamper_bump_untouched_rejected() {
        for affine in [false, true] {
            let (params, prior, batch) = tamper_params(affine);
            let msg = expect_reject(
                Knobs {
                    tamper: Tamper::BumpUntouched,
                    ..Knobs::default()
                },
                move || {
                    let _ = prove_countmin_omc_ungrouped(params, prior, batch);
                },
            );
            println!("bump_untouched (affine={affine}): rejected at {} — {msg}", layer(&msg));
            assert_runner_conflict("bump_untouched", &msg);
        }
    }

    /// Wrong final counter (b): a touched cell reverted to its old value
    /// (suppression). Every claimed value still occurs on the input side, so
    /// the non-bijective hint lets the trace generator finish; only the
    /// PermuteBus LogUp balance can reject — asserts it is the STARK layer.
    #[test]
    fn tamper_revert_touched_rejected_by_stark() {
        for affine in [false, true] {
            let (params, prior, batch) = tamper_params(affine);
            let msg = expect_reject(
                Knobs {
                    tamper: Tamper::RevertTouched,
                    ..Knobs::default()
                },
                move || {
                    let _ = prove_countmin_omc_ungrouped(params, prior, batch);
                },
            );
            println!("revert_touched (affine={affine}): rejected at {} — {msg}", layer(&msg));
            assert_eq!(layer(&msg), "STARK prove/verify");
        }
    }

    /// A record's increment dropped (the last record, on all d cells), honest
    /// reads. As above, rejection must come from the STARK.
    #[test]
    fn tamper_drop_record_rejected_by_stark() {
        for affine in [false, true] {
            let (params, prior, batch) = tamper_params(affine);
            let msg = expect_reject(
                Knobs {
                    tamper: Tamper::DropLastRecord,
                    ..Knobs::default()
                },
                move || {
                    let _ = prove_countmin_omc_ungrouped(params, prior, batch);
                },
            );
            println!("drop_last_record (affine={affine}): rejected at {} — {msg}", layer(&msg));
            assert_eq!(layer(&msg), "STARK prove/verify");
        }
    }

    /// Wrong final counter (c): a touched cell inflated by +1 using
    /// ADVERSARIAL free reads (`Tamper::InflateViaReads`) — the attack
    /// surface that ungrouping opens. Records 1 and 4 share a key (value 3
    /// and 0), so their row-0 accesses hit the same cell. Every claimed value
    /// occurs on the input side, the runner finishes, and the rejection must
    /// come from the STARK (PermuteBus LogUp multiplicities).
    #[test]
    fn tamper_inflate_via_free_reads_rejected_by_stark() {
        for affine in [false, true] {
            let (params, prior, mut batch) = tamper_params(affine);
            let key = batch[1].key;
            batch[1] = CountMinUpdate { key, value: 3 };
            batch[4] = CountMinUpdate { key, value: 0 };
            let d = params.d;
            let (z1, z2) = (d, 4 * d); // row 0 of records 1 and 4
            let honest = native_final(&prior, &batch);
            // The tamper really claims a different (inflated) state.
            let nw = native_witness(params, &prior, &batch, Tamper::InflateViaReads { z1, z2 });
            let claimed = state_from_cells(d, params.w, &nw.final_cells);
            let a = nw.addr[z1] as usize;
            assert_eq!(
                claimed.counters[0][a],
                honest.counters[0][a] + 1,
                "tamper must inflate cell {a} by exactly 1"
            );
            let msg = expect_reject(
                Knobs {
                    tamper: Tamper::InflateViaReads { z1, z2 },
                    ..Knobs::default()
                },
                move || {
                    let _ = prove_countmin_omc_ungrouped(params, prior, batch);
                },
            );
            println!("inflate_via_free_reads (affine={affine}): rejected at {} — {msg}", layer(&msg));
            assert_eq!(layer(&msg), "STARK prove/verify");
        }
    }

    /// Find a batch whose record `k` has digest coefficient `i` below
    /// `2^31 − p`, so the non-canonical decomposition `x + p` fits 31 bits.
    fn noncanonical_setup(i: usize) -> (CmOmcUngroupedParams, CountMinState, Vec<CountMinUpdate>, usize) {
        let params = CmOmcUngroupedParams {
            d: 3,
            w: 16,
            batch: 4,
            affine_enc: false,
        };
        let bound = (1u64 << val_bits()) - p_u64();
        let key = (1u64..)
            .find(|&kk| <Val as PrimeField64>::as_canonical_u64(&key_digest(kk)[i]) < bound)
            .expect("a key with a small digest coeff");
        let mut batch = batch_of(4, 0x99);
        let k = 2;
        batch[k] = CountMinUpdate { key, value: 4 };
        (params, seeded_prior(3, 16, 7), batch, k)
    }

    /// Non-canonical bucket bits (`x + p` ⇒ bucket + 1, a shifted address),
    /// with the canonical check ON: rejected.
    #[test]
    fn noncanonical_bits_rejected() {
        for affine in [false, true] {
            let (params, prior, batch, k) = noncanonical_setup(1);
            let params = CmOmcUngroupedParams {
                affine_enc: affine,
                ..params
            };
            let msg = expect_reject(
                Knobs {
                    tamper: Tamper::NonCanonical { k, i: 1 },
                    ..Knobs::default()
                },
                move || {
                    let _ = prove_countmin_omc_ungrouped(params, prior, batch);
                },
            );
            println!("noncanonical (affine={affine}): rejected at {} — {msg}", layer(&msg));
            assert_runner_conflict("noncanonical", &msg);
        }
    }

    /// Same shifted-address witness with the canonical check REMOVED: the proof
    /// verifies and certifies a final state that differs from the true
    /// Count-Min (the record is credited one bucket over). Demonstrates that
    /// the canonical-bits check is load-bearing, and that the tamper really moves the address.
    #[test]
    fn noncanonical_bits_accepted_without_check() {
        let (params, prior, batch, k) = noncanonical_setup(1);
        let honest = native_final(&prior, &batch);
        let r = with_knobs(
            Knobs {
                tamper: Tamper::NonCanonical { k, i: 1 },
                skip_canonical: true,
                ..Knobs::default()
            },
            || prove_countmin_omc_ungrouped(params, prior.clone(), batch.clone()),
        );
        assert_ne!(
            r.final_commit.0,
            commit_countmin(&honest).0,
            "the accepted proof certifies a mis-routed (wrong) state"
        );
    }

    /// An extension-valued read `r_z = r0 + r3·X³` re-routes access `z` to an
    /// arbitrary cell `c` because `r3·X⁴ = W·r3` lands in the address
    /// coordinate. With the 31-bit range check (base-field) ON: rejected.
    #[test]
    fn r_extension_reroute_rejected() {
        for affine in [false, true] {
            let (params, prior, batch) = tamper_params(affine);
            let msg = expect_reject(
                Knobs {
                    tamper: Tamper::RExtension { z: 4, c: 0 },
                    ..Knobs::default()
                },
                move || {
                    let _ = prove_countmin_omc_ungrouped(params, prior, batch);
                },
            );
            println!("r_extension (affine={affine}): rejected at {} — {msg}", layer(&msg));
            assert_runner_conflict("r_extension", &msg);
        }
    }

    /// …and with the range check REMOVED the re-routed state is accepted:
    /// the base-field constraint on `r_z` is load-bearing.
    #[test]
    fn r_extension_reroute_accepted_without_range_check() {
        for affine in [false, true] {
            let (params, prior, batch) = tamper_params(affine);
            let honest = native_final(&prior, &batch);
            let r = with_knobs(
                Knobs {
                    tamper: Tamper::RExtension { z: 4, c: 0 },
                    skip_r_range: true,
                    ..Knobs::default()
                },
                || prove_countmin_omc_ungrouped(params, prior.clone(), batch.clone()),
            );
            assert_ne!(r.final_commit.0, commit_countmin(&honest).0);
        }
    }

    /// Per-record ALU / range-lookup cost breakdown (prints; `#[ignore]`d).
    /// Differencing two batch sizes isolates the per-record cost; toggling the
    /// test knobs isolates the canonical check and the `r_z` range check.
    ///
    /// Run: `cargo test --release --lib countmin_omc_ungrouped::tests::op_count_breakdown -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn op_count_breakdown() {
        fn counts(p: CmOmcUngroupedParams, k: Knobs) -> (usize, usize) {
            with_knobs(k, || {
                let leaf = build_countmin_omc_ungrouped_leaf(p, false);
                let mut alu = 0;
                let mut range = 0;
                for op in &leaf.circuit.ops {
                    match op {
                        p3_circuit::ops::Op::Alu { .. } => alu += 1,
                        p3_circuit::ops::Op::NonPrimitiveOpWithExecutor {
                            executor, inputs, ..
                        } if *executor.op_type() == p3_circuit::ops::NpoTypeId::range() => {
                            range += inputs[0].len()
                        }
                        _ => {}
                    }
                }
                (alu, range)
            })
        }
        for &(d, w) in &[(3usize, 1024usize), (7, 16384)] {
            for affine in [false, true] {
                let p = |m| CmOmcUngroupedParams {
                    d,
                    w: if w > 1024 { 64 } else { w }, // per-record cost: only log w matters
                    batch: m,
                    affine_enc: affine,
                };
                let lw = w.trailing_zeros() as usize;
                let lw_used = p(8).w.trailing_zeros() as usize;
                for (name, k) in [
                    ("full", Knobs::default()),
                    (
                        "no_canonical",
                        Knobs {
                            skip_canonical: true,
                            ..Knobs::default()
                        },
                    ),
                    (
                        "no_r_range",
                        Knobs {
                            skip_r_range: true,
                            ..Knobs::default()
                        },
                    ),
                    (
                        "+omc_unused",
                        Knobs {
                            decompose_unused: true,
                            ..Knobs::default()
                        },
                    ),
                ] {
                    let (a8, r8) = counts(p(8), k);
                    let (a16, r16) = counts(p(16), k);
                    let per_rec_alu = (a16 - a8) as f64 / 8.0 + (d * (lw - lw_used)) as f64;
                    println!(
                        "d={d} w={w} affine={affine} {name:13}: ALU ops/record = {per_rec_alu:.1} (= {:.1}/access), range lookups/record = {:.1}",
                        per_rec_alu / d as f64,
                        (r16 - r8) as f64 / 8.0
                    );
                }
            }
        }
    }

    /// Canonical gadget arithmetic (mirror of hll_omc's test for the local copy).
    #[test]
    fn canonical_gadget_logic() {
        let n = val_bits();
        let m = canon_low_bits();
        let p = p_u64() as u128;
        let rejected = |v: u128| -> bool {
            let hi_mask = (1u128 << (n - m)) - 1;
            ((v >> m) & hi_mask) == hi_mask && (v & ((1u128 << m) - 1)) != 0
        };
        for x in [0u128, 1, 7, 255, p - 2, p - 1] {
            assert!(!rejected(x));
        }
        for x in 0u128..6 {
            assert!(rejected(x + p));
        }
        assert!(rejected(p));
    }

    // ── Backend probe: are decompose coefficients bound? (not specific to this leaf) ──

    /// Tiny circuit: `h = Poseidon2(const 123)`, `c = decompose(h[0])`;
    /// `c[0]` feeds `t = c0·key` and `u = c0 + key` (so it has a creator AND a
    /// reader on the `WitnessChecks` bus), `c[1..4]` are consumed by a
    /// self-`mul` (the `hll_omc` pattern). `coeff_ctl = false` is the NPO
    /// configuration every leaf in this crate uses (standard `recompose`
    /// table); `coeff_ctl = true` routes the decomposition through the fork's
    /// `recompose/coeff` table (per-coefficient `WitnessChecks` receives).
    fn probe_circuit(
        coeff_ctl: bool,
    ) -> (
        p3_circuit::Circuit<Challenge>,
        BatchStarkProver<ConfigWithFriParams>,
        Rc<CircuitProverData<ConfigWithFriParams>>,
    ) {
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        if coeff_ctl {
            b.set_recompose_coeff_ctl_for_decompose_links(true);
        }
        let key = b.alloc_const(Challenge::from(Val::from_u64(123)), "key");
        let h = b.add_hash_slice(&cfg, &[key], true).expect("hash");
        let c = b.decompose_ext_to_base_coeffs::<Val>(h[0]).expect("decompose");
        // Two separate (non-fusable) uses: the first ALU row creates c0, the
        // second reads it (non-zero bus multiplicity).
        let _t = b.mul(c[0], key);
        let _u = b.add(c[0], key);
        for &x in &c[1..4] {
            let _ = b.mul(x, x);
        }
        b.tag(c[0], "c0").unwrap();
        let circuit = b.build().expect("build probe");
        let config = make_leaf_config();
        let table_packing =
            TablePacking::new(1, 2).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);
        let preprocessors = vec![
            poseidon2_preprocessor::<Val>(),
            recompose_preprocessor::<Val>(coeff_ctl),
        ];
        let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
        air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, coeff_ctl));
        let (airs_degrees, pc, npc) =
            get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
                &circuit,
                &table_packing,
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .expect("prep probe");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext);
        let cpd = Rc::new(CircuitProverData::new(pd, pc, npc));
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
        prover.register_recompose_table::<4>(coeff_ctl);
        (circuit, prover, cpd)
    }

    /// Re-run the ALU table forward with `c0 := forged`: substitute every
    /// operand slot carrying a changed witness and recompute each touched
    /// row's output (Add/Mul/MulAdd). Poseidon2 / recompose rows and all
    /// constants are left untouched. With `consistent = false` the outputs are
    /// NOT recomputed (a control whose ALU constraint must fail).
    fn forge_alu(
        t: &mut p3_circuit::tables::Traces<Challenge>,
        c0w: p3_circuit::WitnessId,
        forged: Challenge,
        consistent: bool,
    ) -> usize {
        use p3_circuit::ops::AluOpKind;
        let mut changed: HashMap<p3_circuit::WitnessId, Challenge> = HashMap::new();
        changed.insert(c0w, forged);
        let mut rows = 0;
        for row in 0..t.alu_trace.indices.len() {
            let ix = t.alu_trace.indices[row];
            let mut hit = false;
            for s in 0..3 {
                if let Some(v) = changed.get(&ix[s]) {
                    t.alu_trace.values[row][s] = *v;
                    hit = true;
                }
            }
            if !hit {
                continue;
            }
            rows += 1;
            if !consistent {
                continue;
            }
            let v = t.alu_trace.values[row];
            let out = match t.alu_trace.op_kind[row] {
                AluOpKind::Add => v[0] + v[1],
                AluOpKind::Mul => v[0] * v[1],
                AluOpKind::MulAdd => v[0] * v[1] + v[2],
                k => panic!("probe forge: unexpected ALU kind {k:?}"),
            };
            t.alu_trace.values[row][3] = out;
            changed.insert(ix[3], out);
        }
        rows
    }

    /// Returns (honest result, control result, forged result).
    fn run_probe(coeff_ctl: bool) -> (Result<(), String>, Result<(), String>, Result<(), String>) {
        let limb0 = key_digest(123)[0];
        let forged: Challenge = (limb0 + Val::ONE).into();
        let (c, p, cpd) = probe_circuit(coeff_ctl);
        let c0w = c.tag_to_witness["c0"];
        let try_prove = |t: &p3_circuit::tables::Traces<Challenge>| -> Result<(), String> {
            let r = silently(std::panic::AssertUnwindSafe(|| {
                match p.prove_all_tables(t, &cpd) {
                    Err(e) => Err(format!("prove: {e:?}")),
                    Ok(proof) => p
                        .verify_all_tables(&proof)
                        .map_err(|e| format!("verify: {e:?}")),
                }
            }));
            r.unwrap_or_else(|_| Err("panic".into()))
        };
        let honest = c.runner().run().expect("honest probe run");
        let pos = honest
            .alu_trace
            .indices
            .iter()
            .position(|ix| ix[0] == c0w)
            .expect("c0 ALU row");
        assert_eq!(
            honest.alu_trace.values[pos][0],
            Challenge::from(limb0),
            "honest c0 = limb 0 of the digest"
        );
        let h = try_prove(&honest);
        let mut t = c.runner().run().expect("re-run");
        assert_eq!(forge_alu(&mut t, c0w, forged, false), 2);
        let ctrl = try_prove(&t);
        let mut t = c.runner().run().expect("re-run");
        assert_eq!(forge_alu(&mut t, c0w, forged, true), 2);
        let f = try_prove(&t);
        println!(
            "probe(coeff_ctl={coeff_ctl}): honest={h:?} control={ctrl:?} forged(c0={} vs true {})={f:?}",
            limb0 + Val::ONE,
            limb0
        );
        (h, ctrl, f)
    }

    /// **Probe: are `decompose_ext_to_base_coeffs` outputs bound to the packed
    /// value?** Honest traces are rewritten ONLY in the ALU rows that carry
    /// `c[0]` (`c[0] := limb0 + 1`, dependent outputs recomputed), leaving the
    /// Poseidon2 and recompose rows (and every constant) untouched — they keep
    /// the TRUE limbs of `h[0]` — then proven + verified with the SAME prover
    /// data. A control that breaks an ALU row's own constraint must reject.
    ///
    /// Observed at fork rev 19dcb37 with the standard `recompose` table (the
    /// configuration of every leaf in this crate): the forged proof VERIFIES,
    /// i.e. the decomposed coefficient is not bound to the packed value. The
    /// assertion is gated on [`crate::sketch::bind::probe::fork_binds_decompose`]:
    /// at the pinned rev the gap must reproduce; on a fork that binds
    /// decompose coefficients itself (the merged soundness fork) the forged
    /// proof must be REJECTED. `#[ignore]`d: it documents a backend property,
    /// not a property of this leaf.
    ///
    /// Run: `cargo test --release --lib countmin_omc_ungrouped::tests::probe_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn probe_decompose_coeff_binding() {
        let (h, ctrl, f) = run_probe(false);
        assert!(h.is_ok(), "honest probe must verify");
        assert!(ctrl.is_err(), "control must reject");
        if crate::sketch::bind::probe::fork_binds_decompose() {
            assert!(
                f.is_err(),
                "fork binds decompose coefficients (probe), yet the forged c0 verified"
            );
        } else {
            // A1: this leaf's soundness assumes decomposed coefficients are
            // base-field values bound to the packed digest.
            assert!(
                f.is_ok(),
                "gap no longer reproduces — decompose coefficients now look bound; revisit A1"
            );
        }
    }

    /// Same probe with `set_recompose_coeff_ctl_for_decompose_links(true)` and
    /// the split `recompose/coeff` table — a candidate backend-level fix.
    /// Outcome is printed, not asserted (exploratory).
    #[test]
    #[ignore]
    fn probe_decompose_coeff_binding_with_coeff_ctl() {
        let (h, ctrl, f) = run_probe(true);
        println!(
            "coeff_ctl: honest_ok={} control_rejected={} forged_rejected={}",
            h.is_ok(),
            ctrl.is_err(),
            f.is_err()
        );
    }
}
