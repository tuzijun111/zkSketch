//! Shared in-circuit gadgets for the Pattern-B leaves (SpaceSaving, GK).
//!
//! These mirror the primitives the §5.2 Count-Min leaf
//! ([`crate::leaf::countmin_final`]) builds inline, lifted out so the
//! SpaceSaving and Greenwald–Khanna leaves can share them:
//!
//! - [`vhash`] — a virtual 4-element hash target (commitment slot).
//! - [`assert_perm_cols`] — multiset-equality (grand-product) over **multi-column
//!   rows**, the plonky2 stand-in for the plonky3 `PermuteAir`. Folds each row's
//!   columns with powers of a Fiat-Shamir challenge `α`, then asserts the two
//!   shifted products match for two independent challenges `β₁, β₂` (soundness
//!   ≈ `(n/|F|)² ≈ 2⁻¹⁰⁰` over Goldilocks).
//! - [`is_zero`] — the standard `x == 0` flag, **forced** correct via a prover
//!   inverse witness (`x·zf == 0`, `zf = 1 − x·inv`). Pattern-B grouping must be
//!   exact (unlike linear Count-Min), so we use this rather than the
//!   honest-prover tag shortcut.

use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::config::{D, F};

/// A fresh 4-element hash target (used for the public commitment slots).
pub fn vhash(b: &mut CircuitBuilder<F, D>) -> HashOutTarget {
    HashOutTarget { elements: core::array::from_fn(|_| b.add_virtual_target()) }
}

/// Hash `cells` with Poseidon and connect the digest to `commit` (binds the
/// committed object to its witnessed cells).
pub fn bind_commit(b: &mut CircuitBuilder<F, D>, cells: Vec<Target>, commit: &HashOutTarget) {
    let h = b.hash_n_to_hash_no_pad::<PoseidonHash>(cells);
    for i in 0..4 {
        b.connect(h.elements[i], commit.elements[i]);
    }
}

/// Multiset-equality over multi-column rows: assert
/// `{ row_a[i] }_i == { row_b[i] }_i` where each row is folded as
/// `Σ_c α^c · col_c[i]`. `a` and `bcols` are equal-length lists of equal-length
/// columns (one entry per row column). Uses two independent shift challenges.
pub fn assert_perm_cols(b: &mut CircuitBuilder<F, D>, a: &[&[Target]], bcols: &[&[Target]]) {
    assert_eq!(a.len(), bcols.len(), "column count mismatch");
    let ncols = a.len();
    assert!(ncols >= 1);
    let n = a[0].len();
    for c in a.iter().chain(bcols.iter()) {
        assert_eq!(c.len(), n, "row count mismatch");
    }

    // Fiat-Shamir seed = all a columns ‖ all b columns.
    let mut seed: Vec<Target> = Vec::with_capacity(2 * ncols * n);
    for c in a {
        seed.extend_from_slice(c);
    }
    for c in bcols {
        seed.extend_from_slice(c);
    }
    let h = b.hash_n_to_hash_no_pad::<PoseidonHash>(seed);
    let alpha = h.elements[0];

    // α powers [1, α, α², …, α^{ncols-1}].
    let one = b.one();
    let mut alpha_pow = Vec::with_capacity(ncols);
    alpha_pow.push(one);
    for _ in 1..ncols {
        let prev = *alpha_pow.last().unwrap();
        alpha_pow.push(b.mul(prev, alpha));
    }

    let fold = |b: &mut CircuitBuilder<F, D>, cols: &[&[Target]], i: usize| -> Target {
        let mut acc = b.mul(alpha_pow[0], cols[0][i]);
        for c in 1..cols.len() {
            acc = b.mul_add(alpha_pow[c], cols[c][i], acc);
        }
        acc
    };

    for &beta in &[h.elements[1], h.elements[2]] {
        let mut pa = b.one();
        for i in 0..n {
            let f = fold(b, a, i);
            let term = b.add(f, beta);
            pa = b.mul(pa, term);
        }
        let mut pb = b.one();
        for i in 0..n {
            let f = fold(b, bcols, i);
            let term = b.add(f, beta);
            pb = b.mul(pb, term);
        }
        b.connect(pa, pb);
    }
}

/// `x == 0` flag, forced correct by the prover-supplied `inv`:
/// returns `zf = 1 − x·inv` and enforces `x·zf == 0`. When `x == 0`, `zf == 1`
/// for any `inv`; when `x != 0`, the constraint forces `inv = x⁻¹` and `zf == 0`.
/// So `zf` is a sound boolean equal to `[x == 0]`.
pub fn is_zero(b: &mut CircuitBuilder<F, D>, x: Target, inv: Target) -> Target {
    let one = b.one();
    let prod = b.mul(x, inv);
    let zf = b.sub(one, prod);
    let chk = b.mul(x, zf);
    let zero = b.zero();
    b.connect(chk, zero);
    zf
}
