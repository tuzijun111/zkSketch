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
//!   `β`-shifted products match, with `α, β` drawn from the degree-2 extension of
//!   Goldilocks (soundness `≤ n·max(1, k−1)/p² ≈ 2⁻¹⁰⁵` at `n = 2²⁰` rows,
//!   `k = 6` columns).
//! - [`is_zero`] — the standard `x == 0` flag, **forced** correct via a prover
//!   inverse witness (`x·zf == 0`, `zf = 1 − x·inv`). Pattern-B grouping must be
//!   exact (unlike linear Count-Min), so we use this rather than the
//!   honest-prover tag shortcut.

use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::ext_target::ExtensionTarget;
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
/// `β + Σ_c α^c · col_c[i]`. `a` and `bcols` are equal-length lists of
/// equal-length columns (one entry per row column).
///
/// The challenges live in the degree-`D` extension `F_{p^D}` (`D = 2`,
/// `|F_{p²}| ≈ 2¹²⁸`): `α = (h₀, h₁)` and `β = (h₂, h₃)`, where `h` is an
/// in-circuit Poseidon digest of every cell of both tables. If the row
/// multisets differ, `Π_i(β + A_i(α)) − Π_i(β + B_i(α))` is a nonzero
/// polynomial of total degree `≤ n·max(1, k−1)` (`k` columns, `n` rows), so by
/// Schwartz–Zippel a false claim passes with probability at most
/// `n·max(1, k−1) / p²` per pair of tables the prover tries: `≈ 2⁻¹⁰⁵·⁷` at
/// `n = 2²⁰`, `k = 6`.
///
/// Cost per row and side: the columns are base-field values, so each limb of
/// the folded row is a base linear combination (`1 + D·(k−1)` arithmetic ops),
/// then one extension multiplication into the running product.
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
    let alpha = ExtensionTarget::<D>(core::array::from_fn(|l| h.elements[l]));
    let beta = ExtensionTarget::<D>(core::array::from_fn(|l| h.elements[D + l]));

    // α powers [1, α, α², …, α^{ncols-1}] in the extension.
    let mut alpha_pow = Vec::with_capacity(ncols);
    alpha_pow.push(b.one_extension());
    for _ in 1..ncols {
        let prev = *alpha_pow.last().unwrap();
        alpha_pow.push(b.mul_extension(prev, alpha));
    }

    // β + Σ_c α^c·col_c[i], limb by limb (α⁰ = 1 touches limb 0 only).
    let fold = |b: &mut CircuitBuilder<F, D>, cols: &[&[Target]], i: usize| -> ExtensionTarget<D> {
        let mut acc = beta;
        acc.0[0] = b.add(cols[0][i], beta.0[0]);
        for c in 1..cols.len() {
            for l in 0..D {
                acc.0[l] = b.mul_add(alpha_pow[c].0[l], cols[c][i], acc.0[l]);
            }
        }
        acc
    };

    let mut pa = b.one_extension();
    for i in 0..n {
        let term = fold(b, a, i);
        pa = b.mul_extension(pa, term);
    }
    let mut pb = b.one_extension();
    for i in 0..n {
        let term = fold(b, bcols, i);
        pb = b.mul_extension(pb, term);
    }
    b.connect_extension(pa, pb);
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

#[cfg(test)]
mod tests {
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    use super::*;
    use crate::config::{build_circuit, circuit_config};

    /// Build `assert_perm_cols` over two 2-column tables and try to prove it on
    /// the given rows; `true` iff a proof is produced and verifies.
    fn perm_holds(rows_a: &[[u64; 2]], rows_b: &[[u64; 2]]) -> bool {
        let n = rows_a.len();
        let mut b = CircuitBuilder::<F, D>::new(circuit_config());
        let cols: Vec<Vec<Target>> = (0..4).map(|_| b.add_virtual_targets(n)).collect();
        assert_perm_cols(&mut b, &[&cols[0], &cols[1]], &[&cols[2], &cols[3]]);
        let data = build_circuit(b);
        let mut pw = PartialWitness::<F>::new();
        for (side, rows) in [rows_a, rows_b].into_iter().enumerate() {
            for (i, row) in rows.iter().enumerate() {
                for (c, &v) in row.iter().enumerate() {
                    pw.set_target(cols[2 * side + c][i], F::from_canonical_u64(v)).unwrap();
                }
            }
        }
        data.prove(pw).is_ok_and(|p| data.verify(p).is_ok())
    }

    #[test]
    fn perm_cols_accepts_row_permutation() {
        assert!(perm_holds(&[[1, 2], [3, 4], [5, 6]], &[[5, 6], [1, 2], [3, 4]]));
    }

    #[test]
    fn perm_cols_rejects_recombined_rows() {
        // Each column is a permutation of the other side's, but the rows are not.
        assert!(!perm_holds(&[[1, 2], [3, 4], [5, 6]], &[[1, 4], [3, 2], [5, 6]]));
    }

    #[test]
    fn perm_cols_rejects_changed_multiplicity() {
        assert!(!perm_holds(&[[1, 2], [1, 2], [3, 4]], &[[1, 2], [3, 4], [3, 4]]));
    }
}
