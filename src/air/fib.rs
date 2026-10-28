//! Toy Fibonacci leaf AIR (`a' = b`, `b' = a + b`); public values are the first and last rows.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField64;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::LeafAir;
use crate::config::Val;

pub const NUM_FIB_COLS: usize = 2;

/// Number of field elements used to expose one boundary `(a, b)`.
pub const BOUNDARY_FIELDS: usize = 2;

/// FibAir public values are `[a0, b0, aT, bT]`.
pub const NUM_FIB_PUBLIC_VALUES: usize = 2 * BOUNDARY_FIELDS;

pub struct FibAir;

impl<F> BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        NUM_FIB_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_FIB_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // First-row / last-row / transition selectors are degree 1 applied to
        // degree-1 expressions, giving degree-2 constraints overall.
        Some(2)
    }
}

#[repr(C)]
pub struct FibRow<F> {
    pub a: F,
    pub b: F,
}

impl<F> FibRow<F> {
    const fn new(a: F, b: F) -> Self {
        Self { a, b }
    }
}

impl<F> Borrow<FibRow<F>> for [F] {
    fn borrow(&self) -> &FibRow<F> {
        debug_assert_eq!(self.len(), NUM_FIB_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<AB: AirBuilder> Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &FibRow<AB::Var> = main.current_slice().borrow();
        let next: &FibRow<AB::Var> = main.next_slice().borrow();

        let pis = builder.public_values();
        let a0 = pis[0];
        let b0 = pis[1];
        let a_t = pis[2];
        let b_t = pis[3];

        // First row pins the initial boundary.
        let mut when_first = builder.when_first_row();
        when_first.assert_eq(local.a, a0);
        when_first.assert_eq(local.b, b0);

        // Transition: a' = b, b' = a + b.
        let mut when_trans = builder.when_transition();
        when_trans.assert_eq(local.b, next.a);
        when_trans.assert_eq(local.a + local.b, next.b);

        // Last row pins the final boundary.
        let mut when_last = builder.when_last_row();
        when_last.assert_eq(local.a, a_t);
        when_last.assert_eq(local.b, b_t);
    }
}

/// Generate an honest trace of `n` rows starting from `(a, b)`. `n` must be a
/// power of two and at least 2 so the transition selector matches at least one row.
pub fn generate_fib_trace<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two(), "trace length must be a power of two");
    assert!(n >= 2, "trace must have at least 2 rows");

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIB_COLS), NUM_FIB_COLS);
    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibRow<F>>() };
    assert!(prefix.is_empty() && suffix.is_empty(), "alignment should match");
    assert_eq!(rows.len(), n);

    rows[0] = FibRow::new(F::from_u64(a), F::from_u64(b));
    for i in 1..n {
        rows[i].a = rows[i - 1].b;
        rows[i].b = rows[i - 1].a + rows[i - 1].b;
    }
    trace
}

/// Compute `(a, b)` after `n - 1` Fibonacci steps starting from the given pair.
/// Returns the last-row pair. Useful for building the public-value vector
/// before producing a proof.
pub fn fib_last_pair(a: u64, b: u64, n: usize) -> (u64, u64) {
    assert!(n >= 1);
    let mut x = a;
    let mut y = b;
    for _ in 1..n {
        let z = x + y;
        x = y;
        y = z;
    }
    (x, y)
}

impl LeafAir for FibAir {
    type Boundary = [Val; BOUNDARY_FIELDS];

    fn boundary_to_public_values(initial: Self::Boundary, final_: Self::Boundary) -> Vec<Val> {
        let mut out = Vec::with_capacity(NUM_FIB_PUBLIC_VALUES);
        out.extend_from_slice(&initial);
        out.extend_from_slice(&final_);
        out
    }

    fn boundary_from_public_values(pis: &[Val]) -> (Self::Boundary, Self::Boundary) {
        assert_eq!(pis.len(), NUM_FIB_PUBLIC_VALUES, "FibAir expects 4 public values");
        ([pis[0], pis[1]], [pis[2], pis[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_pair_matches_trace() {
        use p3_matrix::Matrix;

        let n = 16usize;
        let trace = generate_fib_trace::<Val>(0, 1, n);
        let last = trace.row_slice(n - 1).unwrap();
        let row: &FibRow<Val> = (&*last).borrow();
        let (a_t, b_t) = fib_last_pair(0, 1, n);
        assert_eq!(row.a.as_canonical_u64(), a_t);
        assert_eq!(row.b.as_canonical_u64(), b_t);
    }
}
