//! Boundary `(a, b)` of the toy `FibAir` leaf, standing in for `Com(S_t)`.

use crate::config::Val;
use crate::prover::Boundary as LeafBoundary;

/// Phase-1 boundary type re-export. Phase 2 will replace this with a hash-of-
/// state commitment whose width is `DIGEST_ELEMS`.
pub type Boundary = LeafBoundary;

/// Pack a boundary into its raw field-element form `[a, b]`. The recursive
/// merge atom uses this to feed boundary values into the verification circuit.
pub fn pack(b: Boundary) -> [Val; 2] {
    [b.a, b.b]
}

/// Inverse of `pack` — used when reconstructing a boundary from a public-
/// values vector.
pub fn unpack(values: &[Val]) -> Boundary {
    assert!(values.len() >= 2, "boundary requires 2 field elements");
    Boundary {
        a: values[0],
        b: values[1],
    }
}
