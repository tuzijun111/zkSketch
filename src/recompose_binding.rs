//! Binds the recompose NPO's coefficients to the packed value (fork table `recompose/coeff`).
//! `with_unbound_recompose` gives the old unbound lowering (soundness PoCs, cost comparisons).

use std::cell::Cell;
use std::hash::Hash;

use p3_circuit::CircuitBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

thread_local! {
    static UNBOUND: Cell<bool> = const { Cell::new(false) };
}

/// Apply this thread's recompose lowering to `b`. Call right after
/// `enable_recompose`.
pub fn configure<F>(b: &mut CircuitBuilder<F>)
where
    F: Field + PrimeCharacteristicRing + Eq + Hash,
{
    b.set_bind_recompose_coeffs(!UNBOUND.with(Cell::get));
}

/// Run `f` with circuits built on this thread using the pre-fix, UNBOUND
/// recompose lowering (only in builders that call [`configure`]). For
/// soundness proofs-of-concept and cost comparisons only.
pub fn with_unbound_recompose<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            UNBOUND.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(UNBOUND.with(|c| c.replace(true)));
    f()
}
