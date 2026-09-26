//! Coefficient binding of the recompose NPO.
//!
//! Every circuit here opens committed packed values with
//! `decompose_ext_to_base_coeffs`, and the fork lowers that decomposition's
//! reconnect through the recompose NPO. By default the fork
//! (`CircuitBuilder::set_bind_recompose_coeffs`) uses the `recompose/coeff`
//! table, whose row publishes every coefficient on the WitnessChecks bus as
//! `[idx, v_i, 0, 0, 0]` next to `[x_idx, v_0..v_3]`. The coefficients a
//! circuit constrains are then exactly the base-field coefficients of the
//! packed value it hashes or permutes. The pre-fix lowering (the plain
//! `recompose` table, fork rev 19dcb37) published only `[x_idx, v_0..v_3]`
//! from free columns: nothing tied the decomposed fields to the committed
//! value, so a leaf could commit to one state while its constraints ran on
//! another.
//!
//! [`configure`] applies the calling thread's mode to a fresh builder (bound
//! unless inside [`with_unbound_recompose`]). The unbound mode exists only for
//! soundness proofs-of-concept and cost comparisons.

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
