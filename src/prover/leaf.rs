//! Prove/verify for the toy `FibAir` leaf (plain uni-stark; tests and the `chain_two` example).
//! Its 16-64-row traces are below the ZK hiding budget: these proofs are not claimed to hide them.

use core::borrow::Borrow;
use core::fmt;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use p3_uni_stark::{PcsError, Proof, VerificationError, prove, verify};

use crate::air::FibAir;
use crate::air::fib::{FibRow, NUM_FIB_PUBLIC_VALUES, generate_fib_trace};
use crate::config::{LOG_BLOWUP, StarkCfg, Val, make_config};

/// The `StarkGenericConfig` used to prove and verify a leaf `FibAir`.
pub type LeafCfg = StarkCfg;

/// The concrete `VerificationError` returned by our leaf verifier.
pub type LeafVerifyError = VerificationError<PcsError<LeafCfg>>;

/// Build the leaf-stark config.
fn leaf_config(log_steps: usize) -> LeafCfg {
    let log_final_poly_len = log_final_poly_len_for(log_steps);
    make_config(log_final_poly_len)
}

/// Pick a FRI `log_final_poly_len` compatible with the leaf trace size.
pub(crate) fn log_final_poly_len_for(log_steps: usize) -> usize {
    log_steps.saturating_sub(LOG_BLOWUP + 1).min(5)
}

/// Boundary state of one `FibAir` leaf: a single `(a, b)` pair. Stands in for
/// the paper's `Com(S_t)` in Phase 1.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub a: Val,
    pub b: Val,
}

impl Boundary {
    pub fn new(a: u64, b: u64) -> Self {
        Self {
            a: Val::from_u64(a),
            b: Val::from_u64(b),
        }
    }

    pub fn from_field(a: Val, b: Val) -> Self {
        Self { a, b }
    }

    pub(crate) fn to_array(self) -> [Val; 2] {
        [self.a, self.b]
    }
}

/// Output of `prove_fib_leaf`: the uni-stark proof plus the boundary that
/// defines its public values. Carries enough metadata (`log_steps`) so the
/// verifier can reconstruct the StarkConfig and rerun verification without
/// extra plumbing.
pub struct LeafProof {
    pub proof: Proof<LeafCfg>,
    pub initial: Boundary,
    pub final_: Boundary,
    pub log_steps: usize,
}

impl LeafProof {
    /// Public-values vector this proof was bound to, in the exact order the
    /// verifier expects (`[a0, b0, aT, bT]`).
    pub fn public_values(&self) -> Vec<Val> {
        let mut v = Vec::with_capacity(NUM_FIB_PUBLIC_VALUES);
        v.extend_from_slice(&self.initial.to_array());
        v.extend_from_slice(&self.final_.to_array());
        v
    }
}

#[derive(Debug)]
pub enum LeafProveError {
    BadTraceLen(usize),
}

impl fmt::Display for LeafProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadTraceLen(n) => write!(
                f,
                "trace length must be a power of two and >= 2 (got {n})"
            ),
        }
    }
}

impl core::error::Error for LeafProveError {}

/// Prove one `FibAir` epoch: starting from `initial`, run `2^log_steps`
/// Fibonacci updates inside BabyBear and return a proof certifying the
/// resulting boundary `(aT, bT)`.
pub fn prove_fib_leaf(initial: Boundary, log_steps: usize) -> Result<LeafProof, LeafProveError> {
    // The recursion-layer FRI verifier requires the leaf trace to be large
    // enough that `log_steps > log_final_poly_len + log_blowup`. With
    // log_blowup=2 and the recursion's expected log_final_poly_len≥1, we
    // need log_steps ≥ 4.
    if log_steps < LOG_BLOWUP + 2 {
        return Err(LeafProveError::BadTraceLen(1 << log_steps));
    }
    let n = 1usize << log_steps;
    let config = leaf_config(log_steps);

    let trace = generate_fib_trace::<Val>(
        initial.a.as_canonical_u64(),
        initial.b.as_canonical_u64(),
        n,
    );

    // Read the actual last row out of the trace so the boundary lives in
    // BabyBear, not in a parallel u64 computation that could disagree once
    // values exceed the prime.
    let final_ = {
        let last = trace.row_slice(n - 1).expect("last row exists");
        let row: &FibRow<Val> = (&*last).borrow();
        Boundary {
            a: row.a,
            b: row.b,
        }
    };

    let pis = vec![initial.a, initial.b, final_.a, final_.b];
    let proof = prove(&config, &FibAir, trace, &pis);

    Ok(LeafProof {
        proof,
        initial,
        final_,
        log_steps,
    })
}

/// Verify a previously-produced `LeafProof`. The StarkConfig is reconstructed
/// from `log_steps` so the verifier carries no shared state with the prover.
pub fn verify_fib_leaf(proof: &LeafProof) -> Result<(), LeafVerifyError> {
    let config = leaf_config(proof.log_steps);
    let pis = proof.public_values();
    verify(&config, &FibAir, &proof.proof, &pis)
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeField64;

    use super::*;

    /// Honest round-trip: prove then verify should accept.
    #[test]
    fn leaf_round_trip_small() {
        let leaf = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove");
        assert!(
            verify_fib_leaf(&leaf).is_ok(),
            "verify should accept honest proof"
        );
        // log_steps=4 → 16 rows starting from (0, 1). Row 15 is (F_15, F_16) = (610, 987).
        assert_eq!(leaf.final_.a.as_canonical_u64(), 610);
        assert_eq!(leaf.final_.b.as_canonical_u64(), 987);
    }

    /// Tampering with the public values must cause the verifier to reject.
    #[test]
    fn tampered_final_rejected() {
        let mut leaf = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove");
        leaf.final_.a = leaf.final_.a + Val::ONE;
        assert!(
            verify_fib_leaf(&leaf).is_err(),
            "verify should reject tampered pis"
        );
    }

    /// Two consecutive epochs starting from `(0, 1)` should satisfy the chain
    /// invariant: epoch-2 begins at the final boundary of epoch-1.
    #[test]
    fn boundary_threads_between_leaves() {
        let l1 = prove_fib_leaf(Boundary::new(0, 1), 4).expect("prove l1");
        let l2 = prove_fib_leaf(l1.final_, 4).expect("prove l2");
        assert!(verify_fib_leaf(&l1).is_ok());
        assert!(verify_fib_leaf(&l2).is_ok());
        assert_eq!(l2.initial, l1.final_);
    }
}
