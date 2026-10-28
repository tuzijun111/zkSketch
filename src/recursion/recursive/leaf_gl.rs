//! Goldilocks leaf config, digest packing and hiding-salt helpers shared by the `_gl`
//! leaf circuits (CM/HLL omc, SpaceSaving, GK).

use p3_circuit::CircuitBuilder;
use p3_field::BasedVectorSpace;

use crate::commitment::hiding::{self, CommitMode, LeafSaltTargets};
use crate::config_gl::{
    COMMIT_POW_BITS, Challenge, LOG_BLOWUP, QUERY_POW_BITS, Val, make_config,
};
use crate::recursion::recursive::config_gl::{ConfigWithFriParamsGl, make_recursion_config_gl};

/// Base elements packed per `Challenge` (extension degree D = 2).
pub const CELL_ALIGNMENT: usize = 2;
/// Number of `Challenge` digest outputs from `add_hash_slice`: the digest is
/// always 4 base elements = 2 `Challenge` elements.
pub const DIGEST_PACKING: usize = 2;

/// FRI final-poly length for the leaf — equal to the BabyBear side so the two
/// backends share a verifier-circuit shape.
pub const LOG_FINAL_POLY_LEN: usize = 6;

/// Goldilocks state-commit digest (`[Val; 4]`). Analog of
/// [`crate::commitment::CountMinCommit`]'s `[Val; 8]`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GlCommit(pub [Val; 4]);

/// Pack a Goldilocks digest (`[Val; 4]`) into `DIGEST_PACKING` (= 2) `Challenge`
/// elements — the shape the in-circuit hash returns and the leaf PIs use.
pub fn pack_commit_to_challenge(c: &GlCommit) -> [Challenge; DIGEST_PACKING] {
    [
        Challenge::from_basis_coefficients_slice(&c.0[0..2]).expect("2 base coeffs"),
        Challenge::from_basis_coefficients_slice(&c.0[2..4]).expect("2 base coeffs"),
    ]
}

/// Reconstruct the Goldilocks recursion-friendly config used by both the leaf
/// prove and the aggregation step.
pub fn make_leaf_config() -> ConfigWithFriParamsGl {
    let leaf_cfg = make_config(LOG_FINAL_POLY_LEN);
    make_recursion_config_gl(
        leaf_cfg,
        LOG_BLOWUP,
        LOG_FINAL_POLY_LEN,
        COMMIT_POW_BITS,
        QUERY_POW_BITS,
    )
}

/// Allocate a Goldilocks leaf's commitment salts (init, final, batch) with
/// [`hiding::alloc_leaf_salts`], enforcing the B2 order: under `Hiding` they
/// are the FIRST 9 private inputs, because every Goldilocks leaf pushes
/// [`hiding::OpeningsGl::private_inputs`] before its other private values.
/// Panics if a private input was allocated before them. `Plain` allocates
/// nothing, so its circuit is byte-identical.
pub fn alloc_leaf_salts_first(
    b: &mut CircuitBuilder<Challenge>,
    mode: CommitMode,
) -> Option<LeafSaltTargets> {
    if mode.is_hiding() {
        assert_eq!(
            b.private_input_count(),
            0,
            "B2: the commitment salts must be the first private inputs of a Hiding leaf"
        );
    }
    hiding::alloc_leaf_salts(b, mode)
}

#[cfg(test)]
mod salts_first_tests {
    use super::*;

    #[test]
    fn hiding_salts_are_the_first_nine_private_inputs() {
        let mut b = CircuitBuilder::<Challenge>::new();
        assert!(alloc_leaf_salts_first(&mut b, CommitMode::Plain).is_none());
        assert_eq!(b.private_input_count(), 0, "Plain allocates nothing");
        assert!(alloc_leaf_salts_first(&mut b, CommitMode::Hiding).is_some());
        assert_eq!(b.private_input_count(), 3 * hiding::SALT_CHALLENGES);
    }

    #[test]
    #[should_panic(expected = "the commitment salts must be the first private inputs")]
    fn salts_after_another_private_input_are_refused() {
        let mut b = CircuitBuilder::<Challenge>::new();
        let _ = b.alloc_private_input("state");
        let _ = alloc_leaf_salts_first(&mut b, CommitMode::Hiding);
    }
}

/// Test-only proof inspectors of the Goldilocks hiding-commitment tests
/// (revision B2): the Goldilocks twin of `commitment::hiding::probe`.
#[cfg(test)]
pub(crate) mod hiding_probe {
    use p3_circuit::ops::{NpoTypeId, Poseidon2Config};
    use p3_circuit_prover::{BatchStarkProof, PrimitiveTable};
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::commitment::hiding::SaltGl;

    /// Logical `(Poseidon2, ALU)` rows of a Goldilocks run (before padding).
    pub(crate) fn trace_rows(traces: &p3_circuit::tables::Traces<Challenge>) -> (usize, usize) {
        let key = NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8);
        let p2 = traces.non_primitive_traces.get(&key).map_or(0, |t| t.rows());
        (p2, traces.alu_trace.values.len())
    }

    /// The ALU rows a proof reports (logical, equal to [`trace_rows`]'s).
    pub(crate) fn proof_alu_rows(proof: &BatchStarkProof<ConfigWithFriParamsGl>) -> usize {
        proof.rows[PrimitiveTable::Alu]
    }

    /// Every public value the verifier is handed (the non-primitive tables';
    /// the primitive tables carry none).
    pub(crate) fn public_values(proof: &BatchStarkProof<ConfigWithFriParamsGl>) -> Vec<Val> {
        proof.non_primitives.iter().flat_map(|e| e.public_values.iter().copied()).collect()
    }

    /// The nonzero coefficients of `salts` that occur among
    /// [`public_values`] (zero is the public salt, so it is skipped).
    pub(crate) fn leaked_salts(proof: &BatchStarkProof<ConfigWithFriParamsGl>, salts: &[SaltGl]) -> Vec<Val> {
        let pv = public_values(proof);
        salts.iter().flat_map(|s| s.0).filter(|c| *c != Val::ZERO && pv.contains(c)).collect()
    }

    /// Flat basis coefficients of VK pin values (`expose_forest_gl::vk_pin_values`).
    pub(crate) fn vk_flat(vk: &[Challenge]) -> Vec<u64> {
        use p3_field::PrimeField64;
        vk.iter()
            .flat_map(|c| {
                <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                    .iter()
                    .map(|x| x.as_canonical_u64())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// A recorded Goldilocks VK (Plain: b2-hiding@94e9f58, the pre-B2
    /// Goldilocks leaves; Hiding: b2-gl@77a02a3): 4 base values, each the
    /// first coefficient of one pin Challenge.
    pub(crate) fn vk_literal(v: [u64; 4]) -> Vec<u64> {
        v.iter().flat_map(|&x| [x, 0]).collect()
    }
}
