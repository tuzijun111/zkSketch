//! Shared Goldilocks leaf-config + digest-packing helpers for the `_gl`
//! SpaceSaving / Greenwald-Khanna circuits.
//!
//! Goldilocks analog of the helpers in
//! [`crate::recursion::recursive::countmin_leaf`] (BabyBear): `make_leaf_config`,
//! `DIGEST_PACKING`, `pack_commit_to_challenge`. The Goldilocks digest is
//! `[Val; 4]` (width-8 Poseidon2) rather than `[Val; 8]`, and one `Challenge`
//! packs `CELL_ALIGNMENT = 2` base elements (D = 2) rather than 4.

use p3_field::BasedVectorSpace;

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
