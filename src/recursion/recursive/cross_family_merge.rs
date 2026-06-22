//! **Real recursive cross-family merge** (§4.2 merge atom across heterogeneous
//! sketch families): aggregate a Count-Min leaf proof AND a HyperLogLog leaf
//! proof into ONE batch-STARK that recursively re-verifies *both* leaves.
//!
//! This is the genuine recursive counterpart of the framework's option-(i)
//! cross-family `merge_atom` (which only combines boundary digests, without
//! re-verifying either leaf). It works because both leaf proofs are the **same
//! Rust type** — `RecursionOutput<ConfigWithFriParams>` wrapping a
//! `BatchStarkProof<ConfigWithFriParams>` — produced under the same leaf config
//! / extension degree / table packing. The aggregation prover verifies an
//! arbitrary-shaped batch-STARK proof generically (it already merges
//! differently-shaped proofs in `CountMinChainState::extend`, e.g. a large
//! chain root with a small fresh leaf), so a CM leaf and an HLL leaf — both
//! `BatchOnly` recursion inputs — aggregate the same way.
//!
//! Unlike a same-family chain there is **no shared-boundary equality**: CM and
//! HLL states are independent, so this proves "both epochs are valid" composed
//! under one root, binding both families' `(initial, final)` commitments into a
//! single combined digest.

use p3_circuit_prover::BatchStarkProver;
use p3_recursion::{BatchOnly, Poseidon2Config, RecursionOutput, build_and_prove_aggregation_layer};

use crate::commitment::{CountMinCommit, HyperLogLogCommit};
use crate::config::Val;
use crate::recursion::digest::{ChainDigest, combine_digest, leaf_digest};
use crate::recursion::recursive::backend::{Backend, make_backend};
use crate::recursion::recursive::config::{ConfigWithFriParams, D as EXT_D};
use crate::recursion::recursive::countmin_leaf::{CountMinLeafProof, make_leaf_config};
use crate::recursion::recursive::countmin_merge::{CountMinMergeError, agg_params, cm_leaf_digest};
use crate::recursion::recursive::hll_leaf::HllLeafProof;

/// A recursive proof that one Count-Min epoch AND one HyperLogLog epoch are both
/// valid, aggregated into a single batch-STARK and bound by a combined digest.
pub struct CrossFamilyMergeProof {
    pub recursive_proof: RecursionOutput<ConfigWithFriParams>,
    pub cm_initial: CountMinCommit,
    pub cm_final: CountMinCommit,
    pub hll_initial: HyperLogLogCommit,
    pub hll_final: HyperLogLogCommit,
    /// Combined ordered digest over the two families' boundaries.
    pub digest: ChainDigest,
}

/// Fold a `HyperLogLogCommit` (`[Val; 8]`) to the 2-element boundary id the
/// chain-digest helpers consume — the same reduction `cm_leaf_digest` uses
/// (the full 8 elements are themselves a collision-resistant Poseidon2 digest).
fn hll_leaf_digest(c: &HyperLogLogCommit) -> [Val; 2] {
    [c.0[0], c.0[1]]
}

fn combined_digest(
    cm_initial: &CountMinCommit,
    cm_final: &CountMinCommit,
    hll_initial: &HyperLogLogCommit,
    hll_final: &HyperLogLogCommit,
) -> ChainDigest {
    let dl = leaf_digest(&cm_leaf_digest(cm_initial), &cm_leaf_digest(cm_final), 1);
    let dr = leaf_digest(&hll_leaf_digest(hll_initial), &hll_leaf_digest(hll_final), 2);
    combine_digest(1, 1, 2, &dl, &dr)
}

/// Merge a Count-Min leaf and a HyperLogLog leaf into one recursive batch-STARK.
pub fn merge_cm_hll(
    cm: &CountMinLeafProof,
    hll: &HllLeafProof,
) -> Result<CrossFamilyMergeProof, CountMinMergeError> {
    let config = make_leaf_config();
    let backend = make_backend();
    let params = agg_params();

    let left_input = cm.output.into_recursion_input::<BatchOnly>();
    let right_input = hll.output.into_recursion_input::<BatchOnly>();

    let recursive_proof = build_and_prove_aggregation_layer::<
        ConfigWithFriParams,
        BatchOnly,
        BatchOnly,
        Backend,
        EXT_D,
    >(&left_input, &right_input, &config, &backend, &params, None)
    .map_err(|e| CountMinMergeError::AggregationFailed(format!("{e:?}")))?;

    let digest = combined_digest(&cm.initial, &cm.final_, &hll.initial, &hll.final_);

    Ok(CrossFamilyMergeProof {
        recursive_proof,
        cm_initial: cm.initial,
        cm_final: cm.final_,
        hll_initial: hll.initial,
        hll_final: hll.final_,
        digest,
    })
}

/// Verify a cross-family merge: the single recursive batch-STARK is sound and
/// the combined boundary digest re-derives.
pub fn verify_cm_hll(m: &CrossFamilyMergeProof) -> Result<(), CountMinMergeError> {
    let config = make_leaf_config();
    let params = agg_params();

    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<EXT_D>(Poseidon2Config::BABY_BEAR_D4_W16.d() != EXT_D);
    verifier
        .verify_all_tables(&m.recursive_proof.0)
        .map_err(|e| CountMinMergeError::BatchVerifyFailed(format!("{e:?}")))?;

    let expect = combined_digest(&m.cm_initial, &m.cm_final, &m.hll_initial, &m.hll_final);
    if expect != m.digest {
        return Err(CountMinMergeError::DigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::recursive::countmin_leaf::{D, W, prove_countmin_leaf};
    use crate::recursion::recursive::hll_leaf::{B, prove_hll_leaf};
    use crate::sketch::Sketch;
    use crate::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};
    use crate::sketch::hyperloglog::{HyperLogLog, HyperLogLogParams, HyperLogLogUpdate};

    #[test]
    fn cross_family_cm_hll_merge_accepts() {
        // An independent Count-Min epoch and HyperLogLog epoch.
        let cm = prove_countmin_leaf(
            CountMin::new(&CountMinParams { d: D, w: W }),
            [CountMinUpdate { key: 7, value: 3 }, CountMinUpdate { key: 11, value: 5 }],
        );
        let hll = prove_hll_leaf(
            HyperLogLog::new(&HyperLogLogParams { b: B }),
            [
                HyperLogLogUpdate { key: 0xDEAD_BEEF_0000_1111 },
                HyperLogLogUpdate { key: 0xC0FFEE_C0FFEE },
            ],
        );

        // The REAL recursive cross-family merge must aggregate + verify both.
        let merged = merge_cm_hll(&cm, &hll).expect("cross-family merge");
        verify_cm_hll(&merged).expect("verify cross-family merge");

        assert_eq!(merged.cm_initial, cm.initial);
        assert_eq!(merged.hll_final, hll.final_);
    }

    #[test]
    fn cross_family_tamper_digest_rejected() {
        let cm = prove_countmin_leaf(
            CountMin::new(&CountMinParams { d: D, w: W }),
            [CountMinUpdate { key: 1, value: 1 }, CountMinUpdate { key: 2, value: 1 }],
        );
        let hll = prove_hll_leaf(
            HyperLogLog::new(&HyperLogLogParams { b: B }),
            [HyperLogLogUpdate { key: 42 }, HyperLogLogUpdate { key: 99 }],
        );
        let mut merged = merge_cm_hll(&cm, &hll).expect("merge");
        // Corrupt a bound boundary → digest re-derivation must fail. (hll.initial
        // ≠ hll.final_ after the batch, so this is a real boundary change.)
        merged.hll_final = hll.initial;
        match verify_cm_hll(&merged) {
            Err(CountMinMergeError::DigestMismatch) => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }
}
