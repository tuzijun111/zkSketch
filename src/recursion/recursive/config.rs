//! `ConfigWithFriParams` — `StarkCfg` wrapper that implements
//! [`p3_recursion::FriRecursionConfig`].
//!
//! Hand-translation of the `define_field_module_types!` macro from
//! `Plonky3-recursion/recursion/examples/common/mod.rs` (lines 207–342),
//! specialised to BabyBear + Poseidon2 width-16 + binomial extension D=4.

use std::sync::Arc;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{
    Poseidon2Params, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_commit::Pcs as PcsTrait;
use p3_field::BasedVectorSpace;
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::{
    FriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs, RecValMmcs,
    Witness, set_fri_mmcs_private_data,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{FriRecursionConfig, FriVerifierParams, Poseidon2Config, RecursionInput};
use p3_uni_stark::{StarkGenericConfig, Val as UniVal};

use crate::config::{
    Challenge, ChallengeMmcs, Challenger, MyCompress, MyHash, Pcs, StarkCfg, Val, ValMmcs,
};

/// Width 16 / rate 8 / digest 8 — must match `crate::config::MyHash`.
pub const DIGEST_ELEMS: usize = 8;

/// Challenge extension degree (BinomialExtensionField<BabyBear, 4>).
pub const D: usize = 4;

/// The FRI proof targets the recursive verifier carries — opaque to callers.
pub type InnerFri = FriProofTargets<
    Val,
    Challenge,
    RecExtensionValMmcs<
        Val,
        Challenge,
        DIGEST_ELEMS,
        RecValMmcs<Val, DIGEST_ELEMS, MyHash, MyCompress>,
    >,
    InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, MyHash, MyCompress>>,
    Witness<Val>,
>;

/// Wrapper around our leaf `StarkCfg` that also carries the FRI verifier
/// parameters needed when this config is used as the recursion layer.
#[derive(Clone)]
pub struct ConfigWithFriParams {
    pub config: Arc<StarkCfg>,
    pub fri_verifier_params: FriVerifierParams,
    pub disable_recompose_npo: bool,
}

impl ConfigWithFriParams {
    pub fn new(config: StarkCfg, fri_verifier_params: FriVerifierParams) -> Self {
        Self {
            config: Arc::new(config),
            fri_verifier_params,
            disable_recompose_npo: false,
        }
    }
}

impl core::ops::Deref for ConfigWithFriParams {
    type Target = StarkCfg;
    fn deref(&self) -> &StarkCfg {
        &self.config
    }
}

impl StarkGenericConfig for ConfigWithFriParams {
    type Challenge = Challenge;
    type Challenger = Challenger;
    type Pcs = Pcs;

    fn pcs(&self) -> &Pcs {
        self.config.pcs()
    }

    fn initialise_challenger(&self) -> Challenger {
        self.config.initialise_challenger()
    }
}

impl FriRecursionConfig for ConfigWithFriParams
where
    Pcs: RecursivePcs<
            ConfigWithFriParams,
            InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, MyHash, MyCompress>>,
            InnerFri,
            MerkleCapTargets<Val, DIGEST_ELEMS>,
            <Pcs as PcsTrait<Challenge, Challenger>>::Domain,
        >,
{
    type Commitment = MerkleCapTargets<Val, DIGEST_ELEMS>;
    type InputProof =
        InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, MyHash, MyCompress>>;
    type OpeningProof = InnerFri;
    type RawOpeningProof = <Pcs as PcsTrait<Challenge, Challenger>>::Proof;
    const DIGEST_ELEMS: usize = 8;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<UniVal<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        let perm = default_babybear_poseidon2_16();
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            perm,
        );
        if self.disable_recompose_npo {
            circuit.noop_enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        } else {
            circuit.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        }
        // Branch only matters when the extension degree on the Poseidon2 side
        // is 1 but the challenge extension is wider — i.e. quintic config.
        // We use D=4 binomial, so this is always false here, but keep the
        // shape so the file stays close to the upstream template.
        if <BabyBearD4Width16 as Poseidon2Params>::D == 1
            && <Challenge as BasedVectorSpace<Val>>::DIMENSION > 1
        {
            circuit.set_recompose_coeff_ctl_for_decompose_links(true);
        }
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<Pcs as RecursivePcs<
        ConfigWithFriParams,
        InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        MerkleCapTargets<Val, DIGEST_ELEMS>,
        <Pcs as PcsTrait<Challenge, Challenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_fri_mmcs_private_data::<
            Val,
            Challenge,
            ChallengeMmcs,
            ValMmcs,
            MyHash,
            MyCompress,
            DIGEST_ELEMS,
        >(runner, op_ids, opening_proof, Poseidon2Config::BABY_BEAR_D4_W16)
    }
}

/// Build a `ConfigWithFriParams` for the leaf-stark FRI parameters used in
/// `crate::config::make_config`. The recursion-layer FRI verifier params must
/// match the leaf's FRI shape exactly (same log_blowup, log_final_poly_len,
/// PoW bits) since the recursive circuit verifies the inner proof's FRI.
pub fn make_recursion_config(
    leaf_config: StarkCfg,
    log_blowup: usize,
    log_final_poly_len: usize,
    commit_pow_bits: usize,
    query_pow_bits: usize,
) -> ConfigWithFriParams {
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        log_blowup,
        log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
        Poseidon2Config::BABY_BEAR_D4_W16,
    );
    ConfigWithFriParams::new(leaf_config, fri_verifier_params)
}
