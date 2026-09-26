//! `ConfigWithFriParamsGl` — Goldilocks `StarkCfg` wrapper that implements
//! [`p3_recursion::FriRecursionConfig`].
//!
//! Goldilocks analog of [`crate::recursion::recursive::config`] (BabyBear).
//! Specialised to Goldilocks + Poseidon2 width-8 + binomial extension D = 2,
//! matching the fork's `GoldilocksD2Width8` / `Poseidon2Config::GOLDILOCKS_D2_W8`
//! path (see `recursion/tests/goldilocks.rs`).

use std::sync::Arc;

use p3_circuit::ops::{
    GoldilocksD2Width8, Poseidon2Params, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_commit::Pcs as PcsTrait;
use p3_field::BasedVectorSpace;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::pcs::{
    FriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs, RecValMmcs,
    Witness, set_fri_mmcs_private_data,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{FriRecursionConfig, FriVerifierParams, Poseidon2Config, RecursionInput};
use p3_uni_stark::{StarkGenericConfig, Val as UniVal};

use crate::config_gl::{
    Challenge, ChallengeMmcs, Challenger, MyCompress, MyHash, Pcs, StarkCfg, Val, ValMmcs, make_perm,
};

/// Width 8 / rate 4 / digest 4 — must match `crate::config_gl::MyHash`.
pub const DIGEST_ELEMS: usize = 4;

/// Challenge extension degree (BinomialExtensionField<Goldilocks, 2>).
pub const D: usize = 2;

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

/// Goldilocks analog of [`crate::recursion::recursive::config::ConfigWithFriParams`].
#[derive(Clone)]
pub struct ConfigWithFriParamsGl {
    pub config: Arc<StarkCfg>,
    pub fri_verifier_params: FriVerifierParams,
    pub disable_recompose_npo: bool,
}

impl ConfigWithFriParamsGl {
    pub fn new(config: StarkCfg, fri_verifier_params: FriVerifierParams) -> Self {
        Self {
            config: Arc::new(config),
            fri_verifier_params,
            disable_recompose_npo: false,
        }
    }
}

impl core::ops::Deref for ConfigWithFriParamsGl {
    type Target = StarkCfg;
    fn deref(&self) -> &StarkCfg {
        &self.config
    }
}

impl StarkGenericConfig for ConfigWithFriParamsGl {
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

impl FriRecursionConfig for ConfigWithFriParamsGl
where
    Pcs: RecursivePcs<
            ConfigWithFriParamsGl,
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
    const DIGEST_ELEMS: usize = 4;

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
        let perm = make_perm();
        circuit.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
            perm,
        );
        if self.disable_recompose_npo {
            circuit.noop_enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        } else {
            circuit.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        }
        // Quintic-only branch (Poseidon2 D == 1 with a wider challenge); D = 2 here.
        if <GoldilocksD2Width8 as Poseidon2Params>::D == 1
            && <Challenge as BasedVectorSpace<Val>>::DIMENSION > 1
        {
            circuit.set_recompose_coeff_ctl_for_decompose_links(true);
        }
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<Pcs as RecursivePcs<
        ConfigWithFriParamsGl,
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
        >(runner, op_ids, opening_proof, Poseidon2Config::GOLDILOCKS_D2_W8)
    }
}

/// Goldilocks analog of `make_recursion_config`. The recursion-layer FRI
/// verifier params must match the leaf's FRI shape exactly.
pub fn make_recursion_config_gl(
    leaf_config: StarkCfg,
    log_blowup: usize,
    log_final_poly_len: usize,
    commit_pow_bits: usize,
    query_pow_bits: usize,
) -> ConfigWithFriParamsGl {
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        log_blowup,
        log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
        // The recursive FRI verifier now requires the query count (fork 125da1e port).
        crate::config_gl::num_queries(),
        Poseidon2Config::GOLDILOCKS_D2_W8,
    );
    ConfigWithFriParamsGl::new(leaf_config, fri_verifier_params)
}
