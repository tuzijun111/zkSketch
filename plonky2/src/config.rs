//! Proof-system configuration: Goldilocks field, Poseidon hash, shared circuit config.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, ProverOnlyCircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

/// Base field — Goldilocks, `p = 2^64 - 2^32 + 1`.
pub type F = GoldilocksField;

/// Proof config — Poseidon over Goldilocks (recursion-friendly).
pub type C = PoseidonGoldilocksConfig;

/// FRI extension degree.
pub const D: usize = 2;

/// The one `CircuitConfig` every circuit in this crate builds with, pinned to
/// the SAME conjectured-security target as the plonky3 backend
/// (`../src/config.rs` `SECURITY_LEVEL = 124`) so cross-stack rows compare at
/// parity. Conjectured FRI soundness is
/// `proof_of_work_bits + rate_bits · num_query_rounds`: plonky2's stock
/// `standard_recursion_config` is 100-bit (16 + 3·28); raising the query count
/// to 36 gives 16 + 3·36 = 124. Challenge-space soundness already clears the
/// target (degree-2 Goldilocks extension ≈ 128 bits, `num_challenges = 2`).
/// Everything else (wires, arity, cap height) keeps the recursion-friendly
/// defaults.
///
/// Zero knowledge follows the `zk` cargo feature (on by default, like the
/// plonky3 backend): plonky2 then adds random blinding rows for the wires and
/// for Z / the partial products, and salts the wires, Z and quotient Merkle
/// leaves. That makes every circuit at least 2^14 rows (about 10.7k blinding
/// rows at 36 queries). The Z blinding needs plonky2's `blind()` fix
/// (`connect`, not `generate_copy`, between each blinding pair);
/// [`build_circuit`] refuses to build a zero-knowledge circuit without it, and
/// `tests/zk_blinding.rs` attacks it. The hiding is plonky2's standard heuristic
/// ZK (no formal proof): quotient chunks are only salted, and lookup polynomials
/// are not blinded at all, which [`build_circuit`] also guards against.
pub fn circuit_config() -> CircuitConfig {
    let mut config = CircuitConfig::standard_recursion_config();
    config.security_bits = 124;
    config.fri_config.num_query_rounds = 36;
    config.zero_knowledge = cfg!(feature = "zk");
    config
}

/// Build a circuit, checking that it is safe to publish under zero knowledge.
/// Every circuit in this crate is built through this function.
pub fn build_circuit(builder: CircuitBuilder<F, D>) -> CircuitData<F, C, D> {
    let data = builder.build::<C>();
    assert_zk_safe(&data);
    data
}

/// Under `zero_knowledge`, fail closed on the two known plonky2 hiding gaps:
///
/// - **Lookups.** plonky2 computes its lookup polynomials (RE and the partial
///   SLDCs) only from the lookup and table rows, so the blinding rows do not
///   randomize them and they would leak the looked-up witness values. Require
///   that the circuit uses none.
/// - **Z blinding.** Require at least [`z_blinding_openings`] Z-blinding row
///   pairs whose routed wires are joined by copy constraints, i.e. whose sigma
///   swaps the two rows (counted by [`z_blinding_pairs`]). Upstream plonky2 at
///   the pinned rev 5d9da5a adds the rows but joins them with `generate_copy`, so
///   sigma is the identity there and Z and the partial products stay a
///   deterministic function of the witness. Such a build has 0 pairs and panics
///   here, so the `zk` default cannot silently produce leaking proofs from a
///   checkout that lacks the plonky2 fix.
pub fn assert_zk_safe(data: &CircuitData<F, C, D>) {
    let common = &data.common;
    if !common.config.zero_knowledge {
        return;
    }
    assert!(
        common.num_lookup_polys == 0 && common.luts.is_empty(),
        "zero-knowledge circuit uses plonky2 lookups ({} lookup polys, {} tables), \
         whose polynomials plonky2 does not blind",
        common.num_lookup_polys,
        common.luts.len()
    );
    let need = z_blinding_openings(common);
    let have = z_blinding_pairs(&data.prover_only, common);
    assert!(
        have >= need,
        "zero-knowledge circuit has {have} Z-blinding copy pairs but opens Z {need} times: this plonky2 \
         build does not blind Z (it needs the blind() `connect` fix, branch zk-blinding-fix; build with \
         --no-default-features for plain proofs)"
    );
}

/// The number of Z values the verifier sees for one circuit, which is also the
/// number of Z-blinding row pairs plonky2's `blind()` adds: `2·D` openings at
/// zeta and g·zeta plus, per FRI query, one leaf, `D` values per folding sibling
/// and `D` per final-polynomial coefficient. Mirrors plonky2's
/// `CircuitBuilder::num_blinding_gates` at the circuit's final degree (the
/// blinding loop always settles on that degree).
pub fn z_blinding_openings(common: &CommonCircuitData<F, D>) -> usize {
    let arities: Vec<usize> = common.fri_params.reduction_arity_bits.iter().map(|&bits| 1 << bits).collect();
    let folding_points: usize = arities.iter().map(|a| a - 1).sum();
    let final_poly_coeffs = common.degree() / arities.iter().product::<usize>();
    let fri_openings = common.config.fri_config.num_query_rounds * (1 + D * folding_points + D * final_poly_coeffs);
    2 * D + fri_openings
}

/// Count the adjacent row pairs `(r, r+1)` whose sigma swaps every routed wire
/// between the two rows, i.e. pairs joined wire-by-wire by a 2-cycle copy
/// constraint. These are the Z-blinding pairs of a correctly blinded circuit; an
/// ordinary circuit has essentially none. Each pair is counted once
/// (non-overlapping scan). Costs one field multiplication per row in practice,
/// since non-pairs fail on the first wire.
pub fn z_blinding_pairs(prover: &ProverOnlyCircuitData<F, C, D>, common: &CommonCircuitData<F, D>) -> usize {
    let n = common.degree();
    let (sigmas, subgroup, k_is) = (&prover.sigmas, &prover.subgroup, &common.k_is);
    let swapped = |r: usize| {
        (0..common.config.num_routed_wires)
            .all(|w| sigmas[r][w] == k_is[w] * subgroup[r + 1] && sigmas[r + 1][w] == k_is[w] * subgroup[r])
    };
    let (mut pairs, mut r) = (0, 0);
    while r + 1 < n {
        if swapped(r) {
            pairs += 1;
            r += 2;
        } else {
            r += 1;
        }
    }
    pairs
}
