//! Zero-knowledge regression tests. zk_blinds_permutation_argument fails unless plonky2's blind()
//! joins the Z-blinding rows with connect rather than generate_copy.

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{MatrixWitness, PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use zksketch_snark::config::{
    assert_zk_safe, build_circuit, circuit_config, z_blinding_openings, z_blinding_pairs, C, D, F,
};

type FE = <F as Extendable<D>>::Extension;

const SECRET: u64 = 617;

/// A circuit whose only private input is a low-entropy secret `x < 2^10`, so an
/// attacker can enumerate it. Nothing derived from `x` is made public. Built with
/// plonky2's own `build` rather than [`build_circuit`], so the attack below runs
/// even on a plonky2 build that the crate's fail-closed guard would refuse.
fn secret_circuit(zero_knowledge: bool) -> (CircuitData<F, C, D>, Target) {
    let mut config = circuit_config();
    config.zero_knowledge = zero_knowledge;
    let mut b = CircuitBuilder::<F, D>::new(config);
    let x = b.add_virtual_target();
    b.range_check(x, 10);
    let x2 = b.mul(x, x);
    let x3 = b.mul(x2, x);
    let y = b.add(x3, x);
    b.split_le(y, 40);
    let one = b.one();
    b.register_public_input(one);
    (b.build::<C>(), x)
}

fn prove_secret(data: &CircuitData<F, C, D>, x: Target, secret: u64) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(secret))?;
    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;
    Ok(proof)
}

/// Regenerate the full witness from `secret` alone. Every blinding value is
/// sampled afresh, as an attacker (who does not know the prover's) would.
fn regenerate_witness(data: &CircuitData<F, C, D>, x: Target, secret: u64) -> Result<MatrixWitness<F>> {
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(secret))?;
    Ok(generate_partial_witness(pw, &data.prover_only, &data.common)?.full_witness())
}

/// Z and the partial products for one challenge pair, computed from a witness as
/// plonky2's prover does: `z[i] = Z(g^i)`; `pps[k][i] = Z(g^i)` times the product
/// of the first `k+1` chunks of row `i`'s ratios, the last chunk closing to
/// `Z(g^{i+1})`.
fn permutation_polys(data: &CircuitData<F, C, D>, witness: &MatrixWitness<F>, beta: F, gamma: F) -> (Vec<F>, Vec<Vec<F>>) {
    let (common, prover) = (&data.common, &data.prover_only);
    let n = common.degree();
    let num_prods = common.num_partial_products;
    let mut z = vec![F::ONE; n];
    let mut pps = vec![vec![F::ZERO; n]; num_prods];
    for i in 0..n {
        let x_i = prover.subgroup[i];
        let (nums, dens): (Vec<F>, Vec<F>) = (0..common.config.num_routed_wires)
            .map(|j| {
                let v = witness.get_wire(i, j);
                (v + beta * common.k_is[j] * x_i + gamma, v + beta * prover.sigmas[i][j] + gamma)
            })
            .unzip();
        let ratios: Vec<F> =
            nums.iter().zip(F::batch_multiplicative_inverse(&dens)).map(|(&num, den_inv)| num * den_inv).collect();
        let mut acc = z[i];
        for (k, chunk) in ratios.chunks(common.quotient_degree_factor).enumerate() {
            acc *= chunk.iter().copied().product::<F>();
            if k < num_prods {
                pps[k][i] = acc;
            }
        }
        if i + 1 < n {
            z[i + 1] = acc;
        }
    }
    (z, pps)
}

/// Guess-and-check on the permutation argument, from the circuit and the proof
/// plus a guessed secret only: replay the transcript for beta, gamma and zeta,
/// regenerate the witness from the guess, recompute Z and the partial products,
/// and count how many of the proof's openings (Z at zeta and g·zeta, partial
/// products at zeta) the recomputation reproduces. Returns `(hits, total)`.
fn permutation_openings_reproduced(
    data: &CircuitData<F, C, D>,
    x: Target,
    proof: &ProofWithPublicInputs<F, C, D>,
    guess: u64,
) -> Result<(usize, usize)> {
    let common = &data.common;
    let ch = proof.get_challenges(proof.get_public_inputs_hash(), &data.verifier_only.circuit_digest, common)?;
    let zeta = ch.plonk_zeta;
    let g_zeta = FE::primitive_root_of_unity(common.degree_bits()) * zeta;
    let witness = regenerate_witness(data, x, guess)?;

    let num_prods = common.num_partial_products;
    let eval = |values: &[F], point: FE| PolynomialValues::new(values.to_vec()).ifft().to_extension::<D>().eval(point);
    let openings = &proof.proof.openings;
    let (mut hits, mut total) = (0, 0);
    for c in 0..common.config.num_challenges {
        let (z, pps) = permutation_polys(data, &witness, ch.plonk_betas[c], ch.plonk_gammas[c]);
        let mut checks = vec![eval(&z, zeta) == openings.plonk_zs[c], eval(&z, g_zeta) == openings.plonk_zs_next[c]];
        for (k, pp) in pps.iter().enumerate() {
            checks.push(eval(pp, zeta) == openings.partial_products[c * num_prods + k]);
        }
        total += checks.len();
        hits += checks.into_iter().filter(|&hit| hit).count();
    }
    Ok((hits, total))
}

/// How much randomness the blinding puts into Z and the partial products: build
/// two witnesses for the same secret (fresh blinding values each time) and count
/// the rows where Z, and each partial-product polynomial, differ between them.
fn blinded_rows(data: &CircuitData<F, C, D>, x: Target) -> Result<(usize, Vec<usize>)> {
    let (beta, gamma) = (F::from_canonical_u64(0x1234_5678_9abc), F::from_canonical_u64(0x0fed_cba9_8765));
    let (z1, pps1) = permutation_polys(data, &regenerate_witness(data, x, SECRET)?, beta, gamma);
    let (z2, pps2) = permutation_polys(data, &regenerate_witness(data, x, SECRET)?, beta, gamma);
    let differing = |a: &[F], b: &[F]| a.iter().zip(b).filter(|(u, v)| u != v).count();
    Ok((differing(&z1, &z2), pps1.iter().zip(&pps2).map(|(a, b)| differing(a, b)).collect()))
}

#[test]
fn config_follows_zk_feature() {
    assert_eq!(circuit_config().zero_knowledge, cfg!(feature = "zk"));
}

/// Control: with zero knowledge off, Z and the partial products are determined
/// by the witness and the challenges, so the attack reproduces every opening for
/// the right guess and none for a wrong one. This validates the recomputation
/// that `zk_blinds_permutation_argument` relies on. There are no Z-blinding
/// pairs, and Z does not change between witness generations.
#[test]
fn permutation_guess_and_check_without_zk() -> Result<()> {
    let (data, x) = secret_circuit(false);
    let proof = prove_secret(&data, x, SECRET)?;

    let (hits, total) = permutation_openings_reproduced(&data, x, &proof, SECRET)?;
    assert!(total > 0);
    assert_eq!(hits, total, "right guess must reproduce every opening");
    let (hits, _) = permutation_openings_reproduced(&data, x, &proof, SECRET + 1)?;
    assert_eq!(hits, 0, "wrong guess must reproduce no opening");

    assert_eq!(z_blinding_pairs(&data.prover_only, &data.common), 0);
    let (z_rows, pp_rows) = blinded_rows(&data, x)?;
    assert_eq!(z_rows, 0);
    assert!(pp_rows.iter().all(|&rows| rows == 0));
    Ok(())
}

/// Z-leak regression: with `zero_knowledge` forced on, not even the right guess
/// may reproduce any Z or partial-product opening. Fails on plonky2 5d9da5a
/// without the `blind()` fix (every opening is reproduced there, and the secret
/// is recovered uniquely). Not gated on the `zk` feature.
///
/// It also checks the amount of blinding, not only its presence (a single
/// connected pair would already defeat the 0-hit check): the circuit must have
/// exactly one sigma-swapped row pair per Z value the verifier sees, and two
/// witness generations must give Z exactly one fresh value per pair (Z returns to
/// its old value after each pair) and each partial product two fresh values per
/// pair. Finally the crate's fail-closed guard must accept the circuit.
#[test]
fn zk_blinds_permutation_argument() -> Result<()> {
    let (data, x) = secret_circuit(true);
    assert!(data.common.config.zero_knowledge && data.common.fri_params.hiding);
    let proof = prove_secret(&data, x, SECRET)?;

    let (hits, total) = permutation_openings_reproduced(&data, x, &proof, SECRET)?;
    assert!(total > 0);
    assert_eq!(
        hits, 0,
        "plonky2 Z / partial products are not blinded: the honest witness reproduces {hits} of {total} \
         openings (is the plonky2 Z-blinding fix applied?)"
    );

    let need = z_blinding_openings(&data.common);
    assert!(need > 2 * D);
    assert_eq!(z_blinding_pairs(&data.prover_only, &data.common), need, "one Z-blinding pair per Z opening");
    let (z_rows, pp_rows) = blinded_rows(&data, x)?;
    assert_eq!(z_rows, need, "Z must take one fresh random value per Z-blinding pair");
    assert_eq!(pp_rows.len(), data.common.num_partial_products);
    assert!(pp_rows.iter().all(|&rows| rows == 2 * need), "partial products: {pp_rows:?} fresh rows, want {}", 2 * need);

    assert_zk_safe(&data);
    Ok(())
}

/// Blinding values are prover-only and the blinding copy constraints are
/// deterministic, so verifier data stays a fixed function of the shape under
/// zero knowledge. Not gated on the `zk` feature.
#[test]
fn zk_secret_circuit_digest_is_deterministic() {
    let (a, _) = secret_circuit(true);
    let (b, _) = secret_circuit(true);
    assert_eq!(a.verifier_only.circuit_digest, b.verifier_only.circuit_digest);
    assert_eq!(a.common, b.common);
}

/// The same for the crate's own circuits, which follow the `zk` feature (so this
/// one is gated); also checks they carry the full Z blinding.
#[cfg(feature = "zk")]
#[test]
fn zk_circuit_digests_are_deterministic() {
    use zksketch_snark::decode::countmin::{build_cm_decode, CmDecodeParams};
    use zksketch_snark::decode::ReleasePolicy;
    use zksketch_snark::leaf::countmin_omc::{build_countmin_omc_leaf, CmOmcParams};

    let leaf = || build_countmin_omc_leaf(CmOmcParams { d: 2, w: 4, batch: 2 });
    let (a, b) = (leaf(), leaf());
    assert!(a.data.common.config.zero_knowledge);
    assert_eq!(a.data.verifier_only.circuit_digest, b.data.verifier_only.circuit_digest);
    assert_eq!(a.data.common, b.data.common);
    assert_eq!(z_blinding_pairs(&a.data.prover_only, &a.data.common), z_blinding_openings(&a.data.common));

    let decode = || build_cm_decode(CmDecodeParams { d: 4, w: 8, release: ReleasePolicy::Identity });
    let (c, d) = (decode(), decode());
    assert_eq!(c.data.verifier_only.circuit_digest, d.data.verifier_only.circuit_digest);
    assert_eq!(c.data.common, d.data.common);
    assert_eq!(z_blinding_pairs(&c.data.prover_only, &c.data.common), z_blinding_openings(&c.data.common));
}

/// Fail-closed guard: a circuit that claims zero knowledge but has no Z-blinding
/// pairs (what upstream plonky2 5d9da5a builds) must be refused.
#[test]
#[should_panic(expected = "does not blind Z")]
fn zk_guard_rejects_unblinded_z() {
    let (mut data, _) = secret_circuit(false);
    data.common.config.zero_knowledge = true;
    assert_zk_safe(&data);
}

/// plonky2 does not blind its lookup polynomials, so `build_circuit` must refuse
/// a zero-knowledge circuit that uses a lookup table. Not gated on the `zk`
/// feature.
#[test]
#[should_panic(expected = "plonky2 lookups")]
fn zk_build_rejects_plonky2_lookups() {
    use std::sync::Arc;

    use plonky2::gates::lookup_table::LookupTable;

    let mut config = circuit_config();
    config.zero_knowledge = true;
    let mut b = CircuitBuilder::<F, D>::new(config);
    let table: LookupTable = Arc::new((0..16u16).map(|i| (i, i * i)).collect());
    let index = b.add_lookup_table_from_pairs(table);
    let x = b.add_virtual_target();
    let y = b.add_lookup_from_index(x, index);
    b.register_public_input(y);
    let _ = build_circuit(b);
}
