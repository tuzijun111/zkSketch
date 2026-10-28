//! KMV (bottom-`k`) distinct-count decode circuit: the active-row count `D` if `D < k`, else
//! `floor((k − 1)·2^27 / v_k)`. Budget: base-2^14 limbs, every digit equation < 2^30 < p.

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::ops::{
    Poseidon2Config, generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::BatchStarkProof;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;

use crate::commitment::hiding::{self, CommitMode, SaltBb};
use crate::config::{Challenge, Val};
use crate::decode::{
    DecodeProof, DecodeVk, ReleasePolicy, StdDecodeCircuit, verify_pinned_decode_stark,
};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::countmin_leaf::DIGEST_PACKING;
use crate::sketch::bind::{self, Binding};
use crate::sketch::kmv::{
    HASH_BITS, KmvConsts, KmvState, MAX_K, commit_kmv_state_with, kmv_binding, kmv_estimate,
    state_commit_gadget,
};
#[cfg(test)]
use crate::sketch::kmv::commit_kmv_state;

/// Limb width of the division certificate.
const LIMB_BITS: usize = 14;
/// Exact widths of the top limbs of `v` and `rem` (`< 2^27`).
const TOP_BITS: usize = HASH_BITS - LIMB_BITS;
/// Range window of the two carries.
const CARRY_BITS: usize = 15;
/// Release-policy compare window: `ans < 2^28 + 2^15 < 2^29`, `θ < 2^29`,
/// and `p − 2^29 > 2^29` (a wrapped "negative" difference never fits).
const DIFF_BITS: usize = 29;

/// Base values of the `(Com(S), answer)` statement the decoder exposes.
pub const KMV_STATEMENT_LEN: usize = 12;

#[derive(Copy, Clone, Debug)]
pub struct KmvDecodeParams {
    /// Capacity of the decoded state.
    pub k: usize,
    pub release: ReleasePolicy,
}

impl KmvDecodeParams {
    pub fn validate(&self) {
        assert!(
            self.k >= 4 && self.k.is_multiple_of(4) && self.k <= MAX_K,
            "k must be a multiple of 4 in 4..={MAX_K}, got {}",
            self.k
        );
        if let ReleasePolicy::Threshold(t) = self.release {
            assert!(t < 1u64 << DIFF_BITS, "threshold θ = {t} must be < 2^{DIFF_BITS}");
        }
    }
}

/// The `(Com(S), answer)` statement a KMV decode proof exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KmvStatement {
    pub commit: [Val; 8],
    /// The released answer as a Challenge's 4 base coordinates.
    pub answer: [Val; 4],
}

impl KmvStatement {
    /// The statement an honest proof of `answer` against `commit` exposes.
    pub fn new(commit: [Val; 8], answer: u64) -> Self {
        Self { commit, answer: [Val::from_u64(answer), Val::ZERO, Val::ZERO, Val::ZERO] }
    }
}

/// Read the exposed `(Com(S), answer)` of a KMV decode proof (`None` if the
/// proof exposes no 12-value statement).
pub fn read_kmv_statement(proof: &BatchStarkProof<ConfigWithFriParams>) -> Option<KmvStatement> {
    let pv = proof
        .non_primitives
        .iter()
        .map(|e| &e.public_values)
        .find(|v| v.len() == KMV_STATEMENT_LEN)?;
    Some(KmvStatement {
        commit: std::array::from_fn(|i| pv[i]),
        answer: std::array::from_fn(|i| pv[8 + i]),
    })
}

/// Verifier-side statement check: the proof exposes exactly `want`.
pub fn check_kmv_statement(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    want: &KmvStatement,
) -> Result<(), String> {
    let got = read_kmv_statement(proof).ok_or("decode proof exposes no (Com(S), answer) statement")?;
    if got.commit != want.commit {
        return Err("exposed Com(S) differs from the queried commitment".into());
    }
    if got.answer != want.answer {
        return Err(format!("exposed answer {:?} differs from {:?}", got.answer, want.answer));
    }
    Ok(())
}

/// **Pinned verifier of a KMV decode proof**: the proof's metadata and
/// preprocessed commitment must equal the trusted `vk` ([`kmv_decode_vk`]),
/// the STARK must verify under the standard decode verifier, and the exposed
/// statement is returned for the caller to compare with the commitment it
/// trusts ([`check_kmv_statement`]). A self-pinned `verify_all_tables` alone
/// accepts a proof of ANY circuit exposing chosen values.
pub fn verify_kmv_decode_proof(
    proof: &BatchStarkProof<ConfigWithFriParams>,
    vk: &DecodeVk,
) -> Result<KmvStatement, String> {
    verify_pinned_decode_stark(proof, vk)?;
    read_kmv_statement(proof).ok_or_else(|| "decode proof exposes no statement".into())
}

/// The trusted VK of the KMV decoder for `params` under `binding`, derived
/// from public parameters only (a proof over the empty state; the circuit
/// does not depend on the state). The `Plain` decoder's VK
/// ([`kmv_decode_vk_commit`] with [`CommitMode::Plain`]).
pub fn kmv_decode_vk(params: KmvDecodeParams, binding: Binding) -> DecodeVk {
    kmv_decode_vk_commit(params, binding, CommitMode::Plain)
}

/// [`kmv_decode_vk`] of the decoder built under `mode` (revision B2): the
/// trusted VK of every [`prove_kmv_decode_commit`] proof of that mode.
/// Derived over the empty state with the public zero salt (the one state a
/// `Hiding` decoder opens with the zero salt); the salt is a witness, so the
/// VK does not depend on it.
pub fn kmv_decode_vk_commit(params: KmvDecodeParams, binding: Binding, mode: CommitMode) -> DecodeVk {
    build_kmv_decode_commit(params, &KmvState::empty(params.k), binding, mode, &SaltBb::ZERO)
        .derive_vk("kmv decode")
}

/// Prove the KMV distinct-count decode under the process default
/// [`Binding`].
pub fn prove_kmv_decode(params: KmvDecodeParams, state: &KmvState) -> DecodeProof {
    prove_kmv_decode_with(params, state, bind::default_binding())
}

/// [`prove_kmv_decode`] with an explicit binding (`Semantic` or `Bound`;
/// `Bound` hashes the state with a bound zero IV; `Legacy` builds `Semantic`).
pub fn prove_kmv_decode_with(params: KmvDecodeParams, state: &KmvState, binding: Binding) -> DecodeProof {
    build_kmv_decode(params, state, binding).prove("kmv decode")
}

/// [`prove_kmv_decode_with`] against a commitment made under `mode`
/// (revision B2). `Plain` is the pre-B2 circuit op for op (`salt` ignored).
/// Under `Hiding` the decoder opens `Com(S_t; ρ) = commit_kmv_state_with(S,
/// Hiding, ρ)`; for a query at version `t` of the genesis history the honest
/// salt is `rho_state_bb(seed, CommitFamily::Kmv, t)`, the randomizer leaf
/// `t` closed its final state with. The public zero salt opens only the
/// empty genesis state (`Com(S_0; 0)`, which the verifier recomputes
/// itself): handed [`SaltBb::ZERO`] with any other state the decoder panics
/// instead of publishing the guess-checkable `Com(S_t; 0)`. Pin the proof to
/// [`kmv_decode_vk_commit`] with the same `mode`.
pub fn prove_kmv_decode_commit(
    params: KmvDecodeParams,
    state: &KmvState,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> DecodeProof {
    build_kmv_decode_commit(params, state, binding, mode, salt).prove("kmv decode")
}

/// Division-certificate witness `[r0, r1, v0, v1, m0, m1, g0, g1]` of
/// `res = floor(n / v)` (see the module budget).
fn div_limbs(n: u64, v: u64) -> [u64; 8] {
    assert!(v >= 1 && v < 1 << HASH_BITS, "divisor out of range");
    assert!(n < 1 << (3 * LIMB_BITS), "numerator must fit three digits");
    let mask = (1u64 << LIMB_BITS) - 1;
    let (res, rem) = (n / v, n % v);
    assert!(res < 1 << (2 * LIMB_BITS), "quotient exceeds two limbs");
    let (r0, r1) = (res & mask, res >> LIMB_BITS);
    let (v0, v1) = (v & mask, v >> LIMB_BITS);
    let (m0, m1) = (rem & mask, rem >> LIMB_BITS);
    let nd = [n & mask, (n >> LIMB_BITS) & mask, n >> (2 * LIMB_BITS)];
    let c0 = r0 * v0;
    let g0 = (c0 + m0 - nd[0]) >> LIMB_BITS;
    let c1 = r0 * v1 + r1 * v0;
    let g1 = (c1 + m1 + g0 - nd[1]) >> LIMB_BITS;
    debug_assert_eq!(c0 + m0 - nd[0], g0 << LIMB_BITS, "digit 0 must close");
    debug_assert_eq!(c1 + m1 + g0 - nd[1], g1 << LIMB_BITS, "digit 1 must close");
    debug_assert_eq!(r1 * v1 + g1, nd[2], "digit 2 must close");
    [r0, r1, v0, v1, m0, m1, g0, g1]
}

/// `N = (k − 1)·2^27` digits (base 2^14).
fn n_digits(k: usize) -> [u64; 3] {
    let n = (k as u64 - 1) << HASH_BITS;
    let mask = (1u64 << LIMB_BITS) - 1;
    [n & mask, (n >> LIMB_BITS) & mask, n >> (2 * LIMB_BITS)]
}

/// Build the KMV decode circuit and its witness (`Plain` commitments).
pub(crate) fn build_kmv_decode(
    params: KmvDecodeParams,
    state: &KmvState,
    binding: Binding,
) -> StdDecodeCircuit {
    build_kmv_decode_commit(params, state, binding, CommitMode::Plain, &SaltBb::ZERO)
}

/// [`build_kmv_decode`] against a commitment made under `mode` with
/// randomizer `salt` ([`prove_kmv_decode_commit`]).
pub(crate) fn build_kmv_decode_commit(
    params: KmvDecodeParams,
    state: &KmvState,
    binding: Binding,
    mode: CommitMode,
    salt: &SaltBb,
) -> StdDecodeCircuit {
    params.validate();
    let binding = kmv_binding(binding);
    let KmvDecodeParams { k, release } = params;
    assert_eq!(state.k, k, "state capacity must match params.k");
    assert!(state.vals.len() <= k && state.vals.windows(2).all(|w| w[0] < w[1]));
    if mode.is_hiding() && salt.is_zero() {
        assert!(
            state.vals.is_empty(),
            "Hiding KMV decode: the public zero salt opens only the empty genesis state Com(S_0; 0); \
             a query at t >= 1 needs its real salt"
        );
    }

    // ─── Native decode ───────────────────────────────────────────────────
    let commit = commit_kmv_state_with(state, mode, salt);
    let full = state.is_full();
    let raw = kmv_estimate(state);
    let answer = release.apply(raw);
    let (n_eff, v_eff) =
        if full { ((k as u64 - 1) << HASH_BITS, state.vals[k - 1] as u64) } else { (0, 1) };
    let limbs = div_limbs(n_eff, v_eff);
    debug_assert_eq!(if full { limbs[0] + (limbs[1] << LIMB_BITS) } else { raw }, raw);

    // ─── Circuit ─────────────────────────────────────────────────────────
    let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
    let mut b = CircuitBuilder::<Challenge>::new();
    b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
    b.enable_range(generate_range_trace::<Val, Challenge>);
    b.enable_expose(generate_expose_trace::<Val, Challenge>);

    let commit_pis: [ExprId; DIGEST_PACKING] = std::array::from_fn(|i| {
        b.alloc_public_input(if i == 0 { "commit_lo" } else { "commit_hi" })
    });
    let answer_pi = b.alloc_public_input("answer");
    b.tag(answer_pi, "kmv_answer").expect("tag");
    b.add_expose(&[commit_pis[0], commit_pis[1], answer_pi]).expect("expose (commit, answer)");

    let c = KmvConsts::new(&mut b, k);
    let (one, zero) = (c.one, c.zero);
    let p_limb = b.alloc_const(Challenge::from_u64(1 << LIMB_BITS), "2^14");
    let nd: Vec<ExprId> =
        n_digits(k).iter().map(|&d| b.alloc_const(Challenge::from_u64(d), "n_digit")).collect();

    // B2: under `Hiding` the salt of `Com(S)` comes first (3 private
    // inputs); `Plain` allocates nothing.
    let salt_t = mode.is_hiding().then(|| hiding::alloc_salt_targets(&mut b));
    let rows: Vec<[ExprId; 2]> =
        (0..k).map(|_| std::array::from_fn(|_| b.alloc_private_input("row"))).collect();
    let lw: [ExprId; 8] = std::array::from_fn(|_| b.alloc_private_input("div_limb"));
    let flag = matches!(release, ReleasePolicy::Threshold(_)).then(|| b.alloc_private_input("flag"));

    // ── Stage 1: open the committed state (exact 27-bit values) ──
    let (packs, digest) =
        state_commit_gadget(&mut b, &cfg, &rows, &c, binding, true, 0, salt_t.as_ref());
    for (q, &p) in packs.iter().enumerate() {
        b.tag(p, format!("kmv_dec_pack_{q}")).expect("tag");
    }
    for i in 0..DIGEST_PACKING {
        b.connect(digest[i], commit_pis[i]);
    }

    // ── Stage 2: actives are a strictly increasing prefix ──
    let mut count = rows[0][1];
    for j in 0..k - 1 {
        let [h0, a0] = rows[j];
        let [h1, a1] = rows[j + 1];
        let oma0 = b.sub(one, a0);
        let pre = b.mul(oma0, a1);
        b.connect(pre, zero);
        let d = b.sub(h1, h0);
        let dm1 = b.sub(d, one);
        let g = b.mul(a1, dm1);
        b.add_range_bits::<Val>(g, HASH_BITS).expect("strictly increasing");
        count = b.add(count, a1);
    }
    let full_w = rows[k - 1][1];

    // ── Stage 3: gated division certificate ──
    let [r0, r1, v0, v1, m0, m1, g0, g1] = lw;
    for (x, bits) in [
        (r0, LIMB_BITS),
        (r1, LIMB_BITS),
        (v0, LIMB_BITS),
        (v1, TOP_BITS),
        (m0, LIMB_BITS),
        (m1, TOP_BITS),
        (g0, CARRY_BITS),
        (g1, CARRY_BITS),
    ] {
        let xv = b.mul(x, one);
        b.add_range_bits::<Val>(xv, bits).expect("division limb range");
    }
    // v = h_{k−1} + (1 − full) = v1·2^14 + v0.
    let omf = b.sub(one, full_w);
    let v_eff = b.add(rows[k - 1][0], omf);
    let v_rec = b.mul_add(v1, p_limb, v0);
    b.connect(v_rec, v_eff);
    // rem = m1·2^14 + m0 ≤ v − 1.
    let rem = b.mul_add(m1, p_limb, m0);
    let vm1 = b.sub(v_eff, one);
    let slack = b.sub(vm1, rem);
    b.add_range_bits::<Val>(slack, HASH_BITS).expect("rem < v");
    // Digit equations against full·N.
    let n0 = b.mul(full_w, nd[0]);
    let n1 = b.mul(full_w, nd[1]);
    let n2 = b.mul(full_w, nd[2]);
    let c0 = b.mul(r0, v0);
    let l0 = b.add(c0, m0);
    let rhs0 = b.mul_add(g0, p_limb, n0);
    b.connect(l0, rhs0);
    let t01 = b.mul(r0, v1);
    let c1 = b.mul_add(r1, v0, t01);
    let l1a = b.add(c1, m1);
    let l1 = b.add(l1a, g0);
    let rhs1 = b.mul_add(g1, p_limb, n1);
    b.connect(l1, rhs1);
    let c2 = b.mul(r1, v1);
    let l2 = b.add(c2, g1);
    b.connect(l2, n2);
    let res = b.mul_add(r1, p_limb, r0);

    // ── Stage 4: answer = full·res + (1 − full)·count, then release ──
    let exact = b.mul(omf, count);
    let ans = b.mul_add(full_w, res, exact);
    match release {
        ReleasePolicy::Identity => b.connect(ans, answer_pi),
        ReleasePolicy::Threshold(t) => {
            let theta = b.alloc_const(Challenge::from_u64(t), "theta");
            let fl = flag.expect("threshold flag");
            b.assert_bool(fl);
            // chosen = fl·(ans − θ) + (1 − fl)·(θ − ans − 1) ≥ 0  ⇔  fl = [ans ≥ θ].
            let ge = b.sub(ans, theta);
            let tm = b.sub(theta, ans);
            let lt = b.sub(tm, one);
            let nf = b.sub(one, fl);
            let a = b.mul(fl, ge);
            let nft = b.mul(nf, lt);
            let chosen = b.add(a, nft);
            b.add_range_bits::<Val>(chosen, DIFF_BITS).expect("release compare");
            let released = b.mul(fl, ans);
            b.connect(released, answer_pi);
        }
    }

    let circuit = b.build().expect("build kmv decode circuit");

    // ─── Inputs ──────────────────────────────────────────────────────────
    let ch = |d: &[Val]| Challenge::from_basis_coefficients_slice(d).expect("4 coeffs");
    let public_inputs = vec![ch(&commit[0..4]), ch(&commit[4..8]), Challenge::from_u64(answer)];
    let mut private_inputs: Vec<Challenge> = Vec::with_capacity(2 * k + 12);
    if mode.is_hiding() {
        private_inputs.extend(salt.packed());
    }
    for (h, a) in state.rows() {
        private_inputs.push(Challenge::from_u32(h));
        private_inputs.push(Challenge::from_u32(a));
    }
    private_inputs.extend(limbs.iter().map(|&x| Challenge::from_u64(x)));
    if let ReleasePolicy::Threshold(t) = release {
        private_inputs.push(Challenge::from_bool(raw >= t));
    }
    StdDecodeCircuit::new(circuit, public_inputs, private_inputs, answer, true, "kmv decode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::make_perm;
    use crate::sketch::forge;
    use crate::sketch::kmv::{kmv_advance, kmv_hash};

    /// States of capacity `k`: empty, below capacity, exactly full, and full
    /// after a long stream.
    fn states(k: usize) -> Vec<KmvState> {
        let keys: Vec<u64> = (0..4000u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 7).collect();
        let e = KmvState::empty(k);
        vec![
            e.clone(),
            kmv_advance(&e, &keys[..k / 2]),
            kmv_advance(&e, &keys[..k]),
            kmv_advance(&e, &keys),
        ]
    }

    fn statement(p: &DecodeProof) -> KmvStatement {
        read_kmv_statement(&p.output.0).expect("exposed (commit, answer)")
    }

    /// The certified answer equals the native estimate for not-full and
    /// full states (k ∈ {4, 8}), and the proof exposes `(Com(S), answer)`.
    #[test]
    fn kmv_decode_matches_native() {
        for k in [4usize, 8] {
            for s in states(k) {
                let want = kmv_estimate(&s);
                let p = prove_kmv_decode(KmvDecodeParams { k, release: ReleasePolicy::Identity }, &s);
                assert_eq!(p.answer, want, "k={k} vals={:?}", s.vals);
                assert_eq!(statement(&p), KmvStatement::new(commit_kmv_state(&s), want));
            }
            assert!(states(k)[3].is_full() && !states(k)[1].is_full());
        }
        // A large-v_k full state: answer near (k−1)·2^27 / v_k exactly.
        let s = KmvState { k: 4, vals: vec![1, 2, 3, (1 << 27) - 1] };
        let p = prove_kmv_decode(KmvDecodeParams { k: 4, release: ReleasePolicy::Identity }, &s);
        assert_eq!(p.answer, kmv_estimate(&s));
        // The smallest possible v_k = k − 1: res = 2^27.
        let s = KmvState { k: 4, vals: vec![0, 1, 2, 3] };
        let p = prove_kmv_decode(KmvDecodeParams { k: 4, release: ReleasePolicy::Identity }, &s);
        assert_eq!(p.answer, 1 << 27);
        // Bound binding agrees.
        let s = &states(8)[3];
        let p = prove_kmv_decode_with(KmvDecodeParams { k: 8, release: ReleasePolicy::Identity }, s, Binding::Bound);
        assert_eq!(p.answer, kmv_estimate(s));
    }

    /// Threshold release: suppressed below θ, passed at and above θ.
    #[test]
    fn kmv_decode_threshold() {
        let s = &states(8)[3];
        let est = kmv_estimate(s);
        let at = |t: u64| prove_kmv_decode(KmvDecodeParams { k: 8, release: ReleasePolicy::Threshold(t) }, s).answer;
        assert_eq!(at(est), est);
        assert_eq!(at(est + 1), 0);
        let small = &states(8)[1];
        let p = prove_kmv_decode(KmvDecodeParams { k: 8, release: ReleasePolicy::Threshold(5) }, small);
        assert_eq!(p.answer, ReleasePolicy::Threshold(5).apply(kmv_estimate(small)));
    }

    /// A tampered answer is rejected: (a) altering the exposed answer or
    /// `Com(S)` of an honest proof fails verification; (b) a prover that
    /// writes a wrong answer into the answer wire (transplant through every
    /// table) is rejected, while the honest answer through the same forger
    /// verifies (positive control); (c) the statement check rejects a
    /// different answer, for a full and a not-full state.
    #[test]
    fn kmv_decode_tampered_answer_rejected() {
        let params = KmvDecodeParams { k: 8, release: ReleasePolicy::Identity };
        let verifies = |dc: &StdDecodeCircuit, p: &BatchStarkProof<ConfigWithFriParams>| {
            forge::catch(|| dc.prover.verify_all_tables(p).is_ok()).unwrap_or(false)
        };
        for s in [states(8)[3].clone(), states(8)[1].clone()] {
            let want = KmvStatement::new(commit_kmv_state(&s), kmv_estimate(&s));
            let dc = build_kmv_decode(params, &s, Binding::Semantic);
            // (a)
            let honest = dc.prove_traces(&dc.run("kmv")).expect("honest proof");
            assert!(verifies(&dc, &honest));
            assert_eq!(read_kmv_statement(&honest), Some(want));
            assert!(verifies(&dc, &crate::decode::clone_proof(&honest)), "control: copied proof verifies");
            for (slot, what) in [(8usize, "answer"), (0, "Com(S)")] {
                let mut forged = crate::decode::clone_proof(&honest);
                let e = forged
                    .non_primitives
                    .iter_mut()
                    .find(|e| e.public_values.len() == KMV_STATEMENT_LEN)
                    .expect("statement");
                e.public_values[slot] += Val::ONE;
                assert!(!verifies(&dc, &forged), "a tampered exposed {what} must fail verification");
            }
            // (b)
            let transplant = |v: u64| -> bool {
                let mut traces = dc.run("kmv");
                let aw = traces.tag_to_witness["kmv_answer"];
                forge::set_wid::<Val, Challenge>(&mut traces, aw, Challenge::from_u64(v));
                forge::accepted(|| dc.prove_traces(&traces).map(|_| ()))
            };
            let a = kmv_estimate(&s);
            assert!(transplant(a), "positive control: the honest answer through the forger verifies");
            for bad in [a + 1, a.saturating_sub(1), a ^ 0x55, 999_999] {
                if bad != a {
                    assert!(!transplant(bad), "answer {bad} (honest {a}) must be rejected");
                }
            }
            // (c)
            assert_eq!(check_kmv_statement(&honest, &want), Ok(()));
            let mut lie = want;
            lie.answer[0] += Val::ONE;
            assert!(check_kmv_statement(&honest, &lie).is_err());
            let mut other = want;
            other.commit[0] += Val::ONE;
            assert!(check_kmv_statement(&honest, &other).is_err());
        }
    }

    /// FORGED STATE: decode a state whose `k`-th value is smaller (a larger
    /// estimate), then write the honest packed state element back into its
    /// wire and rehash, so the proof exposes the HONEST `Com(S)` with the
    /// forged answer. The ALU packing binds the opened values to the
    /// commitment: rejected. Positive control: the honest state through the
    /// same forger verifies and exposes the honest statement.
    #[test]
    fn kmv_decode_forged_state_rejected() {
        let params = KmvDecodeParams { k: 8, release: ReleasePolicy::Identity };
        let real = states(8)[3].clone();
        let mut fake = real.clone();
        fake.vals[7] = fake.vals[6] + 1;
        assert!(kmv_estimate(&fake) > kmv_estimate(&real));
        let run = |forge_it: bool| -> Option<KmvStatement> {
            let dc = build_kmv_decode(params, if forge_it { &fake } else { &real }, Binding::Semantic);
            let mut traces = dc.run("kmv");
            // Row 7 lives in packed element 1; restore the real packing.
            let real_dc = build_kmv_decode(params, &real, Binding::Semantic);
            let real_traces = real_dc.run("kmv");
            let wid = traces.tag_to_witness["kmv_dec_pack_1"];
            let rwid = real_traces.tag_to_witness["kmv_dec_pack_1"];
            let honest_pack = forge::get_wid::<Val, Challenge>(&real_traces, rwid).expect("pack");
            forge::set_wid::<Val, Challenge>(&mut traces, wid, honest_pack);
            forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, Poseidon2Config::BABY_BEAR_D4_W16, &make_perm());
            forge::catch(|| dc.prove_traces(&traces).ok()).flatten().and_then(|p| read_kmv_statement(&p))
        };
        let got = forge::forged_with_control(
            "kmv decode forged state",
            run,
            |st| assert_eq!(*st, KmvStatement::new(commit_kmv_state(&real), kmv_estimate(&real))),
        );
        assert!(got.is_none(), "a forged state behind the honest Com(S) must be rejected: {got:?}");
    }

    /// B2 hiding decoder: a query at version `t` opens the `Com(S_t; ρ^S_t)`
    /// a hiding leaf `t` published (the exposed statement is that leaf's
    /// final), pinned to the HIDING decode VK (derived from public parameters:
    /// the empty state under the public zero salt), which differs from the
    /// plain one — each mode's proof fails the other mode's VK. The salt is a
    /// witness (no salt value is a public value; +3 ALU rows, its creators),
    /// and the public zero salt opens only the empty genesis state. `Plain`
    /// through the commit API is the pre-B2 decoder. Under both `Semantic`
    /// and `Bound` (the salted sponge with the bound zero IV).
    #[test]
    fn hiding_decode_exposes_hiding_commit_and_pins_to_the_hiding_vk() {
        use crate::commitment::hiding::probe::{leaked_salts, proof_alu_rows};
        use crate::commitment::hiding::{CommitFamily, Openings, SaltSeed, rho_state_bb};
        use crate::recursion::recursive::statement::Expose;
        use crate::sketch::kmv::{KmvParams, build_kmv_leaf_commit};
        let params = KmvDecodeParams { k: 4, release: ReleasePolicy::Identity };
        for sem in [Binding::Semantic, Binding::Bound] {
            let seed = SaltSeed::for_tests(61);
            let t = 2u64;
            let s1 = kmv_advance(&KmvState::empty(4), &[1, 2, 3]);
            let leaf = build_kmv_leaf_commit(KmvParams { k: 4, batch: 4 }, Expose::Interval, sem, CommitMode::Hiding)
                .prove_epoch_commit(t, s1, vec![4, 5, 1], &Openings::for_leaf(&seed, CommitFamily::Kmv, t));
            let s2 = leaf.final_state.clone();
            let salt = rho_state_bb(&seed, CommitFamily::Kmv, t);
            let (vk_h, vk_p) = (kmv_decode_vk_commit(params, sem, CommitMode::Hiding), kmv_decode_vk(params, sem));
            assert_ne!(vk_h.commitment, vk_p.commitment, "the hiding decoder is another circuit");
            let q = prove_kmv_decode_commit(params, &s2, sem, CommitMode::Hiding, &salt);
            let st = verify_kmv_decode_proof(&q.output.0, &vk_h).expect("hiding proof under the hiding pin");
            assert_eq!(st, KmvStatement::new(leaf.final_commit, kmv_estimate(&s2)), "{sem:?}: exposes leaf t's final");
            assert_eq!(st.commit, commit_kmv_state_with(&s2, CommitMode::Hiding, &salt));
            assert!(verify_kmv_decode_proof(&q.output.0, &vk_p).is_err(), "the plain VK rejects a hiding proof");
            let p = prove_kmv_decode_with(params, &s2, sem);
            assert!(verify_kmv_decode_proof(&p.output.0, &vk_h).is_err(), "the hiding VK rejects a plain proof");
            assert_eq!(proof_alu_rows(&q.output.0), proof_alu_rows(&p.output.0) + 3, "{sem:?}: the salt's 3 ALU creators");
            assert_eq!(leaked_salts(&q.output.0, &[salt]), vec![], "no salt in the public values");
            // The zero salt opens only the empty genesis state.
            let r = forge::catch_msg(|| prove_kmv_decode_commit(params, &s2, sem, CommitMode::Hiding, &SaltBb::ZERO).answer);
            assert!(r.is_err_and(|e| e.contains("public zero salt opens only the empty genesis state")));
            let e = KmvState::empty(4);
            let g = prove_kmv_decode_commit(params, &e, sem, CommitMode::Hiding, &SaltBb::ZERO);
            let gs = verify_kmv_decode_proof(&g.output.0, &vk_h).expect("the genesis query under the hiding pin");
            assert_eq!(gs, KmvStatement::new(commit_kmv_state_with(&e, CommitMode::Hiding, &SaltBb::ZERO), 0));
            // Plain through the commit API (salt ignored) is the pre-B2 decoder.
            let pc = prove_kmv_decode_commit(params, &s2, sem, CommitMode::Plain, &salt);
            let ps = verify_kmv_decode_proof(&pc.output.0, &vk_p).expect("plain proof under the plain pin");
            assert_eq!(ps, KmvStatement::new(commit_kmv_state(&s2), kmv_estimate(&s2)));
        }
    }

    /// `Binding::Legacy` (a `ZKSKETCH_BINDING=legacy` run) builds the Semantic
    /// decoder instead of panicking: the same derived VK, and a Legacy-built
    /// proof verifies under the Semantic pin.
    #[test]
    fn kmv_decode_legacy_selects_semantic() {
        let params = KmvDecodeParams { k: 4, release: ReleasePolicy::Identity };
        let vk = kmv_decode_vk(params, Binding::Semantic);
        assert_eq!(kmv_decode_vk(params, Binding::Legacy), vk);
        let s = &states(4)[3];
        let p = prove_kmv_decode_with(params, s, Binding::Legacy);
        let st = verify_kmv_decode_proof(&p.output.0, &vk).expect("Legacy-built proof under the Semantic pin");
        assert_eq!(st, KmvStatement::new(commit_kmv_state(s), kmv_estimate(s)));
    }

    /// The pinned decoder VK (derived from public parameters) accepts honest
    /// proofs of every state and returns their statements, and rejects a
    /// KMV decoder of another `k`, the HyperLogLog decoder (also a 12-value
    /// `(Com(S), answer)` exposure) and a circuit that merely exposes a lying
    /// statement — which the self-pinned `verify_all_tables` accepts.
    #[test]
    fn kmv_decode_pinned_vk() {
        use p3_circuit::ops::{
            generate_expose_trace, generate_poseidon2_trace, generate_range_trace,
            generate_recompose_trace,
        };
        let params = KmvDecodeParams { k: 8, release: ReleasePolicy::Identity };
        let vk = kmv_decode_vk(params, Binding::Semantic);
        for s in states(8) {
            let p = prove_kmv_decode_with(params, &s, Binding::Semantic);
            let st = verify_kmv_decode_proof(&p.output.0, &vk).expect("honest proof under the pin");
            assert_eq!(st, KmvStatement::new(commit_kmv_state(&s), kmv_estimate(&s)));
        }
        // Another k.
        let p4 = prove_kmv_decode_with(KmvDecodeParams { k: 4, ..params }, &states(4)[3], Binding::Semantic);
        assert!(verify_kmv_decode_proof(&p4.output.0, &vk).is_err(), "another k is another circuit");
        // Another binding of the same shape.
        let pb = prove_kmv_decode_with(params, &states(8)[3], Binding::Bound);
        assert!(verify_kmv_decode_proof(&pb.output.0, &vk).is_err(), "Bound is another circuit");
        // The HLL decoder (12-value exposure).
        let regs: Vec<u64> = vec![3, 1, 4, 2];
        let hp = crate::decode::hyperloglog::prove_hll_decode_omc_with(
            crate::decode::hyperloglog::HllDecodeParams { b: 2, release: ReleasePolicy::Identity },
            regs,
            0,
            Binding::Semantic,
        );
        assert!(read_kmv_statement(&hp.output.0).is_some(), "HLL exposes a 12-value statement too");
        assert!(verify_kmv_decode_proof(&hp.output.0, &vk).is_err(), "the HLL decoder is rejected");
        // A circuit that computes nothing and exposes a lying statement.
        let s = &states(8)[3];
        let lie = KmvStatement::new(commit_kmv_state(s), kmv_estimate(s) + 1000);
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_range(generate_range_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let pis: Vec<ExprId> = (0..3).map(|_| b.alloc_public_input("pi")).collect();
        b.add_expose(&pis).expect("expose");
        let _ = b.add_hash_slice(&Poseidon2Config::BABY_BEAR_D4_W16, &pis[2..3], true).expect("hash");
        let _ = b.add_range_bits::<Val>(pis[2], 24).expect("range");
        let circuit = b.build().expect("fake decoder");
        let ch = |v: &[Val]| Challenge::from_basis_coefficients_slice(v).expect("4 coeffs");
        let fake = StdDecodeCircuit::new(
            circuit,
            vec![ch(&lie.commit[..4]), ch(&lie.commit[4..]), ch(&lie.answer)],
            vec![],
            0,
            true,
            "fake kmv decoder",
        );
        let fp = fake.prove_traces(&fake.run("fake")).expect("the fake circuit proves");
        assert!(forge::catch(|| fake.prover.verify_all_tables(&fp).is_ok()).unwrap_or(false));
        assert_eq!(check_kmv_statement(&fp, &lie), Ok(()), "…and its lying statement passes the value check");
        let err = verify_kmv_decode_proof(&fp, &vk).expect_err("the pinned verifier must reject it");
        assert!(err.contains("trusted decoder VK"), "{err}");
        // The estimate the decoder certifies tracks the hash: a sanity anchor.
        assert!(kmv_hash(1) < 1 << HASH_BITS);
    }
}
