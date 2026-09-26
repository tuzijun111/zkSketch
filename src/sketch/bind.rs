//! **In-circuit binding helpers** for the sound (`Binding::Bound`) builds of
//! the Count-Min / HyperLogLog leaves and decoders.
//!
//! Three properties of the pinned fork (July620/Plonky3_RangeAir @ 19dcb37)
//! make the pre-fix (`Binding::Legacy`) builds unsound:
//!
//! 1. **Unbound decompose coefficients.** With the recompose NPO enabled and
//!    `coeff_lookups = false` (every leaf here), `decompose_ext_to_base_coeffs(x)`
//!    returns hint coefficients that the Recompose table never reads on the
//!    WitnessChecks bus: `RecomposeAir::eval` receives only the packed output
//!    `[x_idx, v_0..v_3]`, and `v_i` is not tied to the coefficient witnesses.
//!    A prover may put any value, even a non-base extension element, in them.
//!    [`decompose_bound`] re-binds them. It pins each coefficient to the base
//!    field (range check, bits, or [`canonical_split_gadget`]) and asserts
//!    `x == Σ c_i·e_i` through ALU rows (`recompose_base_coeffs_to_ext_via_alu`
//!    + `connect`), which ARE constrained. Witness generation is unchanged
//!    because the coefficients still come from the fork's decomposition hint.
//!    The now-redundant Recompose NPO row stays; it only re-checks `x`.
//! 2. **Free sponge IV (D = 4 Poseidon2).** The non-compact D = 4 layout puts
//!    no constraint on first-row input limbs that carry no CTL (the zero
//!    capacity assertion exists only in the compact D = 1 layout). So
//!    `add_hash_slice` hashes under a prover-chosen capacity, and for a
//!    one-Challenge input also a prover-chosen second rate limb. A
//!    single-block digest, such as a record's routing hash, can then be
//!    ground at will. [`hash_slice_bound`] feeds the zero constant into every
//!    first-row limb.
//! 3. **Non-canonical positions.** `decompose_to_bits(x, Val::bits())` also
//!    admits the bits of `x + p` (BabyBear: whenever `x < 2^31 − p`). Because
//!    `p ≡ 1 (mod 2^27)`, that shifts a `mod 2^k` position to `(x+1) mod 2^k`.
//!    [`canonical_split_gadget`] (positions) and [`assert_canonical_bits`]
//!    (full-width bit decompositions) reject it. (The merged soundness fork
//!    canonicalises full-width `decompose_to_bits` itself;
//!    `probe::fork_canonical_bits` reports which fork is linked.)
//!
//! The candidate fork switch `set_recompose_coeff_ctl_for_decompose_links(true)`,
//! with the `recompose/coeff` table, does NOT fix (1) for these circuits.
//! That table becomes a WitnessChecks *creator* of every hint coefficient
//! (multiplicity `ext_reads`, `batch_stark_prover/recompose.rs:345`). The
//! ALU also creates a hint output on its first ALU use, because the Hint op
//! does not mark it defined (`circuit.rs` creator rules). Neither creator
//! ever reads the coefficient. If the ALU reads it once, `ext_reads = 0`, so
//! nothing checks it and a forged coefficient is still accepted. If it is
//! read two or more times, it is created twice and even honest proofs fail.
//! See `tests::coeff_ctl_candidate_is_not_a_fix`.
//!
//! **Open caveat.** The fork does not bind constant VALUES: ConstAir keeps
//! them in the main trace and only `(index, multiplicity)` is preprocessed.
//! The basis constants `e_i` of the ALU recomposition, the zero IV, and every
//! range/split constant are all constants. Soundness of the bound builds is
//! therefore conditional on that separate fix.

use p3_circuit::ops::{Poseidon2Config, Poseidon2PermCall};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField64};

/// Which binding discipline a leaf/decoder is built with.
///
/// The fixes are layered so that a fork that binds decompose coefficients and
/// the sponge IV itself can drop the in-circuit workarounds:
///
/// | mode       | circuit-semantic fixes | ALU coefficient re-binding + zero-IV sponge |
/// |------------|------------------------|---------------------------------------------|
/// | `Legacy`   | –                      | –                                           |
/// | `Semantic` | ✓                      | –                                           |
/// | `Bound`    | ✓                      | ✓                                           |
///
/// The *semantic* fixes are needed whatever the fork does: canonical position
/// splits, coordinate-wise sort keys, base pins on free private inputs, and
/// exposing a decoder's answer. `Bound` is the only sound choice at the
/// pinned fork rev. `Semantic` is sound only on a fork that binds every
/// `decompose_ext_to_base_coeffs` coefficient (pinned to the base field) and
/// every non-CTL first-row sponge limb.
///
/// **Default: `Semantic`.** The integration builds against the merged
/// soundness fork (coefficient binding via `recompose/coeff` on by default in
/// `CircuitBuilder`, zero IV enforced on every `new_start` sponge row), which
/// makes `Bound`'s in-circuit re-binding redundant cost. `Bound` stays
/// selectable (`ZKSKETCH_BINDING=bound`) as the fallback for an unfixed fork;
/// the `probe::fork_binds_decompose` / `probe::fork_binds_iv` tests report
/// which fork is linked.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Binding {
    /// Sound at the pinned fork: semantic fixes plus ALU re-binding of every
    /// decomposed coefficient and a bound zero IV on every sponge.
    Bound,
    /// Semantic fixes only; relies on the fork for coefficient and IV binding.
    /// The default on the merged soundness fork.
    #[default]
    Semantic,
    /// The pre-fix construction, kept only for side-by-side cost comparison
    /// and the forgery PoCs. **Unsound** at the pinned fork: its decomposed
    /// coefficients and first-row sponge limbs are prover-chosen.
    Legacy,
}

impl Binding {
    /// Circuit-semantic fixes on (`Bound` and `Semantic`).
    pub const fn is_bound(self) -> bool {
        !matches!(self, Binding::Legacy)
    }
    /// In-circuit ALU re-binding of decomposed coefficients (`Bound` only).
    pub const fn binds_coeffs(self) -> bool {
        matches!(self, Binding::Bound)
    }
    /// Zero-fed first-row sponge limbs (`Bound` only).
    pub const fn binds_iv(self) -> bool {
        matches!(self, Binding::Bound)
    }
}

// ─── Sponge ──────────────────────────────────────────────────────────────

/// Sponge hash equal to `add_hash_slice(cfg, inputs, true)` and to the native
/// `MyHash` (`PaddingFreeSponge`, zero IV, overwrite mode), except that EVERY
/// input limb of the first (`new_start`) permutation row is CTL-bound. Rate
/// limbs the first chunk does not fill, and all capacity limbs, are fed
/// `zero` (the zero constant). Later rows are unchanged: their missing rate
/// limbs and capacity chain from the previous row's output.
pub(crate) fn hash_slice_bound<F: Field>(
    b: &mut CircuitBuilder<F>,
    cfg: &Poseidon2Config,
    inputs: &[ExprId],
    zero: ExprId,
) -> Vec<ExprId> {
    assert!(!inputs.is_empty(), "hash_slice_bound: empty input");
    let width_ext = cfg.width_ext();
    let rate_ext = cfg.rate_ext();
    let chunks: Vec<&[ExprId]> = inputs.chunks(rate_ext).collect();
    let last = chunks.len() - 1;
    let mut outputs: Vec<Option<ExprId>> = Vec::new();
    for (i, ch) in chunks.iter().enumerate() {
        let first = i == 0;
        let call_inputs: Vec<Option<ExprId>> = (0..width_ext)
            .map(|j| {
                if j < ch.len() {
                    Some(ch[j])
                } else if first {
                    Some(zero)
                } else {
                    None
                }
            })
            .collect();
        let (_, outs) = b
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: *cfg,
                new_start: first,
                merkle_path: false,
                mmcs_bit: None,
                inputs: call_inputs,
                out_ctl: vec![i == last; rate_ext],
                return_all_outputs: false,
                mmcs_index_sum: None,
            })
            .expect("poseidon2 perm");
        outputs = outs;
    }
    outputs
        .into_iter()
        .take(rate_ext)
        .map(|o| o.expect("rate output"))
        .collect()
}

/// `hash_slice_bound` under [`Binding::Bound`], plain `add_hash_slice`
/// otherwise.
pub(crate) fn hash_slice<F: Field>(
    b: &mut CircuitBuilder<F>,
    cfg: &Poseidon2Config,
    inputs: &[ExprId],
    zero: ExprId,
    binding: Binding,
) -> Vec<ExprId> {
    if binding.binds_iv() {
        hash_slice_bound(b, cfg, inputs, zero)
    } else {
        b.add_hash_slice(cfg, inputs, true).expect("add_hash_slice")
    }
}

/// Process-wide default [`Binding`] for the entry points that do not take
/// one: `Semantic` (the merged soundness fork binds decompose coefficients
/// and the sponge IV itself). The environment variable `ZKSKETCH_BINDING`
/// overrides it: `legacy` (the pre-fix circuits, byte-for-byte against the
/// same fork, for side-by-side cost runs), `semantic`, or `bound` (adds the
/// in-circuit ALU re-binding + zero-IV sponge, the fallback for an unfixed
/// fork). Any other non-empty value, including one that is not valid
/// UTF-8, panics rather than silently picking a mode
/// ([`parse_binding_env`]).
///
/// Selecting `legacy` prints a loud warning to stderr (once per process,
/// [`warn_legacy_binding`]): the Legacy circuits are UNSOUND on the merged
/// fork too.
pub fn default_binding() -> Binding {
    let binding = parse_binding_env(std::env::var("ZKSKETCH_BINDING"));
    if binding == Binding::Legacy {
        warn_legacy_binding();
    }
    binding
}

/// Parse a `ZKSKETCH_BINDING` lookup (`std::env::var` result). Unset or empty
/// gives the default (`Semantic`); `legacy` / `semantic` / `bound` (any case)
/// select that mode; every other value panics, and so does a value that is
/// not valid UTF-8 (`VarError::NotUnicode`), which would otherwise be
/// mistaken for "unset".
pub fn parse_binding_env(var: Result<String, std::env::VarError>) -> Binding {
    match var {
        Ok(v) if v.eq_ignore_ascii_case("legacy") => Binding::Legacy,
        Ok(v) if v.eq_ignore_ascii_case("semantic") => Binding::Semantic,
        Ok(v) if v.eq_ignore_ascii_case("bound") => Binding::Bound,
        Ok(v) if v.is_empty() => Binding::default(),
        Ok(v) => panic!("ZKSKETCH_BINDING={v:?}: expected legacy, semantic or bound"),
        Err(std::env::VarError::NotPresent) => Binding::default(),
        Err(std::env::VarError::NotUnicode(v)) => panic!(
            "ZKSKETCH_BINDING={v:?}: not valid UTF-8; expected legacy, semantic or bound"
        ),
    }
}

/// The warning [`warn_legacy_binding`] prints.
pub const LEGACY_BINDING_WARNING: &str = "\n!!! WARNING: ZKSKETCH_BINDING=legacy selects the \
PRE-FIX circuits, which are UNSOUND even on the merged soundness fork: the Count-Min leaves accept \
the Stage-G packing collision and the extension-valued op_old redirect (an update routed to any \
cell), the GK band-merge leaves take the fusion threshold theta as a free public input (a prover \
may over-merge past the epsilon-N rank guarantee), the Count-Min/HLL/SpaceSaving/GK query proofs \
expose no statement (their commitment, query and answer never reach the verifier), and the \
composition layout falls back to Boundary (the batch log is not checked). Use it ONLY for \
side-by-side cost runs; never report its numbers as sound. Unset ZKSKETCH_BINDING for the \
default (semantic). !!!\n";

/// Print [`LEGACY_BINDING_WARNING`] to stderr, once per process.
pub fn warn_legacy_binding() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| eprintln!("{LEGACY_BINDING_WARNING}"));
}

// ─── Coefficient binding ─────────────────────────────────────────────────

/// Assert `x == Σ coeffs[i]·e_i` through ALU rows. The caller must pin every
/// coefficient to the base field, otherwise one extension-valued coefficient
/// can absorb a change to the others.
pub(crate) fn bind_coeffs<BF, F>(b: &mut CircuitBuilder<F>, x: ExprId, coeffs: &[ExprId])
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let r = b
        .recompose_base_coeffs_to_ext_via_alu::<BF>(coeffs)
        .expect("ALU recompose");
    b.connect(r, x);
}

/// `decompose_ext_to_base_coeffs(x)` whose coefficients are actually bound to
/// `x`. `pin(b, i, c_i)` must pin coefficient `i` to the base field (and may
/// constrain it further, e.g. range, bits, canonical split). The helper then
/// asserts `x == Σ c_i·e_i` via [`bind_coeffs`].
pub(crate) fn decompose_bound<BF, F>(
    b: &mut CircuitBuilder<F>,
    x: ExprId,
    mut pin: impl FnMut(&mut CircuitBuilder<F>, usize, ExprId),
) -> Vec<ExprId>
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let cs = b
        .decompose_ext_to_base_coeffs::<BF>(x)
        .expect("decompose_ext_to_base_coeffs");
    for (i, &c) in cs.iter().enumerate() {
        pin(b, i, c);
    }
    bind_coeffs::<BF, F>(b, x, &cs);
    cs
}

/// Decomposition under a [`Binding`], with the pins split by purpose:
/// - `semantic(b, i, c_i)` adds constraints the relation needs whatever the
///   fork binds, e.g. a canonical position split or canonical bits. It runs
///   under `Bound` and `Semantic`.
/// - `base(b, i, c_i)` only pins `c_i` to the base field, for the ALU
///   recomposition's uniqueness. It runs under `Bound` only, after
///   `semantic`, and must be a no-op for coefficients `semantic` already
///   pins.
///
/// Under `Bound` the coefficients are then ALU-bound to `x`
/// ([`decompose_bound`]). `Semantic` relies on the fork to bind them, and
/// `Legacy` is the plain (unbound at the pinned rev) fork decomposition.
pub(crate) fn decompose<BF, F>(
    b: &mut CircuitBuilder<F>,
    x: ExprId,
    binding: Binding,
    mut semantic: impl FnMut(&mut CircuitBuilder<F>, usize, ExprId),
    mut base: impl FnMut(&mut CircuitBuilder<F>, usize, ExprId),
) -> Vec<ExprId>
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    match binding {
        Binding::Bound => decompose_bound::<BF, F>(b, x, |b, i, c| {
            semantic(b, i, c);
            base(b, i, c);
        }),
        Binding::Semantic => {
            let cs = b
                .decompose_ext_to_base_coeffs::<BF>(x)
                .expect("decompose_ext_to_base_coeffs");
            for (i, &c) in cs.iter().enumerate() {
                semantic(b, i, c);
            }
            cs
        }
        Binding::Legacy => b
            .decompose_ext_to_base_coeffs::<BF>(x)
            .expect("decompose_ext_to_base_coeffs"),
    }
}

/// No-op pin (for `decompose`'s `semantic` or `base` slot).
pub(crate) fn no_pin<F: Field>(_b: &mut CircuitBuilder<F>, _i: usize, _c: ExprId) {}

// ─── Base pins / range checks ────────────────────────────────────────────

/// Pin `x` to the base field and accept EVERY base element: a full-width
/// `add_range_bits`, i.e. `BF::bits()` bits, whose byte lookups force the
/// higher extension coefficients of every byte to zero. For `BF::bits() % 8
/// != 0` this is not an exact `< 2^bits` bound (see [`range_exact`]), which
/// is fine here: any canonical base value is `< p < 2^bits` and passes.
/// Cost: `⌈bits/8⌉` Range lookups plus about `2⌈bits/8⌉ + 1` ALU rows.
pub(crate) fn pin_base<BF, F>(b: &mut CircuitBuilder<F>, x: ExprId)
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    b.add_range_bits::<BF>(x, BF::bits()).expect("pin_base");
}

/// Pin a natively-`u32` quantity (a counter or value): an exact `x < 2^32`
/// (4 byte lookups, byte-aligned so exact) when the base field is wider than
/// 32 bits (Goldilocks), which also pins `x` to the base field and costs
/// half of [`pin_base`]'s 8 bytes there. On narrower fields (BabyBear: every
/// base value is `< p < 2^32` anyway) it is [`pin_base`].
pub(crate) fn pin_u32<BF, F>(b: &mut CircuitBuilder<F>, x: ExprId)
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    if BF::bits() > 32 {
        b.add_range_bits::<BF>(x, 32).expect("pin_u32");
    } else {
        pin_base::<BF, F>(b, x);
    }
}

/// [`pin_u32`] with the `decompose` pin-callback signature.
pub(crate) fn pin_all_u32<BF, F>(b: &mut CircuitBuilder<F>, _i: usize, c: ExprId)
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    pin_u32::<BF, F>(b, c);
}

/// [`pin_base`] with the `decompose` pin-callback signature.
pub(crate) fn pin_all_base<BF, F>(b: &mut CircuitBuilder<F>, _i: usize, c: ExprId)
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    pin_base::<BF, F>(b, c);
}

/// Exact `x ∈ [0, 2^n)` (which also pins `x` to the base field).
///
/// - `n ≤ 24`: two byte-aligned `add_range_bits` checks, `x ∈ [0, 2^{n8})`
///   and `x + (2^{n8} − 2^n) ∈ [0, 2^{n8})` with `n8 = 8⌈n/8⌉`. The sum cannot
///   wrap (`< 2^25 ≪ p`). The fork's `add_range_bits(x, n)` alone is NOT exact
///   for `n % 8 != 0`: its top-byte lookup `byte·2^{8−r}` admits `byte =
///   v·2^{−(8−r)}` for every byte `v`.
/// - `n > 24`: `decompose_to_bits(x, n)` (bool-checked bits, exact while
///   `2^n < p`).
pub(crate) fn range_exact<BF, F>(b: &mut CircuitBuilder<F>, x: ExprId, n: usize)
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    assert!(n >= 1, "range_exact: n must be ≥ 1");
    if n <= 24 {
        let n8 = n.div_ceil(8) * 8;
        b.add_range_bits::<BF>(x, n8).expect("range_exact aligned");
        if n8 != n {
            let off = b.alloc_const(F::from_u64((1u64 << n8) - (1u64 << n)), "range_exact_off");
            let y = b.add(x, off);
            b.add_range_bits::<BF>(y, n8).expect("range_exact shifted");
        }
    } else {
        assert!(
            (n as u32) < 64 && (1u128 << n) < BF::ORDER_U64 as u128,
            "range_exact: 2^{n} must be < p"
        );
        let _ = b.decompose_to_bits::<BF>(x, n).expect("range_exact bits");
    }
}

// ─── Canonical full-width bits ───────────────────────────────────────────

/// Low-bit count `m` of `p = 2^n − 2^m + 1` (BabyBear: 27, Goldilocks: 32).
pub(crate) fn canon_low_bits<BF: PrimeField64>() -> usize {
    let pm1 = BF::ORDER_U64 - 1;
    let m = pm1.trailing_zeros() as usize;
    let n = BF::bits();
    let expected = ((1u128 << (n - m)) - 1) << m;
    assert_eq!(
        pm1 as u128, expected,
        "canonical gadget requires p = 2^n − 2^m + 1"
    );
    m
}

/// Assert the LSB-first boolean `bits` (length `BF::bits()`) encode a
/// CANONICAL value `< p`. For `p = 2^n − 2^m + 1`, `V ≥ p` iff the top `n−m`
/// bits are all 1 AND the low `m` bits are nonzero. The gadget asserts the
/// negation: `(∏_{i≥m} bit_i) · (Σ_{i<m} bit_i·2^i) == 0`. `pow2_lo[i] =
/// 2^i` for `i < m`.
pub(crate) fn assert_canonical_bits<F: Field>(
    b: &mut CircuitBuilder<F>,
    bits: &[ExprId],
    pow2_lo: &[ExprId],
    one: ExprId,
    zero: ExprId,
) {
    let m = pow2_lo.len();
    let n = bits.len();
    let mut hi_and = one;
    for &bit in &bits[m..n] {
        hi_and = b.mul(hi_and, bit);
    }
    let mut lo = zero;
    for i in 0..m {
        lo = b.mul_add(bits[i], pow2_lo[i], lo);
    }
    let prod = b.mul(hi_and, lo);
    b.connect(prod, zero);
}

// ─── Canonical position split ────────────────────────────────────────────

/// `HI_MAX = (p−1) / 2^log_w`, the largest high part of a canonical limb.
pub(crate) fn hi_max<BF: PrimeField64>(log_w: usize) -> u64 {
    let pm1 = BF::ORDER_U64 - 1;
    assert!(
        pm1.trailing_zeros() as usize >= log_w,
        "p−1 must be divisible by 2^log_w (log_w = {log_w})"
    );
    pm1 >> log_w
}

/// Native canonical split of a canonical limb `x < p`: `(pos, hi, dinv)` with
/// `x = pos + 2^log_w·hi`, `pos < 2^log_w`, and `dinv = (HI_MAX − hi)^{-1}`
/// (0 when `hi = HI_MAX`). These are the private witnesses
/// [`canonical_split_gadget`] consumes.
pub(crate) fn canonical_split<BF: PrimeField64>(x: u64, log_w: usize) -> (u64, u64, BF) {
    debug_assert!(x < BF::ORDER_U64);
    let pos = x & ((1u64 << log_w) - 1);
    let hi = x >> log_w;
    let d = hi_max::<BF>(log_w) - hi;
    let dinv = BF::from_u64(d).try_inverse().unwrap_or(BF::ZERO);
    (pos, hi, dinv)
}

/// [`canonical_split`] as three field values (push order of the gadget).
pub(crate) fn canonical_split_vals<BF: PrimeField64>(limb: BF, log_w: usize) -> [BF; 3] {
    let (pos, hi, dinv) = canonical_split::<BF>(limb.as_canonical_u64(), log_w);
    [BF::from_u64(pos), BF::from_u64(hi), dinv]
}

/// Constants shared by every [`canonical_split_gadget`] of one `log_w`.
#[derive(Copy, Clone, Debug)]
pub(crate) struct SplitConsts {
    pub(crate) log_w: usize,
    /// Exact bit width used for `hi` and `HI_MAX − hi`.
    pub(crate) hi_bits: usize,
    pub(crate) one: ExprId,
    pub(crate) zero: ExprId,
    pub(crate) pow_log_w: ExprId,
    pub(crate) hi_max: ExprId,
}

impl SplitConsts {
    pub(crate) fn new<BF, F>(
        b: &mut CircuitBuilder<F>,
        log_w: usize,
        one: ExprId,
        zero: ExprId,
    ) -> Self
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        assert!((1..=24).contains(&log_w), "split: log_w must be in 1..=24");
        let hm = hi_max::<BF>(log_w);
        let hi_bits = (64 - hm.leading_zeros()) as usize;
        // `hi < 2^k` and `HI_MAX − hi (mod p) < 2^k` imply `hi ≤ HI_MAX` iff a
        // wrapped difference `p − (hi − HI_MAX) > p − 2^k + HI_MAX` cannot be
        // `< 2^k`, i.e. `p + HI_MAX ≥ 2^{k+1}`. Both ranges must be exact:
        // `2^k < p`.
        let p = BF::ORDER_U64 as u128;
        assert!(
            p + hm as u128 >= 1u128 << (hi_bits + 1) && (1u128 << hi_bits) < p,
            "split: unsupported (p, log_w) = ({p}, {log_w})"
        );
        Self {
            log_w,
            hi_bits,
            one,
            zero,
            pow_log_w: b.alloc_const(F::from_u64(1u64 << log_w), "split 2^log_w"),
            hi_max: b.alloc_const(F::from_u64(hm), "split hi_max"),
        }
    }
}

/// Canonical split of a digest limb. Given private witnesses `(pos, hi,
/// dinv)`, returns `x = pos + 2^log_w·hi` (an ALU output; `connect` it to the
/// limb) after constraining:
/// - `pos ∈ [0, 2^log_w)` and `hi ∈ [0, 2^hi_bits)`, both exact;
/// - `d = HI_MAX − hi ∈ [0, 2^hi_bits)`, so `hi ≤ HI_MAX`;
/// - `d = 0 ⇒ pos = 0`: `pos·(1 − d·dinv) = 0`.
///
/// So the split integer is `≤ p − 1`, the unique canonical one, and `pos` is
/// exactly `limb mod 2^log_w`. Also pins `x` (hence the limb) to the base
/// field.
pub(crate) fn canonical_split_gadget<BF, F>(
    b: &mut CircuitBuilder<F>,
    pos: ExprId,
    hi: ExprId,
    dinv: ExprId,
    c: &SplitConsts,
) -> ExprId
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    range_exact::<BF, F>(b, pos, c.log_w);
    range_exact::<BF, F>(b, hi, c.hi_bits);
    let d = b.sub(c.hi_max, hi);
    range_exact::<BF, F>(b, d, c.hi_bits);
    let e = b.mul(d, dinv);
    let z = b.sub(c.one, e);
    let chk = b.mul(pos, z);
    b.connect(chk, c.zero);
    b.mul_add(hi, c.pow_log_w, pos)
}

// ─── Exact 64-bit key limbs ──────────────────────────────────────────────

/// Bits per key limb on base field `BF`: 16 on BabyBear and 32 on Goldilocks.
/// Either way the `64 / L` limbs of a 64-bit key fill exactly one element of
/// the leaves' challenge extension (4 × 16 bits for D = 4, 2 × 32 bits for
/// D = 2). Every limb is `< 2^L < p`, so the limb vector is an injective
/// encoding of the key. `BF::from_u64(key)` is not injective: it reduces the
/// key mod `p`, and keys congruent mod `p` then hash, route and commit
/// identically. On BabyBear that already happens among 32-bit keys (`k` and
/// `k + p` for every `k < 2^32 − p`).
pub fn key_limb_bits<BF: PrimeField64>() -> usize {
    if BF::bits() > 32 { 32 } else { 16 }
}

/// The exact limbs of `key`, little-endian: `key = Σ_i limb_i · 2^{L·i}` with
/// `L = key_limb_bits::<BF>()`.
pub fn key_limbs<BF: PrimeField64>(key: u64) -> Vec<BF> {
    let l = key_limb_bits::<BF>();
    let mask = (1u64 << l) - 1;
    (0..64 / l).map(|i| BF::from_u64((key >> (l * i)) & mask)).collect()
}

/// The routing-hash input of `key` under `binding`: the `64 / L` base
/// coefficients of ONE extension element. `Legacy` keeps the pre-fix
/// `[key mod p, 0, …]`; `Semantic`/`Bound` use the exact limbs
/// ([`key_limbs`]).
pub fn key_hash_input<BF: PrimeField64>(key: u64, binding: Binding) -> Vec<BF> {
    if binding.is_bound() {
        key_limbs::<BF>(key)
    } else {
        let mut v = vec![BF::ZERO; 64 / key_limb_bits::<BF>()];
        v[0] = BF::from_u64(key);
        v
    }
}

/// In-circuit key from exact limbs: range-checks every limb to exactly
/// `L = key_limb_bits::<BF>()` bits (a byte-aligned `add_range_bits`, hence
/// exact, which also pins the limb to the base field) and recomposes the
/// limbs into ONE extension element through the ALU. The returned element is
/// the record's key both as the batch commitment absorbs it and as the single
/// input of its routing hash (one Poseidon2 absorb, as in `bloom_omc`).
pub(crate) fn key_from_limbs<BF, F>(b: &mut CircuitBuilder<F>, limbs: &[ExprId]) -> ExprId
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let l = key_limb_bits::<BF>();
    assert_eq!(limbs.len(), 64 / l, "key_from_limbs: expected {} limbs", 64 / l);
    assert_eq!(
        limbs.len(),
        <F as BasedVectorSpace<BF>>::DIMENSION,
        "key limbs must fill one extension element"
    );
    for &x in limbs {
        b.add_range_bits::<BF>(x, l).expect("key limb range");
    }
    b.recompose_base_coeffs_to_ext_via_alu::<BF>(limbs)
        .expect("recompose key limbs")
}

/// Constrain an existing key element (e.g. a decoder's public query key) to
/// the exact-limb encoding: decompose it under `binding`, with an exact
/// `L`-bit range check on every coefficient (a semantic pin, so it runs under
/// `Semantic` and `Bound`; `Bound` also ALU-binds the coefficients to `key`).
pub(crate) fn assert_key_limbs<BF, F>(b: &mut CircuitBuilder<F>, key: ExprId, binding: Binding)
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let l = key_limb_bits::<BF>();
    let _ = decompose::<BF, F>(
        b,
        key,
        binding,
        |b, _i, c| {
            b.add_range_bits::<BF>(c, l).expect("key limb range");
        },
        no_pin,
    );
}

/// Test-only probes: does the fork in use bind decompose coefficients / the
/// first-row sponge IV by itself? The pinned rev does neither, so `Legacy`
/// accepts the forgeries. A patched fork (coefficient binding, zero IV on
/// `new_start`) flips them, and the forgery tests assert `Legacy` acceptance
/// only when the corresponding probe says the fork does NOT bind.
#[cfg(test)]
pub(crate) mod probe {
    use super::*;
    use crate::config::{Challenge, LOG_BLOWUP, MyHash, Val, make_perm};
    use crate::recursion::recursive::config::ConfigWithFriParams;
    use crate::recursion::recursive::countmin_leaf::make_leaf_config;
    use crate::sketch::forge;
    use p3_baby_bear::default_babybear_poseidon2_16;
    use p3_batch_stark::ProverData;
    use p3_circuit::ops::{
        NpoTypeId, Poseidon2Trace, generate_expose_trace, generate_poseidon2_trace,
        generate_range_trace, generate_recompose_trace,
    };
    use p3_circuit_prover::batch_stark_prover::{
        expose_air_builders, expose_preprocessor, poseidon2_air_builders_d4,
        poseidon2_preprocessor, range_air_builders, range_preprocessor, recompose_air_builders,
        recompose_preprocessor,
    };
    use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
    use p3_circuit_prover::{BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking};
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_poseidon2_circuit_air::BabyBearD4Width16;
    use p3_symmetric::CryptographicHasher;
    use p3_uni_stark::StarkGenericConfig;
    use std::sync::OnceLock;

    /// Prove + verify traces of a small circuit using Poseidon2 (D = 4),
    /// Recompose, Range and Expose (`coeff_ctl` additionally registers the
    /// `recompose/coeff` table). Returns the first non-empty exposed values.
    pub(crate) fn prove_small(
        circuit: &p3_circuit::Circuit<Challenge>,
        traces: &p3_circuit::tables::Traces<Challenge>,
        coeff_ctl: bool,
    ) -> Option<Vec<Val>> {
        forge::catch(|| {
            let config = make_leaf_config();
            let table_packing = TablePacking::new(1, 2).with_fri_params(6, LOG_BLOWUP);
            let preprocessors = vec![
                poseidon2_preprocessor::<Val>(),
                recompose_preprocessor::<Val>(coeff_ctl),
                range_preprocessor::<Val>(),
                expose_preprocessor::<Val>(),
            ];
            let mut air_builders = poseidon2_air_builders_d4::<ConfigWithFriParams>();
            air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, false));
            if coeff_ctl {
                air_builders.extend(recompose_air_builders::<ConfigWithFriParams, 4>(1, true));
            }
            air_builders.extend(range_air_builders::<ConfigWithFriParams, 4>(1));
            air_builders.extend(expose_air_builders::<ConfigWithFriParams, 4>());
            let (airs_degrees, pc, npc) =
                get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
                    circuit,
                    &table_packing,
                    &preprocessors,
                    &air_builders,
                    ConstraintProfile::Standard,
                )
                .ok()?;
            let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
            let ext: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
            let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext);
            let cpd = CircuitProverData::new(pd, pc, npc);
            let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
            prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
            prover.register_recompose_table::<4>(false);
            if coeff_ctl {
                prover.register_recompose_table::<4>(true);
            }
            prover.register_range_table::<4>();
            prover.register_expose_table::<4>();
            let proof = prover.prove_all_tables(traces, &cpd).ok()?;
            prover.verify_all_tables(&proof).ok()?;
            proof
                .non_primitives
                .iter()
                .map(|e| e.public_values.clone())
                .find(|v| !v.is_empty())
        })
        .flatten()
    }

    pub(crate) const XS: [u64; 4] = [0x0123_4567, 0x0765_4321, 3, 4];

    /// Exposed `x` (a Challenge) and `y`, with the in-circuit claim `y =
    /// coeff0(x) mod 2^log_w` (a routing position), coefficients from
    /// [`decompose`] under `binding`. `Bound`/`Semantic` take `y` from the
    /// canonical split of coefficient 0 (plus canonical bits on coefficient
    /// 1, base pins on 2..3 under `Bound`); `Legacy` takes it from the bits of
    /// the coefficient.
    ///
    /// Honest: `x = XS`. Forged (transplant): run honestly on `x' = XS + e_0`
    /// (so `y' = pos + 1`), then put the original `x` back with
    /// [`forge::set_wid`]. The honest run goes through the SAME `set_wid`
    /// (writing `x` over itself), so it is the forger's positive control.
    /// Returns the exposed `(x0, y)` if the proof verifies.
    pub(crate) fn position_circuit(log_w: usize, binding: Binding, forged: bool) -> Option<(Val, Val)> {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_range(generate_range_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        let ypub = b.alloc_public_input("y");
        b.add_expose(&[xpub, ypub]).unwrap();
        b.tag(xpub, "x").unwrap();
        let one = b.alloc_const(Challenge::ONE, "one");
        let zero = b.alloc_const(Challenge::ZERO, "zero");
        let sc = SplitConsts::new::<Val, Challenge>(&mut b, log_w, one, zero);
        let canon_pow2: Vec<ExprId> = (0..canon_low_bits::<Val>())
            .map(|i| b.alloc_const(Challenge::from_u64(1 << i), "2^i"))
            .collect();
        let split: [ExprId; 3] = std::array::from_fn(|_| b.alloc_private_input("split"));
        let cs = decompose::<Val, Challenge>(
            &mut b,
            xpub,
            binding,
            |b, i, c| match i {
                0 => {
                    let x = canonical_split_gadget::<Val, Challenge>(b, split[0], split[1], split[2], &sc);
                    b.connect(x, c);
                }
                1 => {
                    let bits = b.decompose_to_bits::<Val>(c, Val::bits()).unwrap();
                    assert_canonical_bits(b, &bits, &canon_pow2, one, zero);
                }
                _ => {}
            },
            |b, i, c| {
                if i >= 2 {
                    pin_base::<Val, Challenge>(b, c);
                }
            },
        );
        let pos = if binding.is_bound() {
            split[0]
        } else {
            for &s in &split {
                let _ = b.mul(s, s);
            }
            let bits = b.decompose_to_bits::<Val>(cs[0], Val::bits()).unwrap();
            let mut p = zero;
            for (j, &bit) in bits.iter().take(log_w).enumerate() {
                let c = b.alloc_const(Challenge::from_u64(1 << j), "2^j");
                p = b.mul_add(bit, c, p);
            }
            p
        };
        b.connect(pos, ypub);
        let circuit = b.build().unwrap();

        let honest: [Val; 4] = XS.map(Val::from_u64);
        let mut run_x = honest;
        if forged {
            run_x[0] += Val::ONE;
        }
        let x_of = |v: &[Val; 4]| Challenge::from_basis_coefficients_slice(v).unwrap();
        let y = Challenge::from_u64(run_x[0].as_canonical_u64() & ((1 << log_w) - 1));
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[x_of(&run_x), y]).unwrap();
        let sv = canonical_split_vals::<Val>(run_x[0], log_w);
        runner
            .set_private_inputs(&sv.iter().map(|&v| Challenge::from(v)).collect::<Vec<_>>())
            .unwrap();
        let mut traces = runner.run().expect("honest run");
        // Forged: restore the original `x`. Honest: the same write, a no-op
        // (positive control of the transplant plumbing).
        let xw = traces.tag_to_witness["x"];
        forge::set_wid::<Val, Challenge>(&mut traces, xw, x_of(&honest));
        prove_small(&circuit, &traces, false).map(|pv| (pv[0], pv[4]))
    }

    /// Hash one exposed Challenge `x` with [`hash_slice`] under `binding` and
    /// expose the digest. If `forged`, bump a capacity input of the (single)
    /// Poseidon2 row and rehash; the honest run makes the same row edit with a
    /// zero bump and the same rehash (the forger's positive control). Returns
    /// the exposed digest if the proof verifies.
    pub(crate) fn iv_circuit(binding: Binding, forged: bool) -> Option<[Val; 8]> {
        let cfg = Poseidon2Config::BABY_BEAR_D4_W16;
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_range(generate_range_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        let zero = b.alloc_const(Challenge::ZERO, "zero");
        let h = hash_slice(&mut b, &cfg, &[xpub], zero, binding);
        b.add_expose(&[xpub, h[0], h[1]]).unwrap();
        let circuit = b.build().unwrap();
        let xs = [1u64, 2, 3, 4].map(Val::from_u64);
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[Challenge::from_basis_coefficients_slice(&xs).unwrap()])
            .unwrap();
        let mut traces = runner.run().expect("honest run");
        let key = NpoTypeId::poseidon2_perm(cfg);
        let mut pt = traces
            .non_primitive_trace::<Poseidon2Trace<Val>>(&key)
            .expect("poseidon2 trace")
            .clone();
        if forged {
            pt.operations[0].input_values[8] += Val::ONE;
        }
        traces.non_primitive_traces.insert(key, Box::new(pt));
        forge::rehash_all::<Val, Challenge, _, 16>(&mut traces, cfg, &make_perm());
        prove_small(&circuit, &traces, false).map(|pv| std::array::from_fn(|i| pv[4 + i]))
    }

    /// `true` iff the fork itself binds `decompose_ext_to_base_coeffs`
    /// coefficients (the forged `Legacy` decomposition is rejected). The
    /// honest run through the same forger is a positive control: it must
    /// verify, else the probe panics rather than report a vacuous `true`
    /// (which would turn every gated "must reject too" assertion vacuous).
    pub(crate) fn fork_binds_decompose() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| {
            assert!(
                position_circuit(14, Binding::Legacy, false).is_some(),
                "fork_binds_decompose: the honest run through the same forger must verify"
            );
            position_circuit(14, Binding::Legacy, true).is_none()
        })
    }

    /// `true` iff the fork itself binds the first-row sponge IV (the forged
    /// plain `add_hash_slice` capacity is rejected). Positive control as in
    /// [`fork_binds_decompose`]: the zero-bump run must verify and expose
    /// `MyHash(x)`.
    pub(crate) fn fork_binds_iv() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| {
            assert_eq!(
                iv_circuit(Binding::Legacy, false),
                Some(native_iv_digest()),
                "fork_binds_iv: the honest run through the same forger must verify"
            );
            iv_circuit(Binding::Legacy, true).is_none()
        })
    }

    /// Exposed `x` and `y = bit 0` of `decompose_to_bits(x, Val::bits())`, for
    /// `x = 5`. If `forged`, the bit hint writes the bits of `x + p` instead:
    /// booleans that still reconstruct `x` mod p, but a non-canonical integer
    /// (BabyBear: `x + p < 2^31`), so `y` flips to 0. Returns the exposed
    /// `(x, y)` if the run succeeds and the proof verifies.
    pub(crate) fn bits_circuit(forged: bool) -> Option<(Val, Val)> {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_range(generate_range_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        let ypub = b.alloc_public_input("y");
        b.add_expose(&[xpub, ypub]).unwrap();
        let bits = b.decompose_to_bits::<Val>(xpub, Val::bits()).unwrap();
        b.connect(bits[0], ypub);
        let mut circuit = b.build().unwrap();
        let x = 5u64;
        let v = if forged { x + Val::ORDER_U64 } else { x };
        assert!(v < 1u64 << Val::bits());
        let xw = crate::sketch::forge_permute::wid_of(&circuit, xpub);
        crate::sketch::forge_permute::forge_hint(
            &mut circuit,
            xw,
            (0..Val::bits())
                .map(|j| Challenge::from_u64((v >> j) & 1))
                .collect(),
        );
        let traces = forge::catch(|| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&[Challenge::from_u64(x), Challenge::from_u64(v & 1)])
                .unwrap();
            runner.run().ok()
        })
        .flatten()?;
        prove_small(&circuit, &traces, false).map(|pv| (pv[0], pv[4]))
    }

    /// `true` iff the fork's full-width `decompose_to_bits` only admits the
    /// CANONICAL bits (the forged `x + p` bits of [`bits_circuit`] are
    /// rejected). The pinned rev accepts them, which is what lets the
    /// `Legacy` Count-Min leaf route a record to bucket `(h + 1) mod w`. The
    /// honest run is a positive control of the same hint-forging path: it
    /// must verify, else the probe panics rather than report.
    pub(crate) fn fork_canonical_bits() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| {
            assert_eq!(
                bits_circuit(false),
                Some((Val::from_u64(5), Val::ONE)),
                "fork_canonical_bits: the honest (identically forged) run must verify"
            );
            bits_circuit(true).is_none()
        })
    }

    /// Native `MyHash` of the probe input (for the digest checks).
    pub(crate) fn native_iv_digest() -> [Val; 8] {
        MyHash::new(make_perm()).hash_iter([1u64, 2, 3, 4].map(Val::from_u64))
    }

    /// Preprocessed commitment (VK, `vk_pin_values` order) of `y = x + k`
    /// with `(x, y)` exposed. Structural: no trace, no proof.
    fn const_circuit_vk(k: u64) -> Vec<Challenge> {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        let xpub = b.alloc_public_input("x");
        let kc = b.alloc_const(Challenge::from_u64(k), "K");
        let y = b.add(xpub, kc);
        b.add_expose(&[xpub, y]).unwrap();
        let circuit = b.build().unwrap();
        let config = make_leaf_config();
        let table_packing = TablePacking::new(1, 2).with_fri_params(6, LOG_BLOWUP);
        let preprocessors = vec![expose_preprocessor::<Val>()];
        let air_builders = expose_air_builders::<ConfigWithFriParams, 4>();
        let (airs_degrees, _, _) = get_airs_and_degrees_with_prep::<ConfigWithFriParams, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("const probe AIRs");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let ext: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let pd = ProverData::from_airs_and_degrees(&config, &airs, &ext);
        crate::recursion::recursive::expose_forest::common_vk_pin_values(&pd.common)
    }

    /// `true` iff the fork binds constant VALUES (ConstAir commits each value in
    /// its preprocessed trace, so two circuits that differ only in one constant
    /// have different VKs). Structural probe, independent of the trace-forging
    /// PoCs it gates (e.g. the Bloom leaf's `poc_const_values_are_prover_chosen`).
    pub(crate) fn fork_binds_const() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| const_circuit_vk(5) != const_circuit_vk(7))
    }

    /// `true` iff the fork's `add_range_bits` range-checks a non-byte-aligned
    /// top byte UNSHIFTED as well as shifted (two Range lookups for `n = 4`,
    /// one at the pinned rev). Structural probe (counts the Range ops of the
    /// built circuit), independent of the forged-trace PoCs it gates.
    pub(crate) fn fork_binds_range_top_byte() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(|| {
            let mut b = CircuitBuilder::<Challenge>::new();
            b.enable_range(generate_range_trace::<Val, Challenge>);
            let x = b.alloc_public_input("x");
            b.add_range_bits::<Val>(x, 4).unwrap();
            let circuit = b.build().unwrap();
            let lookups = circuit
                .ops
                .iter()
                .filter(|op| {
                    matches!(op, p3_circuit::Op::NonPrimitiveOpWithExecutor { executor, .. }
                        if *executor.op_type() == NpoTypeId::range())
                })
                .count();
            assert!(
                (1..=2).contains(&lookups),
                "add_range_bits(x, 4): unexpected Range op count {lookups}"
            );
            lookups == 2
        })
    }
}

#[cfg(test)]
mod tests {
    use super::probe::*;
    use super::*;
    use crate::config::{Challenge, Val};
    use crate::sketch::forge;
    use p3_circuit::ops::{generate_expose_trace, generate_range_trace, generate_recompose_trace};
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

    #[test]
    fn canonical_split_native_rule() {
        let p = <Val as PrimeField64>::ORDER_U64;
        for log_w in [1usize, 2, 3, 7, 14, 20, 24] {
            let hm = hi_max::<Val>(log_w);
            for x in [0u64, 1, 5, (1 << log_w) - 1, 1 << log_w, p - 2, p - 1, 0x1234_5678 % p] {
                let (pos, hi, _) = canonical_split::<Val>(x, log_w);
                assert_eq!(pos + (hi << log_w), x);
                assert!(hi <= hm && (hi < hm || pos == 0));
            }
        }
    }

    #[test]
    fn position_circuit_honest_all_bindings() {
        for log_w in [3usize, 14] {
            for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
                let (x0, y) = position_circuit(log_w, binding, false)
                    .unwrap_or_else(|| panic!("honest run must verify ({binding:?}, log_w={log_w})"));
                assert_eq!(y.as_canonical_u64(), x0.as_canonical_u64() & ((1 << log_w) - 1));
            }
        }
    }

    /// Forged decomposition (transplant): the proof claims `x = XS` but routes
    /// by `XS + e_0`. At the pinned fork `Legacy` and `Semantic` ACCEPT it,
    /// with the exposed position off by one, because the NPO decompose leaves
    /// the coefficient free. `Bound` REJECTS it: the ALU recomposition row no
    /// longer sums to `x`.
    #[test]
    fn forged_decomposition_legacy_accepts_bound_rejects() {
        // Positive controls: the same forger with the honest value verifies.
        for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
            let (x0, y) = position_circuit(14, binding, false)
                .unwrap_or_else(|| panic!("control ({binding:?}): the honest run must verify"));
            assert_eq!(x0.as_canonical_u64(), XS[0]);
            assert_eq!(y.as_canonical_u64(), XS[0] & ((1 << 14) - 1));
        }
        if !fork_binds_decompose() {
            let (x0, y) = position_circuit(14, Binding::Legacy, true)
                .expect("Legacy must accept the forged decomposition (the PoC)");
            assert_eq!(x0.as_canonical_u64(), XS[0], "exposes the ORIGINAL x");
            assert_eq!(
                y.as_canonical_u64(),
                (XS[0] & ((1 << 14) - 1)) + 1,
                "…but a position shifted by one"
            );
            assert!(
                position_circuit(14, Binding::Semantic, true).is_some(),
                "Semantic relies on the fork for coefficient binding"
            );
        } else {
            assert!(position_circuit(14, Binding::Semantic, true).is_none());
        }
        assert!(
            position_circuit(14, Binding::Bound, true).is_none(),
            "Bound must reject the forged decomposition"
        );
    }

    /// Free sponge IV: plain `add_hash_slice` at the pinned fork accepts a
    /// "digest" of `x` that is not `MyHash(x)`; `hash_slice_bound` rejects it.
    #[test]
    fn forged_iv_legacy_accepts_bound_rejects() {
        let native = native_iv_digest();
        // Also the positive controls: the zero-bump edit + rehash verifies.
        for binding in [Binding::Bound, Binding::Semantic, Binding::Legacy] {
            assert_eq!(iv_circuit(binding, false), Some(native), "honest digest = MyHash ({binding:?})");
        }
        if !fork_binds_iv() {
            let forged = iv_circuit(Binding::Legacy, true).expect("Legacy accepts a free IV (PoC)");
            assert_ne!(forged, native);
        }
        assert!(iv_circuit(Binding::Bound, true).is_none(), "Bound must reject the IV forgery");
    }

    /// Canonical split: the non-canonical witness `x + p` (BabyBear: every
    /// limb `< 2^31 − p`) would shift the position by one. The split rejects
    /// it at run time (range of `HI_MAX − hi`), so an honest-runner trace
    /// cannot even be produced, and a hand-built one fails the Range bus.
    #[test]
    fn noncanonical_split_rejected() {
        let log_w = 14;
        let p = <Val as PrimeField64>::ORDER_U64;
        let x = 5u64; // x + p < 2^31
        let xp = x + p;
        let (pos, hi) = (xp & ((1 << log_w) - 1), xp >> log_w);
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_range(generate_range_trace::<Val, Challenge>);
        let one = b.alloc_const(Challenge::ONE, "one");
        let zero = b.alloc_const(Challenge::ZERO, "zero");
        let sc = SplitConsts::new::<Val, Challenge>(&mut b, log_w, one, zero);
        let w: [ExprId; 3] = std::array::from_fn(|_| b.alloc_private_input("split"));
        let target = b.alloc_const(Challenge::from_u64(x), "x");
        let out = canonical_split_gadget::<Val, Challenge>(&mut b, w[0], w[1], w[2], &sc);
        b.connect(out, target);
        let circuit = b.build().unwrap();
        let run = |vals: [u64; 3]| {
            let mut r = circuit.runner();
            r.set_public_inputs(&[]).unwrap();
            r.set_private_inputs(&vals.map(Challenge::from_u64)).unwrap();
            forge::catch(|| r.run().is_ok()).unwrap_or(false)
        };
        let (hp, hh, hd) = canonical_split::<Val>(x, log_w);
        assert!(run([hp, hh, hd.as_canonical_u64()]), "honest split runs");
        assert!(!run([pos, hi, 0]), "x + p split must be rejected");
    }

    /// The candidate fork switch `set_recompose_coeff_ctl_for_decompose_links`
    /// (+ the `recompose/coeff` table): `y = 2·coeff0(x)` with coeff0 read by
    /// `uses` ALU ops. Returns whether the (honest or transplant-forged,
    /// `x' = XS + e_0`) proof verifies.
    fn coeff_ctl_circuit(uses: usize, forged: bool) -> bool {
        let mut b = CircuitBuilder::<Challenge>::new();
        b.enable_recompose::<Val>(generate_recompose_trace::<Val, Challenge>);
        b.enable_range(generate_range_trace::<Val, Challenge>);
        b.enable_expose(generate_expose_trace::<Val, Challenge>);
        b.set_recompose_coeff_ctl_for_decompose_links(true);
        let xpub = b.alloc_public_input("x");
        let ypub = b.alloc_public_input("y");
        b.add_expose(&[xpub, ypub]).unwrap();
        b.tag(xpub, "x").unwrap();
        let two = b.alloc_const(Challenge::from_u64(2), "two");
        let cs = b.decompose_ext_to_base_coeffs::<Val>(xpub).unwrap();
        let t = b.mul(cs[0], two);
        b.connect(t, ypub);
        for _ in 1..uses {
            let _ = b.mul(cs[0], cs[0]);
        }
        let circuit = b.build().unwrap();
        let honest: [Val; 4] = XS.map(Val::from_u64);
        let mut run_x = honest;
        if forged {
            run_x[0] += Val::ONE;
        }
        let x_of = |v: &[Val; 4]| Challenge::from_basis_coefficients_slice(v).unwrap();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[x_of(&run_x), Challenge::from(run_x[0] * Val::from_u64(2))])
            .unwrap();
        let mut traces = runner.run().expect("honest run");
        if forged {
            let xw = traces.tag_to_witness["x"];
            forge::set_wid::<Val, Challenge>(&mut traces, xw, x_of(&honest));
        }
        prove_small(&circuit, &traces, true).is_some()
    }

    /// The pinned fork's candidate is NOT a fix. The `recompose/coeff` row and
    /// the coefficient's first ALU use are BOTH WitnessChecks creators
    /// (multiplicity `ext_reads`). With one ALU use, `ext_reads = 0`, so
    /// nothing checks the coefficient and the transplant forgery verifies.
    /// With two uses, the double creation unbalances the bus and even the
    /// HONEST proof fails. (Skipped on a fork that binds coefficients itself.)
    #[test]
    fn coeff_ctl_candidate_is_not_a_fix() {
        if fork_binds_decompose() {
            return;
        }
        assert!(coeff_ctl_circuit(1, false), "one use: honest verifies");
        assert!(
            coeff_ctl_circuit(1, true),
            "one use: the forged coefficient is still accepted (unbound)"
        );
        assert!(
            !coeff_ctl_circuit(2, false),
            "two uses: double creator rejects even the honest proof"
        );
    }

    /// Reports which fork gaps the linked fork closes (the probes every
    /// fork-dependent PoC is gated on), and that the default binding is
    /// `Semantic` unless `ZKSKETCH_BINDING` overrides it. On the merged
    /// soundness fork all five probes are `true`.
    #[test]
    fn fork_probe_report() {
        let (dec, iv, cst, rng, bits) = (
            fork_binds_decompose(),
            fork_binds_iv(),
            fork_binds_const(),
            fork_binds_range_top_byte(),
            fork_canonical_bits(),
        );
        eprintln!(
            "fork probes: binds_decompose={dec} binds_iv={iv} binds_const={cst} \
             binds_range_top_byte={rng} canonical_bits={bits}"
        );
        assert_eq!(Binding::default(), Binding::Semantic);
        if std::env::var("ZKSKETCH_BINDING").map_or(true, |v| v.is_empty()) {
            assert_eq!(default_binding(), Binding::Semantic);
        }
    }

    /// `ZKSKETCH_BINDING` parsing, without touching the process environment
    /// (other tests read it concurrently): unset/empty = `Semantic`, the three
    /// names in any case, and a panic for every other value — including a
    /// non-UTF-8 one, which used to fall through to the default silently.
    #[test]
    fn binding_env_parsing() {
        use std::env::VarError;
        assert_eq!(parse_binding_env(Err(VarError::NotPresent)), Binding::Semantic);
        assert_eq!(parse_binding_env(Ok(String::new())), Binding::Semantic);
        for (v, want) in [
            ("legacy", Binding::Legacy),
            ("LEGACY", Binding::Legacy),
            ("Semantic", Binding::Semantic),
            ("bound", Binding::Bound),
        ] {
            assert_eq!(parse_binding_env(Ok(v.into())), want, "{v}");
        }
        for bad in ["sound", "legacy ", "1"] {
            let msg = forge::catch_msg(|| parse_binding_env(Ok(bad.into()))).unwrap_err();
            assert!(msg.contains("expected legacy, semantic or bound"), "{bad:?}: {msg}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = std::ffi::OsString::from_vec(b"leg\x80acy".to_vec());
            let msg = forge::catch_msg(|| parse_binding_env(Err(VarError::NotUnicode(bad))))
                .unwrap_err();
            assert!(msg.contains("not valid UTF-8"), "{msg}");
        }
    }

    /// Child half of [`legacy_env_warns_once_and_bad_env_panics`]: a no-op
    /// unless the parent re-runs this test binary with
    /// `ZKSKETCH_BINDING_CHILD` set.
    #[test]
    fn binding_env_child() {
        if std::env::var_os("ZKSKETCH_BINDING_CHILD").is_none() {
            return;
        }
        let a = default_binding();
        let b = default_binding();
        println!("CHILD_BINDING={a:?},{b:?}");
    }

    /// Runtime behaviour of `ZKSKETCH_BINDING`, in a child process (this test
    /// binary re-run on [`binding_env_child`]) so the environment of the
    /// parallel test run is untouched: `legacy` selects `Legacy` and prints
    /// the loud warning exactly once per process however often it is read;
    /// `semantic` prints nothing; a non-UTF-8 value panics.
    #[test]
    fn legacy_env_warns_once_and_bad_env_panics() {
        let exe = std::env::current_exe().expect("test binary path");
        let run = |val: &std::ffi::OsStr| {
            let out = std::process::Command::new(&exe)
                .args(["--exact", "sketch::bind::tests::binding_env_child", "--nocapture"])
                .args(["--test-threads", "1"])
                .env("ZKSKETCH_BINDING_CHILD", "1")
                .env("ZKSKETCH_BINDING", val)
                .output()
                .expect("spawn child test");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), text)
        };
        let marker = "ZKSKETCH_BINDING=legacy selects the PRE-FIX circuits";
        assert!(LEGACY_BINDING_WARNING.replace('\n', " ").contains(marker));

        let (ok, text) = run("legacy".as_ref());
        assert!(ok, "legacy child failed:\n{text}");
        assert!(text.contains("CHILD_BINDING=Legacy,Legacy"), "{text}");
        assert_eq!(text.matches("PRE-FIX circuits, which are UNSOUND").count(), 1, "{text}");

        let (ok, text) = run("semantic".as_ref());
        assert!(ok, "semantic child failed:\n{text}");
        assert!(text.contains("CHILD_BINDING=Semantic,Semantic"), "{text}");
        assert!(!text.contains("UNSOUND"), "{text}");

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = std::ffi::OsString::from_vec(b"leg\x80acy".to_vec());
            let (ok, text) = run(&bad);
            assert!(!ok, "a non-UTF-8 ZKSKETCH_BINDING must panic:\n{text}");
            assert!(text.contains("not valid UTF-8"), "{text}");
        }
    }
}
