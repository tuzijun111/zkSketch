//! **Interval statement** of the composition layer (revision B6(b)): what a
//! composable leaf or merge proof surfaces through its Expose table, the
//! in-circuit leaf gadget that produces it, and the native (auditor-side)
//! recomputation of the root statement from the public batch log.
//!
//! ## Layouts
//!
//! A composable proof exposes one of two layouts (both field-generic; `C` =
//! commitment length in base elements, `D` = extension degree):
//!
//! | layout     | exposed base values                                     | BabyBear | Goldilocks |
//! |------------|---------------------------------------------------------|----------|------------|
//! | `Boundary` | `init[C] ‖ final[C]`                                    | 16       | 8          |
//! | `Interval` | `init[C] ‖ final[C] ‖ idx[D] ‖ H[C]`, `idx = (lo, hi, 0…)` | 28       | 14         |
//!
//! `Boundary` is the pre-B6(b) statement (only `(Com(S_{i-1}), Com(S_j))`;
//! the root then certifies only that SOME batch sequence maps `S_0` to
//! `S_T`). It stays available, byte for byte, for side-by-side runs.
//! `Interval` is the paper's interval-proof boundary
//! `pub_[i,j] = (i, j, Com(S_{i-1}), Com(S_j), H_[i,j])` (zk1.tex Def.
//! "Interval proof"):
//!
//! * **leaf** for batch `t`: `lo = hi = t`, where `t` is a public input of the
//!   leaf circuit pinned to the base field, and
//!   `H = Poseidon2(TAG_LEAF, t, Com(B_t))`. `Com(B_t)` is the leaf's
//!   IN-CIRCUIT batch digest, i.e. the same sponge output the leaf already
//!   connects to its batch-commitment public input, so it is bound to the
//!   batch records the transition consumed.
//! * **merge** of adjacent children `[i, h]` and `[h+1, j]`: enforces
//!   `left.final == right.init` and `left.hi + 1 == right.lo` in-circuit,
//!   and exposes `(left.init, right.final, (i, j), H)` with
//!   `H = Poseidon2(TAG_MERGE, i, h, j, H_L, H_R)` (the paper's
//!   `H_[i,j] = hash(i, h, j, H_[i,h], H_[h+1,j])`). The adjacency is a field
//!   equation, so on BabyBear it wraps modulo p (a leaf at `t = p - 1` merges
//!   with one at `t = 0`); an intermediate `(i, j)` is meaningful only under a
//!   root the auditor accepted with `lo == 1`, `hi == T < p` and the digest,
//!   which rule wrapped trees out. On Goldilocks `t < 2^32`, so it cannot wrap.
//!
//! **Standalone leaves.** A leaf proof the auditor receives directly (the
//! per-batch mode, or the lone leaf of a one-batch stream) is not covered by
//! any root-VK pin, and its exposed statement alone authenticates nothing (a
//! toy circuit can expose any values). The auditor therefore pins it to the
//! trusted LEAF VK (derived from a no-op leaf) and STARK-verifies it with a
//! verifier configured from public parameters before checking the statements
//! ([`check_leaf_statements_against_log`]; the field-specific
//! `expose_forest[_gl]::verify_leaves_against_log` does both).
//!
//! Hash inputs are extension elements; the in-circuit sponge equals the native
//! `MyHash` (`PaddingFreeSponge`, zero IV, overwrite mode) over their
//! concatenated base coordinates, so the natively recomputed digests are:
//!
//! ```text
//! leaf  : MyHash([TAG_LEAF, 0^(D-1), t, 0^(D-1), Com(B_t)[0..C]])
//! merge : MyHash([TAG_MERGE, i, h, j, H_L[0..C], H_R[0..C]])
//! ```
//!
//! ## Auditor
//!
//! [`check_root_statement`] takes the published log (`Com(S_0)`, `Com(S_T)`
//! and the ordered `Com(B_1..B_T)`) and the composition [`ForestShape`] (the
//! bracketing the prover used: forest / chain / multi-machine forest), and
//! checks `lo == 1`, `hi == T`, `init == Com(S_0)`, `final == Com(S_T)`, the
//! padding coordinates of `idx`, and `H == H_expected`, where `H_expected` is
//! folded natively over exactly that bracketing. The root-VK pin
//! ([`super::root_vk::RootVk`]) fixes the bracketing inside the proof; the
//! digest check fixes which batch sits at which leaf position. By collision
//! resistance of Poseidon2 and the domain tags, an accepting root was composed
//! from leaves `t = 1..T` in order, leaf `t` having consumed exactly the batch
//! whose commitment the log lists at position `t`.

use p3_circuit::ops::Poseidon2Config;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, ExtensionField, PrimeField64};

use crate::recursion::recursive::root_vk::ForestShape;
use crate::sketch::bind::{self, Binding};

/// Domain tag of a leaf digest (`"LEAF"` in ASCII, < 2^31).
pub const TAG_LEAF: u64 = 0x4C45_4146;
/// Domain tag of a merge digest (`"MRGE"` in ASCII, < 2^31).
pub const TAG_MERGE: u64 = 0x4D52_4745;

// ─── Layout ──────────────────────────────────────────────────────────────────

/// What a leaf circuit surfaces for composition.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Expose {
    /// No Expose table: a standalone leaf that cannot be composed.
    None,
    /// Pre-B6(b) `(init, final)` only. Byte-for-byte the old circuits.
    Boundary,
    /// `(init, final, idx, H)`: the interval statement.
    Interval,
}

impl Expose {
    /// The legacy `expose_boundary: bool` switch of the leaf builders.
    pub const fn from_bool(expose_boundary: bool) -> Self {
        if expose_boundary { Expose::Boundary } else { Expose::None }
    }
    /// Whether an Expose table is present at all.
    pub const fn exposes(self) -> bool {
        !matches!(self, Expose::None)
    }
    /// Whether the interval statement is exposed.
    pub const fn is_interval(self) -> bool {
        matches!(self, Expose::Interval)
    }
}

/// The statement layout of an exposed-values vector (see the module table).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Layout {
    Boundary,
    Interval,
}

impl Layout {
    /// Number of exposed base values under this layout.
    pub const fn len(self, commit_len: usize, d: usize) -> usize {
        match self {
            Layout::Boundary => 2 * commit_len,
            Layout::Interval => 3 * commit_len + d,
        }
    }
    /// Detect the layout from an exposed-values length.
    pub fn of_len(len: usize, commit_len: usize, d: usize) -> Option<Self> {
        if len == Layout::Boundary.len(commit_len, d) {
            Some(Layout::Boundary)
        } else if len == Layout::Interval.len(commit_len, d) {
            Some(Layout::Interval)
        } else {
            None
        }
    }
}

/// The composition layout the experiment harnesses build their leaves with
/// and the auditor expects (fails closed: a root whose layout differs is
/// rejected).
///
/// Default: [`Expose::Interval`]. [`Expose::Boundary`] (the pre-B6(b)
/// statement, byte-for-byte the old leaf and merge circuits) is selected by
/// `ZKSKETCH_STATEMENT=boundary`, and also by `ZKSKETCH_BINDING=legacy` so a
/// Legacy side-by-side run stays byte-for-byte legacy end to end. Any other
/// non-empty value of `ZKSKETCH_STATEMENT`, including one that is not valid
/// UTF-8, panics rather than silently picking a layout
/// ([`parse_statement_env`]).
pub fn composition_expose() -> Expose {
    match parse_statement_env(std::env::var("ZKSKETCH_STATEMENT")) {
        Some(e) => e,
        None if bind::default_binding() == Binding::Legacy => Expose::Boundary,
        None => Expose::Interval,
    }
}

/// Parse a `ZKSKETCH_STATEMENT` lookup: `None` when unset or blank,
/// `interval` / `boundary` (any case, surrounding whitespace ignored) select
/// that layout, and every other value panics, including a non-UTF-8 one
/// (`VarError::NotUnicode`, which `.ok()` used to treat as unset).
pub fn parse_statement_env(var: Result<String, std::env::VarError>) -> Option<Expose> {
    match var {
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(v)) => {
            panic!("ZKSKETCH_STATEMENT={v:?}: not valid UTF-8; expected interval or boundary")
        }
        Ok(v) => match v.trim() {
            "" => None,
            t if t.eq_ignore_ascii_case("interval") => Some(Expose::Interval),
            t if t.eq_ignore_ascii_case("boundary") => Some(Expose::Boundary),
            _ => panic!("ZKSKETCH_STATEMENT={v:?}: expected interval or boundary"),
        },
    }
}

/// Loud stderr notice for an explicit `Boundary`-layout run: the auditor can
/// then check only `(Com(S_0), Com(S_T))`, not which batches were composed.
pub fn warn_boundary_layout(context: &str) {
    eprintln!(
        "\n!!! WARNING ({context}): composition layout = Boundary (pre-B6(b)): the root \
         exposes only (Com(S_0), Com(S_T)); the batch log (indices + Com(B_t) digest) is \
         NOT checked, so the root certifies only that SOME batch sequence maps S_0 to S_T. \
         Only for side-by-side runs; unset ZKSKETCH_STATEMENT (and ZKSKETCH_BINDING=legacy) \
         for the interval statement. !!!\n"
    );
}

// ─── In-circuit leaf gadget ──────────────────────────────────────────────────

/// How a leaf pins its batch index `t` to the base field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IndexPin {
    /// `bind::pin_u32` through the Range NPO (the leaf enables Range).
    Range,
    /// `decompose_to_bits(t, min(32, bits))` (no Range table needed).
    Bits,
}

/// Add the interval statement to a leaf circuit and expose it.
///
/// * allocates the batch index `t` as the LAST public input the circuit has
///   at call time (callers append `t` to their public-input vector), pinned
///   per `pin`;
/// * `idx = t·(1 + X)` (coordinates `(t, t, 0, …)`);
/// * `H = hash([TAG_LEAF, t, batch_digest…])` with the leaf's own sponge
///   discipline ([`bind::hash_slice`] under `binding`);
/// * `add_expose([init…, final…, idx, H…])`.
///
/// `init` / `final_` are the leaf's boundary-commitment wires (the same ones
/// the Boundary layout exposes) and `batch_digest` the IN-CIRCUIT batch
/// digest (the sponge output the leaf connects to its batch public input).
/// Returns the `t` wire.
#[allow(clippy::too_many_arguments)]
pub(crate) fn expose_leaf_interval<BF, F>(
    b: &mut CircuitBuilder<F>,
    cfg: &Poseidon2Config,
    init: &[ExprId],
    final_: &[ExprId],
    batch_digest: &[ExprId],
    zero: ExprId,
    binding: Binding,
    pin: IndexPin,
) -> ExprId
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let d = <F as BasedVectorSpace<BF>>::DIMENSION;
    let t = b.alloc_public_input("batch_index");
    match pin {
        IndexPin::Range => bind::pin_u32::<BF, F>(b, t),
        IndexPin::Bits => {
            let _ = b
                .decompose_to_bits::<BF>(t, BF::bits().min(32))
                .expect("pin batch index (bits)");
        }
    }
    let mut one_plus_x = vec![BF::ZERO; d];
    one_plus_x[0] = BF::ONE;
    one_plus_x[1] = BF::ONE;
    let one_plus_x = b.alloc_const(
        F::from_basis_coefficients_slice(&one_plus_x).expect("1 + X"),
        "stmt_1+X",
    );
    let idx = b.mul(t, one_plus_x);
    let tag = b.alloc_const(F::from_u64(TAG_LEAF), "stmt_tag_leaf");
    let mut inputs = vec![tag, t];
    inputs.extend_from_slice(batch_digest);
    let h = bind::hash_slice(b, cfg, &inputs, zero, binding);
    let mut exposed: Vec<ExprId> = Vec::with_capacity(init.len() + final_.len() + 1 + h.len());
    exposed.extend_from_slice(init);
    exposed.extend_from_slice(final_);
    exposed.push(idx);
    exposed.extend_from_slice(&h);
    b.add_expose(&exposed).expect("add_expose interval statement");
    t
}

// ─── Native statement ────────────────────────────────────────────────────────

/// A statement read back from a proof's exposed values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement<BF> {
    pub init: Vec<BF>,
    pub final_: Vec<BF>,
    /// `Some` under the Interval layout.
    pub interval: Option<IntervalPart<BF>>,
}

impl<BF: Copy> Statement<BF> {
    /// The exposed base values in the Expose-table layout order (the inverse
    /// of [`parse_statement`]): `init ‖ final [‖ lo, hi, pad… ‖ H]`.
    pub fn values(&self) -> Vec<BF> {
        let mut v = self.init.clone();
        v.extend_from_slice(&self.final_);
        if let Some(iv) = &self.interval {
            v.push(iv.lo);
            v.push(iv.hi);
            v.extend_from_slice(&iv.idx_pad);
            v.extend_from_slice(&iv.digest);
        }
        v
    }
}

/// The interval part of a [`Statement`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalPart<BF> {
    pub lo: BF,
    pub hi: BF,
    /// `idx` coordinates `2..D` (zero for an honest circuit).
    pub idx_pad: Vec<BF>,
    pub digest: Vec<BF>,
}

/// Parse exposed base values (`commit_len` = `C`, `d` = `D`).
pub fn parse_statement<BF: Copy>(pv: &[BF], commit_len: usize, d: usize) -> Option<Statement<BF>> {
    let layout = Layout::of_len(pv.len(), commit_len, d)?;
    let init = pv[0..commit_len].to_vec();
    let final_ = pv[commit_len..2 * commit_len].to_vec();
    let interval = (layout == Layout::Interval).then(|| {
        let idx = &pv[2 * commit_len..2 * commit_len + d];
        IntervalPart {
            lo: idx[0],
            hi: idx[1],
            idx_pad: idx[2..].to_vec(),
            digest: pv[2 * commit_len + d..].to_vec(),
        }
    });
    Some(Statement { init, final_, interval })
}

/// Native leaf digest `MyHash([TAG_LEAF, 0^(D-1), t, 0^(D-1), Com(B_t)])`.
pub fn leaf_digest<BF: PrimeField64>(
    hash: &dyn Fn(&[BF]) -> Vec<BF>,
    d: usize,
    t: u64,
    batch_commit: &[BF],
) -> Vec<BF> {
    let mut input = vec![BF::ZERO; 2 * d];
    input[0] = BF::from_u64(TAG_LEAF);
    input[d] = BF::from_u64(t);
    input.extend_from_slice(batch_commit);
    hash(&input)
}

/// Native merge digest `MyHash([TAG_MERGE, i, h, j, H_L, H_R])`.
pub fn merge_digest<BF: PrimeField64>(
    hash: &dyn Fn(&[BF]) -> Vec<BF>,
    i: u64,
    h: u64,
    j: u64,
    left: &[BF],
    right: &[BF],
) -> Vec<BF> {
    let mut input = vec![
        BF::from_u64(TAG_MERGE),
        BF::from_u64(i),
        BF::from_u64(h),
        BF::from_u64(j),
    ];
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    hash(&input)
}

/// The `(lo, hi, H)` a composition of `shape` over batches
/// `first_index, first_index + 1, …` (commitments `batch_commits`, in order)
/// exposes — folded natively under exactly `shape`'s bracketing.
pub fn expected_interval<BF: PrimeField64>(
    hash: &dyn Fn(&[BF]) -> Vec<BF>,
    d: usize,
    shape: &ForestShape,
    first_index: u64,
    batch_commits: &[Vec<BF>],
) -> (u64, u64, Vec<BF>) {
    assert_eq!(
        shape.num_leaves(),
        batch_commits.len(),
        "shape covers {} leaves but {} batch commitments were given",
        shape.num_leaves(),
        batch_commits.len()
    );
    match shape {
        ForestShape::Leaf => {
            (first_index, first_index, leaf_digest(hash, d, first_index, &batch_commits[0]))
        }
        ForestShape::Merge(l, r) => {
            let nl = l.num_leaves();
            let (i, h, hl) = expected_interval(hash, d, l, first_index, &batch_commits[..nl]);
            let (h1, j, hr) = expected_interval(hash, d, r, h + 1, &batch_commits[nl..]);
            debug_assert_eq!(h1, h + 1);
            (i, j, merge_digest(hash, i, h, j, &hl, &hr))
        }
    }
}

/// The public batch log an auditor holds: the anchor `Com(S_0)`, the posted
/// `Com(S_T)`, and the ordered batch commitments `Com(B_1..B_T)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchLog<BF> {
    pub init: Vec<BF>,
    pub final_: Vec<BF>,
    pub batch_commits: Vec<Vec<BF>>,
}

impl<BF> BatchLog<BF> {
    pub fn num_batches(&self) -> usize {
        self.batch_commits.len()
    }
}

/// Check a root statement against the log and the composition shape:
/// Interval layout, `lo == 1`, `hi == T`, zero `idx` padding,
/// `init == Com(S_0)`, `final == Com(S_T)`, `H == H_expected(shape, log)`.
pub fn check_root_statement<BF: PrimeField64>(
    stmt: &Statement<BF>,
    log: &BatchLog<BF>,
    shape: &ForestShape,
    hash: &dyn Fn(&[BF]) -> Vec<BF>,
    d: usize,
) -> Result<(), String> {
    let t = log.num_batches();
    if t == 0 {
        return Err("empty batch log".into());
    }
    if shape.num_leaves() != t {
        return Err(format!(
            "composition shape covers {} batches but the log lists {t}",
            shape.num_leaves()
        ));
    }
    let iv = stmt
        .interval
        .as_ref()
        .ok_or("root exposes the Boundary layout only (no batch indices / digest)")?;
    if iv.lo != BF::ONE {
        return Err(format!("root idx_lo = {} != 1", iv.lo));
    }
    if iv.hi != BF::from_u64(t as u64) {
        return Err(format!("root idx_hi = {} != T = {t}", iv.hi));
    }
    if iv.idx_pad.iter().any(|&x| x != BF::ZERO) {
        return Err("root idx padding coordinates are not zero".into());
    }
    if stmt.init != log.init {
        return Err("root init != Com(S_0) of the log".into());
    }
    if stmt.final_ != log.final_ {
        return Err("root final != Com(S_T) of the log".into());
    }
    let (_, _, expected) = expected_interval(hash, d, shape, 1, &log.batch_commits);
    if iv.digest != expected {
        return Err(
            "root ordered-batch digest H != the digest recomputed from the log's batch \
             commitments under the declared bracketing"
                .into(),
        );
    }
    Ok(())
}

/// Check a single (per-batch) leaf statement against the log entry of batch
/// `t`: Interval layout, `lo == hi == t`, zero `idx` padding, and
/// `H == leaf_digest(t, Com(B_t))`. (The per-batch auditor checks the
/// boundary chain `init`/`final` separately.)
pub fn check_leaf_statement<BF: PrimeField64>(
    stmt: &Statement<BF>,
    t: u64,
    batch_commit: &[BF],
    hash: &dyn Fn(&[BF]) -> Vec<BF>,
    d: usize,
) -> Result<(), String> {
    let iv = stmt
        .interval
        .as_ref()
        .ok_or("leaf exposes the Boundary layout only (no batch index / digest)")?;
    if iv.lo != BF::from_u64(t) || iv.hi != BF::from_u64(t) {
        return Err(format!("leaf idx = [{}, {}] != [{t}, {t}]", iv.lo, iv.hi));
    }
    if iv.idx_pad.iter().any(|&x| x != BF::ZERO) {
        return Err("leaf idx padding coordinates are not zero".into());
    }
    if iv.digest != leaf_digest(hash, d, t, batch_commit) {
        return Err(format!("leaf {t} digest != H(TAG_LEAF, {t}, Com(B_{t})) of the log"));
    }
    Ok(())
}

/// Check the statements of the `T` leaf proofs an auditor received directly
/// (per-batch mode, or the lone leaf of a one-batch stream) against the log:
/// one statement per log entry, the boundary chain
/// `leaf_1.init == Com(S_0)`, `leaf_t.final == leaf_{t+1}.init`,
/// `leaf_T.final == Com(S_T)`, and, under the Interval layout, each leaf's
/// [`check_leaf_statement`] at its position `t`. For `T == 1` this is exactly
/// [`check_root_statement`] over [`ForestShape::Leaf`].
///
/// This checks VALUES only. It authenticates nothing unless each proof was
/// first verified against the trusted leaf VK (the field-specific
/// `verify_leaves_against_log` does both).
pub fn check_leaf_statements_against_log<BF: PrimeField64>(
    stmts: &[Statement<BF>],
    log: &BatchLog<BF>,
    layout: Expose,
    hash: &dyn Fn(&[BF]) -> Vec<BF>,
    d: usize,
) -> Result<(), String> {
    let t_total = log.num_batches();
    if t_total == 0 {
        return Err("empty batch log".into());
    }
    if stmts.len() != t_total {
        return Err(format!("{} leaf proofs for a log of {t_total} batches", stmts.len()));
    }
    let mut prev = &log.init;
    for (i, s) in stmts.iter().enumerate() {
        let t = i as u64 + 1;
        if &s.init != prev {
            return Err(if i == 0 {
                "leaf 1 init != Com(S_0) of the log".into()
            } else {
                format!("boundary break: leaf {t} init != leaf {} final", t - 1)
            });
        }
        match layout {
            Expose::Interval => check_leaf_statement(s, t, &log.batch_commits[i], hash, d)?,
            Expose::Boundary => {}
            Expose::None => return Err("an unexposed leaf carries no statement".into()),
        }
        prev = &s.final_;
    }
    if prev != &log.final_ {
        return Err(format!("leaf {t_total} final != Com(S_T) of the log"));
    }
    Ok(())
}

/// Check the statements of a **prefix certificate** against the log
/// (Property 3, query time): the interval proofs a verifier holds at version
/// `t` (the forest's live peaks, the chain's current fold, or the per-batch
/// leaves), in order, each with the bracketing it was folded under. They must
/// tile `[1, t]` exactly: part `k` exposes `lo` = one past the previous part's
/// `hi` (the first `lo == 1`), `hi = lo + |shape| - 1`, zero `idx` padding,
/// `init` = the previous part's `final` (the first `init == Com(S_0)`), and
/// `H == H_expected(shape, Com(B_lo..B_hi))` recomputed from the log. Returns
/// the certified `Com(S_t)`, the last part's `final`, which a query proof's
/// exposed state commitment must equal.
///
/// Each part's digest is recomputed with the honest indices, so a part whose
/// exposed `(lo, hi)` wrapped modulo `p` (see the module docs) fails the
/// digest check exactly as a wrapped root would. This checks VALUES only: it
/// authenticates nothing unless every part was first verified against the
/// trusted VK of its bracketing (`expose_forest::PrefixAuditor` does both).
pub fn check_prefix_statements<BF: PrimeField64>(
    parts: &[(&Statement<BF>, &ForestShape)],
    log: &BatchLog<BF>,
    t: usize,
    hash: &dyn Fn(&[BF]) -> Vec<BF>,
    d: usize,
) -> Result<Vec<BF>, String> {
    if t == 0 || t > log.num_batches() {
        return Err(format!("version t = {t} is outside the log's 1..={}", log.num_batches()));
    }
    if parts.is_empty() {
        return Err("empty prefix certificate".into());
    }
    let mut next = 1usize;
    let mut prev = &log.init;
    for (k, (stmt, shape)) in parts.iter().enumerate() {
        let n = shape.num_leaves();
        let hi = next + n - 1;
        if hi > t {
            return Err(format!("part {} covers up to batch {hi}, past version t = {t}", k + 1));
        }
        let iv = stmt
            .interval
            .as_ref()
            .ok_or_else(|| format!("part {} exposes the Boundary layout only", k + 1))?;
        if iv.lo != BF::from_u64(next as u64) || iv.hi != BF::from_u64(hi as u64) {
            return Err(format!(
                "part {} idx = [{}, {}] != [{next}, {hi}] (parts must tile [1, t] in order)",
                k + 1,
                iv.lo,
                iv.hi
            ));
        }
        if iv.idx_pad.iter().any(|&x| x != BF::ZERO) {
            return Err(format!("part {} idx padding coordinates are not zero", k + 1));
        }
        if &stmt.init != prev {
            return Err(if k == 0 {
                "part 1 init != Com(S_0) of the log".into()
            } else {
                format!("boundary break: part {} init != part {k} final", k + 1)
            });
        }
        let (_, _, expected) =
            expected_interval(hash, d, shape, next as u64, &log.batch_commits[next - 1..hi]);
        if iv.digest != expected {
            return Err(format!(
                "part {} ordered-batch digest != the digest recomputed from Com(B_{next}..B_{hi}) \
                 under its bracketing",
                k + 1
            ));
        }
        prev = &stmt.final_;
        next = hi + 1;
    }
    if next - 1 != t {
        return Err(format!("the parts certify [1, {}], not [1, {t}]", next - 1));
    }
    Ok(prev.clone())
}

// ─── Field instances ─────────────────────────────────────────────────────────

/// BabyBear native sponge (`crate::config::MyHash`, digest `[Val; 8]`).
pub fn hash_bb(input: &[crate::config::Val]) -> Vec<crate::config::Val> {
    use p3_symmetric::CryptographicHasher;
    let h = crate::config::MyHash::new(crate::config::make_perm());
    let out: [crate::config::Val; 8] = h.hash_iter(input.iter().copied());
    out.to_vec()
}

/// Goldilocks native sponge (`crate::config_gl::MyHash`, digest `[Val; 4]`).
pub fn hash_gl(input: &[crate::config_gl::Val]) -> Vec<crate::config_gl::Val> {
    use p3_symmetric::CryptographicHasher;
    let h = crate::config_gl::MyHash::new(crate::config_gl::make_perm());
    let out: [crate::config_gl::Val; 4] = h.hash_iter(input.iter().copied());
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Val;
    use p3_field::PrimeCharacteristicRing;

    fn commits(n: usize) -> Vec<Vec<Val>> {
        (0..n).map(|i| (0..8).map(|k| Val::from_u64((i * 31 + k + 7) as u64)).collect()).collect()
    }

    /// The native fold follows the bracketing: forest(4) and chain(4) give
    /// different digests over the same batches; permuting two batches, or
    /// changing one, changes the digest.
    #[test]
    fn expected_interval_binds_order_content_and_bracketing() {
        let c = commits(4);
        let (lo, hi, f4) = expected_interval(&hash_bb, 4, &ForestShape::forest(4), 1, &c);
        assert_eq!((lo, hi), (1, 4));
        let (_, _, c4) = expected_interval(&hash_bb, 4, &ForestShape::chain(4), 1, &c);
        assert_ne!(f4, c4, "bracketing is bound");
        let mut swapped = c.clone();
        swapped.swap(1, 2);
        let (_, _, s4) = expected_interval(&hash_bb, 4, &ForestShape::forest(4), 1, &swapped);
        assert_ne!(f4, s4, "order is bound");
        let mut changed = c.clone();
        changed[3][0] += Val::ONE;
        let (_, _, x4) = expected_interval(&hash_bb, 4, &ForestShape::forest(4), 1, &changed);
        assert_ne!(f4, x4, "content is bound");
        // forest(3) == chain(3) as shapes, so their digests agree.
        let (_, _, f3) = expected_interval(&hash_bb, 4, &ForestShape::forest(3), 1, &c[..3]);
        let (_, _, c3) = expected_interval(&hash_bb, 4, &ForestShape::chain(3), 1, &c[..3]);
        assert_eq!(f3, c3);
    }

    /// The honest statement of an interval proof over batches `[lo, lo+|shape|-1]`
    /// whose boundaries are `states[lo-1]` and `states[hi]`.
    fn honest(states: &[Vec<Val>], c: &[Vec<Val>], lo: usize, shape: &ForestShape) -> Statement<Val> {
        let hi = lo + shape.num_leaves() - 1;
        let (_, _, digest) = expected_interval(&hash_bb, 4, shape, lo as u64, &c[lo - 1..hi]);
        Statement {
            init: states[lo - 1].clone(),
            final_: states[hi].clone(),
            interval: Some(IntervalPart {
                lo: Val::from_u64(lo as u64),
                hi: Val::from_u64(hi as u64),
                idx_pad: vec![Val::ZERO; 2],
                digest,
            }),
        }
    }

    /// A prefix certificate at version t = 7 = 4 + 2 + 1 (the forest's live
    /// peaks) is accepted and yields Com(S_7); so do the chain's single fold
    /// and the per-batch leaves. Gaps, overlaps, a wrong order, a broken
    /// boundary, a foreign Com(S_0), a wrong bracketing, a part past t, and a
    /// certificate of a shorter prefix are all rejected.
    #[test]
    fn prefix_statements_tile_the_log() {
        let c = commits(9);
        let states: Vec<Vec<Val>> = (0..10).map(|i| vec![Val::from_u64(1000 + i as u64); 8]).collect();
        let log = BatchLog { init: states[0].clone(), final_: states[9].clone(), batch_commits: c.clone() };
        let check = |parts: &[(Statement<Val>, ForestShape)], t: usize| {
            let refs: Vec<(&Statement<Val>, &ForestShape)> = parts.iter().map(|(s, sh)| (s, sh)).collect();
            check_prefix_statements(&refs, &log, t, &hash_bb, 4)
        };
        let (p4, p2, p1) = (ForestShape::forest(4), ForestShape::forest(2), ForestShape::Leaf);
        let peaks = vec![
            (honest(&states, &c, 1, &p4), p4.clone()),
            (honest(&states, &c, 5, &p2), p2.clone()),
            (honest(&states, &c, 7, &p1), p1.clone()),
        ];
        assert_eq!(check(&peaks, 7), Ok(states[7].clone()));
        let chain7 = ForestShape::chain(7);
        assert_eq!(check(&[(honest(&states, &c, 1, &chain7), chain7.clone())], 7), Ok(states[7].clone()));
        let leaves: Vec<_> = (1..=7).map(|lo| (honest(&states, &c, lo, &p1), p1.clone())).collect();
        assert_eq!(check(&leaves, 7), Ok(states[7].clone()));

        // A certificate of [1, 6] does not certify version 7, and vice versa.
        assert!(check(&peaks[..2], 7).is_err(), "missing the last peak");
        assert!(check(&peaks, 6).is_err(), "a part past t");
        // Gap: drop the middle peak.
        assert!(check(&[peaks[0].clone(), peaks[2].clone()], 7).is_err(), "gap");
        // Order: swap two peaks.
        assert!(check(&[peaks[1].clone(), peaks[0].clone(), peaks[2].clone()], 7).is_err(), "order");
        // Wrong bracketing for the first peak: chain(4) instead of forest(4).
        let mut wrong = peaks.clone();
        wrong[0].1 = ForestShape::chain(4);
        assert!(check(&wrong, 7).is_err(), "bracketing");
        // Broken boundary: the middle peak starts from a different state.
        let mut brk = peaks.clone();
        brk[1].0.init = vec![Val::from_u64(7); 8];
        assert!(check(&brk, 7).is_err(), "boundary");
        // Foreign anchor.
        let mut anchor = peaks.clone();
        anchor[0].0.init = vec![Val::from_u64(7); 8];
        assert!(check(&anchor, 7).is_err(), "Com(S_0)");
        // A peak whose digest covers other batches.
        let mut other = peaks.clone();
        other[1].0 = honest(&states, &c, 5, &p2);
        other[1].0.interval.as_mut().unwrap().digest = honest(&states, &c, 3, &p2).interval.unwrap().digest;
        assert!(check(&other, 7).is_err(), "digest");
        // Boundary-only statements carry no interval.
        let mut bnd = peaks.clone();
        bnd[2].0.interval = None;
        assert!(check(&bnd, 7).is_err(), "boundary layout");
        assert!(check(&[], 7).is_err(), "empty");
        assert!(check(&peaks, 10).is_err(), "t beyond the log");
    }

    #[test]
    fn layout_lengths() {
        assert_eq!(Layout::Boundary.len(8, 4), 16);
        assert_eq!(Layout::Interval.len(8, 4), 28);
        assert_eq!(Layout::Boundary.len(4, 2), 8);
        assert_eq!(Layout::Interval.len(4, 2), 14);
        assert_eq!(Layout::of_len(28, 8, 4), Some(Layout::Interval));
        assert_eq!(Layout::of_len(16, 8, 4), Some(Layout::Boundary));
        assert_eq!(Layout::of_len(24, 8, 4), None);
    }

    /// `ZKSKETCH_STATEMENT` parsing without touching the process environment:
    /// unset/blank = `None` (the default), the two names in any case, and a
    /// panic on anything else, including a non-UTF-8 value.
    #[test]
    fn statement_env_parsing() {
        use std::env::VarError;
        assert_eq!(parse_statement_env(Err(VarError::NotPresent)), None);
        assert_eq!(parse_statement_env(Ok("  ".into())), None);
        assert_eq!(parse_statement_env(Ok("Interval".into())), Some(Expose::Interval));
        assert_eq!(parse_statement_env(Ok(" boundary ".into())), Some(Expose::Boundary));
        let msg = crate::sketch::forge::catch_msg(|| parse_statement_env(Ok("leaf".into())))
            .unwrap_err();
        assert!(msg.contains("expected interval or boundary"), "{msg}");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = std::ffi::OsString::from_vec(b"inter\xffval".to_vec());
            let msg = crate::sketch::forge::catch_msg(|| {
                parse_statement_env(Err(VarError::NotUnicode(bad)))
            })
            .unwrap_err();
            assert!(msg.contains("not valid UTF-8"), "{msg}");
        }
    }
}
