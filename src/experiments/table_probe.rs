//! Per-table trace shapes of a batch-STARK circuit, read at build time
//! (revision E-0: does every table of every deployed circuit fit the hiding
//! row ceiling?).
//!
//! The deployed leaf builders (`countmin_omc`, `hll_omc`, `ss_final_full`,
//! `gk_bandmerge` bandmerge2, `bloom_omc`) and the merge-VK builder
//! (`expose_forest::aggregation_circuit_commitment`) call [`record_leaf`] /
//! [`record_merge`] right after `get_airs_and_degrees_with_prep`, then
//! [`maybe_stop`]. Both hooks are read-only: the shapes are read off the AIRs
//! and preprocessed columns the builder already computed and nothing is fed
//! back, so circuits, VKs and proofs are unchanged. With nothing armed (the
//! default) [`record_leaf`] returns at once and [`maybe_stop`] only reads
//! `ZKSKETCH_SHAPES_ONLY`.
//!
//! * [`capture`] arms the recorder on this thread around a closure (a full
//!   build, a proof, or a root-VK derivation that builds merge circuits).
//! * [`capture_shapes`] also stops every builder right after its shapes are
//!   recorded, before the preprocessed commit: a shapes-only probe of a
//!   deployed-geometry leaf costs seconds and a few GB instead of a full
//!   build. `ZKSKETCH_SHAPES_ONLY=1` stops the builders process-wide.
//! * `E0_QUOTIENT=1` also records each table's log quotient-chunk count,
//!   non-ZK and ZK (a symbolic evaluation of every AIR).
//!
//! `log_h` is the base (non-ZK) log2 padded height of the circuit that was
//! built (a hiding PCS commits `2^(log_h + 1)` rows). A leaf circuit is the
//! same under both PCS; a merge circuit is not, since it verifies its
//! children's proofs and a hiding proof has more to verify, so merge shapes
//! describe the PCS of the build that recorded them.
//!
//! Every committed LDE has `2^(log_h + is_zk + LOG_BLOWUP)` rows and the
//! quotient domain `2^(log_h + is_zk + lq)` points (`lq` = log quotient-chunk
//! count), and BabyBear's two-adicity is 27, so a table fits iff
//! `log_h + is_zk + max(LOG_BLOWUP, lq) <= 27` ([`TableShape::log_ceiling`]).
//! With `lq` recorded (`E0_QUOTIENT=1`) that is checked as is; without it
//! `lq <= LOG_BLOWUP` is assumed, i.e. `log_h <= 25` non-hiding and
//! `log_h <= 24` hiding ([`LOG_CEILING_NONHIDING`], [`LOG_CEILING_HIDING`]).

use std::cell::{Cell, RefCell};
use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::BaseAir;
use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::get_log_num_quotient_chunks;
use p3_circuit::ops::NonPrimitivePreprocessedMap;
use p3_circuit_prover::common::CircuitTableAir;
use p3_circuit_prover::{PrimitiveTable, TablePacking};
use p3_field::TwoAdicField;
use p3_lookup::Lookups;
use p3_lookup::logup::LogUpGadget;

use crate::config::{Challenge, LOG_BLOWUP, Val};
use crate::recursion::recursive::config::{ConfigWithFriParams, D};

const TWO_ADICITY: usize = <Val as TwoAdicField>::TWO_ADICITY;
/// Largest `log_h` a non-hiding table with `lq <= LOG_BLOWUP` may have:
/// `TWO_ADICITY - LOG_BLOWUP`.
pub const LOG_CEILING_NONHIDING: usize = TWO_ADICITY - LOG_BLOWUP;
/// Largest `log_h` a hiding table with `lq <= LOG_BLOWUP` may have (the PCS
/// doubles every trace).
pub const LOG_CEILING_HIDING: usize = LOG_CEILING_NONHIDING - 1;

/// Non-primitive AIR order of the zkSketch leaf builders (their
/// `air_builders` registration order). Entries match a table's `NpoTypeId`
/// exactly or as a `<entry>_` prefix (`poseidon2_perm/...`).
const LEAF_NPO_ORDER: &[&str] =
    &["poseidon2", "recompose", "recompose/coeff", "permute", "range", "expose"];
/// Non-primitive AIR order of the recursion backend's merge circuits
/// (`FriRecursionBackendForExt::non_primitive_air_builders`: expose before range).
const MERGE_NPO_ORDER: &[&str] =
    &["poseidon2", "recompose", "recompose/coeff", "permute", "expose", "range"];

/// One table of a built circuit.
#[derive(Clone, Debug)]
pub struct TableShape {
    /// Position in AIR (= proof instance) order.
    pub idx: usize,
    /// `const` / `public` / `alu`, or the non-primitive op type.
    pub name: String,
    /// log2 of the padded (base, non-ZK) height.
    pub log_h: usize,
    /// Rows before power-of-two padding (ops / lanes).
    pub rows: usize,
    /// Main trace width (base-field columns).
    pub width: usize,
    /// Preprocessed width (base-field columns).
    pub prep_width: usize,
    /// `(non-ZK, ZK)` log2 quotient-chunk counts, under `E0_QUOTIENT=1`.
    pub lq: Option<(usize, usize)>,
    /// `rows` pads to exactly `2^log_h` under the packing's minimum height
    /// (a check on the name assignment and the row formula).
    pub consistent: bool,
}

impl TableShape {
    pub fn padded(&self) -> u64 {
        1u64 << self.log_h
    }
    /// Fraction of the padded height holding real rows.
    pub fn fill(&self) -> f64 {
        self.rows as f64 / self.padded() as f64
    }
    /// Largest `log_h` this table may have under the non-hiding (`zk =
    /// false`) or hiding PCS: `TWO_ADICITY - is_zk - max(LOG_BLOWUP, lq)`,
    /// with the recorded `lq` of that PCS, or `lq <= LOG_BLOWUP` assumed when
    /// none was recorded ([`LOG_CEILING_NONHIDING`] / [`LOG_CEILING_HIDING`]).
    pub fn log_ceiling(&self, zk: bool) -> usize {
        let lq = self.lq.map_or(0, |(lq0, lq1)| if zk { lq1 } else { lq0 });
        TWO_ADICITY.saturating_sub(usize::from(zk) + LOG_BLOWUP.max(lq))
    }
    pub fn fits_nonhiding(&self) -> bool {
        self.log_h <= self.log_ceiling(false)
    }
    pub fn fits_hiding(&self) -> bool {
        self.log_h <= self.log_ceiling(true)
    }
    /// Rows this table can still grow by before it outgrows its hiding
    /// ceiling (negative once it has).
    pub fn headroom_hiding(&self) -> i64 {
        (1i64 << self.log_ceiling(true)) - self.rows as i64
    }
}

/// The tables of one built circuit.
#[derive(Clone, Debug)]
pub struct CircuitShape {
    /// Which builder recorded it (`countmin_omc`, ..., `merge`).
    pub site: &'static str,
    pub tables: Vec<TableShape>,
}

impl CircuitShape {
    pub fn max_log_h(&self) -> usize {
        self.tables.iter().map(|t| t.log_h).max().unwrap_or(0)
    }
    /// The tables at [`Self::max_log_h`].
    pub fn largest(&self) -> Vec<&TableShape> {
        let max = self.max_log_h();
        self.tables.iter().filter(|t| t.log_h == max).collect()
    }
    /// `Σ 2^log_h`: the (non-ZK) `trace_rows` metric of the builders.
    pub fn sum_padded(&self) -> u64 {
        self.tables.iter().map(TableShape::padded).sum()
    }
    pub fn consistent(&self) -> bool {
        self.tables.iter().all(|t| t.consistent)
    }
    /// Every table fits its non-hiding ceiling.
    pub fn fits_nonhiding(&self) -> bool {
        self.tables.iter().all(TableShape::fits_nonhiding)
    }
    /// Every table fits its hiding ceiling (with `lq` recorded, a table below
    /// [`Self::max_log_h`] can be the one that does not).
    pub fn fits_hiding(&self) -> bool {
        self.tables.iter().all(TableShape::fits_hiding)
    }
}

/// Panic payload of a builder stopped by [`maybe_stop`].
pub struct ShapesOnly;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static STOP: Cell<bool> = const { Cell::new(false) };
    static LOG: RefCell<Vec<CircuitShape>> = const { RefCell::new(Vec::new()) };
}

fn env_is_one(key: &str) -> bool {
    std::env::var(key).is_ok_and(|v| v == "1")
}

fn stopping() -> bool {
    STOP.get() || env_is_one("ZKSKETCH_SHAPES_ONLY")
}

fn armed() -> bool {
    ARMED.get() || stopping()
}

/// Leaf-builder hook: record the tables of a zkSketch leaf.
pub fn record_leaf(
    site: &'static str,
    packing: &TablePacking,
    airs_degrees: &[(CircuitTableAir<ConfigWithFriParams, D>, usize)],
    npo: &NonPrimitivePreprocessedMap<Val>,
    prim: &[Vec<Val>],
) {
    if armed() {
        record(site, LEAF_NPO_ORDER, packing, airs_degrees, npo, prim);
    }
}

/// Merge-builder hook: record the tables of a merge (aggregation) circuit.
pub fn record_merge(
    packing: &TablePacking,
    airs_degrees: &[(CircuitTableAir<ConfigWithFriParams, D>, usize)],
    npo: &NonPrimitivePreprocessedMap<Val>,
    prim: &[Vec<Val>],
) {
    if armed() {
        record("merge", MERGE_NPO_ORDER, packing, airs_degrees, npo, prim);
    }
}

fn npo_rank(key: &str, order: &[&str]) -> usize {
    order
        .iter()
        .position(|e| key == *e || key.strip_prefix(e).is_some_and(|r| r.starts_with('_')))
        .unwrap_or(order.len())
}

fn record(
    site: &'static str,
    order: &[&str],
    packing: &TablePacking,
    airs_degrees: &[(CircuitTableAir<ConfigWithFriParams, D>, usize)],
    npo: &NonPrimitivePreprocessedMap<Val>,
    prim: &[Vec<Val>],
) {
    // `get_airs_and_degrees_with_prep` emits one AIR per primitive table, then
    // one per non-primitive op type in builder order.
    let mut npo_keys: Vec<&str> = npo.keys().map(|k| k.as_str()).collect();
    npo_keys.sort_by_key(|k| (npo_rank(k, order), k.to_string()));
    let n_dynamic =
        airs_degrees.iter().filter(|(a, _)| matches!(a, CircuitTableAir::Dynamic(_))).count();
    let names_ok = n_dynamic == npo_keys.len();
    let quotient = env_is_one("E0_QUOTIENT");
    let min_rows = packing.min_trace_height().next_power_of_two();

    let mut next_dynamic = 0;
    let tables = airs_degrees
        .iter()
        .enumerate()
        .map(|(idx, (air, log_h))| {
            let width = BaseAir::<Val>::width(air);
            let prep_width = BaseAir::<Val>::preprocessed_width(air);
            let (name, rows) = match air {
                // Primitive columns after conversion: const rows are `2 + D`
                // wide, public ops 2 wide (packed `lanes` per row).
                CircuitTableAir::Const(_) => {
                    ("const".to_string(), prim[PrimitiveTable::Const as usize].len() / (2 + D))
                }
                CircuitTableAir::Public(_) => {
                    let ops = prim[PrimitiveTable::Public as usize].len() / 2;
                    let lanes = if ops <= 1 { 1 } else { packing.public_lanes() };
                    ("public".to_string(), ops.div_ceil(lanes))
                }
                CircuitTableAir::Alu(a) => {
                    ("alu".to_string(), a.scheduled_entry_count().div_ceil(packing.alu_lanes()))
                }
                CircuitTableAir::Dynamic(_) => {
                    let j = next_dynamic;
                    next_dynamic += 1;
                    if names_ok {
                        let key = npo_keys[j];
                        let len = npo.iter().find(|(k, _)| k.as_str() == key).map_or(0, |(_, v)| v.len());
                        (key.to_string(), len.div_ceil(prep_width.max(1)))
                    } else {
                        (format!("npo#{j}"), 0)
                    }
                }
            };
            let consistent = rows.next_power_of_two().max(min_rows) == 1usize << log_h;
            let lq = quotient.then(|| {
                let lookups = Lookups::<Val>::from_air::<Challenge, _>(air);
                let layout = AirLayout {
                    preprocessed_width: prep_width,
                    main_width: width,
                    num_public_values: BaseAir::<Val>::num_public_values(air),
                    num_periodic_columns: BaseAir::<Val>::num_periodic_columns(air),
                    ..Default::default()
                };
                let g = LogUpGadget::new();
                let lq = |zk| {
                    get_log_num_quotient_chunks::<Val, Challenge, _, LogUpGadget>(
                        air,
                        layout.clone(),
                        &lookups,
                        zk,
                        &g,
                    )
                };
                (lq(0), lq(1))
            });
            TableShape { idx, name, log_h: *log_h, rows, width, prep_width, lq, consistent }
        })
        .collect();
    LOG.with(|l| l.borrow_mut().push(CircuitShape { site, tables }));
}

/// Builder hook: stop the build (a [`ShapesOnly`] panic) under
/// [`capture_shapes`] or `ZKSKETCH_SHAPES_ONLY=1`. A process-wide stop outside
/// any capture prints the recorded shapes to stderr first.
pub fn maybe_stop() {
    if !stopping() {
        return;
    }
    if !STOP.get() {
        for shape in LOG.with(|l| l.borrow().clone()) {
            eprintln!("{}", summary(&shape));
        }
    }
    std::panic::panic_any(ShapesOnly);
}

/// One-line-per-table rendering of a shape.
pub fn summary(shape: &CircuitShape) -> String {
    let mut s = format!(
        "[table_probe] {}: max_log_h={} sum_padded={} fits_hiding={} (hiding ceiling 2^{} while lq<={})",
        shape.site,
        shape.max_log_h(),
        shape.sum_padded(),
        shape.fits_hiding(),
        LOG_CEILING_HIDING,
        LOG_BLOWUP
    );
    for t in &shape.tables {
        let ceiling = t.log_ceiling(true);
        s.push_str(&format!(
            "\n  {:>2} {:<32} 2^{:<2} rows={:<10} fill={:.3} width={} prep={}{}{}{}",
            t.idx,
            t.name,
            t.log_h,
            t.rows,
            t.fill(),
            t.width,
            t.prep_width,
            t.lq.map_or(String::new(), |(a, b)| format!(" lq={a}/{b}")),
            if ceiling < LOG_CEILING_HIDING { format!(" hiding_ceiling=2^{ceiling}") } else { String::new() },
            if t.consistent { "" } else { " (inconsistent)" }
        ));
    }
    s
}

thread_local! {
    /// The phase prefix the Count-Min `omc` and Greenwald--Khanna stable leaf
    /// builders emit on this thread; `usize::MAX` = every phase (the deployed
    /// circuit). Private: only [`capture_prefix_shapes`] sets it, and that
    /// stops every build right after its shapes are recorded, so a prefix
    /// circuit can never be returned, let alone proved.
    static PHASE_LIMIT: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// The phase prefix a leaf builder should emit on this thread: `usize::MAX`
/// (every phase) unless inside [`capture_prefix_shapes`]. The builders'
/// guards only skip gates, never reorder them, so outside a probe the
/// circuit is unchanged.
pub fn phase_limit() -> usize {
    PHASE_LIMIT.get()
}

/// Shapes of a leaf built with only its first `k` paper phases (`k >= 1`):
/// [`capture_shapes`] with the thread's phase prefix set to `k` for the
/// duration of `build`, so each phase's rows per table are the difference
/// between consecutive prefixes (`examples/exp_operator.rs`). The build is
/// stopped after `get_airs_and_degrees_with_prep` like every shapes-only
/// probe; a prefix circuit is never constructed.
pub fn capture_prefix_shapes<R>(k: usize, build: impl FnOnce() -> R) -> Result<Vec<CircuitShape>, String> {
    assert!(k >= 1, "capture_prefix_shapes: the prefix needs at least phase 1 (bind)");
    let prev = PHASE_LIMIT.replace(k);
    let res = capture_shapes(build);
    PHASE_LIMIT.set(prev);
    res
}

/// Builder hook after [`maybe_stop`]: a phase-limited build that was not
/// stopped must never become a circuit.
pub fn assert_full_circuit(site: &str) {
    assert!(
        phase_limit() == usize::MAX,
        "{site}: a phase-limited (prefix) circuit is for shapes-only probing and must not be built or proved"
    );
}

/// Drain this thread's recorded shapes.
pub fn take() -> Vec<CircuitShape> {
    LOG.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

/// Restores the thread's flags when a capture ends (also on unwind).
struct Flags {
    armed: bool,
    stop: bool,
}

impl Flags {
    fn set(armed: bool, stop: bool) -> Self {
        let prev = Self { armed: ARMED.get(), stop: STOP.get() };
        ARMED.set(armed);
        STOP.set(stop);
        prev
    }
}

impl Drop for Flags {
    fn drop(&mut self) {
        ARMED.set(self.armed);
        STOP.set(self.stop);
    }
}

/// Run `f` with the recorder armed on this thread; returns its result and
/// the shapes of every circuit built meanwhile. Panics propagate.
pub fn capture<R>(f: impl FnOnce() -> R) -> (R, Vec<CircuitShape>) {
    let _ = take();
    let flags = Flags::set(true, STOP.get());
    let out = f();
    drop(flags);
    (out, take())
}

/// Run `build` with every builder stopped right after its shapes are
/// recorded (no preprocessed commit, no proving). `Ok` with the shapes when
/// the builder stopped or `build` returned; `Err` with the message of any
/// other panic. Pair with [`quiet_shapes_only_panics`] to keep the stops off
/// stderr.
pub fn capture_shapes<R>(build: impl FnOnce() -> R) -> Result<Vec<CircuitShape>, String> {
    let _ = take();
    let flags = Flags::set(true, true);
    let res = catch_unwind(AssertUnwindSafe(build));
    drop(flags);
    let shapes = take();
    match res {
        Ok(_) => Ok(shapes),
        Err(e) if e.is::<ShapesOnly>() => Ok(shapes),
        Err(e) => Err(e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic".into())),
    }
}

/// Install (once) a panic hook that stays silent for [`ShapesOnly`] stops and
/// defers to the previous hook for every other panic.
pub fn quiet_shapes_only_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info.payload().is::<ShapesOnly>() {
                prev(info);
            }
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sketch::bind::Binding;
    use crate::sketch::hll_omc::{HllOmcParams, build_hll_omc_leaf_expose};
    use crate::recursion::recursive::statement::Expose;

    #[test]
    fn ceilings() {
        assert_eq!(LOG_CEILING_NONHIDING, 25);
        assert_eq!(LOG_CEILING_HIDING, 24);
    }

    fn table(log_h: usize, lq: Option<(usize, usize)>) -> TableShape {
        let rows = (1usize << log_h) - 5;
        TableShape { idx: 0, name: "alu".into(), log_h, rows, width: 1, prep_width: 1, lq, consistent: true }
    }

    /// The ceiling tracks the recorded quotient-chunk count: a degree >= 5
    /// AIR (`lq_zk = 3`) has a `2^(log_h + 4)` hiding quotient domain, so a
    /// 2^24 table no longer fits although `log_h <= LOG_CEILING_HIDING`.
    #[test]
    fn ceiling_tracks_quotient_chunks() {
        let t = table(24, None);
        assert_eq!((t.log_ceiling(false), t.log_ceiling(true)), (25, 24));
        assert!(t.fits_hiding() && t.fits_nonhiding());
        assert!(table(24, Some((1, 2))).fits_hiding());
        assert_eq!(table(24, Some((1, 2))).headroom_hiding(), 5);

        let deg5 = table(24, Some((2, 3)));
        assert_eq!((deg5.log_ceiling(false), deg5.log_ceiling(true)), (25, 23));
        assert!(!deg5.fits_hiding());
        assert!(deg5.fits_nonhiding());
        assert_eq!(deg5.headroom_hiding(), (1i64 << 23) - deg5.rows as i64);
        assert!(deg5.headroom_hiding() < 0);
        assert!(!table(25, Some((3, 3))).fits_nonhiding());
        assert!(table(23, Some((2, 3))).fits_hiding());

        // A shorter table with a larger `lq` decides the circuit.
        let mut small = table(23, Some((3, 4)));
        small.idx = 1;
        assert_eq!(small.log_ceiling(true), 22);
        let shape = CircuitShape { site: "merge", tables: vec![table(24, Some((1, 2))), small] };
        assert_eq!(shape.max_log_h(), 24);
        assert!(shape.tables[0].fits_hiding());
        assert!(!shape.fits_hiding());
        assert!(shape.fits_nonhiding());
    }

    #[test]
    fn npo_order_ranks() {
        assert_eq!(npo_rank("poseidon2_perm/baby_bear_d4_w16", LEAF_NPO_ORDER), 0);
        assert_eq!(npo_rank("recompose", LEAF_NPO_ORDER), 1);
        assert_eq!(npo_rank("recompose/coeff", LEAF_NPO_ORDER), 2);
        assert_eq!(npo_rank("range", LEAF_NPO_ORDER), 4);
        assert_eq!(npo_rank("expose", MERGE_NPO_ORDER), 4);
        assert_eq!(npo_rank("unknown", LEAF_NPO_ORDER), LEAF_NPO_ORDER.len());
    }

    /// Unarmed, the hooks record nothing and a leaf builds as before; a
    /// shapes-only capture stops the same builder with consistent shapes
    /// that agree with the full build's per-table heights.
    #[test]
    fn capture_matches_full_build() {
        let params = HllOmcParams { b: 4, batch: 4 };
        let leaf = build_hll_omc_leaf_expose(params, Expose::Interval, Binding::Semantic);
        assert!(take().is_empty(), "an unarmed build must not record");

        quiet_shapes_only_panics();
        let shapes = capture_shapes(|| {
            build_hll_omc_leaf_expose(params, Expose::Interval, Binding::Semantic)
        })
        .expect("shapes-only build");
        assert_eq!(shapes.len(), 1);
        let shape = &shapes[0];
        assert_eq!(shape.site, "hll_omc");
        assert!(shape.consistent(), "{}", summary(shape));
        // `table_rows()` are ZK-extended heights.
        let is_zk = usize::from(cfg!(feature = "zk"));
        let heights: Vec<usize> =
            shape.tables.iter().map(|t| (t.padded() as usize) << is_zk).collect();
        assert_eq!(heights, leaf.table_rows());
        assert_eq!(shape.tables[2].name, "alu");
        assert_eq!(shape.tables.last().unwrap().name, "expose");

        let (_, full) = capture(|| {
            build_hll_omc_leaf_expose(params, Expose::Interval, Binding::Semantic)
        });
        assert_eq!(full.len(), 1);
        assert_eq!(
            full[0].tables.iter().map(|t| (t.log_h, t.rows)).collect::<Vec<_>>(),
            shape.tables.iter().map(|t| (t.log_h, t.rows)).collect::<Vec<_>>()
        );
    }
}
