//! **E-0** (revision plan): per-table trace heights of every deployed circuit
//! against the hiding row ceiling. Does each family's largest table fit
//! under 2^24 rows (hiding PCS) and 2^25 (non-hiding) at each batch size m?
//!
//! Heights are static functions of the circuit, so nothing is proved: each
//! builder stops right after `get_airs_and_degrees_with_prep`
//! ([`zksketch::experiments::table_probe`]), before the preprocessed commit.
//! Leaf heights are the same under both PCS (a hiding PCS commits
//! `2^(log_h + 1)` rows of each table). Merge heights are NOT: a merge circuit
//! verifies its children's proofs, and under `--features zk` those are hiding
//! proofs (random-codeword openings, the randomization-polynomial round, a
//! doubled FRI domain), so the hiding merge circuit is larger. Every row
//! carries the `pcs` of the build that recorded it; the hiding merges come
//! only from a `--features zk` run. The circuits are the ones the
//! composition harness deploys (`stream_compose`): CM omc, HLL omc, SS
//! certified (`ss_final_full`), GK bandmerge2, plus the Bloom omc leaf, under
//! `composition_expose()` (Interval unless `ZKSKETCH_STATEMENT` says otherwise),
//! `default_binding()` (Semantic unless `ZKSKETCH_BINDING` says otherwise) and
//! `commit_mode_from_env()` (revision B2: `ZKSKETCH_COMMIT=plain|hiding`,
//! unset = Hiding except Plain under `ZKSKETCH_BINDING=legacy`). The four
//! deployed leaves are built with their `*_commit` builders in that mode (a
//! Hiding leaf carries the 9 salt private inputs and the salted commitment
//! sponges); the Bloom leaf has no hiding variant and stays Plain. Every CSV
//! row records the mode its circuit was built in (`commit_mode`).
//!
//! ```bash
//! cargo run --release --example exp_e0                  # 5 families x m in {2^12, 2^13, 2^14}
//! ZKSKETCH_COMMIT=plain cargo run --release --example exp_e0   # the pre-B2 (Plain) leaves
//! ZKSKETCH_BINDING=bound E0_FAMILY=cm,hll cargo run --release --example exp_e0
//! E0_MERGE=1 E0_FAMILY=hll E0_M=4096 cargo run --release --example exp_e0
//! E0_COST=1 cargo run --release --example exp_e0 [--features zk]
//! ```
//!
//! Knobs:
//! * `E0_FAMILY` (`cm,hll,ss,gk,bloom`), `E0_M` (`4096,8192,16384`).
//! * Geometry (paper defaults): `EXP_D`=7, `EXP_W`=16384 (CM), `EXP_HLL_B`=14,
//!   `EXP_SS_CAP`=16384, `EXP_GK_CAP`=2048, `EXP_GK_S`=73, `EXP_BLOOM_K`=7,
//!   `EXP_BLOOM_LOGW`=14.
//! * `E0_QUOTIENT=1`: also record each table's log quotient-chunk count
//!   (non-ZK and ZK).
//! * `E0_PROVE=1`: also build and prove one no-op epoch per cell and check the
//!   proof's per-table `degree_bits == log_h + is_zk` and op types (a Hiding
//!   leaf proves the VK-derivation no-op through `prove_epoch_public_zero`
//!   at batch index 1, the one zero-salt path). It proves
//!   at the probed geometry, so keep m small (GK at m=2^14 needs ~85 GB
//!   non-hiding, ~250 GB hiding).
//! * `E0_MERGE=1`: also probe the merge circuits (cm/hll/ss/gk): prove the
//!   family's no-op leaf at the cell's geometry, then derive the root VK of an
//!   `E0_MERGE_T`-leaf forest (default 8: merge levels L1..L3), recording each
//!   level's real merge circuit. Merge rows report the child's m, and
//!   `variant=hiding_merge` names `expose_forest`'s state-hiding merge
//!   circuit, not the PCS (see `pcs`). `E0_MERGE=only` writes the merge rows
//!   alone (no leaf rows). Run it under `--features zk` for the hiding merges;
//!   the zk leaf it proves first peaks at ~107 GB for CM at m=2^14 and
//!   ~122 GB for GK at m=2^13 (GK at m=2^14: ~250 GB), so probe GK's hiding
//!   merges over m <= 8192 children.
//! * `E0_COST=1`: instead of the probe, measure prove time, peak RSS and proof
//!   bytes of one leaf per family and one merge at a SMALL geometry (CM d=4
//!   w=1024, HLL b=10, SS cap=1024, GK cap=256, Bloom k=7 log_w=10, all at
//!   m=`E0_COST_M`=1024; merge over two CM leaves). Run once per PCS build.
//!   Under Hiding the two merged CM leaves are opened honestly
//!   (`Openings::for_leaf` from `ZKSKETCH_SALT_SEED` or an OS-random seed,
//!   never printed), so leaf 1's final `Com(S_0; ρ_1)` is leaf 2's init.
//!
//! Output (`results/`): `e0_tables.csv` (one row per table), `e0_summary.csv`
//! (one row per circuit), `e0_cost.csv` (`E0_COST`). `m_cross_hiding` is the
//! m at which a straight-line fit of the table's unpadded rows over the
//! probed m values reaches the table's hiding ceiling (min over tables in the
//! summary). That ceiling is 2^24 unless a recorded `lq_zk` exceeds
//! `LOG_BLOWUP` (`TableShape::log_ceiling`); `fits_*` use the same ceilings,
//! and a circuit fits only if every table does.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use p3_circuit_prover::{BatchStarkProof, PrimitiveTable};
use p3_uni_stark::StarkGenericConfig;
use zksketch::commitment::hiding::{CommitFamily, CommitMode, Openings, SaltSeed, commit_mode_from_env};
use zksketch::config::LOG_BLOWUP;
use zksketch::experiments::metrics::{self, BenchCfg, RunOutcome};
use zksketch::experiments::table_probe::{
    self, CircuitShape, LOG_CEILING_HIDING, LOG_CEILING_NONHIDING, TableShape,
};
use zksketch::experiments::{proof_size, results_dir};
use zksketch::recursion::recursive::config::ConfigWithFriParams;
use zksketch::recursion::recursive::expose_forest::{derive_forest_root_vk, prove_hiding_merge_proofs};
use zksketch::recursion::recursive::statement::{Expose, composition_expose};
use zksketch::recursion::recursive::timing;
use zksketch::sketch::Sketch;
use zksketch::sketch::bind::{Binding, default_binding};
use zksketch::sketch::bloom_omc::{BloomOmcLeafCircuit, BloomOmcParams, bloom_empty, build_bloom_omc_leaf};
use zksketch::sketch::countmin::{CountMinParams, CountMinUpdate};
use zksketch::sketch::countmin_omc::{CmOmcLeafCircuit, CmOmcParams, build_countmin_omc_leaf_commit};
use zksketch::sketch::countmin_v9::CountMinV9;
use zksketch::sketch::gk_bandmerge::{Gk2State, Gkb2LeafCircuit, GkbParams, build_gkb2_leaf_commit};
use zksketch::sketch::hll_omc::{
    HllOmcLeafCircuit, HllOmcParams, build_hll_omc_leaf_commit, hll_omc_advance_with, hll_omc_empty,
};
use zksketch::sketch::ss_final_full::{
    SsFullLeafCircuit, SsFullParams, SsFullState, SsFullUpdate, build_ss_full_leaf_commit,
};

type Proof = BatchStarkProof<ConfigWithFriParams>;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(default)
}

fn env_on(key: &str) -> bool {
    std::env::var(key).is_ok_and(|v| v == "1")
}

/// Deployed geometry of each family (the `stream_compose` table's paper values).
#[derive(Clone, Copy, Debug)]
struct Geometry {
    cm_d: usize,
    cm_w: usize,
    hll_b: usize,
    ss_cap: usize,
    gk_cap: usize,
    gk_s: u64,
    bloom_k: usize,
    bloom_log_w: usize,
}

impl Geometry {
    fn from_env() -> Self {
        Self {
            cm_d: env_usize("EXP_D", 7),
            cm_w: env_usize("EXP_W", 1 << 14),
            hll_b: env_usize("EXP_HLL_B", 14),
            ss_cap: env_usize("EXP_SS_CAP", 1 << 14),
            gk_cap: env_usize("EXP_GK_CAP", 1 << 11),
            gk_s: env_usize("EXP_GK_S", 73) as u64,
            bloom_k: env_usize("EXP_BLOOM_K", 7),
            bloom_log_w: env_usize("EXP_BLOOM_LOGW", 14),
        }
    }

    /// The small geometry of the `E0_COST` table.
    fn small() -> Self {
        Self {
            cm_d: 4,
            cm_w: 1024,
            hll_b: 10,
            ss_cap: 1024,
            gk_cap: 256,
            gk_s: env_usize("EXP_GK_S", 73) as u64,
            bloom_k: 7,
            bloom_log_w: 10,
        }
    }

    fn label(&self, fam: &str) -> String {
        match fam {
            "cm" => format!("d={} w={}", self.cm_d, self.cm_w),
            "hll" => format!("b={}", self.hll_b),
            "ss" => format!("cap={}", self.ss_cap),
            "gk" => format!("cap={} s={}", self.gk_cap, self.gk_s),
            "bloom" => format!("k={} log_w={}", self.bloom_k, self.bloom_log_w),
            _ => unreachable!(),
        }
    }
}

fn variant(fam: &str) -> &'static str {
    match fam {
        "cm" | "hll" | "bloom" => "omc",
        "ss" => "certified",
        "gk" => "bandmerge2",
        _ => unreachable!(),
    }
}

/// The commitment mode a family's leaf is built in: the run's mode for the
/// four deployed families, `Plain` for Bloom (no hiding variant).
fn family_mode(fam: &str, mode: CommitMode) -> CommitMode {
    if fam == "bloom" { CommitMode::Plain } else { mode }
}

fn mode_name(mode: CommitMode) -> &'static str {
    match mode {
        CommitMode::Plain => "plain",
        CommitMode::Hiding => "hiding",
    }
}

/// A built deployed leaf of one family.
enum Leaf {
    Cm(CmOmcLeafCircuit, CmOmcParams),
    Hll(HllOmcLeafCircuit, HllOmcParams, Binding),
    Ss(SsFullLeafCircuit, SsFullParams),
    Gk(Gkb2LeafCircuit, GkbParams),
    Bloom(BloomOmcLeafCircuit, BloomOmcParams),
}

impl Leaf {
    /// Build the family's deployed leaf in `mode` (Bloom ignores it). Under
    /// `Plain` these are exactly the pre-B2 `*_expose` builders (which
    /// delegate to the same `*_commit` builders with `CommitMode::Plain`;
    /// GK's used `default_binding()`, which is the run's `binding`).
    fn build(fam: &str, g: &Geometry, m: usize, expose: Expose, binding: Binding, mode: CommitMode) -> Self {
        match fam {
            "cm" => {
                let p = CmOmcParams { d: g.cm_d, w: g.cm_w, batch: m };
                Leaf::Cm(build_countmin_omc_leaf_commit(p, expose, binding, mode), p)
            }
            "hll" => {
                let p = HllOmcParams { b: g.hll_b, batch: m };
                Leaf::Hll(build_hll_omc_leaf_commit(p, expose, binding, mode), p, binding)
            }
            "ss" => {
                let p = SsFullParams { capacity: g.ss_cap, batch: m };
                Leaf::Ss(build_ss_full_leaf_commit(p, expose, mode), p)
            }
            "gk" => {
                let p = GkbParams { capacity: g.gk_cap, batch: m, s: g.gk_s };
                Leaf::Gk(build_gkb2_leaf_commit(p, expose, binding, mode), p)
            }
            "bloom" => {
                let p = BloomOmcParams { k: g.bloom_k, log_w: g.bloom_log_w, batch: m };
                Leaf::Bloom(build_bloom_omc_leaf(p), p)
            }
            _ => panic!("unknown family {fam} (cm|hll|ss|gk|bloom)"),
        }
    }

    /// Prove batch `t` over the family's provable no-op records from a
    /// public state (the `noop_leaf` inputs): `initial == final`, so leaves
    /// at consecutive `t` merge. The circuit, hence the cost, is data-free.
    /// A `Hiding` leaf proves this input through its one zero-salt path,
    /// `prove_epoch_public_zero`, meant for the VK-derivation no-op leaf at
    /// batch index 1 (Count-Min and GK refuse any other index); chained
    /// Hiding leaves use [`Self::prove_chained`].
    fn prove_noop(&mut self, t: u64) -> Proof {
        match self {
            Leaf::Cm(leaf, p) => {
                let state = CountMinV9::new(&CountMinParams { d: p.d, w: p.w });
                let batch = vec![CountMinUpdate { key: 0, value: 0 }; p.batch];
                if leaf.commit_mode().is_hiding() {
                    leaf.prove_epoch_public_zero(t, state, batch).output.0
                } else {
                    leaf.prove_epoch_at(t, state, batch).output.0
                }
            }
            Leaf::Hll(leaf, p, binding) => {
                let mut regs = hll_omc_empty(p.b);
                hll_omc_advance_with(&mut regs, &[1], p.m(), *binding);
                if leaf.commit_mode().is_hiding() {
                    leaf.prove_epoch_public_zero(t, regs, vec![1; p.batch]).output.0
                } else {
                    leaf.prove_epoch_at(t, regs, vec![1; p.batch]).output.0
                }
            }
            Leaf::Ss(leaf, p) => {
                let batch = vec![SsFullUpdate::dummy(); p.batch];
                if leaf.commit_mode().is_hiding() {
                    leaf.prove_epoch_public_zero(t, SsFullState::empty(*p), batch).output.0
                } else {
                    leaf.prove_epoch_at(t, SsFullState::empty(*p), batch).output.0
                }
            }
            Leaf::Gk(leaf, p) => {
                if leaf.commit_mode().is_hiding() {
                    leaf.prove_epoch_public_zero(t, Gk2State::empty(*p), Vec::new()).output.0
                } else {
                    leaf.prove_epoch_at(t, Gk2State::empty(*p), Vec::new()).output.0
                }
            }
            Leaf::Bloom(leaf, p) => leaf.prove_epoch(&bloom_empty(p), &[]).output.0,
        }
    }

    /// Leaf `t` of a chain of no-op batches over the public state, for the
    /// `E0_COST` merge: `Plain` is [`Self::prove_noop`]; a `Hiding` leaf opens
    /// its commitments honestly (`Openings::for_leaf(seed, family, t)`), so
    /// leaf `t`'s final `Com(S_0; ρ_t)` is leaf `t + 1`'s init. `seed` is
    /// required for a `Hiding` leaf only.
    fn prove_chained(&mut self, t: u64, seed: Option<&SaltSeed>) -> Proof {
        let hiding = match self {
            Leaf::Cm(l, _) => l.commit_mode().is_hiding(),
            Leaf::Hll(l, _, _) => l.commit_mode().is_hiding(),
            Leaf::Ss(l, _) => l.commit_mode().is_hiding(),
            Leaf::Gk(l, _) => l.commit_mode().is_hiding(),
            Leaf::Bloom(..) => false,
        };
        if !hiding {
            return self.prove_noop(t);
        }
        let seed = seed.expect("a Hiding leaf needs the prover's salt seed");
        match self {
            Leaf::Cm(leaf, p) => {
                let state = CountMinV9::new(&CountMinParams { d: p.d, w: p.w });
                let batch = vec![CountMinUpdate { key: 0, value: 0 }; p.batch];
                let o = Openings::for_leaf(seed, CommitFamily::CountMin, t);
                leaf.prove_epoch_commit(t, state, batch, &o).output.0
            }
            Leaf::Hll(leaf, p, binding) => {
                let mut regs = hll_omc_empty(p.b);
                hll_omc_advance_with(&mut regs, &[1], p.m(), *binding);
                let o = Openings::for_leaf(seed, CommitFamily::HyperLogLog, t);
                leaf.prove_epoch_commit(t, regs, vec![1; p.batch], &o).output.0
            }
            Leaf::Ss(leaf, p) => {
                let batch = vec![SsFullUpdate::dummy(); p.batch];
                let o = Openings::for_leaf(seed, CommitFamily::SpaceSaving, t);
                leaf.prove_epoch_commit(t, SsFullState::empty(*p), batch, &o).output.0
            }
            Leaf::Gk(leaf, p) => {
                let o = Openings::for_leaf(seed, CommitFamily::GreenwaldKhanna, t);
                leaf.prove_epoch_commit(t, Gk2State::empty(*p), Vec::new(), &o).output.0
            }
            Leaf::Bloom(..) => unreachable!("Bloom has no hiding variant"),
        }
    }
}

/// `git describe` of the checkout the example was built from.
fn commit() -> String {
    std::process::Command::new("git")
        .args(["describe", "--always", "--dirty", "--abbrev=7"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn reset_hwm() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

fn hwm_mb() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|r| r.trim().trim_end_matches("kB").trim().parse::<f64>().ok())
        .map_or(0.0, |kb| kb / 1024.0)
}

/// Least-squares line `rows = a + b·m`; `None` with fewer than two m values.
fn fit(points: &[(usize, usize)]) -> Option<(f64, f64)> {
    if points.len() < 2 {
        return None;
    }
    let n = points.len() as f64;
    let (sx, sy) = points.iter().fold((0.0, 0.0), |(x, y), &(m, r)| (x + m as f64, y + r as f64));
    let (mx, my) = (sx / n, sy / n);
    let sxx: f64 = points.iter().map(|&(m, _)| (m as f64 - mx).powi(2)).sum();
    let sxy: f64 = points.iter().map(|&(m, r)| (m as f64 - mx) * (r as f64 - my)).sum();
    if sxx == 0.0 {
        return None;
    }
    let b = sxy / sxx;
    Some((my - b * mx, b))
}

/// m at which the fitted line reaches `2^log_ceiling` rows (`None` if flat).
fn m_cross((a, b): (f64, f64), log_ceiling: usize) -> Option<f64> {
    (b > 0.0).then(|| ((1u64 << log_ceiling) as f64 - a) / b)
}

fn fmt_opt(x: Option<f64>, prec: usize) -> String {
    x.map_or_else(|| "-".into(), |v| format!("{v:.prec$}"))
}

/// One recorded circuit plus its run metadata.
struct Probe {
    fam: String,
    level: String,
    geometry: String,
    m: usize,
    shape: CircuitShape,
    probe_s: f64,
    hwm_mb: f64,
    proof_check: String,
}

/// Run-wide CSV columns.
struct Ctx {
    commit: String,
    pcs: &'static str,
    binding: Binding,
    statement: Expose,
    /// `ZKSKETCH_COMMIT` (Bloom rows are always `plain`, [`family_mode`]).
    mode: CommitMode,
    is_zk: usize,
}

impl Ctx {
    /// The leading columns of family `fam`'s rows.
    fn prefix(&self, fam: &str) -> Vec<String> {
        vec![
            self.commit.clone(),
            self.pcs.into(),
            format!("{:?}", self.binding).to_lowercase(),
            format!("{:?}", self.statement).to_lowercase(),
            mode_name(family_mode(fam, self.mode)).into(),
        ]
    }
}

const TABLE_HEADER: &[&str] = &[
    "commit", "pcs", "binding", "statement", "commit_mode", "family", "variant", "site", "level", "geometry", "m",
    "table_idx", "table", "log_h", "rows_padded", "rows_unpadded", "fill", "width", "prep_width",
    "lq_nonzk", "lq_zk", "fits_nonhiding", "fits_hiding", "headroom_rows_hiding",
    "rows_per_record", "m_cross_hiding", "consistent",
];

const SUMMARY_HEADER: &[&str] = &[
    "commit", "pcs", "binding", "statement", "commit_mode", "family", "variant", "site", "level", "geometry", "m",
    "tables", "max_log_h", "largest", "max_rows_unpadded", "max_fill", "sum_rows_padded",
    "fits_nonhiding", "fits_hiding", "min_headroom_rows_hiding", "m_cross_hiding",
    "m_cross_table", "consistent", "probe_s", "hwm_mb", "proof_check",
];

fn header(h: &[&str]) -> Vec<String> {
    h.iter().map(|s| s.to_string()).collect()
}

/// Write the rows of one family's probes. Leaf tables get a per-table line
/// fit over the probed m values; merge rows do not (their shape follows the
/// child's proof, not m).
fn write_family(ctx: &Ctx, probes: &[Probe]) {
    let dir = results_dir();
    let mut fits: BTreeMap<(String, String), (f64, f64)> = BTreeMap::new();
    let mut points: BTreeMap<(String, String), Vec<(usize, usize)>> = BTreeMap::new();
    for p in probes.iter().filter(|p| p.level == "leaf") {
        for t in &p.shape.tables {
            points.entry((p.fam.clone(), t.name.clone())).or_default().push((p.m, t.rows));
        }
    }
    for (k, pts) in points {
        if let Some(f) = fit(&pts) {
            fits.insert(k, f);
        }
    }
    for p in probes {
        let leaf = p.level == "leaf";
        let variant = if leaf { variant(&p.fam) } else { "hiding_merge" };
        let mut cross: Option<(f64, &str)> = None;
        let mut min_headroom = i64::MAX;
        for t in &p.shape.tables {
            let f = if leaf { fits.get(&(p.fam.clone(), t.name.clone())).copied() } else { None };
            let mc = f.and_then(|f| m_cross(f, t.log_ceiling(true)));
            if let Some(v) = mc {
                if cross.is_none_or(|(c, _)| v < c) {
                    cross = Some((v, &t.name));
                }
            }
            min_headroom = min_headroom.min(t.headroom_hiding());
            let (lq0, lq1) = t.lq.map_or(("-".into(), "-".into()), |(a, b)| (a.to_string(), b.to_string()));
            let mut row = ctx.prefix(&p.fam);
            row.extend([
                p.fam.clone(),
                variant.into(),
                p.shape.site.into(),
                p.level.clone(),
                p.geometry.clone(),
                p.m.to_string(),
                t.idx.to_string(),
                t.name.clone(),
                t.log_h.to_string(),
                t.padded().to_string(),
                t.rows.to_string(),
                format!("{:.4}", t.fill()),
                t.width.to_string(),
                t.prep_width.to_string(),
                lq0,
                lq1,
                t.fits_nonhiding().to_string(),
                t.fits_hiding().to_string(),
                t.headroom_hiding().to_string(),
                fmt_opt(f.map(|(_, b)| b), 2),
                fmt_opt(mc, 0),
                t.consistent.to_string(),
            ]);
            metrics::append_csv(&dir, "e0_tables", &header(TABLE_HEADER), &row);
        }
        let largest = p.shape.largest();
        let max: &TableShape = largest
            .iter()
            .copied()
            .max_by_key(|t| t.rows)
            .expect("a circuit has tables");
        let mut row = ctx.prefix(&p.fam);
        row.extend([
            p.fam.clone(),
            variant.into(),
            p.shape.site.into(),
            p.level.clone(),
            p.geometry.clone(),
            p.m.to_string(),
            p.shape.tables.len().to_string(),
            p.shape.max_log_h().to_string(),
            largest.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join("+"),
            max.rows.to_string(),
            format!("{:.4}", max.fill()),
            p.shape.sum_padded().to_string(),
            p.shape.fits_nonhiding().to_string(),
            p.shape.fits_hiding().to_string(),
            min_headroom.to_string(),
            fmt_opt(cross.map(|(v, _)| v), 0),
            cross.map_or("-".into(), |(_, n)| n.to_string()),
            p.shape.consistent().to_string(),
            format!("{:.2}", p.probe_s),
            format!("{:.0}", p.hwm_mb),
            p.proof_check.clone(),
        ]);
        metrics::append_csv(&dir, "e0_summary", &header(SUMMARY_HEADER), &row);
    }
}

fn print_probe(ctx: &Ctx, p: &Probe) {
    let s = &p.shape;
    let largest = s.largest();
    println!(
        "E0 fam={} commit_mode={} level={} m={} [{}] max_log_h={} ({}) fill={:.3} sum_padded={} fits_hiding(<=2^{} if lq<={})={} fits_nonhiding(<=2^{})={} consistent={} probe_s={:.1} hwm_mb={:.0} check={}",
        p.fam,
        mode_name(family_mode(&p.fam, ctx.mode)),
        p.level,
        p.m,
        p.geometry,
        s.max_log_h(),
        largest.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join("+"),
        largest.iter().map(|t| t.fill()).fold(0.0, f64::max),
        s.sum_padded(),
        LOG_CEILING_HIDING,
        LOG_BLOWUP,
        s.fits_hiding(),
        LOG_CEILING_NONHIDING,
        s.fits_nonhiding(),
        s.consistent(),
        p.probe_s,
        p.hwm_mb,
        p.proof_check
    );
    println!("{}", table_probe::summary(s));
}

/// Compare a probed shape with a real proof of the same circuit: per-table
/// `degree_bits == log_h + is_zk`, the non-primitive op types, and every
/// table's row count (row differences are reported, not fatal). The proof's
/// Poseidon2 entry reports that table's padded height, so it is compared
/// with `2^log_h`; every other table must match its unpadded rows exactly.
fn check_proof(shape: &CircuitShape, proof: &Proof, is_zk: usize) -> String {
    let db = &proof.proof.degree_bits;
    let probed: Vec<usize> = shape.tables.iter().map(|t| t.log_h + is_zk).collect();
    if *db != probed {
        return format!("MISMATCH degree_bits proof={db:?} probe={probed:?}");
    }
    let n_prim = shape.tables.len() - proof.non_primitives.len();
    let names_ok = proof
        .non_primitives
        .iter()
        .zip(&shape.tables[n_prim..])
        .all(|(e, t)| e.op_type.as_str() == t.name);
    if !names_ok {
        let got: Vec<&str> = proof.non_primitives.iter().map(|e| e.op_type.as_str()).collect();
        return format!("MISMATCH op_types proof={got:?}");
    }
    let mut diffs = Vec::new();
    let packing = &proof.table_packing;
    for t in &shape.tables[..n_prim] {
        let rows = match t.name.as_str() {
            "const" => proof.rows[PrimitiveTable::Const],
            "public" => {
                let ops = proof.rows[PrimitiveTable::Public];
                ops.div_ceil(if ops <= 1 { 1 } else { packing.public_lanes() })
            }
            "alu" => proof.rows[PrimitiveTable::Alu].div_ceil(packing.alu_lanes()),
            other => return format!("MISMATCH primitive table {other}"),
        };
        if rows != t.rows {
            diffs.push(format!("{} {rows}!={}", t.name, t.rows));
        }
    }
    for (e, t) in proof.non_primitives.iter().zip(&shape.tables[n_prim..]) {
        let rows = e.rows.div_ceil(e.lanes.max(1));
        let (want, what) = if t.name.starts_with("poseidon2") {
            (t.padded() as usize, "padded")
        } else {
            (t.rows, "rows")
        };
        if rows != want {
            diffs.push(format!("{} {rows}!={want}({what})", t.name));
        }
    }
    if diffs.is_empty() { "ok".into() } else { format!("ok(rows:{})", diffs.join(";")) }
}

fn probe(ctx: &Ctx, fams: &[String], ms: &[usize], g: &Geometry) {
    let expose = ctx.statement;
    let binding = ctx.binding;
    let mode = ctx.mode;
    let prove = env_on("E0_PROVE");
    let merge_only = std::env::var("E0_MERGE").is_ok_and(|v| v == "only");
    let merge = merge_only || env_on("E0_MERGE");
    let merge_t = env_usize("E0_MERGE_T", 8);
    if merge && ctx.is_zk == 0 {
        println!(
            "E0 note: non-hiding build, so the merge rows describe the NON-ZK merge circuits \
             (they verify non-hiding children); rerun with --features zk for the hiding merges"
        );
    }
    for fam in fams {
        let mut probes = Vec::new();
        for &m in ms {
            reset_hwm();
            let t0 = Instant::now();
            let res = table_probe::capture_shapes(|| Leaf::build(fam, g, m, expose, binding, mode));
            let probe_s = t0.elapsed().as_secs_f64();
            let shape = match res {
                Ok(mut shapes) if shapes.len() == 1 => shapes.remove(0),
                Ok(shapes) => panic!("{fam} m={m}: expected one recorded circuit, got {}", shapes.len()),
                Err(e) => {
                    eprintln!("E0 fam={fam} m={m}: build panicked: {e}");
                    continue;
                }
            };
            let mut p = Probe {
                fam: fam.clone(),
                level: "leaf".into(),
                geometry: g.label(fam),
                m,
                shape,
                probe_s,
                hwm_mb: hwm_mb(),
                proof_check: "-".into(),
            };

            let mut noop: Option<Proof> = None;
            if prove || (merge && fam != "bloom") {
                reset_hwm();
                let t1 = Instant::now();
                let (proof, shapes) = table_probe::capture(|| {
                    let mut leaf = Leaf::build(fam, g, m, expose, binding, mode);
                    leaf.prove_noop(1)
                });
                if prove {
                    p.proof_check = check_proof(&shapes[0], &proof, ctx.is_zk);
                    println!(
                        "E0P fam={fam} m={m} check={} degree_bits={:?} build+prove_s={:.1} hwm_mb={:.0}",
                        p.proof_check,
                        proof.proof.degree_bits,
                        t1.elapsed().as_secs_f64(),
                        hwm_mb()
                    );
                }
                noop = Some(proof);
            }
            if !merge_only {
                print_probe(ctx, &p);
                probes.push(p);
            }

            if let (true, Some(leaf)) = (merge && fam != "bloom", noop) {
                reset_hwm();
                let t2 = Instant::now();
                let (_, shapes) = table_probe::capture(|| derive_forest_root_vk(leaf, merge_t));
                let derive_s = t2.elapsed().as_secs_f64();
                let hwm = hwm_mb();
                for (level, shape) in shapes.into_iter().enumerate() {
                    let mp = Probe {
                        fam: fam.clone(),
                        level: format!("L{}", level + 1),
                        geometry: g.label(fam),
                        m,
                        shape,
                        probe_s: derive_s,
                        hwm_mb: hwm,
                        proof_check: "-".into(),
                    };
                    print_probe(ctx, &mp);
                    probes.push(mp);
                }
            }
        }
        write_family(ctx, &probes);
    }
}

const COST_HEADER: &[&str] = &[
    "commit", "pcs", "binding", "statement", "commit_mode", "family", "circuit", "geometry", "m", "build_s",
    "witness_ms", "prove_ms", "verify_ms", "peak_rss_mb", "proof_bytes", "max_degree_bits",
];

fn cost_row(ctx: &Ctx, fam: &str, circuit: &str, geometry: &str, m: usize, build_s: f64, run: impl FnMut() -> (RunOutcome, usize)) {
    let mut run = run;
    let mut max_db = 0;
    let agg = metrics::bench(BenchCfg { warmup: 1, trials: 1 }, || {
        let (out, db) = run();
        max_db = db;
        out
    });
    let mut row = ctx.prefix(fam);
    row.extend([
        fam.into(),
        circuit.into(),
        geometry.into(),
        m.to_string(),
        format!("{build_s:.2}"),
        format!("{:.1}", agg.witness_gen_ms_median),
        format!("{:.1}", agg.prove_ms_median),
        format!("{:.1}", agg.verify_ms_median),
        format!("{:.0}", agg.peak_rss_mb_median),
        agg.proof_size_bytes.to_string(),
        max_db.to_string(),
    ]);
    println!(
        "E0C pcs={} commit_mode={} fam={fam} circuit={circuit} [{geometry}] m={m} build_s={build_s:.1} prove_ms={:.0} peak_rss_mb={:.0} proof_bytes={} max_degree_bits={max_db}",
        ctx.pcs, mode_name(family_mode(fam, ctx.mode)), agg.prove_ms_median, agg.peak_rss_mb_median, agg.proof_size_bytes
    );
    metrics::append_csv(&results_dir(), "e0_cost", &header(COST_HEADER), &row);
}

fn outcome(proof: &Proof, witness: Duration, prove: Duration, verify: Duration) -> (RunOutcome, usize) {
    let out = RunOutcome {
        witness_gen: witness,
        prove,
        verify,
        proof_size_bytes: proof_size(proof) as u64,
        trace_rows: 0,
        num_columns: 1,
    };
    (out, proof.proof.degree_bits.iter().copied().max().unwrap_or(0))
}

/// Indicative cost of the hiding PCS: one no-op leaf epoch per family and
/// one merge, at a small geometry (see the module docs). One warm-up prove,
/// then one measured prove on the same prebuilt leaf.
fn cost(ctx: &Ctx, fams: &[String]) {
    let g = Geometry::small();
    let m = env_usize("E0_COST_M", 1024);
    for fam in fams {
        let t0 = Instant::now();
        let mut leaf = Leaf::build(fam, &g, m, ctx.statement, ctx.binding, ctx.mode);
        let build_s = t0.elapsed().as_secs_f64();
        cost_row(ctx, fam, "leaf", &g.label(fam), m, build_s, || {
            let proof = leaf.prove_noop(1);
            let tm = timing::take();
            outcome(&proof, tm.witness, tm.prove, tm.verify)
        });
    }
    // One merge over two adjacent CM no-op leaves (t = 1, 2); Hiding leaves
    // are opened honestly so that they chain ([`Leaf::prove_chained`]).
    let mut leaf = Leaf::build("cm", &g, m, ctx.statement, ctx.binding, ctx.mode);
    let seed = ctx.mode.is_hiding().then(|| SaltSeed::from_env().unwrap_or_else(SaltSeed::os_random));
    let (left, right) = (leaf.prove_chained(1, seed.as_ref()), leaf.prove_chained(2, seed.as_ref()));
    cost_row(ctx, "cm", "merge", &g.label("cm"), m, 0.0, || {
        let t = Instant::now();
        let merged = prove_hiding_merge_proofs(&left, &right);
        outcome(&merged.0, Duration::ZERO, t.elapsed(), Duration::ZERO)
    });
}

fn main() {
    let fams: Vec<String> = std::env::var("E0_FAMILY")
        .unwrap_or_else(|_| "cm,hll,ss,gk,bloom".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let ms: Vec<usize> = std::env::var("E0_M")
        .unwrap_or_else(|_| "4096,8192,16384".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let is_zk = zksketch::config::make_config(6).is_zk();
    let ctx = Ctx {
        commit: commit(),
        pcs: if is_zk == 1 { "hiding" } else { "nonhiding" },
        binding: default_binding(),
        statement: composition_expose(),
        mode: commit_mode_from_env(),
        is_zk,
    };
    println!(
        "E0 commit={} pcs={} binding={:?} statement={:?} commit_mode={} (bloom: plain) families={fams:?} m={ms:?}",
        ctx.commit,
        ctx.pcs,
        ctx.binding,
        ctx.statement,
        mode_name(ctx.mode)
    );
    table_probe::quiet_shapes_only_panics();
    if env_on("E0_COST") {
        cost(&ctx, &fams);
    } else {
        let g = Geometry::from_env();
        println!("geometry {g:?}");
        probe(&ctx, &fams, &ms, &g);
    }
}
