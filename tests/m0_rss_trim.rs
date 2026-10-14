//! M0 harness memory fix (`EXP_MALLOC_TRIM` + bare forest peaks): while a
//! prover folds a Bentley–Saxe forest, its resident set between proofs
//! returns to within [`SLACK_MB`] of the level right after the first leaf,
//! once freed heap pages are handed back (`malloc_trim(0)`) and the peaks
//! keep bare proofs only (`ForestCascade::with_options(_, false, None)`, the
//! merge cache off: an entry holds a merge's prover data on purpose).
//!
//! A test binary of its own (one test, one process), so no other test's
//! allocations share the measured `VmRSS`:
//!
//! ```bash
//! cargo test --release --test m0_rss_trim -- --nocapture
//! ```
//!
//! glibc only (`malloc_trim`); elsewhere the test only reports.

use zksketch::experiments::metrics::{read_vmrss_kb, trim_heap_now};
use zksketch::recursion::recursive::expose_forest::ForestCascade;
use zksketch::recursion::recursive::statement::Expose;
use zksketch::sketch::Sketch;
use zksketch::sketch::bind::Binding;
use zksketch::sketch::countmin::{CountMinParams, CountMinUpdate};
use zksketch::sketch::countmin_omc::{CmOmcParams, build_countmin_omc_leaf_expose};
use zksketch::sketch::countmin_v9::CountMinV9;

/// Allowed growth of the between-proof `VmRSS` over the post-first-leaf level.
const SLACK_MB: f64 = 200.0;
const LEAVES: u64 = 8;

fn rss_mb() -> f64 {
    read_vmrss_kb().unwrap_or(0) as f64 / 1024.0
}

/// Fold `LEAVES` no-op Count-Min leaves through `forest`; returns the
/// between-proof `VmRSS` after each leaf (after its cascade), in MiB.
fn fold(mut forest: ForestCascade, trim: bool, label: &str) -> Vec<f64> {
    let p = CmOmcParams { d: 2, w: 4, batch: 2 };
    let mut leaf = build_countmin_omc_leaf_expose(p, Expose::Interval, Binding::Semantic);
    let state = CountMinV9::new(&CountMinParams { d: p.d, w: p.w });
    let noop = vec![CountMinUpdate { key: 0, value: 0 }; p.batch];
    let mut rss = Vec::new();
    for t in 1..=LEAVES {
        let out = leaf.prove_epoch_at(t, state.clone(), noop.clone()).output;
        if trim {
            trim_heap_now();
        }
        let merges = forest.push(out);
        if trim {
            trim_heap_now();
        }
        let r = rss_mb();
        println!(
            "M0RSS {label} t={t} merges={merges} rss_mb={r:.0} holds_prover_data={}",
            forest.holds_prover_data()
        );
        rss.push(r);
    }
    let (root, merges) = forest.finalize();
    assert_eq!(merges, 0, "8 leaves are one perfect tree");
    drop(root);
    rss
}

#[test]
fn rss_between_proofs_returns_near_the_first_leaf_level() {
    let trimmed = fold(ForestCascade::with_options(1, false, None), true, "bare+trim");
    let base = trimmed[0];
    let worst = trimmed.iter().map(|r| r - base).fold(f64::MIN, f64::max);
    println!("M0RSS bare+trim: post-first-leaf {base:.0} MiB, worst later {worst:+.0} MiB");
    // Control: the pre-M0 fold, retaining and untrimmed.
    let old = fold(ForestCascade::retaining(1), false, "retain+notrim");
    let old_worst = old.iter().map(|r| r - old[0]).fold(f64::MIN, f64::max);
    println!("M0RSS retain+notrim: post-first-leaf {:.0} MiB, worst later {old_worst:+.0} MiB", old[0]);
    if cfg!(all(target_os = "linux", target_env = "gnu")) {
        assert!(
            worst <= SLACK_MB,
            "between-proof RSS grew {worst:.0} MiB over the post-first-leaf level (> {SLACK_MB} MiB)"
        );
        // Positive control: the pre-M0 fold does creep.
        assert!(old_worst > worst, "control: retaining + untrimmed grew only {old_worst:.0} MiB");
    }
}
