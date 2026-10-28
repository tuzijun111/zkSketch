//! Resident set between forest proofs stays flat with malloc_trim and bare peaks (glibc only).
//! Run: cargo test --release --test m0_rss_trim -- --nocapture

use zksketch::experiments::metrics::{read_vmrss_kb, trim_heap_now};
use zksketch::recursion::recursive::expose_forest::{ForestCascade, MergeCache};
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
        let entries = forest.merge_cache().map_or(0, |c| c.len());
        println!(
            "M0RSS {label} t={t} merges={merges} rss_mb={r:.0} peaks_hold_prover_data={} \
             holds_prover_data={} cache_entries={entries}",
            forest.peaks_hold_prover_data(),
            forest.holds_prover_data()
        );
        assert!(!forest.peaks_hold_prover_data() || label.starts_with("retain"), "{label}: bare peaks");
        assert!(entries <= 1, "{label}: the cache holds at most its one entry");
        if label.contains("cache") {
            // The first merge (t = 2) fills the one entry; it stays.
            assert_eq!(entries, usize::from(t >= 2), "{label}: one entry from t = 2 on");
            assert_eq!(forest.holds_prover_data(), t >= 2, "{label}: the entry's prover data");
        }
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
    // The default: bare peaks + the one-entry merge cache, trimmed. The entry
    // is filled by the first merge (t = 2) and kept; nothing grows past it.
    let cached = fold(
        ForestCascade::with_options(1, false, Some(MergeCache::new(1))),
        true,
        "bare+cache+trim",
    );
    let (c_base, c_entry) = (cached[0], cached[1]);
    let c_worst = cached[1..].iter().map(|r| r - c_entry).fold(f64::MIN, f64::max);
    println!(
        "M0RSS bare+cache+trim: post-first-leaf {c_base:.0} MiB, one entry {:+.0} MiB (t=2), \
         worst later {c_worst:+.0} MiB over post-first-leaf + entry",
        c_entry - c_base
    );
    // Control: the pre-M0 fold, retaining and untrimmed.
    let old = fold(ForestCascade::retaining(1), false, "retain+notrim");
    let old_worst = old.iter().map(|r| r - old[0]).fold(f64::MIN, f64::max);
    println!("M0RSS retain+notrim: post-first-leaf {:.0} MiB, worst later {old_worst:+.0} MiB", old[0]);
    if cfg!(all(target_os = "linux", target_env = "gnu")) {
        assert!(
            worst <= SLACK_MB,
            "between-proof RSS grew {worst:.0} MiB over the post-first-leaf level (> {SLACK_MB} MiB)"
        );
        assert!(
            c_worst <= SLACK_MB,
            "with the cache, between-proof RSS grew {c_worst:.0} MiB over the post-first-leaf \
             level plus its one entry (> {SLACK_MB} MiB)"
        );
        // Positive control: the pre-M0 fold does creep, by the same measure.
        assert!(old_worst > worst, "control: retaining + untrimmed grew only {old_worst:.0} MiB");
        assert!(old_worst > SLACK_MB, "control: retaining + untrimmed grew only {old_worst:.0} MiB");
    }
}
