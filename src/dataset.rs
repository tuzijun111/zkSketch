//! **Datasets for testing — same as `paper/Streaming_MPC.pdf` §6.2.3.**
//!
//! The Streaming-MPC paper evaluates its sketches on two synthetic
//! distributions and two real datasets, all with 32-bit keys drawn from the
//! domain `[2^32]`. This module reproduces that dataset suite so the four
//! zkSketch circuits can be tested on the **same data**:
//!
//! - **Synthetic** (generated deterministically here, no download):
//!   - [`Synthetic::Gaussian`] — `μ = 2^31`, `σ = 2^13` (the paper's params).
//!   - [`Synthetic::Uniform`] — uniform over `[0, 2^32)`.
//! - **Real** (downloaded + processed by `scripts/fetch_datasets.py` into
//!   `data/<name>.keys`, a flat little-endian `u32` stream):
//!   - [`aol`] — AOL "user-ct-collection" web log; each record's request
//!     URL hashed to a 32-bit key ("hash the website … into 32-bit").
//!   - [`netflix`] — Netflix-Prize ratings; the user-ID number as the key.
//!
//! Synthetic streams always work offline. The real loaders return `None`
//! when the files haven't been fetched, so tests degrade gracefully:
//!
//! ```bash
//! python3 scripts/fetch_datasets.py            # fetch AOL + Netflix
//! AOL_MAX_KEYS=200000 NETFLIX_MAX_KEYS=200000 python3 scripts/fetch_datasets.py
//! ```
//!
//! Per the goal, the four-circuit tests consume only a **small slice**
//! ([`take`]) of a dataset — enough to exercise one proving epoch.

use std::path::PathBuf;

/// The two synthetic distributions from §6.2.3.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Synthetic {
    /// `μ = 2^31`, `σ = 2^13`.
    Gaussian,
    /// Uniform over `[0, 2^32)`.
    Uniform,
}

/// SplitMix64 — a tiny, dependency-free, deterministic PRNG. Same seed ⇒
/// same stream, so dataset-driven tests are reproducible.
#[inline]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Generate `n` 32-bit keys from a synthetic distribution (deterministic in
/// `seed`). Keys land in `[0, 2^32)`, the `[2^32]` domain S³ uses.
///
/// Matches S³'s `DataGenerator`/`TestDataGenerator` (mpc4j, Apache-2.0):
/// **Gaussian** = `nextGaussian(μ=2^31, σ=2^13)` with the same clamp
/// (`bitLen=32`, `GaussianSTD=13`); **Uniform** = a random 32-bit value.
/// We match S³ at the *distribution* level (S³ seeds with an unseeded
/// `new Random()`, so even their own synthetic keys aren't reproducible
/// run-to-run); ours are deterministic in `seed`. The real AOL/Netflix
/// streams, by contrast, match S³ byte-for-byte (see `scripts/fetch_datasets.py`).
pub fn synthetic_stream(dist: Synthetic, n: usize, seed: u64) -> Vec<u32> {
    let mut s = seed ^ 0xD1B5_4A32_D192_ED03;
    let mut out = Vec::with_capacity(n);
    match dist {
        Synthetic::Uniform => {
            for _ in 0..n {
                out.push((splitmix64(&mut s) & 0xFFFF_FFFF) as u32);
            }
        }
        Synthetic::Gaussian => {
            // Box–Muller from two uniforms in (0,1); scale to μ=2^31, σ=2^13.
            let mu = (1u64 << 31) as f64;
            let sigma = (1u64 << 13) as f64;
            while out.len() < n {
                let u1 = ((splitmix64(&mut s) >> 11) as f64 + 1.0) / ((1u64 << 53) as f64 + 2.0);
                let u2 = ((splitmix64(&mut s) >> 11) as f64) / ((1u64 << 53) as f64);
                let r = (-2.0 * u1.ln()).sqrt();
                let z0 = r * (2.0 * std::f64::consts::PI * u2).cos();
                let z1 = r * (2.0 * std::f64::consts::PI * u2).sin();
                for z in [z0, z1] {
                    let v = mu + sigma * z;
                    // S³'s clamp (genGaussianData): values ≥ 2^32 → 2^31,
                    // values ≤ 0 → 1; otherwise truncate toward zero like
                    // Java's `(long)` cast. (For μ=2^31, σ=2^13 the clamp
                    // essentially never fires — it's 2^18 σ to either edge.)
                    let k: u32 = if v >= 4_294_967_296.0 {
                        1u32 << 31
                    } else if v <= 0.0 {
                        1
                    } else {
                        v as u32
                    };
                    out.push(k);
                    if out.len() == n {
                        break;
                    }
                }
            }
        }
    }
    out
}

/// Generate `n` keys from a **Zipf(`alpha`)** distribution over a universe of
/// `universe` distinct keys (paper §6.2.3 / RQ3: the controllable collision
/// knob the fixed-distribution datasets cannot provide). Rank `r ∈ [1,
/// universe]` is drawn with probability `∝ 1/r^alpha`, then mapped to a
/// spread-out 32-bit key. `alpha = 0` degenerates to uniform-over-universe;
/// larger `alpha` concentrates mass on a few heavy hitters (more duplicates,
/// fewer realised distinct keys). Deterministic in `seed`.
///
/// The realised distinct-key count `u ≤ universe` falls as `alpha` rises —
/// this is exactly the `u` that a skew-aware deployment measures to provision
/// `u_max` for the hash-once-per-distinct-key optimisation (Appendix HLL-opt).
pub fn zipf_stream(alpha: f64, universe: usize, n: usize, seed: u64) -> Vec<u32> {
    assert!(universe >= 1, "universe must be ≥ 1");
    // Cumulative weights over ranks 1..=universe with weight 1/r^alpha.
    let mut cum = Vec::with_capacity(universe);
    let mut total = 0.0f64;
    for r in 1..=universe {
        total += 1.0 / (r as f64).powf(alpha);
        cum.push(total);
    }
    // Map a rank to a 32-bit key, spread across the domain (so heavy hitters
    // are not just 1,2,3,…; the mixing is a bijection on the low bits).
    let key_of_rank = |rank: usize| -> u32 {
        (((rank as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) >> 24) as u32
    };
    let mut s = seed ^ 0x5DEE_CE66_D1B5_4A32;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        // u ~ Uniform(0, total).
        let u = (splitmix64(&mut s) >> 11) as f64 / ((1u64 << 53) as f64) * total;
        // First rank whose cumulative weight ≥ u (binary search).
        let idx = match cum.binary_search_by(|w| w.partial_cmp(&u).unwrap()) {
            Ok(i) => i,
            Err(i) => i.min(universe - 1),
        };
        out.push(key_of_rank(idx + 1));
    }
    out
}

/// `data/<name>.keys` path under the crate root.
fn keys_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data").join(format!("{name}.keys"))
}

/// Load a real dataset's processed key stream (flat little-endian `u32`),
/// or `None` if `scripts/fetch_datasets.py` hasn't produced it yet.
pub fn load_keys(name: &str) -> Option<Vec<u32>> {
    let bytes = std::fs::read(keys_path(name)).ok()?;
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    )
}

/// AOL "user-ct-collection" keys (request URLs hashed to 32-bit), if fetched.
pub fn aol() -> Option<Vec<u32>> {
    load_keys("aol")
}

/// Netflix-Prize keys (user IDs), if fetched.
pub fn netflix() -> Option<Vec<u32>> {
    load_keys("netflix")
}

// ─── Canonical *materialized* synthetic datasets ──────────────────────────
//
// The synthetic streams are deterministic in their seed, so storing them is not
// strictly required — but the Gaussian/Zipf path uses libm transcendentals
// (`ln/cos/sin/powf`) whose last-ULP rounding can differ across platforms/libc,
// so a *frozen* copy is the only way to guarantee byte-identical inputs on every
// machine (Uniform is pure integer ops and is already bit-portable). We freeze a
// canonical trio into `data/<name>.keys`, beside the real `aol.keys`/`netflix.keys`,
// via `examples/gen_synthetic.rs`, which calls the SAME generators below — one
// source of truth, no re-implementation drift. The loaders mirror `aol()`/
// `netflix()` and return `None` when the files are absent, so the in-code
// generators remain the offline fallback (per the "keep baselines" rule).

/// Canonical length of a materialized synthetic stream — matches the real
/// datasets' default cap, so each is a drop-in sibling of `aol.keys`/`netflix.keys`.
pub const SYNTH_N: usize = 200_000;
/// Canonical seed for the materialized **Gaussian** stream.
pub const GAUSSIAN_SEED: u64 = 1;
/// Canonical seed for the materialized **Uniform** stream.
pub const UNIFORM_SEED: u64 = 2;
/// Canonical skew for the materialized **Zipf** stream.
pub const ZIPF_ALPHA: f64 = 1.0;
/// Canonical universe size for the materialized **Zipf** stream.
pub const ZIPF_UNIVERSE: usize = 1 << 16;
/// Canonical seed for the materialized **Zipf** stream.
pub const ZIPF_SEED: u64 = 1;

/// Build a canonical synthetic stream of `n` keys by name
/// (`"gaussian" | "uniform" | "zipf"`) at the documented canonical seeds/params.
/// This is what `examples/gen_synthetic.rs` freezes to disk, and what the
/// prefix-equivalence test checks the frozen files against.
pub fn canonical_stream(name: &str, n: usize) -> Option<Vec<u32>> {
    match name {
        "gaussian" => Some(synthetic_stream(Synthetic::Gaussian, n, GAUSSIAN_SEED)),
        "uniform" => Some(synthetic_stream(Synthetic::Uniform, n, UNIFORM_SEED)),
        "zipf" => Some(zipf_stream(ZIPF_ALPHA, ZIPF_UNIVERSE, n, ZIPF_SEED)),
        _ => None,
    }
}

/// Write a key stream to `data/<name>.keys` as a flat little-endian `u32` stream
/// (the exact format the real loaders read). Returns the path written.
pub fn write_keys(name: &str, keys: &[u32]) -> std::io::Result<PathBuf> {
    let path = keys_path(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = Vec::with_capacity(keys.len() * 4);
    for &k in keys {
        bytes.extend_from_slice(&k.to_le_bytes());
    }
    std::fs::write(&path, &bytes)?;
    Ok(path)
}

/// Materialized canonical **Gaussian** stream (`data/gaussian.keys`), if present.
pub fn gaussian() -> Option<Vec<u32>> {
    load_keys("gaussian")
}
/// Materialized canonical **Uniform** stream (`data/uniform.keys`), if present.
pub fn uniform() -> Option<Vec<u32>> {
    load_keys("uniform")
}
/// Materialized canonical **Zipf** stream (`data/zipf.keys`), if present.
pub fn zipf() -> Option<Vec<u32>> {
    load_keys("zipf")
}

/// The "small part of the dataset" the circuit tests use: the first `k`
/// keys (or all, if fewer).
pub fn take(keys: &[u32], k: usize) -> Vec<u32> {
    keys[..k.min(keys.len())].to_vec()
}

// ─── Tests: feed small dataset slices into the four circuits ──────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_is_deterministic_and_in_domain() {
        let a = synthetic_stream(Synthetic::Gaussian, 1000, 7);
        let b = synthetic_stream(Synthetic::Gaussian, 1000, 7);
        assert_eq!(a, b, "same seed ⇒ same stream");
        let c = synthetic_stream(Synthetic::Uniform, 1000, 7);
        assert_ne!(a, c, "different distribution ⇒ different stream");
        // Gaussian mass concentrates near μ = 2^31 (within a few σ).
        let mu = 1u64 << 31;
        let near = a.iter().filter(|&&k| (k as i64 - mu as i64).unsigned_abs() < (1 << 17)).count();
        assert!(near > 900, "Gaussian should concentrate near μ; got {near}/1000");
    }

    #[test]
    fn zipf_is_deterministic_and_skews_with_alpha() {
        let universe = 256;
        let a = zipf_stream(1.0, universe, 2000, 7);
        let b = zipf_stream(1.0, universe, 2000, 7);
        assert_eq!(a, b, "same seed ⇒ same stream");
        // Realised distinct-key count falls as skew rises.
        let distinct = |ks: &[u32]| ks.iter().copied().collect::<std::collections::HashSet<_>>().len();
        let flat = distinct(&zipf_stream(0.0, universe, 2000, 1));
        let skewed = distinct(&zipf_stream(2.0, universe, 2000, 1));
        assert!(
            skewed < flat,
            "higher alpha ⇒ fewer distinct keys: flat={flat}, skewed={skewed}"
        );
        // Heaviest hitter takes a larger share under more skew.
        let max_share = |alpha: f64| {
            let ks = zipf_stream(alpha, universe, 2000, 2);
            let mut counts = std::collections::HashMap::new();
            for k in ks {
                *counts.entry(k).or_insert(0u32) += 1;
            }
            *counts.values().max().unwrap()
        };
        assert!(max_share(2.0) > max_share(0.0), "skew concentrates a heavy hitter");
    }

    #[test]
    fn real_loaders_are_well_formed_when_present() {
        for (name, loader) in [("aol", aol as fn() -> Option<Vec<u32>>), ("netflix", netflix)] {
            match loader() {
                Some(keys) => {
                    assert!(!keys.is_empty(), "{name}: non-empty when present");
                    println!("dataset {name}: {} keys loaded", keys.len());
                }
                None => println!("dataset {name}: not fetched (run scripts/fetch_datasets.py)"),
            }
        }
    }

    // Each circuit consumes a small slice (= one epoch's batch). We test on
    // the synthetic distributions always, and on the real datasets when
    // they've been fetched.

    /// All key-sources to drive a circuit test on a `batch`-sized slice:
    /// the two synthetic distributions plus any fetched real datasets.
    ///
    /// The synthetic slices prefer the **frozen** `data/{gaussian,uniform}.keys`
    /// (byte-portable across platforms) and fall back to in-code generation at
    /// the canonical seeds when the files haven't been materialized. The two are
    /// byte-identical by construction (the file is the canonical seeded stream),
    /// so this changes no test input — only its portability.
    fn sources(batch: usize) -> Vec<(String, Vec<u32>)> {
        let gauss = match gaussian() {
            Some(k) if k.len() >= batch => take(&k, batch),
            _ => take(&synthetic_stream(Synthetic::Gaussian, batch, GAUSSIAN_SEED), batch),
        };
        let unif = match uniform() {
            Some(k) if k.len() >= batch => take(&k, batch),
            _ => take(&synthetic_stream(Synthetic::Uniform, batch, UNIFORM_SEED), batch),
        };
        let mut v: Vec<(String, Vec<u32>)> = vec![
            ("gaussian".into(), gauss),
            ("uniform".into(), unif),
        ];
        if let Some(k) = aol() {
            v.push(("aol".into(), take(&k, batch)));
        }
        if let Some(k) = netflix() {
            v.push(("netflix".into(), take(&k, batch)));
        }
        v
    }

    #[test]
    fn materialized_synthetic_is_prefix_equivalent_when_present() {
        // If the frozen files exist, their prefix must equal in-code generation
        // at the canonical seed — proof that the file is a faithful frozen copy
        // and that loading it (rather than generating) changes no downstream
        // bytes. If absent, the test is a no-op (run `gen_synthetic` to create).
        for name in ["gaussian", "uniform", "zipf"] {
            let loaded = match name {
                "gaussian" => gaussian(),
                "uniform" => uniform(),
                "zipf" => zipf(),
                _ => None,
            };
            match loaded {
                Some(k) => {
                    let n = 1000.min(k.len());
                    assert_eq!(
                        &k[..n],
                        &canonical_stream(name, n).unwrap()[..n],
                        "{name}.keys must be the canonical seeded stream's prefix"
                    );
                    println!("dataset {name}: {} frozen keys, prefix matches generator", k.len());
                }
                None => println!(
                    "dataset {name}: not materialized (run: cargo run --release --example gen_synthetic)"
                ),
            }
        }
    }

    #[test]
    fn countmin_on_dataset_slices() {
        use crate::commitment::countmin::commit_countmin;
        use crate::sketch::countmin::CountMinUpdate;
        use crate::sketch::countmin_final::{CountMinFinalParams, generate_proof};
        let params = CountMinFinalParams { d: 4, w: 8, batch: 8, distinct_bound: 8 };
        for (name, keys) in sources(params.batch) {
            let updates: Vec<CountMinUpdate> =
                keys.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
            let r = generate_proof(params, updates);
            // Round-trips: the committed final state matches the native one.
            assert_eq!(
                commit_countmin(&r.final_state).0,
                r.proof.final_.0,
                "count-min on {name}"
            );
        }
    }

    #[test]
    fn gk_on_dataset_slices() {
        use crate::sketch::gk_final_full::{GKFullParams, GKFullUpdate, commit_gk_state, generate_proof};
        let params = GKFullParams { capacity: 8, batch: 8 };
        for (name, keys) in sources(params.batch) {
            // GK is a quantile sketch over a numerical attribute; map the
            // 32-bit key into the circuit's 20-bit value bound (VALUE_DIFF_BITS).
            let updates: Vec<GKFullUpdate> =
                keys.iter().map(|&k| GKFullUpdate::real(k & 0x000F_FFFF)).collect();
            let r = generate_proof(params, updates);
            assert_eq!(commit_gk_state(&r.final_state).0, r.proof.final_.0, "gk on {name}");
        }
    }

    #[test]
    fn hll_on_dataset_slices() {
        use crate::sketch::hll_final_full::{HllFullParams, HllFullUpdate, commit_hll_state, generate_proof};
        let params = HllFullParams { b: 4, batch: 8 };
        for (name, keys) in sources(params.batch) {
            let updates: Vec<HllFullUpdate> =
                keys.iter().map(|&k| HllFullUpdate::real(k as u64)).collect();
            let r = generate_proof(params, updates);
            assert_eq!(commit_hll_state(&r.final_state).0, r.proof.final_.0, "hll on {name}");
        }
    }

    #[test]
    fn ss_on_dataset_slices() {
        use crate::sketch::ss_final_full::{SsFullParams, SsFullUpdate, commit_ss_state, generate_proof};
        let params = SsFullParams { capacity: 8, batch: 8 };
        for (name, keys) in sources(params.batch) {
            // SS keys: keep < 2^30 and non-zero (0 is the dummy sentinel; the
            // group-by needs distinct keys mod the field).
            let updates: Vec<SsFullUpdate> =
                keys.iter().map(|&k| SsFullUpdate::real(((k & 0x3FFF_FFFF) | 1) as u64, 1)).collect();
            let r = generate_proof(params, updates);
            assert_eq!(commit_ss_state(&r.final_state).0, r.proof.final_.0, "ss on {name}");
        }
    }
}
