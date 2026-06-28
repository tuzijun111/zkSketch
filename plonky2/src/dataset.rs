//! Datasets for the plonky2 backend — the **same S³ suite** as the plonky3
//! crate (`../src/dataset.rs`), so both stacks run on identical inputs.
//!
//! Synthetic streams are generated here to match S³'s `DataGenerator`
//! (Gaussian μ=2³¹ σ=2¹³ at distribution level; Uniform 32-bit) and a tunable
//! Zipf for skew sweeps. The real AOL/Netflix streams are **shared** with the
//! plonky3 crate: this module reads the same processed key files from the
//! parent repo's `data/` directory (`../data/<name>.keys`, produced by
//! `../scripts/fetch_datasets.py` with S³'s exact CRC32/customer-id recipe), so
//! there is no duplicate download.

use std::path::PathBuf;

/// The two synthetic distributions (Gaussian/Uniform); Zipf has its own fn.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Synthetic {
    Gaussian,
    Uniform,
}

#[inline]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// `n` 32-bit keys from a synthetic distribution (deterministic in `seed`),
/// matching S³'s generator at the distribution level (`bitLen=32`,
/// `GaussianSTD=13`; Gaussian clamp ≥2³²→2³¹, ≤0→1).
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

/// `n` keys from a Zipf(`alpha`) distribution over a `universe` of distinct
/// keys (the RQ3 skew knob). Deterministic in `seed`.
pub fn zipf_stream(alpha: f64, universe: usize, n: usize, seed: u64) -> Vec<u32> {
    assert!(universe >= 1);
    let mut cum = Vec::with_capacity(universe);
    let mut total = 0.0f64;
    for r in 1..=universe {
        total += 1.0 / (r as f64).powf(alpha);
        cum.push(total);
    }
    let key_of_rank = |rank: usize| -> u32 {
        (((rank as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) >> 24) as u32
    };
    let mut s = seed ^ 0x5DEE_CE66_D1B5_4A32;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let u = (splitmix64(&mut s) >> 11) as f64 / ((1u64 << 53) as f64) * total;
        let idx = match cum.binary_search_by(|w| w.partial_cmp(&u).unwrap()) {
            Ok(i) => i,
            Err(i) => i.min(universe - 1),
        };
        out.push(key_of_rank(idx + 1));
    }
    out
}

/// `../data/<name>.keys` — shared with the plonky3 crate (one repo, one
/// processed copy).
fn keys_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("data").join(format!("{name}.keys"))
}

/// Load a real dataset's processed key stream (flat little-endian `u32`), or
/// `None` if not fetched.
pub fn load_keys(name: &str) -> Option<Vec<u32>> {
    let bytes = std::fs::read(keys_path(name)).ok()?;
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    Some(bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
}

/// AOL keys (CRC32 of normalised ClickURL, S³ recipe), if fetched.
pub fn aol() -> Option<Vec<u32>> {
    load_keys("aol")
}

/// Netflix-Prize keys (customer IDs, S³ recipe), if fetched.
pub fn netflix() -> Option<Vec<u32>> {
    load_keys("netflix")
}

/// First `k` keys (or all, if fewer) — the small slice the leaves consume.
pub fn take(keys: &[u32], k: usize) -> Vec<u32> {
    keys[..k.min(keys.len())].to_vec()
}

// ─── Canonical *materialized* synthetic datasets ──────────────────────────
//
// Port of `../src/dataset.rs`'s frozen-synthetic layer. The Gaussian/Zipf paths
// use libm transcendentals (`ln/cos/sin/powf`) whose last-ULP rounding can differ
// across platforms, so a *frozen* copy is the only way to guarantee byte-identical
// inputs everywhere. Because this crate's `keys_path` already points at the shared
// `../data/`, the frozen files are the **same** ones the plonky3 crate freezes —
// both stacks load identical canonical streams. The in-code generators remain the
// offline fallback (per the "keep baselines" rule).

/// Canonical length of a materialized synthetic stream (matches the real
/// datasets' default cap, so each is a drop-in sibling of `aol.keys`/`netflix.keys`).
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
/// (`"gaussian" | "uniform" | "zipf"`) at the documented canonical seeds/params —
/// the single source of truth shared with the plonky3 crate's `gen_synthetic`.
pub fn canonical_stream(name: &str, n: usize) -> Option<Vec<u32>> {
    match name {
        "gaussian" => Some(synthetic_stream(Synthetic::Gaussian, n, GAUSSIAN_SEED)),
        "uniform" => Some(synthetic_stream(Synthetic::Uniform, n, UNIFORM_SEED)),
        "zipf" => Some(zipf_stream(ZIPF_ALPHA, ZIPF_UNIVERSE, n, ZIPF_SEED)),
        _ => None,
    }
}

/// Write a key stream to `../data/<name>.keys` as a flat little-endian `u32`
/// stream (the exact format the real loaders read). Returns the path written.
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

/// Materialized canonical **Gaussian** stream (`../data/gaussian.keys`), if present.
pub fn gaussian() -> Option<Vec<u32>> {
    load_keys("gaussian")
}
/// Materialized canonical **Uniform** stream (`../data/uniform.keys`), if present.
pub fn uniform() -> Option<Vec<u32>> {
    load_keys("uniform")
}
/// Materialized canonical **Zipf** stream (`../data/zipf.keys`), if present.
pub fn zipf() -> Option<Vec<u32>> {
    load_keys("zipf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_deterministic_and_in_domain() {
        let a = synthetic_stream(Synthetic::Gaussian, 1000, 7);
        assert_eq!(a, synthetic_stream(Synthetic::Gaussian, 1000, 7));
        let mu = 1u64 << 31;
        let near = a.iter().filter(|&&k| (k as i64 - mu as i64).unsigned_abs() < (1 << 17)).count();
        assert!(near > 900, "Gaussian concentrates near μ; got {near}/1000");
    }

    #[test]
    fn real_loaders_well_formed_when_present() {
        for (name, ld) in [("aol", aol as fn() -> Option<Vec<u32>>), ("netflix", netflix)] {
            match ld() {
                Some(k) => {
                    assert!(!k.is_empty());
                    println!("dataset {name}: {} keys (shared with plonky3 crate)", k.len());
                }
                None => println!("dataset {name}: not fetched (run ../scripts/fetch_datasets.py)"),
            }
        }
    }

    #[test]
    fn materialized_synthetic_is_prefix_equivalent_when_present() {
        // If the frozen files exist (shared with the plonky3 crate), their prefix
        // must equal in-code generation at the canonical seed. Absent ⇒ no-op.
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
                None => println!("dataset {name}: not materialized (run gen_synthetic)"),
            }
        }
    }
}
