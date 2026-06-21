//! Materialize the **canonical synthetic datasets** to `data/*.keys` — the
//! seeded Gaussian / Uniform / Zipf streams frozen as flat little-endian `u32`
//! files, siblings of the real `aol.keys` / `netflix.keys`.
//!
//! Why freeze a *deterministic* generator? The synthetic streams are already
//! reproducible from `(generator, seed)`, but the Gaussian/Zipf path uses libm
//! transcendentals (`ln/cos/sin/powf`) whose last-ULP rounding can differ across
//! platforms/libc. Freezing the bytes guarantees **byte-identical inputs on every
//! machine** — the only fully airtight form of reproducibility. (Uniform is pure
//! integer ops and is bit-portable regardless, but we freeze it too for uniform
//! treatment.) These files use the SAME generators as `src/dataset.rs`, so there
//! is one source of truth and no re-implementation drift.
//!
//! Run:    cargo run --release --example gen_synthetic
//! Config: GEN_SYNTH_N=200000   (keys per file; default = `dataset::SYNTH_N`)
//! Output: data/{gaussian,uniform,zipf}.keys  +  data/synthetic.manifest.json

use std::collections::HashSet;

use zksketch::dataset::{
    canonical_stream, write_keys, GAUSSIAN_SEED, SYNTH_N, UNIFORM_SEED, ZIPF_ALPHA, ZIPF_SEED,
    ZIPF_UNIVERSE,
};

fn main() {
    let n = std::env::var("GEN_SYNTH_N").ok().and_then(|s| s.parse().ok()).unwrap_or(SYNTH_N);
    println!("materializing canonical synthetic datasets ({n} keys each) → data/");

    let specs: [(&str, String); 3] = [
        ("gaussian", format!("Gaussian mu=2^31 sigma=2^13, seed={GAUSSIAN_SEED}")),
        ("uniform", format!("Uniform over [0,2^32), seed={UNIFORM_SEED}")),
        ("zipf", format!("Zipf alpha={ZIPF_ALPHA:?} universe={ZIPF_UNIVERSE}, seed={ZIPF_SEED}")),
    ];

    let mut entries: Vec<(String, String, usize, usize)> = Vec::new();
    for (name, desc) in &specs {
        let keys = canonical_stream(name, n).expect("known synthetic name");
        let path = write_keys(name, &keys).expect("write keys file");
        let distinct = keys.iter().copied().collect::<HashSet<_>>().len();
        println!(
            "  {name:<9} {} keys, {distinct} distinct → {} ({desc})",
            keys.len(),
            path.display()
        );
        entries.push((name.to_string(), desc.clone(), keys.len(), distinct));
    }

    write_manifest(n, &entries);
    println!("done. (regenerate any time; output is deterministic)");
}

/// Write `data/synthetic.manifest.json` — provenance so every frozen file is
/// self-describing (distribution, seed, params, counts, generator command).
fn write_manifest(n: usize, entries: &[(String, String, usize, usize)]) {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data").join("synthetic.manifest.json");
    let files = entries
        .iter()
        .map(|(name, desc, len, distinct)| {
            format!(
                "    {{ \"file\": \"{name}.keys\", \"description\": \"{desc}\", \"keys\": {len}, \"distinct\": {distinct} }}"
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let body = format!(
        "{{\n  \"generator\": \"cargo run --release --example gen_synthetic\",\n  \"source_of_truth\": \"src/dataset.rs (synthetic_stream / zipf_stream)\",\n  \"format\": \"flat little-endian u32 (4 bytes/key)\",\n  \"keys_per_file\": {n},\n  \"seeds\": {{ \"gaussian\": {GAUSSIAN_SEED}, \"uniform\": {UNIFORM_SEED}, \"zipf\": {ZIPF_SEED} }},\n  \"zipf\": {{ \"alpha\": {ZIPF_ALPHA:?}, \"universe\": {ZIPF_UNIVERSE} }},\n  \"files\": [\n{files}\n  ]\n}}\n"
    );
    std::fs::write(&path, body).expect("write manifest");
    println!("  manifest  → {}", path.display());
}
