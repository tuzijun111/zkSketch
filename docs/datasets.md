# Datasets — identical key derivation to S³

To test the four zkSketch circuits on the **same data** S³
([Yu et al. 2026](https://doi.org/10.1145/3802110)) evaluates on, we reproduce
**S³'s exact dataset recipe**, copied from their own data generator
(`mpc4j-work-db-sketch/.../utils/{TestDataGenerator,DataGenerator}.java` in
[alibaba-edu/mpc4j](https://github.com/alibaba-edu/mpc4j), Apache-2.0). S³ uses
`bitLen = 32` (key domain `[2^32]`), `GaussianSTD = 13`, and `mask = 2^32 − 1`.

## What S³ uses (and exactly how we match it)

| Dataset | Kind | S³'s key = | Our source / match |
| ------- | ---- | ---------- | ------------------ |
| **Gaussian** | synthetic | `nextGaussian(μ=2³¹, σ=2¹³)`, clamp ≥2³²→2³¹, ≤0→1 | seeded (`dataset::Synthetic::Gaussian`), **frozen** to `data/gaussian.keys`; **distribution-match** |
| **Uniform** | synthetic | random 32-bit value | seeded (`dataset::Synthetic::Uniform`), **frozen** to `data/uniform.keys`; **distribution-match** |
| **Zipf** | synthetic | (our skew knob for RQ3; S³ uses `DISTINCT`) | seeded (`dataset::zipf_stream(α, …)`), **frozen** to `data/zipf.keys` |
| **AOL** | real | extract first `https?://\S+` (the *ClickURL*) → normalize (lowercase, strip scheme/`www.`/trailing `/`) → `CRC32(norm) & mask` | search-query log → **byte-exact match** |
| **Netflix-Prize** | real | first integer per line `& mask` (= CustomerID) | `nf_prize_dataset.tar` rating lines → **byte-exact match** |

> **Synthetic = distribution-match to S³ (not byte-exact to S³), and that's the
> best possible:** S³ seeds its generator with an unseeded `new Random()` (and
> `SecureRandom`), so even S³'s own synthetic keys aren't reproducible
> run-to-run — only the *distribution* is defined (verified in
> `mpc4j-work-db-sketch/.../utils/{Test,}DataGenerator.java`; callers pass
> `new Random()`). **Ours are fully reproducible:** deterministic in `seed`, and
> additionally **frozen byte-for-byte** into `data/{gaussian,uniform,zipf}.keys`
> (tracked in git — un-ignored, so committing them gives every clone identical
> inputs) — see *Materializing the synthetic datasets* below.
>
> **Real = byte-exact match:** AOL keys use `CRC32` (Java's `java.util.zip.CRC32`
> = the IEEE-802.3 CRC-32 = Python's `zlib.crc32`), so on the same source file
> our keys equal S³'s bit-for-bit. The AOL source is the **search-query log**
> (archive.org `aolsearchdata2006`, the `user-ct-test-collection` files whose
> *ClickURL* column carries the clicked website) — **not** the access-log in the
> mislabelled `AOL-user-ct-collection` item, and **not** FNV-1a. Netflix is the
> Netflix-Prize ratings; the first integer of a rating line is the CustomerID.
>
> Note: the only stream file committed in mpc4j, `data/stream/synthetic_data.dat`,
> belongs to a *different* (DP-streaming) module — **not** S³'s sketches — so we
> do not use it.

## Where the code lives

| Concern | File |
| ------- | ---- |
| Synthetic generators + real/synthetic loaders + per-circuit tests | `src/dataset.rs` |
| Materialize the synthetic datasets (deterministic) | `examples/gen_synthetic.rs` |
| Download + process the real datasets | `scripts/fetch_datasets.py` |
| Synthetic key files (**tracked in git** — un-ignored, commit alongside the code) | `data/gaussian.keys`, `data/uniform.keys`, `data/zipf.keys`, `data/synthetic.manifest.json` |
| Real key files (**tracked in git** — processed 32-bit keys only, not the raw corpora) | `data/aol.keys`, `data/netflix.keys` |

All key files are a flat **little-endian `u32`** stream (4 bytes/key);
`dataset::load_keys` reads `file_len / 4` keys. Loaders: `dataset::{gaussian,
uniform, zipf}()` for the frozen synthetic trio and `dataset::{aol, netflix}()`
for the real pair — each returns `Option<Vec<u32>>` (`None` when absent).

## Materializing the synthetic datasets

The synthetic streams are deterministic in their seed, so the *generator + seed*
already pins them. But the Gaussian/Zipf path uses libm transcendentals
(`ln/cos/sin/powf`) whose last-ULP rounding can differ across platforms/libc, so
to make reproduction **unconditionally byte-exact** we freeze a canonical trio to
disk (Uniform is pure integer ops and bit-portable regardless, but we freeze it
too for uniform treatment). The frozen files are tracked in git (un-ignored, so
they ship with the repo once committed); regenerate any time:

```bash
cargo run --release --example gen_synthetic        # → data/{gaussian,uniform,zipf}.keys + manifest
GEN_SYNTH_N=1000000 cargo run --release --example gen_synthetic   # larger
```

Canonical params (also recorded in `data/synthetic.manifest.json`): `SYNTH_N =
200 000` keys/file; Gaussian seed 1; Uniform seed 2; Zipf `α = 1.0`, universe
`2¹⁶`, seed 1. The generator calls the **same** `dataset::synthetic_stream` /
`zipf_stream` the runners use (one source of truth, no re-implementation drift),
and `dataset::tests::materialized_synthetic_is_prefix_equivalent_when_present`
asserts each frozen file equals the seeded generator's prefix — so loading the
file changes no input, only its cross-machine portability.

> **Reproducibility model.** *Uniform* is byte-identical everywhere by
> construction. *Gaussian/Zipf* are byte-identical when loaded from the committed
> files (the recommended path); if regenerated from source on a different
> platform, they match the distribution and are typically bit-identical but not
> guaranteed at the last ULP — load the frozen files for an exact match. The
> parametric Zipf/Gaussian draws inside the RQ runners (varying `seed`/`universe`
> per call) remain reproducible from code + seed; the committed `zipf.keys` is a
> representative canonical artifact, not every parametric draw.

## Fetching the real datasets

```bash
# both, default cap 2^20 = 1,048,576 keys each (the committed files)
python3 scripts/fetch_datasets.py

# just one, or with a smaller cap
python3 scripts/fetch_datasets.py aol
AOL_MAX_KEYS=200000 NETFLIX_MAX_KEYS=200000 python3 scripts/fetch_datasets.py
python3 scripts/fetch_datasets.py --force        # re-download
```

The script **streams** both sources (the AOL `user-ct-test-collection-01.txt`
and the Netflix `tar.gz`) and aborts once the cap is reached, so only a small
prefix of each multi-hundred-MB corpus is downloaded. Caps keep "a small part"
for testing. If a download fails (network/restriction), the script reports it
and the synthetic datasets still work offline. A processed pair lives in
`data/aol.keys` / `data/netflix.keys` (tracked in git — these are the derived
32-bit key streams, flat LE-`u32`; the raw corpora are not included). Re-run the
script (raise `*_MAX_KEYS`) to refresh or grow them.

## Using the data

```rust
use zksketch::dataset::{self, Synthetic};

// Frozen synthetic files (byte-portable) — prefer these for reproduction:
let gauss = dataset::gaussian();     // Option<Vec<u32>> — Some(..) if materialized
let unif  = dataset::uniform();      // Option<Vec<u32>>
let zipf  = dataset::zipf();         // Option<Vec<u32>>
// In-code fallback (offline, deterministic in seed):
let gauss_gen = dataset::synthetic_stream(Synthetic::Gaussian, 1024, dataset::GAUSSIAN_SEED);
// Real datasets:
let aol   = dataset::aol();          // Option<Vec<u32>> — Some(..) if fetched
let netf  = dataset::netflix();      // Option<Vec<u32>>
let slice = dataset::take(&gauss_gen, 8);   // first 8 keys (one epoch's batch)
```

Each circuit maps a `u32` key into its update type (see `src/dataset.rs`
tests): Count-Min/HLL/SS use the key directly (SS masks to `<2³⁰`, non-zero,
since `0` is its dummy sentinel and the group-by needs field-distinct keys);
GK is a quantile sketch over a numerical attribute, so the key is masked to
the circuit's 20-bit value bound.

## Tests — the four circuits on these datasets

`src/dataset.rs` runs each circuit's round-trip proof on a small slice of
**every available source** (synthetic always; AOL/Netflix when fetched):

```bash
# everything
cargo test --release --lib dataset::

# synthetic determinism + domain check
cargo test --release --lib dataset::tests::synthetic_is_deterministic_and_in_domain

# one circuit across all dataset sources (gaussian, uniform, + aol/netflix if present)
cargo test --release --lib dataset::tests::countmin_on_dataset_slices
cargo test --release --lib dataset::tests::gk_on_dataset_slices
cargo test --release --lib dataset::tests::hll_on_dataset_slices
cargo test --release --lib dataset::tests::ss_on_dataset_slices
```

Each `*_on_dataset_slices` test proves one epoch (batch = 8) per source and
asserts the committed final state matches the natively-recomputed sketch —
i.e. the circuit accepts real/synthetic data end-to-end. With both real
datasets fetched, each runs over 4 sources (2 synthetic + AOL + Netflix);
without them, over the 2 synthetic sources (the real ones are skipped, not
failed).
