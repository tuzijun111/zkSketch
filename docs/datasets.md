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
| **Gaussian** | synthetic | `nextGaussian(μ=2³¹, σ=2¹³)`, clamp ≥2³²→2³¹, ≤0→1 | generated (`dataset::Synthetic::Gaussian`); **distribution-match** |
| **Uniform** | synthetic | random 32-bit value | generated (`dataset::Synthetic::Uniform`); **distribution-match** |
| **Zipf** | synthetic | (our skew knob for RQ3; S³ uses `DISTINCT`) | generated (`dataset::zipf_stream(α, …)`) |
| **AOL** | real | extract first `https?://\S+` (the *ClickURL*) → normalize (lowercase, strip scheme/`www.`/trailing `/`) → `CRC32(norm) & mask` | search-query log → **byte-exact match** |
| **Netflix-Prize** | real | first integer per line `& mask` (= CustomerID) | `nf_prize_dataset.tar` rating lines → **byte-exact match** |

> **Synthetic = distribution-match (not byte-exact), and that's the best
> possible:** S³ seeds its generator with an unseeded `new Random()`, so even
> S³'s own synthetic keys aren't reproducible run-to-run — only the
> *distribution* is defined. Ours are deterministic in `seed`.
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
| Synthetic generators + real loaders + per-circuit tests | `src/dataset.rs` |
| Download + process the real datasets | `scripts/fetch_datasets.py` |
| Processed key files (git-ignored) | `data/aol.keys`, `data/netflix.keys` |

The processed files are a flat **little-endian `u32`** stream (4 bytes/key);
`dataset::load_keys` reads `file_len / 4` keys.

## Fetching the real datasets

```bash
# both, default cap 1,000,000 keys each
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
`data/aol.keys` / `data/netflix.keys` (git-ignored, flat LE-`u32`).

## Using the data

```rust
use zksketch::dataset::{self, Synthetic};

let gauss = dataset::synthetic_stream(Synthetic::Gaussian, 1024, /*seed*/ 1);
let unif  = dataset::synthetic_stream(Synthetic::Uniform, 1024, 2);
let aol   = dataset::aol();      // Option<Vec<u32>> — Some(..) if fetched
let netf  = dataset::netflix();  // Option<Vec<u32>>
let slice = dataset::take(&gauss, 8);   // first 8 keys (one epoch's batch)
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
