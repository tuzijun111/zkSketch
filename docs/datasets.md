# Datasets — same suite as `paper/Streaming_MPC.pdf` §6.2.3

To test the four zkSketch circuits on the **same data** the Streaming-MPC
paper evaluates on, we reproduce its dataset suite: two synthetic
distributions (generated in-process) and two real datasets (downloaded +
processed). All keys are 32-bit, drawn from the domain `[2^32]`.

## What the paper uses (§6.2.3)

| Dataset | Kind | Key = | Our source |
| ------- | ---- | ----- | ---------- |
| **Gaussian** | synthetic | `N(μ=2³¹, σ=2¹³)` clamped to `[0,2³²)` | generated (`dataset::Synthetic::Gaussian`) |
| **Uniform** | synthetic | uniform over `[0,2³²)` | generated (`dataset::Synthetic::Uniform`) |
| **AOL** | real | "hash the website of each record into 32-bit" | `AOL-user-ct-collection` web log → request URL hashed (FNV-1a) to `u32` |
| **Netflix-Prize** | real | "user ID number as input data" | `nf_prize_dataset.tar` → rating-file user IDs |

> AOL note: the archive.org `AOL-user-ct-collection` item serves web **access
> logs** (the original search-query log is privacy-restricted). We hash each
> record's request URL to a 32-bit key, faithful to the paper's "hash the
> website → 32-bit." Document/source URLs are in `scripts/fetch_datasets.py`.

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

The script **streams** the Netflix `tar.gz` and aborts once the cap is
reached, so only a small prefix of the 665 MB corpus is downloaded. Caps
keep "a small part" for testing. If a download fails (network/restriction),
the script reports it and the synthetic datasets still work offline.

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
