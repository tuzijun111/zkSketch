# Reproducing the zkSketch vs zk-Analytics comparison (six sketches, one machine): full guide

(Moved here from the top-level README on 2026-10-18; the README keeps the short version. The reference numbers and the step-by-step configuration are in [`scripts/baselines/zka/README.md`](../scripts/baselines/zka/README.md), section "Six-sketch comparison (small scale)".)

**What it measures.** zkSketch against zk-Analytics (Zhu et al., "Zero-Knowledge
Cloud Analytics", SIGCOMM '26; a RISC Zero zkVM pipeline, cloned at `d4a5a9a`) on
six sketches: Count-Min (3 x 1024), HyperLogLog (b = 14), SpaceSaving / Misra-Gries
(1,024 counters), Greenwald-Khanna (eps = 1/51), Bloom (7 x 2^14) and KMV
(k = 1,024), over the same AOL records (`data/aol.keys`, tracked in git, so there is
nothing to download). zk-Analytics ships only Count-Min. **For the other five
sketches the zk-Analytics side is our code inside their per-epoch RISC Zero pipeline
(marked † in every table), not zk-Analytics code: plain textbook per-record HLL,
SpaceSaving, Bloom and KMV, and for Greenwald-Khanna zkSketch's own GK algorithm.**
GK is the one sketch where "the same sketch" leaves the algorithm open (zkSketch
certifies a two-sided band-merge batch rule, textbook GK is per-record INSERT /
COMPRESS rebuilt per epoch), so a run puts zkSketch's rule, with zkSketch's capacity,
s and leaf size and the state carried from epoch to epoch, on the zk-Analytics side too
(`scripts/baselines/zka/gk_matched`, `SIX_ZKA_GK=matched`, the default since
2026-10-15): both sides compute the same function and return the same answer, and the GK
comparison prices the same work. Textbook GK stays as a labelled reference
(`SIX_ZKA_GK=textbook`; the committed 2026-10-09 rows are textbook).
Per sketch it reports update proving (per epoch and for the whole stream), query
proving after n = 1, 2, 4, 8 epochs, the verifier's work and bytes to accept one
answer, peak memory, and answers vs exact. Both systems run on the same machine, one
job at a time. zkSketch runs its default build, which is zero-knowledge
(`pcs=hiding`, `logup_mask=on` in its CSV rows); RISC Zero's succinct receipts are
zero-knowledge too.

**zk-Analytics without its unused Merkle root (`noroot`) is the default and the
headline.** As their code ships, every zk-Analytics aggregation proof also builds a
Merkle tree over the sketch's buckets and outputs its root. That root is not part of
zk-Analytics' protocol: in the paper (Section 5.2, Algorithm 2, and Section 5.3) each
epoch publishes the source hash-chain boundaries, its epoch hash-chain values and one
commitment to the whole epoch state, and the query proof opens that one commitment; the
paper never mentions per-bucket roots (its only Merkle mention, in Section 4, says the
data sources commit their logs with hash chains instead of Merkle trees because membership
proofs are not required at that stage). In their code the
roots go into the proof's journal and into an `out_commit` the host stores in its
database, and nothing reads them: no query guest, no verifier, no other code (their
per-bucket inclusion-proof helpers are never called, and a per-key Merkle-proof query mode
exists only as a TODO in their querier). zkSketch commits to its state too
and publishes no such root. So for all six sketches the comparison proves **`zkA
noroot`**: their aggregation guests with only the root work removed (for Count-Min, their
own code minus only the Merkle lines). It holds the same state and gives the same answers
as the guest with the root (the scripts check this on every run). Their shipped Count-Min
guest, roots included, is still proved, as a **reference** only (`zkA shipped CM`, in its
own small table, never the headline), so the numbers can be related to zk-Analytics'
published ones, which include that cost: at 2,048 records per epoch its roots take 11.2M
of its 22.5M cycles (24 segments of 2^20 cycles instead of 12). Query proofs read no
root, so they are proved once. Their code also commits to each epoch state with unsalted
SHA-256 where the paper uses a hiding commitment; we keep the code as is, which favours
zk-Analytics slightly. The knobs: `SIX_ZKA_CM_REF=0` drops the Count-Min
reference; `SIX_ZKA_ROOTS=designed,noroot` (`designed` is a historical name: as their code
ships, root included, not as their paper designs it) gives the earlier two-variant plan (every
aggregation proof also as `designed`: their Count-Min guest unchanged, the five ports with
their samples-pattern root over 64 buckets). The reference numbers committed on
2026-10-09 are a third, mixed variant, `legacy` (details:
[`scripts/baselines/zka/README.md`](../scripts/baselines/zka/README.md), "Root variants of
the zk-Analytics aggregation proofs").

**Machine.** Linux x86_64 with glibc >= 2.34 and the libstdc++ of GCC >= 12 (Ubuntu 22.04+,
Debian 12+, Fedora 37+; NOT RHEL / Rocky / Alma 9 or Amazon Linux 2023, whose GCC 11
libstdc++ cannot run RISC Zero's compiler; `check` tests this); at least
16 GiB RAM for `quick`, and 32 GiB for `full` (its largest process, zkSketch's GK run,
peaks at about 15 GiB with the default circuits, measured 2026-10-19; the pre-M3 GK
circuit needed 59 GiB, hence the 96 GiB this guide asked for until then; `check` accepts
15 / 30 GiB of `MemTotal`, which is what 16 / 32 GiB machines report); about 30 GB of free disk (zk-Analytics builds
~13 GB, `~/.risc0` ~1.8 GB, the Rust toolchain and cargo cache ~1 GB, zkSketch's
`target/` ~0.3 GB; a fresh install measured about 16 GB in all). The paper
configuration runs zkSketch on 32 physical cores; on a smaller machine it uses the
physical cores there are (`SIX_CORES`). The reference numbers come from an AMD
Threadripper PRO 9975WX (32 cores / 64 threads).

**Prerequisites**, once per machine (`run_all.sh check` verifies all of them and
prints the fix for anything missing):

```bash
# 1. System packages (the only step that needs sudo; numactl is optional).
sudo apt-get update
sudo apt-get install -y build-essential git curl ca-certificates python3 procps util-linux diffutils numactl
#    (Fedora 37+: sudo dnf install -y gcc gcc-c++ make git curl ca-certificates python3 procps-ng util-linux diffutils numactl)
# 2. Rust via rustup (distro rustc packages are too old), pinned to the reference
#    toolchain 1.97.1. Any stable >= 1.90 builds (1.99.0 is tested too); with rustup
#    already installed, `rustup toolchain install 1.97.1 --profile minimal && rustup default 1.97.1`.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1
. "$HOME/.cargo/env"
# 3. RISC Zero at the exact versions used (the installer needs rustc from step 2 on PATH).
curl -L https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$PATH"
rzup install rust 1.97.0    # guest toolchain
rzup install r0vm 3.0.6     # prover; the drivers link risc0-zkvm 3.0.6 and accept r0vm 3.0.x only
rzup default rust 1.97.0    # the guests build with rzup's DEFAULT rust. rzup 0.5.0's `install` already makes
rzup default r0vm 3.0.6     # the version the default (also when it was installed before); these two lines are a
                            # safeguard for other rzup versions
```

Tested with rzup 0.5.0 (the installer fetches the latest rzup; `check` reads its
`settings.toml`). The machine needs outbound HTTPS to github.com, crates.io /
static.crates.io, sh.rustup.rs / static.rust-lang.org and risczero.com. Of
`build-essential`, only a C compiler (`cc`) is actually used.

Not needed here: clang / libclang, cmake, protoc, OpenSSL headers, numpy, GNU time,
Docker, the rzup `cpp` toolchain, the plonky2 nightly. Without sudo, steps 2 and 3
are per-user anyway; you then need `cc`, `git`, `curl` and `python3` (>= 3.8,
standard library only) on PATH.

**Run**, from a fresh clone (the scripts work from any directory). If the
repository is private (it is as of 2026-10-12), `git clone` needs your GitHub
credentials: run `gh auth login` first (then `gh repo clone tuzijun111/zkSketch`), clone over SSH
(`git clone git@github.com:tuzijun111/zkSketch.git`), or give a personal access token
as the HTTPS password. Nothing else needs credentials: zk-Analytics and the pinned
Plonky3 / plonky2 forks are public.

```bash
git clone https://github.com/tuzijun111/zkSketch.git
cd zkSketch
scripts/baselines/zka/six/run_all.sh check    # OK / WARN / MISSING per item; exit 1 if anything blocks
scripts/baselines/zka/six/run_all.sh build    # clone zk-Analytics @ d4a5a9a into ~/ext-baselines; build both sides
scripts/baselines/zka/six/run_all.sh quick    # smoke test of the whole pipeline at tiny scale
scripts/baselines/zka/six/run_all.sh full     # the paper configuration
scripts/baselines/zka/six/run_all.sh memmatch # the memory-matched shape of the final GK / Bloom numbers (--quick: smoke test)
```

`run_all.sh assemble <results dir>` re-runs only the tables of a finished run;
`run_all.sh` alone prints the usage. Build in the clone's final location: `exp_compose`
records the repository path at compile time, so after moving or renaming the clone run
`run_all.sh build` again.

What success looks like: `check` ends with `check: ok`; `build` prints about 20 Rust
compiler warnings for the zkSketch library, which are harmless, and ends with every
step `ok`; `quick` exits with status 0 and its last line is `quick: OK in ...`, with
the summary tables above it (the update proofs side by side, the Count-Min reference,
then query proving), followed by the list of result files. With `GATE_WAIT_S=0` (the `quick` default) the `gate failed for <job>: ...
-- running anyway` lines are expected, not errors.

| step | what it does | time | peak RAM | disk |
|---|---|---|---|---|
| `check` | tools and versions, RAM, cores, disk, dataset, builds | seconds | - | - |
| `build` | clones zk-Analytics (5 MB); builds the 7 zk-Analytics-side drivers (their CM, which also embeds the CM `noroot` guest; our † ports, each with its `designed` / `noroot` guest; GK twice: the matched port and the textbook reference) and zkSketch's `exp_compose` | about 7-8 min on the 32-core reference machine, including the first-time download of crates, the pinned forks and zk-Analytics (a cold build with an empty cargo cache took 7 min 16 s, measured before the matched GK driver was added: the six zk-Analytics-side drivers of then 5 min 10 s, `exp_compose` 2 min 5 s); much faster when nothing changed | 1.8 GB for `exp_compose` (zk-Analytics side not measured) | ~13 GB under `$BASELINE_DIR/build`, ~0.3 GB in `target/` |
| `quick` | zkSketch: 7 runs at N = 512 (2 batches of 256). zk-Analytics: executor for all six (`noroot`, plus `designed` for the Count-Min reference and the root-work table), 4 real proofs (`cm:aggr:0:noroot`, `kmv:aggr:0:noroot`, `gk:query:1:<v>`, `bloom:query:1:key:<k>`), the other 24 of 28 planned jobs ESTIMATED (their shipped Count-Min among them: 14 segments of 2^20 cycles at 256 records, about 7 min if proved) | 5-11 min here (2026-10-18, stable GK + packed Bloom defaults: 5 min 27 s in all, zkSketch 3 min 16 s; before M2/M3 9-11 min, zkSketch 6.5-8 min; zk-Analytics executor ~10 s, the 4 proofs ~2 min) | ~9.2 GiB (one r0vm proof; zkSketch runs up to 6.6 GiB today, 8.4 GiB before M2/M3) | < 1 MB |
| `full` | zkSketch: 7 runs at N = 16,384 (8 batches of 2,048). zk-Analytics: executor (`noroot`, plus `designed` for the reference), then 42 proofs: aggregation epochs 0 and 7 of every family as `noroot` (12), queries at n = 1, 2, 4, 8, Bloom with an inserted and an absent key (28), and their shipped Count-Min at epochs 0 and 7 as the reference (2, last) | about 3 h 15 min of running, an ESTIMATE: zkSketch's 7 runs ~15-25 min (extrapolated per leaf and per merge from the 2-batch probe of 2026-10-19 in Notes, 6.1 min for all 7 runs at 2 batches; the reference run's non-ZK build took ~10 min), the zk-Analytics executor ~2 min, and the 42 proofs about 2 h 50 min, from segment counts x ~30 s per segment of 2^20 cycles (the rate of the reference run): the 12 `noroot` aggregation proofs 150 segments (147 x 2^20 padded cycles), ~74 min; the 2 Count-Min reference proofs 48 segments, ~24 min (the same guest took 712 and 713 s in the 2026-10-09 reference run); the 28 queries ~58 min, as in that run (the 74 min uses the textbook GK's segment counts; the matched GK's two noroot aggregation proofs at (2048, 2048) with the default `literal` are about 29.25 + 30.0 x 2^20 padded cycles, against about 13.25 x 2^20 each for textbook GK, so about 17 min more, included in the totals here; its queries open one compact state instead of merging n summaries). Plus the quiet-machine waits (1 h 17 min for 47 jobs in the reference run, so about 1 h 20 min for 49; see Notes). `SIX_ZKA_CM_REF=0`: 40 proofs, about 3 h 5 min in all; `SIX_ZKA_ROOTS=designed,noroot`: 52 proofs (the 12 `designed` ones add 176 segments, ~88 min), about 4 h 30 min | zkSketch GK run ~15 GiB (ZK build, default circuits; see Notes); r0vm ~9.2 GiB per proof; one job at a time | < 100 MB |

`full --dry-run` prints the plan, including the 42 zk-Analytics jobs, and runs
nothing. Times are for the 32-core machine above.

**The memory-matched shape (`memmatch`).** zkSketch proves a batch as one monolithic
leaf in `full`, so its memory grows with the batch (GK at 2,048 records: 59 GiB with the
pre-M3 circuit, ~15 GiB with today's); zk-Analytics splits its proof into 2^20-cycle segments and stays
at ~9.4 GiB. The final GK and Bloom numbers therefore cap zkSketch's memory instead: each
family proves its paper batch (GK 2,048 records, the others 16,384) as one zk-Analytics
epoch and as k zkSketch leaves plus their k - 1 merges in one forest, under 8 GiB
(`scripts/baselines/zka/results/memmatch-20261014`, `20261016-m2`, `20261016-m3`).
`memmatch` runs that shape: the leaf sizes are those reports' (GK capacity 768 with
leaves of 512, k = 4; Bloom, CM and HLL 1,024, k = 16; SS and KMV 4,096, k = 4), the
zk-Analytics side is unchanged (one receipt per epoch; its matched GK applies the epoch as
k `apply_batch2` steps of 512, zkSketch's leaves), and a query follows every zkSketch leaf.
What changes in the tables:

- zkSketch's "1 epoch" is the epoch's k leaves + k - 1 merges: the forest's measured
  makespan (`total_time_ms`) when it is one epoch (T = 1, the default), else
  k x leaf_s + (k - 1) x merge_s with leaf_s = `leafgen_seq_ms` / t and merge_s =
  (`total_time_ms` - `leafgen_seq_ms`) / (t - 1) over the run's t = k x T leaves (the
  memmatch method; merge_s also carries the worker spawn and the per-leaf verifies). Its
  proof is the epoch's live forest peak(s).
- zk-Analytics' query point n (after n epochs) is compared with zkSketch's query after
  leaf n x k, over the same n x epoch records; `jobs.py` reads the GK rank value and the
  Bloom keys there. With k > 1 the inserted Bloom key is named (`bloom:query:<n>:key:<k>`):
  zkSketch probes the first record of leaf n x k, not of epoch n.
- The first table adds the coordinator's peak (zkSketch: `exp_compose`, which derives the
  verifying keys, audits and proves the queries; zk-Analytics: their host driver) and the
  combined peak (the whole process tree at once, VmRSS summed per 0.5 s sample by
  `rss_tree.sh`) next to the prover's; a "zkSketch run shape and memory" table lists per
  family the epoch, k x leaf, the zkSketch circuit variant / GK rounds / shape, the 1-epoch
  time and whether the combined peak is within 8 GiB.
- `six_sketch_comparison.csv` gets the columns `epoch_records`, `zks_leaf_records`,
  `zks_leaves_per_epoch`, `zks_variant`, `zks_gk_rounds`, `zks_shape`,
  `coord_peak_rss_mb` and `combined_peak_rss_mb` (`assemble.py --extended`), so a run
  with `SIX_GK_ROUNDS=sorted` or `SIX_BLOOM_VARIANT=omc` says so in every zkSketch row.

| step | what it does | time | peak RAM | disk |
|---|---|---|---|---|
| `memmatch` | T = 1 epoch per family (`--epochs T` for more): zkSketch 7 runs, CM / HLL / Bloom 16,384 records = 16 leaves of 1,024 + 15 merges, SS / KMV 16,384 = 4 x 4,096 + 3, GK 2,048 = 4 x 512 + 3 at capacity 768; zk-Analytics executor, then 14 proofs: aggregation epoch 0 of every family as `noroot` (6; the matched GK with `--m-sub 512`), queries at n = 1 (7, Bloom with an inserted and an absent key), their shipped Count-Min at epoch 0 (1, last) | about 5 h 30 min of running, an ESTIMATE: the 16,384-record aggregation proofs ~2,500-3,100 s each (85-104 segments of 2^20 cycles x ~30 s; memmatch-20261014), GK ~930 s (31 segments; M3), the queries and zkSketch's 7 runs (~13 min of proving) ~40 min; plus the quiet-machine waits. `--epochs 2`: 28 proofs, about twice that | each zkSketch process < 9 GiB (the M2/M3 shapes: 4.9-5.2 GiB combined for Bloom and GK; HLL's coordinator reaches 8.5 GiB in its query phase); r0vm ~9.4 GiB per proof | < 50 MB |
| `memmatch --quick` | the same pipeline at tiny scale, T = 2: CM / HLL / Bloom epochs of 256 = 2 leaves of 128, SS / KMV 256 = one leaf, GK 512 = 4 x 128 at capacity 384; zk-Analytics executor, 5 real proofs (`SIX_QUICK_PROVE`, as `quick`; `bloom:query:1:key` selects both Bloom queries, since with k > 1 the inserted key is named too), the other 23 of 28 planned jobs ESTIMATED | 8 min 10 s here (2026-10-19, `c9d38fb`, an otherwise idle machine: zkSketch's 7 runs 5 min 48 s, the zk-Analytics executor, query executor and profile 6 s, the 5 proofs 2 min 16 s) | ~9.4 GiB (one r0vm proof) | < 1 MB |

`memmatch` needs no more machine than `quick` (16 GiB RAM). `memmatch --dry-run` prints
the per-family plan (epoch, k x leaf, the exp_compose shape, the zk-Analytics GK's
`--m-sub`) and the job list; `--epochs T` proves T epochs per family
(aggregation epochs 0 and T - 1, queries at the powers of two <= T). The `quick` and
`full` shapes and their outputs are unchanged. The individual scripts take the same shape
from `SIX_M_<FAM>` and `SIX_LEAF` / `SIX_LEAF_<FAM>` (knobs below), and every zkSketch log
records it in a `# shape:` line, which `assemble.py` reads.

**Outputs.** Every `quick` / `full` writes a fresh, git-ignored directory
`results/six/<mode>-<YYYYmmdd-HHMMSS>/`; the run prints its path and the summary
tables at the end.

- `six_sketch_table.md`: all tables, zk-Analytics `noroot` (`zkA`, the headline) next
  to zkSketch (`zkS`), in this order: the update proofs side by side (per sketch:
  proving time for one epoch and for the whole stream, verification time, proof size
  and peak memory, with the ratio zkA / zkS for each); the reference table for their
  shipped Count-Min (`zkA shipped CM (reference)` next to the headline and zkS, with its
  ratio to zkS); update proving (per epoch, and for the whole stream including
  zkSketch's merges); proof bytes on the update side; query proving at each n (query
  proofs are the same for every variant); in `full`, zkSketch's query proving at the n
  zk-Analytics does not prove (n = 3, 5, 6, 7); the verifier's work and bytes to accept one
  answer at each n (n aggregation receipts + 1 query receipt); peak RSS while proving a
  query; the answers next to the exact ones; the per-proof verify protocol (first call /
  median / best of 5, when the run recorded those timings); the zk-Analytics guest profile; and each
  executed variant's root construction and executor cycles (root work = designed -
  noroot). With `SIX_ZKA_ROOTS=designed,noroot` the update-side and accept tables show
  `zkA designed` and `zkA noroot` side by side, with a ratio against each. Ratios are
  zk-Analytics / zkSketch, so above 1 means zkSketch is faster, smaller or lighter. The
  console summary at the end of a run shows the side-by-side table, the Count-Min
  reference and the query-proving table.
- `six_sketch_comparison.csv`: one row per (family, system, root variant,
  operation); `variant` and `root_construction` name the zk-Analytics variant of the
  update and accept rows (`-` on query and zkSketch rows; the Count-Min reference rows
  are `designed`, and their `note` says they are the reference); `provenance` says
  measured, sampled, derived or ESTIMATED, and `detail` says how.
- `manifest.txt` (configuration, commits, tool versions, per-step times),
  `run_all.log` (the console), and the raw files: zkSketch
  `six_zksketch_<tag>.csv/.log` and `six_zksketch_runs.csv`; zk-Analytics
  `six_zka_<family>_exec.csv` + `six_zka_exec.log` (executor; the rows of every
  executed variant, told apart by their `root_variant` column),
  `six_zka_<family>_prove.csv/.log` (proved families only) + `six_zka_jobs.csv`,
  `six_zka_prof_ss.csv` (+ `six_zka_prof_gk.csv` only with `SIX_ZKA_GK=textbook`) + `six_zka_prof.log` (guest profile), `zka_plan.txt`,
  and in `quick` also `six_zka_<family>_qexec.csv`, `six_zka_qexec.log`,
  `six_zka_qexec_jobs.csv` (the cycle counts behind the estimates). Per-batch proofs
  go to a `work/` scratch subdirectory that is deleted after each zkSketch run.
  Outside the results directory, each zkSketch run also (over)writes
  `results/env.json` at the repository root (exp_compose's machine snapshot;
  git-ignored).

`quick` checks the pipeline end to end; it is not a measurement. With 2 batches of
256 records its costs and ratios differ from `full`, and its `est` cells are the
executor's padded cycle count of that job's variant x the seconds per 2^20 padded
cycles of that run's 4 proofs. Over the 40 proofs of the reference run this model gave
between 5% below and 9% above the measured time for proofs of at least 2^19 padded
cycles, and 19-37% below for proofs of at most 2^18 (fixed overhead).

**Knobs** (environment variables):

| variable | default | meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zk-Analytics clone and its builds (~13 GB) |
| `RESULTS` | `results/six/<mode>-<stamp>` | output directory; must be new or empty |
| `SIX_CORES` | physical cores, at most 32 | cores of zkSketch's prover process, pinned to CPUs 0 .. SIX_CORES-1 |
| `GATE_WAIT_S` | `quick` and `memmatch --quick` 0, `full` and `memmatch` 1800 | seconds each timed job waits for a quiet machine; then it runs anyway and its row records the load |
| `GATE_MAX_LOAD`, `GATE_MAX_BUSY` | CPUs / 8 (2 below 16 CPUs), 4 | "quiet": 1-minute load <= `GATE_MAX_LOAD`, fewer than `GATE_MAX_BUSY` busy cores, and no `r0vm`, `exp_compose`, `cargo` or `rustc` of any user |
| `SIX_ZKA_ROOTS` | `noroot` | the zk-Analytics aggregation variants executed and proved (any comma list of `designed`, `noroot`, `legacy`); `full` proves 12 aggregation jobs per variant + the 28 queries (+ 2 for the Count-Min reference): 42 at the defaults; `designed,noroot` gives the earlier 52-job plan |
| `SIX_ZKA_CM_REF` | `1` | `1`: also prove their shipped Count-Min aggregation (`cm:aggr:0:designed`, `cm:aggr:7:designed`) as the reference, and execute `designed` for all six (executor only, cheap: the reference's cycle counts and the root-work table); skipped when `SIX_ZKA_ROOTS` already has `designed` or `legacy` (the same Count-Min guest). `0`: neither (`full`: 40 jobs) |
| `SIX_ZKA_GK` | `matched` | the zk-Analytics side's GK: `matched` = zkSketch's GK rule in their pipeline (same algorithm both sides); `textbook` = textbook Greenwald-Khanna, the reference (needed with `SIX_ZKA_ROOTS=legacy`) |
| `SIX_ZKA_GK_IMPL` | `literal` | implementation of the matched GK guest, all with the same output. `literal` = zkSketch's GK algorithm as its original code (`apply_batch2` statement for statement): the baseline, because the zkVM side must run the algorithm, not a program re-engineered with zkSketch's circuit-design insights. `tuned`, `fast`, `fixed_linear` are our rewrites (they compact survivors instead of re-sorting, the idea of zkSketch's planned stable-compaction circuit) and are sensitivity rows only |
| `SIX_GK_ROUNDS` | `stable` | zkSketch's GK circuit: `stable` = the stable-compaction circuit (M3), `sorted` = the earlier circuit that re-sorts every round; same GK rule, commitments and answers, different verification keys |
| `SIX_BLOOM_VARIANT` | `packed` | zkSketch's Bloom circuit: `packed` = the packed-byte circuit (M2, commitment family 7), `omc` = the earlier one-field-element-per-bit circuit; same filter and answers, different verification keys |
| `SIX_QUICK_PROVE` | `cm:aggr:0:noroot,kmv:aggr:0:noroot,gk:query:1,bloom:query:1:key` | the jobs `quick` and `memmatch --quick` prove for real (`jobs.py --select` selectors; `cm:aggr:0` would select every planned variant of that epoch, the reference included) |
| `SIX_M_<FAM>`, `SIX_LEAF`, `SIX_LEAF_<FAM>` | `SIX_M`; the epoch | individual scripts only (`run_all.sh` sets them for `memmatch` and ignores them otherwise); FAM = `CM`, `HLL`, `SS`, `GK`, `BLOOM`, `KMV`. `SIX_M_<FAM>`: that family's records per epoch on both sides. `SIX_LEAF` (every family) / `SIX_LEAF_<FAM>`: records per zkSketch leaf, a divisor of the epoch: `run_zks.sh` then proves each epoch as epoch / leaf leaves + their merges, and the matched zk-Analytics GK takes the GK leaf as `--m-sub` (`SIX_GK_MSUB`, which defaults to it) |
| `SIX_ALLOW_STALE` | unset | `1` lets `quick` / `full` / `memmatch` use binaries older than their sources (see Notes) |
| `TMPDIR` | `/tmp` | zkSketch's worker runs from a copy there and binds a unix socket: it must allow exec and be at most 60 characters long, else the scripts use `/tmp` |
| `EXP_VERIFY_REPEATS` | 5 | how often each zkSketch root proof, query proof and prefix certificate is verified (logged as `QLOG_ROOTV` / `QLOG_VERIFY` / `QLOG_BINDV`); the tables report the best, as for the zk-Analytics drivers' best of 5 receipt verifies |
| `RISC0_HOME` | `~/.risc0` | where rzup installed RISC Zero (rzup's own variable); the scripts put its `bin/` on `PATH` |

Notes:

- Use an otherwise idle machine: all times are wall-clock. With the default gate,
  `full` lets the load settle before each of its 49 timed jobs (7 zkSketch runs + 42
  proofs; 30-180 s each on a quiet machine, about 1 h 17 min in all for the reference
  run's 47; up to 30 min per job on a busy one). On an otherwise idle machine that
  wait is the previous job's own load decaying out of the 1-minute average. `GATE_WAIT_S=0` never waits; that is why `quick`
  rows often record `gate=busy:load1=...` even on an idle machine.
- `full` takes hours: start it so that it survives a closed terminal, e.g. inside
  `tmux` / `screen`, or `nohup scripts/baselines/zka/six/run_all.sh full > full.out 2>&1 &`
  (the console is also saved in the results directory as `run_all.log`).
- Ctrl-C stops the running job together with its child processes (each job runs in
  its own process group) and exits; nothing else is touched. A failed zkSketch run
  stops `quick` at once; in `full` the remaining zkSketch runs still execute, then
  `full` stops before the zk-Analytics side. A failed zk-Analytics proof stops
  `quick`, while `full` carries on with the other proofs, shows `-` for the failed one
  and exits 1. A failed zk-Analytics executor step (`run_zka.sh exec`) stops `full`
  before any proof; fix it and start `full` again.
- To finish a `full` run whose zk-Analytics proofs failed or were interrupted, without
  starting over: prove the jobs of its `zka_plan.txt` that have no `rc=0` line in its
  `six_zka_jobs.csv` yet (`run_zka.sh prove` takes any number of jobs and appends to
  the run's files), then rebuild the tables. From the repository root:

  ```bash
  D=results/six/full-YYYYmmdd-HHMMSS     # that run's directory
  RESULTS=$D scripts/baselines/zka/six/run_zka.sh prove \
    $(grep -vxFf <(awk -F, 'NR > 1 && $13 == 0 {print $1}' "$D/six_zka_jobs.csv" 2>/dev/null) "$D/zka_plan.txt")
  scripts/baselines/zka/six/run_all.sh assemble "$D"
  ```

  If it stopped before its first proof (no `six_zka_jobs.csv` yet), also re-run
  `RESULTS=$D scripts/baselines/zka/six/prof_exec.sh` first. Without a `zka_plan.txt`
  (it stopped during the zkSketch runs or the executor), start `full` again.
- `quick` and `full` refuse to run with binaries older than their sources (`check`
  warns): re-run `run_all.sh build` after pulling changes or editing sources, or when
  reusing a `BASELINE_DIR` built from an older checkout (it is much faster when cargo
  has little to recompile). `SIX_ALLOW_STALE=1` skips the check.
- After switching the Rust toolchain, `run_all.sh build` recompiles everything next
  to the old artifacts (another ~13 GB; `check` does not notice a toolchain switch,
  and the old builds stay usable). To reclaim the space, delete the old builds first,
  from the repository root: `rm -rf ~/ext-baselines/build/{cyc-t1,hll,zka-ss,zka-gk,zka-gk-matched,zka-bloom,zka-kmv} target`
  (with `BASELINE_DIR` set, use that instead of `~/ext-baselines`).
- If cargo fails to fetch the pinned Plonky3 forks (`failed to authenticate`), retry
  with `CARGO_NET_GIT_FETCH_WITH_CLI=true scripts/baselines/zka/six/run_all.sh build`
  (see [build.md](build.md)).
- zkSketch's worker is pinned with `numactl --physcpubind --membind` (else `taskset`).
  In a Docker container `--membind` needs `--cap-add SYS_NICE`; inside a cpuset, CPUs
  0 .. SIX_CORES-1 must be allowed (`run_all.sh check` tests the latter).
- The reference numbers in `scripts/baselines/zka/README.md` (2026-10-09) are the
  `legacy` zk-Analytics variant (CM with its roots, SS with a samples-pattern root, GK with a
  per-tuple root, HLL / Bloom / KMV without), neither `designed` nor `noroot`, and their GK is
  the textbook port, not zkSketch's rule; they were
  measured before zkSketch's default build became zero-knowledge; `full` measures
  the zero-knowledge build, which costs zkSketch more. At this shape it is much
  heavier for GK: one GK run of the default build here (2026-10-12, on a shared,
  loaded machine, with the pre-M3 `sorted` GK circuit, today's `SIX_GK_ROUNDS=sorted`)
  took 824 s and peaked at 58.8 GiB RSS, with 70 s of proving per
  batch, against 215 s, 19.4 GiB and 14.7 s per batch for the non-ZK reference run
  (`six_zksketch_r2_gk`). At 2 batches of 2,048 on the zero-knowledge build
  (2026-10-12, same machine, pre-M2/M3: `sorted` GK and the `omc` Bloom leaf) the 7 runs
  took 14.7 min in all: GK 371 s and 58 GiB, Bloom 126 s and 15 GiB per run (two
  runs), CM / HLL / SS / KMV 38-95 s and 5-8 GiB each.
  The same probe with today's defaults (2026-10-19, zkSketch `2c9fc17`, ZK build,
  `stable` GK, `packed` Bloom, 32 cores, an otherwise idle machine) took 6.1 min for
  the 7 runs (Bloom's absent-key run is the same circuit as its inserted-key run):

  | sketch | wall (s) | leaf proving per batch (s) | worker peak (GiB) | coordinator peak (GiB) |
  |---|---|---|---|---|
  | CM | 48 | 10.1 | 7.3 | 7.3 |
  | HLL | 73 | 8.9 | 6.8 | 6.9 |
  | SS | 35 | 5.4 | 4.9 | 4.4 |
  | GK | 86 | 19.3 | 15.1 | 15.1 |
  | Bloom | 49 | 11.3 | 8.1 | 8.1 |
  | KMV | 27 | 3.4 | 4.6 | 4.3 |

  The coordinator peaks while it derives the auditor's verifying keys, before the worker
  starts, so the two peaks do not add up. The ~15-25 min estimate for `full`'s 7 runs
  extrapolates these per leaf and per merge; `full` as a whole has not been run on the
  zero-knowledge build yet. Memory does not grow with the number of batches (the M0
  harness frees each proof's prover data; the M3 report measured the same peak at 4
  and 8 batches). To see each sketch's time and memory at the full batch size on a new
  machine (~6 min here) before starting `full`:
  `RESULTS=$PWD/results/six/m2048t2 SIX_M=2048 SIX_T=2 GATE_WAIT_S=0 scripts/baselines/zka/six/run_zks.sh`
  (the 7 zkSketch runs at 2 batches of 2,048; `wall_s` and `desc_peak_rss_mb` in
  that directory's `six_zksketch_runs.csv`).
- On another machine the proving times change with the CPU. The guest ELF hashes and
  exact `user_cycles` also depend on `$HOME` and the checkout path (panic-location
  strings); expect `user_cycles` within about 0.02% and identical segment and padded
  cycle counts.
- Step by step, the exact configuration, what is ours vs upstream, the reference
  results and caveats: [`scripts/baselines/zka/README.md`](../scripts/baselines/zka/README.md),
  section "Six-sketch comparison (small scale)".

