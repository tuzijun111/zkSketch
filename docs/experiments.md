# Running the experiments and reproducing the paper's results

The paper's evaluation is produced by `scripts/baselines/zka/six/run_all.sh` (Tables 2
and 3 and Figure 5; see [six_sketch_comparison.md](six_sketch_comparison.md)),
`examples/exp_operator.rs` (Figure 6) and `scripts/forest_tables.py` (Tables 4 and 5, from
Table 2's run and the speedups and dataset ratios of the `run_compose.sh` runs below).
`run_experiments.sh e1` and the other surfaces below remain live and supported, but no
current paper result depends on them. `run_experiments.sh` runs the relevant
backend(s), merges rows into a combined `results/<exp>.csv` with a `backend`
column, and writes per-backend `env.json` (CPU/RAM/OS/rustc + config);
`run_compose.sh` is **dual-backend** (`EXP_COMPOSE_BACKEND=plonky3|plonky2`),
while `run_stream.sh` and `run_decode.sh` are plonky3-only.

```bash
scripts/run_experiments.sh            # e1 (default), both backends, small slice
EXP_DATASET=aol scripts/run_experiments.sh e1
scripts/run_compose.sh                # real recursive composition (+ mixed queries)
scripts/run_stream.sh                 # whole-stream total prove time
scripts/run_decode.sh                 # decode/query circuits (tests + table)
```

| Surface | What it measures | Backends | Output |
| --- | --- | --- | --- |
| `run_experiments.sh e1` | **the per-family circuit-cost matrix**: family × variant × batch sweep (witness/prove/verify split, proof size, peak RSS), incl. the naive replay baselines and the CM/HLL rebind variants | both | `results/e1_circuit.csv` (rename per run via `EXP_OUT`) | 
| `run_compose.sh` | composition over **real recursive proofs**: 4 families × {per_batch, chain, forest}, cores/machines budgets, multi-machine staging; **mixed updates+queries** via `EXP_COMPOSE_QUERY_EVERY_OPS=Q` | **both** (`EXP_COMPOSE_BACKEND`) | `results/stream_compose.csv`, or `$1`/`EXP_OUT` | 


**`run_experiments.sh` config:**

| Var | Meaning | Default |
| --- | --- | --- |
| `EXP_DATASET` | `uniform` \| `gaussian` \| `zipf` \| `aol` \| `netflix` | `uniform` |
| `EXP_M` | e1 batch sizes. **Comma list only** — unparseable entries (`...`, `16..64`) are dropped *silently*, yielding a short sweep with exit 0. e2: one batch size | `4,8,16,32` (e2: `16`) |
| `EXP_FAMILY` | e1: `all` or comma-list of `cm,gk,hll,ss` | `all` |
| `EXP_{CM,HLL}_VARIANT` | e1 rebind variant: `one_hot` \| `merkle` \| `omc` (+ CM `merkle_fast`/`merkle_gb`/`memcheck`) | `one_hot` |
| `EXP_SS_VARIANT` | e1: `certified` \| `naive` \| `both`. `naive` runs out of memory from about m = 512 at capacity 16384, which kills the rest of the sweep: run it in its own invocation | `certified` |
| `EXP_GK_VARIANT` | e1: `bandmerge2` (the **deployed** circuit) \| `bandmerge2_naive` (its replay baseline) \| `certified` \| `naive` \| `bandmerge` \| `both`. `naive` has the same small-m limit as SS `naive`: run it in its own invocation | `certified` |
| `EXP_D`, `EXP_W` | CM depth `d` / width `w` | `4` / `8` |
| `EXP_HLL_B`, `EXP_SS_CAP`, `EXP_GK_CAP` | HLL precision `b` (registers `2^b`) / SS capacity / GK capacity. Comma-lists. (The `run_compose.sh` surface defaults `EXP_GK_CAP` to `64` instead.) | `4` / `8` / `8` |
| `EXP_GK_S` | e1 GK band-merge variants: accuracy `s = 1/eps`. Unset, it is `floor(cap / (2 ceil(log2 m)))` per (cap, m) cell, so it drifts across an m-sweep; pin it there (e.g. `73` at cap 2048) | per cell |
| `COUNTMIN_MAX_SEL_CELLS` | e1 CM `one_hot`: cap on its `m·d·(d·w)` selector cells; a larger cell is reported `too_large`. Raise it for big widths (at `d = 7, w = 16384` the default admits m = 16, not m = 32) | `16000000` |
| `HLL_FULL_MAX_SEL_CELLS` | e1 HLL `one_hot`: cap on its `2^b·m` selector cells (about 32 ALU rows each); a larger cell is reported `too_large` | `4194304` |
| `EXP_OUT` | rename the output CSV so successive runs don't overwrite | per-exp name |
| `EXP_CORES` | e1/plonky3: cores-per-proof pin (distributed-setting knob) | all cores |
| `EXP_TRIALS`, `EXP_WARMUP` | e5 measured trials / warm-up runs (e8 reads `EXP_E8_TRIALS`, default 2; e1 runs each cell once) | `5` / `1` |
| `EXP_TAMPER_TRIALS` | e2 tamper trials | `50` |
| `BACKENDS` | `plonky3` \| `plonky2` \| `both` | `both` |

**`run_compose.sh` config (the surface behind every paper table):**

| Var | Meaning | Default |
| --- | --- | --- |
| `EXP_COMPOSE_BACKEND` | `plonky3` \| `plonky2`. plonky2 takes **one** value for every knob except `EXP_COMPOSE_FAMILY` and `EXP_COMPOSE_MODE` (a list falls back to the default), and silently ignores `EXP_COMPOSE_EXEC`, `EXP_COMPOSE_NODES`, `EXP_COMPOSE_WAVE_SIZE`, `EXP_GK_S`, and all three mixed-query knobs. The Default column of this table is the plonky3 runner's; the plonky2 runner's own defaults are smaller: N 16, m 4, cores 4, d 2, w 4, SS/GK capacity 4 | `plonky3` |
| `EXP_COMPOSE_N` | total stream records — integer or `2^k` | `32` |
| `EXP_COMPOSE_BATCHES` | batch sizes `m`, comma-list | `8` |
| `EXP_COMPOSE_FAMILY` | comma-list of `cm,hll,ss,gk`, the opt-in BabyBear-only `bloom` (`EXP_BLOOM_K`, `EXP_BLOOM_LOGW`) and `kmv` (KMV / bottom-`k` distinct count, capacity `EXP_KMV_K`, default `1024`: a multiple of 4 in `4..=32768` with `k + m < 2^24`, a bad value exits 2), and the Goldilocks ports `cm_gl,hll_gl,ss_gl,gk_gl` | `cm,hll,ss,gk` |
| `EXP_COMPOSE_MODE` | `per_batch` \| `chain` \| `forest`, comma-list | all three |
| `EXP_COMPOSE_PROOF_DIR` | plonky3: folder for the `per_batch` mode's proofs, emptied at the start of every run | `results/compose_per_batch_proofs` |
| `EXP_COMPOSE_CROSS_FAMILY` | plonky2 only: `1` also builds one forest root per family and binds the four roots pairwise (cm with hll, ss with gk), written as a `family = xfamily` row | `0` |
| `EXP_COMPOSE_MACHINES` / `_CORES` | machine count / cores per machine, comma-list on plonky3 | `1` / all |
| `EXP_COMPOSE_EXEC` | `procs` (real pinned processes + socket IPC) \| `sim` (one process proves every leaf in turn; with M machines the leaf time is the largest of M contiguous sums of the measured leaf times). **Defaults to `procs` only when machines > 1** — pass it explicitly at `MACHINES=1` to get real process measurements | `procs` iff machines > 1 |
| `EXP_COMPOSE_NODES` | explicit NUMA-node assignment, e.g. `0,2` (one machine per socket) | round-robin |
| `EXP_COMPOSE_NODE_OFFSET` | shifts the default round-robin node assignment (the busy-sibling dummy runs at offset 1); ignored when `EXP_COMPOSE_NODES` is set | `0` |
| `EXP_BLOOM_VARIANT` | Bloom leaf: `packed` (bytes; needs `k m < 2^16`, so it exits 2 at `m = 16384`) \| `omc` (one field element per bit) | `packed` |
| `EXP_COMPOSE_WAVE_SIZE` | staged-wave execution: run machines in time-shifted waves of this size (see the paper's staged-wave methodology). **plonky3 BabyBear + `forest` only**, and needs `wave_size < machines`; ignored otherwise | off |
| `EXP_NET_MBPS`, `EXP_NET_RTT_MS` | link bandwidth (Mb/s) and per-message RTT (ms) for the `comm_model_ms` column: the **measured** bytes of each critical-path transfer x 8 / bandwidth, plus the RTT | `200` / `0.2` |
| `EXP_COMPOSE_QUERY_EVERY_OPS` | **mixed operation stream** (the paper's workload): every `Q`-th stream *position* is a query. plonky3 only | `0` (off) |
| `EXP_COMPOSE_QUERY_EVERY` | mixed *per-batch* variant: one query after every `k`-th batch. Mutually exclusive with `_OPS`; plonky3 only | `0` (off) |
| `EXP_QUERY_KEY_MODE` | probe key for keyed queries: `first` \| `uniform_stream` \| `hot` \| `absent`. plonky3 only | `first` |
| `EXP_GK_ROUNDS` | round certification of the BabyBear GK band-merge leaf (`gk`; M3): `stable` = the G1 stable-compaction circuit (`GkRounds::StableCompact`: per round one selected threshold test, a shared survivor update and a stable compaction certified by destination-bound permute coordinates), `sorted` = the pre-M3 bm2 circuit (`GkRounds::SortedCopy`: per round a fused table, a general sorted copy and its order checks), byte for byte, for side-by-side runs. Both prove the same batch rule (`apply_batch2`), the same `Com(S_t)` / `Com(B_t)` encodings, genesis and statement, and share the GK decoder and its VK; the leaf, merge and root VKs differ. It is a PUBLIC shape parameter: the workers, the no-op VK-derivation leaf and the auditor all build the leaf from it, and the CSV records it in `variant` (`gk_bandmerge2_stable` vs `gk_bandmerge2`) and the `gk_rounds` column (`n/a` for the other families), and in env.json. The default is `stable` since the G-sound attack suite passed (`src/sketch/gk_stable_attacks.rs`; see `HARNESS_DEFAULT_GK_ROUNDS`); under `ZKSKETCH_BINDING=legacy` it falls back to `sorted` (the stable leaf needs the in-circuit `θ`). The Goldilocks `gk_gl` leaf, the plonky2 backend and `exp_e1` ignore it (`exp_e1` warns when it is set). A step that exceeds `EXP_GK_CAP` is a hard error in either variant (the row is `too_large`). Any other value panics | `stable` |
| `EXP_OUT` / `$1` | output name; `results/<name>.csv` (the `.csv` suffix is optional) | `stream_compose.csv` (plonky3) / `stream_compose_p2.csv` (plonky2) |

**`run_stream.sh` config (Count-Min only, plonky3):**

| Var | Meaning | Default |
| --- | --- | --- |
| `EXP_STREAM_N` | total stream records — integer or `2^k` | `65536` |
| `EXP_STREAM_BATCHES` | batch sizes `m`, comma-list | `64,256,1024` |
| `EXP_STREAM_CORES` | `k` = leaf proofs run at once, each on `floor(threads / k)` cores; comma-list, each value clamped to the available threads | `1,2,4,8,16,32,64` |
| `EXP_STREAM_MERGE` | `digest` (folds the leaves' commitment digests; no recursive proof) \| `per_batch` (stores one proof per batch, no fold) \| `chain` (linear recursive fold) \| `recursive` (tree fold) \| `recursive_bound` (tree fold that also binds adjacent boundaries in-circuit). All but `digest` prove the leaves one after another and ignore `EXP_STREAM_CORES` | `digest` |
| `EXP_STREAM_PROOF_DIR` | folder for the `per_batch` proofs, emptied at the start of a `per_batch` run | `results/per_batch_proofs` |
| `EXP_CM_VARIANT` (or `EXP_STREAM_CM_VARIANT`) | leaf: `one_hot` \| `omc` \| `merkle`, comma-list | `omc,merkle` |
| `EXP_D`, `EXP_W`, `EXP_DATASET` | as for `run_experiments.sh` (`EXP_DATASET` takes a comma-list) | `4` / `8` / `uniform` |
| `EXP_OUT` / `$1` | output name in `results/` | `stream_forest.csv` |

**Soundness knobs (plonky3, every surface):**

| Var | Meaning | Default |
| --- | --- | --- |
| `ZKSKETCH_BINDING` | binding mode of the circuits that implement it: the Count-Min `omc` and `memcheck` leaves, the HyperLogLog `omc` and `one_hot` (`hll_final_full`) leaves (the `omc` leaves on BabyBear and Goldilocks), the standalone `countmin_merkle` leaf (no runner selects it), the GK band-merge leaves (`bandmerge`, `bandmerge2` on BabyBear and Goldilocks: the in-circuit threshold `θ = ⌊N_t/s⌋`) and the CM/HLL/SpaceSaving/GK decoders (the exposed query statement), and the KMV `kmv` leaf and decoder (`semantic` / `bound` only: there is no pre-fix KMV circuit, so `legacy` builds the `semantic` KMV leaf and decoder and a `legacy` KMV row reports the `semantic` cost; the `exp_compose` CSV has no binding column, so the row does not show this). CM `one_hot`, CM `merkle`/`merkle_fast`/`merkle_gb` (`countmin_c_merkle`), HLL `merkle`, the GK `bandmerge2_naive` baseline and the SS/GK-group-by update leaves ignore it. Modes: `semantic` (canonical positions, coordinate sort keys, base pins, GK `θ` bound to `N_t`, decoder statements exposed; relies on the fork for coefficient + IV binding), `bound` (adds in-circuit ALU coefficient re-binding and a zero-IV sponge where implemented (CM/HLL) — the fallback for an unfixed fork; the GK/SS circuits build the `semantic` circuit), `legacy` (the pre-fix zkSketch circuits, byte-for-byte against the same fork, for side-by-side cost runs; the merged fork itself changes even the pristine circuits, so `legacy` rows do not reproduce numbers measured at fork rev 19dcb37; **unsound** — only the fork-level fixes still apply; selecting it prints a loud warning to stderr, once per process). Any other value, including a non-UTF-8 one, panics. The variant knobs (`EXP_{CM,HLL}_VARIANT`, `EXP_SS_VARIANT`, `EXP_GK_VARIANT`) are unchanged | `semantic` |
| `ZKSKETCH_STATEMENT` | composition statement the harness leaves expose and the auditor checks (`statement::composition_expose`): `interval` = `(Com(S_{t-1}), Com(S_t), (t, t), H(TAG_LEAF, t, Com(B_t)))` per leaf, folded by the merge atom (index adjacency + merge digest) and checked at the root against the public batch log (`Com(S_0)`, `Com(S_T)`, every `Com(B_t)`) under the run's bracketing; `boundary` = the pre-B6(b) `(Com(S_{i-1}), Com(S_j))` leaves and merges, byte for byte, with a loud warning that the batch log is not checked. `ZKSKETCH_BINDING=legacy` also selects `boundary` unless this is set. Any other value, including a non-UTF-8 one, panics | `interval` |
| `ZKSKETCH_COMMIT` | state / batch commitment mode (revision B2, `commitment::hiding`), read once per run by `exp_compose` (both engines, every family including the Bloom filter `bloom`, commitment family id 5, and the KMV sketch `kmv`, family id 6), `exp_decode` and the deployed `exp_e1` variants (cm `omc`, hll `omc`, ss `certified`, gk `bandmerge2`; every baseline stays plain): `hiding` = every published `Com(S_t)` (`t ≥ 1`) and `Com(B_t)` absorbs a secret per-version randomizer derived from the prover's salt seed (leaf `t` opens with `Openings::for_leaf(seed, family, t)` at its global batch index; query-sealed and padded batches are real leaves; a query at version `t` opens `Com(S_t; ρ_t)`); the batch log is built prover-side, and the auditor takes only that log, the proofs and public parameters (it recomputes the genesis `Com(S_0; 0)` itself); in the mixed workload each query proof is pinned to the decoder VK of the run's mode (derived from public parameters: the empty state under the public zero salt) and its exposed salted `Com(S_t')` is bound to the prefix certificate checked against that published log (`query_bind_ms`); `plain` = the pre-B2 circuits, commitments and VKs byte for byte. The mode (never the seed) lands in the `exp_compose` CSV `commit` column, in the `exp_e1` CSV `commit` column (per row: the run's mode for the deployed variants, `plain` for every baseline and for the plonky2 leg) and in env.json. `exp_stream` (`run_stream.sh`) proves plain leaves only: it records `commit=plain` and refuses an explicit `hiding`. The external-baseline scripts (`scripts/baselines/zka/compare.sh`, `our_query.sh`, `scripts/baselines/zkstream/run_ours.sh`) pin `plain` (the mode of their stored comparison rows) unless `ZKSKETCH_COMMIT` is set, and write hiding runs to `*_hiding.csv` files. With `ZKSKETCH_BINDING=legacy` and this unset, `plain`. Any other value, including a non-UTF-8 one, panics. The randomizers are hidden only by the zero-knowledge PCS (B1, the default `zk` build); a `--no-default-features` build can still reveal them through its openings | `hiding` |
| `ZKSKETCH_SALT_SEED` | under `ZKSKETCH_COMMIT=hiding`: the prover's 256-bit salt seed as exactly 64 hex characters, for reproducible runs; unset or empty = drawn from the OS RNG. PROVER-side only: never printed or logged (a malformed value panics without echoing it); the distributed engine ships it to its own worker processes inside the task message, never to the auditor. The `salt_seed` CSV column / env.json key records its source (`env` / `os`; `n/a` under `plain`). Every stream is the seed's genesis history, so reuse a seed only for reproducibility, not across deployments | OS RNG |
| `EXP_ROOT_VK` | where the auditor's trusted VK comes from: for a composed (chain/forest, `t >= 2`) root the ROOT VK, and wherever the auditor receives leaf proofs directly (per_batch; a one-batch stream) the LEAF VK, against which each leaf is pinned (commitment + metadata) and STARK-verified by a verifier configured from public parameters before its statement is checked against the log. `derive` = from public parameters only (a no-op leaf, plus the fold's tree shape for a root; `O(log t)` dummy merges outside every timed phase), `self` = the legacy self-pin read from the root itself, with per_batch / lone-leaf proofs not re-verified by the auditor (the provers' self-verify is reported). Under `self` the batch-log check is worthless, since any circuit can expose the log's values (loud warning; side-by-side timing only). Or a path to a postcard `RootVk` file (`dist_compose` only; a per_batch or `t = 1` run expects the leaf VK). Files saved before the Interval statement (B6(b)) hold the Boundary-layout VK and now fail closed: re-derive them. A derivation or file error aborts the run | `derive` |
| `EXP_ROOT_VK_SAVE` | `dist_compose` with `EXP_ROOT_VK=derive`: also write the derived root (or leaf) VK to this path | unset |

`semantic` is only sound on the merged soundness fork (decompose coefficients
bound through `recompose/coeff`, zero IV on every `new_start` sponge row, bound
constants, full top-byte range check). `Cargo.toml` pins that fork
(`tuzijun111/Plonky3_RangeAir` @ `e11b1a6`, branch `zk-logup-mask`, which
also carries the LogUp masks, over the Plonky3 core fork `tuzijun111/Plonky3`
@ `280b1a0`), so a plain clone links it; no `[patch]` or local fork checkout is
needed.
`cargo test --release --lib bind::tests::fork_probe_report -- --nocapture`
prints which of these the linked fork provides.

Earlier modes of the E1–E10 ladder (**e3, e4, e5real, e6, e7, e9, e10, inputfold,
casestudy**) and the RQ1–RQ4 figure track are **retired from the driver** —
each was superseded by one of the surfaces above. Their runners stay in
`examples/` and remain directly runnable via `cargo run --release --example
exp_<name>` (`exp_e5_real` for e5real; e10 is `python3 scripts/cost_model_e10.py`).

### Reproducing the paper's results

The exact commands behind each figure/table, at the deployed configuration
(Count-Min `d=7, w=2^14`; HyperLogLog `b=14`; Misra-Gries (`ss`) `s=2^14`;
Greenwald–Khanna `s'=2^11`; `N=2^20` AOL records in `t=64` batches of `m=2^14`;
32 cores/machine). These are **long** runs — the full set is on the order of
days of prover time on the 128-core testbed.

(Figure `fig:eval-batch` below was removed from the paper on 2026-10-26, as was `tab:eval-datasets`' leaf-memory column, which read its `m = 2^14` rows; kept here for reference.)

**Figure `fig:eval-batch` — batch-size sweep** (`results/{cm,hll,ss,gk}_batch_*.csv`,
plotted by `scripts/plot_eval.py`). Baselines stop where the padded trace
exceeds the backend's `2^27` FRI domain (`2^24` rows per table under the default
zero-knowledge build, which makes the Count-Min one-hot leaf `too_large` already at `m = 16`);
those points are recorded as `status=too_large` and drawn as the infeasibility ✗:

```bash
# Count-Min: one-hot replay / Merkle sparse-opening / deployed memory-checked
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=one_hot \
  EXP_M=16,32,64 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=cm_batch_one_hot.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=merkle \
  EXP_M=16,32,64,128,256,512,1024,2048 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=cm_batch_merkle.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=cm EXP_D=7 EXP_W=16384 EXP_CM_VARIANT=omc \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=cm_batch_omc.csv scripts/run_experiments.sh e1

# HyperLogLog
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=one_hot \
  EXP_M=16,32,64,128,256,512,1024,2048 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=hll_batch_one_hot.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=merkle \
  EXP_M=16,32,64,128,256,512,1024,2048,4096 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=hll_batch_merkle.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=hll EXP_HLL_B=14 EXP_HLL_VARIANT=omc \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=hll_batch_omc.csv scripts/run_experiments.sh e1

# Misra-Gries (ss): per-record replay baseline (SpaceSaving's rule) / deployed certified leaf
EXP_DATASET=aol EXP_FAMILY=ss EXP_SS_CAP=16384 EXP_SS_VARIANT=naive \
  EXP_M=16,32,64,128 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=ss_batch_naive.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=ss EXP_SS_CAP=16384 EXP_SS_VARIANT=certified \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=ss_batch_certified.csv scripts/run_experiments.sh e1

# Greenwald–Khanna: replay baseline / deployed band-merge leaf
EXP_DATASET=aol EXP_FAMILY=gk EXP_GK_CAP=2048 EXP_GK_VARIANT=bandmerge2_naive \
  EXP_M=16,32,64,128,256 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=gk_batch_naive.csv scripts/run_experiments.sh e1
EXP_DATASET=aol EXP_FAMILY=gk EXP_GK_CAP=2048 EXP_GK_VARIANT=bandmerge2 \
  EXP_M=16,32,64,128,256,512,1024,2048,4096,8192,16384 EXP_CORES=32 BACKENDS=plonky3 \
  EXP_OUT=gk_batch_certified.csv scripts/run_experiments.sh e1

python3 scripts/plot_eval.py        # -> latex/pics/zkSketch_eval_batch.pdf if latex/pics/ exists, else results/
```

**The deployed reference run** (four sketches, Count-Min at `d = 7`; `scripts/forest_tables.py` uses it only
when the six-sketch files of README items 6-7 are absent) — one command fed five artifacts: the forest
column of `tab:compose-schedules`, the measured `M=1` runs behind `tab:compose-scale`, the
`2^20` Plonky3 row of `tab:stream-scale`, the AOL column of `tab:eval-datasets`,
and the Plonky3 (BabyBear) rows of `tab:p2-forest`. Run it first:

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky3 \
scripts/run_compose.sh frame_out_1machine_plonky3.csv
```

**Tables `tab:compose-schedules`, `tab:compose-scale` — composition schedules.**
The per-batch chain (the verifier-cost baseline), and the multi-machine forest.
`EXP_COMPOSE_NODES=0,2` puts one machine per socket; `EXP_COMPOSE_WAVE_SIZE=2`
runs `M≥3` in time-shifted waves of two so every machine owns a full socket
(`exec=staged` in the CSV; `M=2` runs concurrently as `exec=procs`):

```bash
# per-batch chain (same 64 leaves, no folds)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=per_batch \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky3 \
scripts/run_compose.sh frame_out_1machine_plonky3_perbatch.csv

# forest on M = 2, 3, 4 machines (staged waves)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=2,3,4 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky3 \
EXP_COMPOSE_NODES=0,2 EXP_COMPOSE_WAVE_SIZE=2 \
scripts/run_compose.sh frame_out_staged_m234_plonky3.csv
```

`frame_out_staged_m234_plonky3.csv` holds all 12 rows (4 families × 3 machine
counts); `results/frame_out_{2,3,4}machine_plonky3.csv` are that file split by
machine count. (`tab:eval-datasets`' M = 4 memory column, removed 2026-10-26, read the `M=4` rows.)

**Six-family version of `tab:compose-scale`** (adds the Bloom filter and KMV; current
circuits, zero knowledge on by default; README item 6). Beyond the four-family command it sets
`EXP_BLOOM_VARIANT=omc`, because the default packed Bloom leaf needs `7 m < 2^16` and
`exp_compose` exits 2 at `m = 16384`, `EXP_KMV_K=16384` (the default is 1024) and Count-Min
at `EXP_D=3`. GK's `1/eps` needs no knob: `exp_compose` sets
`s = floor(cap / (2 ceil(log2 N)))`, which is 51 at `N = 2^20`, the paper's value and how the
published `tab:compose-scale` rows got `cap2048_s51` (`EXP_GK_S` overrides it). One command covers
M = 1, 2, 3, 4 (M = 1 runs on node 0, as it would without the node list, and ignores the wave size):

```bash
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=3 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1,2,3,4 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky3 \
EXP_COMPOSE_NODES=0,2 EXP_COMPOSE_WAVE_SIZE=2 \
scripts/run_compose.sh frame_out_m1234_plonky3_6fam.csv
```

It needs the four-NUMA-node, two-socket server of the original runs (each machine = 32
physical cores of one node). Validated on 2026-10-26 on a one-node 32-core machine: the
same command shape for all six families at M = 1, 2, 3, 4 with 8 cores per machine and
tiny shapes (`results/smoke_forest6_m1234.csv`, all 24 rows ok, M = 3 and 4 `exec=staged`),
and every family at its deployed shape on one 32-core machine, two 2^14-record leaves plus
one composition (`results/smoke_forest6_deployed_n2e15.csv`, GK at `s = 51` in
`results/smoke_forest6_deployed_gk_s51.csv`; Count-Min at `d = 3` in
`results/smoke_forest6_deployed_cm_d3.csv`). Count-Min runs at `d = 3` (`EXP_D=3`), its
default size; at `d = 7` it costs twice as much. `scripts/forest_tables.py` applies this run's
M = 2, 3, 4 speedups to Table 2's whole-stream time (Bloom's from the `omc` leaf, since Table 2's
packed leaf cannot run at `m = 2^14`). Per-machine peak
memory at the deployed shapes: GK 74 GiB, Bloom 60, CM 58 (117 at `d = 7`), SS 53, HLL 51,
KMV 29 GiB (two machines live at once under the waves). Leaf times there: GK 94 s, Bloom 72,
CM 67 (134 at `d = 7`), SS 61, HLL 57, KMV 35 s, a composition 5-8 s. At these times the M = 1
forest (64 leaves and 63 compositions per family) adds up to about 7.5 h for the six families, and
the whole command to about a day of wall clock.

**Table `tab:stream-scale` — stream scaling on both backends.** `k=16..19` only:
the `2^20` row is the deployed reference run above (Plonky3) and the
`frame_out_1machine_plonky2.csv` run below (Plonky2), not a `k=20` sweep point.

```bash
for k in 16 17 18 19; do
  EXP_DATASET=aol \
  EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
  EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
  EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
  EXP_COMPOSE_BACKEND=plonky3 \
  scripts/run_compose.sh forest_plonky3_1machine_verify_2e$k.csv
done

for k in 16 17 18 19; do
  EXP_DATASET=aol \
  EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
  EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
  EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
  EXP_COMPOSE_BACKEND=plonky2 \
  scripts/run_compose.sh forest_plonky2_1machine_verify_2e$k.csv
done
```

**Six-family version of `tab:stream-scale`** (adds the Bloom filter and KMV; current
circuits, zero knowledge on by default; Plonky3 only, since the Plonky2 crate has no Bloom
or KMV circuit). Count-Min at `d = 3` (`EXP_D=3`), its default size. The paper's Table 4 is
computed by `scripts/forest_tables.py` instead.
Same extra knob as the six-family `tab:compose-scale` command
(`EXP_BLOOM_VARIANT=omc`); GK's `1/eps` is set per `N` by the same formula, as in the published rows (64, 60, 56,
53, 51 at `k = 16..20`). `k = 20` is included, although it is the same configuration as the
M = 1 rows of that command (skip it if you have those):

```bash
for k in 16 17 18 19 20; do
  EXP_DATASET=aol \
  EXP_D=3 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
  EXP_BLOOM_K=7 EXP_BLOOM_LOGW=14 EXP_BLOOM_VARIANT=omc EXP_KMV_K=16384 \
  EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest \
  EXP_COMPOSE_N=2^$k EXP_COMPOSE_BATCHES=16384 \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
  EXP_COMPOSE_BACKEND=plonky3 \
  scripts/run_compose.sh forest_plonky3_1machine_6fam_2e$k.csv
done
```

Validated on 2026-10-26 without the long run: the same loop at tiny shapes and
N = 2^8..2^10 in 64-record batches for all six families (`results/smoke_stream6_2e{8,9,10}.csv`),
and every family at the deployed shape with two 2^14-record leaves plus one composition
(`results/smoke_forest6_deployed_n2e15.csv`, GK at `s = 51` in
`results/smoke_forest6_deployed_gk_s51.csv`; Count-Min at `d = 3` in
`results/smoke_forest6_deployed_cm_d3.csv`). In the loop's
`forest_plonky3_1machine_6fam_2e*.csv` the proving time is `leaf_busy_max_ms` and
the setup `total_time_ms − leaf_busy_max_ms`; the paper's `tab:stream-scale` is
computed by `scripts/forest_tables.py` instead (see "Where each result lives").
At the deployed-shape leaf and composition times above,
the whole loop adds up to about 15 h on one 32-core machine: about 7.5 h for
k = 20 with CM at `d = 3`, and half that for each smaller k.

**Table `tab:p2-forest` — cross-backend at stream scale.** The Plonky3
(BabyBear) rows are the reference run above; add the Goldilocks port and Plonky2:

```bash
# Plonky3 over Goldilocks (the *_gl family ports)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm_gl,hll_gl,ss_gl,gk_gl EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs \
scripts/run_compose.sh frame_out_1machine_Goldilocks.csv

# Plonky2 (Goldilocks)
EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
EXP_COMPOSE_BACKEND=plonky2 \
scripts/run_compose.sh frame_out_1machine_plonky2.csv
```

**Table `tab:mixed` — query-rate sweep.** One query every `Q` stream positions. Since
2026-10-24 the paper's table comes from the six-sketch harness, which runs all six families
at the memory-matched leaf sizes over 2^17 AOL positions (Q = 1,000, 10,000, 100,000 plus the
query-free baseline) and adds a zk-Analytics column that `six/queryrate_model.py` computes from
real zk-Analytics proofs and executor cycle counts ([docs/six_sketch_comparison.md](six_sketch_comparison.md), "The query-rate experiment"):

```bash
taskset -c 0-31 scripts/baselines/zka/six/run_all.sh queryrate
```

The earlier four-family, zero-knowledge-off version of the table (Uniform stream, N = 2^20,
m = 16,384 leaves) was produced by:

```bash
for Q in 1000 10000 100000 1000000; do
  EXP_DATASET=uniform EXP_COMPOSE_N=2^20 EXP_COMPOSE_BATCHES=16384 \
  EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
  EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
  EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
  EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
  EXP_COMPOSE_QUERY_EVERY_OPS="$Q" EXP_QUERY_KEY_MODE=uniform_stream \
  scripts/run_compose.sh s3_plonky3_1machine_mixed_q$Q.csv
done
```



**Table `tab:eval-datasets` — dataset sensitivity.** Three datasets here. Six sketches (README item 7);
the AOL denominator is the `M=1` rows of `frame_out_m1234_plonky3_6fam.csv` (README item 6):

```bash
EXP_DATASET=uniform,gaussian,netflix EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=3 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 EXP_KMV_K=16384 EXP_BLOOM_VARIANT=omc \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk,bloom,kmv EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs \
scripts/run_compose.sh frame_out_1machine_datasets_plonky3_6fam.csv
```

The archived four-sketch run (Count-Min at `d = 7`; its AOL column is the deployed reference run above):

```bash
EXP_DATASET=uniform,gaussian,netflix EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 \
EXP_COMPOSE_EXEC=procs EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 \
scripts/run_compose.sh frame_out_1machine_datasets_plonky3.csv
```

**Where each result lives.** A table read straight from a `run_compose.sh` CSV
takes `total_time_ms` as the prover time (leaf-gen `= leafgen_ms`, fold total
`= merge_total_ms`). `tab:compose-scale`, `tab:stream-scale` and
`tab:eval-datasets` are computed by `scripts/forest_tables.py` (table below).
`tab:mixed`'s per-update cost is `(total_time_ms + query_prove_ms)/(n - n_queries)`
per `qr_zks_<group>_q<Q>.csv` row for zkSketch (measured) and
`zka_total_s / updates_U` for zk-Analytics, the `zks_ms_per_update` and
`zka_ms_per_update` columns of `queryrate.csv`.
`scripts/baselines/zka/six/queryrate_model.py` computes `zka_total_s` as
T x A(Q) + q(1) + ... + q(T) + (N - T Q) x A(Q) / Q, T = floor(N/Q). A(Q) is the
epoch-0 aggregation proof at E = Q records (the real proof where one was run, else
its padded cycles / 2^20 x k), charged for every epoch and, per record, for the
N - T Q records after the last query (`--tail skip` leaves them out, as the table in
`scripts/baselines/zka/results/queryrate-20261023-230106` does). q(n) = a + b n is a
least-squares line through the query executor's padded cycles / 2^20 x k at
n = 1, 2, 4, ..., 64, also used for larger n (`zka_total_flag` = `beyond_measured_n`).
k is the seconds per 2^20 padded cycles over all real proofs of the run.

| Paper artifact | `results/` file(s) |
| --- | --- |
| `fig:eval-batch` (removed from the paper 2026-10-26) | `{cm,hll}_batch_{one_hot,merkle,omc}.csv`, `{ss,gk}_batch_{naive,certified}.csv` (plotted by `scripts/plot_eval.py`) |
| `tab:compose-schedules` | `frame_out_1machine_plonky3_perbatch.csv` (per-batch) + `frame_out_1machine_plonky3.csv` (forest) |
| `tab:compose-scale` | computed by `scripts/forest_tables.py` -> `results/forest_tables.md`, in Table 2's setting: M=1 = zkSketch's whole-stream time of `tab:zka` (the same computation; it reproduces Table 2's hours); M=2,3,4 = M=1 divided by the measured speedups of `frame_out_m1234_plonky3_6fam.csv` (README item 6: six sketches, Count-Min d = 3) when present, else of the archived `frame_out_staged_m234_plonky3.csv` vs `frame_out_1machine_plonky3.csv` (four sketches, d = 7; Bloom/KMV at their mean). `results/forest_tables.md` lists the source of every family |
| `tab:stream-scale` | computed by `scripts/forest_tables.py` -> `results/forest_tables.md`, in Table 2's setting: zkSketch's time for N = 2^16..2^20 records = t = N/L memory-matched leaves + t-1 compositions with the time per leaf and remaining time per composition of `scripts/baselines/zka/results/memmatch-20261022-205419/` (the N=2^20 column is Table 2's whole-stream time). The earlier default-size runs `forest_plonky3_1machine_verify_2e{16..19}.csv` + `frame_out_1machine_plonky3.csv` are no longer in the paper; six-sketch command: `forest_plonky3_1machine_6fam_2e{16..20}.csv` |
| `tab:mixed` | `scripts/baselines/zka/results/queryrate-20261023-230106/queryrate.csv` (+ `queryrate_table.md`, `qr_zks_{a,b,c}_q{0,1000,10000,100000}.csv`, `zka_epoch_E*/`, `zka_query_E4096_T64/`); the four-family `s3_plonky3_1machine_mixed_q{1000,10000,100000,1000000}.csv` files are superseded |
| `tab:eval-datasets` | computed by `scripts/forest_tables.py` -> `results/forest_tables.md`, in Table 2's setting: AOL = zkSketch's whole-stream time of `tab:zka`, the other datasets = AOL x the measured ratios of `frame_out_1machine_datasets_plonky3_6fam.csv` (README item 7) to the M=1 rows of `frame_out_m1234_plonky3_6fam.csv` when present, else of the archived `frame_out_1machine_datasets_plonky3.csv` to `frame_out_1machine_plonky3.csv` (Bloom/KMV at the four-family mean). No memory columns |
| `tab:zka` | `scripts/baselines/zka/results/memmatch-20261022-205419/` (`six_sketch_table.md`, `six_sketch_comparison.csv`) |
| `fig:eval-sweep` | `scripts/baselines/zka/results/sweep-memmatch/sweep_memmatch.csv` (+ `.md`, `manifest.txt`), written by `scripts/sweep_memmatch.py`: zkSketch from `batches-20261028-153827/` (`six/batches.sh`: every batch size 2^6..2^14 in Table 2's setting, 54 runs) and, at Table 2's epochs, `memmatch-20261022-205419/`; zk-Analytics receipts from `sweep-20261024-195453/` and `memmatch-20261022-205419/`, GK at capacity 768 from `sweep-gk768-20261028-143107/` (its m=2^6 receipt; the GK sizes other than 2^6 and Table 2's 2^11 are not proved: padded executor cycles / 2^20 x the seconds per 2^20 padded cycles of those two receipts, marked in the `zka_basis` column); plotted by `scripts/plot_sweep.py` |
| appendix staged-wave controls (not in the README) | archived four-sketch runs: `frame_out_{2,3,4}machine_plonky3_coresident.csv`, `frame_out_1machine_plonky3_busysib.csv` (SS row only) |
| `tab:p2-forest` (earlier drafts; not in the current paper) | `frame_out_1machine_plonky3.csv`, `frame_out_1machine_Goldilocks.csv`, `frame_out_1machine_plonky2.csv` |

> **Superseded** (kept for provenance; no current table reads them): the `_old`
> and `_new` suffixes, `forest_plonky3_1machine_verify_2e20.csv`, and the
> pre-rename / M=4-era leftovers `frame_out_1machine.csv`,
> `frame_out_4machine.csv`, `frame_out_4machine_{datasets_plonky3,plonky2,ssgk_Goldilocks}.csv`,
> `s3_mixed_q*.csv` and `s3_plonky3_mixed_q100000.csv`.
>
> **Still live**, despite looking like leftovers: `frame_out_{2,3,4}machine_plonky3_coresident.csv`
> and `frame_out_1machine_plonky3_busysib.csv` are the co-residency controls
> behind the appendix's staged-wave fidelity argument (the ~6% package-sharing
> penalty). `scripts/run_m1_busy_sibling.sh` produces the `_busysib` file (one M=1
> forest per family next to a busy sibling node, each family in its own file, then merged). The
> `_coresident` files are plain
> `run_compose.sh` forest runs at M=2,3,4 without `EXP_COMPOSE_NODES` /
> `EXP_COMPOSE_WAVE_SIZE` (the default, socket-unaware placement):
>
> ```bash
> for M in 2 3 4; do
>   EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
>   EXP_D=7 EXP_W=16384 EXP_HLL_B=14 EXP_SS_CAP=16384 EXP_GK_CAP=2048 \
>   EXP_COMPOSE_FAMILY=cm,hll,ss,gk EXP_COMPOSE_MODE=forest \
>   EXP_COMPOSE_MACHINES=$M EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs \
>   scripts/run_compose.sh frame_out_${M}machine_plonky3_coresident.csv
> done
> scripts/run_m1_busy_sibling.sh frame_out_1machine_plonky3_busysib.csv ss   # the kept file has the SS row only
> ```

### Standalone comparison demos

Quick side-by-side prove/verify/size demos (no CSV):

```bash
cargo run --release --example chain_two            # §4.1 flat vs §4.2 recursive (toy AIR)
cargo run --release --example countmin_chain_n     # recursive chain sweep E ∈ {2,4,8}
cargo run --release --example countmin_v1_vs_v2    # §5.1 strawman vs §5.4-shaped leaf
cargo run --release --example hll_chain_n          # HLL chain sweep
```


### Per-phase cost breakdown (`exp_operator`)

`examples/exp_operator.rs` measures the paper's "Cost Breakdown by Phase" figure for the
deployed Count-Min (`countmin_omc`) and Misra--Gries (`ss_final_full`) leaves, optionally
also Greenwald--Khanna (`gk_bandmerge2_stable`, `EXP_FAMILIES=cm,mg,gk`), by default at the
paper's default parameters (`EXP_D=3 EXP_W=16384 EXP_M_CM=16384`, `EXP_SS_CAP=16384
EXP_M_MG=16384`; GK at `EXP_GK_CAP=768 EXP_GK_S=51 EXP_M_GK=512`). The default CM+MG run takes
about 11 minutes on 32 cores and peaks at 61 GB: rows per table per phase from shapes-only prefix builds
(`table_probe::capture_prefix_shapes(k, ..)`, `k = 1..K`, a thread-local prefix the two
builders read through `table_probe::phase_limit`; the guards only skip gates, the probe stops every build
before a circuit exists, and the deployed circuit is unchanged: `examples/leaf_vk.rs`
prints the three leaves' VK digests, identical before and after), then a warm-up leaf and `EXP_REPEATS` timed leaf proofs under a `tracing`
layer that times every prover span, and one query proof. Output in `results/operator/`;
`scripts/plot_operator.py` (needs matplotlib) apportions the joint prover stages by
committed cells and each table by its rows per phase, prints the breakdown, and writes
`latex/pics/zkSketch_eval_operator.pdf`.

```bash
RAYON_NUM_THREADS=32 taskset -c 0-31 cargo run --release --example exp_operator
python3 scripts/plot_operator.py
```
