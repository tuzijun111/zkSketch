# M1 (2026-10-15): real zk-Analytics GK proofs with zkSketch's own GK rule, and zkSketch scalar vs AVX2

This file has six parts, newest first:

- **Measurement (round 3, measurer)**, directly below. It re-checked the round-3 fix (`e9968eb`)
  and restates the **final M1 result, tables (a)-(d)**. Nothing measured changed.
- **Fixer (round 3)**. It fixed the round-2 reviews' minor issues: the tests, the harness
  labelling and the documentation. No guest binary changed.
- **Measurement (round 2, measurer)**, at `5f96d1d`. It re-ran the zk-Analytics GK executor matrix,
  the two real proofs (harness default `tuned`) and the renders. Its numbers are the zk-Analytics
  side of the result below.
- **Fixer (round 2)**. It made the steelman `tuned` guest the zk-Analytics GK default and
  re-measured the two real proofs once. Round 2 pools them.
- **Measurement (round 1, measurer)**, at `235c87b` with the `fast` guest. Its zkSketch numbers
  (b), (d) and its AVX2 checks are the zkSketch side of the result below.
- **Implementation and equivalence (implementer)**. It describes the matched-GK port and shows
  that zk-Analytics' GK now computes exactly zkSketch's function.

# Measurement (round 3, measurer), 2026-10-15 17:37-17:45, at `e9968eb`

## Verdict

**Everything the round-3 fix could change was re-run, and all of it reproduced. No measured
number changed, so the M1 result below stands.**

- The fix (`5f96d1d..e9968eb`) touches only `gk_matched/` (a doc comment in `core/src/lib.rs`, a
  `Cargo.toml` comment, the host's test module), `six/assemble.py` and READMEs. Nothing under
  `src/`, `examples/`, `Cargo.*`, `plonky2/` or `build.rs` changed since `235c87b`.
- **The guest ELFs are byte-identical** to round 2's: `aggr_gkm` `bfc5cda6f751`, `querier_gkm`
  `44b7ffd00163`, image ID `3d746b3b…` in every row. So the guest that round 2 proved is the
  guest at `e9968eb`.
- **The host driver's code is byte-identical.** Its md5 changed (`c763ba4f4277` to
  `986c861141e6`), but all 100 differing bytes are in the build-ID note (20) and in `.strtab`
  symbol names (80). Every loaded section (`.text`, `.rodata`, `.data.rel.ro`, `.data`,
  `.eh_frame`, ...) and the LOAD program headers are identical (`measure3/driver_binary_compare.txt`).
  A second rebuild at `e9968eb` gave the same md5.
- **Executor rows identical.** All 34 rows (16 matched `aggr`, 16 `check`, 2 textbook) equal round
  2's in all 58 / 53 non-timing columns; only `exec_s` differs. Every row has
  `journal_eq_native=true`, every matched row `state_eq_zksketch=true`, every `check` row
  `query_eq_zksketch=true`. The overflow control (cap 16) still exits 3.
- **Tests.** 8/8 in release and 8/8 in debug at `e9968eb`. As an independent control, the
  `5f96d1d` test module in a debug build fails the same 2 of 8 at `gk_bandmerge.rs:1490`, so the
  fix is what makes debug pass.
- **The new `assemble.py` check works, and changes nothing else.** It refuses all three mixed
  copies, which the `5f96d1d` script accepts and mislabels. The committed, smoke and mismatch
  renders are byte-identical to round 2's (details below).
- **Not re-run, because the fix cannot change them:** the real proofs (same guest image, same
  r0vm `9e13aa14c059`, driver code identical), every zkSketch run (no source change; `exp_compose`
  scalar `38c33b46bc13` and AVX2 `beced0ce5acb`, unchanged before and after the build) and
  `certify`.

## What was re-run (sandbox clone `$HOME/zkSketch` at `e9968eb`, dirty 0)

| item | could `e9968eb` change it? | action | result |
|---|---|---|---|
| build, `run_all.sh check` | yes (sources edited) | `six/run_all.sh build` + `check` (`measure3/build.log.gz`) | 8 builds ok in 22 s. `check`: ok, 0 warnings, 7 drivers, `SIX_ZKA_GK=matched`, implementation `tuned`. |
| guest ELFs | only through the doc-comment edit | md5 after the build | `aggr_gkm` `bfc5cda6f751`, `querier_gkm` `44b7ffd00163`: the same as rounds 2 and 3 (fixer). |
| host driver `gk_matched` | yes (test module, comments) | section-by-section comparison with round 2's binary (`c763ba4f4277`, kept by the fixer); rebuilt once more | Code and data identical. Only the build ID and 80 bytes of symbol names differ. The rebuild reproduced `986c861141e6`. |
| executor matrix: A and B x 4 implementations x epochs 0-1, textbook, overflow control | driver changed (symbols only) | re-ran round 2's `exec_matrix.sh` (`measure3/exec/`) | identical to `measure2/exec/` except `exec_s`; overflow exit 3 |
| `gk_matched_check.sh` | yes (tests) | re-run (`measure3/check/`) | 8/8 release tests; its 4 `aggr` and 16 `check` rows identical to `fixer3/check2/` except `exec_s` |
| debug `cargo test` (R2-1 fix) | yes | at `e9968eb`, twice (cached and after a forced rebuild); control with `5f96d1d`'s `host/src/main.rs` swapped in and restored (`git status` empty after) | 8/8 and 8/8; control 6/8: `overflow_is_a_hard_error` and `tuned_matches_zksketch_at_the_edges` panic at `src/sketch/gk_bandmerge.rs:1490` |
| `assemble.py` / `table.py` (R2-2 fix) | yes | `measure3/runner/render.sh` (`measure3/render/`) | see the next table |
| real zk-Analytics proofs | no: same image ID, r0vm and driver code | not re-run | round 2's 351.78 / 334.57 s and the fixer's 352.40 / 338.10 s stand |
| zkSketch scalar / AVX2 runs, VK identity, cross-verification, Bloom | no: no zkSketch change, binaries unchanged | not re-run | round 1's numbers stand |
| README numbers added by the fix | n/a | checked against `measure3/exec/` | R2-4: 102.8k = (7,714,745 − 7,605,761) − 6,186 (A); 93.8k = (7,705,745 − 7,605,761) − 6,186 (B). M2-5: 351.783 s / 11.5 = 30.59 vs / 12 = 29.32. All correct. |

**Renders** (`assemble.py` md5 `568968d506da`, `table.py` `a702c0a1601a`):

| set | expected | result |
|---|---|---|
| committed 2026-10-09 set (textbook rows) | unchanged | CSV md5 `a6e493c381af` (318 rows); `committed.md` byte-identical to `measure2/render/` and `fixer3/render/`; 24 GK labels "zkA: textbook GK" |
| M1 smoke set (matched) | unchanged | CSV and table byte-identical to `harness_smoke/`; 17 labels "same rule both sides" |
| mismatch copy (zkSketch GK shape relabelled `cap384_s51`) | warn | WARNING printed; table byte-identical to `measure2/render/mism.md` (17 "CONFIG MISMATCH" labels) |
| mixA: `algorithm` column dropped from `six_zka_gk_prove.csv` | exit 1 | exit 1: "6 matched-port rows ... and 2 textbook-port rows". The `5f96d1d` script: exit 0, 17 labels "same rule both sides" (the defect) |
| mixB: dropped from `six_zka_gk_exec.csv` | exit 1 | exit 1 (4 vs 4). The `5f96d1d` script: exit 0, mislabelled |
| mixD: a textbook-style `six_zka_vt_gk_prove.csv` added (the new `vt` source) | exit 1 | exit 1 (8 vs 2) |
| all-textbook copy (dropped from exec, qexec and prove) | accepted, labelled textbook | exit 0; the 9 zk-Analytics GK rows are `zk-Analytics arch. (port †)` with the textbook note; 17 labels "zkA: textbook GK" |

**Load.** No timed job ran in this round. The box had one other user's single-threaded python
and a short data-loader burst (load average 1.3-2.4).

## M1 result (final)

Sources: (a) rounds 1-2 (real proofs pooled with the round-2 fixer's), its executor re-confirmed
here; (b) and (d) round 1; (c) derived. Every zkSketch proof is zero-knowledge (default
features: hiding PCS and LogUp masks).

### (a) zk-Analytics with zkSketch's GK rule (bm2), B = 2,048 AOL records, noroot, epoch 0

| | config A: cap 384, m_sub 128, 16 steps | config B: cap 768, m_sub 512, 4 steps |
|---|---|---|
| **real proof, `tuned` (the default)** | **352.09 s** (351.78 / 352.40) | **336.33 s** (334.57 / 338.10) |
| segments (padded / 2^20) / user cycles | 12 (11.5) / 10,979,416 | 11 (11.0) / 10,693,564 |
| effective k_s (s per padded 2^20 cycles; calibration 30.07) | 30.62 (+1.8 %) | 30.58 (+1.7 %) |
| verify (best of 5) / receipt | 9.7-11.6 ms / 225,114 B | 9.8-11.6 ms / 225,114 B |
| r0vm peak / combined with the driver | 9,398-9,401 / 9,428 MiB (above 8 GiB) | 9,390-9,398 / 9,428 MiB |
| journal == native / state == zkSketch's chain | true / true | true / true |
| real proof, `fast` (round 1) | 392.66 s, 13 segments | 363.04 s, 12 segments |
| executor epoch 1 (carried state), `tuned` | 11,085,631 cycles, 12 (11.5) | 10,822,662 cycles, 12 (11.25) |
| executor, `fixed_linear` / `literal` (e0) | 18 / 37 segments | 16 / 31 segments |
| against the plan's textbook estimates 398.5 / 421.0 s | 11.6 % / 16.4 % below | 15.6 % / 20.1 % below |

**Textbook GK (reference only; not zkSketch's function):** 12,862,178 user cycles, 14 segments
(13.25 padded) at epoch 0; 12,958,972, 14 (13.5) at epoch 1. The matched `tuned` guest needs
14.6 % (A) and 16.9 % (B) fewer cycles. Its committed real proofs (2026-10-09, legacy root, 14 segments)
took 415.4 s (epoch 0) and 424.6 s (epoch 7).

The GK rule is 8.8 % (A) and 6.4 % (B) of the `tuned` guest's cycles. zk-Analytics' Event read and
batch chain are 89.7 % (A) and 92.1 % (B), so no faster GK guest can bring their epoch below about
10 segments.

### (b) zkSketch scalar vs AVX2, M0 defaults (round 1; combined RSS by `memsample.py`)

| shape | build | update makespan s | leaves s (per leaf) | merges s (per merge) | combined peak MiB | AVX2 factor (makespan / leaf / merge) |
|---|---|---|---|---|---|---|
| GK A: cap 384, m 128, T 16 | scalar | **177.13** (171.5 / 182.8) | 96.4 (6.03) | 77.3 (5.16) | 5,200 | |
| | AVX2 | **91.72** (92.8 / 90.6) | 50.6 (3.16) | 38.1 (2.54) | 5,202 | **1.93** / 1.91 / 2.03 |
| GK cap 768, m 512, T 2 | scalar | 55.1 (55.9 / 54.3) | 43.5 (21.73) | 7.1 (7.10) | 16,547 | |
| | AVX2 | 28.8 (28.2 / 29.4) | 21.8 (10.90) | 3.5 (3.50) | 16,423 | **1.91** / 1.99 / 2.03 |
| GK B: cap 768, m 512, T 4 | scalar | **110.00** (110.2 / 109.8) | 87.7 (21.92) | 17.3 (5.77) | **17,177** | |
| | AVX2 | **53.59** (52.5 / 54.7) | 41.6 (10.41) | 8.2 (2.74) | **17,172** | **2.05** / 2.11 / 2.10 |
| Bloom m 256, T 8 | scalar | **117.2** (114.6 / 119.8) | 81.5 (10.18) | 31.5 (4.50) | 8,267 | |
| | AVX2 | **53.9** (52.0 / 55.7) | 36.5 (4.57) | 14.0 (1.99) | 8,242 | **2.18** / 2.23 / 2.26 |

AVX2 packing is active (86,093 `%ymm`, 7,535 `vpmuludq %ymm`, 0 `%zmm`; scalar: 121 `%ymm`, all in
runtime-dispatched chacha20). Leaf and root VK bytes are identical across builds, proofs
cross-verify both ways, a tampered root is rejected, and answers are identical (1,778 at A, 1,780
at B, the same as the zk-Analytics query guest).

### (c) The fair GK speedup today, and the M3 projection

Ranges run from min zk-Analytics / max zkSketch to max / min.

| GK configuration | zk-Analytics real (`tuned`) | zkSketch scalar | **speedup, scalar (matched)** | zkSketch AVX2 | speedup, AVX2 (not matched) | zkSketch combined peak | 10x threshold |
|---|---|---|---|---|---|---|---|
| A: cap 384, m 128 x 16 (measured) | 352.09 s | 177.13 s | **1.99x** (1.92-2.06) | 91.72 s | 3.84x (3.79-3.89) | 5,200 MiB | 35.21 s |
| B: cap 768, m 512 x 4, today's bm2 (measured) | 336.33 s | 110.00 s | **3.06x** (3.04-3.08) | 53.59 s | 6.28x (6.12-6.44) | **17,177 MiB (fails 8 GiB)** | 33.63 s |
| **B with M3 / G1 stable compaction (PROJECTION)** | 336.33 s | 43-46 s (plan §2 G1, scalar; not measured) | **7.3-7.8x: misses 10x** | 21.0-23.8 s (scaled by the measured 1.93-2.05) | 14.1-16.0x | not estimated | 33.63 s |

- **Scalar is the matched comparison.** r0vm 3.0.6's 5,065 `%ymm` instructions are all in
  runtime-dispatched library code (ring, aho-corasick, memchr, rand_chacha, httparse), none in a
  `risc0_*` function. Its prover is baseline x86-64, like our scalar build. The AVX2 columns would
  be matched only against an r0vm rebuilt with `-C target-cpu=x86-64-v3`, which was not built.
- **The speedups use zk-Analytics' epoch 0** (no carried state). Its carried-state epoch is the
  same 11.5 padded segments at A and 11.25 vs 11.0 at B (+2 %), so these speedups are
  conservative for zkSketch.
- **To reach 10x at config B**, G1 must take at most 33.6 s scalar. The plan estimates 43-46 s.
  The alternatives are G2-C, or a matched AVX2 comparison against a rebuilt r0vm.

### (d) Bloom AVX2 factor (m 256, T 8, k 7, w 2^14; `bloom_omc`, M0 defaults)

**2.18x** on the update makespan (117.2 to 53.9 s; repetition pairs 2.20x and 2.15x), 2.23x per
leaf, 2.26x per merge, and 1.69-2.05x on VK derivation, audit and queries. The combined peak
(8,267 / 8,242 MiB) does not change, and is above 8 GiB in both builds. The zk-Analytics Bloom time
stays estimated, by the user's decision.

### Builds, commits, measured vs estimated

| | |
|---|---|
| code | Sandbox clone, branch `m1-gk-matched`: zk-Analytics results at `5f96d1d` (round 2), confirmed at `e9968eb` (this round); zkSketch results at `235c87b` (round 1; zkSketch unchanged since). zk-Analytics clone `d4a5a9a`. |
| zk-Analytics | guests risc0-zkvm 3.0.5 (rzup rust 1.97.0); host and r0vm 3.0.6 as shipped, no RUSTFLAGS; `ProverOpts::succinct()`, CPU, po2-20 segments; `run_zka.sh prove gk:aggr:0:noroot` with `SIX_M=2048 SIX_T=1 SIX_GK_CAP=<384\|768> SIX_GK_MSUB=<128\|512> SIX_ZKA_GK=matched`, `SIX_ZKA_GK_IMPL` unset (`tuned`) |
| zkSketch scalar | `cargo build --release --locked --example exp_compose`, no RUSTFLAGS (`p3-monty-31` `no_packing`); opt-level 3, thin LTO, codegen-units 1; default features (hiding PCS, LogUp masks); md5 `38c33b46bc13` |
| zkSketch AVX2 | the same with `CARGO_TARGET_DIR=$HOME/target-avx2 RUSTFLAGS="-C target-cpu=x86-64-v3"` (AVX2, FMA, BMI2; no AVX-512); md5 `beced0ce5acb` |
| host and load | AMD Threadripper PRO 9975WX (32 cores / 64 threads), 559 GiB, shared. Measured runs were gated (other users < 6 busy cores; measured at 0.06-1.3 on average, Bloom's second pair at 4.0-4.8). |
| **measured** | (a) real proofs and executor rows; (b) and (d) zkSketch runs; VK identity; cross-verification; objdump counts |
| **derived** | speedups, thresholds, AVX2 factors, effective k_s |
| **estimated, not measured** | the M3 / G1 batch time (43-46 s) and its AVX2 scaling; the zk-Analytics Bloom time; any AVX2-rebuilt r0vm |

**Open, for the user (unchanged from round 2):** the projected M3/G1 misses 10x at config B
(M2-1); config B is 17.2 GiB until M3 (M2-2); the premise that AVX2 zkSketch vs r0vm as shipped
is "matched" does not hold, because r0vm's prover has no AVX2 (M2-3; the plan's own §1.5 condition,
"only after checking how r0vm 3.0.6 was built", and §4.0 G-zka, "scalar against r0vm as shipped",
already point to the scalar comparison); zk-Analytics itself peaks at 9.2 GiB (M2-4).

### Files (`measure3/`, plain copies, never git-added)

- `driver_binary_compare.txt`, `sec_pre.txt`, `sec_post.txt`: the driver's section-by-section comparison.
- `build.log.gz`: `run_all.sh build` and `check`, with md5s before and after.
- `exec/`: `matched_exec.csv` (16), `matched_check.csv` (16), `textbook_exec.csv` (2), `exec.log`, `neg.log`.
- `check/`: `gk_matched_check.sh` console and CSVs; `debug_test.log.gz`, `debug_test_rebuilt.log.gz`,
  `debug_test_control_5f96d1d.log.gz`, `release_rebuild.log.gz`.
- `render/`: `render.log`, each set's `assemble.py` output (`*.assemble.out`) and table (`*.md`).
- `runner/`: `env.sh`, `build.sh`, `exec_matrix.sh` (round 2's), `render.sh`, `cmp_exec.py`.

# Fixer (round 3), 2026-10-15 17:20-17:40, commit `e9968eb` (on `5f96d1d`)

## Verdict

**No measured number changed, and none needed re-measuring.**

- The guest ELFs are byte-identical: `aggr_gkm` `bfc5cda6f751`, `querier_gkm` `44b7ffd00163`.
  The image IDs are therefore unchanged, and every real proof, executor row and certify row of
  rounds 1-2 stays valid.
  - The only guest-compiled edit is a doc comment in `gk_matched/core/src/lib.rs`, rewritten
    with the same line count so that no panic location moves.
- The host driver's md5 changed from `c763ba4f4277` to `986c861141e6`, but only in symbol names
  (`.llvm.<hash>` suffixes) and the build ID. `.text`, `.rodata` and `.data.rel.ro` are
  identical. The change comes from the test-module edit in `host/src/main.rs`.
- zkSketch is untouched: no file under `src/`, `examples/`, `Cargo.*`, `plonky2/` or `build.rs`
  changed, and `exp_compose` (scalar) is still `38c33b46bc13`.
- The harness re-ran clean at `e9968eb`: `run_all.sh build` (all 8 builds ok) and `check` (ok,
  0 warnings, 7 drivers, impl tuned).
- `gk_matched_check.sh` re-ran at `e9968eb`:
  - 8 of 8 unit tests pass in release, and 8 of 8 in a debug build.
  - 16 check rows and 4 aggr rows (A and B, epochs 0-1) are equal to round 2's
    `measure2/exec/` in every deterministic column: user cycles, segments, state_commit,
    result, prof, input bytes, image ID and the three equality flags.

## Issues and what was done

| issue | verdict | done |
|---|---|---|
| M2-1 (major): the fair speedup is 1.99x (A) / 3.06x (B), and the M3/G1 projection (7.3-7.8x) misses 10x | Confirmed. This is a result, not a defect. | **Skipped: it needs a user decision.** The options are G2-C, a G1 at 33.6 s or less scalar, or an AVX2-rebuilt r0vm. The zka README thresholds now come from the mean of the two proofs: 35.2 / 33.6 s (was 35.2 / 33.8 s from one proof). |
| M2-2: config B is at 17,177 MiB, not memory-matched | Confirmed | **Skipped:** this is M3 scope. Re-measure B after M3. |
| M2-3: the plan calls AVX2 the fair configuration, but r0vm 3.0.6's prover has no AVX2 | Confirmed. No worktree doc makes that claim. | **Skipped:** the claim is only in `latex/gk_bloom_redesign_plan.md` §1.5 / §4.0 (G-zka), in main's working tree, outside the fixer's worktree. Left for the user. Suggested wording: "matched = scalar zkSketch vs r0vm 3.0.6 as shipped (its prover is baseline x86-64; its 5,065 ymm instructions are in ring/memchr/etc.); an AVX2 row needs an r0vm rebuilt with x86-64-v3". |
| M2-4: zk-Analytics' own peak (about 9.2 GiB) is above the 8 GiB cap | Confirmed | **Fixed (docs).** The zka README's "zk-Analytics' own memory" bullet now reads r0vm 9,388-9,401 MiB (9,404-9,428 MiB with the driver). The memory-matched procedure paragraph (`SIX_GK_MSUB`) now says that 8 GiB is zkSketch's cap and that zk-Analytics peaks at about 9.2 GiB. |
| M2-5: `s_per_segment` counts a partial last segment as a whole one | Confirmed | **Fixed (docs).** `gk_matched/README.md` defines the column and gives the per-padded-2^20 formula, with the example of A: 30.59 s against `s_per_segment` 29.32. The zka README's real-proof table already has a "s per padded 2^20" column. No CSV column was added: that would change the schema and binaries of every driver. |
| R2-1: the native tests only pass with `--release` | **Confirmed by a control.** At `5f96d1d`, a debug `cargo test` fails both `overflow_is_a_hard_error` and `tuned_matches_zksketch_at_the_edges` at `src/sketch/gk_bandmerge.rs:1490` (the `debug_assert!`). | **Fixed.** A test helper `zk_step` (catch_unwind plus the mass check) counts either outcome as a lost record: the silent truncation (release) or the `debug_assert!` panic (debug). Now 8/8 pass in debug and 8/8 in release. The test comment, `gk_matched/README.md` and the zka README say so. |
| R2-2: assemble.py labels a directory that mixes matched and textbook GK rows as "zkSketch GK rule" | **Confirmed.** On doctored copies of `harness_smoke/`, the `5f96d1d` assemble.py exits 0 and labels all 9 GK rows "zkSketch GK rule". | **Fixed.** `gk_algorithm()` now exits when some of the gk exec / qexec / prove / vt rows have `algorithm` and others do not. Tests: see Re-runs below. |
| R2-3: stale "default from `gk_bm2/core`" attributions | Confirmed (3 places) | **Fixed:** the zka README "What is the same" GK row, the `gk_matched/core/Cargo.toml` comment, and `lib.rs` header step 5 (same line count). |
| R2-4: the carry read cost includes the source chain-tip entry that every port reads | **Confirmed and measured.** Textbook GK's epoch-1 input is +140 B (35 words) over epoch 0: exactly that entry. The SpaceSaving profile guest (`harness_smoke/six_zka_prof_ss.csv`, same entry type) spends 6,186 `read` cycles on it. | **Fixed.** The carried-word read is now about 102.8k / 93.8k / 101.0k (was 108,984 / 99,984 / 107,184): 679 / 619 / 667 words at about 150 cycles each (the README had said 170). The extra per epoch is still about 0.11-0.12M, 1.0-1.1 %. Changed in `gk_matched/README.md` (table) and the zka README (caveat). |
| R2-5: the headline proofs are epoch 0 (no carried state), and this is not stated by the speedup table | Confirmed | **Fixed.** One paragraph under the zka README's real-proof table, and one under (c) below. Carried-state epochs: A is still 11.5 padded segments; B is 11.25 vs 11.0 (+2 %, about +8 s). The epoch-0 speedups and thresholds are therefore conservative for zkSketch. |

## Re-runs (sandbox clone, `e9968eb`; files in `fixer3/`)

- **Build.** `six/run_all.sh build` and `check` both ok, 0 warnings. Binary md5s are in
  `md5_before.txt` (`5f96d1d`) and `md5_after.txt` (`e9968eb`). The driver at `5f96d1d` was
  rebuilt from source to `c763ba4f4277` (deterministic), and the patched one to
  `986c861141e6`, twice.
- **Unit tests and rows.** `gk_matched_check.sh` (A, B; epochs 0-1): 8/8 release unit tests;
  16 check rows and 4 aggr rows identical to `measure2/exec/` (`check2/`).
- **Debug tests.** At `e9968eb`, `cargo test` (debug) gives 8/8 (`check2/debug_test.log.gz`). The
  control at `5f96d1d` fails 2 of 2 (`debug_test_orig.log`).
- **assemble.py / table.py renders** (`render/`):
  - Committed 2026-10-09 set: CSV md5 `a6e493c381af`; the table is byte-identical to
    `measure2/render/committed.md`.
  - Smoke set: CSV and table byte-identical to `harness_smoke/`.
  - Config-mismatch copy: warns, and the table is byte-identical to `measure2/render/mism.md`.
  - Mixed copies exit 1 with the new message, and the old script exits 0 with them mislabelled:
    - textbook-style prove rows next to matched exec / qexec rows: 6 matched vs 2 textbook rows;
    - textbook-style exec rows next to matched rows: 4 vs 4.
  - An all-textbook copy is accepted, and its GK rows are labelled textbook GK.
- **Load.** Other users' jobs only. No proofs and no long runs: nothing here needed one.

## What stays valid

- All of round 2's measurement: (a) to (d), the real proofs (A 351.78 / 352.40 s, B 334.57 /
  338.10 s), the executor matrix and the renders.
- Round 1's zkSketch scalar and AVX2 numbers, the Bloom factor and the certify rows. The
  guest images and zkSketch are unchanged.

# Measurement (round 2, measurer), 2026-10-15 17:02-17:20, at `5f96d1d`

## Verdict

**Every re-run completed, with correct answers and states.** The fixer's numbers reproduce: the
two real zk-Analytics GK proofs came in within 0.2 % (A) and 1.1 % (B) of the fixer's.

| | result |
|---|---|
| **zk-Analytics GK, real proofs at B = 2,048** (zkSketch's rule bm2, harness default `tuned`, noroot, epoch 0) | config A (cap 384, m_sub 128, 16 steps): **351.78 s** here and 352.40 s (fixer), so **352.09 s**. 12 segments (11.5 x 2^20 padded cycles).<br>Config B (cap 768, m_sub 512, 4 steps): **334.57 s** here and 338.10 s (fixer), so **336.33 s**. 11 segments.<br>Journal == native and state == zkSketch's chain in both; r0vm peak 9,398-9,401 MiB (9.2 GiB). |
| Textbook GK (reference only) | 12,862,178 user cycles, 14 segments at B = 2,048 (unchanged). The matched `tuned` guest needs 14.6 % (A) and 16.9 % (B) fewer user cycles. |
| **Fair GK speedup today** (scalar zkSketch vs r0vm as shipped, whose prover is scalar) | **A: 1.99x** (1.92-2.06). **B: 3.06x** (3.04-3.08), but at a 17,177 MiB combined peak, which fails 8 GiB. |
| 10x thresholds for zkSketch's 2,048-record GK batch | **35.21 s** (A), **33.63 s** (B) |
| **Projected M3 (G1 stable compaction) at config B** | Plan estimate 43-46 s scalar gives **7.3-7.8x: misses 10x** (G1 must be ≤ 33.6 s). Scaled by the measured GK AVX2 factor (1.93-2.05): 21.0-23.8 s, or 14.1-16.0x. That AVX2 ratio is fair only against an AVX2-rebuilt r0vm, which was not built. |
| zkSketch scalar vs AVX2 (round 1, carried) | GK 1.93x (A), 2.05x (B at T 4), 1.91x (cap 768, T 2). Root and leaf VKs are identical across builds, and proofs cross-verify both ways. |
| Bloom AVX2 factor (round 1, carried) | **2.18x** (m 256, T 8). The zk-Analytics Bloom time stays estimated, by decision. |

## Re-check scope: what was re-run, and why

The fixes are `f669c92` (code and docs) and `5f96d1d` (docs only). Between `235c87b` and
`5f96d1d`, `git diff --stat -- src examples Cargo.toml Cargo.lock plonky2 build.rs` is empty.
The change touches only `scripts/baselines/zka/{gk_matched,six}` and READMEs.

| item | could the fix change it? | action | result |
|---|---|---|---|
| build, `run_all.sh check` | yes (new guest code) | re-run in the sandbox clone at `5f96d1d`, dirty 0 | all 8 builds ok. `check`: ok, 0 warnings, 7 drivers, `implementation tuned`. The md5s equal the fixer's: `gk_matched` `c763ba4f4277`, ELFs `aggr_gkm` `bfc5cda6f751` and `querier_gkm` `44b7ffd00163`. |
| zk-Analytics matched GK executor: A and B x epochs 0-1 x 4 implementations | yes | re-run: 16 `aggr` rows (noroot) and 16 `check` rows | all correct (table below) |
| textbook GK executor at B = 2,048 | no (`gk/` untouched) | re-run anyway (cheap) | identical to round 1 |
| real proofs, config A and config B, epoch 0 | yes (default `tuned`) | re-run, gated, with `SIX_ZKA_GK_IMPL` **unset**, so the harness default is used | the CSV says `implementation=tuned`; times below |
| harness rendering (`assemble.py`, `table.py`) | yes | re-rendered three sets: the committed 2026-10-09 set, the M1 smoke set, and a doctored copy of the smoke set with the zkSketch GK capacity changed to 384 | Committed set: `six_sketch_comparison.csv` md5 `a6e493c381af` (= the implementer's 3fd232e / 235c87b renders). The table is byte-identical to the implementer's new render: GK label "zkA: textbook GK".<br>Smoke set: CSV and table byte-identical to `harness_smoke/`, label "same rule both sides".<br>Doctored copy: `assemble.py` warns, and all 17 GK rows read "CONFIG MISMATCH: same rule, NOT the same function". |
| overflow negative control | yes | re-run (cap 16, m_sub 256, default impl) | exit 3 |
| zkSketch scalar and AVX2 runs, VK identity, cross-verification, objdump counts, Bloom | **no** | not re-run | The binaries are unchanged: `exp_compose` scalar md5 `38c33b46bc13`, AVX2 `beced0ce5acb`, before and after `run_all.sh build`. These are the binaries round 1 measured. |
| `certify` (zkSketch's leaf proves the guest's state) | only through the guest's state | not re-run; the fixer ran it at A with `tuned` | Not needed. `tuned` emits the same state as `fast`: equal SHA-256 `state_commit` over the one-to-one compact encoding, at every epoch of A and B. Round 1's `certify` proved that state with zkSketch's leaf at both A and B. |

## (a) zk-Analytics matched GK at B = 2,048 (AOL, noroot), and the textbook reference

### Real proofs (`run_zka.sh prove gk:aggr:0:noroot`, `ProverOpts::succinct()`, CPU r0vm 3.0.6)

| | config A: cap 384, m_sub 128, 16 steps | config B: cap 768, m_sub 512, 4 steps |
|---|---|---|
| implementation | `tuned` (harness default; `SIX_ZKA_GK_IMPL` unset) | `tuned` (same) |
| **prove_s, this round** | **351.783** | **334.569** |
| prove_s, fixer (16:46 / 16:53, same binary) | 352.402 | 338.099 |
| **mean of the two** | **352.09** | **336.33** |
| segments / padded / user cycles | 12 / 12,058,624 (11.5 x 2^20; last segment po2 19) / 10,979,416 | 11 / 11,534,336 (11.0 x 2^20) / 10,693,564 |
| s per padded 2^20 cycles (this round) | 30.59 | 30.42 |
| MODELED (driver: segments x 30.1 s) | 361.2 (measured −2.6 %) | 331.1 (+1.0 %) |
| journal == native (checked after proving) / state == zkSketch's native chain | true / true | true / true |
| verify (best of 5, in process) / receipt (bincode) | 11.565 ms / 225,114 B | 11.586 ms / 225,114 B |
| r0vm peak: driver sampler / `rss_tree.sh` VmHWM | 9,400.6 / 9,390.5 MiB | 9,398.1 / 9,390.6 MiB |
| combined peak (driver + r0vm + shells, `memsample.py` at 0.1 s) | 9,428 MiB | 9,428 MiB |
| state_commit / image_id | `72e60704…` / `3d746b3b…` | `01d8f68d…` / `3d746b3b…` |
| window; other users' busy cores mean / max | 17:04:53-17:10:48; 1.18 / 1.96 | 17:11:33-17:17:09; 1.15 / 1.52 |

- **Comparison with round 1's `fast` guest.** The proofs dropped 10.3 % at A (392.66 to 352.09 s)
  and 7.4 % at B (363.04 to 336.33 s).
- **Verify time.** It was 11.6 ms here, against the fixer's 9.7 ms and round 1's 11.5 ms, all with
  the same 225,114-byte receipt. That spread is run-to-run noise of a sub-millisecond-sensitive
  in-process timing. It is not a property of the guest.
- **The CSV column `s_per_segment`** is prove_s / segments: 29.3 s at A. At A it understates the
  cost per 2^20 cycles, because the last segment there is half size. The table uses padded cycles
  instead.

### Executor (`measure2/exec/`; `--mode aggr --root noroot`, 2,048 AOL records per epoch)

| config | impl | e0 user cycles | e0 segments (padded / 2^20) | e1 user cycles | e1 segments (padded / 2^20) | GK update e0 | MODELED e0 |
|---|---|---|---|---|---|---|---|
| A (384, 128) | **tuned** | 10,979,416 | **12** (11.5) | 11,085,631 | 12 (11.5) | 965,322 | 361.2 s |
| A | fast | 11,879,837 | 13 (13.0) | 11,983,858 | 13 (13.0) | 1,841,352 | 391.3 s |
| A | fixed_linear | 16,674,951 | 18 (17.5) | 16,793,421 | 18 (17.5) | 6,636,466 | 541.8 s |
| A | literal | 30,321,545 | 37 (37.0) | 30,412,391 | 37 (37.0) | 20,283,058 | 1,113.7 s |
| B (768, 512) | **tuned** | 10,693,564 | **11** (11.0) | 10,822,662 | 12 (11.25) | 680,565 | 331.1 s |
| B | fast | 11,047,367 | 12 (12.0) | 11,174,809 | 12 (12.0) | 987,885 | 361.2 s |
| B | fixed_linear | 14,777,799 | 16 (15.5) | 14,903,149 | 16 (16.0) | 4,718,317 | 481.6 s |
| B | literal | 25,295,367 | 31 (30.5) | 25,456,836 | 31 (31.0) | 15,235,883 | 933.1 s |
| **textbook `gk/` (reference)** | | 12,862,178 | **14** (13.25) | 12,958,972 | 14 (13.5) | | 421.4 s |

**Correctness.**

- **All 16 `aggr` rows** have `journal_eq_native=true` and `state_eq_zksketch=true`.
- **At each epoch the four implementations give the same `state_commit`.** Config A: `72e60704…`
  (e0) and `7ee84181…` (e1). Config B: `01d8f68d…` (e0) and `e405e120…` (e1). These equal round 1's
  and the fixer's.
- **All 16 `check` rows** (A and B x 4 implementations x epochs 0-1) have
  `state_eq_zksketch=true(tuples)` and `query_eq_zksketch=true`.
  - rank(1810625) at A: 1,778 [1,745, 1,812] at e0 and 3,539 [3,474, 3,605] at e1.
  - At B: 1,780 [1,749, 1,812] and 3,551 [3,497, 3,605].
  - Exact: 1,789 and 3,569.
  - 1,778 and 1,780 are also zkSketch's own `exp_compose` answers after 2,048 records (round 1, (b)).

**Stability against earlier rounds.**

- `tuned` gives the fixer's cycle counts exactly.
- `fast`, `fixed_linear` and `literal` are 11-28 user cycles above round 1 (code layout), with the
  same segments and padded cycles. So round 1's real `fast` proofs (392.66 s and 363.04 s) stay
  valid as `fast` measurements.

**Where zk-Analytics' time goes** (`tuned`, guest marks):

- At A, epoch 0, their framework is 89.7 % of the user cycles: Event read 7,605,761 plus batch
  chain 2,245,159.
- The GK rule itself is 8.8 % at A (965,322) and 6.4 % at B (680,565).
- So the steelman's remaining slack is bounded. Even a zero-cost GK update would still leave about
  10.0M user cycles at A: at least 10 segments, and above 300 s at the measured cost per segment.

**Textbook reference.**

- It was executed here only, not proved. Its committed real proofs (2026-10-09, legacy root,
  14 segments) took 415.4 s (epoch 0) and 424.6 s (epoch 7).
- It is not zkSketch's function and is kept only as the labelled reference
  (`SIX_ZKA_GK=textbook`).

## (b) zkSketch scalar vs AVX2, M0 defaults (round 1, carried: same binaries)

Combined = coordinator + worker VmRSS summed at the same 0.1 s sample (`memsample.py`).
Makespan = the update makespan: leaves plus merges. Two repetitions of each, gated at 1.1-1.3
foreign busy cores, except Bloom's second pair at 4.0-4.8. Per-run rows are in round 1's
`runtable.md`.

| shape | build | makespan s (runs) | leaves s (per leaf) | merges s (per merge) | combined peak MiB | AVX2 factor: makespan / leaf / merge |
|---|---|---|---|---|---|---|
| GK A: cap 384, m 128, T 16 (2,048 records) | scalar | **177.13** (171.5 / 182.8) | 96.4 (6.03) | 77.3 (5.16) | 5,200 | |
| | AVX2 | **91.72** (92.8 / 90.6) | 50.6 (3.16) | 38.1 (2.54) | 5,202 | **1.93** / 1.91 / 2.03 |
| GK cap 768, m 512, T 2 (1,024 records) | scalar | 55.1 (55.9 / 54.3) | 43.5 (21.73) | 7.1 (7.10) | 16,547 | |
| | AVX2 | 28.8 (28.2 / 29.4) | 21.8 (10.90) | 3.5 (3.50) | 16,423 | **1.91** / 1.99 / 2.03 |
| GK B: cap 768, m 512, T 4 (2,048 records) | scalar | **110.00** (110.2 / 109.8) | 87.7 (21.92) | 17.3 (5.77) | **17,177** | |
| | AVX2 | **53.59** (52.5 / 54.7) | 41.6 (10.41) | 8.2 (2.74) | **17,172** | **2.05** / 2.11 / 2.10 |
| Bloom m 256, T 8, k 7, w 2^14 | scalar | **117.2** (114.6 / 119.8) | 81.5 (10.18) | 31.5 (4.50) | 8,267 | |
| | AVX2 | **53.9** (52.0 / 55.7) | 36.5 (4.57) | 14.0 (1.99) | 8,242 | **2.18** / 2.23 / 2.26 |

**Checks from round 1, still valid because the binaries are unchanged:**

- **Packing is active in the AVX2 build.** It has 86,093 `%ymm` instructions, including 7,535
  `vpmuludq %ymm` and 170 `PackedMontyField31AVX2` symbols, and 0 `%zmm`. The scalar build has 121
  `%ymm`, all in runtime-dispatched `chacha20`.
- **VK bytes are identical** between the scalar and AVX2 builds, for the GK cap 384 and cap 768
  leaves and roots and for the Bloom leaf and root. Each run's saved root VK is identical too.
- **Proofs cross-verify both ways**, and a tampered root is rejected.
- **Answers are identical** across builds and runs.
- **Neither build fits 8 GiB at cap 768.** Today's bm2 leaf peaks at about 16.4-17.2 GiB. M3 must
  fix that.

## (c) The fair GK speedup today, and the M3 projection

zk-Analytics time = the real proofs of (a), epoch 0 (2,048 records), the mean of the two
measurements. zkSketch time = the makespan of (b) for the same 2,048 records. Ranges run from
min zk-Analytics / max zkSketch to max zk-Analytics / min zkSketch.

zk-Analytics time = epoch 0, from the empty state with no carried state (added by the round-3
fixer). The carried-state epoch is 11.5 padded segments at A, the same as epoch 0, and 11.25
instead of 11.0 at B (+2 %, about +8 s). So the steady-state speedup is the same at A and slightly
higher at B, and these epoch-0 speedups and thresholds are conservative for zkSketch.

| GK configuration | zk-Analytics real (`tuned`) | zkSketch scalar | **speedup, scalar (matched)** | zkSketch AVX2 | speedup, AVX2 (vs r0vm as shipped: not matched) | zkSketch combined peak | 10x threshold |
|---|---|---|---|---|---|---|---|
| A: cap 384, m 128 x 16 (measured) | 352.09 s (351.78 / 352.40) | 177.13 s | **1.99x** (1.92-2.06) | 91.72 s | 3.84x (3.79-3.89) | 5,200 MiB | 35.21 s |
| B: cap 768, m 512 x 4, today's bm2 (measured) | 336.33 s (334.57 / 338.10) | 110.00 s | **3.06x** (3.04-3.08) | 53.59 s | 6.28x (6.12-6.44) | **17,177 MiB (fails 8 GiB)** | 33.63 s |
| **B with M3 / G1 stable compaction (PROJECTION)** | 336.33 s | **43-46 s** (plan §2 G1 estimate, scalar; not measured) | **7.3-7.8x: misses 10x** | 21.0-23.8 s (43-46 s / measured GK AVX2 factor 2.05-1.93) | 14.1-16.0x (fair only against an AVX2-rebuilt r0vm, not built) | not estimated here | 33.63 s |

**Why scalar is the matched comparison.**

- r0vm 3.0.6's 5,065 `%ymm` instructions are all in runtime-dispatched library code: ring,
  aho-corasick, memchr, rand_chacha and httparse. None is in a `risc0_*` function. So its prover is
  baseline x86-64, like our scalar build.
- The AVX2 column is therefore an upper bound. It would be a matched comparison only against an
  r0vm rebuilt with `-C target-cpu=x86-64-v3`. That rebuild's own gain is unknown: nobody has
  measured it.
- The plan's "matched AVX2" premise (§4.0 G-zka) does not hold for r0vm as shipped.

**Distance to 10x.**

- Today, zkSketch's GK is 2.0x (A) and 3.1x (B, 17 GiB) faster than zk-Analytics running the
  same function.
- Reaching 10x at config B needs one of these:
  - G1 at ≤ 33.6 s scalar. The plan estimates 43-46 s, which is 28-37 % too slow.
  - G2-C.
  - A matched AVX2 comparison against a rebuilt r0vm.
- The 10x thresholds fell from round 1's 39.27 / 36.30 s, because the `tuned` steelman made
  zk-Analytics 7-10 % faster.

## (d) Bloom AVX2 factor (round 1, carried)

| Bloom m 256, T 8 (`bloom_omc`, M0 defaults) | scalar | AVX2 | AVX2 factor |
|---|---|---|---|
| update makespan | 117.2 s | 53.9 s | **2.18x** (repetition pairs 2.20x and 2.15x) |
| 8 leaves (per leaf) | 81.5 s (10.18) | 36.5 s (4.57) | 2.23x |
| 7 merges (per merge) | 31.5 s (4.50) | 14.0 s (1.99) | 2.26x |
| VK derivation / audit / 8 queries | 19.6 / 14.7 / 78.5 s | 10.9 / 8.7 / 38.2 s | 1.80x / 1.69x / 2.05x |
| combined peak | 8,267 MiB | 8,242 MiB | unchanged (above 8 GiB in both builds) |

The zk-Analytics Bloom time stays estimated, by the user's decision: no 45-50 min run.

## Build, commits, load, measured vs estimated

| | |
|---|---|
| code | Sandbox clone `$HOME/zkSketch` (`HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold`), branch `m1-gk-matched` at `5f96d1d` (the fixer had already synced it); dirty 0 in every run's provenance line. zk-Analytics clone `d4a5a9a`. |
| build | `six/run_all.sh build`: 8 builds ok in 22 s; `check`: ok, 0 warnings (`measure2/build.log.gz`). Binary md5s: `gk_matched` `c763ba4f4277`, `aggr_gkm` `bfc5cda6f751`, `querier_gkm` `44b7ffd00163`, textbook `gk` `b62f3f8b45e9`, r0vm `9e13aa14c059`. |
| zk-Analytics flags | RISC Zero guests: risc0-zkvm 3.0.5, rzup rust 1.97.0. Host and r0vm 3.0.6 as shipped (no RUSTFLAGS). Proving: `ProverOpts::succinct()`, CPU, default po2-20 segments. |
| scalar zkSketch (round 1) | `cargo build --release --locked --example exp_compose`, no RUSTFLAGS (`p3-monty-31` `no_packing`); opt-level 3, thin LTO, codegen-units 1; default features: hiding PCS and LogUp masks, so every proof is zero-knowledge. md5 `38c33b46bc13`. |
| AVX2 zkSketch (round 1) | the same, with `CARGO_TARGET_DIR=$HOME/target-avx2 RUSTFLAGS="-C target-cpu=x86-64-v3"` (AVX2, FMA, BMI2; no AVX-512); md5 `beced0ce5acb` |
| zk-Analytics prove command | `RESULTS=<dir> SIX_M=2048 SIX_T=1 SIX_GK_CAP=<384\|768> SIX_GK_MSUB=<128\|512> SIX_ZKA_GK=matched GATE_WAIT_S=0 run_zka.sh prove gk:aggr:0:noroot`, with `SIX_ZKA_GK_IMPL` unset (`measure2/runner/zka_prove.sh`) |
| gate | `measure2/runner/gated.sh`: 45 s cool-down, then other users < 6 busy cores for 60 s, then a 590 s watchdog. Both proofs passed on the first try. |
| host and load | SPRL6201019991, AMD Threadripper PRO 9975WX (32 cores / 64 threads), 559 GiB, shared. `loadsample.py` sampled every 5 s (`measure2/load.csv`). During the proofs other users averaged 1.15-1.18 busy cores (max 1.96): one other user's single-threaded python. Our own load was about 49 busy cores. |
| **measured in this round** | (a): the 2 real proofs, 32 executor rows, 2 textbook rows and the negative control; the harness renders |
| **measured earlier, carried** | the fixer's 2 real proofs (pooled into (a) and (c)); round 1's (b) and (d) zkSketch runs, VK identity, cross-verification and objdump counts |
| **derived** | the speedups, the thresholds and the AVX2 factors (ratios of measured numbers) |
| **estimated, not measured** | the M3 / G1 batch time (plan §2: 43-46 s at cap 768, m 512 x 4), its AVX2 scaling, the zk-Analytics Bloom time, and any AVX2-rebuilt r0vm |

## Files (`measure2/`, plain copies, never git-added)

- `zka/zkaA_default_e0/`, `zka/zkaB_default_e0/`: `meta.txt` (provenance, window, foreign load),
  `out/six_zka_gk_prove.{csv,log}`, `out/six_zka_jobs.csv`, `mem.csv.gz`, `memsum.txt`,
  `run_zka.stderr`.
- `exec/`:
  - `matched_exec.csv`: 16 `aggr` rows;
  - `matched_check.csv`: 16 `check` rows;
  - `textbook_exec.csv`: 2 rows;
  - `exec.log` (provenance and md5s) and `neg.log`.
- `render/`: the committed set (`committed.md`), the smoke set (`smoke.md`) and the doctored
  mismatch set (`mism.md`, `mism.assemble.out`).
- `load.csv`, `gated.log`, `jobs.txt`, `build.log.gz`.
- `runner/`: `env.sh`, `build.sh`, `exec_matrix.sh`, `zka_prove.sh`, `gated.sh`, `gate.py`,
  `loadsample.py`, and `memsample.py` (identical to
  `latex/redesign_20261014/profile/memsample.py`).

---

# Fixer (round 2), 2026-10-15 16:30-17:00, commits `f669c92` (code + docs) and `5f96d1d` (docs only)

> Confirmed by measurement round 2 above. It re-measured both real proofs at `5f96d1d` (351.78 s
> and 334.57 s) and pools them with the fixer's ones below.

## Verdict

**The zk-Analytics GK headline is now the `tuned` guest, and the fair GK speedup is smaller than
round 1 reported.** Round 2 reviewed `fast`, round 1's default, and found it was not a fair
steelman at 16 steps per epoch. It paid about 55k user cycles of fixed overhead at every
`apply_batch2_fast` call:

- a canonical-form check over all `capacity` rows;
- two 2,049-entry radix tables, cleared and prefix-summed;
- padding the output to `capacity`;
- fresh buffers, and a `capacity`-row empty state at epoch 0.

`tuned` is the new default. It runs the same data-dependent schedule as one loop over the
epoch: the state stays compact, the canonical form and mass are checked once, the radix digits
are sized to the batch, and the buffers are reused. It computes the same state, tuple for
tuple, and an overflow is still a hard error.

| | round 1 (`fast`) | **round 2 (`tuned`)** |
|---|---|---|
| zka real proof, config A (cap 384, m_sub 128, 16 steps) | 392.66 s, 13 segments (13.0 x 2^20) | **352.40 s**, 12 segments (11.5 x 2^20) |
| zka real proof, config B (cap 768, m_sub 512, 4 steps) | 363.04 s, 12 segments | **338.10 s**, 11 segments |
| 10x threshold for zkSketch's 2,048-record batch | 39.27 s (A), 36.30 s (B) | **35.24 s (A), 33.81 s (B)** |
| **fair speedup, scalar zkSketch (matched)** | 2.22x (A), 3.30x (B) | **1.99x (A)** (1.93-2.05), **3.07x (B)** (3.07-3.08) |
| AVX2 zkSketch vs r0vm as shipped (not matched, see round 1's SIMD finding) | 4.28x, 6.77x | 3.84x, 6.31x |
| M3 / G1 projection at B (plan estimate 43-46 s scalar) | 7.9-8.4x | **7.3-7.9x: misses 10x by more** |
| same, AVX2-scaled (fair only against an AVX2-rebuilt r0vm) | 15.2-17.3x | 14.2-16.1x |

zkSketch's times are round 1's, unchanged: scalar 177.13 s (A) and 110.00 s (B), AVX2 91.72 s
and 53.59 s. No zkSketch code changed (`exp_compose` md5 `38c33b46bc13`).

## Issues and what was done

| # | issue (reviewer) | verdict | action |
|---|---|---|---|
| R2-1 | `fast` is not a fair steelman at m_sub 128 (major) | **Confirmed.** `fast`'s update was 1,841,352 cycles for 16 steps against 555,837 for one 2,048-record step. 0.88M of it was removable, and it cost a whole segment at A. | **Fixed.** `GkmImpl::Tuned` (`gk_matched/core`, `apply_epoch_tuned`; `gk_bm2/core` untouched) is the default in the driver, `six_common.sh` and `run_all.sh`. `fast` is kept as a labelled comparison. Both real proofs were re-measured. |
| R2-2 | state carry not framed as a deviation; extra cost misreported (minor) | **Confirmed.** The 15k commit is paid by every port, so it is not extra. The real extra is the carried words' read plus the `carry` phase. | **Fixed.** A Caveats bullet in `gk_matched/README.md` and the zka README frames the deviation and why it is forced. It gives the per-config extra (read +108,984 / 99,984 / 107,184; carry 12,653 / 11,798 / 12,522; about 1.0-1.1% of the epoch). The column is relabelled `read (Events + carried state)`. |
| R2-3 | README pairs the cap 64/128 forests with (768, 512) (minor) | **Confirmed.** | **Fixed.** The text now says (128, 512) / (64, 512), and that config B is covered by `certify` and by M1, not by an `exp_compose` run. |
| R2-4 | `PAD_KEY` strip is dead code (minor) | **Confirmed.** | **Fixed.** The driver refuses a dataset with a `u32::MAX` key in the epochs it runs (exit 2). The READMEs state that zk-Analytics epochs carry no padding, so the strip is a no-op. |
| R2-5 | a config mismatch only warns while the label says "same rule" (minor) | **Confirmed.** | **Fixed.** `table.py` labels the GK row "CONFIG MISMATCH: same rule, NOT the same function" when `assemble.py` flagged it; tested on a doctored copy of `harness_smoke/`. |
| R2-6 | stale README numbers (minor) | **Confirmed.** | **Fixed.** The cold-build timing is marked as predating the 7th driver. The `full` estimate is marked as predating the matched GK, at about 2 min less for its two GK aggregation proofs (11.0 + 11.125 x 2^20 padded cycles with `tuned`). |
| R1-1 | "matched AVX2" premise does not hold: r0vm's prover has no AVX2 (major) | **Confirmed** (round 1's objdump). | **Partly fixed.** The headline is scalar zkSketch against r0vm as shipped, here and in round 1's (c). No committed doc claimed a matched AVX2 result. An AVX2-rebuilt r0vm was **not** built: it needs a decision and a long build. The plan file `latex/gk_bloom_redesign_plan.md` (§4.0 G-zka) is outside this branch and still names AVX2 as the fair configuration. |
| R1-2 | GK far from 10x; G1 misses 10x (major) | **Confirmed, and worse with `tuned`:** 1.99x / 3.07x today; G1 7.3-7.9x. | **Not fixed: a user decision** (G2-C, G1 at ≤ 33.8 s scalar, or a matched AVX2 comparison with a rebuilt r0vm). |
| R1-3 | zka itself peaks above 8 GiB (minor) | **Confirmed.** `tuned` gives r0vm 9,398 / 9,390 MiB and combined 9,428 / 9,424 MiB. | **Fixed (docs).** The zka README states zka's own peak next to the memory discussion. A smaller-segment r0vm was not measured (optional). |
| R1-4 | config B needs 17 GiB today (minor) | **Confirmed.** | Not fixed: M3 scope. |
| R1-5 | shared-box load (minor) | No action. | Both round-2 proofs ran gated, at 1.14-1.17 foreign busy cores on average. |
| R1-6 | additions and deviations disclosed (minor) | No action. | None. |

## New measurements (sandbox clone at `f669c92`, clean)

Toolchain and binaries:

- rustc 1.97.1 and r0vm 3.0.6 (md5 `9e13aa14c059`); zk-Analytics `d4a5a9a`.
- `run_all.sh build` and `check`: ok, 0 warnings, 7 drivers, implementation `tuned`.
- `gk_matched` md5 `c763ba4f4277`; ELFs `aggr_gkm` `bfc5cda6f751`, `querier_gkm` `44b7ffd00163`.

### Real proofs (`fixer/zka/`)

Both proofs: `run_zka.sh prove gk:aggr:0:noroot`, `SIX_ZKA_GK_IMPL=tuned`, `ProverOpts::succinct()`,
CPU. Each was gated as in round 1 (`gated.sh`: other users below 6 busy cores for 60 s, 590 s
watchdog).

| | config A (384, 128), 16 steps | config B (768, 512), 4 steps |
|---|---|---|
| prove_s | **352.402** | **338.099** |
| segments / padded / user cycles | 12 / 12,058,624 (11 x 2^20 + 2^19) / 10,979,416 | 11 / 11,534,336 / 10,693,564 |
| s per padded 2^20 | 30.64 | 30.74 |
| driver MODELED (segments x 30.1) | 361.2 (measured -2.4%) | 331.1 (+2.1%) |
| journal == native / state == zkSketch chain | true / true | true / true |
| verify (best of 5) / receipt | 9.700 ms / 225,114 B | 9.782 ms / 225,114 B |
| r0vm peak (driver sampler / rss_tree) / combined (memsample) | 9,398.0 / 9,391.4 / 9,428 MiB | 9,390.1 / 9,394.2 / 9,424 MiB |
| state_commit | `72e60704…` (= round 1, = every impl) | `01d8f68d…` (= round 1) |
| window, other users' busy cores mean / max | 16:45:59-16:51:52, 1.14 / 1.40 | 16:52:37-16:58:16, 1.17 / 2.72 |

The cost per padded 2^20 rose by 1.5% at A and 1.6% at B over round 1 (30.20 / 30.25). At A the
last segment is po2 19 and costs more than half a full one. Within the round-1 envelope, this
is noise.

### Executor (`fixer/exec/`, `fixer/equivalence/`)

All 60 executor rows (40 in `exec/`, 20 from `gk_matched_check.sh`) have `journal_eq_native=true` and
`state_eq_zksketch=true`. Every check row also has `query_eq_zksketch=true`. At every epoch all
implementations give the same `state_commit`.

| config | impl | e0 user cycles / segments (padded x 2^20) | e1 | GK update e0 | read e1 - e0 | carry e0 / e1 |
|---|---|---|---|---|---|---|
| A (384, 128) | **tuned** | 10,979,416 / 12 (11.5) | 11,085,631 / 12 (11.5) | 965,322 | 108,984 | 1,603 / 12,653 |
| A | fast | 11,879,837 / 13 (13.0) | 11,983,858 / 13 | 1,841,352 | 108,984 | 23,988 / 34,719 |
| B (768, 512) | **tuned** | 10,693,564 / 11 (11.0) | 10,822,662 / 12 (11.25) | 680,565 | 99,984 | 1,603 / 11,798 |
| B | fast | 11,047,367 / 12 (12.0) | 11,174,809 / 12 | 987,885 | 99,984 | 46,260 / 57,024 |
| D (2048, 2048) | **tuned** | 10,569,752 / 11 (11.0) | e7: 10,716,409 / 12 (11.125) | 555,837 | | 1,603 / e7 11,598 |

- **`fast` is unchanged** by this commit, apart from code layout: 11,879,837 vs round 1's
  11,879,811 (+26) at A and +14 at B, with the same segments and padded cycles. Round 1's two
  real `fast` proofs therefore stay valid as `fast` measurements.
- **Steelman sweep.** Same 2,048 AOL records, capacity 384, `tuned`, GK update by m_sub:

  | m_sub (steps) | GK update | user cycles / segments |
  |---|---|---|
  | 2048 (1) | 555,837 | 10.57M / 11 |
  | 512 (4) | 680,565 | 10.69M / 11 |
  | 256 (8) | 774,181 | 10.79M / 12 |
  | 128 (16) | 965,322 | 10.98M / 12 |

  The reviewer's `fast` numbers on the same records were 586,458 / 848,102 / 1,178,141 /
  1,841,333 (12 / 12 / 12 / 13 segments). `tuned` costs about 27k cycles per extra step, close
  to the schedule's own work per step.
- **Check rows (`fixer/exec/check.csv`, 26 rows):**
  - A, epochs 0-3: `tuned`, `fast`, `fixed_linear`. The answers are 1,778 / 3,539 / 5,268 / 7,089, the same as round 1.
  - B, epochs 0-1: all four implementations; 1,780 / 3,551.
  - D, epochs 0-1: `tuned`, `fast`.
  - (64, 256), epochs 0-1: `tuned`.
- **`gk_matched_check.sh` (`fixer/equivalence/`):** 8 unit tests passed, 16 check rows (A and B x 4 implementations x 2 epochs), and 4 aggr rows (`tuned`).
- **Negative control:** capacity 16 / m_sub 256 exits 3 (overflow detected on zkSketch's chain).
- **Determinism:** the development run before the commit (dirty clone, same sources) gave
  byte-identical rows.

### zkSketch's leaf circuit certifies the `tuned` guest's state (`fixer/certify/`)

`--mode certify` at config A, epochs 0-1, with the guest running `tuned`:

- zkSketch's GK leaf (hiding, built as `exp_compose` builds it) proved all 32 leaves, in 86.8 s and 87.1 s per epoch.
- Every exposed commitment equals Com of zkSketch's chain, and each epoch's last leaf exposes Com(S) of the `tuned` guest's state (`certified_eq=true`).
- The decoder's answers, 1,778 and 3,539, equal the query guest's.
- This was not gated: it is evidence, not timing.

## What stays valid from round 1

**Unchanged:**

- (b) zkSketch scalar vs AVX2;
- the SIMD finding;
- VK identity and cross-verification;
- (d) Bloom;
- every zkSketch time.

**Superseded as the headline** (still valid as `fast` measurements):

- (a) "Real proofs", now the `tuned` table above;
- (c) speedups and thresholds;
- the M3 projection.

**Measured but no longer the headline:** (a)'s executor rows for `fast`, `fixed_linear` and
`literal`, and the textbook reference.

**Estimate:** the zka Bloom time stays estimated, by decision.

## Files (`fixer/`, plain copies, never git-added)

- `zka/zkaA_tuned_e0/`, `zka/zkaB_tuned_e0/`: `meta.txt`, `out/six_zka_gk_prove.{csv,log}`, `mem.csv.gz`, `memsum.txt`.
- `exec/`: `check.csv`, `aggr.csv`, `sweep.csv`, `exec.log`, `neg.log`.
- `equivalence/`: the `gk_matched_check.sh` CSVs and log.
- `certify/`: the certify CSV and log, including `/usr/bin/time -v`.
- `load.csv`, `gated.log`.
- `build_run_all.log.gz`, `check_run_all.log`.
- `runner/`: `exec1.sh`, `certA.sh`, `jobs_tuned.txt`, plus round 1's `gated.sh`, `gate.py`, `zka_prove.sh`, `loadsample.py` and `memsample.py`, unchanged.

---

# Measurement (round 1, measurer), 2026-10-15 13:41-16:21, at `235c87b`

> Superseded as the zk-Analytics GK headline by the fixer round above (`tuned`); every number below
> is still a valid `fast` / zkSketch measurement.

## Verdict

**Every planned run completed, with correct and identical answers.**

| | result |
|---|---|
| **zk-Analytics GK at B = 2,048, real proofs** (zkSketch's rule, `fast`, noroot, epoch 0) | config A (cap 384, m_sub 128, 16 steps): **392.7 s**, 13 segments, r0vm peak **9,388 MiB**. Config B (cap 768, m_sub 512, 4 steps): **363.0 s**, 12 segments, r0vm peak **9,397 MiB**. Both: journal equal to the native one, verify 11.5 ms, 225,114-byte receipt. |
| Effective k_s | 30.20 and 30.25 s per 2^20 padded cycles, against the 30.07 calibration (+0.4 % and +0.6 %). The MODELED estimates (391.3 s and 361.2 s) were 0.3-0.5 % low. |
| 10x thresholds for zkSketch's B = 2,048 GK batch | **39.27 s** at config A, **36.30 s** at config B. The plan's thresholds were 39.9 / 42.1 s (textbook estimates 398.5 / 421.0 s). |
| zkSketch scalar vs AVX2 (`-C target-cpu=x86-64-v3`) | Root and leaf VK bytes are identical. Proofs cross-verify both ways, and a tampered proof is rejected. Answers are identical. Speed-up: **1.93x** (GK cap 384 / m 128 / T 16), **2.05x** (GK cap 768 / m 512 / T 4, config B's 2,048 records; 1.91x at T 2), **2.18x** (Bloom m 256 / T 8: 2.20x and 2.15x per repetition pair). Peaks do not change. |
| **Fair GK speedup today** (scalar zkSketch vs real zka; see the SIMD finding) | config A: 392.7 / 177.1 = **2.22x** (2.15-2.29x across runs). Config B (cap 768, m 512 x 4, measured): 363.0 / 110.0 = **3.30x** (3.29-3.31x), at a **17,177 MiB** combined peak, which fails 8 GiB. |
| Same, with zkSketch on AVX2 | 4.28x (A); 6.77x (B). Not a matched comparison: r0vm's prover has no AVX2 (next row). |
| **SIMD finding: the premise of the matched-AVX2 comparison does not hold** | r0vm 3.0.6 does have 5,065 `%ymm` instructions and 0 `%zmm`. But **all 5,065 are in 40 runtime-dispatched library functions**: ring (TLS ChaCha20-Poly1305, AES-GCM, P-256), aho-corasick, memchr, httparse and rand_chacha. **None is in the prover** (`risc0_zkp` CPU HAL, `risc0_circuit_*`). r0vm proves with baseline x86-64 (SSE2) code, like our scalar build, whose own 121 `%ymm` are all in the runtime-dispatched `chacha20` AVX2 backend. **So the matched configuration is scalar zkSketch vs r0vm as shipped.** The AVX2 rows are an upper bound: they would be matched only against an r0vm rebuilt for x86-64-v3, which was not built here. |
| Projected M3 (G1 stable compaction) at config B | Plan estimate 43-46 s (scalar) → **7.9-8.4x** against the real 363.0 s, which **misses 10x** (threshold 36.3 s). Scaled by the measured GK AVX2 factor (1.93 at A, 2.05 at B): 21.0-23.8 s → 15.2-17.3x. That is a projection, and only fair against an AVX2-rebuilt r0vm. |

**Load.** Another user's training sweep saturated the box for part of the session, at up to 63 busy
cores. Every measurement in the tables comes from a window in which other users used ≤ 1.3 busy
cores on average (`load.csv`), except Bloom's second repetition pair: 4.0 and 4.8, close to M0's
2.8-3.3. That pair needed three tries. Runs during the sweep were stopped or repeated (details under
"Host and load").

## (a) zk-Analytics GK at B = 2,048 (AOL, noroot, epoch 0 from empty, epoch 1 from the carried state)

### Real proofs (`run_zka.sh prove gk:aggr:0:noroot`; `ProverOpts::succinct()`, CPU r0vm 3.0.6, `fast`)

| | config A: cap 384, m_sub 128, 16 steps | config B: cap 768, m_sub 512, 4 steps |
|---|---|---|
| prove_s (measured) | **392.656** | **363.036** |
| segments / padded cycles / user cycles | 13 / 13,631,488 / 11,879,811 | 12 / 12,582,912 / 11,047,353 |
| s per segment (= per 2^20 padded cycles; every segment is po2 20) | 30.204 | 30.253 |
| MODELED (driver, 30.1 s/segment) | 391.3 (measured +0.3 %) | 361.2 (+0.5 %) |
| journal == native (asserted in the driver after proving) / state == zkSketch native chain | true / true | true / true |
| verify (best of 5, in process) | 11.548 ms | 11.517 ms |
| receipt (bincode) | 225,114 B | 225,114 B |
| r0vm peak RSS: driver's sampler / `rss_tree.sh` VmHWM | 9,388.1 / 9,392.0 MiB | 9,397.4 / 9,390.7 MiB |
| combined (driver + r0vm, `memsample.py` 0.1 s) | 9,404 MiB | 9,418 MiB |
| state_commit | `72e60704…` | `01d8f68d…` |
| window, others' busy cores (mean / max) | 14:09:11-14:15:47, 0.08 / 0.24 | 14:16:32-14:22:36, 0.06 / 0.25 |

- **Against the plan's numbers (§4.2).** The plan's estimates, 398.5 s (padded-cycle model) and
  421.0 s (segment model), were for the textbook GK. The real matched proofs are 1.5 % / 6.7 % below
  them at config A, and 8.9 % / 13.8 % below them at config B.
- **zk-Analytics' own memory is above 8 GiB.** Its peak, 9,388-9,418 MiB (9.2 GiB), is r0vm's default
  po2-20 segment prover. This was not tuned: it is their shipped configuration.

### Executor, B = 2,048, every implementation (`--mode aggr`, noroot; `exec/matched_exec.csv`)

All 12 matched rows have `journal_eq_native=true` and `state_eq_zksketch=true`. At each epoch the
three implementations give the same `state_commit`: config A `72e60704…` (e0) and `7ee84181…` (e1);
config B `01d8f68d…` (e0) and `e405e120…` (e1).

| zk-Analytics GK | impl | e0 user cycles | e0 segments / padded | e1 user cycles | e1 segments / padded | GK update cycles e0 | MODELED (30.1 s/seg) |
|---|---|---|---|---|---|---|---|
| matched A (384, 128) | **fast** | 11,879,811 | **13** / 13,631,488 | 11,983,830 | 13 / 13,631,488 | 1,841,333 | 391.3 s |
| matched A | fixed_linear | 16,674,928 | 18 / 18,350,080 | 16,793,396 | 18 / 18,350,080 | 6,636,447 | 541.8 s |
| matched A | literal | 30,321,517 | 37 / 38,797,312 | 30,412,361 | 37 / 38,797,312 | 20,283,039 | 1,113.7 s |
| matched B (768, 512) | **fast** | 11,047,353 | **12** / 12,582,912 | 11,174,793 | 12 / 12,582,912 | 987,878 | 361.2 s |
| matched B | fixed_linear | 14,777,788 | 16 / 16,252,928 | 14,903,136 | 16 / 16,777,216 | 4,718,310 | 481.6 s |
| matched B | literal | 25,295,351 | 31 / 31,981,568 | 25,456,818 | 31 / 32,505,856 | 15,235,876 | 933.1 s |
| **textbook `gk/` (reference only)** | | 12,862,178 | **14** / 13,893,632 | 12,958,972 | 14 / 14,155,776 | | 421.4 s |

- Their framework (Event read and batch-chain check) costs 9.85M cycles at epoch 0 (7.61M + 2.25M)
  and 9.95-9.96M at epoch 1, in every matched row.
- **The headline is `fast`**, the efficient data-dependent implementation, so zk-Analytics is
  steelmanned. `fixed_linear` (zkSketch's fixed schedule) and `literal` (zkSketch's native code,
  statement by statement) would only make zk-Analytics slower.
- **Textbook GK reference.** It was executed here only, not proved. The committed real proofs of it
  are from 2026-10-09 (`../six_zka_gk_prove.csv`, legacy root, 14 segments): 415.4 s (epoch 0) and
  424.6 s (epoch 7), with an r0vm peak of 9,397 MiB.

## (b) zkSketch scalar vs AVX2, M0 defaults

**What every run is.** One `six/run_zks.sh` run:

- forest, procs engine, 1 machine with 32 pinned cores, AOL keys, a query after every batch;
- default zero-knowledge build (`pcs=hiding`, `logup_mask=on`, recorded in every CSV row);
- no M0 switch set. `QLOG_WORKER` shows `merge_cache=hits/misses`, `retain_prep=false` and
  `trim=Every`.

**Memory.** Combined = coordinator (`exp_compose`) + worker (`zks_dc_exe_*`), VmRSS summed at the same
0.1 s sample by `memsample.py`, over the whole run. The run_zks.sh shells (12 MiB) are left out.

**Time.** Makespan = `total_time_ms`, the update makespan: leaves plus merges, the batch time that
M0 and the plan use.

### Per run, in run order (`runtable.md`)

| run | build | start | makespan s | leaves s (per leaf) | merges s (per merge; cache hits/misses) | VK phase s / peak MiB | worker peak MiB (coord + worker) | audit s / peak | queries s / peak | whole-run peak MiB | wall s | others' busy cores mean / max |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gkA_scalar_1 | scalar | 14:23:21 | 171.5 | 92.8 (5.80) | 75.3 (5.02; 7/8) | 7.5 / 4,390 | 5,202 (113 + 5,089) | 21.6 / 4,555 | 12.9 / 430 | 5,202 | 213.6 | 0.07 / 0.22 |
| gkA_avx2_1 | avx2 | 14:27:40 | 92.8 | 51.4 (3.21) | 38.4 (2.56; 7/8) | 4.6 / 4,352 | 5,226 (75 + 5,151) | 12.8 / 4,443 | 7.8 / 425 | 5,226 | 118.3 | 0.09 / 0.30 |
| gk768_scalar_1 | scalar | 14:30:24 | 55.9 | 43.8 (21.88) | 7.5 (7.55; 0/1) | 23.6 / 16,473 | 16,532 (107 + 16,425) | 7.4 / 4,548 | 2.4 / 699 | 16,532 | 89.7 | 0.06 / 0.08 |
| gk768_avx2_1 | avx2 | 14:32:41 | 28.2 | 21.0 (10.50) | 3.6 (3.64; 0/1) | 13.7 / 16,367 | 16,410 (64 + 16,346) | 4.3 / 4,447 | 1.6 / 645 | 16,410 | 48.0 | 0.10 / 0.23 |
| bloom_scalar_1 | scalar | 14:34:15 | 114.6 | 79.1 (9.89) | 31.5 (4.50; 3/4) | 19.3 / 7,776 | 8,257 (98 + 8,159) | 14.7 / 3,096 | 75.2 / 6,646 | 8,257 | 224.0 | 0.28 / 2.30 |
| bloom_avx2_1 | avx2 | 14:38:45 | 52.0 | 35.3 (4.41) | 13.6 (1.94; 3/4) | 11.1 / 7,759 | 8,237 (79 + 8,158) | 8.6 / 3,110 | 37.5 / 6,540 | 8,237 | 109.4 | 1.17 / 2.30 |
| gkA_avx2_2 | avx2 | 14:41:19 | 90.6 | 49.7 (3.11) | 37.9 (2.53; 7/8) | 4.6 / 4,297 | 5,178 (74 + 5,104) | 12.5 / 4,500 | 7.8 / 428 | 5,178 | 115.5 | 1.16 / 1.31 |
| gkA_scalar_2 | scalar | 14:44:01 | 182.8 | 100.1 (6.25) | 79.4 (5.29; 7/8) | 7.2 / 4,370 | 5,198 (99 + 5,099) | 21.0 / 4,529 | 12.4 / 418 | 5,198 | 223.6 | 1.15 / 1.49 |
| gk768_avx2_2 | avx2 | 14:48:30 | 29.4 | 22.6 (11.30) | 3.4 (3.37; 0/1) | 13.4 / 16,436 | 16,427 (68 + 16,359) | 4.1 / 4,519 | 1.5 / 654 | 16,436 | 48.6 | 1.26 / 1.53 |
| gk768_scalar_2 | scalar | 14:50:04 | 54.3 | 43.1 (21.57) | 6.6 (6.65; 0/1) | 23.2 / 16,426 | 16,561 (108 + 16,453) | 7.1 / 4,509 | 2.4 / 659 | 16,561 | 87.2 | 1.13 / 1.32 |
| CONTAM_bloom_avx2_2_try1 | avx2 | 14:52:17 | 113.2 | 74.8 (9.35) | 31.9 (4.56; 3/4) | 11.3 / 7,746 | 8,272 (85 + 8,187) | 20.6 / 3,083 | 83.9 / 6,549 | 8,272 | 229.2 | 48.67 / 59.13 |
| CONTAM_bloom_avx2_2_try2 | avx2 | 15:11:32 | 57.3 | 39.1 (4.88) | 15.2 (2.17; 3/4) | 11.0 / 7,756 | 8,267 (78 + 8,189) | 8.5 / 3,082 | 46.5 / 6,543 | 8,267 | 123.5 | 9.93 / 55.77 |
| bloom_avx2_2 | avx2 | 15:30:53 | 55.7 | 37.8 (4.73) | 14.4 (2.05; 3/4) | 10.6 / 7,763 | 8,247 (85 + 8,162) | 8.8 / 3,101 | 38.9 / 6,534 | 8,247 | 114.2 | 4.04 / 4.23 |
| bloom_scalar_2 | scalar | 15:33:35 | 119.8 | 83.8 (10.48) | 31.6 (4.51; 3/4) | 19.9 / 7,783 | 8,277 (120 + 8,157) | 14.8 / 3,124 | 81.7 / 6,688 | 8,277 | 236.4 | 4.77 / 18.91 |
| gk768x4_scalar_1 | scalar | 16:10:39 | 110.2 | 87.8 (21.95) | 17.3 (5.77; 1/2) | 23.5 / 16,418 | 17,181 (105 + 17,076) | 11.8 / 4,499 | 5.0 / 666 | 17,181 | 150.8 | 1.19 / 1.68 |
| gk768x4_avx2_1 | avx2 | 16:13:57 | 52.5 | 40.7 (10.17) | 8.1 (2.70; 1/2) | 13.2 / 16,332 | 17,210 (69 + 17,141) | 6.7 / 4,446 | 3.0 / 667 | 17,210 | 75.7 | 1.16 / 1.37 |
| gk768x4_avx2_2 | avx2 | 16:15:59 | 54.7 | 42.6 (10.64) | 8.3 (2.78; 1/2) | 13.3 / 16,378 | 17,134 (66 + 17,068) | 6.9 / 4,475 | 2.9 / 682 | 17,134 | 78.1 | 1.12 / 1.28 |
| gk768x4_scalar_2 | scalar | 16:18:02 | 109.8 | 87.6 (21.89) | 17.3 (5.76; 1/2) | 23.3 / 16,474 | 17,172 (109 + 17,063) | 11.9 / 4,502 | 4.9 / 681 | 17,172 | 150.2 | 1.18 / 1.96 |

The `CONTAM_*` rows were repeated and are left out of every mean (see "Host and load").

### Means (`means2.txt`)

| shape | build | makespan s | leaves s (per leaf) | merges s (per merge) | VK phase s | audit s | queries s | combined peak MiB | AVX2 factor (makespan / leaf / merge) |
|---|---|---|---|---|---|---|---|---|---|
| GK cap 384, m 128, T 16 (config A, 2,048 records) | scalar | **177.1** (171.5 / 182.8) | 96.4 (6.03) | 77.3 (5.16) | 7.4 | 21.3 | 12.7 | 5,200 (worker) | |
| | AVX2 | **91.7** (92.8 / 90.6) | 50.6 (3.16) | 38.1 (2.54) | 4.6 | 12.7 | 7.8 | 5,202 (worker) | **1.93** / 1.91 / 2.03 |
| GK cap 768, m 512, T 2 (today's circuit, 1,024 records) | scalar | 55.1 (55.9 / 54.3) | 43.5 (21.73) | 7.1 (7.10) | 23.4 | 7.3 | 2.4 | **16,547** (worker; VK phase 16,450) | |
| | AVX2 | 28.8 (28.2 / 29.4) | 21.8 (10.90) | 3.5 (3.50) | 13.6 | 4.2 | 1.5 | **16,423** | **1.91** / 1.99 / 2.03 |
| **GK cap 768, m 512, T 4 (config B, 2,048 records)** | scalar | **110.0** (110.2 / 109.8) | 87.7 (21.92) | 17.3 (5.77; 1 hit / 2 misses) | 23.4 | 11.9 | 5.0 | **17,177** (worker) | |
| | AVX2 | **53.6** (52.5 / 54.7) | 41.6 (10.41) | 8.2 (2.74) | 13.3 | 6.8 | 2.9 | **17,172** | **2.05** / 2.11 / 2.10 |
| Bloom m 256, T 8 (k 7, w 2^14, 2,048 records) | scalar | **117.2** (114.6 / 119.8) | 81.5 (10.18) | 31.5 (4.50) | 19.6 | 14.7 | 78.5 | 8,267 (worker) | |
| | AVX2 | **53.9** (52.0 / 55.7) | 36.5 (4.57) | 14.0 (1.99) | 10.9 | 8.7 | 38.2 | 8,242 (worker) | **2.18** / 2.23 / 2.26 |

**Cap 768 / m 512 does not fit 8 GiB today**, as expected:

- one leaf of today's bm2 circuit peaks at 16,346-17,141 MiB in the worker (17,177 MiB combined
  at T 4);
- the coordinator's VK derivation (its no-op leaf) also peaks at 16,332-16,474 MiB.

The T = 4 runs were added after the planned matrix, so that config B's 2,048-record batch is
measured rather than derived. Derived from T = 2 (4 x leaf + 3 x first-level merge) it would have
been 108.2 s scalar / 54.1 s AVX2: within 1.6 % and 1.0 % of the measured 110.0 / 53.6 s.

**Further observations:**

- **AVX2 leaves the serial parts of the ZK prover more exposed.** Our busy cores during a run were
  about 22-24 of the 32 pinned cores on scalar, and 13-14 on AVX2 (`load.csv`). The phases outside
  the prove loop gain less: VK derivation, audit and queries are 1.6-1.7x faster for GK.
- **Answers are identical across all clean runs and both builds.**
  - GK A at batches 1-16: `44 170 252 327 395 481 782 896 1002 1116 1231 1343 1454 1550 1664 1778`. These are M0's answers. The `QLOG_KEY` lines are identical to M0 round 2's (diff).
  - GK 768: `321 900` (T 2) and `321 900 1354 1780` (T 4). 1,780 after 2,048 records is the matched zk-Analytics query guest's config B answer.
  - Bloom: `1` at each of the 8 batches.
  - Every query was bound: 16, 2, 4 and 8 `QLOG_BIND` / `QLOG_BINDV` lines.
  - Every CSV has `status=ok`.
- **The last batch's answer matches the zk-Analytics side.** The answer after the 2,048th record
  at config A (1,778) is the matched zk-Analytics query guest's answer at config A, epoch 0
  (implementer's evidence below).

### AVX2 build checks (`simd/`, `xv/`)

| check | result |
|---|---|
| packing active | `objdump -d`, counting instructions that name a `%ymm` / `%zmm` register:<br>• scalar `exp_compose` (md5 `38c33b46bc13`): 121 `%ymm`, all in `chacha20::backends::avx2` (runtime-dispatched); 0 `%zmm`; 0 `vpmuludq %ymm`.<br>• AVX2 `exp_compose` (md5 `beced0ce5acb`): **86,093** `%ymm` in 1,741 functions, 7,535 `vpmuludq %ymm` (Montgomery products), 170 `PackedMontyField31AVX2` symbols (0 in scalar), 0 `%zmm`. |
| r0vm 3.0.6 (md5 `9e13aa14c059`) | 5,065 `%ymm`, 0 `%zmm`, in 40 functions: ring (3,857), aho-corasick (790), memchr (275), rand_chacha (124), httparse (19). **0** in any `risc0_*` function. It links only libc / libstdc++. `simd/r0vm_funcs.txt` lists them. |
| VK bytes, scalar vs AVX2 | Derived from public parameters only (a no-op leaf, then `derive_forest_root_vk`) by the scratch tool `runner/xverify.rs`, built in both configurations. **All 6 files are byte-identical:**<br>• GK cap 384 / m 128 leaf VK (229 B) and forest root VK over 16 leaves (197 B, md5 `aa12f25422fe57e8`);<br>• GK cap 768 / m 512 leaf VK (234 B) and root VK over 2 leaves (196 B, `5348b67af4cef65d`);<br>• Bloom k 7 / w 2^14 / m 256 leaf VK (205 B) and root VK over 8 leaves (195 B, `657e3dc3b028f1f4`).<br>The two root VKs at the M0 shapes equal, byte for byte (`cmp`), the VKs `exp_compose`'s own auditor saved in M0 (`../20261015-m0/measurer_round2/idruns/{gk,bloom}_B/root_vk.bin`). So the tool derives exactly what the harness derives. |
| VK saved by every measured run | Each run's auditor saved its root VK (`EXP_ROOT_VK_SAVE`, through the `zks_bin.sh` wrapper). All GK A runs: `aa12f25422fe57e8`. All GK 768 T 2 runs: `5348b67af4cef65d`. All Bloom runs, including the contaminated ones: `657e3dc3b028f1f4`. These 14 files are byte-identical (`cmp`) to the corresponding `xverify` VK. The 4 GK 768 T 4 runs all saved `672e75ab9b18224e` (197 B); `xverify` did not derive that shape. Scalar and AVX2 agree everywhere. |
| cross-verification | Each build proved 2 real AOL GK leaves (cap 384, m 128, hiding, test seed 1) and folded them into a forest root. **The scalar build verified the AVX2 build's leaves and root, and the AVX2 build verified the scalar build's**, against its own locally derived leaf and root VKs (`verify_leaf_proof_pinned`, `verify_bound_stark_proof_pinned`). Every exposed boundary equals Com of the native chain. Negative control: one flipped byte in the AVX2 root → the scalar build rejects it (`xv/verify_tampered_by_scalar.out`). |

## (c) The fair GK speedup today, and the M3 projection

zk-Analytics time = the real proofs of (a), epoch 0 (2,048 records). zkSketch time = the update
makespan for the same 2,048 records.

| GK configuration | zka real | zkSketch scalar | **speedup, scalar (matched)** | zkSketch AVX2 | speedup, AVX2 (vs r0vm as shipped) | zkSketch combined peak | 10x threshold |
|---|---|---|---|---|---|---|---|
| A: cap 384, m 128 x 16 (measured, T = 16) | 392.66 s | 177.13 s (171.5-182.8) | **2.22x** (2.15-2.29) | 91.72 s | 4.28x (4.23-4.34) | 5,200 MiB | 39.27 s |
| B: cap 768, m 512 x 4, today's bm2 (measured, T = 4) | 363.04 s | 110.00 s (109.8-110.2) | **3.30x** (3.29-3.31) | 53.59 s (52.5-54.7) | 6.77x (6.64-6.91) | **17,177 MiB (fails 8 GiB)** | 36.30 s |
| **B with M3 / G1 stable compaction (PROJECTION)** | 363.04 s | **43-46 s** (plan §2 G1 estimate, scalar; not measured) | **7.9-8.4x: misses 10x** | 21.0-23.8 s (= 43-46 / measured GK AVX2 factor 1.93-2.05) | 15.2-17.3x (fair only against an AVX2-rebuilt r0vm, which was not built) | not measured or estimated here | 36.30 s |

- **The plan's 10x criterion needs a matched comparison** (plan §4.0 G-zka: "Scalar against r0vm as
  shipped, or native against r0vm rebuilt native").
  - Today, at matched scalar, zkSketch's GK is **2.2x (A)** and **3.3x (B, 17,177 MiB)** faster.
  - The G1 projection reaches **7.9-8.4x** at config B, short of 10x.
  - Reaching 10x on the GK side needs one of these, in the plan's own terms:
    - G1 ≤ 36.3 s scalar;
    - G2-C;
    - an AVX2 comparison against an r0vm rebuilt with the same flags. That rebuild is not done. Its
      own AVX2 gain is unknown: r0vm's CPU prover was not built with AVX2, so nobody has measured it.

## (d) Bloom AVX2 factor (m 256, T 8, k 7, w 2^14)

| Bloom m 256, T 8 (`bloom_omc`, M0 defaults) | scalar | AVX2 | AVX2 factor |
|---|---|---|---|
| update makespan | 117.2 s (114.6 / 119.8) | 53.9 s (52.0 / 55.7) | **2.18x** (rep 1 pair 2.20x, rep 2 pair 2.15x) |
| 8 leaves (per leaf) | 81.5 s (10.18) | 36.5 s (4.57) | 2.23x |
| 7 merges (per merge; cache 3 hits / 4 misses) | 31.5 s (4.50) | 14.0 s (1.99) | 2.26x |
| VK derivation (coordinator) | 19.6 s | 10.9 s | 1.80x |
| audit | 14.7 s | 8.7 s | 1.69x |
| 8 queries | 78.5 s | 38.2 s | 2.05x |
| wall | 230.2 s | 111.8 s | 2.06x |
| combined peak | 8,267 MiB (worker phase) | 8,242 MiB | unchanged |

- **Memory.** The peak is the same, and still above 8 GiB (8,192 MiB) in both builds, as in M0
  (8,291 MiB). The peak is set by the worker's leaf; packing does not change the memory.
- **Most of the plan's native-SIMD gain comes from AVX2 alone.** Plan §1.5 measured 2.1-2.4x with
  `-C target-cpu=native` on every ZK leaf and merge. AVX2 alone gives 2.23-2.26x on Bloom leaves and
  merges, and 1.91-2.11x on GK ones.
- **The same fairness caveat applies to any Bloom AVX2 ratio against zk-Analytics.** r0vm's
  prover is scalar.

The zk-Analytics Bloom time stays estimated, by the user's decision: no 45-50 min run.

## Build, commits, measured vs estimated

| | |
|---|---|
| code | Sandbox clone `$HOME/zkSketch` (`HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold`), synced with `git fetch /home/binbin/zkSketch m1-gk-matched && git checkout -q -B m1-gk-matched FETCH_HEAD` → `235c87b`. Clean: every run log records `HEAD=235c87be2 dirty_files_outside_results=0`. The scratch tool `examples/xverify.rs` was copied in only while it was built, then deleted, before any measured run (`git status` empty afterwards). |
| build (both sides) | `scripts/baselines/zka/six/run_all.sh build`: all 8 builds ok (`build_run_all.log.gz`), in 30 s.<br>• `exp_compose` was not rebuilt: md5 `38c33b46bc13`, the binary M0 measured.<br>• `gk_matched` md5 `b18f09993e7b`; ELFs `aggr_gkm` `0c515a0a`, `querier_gkm` `46880a39`.<br>• textbook `gk` md5 `b62f3f8b45e9`. |
| scalar zkSketch | `cargo build --release --locked --example exp_compose`, `CARGO_TARGET_DIR=$HOME/zkSketch/target`, **no RUSTFLAGS**: `p3-monty-31` `no_packing`. Profile: opt-level 3, `lto = "thin"`, `codegen-units = 1`. Features: default (hiding PCS, LogUp masks). |
| AVX2 zkSketch | The same command with `CARGO_TARGET_DIR=$HOME/target-avx2 RUSTFLAGS="-C target-cpu=x86-64-v3"` (AVX2 + FMA + BMI2, no AVX-512); md5 `beced0ce5acb`; 3 min 4 s (`build_avx2.log`). The scalar binary was not touched. |
| toolchains | rustc / cargo 1.97.1; r0vm 3.0.6 (`risc0-r0vm 3.0.6`, md5 `9e13aa14c059`); zk-Analytics clone `d4a5a9a`. |
| zka driver | `run_zka.sh prove` with `SIX_M=2048 SIX_T=1 SIX_GK_CAP=<cap> SIX_GK_MSUB=<m_sub> SIX_ZKA_GK=matched SIX_ZKA_GK_IMPL=fast GATE_WAIT_S=0` (`runner/zka_prove.sh`). |
| zks driver | `run_zks.sh <gk\|bloom>` with `SIX_M SIX_T SIX_GK_CAP GATE_WAIT_S=0 EXP_VERIFY_REPEATS=5 ZKS_BIN=<wrapper>` (`runner/runzks.sh`).<br>• The wrapper (`zks_bin.sh` in each run directory) is `export EXP_ROOT_VK_SAVE=...; exec <real exp_compose>`. It keeps the same PID, and the worker snapshot is `/proc/self/exe`, the real binary.<br>• So the `bin_md5` column of `six_zksketch_runs.csv` is the wrapper's. The real binary's md5 is in each `meta.txt`. |
| **measured** | everything in (a), (b) and (d); the zka executor rows; VK bytes; cross-verification; objdump counts |
| **derived** | nothing in the speedups. Config B's batch was first derived from T = 2, then measured at T = 4 (extra runs `gk768x4_*`, gated like the rest, sampled in `load2.csv`). |
| **estimated (not measured)** | the M3 / G1 batch time (plan §2: 43-46 s); its AVX2 scaling; the zka Bloom time (unchanged, by decision); any AVX2-rebuilt r0vm |

## Host and load

**Host.** SPRL6201019991: AMD Threadripper PRO 9975WX, 32 cores / 64 threads, 559 GiB.

**Load sampling.** `runner/loadsample.py` sampled the whole session every 5 s (`load.csv`): the
1-minute load, and the busy cores of this uid and of other uids.

**Gate.** Before every run, `runner/gated.sh` waited 45 s, then waited for `gate.py`: other users
below 6 busy cores for 60 s. After the run it checked the run window, and **repeated any run whose
mean foreign load exceeded 6 busy cores** (at most 3 tries). A 590 s watchdog stops any run, so
none can exceed 10 min.

`run_zks.sh` / `run_zka.sh` record their own gate as `busy:load1=...`. That gate is the 1-minute
load average, which still contains our previous run's decay. The foreign load is the column below.

| run | window | load1 mean / max | busy cores, others: mean / max | busy cores, ours: mean |
|---|---|---|---|---|
| ABORTED_zkaA_e0_try1 | 13:53:45-14:04:26 | 100.0 / 111.3 | 32.53 / 53.24 | 28.0 |
| zkaA_e0 | 14:09:11-14:15:47 | 45.3 / 55.9 | 0.08 / 0.24 | 49.3 |
| zkaB_e0 | 14:16:32-14:22:36 | 47.7 / 54.6 | 0.06 / 0.25 | 50.1 |
| gkA_scalar_1 | 14:23:21-14:26:55 | 22.9 / 25.9 | 0.07 / 0.22 | 23.4 |
| gkA_avx2_1 | 14:27:40-14:29:39 | 13.7 / 16.1 | 0.09 / 0.30 | 12.8 |
| gk768_scalar_1 | 14:30:24-14:31:56 | 16.0 / 25.7 | 0.06 / 0.08 | 24.0 |
| gk768_avx2_1 | 14:32:41-14:33:30 | 13.1 / 16.1 | 0.10 / 0.23 | 13.4 |
| bloom_scalar_1 | 14:34:15-14:38:00 | 21.0 / 25.5 | 0.28 / 2.30 | 22.5 |
| bloom_avx2_1 | 14:38:45-14:40:34 | 15.9 / 21.7 | 1.17 / 2.30 | 14.1 |
| gkA_avx2_2 | 14:41:19-14:43:15 | 15.9 / 24.1 | 1.16 / 1.31 | 13.0 |
| gkA_scalar_2 | 14:44:01-14:47:45 | 21.9 / 32.2 | 1.15 / 1.49 | 21.4 |
| gk768_avx2_2 | 14:48:30-14:49:19 | 21.4 / 26.9 | 1.26 / 1.53 | 14.0 |
| gk768_scalar_2 | 14:50:04-14:51:32 | 26.1 / 30.0 | 1.13 / 1.32 | 24.1 |
| CONTAM_bloom_avx2_2_try1 | 14:52:17-14:56:07 | 59.5 / 75.8 | 48.67 / 59.13 | 7.5 |
| CONTAM_bloom_avx2_2_try2 | 15:11:32-15:13:38 | 15.0 / 26.9 | 9.93 / 55.77 | 12.6 |
| bloom_avx2_2 | 15:30:53-15:32:50 | 10.0 / 15.2 | 4.04 / 4.23 | 12.4 |
| bloom_scalar_2 | 15:33:35-15:37:32 | 23.3 / 29.4 | 4.77 / 18.91 | 22.8 |
| gk768x4_scalar_1 | 16:10:39-16:13:12 | 17.5 / 28.3 | 1.19 / 1.68 | 23.4 |
| gk768x4_avx2_1 | 16:13:57-16:15:14 | 13.2 / 19.6 | 1.16 / 1.37 | 14.5 |
| gk768x4_avx2_2 | 16:15:59-16:17:17 | 11.8 / 14.9 | 1.12 / 1.28 | 14.0 |
| gk768x4_scalar_2 | 16:18:02-16:20:35 | 21.5 / 26.4 | 1.18 / 1.96 | 24.2 |

**Runs discarded for foreign load** (kept as `CONTAM_*` / `ABORTED_*`; the contaminated zkSketch runs'
answers and VKs were still correct; the aborted zka run produced no row):

- `ABORTED_zkaA_e0_try1` (13:53-14:04):
  - the first zka config A proof, started before the gate existed;
  - another user's 6-run training sweep started at the same moment (load1 about 105, 33 foreign busy cores on average, up to 53);
  - it had not finished after 10 min 40 s, so it was stopped (TERM to its `run_zka.sh`, which stops its process group).
- `CONTAM_bloom_avx2_2_try1`: 49 foreign busy cores on average; makespan 113.2 s, against 52.0 s clean.
- `CONTAM_bloom_avx2_2_try2`: the sweep restarted 90 s into the run; makespan 57.3 s.
- `bloom_avx2_2` (try 3) and `bloom_scalar_2` count as clean under the rule (mean ≤ 6), but ran at 4.0 and
  4.8 foreign busy cores on average; `bloom_scalar_2` had one spike to 18.9. The other clean runs ran at
  ≤ 1.3. Both builds' repetition-2 makespans are 4-7 % above repetition 1, so the AVX2 factor barely
  moves (2.20x and 2.15x per pair).

## Files (`measure/`, plain copies, never git-added)

- `exec/`:
  - `matched_exec.csv`: 12 rows, configs A and B × fast / fixed_linear / literal × epochs 0-1;
  - `textbook_exec.csv`: 2 rows;
  - `exec.log`: with provenance.
- `zka/<label>/`:
  - `meta.txt`: window and foreign load;
  - `out/six_zka_gk_prove.{csv,log}`, `out/six_zka_jobs.csv`;
  - `mem.csv.gz`, `memsum.txt`;
  - `ABORTED_zkaA_e0_try1`.
- `runs/<label>/`:
  - `meta.txt`, `zks_bin.sh`, `root_vk.bin`, `run_zks.stderr`;
  - `out/six_zksketch_<tag>.{log,csv}`, `out/six_zksketch_runs.csv`;
  - `mem.csv.gz`, `memsum.txt`;
  - `phases.json`, `phases.txt`.
- `runtable.md`, `means2.txt`, `means2.json`, `answers.txt`, `loadwin.md`, `load.csv` + `load2.csv` (the second sampler, for the T = 4 runs), `gated1.log` + `gated2.log`.
- `simd/`:
  - `counts.txt`;
  - `{scalar,avx2,r0vm}_funcs.txt`: per-function `%ymm` counts.
- `xv/`:
  - `vk_scalar/`, `vk_avx2/`: the six VK files each;
  - the prove / verify outputs and `xv.log`. The proof files themselves (5 MB) stayed in scratch.
- `build_avx2.log`, `build_run_all.log.gz`.
- `runner/`:
  - the scripts, run from the session scratch directory `.../scratchpad/m1/meas/`;
  - `env.sh`, `exec_matrix.sh`, `zka_prove.sh`, `runzks.sh`, `gated.sh`, `gate.py`, `jobs1.txt`, `jobs2.txt`, `build_avx2.sh`, `xv.sh`;
  - `xverify.rs`: the scratch tool, built as an example only while checking;
  - `simdfuncs.py`, `memsample.py`, `loadsample.py`, `phases.py`, `means2.py`, `runtable.py`, `answers.py`, `loadwin.py`.

---

# Implementation and equivalence (implementer, commit `235c87b`): zkSketch's GK algorithm on the zk-Analytics side

**User requirement.** The GK algorithm on the zk-Analytics side must be zkSketch's own, not a
different or simplified GK. The six-sketch harness used textbook Greenwald-Khanna
(`scripts/baselines/zka/gk`: per-record INSERT / COMPRESS, a summary rebuilt every epoch, a
k-way COMBINE at query time). That is a different function from the one zkSketch certifies.

**What was built** (branch `m1-gk-matched`, commit `235c87b`, message "update"):
`scripts/baselines/zka/gk_matched/`. It keeps zk-Analytics' pipeline step for step, as in
the other ports:

- their batch-chain check (`verify_and_compute_chain`, verbatim), Event deserialisation and
  flatten;
- a flat unsalted SHA-256 `state_commit` and their `EpochChainLink`;
- `noroot` = no per-bucket root.

Only the summary update is swapped, for zkSketch's GK batch rule (`apply_batch2` from
`gk_bm2/core`, unchanged). Each epoch of B records is applied as B / m_sub successive steps
(capacity `cap`, s = 51), starting from the previous epoch's state. That state is carried
as input and checked against the previous epoch's `state_commit` through the epoch link;
epoch 0 starts from the empty state.

- A capacity overflow is a hard error: the guest panics and the driver exits 3.
- The query guest re-verifies the epoch chain and requires one unbroken chain. It opens the
  latest state against the last link and answers rank(v) with zkSketch's GK decoder
  estimator.
- The harness uses this port for GK by default (`SIX_ZKA_GK=matched`); the textbook port
  remains as the labelled reference (`SIX_ZKA_GK=textbook`).

**Verdict: the zk-Analytics GK now computes exactly zkSketch's function.** It is
tuple-equal to zkSketch's native chain and to the states zkSketch's own leaf circuit
certifies, and it gives the same answers as zkSketch's `exp_compose` forests.

## Where and how it ran

| | |
|---|---|
| host | SPRL6201019991, AMD Threadripper PRO 9975WX (32 cores / 64 threads), shared box (load at the start of the evidence run: 2.05, see `equivalence/AB/zka_gk_matched_check.log`) |
| sandbox | `HOME=/home/binbin/six-repro-verify/round-shared/home-r3cold` (fresh toolchains: rustc 1.97.1, r0vm 3.0.6), its own clone `$HOME/zkSketch` checked out at `235c87b` (`git fetch /home/binbin/zkSketch m1-gk-matched`), `BASELINE_DIR=$HOME/ext-baselines` (zk-Analytics `d4a5a9a`) |
| build | `scripts/baselines/zka/six/build.sh zka`: all 7 zk-Analytics-side drivers ok; ELF `aggr_gkm` md5 `0c515a0a`, `querier_gkm` md5 `46880a39` (both depend on the checkout path) |
| check | `six/run_all.sh check`: ok, 0 warnings |
| environment | `scripts/env.sh` (its `WT` line is the development worktree; the evidence below ran in the sandbox clone) |

## Equivalence evidence (`equivalence/`)

All rows below are executor runs of the guests, plus real zkSketch STARK proofs in
`certify`. Nothing on the zk-Analytics side was proved here except the smoke test at the
end.

| check | configurations | result |
|---|---|---|
| native unit tests (`cargo test --release --locked -p gk-matched-host`, 6 tests) | chain at (384,128), (768,512), (2048,2048), (64,256) x 3 implementations; carried-state binding; overflow; estimator; root variants; query linkage | 6 passed (`AB/runner.out`) |
| `--mode check`: guest-emitted state vs zkSketch's native `apply_batch2` chain, all 7 fields of every row + n + parameters; journal vs native; query bounds vs zkSketch `rank_interval` | (384,128) 16 steps/epoch, (768,512) 4 steps, (2048,2048) 1 step; epochs 0 and 1; `fast`, `fixed_linear`, `literal` | 18 rows, every one `journal_eq_native=true`, `state_eq_zksketch=true(tuples)`, `query_eq_zksketch=true` (`AB/`, `D/zka_gk_matched_check.csv`) |
| `--mode certify`: zkSketch's GK leaf circuit built as `exp_compose` builds it (hiding commitments, public test seed 1), every leaf of epochs 0-1 proved; each leaf's exposed init / final Com equals Com of zkSketch's native chain; each epoch's last leaf exposes Com(S) of the GUEST's state; zkSketch's decoder proof on that state answers what `querier_gkm` answers | (384,128): 32 leaves, 90.0 + 89.5 s; (768,512): 8 leaves, 74.1 + 74.3 s | 4 rows, all `certified_eq=true`; decoder 1,778 / 3,539 and 1,780 / 3,551 = query guest (`AB/zka_gk_matched_certify.csv`) |
| zkSketch `exp_compose` answers (committed runs) vs the query guest | memmatch-20261014 forests (384/128 x 16 leaves, 128/512 and 64/512 x 4 leaves, 2048/2048 x 1) at n = 1; the committed six-sketch runs `six_zksketch_gk` and `six_zksketch_r2_gk` (2048/2048, 8 carried epochs) at n = 1..8 | 20 of 20 equal (`exp_compose_crosscheck.csv`, made by `scripts/xcheck.py`) |
| six harness end to end (`harness_smoke/`, quick shape: 2 x 256 records, cap 512) | zkSketch `run_zks.sh gk` + zk-Analytics `run_zka.sh exec/qexec/prove` + `prof_exec.sh` + `assemble.py` + `table.py` | answers 171 / 330 on both sides (exact 173 / 328); `gk:aggr:0:noroot` and `gk:query:1:1242150` proved (2 segments, 58.4 s, r0vm 9.4 GB; 1 segment, 9.1 s, r0vm 2.3 GB; journal == native); table labels "same rule both sides" |

The `certify` runs used 16.9 GB of peak RSS at (768, 512) (`/usr/bin/time`, development
run). The zkSketch leaf times are not measurements: no gate was applied and the run
shared the box.

## Executor cost, one 2,048-record AOL epoch (noroot, `fast`)

Source: `equivalence/{AB,D}/zka_gk_matched_aggr.csv`. Phases are in user cycles, from the
guest's marks. MODELED = segments x 30.1 s/segment; it is not a measured time.

| zk-Analytics GK | epoch | user cycles | segments | padded cycles | Event read | batch chain | GK update | rest | MODELED |
|---|---|---|---|---|---|---|---|---|---|
| matched (384, 128), 16 steps | 0 | 11,879,811 | 13 | 13,631,488 | 7,605,762 | 2,245,157 | 1,841,333 | 187,559 | 391 s |
| matched (384, 128) | 1 | 11,983,830 | 13 | 13,631,488 | 7,714,746 | 2,245,656 | 1,826,401 | 197,027 | 391 s |
| matched (768, 512), 4 steps | 0 | 11,047,353 | 12 | 12,582,912 | 7,605,762 | 2,245,157 | 987,878 | 208,556 | 361 s |
| matched (768, 512) | 1 | 11,174,793 | 12 | 12,582,912 | 7,705,746 | 2,245,656 | 1,004,059 | 219,332 | 361 s |
| matched (2048, 2048), 1 step | 0 | 10,872,657 | 12 | 12,058,624 | 7,605,762 | 2,245,157 | 737,882 | 283,856 | 361 s |
| textbook `gk/` (memmatch-20261014, `zka-m2048`) | 0 | 12,862,178 | 14 | 13,893,632 | | | | | 421 s |

- **The matched baseline is slightly cheaper than the textbook one.** zk-Analytics'
  framework (Event read + batch chain) is 83-91% of each epoch either way.
  - At k_s = 30.07 s per 2^20 padded cycles, the zk-Analytics estimate is 390.9 s at
    (384, 128) and 360.8 s at (768, 512), instead of 398.5 s.
  - So the GK 10x threshold for zkSketch tightens from 39.9 s to **39.1 s at config A**
    and **36.1 s at config B**.
  - These are estimates; the real B = 2,048 aggregation proof is still to be measured.
- **Implementation sensitivity** (epoch 0, user cycles / segments):

  | config | `fast` | `fixed_linear` | `literal` |
  |---|---|---|---|
  | (384, 128) | 11.92M / 13 | 16.71M / 18 | 30.36M / 37 |
  | (768, 512) | 11.12M / 12 | 14.85M / 16 | 25.37M / 31 |
  | (2048, 2048) | 11.08M / 12 | 14.35M / 16 | 23.69M / 30 |

  These are check rows, which include about 38k cycles of state emission.
- **Accuracy** (native checks of the guest's state): every exact rank of every covered value
  lies inside the decoder's [lo, hi]. The certified half-width is ≤ εN: 37 vs 40.2 and 77 vs
  80.3 at (384, 128).

## Harness behaviour (in the commit)

- `SIX_ZKA_GK=matched|textbook` (default matched).
  - `run_zka.sh` passes `--capacity $SIX_GK_CAP --m-sub $SIX_GK_MSUB --s 51 --impl
    $SIX_ZKA_GK_IMPL`, where `SIX_GK_MSUB` defaults to `SIX_M`, the zkSketch leaf size of
    the same run.
  - It refuses `legacy` for the matched GK.
- `build.sh` builds both GK drivers. `run_all.sh check` knows 7 drivers and checks the new
  knobs, and its stale check covers `gk_matched/` and `gk_bm2/core`.
- `prof_exec.sh` profiles the textbook GK only. The matched rows carry a `prof` column,
  which `table.py` reads.
- `assemble.py` names the matched rows `zk-Analytics arch. (port †, zkSketch GK rule)`, puts
  the configuration in `note` and warns when it differs from the zkSketch GK CSV.
  `table.py` labels the GK row "same rule both sides", or "zkA: textbook GK".
- **Committed reference set** (`legacy_check/committed_set_check.txt`): re-assembling it
  with the new `assemble.py` gives a byte-identical CSV. `table.py` changes only the GK label
  and adds one note line saying that the set's zk-Analytics GK is textbook.

## Files

- `equivalence/AB/`: runner output, log with provenance, check / aggr / certify CSVs for
  configs A (384, 128) and B (768, 512).
- `equivalence/D/`: the same, without certify, for (2048, 2048).
- `equivalence/zka_gk_matched_query.csv`: query rows at (2048, 2048) for n = 1..8, and at
  (128, 512) and (64, 512) for n = 1.
- `equivalence/exp_compose_crosscheck.csv`: the 20 comparisons with `exp_compose`.
- `harness_smoke/`: the smoke-test results directory, including `six_sketch_table.md`,
  `six_sketch_comparison.csv` and the zkSketch run.
- `legacy_check/`: the committed-set rendering check.
- `scripts/`:
  - `env.sh`;
  - `post.sh`: the D runs and the queries;
  - `smoke.sh`;
  - `xcheck.py`;
  - `lockmerge.py` / `lockmerge2.py`: the lock seeding. The host `Cargo.lock` is a priority
    merge of `gk/Cargo.lock`, the zkSketch `Cargo.lock` and `gk_bm2/Cargo.lock`, resolved
    with `cargo update -w --offline`; every third-party entry is in one of them. The guest
    lock's third-party entries are exactly `gk/guests/Cargo.lock`'s.
