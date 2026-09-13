# zk-Analytics comparison harness

Drivers, results and provenance for the zkSketch vs zk-Analytics comparison
(Zhu et al., "Zero-Knowledge Cloud Analytics", SIGCOMM '26). Their code is not
vendored: `../fetch_baselines.sh` clones it at `d4a5a9a` into `$BASELINE_DIR`
(default `~/ext-baselines`), and the zk-Analytics-side builds go under that
directory too (see Layout).

## Running

```bash
scripts/baselines/fetch_baselines.sh
scripts/baselines/zka/a1_cycles.sh
```

Scripts run from any directory; `common.sh` resolves locations.

| Variable | Default | Meaning |
|---|---|---|
| `BASELINE_DIR` | `~/ext-baselines` | zk-Analytics clone and its builds |
| `RESULTS` | `results/` next to the scripts | where CSVs and logs are written |
| `CM_TOPK_SLOTS` | per script | zk-Analytics top-k heap slots, a build-time constant |

`ourcm/` and `zksq/` build against the zkSketch checkout they sit in, so a
worktree measures its own sources.

| Script | Proves | Writes to `$RESULTS` | Measures |
|---|---|---|---|
| `a1_cycles.sh` | no | `a1_cycles.csv` | their CM aggregation guest cycles, T in {100, 8, 1} |
| `sha_accel_control.sh` | no | `sha_accel_control.csv` | the same guest with and without risc0's SHA-256 accelerator patch |
| `accuracy.sh` | no | `accuracy_parity.csv`, `accuracy_parity_summary.txt`, `native_baseline.txt` | Count-Min error laws of both systems; plaintext cost |
| `q_sweep.sh` | yes (`--exec`: no) | `zka_query_sweep.csv` | their whole-prefix CM query over n epochs |
| `our_query.sh` | yes (`DRY_RUN=1`: no) | `zks_query_matched.csv` | zkSketch query cost at the matched d=3, w=1024 |
| `compare.sh` | yes, hours | `zks_matched_*.csv`, `zka_matched.csv`, `q_n*.log` | four-metric update comparison, their query sweep |
| `a234.sh` | yes | `a2_anchor.csv`, `a4_native.log`, `a3_n*.log` | prove-time anchors, their native baseline, query slope |
| `rss_watch.sh` | no | stdout | wraps a command and reports r0vm peak RSS |

`compare.sh`, `q_sweep.sh` and `rss_watch.sh` refuse to start while an `r0vm`
of yours is running, then kill this user's `r0vm` processes around their own
runs. `our_query.sh` kills this user's leftover `exp_compose` workers on exit.
Don't run them next to another job of yours.

## Layout

- `cyc/` drives their guests. It is built once per `CM_TOPK_SLOTS` value into
  `$BASELINE_DIR/build/cyc-t<T>`: T is baked into both the host binary and the
  guest ELF, and a shared target dir let a T=1 build relink binaries another
  script expected at T=100. Its path dependencies go through `.zka`, an
  untracked symlink to the clone that `common.sh` creates.
- Other build locations: `build/ourcm`, `build/zksq` and `build/shaccel` under
  `$BASELINE_DIR`; `nb-target-<T>` (`accuracy.sh native`) and `zka/target`
  (`a234.sh`, `compare.sh`) inside the clone's directory. `compare.sh` S1/S2 and
  `our_query.sh` Q1 build zkSketch's `exp_compose` in this checkout's `target/`.
- `sha2-risc0-accel.patch` is the complete accelerator change: the root
  `[patch.crates-io]`, the `=0.10.6` pins in `aggregator/core` and
  `querier/core`, and the `Cargo.lock` hunk. The `[patch]` section on its own
  does nothing, because the lock keeps sha2 0.10.9.
- `cyc/Cargo.lock` pins the host binaries and builds use `--locked`. The guest
  ELFs resolve from the clone's own `Cargo.lock`; `RISC0_BUILD_LOCKED=1` makes
  risc0-build's nested guest build honour it.
- `results/*.log` are the raw console logs behind the CSVs; `.gitignore`
  re-includes them against the repo-wide `*.log` rule.
- `steelman_plan.md` is a plan snapshot. It cites the pre-move `~/ext-baselines`
  paths, and its premise that their guests run software SHA-256 was later
  refuted (see `sha_accel_control.sh`).

## Provenance

Copied from `~/ext-baselines` on 2026-09-13 and checked by re-running from here:

- all 14 guest ELFs rebuilt at T=1 and T=100 are byte-identical to the ones
  that produced `results/`;
- `a1_cycles.sh` reproduces every cycle count in `a1_cycles.csv`;
- `accuracy.sh accuracy` reproduces `accuracy_parity.csv` and its summary byte for byte;
- `q_sweep.sh --exec` reproduces the measured cycle count at n=4;
- `our_query.sh` with `PHASES=q0 DRY_RUN=1` builds `cmq` from here and runs its
  no-proof path with the same configuration as the measured rows.

Prover timings were not re-run.

`sha_accel_control.csv` was re-measured on 2026-09-13. The 2026-09-12 file had
the same numbers, but its "accel" arm ran the unpatched guest, the same ELF as
the baseline. The new file records both ELF hashes (`90fce45d…` baseline,
`bab5ef8f…` patched). The cycle counts are still identical because their guest
already calls risc0's accelerated SHA-256.
