# frame_out_1machine_plonky3.csv — DERIVED, NOT MEASURED

Rows are projections for `machines=1` computed from the **measured**
`frame_out_4machine_plonky3.csv` (aol, forest, hoisted leaf circuits), plus two
measured 1-machine smoke anchors (`smoke_hoist_cm_1m.csv`, t=4;
`smoke_hoist_hll_b14.csv`, t=2). The `status` column says `estimated`.

## Model

Forest mode on one machine proves all `t=64` leaves sequentially on one worker
and folds in place; there are no cross-machine merges.

Carried over unchanged from the 4-machine row (machine-count independent):
`leafgen_seq_ms` (sum of per-leaf witness+prove — measured per leaf),
`witness_pass_ms`, `verify_ms`, `proof_bytes`, `peak_rss_mb` (the two smokes
matched the 4-machine values within 1–2%: proving memory is per-worker and the
coordinator's VmHWM tracks the max), `scatter_ms`, `scatter_data_bytes`
(all 64 batches go to the one worker), and the shape/query columns.

Derived:
- `build once` = leafgen_ms(4m) − leaf_busy_max_ms(4m)  [one circuit build + collect skew]
- `local_fold_ms(1m)` = local_fold_ms(4m) / 15 × 63     [per-merge cost × 63 merges;
  local_fold_ms is the per-machine max, i.e. one machine's 15 merges]
- `leaf_busy_{min,max}(1m)` = leafgen_seq + local_fold(1m)
- `leafgen_ms(1m)` = build + leaf_busy(1m)
- `merge_ms(1m)` = 2.7 ms                                [smoke-measured: no cross merge]
- `total_time_ms` = witness_pass + scatter + leafgen + merge + verify
  (the 4-machine rows sum to their totals the same way, to <10 ms)
- `merges_local=63`, `merges_cross=0`, `cross_rounds=0`
- `comm_msgs=1`, `comm_bytes` = root proof + 4 B frame   [smoke-measured]
- `comm_model_ms` = (scatter_state + scatter_data + root) × 8 / 200 Mb/s + 2 RTT
  [reproduces the runner's own value on both smokes to 0.01 ms]
- `scatter_state_bytes`: measured on the smokes for cm/hll; 4m value ÷ 4 for ss/gk
- `records_per_sec` = 1048576 / total_s

## Cross-validation

The pre-hoist measured 1-machine cm total was 6926 s. Removing the 63
per-leaf rebuilds it paid (≈53 s each, from the pre-hoist wall/busy split)
predicts ≈3590 s; this model independently gives 3612 s.

## If these numbers are published

Label them as modeled/projected, or validate the model by actually running one
family — ss is the cheapest (projected ≈18 min):

    EXP_DATASET=aol EXP_COMPOSE_N=1048576 EXP_COMPOSE_BATCHES=16384 \
    EXP_SS_CAP=16384 EXP_COMPOSE_FAMILY=ss EXP_COMPOSE_MODE=forest \
    EXP_COMPOSE_MACHINES=1 EXP_COMPOSE_CORES=32 EXP_COMPOSE_EXEC=procs \
    EXP_NET_MBPS=200 EXP_NET_RTT_MS=0.2 EXP_COMPOSE_BACKEND=plonky3 \
    scripts/run_compose.sh validate_1machine_ss.csv
