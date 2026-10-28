# Batch-size figure in the memory-matched setting of Table 2 (sweep_memmatch.py)

_zkSketch: every point is the measured total_time_ms (leaves + compositions + setup; queries excluded) of a forest run of the batch: from the batches runs `scripts/baselines/zka/results/batches-20261028-153827` where they hold the point, else the sweep's single leaves `scripts/baselines/zka/results/sweep-20261024-195453` (GK: `scripts/baselines/zka/results/sweep-gk768-20261028-143107`); Table 2's epochs from `scripts/baselines/zka/results/memmatch-20261022-205419`. zk-Analytics: the measured receipts of the sweep and of Table 2; GK receipts not measured at capacity 768: padded cycles x 44.51 s per 2^20 (the capacity-768 receipts at m=64, 2048), which reproduces the sweep's capacity-2048 receipts within 1.2%._


## Count-Min (zkSketch leaf L = 1024 records, shape d3_w1024; Table 2 epoch 16384)

| m | leaves | zkA prove (s) | zkS prove (s) | zkA ms/rec | zkS ms/rec | zkA / zkS | zkS worker GiB | zkA basis |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 64 | 1 | 40.1 | 1.04 | 626.2 | 16.18 | 38.7x | 0.4 | measured |
| 128 | 1 | 52.7 | 1.66 | 411.6 | 12.95 | 31.8x | 0.9 | measured |
| 256 | 1 | 84.2 | 1.81 | 328.8 | 7.09 | 46.4x | 1.0 | measured |
| 512 | 1 | 144.9 | 3.11 | 283.1 | 6.07 | 46.6x | 1.8 | measured |
| 1024 | 1 | 261.5 | 5.63 | 255.4 | 5.50 | 46.4x | 3.4 | measured |
| 2048 | 2 | 530.2 | 18.17 | 258.9 | 8.87 | 29.2x | 4.9 | measured |
| 4096 | 4 | 1020.8 | 38.26 | 249.2 | 9.34 | 26.7x | 4.9 | measured |
| 8192 | 8 | 2031.3 | 74.86 | 248.0 | 9.14 | 27.1x | 4.9 | measured |
| 16384 | 16 | 4011.2 | 154.86 | 244.8 | 9.45 | 25.9x | 4.9 | measured |

## HLL (zkSketch leaf L = 1024 records, shape b14; Table 2 epoch 16384)

| m | leaves | zkA prove (s) | zkS prove (s) | zkA ms/rec | zkS ms/rec | zkA / zkS | zkS worker GiB | zkA basis |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 64 | 1 | 22.3 | 3.26 | 347.8 | 50.98 | 6.8x | 1.9 | measured |
| 128 | 1 | 40.3 | 3.37 | 315.0 | 26.30 | 12.0x | 1.7 | measured |
| 256 | 1 | 68.0 | 3.36 | 265.8 | 13.12 | 20.3x | 2.0 | measured |
| 512 | 1 | 129.7 | 5.38 | 253.3 | 10.50 | 24.1x | 3.5 | measured |
| 1024 | 1 | 243.7 | 5.81 | 238.0 | 5.68 | 41.9x | 3.7 | measured |
| 2048 | 2 | 482.2 | 16.30 | 235.4 | 7.96 | 29.6x | 4.9 | measured |
| 4096 | 4 | 941.9 | 34.31 | 230.0 | 8.38 | 27.5x | 4.9 | measured |
| 8192 | 8 | 1884.8 | 71.42 | 230.1 | 8.72 | 26.4x | 4.9 | measured |
| 16384 | 16 | 3752.4 | 160.27 | 229.0 | 9.78 | 23.4x | 4.9 | measured |

## MG (zkSketch leaf L = 4096 records, shape cap1024; Table 2 epoch 16384)

| m | leaves | zkA prove (s) | zkS prove (s) | zkA ms/rec | zkS ms/rec | zkA / zkS | zkS worker GiB | zkA basis |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 64 | 1 | 22.5 | 2.87 | 351.0 | 44.79 | 7.8x | 1.5 | measured |
| 128 | 1 | 40.8 | 3.34 | 318.8 | 26.10 | 12.2x | 1.7 | measured |
| 256 | 1 | 84.4 | 3.07 | 329.9 | 11.98 | 27.5x | 1.6 | measured |
| 512 | 1 | 173.9 | 3.18 | 339.7 | 6.21 | 54.7x | 1.9 | measured |
| 1024 | 1 | 309.6 | 4.95 | 302.4 | 4.83 | 62.6x | 3.3 | measured |
| 2048 | 1 | 613.7 | 6.65 | 299.6 | 3.25 | 92.3x | 3.7 | measured |
| 4096 | 1 | 1150.0 | 10.64 | 280.8 | 2.60 | 108.1x | 6.7 | measured |
| 8192 | 2 | 2265.9 | 24.19 | 276.6 | 2.95 | 93.7x | 6.7 | measured |
| 16384 | 4 | 4445.8 | 52.89 | 271.4 | 3.23 | 84.1x | 7.3 | measured |

## GK (zkSketch leaf L = 512 records, shape cap768_s51; Table 2 epoch 2048)

| m | leaves | zkA prove (s) | zkS prove (s) | zkA ms/rec | zkS ms/rec | zkA / zkS | zkS worker GiB | zkA basis |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 64 | 1 | 154.5 | 6.85 | 2414.8 | 107.02 | 22.6x | 3.7 | measured |
| 128 | 1 | 178.1 | 6.10 | 1391.0 | 47.63 | 29.2x | 3.8 | cycles |
| 256 | 1 | 222.6 | 6.07 | 869.4 | 23.70 | 36.7x | 3.7 | cycles |
| 512 | 1 | 356.1 | 6.77 | 695.5 | 13.23 | 52.6x | 4.2 | cycles |
| 1024 | 2 | 678.8 | 19.17 | 662.9 | 18.72 | 35.4x | 4.9 | cycles |
| 2048 | 4 | 1358.9 | 43.46 | 663.5 | 21.22 | 31.3x | 5.0 | measured |
| 4096 | 8 | 2715.3 | 82.32 | 662.9 | 20.10 | 33.0x | 5.0 | cycles |
| 8192 | 16 | 5386.1 | 166.18 | 657.5 | 20.29 | 32.4x | 5.1 | cycles |
| 16384 | 32 | 10772.2 | 333.07 | 657.5 | 20.33 | 32.3x | 5.1 | cycles |

## Bloom (zkSketch leaf L = 1024 records, shape k7_logw14; Table 2 epoch 16384)

| m | leaves | zkA prove (s) | zkS prove (s) | zkA ms/rec | zkS ms/rec | zkA / zkS | zkS worker GiB | zkA basis |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 64 | 1 | 22.3 | 2.19 | 348.8 | 34.22 | 10.2x | 1.2 | measured |
| 128 | 1 | 40.5 | 3.16 | 316.1 | 24.71 | 12.8x | 1.6 | measured |
| 256 | 1 | 85.1 | 3.53 | 332.6 | 13.78 | 24.1x | 2.1 | measured |
| 512 | 1 | 128.7 | 3.85 | 251.3 | 7.52 | 33.4x | 2.2 | measured |
| 1024 | 1 | 261.3 | 6.61 | 255.2 | 6.45 | 39.6x | 4.2 | measured |
| 2048 | 2 | 515.6 | 17.23 | 251.8 | 8.42 | 29.9x | 4.2 | measured |
| 4096 | 4 | 1018.6 | 36.31 | 248.7 | 8.86 | 28.1x | 4.6 | measured |
| 8192 | 8 | 2016.7 | 78.66 | 246.2 | 9.60 | 25.6x | 4.7 | measured |
| 16384 | 16 | 4017.0 | 157.91 | 245.2 | 9.64 | 25.4x | 4.7 | measured |

## KMV (zkSketch leaf L = 4096 records, shape k1024; Table 2 epoch 16384)

| m | leaves | zkA prove (s) | zkS prove (s) | zkA ms/rec | zkS ms/rec | zkA / zkS | zkS worker GiB | zkA basis |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 64 | 1 | 22.3 | 1.09 | 348.5 | 16.97 | 20.5x | 0.5 | measured |
| 128 | 1 | 40.3 | 1.64 | 314.6 | 12.80 | 24.6x | 0.8 | measured |
| 256 | 1 | 66.5 | 1.65 | 259.9 | 6.45 | 40.3x | 0.8 | measured |
| 512 | 1 | 129.0 | 1.89 | 251.9 | 3.69 | 68.4x | 1.0 | measured |
| 1024 | 1 | 261.2 | 2.94 | 255.1 | 2.87 | 88.8x | 1.6 | measured |
| 2048 | 1 | 510.7 | 3.41 | 249.4 | 1.66 | 149.8x | 1.8 | measured |
| 4096 | 1 | 1002.3 | 6.62 | 244.7 | 1.62 | 151.5x | 4.1 | measured |
| 8192 | 2 | 1978.5 | 20.20 | 241.5 | 2.47 | 97.9x | 4.9 | measured |
| 16384 | 4 | 3890.5 | 41.61 | 237.5 | 2.54 | 93.5x | 4.9 | measured |

## At Table 2's epoch (m = 2^14; GK 2^11): zkA prove (s) / zkS prove (s) / ratio

Count-Min 4011 / 154.9 / 26x | HLL 3752 / 160.3 / 23x | MG 4446 / 52.9 / 84x | GK 1359 / 43.5 / 31x | Bloom 4017 / 157.9 / 25x | KMV 3890 / 41.6 / 93x

## Table 2's epochs re-measured by a batches run (not plotted)

- Count-Min: Table 2 154.9 s, re-measured 151.6 s (-2.1%, scripts/baselines/zka/results/batches-20261028-153827/m14/six_zksketch_cm.csv)
- HLL: Table 2 160.3 s, re-measured 151.5 s (-5.4%, scripts/baselines/zka/results/batches-20261028-153827/m14/six_zksketch_hll.csv)
- MG: Table 2 52.9 s, re-measured 48.6 s (-8.1%, scripts/baselines/zka/results/batches-20261028-153827/m14/six_zksketch_ss.csv)
- GK: Table 2 43.5 s, re-measured 38.9 s (-10.5%, scripts/baselines/zka/results/batches-20261028-153827/m11/six_zksketch_gk.csv)
- Bloom: Table 2 157.9 s, re-measured 150.4 s (-4.7%, scripts/baselines/zka/results/batches-20261028-153827/m14/six_zksketch_bloom.csv)
- KMV: Table 2 41.6 s, re-measured 40.8 s (-2.0%, scripts/baselines/zka/results/batches-20261028-153827/m14/six_zksketch_kmv.csv)
