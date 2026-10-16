| run | switches | load1 at start | VK deriv. (QueryAudit::new) s / peak | update makespan s (leaves + merges) | worker-phase peak (coord + worker) | audit s / peak | query phase s / peak | wall s | **combined peak** (phase) | merge cache |
|---|---|---|---|---|---|---|---|---|---|---|
| bloom_Bidle1 | B + EXP_MALLOC_TRIM=idle | 12.48 | 19.6 / 7,784 | 110.4 (78.0 + 29.3) | 8,350 (124 + 8,226) | 14.8 / 3,114 (3,114 + 0) | 76.2 / 6,682 | 221.1 | **8,350** (worker) | hits=3;misses=4 |
| gk_A4 | A (all off) | 12.60 | 7.4 / 4,383 | 180.3 (94.3 + 84.1) | 7,157 (791 + 6,366) | 27.6 / 7,353 (4,508 + 2,845) | 34.5 / 5,336 | 250.3 | **7,353** (audit) | off |
| gk_B4 | B (all on) | 16.03 | 7.2 / 4,330 | 182.5 (99.3 + 79.8) | 5,201 (108 + 5,093) | 21.2 / 4,485 (4,485 + 0) | 12.4 / 427 | 223.4 | **5,201** (worker) | hits=7;misses=8 |
| gk_Bidle1 | B + EXP_MALLOC_TRIM=idle | 10.91 | 7.2 / 4,356 | 179.5 (98.0 + 79.6) | 5,760 (103 + 5,657) | 21.3 / 4,489 (4,489 + 0) | 12.3 / 419 | 220.5 | **5,760** (worker) | hits=7;misses=8 |
| gk_Bidle2 | B + EXP_MALLOC_TRIM=idle | 16.86 | 7.4 / 4,328 | 172.0 (93.7 + 76.3) | 5,761 (104 + 5,657) | 21.5 / 4,472 (4,472 + 0) | 12.9 / 420 | 213.9 | **5,761** (worker) | hits=7;misses=8 |
| gk_Bnocache | B + EXP_MERGE_CACHE=0 | 16.80 | 7.2 / 4,379 | 189.9 (99.5 + 86.9) | 5,269 (105 + 5,164) | 21.3 / 4,508 (4,508 + 0) | 12.5 / 432 | 231.0 | **5,269** (worker) | off |
