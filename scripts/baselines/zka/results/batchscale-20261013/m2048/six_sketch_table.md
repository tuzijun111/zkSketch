_Run: 4,096 AOL records = 2 epochs x 2,048; zk-Analytics proved epochs 0 and 1 and queries at n = 1, 2; zkSketch features: default:pcs=hiding;logup_mask=on._

_`est` = ESTIMATED zk-Analytics prove time, NOT proved in this run: padded_cycles x k=30.073 s per 2^20 cycles, calibrated from the 12 aggregation proofs of the committed 2026-10-09 run at M=2048 (scripts/baselines/zka/results; legacy guests; no proof in this directory). Verify time and bytes of an estimated receipt are the mean of the measured ones; ratios built on an estimate are marked too._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM not run, HLL none, SS none, GK none, Bloom not run, KMV not run._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 2,048 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 and 1 (sampled), "2 epochs" = 2 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 2, EXCLUDING composition; its proof = the leaf-1 proof), "2 epochs" = the whole forest incl. its 1 merge (measured), which ends in ONE root proof: "verify" is that root, best of 5 calls (as zkA), in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | - | - | - |
| Count-Min 3x1024 | prove, 2 epochs (s) | - | - | - |
| Count-Min 3x1024 | verify, 1 epoch (ms) | - | - | - |
| Count-Min 3x1024 | verify, 2 epochs (ms) | - | - | - |
| Count-Min 3x1024 | proof, 1 epoch (KB) | - | - | - |
| Count-Min 3x1024 | proof, 2 epochs (KB) | - | - | - |
| Count-Min 3x1024 | peak RSS (GB) | - | - | - |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 330.8 est | 9.25 | 36x est |
| HLL b=14 † ‡ | prove, 2 epochs (s) | 661.6 est | 27.28 | 24x est |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 10.8 est | 22.8 | 0.47x est |
| HLL b=14 † ‡ | verify, 2 epochs (ms) | 21.6 est | 22.8 | 0.95x est |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 est | 922 | 0.24x est |
| HLL b=14 † ‡ | proof, 2 epochs (KB) | 450 est | 803 | 0.56x est |
| HLL b=14 † ‡ | peak RSS (GB) | - | 6.8 | - |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 421.0 est | 5.38 | 78x est |
| SS / MG s=1,024 † § | prove, 2 epochs (s) | 842.1 est | 19.06 | 44x est |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 10.8 est | 22.7 | 0.47x est |
| SS / MG s=1,024 † § | verify, 2 epochs (ms) | 21.6 est | 22.7 | 0.95x est |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 est | 940 | 0.24x est |
| SS / MG s=1,024 † § | proof, 2 epochs (KB) | 450 est | 804 | 0.56x est |
| SS / MG s=1,024 † § | peak RSS (GB) | - | 4.9 | - |
| GK eps=1/51 † | prove, 1 epoch (s) | 406.0 est | 69.93 | 5.8x est |
| GK eps=1/51 † | prove, 2 epochs (s) | 812.0 est | 166.0 | 4.9x est |
| GK eps=1/51 † | verify, 1 epoch (ms) | 10.8 est | 22.4 | 0.48x est |
| GK eps=1/51 † | verify, 2 epochs (ms) | 21.6 est | 22.4 | 0.96x est |
| GK eps=1/51 † | proof, 1 epoch (KB) | 225 est | 1,064 | 0.21x est |
| GK eps=1/51 † | proof, 2 epochs (KB) | 450 est | 804 | 0.56x est |
| GK eps=1/51 † | peak RSS (GB) | - | 57.8 | - |
| Bloom 7x2^14 † | prove, 1 epoch (s) | - | - | - |
| Bloom 7x2^14 † | prove, 2 epochs (s) | - | - | - |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | - | - | - |
| Bloom 7x2^14 † | verify, 2 epochs (ms) | - | - | - |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | - | - | - |
| Bloom 7x2^14 † | proof, 2 epochs (KB) | - | - | - |
| Bloom 7x2^14 † | peak RSS (GB) | - | - | - |
| KMV k=1,024 † | prove, 1 epoch (s) | - | - | - |
| KMV k=1,024 † | prove, 2 epochs (s) | - | - | - |
| KMV k=1,024 † | verify, 1 epoch (ms) | - | - | - |
| KMV k=1,024 † | verify, 2 epochs (ms) | - | - | - |
| KMV k=1,024 † | proof, 1 epoch (KB) | - | - | - |
| KMV k=1,024 † | proof, 2 epochs (KB) | - | - | - |
| KMV k=1,024 † | peak RSS (GB) | - | - | - |

**Update side.** One epoch = one batch of 2,048 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 and 1 (sampled); zkA 2 epochs = 2 x that mean (derived). zkS "2 batches" is measured and includes the 1 forest merge; "leaf alone" is leafgen_seq_ms / 2 and EXCLUDES composition.

| sketch | zkA 2 epochs (s) | zkS 2 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | - | - | - | - | - | - | - / - |
| HLL b=14 † ‡ | 662 est | 27.28 | 24x est | 330.8 est | 9.25 | 36x est | - / 6.8 |
| SS / MG s=1,024 † § | 842 est | 19.06 | 44x est | 421.0 est | 5.38 | 78x est | - / 4.9 |
| GK eps=1/51 † | 812 est | 166.0 | 4.9x est | 406.0 est | 69.93 | 5.8x est | - / 57.8 |
| Bloom 7x2^14 † | - | - | - | - | - | - | - / - |
| KMV k=1,024 † | - | - | - | - | - | - | - / - |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 2 receipts | zkS root | zkS root verify, best of 5 (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | - | - | - | - |
| HLL b=14 † ‡ | 225 est | 450 est | 803 | 22.8 |
| SS / MG s=1,024 † § | 225 est | 450 est | 804 | 22.7 |
| GK eps=1/51 † | 225 est | 450 est | 804 | 22.4 |
| Bloom 7x2^14 † | - | - | - | - |
| KMV k=1,024 † | - | - | - | - |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | n=2 | zkA / zkS at n=1 | at n=2 |
|---|---|---|---|---|
| Count-Min 3x1024 | - / - | - / - | - | - |
| HLL b=14 † ‡ | 15.04 est / 8.00 | 30.07 est / 7.88 | 1.9x est | 3.8x est |
| SS / MG s=1,024 † § | 157.9 est / 0.510 | 330.8 est / 0.448 | 309x est | 738x est |
| GK eps=1/51 † | 3.76 est / 1.59 | 7.52 est / 1.53 | 2.4x est | 4.9x est |
| Bloom 7x2^14 † (inserted key) | - / - | - / - | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - / - | - | - |
| KMV k=1,024 † | - / - | - / - | - | - |

**Verifier work to accept one answer at n, zkA vs zkSketch** (ms; best of 5 calls per proof on both sides; deserialisation excluded on both sides; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) |
|---|---|---|
| Count-Min 3x1024 | - | - |
| HLL b=14 † ‡ | **21.6** est / 43.2 | **32.4** est / 43.2 |
| SS / MG s=1,024 † § | **21.6** est / 44.8 | **32.4** est / 40.9 |
| GK eps=1/51 † | **21.6** est / 44.5 | **32.4** est / 38.1 |
| Bloom 7x2^14 † (inserted key) | - | - |
| Bloom 7x2^14 † (absent key) | - | - |
| KMV k=1,024 † | - | - |

**Bytes the verifier receives for one answer at n, zkA vs zkSketch** (KB; KB = 10^3 bytes; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) |
|---|---|---|
| Count-Min 3x1024 | - | - |
| HLL b=14 † ‡ | **450** est / 1,783 | **675** est / 1,664 |
| SS / MG s=1,024 † § | **450** est / 1,662 | **675** est / 1,526 |
| GK eps=1/51 † | **450** est / 1,848 | **675** est / 1,588 |
| Bloom 7x2^14 † (inserted key) | - | - |
| Bloom 7x2^14 † (absent key) | - | - |
| KMV k=1,024 † | - | - |

**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the process already held; the same for every zkA root variant: query guests read no root)

| sketch | zkA n=1 | zkA n=2 | zkS n=1 / n=2 (max over n=1..2) |
|---|---|---|---|
| Count-Min 3x1024 | - | - | - |
| HLL b=14 † ‡ | - | - | 7.9 / 8.0 (8.0) |
| SS / MG s=1,024 † § | - | - | 1.2 / 1.2 (1.2) |
| GK eps=1/51 † | - | - | 3.5 / 3.7 (3.7) |
| Bloom 7x2^14 † | - | - | - |
| KMV k=1,024 † | - | - | - |

**Answers vs exact** (same 4,096 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | - | - |
| Count-Min 3x1024 | 2 | - | - | - |
| HLL b=14 † ‡ | 1 | 1232 | 12422.5 | 1234 |
| HLL b=14 † ‡ | 2 | 2397 | 13011.8 | 2372 |
| SS / MG s=1,024 † § | 1 | key 3011223745 count 115 (error 0) | count 114 (no key) | key 3011223745 count 115 |
| SS / MG s=1,024 † § | 2 | key 3011223745 count 115 (error 0) | count 113 (no key) | key 3011223745 count 115 |
| GK eps=1/51 † | 1 | 1789 [1750..1829] | 1786 | 1789 |
| GK eps=1/51 † | 2 | 3595 [3518..3672] | 3557 | 3569 |
| Bloom 7x2^14 † (inserted key) | 1 | - | - | - |
| Bloom 7x2^14 † (inserted key) | 2 | - | - | - |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| Bloom 7x2^14 † (absent key) | 2 | - | - | - |
| KMV k=1,024 † | 1 | - | - | - |
| KMV k=1,024 † | 2 | - | - | - |

**zk-Analytics aggregation guest, epoch 0 (2,048 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 11,364,064 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 10,383,921 | 7,604,772 | 2,223,132 | 94.6% | measured (profiling marks) | 17.71 est | 1.9x est | 1.3x est |
| SS / MG s=1,024 † § | 13,158,936 | 7,604,791 | 2,245,163 | 74.9% | read + chain: legacy profiling twin aggr_ss_prof; user cycles: this variant (executor) | 105.9 est | 20x est | 11x est |
| GK eps=1/51 † | 12,983,145 | 7,604,628 | 2,229,799 | 75.7% | read + chain: legacy profiling twin aggr_gk_prof; user cycles: this variant (executor) | 98.46 est | 1.4x est | 1.2x est |
| Bloom 7x2^14 † | 11,080,766 | 7,604,772 | 2,223,134 | 88.7% | measured (profiling marks) | - | - | - |
| KMV k=1,024 † | 11,108,717 | 7,604,772 | 2,223,132 | 88.5% | measured (profiling marks) | - | - | - |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (2,048 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 11,364,064 (12) |
| HLL b=14 † ‡ | none | 10,383,921 (11) |
| SS / MG s=1,024 † § | none | 13,158,936 (14) |
| GK eps=1/51 † | none | 12,983,145 (14) |
| Bloom 7x2^14 † | none | 11,080,766 (12) |
| KMV k=1,024 † | none | 11,108,717 (12) |
