_Run (memory-matched shape): 1 epoch per family, each epoch of the family's own size on both sides; zkSketch proves an epoch as k leaves + k - 1 merges (epoch records = k x leaf records: CM 16,384 = 16 x 1,024; HLL 16,384 = 16 x 1,024; SS 16,384 = 4 x 4,096; GK 2,048 = 4 x 512; Bloom 16,384 = 16 x 1,024; KMV 16,384 = 4 x 4,096); zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 768, s 51, 4 step(s) of 512 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none. Their shipped Count-Min aggregation (variant designed: their guest unchanged, with its per-row Merkle roots) is reported only as a REFERENCE, in its own table after the first one, so the numbers can be related to zk-Analytics' published ones; it is not the headline._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = the family's epoch, run line. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled); verify = best of 5 calls per receipt; peak RSS: prover = the r0vm process (max over the proved epochs), no coordinator (their host driver, tens of MB, is in the CSV). zkS: "1 epoch" = the epoch's k leaves + k - 1 merges (the forest's measured makespan when it is one epoch, else k x leaf_s + (k - 1) x merge_s from the run, excluding the merges across epochs; its proof = the epoch's live peak(s)); the forest is that one epoch and ends in ONE root proof: "verify" is that root, best of 5 calls (as zkA); peak RSS: prover = the procs-engine worker, coordinator = exp_compose (VK derivation, audit, queries), over the run. "together" = the whole process tree at once (VmRSS summed per 0.5 s sample, so it can read a little below a process's own peak). Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 4,011.2 | 154.9 | 26x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 9.7 | 19.0 | 0.51x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 791 | 0.29x |
| Count-Min 3x1024 | peak RSS, prover (GB) | 9.2 | 4.9 | 1.9x |
| Count-Min 3x1024 | peak RSS, coordinator (GB) | - | 4.4 | - |
| Count-Min 3x1024 | peak RSS, together (GB) | 9.2 | 5.0 | 1.8x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 3,752.4 | 160.3 | 23x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 9.7 | 19.0 | 0.51x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 791 | 0.28x |
| HLL b=14 † ‡ | peak RSS, prover (GB) | 9.2 | 4.9 | 1.9x |
| HLL b=14 † ‡ | peak RSS, coordinator (GB) | - | 6.8 | - |
| HLL b=14 † ‡ | peak RSS, together (GB) | 9.2 | 6.8 | 1.4x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 4,445.8 | 52.89 | 84x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 9.8 | 19.1 | 0.51x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 791 | 0.28x |
| SS / MG s=1,024 † § | peak RSS, prover (GB) | 9.2 | 7.3 | 1.3x |
| SS / MG s=1,024 † § | peak RSS, coordinator (GB) | - | 6.8 | - |
| SS / MG s=1,024 † § | peak RSS, together (GB) | 9.2 | 7.3 | 1.3x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 1,358.9 | 43.46 | 31x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 9.7 | 18.9 | 0.51x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 791 | 0.28x |
| GK eps=1/51 † (same rule both sides) | peak RSS, prover (GB) | 9.2 | 5.0 | 1.8x |
| GK eps=1/51 † (same rule both sides) | peak RSS, coordinator (GB) | - | 4.4 | - |
| GK eps=1/51 † (same rule both sides) | peak RSS, together (GB) | 9.2 | 5.0 | 1.8x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 4,017.0 | 157.9 | 25x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 9.7 | 19.0 | 0.51x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 791 | 0.28x |
| Bloom 7x2^14 † | peak RSS, prover (GB) | 9.2 | 4.7 | 2.0x |
| Bloom 7x2^14 † | peak RSS, coordinator (GB) | - | 4.2 | - |
| Bloom 7x2^14 † | peak RSS, together (GB) | 9.3 | 4.8 | 1.9x |
| KMV k=1,024 † | prove, 1 epoch (s) | 3,890.5 | 41.61 | 93x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 9.7 | 19.0 | 0.51x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 791 | 0.28x |
| KMV k=1,024 † | peak RSS, prover (GB) | 9.2 | 4.9 | 1.9x |
| KMV k=1,024 † | peak RSS, coordinator (GB) | - | 4.4 | - |
| KMV k=1,024 † | peak RSS, together (GB) | 9.2 | 5.0 | 1.9x |

**Reference, not the headline: zk-Analytics' shipped Count-Min aggregation** (zkA shipped = their `aggr_cm` unchanged, the `designed` variant. Besides the sketch update it builds per-row Merkle roots over the 3 x 1,024 counters plus cm_root and heap_root: 11,788,841 user cycles more than noroot at epoch 0 (100,439,836 vs 88,650,995; 104 vs 91 segments of 2^20, executor). No query guest or verifier reads those roots, and zk-Analytics' paper protocol has none (sections 5.2 and 5.3). It is reported so the numbers can be related to zk-Analytics' published ones, which include that cost. Metrics and conventions as in the table above; ratios are zkA / zkS)

| metric | zkA shipped CM (reference) | zkA noroot (headline) | zkS | reference / zkS | headline / zkS |
|---|---|---|---|---|---|
| prove, 1 epoch (s) | 4,601.7 | 4,011.2 | 154.9 | 30x | 26x |
| verify, 1 epoch (ms) | 9.7 | 9.7 | 19.0 | 0.51x | 0.51x |
| proof, 1 epoch (KB) | 226 | 226 | 791 | 0.29x | 0.29x |
| peak RSS, prover (GB) | 9.2 | 9.2 | 4.9 | 1.9x | 1.9x |
| peak RSS, coordinator (GB) | - | - | 4.4 | - | - |
| peak RSS, together (GB) | 9.2 | 9.2 | 5.0 | 1.8x | 1.8x |

**zkSketch run shape and memory** (per family: zk-Analytics proves one receipt per epoch, zkSketch k leaves + k - 1 merges per epoch; zkS variant / gk_rounds / shape = the exp_compose CSV's; "1 epoch" as in the first table, measured = the whole forest is one epoch; peaks over the zkSketch run in GB = 2^30 bytes: worker = the procs-engine worker, coordinator = exp_compose, together = both at once (VmRSS summed per 0.5 s sample); budget = together <= 8 GiB, the memory-matched budget; zkA prover = their r0vm, max over the proved epochs)

| sketch | epoch (records) | zkS leaves x records | zkS variant / gk_rounds / shape | zkS 1 epoch (s) | zkS worker / coordinator / together (GB) | within 8 GiB | zkA prover (GB) |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 16,384 | 16 x 1,024 | cm_omc / n/a / d3_w1024 | 154.9 (measured) | 4.9 / 4.4 / 5.0 | yes | 9.2 |
| HLL b=14 † ‡ | 16,384 | 16 x 1,024 | hll_omc / n/a / b14 | 160.3 (measured) | 4.9 / 6.8 / 6.8 | yes | 9.2 |
| SS / MG s=1,024 † § | 16,384 | 4 x 4,096 | ss_certified / n/a / cap1024 | 52.89 (measured) | 7.3 / 6.8 / 7.3 | yes | 9.2 |
| GK eps=1/51 † (same rule both sides) | 2,048 | 4 x 512 | gk_bandmerge2_stable / stable / cap768_s51 | 43.46 (measured) | 5.0 / 4.4 / 5.0 | yes | 9.2 |
| Bloom 7x2^14 † | 16,384 | 16 x 1,024 | bloom_packed / n/a / k7_logw14 | 157.9 (measured) | 4.7 / 4.2 / 4.8 | yes | 9.2 |
| KMV k=1,024 † | 16,384 | 4 x 4,096 | kmv / n/a / k1024 | 41.61 (measured) | 4.9 / 4.4 / 5.0 | yes | 9.2 |

**Update side.** One epoch = the family's epoch (run line). Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkS "1 epoch" is the measured forest, its k leaves + k - 1 merges (first table).

| sketch | zkA / epoch (s) | zkS 1 epoch (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|
| Count-Min 3x1024 | 4,011.2 | 154.9 | 26x | 9.2 / 4.9 |
| HLL b=14 † ‡ | 3,752.4 | 160.3 | 23x | 9.2 / 4.9 |
| SS / MG s=1,024 † § | 4,445.8 | 52.89 | 84x | 9.2 / 7.3 |
| GK eps=1/51 † (same rule both sides) | 1,358.9 | 43.46 | 31x | 9.2 / 5.0 |
| Bloom 7x2^14 † | 4,017.0 | 157.9 | 25x | 9.2 / 4.7 |
| KMV k=1,024 † | 3,890.5 | 41.61 | 93x | 9.2 / 4.9 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkS root | zkS root verify, best of 5 (ms) |
|---|---|---|---|
| Count-Min 3x1024 | 226 | 791 | 19.0 |
| HLL b=14 † ‡ | 225 | 791 | 19.0 |
| SS / MG s=1,024 † § | 225 | 791 | 19.1 |
| GK eps=1/51 † (same rule both sides) | 225 | 791 | 18.9 |
| Bloom 7x2^14 † | 225 | 791 | 19.0 |
| KMV k=1,024 † | 225 | 791 | 19.0 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root; n = epochs: zkS proves its query after leaf n x k)

| sketch | n=1 | zkA / zkS at n=1 |
|---|---|---|
| Count-Min 3x1024 | 40.88 / 0.262 | 156x |
| HLL b=14 † ‡ | 22.76 / 8.33 | 2.7x |
| SS / MG s=1,024 † § | 234.7 / 0.527 | 446x |
| GK eps=1/51 † (same rule both sides) | 13.19 / 0.944 | 14x |
| Bloom 7x2^14 † (inserted key) | 12.93 / 0.533 | 24x |
| Bloom 7x2^14 † (absent key) | 12.96 / 0.543 | 24x |
| KMV k=1,024 † | 13.48 / 0.439 | 31x |

**Verifier work to accept one answer at n, zkA vs zkSketch** (ms; best of 5 calls per proof on both sides; deserialisation excluded on both sides; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) after leaf n x k (popcount(n x k) peaks; k per family, run line) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 |
|---|---|
| Count-Min 3x1024 | **19.4** / 36.0 |
| HLL b=14 † ‡ | **19.4** / 39.7 |
| SS / MG s=1,024 † § | **19.5** / 37.2 |
| GK eps=1/51 † (same rule both sides) | **19.4** / 37.9 |
| Bloom 7x2^14 † (inserted key) | **20.2** / 35.0 |
| Bloom 7x2^14 † (absent key) | **19.5** / 35.1 |
| KMV k=1,024 † | **19.5** / 35.6 |

**Bytes the verifier receives for one answer at n, zkA vs zkSketch** (KB; KB = 10^3 bytes; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) after leaf n x k (popcount(n x k) peaks; k per family, run line) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 |
|---|---|
| Count-Min 3x1024 | **450** / 1,468 |
| HLL b=14 † ‡ | **449** / 1,652 |
| SS / MG s=1,024 † § | **449** / 1,513 |
| GK eps=1/51 † (same rule both sides) | **449** / 1,526 |
| Bloom 7x2^14 † (inserted key) | **449** / 1,444 |
| Bloom 7x2^14 † (absent key) | **449** / 1,444 |
| KMV k=1,024 † | **449** / 1,440 |

**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the process already held; the same for every zkA root variant: query guests read no root)

| sketch | zkA n=1 | zkS n=1 / n=1 (max over n=1..1) |
|---|---|---|
| Count-Min 3x1024 | 9.1 | 0.2 / 0.2 (0.2) |
| HLL b=14 † ‡ | 4.6 | 6.8 / 6.8 (6.8) |
| SS / MG s=1,024 † § | 9.2 | 0.4 / 0.4 (0.4) |
| GK eps=1/51 † (same rule both sides) | 2.3 | 0.6 / 0.6 (0.6) |
| Bloom 7x2^14 † | 2.3 | 0.4 / 0.4 (0.4) |
| KMV k=1,024 † | 2.3 | 0.4 / 0.4 (0.4) |

**Answers vs exact** (same first n epochs of AOL records per family; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | 189 | 185 | 180 |
| HLL b=14 † ‡ | 1 | 8472 | 16373.6 | 8433 |
| SS / MG s=1,024 † § | 1 | key 3780053395 count 180 (error 0) | count 175 (no key) | key 3780053395 count 180 |
| GK eps=1/51 † (same rule both sides) | 1 | 1780 [1749..1812] | 1780 | 1789 |
| Bloom 7x2^14 † (inserted key) | 1 | true | true | true |
| Bloom 7x2^14 † (absent key) | 1 | false | false | false |
| KMV k=1,024 † | 1 | 8202 | 8484 | 8433 |

**zk-Analytics aggregation guest, epoch 0 (the family's epoch): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS 1 epoch | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 88,650,995 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 82,527,841 | 60,793,124 | 17,783,068 | 95.2% | measured (profiling marks) | 179.7 | 1.1x | 1.1x |
| SS / MG s=1,024 † § | 96,967,708 | 60,793,143 | 17,959,211 | 81.2% | read + chain: legacy profiling twin aggr_ss_prof; user cycles: this variant (executor) | 835.1 | 16x | 16x |
| GK eps=1/51 † (same rule both sides) | 25,295,367 | 7,605,761 | 2,245,159 | 38.9% | measured (profiling marks) | 829.7 | 19x | 19x |
| Bloom 7x2^14 † | 88,144,348 | 60,793,124 | 17,783,070 | 89.1% | measured (profiling marks) | 436.1 | 2.8x | 2.8x |
| KMV k=1,024 † | 85,011,047 | 60,793,124 | 17,783,068 | 92.4% | measured (profiling marks) | 294.5 | 7.1x | 7.1x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (the family's epoch): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root; root work = designed - noroot, the cost of the root nothing reads; designed is executed for every family but proved only for Count-Min, as the reference)

| sketch | designed: root | designed: user cycles (segments) | noroot: root | noroot: user cycles (segments) | root work (cycles) | share of designed |
|---|---|---|---|---|---|---|
| Count-Min 3x1024 | cm_rows+cm+heap | 100,439,836 (104) | none | 88,650,995 (91) | 11,788,841 | 11.7% |
| HLL b=14 † ‡ | samples64 | 82,823,019 (85) | none | 82,527,841 (85) | 295,178 | 0.4% |
| SS / MG s=1,024 † § | samples64 | 97,874,997 (101) | none | 96,967,708 (100) | 907,289 | 0.9% |
| GK eps=1/51 † (same rule both sides) | samples64 | 25,561,597 (31) | none | 25,295,367 (31) | 266,230 | 1.0% |
| Bloom 7x2^14 † | samples64 | 88,415,857 (91) | none | 88,144,348 (90) | 271,509 | 0.3% |
| KMV k=1,024 † | samples64 | 85,428,024 (88) | none | 85,011,047 (87) | 416,977 | 0.5% |
