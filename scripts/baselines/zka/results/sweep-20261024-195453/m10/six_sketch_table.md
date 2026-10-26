_Run: 1,024 AOL records = 1 epochs x 1,024; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 1024 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 1,024 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 261.5 | 4.78 | 55x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 261.5 | 5.86 | 45x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 23.8 | 0.48x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.5 | 23.8 | 0.48x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 906 | 0.25x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 906 | 0.25x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 3.7 | 2.5x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 243.7 | 5.18 | 47x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 243.7 | 6.37 | 38x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 11.5 | 22.6 | 0.51x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 11.5 | 22.6 | 0.51x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 908 | 0.25x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 908 | 0.25x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 3.7 | 2.5x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 309.6 | 4.33 | 72x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 309.6 | 5.30 | 58x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 25.6 | 0.45x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 25.6 | 0.45x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 868 | 0.26x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 868 | 0.26x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 3.3 | 2.8x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 838.2 | 19.00 | 44x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 838.2 | 23.35 | 36x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.5 | 28.2 | 0.41x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.5 | 28.2 | 0.41x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 943 | 0.24x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 943 | 0.24x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 14.9 | 0.62x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 261.3 | 6.39 | 41x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 261.3 | 7.55 | 35x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.7 | 26.3 | 0.44x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.7 | 26.3 | 0.44x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 862 | 0.26x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 862 | 0.26x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 4.2 | 2.2x |
| KMV k=1,024 † | prove, 1 epoch (s) | 261.2 | 2.67 | 98x |
| KMV k=1,024 † | prove, 1 epochs (s) | 261.2 | 3.23 | 81x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.8 | 25.8 | 0.46x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.8 | 25.8 | 0.46x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 882 | 0.25x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 882 | 0.25x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 1.6 | 5.9x |

**Update side.** One epoch = one batch of 1,024 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 262 | 5.86 | 45x | 261.5 | 4.78 | 55x | 9.2 / 3.7 |
| HLL b=14 † ‡ | 244 | 6.37 | 38x | 243.7 | 5.18 | 47x | 9.2 / 3.7 |
| SS / MG s=1,024 † § | 310 | 5.30 | 58x | 309.6 | 4.33 | 72x | 9.2 / 3.3 |
| GK eps=1/51 † (same rule both sides) | 838 | 23.35 | 36x | 838.2 | 19.00 | 44x | 9.2 / 14.9 |
| Bloom 7x2^14 † | 261 | 7.55 | 35x | 261.3 | 6.39 | 41x | 9.2 / 4.2 |
| KMV k=1,024 † | 261 | 3.23 | 81x | 261.2 | 2.67 | 98x | 9.2 / 1.6 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 906 | 23.8 |
| HLL b=14 † ‡ | 225 | 225 | 908 | 22.6 |
| SS / MG s=1,024 † § | 225 | 225 | 868 | 25.6 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 943 | 28.2 |
| Bloom 7x2^14 † | 225 | 225 | 862 | 26.3 |
| KMV k=1,024 † | 225 | 225 | 882 | 25.8 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.273 | - | - |
| HLL b=14 † ‡ | - / 8.36 | - | - |
| SS / MG s=1,024 † § | - / 0.479 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 2.11 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.507 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.497 | - | - |

**Verifier work to accept one answer at n, zkA vs zkSketch** (ms; best of 5 calls per proof on both sides; deserialisation excluded on both sides; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) |
|---|---|
| Count-Min 3x1024 | - |
| HLL b=14 † ‡ | - |
| SS / MG s=1,024 † § | - |
| GK eps=1/51 † (same rule both sides) | - |
| Bloom 7x2^14 † (inserted key) | - |
| Bloom 7x2^14 † (absent key) | - |
| KMV k=1,024 † | - |

**Bytes the verifier receives for one answer at n, zkA vs zkSketch** (KB; KB = 10^3 bytes; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) |
|---|---|
| Count-Min 3x1024 | - |
| HLL b=14 † ‡ | - |
| SS / MG s=1,024 † § | - |
| GK eps=1/51 † (same rule both sides) | - |
| Bloom 7x2^14 † (inserted key) | - |
| Bloom 7x2^14 † (absent key) | - |
| KMV k=1,024 † | - |

**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the process already held; the same for every zkA root variant: query guests read no root)

| sketch | zkA n=1 | zkS n=1 / n=1 (max over n=1..1) |
|---|---|---|
| Count-Min 3x1024 | - | 0.2 / 0.2 (0.2) |
| HLL b=14 † ‡ | - | 6.6 / 6.6 (6.6) |
| SS / MG s=1,024 † § | - | 0.3 / 0.3 (0.3) |
| GK eps=1/51 † (same rule both sides) | - | 1.2 / 1.2 (1.2) |
| Bloom 7x2^14 † | - | 0.3 / 0.3 (0.3) |
| KMV k=1,024 † | - | 0.3 / 0.3 (0.3) |

**Answers vs exact** (same 1,024 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 115 | 115 |
| HLL b=14 † ‡ | 1 | - | 12120.1 | 624 |
| SS / MG s=1,024 † § | 1 | - | count 115 (no key) | key 3011223745 count 115 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 893 | 906 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 624 | 624 |

**zk-Analytics aggregation guest, epoch 0 (1,024 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 5,843,303 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 5,230,353 | 3,805,604 | 1,111,708 | 94.0% | measured (profiling marks) | 14.58 | 2.8x | 2.3x |
| SS / MG s=1,024 † § | 6,655,033 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 14,792,755 | 3,806,593 | 1,122,727 | 33.3% | measured (profiling marks) | 558.9 | 29x | 24x |
| Bloom 7x2^14 † | 5,576,116 | 3,805,604 | 1,111,710 | 88.2% | measured (profiling marks) | 30.87 | 4.8x | 4.1x |
| KMV k=1,024 † | 5,541,932 | 3,805,604 | 1,111,708 | 88.7% | measured (profiling marks) | 29.44 | 11x | 9.1x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (1,024 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 5,843,303 (6) |
| HLL b=14 † ‡ | none | 5,230,353 (6) |
| SS / MG s=1,024 † § | none | 6,655,033 (7) |
| GK eps=1/51 † (same rule both sides) | none | 14,792,755 (19) |
| Bloom 7x2^14 † | none | 5,576,116 (6) |
| KMV k=1,024 † | none | 5,541,932 (6) |
