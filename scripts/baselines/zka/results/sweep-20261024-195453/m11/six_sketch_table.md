_Run: 2,048 AOL records = 1 epochs x 2,048; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 2048 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 2,048 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 530.2 | 9.07 | 58x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 530.2 | 11.31 | 47x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 28.7 | 0.40x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.5 | 28.7 | 0.40x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 956 | 0.24x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 956 | 0.24x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 7.2 | 1.3x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 482.2 | 9.06 | 53x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 482.2 | 11.00 | 44x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 9.7 | 26.2 | 0.37x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 9.7 | 26.2 | 0.37x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 923 | 0.24x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 923 | 0.24x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 6.8 | 1.3x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 613.7 | 4.87 | 126x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 613.7 | 6.10 | 101x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 25.4 | 0.45x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 25.4 | 0.45x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 940 | 0.24x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 940 | 0.24x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 3.7 | 2.5x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 1,290.6 | 17.81 | 72x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 1,290.6 | 22.71 | 57x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.6 | 24.8 | 0.47x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.6 | 24.8 | 0.47x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 944 | 0.24x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 944 | 0.24x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 15.1 | 0.61x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 515.6 | 10.73 | 48x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 515.6 | 12.77 | 40x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.6 | 23.4 | 0.50x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.6 | 23.4 | 0.50x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 849 | 0.26x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 849 | 0.26x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 8.1 | 1.1x |
| KMV k=1,024 † | prove, 1 epoch (s) | 510.7 | 2.83 | 181x |
| KMV k=1,024 † | prove, 1 epochs (s) | 510.7 | 3.38 | 151x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.7 | 22.7 | 0.52x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.7 | 22.7 | 0.52x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 851 | 0.26x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 851 | 0.26x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 2.0 | 4.5x |

**Update side.** One epoch = one batch of 2,048 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 530 | 11.31 | 47x | 530.2 | 9.07 | 58x | 9.2 / 7.2 |
| HLL b=14 † ‡ | 482 | 11.00 | 44x | 482.2 | 9.06 | 53x | 9.2 / 6.8 |
| SS / MG s=1,024 † § | 614 | 6.10 | 101x | 613.7 | 4.87 | 126x | 9.2 / 3.7 |
| GK eps=1/51 † (same rule both sides) | 1,291 | 22.71 | 57x | 1,290.6 | 17.81 | 72x | 9.2 / 15.1 |
| Bloom 7x2^14 † | 516 | 12.77 | 40x | 515.6 | 10.73 | 48x | 9.2 / 8.1 |
| KMV k=1,024 † | 511 | 3.38 | 151x | 510.7 | 2.83 | 181x | 9.2 / 2.0 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 956 | 28.7 |
| HLL b=14 † ‡ | 225 | 225 | 923 | 26.2 |
| SS / MG s=1,024 † § | 225 | 225 | 940 | 25.4 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 944 | 24.8 |
| Bloom 7x2^14 † | 225 | 225 | 849 | 23.4 |
| KMV k=1,024 † | 225 | 225 | 851 | 22.7 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.294 | - | - |
| HLL b=14 † ‡ | - / 7.84 | - | - |
| SS / MG s=1,024 † § | - / 0.484 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.70 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.467 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.446 | - | - |

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

**Answers vs exact** (same 2,048 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 115 | 115 |
| HLL b=14 † ‡ | 1 | - | 12422.5 | 1234 |
| SS / MG s=1,024 † § | 1 | - | count 114 (no key) | key 3011223745 count 115 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 1786 | 1789 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 1241 | 1234 |

**zk-Analytics aggregation guest, epoch 0 (2,048 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 11,364,064 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 10,383,921 | 7,604,772 | 2,223,132 | 94.6% | measured (profiling marks) | 25.82 | 2.9x | 2.3x |
| SS / MG s=1,024 † § | 13,158,936 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 23,489,452 | 7,605,761 | 2,245,159 | 41.9% | measured (profiling marks) | 749.4 | 42x | 33x |
| Bloom 7x2^14 † | 11,080,766 | 7,604,772 | 2,223,134 | 88.7% | measured (profiling marks) | 58.30 | 5.4x | 4.6x |
| KMV k=1,024 † | 11,108,717 | 7,604,772 | 2,223,132 | 88.5% | measured (profiling marks) | 58.88 | 21x | 17x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (2,048 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 11,364,064 (12) |
| HLL b=14 † ‡ | none | 10,383,921 (11) |
| SS / MG s=1,024 † § | none | 13,158,936 (14) |
| GK eps=1/51 † (same rule both sides) | none | 23,489,452 (29) |
| Bloom 7x2^14 † | none | 11,080,766 (12) |
| KMV k=1,024 † | none | 11,108,717 (12) |
