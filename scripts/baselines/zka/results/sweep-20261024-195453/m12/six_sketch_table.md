_Run: 4,096 AOL records = 1 epochs x 4,096; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 4096 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 4,096 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 1,020.8 | 17.21 | 59x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 1,020.8 | 21.71 | 47x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 26.2 | 0.44x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.5 | 26.2 | 0.44x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 976 | 0.23x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 976 | 0.23x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 14.4 | 0.64x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 941.9 | 16.45 | 57x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 941.9 | 19.94 | 47x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 9.7 | 25.5 | 0.38x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 9.7 | 25.5 | 0.38x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 972 | 0.23x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 972 | 0.23x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 13.2 | 0.70x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 1,150.0 | 8.51 | 135x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 1,150.0 | 10.67 | 108x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 27.6 | 0.42x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 27.6 | 0.42x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 920 | 0.24x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 920 | 0.24x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 6.7 | 1.4x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 2,375.6 | 35.84 | 66x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 2,375.6 | 44.87 | 53x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.6 | 28.6 | 0.40x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.6 | 28.6 | 0.40x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 994 | 0.23x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 994 | 0.23x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 29.8 | 0.31x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 1,018.6 | 19.35 | 53x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 1,018.6 | 23.34 | 44x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.5 | 25.2 | 0.46x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.5 | 25.2 | 0.46x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 943 | 0.24x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 943 | 0.24x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 14.5 | 0.63x |
| KMV k=1,024 † | prove, 1 epoch (s) | 1,002.3 | 6.05 | 166x |
| KMV k=1,024 † | prove, 1 epochs (s) | 1,002.3 | 7.21 | 139x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 9.7 | 24.1 | 0.40x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 9.7 | 24.1 | 0.40x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 901 | 0.25x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 901 | 0.25x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 4.1 | 2.3x |

**Update side.** One epoch = one batch of 4,096 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 1,021 | 21.71 | 47x | 1,020.8 | 17.21 | 59x | 9.2 / 14.4 |
| HLL b=14 † ‡ | 942 | 19.94 | 47x | 941.9 | 16.45 | 57x | 9.2 / 13.2 |
| SS / MG s=1,024 † § | 1,150 | 10.67 | 108x | 1,150.0 | 8.51 | 135x | 9.2 / 6.7 |
| GK eps=1/51 † (same rule both sides) | 2,376 | 44.87 | 53x | 2,375.6 | 35.84 | 66x | 9.2 / 29.8 |
| Bloom 7x2^14 † | 1,019 | 23.34 | 44x | 1,018.6 | 19.35 | 53x | 9.2 / 14.5 |
| KMV k=1,024 † | 1,002 | 7.21 | 139x | 1,002.3 | 6.05 | 166x | 9.2 / 4.1 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 976 | 26.2 |
| HLL b=14 † ‡ | 225 | 225 | 972 | 25.5 |
| SS / MG s=1,024 † § | 225 | 225 | 920 | 27.6 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 994 | 28.6 |
| Bloom 7x2^14 † | 225 | 225 | 943 | 25.2 |
| KMV k=1,024 † | 225 | 225 | 901 | 24.1 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.279 | - | - |
| HLL b=14 † ‡ | - / 8.49 | - | - |
| SS / MG s=1,024 † § | - / 0.531 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.75 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.566 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.552 | - | - |

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

**Answers vs exact** (same 4,096 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 115 | 115 |
| HLL b=14 † ‡ | 1 | - | 13011.8 | 2372 |
| SS / MG s=1,024 † § | 1 | - | count 114 (no key) | key 3011223745 count 115 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 3514 | 3569 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 2320 | 2372 |

**zk-Analytics aggregation guest, epoch 0 (4,096 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 22,404,889 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 20,690,711 | 15,203,108 | 4,445,980 | 95.0% | measured (profiling marks) | 47.42 | 2.9x | 2.4x |
| SS / MG s=1,024 † § | 25,137,842 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 42,757,574 | 15,204,097 | 4,490,023 | 46.1% | measured (profiling marks) | 1,281.4 | 36x | 29x |
| Bloom 7x2^14 † | 22,089,928 | 15,203,108 | 4,445,982 | 89.0% | measured (profiling marks) | 112.5 | 5.8x | 4.8x |
| KMV k=1,024 † | 21,980,495 | 15,203,108 | 4,445,980 | 89.4% | measured (profiling marks) | 106.3 | 18x | 15x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (4,096 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 22,404,889 (23) |
| HLL b=14 † ‡ | none | 20,690,711 (22) |
| SS / MG s=1,024 † § | none | 25,137,842 (26) |
| GK eps=1/51 † (same rule both sides) | none | 42,757,574 (54) |
| Bloom 7x2^14 † | none | 22,089,928 (23) |
| KMV k=1,024 † | none | 21,980,495 (23) |
