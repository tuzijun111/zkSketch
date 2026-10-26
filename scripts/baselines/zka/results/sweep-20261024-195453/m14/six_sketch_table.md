_Run: 16,384 AOL records = 1 epochs x 16,384; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 16384 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 16,384 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 4,037.8 | 66.27 | 61x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 4,037.8 | 86.87 | 46x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 30.3 | 0.38x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.5 | 30.3 | 0.38x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 1,054 | 0.21x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 1,054 | 0.21x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 57.5 | 0.16x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 3,768.4 | 58.42 | 65x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 3,768.4 | 72.32 | 52x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 11.5 | 26.1 | 0.44x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 11.5 | 26.1 | 0.44x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 1,013 | 0.22x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 1,013 | 0.22x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 51.4 | 0.18x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 4,452.3 | 31.13 | 143x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 4,452.3 | 38.74 | 115x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 29.7 | 0.38x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 29.7 | 0.38x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 993 | 0.23x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 993 | 0.23x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 26.6 | 0.35x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 9,397.3 | 92.51 | 102x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 9,397.3 | 122.0 | 77x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 9.7 | 30.4 | 0.32x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 9.7 | 30.4 | 0.32x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 1,063 | 0.21x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 1,063 | 0.21x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.3 | 73.6 | 0.13x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 4,015.5 | 69.68 | 58x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 4,015.5 | 90.92 | 44x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.4 | 29.2 | 0.39x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.4 | 29.2 | 0.39x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 1,014 | 0.22x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 1,014 | 0.22x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 59.5 | 0.15x |
| KMV k=1,024 † | prove, 1 epoch (s) | 3,883.3 | 18.78 | 207x |
| KMV k=1,024 † | prove, 1 epochs (s) | 3,883.3 | 23.40 | 166x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.5 | 29.8 | 0.39x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.5 | 29.8 | 0.39x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 1,017 | 0.22x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 1,017 | 0.22x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 14.8 | 0.62x |

**Update side.** One epoch = one batch of 16,384 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 4,038 | 86.87 | 46x | 4,037.8 | 66.27 | 61x | 9.2 / 57.5 |
| HLL b=14 † ‡ | 3,768 | 72.32 | 52x | 3,768.4 | 58.42 | 65x | 9.2 / 51.4 |
| SS / MG s=1,024 † § | 4,452 | 38.74 | 115x | 4,452.3 | 31.13 | 143x | 9.2 / 26.6 |
| GK eps=1/51 † (same rule both sides) | 9,397 | 122.0 | 77x | 9,397.3 | 92.51 | 102x | 9.3 / 73.6 |
| Bloom 7x2^14 † | 4,016 | 90.92 | 44x | 4,015.5 | 69.68 | 58x | 9.2 / 59.5 |
| KMV k=1,024 † | 3,883 | 23.40 | 166x | 3,883.3 | 18.78 | 207x | 9.2 / 14.8 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 1,054 | 30.3 |
| HLL b=14 † ‡ | 225 | 225 | 1,013 | 26.1 |
| SS / MG s=1,024 † § | 225 | 225 | 993 | 29.7 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 1,063 | 30.4 |
| Bloom 7x2^14 † | 225 | 225 | 1,014 | 29.2 |
| KMV k=1,024 † | 225 | 225 | 1,017 | 29.8 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.288 | - | - |
| HLL b=14 † ‡ | - / 7.96 | - | - |
| SS / MG s=1,024 † § | - / 0.547 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.64 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 7.08 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.537 | - | - |

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
| Bloom 7x2^14 † | - | 6.3 / 6.3 (6.3) |
| KMV k=1,024 † | - | 0.3 / 0.3 (0.3) |

**Answers vs exact** (same 16,384 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 185 | 180 |
| HLL b=14 † ‡ | 1 | - | 16373.6 | 8433 |
| SS / MG s=1,024 † § | 1 | - | count 177 (no key) | key 3780053395 count 180 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 7934 | 7967 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 8484 | 8433 |

**zk-Analytics aggregation guest, epoch 0 (16,384 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 88,650,995 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 82,527,841 | 60,793,124 | 17,783,068 | 95.2% | measured (profiling marks) | 180.4 | 3.1x | 2.5x |
| SS / MG s=1,024 † § | 96,967,708 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 161,246,488 | 60,794,113 | 17,959,207 | 48.8% | measured (profiling marks) | 4,807.6 | 52x | 39x |
| Bloom 7x2^14 † | 88,144,348 | 60,793,124 | 17,783,070 | 89.1% | measured (profiling marks) | 435.9 | 6.3x | 4.8x |
| KMV k=1,024 † | 85,011,047 | 60,793,124 | 17,783,068 | 92.4% | measured (profiling marks) | 293.9 | 16x | 13x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (16,384 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 88,650,995 (91) |
| HLL b=14 † ‡ | none | 82,527,841 (85) |
| SS / MG s=1,024 † § | none | 96,967,708 (100) |
| GK eps=1/51 † (same rule both sides) | none | 161,246,488 (210) |
| Bloom 7x2^14 † | none | 88,144,348 (90) |
| KMV k=1,024 † | none | 85,011,047 (87) |
