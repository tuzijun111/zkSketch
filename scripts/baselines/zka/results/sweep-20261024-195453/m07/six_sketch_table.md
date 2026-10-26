_Run: 128 AOL records = 1 epochs x 128; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 128 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 128 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 52.68 | 1.42 | 37x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 52.68 | 1.71 | 31x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 25.1 | 0.46x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.5 | 25.1 | 0.46x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 804 | 0.28x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 804 | 0.28x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 0.8 | 11x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 40.32 | 3.40 | 12x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 40.32 | 4.07 | 9.9x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 9.7 | 26.7 | 0.36x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 9.7 | 26.7 | 0.36x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 856 | 0.26x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 856 | 0.26x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.1 | 2.0 | 4.7x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 40.80 | 2.49 | 16x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 40.80 | 3.04 | 13x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 25.6 | 0.45x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 25.6 | 0.45x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 851 | 0.26x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 851 | 0.26x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.1 | 1.5 | 6.2x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 441.7 | 11.33 | 39x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 441.7 | 14.36 | 31x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.6 | 28.3 | 0.41x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.6 | 28.3 | 0.41x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 968 | 0.23x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 968 | 0.23x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 8.3 | 1.1x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 40.46 | 2.70 | 15x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 40.46 | 3.24 | 12x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.5 | 21.6 | 0.53x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.5 | 21.6 | 0.53x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 817 | 0.28x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 817 | 0.28x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.1 | 1.4 | 6.6x |
| KMV k=1,024 † | prove, 1 epoch (s) | 40.27 | 1.38 | 29x |
| KMV k=1,024 † | prove, 1 epochs (s) | 40.27 | 1.66 | 24x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.5 | 25.0 | 0.46x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.5 | 25.0 | 0.46x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 839 | 0.27x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 839 | 0.27x |
| KMV k=1,024 † | peak RSS (GB) | 9.1 | 0.8 | 12x |

**Update side.** One epoch = one batch of 128 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 53 | 1.71 | 31x | 52.68 | 1.42 | 37x | 9.2 / 0.8 |
| HLL b=14 † ‡ | 40 | 4.07 | 9.9x | 40.32 | 3.40 | 12x | 9.1 / 2.0 |
| SS / MG s=1,024 † § | 41 | 3.04 | 13x | 40.80 | 2.49 | 16x | 9.1 / 1.5 |
| GK eps=1/51 † (same rule both sides) | 442 | 14.36 | 31x | 441.7 | 11.33 | 39x | 9.2 / 8.3 |
| Bloom 7x2^14 † | 40 | 3.24 | 12x | 40.46 | 2.70 | 15x | 9.1 / 1.4 |
| KMV k=1,024 † | 40 | 1.66 | 24x | 40.27 | 1.38 | 29x | 9.1 / 0.8 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 804 | 25.1 |
| HLL b=14 † ‡ | 225 | 225 | 856 | 26.7 |
| SS / MG s=1,024 † § | 225 | 225 | 851 | 25.6 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 968 | 28.3 |
| Bloom 7x2^14 † | 225 | 225 | 817 | 21.6 |
| KMV k=1,024 † | 225 | 225 | 839 | 25.0 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.290 | - | - |
| HLL b=14 † ‡ | - / 8.36 | - | - |
| SS / MG s=1,024 † § | - / 0.566 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.74 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.568 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.513 | - | - |

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

**Answers vs exact** (same 128 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 13 | 13 |
| HLL b=14 † ‡ | 1 | - | 11864.9 | 97 |
| SS / MG s=1,024 † § | 1 | - | count 13 (no key) | key 2993289653 count 13 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 44 | 43 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 97 | 97 |

**zk-Analytics aggregation guest, epoch 0 (128 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 1,008,850 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 720,683 | 481,332 | 139,212 | 86.1% | measured (profiling marks) | 5.60 | 1.6x | 1.4x |
| SS / MG s=1,024 † § | 857,128 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 7,207,755 | 482,321 | 140,599 | 8.6% | measured (profiling marks) | 403.5 | 36x | 28x |
| Bloom 7x2^14 † | 759,254 | 481,332 | 139,214 | 81.7% | measured (profiling marks) | 7.39 | 2.7x | 2.3x |
| KMV k=1,024 † | 720,089 | 481,332 | 139,212 | 86.2% | measured (profiling marks) | 5.57 | 4.0x | 3.3x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (128 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 1,008,850 (2) |
| HLL b=14 † ‡ | none | 720,683 (1) |
| SS / MG s=1,024 † § | none | 857,128 (1) |
| GK eps=1/51 † (same rule both sides) | none | 7,207,755 (10) |
| Bloom 7x2^14 † | none | 759,254 (1) |
| KMV k=1,024 † | none | 720,089 (1) |
