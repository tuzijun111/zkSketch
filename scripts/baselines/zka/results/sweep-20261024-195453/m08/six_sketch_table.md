_Run: 256 AOL records = 1 epochs x 256; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 256 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 256 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 84.18 | 1.64 | 51x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 84.18 | 2.04 | 41x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 25.8 | 0.44x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.5 | 25.8 | 0.44x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 839 | 0.27x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 839 | 0.27x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 0.9 | 11x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 68.04 | 2.67 | 26x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 68.04 | 3.25 | 21x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 11.7 | 22.9 | 0.51x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 11.7 | 22.9 | 0.51x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 856 | 0.26x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 856 | 0.26x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 2.0 | 4.6x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 84.44 | 2.76 | 31x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 84.44 | 3.34 | 25x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 26.7 | 0.43x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 26.7 | 0.43x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 888 | 0.25x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 888 | 0.25x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 1.7 | 5.4x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 484.8 | 10.81 | 45x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 484.8 | 13.65 | 36x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.5 | 28.1 | 0.41x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.5 | 28.1 | 0.41x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 968 | 0.23x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 968 | 0.23x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 8.3 | 1.1x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 85.14 | 3.03 | 28x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 85.14 | 3.59 | 24x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.1 | 21.4 | 0.52x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.1 | 21.4 | 0.52x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 815 | 0.28x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 815 | 0.28x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 1.9 | 4.8x |
| KMV k=1,024 † | prove, 1 epoch (s) | 66.53 | 1.29 | 52x |
| KMV k=1,024 † | prove, 1 epochs (s) | 66.53 | 1.59 | 42x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.5 | 23.3 | 0.49x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.5 | 23.3 | 0.49x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 865 | 0.26x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 865 | 0.26x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 0.9 | 10x |

**Update side.** One epoch = one batch of 256 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 84 | 2.04 | 41x | 84.18 | 1.64 | 51x | 9.2 / 0.9 |
| HLL b=14 † ‡ | 68 | 3.25 | 21x | 68.04 | 2.67 | 26x | 9.2 / 2.0 |
| SS / MG s=1,024 † § | 84 | 3.34 | 25x | 84.44 | 2.76 | 31x | 9.2 / 1.7 |
| GK eps=1/51 † (same rule both sides) | 485 | 13.65 | 36x | 484.8 | 10.81 | 45x | 9.2 / 8.3 |
| Bloom 7x2^14 † | 85 | 3.59 | 24x | 85.14 | 3.03 | 28x | 9.2 / 1.9 |
| KMV k=1,024 † | 67 | 1.59 | 42x | 66.53 | 1.29 | 52x | 9.2 / 0.9 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 839 | 25.8 |
| HLL b=14 † ‡ | 225 | 225 | 856 | 22.9 |
| SS / MG s=1,024 † § | 225 | 225 | 888 | 26.7 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 968 | 28.1 |
| Bloom 7x2^14 † | 225 | 225 | 815 | 21.4 |
| KMV k=1,024 † | 225 | 225 | 865 | 23.3 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.314 | - | - |
| HLL b=14 † ‡ | - / 7.57 | - | - |
| SS / MG s=1,024 † § | - / 0.527 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.75 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.476 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.461 | - | - |

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

**Answers vs exact** (same 256 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 20 | 20 |
| HLL b=14 † ‡ | 1 | - | 11901.7 | 174 |
| SS / MG s=1,024 † § | 1 | - | count 20 (no key) | key 418575398 count 20 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 171 | 173 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 174 | 174 |

**zk-Analytics aggregation guest, epoch 0 (256 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 1,699,349 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 1,365,003 | 956,228 | 278,140 | 90.4% | measured (profiling marks) | 6.51 | 2.4x | 2.0x |
| SS / MG s=1,024 † § | 1,682,947 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 8,280,135 | 957,217 | 280,903 | 15.0% | measured (profiling marks) | 412.3 | 38x | 30x |
| Bloom 7x2^14 † | 1,447,456 | 956,228 | 278,142 | 85.3% | measured (profiling marks) | 12.53 | 4.1x | 3.5x |
| KMV k=1,024 † | 1,408,383 | 956,228 | 278,140 | 87.6% | measured (profiling marks) | 8.22 | 6.4x | 5.2x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (256 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 1,699,349 (2) |
| HLL b=14 † ‡ | none | 1,365,003 (2) |
| SS / MG s=1,024 † § | none | 1,682,947 (2) |
| GK eps=1/51 † (same rule both sides) | none | 8,280,135 (11) |
| Bloom 7x2^14 † | none | 1,447,456 (2) |
| KMV k=1,024 † | none | 1,408,383 (2) |
