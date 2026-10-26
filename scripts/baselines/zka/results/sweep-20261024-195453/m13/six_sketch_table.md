_Run: 8,192 AOL records = 1 epochs x 8,192; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 8192 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 8,192 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 2,031.3 | 35.19 | 58x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 2,031.3 | 45.93 | 44x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 26.0 | 0.44x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.5 | 26.0 | 0.44x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 1,030 | 0.22x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 1,030 | 0.22x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 28.8 | 0.32x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 1,884.8 | 29.46 | 64x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 1,884.8 | 36.16 | 52x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 11.5 | 28.6 | 0.40x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 11.5 | 28.6 | 0.40x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 989 | 0.23x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 989 | 0.23x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 26.0 | 0.35x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 2,265.9 | 16.56 | 137x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 2,265.9 | 20.62 | 110x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 27.9 | 0.41x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 27.9 | 0.41x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 941 | 0.24x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 941 | 0.24x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 13.3 | 0.69x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 4,654.2 | 47.60 | 98x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 4,654.2 | 61.86 | 75x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.5 | 30.8 | 0.37x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.5 | 30.8 | 0.37x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 1,036 | 0.22x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 1,036 | 0.22x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 36.9 | 0.25x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 2,016.7 | 34.54 | 58x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 2,016.7 | 41.91 | 48x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.5 | 28.4 | 0.40x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.5 | 28.4 | 0.40x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 996 | 0.23x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 996 | 0.23x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 28.9 | 0.32x |
| KMV k=1,024 † | prove, 1 epoch (s) | 1,978.5 | 10.45 | 189x |
| KMV k=1,024 † | prove, 1 epochs (s) | 1,978.5 | 12.54 | 158x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.5 | 27.5 | 0.42x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.5 | 27.5 | 0.42x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 922 | 0.24x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 922 | 0.24x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 8.2 | 1.1x |

**Update side.** One epoch = one batch of 8,192 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 2,031 | 45.93 | 44x | 2,031.3 | 35.19 | 58x | 9.2 / 28.8 |
| HLL b=14 † ‡ | 1,885 | 36.16 | 52x | 1,884.8 | 29.46 | 64x | 9.2 / 26.0 |
| SS / MG s=1,024 † § | 2,266 | 20.62 | 110x | 2,265.9 | 16.56 | 137x | 9.2 / 13.3 |
| GK eps=1/51 † (same rule both sides) | 4,654 | 61.86 | 75x | 4,654.2 | 47.60 | 98x | 9.2 / 36.9 |
| Bloom 7x2^14 † | 2,017 | 41.91 | 48x | 2,016.7 | 34.54 | 58x | 9.2 / 28.9 |
| KMV k=1,024 † | 1,979 | 12.54 | 158x | 1,978.5 | 10.45 | 189x | 9.2 / 8.2 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 1,030 | 26.0 |
| HLL b=14 † ‡ | 225 | 225 | 989 | 28.6 |
| SS / MG s=1,024 † § | 225 | 225 | 941 | 27.9 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 1,036 | 30.8 |
| Bloom 7x2^14 † | 225 | 225 | 996 | 28.4 |
| KMV k=1,024 † | 225 | 225 | 922 | 27.5 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.299 | - | - |
| HLL b=14 † ‡ | - / 7.74 | - | - |
| SS / MG s=1,024 † § | - / 0.525 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.87 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.509 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.498 | - | - |

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

**Answers vs exact** (same 8,192 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 118 | 115 |
| HLL b=14 † ‡ | 1 | - | 14078.0 | 4432 |
| SS / MG s=1,024 † § | 1 | - | count 113 (no key) | key 3011223745 count 115 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 7064 | 7115 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 4365 | 4432 |

**zk-Analytics aggregation guest, epoch 0 (8,192 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 44,486,348 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 41,303,437 | 30,399,780 | 8,891,676 | 95.1% | measured (profiling marks) | 91.81 | 3.1x | 2.5x |
| SS / MG s=1,024 † § | 49,317,705 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 81,565,834 | 30,400,769 | 8,979,751 | 48.3% | measured (profiling marks) | 2,407.1 | 51x | 39x |
| Bloom 7x2^14 † | 44,108,114 | 30,399,780 | 8,891,678 | 89.1% | measured (profiling marks) | 220.2 | 6.4x | 5.3x |
| KMV k=1,024 † | 43,199,016 | 30,399,780 | 8,891,676 | 91.0% | measured (profiling marks) | 179.0 | 17x | 14x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (8,192 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 44,486,348 (46) |
| HLL b=14 † ‡ | none | 41,303,437 (43) |
| SS / MG s=1,024 † § | none | 49,317,705 (51) |
| GK eps=1/51 † (same rule both sides) | none | 81,565,834 (105) |
| Bloom 7x2^14 † | none | 44,108,114 (46) |
| KMV k=1,024 † | none | 43,199,016 (45) |
