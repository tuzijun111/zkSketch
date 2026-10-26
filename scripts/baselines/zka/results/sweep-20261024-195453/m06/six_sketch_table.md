_Run: 64 AOL records = 1 epochs x 64; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 64 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 64 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 40.08 | 0.935 | 43x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 40.08 | 1.12 | 36x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 9.7 | 24.7 | 0.39x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 9.7 | 24.7 | 0.39x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 816 | 0.28x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 816 | 0.28x |
| Count-Min 3x1024 | peak RSS (GB) | 9.1 | 0.4 | 21x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 22.26 | 3.36 | 6.6x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 22.26 | 3.97 | 5.6x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 9.7 | 26.4 | 0.37x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 9.7 | 26.4 | 0.37x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 884 | 0.25x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 884 | 0.25x |
| HLL b=14 † ‡ | peak RSS (GB) | 4.6 | 2.0 | 2.4x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 22.46 | 2.78 | 8.1x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 22.46 | 3.35 | 6.7x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 25.5 | 0.45x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 25.5 | 0.45x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 851 | 0.26x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 851 | 0.26x |
| SS / MG s=1,024 † § | peak RSS (GB) | 4.6 | 1.5 | 3.1x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 408.1 | 11.81 | 35x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 408.1 | 14.59 | 28x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.6 | 28.6 | 0.41x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.6 | 28.6 | 0.41x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 968 | 0.23x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 968 | 0.23x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 8.3 | 1.1x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 22.32 | 1.77 | 13x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 22.32 | 2.15 | 10x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.5 | 21.3 | 0.54x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.5 | 21.3 | 0.54x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 765 | 0.29x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 765 | 0.29x |
| Bloom 7x2^14 † | peak RSS (GB) | 4.6 | 1.1 | 4.3x |
| KMV k=1,024 † | prove, 1 epoch (s) | 22.31 | 0.893 | 25x |
| KMV k=1,024 † | prove, 1 epochs (s) | 22.31 | 1.09 | 20x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.5 | 23.5 | 0.49x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.5 | 23.5 | 0.49x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 789 | 0.28x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 789 | 0.28x |
| KMV k=1,024 † | peak RSS (GB) | 4.6 | 0.5 | 9.3x |

**Update side.** One epoch = one batch of 64 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 40 | 1.12 | 36x | 40.08 | 0.935 | 43x | 9.1 / 0.4 |
| HLL b=14 † ‡ | 22 | 3.97 | 5.6x | 22.26 | 3.36 | 6.6x | 4.6 / 2.0 |
| SS / MG s=1,024 † § | 22 | 3.35 | 6.7x | 22.46 | 2.78 | 8.1x | 4.6 / 1.5 |
| GK eps=1/51 † (same rule both sides) | 408 | 14.59 | 28x | 408.1 | 11.81 | 35x | 9.2 / 8.3 |
| Bloom 7x2^14 † | 22 | 2.15 | 10x | 22.32 | 1.77 | 13x | 4.6 / 1.1 |
| KMV k=1,024 † | 22 | 1.09 | 20x | 22.31 | 0.893 | 25x | 4.6 / 0.5 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 816 | 24.7 |
| HLL b=14 † ‡ | 225 | 225 | 884 | 26.4 |
| SS / MG s=1,024 † § | 225 | 225 | 851 | 25.5 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 968 | 28.6 |
| Bloom 7x2^14 † | 225 | 225 | 765 | 21.3 |
| KMV k=1,024 † | 225 | 225 | 789 | 23.5 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.315 | - | - |
| HLL b=14 † ‡ | - / 8.39 | - | - |
| SS / MG s=1,024 † § | - / 0.558 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.82 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.521 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.486 | - | - |

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

**Answers vs exact** (same 64 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 9 | 9 |
| HLL b=14 † ‡ | 1 | - | 11840.1 | 46 |
| SS / MG s=1,024 † § | 1 | - | count 9 (no key) | key 2993289653 count 9 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 22 | 23 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 46 | 46 |

**zk-Analytics aggregation guest, epoch 0 (64 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 663,500 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 398,429 | 243,884 | 69,748 | 78.7% | measured (profiling marks) | 4.74 | 1.4x | 1.2x |
| SS / MG s=1,024 † § | 435,722 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 6,658,626 | 244,873 | 70,447 | 4.7% | measured (profiling marks) | 388.8 | 33x | 27x |
| Bloom 7x2^14 † | 415,084 | 243,884 | 69,750 | 75.6% | measured (profiling marks) | 5.46 | 3.1x | 2.5x |
| KMV k=1,024 † | 374,635 | 243,884 | 69,748 | 83.7% | measured (profiling marks) | 3.63 | 4.1x | 3.3x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (64 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 663,500 (1) |
| HLL b=14 † ‡ | none | 398,429 (1) |
| SS / MG s=1,024 † § | none | 435,722 (1) |
| GK eps=1/51 † (same rule both sides) | none | 6,658,626 (10) |
| Bloom 7x2^14 † | none | 415,084 (1) |
| KMV k=1,024 † | none | 374,635 (1) |
