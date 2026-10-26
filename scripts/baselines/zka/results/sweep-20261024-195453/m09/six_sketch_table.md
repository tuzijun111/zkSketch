_Run: 512 AOL records = 1 epochs x 512; zk-Analytics proved epochs 0 and queries at n = 1; zkSketch features: default:pcs=hiding;logup_mask=on._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 2048, s 51, 1 step(s) of 512 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation literal._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 512 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 (sampled), "1 epochs" = 1 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 1, EXCLUDING composition; its proof = the leaf-1 proof), "1 epochs" = the whole forest incl. its 0 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 144.9 | 2.61 | 56x |
| Count-Min 3x1024 | prove, 1 epochs (s) | 144.9 | 3.24 | 45x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.4 | 26.6 | 0.43x |
| Count-Min 3x1024 | verify, 1 epochs (ms) | 11.4 | 26.6 | 0.43x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 889 | 0.25x |
| Count-Min 3x1024 | proof, 1 epochs (KB) | 226 | 889 | 0.25x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 1.8 | 5.1x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 129.7 | 4.65 | 28x |
| HLL b=14 † ‡ | prove, 1 epochs (s) | 129.7 | 5.55 | 23x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 11.5 | 28.1 | 0.41x |
| HLL b=14 † ‡ | verify, 1 epochs (ms) | 11.5 | 28.1 | 0.41x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 908 | 0.25x |
| HLL b=14 † ‡ | proof, 1 epochs (KB) | 225 | 908 | 0.25x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 3.4 | 2.7x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 173.9 | 2.59 | 67x |
| SS / MG s=1,024 † § | prove, 1 epochs (s) | 173.9 | 3.23 | 54x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 | 23.7 | 0.48x |
| SS / MG s=1,024 † § | verify, 1 epochs (ms) | 11.5 | 23.7 | 0.48x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 888 | 0.25x |
| SS / MG s=1,024 † § | proof, 1 epochs (KB) | 225 | 888 | 0.25x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 1.9 | 4.9x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epoch (s) | 618.5 | 12.36 | 50x |
| GK eps=1/51 † (same rule both sides) | prove, 1 epochs (s) | 618.5 | 15.33 | 40x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epoch (ms) | 11.4 | 27.4 | 0.42x |
| GK eps=1/51 † (same rule both sides) | verify, 1 epochs (ms) | 11.4 | 27.4 | 0.42x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epoch (KB) | 225 | 931 | 0.24x |
| GK eps=1/51 † (same rule both sides) | proof, 1 epochs (KB) | 225 | 931 | 0.24x |
| GK eps=1/51 † (same rule both sides) | peak RSS (GB) | 9.2 | 9.3 | 0.99x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 128.7 | 3.31 | 39x |
| Bloom 7x2^14 † | prove, 1 epochs (s) | 128.7 | 3.95 | 33x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.4 | 23.6 | 0.49x |
| Bloom 7x2^14 † | verify, 1 epochs (ms) | 11.4 | 23.6 | 0.49x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 782 | 0.29x |
| Bloom 7x2^14 † | proof, 1 epochs (KB) | 225 | 782 | 0.29x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 2.1 | 4.4x |
| KMV k=1,024 † | prove, 1 epoch (s) | 129.0 | 1.77 | 73x |
| KMV k=1,024 † | prove, 1 epochs (s) | 129.0 | 2.12 | 61x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.8 | 24.0 | 0.49x |
| KMV k=1,024 † | verify, 1 epochs (ms) | 11.8 | 24.0 | 0.49x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 804 | 0.28x |
| KMV k=1,024 † | proof, 1 epochs (KB) | 225 | 804 | 0.28x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 1.1 | 8.6x |

**Update side.** One epoch = one batch of 512 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 (sampled); zkA 1 epochs = 1 x that mean (derived). zkS "1 batches" is measured and includes the 0 forest merges; "leaf alone" is leafgen_seq_ms / 1 and EXCLUDES composition.

| sketch | zkA 1 epochs (s) | zkS 1 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 145 | 3.24 | 45x | 144.9 | 2.61 | 56x | 9.2 / 1.8 |
| HLL b=14 † ‡ | 130 | 5.55 | 23x | 129.7 | 4.65 | 28x | 9.2 / 3.4 |
| SS / MG s=1,024 † § | 174 | 3.23 | 54x | 173.9 | 2.59 | 67x | 9.2 / 1.9 |
| GK eps=1/51 † (same rule both sides) | 618 | 15.33 | 40x | 618.5 | 12.36 | 50x | 9.2 / 9.3 |
| Bloom 7x2^14 † | 129 | 3.95 | 33x | 128.7 | 3.31 | 39x | 9.2 / 2.1 |
| KMV k=1,024 † | 129 | 2.12 | 61x | 129.0 | 1.77 | 73x | 9.2 / 1.1 |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 1 receipts | zkS root | zkS root verify, single call (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 226 | 889 | 26.6 |
| HLL b=14 † ‡ | 225 | 225 | 908 | 28.1 |
| SS / MG s=1,024 † § | 225 | 225 | 888 | 23.7 |
| GK eps=1/51 † (same rule both sides) | 225 | 225 | 931 | 27.4 |
| Bloom 7x2^14 † | 225 | 225 | 782 | 23.6 |
| KMV k=1,024 † | 225 | 225 | 804 | 24.0 |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | zkA / zkS at n=1 | at n=1 |
|---|---|---|---|
| Count-Min 3x1024 | - / 0.289 | - | - |
| HLL b=14 † ‡ | - / 7.48 | - | - |
| SS / MG s=1,024 † § | - / 0.510 | - | - |
| GK eps=1/51 † (same rule both sides) | - / 1.67 | - | - |
| Bloom 7x2^14 † (inserted key) | - / 0.656 | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - | - |
| KMV k=1,024 † | - / 0.520 | - | - |

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

**Answers vs exact** (same 512 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | 20 | 20 |
| HLL b=14 † ‡ | 1 | - | 11992.4 | 365 |
| SS / MG s=1,024 † § | 1 | - | count 20 (no key) | key 418575398 count 20 |
| GK eps=1/51 † (same rule both sides) | 1 | - | 321 | 328 |
| Bloom 7x2^14 † (inserted key) | 1 | - | true | true |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| KMV k=1,024 † | 1 | - | 365 | 365 |

**zk-Analytics aggregation guest, epoch 0 (512 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 3,079,730 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 2,653,579 | 1,906,020 | 555,996 | 92.8% | measured (profiling marks) | 9.36 | 2.0x | 1.7x |
| SS / MG s=1,024 † § | 3,402,051 | not profiled | not profiled | - | no six_zka_prof_* / exec CSV | - | - | - |
| GK eps=1/51 † (same rule both sides) | 10,452,720 | 1,907,009 | 561,511 | 23.6% | measured (profiling marks) | 472.4 | 38x | 31x |
| Bloom 7x2^14 † | 2,823,722 | 1,906,020 | 555,998 | 87.2% | measured (profiling marks) | 16.48 | 5.0x | 4.2x |
| KMV k=1,024 † | 2,797,263 | 1,906,020 | 555,996 | 88.0% | measured (profiling marks) | 15.46 | 8.7x | 7.3x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (512 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 3,079,730 (4) |
| HLL b=14 † ‡ | none | 2,653,579 (3) |
| SS / MG s=1,024 † § | none | 3,402,051 (4) |
| GK eps=1/51 † (same rule both sides) | none | 10,452,720 (14) |
| Bloom 7x2^14 † | none | 2,823,722 (3) |
| KMV k=1,024 † | none | 2,797,263 (3) |
