_Run: 512 AOL records = 2 epochs x 256; zk-Analytics proved epochs 0 and 1 and queries at n = 1, 2; zkSketch features: default:pcs=hiding;logup_mask=on._

_`est` = ESTIMATED zk-Analytics prove time, NOT proved in this run: padded_cycles x k=30.000 s per 2^20 cycles, calibrated from 2 proof(s) of this run. Verify time and bytes of an estimated receipt are the mean of the measured ones; ratios built on an estimate are marked too._

_GK, zk-Analytics side: same GK algorithm as zkSketch: its batch rule (two-sided band-merge apply_batch2) in their pipeline; capacity 512, s 51, 1 step(s) of 256 records per epoch (zkSketch leaf size), state carried across epochs, guest implementation fast; CONFIG MISMATCH: the zkSketch GK run used cap384_s51 with 256-record leaves._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM none, HLL none, SS none, GK none, Bloom none, KMV none. Their shipped Count-Min aggregation (variant designed: their guest unchanged, with its per-row Merkle roots) is reported only as a REFERENCE, in its own table after the first one, so the numbers can be related to zk-Analytics' published ones; it is not the headline._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 256 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 and 1 (sampled), "2 epochs" = 2 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 2, EXCLUDING composition; its proof = the leaf-1 proof), "2 epochs" = the whole forest incl. its 1 merge (measured), which ends in ONE root proof: "verify" is that root, best of 5 calls (as zkA), in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 60.00 est | - | - |
| Count-Min 3x1024 | prove, 2 epochs (s) | 120.0 est | - | - |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 est | - | - |
| Count-Min 3x1024 | verify, 2 epochs (ms) | 23.0 est | - | - |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 225 est | - | - |
| Count-Min 3x1024 | proof, 2 epochs (KB) | 449 est | - | - |
| Count-Min 3x1024 | peak RSS (GB) | - | - | - |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 45.00 est | - | - |
| HLL b=14 † ‡ | prove, 2 epochs (s) | 90.00 est | - | - |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 11.5 est | - | - |
| HLL b=14 † ‡ | verify, 2 epochs (ms) | 23.0 est | - | - |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 est | - | - |
| HLL b=14 † ‡ | proof, 2 epochs (KB) | 449 est | - | - |
| HLL b=14 † ‡ | peak RSS (GB) | - | - | - |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 60.00 est | - | - |
| SS / MG s=1,024 † § | prove, 2 epochs (s) | 120.0 est | - | - |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.5 est | - | - |
| SS / MG s=1,024 † § | verify, 2 epochs (ms) | 23.0 est | - | - |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 est | - | - |
| SS / MG s=1,024 † § | proof, 2 epochs (KB) | 449 est | - | - |
| SS / MG s=1,024 † § | peak RSS (GB) | - | - | - |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | prove, 1 epoch (s) | 59.19 est | 11.67 | 5.1x est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | prove, 2 epochs (s) | 118.4 est | 32.73 | 3.6x est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | verify, 1 epoch (ms) | 11.5 est | 22.7 | 0.51x est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | verify, 2 epochs (ms) | 23.0 est | 22.7 | 1.0x est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | proof, 1 epoch (KB) | 225 est | 926 | 0.24x est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | proof, 2 epochs (KB) | 450 est | 804 | 0.56x est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | peak RSS (GB) | 9.2 | 8.3 | 1.1x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 60.00 est | - | - |
| Bloom 7x2^14 † | prove, 2 epochs (s) | 120.0 est | - | - |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 11.5 est | - | - |
| Bloom 7x2^14 † | verify, 2 epochs (ms) | 23.0 est | - | - |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 est | - | - |
| Bloom 7x2^14 † | proof, 2 epochs (KB) | 449 est | - | - |
| Bloom 7x2^14 † | peak RSS (GB) | - | - | - |
| KMV k=1,024 † | prove, 1 epoch (s) | 45.00 est | - | - |
| KMV k=1,024 † | prove, 2 epochs (s) | 90.00 est | - | - |
| KMV k=1,024 † | verify, 1 epoch (ms) | 11.5 est | - | - |
| KMV k=1,024 † | verify, 2 epochs (ms) | 23.0 est | - | - |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 est | - | - |
| KMV k=1,024 † | proof, 2 epochs (KB) | 449 est | - | - |
| KMV k=1,024 † | peak RSS (GB) | - | - | - |

**Reference, not the headline: zk-Analytics' shipped Count-Min aggregation** (zkA shipped = their `aggr_cm` unchanged, the `designed` variant. Besides the sketch update it builds per-row Merkle roots over the 3 x 1,024 counters plus cm_root and heap_root: 11,099,855 user cycles more than noroot at epoch 0 (12,799,204 vs 1,699,349; 14 vs 2 segments of 2^20, executor). No query guest or verifier reads those roots, and zk-Analytics' paper protocol has none (sections 5.2 and 5.3). It is reported so the numbers can be related to zk-Analytics' published ones, which include that cost. Metrics and conventions as in the table above; ratios are zkA / zkS)

| metric | zkA shipped CM (reference) | zkA noroot (headline) | zkS | reference / zkS | headline / zkS |
|---|---|---|---|---|---|
| prove, 1 epoch (s) | 420.0 est | 60.00 est | - | - | - |
| prove, 2 epochs (s) | 840.0 est | 120.0 est | - | - | - |
| verify, 1 epoch (ms) | 11.5 est | 11.5 est | - | - | - |
| verify, 2 epochs (ms) | 23.0 est | 23.0 est | - | - | - |
| proof, 1 epoch (KB) | 225 est | 225 est | - | - | - |
| proof, 2 epochs (KB) | 449 est | 449 est | - | - | - |
| peak RSS (GB) | - | - | - | - | - |

**Update side.** One epoch = one batch of 256 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 and 1 (sampled); zkA 2 epochs = 2 x that mean (derived). zkS "2 batches" is measured and includes the 1 forest merge; "leaf alone" is leafgen_seq_ms / 2 and EXCLUDES composition.

| sketch | zkA 2 epochs (s) | zkS 2 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 120 est | - | - est | 60.00 est | - | - est | - / - |
| HLL b=14 † ‡ | 90 est | - | - est | 45.00 est | - | - est | - / - |
| SS / MG s=1,024 † § | 120 est | - | - est | 60.00 est | - | - est | - / - |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | 118 est | 32.73 | 3.6x est | 59.19 est | 11.67 | 5.1x est | 9.2 / 8.3 |
| Bloom 7x2^14 † | 120 est | - | - est | 60.00 est | - | - est | - / - |
| KMV k=1,024 † | 90 est | - | - est | 45.00 est | - | - est | - / - |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 2 receipts | zkS root | zkS root verify, best of 5 (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | 225 est | 449 est | - | - |
| HLL b=14 † ‡ | 225 est | 449 est | - | - |
| SS / MG s=1,024 † § | 225 est | 449 est | - | - |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | 225 est | 450 est | 804 | 22.7 |
| Bloom 7x2^14 † | 225 est | 449 est | - | - |
| KMV k=1,024 † | 225 est | 449 est | - | - |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | n=2 | zkA / zkS at n=1 | at n=2 |
|---|---|---|---|---|
| Count-Min 3x1024 | 30.00 est / - | 60.00 est / - | - est | - est |
| HLL b=14 † ‡ | 15.00 est / - | 30.00 est / - | - est | - est |
| SS / MG s=1,024 † § | 30.00 est / - | 60.00 est / - | - est | - est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | 9.12 / 0.567 | 7.50 est / 0.585 | 16x | 13x est |
| Bloom 7x2^14 † (inserted key) | 7.50 est / - | 15.00 est / - | - est | - est |
| Bloom 7x2^14 † (absent key) | 7.50 est / - | 15.00 est / - | - est | - est |
| KMV k=1,024 † | 3.75 est / - | 7.50 est / - | - est | - est |

**Verifier work to accept one answer at n, zkA vs zkSketch** (ms; best of 5 calls per proof on both sides; deserialisation excluded on both sides; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) |
|---|---|---|
| Count-Min 3x1024 | - | - |
| HLL b=14 † ‡ | - | - |
| SS / MG s=1,024 † § | - | - |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | **23.0** est / 47.8 | **34.4** est / 43.8 |
| Bloom 7x2^14 † (inserted key) | - | - |
| Bloom 7x2^14 † (absent key) | - | - |
| KMV k=1,024 † | - | - |

**Bytes the verifier receives for one answer at n, zkA vs zkSketch** (KB; KB = 10^3 bytes; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) |
|---|---|---|
| Count-Min 3x1024 | - | - |
| HLL b=14 † ‡ | - | - |
| SS / MG s=1,024 † § | - | - |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | **449** est / 1,646 | **674** est / 1,523 |
| Bloom 7x2^14 † (inserted key) | - | - |
| Bloom 7x2^14 † (absent key) | - | - |
| KMV k=1,024 † | - | - |

**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the process already held; the same for every zkA root variant: query guests read no root)

| sketch | zkA n=1 | zkA n=2 | zkS n=1 / n=2 (max over n=1..2) |
|---|---|---|---|
| Count-Min 3x1024 | - | - | - |
| HLL b=14 † ‡ | - | - | - |
| SS / MG s=1,024 † § | - | - | - |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | 2.3 | - | 0.4 / 0.4 (0.4) |
| Bloom 7x2^14 † | - | - | - |
| KMV k=1,024 † | - | - | - |

**Answers vs exact** (same 512 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | 20 | - | 20 |
| Count-Min 3x1024 | 2 | 21 | - | 20 |
| HLL b=14 † ‡ | 1 | 174 | - | 174 |
| HLL b=14 † ‡ | 2 | 364 | - | 365 |
| SS / MG s=1,024 † § | 1 | key 418575398 count 20 (error 0) | - | key 418575398 count 20 |
| SS / MG s=1,024 † § | 2 | key 418575398 count 20 (error 0) | - | key 418575398 count 20 |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | 1 | 171 [169..174] | 171 | 173 |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | 2 | 330 [324..336] | 330 | 328 |
| Bloom 7x2^14 † (inserted key) | 1 | true | - | true |
| Bloom 7x2^14 † (inserted key) | 2 | true | - | true |
| Bloom 7x2^14 † (absent key) | 1 | false | - | false |
| Bloom 7x2^14 † (absent key) | 2 | false | - | false |
| KMV k=1,024 † | 1 | 174 | - | 174 |
| KMV k=1,024 † | 2 | 365 | - | 365 |

**zk-Analytics aggregation guest, epoch 0 (256 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 1,699,349 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 1,365,003 | 956,228 | 278,140 | 90.4% | measured (profiling marks) | 4.31 est | - est | - est |
| SS / MG s=1,024 † § | 1,682,947 | 956,247 | 280,907 | 73.5% | read + chain: legacy profiling twin aggr_ss_prof; user cycles: this variant (executor) | 15.89 est | - est | - est |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | 1,471,494 | 957,218 | 280,901 | 84.1% | measured (profiling marks) | 9.39 est | 0.80x est | 0.57x est |
| Bloom 7x2^14 † | 1,447,456 | 956,228 | 278,142 | 85.3% | measured (profiling marks) | 8.83 est | - est | - est |
| KMV k=1,024 † | 1,408,383 | 956,228 | 278,140 | 87.6% | measured (profiling marks) | 5.56 est | - est | - est |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (256 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root; root work = designed - noroot, the cost of the root nothing reads; designed is executed for every family but proved only for Count-Min, as the reference)

| sketch | designed: root | designed: user cycles (segments) | noroot: root | noroot: user cycles (segments) | root work (cycles) | share of designed |
|---|---|---|---|---|---|---|
| Count-Min 3x1024 | cm_rows+cm+heap | 12,799,204 (14) | none | 1,699,349 (2) | 11,099,855 | 86.7% |
| HLL b=14 † ‡ | samples64 | 1,660,181 (2) | none | 1,365,003 (2) | 295,178 | 17.8% |
| SS / MG s=1,024 † § | samples64 | 2,020,896 (3) | none | 1,682,947 (2) | 337,949 | 16.7% |
| GK eps=1/51 † (CONFIG MISMATCH: same rule, NOT the same function) | samples64 | 1,739,550 (2) | none | 1,471,494 (2) | 268,056 | 15.4% |
| Bloom 7x2^14 † | samples64 | 1,719,797 (2) | none | 1,447,456 (2) | 272,341 | 15.8% |
| KMV k=1,024 † | samples64 | 1,664,082 (2) | none | 1,408,383 (2) | 255,699 | 15.4% |
