_Run: 16,384 AOL records = 2 epochs x 8,192; zk-Analytics proved epochs 0 and 1 and queries at n = 1, 2; zkSketch features: default:pcs=hiding;logup_mask=on._

_`est` = ESTIMATED zk-Analytics prove time, NOT proved in this run: padded_cycles x k=31.817 s per 2^20 cycles, calibrated from 2 proof(s) of this run. Verify time and bytes of an estimated receipt are the mean of the measured ones; ratios built on an estimate are marked too._

_zk-Analytics aggregation guests (zkA): root variant noroot, their aggregation guests without the per-bucket Merkle root, the headline: that root is not part of zk-Analytics' protocol (paper sections 5.2 and 5.3: an epoch publishes its hash-chain values and one commitment to the whole state, which the query proof opens) and nothing in their code reads it; zkSketch publishes none either; root: CM not run, HLL none, SS none, GK none, Bloom not run, KMV not run._

**Update proofs side by side (headline: zkA = zk-Analytics without the per-bucket Merkle root, noroot): proving time, verification time, proof size, peak memory** (one epoch = one batch of 8,192 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 and 1 (sampled), "2 epochs" = 2 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 2, EXCLUDING composition; its proof = the leaf-1 proof), "2 epochs" = the whole forest incl. its 1 merge (measured), which ends in ONE root proof: "verify" is that root, best of 5 calls (as zkA), in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | - | - | - |
| Count-Min 3x1024 | prove, 2 epochs (s) | - | - | - |
| Count-Min 3x1024 | verify, 1 epoch (ms) | - | - | - |
| Count-Min 3x1024 | verify, 2 epochs (ms) | - | - | - |
| Count-Min 3x1024 | proof, 1 epoch (KB) | - | - | - |
| Count-Min 3x1024 | proof, 2 epochs (KB) | - | - | - |
| Count-Min 3x1024 | peak RSS (GB) | - | - | - |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 1,347.2 est | 30.45 | 44x est |
| HLL b=14 † ‡ | prove, 2 epochs (s) | 2,694.4 est | 74.93 | 36x est |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 9.9 est | 19.1 | 0.52x est |
| HLL b=14 † ‡ | verify, 2 epochs (ms) | 19.9 est | 19.1 | 1.0x est |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 est | 989 | 0.23x est |
| HLL b=14 † ‡ | proof, 2 epochs (KB) | 449 est | 804 | 0.56x est |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 26.1 | 0.35x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 1,622.7 est | 15.89 | 102x est |
| SS / MG s=1,024 † § | prove, 2 epochs (s) | 3,245.3 est | 42.36 | 77x est |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 9.9 est | 22.7 | 0.43x est |
| SS / MG s=1,024 † § | verify, 2 epochs (ms) | 19.7 est | 22.7 | 0.87x est |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 224 est | 941 | 0.24x est |
| SS / MG s=1,024 † § | proof, 2 epochs (KB) | 449 est | 804 | 0.56x est |
| SS / MG s=1,024 † § | peak RSS (GB) | - | 13.3 | - |
| GK eps=1/51 † | prove, 1 epoch (s) | 1,688.3 est | 172.6 | 9.8x est |
| GK eps=1/51 † | prove, 2 epochs (s) | 3,376.6 est | 403.7 | 8.4x est |
| GK eps=1/51 † | verify, 1 epoch (ms) | 9.9 est | 19.1 | 0.52x est |
| GK eps=1/51 † | verify, 2 epochs (ms) | 19.7 est | 19.1 | 1.0x est |
| GK eps=1/51 † | proof, 1 epoch (KB) | 224 est | 1,111 | 0.20x est |
| GK eps=1/51 † | proof, 2 epochs (KB) | 449 est | 804 | 0.56x est |
| GK eps=1/51 † | peak RSS (GB) | - | 133.3 | - |
| Bloom 7x2^14 † | prove, 1 epoch (s) | - | - | - |
| Bloom 7x2^14 † | prove, 2 epochs (s) | - | - | - |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | - | - | - |
| Bloom 7x2^14 † | verify, 2 epochs (ms) | - | - | - |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | - | - | - |
| Bloom 7x2^14 † | proof, 2 epochs (KB) | - | - | - |
| Bloom 7x2^14 † | peak RSS (GB) | - | - | - |
| KMV k=1,024 † | prove, 1 epoch (s) | - | - | - |
| KMV k=1,024 † | prove, 2 epochs (s) | - | - | - |
| KMV k=1,024 † | verify, 1 epoch (ms) | - | - | - |
| KMV k=1,024 † | verify, 2 epochs (ms) | - | - | - |
| KMV k=1,024 † | proof, 1 epoch (KB) | - | - | - |
| KMV k=1,024 † | proof, 2 epochs (KB) | - | - | - |
| KMV k=1,024 † | peak RSS (GB) | - | - | - |

**Update side.** One epoch = one batch of 8,192 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 and 1 (sampled); zkA 2 epochs = 2 x that mean (derived). zkS "2 batches" is measured and includes the 1 forest merge; "leaf alone" is leafgen_seq_ms / 2 and EXCLUDES composition.

| sketch | zkA 2 epochs (s) | zkS 2 batches incl. merges (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker |
|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | - | - | - | - | - | - | - / - |
| HLL b=14 † ‡ | 2,694 est | 74.93 | 36x est | 1,347.2 est | 30.45 | 44x est | 9.2 / 26.1 |
| SS / MG s=1,024 † § | 3,245 est | 42.36 | 77x est | 1,622.7 est | 15.89 | 102x est | - / 13.3 |
| GK eps=1/51 † | 3,377 est | 403.7 | 8.4x est | 1,688.3 est | 172.6 | 9.8x est | - / 133.3 |
| Bloom 7x2^14 † | - | - | - | - | - | - | - / - |
| KMV k=1,024 † | - | - | - | - | - | - | - / - |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 2 receipts | zkS root | zkS root verify, best of 5 (ms) |
|---|---|---|---|---|
| Count-Min 3x1024 | - | - | - | - |
| HLL b=14 † ‡ | 225 est | 449 est | 804 | 19.1 |
| SS / MG s=1,024 † § | 224 est | 449 est | 804 | 22.7 |
| GK eps=1/51 † | 224 est | 449 est | 804 | 19.1 |
| Bloom 7x2^14 † | - | - | - | - |
| KMV k=1,024 † | - | - | - | - |

**Query proving time** (s; the query proof alone; cells are zkA / zkS; ‡ and § see notes; the same for every zkA root variant: query guests read no root)

| sketch | n=1 | n=2 | zkA / zkS at n=1 | at n=2 |
|---|---|---|---|---|
| Count-Min 3x1024 | - / - | - / - | - | - |
| HLL b=14 † ‡ | 15.91 est / 7.93 | 31.82 est / 7.98 | 2.0x est | 4.0x est |
| SS / MG s=1,024 † § | 167.0 est / 0.506 | 350.0 est / 0.455 | 330x est | 768x est |
| GK eps=1/51 † | 6.03 / 1.66 | 7.95 est / 1.50 | 3.6x | 5.3x est |
| Bloom 7x2^14 † (inserted key) | - / - | - / - | - | - |
| Bloom 7x2^14 † (absent key) | - / - | - / - | - | - |
| KMV k=1,024 † | - / - | - / - | - | - |

**Verifier work to accept one answer at n, zkA vs zkSketch** (ms; best of 5 calls per proof on both sides; deserialisation excluded on both sides; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) |
|---|---|---|
| Count-Min 3x1024 | - | - |
| HLL b=14 † ‡ | **19.8** est / 44.3 | **29.8** est / 39.6 |
| SS / MG s=1,024 † § | **19.7** est / 49.3 | **29.6** est / 44.4 |
| GK eps=1/51 † | **19.5** est / 45.4 | **29.6** est / 38.2 |
| Bloom 7x2^14 † (inserted key) | - | - |
| Bloom 7x2^14 † (absent key) | - | - |
| KMV k=1,024 † | - | - |

**Bytes the verifier receives for one answer at n, zkA vs zkSketch** (KB; KB = 10^3 bytes; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) |
|---|---|---|
| Count-Min 3x1024 | - | - |
| HLL b=14 † ‡ | **449** est / 1,850 | **674** est / 1,665 |
| SS / MG s=1,024 † § | **449** est / 1,662 | **673** est / 1,525 |
| GK eps=1/51 † | **449** est / 1,895 | **673** est / 1,588 |
| Bloom 7x2^14 † (inserted key) | - | - |
| Bloom 7x2^14 † (absent key) | - | - |
| KMV k=1,024 † | - | - |

**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the process already held; the same for every zkA root variant: query guests read no root)

| sketch | zkA n=1 | zkA n=2 | zkS n=1 / n=2 (max over n=1..2) |
|---|---|---|---|
| Count-Min 3x1024 | - | - | - |
| HLL b=14 † ‡ | - | - | 8.4 / 8.5 (8.5) |
| SS / MG s=1,024 † § | - | - | 1.9 / 1.9 (1.9) |
| GK eps=1/51 † | 1.4 | - | 4.5 / 4.5 (4.5) |
| Bloom 7x2^14 † | - | - | - |
| KMV k=1,024 † | - | - | - |

**Answers vs exact** (same 16,384 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | exact |
|---|---|---|---|---|
| Count-Min 3x1024 | 1 | - | - | - |
| Count-Min 3x1024 | 2 | - | - | - |
| HLL b=14 † ‡ | 1 | 4461 | 14078.0 | 4432 |
| HLL b=14 † ‡ | 2 | 8472 | 16373.6 | 8433 |
| SS / MG s=1,024 † § | 1 | key 3011223745 count 115 (error 0) | count 113 (no key) | key 3011223745 count 115 |
| SS / MG s=1,024 † § | 2 | key 3780053395 count 180 (error 0) | count 176 (no key) | key 3780053395 count 180 |
| GK eps=1/51 † | 1 | 7100 [7011..7190] | 7064 | 7115 |
| GK eps=1/51 † | 2 | 7943 [7645..8242] | 7934 | 7967 |
| Bloom 7x2^14 † (inserted key) | 1 | - | - | - |
| Bloom 7x2^14 † (inserted key) | 2 | - | - | - |
| Bloom 7x2^14 † (absent key) | 1 | - | - | - |
| Bloom 7x2^14 † (absent key) | 2 | - | - | - |
| KMV k=1,024 † | 1 | - | - | - |
| KMV k=1,024 † | 2 | - | - | - |

**zk-Analytics aggregation guest, epoch 0 (8,192 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 44,486,348 | not profiled | not profiled | - | the noroot copy of their guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 41,303,437 | 30,399,780 | 8,891,676 | 95.1% | measured (profiling marks) | 65.63 est | 2.2x est | 1.8x est |
| SS / MG s=1,024 † § | 49,317,705 | 30,399,799 | 8,979,755 | 79.8% | read + chain: legacy profiling twin aggr_ss_prof; user cycles: this variant (executor) | 327.0 est | 21x est | 15x est |
| GK eps=1/51 † | 51,634,168 | 30,399,636 | 8,918,311 | 76.1% | read + chain: legacy profiling twin aggr_gk_prof; user cycles: this variant (executor) | 402.7 est | 2.3x est | 2.0x est |
| Bloom 7x2^14 † | 44,108,114 | 30,399,780 | 8,891,678 | 89.1% | measured (profiling marks) | - | - | - |
| KMV k=1,024 † | 43,199,016 | 30,399,780 | 8,891,676 | 91.0% | measured (profiling marks) | - | - | - |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (8,192 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | noroot: root | noroot: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | none | 44,486,348 (46) |
| HLL b=14 † ‡ | none | 41,303,437 (43) |
| SS / MG s=1,024 † § | none | 49,317,705 (51) |
| GK eps=1/51 † | none | 51,634,168 (54) |
| Bloom 7x2^14 † | none | 44,108,114 (46) |
| KMV k=1,024 † | none | 43,199,016 (45) |
