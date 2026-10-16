_GK, zk-Analytics side of this set: textbook Greenwald-Khanna (scripts/baselines/zka/gk), NOT zkSketch's GK rule; since 2026-10-15 the comparison runs zkSketch's own rule on that side (scripts/baselines/zka/gk_matched, SIX_ZKA_GK=matched)._

_zk-Analytics aggregation guests (zkA): root variant legacy, the guests of the committed 2026-10-09 run; root: CM cm_rows+cm+heap, HLL none, SS samples64, GK pertuple, Bloom none, KMV none._

**Update proofs side by side: proving time, verification time, proof size, peak memory** (one epoch = one batch of 2,048 records. zkA: one aggregation receipt per epoch, all kept and verified; "1 epoch" = the mean of proved epochs 0 and 7 (sampled), "8 epochs" = 8 x that (derived); verify = best of 5 calls per receipt; peak RSS = the r0vm process (max over the proved epochs). zkS: "1 epoch" = the leaf proof alone (leafgen_seq_ms / 8, EXCLUDING composition; its proof = the leaf-1 proof), "8 epochs" = the whole forest incl. its 7 merges (measured), which ends in ONE root proof: "verify" is that root, single call, in both rows; peak RSS = the procs-engine worker. Ratio = zkA / zkS for every metric: above 1, zkSketch is faster / smaller / lighter. KB = 10^3 bytes, GB = 2^30 bytes)

| sketch | metric | zkA | zkS | zkA / zkS |
|---|---|---|---|---|
| Count-Min 3x1024 | prove, 1 epoch (s) | 712.3 | 2.22 | 321x |
| Count-Min 3x1024 | prove, 8 epochs (s) | 5,698.5 | 30.08 | 189x |
| Count-Min 3x1024 | verify, 1 epoch (ms) | 11.5 | 16.7 | 0.69x |
| Count-Min 3x1024 | verify, 8 epochs (ms) | 92.0 | 16.7 | 5.5x |
| Count-Min 3x1024 | proof, 1 epoch (KB) | 226 | 658 | 0.34x |
| Count-Min 3x1024 | proof, 8 epochs (KB) | 1,807 | 528 | 3.4x |
| Count-Min 3x1024 | peak RSS (GB) | 9.2 | 2.8 | 3.2x |
| HLL b=14 † ‡ | prove, 1 epoch (s) | 322.9 | 2.05 | 157x |
| HLL b=14 † ‡ | prove, 8 epochs (s) | 2,583.6 | 27.84 | 93x |
| HLL b=14 † ‡ | verify, 1 epoch (ms) | 11.5 | 27.2 | 0.42x |
| HLL b=14 † ‡ | verify, 8 epochs (ms) | 91.8 | 27.2 | 3.4x |
| HLL b=14 † ‡ | proof, 1 epoch (KB) | 225 | 627 | 0.36x |
| HLL b=14 † ‡ | proof, 8 epochs (KB) | 1,796 | 529 | 3.4x |
| HLL b=14 † ‡ | peak RSS (GB) | 9.2 | 2.7 | 3.4x |
| SS / MG s=1,024 † § | prove, 1 epoch (s) | 449.3 | 1.01 | 446x |
| SS / MG s=1,024 † § | prove, 8 epochs (s) | 3,594.2 | 18.18 | 198x |
| SS / MG s=1,024 † § | verify, 1 epoch (ms) | 11.6 | 15.6 | 0.74x |
| SS / MG s=1,024 † § | verify, 8 epochs (ms) | 92.7 | 15.6 | 5.9x |
| SS / MG s=1,024 † § | proof, 1 epoch (KB) | 225 | 643 | 0.35x |
| SS / MG s=1,024 † § | proof, 8 epochs (KB) | 1,799 | 528 | 3.4x |
| SS / MG s=1,024 † § | peak RSS (GB) | 9.2 | 1.9 | 5.0x |
| GK eps=1/51 † (zkA: textbook GK) | prove, 1 epoch (s) | 420.0 | 14.74 | 28x |
| GK eps=1/51 † (zkA: textbook GK) | prove, 8 epochs (s) | 3,359.9 | 143.5 | 23x |
| GK eps=1/51 † (zkA: textbook GK) | verify, 1 epoch (ms) | 10.6 | 15.7 | 0.68x |
| GK eps=1/51 † (zkA: textbook GK) | verify, 8 epochs (ms) | 85.2 | 15.7 | 5.4x |
| GK eps=1/51 † (zkA: textbook GK) | proof, 1 epoch (KB) | 225 | 758 | 0.30x |
| GK eps=1/51 † (zkA: textbook GK) | proof, 8 epochs (KB) | 1,798 | 528 | 3.4x |
| GK eps=1/51 † (zkA: textbook GK) | peak RSS (GB) | 9.2 | 19.4 | 0.47x |
| Bloom 7x2^14 † | prove, 1 epoch (s) | 355.2 | 4.36 | 81x |
| Bloom 7x2^14 † | prove, 8 epochs (s) | 2,841.2 | 50.09 | 57x |
| Bloom 7x2^14 † | verify, 1 epoch (ms) | 9.7 | 15.4 | 0.63x |
| Bloom 7x2^14 † | verify, 8 epochs (ms) | 77.9 | 15.4 | 5.1x |
| Bloom 7x2^14 † | proof, 1 epoch (KB) | 225 | 637 | 0.35x |
| Bloom 7x2^14 † | proof, 8 epochs (KB) | 1,796 | 529 | 3.4x |
| Bloom 7x2^14 † | peak RSS (GB) | 9.2 | 5.3 | 1.7x |
| KMV k=1,024 † | prove, 1 epoch (s) | 356.7 | 0.724 | 493x |
| KMV k=1,024 † | prove, 8 epochs (s) | 2,853.6 | 16.03 | 178x |
| KMV k=1,024 † | verify, 1 epoch (ms) | 9.8 | 15.7 | 0.62x |
| KMV k=1,024 † | verify, 8 epochs (ms) | 78.1 | 15.7 | 5.0x |
| KMV k=1,024 † | proof, 1 epoch (KB) | 225 | 561 | 0.40x |
| KMV k=1,024 † | proof, 8 epochs (KB) | 1,796 | 529 | 3.4x |
| KMV k=1,024 † | peak RSS (GB) | 9.2 | 1.5 | 6.1x |

**Update side.** One epoch = one batch of 2,048 records. Ratios are zkA / zkS. zkA prove per epoch is the mean of proved epochs 0 and 7 (sampled); zkA 8 epochs = 8 x that mean (derived). zkS "8 batches" is measured and includes the 7 forest merges; "leaf alone" is leafgen_seq_ms / 8 and EXCLUDES composition.

| sketch | zkA 8 epochs (s) | zkS 8 batches incl. merges (s) | ratio | zkS-zk 8 batches (s) | ratio | zkA / epoch (s) | zkS leaf alone (s) | ratio | zkS-zk leaf alone (s) | ratio | peak RSS GB: zkA r0vm / zkS worker / zkS-zk worker |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 5,699 | 30.08 | 189x | - | - | 712.3 | 2.22 | 321x | - | - | 9.2 / 2.8 / - |
| HLL b=14 † ‡ | 2,584 | 27.84 | 93x | - | - | 322.9 | 2.05 | 157x | - | - | 9.2 / 2.7 / - |
| SS / MG s=1,024 † § | 3,594 | 18.18 | 198x | - | - | 449.3 | 1.01 | 446x | - | - | 9.2 / 1.9 / - |
| GK eps=1/51 † (zkA: textbook GK) | 3,360 | 143.5 | 23x | - | - | 420.0 | 14.74 | 28x | - | - | 9.2 / 19.4 / - |
| Bloom 7x2^14 † | 2,841 | 50.09 | 57x | - | - | 355.2 | 4.36 | 81x | - | - | 9.2 / 5.3 / - |
| KMV k=1,024 † | 2,854 | 16.03 | 178x | - | - | 356.7 | 0.724 | 493x | - | - | 9.2 / 1.5 / - |

**Proof bytes, update side** (KB = 10^3 bytes): zkA keeps one receipt per epoch; zkS keeps one root.

| sketch | zkA receipt / epoch | zkA 8 receipts | zkS root | zkS-zk root | zkS root verify, single call (ms) | zkS-zk root verify (ms) |
|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 226 | 1,807 | 528 | - | 16.7 | - |
| HLL b=14 † ‡ | 225 | 1,796 | 529 | - | 27.2 | - |
| SS / MG s=1,024 † § | 225 | 1,799 | 528 | - | 15.6 | - |
| GK eps=1/51 † (zkA: textbook GK) | 225 | 1,798 | 528 | - | 15.7 | - |
| Bloom 7x2^14 † | 225 | 1,796 | 529 | - | 15.4 | - |
| KMV k=1,024 † | 225 | 1,796 | 529 | - | 15.7 | - |

**Query proving time** (s; the query proof alone; cells are zkA / zkS / zkS-zk; ‡ and § see notes)

| sketch | n=1 | n=2 | n=4 | n=8 | zkA / zkS at n=1 | at n=8 | zkA / zkS-zk at n=1 | at n=8 |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 27.88 / 0.075 / - | 59.02 / 0.078 / - | 106.8 / 0.076 / - | 210.0 / 0.075 / - | 371x | 2,803x | - | - |
| HLL b=14 † ‡ | 15.39 / 1.97 / - | 27.76 / 1.88 / - | 39.57 / 1.68 / - | 70.77 / 1.89 / - | 7.8x | 37x | - | - |
| SS / MG s=1,024 † § | 163.2 / 0.128 / - | 334.9 / 0.128 / - | 688.4 / 0.130 / - | 1,412.8 / 0.118 / - | 1,274x | 11,947x | - | - |
| GK eps=1/51 † (zkA: textbook GK) | 5.93 / 0.412 / - | 9.27 / 0.401 / - | 15.63 / 0.382 / - | 27.75 / 0.360 / - | 14x | 77x | - | - |
| Bloom 7x2^14 † (inserted key) | 9.36 / 1.71 / - | 15.40 / 1.69 / - | 15.65 / 1.84 / - | 28.14 / 1.82 / - | 5.5x | 15x | - | - |
| Bloom 7x2^14 † (absent key) | 9.28 / 1.89 / - | 15.66 / 1.75 / - | 15.71 / 1.68 / - | 27.50 / 1.69 / - | 4.9x | 16x | - | - |
| KMV k=1,024 † | 9.33 / 0.107 / - | 15.53 / 0.109 / - | 27.70 / 0.109 / - | 46.93 / 0.109 / - | 87x | 432x | - | - |

**zkSketch query proving at the other n** (s; zkS / zkS-zk; zkA did not prove these n)

| sketch | n=3 | n=5 | n=6 | n=7 |
|---|---|---|---|---|
| Count-Min 3x1024 | 0.077 / - | 0.072 / - | 0.073 / - | 0.074 / - |
| HLL b=14 † ‡ | 1.66 / - | 1.71 / - | 1.71 / - | 1.75 / - |
| SS / MG s=1,024 † § | 0.125 / - | 0.121 / - | 0.123 / - | 0.118 / - |
| GK eps=1/51 † (zkA: textbook GK) | 0.399 / - | 0.397 / - | 0.376 / - | 0.366 / - |
| Bloom 7x2^14 † (inserted key) | 1.78 / - | 1.72 / - | 1.71 / - | 1.86 / - |
| Bloom 7x2^14 † (absent key) | 1.77 / - | 1.74 / - | 1.70 / - | 1.67 / - |
| KMV k=1,024 † | 0.112 / - | 0.113 / - | 0.113 / - | 0.108 / - |

**Verifier work to accept one answer at n, zkA vs zkSketch default build** (ms; best of 5 calls per proof on both sides; deserialisation excluded on both sides; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) | n=3 (2 peaks) | n=4 (1 peak) | n=5 (2 peaks) | n=6 (2 peaks) | n=7 (3 peaks) | n=8 (1 peak) |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | **21.2** / 33.2 | 32.8 / **27.5** | 44.2 / **43.9** | 55.8 / **27.8** | 67.2 / **47.3** | 78.7 / **44.1** | 90.2 / **63.7** | 101.7 / **29.1** |
| HLL b=14 † ‡ | **21.1** / 33.7 | **32.9** / 34.1 | **44.2** / 50.2 | 55.6 / **30.0** | 67.2 / **49.0** | 78.6 / **46.5** | 90.1 / **65.5** | 101.6 / **30.4** |
| SS / MG s=1,024 † § | **21.3** / 34.4 | 32.9 / **31.7** | **45.3** / 51.3 | 57.9 / **30.1** | 68.5 / **49.8** | 80.1 / **46.7** | 91.7 / **66.3** | 104.1 / **30.3** |
| GK eps=1/51 † (zkA: textbook GK) | **22.1** / 38.1 | 33.0 / **29.8** | **42.6** / 48.3 | 52.4 / **28.8** | 63.9 / **47.3** | 74.6 / **42.7** | 85.2 / **61.3** | 94.9 / **28.7** |
| Bloom 7x2^14 † (inserted key) | **19.4** / 30.1 | 29.2 / **28.3** | **39.4** / 46.8 | 48.6 / **30.1** | 58.9 / **45.7** | 68.6 / **43.9** | 78.3 / **59.6** | 87.6 / **30.1** |
| Bloom 7x2^14 † (absent key) | **19.4** / 30.2 | 29.2 / **28.3** | **39.4** / 44.0 | 50.5 / **29.9** | 58.9 / **48.5** | 68.6 / **46.3** | 78.3 / **65.0** | 89.4 / **29.8** |
| KMV k=1,024 † | **19.5** / 29.9 | 29.2 / **25.7** | **39.0** / 39.9 | 48.7 / **25.7** | 58.5 / **39.9** | 68.3 / **38.5** | 78.1 / **52.8** | 87.9 / **28.1** |

**Bytes the verifier receives for one answer at n, zkA vs zkSketch default build** (KB; KB = 10^3 bytes; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) | n=3 (2 peaks) | n=4 (1 peak) | n=5 (2 peaks) | n=6 (2 peaks) | n=7 (3 peaks) | n=8 (1 peak) |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | **450** / 1,085 | **676** / 993 | **902** / 1,652 | 1,128 / **955** | **1,354** / 1,613 | 1,580 / **1,522** | **1,806** / 2,180 | 2,033 / **955** |
| HLL b=14 † ‡ | **449** / 1,221 | **673** / 1,160 | **898** / 1,788 | 1,123 / **1,122** | **1,348** / 1,750 | **1,572** / 1,689 | **1,797** / 2,316 | 2,022 / **1,123** |
| SS / MG s=1,024 † § | **449** / 1,110 | **674** / 1,033 | **899** / 1,676 | 1,124 / **995** | **1,349** / 1,638 | 1,574 / **1,562** | **1,799** / 2,205 | 2,025 / **996** |
| GK eps=1/51 † (zkA: textbook GK) | **449** / 1,281 | **674** / 1,090 | **899** / 1,848 | 1,124 / **1,052** | **1,349** / 1,810 | **1,574** / 1,618 | **1,798** / 2,376 | 2,024 / **1,052** |
| Bloom 7x2^14 † (inserted key) | **449** / 1,228 | **674** / 1,158 | **899** / 1,796 | 1,123 / **1,120** | **1,348** / 1,757 | **1,572** / 1,687 | **1,797** / 2,324 | 2,022 / **1,120** |
| Bloom 7x2^14 † (absent key) | **449** / 1,228 | **674** / 1,158 | **899** / 1,795 | 1,123 / **1,120** | **1,348** / 1,757 | **1,572** / 1,687 | **1,797** / 2,324 | 2,022 / **1,120** |
| KMV k=1,024 † | **449** / 988 | **673** / 955 | **898** / 1,517 | 1,123 / **955** | **1,348** / 1,516 | 1,572 / **1,484** | **1,797** / 2,044 | 2,022 / **956** |

**Verifier work to accept one answer at n, zkA vs zkSketch `--features zk`** (ms; best of 5 calls per proof on both sides; deserialisation excluded on both sides; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) | n=3 (2 peaks) | n=4 (1 peak) | n=5 (2 peaks) | n=6 (2 peaks) | n=7 (3 peaks) | n=8 (1 peak) |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | - | - | - | - | - | - | - | - |
| HLL b=14 † ‡ | - | - | - | - | - | - | - | - |
| SS / MG s=1,024 † § | - | - | - | - | - | - | - | - |
| GK eps=1/51 † (zkA: textbook GK) | - | - | - | - | - | - | - | - |
| Bloom 7x2^14 † (inserted key) | - | - | - | - | - | - | - | - |
| Bloom 7x2^14 † (absent key) | - | - | - | - | - | - | - | - |
| KMV k=1,024 † | - | - | - | - | - | - | - | - |

**Bytes the verifier receives for one answer at n, zkA vs zkSketch `--features zk`** (KB; KB = 10^3 bytes; cells zkA / zkS; zkA = n aggregation receipts + 1 query receipt, derived; zkS = live forest peak(s) + 1 query proof, sum of measured parts; **bold** = the smaller side)

| sketch | n=1 (1 peak) | n=2 (1 peak) | n=3 (2 peaks) | n=4 (1 peak) | n=5 (2 peaks) | n=6 (2 peaks) | n=7 (3 peaks) | n=8 (1 peak) |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | - | - | - | - | - | - | - | - |
| HLL b=14 † ‡ | - | - | - | - | - | - | - | - |
| SS / MG s=1,024 † § | - | - | - | - | - | - | - | - |
| GK eps=1/51 † (zkA: textbook GK) | - | - | - | - | - | - | - | - |
| Bloom 7x2^14 † (inserted key) | - | - | - | - | - | - | - | - |
| Bloom 7x2^14 † (absent key) | - | - | - | - | - | - | - | - |
| KMV k=1,024 † | - | - | - | - | - | - | - | - |

**Verify protocol, one proof** (ms; in-process, right after proving; first call / median of 5 / best of 5; decode = deserialisation, not in any verify column)

| sketch | zkA query receipt n=1 (re-proof) | zkA decode (bincode) | zkS query proof n=1 | zkS leaf-1 peak (accept n=1) | zkS decode (postcard), leaf-1 | zkS-zk query proof n=1 |
|---|---|---|---|---|---|---|
| Count-Min 3x1024 | - | - | 13.8 / 13.6 / 13.6 | 19.8 / 19.6 / 19.6 | 0.83 | - |
| HLL b=14 † ‡ | - | - | 14.9 / 14.7 / 14.7 | 19.2 / 19.0 / 19.0 | 0.58 | - |
| SS / MG s=1,024 † § | - | - | 15.1 / 14.9 / 14.8 | 19.7 / 19.6 / 19.6 | 0.68 | - |
| GK eps=1/51 † (zkA: textbook GK) | - | - | 17.2 / 16.2 / 16.1 | 22.2 / 22.1 / 22.0 | 0.74 | - |
| Bloom 7x2^14 † | - | - | 14.8 / 14.5 / 14.5 | 18.7 / 18.1 / 15.7 | 0.58 | - |
| KMV k=1,024 † | - | - | 13.0 / 12.8 / 12.8 | 17.4 / 17.1 / 17.1 | 0.63 | - |

**Peak RSS while proving one query** (GB = 2^30 bytes; zkA: the r0vm process of that proof; zkS: the coordinator process, VmHWM reset when the query starts, so the value is that query alone plus what the process already held)

| sketch | zkA n=1 | zkA n=2 | zkA n=4 | zkA n=8 | zkS n=1 / n=8 (max over n=1..8) | zkS-zk n=1 / n=8 (max) |
|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 9.1 | 9.2 | 9.2 | 9.2 | 0.7 / 0.7 (0.7) | - |
| HLL b=14 † ‡ | 4.6 | 9.1 | 9.1 | 9.2 | 3.0 / 3.0 (3.0) | - |
| SS / MG s=1,024 † § | 9.2 | 9.2 | 9.2 | 9.2 | 0.8 / 0.8 (0.8) | - |
| GK eps=1/51 † (zkA: textbook GK) | 1.4 | 2.3 | 4.6 | 9.1 | 1.5 / 1.5 (1.5) | - |
| Bloom 7x2^14 † | 2.3 | 4.6 | 4.6 | 9.1 | 3.2 / 3.3 (3.3) | - |
| KMV k=1,024 † | 2.3 | 4.6 | 9.1 | 9.1 | 0.6 / 0.6 (0.6) | - |

**Answers vs exact** (same 16,384 AOL records; exact computed natively; ‡ HLL zkSketch answers are the raw estimator, outside HLL error bounds)

| sketch | n | zk-Analytics answer | zkSketch answer | zkSketch-zk answer | exact |
|---|---|---|---|---|---|
| Count-Min 3x1024 | 1 | 115 | 115 | - | 115 |
| Count-Min 3x1024 | 2 | 116 | 115 | - | 115 |
| Count-Min 3x1024 | 4 | 119 | 118 | - | 115 |
| Count-Min 3x1024 | 8 | 189 | 185 | - | 180 |
| HLL b=14 † ‡ | 1 | 1232 | 12422.5 | - | 1234 |
| HLL b=14 † ‡ | 2 | 2397 | 13011.8 | - | 2372 |
| HLL b=14 † ‡ | 4 | 4461 | 14078.0 | - | 4432 |
| HLL b=14 † ‡ | 8 | 8472 | 16373.6 | - | 8433 |
| SS / MG s=1,024 † § | 1 | key 3011223745 count 115 (error 0) | count 114 (no key) | - | key 3011223745 count 115 |
| SS / MG s=1,024 † § | 2 | key 3011223745 count 115 (error 0) | count 113 (no key) | - | key 3011223745 count 115 |
| SS / MG s=1,024 † § | 4 | key 3011223745 count 115 (error 0) | count 111 (no key) | - | key 3011223745 count 115 |
| SS / MG s=1,024 † § | 8 | key 3780053395 count 180 (error 0) | count 172 (no key) | - | key 3780053395 count 180 |
| GK eps=1/51 † (zkA: textbook GK) | 1 | 1789 [1750..1829] | 1786 | - | 1789 |
| GK eps=1/51 † (zkA: textbook GK) | 2 | 3595 [3518..3672] | 3557 | - | 3569 |
| GK eps=1/51 † (zkA: textbook GK) | 4 | 7150 [7014..7287] | 7095 | - | 7115 |
| GK eps=1/51 † (zkA: textbook GK) | 8 | 7985 [7718..8253] | 7927 | - | 7967 |
| Bloom 7x2^14 † (inserted key) | 1 | true | true | - | true |
| Bloom 7x2^14 † (inserted key) | 2 | true | true | - | true |
| Bloom 7x2^14 † (inserted key) | 4 | true | true | - | true |
| Bloom 7x2^14 † (inserted key) | 8 | true | true | - | true |
| Bloom 7x2^14 † (absent key) | 1 | false | false | - | false |
| Bloom 7x2^14 † (absent key) | 2 | false | false | - | false |
| Bloom 7x2^14 † (absent key) | 4 | false | false | - | false |
| Bloom 7x2^14 † (absent key) | 8 | false | false | - | false |
| KMV k=1,024 † | 1 | 1232 | 1241 | - | 1234 |
| KMV k=1,024 † | 2 | 2290 | 2320 | - | 2372 |
| KMV k=1,024 † | 4 | 4405 | 4365 | - | 4432 |
| KMV k=1,024 † | 8 | 8202 | 8484 | - | 8433 |

**Repeatability, zkSketch default build: run r1 (first run) vs r2 (primary)**

| sketch | 8 batches r1 / r2 (s) | leaf alone r1 / r2 (s) | query prove n=1..8 summed r1 / r2 (s) |
|---|---|---|---|
| Count-Min 3x1024 | 29.96 / 30.08 | 2.26 / 2.22 | 0.607 / 0.600 |
| HLL b=14 † ‡ | 25.74 / 27.84 | 1.89 / 2.05 | 14.85 / 14.26 |
| SS / MG s=1,024 † § | 18.03 / 18.18 | 1.02 / 1.01 | 1.03 / 0.991 |
| GK eps=1/51 † (zkA: textbook GK) | 142.2 / 143.5 | 14.59 / 14.74 | 2.96 / 3.09 |
| Bloom 7x2^14 † | 44.87 / 50.09 | 3.97 / 4.36 | 14.52 / 14.15 |
| KMV k=1,024 † | 16.22 / 16.03 | 0.734 / 0.724 | 0.836 / 0.879 |

**zk-Analytics aggregation guest, epoch 0 (2,048 records): their ingest vs the rest** (user cycles; MODELED column = proved per-epoch time x the non-ingest share of user cycles, ignoring paging and segment rounding; it is NOT a measurement)

| sketch | user cycles | Event read | batch-chain check | read + chain share | source | MODELED non-ingest prove / epoch (s) | vs zkS leaf alone | vs zkS amortized |
|---|---|---|---|---|---|---|---|---|
| Count-Min 3x1024 | 22,540,245 | not profiled | not profiled | - | their shipped guest has no profiling twin | - | - | - |
| HLL b=14 † ‡ | 10,395,108 | 7,604,628 | 2,238,471 | 94.7% | measured (profiling marks) | 17.15 | 8.4x | 4.9x |
| SS / MG s=1,024 † § | 14,066,559 | not profiled | not profiled | - | no six_zka_prof_* rows in this results directory | - | - | - |
| GK eps=1/51 † (zkA: textbook GK) | 13,405,908 | not profiled | not profiled | - | no six_zka_prof_* rows in this results directory | - | - | - |
| Bloom 7x2^14 † | 11,091,953 | 7,604,628 | 2,238,473 | 88.7% | measured (profiling marks) | 39.99 | 9.2x | 6.4x |
| KMV k=1,024 † | 11,104,487 | 7,604,628 | 2,223,111 | 88.5% | measured (profiling marks) | 41.01 | 57x | 20x |

**zk-Analytics aggregation guests per root variant** (executor, aggregation epoch 0 (2,048 records): user cycles (segments of at most 2^20 cycles); root = what the variant proves besides the state commitment: cm_rows+cm+heap = their CM row roots over 3 x 1,024 counter leaves + cm_root + heap_root, samples64 / buckets64 = their samples pattern with 64 buckets, pertuple = one leaf per GK tuple, none = no root)

| sketch | legacy: root | legacy: user cycles (segments) |
|---|---|---|
| Count-Min 3x1024 | cm_rows+cm+heap | 22,540,245 (24) |
| HLL b=14 † ‡ | none | 10,395,108 (11) |
| SS / MG s=1,024 † § | samples64 | 14,066,559 (15) |
| GK eps=1/51 † (zkA: textbook GK) | pertuple | 13,405,908 (14) |
| Bloom 7x2^14 † | none | 11,091,953 (12) |
| KMV k=1,024 † | none | 11,104,487 (12) |
