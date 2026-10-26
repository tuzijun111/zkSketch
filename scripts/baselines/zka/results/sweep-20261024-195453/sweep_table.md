# Batch-size sweep: zkSketch vs zk-Analytics, one batch of m = 2^E records per size

_Conventions. zkA = zk-Analytics side: ONE aggregation receipt per m-record epoch (epoch 0 proved; root variant noroot: their guest without the unused per-bucket Merkle root when noroot; † = our port of the sketch into their RISC Zero pipeline, zk-Analytics ships only Count-Min), no shipped-CM reference. zkS = zkSketch: ONE leaf per m-record batch (SIX_T = 1, k = 1: the single leaf proof, `leafgen_seq_ms`; no composition), a query after it. Both on 32 cores (SIX_CORES; zkSketch pins its worker, r0vm takes the same taskset), zero knowledge on (zkSketch pcs=hiding, logup_mask=on; RISC Zero succinct receipts), AOL keys. prove = that one proof; ms/rec = prove x 1000 / m; verify = in-process calls, zkA the best of 5 on the receipt, zkS the best of 5 on the leaf (= the forest's root at k = 1); `1st` = that run's log has no QLOG_ROOTV line, so its verify is the one call exp_compose made; proof = its bytes; peak RSS = zkA the r0vm process, zkS the procs-engine worker (coordinator and combined peaks: m<EE>/six_sketch_comparison.csv). GK: zkSketch's own GK rule on both sides (the matched port). Ratios are zkA / zkS: above 1, zkSketch is faster / smaller / lighter. `est` = a zkA value assemble.py ESTIMATED (not proved in that size); `-` = not run or failed. zkS variant = the zkSketch circuit of that run; a Bloom row marked (omc) ran the bit-array leaf because the packed leaf needs 7 x m < 2^16. KB = 10^3 bytes, GB = 2^30 bytes._

**Prove time, zkA / zkS across batch sizes** (one proof of one m-record batch on each side; cells zkA / zkS; rows m = 2^E)

| m | Count-Min 3x1024 | HLL b=14 † | SS / MG s=1,024 † | GK eps=1/51 † | Bloom 7x2^14 † | KMV k=1,024 † |
|---|---|---|---|---|---|---|
| 2^6 = 64 | 43x | 6.6x | 8.1x | 35x | 13x | 25x |
| 2^7 = 128 | 37x | 12x | 16x | 39x | 15x | 29x |
| 2^8 = 256 | 51x | 26x | 31x | 45x | 28x | 52x |
| 2^9 = 512 | 56x | 28x | 67x | 50x | 39x | 73x |
| 2^10 = 1,024 | 55x | 47x | 72x | 44x | 41x | 98x |
| 2^11 = 2,048 | 58x | 53x | 126x | 72x | 48x | 181x |
| 2^12 = 4,096 | 59x | 57x | 135x | 66x | 53x | 166x |
| 2^13 = 8,192 | 58x | 64x | 137x | 98x | 58x | 189x |
| 2^14 = 16,384 | 61x | 65x | 143x | 102x | 58x | 207x |

**Prove time per record, ms** (prove x 1000 / m; cells zkA / zkS)

| m | Count-Min 3x1024 | HLL b=14 † | SS / MG s=1,024 † | GK eps=1/51 † | Bloom 7x2^14 † | KMV k=1,024 † |
|---|---|---|---|---|---|---|
| 2^6 = 64 | 626.17 / 14.61 | 347.83 / 52.56 | 350.98 / 43.42 | 6,377.09 / 184.51 | 348.83 / 27.63 | 348.55 / 13.95 |
| 2^7 = 128 | 411.59 / 11.09 | 314.98 / 26.57 | 318.77 / 19.47 | 3,450.45 / 88.51 | 316.08 / 21.07 | 314.63 / 10.75 |
| 2^8 = 256 | 328.82 / 6.42 | 265.77 / 10.42 | 329.86 / 10.77 | 1,893.78 / 42.21 | 332.59 / 11.83 | 259.88 / 5.04 |
| 2^9 = 512 | 283.08 / 5.09 | 253.25 / 9.09 | 339.68 / 5.06 | 1,207.92 / 24.14 | 251.28 / 6.46 | 251.93 / 3.46 |
| 2^10 = 1,024 | 255.37 / 4.67 | 237.95 / 5.06 | 302.38 / 4.23 | 818.60 / 18.56 | 255.18 / 6.24 | 255.11 / 2.61 |
| 2^11 = 2,048 | 258.91 / 4.43 | 235.43 / 4.42 | 299.64 / 2.38 | 630.19 / 8.70 | 251.77 / 5.24 | 249.35 / 1.38 |
| 2^12 = 4,096 | 249.21 / 4.20 | 229.97 / 4.02 | 280.77 / 2.08 | 579.97 / 8.75 | 248.68 / 4.72 | 244.71 / 1.48 |
| 2^13 = 8,192 | 247.96 / 4.30 | 230.08 / 3.60 | 276.60 / 2.02 | 568.14 / 5.81 | 246.18 / 4.22 | 241.52 / 1.28 |
| 2^14 = 16,384 | 246.45 / 4.05 | 230.01 / 3.57 | 271.75 / 1.90 | 573.57 / 5.65 | 245.09 / 4.25 | 237.02 / 1.15 |

**Count-Min 3x1024** (rows m = 2^E; zkA one receipt per batch, zkS one leaf per batch; ratios zkA / zkS)

| m | zkA prove (s) | zkS prove (s) | zkA / zkS | zkA ms/rec | zkS ms/rec | zkA verify (ms) | zkS verify (ms) | zkA / zkS | zkA proof (KB) | zkS proof (KB) | zkA / zkS | zkA peak RSS (GB) | zkS peak RSS (GB) | zkA / zkS | zkS variant |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2^6 = 64 | 40.08 | 0.935 | 43x | 626.17 | 14.61 | 9.7 | 24.7 1st | 0.39x 1st | 225.8 | 816.3 | 0.28x | 9.13 | 0.44 | 21x | cm_omc |
| 2^7 = 128 | 52.68 | 1.42 | 37x | 411.59 | 11.09 | 11.5 | 25.1 1st | 0.46x 1st | 225.8 | 804.0 | 0.28x | 9.16 | 0.83 | 11x | cm_omc |
| 2^8 = 256 | 84.18 | 1.64 | 51x | 328.82 | 6.42 | 11.5 | 25.8 1st | 0.44x 1st | 225.8 | 839.2 | 0.27x | 9.16 | 0.85 | 11x | cm_omc |
| 2^9 = 512 | 144.9 | 2.61 | 56x | 283.08 | 5.09 | 11.4 | 26.6 1st | 0.43x 1st | 225.8 | 888.9 | 0.25x | 9.16 | 1.80 | 5.1x | cm_omc |
| 2^10 = 1,024 | 261.5 | 4.78 | 55x | 255.37 | 4.67 | 11.5 | 23.8 1st | 0.48x 1st | 225.8 | 905.5 | 0.25x | 9.16 | 3.69 | 2.5x | cm_omc |
| 2^11 = 2,048 | 530.2 | 9.07 | 58x | 258.91 | 4.43 | 11.5 | 28.7 1st | 0.40x 1st | 225.8 | 955.8 | 0.24x | 9.17 | 7.19 | 1.3x | cm_omc |
| 2^12 = 4,096 | 1,020.8 | 17.21 | 59x | 249.21 | 4.20 | 11.5 | 26.2 1st | 0.44x 1st | 225.8 | 976.2 | 0.23x | 9.18 | 14.42 | 0.64x | cm_omc |
| 2^13 = 8,192 | 2,031.3 | 35.19 | 58x | 247.96 | 4.30 | 11.5 | 26.0 1st | 0.44x 1st | 225.8 | 1,030.1 | 0.22x | 9.20 | 28.79 | 0.32x | cm_omc |
| 2^14 = 16,384 | 4,037.8 | 66.27 | 61x | 246.45 | 4.05 | 11.5 | 30.3 1st | 0.38x 1st | 225.8 | 1,053.6 | 0.21x | 9.23 | 57.53 | 0.16x | cm_omc |

**HLL b=14 †** (rows m = 2^E; zkA one receipt per batch, zkS one leaf per batch; ratios zkA / zkS)

| m | zkA prove (s) | zkS prove (s) | zkA / zkS | zkA ms/rec | zkS ms/rec | zkA verify (ms) | zkS verify (ms) | zkA / zkS | zkA proof (KB) | zkS proof (KB) | zkA / zkS | zkA peak RSS (GB) | zkS peak RSS (GB) | zkA / zkS | zkS variant |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2^6 = 64 | 22.26 | 3.36 | 6.6x | 347.83 | 52.56 | 9.7 | 26.4 1st | 0.37x 1st | 224.8 | 884.5 | 0.25x | 4.59 | 1.95 | 2.4x | hll_omc |
| 2^7 = 128 | 40.32 | 3.40 | 12x | 314.98 | 26.57 | 9.7 | 26.7 1st | 0.36x 1st | 224.8 | 856.1 | 0.26x | 9.13 | 1.96 | 4.7x | hll_omc |
| 2^8 = 256 | 68.04 | 2.67 | 26x | 265.77 | 10.42 | 11.7 | 22.9 1st | 0.51x 1st | 224.8 | 855.9 | 0.26x | 9.17 | 1.98 | 4.6x | hll_omc |
| 2^9 = 512 | 129.7 | 4.65 | 28x | 253.25 | 9.09 | 11.5 | 28.1 1st | 0.41x 1st | 224.8 | 907.6 | 0.25x | 9.17 | 3.37 | 2.7x | hll_omc |
| 2^10 = 1,024 | 243.7 | 5.18 | 47x | 237.95 | 5.06 | 11.5 | 22.6 1st | 0.51x 1st | 224.8 | 908.1 | 0.25x | 9.17 | 3.67 | 2.5x | hll_omc |
| 2^11 = 2,048 | 482.2 | 9.06 | 53x | 235.43 | 4.42 | 9.7 | 26.2 1st | 0.37x 1st | 224.8 | 922.7 | 0.24x | 9.17 | 6.81 | 1.3x | hll_omc |
| 2^12 = 4,096 | 941.9 | 16.45 | 57x | 229.97 | 4.02 | 9.7 | 25.5 1st | 0.38x 1st | 224.8 | 971.6 | 0.23x | 9.18 | 13.20 | 0.70x | hll_omc |
| 2^13 = 8,192 | 1,884.8 | 29.46 | 64x | 230.08 | 3.60 | 11.5 | 28.6 1st | 0.40x 1st | 224.8 | 988.9 | 0.23x | 9.20 | 26.05 | 0.35x | hll_omc |
| 2^14 = 16,384 | 3,768.4 | 58.42 | 65x | 230.01 | 3.57 | 11.5 | 26.1 1st | 0.44x 1st | 224.8 | 1,013.2 | 0.22x | 9.21 | 51.42 | 0.18x | hll_omc |

**SS / MG s=1,024 †** (rows m = 2^E; zkA one receipt per batch, zkS one leaf per batch; ratios zkA / zkS)

| m | zkA prove (s) | zkS prove (s) | zkA / zkS | zkA ms/rec | zkS ms/rec | zkA verify (ms) | zkS verify (ms) | zkA / zkS | zkA proof (KB) | zkS proof (KB) | zkA / zkS | zkA peak RSS (GB) | zkS peak RSS (GB) | zkA / zkS | zkS variant |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2^6 = 64 | 22.46 | 2.78 | 8.1x | 350.98 | 43.42 | 11.5 | 25.5 1st | 0.45x 1st | 224.8 | 851.5 | 0.26x | 4.59 | 1.48 | 3.1x | ss_certified |
| 2^7 = 128 | 40.80 | 2.49 | 16x | 318.77 | 19.47 | 11.5 | 25.6 1st | 0.45x 1st | 224.8 | 851.0 | 0.26x | 9.15 | 1.47 | 6.2x | ss_certified |
| 2^8 = 256 | 84.44 | 2.76 | 31x | 329.86 | 10.77 | 11.5 | 26.7 1st | 0.43x 1st | 224.8 | 888.0 | 0.25x | 9.16 | 1.71 | 5.4x | ss_certified |
| 2^9 = 512 | 173.9 | 2.59 | 67x | 339.68 | 5.06 | 11.5 | 23.7 1st | 0.48x 1st | 224.8 | 888.1 | 0.25x | 9.16 | 1.88 | 4.9x | ss_certified |
| 2^10 = 1,024 | 309.6 | 4.33 | 72x | 302.38 | 4.23 | 11.5 | 25.6 1st | 0.45x 1st | 224.8 | 867.9 | 0.26x | 9.16 | 3.33 | 2.8x | ss_certified |
| 2^11 = 2,048 | 613.7 | 4.87 | 126x | 299.64 | 2.38 | 11.5 | 25.4 1st | 0.45x 1st | 224.8 | 939.9 | 0.24x | 9.18 | 3.71 | 2.5x | ss_certified |
| 2^12 = 4,096 | 1,150.0 | 8.51 | 135x | 280.77 | 2.08 | 11.5 | 27.6 1st | 0.42x 1st | 224.8 | 920.0 | 0.24x | 9.18 | 6.73 | 1.4x | ss_certified |
| 2^13 = 8,192 | 2,265.9 | 16.56 | 137x | 276.60 | 2.02 | 11.5 | 27.9 1st | 0.41x 1st | 224.8 | 940.8 | 0.24x | 9.22 | 13.32 | 0.69x | ss_certified |
| 2^14 = 16,384 | 4,452.3 | 31.13 | 143x | 271.75 | 1.90 | 11.5 | 29.7 1st | 0.38x 1st | 224.8 | 992.7 | 0.23x | 9.21 | 26.55 | 0.35x | ss_certified |

**GK eps=1/51 †** (rows m = 2^E; zkA one receipt per batch, zkS one leaf per batch; ratios zkA / zkS)

| m | zkA prove (s) | zkS prove (s) | zkA / zkS | zkA ms/rec | zkS ms/rec | zkA verify (ms) | zkS verify (ms) | zkA / zkS | zkA proof (KB) | zkS proof (KB) | zkA / zkS | zkA peak RSS (GB) | zkS peak RSS (GB) | zkA / zkS | zkS variant |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2^6 = 64 | 408.1 | 11.81 | 35x | 6,377.09 | 184.51 | 11.6 | 28.6 1st | 0.41x 1st | 225.1 | 967.7 | 0.23x | 9.16 | 8.26 | 1.1x | gk_bandmerge2_stable |
| 2^7 = 128 | 441.7 | 11.33 | 39x | 3,450.45 | 88.51 | 11.6 | 28.3 1st | 0.41x 1st | 225.1 | 968.3 | 0.23x | 9.16 | 8.28 | 1.1x | gk_bandmerge2_stable |
| 2^8 = 256 | 484.8 | 10.81 | 45x | 1,893.78 | 42.21 | 11.5 | 28.1 1st | 0.41x 1st | 225.1 | 968.0 | 0.23x | 9.16 | 8.31 | 1.1x | gk_bandmerge2_stable |
| 2^9 = 512 | 618.5 | 12.36 | 50x | 1,207.92 | 24.14 | 11.4 | 27.4 1st | 0.42x 1st | 225.1 | 931.0 | 0.24x | 9.17 | 9.29 | 0.99x | gk_bandmerge2_stable |
| 2^10 = 1,024 | 838.2 | 19.00 | 44x | 818.60 | 18.56 | 11.5 | 28.2 1st | 0.41x 1st | 225.1 | 943.4 | 0.24x | 9.17 | 14.89 | 0.62x | gk_bandmerge2_stable |
| 2^11 = 2,048 | 1,290.6 | 17.81 | 72x | 630.19 | 8.70 | 11.6 | 24.8 1st | 0.47x 1st | 225.1 | 943.9 | 0.24x | 9.18 | 15.06 | 0.61x | gk_bandmerge2_stable |
| 2^12 = 4,096 | 2,375.6 | 35.84 | 66x | 579.97 | 8.75 | 11.6 | 28.6 1st | 0.40x 1st | 225.1 | 993.7 | 0.23x | 9.19 | 29.80 | 0.31x | gk_bandmerge2_stable |
| 2^13 = 8,192 | 4,654.2 | 47.60 | 98x | 568.14 | 5.81 | 11.5 | 30.8 1st | 0.37x 1st | 225.1 | 1,036.4 | 0.22x | 9.22 | 36.92 | 0.25x | gk_bandmerge2_stable |
| 2^14 = 16,384 | 9,397.3 | 92.51 | 102x | 573.57 | 5.65 | 9.7 | 30.4 1st | 0.32x 1st | 225.1 | 1,063.3 | 0.21x | 9.27 | 73.58 | 0.13x | gk_bandmerge2_stable |

**Bloom 7x2^14 †** (rows m = 2^E; zkA one receipt per batch, zkS one leaf per batch; ratios zkA / zkS)

| m | zkA prove (s) | zkS prove (s) | zkA / zkS | zkA ms/rec | zkS ms/rec | zkA verify (ms) | zkS verify (ms) | zkA / zkS | zkA proof (KB) | zkS proof (KB) | zkA / zkS | zkA peak RSS (GB) | zkS peak RSS (GB) | zkA / zkS | zkS variant |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2^6 = 64 | 22.32 | 1.77 | 13x | 348.83 | 27.63 | 11.5 | 21.3 1st | 0.54x 1st | 224.8 | 765.3 | 0.29x | 4.58 | 1.05 | 4.3x | bloom_packed |
| 2^7 = 128 | 40.46 | 2.70 | 15x | 316.08 | 21.07 | 11.5 | 21.6 1st | 0.53x 1st | 224.8 | 817.1 | 0.28x | 9.14 | 1.38 | 6.6x | bloom_packed |
| 2^8 = 256 | 85.14 | 3.03 | 28x | 332.59 | 11.83 | 11.1 | 21.4 1st | 0.52x 1st | 224.8 | 814.8 | 0.28x | 9.16 | 1.89 | 4.8x | bloom_packed |
| 2^9 = 512 | 128.7 | 3.31 | 39x | 251.28 | 6.46 | 11.4 | 23.6 1st | 0.49x 1st | 224.8 | 782.5 | 0.29x | 9.17 | 2.10 | 4.4x | bloom_packed |
| 2^10 = 1,024 | 261.3 | 6.39 | 41x | 255.18 | 6.24 | 11.7 | 26.3 1st | 0.44x 1st | 224.8 | 862.2 | 0.26x | 9.17 | 4.22 | 2.2x | bloom_packed |
| 2^11 = 2,048 | 515.6 | 10.73 | 48x | 251.77 | 5.24 | 11.6 | 23.4 1st | 0.50x 1st | 224.8 | 848.6 | 0.26x | 9.17 | 8.07 | 1.1x | bloom_packed |
| 2^12 = 4,096 | 1,018.6 | 19.35 | 53x | 248.68 | 4.72 | 11.5 | 25.2 1st | 0.46x 1st | 224.8 | 942.7 | 0.24x | 9.17 | 14.51 | 0.63x | bloom_packed |
| 2^13 = 8,192 | 2,016.7 | 34.54 | 58x | 246.18 | 4.22 | 11.5 | 28.4 1st | 0.40x 1st | 224.8 | 995.5 | 0.23x | 9.22 | 28.90 | 0.32x | bloom_packed |
| 2^14 = 16,384 | 4,015.5 | 69.68 | 58x | 245.09 | 4.25 | 11.4 | 29.2 1st | 0.39x 1st | 224.8 | 1,013.7 | 0.22x | 9.22 | 59.54 | 0.15x | bloom_omc (omc) |

_(omc): the bit-array Bloom leaf (one field element per filter bit, `bloom_omc`), run because the packed-byte leaf (`bloom_packed`, 16-bit timestamps) needs 7 x m < 2^16; both prove the same filter and give the same answers, their leaf / decode / merge / root VKs differ. Rows of the two variants are not one circuit's scaling curve._

**KMV k=1,024 †** (rows m = 2^E; zkA one receipt per batch, zkS one leaf per batch; ratios zkA / zkS)

| m | zkA prove (s) | zkS prove (s) | zkA / zkS | zkA ms/rec | zkS ms/rec | zkA verify (ms) | zkS verify (ms) | zkA / zkS | zkA proof (KB) | zkS proof (KB) | zkA / zkS | zkA peak RSS (GB) | zkS peak RSS (GB) | zkA / zkS | zkS variant |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2^6 = 64 | 22.31 | 0.893 | 25x | 348.55 | 13.95 | 11.5 | 23.5 1st | 0.49x 1st | 224.8 | 789.4 | 0.28x | 4.59 | 0.49 | 9.3x | kmv |
| 2^7 = 128 | 40.27 | 1.38 | 29x | 314.63 | 10.75 | 11.5 | 25.0 1st | 0.46x 1st | 224.8 | 838.6 | 0.27x | 9.15 | 0.79 | 12x | kmv |
| 2^8 = 256 | 66.53 | 1.29 | 52x | 259.88 | 5.04 | 11.5 | 23.3 1st | 0.49x 1st | 224.8 | 865.4 | 0.26x | 9.16 | 0.88 | 10x | kmv |
| 2^9 = 512 | 129.0 | 1.77 | 73x | 251.93 | 3.46 | 11.8 | 24.0 1st | 0.49x 1st | 224.8 | 803.8 | 0.28x | 9.16 | 1.07 | 8.6x | kmv |
| 2^10 = 1,024 | 261.2 | 2.67 | 98x | 255.11 | 2.61 | 11.8 | 25.8 1st | 0.46x 1st | 224.8 | 882.0 | 0.25x | 9.17 | 1.55 | 5.9x | kmv |
| 2^11 = 2,048 | 510.7 | 2.83 | 181x | 249.35 | 1.38 | 11.7 | 22.7 1st | 0.52x 1st | 224.8 | 851.0 | 0.26x | 9.18 | 2.04 | 4.5x | kmv |
| 2^12 = 4,096 | 1,002.3 | 6.05 | 166x | 244.71 | 1.48 | 9.7 | 24.1 1st | 0.40x 1st | 224.8 | 900.8 | 0.25x | 9.18 | 4.08 | 2.3x | kmv |
| 2^13 = 8,192 | 1,978.5 | 10.45 | 189x | 241.52 | 1.28 | 11.5 | 27.5 1st | 0.42x 1st | 224.8 | 921.9 | 0.24x | 9.20 | 8.16 | 1.1x | kmv |
| 2^14 = 16,384 | 3,883.3 | 18.78 | 207x | 237.02 | 1.15 | 11.5 | 29.8 1st | 0.39x 1st | 224.8 | 1,017.0 | 0.22x | 9.20 | 14.83 | 0.62x | kmv |

