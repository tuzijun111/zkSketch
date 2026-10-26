# Query rate: one query every Q stream positions, zkSketch measured, zk-Analytics modeled

_Run: N = 131,072 stream positions (AOL keys), a query every Q positions for Q = 1,000, 10,000, 100,000 plus the query-free baseline Q = 0; zkSketch cores 32; zero-knowledge on both sides (zkSketch rows: pcs=hiding, logup_mask=on, commit=hiding; zk-Analytics RISC Zero succinct receipts); zkSketch leaves: CM / HLL / Bloom 1024, SS / KMV 4096, GK 512 (capacity 768); zkSketch bf5d8bcf1, zk-Analytics d4a5a9a; 2026-10-23T23:01:06+08:00._

**The zk-Analytics side is a MODEL built from measured parts, not a run.** zk-Analytics answers a query only at an epoch end, by a query proof that merges the n epoch summaries published so far, so a query every Q positions means epochs of Q records and N / Q query proofs whose cost grows with n. Its total for a Q is

    total(Q) = T x A(Q) + a T + b T (T + 1) / 2   seconds,   T = floor(N / Q) queries = epochs, U = N - T updates

with these assumptions: (1) epochs of exactly Q records, every epoch at the cost of epoch 0 at E = Q (A(Q): the real aggregation proof when it was proved, else its executor padded cycles / 2^20 x k, marked estimated); the stream tail after the last query is not proved; (2) the query proof cost is linear in the number n of merged epoch summaries, q(n) = a + b n, fitted by least squares over the measured n of the query executor run (Eq = 4096-record epochs, n up to 64), each valued padded cycles / 2^20 x k, and EXTRAPOLATED beyond the largest measured n (rows say so); the SS and KMV summaries hold min(distinct keys, capacity 1,024) entries, so their q(n) depends on the epoch size and is the one of Eq = 4096-record epochs for every Q (on AOL they are saturated from about 2,048 records on: an Eq at or above that carries over to every Q >= Eq and overstates them slightly at Q < Eq; an Eq below it understates them at larger Q; CM / HLL / Bloom summaries have a fixed size, the GK band-merge state is capacity-bounded and stays small); (3) k = s per 2^20 padded cycles is one rate for every guest, calibrated over all real proofs of this run; (4) both sides on the same 32 cores, ZK on, one proof at a time; (5) the T periods of Q positions hold Q - 1 updates and one query each, charged as an epoch of Q records: the last update of each period is counted in the next epoch (one record per epoch more than the stream carries). zkSketch is measured: its total = the update makespan (the forest over the leaves, incl. the leaves sealed early and padded at each query) + the sum of its query proofs; its queries are proved on the coordinator after the update makespan.

**Calibration.** k = 44.327 s per 2^20 padded cycles over 24 real zk-Analytics proof(s) of this run (zka_epoch_E1000:bloom:aggr:0, zka_epoch_E1000:cm:aggr:0, zka_epoch_E1000:gk:aggr:0, zka_epoch_E1000:hll:aggr:0, zka_epoch_E1000:kmv:aggr:0, zka_epoch_E1000:ss:aggr:0, zka_epoch_E10000:bloom:aggr:0, zka_epoch_E10000:cm:aggr:0, zka_epoch_E10000:gk:aggr:0, zka_epoch_E10000:hll:aggr:0, zka_epoch_E10000:kmv:aggr:0, zka_epoch_E10000:ss:aggr:0, zka_query_E4096_T64:bloom:query:n=1, zka_query_E4096_T64:bloom:query:n=8, zka_query_E4096_T64:cm:query:n=1, zka_query_E4096_T64:cm:query:n=8, zka_query_E4096_T64:gk:query:n=1, zka_query_E4096_T64:gk:query:n=8, zka_query_E4096_T64:hll:query:n=1, zka_query_E4096_T64:hll:query:n=8, zka_query_E4096_T64:kmv:query:n=1, zka_query_E4096_T64:kmv:query:n=8, zka_query_E4096_T64:ss:query:n=1, zka_query_E4096_T64:ss:query:n=8).

**zk-Analytics epoch proof A(E)** (epoch 0 at E records, noroot; estimated = padded cycles / 2^20 x k)

| sketch | E = 1,000 | E = 10,000 | E = 100,000 |
|---|---|---|---|
| Count-Min | 262.2 s (measured; 6.0 x 2^20 cycles) | 2,469.3 s (measured; 56.0 x 2^20 cycles) | 24,468.4 s (estimated; 552.0 x 2^20 cycles) |
| HLL | 243.2 s (measured; 5.5 x 2^20 cycles) | 2,299.2 s (measured; 52.0 x 2^20 cycles) | 22,883.7 s (estimated; 516.2 x 2^20 cycles) |
| SS / MG | 308.9 s (measured; 7.0 x 2^20 cycles) | 2,745.4 s (measured; 62.0 x 2^20 cycles) | 26,917.4 s (estimated; 607.2 x 2^20 cycles) |
| GK | 661.4 s (measured; 15.0 x 2^20 cycles) | 6,638.5 s (measured; 149.5 x 2^20 cycles) | 66,401.5 s (estimated; 1498.0 x 2^20 cycles) |
| Bloom | 259.5 s (measured; 6.0 x 2^20 cycles) | 2,463.7 s (measured; 55.2 x 2^20 cycles) | 24,401.9 s (estimated; 550.5 x 2^20 cycles) |
| KMV | 263.9 s (measured; 6.0 x 2^20 cycles) | 2,402.9 s (measured; 54.0 x 2^20 cycles) | 23,061.0 s (estimated; 520.2 x 2^20 cycles) |

**zk-Analytics query proof q(n)** (n merged epoch summaries; est = executor padded cycles / 2^20 x k; real = the proof at the calibration points, with (est - real) / real)

| sketch | per n: est s [real s, rel. err] | fit q(n) = a + b n (s) | note |
|---|---|---|---|
| Count-Min | n=1: 44.3 [40.6, +9%]; n=2: 88.7; n=4: 155.1; n=8: 310.3 [306.0, +1%]; n=16: 620.6; n=32: 1,219.0; n=64: 2,415.8 | 10.57 + 37.636 n |  |
| HLL | n=1: 22.2 [22.5, -2%]; n=2: 44.3; n=4: 55.4; n=8: 99.7 [102.7, -3%]; n=16: 182.8; n=32: 360.2; n=64: 709.2 | 13.82 + 10.843 n |  |
| SS / MG | n=1: 232.7 [234.8, -1%]; n=2: 487.6; n=4: 1,019.5; n=8: 2,105.5 [2106.8, -0%]; n=16: 4,349.6; n=32: 8,887.5; n=64: 18,041.0 | -117.47 + 283.037 n |  |
| GK | n=1: 11.1 [13.4, -17%]; n=2: 11.1; n=4: 11.1; n=8: 22.2 [22.3, -0%]; n=16: 22.2; n=32: 44.3; n=64: 88.7 | 7.77 + 1.230 n |  |
| Bloom | n=1: 11.1 [13.8, -20%]; n=2: 22.2; n=4: 22.2; n=8: 44.3 [41.4, +7%]; n=16: 88.7; n=32: 177.3; n=64: 332.5 | 6.62 + 5.132 n |  |
| KMV | n=1: 11.1 [13.4, -17%]; n=2: 22.2; n=4: 44.3; n=8: 66.5 [67.1, -1%]; n=16: 133.0; n=32: 266.0; n=64: 493.1 | 9.14 + 7.655 n |  |

**Q = 0, the query-free baseline (zkSketch only)**

| sketch | leaf | leaves | update makespan (s) | ms per update record | status |
|---|---|---|---|---|---|
| Count-Min | 1024 | 128 | 1,240.5 | 9.46 | ok |
| HLL | 1024 | 128 | 1,253.7 | 9.57 | ok |
| SS / MG | 4096 | 32 | 419.0 | 3.20 | ok |
| GK | 512 | 256 | 2,739.5 | 20.90 | ok |
| Bloom | 1024 | 128 | 1,278.0 | 9.75 | ok |
| KMV | 4096 | 32 | 342.1 | 2.61 | ok |

**Q = 1,000: T = 131 queries / epochs, U = 130,941 updates** (zkA = zk-Analytics, modeled; zkS = zkSketch, measured; ratio = zkA / zkS, above 1 zkSketch is faster; zkS pad fraction = padded record slots / proved record slots; x Q=0 = zkS total over the baseline makespan; SS / KMV q(n) is the one of 4,096-record epochs: conservative for zkA)

| sketch | zkA epochs T | A(Q) (s) | q(n) = a + b n (s) [measured n] | zkA queries (s) | zkA total (h) | zkA ms/update | zkS update makespan (s) | zkS queries (s) | zkS total (s) | zkS ms/update | zkS leaves (padded) | zkS pad fraction | x Q=0 | zkA / zkS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Count-Min | 131 | 262.2 | 10.6 + 37.64 n [1,2,4,8,16,32,64] | 326,786 | 100.32 extrap. | 2,758.0 | 1,299.8 | 34.7 | 1,334.5 | 10.19 | 132 (132) | 0.031 | 1.08 | 271x |
| HLL | 131 | 243.2 | 13.8 + 10.84 n [1,2,4,8,16,32,64] | 95,563 | 35.39 extrap. | 973.1 | 1,303.3 | 1,067.0 | 2,370.3 | 18.10 | 132 (132) | 0.031 | 1.89 | 54x |
| SS / MG | 131 | 308.9 | -117.5 + 283.04 n [1,2,4,8,16,32,64] | 2,431,752 | 686.73 extrap. | 18,880.4 | 1,778.7 | 66.0 | 1,844.7 | 14.09 | 132 (132) | 0.758 | 4.40 | 1,340x |
| GK | 131 | 661.4 | 7.8 + 1.23 n [1,2,4,8,16,32,64] | 11,649 | 27.30 extrap. | 750.6 | 2,820.9 | 120.4 | 2,941.3 | 22.46 | 263 (132) | 0.028 | 1.07 | 33x |
| Bloom | 131 | 259.5 | 6.6 + 5.13 n [1,2,4,8,16,32,64] | 45,240 | 22.01 extrap. | 605.2 | 1,347.9 | 65.8 | 1,413.8 | 10.80 | 132 (132) | 0.031 | 1.11 | 56x |
| KMV | 131 | 263.9 | 9.1 + 7.65 n [1,2,4,8,16,32,64] | 67,381 | 28.32 extrap. | 778.6 | 1,424.3 | 64.3 | 1,488.6 | 11.37 | 132 (132) | 0.758 | 4.35 | 68x |

**Q = 10,000: T = 13 queries / epochs, U = 131,059 updates** (zkA = zk-Analytics, modeled; zkS = zkSketch, measured; ratio = zkA / zkS, above 1 zkSketch is faster; zkS pad fraction = padded record slots / proved record slots; x Q=0 = zkS total over the baseline makespan; SS / KMV q(n) is the one of 4,096-record epochs: saturated summaries, carries over)

| sketch | zkA epochs T | A(Q) (s) | q(n) = a + b n (s) [measured n] | zkA queries (s) | zkA total (h) | zkA ms/update | zkS update makespan (s) | zkS queries (s) | zkS total (s) | zkS ms/update | zkS leaves (padded) | zkS pad fraction | x Q=0 | zkA / zkS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Count-Min | 13 | 2,469.3 | 10.6 + 37.64 n [1,2,4,8,16,32,64] | 3,562 | 9.91 | 272.1 | 1,309.3 | 3.7 | 1,313.0 | 10.02 | 132 (14) | 0.030 | 1.06 | 27x |
| HLL | 13 | 2,299.2 | 13.8 + 10.84 n [1,2,4,8,16,32,64] | 1,166 | 8.63 | 237.0 | 1,304.4 | 101.1 | 1,405.5 | 10.72 | 132 (14) | 0.030 | 1.12 | 22x |
| SS / MG | 13 | 2,745.4 | -117.5 + 283.04 n [1,2,4,8,16,32,64] | 24,229 | 16.64 | 457.2 | 530.9 | 6.2 | 537.2 | 4.10 | 40 (14) | 0.200 | 1.28 | 112x |
| GK | 13 | 6,638.5 | 7.8 + 1.23 n [1,2,4,8,16,32,64] | 213 | 24.03 | 660.1 | 2,841.2 | 12.3 | 2,853.5 | 21.77 | 263 (14) | 0.027 | 1.04 | 30x |
| Bloom | 13 | 2,463.7 | 6.6 + 5.13 n [1,2,4,8,16,32,64] | 553 | 9.05 | 248.6 | 1,317.2 | 6.3 | 1,323.5 | 10.10 | 132 (14) | 0.030 | 1.04 | 25x |
| KMV | 13 | 2,402.9 | 9.1 + 7.65 n [1,2,4,8,16,32,64] | 815 | 8.90 | 244.6 | 429.3 | 6.5 | 435.8 | 3.33 | 40 (14) | 0.200 | 1.27 | 74x |

**Q = 100,000: T = 1 queries / epochs, U = 131,071 updates** (zkA = zk-Analytics, modeled; zkS = zkSketch, measured; ratio = zkA / zkS, above 1 zkSketch is faster; zkS pad fraction = padded record slots / proved record slots; x Q=0 = zkS total over the baseline makespan; SS / KMV q(n) is the one of 4,096-record epochs: saturated summaries, carries over)

| sketch | zkA epochs T | A(Q) (s) | q(n) = a + b n (s) [measured n] | zkA queries (s) | zkA total (h) | zkA ms/update | zkS update makespan (s) | zkS queries (s) | zkS total (s) | zkS ms/update | zkS leaves (padded) | zkS pad fraction | x Q=0 | zkA / zkS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Count-Min | 1 | 24,468.4 est | 10.6 + 37.64 n [1,2,4,8,16,32,64] | 48 | 6.81 | 187.0 | 1,276.7 | 0.3 | 1,277.0 | 9.74 | 129 (2) | 0.008 | 1.03 | 19x |
| HLL | 1 | 22,883.7 est | 13.8 + 10.84 n [1,2,4,8,16,32,64] | 25 | 6.36 | 174.8 | 1,280.7 | 8.3 | 1,289.1 | 9.83 | 129 (2) | 0.008 | 1.03 | 18x |
| SS / MG | 1 | 26,917.4 est | -117.5 + 283.04 n [1,2,4,8,16,32,64] | 166 | 7.52 | 206.6 | 436.3 | 0.5 | 436.7 | 3.33 | 33 (2) | 0.030 | 1.04 | 62x |
| GK | 1 | 66,401.5 est | 7.8 + 1.23 n [1,2,4,8,16,32,64] | 9 | 18.45 | 506.7 | 2,775.8 | 1.1 | 2,776.9 | 21.19 | 257 (2) | 0.004 | 1.01 | 24x |
| Bloom | 1 | 24,401.9 est | 6.6 + 5.13 n [1,2,4,8,16,32,64] | 12 | 6.78 | 186.3 | 1,321.5 | 0.5 | 1,322.0 | 10.09 | 129 (2) | 0.008 | 1.03 | 18x |
| KMV | 1 | 23,061.0 est | 9.1 + 7.65 n [1,2,4,8,16,32,64] | 17 | 6.41 | 176.1 | 354.4 | 0.5 | 354.8 | 2.71 | 33 (2) | 0.030 | 1.04 | 65x |

_Columns and provenance per row: queryrate.csv._
