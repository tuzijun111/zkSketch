# Misra-Gries on the zk-Analytics pipeline (our port, †)

The zk-Analytics side of the six-sketch comparison for the heavy-hitter sketch
(family `ss` in the harness, Misra-Gries in the paper). zk-Analytics (Zhu et al.,
"Zero-Knowledge Cloud Analytics", SIGCOMM '26; RISC Zero zkVM; code `d4a5a9a`)
does not ship a heavy-hitter summary. **This is our instantiation of their
per-epoch-aggregation / query-time-merge pipeline with our own RISC Zero guests.
It is not zk-Analytics code.**

It is a copy of `../spacesaving/` (textbook SpaceSaving in the same pipeline,
kept unchanged as a separate baseline) with only the summary swapped:

| step | where it comes from |
|---|---|
| verify each data source's SHA-256 batch hash chain | their `verify_and_compute_chain`, copied verbatim |
| flatten batches into events, rebuild the epoch summary from scratch | their pattern |
| **Misra-Gries update per record** | **ours**: textbook (increment; else take a free counter; else decrement every counter and drop the zeros), plain Rust |
| canonical state (entries `(key, count)` sorted by `key_id`), unsalted SHA-256 state commitment | their pattern |
| Merkle root over 64 hash buckets of entries (`designed`; `noroot` omits it) | their samples pattern |
| epoch hash chain link | their `EpochChainLink` |
| query: re-verify epoch links, recompute each epoch's state commitment | their `verify_epoch_chain_integrity`, copied verbatim; their pattern |
| **top-k: the mergeable Misra-Gries merge** (sum equal keys, subtract the (s+1)-th largest sum, keep the positive counters; Agarwal et al., PODS 2012) | **ours**, written the way their `SumTopk` merges |
| point frequency: one scan over every epoch's entries, one sum | their `SumExactKey` loop |
| low-support suppression | their rule (`MIN_SUPPORT`) |

Misra-Gries keeps no error term, so an entry is `(key, count)`; for every key
`count <= f <= count + d`, with `d = (N - sum of counts) / (s + 1)` the number of
decrement steps (of the merged summary, `(N - C) / (s + 1)`).

`../ss_mg/` is a different baseline: zkSketch's own batch rule as a standalone
guest outside their pipeline.

## Layout

| path | what |
|---|---|
| `core/` | `mg-core` (no_std, shared by the guests and the host): the summary, epoch state, commitment, roots, aggregation, merge and query |
| `methods/` | the RISC Zero methods crate: `aggr_mg`, `query_mg` (measured guests), `aggr_mg_prof`, `query_mg_prof` (profiling twins), `aggr_mg_rootvar` (run-time root choice: the six-sketch `designed` / `noroot` rows) |
| `src/bin/mg.rs` | host driver, same flags and CSV header as `../spacesaving/src/bin/ss.rs` |
| `src/reference.rs` | independent references and unit tests (BTreeMap Misra-Gries, BTreeMap merge, binary-search point query, guarantee checks) |
| `common_mg.sh` | build helper used by `../six/build.sh` |

## Build and run

`../six/run_all.sh build` builds it into `~/ext-baselines/build/zka-mg`. Its unit
tests: `cargo test --release` in this directory (needs the `../.zka` link that
`../common.sh` creates). The six-sketch runs (`../six/run_all.sh memmatch |
sweep | queryrate`) call `release/mg` for family `ss`.

The paper's published zk-Analytics heavy-hitter numbers (Table 2, the batch-size
figure, Table 6) were measured with `../spacesaving/` before this port existed;
re-running those modes measures this port.
