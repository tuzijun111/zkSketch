//! E1 — circuit-cost runner for the **plonky3 (STARK)** backend (EVAL_SPEC E1/§1).
//!
//! Benches each certified family leaf over a configurable dataset slice with
//! `1 warm-up + N trials`, capturing the full §1 metric set — witness/prove/
//! verify split (from `recursion::recursive::timing`, recorded inside each
//! `prove_*`), `prove_total` median+p95, proof size, summed trace rows, and
//! **peak RSS** — and appends one row per `(family, m)` to
//! `results/e1_circuit.csv`, plus an `env.json`.
//!
//! **Fair-comparison note:** `witness_gen` = trace generation, `prove` =
//! `prove_all_tables`; the per-call circuit *build* is excluded (amortized),
//! matching plonky2's build-once/prove pattern so the two backends'
//! `prove_total` are comparable (the COMPARISON.md caveat). plonky3's
//! multi-table batch-STARK has no single `num_columns`, so we set it to 1 and
//! report `trace_rows` = Σ padded heights (constraint_count = trace_rows).
//!
//! Run (small slice, default):
//!   cargo run --release --example exp_e1
//! Configure (env): EXP_DATASET=uniform|gaussian|zipf|aol|netflix,
//!   EXP_M=4,8,16,32   EXP_TRIALS=5   EXP_WARMUP=1
//! Whole vs partial dataset: this runner consumes `max(EXP_M)` keys per family
//! (a *small slice* — fine for testing). To exercise the real datasets, fetch
//! them first (`python3 scripts/fetch_datasets.py`) and set EXP_DATASET=aol.
//!
//! Commitments (revision B2): the DEPLOYED variants (cm `omc`, hll `omc`, ss
//! `certified`, gk `bandmerge2`) run under the prover's commitment context,
//! read once (`ProverCommit::from_env`: `ZKSKETCH_COMMIT`, default `hiding`;
//! the salt seed from `ZKSKETCH_SALT_SEED` or the OS RNG, never printed):
//! under `hiding` each is the `*_commit` leaf (9 salt inputs, 3 salted
//! sponges) proved at batch index 1 with `Openings::for_leaf(seed, family,
//! 1)`. Every baseline variant stays `Plain`. Every CSV row records the mode
//! it was proved under in its `commit` column (just before `status`): the
//! run's mode for the deployed variants, `plain` for every baseline (the
//! plonky2 leg writes the same column, always `plain`, so the two CSVs still
//! merge); env.json records `commit_deployed`, `commit_baselines` and
//! `salt_seed` (the seed's source, never the seed).

use zksketch::dataset::{aol, netflix, synthetic_stream, take, zipf_stream, Synthetic};
use zksketch::experiments::metrics::{append_csv, bench, write_env_json, AggRow, BenchCfg, RunOutcome};
use zksketch::experiments::{env_usize, proof_size, results_dir};
use zksketch::recursion::recursive::timing;

use zksketch::commitment::hiding::CommitFamily;
use zksketch::experiments::prover_commit::ProverCommit;
use zksketch::recursion::recursive::statement::Expose;
use zksketch::sketch::bind::default_binding;
use zksketch::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use zksketch::sketch::countmin_final::{generate_proof as cm_prove, CountMinFinalParams};
use zksketch::sketch::countmin_c_merkle::{prove_countmin_c_merkle_leaf, CountMinCMerkleParams};
use zksketch::sketch::countmin_memcheck::{prove_countmin_memcheck, CmMemcheckParams};
use zksketch::sketch::countmin_omc::{build_countmin_omc_leaf_commit, prove_countmin_omc, CmOmcParams};
use zksketch::sketch::hll_merkle::{prove_hll_merkle_leaf, HllMerkleParams};
use zksketch::sketch::hll_omc::{build_hll_omc_leaf_commit, prove_hll_omc, HllOmcParams};
use zksketch::sketch::gk_final_full::{generate_proof as gk_prove, GKFullParams, GKFullState, GKFullUpdate};
use zksketch::sketch::gk_bandmerge::{
    build_gkb2_leaf_commit, generate_proof as gkb_prove, generate_proof2 as gkb2_prove,
    generate_proof2_naive as gkb2n_prove, Gk2State, GkbParams,
};
use zksketch::sketch::greenwald_khanna_naive::generate_proof_naive as gk_naive_prove;
use zksketch::sketch::hll_final_full::{generate_proof as hll_prove, HllFullParams, HllFullUpdate};
use zksketch::sketch::ss_final_full::{
    build_ss_full_leaf_commit, generate_proof as ss_prove, SsFullParams, SsFullState, SsFullUpdate,
};
use zksketch::sketch::spacesaving_naive::generate_proof_naive as ss_naive_prove;

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
fn env_list(key: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(key) {
        Ok(s) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        Err(_) => default.to_vec(),
    }
}

/// Largest GK band-merge accuracy `s = 1/ε` the capacity supports at stream
/// length `n` — the space-accuracy coupling `capacity ≳ s·log2(n/s)`, inverted
/// with a 2× safety factor (using `log2 n ≥ log2(n/s)` so it never fragments).
/// Lets a single `EXP_GK_CAP` set the GK size (matches `exp_compose`). For e1's
/// single-leaf-from-empty benchmark, `n` is the batch size `me` the leaf covers.
fn derive_gk_s(cap: usize, n: usize) -> u64 {
    let logn = (n.max(4) as f64).log2().ceil().max(1.0);
    ((cap as f64 / (2.0 * logn)).floor() as u64).max(2)
}

/// Round a requested batch size up to an even value ≥ 2 (GK/SS/HLL require an
/// even batch). Round the CLAMPED value, else `m=1 → 2+(1%2)=3` (odd → panic).
/// Used for BOTH `me` and `max_m` so enough dataset keys are loaded for the
/// rounded batch (else `slice_e` is short of `batch` and the leaf panics).
fn round_even_batch(m: usize) -> usize {
    let x = m.max(2);
    x + (x % 2)
}

/// `n` keys from the named dataset (synthetic generated; real sliced). `None`
/// when a real dataset hasn't been fetched.
fn keys_for(name: &str, n: usize) -> Option<Vec<u32>> {
    match name {
        "uniform" => Some(synthetic_stream(Synthetic::Uniform, n, 1)),
        "gaussian" => Some(synthetic_stream(Synthetic::Gaussian, n, 1)),
        "zipf" => Some(zipf_stream(1.0, n.max(16), n, 1)),
        "aol" => aol().map(|k| take(&k, n)),
        "netflix" => netflix().map(|k| take(&k, n)),
        _ => None,
    }
}

fn cfg() -> BenchCfg {
    // E1 always runs each config exactly once (no warm-up, one trial) — the CSV
    // reports a single value per metric, not median/p95.
    BenchCfg { warmup: 0, trials: 1 }
}

fn outcome(proof_bytes: u64) -> RunOutcome {
    let t = timing::take();
    RunOutcome {
        witness_gen: t.witness,
        prove: t.prove,
        verify: t.verify,
        proof_size_bytes: proof_bytes,
        trace_rows: t.trace_rows,
        num_columns: 1, // batch-STARK has no single column count; see module note
    }
}

/// Run `bench`, but catch a *capacity* panic so an over-large sweep point is
/// recorded as `too_large` and the run continues — to the next `m` and to the
/// plonky2 leg — instead of aborting the whole process. The panic this guards
/// is BabyBear's `bits <= TWO_ADICITY` ceiling (the FRI evaluation domain tops
/// out at `2^27` rows) or a circuit's own selector-budget guard; both are hard
/// limits of the plonky3/BabyBear backend, not transient errors. EVAL_SPEC E1:
/// "push as high as compiles; mark OOM/TLE beyond."
fn bench_guarded<R: FnMut() -> RunOutcome>(c: BenchCfg, run: R) -> Option<AggRow> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // silence the expected capacity panic
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bench(c, run)));
    std::panic::set_hook(prev);
    if r.is_err() {
        let _ = timing::take(); // drop any partial trace timing from the aborted prove
    }
    r.ok()
}

// The CSV row builders `row` / `row_skip` are defined as closures inside `main`
// so they can capture this run's `dataset` for the leading `dataset` column.

fn main() {
    // EXP_CORES: pin the STARK prover to a fixed number of cores — the
    // "cores-per-proof" knob for the distributed-setting study (one proof per
    // machine of `c` cores). Set ONCE here as the global rayon pool, so every
    // proof in this process uses exactly `c` cores. Unset ⇒ default pool (all
    // cores) and NO `cores` CSV column (schema unchanged / both-backends safe).
    let cores_override: Option<usize> =
        std::env::var("EXP_CORES").ok().and_then(|s| s.trim().parse().ok()).filter(|&c| c >= 1);
    if let Some(c) = cores_override {
        rayon::ThreadPoolBuilder::new()
            .num_threads(c)
            .build_global()
            .expect("EXP_CORES: set global rayon pool");
    }
    let include_cores = cores_override.is_some();
    let cores_used = cores_override.unwrap_or_else(rayon::current_num_threads);
    // The PROVER's commitment context for the deployed variants, read once
    // (the seed is never printed). Baselines stay Plain.
    let commit = ProverCommit::from_env();

    let dataset_arg = env_str("EXP_DATASET", "uniform");
    // EXP_DATASET may be a comma-list of datasets — sweep each in turn.
    let datasets: Vec<String> =
        dataset_arg.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let ms = env_list("EXP_M", &[4, 8, 16, 32]);
    // Load enough keys for the ROUNDED batch (`me`), not the raw `m`, so
    // `slice_e = take(keys, me)` is never short of `batch` (e.g. EXP_M=1 → me=2).
    let max_m = ms.iter().map(|&m| round_even_batch(m)).max().unwrap_or(32);
    // EXP_FAMILY filters which families run: "all" (default) or a comma-list of
    // cm|gk|hll|ss (e.g. EXP_FAMILY=cm runs only Count-Min, both variants).
    let family_sel = env_str("EXP_FAMILY", "all");
    let want = |f: &str| family_sel == "all" || family_sel.split(',').any(|x| x.trim() == f);
    println!(
        "E1 (plonky3 STARK) — datasets={datasets:?}  m={ms:?}  family={family_sel}  cores={cores_used}  trials={}  commit(deployed)={} salt_seed={}",
        cfg().trials,
        commit.label(),
        commit.seed_label()
    );

    let dir = results_dir();
    write_env_json(
        &dir,
        &[
            ("backend", "plonky3".into()),
            ("field", "BabyBear".into()),
            ("hash", "Poseidon2".into()),
            ("ext_degree_D", "4".into()),
            ("dataset", dataset_arg.clone()),
            ("cores", cores_used.to_string()),
            // Deployed variants (cm/hll omc, ss certified, gk bandmerge2) run
            // under the run's commitment mode; baselines are always plain.
            ("commit_deployed", commit.label().into()),
            ("commit_baselines", "plain".into()),
            ("salt_seed", commit.seed_label().into()),
        ],
    );
    let hdr: Vec<String> = {
        let mut cols: Vec<&str> = vec!["backend", "dataset", "family", "variant", "m", "d", "w", "s"];
        // The `cores` column appears only when EXP_CORES is set (keeps the default
        // schema and the both-backends merge untouched).
        if include_cores {
            cols.push("cores");
        }
        let mut h: Vec<String> = cols.iter().map(|s| s.to_string()).collect();
        h.extend(AggRow::header().iter().map(|s| s.to_string()));
        // Per-row provenance of the commitment mode (revision B2).
        h.push("commit".into());
        h.push("status".into());
        h
    };
    // The mode a row was proved under: the run's context for the DEPLOYED
    // variants (the only ones with a hiding circuit here), `plain` for every
    // baseline.
    let commit_of = |family: &str, variant: &str| -> &'static str {
        match (family, variant) {
            ("cm", "omc") | ("hll", "omc") | ("ss", "certified") | ("gk", "bandmerge2") => commit.label(),
            _ => "plain",
        }
    };

    let c = cfg();
    // Count-Min width-sweep knobs (used when EXP_FAMILY includes cm):
    //   EXP_D            depth d                      (default 4, must be 1..=8)
    //   EXP_W            comma-list of widths w        (default 8; powers of two)
    //   EXP_CM_VARIANT   one_hot | merkle | merkle_fast | merkle_gb | memcheck |
    //                    omc | comma-list (default one_hot). All share the
    //                    per-record hash + counter-sort + group-by front half; they
    //                    differ only in the Step-5 rebind:
    //                      one_hot  = flat commit, one-hot sparse patch over all
    //                                 d·w cells (cost Θ(n_ctr·d·w), n_ctr=batch·d).
    //                      merkle   = sparse Merkle-commit rebind, opens only the
    //                                 touched cells (Θ(t_max·d·log w), flat in w).
    //                                 Node combiner = padding-free SPONGE (2
    //                                 permutations/node + per-level bit-select ALU).
    //                      merkle_fast = same sparse rebind, node combiner = a
    //                                 single 2:1 Poseidon2 COMPRESSION in Merkle
    //                                 mode (1 permutation/node; the AIR does the
    //                                 swap by the position bit for free, removing
    //                                 the per-level bit-select ALU ops). Same
    //                                 commitment shape as `merkle` (different roots).
    //                      memcheck = offline-memory-checking rebind: commits the
    //                                 sparse patch of touched (addr,total) cells
    //                                 directly, NO dense d·w and NO Merkle path
    //                                 (Θ(batch·d·log(d·w)), independent of w).
    //                                 Builds from the empty state. Its commitment
    //                                 is a sparse-patch digest, not commit_countmin.
    //                      omc      = SOUND offline-memory-checking against a REAL
    //                                 committed prior state: M_old ⊎ W = M_new ⊎ R
    //                                 via one permutation over d·w+n_ctr elements
    //                                 (Θ(d·w)). Reconciles touched old values by
    //                                 multiset membership (no Merkle, no empty-init);
    //                                 replaces one_hot's Θ(batch·d·d·w) selector
    //                                 matrix, so far below one_hot but loses to the
    //                                 sparse rebinds when t_max≪d·w. In a hash-STARK
    //                                 (only multiset EQUALITY, no LogUp inclusion)
    //                                 this OMC circuit IS the faithful realisation of
    //                                 the §5 "lookup table" design — a true
    //                                 LogUp-inclusion lookup would need native lookups
    //                                 (e.g. plonky2). (The former separate `lookup`
    //                                 label was a duplicate of `omc` and is removed.)
    //                    (merkle_gb = merkle_fast + the group-by routing of opt (ii):
    //                                 replaces the m·t_max·d selector with the
    //                                 O(m·d) group-by; wins at large batch m.)
    //                    e.g. EXP_CM_VARIANT=one_hot,merkle,memcheck,omc for a
    //                    rebind head-to-head. (The retired replay/merkle leaves
    //                    remain in the tree but are no longer wired here.)
    // The one_hot circuit guards its selector budget (raise COUNTMIN_MAX_SEL_CELLS
    // if you hit that budget panic). Any CM point that exceeds the plonky3/BabyBear
    // capacity — the selector budget OR the 2^27 FRI-domain ceiling — is caught,
    // logged, and written as status=too_large so the sweep continues.
    let cm_d = env_usize("EXP_D", 4);
    let cm_ws = env_list("EXP_W", &[8]);
    let cm_variant = env_str("EXP_CM_VARIANT", "one_hot");
    // one_hot | merkle | comma-list (the retired replay/merkle leaves are unwired).
    let cm_wants = |v: &str| cm_variant.split(',').any(|x| x.trim() == v);
    for dataset in &datasets {
        let Some(keys) = keys_for(dataset, max_m) else {
            eprintln!("dataset '{dataset}' unavailable (fetch real ones with `python3 scripts/fetch_datasets.py`) — skipping");
            continue;
        };
        // CSV row builders — capture this dataset for the leading `dataset` column.
        let row = |family: &str, variant: &str, m: usize, d: usize, w: usize, s: usize, agg: &AggRow| -> Vec<String> {
            let mut r = vec![
                "plonky3".into(), dataset.clone(), family.into(), variant.into(),
                m.to_string(), d.to_string(), w.to_string(), s.to_string(),
            ];
            if include_cores {
                r.push(cores_used.to_string());
            }
            r.extend(agg.fields());
            r.push(commit_of(family, variant).into());
            r.push("ok".into());
            r
        };
        let row_skip = |family: &str, variant: &str, m: usize, d: usize, w: usize, s: usize, status: &str| -> Vec<String> {
            let mut r = vec![
                "plonky3".into(), dataset.clone(), family.into(), variant.into(),
                m.to_string(), d.to_string(), w.to_string(), s.to_string(),
            ];
            if include_cores {
                r.push(cores_used.to_string());
            }
            r.extend(std::iter::repeat("n/a".to_string()).take(AggRow::header().len()));
            r.push(commit_of(family, variant).into());
            r.push(status.into());
            r
        };
        println!("-- dataset={dataset} --");
        for &m in &ms {
            let slice = take(&keys, m);
            let me = round_even_batch(m);
            let slice_e = take(&keys, me);

            if want("cm") {
                let ups: Vec<CountMinUpdate> =
                    slice.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect();
                for &cm_w in &cm_ws {
                    let s_cells = cm_d * cm_w;
                    // CM `one_hot`: FLAT-commit certified leaf, applying the update via
                    // a one-hot sparse patch over all d·w cells. Cost Θ(n_ctr·d·w).
                    if cm_wants("one_hot") {
                        let p = CountMinFinalParams { d: cm_d, w: cm_w, batch: m };
                        match bench_guarded(c, || { let r = cm_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("cm", "one_hot", m, cm_d, cm_w, s_cells, &agg)); }
                            None => {
                                println!("  cm one_hot m={m} w={cm_w}: SKIPPED — too large (selector budget or BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("cm", "one_hot", m, cm_d, cm_w, s_cells, "too_large"));
                            }
                        }
                    }
                    // CM `merkle`: the SAME per-record certified update with a sparse
                    // Merkle-commit rebind — opens only the touched cells
                    // (Θ(t_max·d·log w), flat in w) instead of the one_hot patch over
                    // all d·w cells. Holding the update fixed, isolates the rebind axis.
                    if cm_wants("merkle") {
                        let t_max = m.min(cm_w);
                        let initial = CountMinState {
                            counters: vec![vec![0u32; cm_w]; cm_d],
                            params: CountMinParams { d: cm_d, w: cm_w },
                        };
                        let cp = CountMinCMerkleParams {
                            d: cm_d, w: cm_w, batch: m, t_max, compress: false, group_by: false,
                        };
                        match bench_guarded(c, || {
                            let r = prove_countmin_c_merkle_leaf(cp, initial.clone(), ups.clone());
                            outcome(r.proof_size() as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("cm", "merkle", m, cm_d, cm_w, s_cells, &agg)); }
                            None => {
                                println!("  cm merkle m={m} w={cm_w} t_max={t_max}: SKIPPED — too large (exceeds BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("cm", "merkle", m, cm_d, cm_w, s_cells, "too_large"));
                            }
                        }
                    }
                    // CM `merkle_fast`: the SAME sparse-rebind leaf, but the
                    // per-level Merkle combiner is a single 2:1 Poseidon2
                    // compression in Merkle mode (compress: true) instead of the
                    // padding-free sponge. The AIR does the rate↔capacity swap by
                    // the position bit for free, so the per-level bit-select ALU
                    // ops are removed AND each node costs 1 permutation, not 2.
                    // Same routing, op chain, and commitment shape as `merkle`;
                    // isolates the node-combiner cost (the ALU-table delta).
                    if cm_wants("merkle_fast") {
                        let t_max = m.min(cm_w);
                        let initial = CountMinState {
                            counters: vec![vec![0u32; cm_w]; cm_d],
                            params: CountMinParams { d: cm_d, w: cm_w },
                        };
                        let cp = CountMinCMerkleParams {
                            d: cm_d, w: cm_w, batch: m, t_max, compress: true, group_by: false,
                        };
                        match bench_guarded(c, || {
                            let r = prove_countmin_c_merkle_leaf(cp, initial.clone(), ups.clone());
                            outcome(r.proof_size() as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("cm", "merkle_fast", m, cm_d, cm_w, s_cells, &agg)); }
                            None => {
                                println!("  cm merkle_fast m={m} w={cm_w} t_max={t_max}: SKIPPED — too large (exceeds BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("cm", "merkle_fast", m, cm_d, cm_w, s_cells, "too_large"));
                            }
                        }
                    }
                    // CM `merkle_gb` (optimization (ii)): the SAME sparse-rebind
                    // (compress nodes) but the m·t_max·d selector-routing matrix is
                    // replaced by an O(m·d) group-by-counter feeding a SINGLE GLOBAL
                    // sorted Merkle op-chain. Each row contributes exactly m sorted
                    // entries, so the d blocks occupy fixed positions and the per-row
                    // root chain threads through compile-time block boundaries. Same
                    // final roots as merkle_fast (same MyCompress nodes); isolates the
                    // ROUTING cost — its ALU table grows ~linearly in m, not m².
                    if cm_wants("merkle_gb") {
                        let t_max = m.min(cm_w);
                        let initial = CountMinState {
                            counters: vec![vec![0u32; cm_w]; cm_d],
                            params: CountMinParams { d: cm_d, w: cm_w },
                        };
                        let cp = CountMinCMerkleParams {
                            d: cm_d, w: cm_w, batch: m, t_max, compress: true, group_by: true,
                        };
                        match bench_guarded(c, || {
                            let r = prove_countmin_c_merkle_leaf(cp, initial.clone(), ups.clone());
                            outcome(r.proof_size() as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("cm", "merkle_gb", m, cm_d, cm_w, s_cells, &agg)); }
                            None => {
                                println!("  cm merkle_gb m={m} w={cm_w} t_max={t_max}: SKIPPED — too large (exceeds BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("cm", "merkle_gb", m, cm_d, cm_w, s_cells, "too_large"));
                            }
                        }
                    }
                    // CM `memcheck`: offline-memory-checking rebind — commits the
                    // SPARSE patch of touched (addr,total) cells directly (no dense
                    // d·w materialisation, no Merkle path). Cost is independent of w
                    // in the dominant term, so it proves wide sketches that one_hot
                    // (selector budget) and merkle (log-w paths) struggle with.
                    // Builds from the empty state (the regime where omitting
                    // untouched cells is sound — see countmin_memcheck module docs).
                    if cm_wants("memcheck") {
                        let p = CmMemcheckParams { d: cm_d, w: cm_w, batch: m };
                        match bench_guarded(c, || {
                            let r = prove_countmin_memcheck(p, ups.clone());
                            outcome(r.proof_size() as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("cm", "memcheck", m, cm_d, cm_w, s_cells, &agg)); }
                            None => {
                                println!("  cm memcheck m={m} w={cm_w}: SKIPPED — too large (exceeds BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("cm", "memcheck", m, cm_d, cm_w, s_cells, "too_large"));
                            }
                        }
                    }
                    // CM `omc`: SOUND offline-memory-checking against a REAL committed
                    // prior state — proves M_old ⊎ W = M_new ⊎ R by one permutation over
                    // dw+n_ctr tagged (addr,val) elements. Membership of each touched old
                    // value is forced by the multiset (no Merkle, no empty-init). Cost
                    // Θ(dw): worse than the sparse rebinds when t_max≪dw, but replaces
                    // one_hot's Θ(batch·d·dw) selector matrix with a single dw-length
                    // permute, so it sits far below one_hot.
                    if cm_wants("omc") {
                        let initial = CountMinState {
                            counters: vec![vec![0u32; cm_w]; cm_d],
                            params: CountMinParams { d: cm_d, w: cm_w },
                        };
                        let p = CmOmcParams { d: cm_d, w: cm_w, batch: m };
                        match bench_guarded(c, || {
                            let r = if commit.is_hiding() {
                                build_countmin_omc_leaf_commit(p, Expose::None, default_binding(), commit.mode())
                                    .prove_epoch_commit(1, initial.clone(), ups.clone(), &commit.openings(CommitFamily::CountMin, 1))
                            } else {
                                prove_countmin_omc(p, initial.clone(), ups.clone())
                            };
                            outcome(r.proof_size() as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("cm", "omc", m, cm_d, cm_w, s_cells, &agg)); }
                            None => {
                                println!("  cm omc m={m} w={cm_w}: SKIPPED — too large (exceeds BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("cm", "omc", m, cm_d, cm_w, s_cells, "too_large"));
                            }
                        }
                    }
                    // (The former `lookup` label was a duplicate of `omc` — in a
                    // hash-STARK the §5 lookup-table design IS the M_old⊎W=M_new⊎R
                    // OMC circuit, so it is now exposed only under the `omc` name.)
                }
            }

            if want("gk") {
                // GK quantile summary — size = capacity (the tuple budget).
                //   EXP_GK_CAP      comma-list of capacities  (default 8; even ≥2)
                //   EXP_GK_VARIANT  certified|naive|bandmerge|bandmerge2|both|comma-list (default certified).
                //     bandmerge = one-sided (§3 toy) real GK; bandmerge2 = two-sided (§4 optimal, mirrored).
                //   EXP_GK_S        band-merge accuracy s=1/ε (θ_t=⌊N_t/s⌋). DERIVED
                //                   from (cap, batch) unless set — so EXP_GK_CAP alone
                //                   sets the GK size (mirrors run_compose; a small cap
                //                   with a large explicit s fragments → too_large).
                //   `naive` = per-record oblivious in-circuit replay; `certified` =
                //   the same-value-collapse group-by leaf (exact per-value aggregation,
                //   NO log factor); `bandmerge` = the REAL Greenwald–Khanna distinct-value
                //   quantile band-merge (gk_bandmerge.rs) — L_f=⌈log₂(cap+m)⌉ forced-
                //   decision fusion rounds, so it carries the honest log factor and costs
                //   ~L_f× the `certified`/SS leaf. NOTE: the naive leaf computes a valid
                //   GK summary via insert-then-merge, a COST baseline, not a same-final replay.
                let gk_variant = env_str("EXP_GK_VARIANT", "certified");
                let gk_wants = |v: &str| gk_variant == "both" || gk_variant.split(',').any(|x| x.trim() == v);
                let ups: Vec<GKFullUpdate> = slice_e.iter().map(|&k| GKFullUpdate::real(k & 0x003F_FFFF)).collect();
                for &cap in &env_list("EXP_GK_CAP", &[8]) {
                    let cap = cap.max(2) + (cap % 2);
                    let p = GKFullParams { capacity: cap, batch: me };
                    // Band-merge accuracy: honor EXP_GK_S if set, else derive from
                    // (cap, me) so EXP_GK_CAP alone sets the GK size (matches
                    // run_compose). Shared by the three band-merge variants below.
                    let s_param: u64 = match std::env::var("EXP_GK_S") {
                        Ok(v) => v.trim().parse().unwrap_or_else(|_| derive_gk_s(cap, me)),
                        Err(_) => derive_gk_s(cap, me),
                    };
                    if (gk_wants("bandmerge") || gk_wants("bandmerge2") || gk_wants("bandmerge2_naive"))
                        && std::env::var("EXP_GK_S").is_err()
                    {
                        println!("  gk cap={cap} m={me}: s=1/ε={s_param} (derived from cap)");
                    }
                    if gk_wants("certified") {
                        let agg = bench(c, || { let r = gk_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) });
                        append_csv(&dir, "e1_circuit", &hdr, &row("gk", "certified", me, 0, 0, cap, &agg));
                    }
                    if gk_wants("naive") {
                        let st0 = GKFullState::empty(p);
                        match bench_guarded(c, || { let r = gk_naive_prove(p, st0.clone(), ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("gk", "naive", me, 0, 0, cap, &agg)); }
                            None => {
                                println!("  gk naive m={me} cap={cap}: SKIPPED — too large");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("gk", "naive", me, 0, 0, cap, "too_large"));
                            }
                        }
                    }
                    if gk_wants("bandmerge") {
                        // The REAL Greenwald–Khanna band-merge (distinct-value quantile
                        // compression, gk_bandmerge.rs): L_f=⌈log₂(cap+m)⌉ forced-decision
                        // fusion rounds, so its cost carries the honest log factor (unlike
                        // the same-value-collapse `certified` leaf). Accuracy s=1/ε via
                        // EXP_GK_S (θ_t=⌊N_t/s⌋); values masked to 21 bits (< E_MAX=2^22−1).
                        let bvals: Vec<u32> = slice_e.iter().map(|&k| (k & 0x001F_FFFF) as u32).collect();
                        let gp = GkbParams { capacity: cap, batch: me, s: s_param };
                        match bench_guarded(c, || { let r = gkb_prove(gp, bvals.clone()); outcome(proof_size(&r.proof.output.0) as u64) }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("gk", "bandmerge", me, 0, 0, cap, &agg)); }
                            None => {
                                println!("  gk bandmerge m={me} cap={cap}: SKIPPED — too large / hard case");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("gk", "bandmerge", me, 0, 0, cap, "too_large"));
                            }
                        }
                    }
                    if gk_wants("bandmerge2") {
                        // The TWO-SIDED (optimal) Gribelyuk §4 band-merge: combines GK
                        // with its mirror (Khanna–Greenwald), so it certifies the full
                        // bidirectional fusion and achieves the O(ε⁻¹·log εN) worst-case
                        // size. Six-field tuple (e,g₁,g₂,Δ₁,Δ₂,t) packed two challenges
                        // per row ⇒ ~2× per-tuple width vs `bandmerge`.
                        let bvals: Vec<u32> = slice_e.iter().map(|&k| (k & 0x001F_FFFF) as u32).collect();
                        let gp = GkbParams { capacity: cap, batch: me, s: s_param };
                        match bench_guarded(c, || {
                            let out = if commit.is_hiding() {
                                build_gkb2_leaf_commit(gp, Expose::None, default_binding(), commit.mode())
                                    .prove_epoch_commit(1, Gk2State::empty(gp), bvals.clone(), &commit.openings(CommitFamily::GreenwaldKhanna, 1))
                                    .output
                            } else {
                                gkb2_prove(gp, bvals.clone()).proof.output
                            };
                            outcome(proof_size(&out.0) as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("gk", "bandmerge2", me, 0, 0, cap, &agg)); }
                            None => {
                                println!("  gk bandmerge2 m={me} cap={cap}: SKIPPED — too large");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("gk", "bandmerge2", me, 0, 0, cap, "too_large"));
                            }
                        }
                    }
                    if gk_wants("bandmerge2_naive") {
                        // The REPLAY baseline for `bandmerge2`: the SAME two-sided §4
                        // algorithm, proven by per-record in-circuit replay (thread
                        // S_0→…→S_m, each record a Θ(cap) insert + two-sided compress)
                        // instead of one batch-effect certificate. Cost Θ(m·cap) — the
                        // cost-to-beat for the verification-over-computation story.
                        let bvals: Vec<u32> = slice_e.iter().map(|&k| (k & 0x001F_FFFF) as u32).collect();
                        let gp = GkbParams { capacity: cap, batch: me, s: s_param };
                        match bench_guarded(c, || { let r = gkb2n_prove(gp, bvals.clone()); outcome(proof_size(&r.proof.output.0) as u64) }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("gk", "bandmerge2_naive", me, 0, 0, cap, &agg)); }
                            None => {
                                println!("  gk bandmerge2_naive m={me} cap={cap}: SKIPPED — too large");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("gk", "bandmerge2_naive", me, 0, 0, cap, "too_large"));
                            }
                        }
                    }
                }
            }

            if want("hll") {
                // HLL — flat `one_hot` vs sparse `merkle`, sweeping b (m = 2^b).
                //   EXP_HLL_B        comma-list of b values        (default 4)
                //   EXP_HLL_VARIANT  one_hot|merkle|omc|comma-list (default one_hot)
                // one_hot = flat commit, one-hot register scatter + max (cost
                // O(m·batch)); merkle = the sparse Merkle-commit leaf (cost
                // Θ(t_max·log m), flat in m). e.g. EXP_HLL_VARIANT=one_hot,merkle.
                let hll_bs = env_list("EXP_HLL_B", &[4]);
                let hll_variant = env_str("EXP_HLL_VARIANT", "one_hot");
                let hll_wants = |v: &str| hll_variant.split(',').any(|x| x.trim() == v);
                let keys_e: Vec<u64> = slice_e.iter().map(|&k| k as u64).collect();
                for &hb in &hll_bs {
                    let m_reg = 1usize << hb;
                    if hll_wants("one_hot") {
                        // Flat O(m·batch) circuit (b≤16). It DOES prove at large m
                        // (e.g. b=14/batch=16 ≈ 35 GB, 20 s) — that's the head-to-head
                        // point vs the sparse merkle leaf. A point that exceeds the
                        // HLL_FULL_MAX_SEL_CELLS budget / 2^27 FRI domain panics in
                        // validate()/FRI and is caught here as a `too_large` skip
                        // (same guard the cm legs use), so the sweep never aborts.
                        let p = HllFullParams { b: hb, batch: me };
                        let ups: Vec<HllFullUpdate> = slice_e.iter().map(|&k| HllFullUpdate::real(k as u64)).collect();
                        match bench_guarded(c, || { let r = hll_prove(p, ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("hll", "one_hot", me, 0, 0, m_reg, &agg)); }
                            None => {
                                println!("  hll one_hot m={me} b={hb} (regs={m_reg}): SKIPPED — too large (flat O(m·batch) exceeds HLL_FULL_MAX_SEL_CELLS / BabyBear 2^27 FRI domain). Raise HLL_FULL_MAX_SEL_CELLS or use EXP_HLL_VARIANT=merkle.");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("hll", "one_hot", me, 0, 0, m_reg, "too_large"));
                            }
                        }
                    }
                    if hll_wants("merkle") {
                        // Sparse Merkle-commit leaf (cost Θ(t_max·log m), flat in m;
                        // b∈[1,16]). The only HLL path that scales to large b — but the
                        // per-record routing trace Θ(t_max·batch·log m) can still
                        // overflow BabyBear's 2^27 FRI domain at large batch, so guard
                        // it too (mirrors the cm merkle leg).
                        let t_max = me.min(m_reg);
                        let initial = vec![0u64; m_reg];
                        let mp = HllMerkleParams { b: hb, batch: me, t_max };
                        match bench_guarded(c, || {
                            let r = prove_hll_merkle_leaf(mp, initial.clone(), keys_e.clone());
                            outcome(r.proof_size() as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("hll", "merkle", me, 0, 0, m_reg, &agg)); }
                            None => {
                                println!("  hll merkle m={me} b={hb} t_max={t_max}: SKIPPED — too large (routing t_max·batch·log m exceeds BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("hll", "merkle", me, 0, 0, m_reg, "too_large"));
                            }
                        }
                    }
                    if hll_wants("omc") {
                        // Offline-memory-checking leaf (cost Θ(m + batch), a dense
                        // `M_old ⊎ W = M_new ⊎ R` multiset rebind with a max update).
                        // No sparse t_max bound; the max-update analogue of cm `omc`.
                        // Its `m + batch` multiset trace can overflow BabyBear's 2^27
                        // FRI domain at large m·batch, so guard it (mirrors cm omc).
                        let initial = vec![0u64; m_reg];
                        let op = HllOmcParams { b: hb, batch: me };
                        match bench_guarded(c, || {
                            let r = if commit.is_hiding() {
                                build_hll_omc_leaf_commit(op, Expose::None, default_binding(), commit.mode())
                                    .prove_epoch_commit(1, initial.clone(), keys_e.clone(), &commit.openings(CommitFamily::HyperLogLog, 1))
                            } else {
                                prove_hll_omc(op, initial.clone(), keys_e.clone())
                            };
                            outcome(r.proof_size() as u64)
                        }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("hll", "omc", me, 0, 0, m_reg, &agg)); }
                            None => {
                                println!("  hll omc m={me} b={hb} (regs={m_reg}): SKIPPED — too large (m+batch multiset exceeds BabyBear 2^27 FRI domain)");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("hll", "omc", me, 0, 0, m_reg, "too_large"));
                            }
                        }
                    }
                }
            }

            if want("ss") {
                // SpaceSaving — size = capacity (the top-s monitored set).
                //   EXP_SS_CAP      comma-list of capacities  (default 8; even ≥2)
                //   EXP_SS_VARIANT  certified|naive|both|comma-list (default certified).
                //   `naive` = the per-record oblivious in-circuit replay strawman
                //   (Θ(m·s), the cost-to-beat); `certified` = the §G batched leaf
                //   (Θ(s+m)). The gap widens with batch m — the rq3a analog for SS.
                let ss_variant = env_str("EXP_SS_VARIANT", "certified");
                let ss_wants = |v: &str| ss_variant == "both" || ss_variant.split(',').any(|x| x.trim() == v);
                let ups: Vec<SsFullUpdate> = slice_e.iter().map(|&k| SsFullUpdate::real(((k & 0x1FFF_FFFF) | 1) as u64, 1)).collect();
                for &cap in &env_list("EXP_SS_CAP", &[8]) {
                    let cap = cap.max(2) + (cap % 2);
                    let p = SsFullParams { capacity: cap, batch: me };
                    if ss_wants("certified") {
                        let agg = bench(c, || {
                            let out = if commit.is_hiding() {
                                build_ss_full_leaf_commit(p, Expose::None, commit.mode())
                                    .prove_epoch_commit(1, SsFullState::empty(p), ups.clone(), &commit.openings(CommitFamily::SpaceSaving, 1))
                                    .output
                            } else {
                                ss_prove(p, ups.clone()).proof.output
                            };
                            outcome(proof_size(&out.0) as u64)
                        });
                        append_csv(&dir, "e1_circuit", &hdr, &row("ss", "certified", me, 0, 0, cap, &agg));
                    }
                    if ss_wants("naive") {
                        let st0 = SsFullState::empty(p);
                        match bench_guarded(c, || { let r = ss_naive_prove(p, st0.clone(), ups.clone()); outcome(proof_size(&r.proof.output.0) as u64) }) {
                            Some(agg) => { append_csv(&dir, "e1_circuit", &hdr, &row("ss", "naive", me, 0, 0, cap, &agg)); }
                            None => {
                                println!("  ss naive m={me} cap={cap}: SKIPPED — too large");
                                append_csv(&dir, "e1_circuit", &hdr, &row_skip("ss", "naive", me, 0, 0, cap, "too_large"));
                            }
                        }
                    }
                }
            }

                println!("  m={m:<4} done (family={family_sel}) → {}", dir.display());
        }
    }
    println!("done. results in {}", dir.display());
}
