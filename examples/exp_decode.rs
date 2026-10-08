//! `exp_decode` — end-to-end **query-circuit** runner for all four sketches.
//!
//! For each family this builds the *deployed* final state (the exact native
//! state its chosen update variant commits — CM `omc`, HLL `omc`, SS
//! `certified`, GK `bandmerge2`), runs the matching decode/query STARK, and
//! checks the decoded answer against an independent native reference:
//!
//! | family | update variant | query circuit          | answer            |
//! |--------|----------------|------------------------|-------------------|
//! | CM     | omc            | `prove_cm_decode`      | point frequency   |
//! | HLL    | omc            | `prove_hll_decode_omc` | cardinality       |
//! | SS     | certified      | `prove_ss_decode`      | top-`c` mass      |
//! | GK     | bandmerge2     | `prove_gk2_decode`     | approximate rank  |
//!
//! Each decode prover self-verifies internally, so a printed row is a proven,
//! verified result. Run:  `cargo run --release --example exp_decode`
//! (or via `scripts/run_decode.sh`). Any answer/native mismatch aborts non-zero.
//!
//! **Commitments (`ZKSKETCH_COMMIT`, revision B2).** The prover's commitment
//! context is read once (`ProverCommit::from_env`: `hiding` by default, the
//! seed from `ZKSKETCH_SALT_SEED` or the OS RNG, never printed). Each state
//! here is the stream's version `t` (the number of batches applied: CM, HLL
//! and SS `t = 1`, GK `t = 2`); under `hiding` its decoder opens
//! `Com(S_t; ρ^S_t)` with the randomizer leaf `t` closes that state with. A
//! row is `ok` only if the proof also EXPOSES that commitment (the auditor's
//! `check_query_exposure`; skipped under `ZKSKETCH_BINDING=legacy`, whose
//! decoders expose nothing). `ZKSKETCH_COMMIT=plain` runs the pre-B2
//! decoders byte for byte.

use std::time::Duration;

use zksketch::commitment::hiding::{CommitFamily, CommitMode};
use zksketch::config::Val;
use zksketch::decode::{DecodeProof, QueryStatement, ReleasePolicy};
use zksketch::experiments::audit::check_query_exposure;
use zksketch::experiments::prover_commit::ProverCommit;
use zksketch::recursion::recursive::timing;

// ---- CM (omc) ----
use zksketch::commitment::countmin::commit_countmin_with;
use zksketch::decode::countmin::{CmDecodeParams, prove_cm_decode, prove_cm_decode_commit};
use zksketch::sketch::Sketch; // brings `CountMin::new` into scope
use zksketch::sketch::countmin::{CountMin, CountMinParams, CountMinUpdate};
use zksketch::sketch::bind::default_binding;
use zksketch::sketch::countmin_final::{hash_cell_prf_with, key_hash_input};
use zksketch::sketch::countmin_omc::countmin_omc_advance;

// ---- HLL (omc) ----
use zksketch::decode::hyperloglog::{
    BETA, HllDecodeParams, fixed_res, prove_hll_decode_omc, prove_hll_decode_omc_commit,
};
use zksketch::sketch::hll_omc::{commit_hll_omc_with, hll_omc_advance, hll_omc_empty};

// ---- SS (certified) ----
use zksketch::decode::spacesaving::{SsDecodeParams, prove_ss_decode, prove_ss_decode_commit};
use zksketch::sketch::ss_final_full::{
    SsFullParams, SsFullState, SsFullUpdate, apply_batch_ss_full, commit_ss_state_with,
};

// ---- GK (bandmerge2) ----
use zksketch::decode::gk_bandmerge::{Gkb2DecodeParams, prove_gk2_decode, prove_gk2_decode_commit};
use zksketch::sketch::gk_bandmerge::{Gk2State, GkbParams, apply_batch2, commit_gk2_state_with};

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// The auditor-side exposure check: the proof must expose `commit` (the
/// version's published `Com(S_t)`), the query and its answer. `true` when it
/// does (or under Legacy, which exposes nothing and is skipped).
fn exposes(dp: &DecodeProof, commit: [Val; 8], query: Option<[Val; 4]>, t: usize) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check_query_exposure(dp, commit, query, t)))
        .is_ok()
}

/// The exposed query of a scalar-query decoder (ss `c`, gk value).
fn scalar_query(q: u64) -> [Val; 4] {
    QueryStatement::new([Val::new(0); 8], q, 0).query
}

/// One printed result row; `ok` gates the process exit code.
struct Row {
    family: &'static str,
    query: String,
    answer: u64,
    native: String,
    ok: bool,
    prove_ms: f64,
    verify_ms: f64,
    bytes: usize,
}

fn print_header() {
    println!(
        "{:<14} {:<10} {:>12} {:>16} {:>5} {:>9} {:>9} {:>8}",
        "family", "query", "answer", "native", "ok", "prove/ms", "verify/ms", "bytes"
    );
    println!("{}", "-".repeat(90));
}

fn print_row(r: &Row) {
    println!(
        "{:<14} {:<10} {:>12} {:>16} {:>5} {:>9.1} {:>9.1} {:>8}",
        r.family,
        r.query,
        r.answer,
        r.native,
        if r.ok { "ok" } else { "FAIL" },
        r.prove_ms,
        r.verify_ms,
        r.bytes,
    );
}

// ------------------------------------------------------------------ CM (omc)

fn run_cm(commit: &ProverCommit) -> Row {
    // d=4, w=8 sketch; stream with key 7 appearing 3× (truth) among others.
    let d = 4usize;
    let w = 8usize;
    let stream: [u64; 6] = [7, 7, 11, 7, 11, 3];
    let query = 7u64;

    let mut st = CountMin::new(&CountMinParams { d, w });
    let ups: Vec<CountMinUpdate> = stream.iter().map(|&k| CountMinUpdate { key: k, value: 1 }).collect();
    countmin_omc_advance(&mut st, &ups);
    let true_count = stream.iter().filter(|&&k| k == query).count() as u64;
    // PRF-consistent point estimate: min over the PRF-routed cells (the state
    // was built with the omc leaf's native update, so plain `CountMin::query`
    // would read the wrong columns). This mirrors the decode circuit's native
    // estimator under the same (default) binding.
    let sketch_est = (0..d)
        .map(|row| st.counters[row][hash_cell_prf_with(row, query, w, default_binding())] as u64)
        .min()
        .unwrap(); // min-of-rows, ≥ true_count

    let p = CmDecodeParams { d, w, release: ReleasePolicy::Identity };
    // Version t = 1 (one batch applied). Prover side: the version's randomizer.
    let salt = commit.state_salt(CommitFamily::CountMin, 1);
    let com = commit_countmin_with(&st, commit.mode(), &salt).0;
    let proof = match commit.mode() {
        CommitMode::Plain => prove_cm_decode(p, st, query),
        CommitMode::Hiding => prove_cm_decode_commit(p, st, query, default_binding(), CommitMode::Hiding, &salt),
    };
    let t = timing::take();

    // The circuit computes the CM point estimate: must equal the native sketch
    // estimate and upper-bound the true count; the proof must expose Com(S_1).
    let ok = proof.answer == sketch_est
        && proof.answer >= true_count
        && exposes(&proof, com, Some(key_hash_input(query, default_binding())), 1);
    Row {
        family: "CM/omc",
        query: format!("f({query})"),
        answer: proof.answer,
        native: format!("est {sketch_est} (t{true_count})"),
        ok,
        prove_ms: ms(t.prove),
        verify_ms: ms(t.verify),
        bytes: proof.proof_size(),
    }
}

// ----------------------------------------------------------------- HLL (omc)

fn run_hll(commit: &ProverCommit) -> Row {
    // m = 2^b registers; feed distinct keys via the omc register-advance path.
    let b = 4usize;
    let m = 1usize << b;
    let keys: Vec<u64> = (1u64..=50).collect(); // 50 distinct
    let true_distinct = keys.len() as u64;

    let mut regs = hll_omc_empty(b);
    hll_omc_advance(&mut regs, &keys, m);
    let regs32: Vec<u32> = regs.iter().map(|&r| r as u32).collect();
    let native_fp = fixed_res(m, &regs32); // fixed-point cardinality (scale 2^β)

    let p = HllDecodeParams { b, release: ReleasePolicy::Identity };
    // Version t = 1 (one batch applied).
    let salt = commit.state_salt(CommitFamily::HyperLogLog, 1);
    let com = commit_hll_omc_with(&regs, b, commit.mode(), &salt);
    let proof = match commit.mode() {
        CommitMode::Plain => prove_hll_decode_omc(p, regs, 0),
        CommitMode::Hiding => {
            prove_hll_decode_omc_commit(p, regs, 0, default_binding(), CommitMode::Hiding, &salt)
        }
    };
    let t = timing::take();

    let ok = proof.answer == native_fp && exposes(&proof, com, None, 1);
    // Human-readable estimate = fixed-point answer / 2^β.
    let est = proof.answer as f64 / (1u64 << BETA) as f64;
    Row {
        family: "HLL/omc",
        query: "|distinct|".to_string(),
        answer: proof.answer,
        native: format!("≈{est:.1} (t{true_distinct})"),
        ok,
        prove_ms: ms(t.prove),
        verify_ms: ms(t.verify),
        bytes: proof.proof_size(),
    }
}

// ----------------------------------------------------------- SS (certified)

fn run_ss(commit: &ProverCommit) -> Row {
    // capacity 4; keys 101..104 with weights 1..4 via the certified merge.
    let cap = 4usize;
    let s0 = SsFullState::empty(SsFullParams { capacity: cap, batch: 4 });
    let batch = vec![
        SsFullUpdate::real(101, 1),
        SsFullUpdate::real(102, 2),
        SsFullUpdate::real(103, 3),
        SsFullUpdate::real(104, 4),
    ];
    let st = apply_batch_ss_full(&s0, &batch).0;

    let c = 2usize; // top-2 heavy hitters
    let mut counts: Vec<u64> =
        st.rows.iter().filter(|r| r.active == 1).map(|r| r.count as u64).collect();
    counts.sort_unstable_by(|a, b| b.cmp(a));
    let native_mass: u64 = counts.iter().take(c).sum(); // 4 + 3 = 7

    let p = SsDecodeParams { capacity: cap, c, release: ReleasePolicy::Identity };
    // Version t = 1 (one batch applied).
    let salt = commit.state_salt(CommitFamily::SpaceSaving, 1);
    let com = commit_ss_state_with(&st, commit.mode(), &salt).0;
    let proof = match commit.mode() {
        CommitMode::Plain => prove_ss_decode(p, st, c),
        CommitMode::Hiding => prove_ss_decode_commit(p, st, c, default_binding(), CommitMode::Hiding, &salt),
    };
    let t = timing::take();

    let ok = proof.answer == native_mass && exposes(&proof, com, Some(scalar_query(c as u64)), 1);
    Row {
        family: "SS/certified",
        query: format!("top-{c}"),
        answer: proof.answer,
        native: format!("mass {native_mass}"),
        ok,
        prove_ms: ms(t.prove),
        verify_ms: ms(t.verify),
        bytes: proof.proof_size(),
    }
}

// ---------------------------------------------------------- GK (bandmerge2)

fn run_gk(commit: &ProverCommit) -> Row {
    // capacity 16 two-sided band-merge; 16 distinct keys over two batches.
    let cap = 16usize;
    let params = GkbParams { capacity: cap, batch: 8, s: 2 };
    let chunks: [[u32; 8]; 2] =
        [[900, 800, 700, 600, 500, 400, 300, 200], [850, 250, 650, 450, 950, 150, 550, 350]];
    let mut st = Gk2State::empty(params);
    let mut seen: Vec<u32> = Vec::new();
    for chunk in chunks {
        st = apply_batch2(&st, &chunk);
        seen.extend_from_slice(&chunk);
    }
    seen.sort_unstable();

    let query = 500u32;
    let truth = seen.partition_point(|&v| v <= query) as u64; // true rank
    let eps_n = st.n / st.params.s;

    let p = Gkb2DecodeParams { capacity: cap, release: ReleasePolicy::Identity };
    // Version t = 2 (two batches applied).
    let salt = commit.state_salt(CommitFamily::GreenwaldKhanna, 2);
    let com = commit_gk2_state_with(&st, commit.mode(), &salt).0;
    let proof = match commit.mode() {
        CommitMode::Plain => prove_gk2_decode(p, st, query),
        CommitMode::Hiding => {
            prove_gk2_decode_commit(p, st, query, default_binding(), CommitMode::Hiding, &salt)
        }
    };
    let t = timing::take();

    // Approximate rank: within εN of the truth; the proof exposes Com(S_2).
    let ok = proof.answer.abs_diff(truth) <= eps_n + 1
        && exposes(&proof, com, Some(scalar_query(query as u64)), 2);
    Row {
        family: "GK/bandmerge2",
        query: format!("rank≤{query}"),
        answer: proof.answer,
        native: format!("rank {truth} (±{})", eps_n + 1),
        ok,
        prove_ms: ms(t.prove),
        verify_ms: ms(t.verify),
        bytes: proof.proof_size(),
    }
}

fn main() {
    // The prover's commitment context, read once (the seed is never printed).
    let commit = ProverCommit::from_env();
    println!(
        "query-circuit results — four sketches, deployed update variants (commit={} salt_seed={})\n",
        commit.label(),
        commit.seed_label()
    );
    print_header();

    let rows = [run_cm(&commit), run_hll(&commit), run_ss(&commit), run_gk(&commit)];
    for r in &rows {
        print_row(r);
    }

    let failed: Vec<&str> = rows.iter().filter(|r| !r.ok).map(|r| r.family).collect();
    println!();
    if failed.is_empty() {
        println!("all 4 query circuits: answer matches native reference ✓ (each self-verified)");
    } else {
        eprintln!("MISMATCH in: {}", failed.join(", "));
        std::process::exit(1);
    }
}
