//! Procs regression test of the staged-wave engine
//! (`EXP_COMPOSE_WAVE_SIZE`, `dist_compose::measure_compose_dist_staged`)
//! with interleaved queries, under both commitment modes.
//!
//! The staged engine spawns its workers by re-executing the current binary,
//! so this test has its own `main` (`harness = false` in `Cargo.toml`): a
//! child spawned as a worker serves its role through
//! [`maybe_run_child`] and never reaches the scenarios. Each scenario folds a
//! small forest over 4 pinned machines in 2 waves of 2 (intra-wave and
//! cross-wave rounds), for Count-Min, the Bloom filter and the KMV sketch
//! under both commitment modes, then requires every query to be pinned to the decoder VK
//! of the run's commitment mode and bound (`query_bind_ms` set) against the
//! batch log the prover published (salted under `Hiding`). A few minutes on
//! a many-core machine (each machine gets up to 4 cores).
//!
//! ```bash
//! cargo test --release --test staged_queries
//! ```

use zksketch::commitment::hiding::SaltSeed;
use zksketch::experiments::dist_compose::{ExeSnapshotGuard, maybe_run_child, measure_compose_dist};
use zksketch::experiments::prover_commit::ProverCommit;
use zksketch::experiments::stream_compose::{QueryKeyMode, StreamFamily, StreamMode, StreamShape};

const SHAPE: StreamShape = StreamShape {
    d: 4,
    w: 8,
    b: 4,
    capacity: 4,
    gk_s: 2,
    bloom_k: 3,
    bloom_log_w: 7,
    kmv_k: 4,
    gk_rounds: zksketch::sketch::gk_bandmerge::GkRounds::SortedCopy,
};

fn main() {
    if maybe_run_child() {
        return;
    }
    let _exe_guard = ExeSnapshotGuard::new();
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if cpus < 2 {
        println!("staged_queries: skipped (needs 2 CPUs for a wave of 2 single-core machines)");
        return;
    }
    let (wave, cores) = (2usize, (cpus / 2).clamp(1, 4));
    // 8 batches of 4 records over 4 machines (2 leaves each); queries at
    // versions inside the first slice, on a slice boundary and at the end.
    let batches: Vec<Vec<u32>> =
        (0..8u32).map(|t| (0..4u32).map(|i| 1 + (t * 5 + i * 3) % 11).collect()).collect();
    let query_at = [1usize, 4, 7, 8];
    let proof_dir = std::env::temp_dir().join(format!("zks_staged_queries_{}", std::process::id()));
    let mut failures = Vec::new();
    let mut runs = 0usize;
    // SAFETY: no other thread reads the environment yet (no worker, pool or
    // reader thread is alive); the engine reads the knob at dispatch.
    unsafe { std::env::set_var("EXP_COMPOSE_WAVE_SIZE", wave.to_string()) };
    for family in [StreamFamily::CmOmc, StreamFamily::BloomOmc, StreamFamily::KmvSketch] {
        for commit in [ProverCommit::plain(), ProverCommit::hiding(SaltSeed::for_tests(41))] {
            runs += 1;
            let label = format!("wave={wave} cores={cores} {family:?} commit={}", commit.label());
            let t0 = std::time::Instant::now();
            let res = measure_compose_dist(
                family,
                SHAPE,
                &batches,
                StreamMode::Forest,
                cores,
                4,
                &proof_dir,
                200.0,
                0.2,
                &query_at,
                QueryKeyMode::UniformStream,
                &commit,
            );
            match res {
                Err(e) => failures.push(format!("{label}: {e}")),
                Ok(cell) if cell.machines_eff != 4 => {
                    failures.push(format!("{label}: {} machines, want 4", cell.machines_eff))
                }
                Ok(cell) if cell.n_queries != query_at.len() => failures.push(format!(
                    "{label}: {} queries, want {}",
                    cell.n_queries,
                    query_at.len()
                )),
                Ok(cell) => match cell.query_bind_ms {
                    Some(ms) if ms.is_finite() && cell.query_ctx_verifies > 0 => {
                        println!(
                            "ok   {label}: {} queries bound, {} ctx proofs, bind {ms:.1} ms, \
                             root {} B, query proofs {} B ({:.0} s)",
                            cell.n_queries,
                            cell.query_ctx_verifies,
                            cell.proof_bytes,
                            cell.query_proof_bytes,
                            t0.elapsed().as_secs_f64()
                        )
                    }
                    other => failures.push(format!(
                        "{label}: answers not bound (query_bind_ms={other:?}, ctx={})",
                        cell.query_ctx_verifies
                    )),
                },
            }
        }
    }
    let _ = std::fs::remove_dir_all(&proof_dir);
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL {f}");
        }
        panic!("staged_queries: {} of {runs} runs failed", failures.len());
    }
    println!("staged_queries: {runs} runs ok");
}
