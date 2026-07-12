//! Toy BabyBear-vs-Goldilocks comparison of the four update (leaf) circuits.
//!
//! For each sketch family the SAME canonical record stream (via the
//! `stream_compose` mappers) is proven by the BabyBear leaf (D=4 challenges,
//! Poseidon2 width 16) and the Goldilocks leaf (D=2, Poseidon2 width 8). The
//! FRI budgets are identical by construction (54 queries, log_blowup 2,
//! query pow 15, final poly 2^6), so the measured differences isolate the
//! field / extension degree / hash width.
//!
//! Each case builds the leaf circuit once and re-proves the same epoch
//! (warmup + REPS timed), reporting the median witness/prove/verify split
//! from `recursion::recursive::timing` plus the postcard-serialized proof
//! size. Note prove_epoch self-verifies, so `verify` is part of its wall
//! clock; the split separates it back out.
//!
//! Run: RAYON_NUM_THREADS=16 cargo run --release --example bb_vs_gl_toy

use std::time::Instant;

use zksketch::experiments::families::cm_empty;
use zksketch::experiments::proof_size;
use zksketch::experiments::stream_compose::{
    cm_updates_of, gk_vals_of, hll_keys_of, ss_updates_of,
};
use zksketch::recursion::recursive::timing;

use zksketch::sketch::countmin_omc as cm_bb;
use zksketch::sketch::countmin_omc_gl as cm_gl;
use zksketch::sketch::gk_bandmerge as gk_bb;
use zksketch::sketch::gk_bandmerge_gl as gk_gl;
use zksketch::sketch::hll_omc as hll_bb;
use zksketch::sketch::hll_omc_gl as hll_gl;
use zksketch::sketch::ss_final_full as ss_bb;
use zksketch::sketch::ss_final_full_gl as ss_gl;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn warmup() -> usize {
    env_usize("ZKS_WARMUP", 1)
}
fn reps() -> usize {
    env_usize("ZKS_REPS", 3)
}
const BATCHES: [usize; 2] = [256, 1024];

/// Deterministic SplitMix64 key stream, avoiding the PAD_KEY sentinel.
fn key_stream(n: usize, seed: u64) -> Vec<u32> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            let k = (z ^ (z >> 31)) as u32;
            if k == u32::MAX { 0 } else { k }
        })
        .collect()
}

#[derive(Clone)]
struct Row {
    family: &'static str,
    field: &'static str,
    shape: String,
    batch: usize,
    wall_ms: f64,
    witness_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    trace_rows: u64,
    bytes: usize,
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    xs[xs.len() / 2]
}

fn bench(
    family: &'static str,
    field: &'static str,
    shape: String,
    batch: usize,
    mut run: impl FnMut() -> usize,
) -> Row {
    for _ in 0..warmup() {
        run();
        timing::take();
    }
    let (mut walls, mut wits, mut provs, mut vers) = (vec![], vec![], vec![], vec![]);
    let (mut rows, mut bytes) = (0u64, 0usize);
    for _ in 0..reps() {
        let t0 = Instant::now();
        bytes = run();
        walls.push(t0.elapsed().as_secs_f64() * 1e3);
        let tm = timing::take();
        wits.push(tm.witness.as_secs_f64() * 1e3);
        provs.push(tm.prove.as_secs_f64() * 1e3);
        vers.push(tm.verify.as_secs_f64() * 1e3);
        rows = tm.trace_rows;
    }
    let r = Row {
        family,
        field,
        shape,
        batch,
        wall_ms: median(walls),
        witness_ms: median(wits),
        prove_ms: median(provs),
        verify_ms: median(vers),
        trace_rows: rows,
        bytes,
    };
    println!(
        "{},{},{},{},{:.1},{:.1},{:.1},{:.1},{},{}",
        r.family,
        r.field,
        r.shape,
        r.batch,
        r.wall_ms,
        r.witness_ms,
        r.prove_ms,
        r.verify_ms,
        r.trace_rows,
        r.bytes
    );
    r
}

fn main() {
    // Default: small toys (BATCHES × fixed small states). With
    // ZKS_PROD_RATIO=1: one tier at the paper's production shape RATIOS
    // (state size ≈ batch, GK capacity = batch/8 with the paper's s=51).
    // With ZKS_PROD=1: the paper's EXACT per-leaf shapes (batch 16384;
    // b14 / d7_w16384 / cap16384 / cap2048_s51) — heavy, use ZKS_REPS=1.
    let prod_ratio = std::env::var("ZKS_PROD_RATIO").is_ok();
    let prod = std::env::var("ZKS_PROD").is_ok();
    // ZKS_FAMS=hll,gk restricts which families run (default: all four).
    let fams: Vec<String> = std::env::var("ZKS_FAMS")
        .unwrap_or_else(|_| "hll,cm,ss,gk".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    let want = |f: &str| fams.iter().any(|x| x == f);
    println!("family,field,shape,batch,wall_ms,witness_ms,prove_ms,verify_ms,trace_rows,proof_bytes");
    let mut out: Vec<Row> = vec![];

    let batches: Vec<usize> = if prod {
        vec![16384]
    } else if prod_ratio {
        vec![4096]
    } else {
        BATCHES.to_vec()
    };
    for &n in &batches {
        let stream = key_stream(n, 42);
        let hll_b = if prod { 14 } else if prod_ratio { 12 } else { 8 };
        let cm_w = if prod { 16384 } else if prod_ratio { 4096 } else { 64 };
        let ss_cap = if prod { 16384 } else if prod_ratio { 4096 } else { 64 };
        let (gk_cap, gk_s) = if prod {
            (2048, 51)
        } else if prod_ratio {
            (512, 51)
        } else {
            (64, 2)
        };

        // ── HLL: m = 2^b registers ────────────────────────────────────────
        if want("hll") {
            let keys = hll_keys_of(&stream);
            let params = hll_bb::HllOmcParams { b: hll_b, batch: n };
            let mut leaf = hll_bb::build_hll_omc_leaf(params, false);
            out.push(bench("hll", "bb", format!("b{hll_b}"), n, || {
                let p = leaf.prove_epoch(hll_bb::hll_omc_empty(hll_b), keys.clone());
                p.proof_size()
            }));
            let params = hll_gl::HllOmcParams { b: hll_b, batch: n };
            let mut leaf = hll_gl::build_hll_omc_leaf(params, false);
            out.push(bench("hll", "gl", format!("b{hll_b}"), n, || {
                let p = leaf.prove_epoch(hll_gl::hll_omc_empty(hll_b), keys.clone());
                p.proof_size()
            }));
        }

        // ── Count-Min: d=7, w cells per row ───────────────────────────────
        if want("cm") {
            let ups = cm_updates_of(&stream);
            let (d, w) = (7usize, cm_w);
            let params = cm_bb::CmOmcParams { d, w, batch: n };
            let mut leaf = cm_bb::build_countmin_omc_leaf(params, false);
            out.push(bench("cm", "bb", format!("d{d}_w{w}"), n, || {
                let p = leaf.prove_epoch(cm_empty(d, w), ups.clone());
                p.proof_size()
            }));
            let params = cm_gl::CmOmcParams { d, w, batch: n };
            let mut leaf = cm_gl::build_countmin_omc_leaf(params, false);
            out.push(bench("cm", "gl", format!("d{d}_w{w}"), n, || {
                let p = leaf.prove_epoch(cm_gl::cm_gl_empty(d, w), ups.clone());
                p.proof_size()
            }));
        }

        // ── Space-Saving: capacity=64 ─────────────────────────────────────
        if want("ss") {
            let ups_bb = ss_updates_of(&stream);
            let ups_gl: Vec<ss_gl::SsFullUpdate> = ups_bb
                .iter()
                .map(|u| ss_gl::SsFullUpdate { key: u.key, value: u.value, active: u.active })
                .collect();
            let params = ss_bb::SsFullParams { capacity: ss_cap, batch: n };
            let s0 = ss_bb::SsFullState::empty(params);
            let mut leaf = ss_bb::build_ss_full_leaf(params, false);
            out.push(bench("ss", "bb", format!("cap{ss_cap}"), n, || {
                let p = leaf.prove_epoch(s0.clone(), ups_bb.clone());
                proof_size(&p.output.0)
            }));
            let params = ss_gl::SsFullParams { capacity: ss_cap, batch: n };
            let s0 = ss_gl::SsFullState::empty(params);
            let mut leaf = ss_gl::build_ss_full_leaf(params, false);
            out.push(bench("ss", "gl", format!("cap{ss_cap}"), n, || {
                let p = leaf.prove_epoch(s0.clone(), ups_gl.clone());
                proof_size(&p.output.0)
            }));
        }

        // ── GK band-merge (two-sided): capacity=64, s=2 ───────────────────
        if want("gk") {
            let vals = gk_vals_of(&stream);
            let params = gk_bb::GkbParams { capacity: gk_cap, batch: n, s: gk_s };
            let s0 = gk_bb::Gk2State::empty(params);
            let mut leaf = gk_bb::build_gkb2_leaf(params, false);
            out.push(bench("gk", "bb", format!("cap{gk_cap}_s{gk_s}"), n, || {
                let p = leaf.prove_epoch(s0.clone(), vals.clone());
                proof_size(&p.output.0)
            }));
            let params = gk_gl::GkbParams { capacity: gk_cap, batch: n, s: gk_s };
            let s0 = gk_gl::Gk2State::empty(params);
            let mut leaf = gk_gl::build_gkb2_leaf(params, false);
            out.push(bench("gk", "gl", format!("cap{gk_cap}_s{gk_s}"), n, || {
                let p = leaf.prove_epoch(s0.clone(), vals.clone());
                proof_size(&p.output.0)
            }));
        }
    }

    // ── Summary: GL/BB ratios per (family, batch) ─────────────────────────
    println!();
    println!(
        "{:<6} {:<6} {:>10} {:>10} {:>8} {:>12} {:>12} {:>8}",
        "family", "batch", "bb_ms", "gl_ms", "gl/bb", "bb_bytes", "gl_bytes", "gl/bb"
    );
    for &n in &batches {
        for fam in ["hll", "cm", "ss", "gk"] {
            let bb = out.iter().find(|r| r.family == fam && r.field == "bb" && r.batch == n);
            let gl = out.iter().find(|r| r.family == fam && r.field == "gl" && r.batch == n);
            if let (Some(bb), Some(gl)) = (bb, gl) {
                println!(
                    "{:<6} {:<6} {:>10.1} {:>10.1} {:>8.2} {:>12} {:>12} {:>8.2}",
                    fam,
                    n,
                    bb.wall_ms,
                    gl.wall_ms,
                    gl.wall_ms / bb.wall_ms,
                    bb.bytes,
                    gl.bytes,
                    gl.bytes as f64 / bb.bytes as f64
                );
            }
        }
    }
}
