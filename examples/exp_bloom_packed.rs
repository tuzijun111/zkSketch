//! Packed-byte Bloom leaf: table shapes, prove/verify time and peak RSS of the leaf, a query and a merge.
//! Usage: [B1_KIND=leaf|shapes|query|merge|all B1_M=1024 B1_MODE=hiding|plain B1_K=7 B1_LOGW=14 B1_PRIOR=8000 B1_REPS=2]
//!        cargo run --release --example exp_bloom_packed

use std::time::Instant;

use p3_field::PrimeCharacteristicRing;
use zksketch::commitment::hiding::{CommitFamily, CommitMode, Openings, SaltBb, SaltSeed};
use zksketch::config::Val;
use zksketch::decode::bloom_packed::{bloom_packed_decode_vk_commit, prove_bloom_packed_query_commit};
use zksketch::decode::{QueryStatement, verify_decode_proof};
use zksketch::experiments::table_probe::{self, CircuitShape};
use zksketch::recursion::recursive::expose_forest::{prove_hiding_merge_proofs, read_exposed_statement};
use zksketch::recursion::recursive::statement::Expose;
use zksketch::sketch::bloom_omc::bloom_insert;
use zksketch::sketch::bloom_packed::*;

fn env(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(d)
}

fn status_kb(field: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn trim() {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    unsafe { malloc_trim(0) };
}

fn reset_hwm() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

fn keys(n: usize, seed: u64) -> Vec<u64> {
    (0..n as u64).map(|i| (i ^ (seed << 40)).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)).collect()
}

/// Committed cells per row under ZK (hiding PCS + LogUp masks), per table.
fn committed_width(name: &str) -> u64 {
    match name {
        "alu" => 124,
        "const" => 12,
        "public" => 12,
        n if n.starts_with("poseidon2") => 356,
        n if n.starts_with("recompose") => 44,
        n if n.starts_with("permute") => 40,
        n if n.starts_with("range") => 29,
        n if n.starts_with("expose") => 84,
        _ => 0,
    }
}

fn report(tag: &str, m: usize, shapes: &[CircuitShape]) {
    for s in shapes {
        println!("{}", table_probe::summary(s));
        let (mut main, mut com) = (0u64, 0u64);
        for t in &s.tables {
            main += t.padded() * t.width as u64;
            com += t.padded() * committed_width(&t.name);
            if t.name == "alu" || t.name == "range" {
                println!(
                    "SHAPE kind={tag} site={} m={m} table={} rows={} log_h={} fill={:.4} headroom_rows={}",
                    s.site,
                    t.name,
                    t.rows,
                    t.log_h,
                    t.fill(),
                    t.padded() as i64 - t.rows as i64
                );
            }
        }
        println!("CELLS kind={tag} site={} m={m} main={main} committed_zk={com}", s.site);
    }
}

fn mode_of() -> CommitMode {
    if std::env::var("B1_MODE").as_deref() == Ok("plain") { CommitMode::Plain } else { CommitMode::Hiding }
}

fn params(m: usize) -> BloomPackedParams {
    BloomPackedParams { k: env("B1_K", 7), log_w: env("B1_LOGW", 14), batch: m }
}

/// The prior state: `B1_PRIOR` keys (half-full at the deployed shape).
fn prior(p: &BloomPackedParams) -> Vec<u8> {
    let mut w = packed_empty(p);
    packed_insert(&mut w, p, &keys(env("B1_PRIOR", 8000), 1));
    w
}

/// A batch of `m` slots: `m − 1` keys with one repeat, then one dummy slot.
fn batch_keys(m: usize, seed: u64) -> Vec<u64> {
    let mut ks = keys(m.saturating_sub(2).max(1), seed);
    if m >= 3 {
        ks.push(ks[0]);
    }
    ks
}

fn shapes(ms: &[usize], mode: CommitMode) {
    for &m in ms {
        let p = params(m);
        if let Err(e) = p.check() {
            println!("SHAPE m={m} invalid: {e}");
            continue;
        }
        let t0 = Instant::now();
        let r = table_probe::capture_shapes(|| build_bloom_packed_leaf_commit(p, Expose::Interval, mode));
        match r {
            Ok(s) => {
                report("leaf", m, &s);
                println!("SHAPE kind=leaf m={m} probe_s={:.2}", t0.elapsed().as_secs_f64());
            }
            Err(e) => println!("SHAPE m={m} failed: {e}"),
        }
    }
}

fn leaf(m: usize, mode: CommitMode, reps: usize) -> (Vec<u8>, SaltBb, Vec<u64>) {
    let p = params(m);
    let seed = SaltSeed::for_tests(2026);
    let init = prior(&p);
    let t0 = Instant::now();
    let (mut leaf, sh) = table_probe::capture(|| build_bloom_packed_leaf_commit(p, Expose::Interval, mode));
    let build_s = t0.elapsed().as_secs_f64();
    report("leaf", m, &sh);
    println!("LEAF build_s={build_s:.2} rss_mb={}", status_kb("VmRSS:") / 1024);
    let mut last = init.clone();
    let mut last_keys = Vec::new();
    for rep in 0..reps {
        let ks = batch_keys(m, 100 + rep as u64);
        let t = 2u64;
        trim();
        reset_hwm();
        let rss0 = status_kb("VmRSS:") / 1024;
        let w0 = Instant::now();
        let pr = if mode.is_hiding() {
            leaf.prove_epoch_commit(t, &init, &ks, &Openings::for_leaf(&seed, CommitFamily::BloomPacked, t))
        } else {
            leaf.prove_epoch_at(t, &init, &ks)
        };
        let total = w0.elapsed().as_secs_f64();
        let tm = zksketch::recursion::recursive::timing::take();
        let hwm = status_kb("VmHWM:") / 1024;
        // The certified state is the native insert, and the bit-array filter's.
        let mut want = init.clone();
        packed_insert(&mut want, &p, &ks);
        assert_eq!(pr.final_words, want, "proved state = native packed insert");
        let bp = p.omc();
        let mut bits = words_to_bits(&init);
        bloom_insert(&mut bits, &bp, &ks);
        assert_eq!(bits_to_words(&bits), want, "= bloom_omc's bit array");
        let st = read_exposed_statement(&pr.output.0);
        assert_eq!(st.final_, pr.final_commit.0.to_vec(), "exposed final = native Com(S_t)");
        last = want;
        last_keys = ks.clone();
        println!(
            "LEAF mode={mode:?} m={m} rep={rep} witness_s={:.3} prove_s={:.3} verify_ms={:.1} total_s={total:.3} rss_before_mb={rss0} hwm_mb={hwm} proof_bytes={} verified=1",
            tm.witness.as_secs_f64(),
            tm.prove.as_secs_f64(),
            tm.verify.as_secs_f64() * 1e3,
            zksketch::experiments::proof_size(&pr.output.0)
        );
    }
    let salt = zksketch::commitment::hiding::rho_state_bb(&seed, CommitFamily::BloomPacked, 2);
    (last, salt, last_keys)
}

fn query(m: usize, mode: CommitMode, reps: usize, state: Option<(Vec<u8>, SaltBb, Vec<u64>)>) {
    let p = params(m);
    let (words, salt, members) = state.unwrap_or_else(|| {
        let mut w = prior(&p);
        let ks = batch_keys(m, 100);
        packed_insert(&mut w, &p, &ks);
        (w, SaltBb([Val::from_u64(5); 12]), ks)
    });
    let salt = if mode.is_hiding() { salt } else { SaltBb::ZERO };
    let t0 = Instant::now();
    let vk = bloom_packed_decode_vk_commit(p, mode);
    println!("QUERY vk_derive_s={:.3}", t0.elapsed().as_secs_f64());
    for rep in 0..reps.max(2) {
        // Alternate a member and a fresh key.
        let key = if rep % 2 == 0 { members[rep % members.len()] } else { keys(1, 900 + rep as u64)[0] };
        trim();
        reset_hwm();
        let rss0 = status_kb("VmRSS:") / 1024;
        let t0 = Instant::now();
        let (q, sh) = table_probe::capture(|| prove_bloom_packed_query_commit(p, &words, key, mode, &salt));
        let total = t0.elapsed().as_secs_f64();
        let tm = zksketch::recursion::recursive::timing::take();
        let hwm = status_kb("VmHWM:") / 1024;
        if rep == 0 {
            report("query", m, &sh);
        }
        assert_eq!(q.answer, u64::from(packed_contains(&words, &p, key)), "answer = native");
        if rep % 2 == 0 {
            assert_eq!(q.answer, 1, "a member answers 1");
        }
        let commit = commit_packed_with(&p, &words, mode, &salt);
        let want = QueryStatement::with_query(commit, zksketch::decode::bloom_packed::bloom_query_input(key), q.answer);
        assert_eq!(verify_decode_proof(&q.output.0, &vk), Ok(want), "pinned to the derived decode VK");
        println!(
            "QUERY mode={mode:?} rep={rep} answer={} build+witness_s={:.3} prove_s={:.3} verify_ms={:.1} total_s={total:.3} rss_before_mb={rss0} hwm_mb={hwm} proof_bytes={} verified=1",
            q.answer,
            total - tm.prove.as_secs_f64() - tm.verify.as_secs_f64(),
            tm.prove.as_secs_f64(),
            tm.verify.as_secs_f64() * 1e3,
            zksketch::experiments::proof_size(&q.output.0)
        );
    }
}

fn merge(m: usize, mode: CommitMode) {
    let p = params(m);
    let seed = SaltSeed::for_tests(2027);
    let mut leaf = build_bloom_packed_leaf_commit(p, Expose::Interval, mode);
    let mut st = packed_empty(&p);
    let mut proofs = Vec::new();
    for t in 1..=2u64 {
        let ks = batch_keys(m, 200 + t);
        let pr = if mode.is_hiding() {
            leaf.prove_epoch_commit(t, &st, &ks, &Openings::for_leaf(&seed, CommitFamily::BloomPacked, t))
        } else {
            leaf.prove_epoch_at(t, &st, &ks)
        };
        let tm = zksketch::recursion::recursive::timing::take();
        println!("MLEAF t={t} prove_s={:.3}", tm.prove.as_secs_f64());
        st = pr.final_words.clone();
        proofs.push(pr.output.0);
    }
    // The no-op VK-derivation leaf (for the merge circuit's shape below).
    let noop = if mode.is_hiding() {
        leaf.prove_epoch_public_zero(1, &packed_empty(&p), &[])
    } else {
        leaf.prove_epoch_at(1, &packed_empty(&p), &[])
    };
    let _ = zksketch::recursion::recursive::timing::take();
    drop(leaf);
    trim();
    reset_hwm();
    let r0 = status_kb("VmRSS:") / 1024;
    let t0 = Instant::now();
    let out = prove_hiding_merge_proofs(&proofs[0], &proofs[1]);
    let s = t0.elapsed().as_secs_f64();
    let hwm = status_kb("VmHWM:") / 1024;
    // The merge circuit's tables (the VK derivation builds the same circuit
    // from the child proof's shape; nothing is proved there).
    let stm = read_exposed_statement(&out.0);
    let (l, r) = (read_exposed_statement(&proofs[0]), read_exposed_statement(&proofs[1]));
    assert_eq!(stm.init, l.init, "merged init = left init");
    assert_eq!(stm.final_, r.final_, "merged final = right final");
    println!(
        "MERGE mode={mode:?} m={m} total_s={s:.3} rss_before_mb={r0} hwm_mb={hwm} proof_bytes={}",
        zksketch::experiments::proof_size(&out.0)
    );
    let (_, sh) = table_probe::capture(|| {
        zksketch::recursion::recursive::expose_forest::derive_forest_root_vk(noop.output.0, 2)
    });
    report("merge", m, &sh);
}

fn main() {
    let kind = std::env::var("B1_KIND").unwrap_or_else(|_| "leaf".into());
    let ms: Vec<usize> = std::env::var("B1_M")
        .unwrap_or_else(|_| "1024".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let mode = mode_of();
    let reps = env("B1_REPS", 2);
    table_probe::quiet_shapes_only_panics();
    let m = ms[0];
    let p = params(m);
    println!(
        "B1 kind={kind} k={} log_w={} m={ms:?} words={} pairs={} mode={mode:?} pcs={} logup_mask={}",
        p.k,
        p.log_w,
        p.m_words(),
        p.pairs(),
        zksketch::config::pcs_label(),
        zksketch::config::logup_mask_label()
    );
    match kind.as_str() {
        "shapes" => shapes(&ms, mode),
        "leaf" => {
            let _ = leaf(m, mode, reps);
        }
        "query" => query(m, mode, reps, None),
        "merge" => merge(m, mode),
        "all" => {
            let st = leaf(m, mode, reps);
            trim();
            query(m, mode, reps, Some(st));
        }
        other => panic!("B1_KIND={other}: shapes|leaf|query|merge|all"),
    }
}
