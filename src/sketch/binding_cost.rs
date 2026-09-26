//! Targeted cost runs for the binding fix (see [`crate::sketch::bind`]):
//! trace rows (`Σ 2^degree` over all tables), prove time and proof size of
//! every fixed leaf/decoder under `Legacy`, `Semantic` and `Bound`, at one
//! shape each. Explicit only:
//!
//! ```text
//! BINDING_COST=cm_omc,hll_omc cargo test --release --lib \
//!     sketch::binding_cost::binding_cost_report -- --ignored --nocapture
//! ```
//!
//! `BINDING_COST` selects rows (default: all); `BINDING_COST_REPS` repeats
//! each prove (the minimum prove time is reported).

use crate::recursion::recursive::timing;
use crate::sketch::bind::Binding;

struct Row {
    leaf: &'static str,
    shape: String,
    binding: Binding,
    trace_rows: u64,
    prove_ms: f64,
    proof_bytes: usize,
}

fn bytes<T: serde::Serialize>(p: &T) -> usize {
    postcard::to_allocvec(p).map(|v| v.len()).unwrap_or(0)
}

fn keys(n: usize, salt: u64) -> Vec<u64> {
    (0..n as u64)
        .map(|i| i.wrapping_mul(0xD1B5_4A32_D192_ED03) ^ salt)
        .collect()
}

/// Run `f` (one prove) `reps` times; min prove time and the last trace-row
/// count / proof size.
fn measure(reps: usize, mut f: impl FnMut() -> usize) -> (u64, f64, usize) {
    let mut best = f64::INFINITY;
    let mut rows = 0;
    let mut size = 0;
    for _ in 0..reps {
        size = f();
        let t = timing::take();
        rows = t.trace_rows;
        best = best.min(t.prove.as_secs_f64() * 1e3);
    }
    (rows, best, size)
}

#[test]
#[ignore = "measurement: large circuits"]
fn binding_cost_report() {
    use crate::sketch::countmin::{CountMinParams, CountMinUpdate};
    use crate::sketch::countmin_final::apply_update_prf;
    use crate::sketch::countmin_v9::CountMinV9;
    use crate::sketch::Sketch;

    let only: Option<Vec<String>> = std::env::var("BINDING_COST")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    let want = |name: &str| only.as_ref().is_none_or(|v| v.iter().any(|x| x == name));
    let reps: usize = std::env::var("BINDING_COST_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let bindings = [Binding::Legacy, Binding::Semantic, Binding::Bound];
    let mut rows: Vec<Row> = Vec::new();
    let mut push = |leaf: &'static str, shape: String, binding: Binding, m: (u64, f64, usize)| {
        eprintln!(
            "BINDING_COST leaf={leaf} shape={shape} binding={binding:?} trace_rows={} prove_ms={:.0} proof_bytes={}",
            m.0, m.1, m.2
        );
        rows.push(Row { leaf, shape, binding, trace_rows: m.0, prove_ms: m.1, proof_bytes: m.2 });
    };

    let cm_updates = |n: usize| -> Vec<CountMinUpdate> {
        keys(n, 0x5555)
            .into_iter()
            .enumerate()
            .map(|(i, key)| CountMinUpdate { key, value: 1 + (i % 4) as u32 })
            .collect()
    };

    // ── Count-Min omc (BabyBear), d=7, w=2^14, batch=4096 ──
    if want("cm_omc") {
        use crate::sketch::countmin_omc::*;
        let (d, w, m) = (7usize, 1usize << 14, 4096usize);
        let mut prior = CountMinV9::new(&CountMinParams { d, w });
        for u in cm_updates(2000) {
            apply_update_prf(&mut prior, &u);
        }
        let upd = cm_updates(m);
        for binding in bindings {
            let mut leaf = build_countmin_omc_leaf_with(CmOmcParams { d, w, batch: m }, true, binding);
            let r = measure(reps, || leaf.prove_epoch(prior.clone(), upd.clone()).proof_size());
            push("countmin_omc", format!("d={d},w=2^14,batch={m}"), binding, r);
        }
    }
    // ── Count-Min omc (Goldilocks) ──
    if want("cm_omc_gl") {
        use crate::sketch::countmin_omc_gl as g;
        let (d, w, m) = (7usize, 1usize << 14, 4096usize);
        let mut prior = g::cm_gl_empty(d, w);
        for u in cm_updates(2000) {
            g::apply_update_prf(&mut prior, &u);
        }
        let upd = cm_updates(m);
        for binding in bindings {
            let mut leaf = g::build_countmin_omc_leaf_with(g::CmOmcParams { d, w, batch: m }, true, binding);
            let r = measure(reps, || bytes(&leaf.prove_epoch(prior.clone(), upd.clone()).output.0));
            push("countmin_omc_gl", format!("d={d},w=2^14,batch={m}"), binding, r);
        }
    }
    // ── Count-Min memcheck ──
    if want("cm_memcheck") {
        use crate::sketch::countmin_memcheck::*;
        let (d, w, m) = (7usize, 1usize << 14, 4096usize);
        let upd = cm_updates(m);
        for binding in bindings {
            let r = measure(reps, || {
                prove_countmin_memcheck_with(CmMemcheckParams { d, w, batch: m }, upd.clone(), binding)
                    .proof_size()
            });
            push("countmin_memcheck", format!("d={d},w=2^14,batch={m}"), binding, r);
        }
    }
    // ── Count-Min Merkle ──
    if want("cm_merkle") {
        use crate::sketch::countmin_merkle::*;
        let (d, w, m, t) = (7usize, 1usize << 14, 256usize, 256usize);
        let mut prior = CountMinV9::new(&CountMinParams { d, w });
        for u in cm_updates(2000) {
            apply_update_prf(&mut prior, &u);
        }
        let upd = cm_updates(m);
        for binding in bindings {
            let r = measure(reps, || {
                let p = prove_countmin_merkle_leaf_with(
                    CountMinMerkleParams { d, w, batch: m, t_max: t },
                    prior.clone(),
                    upd.clone(),
                    binding,
                );
                bytes(&p.output.0)
            });
            push("countmin_merkle", format!("d={d},w=2^14,batch={m},t_max={t}"), binding, r);
        }
    }
    // ── HLL omc (BabyBear / Goldilocks), b=14, batch=4096 ──
    if want("hll_omc") {
        use crate::sketch::hll_omc::*;
        let (b, m) = (14usize, 4096usize);
        let mut prior = hll_omc_empty(b);
        hll_omc_advance(&mut prior, &keys(20_000, 0x77), 1 << b);
        let ks = keys(m, 0x1234);
        for binding in bindings {
            let mut leaf = build_hll_omc_leaf_with(HllOmcParams { b, batch: m }, true, binding);
            let r = measure(reps, || leaf.prove_epoch(prior.clone(), ks.clone()).proof_size());
            push("hll_omc", format!("b={b},batch={m}"), binding, r);
        }
    }
    if want("hll_omc_gl") {
        use crate::sketch::hll_omc_gl as g;
        let (b, m) = (14usize, 4096usize);
        let mut prior = vec![0u64; 1 << b];
        g::hll_omc_advance(&mut prior, &keys(20_000, 0x77), 1 << b);
        let ks = keys(m, 0x1234);
        for binding in bindings {
            let mut leaf = g::build_hll_omc_leaf_with(g::HllOmcParams { b, batch: m }, true, binding);
            let r = measure(reps, || bytes(&leaf.prove_epoch(prior.clone(), ks.clone()).output.0));
            push("hll_omc_gl", format!("b={b},batch={m}"), binding, r);
        }
    }
    // ── HLL full (O(m·batch) scatter) ──
    if want("hll_full") {
        use crate::sketch::hll_final_full::*;
        let params = HllFullParams { b: 6, batch: 32 };
        let s0 = apply_batch(
            &HllFullState::empty(params),
            &keys(40, 3).into_iter().map(HllFullUpdate::real).collect::<Vec<_>>(),
        );
        let upd: Vec<HllFullUpdate> = keys(32, 9).into_iter().map(HllFullUpdate::real).collect();
        for binding in bindings {
            let r = measure(reps, || {
                bytes(&prove_hll_full_with(params, s0.clone(), upd.clone(), true, binding).output.0)
            });
            push("hll_final_full", "b=6,batch=32".into(), binding, r);
        }
    }
    // ── Decoders ──
    if want("decode_cm") {
        use crate::decode::ReleasePolicy;
        use crate::decode::countmin::*;
        let (d, w) = (7usize, 1usize << 14);
        let mut s = CountMinV9::new(&CountMinParams { d, w });
        for u in cm_updates(4096) {
            apply_update_prf(&mut s, &u);
        }
        for binding in bindings {
            let r = measure(reps, || {
                prove_cm_decode_with(
                    CmDecodeParams { d, w, release: ReleasePolicy::Identity },
                    s.clone(),
                    keys(1, 0x5555)[0],
                    binding,
                )
                .proof_size()
            });
            push("decode_countmin", format!("d={d},w=2^14"), binding, r);
        }
    }
    if want("decode_hll") {
        use crate::decode::ReleasePolicy;
        use crate::decode::hyperloglog::*;
        let b = 14usize;
        let mut regs = crate::sketch::hll_omc::hll_omc_empty(b);
        crate::sketch::hll_omc::hll_omc_advance(&mut regs, &keys(20_000, 0x77), 1 << b);
        for binding in bindings {
            let r = measure(reps, || {
                prove_hll_decode_omc_with(
                    HllDecodeParams { b, release: ReleasePolicy::Identity },
                    regs.clone(),
                    0,
                    binding,
                )
                .proof_size()
            });
            push("decode_hll_omc", format!("b={b}"), binding, r);
        }
    }

    eprintln!("\n| leaf | shape | binding | trace_rows | Δrows vs Legacy | prove_ms | proof_bytes |");
    eprintln!("|---|---|---|---:|---:|---:|---:|");
    for r in &rows {
        let base = rows
            .iter()
            .find(|x| x.leaf == r.leaf && x.binding == Binding::Legacy)
            .map(|x| x.trace_rows)
            .unwrap_or(r.trace_rows);
        let delta = 100.0 * (r.trace_rows as f64 - base as f64) / base as f64;
        eprintln!(
            "| {} | {} | {:?} | {} | {:+.1}% | {:.0} | {} |",
            r.leaf, r.shape, r.binding, r.trace_rows, delta, r.prove_ms, r.proof_bytes
        );
    }
}
