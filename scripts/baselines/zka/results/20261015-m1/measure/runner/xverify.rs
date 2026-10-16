//! M1 measurer scratch tool (NOT part of the repo; copied into examples/ only while it is
//! built, then removed): cross-build check of the scalar and the AVX2 (x86-64-v3) builds.
//!
//!   xverify vk <out_dir>
//!       derive, from public parameters only (no-op leaves, exactly as exp_compose's auditor),
//!       the leaf VK and the forest root VK of the measured shapes and write them (postcard):
//!       gk_384_128 (root over 16 leaves), gk_768_512 (root over 2), bloom_k7_w14_256 (root over 8).
//!   xverify prove <out_dir> <cap> <m> <t>
//!       prove t real AOL GK leaves (hiding, test seed 1, chained from the empty state), fold
//!       them with the online forest (bare peaks, no cache) into the root, and write
//!       leaf_XXXX.bin, root.bin (postcard proofs) and the expected boundary.
//!   xverify verify <in_dir> <cap> <m> <t>
//!       derive the leaf VK and the root VK locally, verify every leaf (pinned) and the root
//!       (pinned) that ANOTHER build wrote, and check the root boundary = Com(S_0), Com(S_t)
//!       of the native chain recomputed here.
use std::path::{Path, PathBuf};
use std::time::Instant;

use zksketch::commitment::hiding::{CommitFamily, CommitMode, SaltSeed};
use zksketch::experiments::prover_commit::ProverCommit;
use zksketch::experiments::stream_compose::gk_vals_of;
use zksketch::recursion::recursive::expose_forest::{
    ForestCascade, derive_forest_root_vk, leaf_vk, read_exposed_boundary_proof, verify_bound_stark_proof_pinned,
    verify_leaf_proof_pinned,
};
use zksketch::recursion::recursive::noop_leaf::{bloom_omc_noop_leaf_commit, gk2_noop_leaf_commit};
use zksketch::recursion::recursive::statement::composition_expose;
use zksketch::sketch::bind::default_binding;
use zksketch::sketch::bloom_omc::BloomOmcParams;
use zksketch::sketch::gk_bandmerge::{Gk2State, GkbParams, apply_batch2, build_gkb2_leaf_commit, commit_gk2_state_with};

type Proof = p3_circuit_prover::BatchStarkProof<zksketch::recursion::recursive::config::ConfigWithFriParams>;

fn md5ish(b: &[u8]) -> String {
    // FNV-1a 64 (a fingerprint for the log; byte equality is checked with cmp / md5sum outside)
    let mut h: u64 = 0xcbf29ce484222325;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn write(p: &Path, b: &[u8]) {
    std::fs::write(p, b).unwrap_or_else(|e| panic!("write {}: {e}", p.display()));
}

fn keys() -> Vec<u32> {
    let p = format!("{}/data/aol.keys", env!("CARGO_MANIFEST_DIR"));
    let b = std::fs::read(&p).expect("read aol.keys");
    b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

fn gk_params(cap: usize, m: usize) -> GkbParams {
    GkbParams { capacity: cap, batch: m, s: 51 }
}

fn gk_noop(p: GkbParams) -> Proof {
    gk2_noop_leaf_commit(p, composition_expose(), default_binding(), CommitMode::Hiding)
}

fn cmd_vk(out: &Path) {
    std::fs::create_dir_all(out).unwrap();
    for (name, cap, m, t) in [("gk_384_128", 384usize, 128usize, 16usize), ("gk_768_512", 768, 512, 2)] {
        let t0 = Instant::now();
        let noop = gk_noop(gk_params(cap, m));
        let lv = postcard::to_allocvec(&leaf_vk(&noop)).unwrap();
        let rv = postcard::to_allocvec(&derive_forest_root_vk(noop, t)).unwrap();
        write(&out.join(format!("{name}_leaf_vk.bin")), &lv);
        write(&out.join(format!("{name}_root_vk_t{t}.bin")), &rv);
        println!(
            "XVK {name} leaf_vk bytes={} fp={} root_vk(t={t}) bytes={} fp={} ({:.1} s)",
            lv.len(),
            md5ish(&lv),
            rv.len(),
            md5ish(&rv),
            t0.elapsed().as_secs_f64()
        );
    }
    let t0 = Instant::now();
    let bp = BloomOmcParams { k: 7, log_w: 14, batch: 256 };
    bp.check().expect("bloom params");
    let noop = bloom_omc_noop_leaf_commit(bp, composition_expose(), CommitMode::Hiding);
    let lv = postcard::to_allocvec(&leaf_vk(&noop)).unwrap();
    let rv = postcard::to_allocvec(&derive_forest_root_vk(noop, 8)).unwrap();
    write(&out.join("bloom_k7_w14_256_leaf_vk.bin"), &lv);
    write(&out.join("bloom_k7_w14_256_root_vk_t8.bin"), &rv);
    println!(
        "XVK bloom_k7_w14_256 leaf_vk bytes={} fp={} root_vk(t=8) bytes={} fp={} ({:.1} s)",
        lv.len(),
        md5ish(&lv),
        rv.len(),
        md5ish(&rv),
        t0.elapsed().as_secs_f64()
    );
}

/// Native chain over t leaves of m AOL keys: (per-leaf value batches, states S_0..S_t).
fn chain(p: GkbParams, t: usize) -> (Vec<Vec<u32>>, Vec<Gk2State>) {
    let k = keys();
    let mut st = Gk2State::empty(p);
    let mut states = vec![st.clone()];
    let mut batches = Vec::new();
    for j in 0..t {
        let vals = gk_vals_of(&k[j * p.batch..(j + 1) * p.batch]);
        st = apply_batch2(&st, &vals);
        states.push(st.clone());
        batches.push(vals);
    }
    (batches, states)
}

fn cmd_prove(dir: &Path, cap: usize, m: usize, t: usize) {
    std::fs::create_dir_all(dir).unwrap();
    let p = gk_params(cap, m);
    let pc = ProverCommit::hiding(SaltSeed::for_tests(1));
    let fam = CommitFamily::GreenwaldKhanna;
    let (batches, states) = chain(p, t);
    let mut leaf = build_gkb2_leaf_commit(p, composition_expose(), default_binding(), pc.mode());
    let mut forest = ForestCascade::with_options(1, false, None);
    let t0 = Instant::now();
    for (j, vals) in batches.iter().enumerate() {
        let ti = j as u64 + 1;
        let lp = leaf.prove_epoch_commit(ti, states[j].clone(), vals.clone(), &pc.openings(fam, ti));
        let b = postcard::to_allocvec(&lp.output.0).unwrap();
        write(&dir.join(format!("leaf_{j:04}.bin")), &b);
        println!("XPROVE leaf t={ti} bytes={} fp={}", b.len(), md5ish(&b));
        forest.push(lp.output);
    }
    let (root, merges) = forest.finalize();
    let rb = postcard::to_allocvec(root.proof()).unwrap();
    write(&dir.join("root.bin"), &rb);
    println!(
        "XPROVE root t={t} merges(finalize)={merges} bytes={} fp={} total {:.1} s",
        rb.len(),
        md5ish(&rb),
        t0.elapsed().as_secs_f64()
    );
}

fn cmd_verify(dir: &Path, cap: usize, m: usize, t: usize) {
    let p = gk_params(cap, m);
    let pc = ProverCommit::hiding(SaltSeed::for_tests(1));
    let fam = CommitFamily::GreenwaldKhanna;
    let (_, states) = chain(p, t);
    let t0 = Instant::now();
    let noop = gk_noop(p);
    let lvk = leaf_vk(&noop);
    let rvk = derive_forest_root_vk(noop, t);
    println!("XVERIFY VKs derived locally in {:.1} s", t0.elapsed().as_secs_f64());
    let mut ok = true;
    for j in 0..t {
        let b = std::fs::read(dir.join(format!("leaf_{j:04}.bin"))).expect("read leaf");
        let proof: Proof = postcard::from_bytes(&b).expect("decode leaf");
        let r = verify_leaf_proof_pinned(&proof, &lvk);
        let (i, f) = read_exposed_boundary_proof(&proof);
        let want_i = commit_gk2_state_with(&states[j], CommitMode::Hiding, &pc.state_salt(fam, j as u64)).0;
        let want_f = commit_gk2_state_with(&states[j + 1], CommitMode::Hiding, &pc.state_salt(fam, j as u64 + 1)).0;
        let bnd = i.0 == want_i && f.0 == want_f;
        println!("XVERIFY leaf t={} fp={} verify={:?} boundary_eq_native={bnd}", j + 1, md5ish(&b), r);
        ok &= r.is_ok() && bnd;
    }
    let b = std::fs::read(dir.join("root.bin")).expect("read root");
    let proof: Proof = postcard::from_bytes(&b).expect("decode root");
    let t1 = Instant::now();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_bound_stark_proof_pinned(&proof, &rvk)));
    let (i, f) = read_exposed_boundary_proof(&proof);
    let want_i = commit_gk2_state_with(&states[0], CommitMode::Hiding, &pc.state_salt(fam, 0)).0;
    let want_f = commit_gk2_state_with(&states[t], CommitMode::Hiding, &pc.state_salt(fam, t as u64)).0;
    let bnd = i.0 == want_i && f.0 == want_f;
    println!(
        "XVERIFY root t={t} fp={} verify={} ({:.3} s) boundary_eq_native={bnd}",
        md5ish(&b),
        if r.is_ok() { "ok" } else { "FAILED" },
        t1.elapsed().as_secs_f64()
    );
    ok &= r.is_ok() && bnd;
    println!("XVERIFY RESULT {}", if ok { "ALL_OK" } else { "FAIL" });
    if !ok {
        std::process::exit(1);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let u = |i: usize| a.get(i).and_then(|s| s.parse::<usize>().ok()).expect("usage: see the file header");
    let d = PathBuf::from(a.get(2).expect("dir"));
    match a.get(1).map(String::as_str) {
        Some("vk") => cmd_vk(&d),
        Some("prove") => cmd_prove(&d, u(3), u(4), u(5)),
        Some("verify") => cmd_verify(&d, u(3), u(4), u(5)),
        _ => panic!("usage: xverify vk|prove|verify <dir> [cap m t]"),
    }
}
