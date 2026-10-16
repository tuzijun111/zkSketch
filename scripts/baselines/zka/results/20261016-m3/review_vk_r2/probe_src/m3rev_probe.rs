//! Reviewer probe (scratch only): fingerprints of what M3 must not move,
//! computed identically on the base export and on the head export.
use p3_field::{BasedVectorSpace, PrimeField32};

use crate::commitment::hiding::{CommitFamily, CommitMode, Openings, SaltBb, SaltSeed};
use crate::config::{Challenge, Val};
use crate::decode::gk_bandmerge::{gk2_decode_vk_commit, Gkb2DecodeParams};
use crate::decode::ReleasePolicy;
use crate::experiments::dist_compose::{derive_dist_leaf_vk, derive_dist_root_vk};
use crate::experiments::stream_compose::{StreamFamily, StreamMode, StreamShape};
use crate::recursion::recursive::statement::Expose;
use crate::sketch::bind::Binding;
use crate::sketch::gk_bandmerge::*;

fn fnv(vals: impl IntoIterator<Item = u64>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for v in vals {
        for b in v.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}
fn fv(v: &[Val]) -> u64 {
    fnv(v.iter().map(|x| x.as_canonical_u32() as u64))
}
fn fc(v: &[Challenge]) -> u64 {
    fnv(v.iter().flat_map(|c| {
        <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
            .iter()
            .map(|x| x.as_canonical_u32() as u64)
            .collect::<Vec<_>>()
    }))
}
fn fs<T: serde::Serialize>(s: &T) -> u64 {
    fnv(postcard::to_allocvec(s).unwrap().into_iter().map(|b| b as u64))
}

fn shape(cap: usize, gk_s: u64) -> StreamShape {
    StreamShape {
        d: 4,
        w: 8,
        b: 4,
        capacity: cap,
        gk_s,
        bloom_k: 3,
        bloom_log_w: 7,
        kmv_k: 4,
        /*GKR*/
    }
}

#[test]
fn m3rev_small() {
    let mut out: Vec<(String, u64, u64)> = Vec::new();
    // Native: genesis / encodings on a different state than the implementer's.
    let params = GkbParams { capacity: 12, batch: 6, s: 3 };
    let mut st = Gk2State::empty(params);
    let mut x = 0x1234_5678u64;
    for t in 1..=5u64 {
        let vals: Vec<u32> = (0..6)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                ((x >> 33) % 5000) as u32
            })
            .collect();
        let salt = Openings::for_leaf(&SaltSeed::for_tests(99), CommitFamily::GreenwaldKhanna, t);
        let nb = fv(&commit_gk2_batch_with(&vals, 6, st.n, CommitMode::Hiding, &salt.batch).0);
        st = apply_batch2(&st, &vals);
        out.push((format!("native t={t} Com(S) plain"), fv(&commit_gk2_state(&st).0), nb));
        out.push((
            format!("native t={t} Com(S) hiding"),
            fv(&commit_gk2_state_with(&st, CommitMode::Hiding, &salt.final_).0),
            st.n,
        ));
    }
    out.push(("genesis hiding".into(), fv(&commit_gk2_state_with(&Gk2State::empty(params), CommitMode::Hiding, &SaltBb::ZERO).0), 0));
    // Auditor-derived leaf / root VKs at the dist test shape (cap 4, m 4, s 2).
    let sh = shape(4, 2);
    for mode in [CommitMode::Plain, CommitMode::Hiding] {
        let lv = derive_dist_leaf_vk(StreamFamily::GkBandmerge2, &sh, 4, mode);
        out.push((format!("leaf vk {mode:?}"), fc(&lv.commitment), fs(lv.shape.as_ref().unwrap())));
        for (sm, t, mach) in [(StreamMode::Forest, 3usize, 2usize), (StreamMode::Chain, 3, 1), (StreamMode::Forest, 4, 1)] {
            let rv = derive_dist_root_vk(StreamFamily::GkBandmerge2, &sh, 4, sm, t, mach, mode);
            out.push((format!("root vk {mode:?} {sm:?} t={t} mach={mach}"), fc(&rv.commitment), fs(rv.shape.as_ref().unwrap())));
        }
    }
    // Library builders at a mid shape, all bindings / layouts / modes.
    let p = GkbParams { capacity: 16, batch: 8, s: 3 };
    for e in [Expose::None, Expose::Boundary, Expose::Interval] {
        for b in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            for mode in [CommitMode::Plain, CommitMode::Hiding] {
                let l = build_gkb2_leaf_commit(p, e, b, mode);
                out.push((format!("lib leaf c16m8 {e:?} {b:?} {mode:?}"), fc(&l.vk_pin_values()), l.trace_rows()));
            }
        }
    }
    for b in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
        for mode in [CommitMode::Plain, CommitMode::Hiding] {
            let d = gk2_decode_vk_commit(Gkb2DecodeParams { capacity: 16, release: ReleasePolicy::Identity }, b, mode);
            out.push((format!("decoder c16 {b:?} {mode:?}"), fc(&d.commitment), 0));
        }
    }
    for (k, a, b) in &out {
        println!("M3REV {k} = {a:#018x} {b:#x}");
    }
}

#[test]
fn m3rev_deployed() {
    // Config B as the harness derives it (cap 768, m 512, s 51), both modes.
    let sh = shape(768, 51);
    let mut out: Vec<(String, u64, u64)> = Vec::new();
    for mode in [CommitMode::Plain, CommitMode::Hiding] {
        let lv = derive_dist_leaf_vk(StreamFamily::GkBandmerge2, &sh, 512, mode);
        out.push((format!("B leaf vk {mode:?}"), fc(&lv.commitment), fs(lv.shape.as_ref().unwrap())));
        let d = gk2_decode_vk_commit(Gkb2DecodeParams { capacity: 768, release: ReleasePolicy::Identity }, Binding::Semantic, mode);
        out.push((format!("B decoder {mode:?}"), fc(&d.commitment), 0));
    }
    let rv = derive_dist_root_vk(StreamFamily::GkBandmerge2, &sh, 512, StreamMode::Forest, 4, 1, CommitMode::Hiding);
    out.push(("B root vk Hiding Forest t=4".into(), fc(&rv.commitment), fs(rv.shape.as_ref().unwrap())));
    for (k, a, b) in &out {
        println!("M3REV {k} = {a:#018x} {b:#x}");
    }
}

// ── Round 2 additions: the Goldilocks GK family (its native apply_batch2
// changed in 3b5e499; its circuit must not move) ──
fn fcg(v: &[crate::config_gl::Challenge]) -> u64 {
    use p3_field::PrimeField64;
    fnv(v.iter().flat_map(|c| {
        <crate::config_gl::Challenge as BasedVectorSpace<crate::config_gl::Val>>::as_basis_coefficients_slice(c)
            .iter()
            .map(|x| x.as_canonical_u64())
            .collect::<Vec<_>>()
    }))
}
fn fgv(v: &[crate::config_gl::Val]) -> u64 {
    use p3_field::PrimeField64;
    fnv(v.iter().map(|x| x.as_canonical_u64()))
}

#[test]
fn m3rev_gl() {
    use crate::commitment::hiding::SaltGl;
    use crate::experiments::dist_compose::derive_dist_leaf_vk_gl;
    use crate::sketch::gk_bandmerge_gl as gl;
    let mut out: Vec<(String, u64, u64)> = Vec::new();
    let params = gl::GkbParams { capacity: 12, batch: 6, s: 3 };
    let mut st = gl::Gk2State::empty(params);
    let mut x = 0x9abc_def0u64;
    for t in 1..=5u64 {
        let vals: Vec<u32> = (0..6)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                ((x >> 33) % 5000) as u32
            })
            .collect();
        let nb = fgv(&gl::commit_gk2_batch_with(&vals, 6, st.n, CommitMode::Hiding, &SaltGl::ZERO).0);
        st = gl::apply_batch2(&st, &vals);
        out.push((format!("gl native t={t} Com(S) plain"), fgv(&gl::commit_gk2_state(&st).0), nb));
        out.push((format!("gl native t={t} Com(S) hiding0"), fgv(&gl::commit_gk2_state_with(&st, CommitMode::Hiding, &SaltGl::ZERO).0), st.n));
    }
    let p = gl::GkbParams { capacity: 16, batch: 8, s: 3 };
    for e in [Expose::None, Expose::Boundary, Expose::Interval] {
        for b in [Binding::Legacy, Binding::Semantic, Binding::Bound] {
            for mode in [CommitMode::Plain, CommitMode::Hiding] {
                let l = gl::build_gkb2_leaf_commit(p, e, b, mode);
                out.push((format!("gl lib leaf c16m8 {e:?} {b:?} {mode:?}"), fcg(&l.vk_pin_values()), 0));
            }
        }
    }
    let sh = shape(4, 2);
    for mode in [CommitMode::Plain, CommitMode::Hiding] {
        let lv = derive_dist_leaf_vk_gl(StreamFamily::GkBandmerge2Gl, &sh, 4, mode);
        out.push((format!("gl derived leaf vk {mode:?}"), fcg(&lv.commitment), fs(lv.shape.as_ref().unwrap())));
    }
    for (k, a, b) in &out {
        println!("M3REV {k} = {a:#018x} {b:#x}");
    }
}
