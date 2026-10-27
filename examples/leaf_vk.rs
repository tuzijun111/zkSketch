//! Prints the verification keys (`vk_pin_values`: the preprocessed commitment
//! and proof metadata every proof of a prebuilt leaf carries) of the deployed
//! Count-Min `omc`, Misra--Gries (`ss_final_full`) and Greenwald--Khanna stable leaves at the given shapes,
//! one line per leaf with a short digest, so that a change to a builder can
//! be checked for VK drift: run it before and after and diff the output.
//!
//! ```bash
//! cargo run --release --example leaf_vk
//! # shapes as examples/exp_operator.rs: EXP_D=3 EXP_W=1024 EXP_M_CM=1024
//! #   EXP_SS_CAP=1024 EXP_M_MG=4096  EXP_GK_CAP=768 EXP_GK_S=51 EXP_M_GK=512
//! ```
use zksketch::commitment::hiding::CommitMode;
use zksketch::recursion::recursive::statement::composition_expose;
use zksketch::sketch::bind::default_binding;
use zksketch::sketch::countmin_omc::{build_countmin_omc_leaf_commit, CmOmcParams};
use zksketch::sketch::gk_bandmerge::{build_gkb2_leaf_rounds, default_gk_rounds, GkbParams};
use zksketch::sketch::ss_final_full::{build_ss_full_leaf_commit, SsFullParams};

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(d)
}

/// FNV-1a over the debug rendering of the VK values: a stable one-line digest.
fn digest(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn main() {
    let mode = CommitMode::Hiding;
    let d = env_usize("EXP_D", 3);
    let w = env_usize("EXP_W", 1024);
    let m_cm = env_usize("EXP_M_CM", 1024);
    let cap = env_usize("EXP_GK_CAP", 768);
    let s = env_usize("EXP_GK_S", 51) as u64;
    let m_gk = env_usize("EXP_M_GK", 512);

    let cm = build_countmin_omc_leaf_commit(CmOmcParams { d, w, batch: m_cm }, composition_expose(), default_binding(), mode);
    let vk = cm.vk_pin_values();
    let text = format!("{vk:?}");
    println!("cm d={d} w={w} m={m_cm} tables={:?} vk_len={} vk_digest={:016x}", cm.table_rows(), vk.len(), digest(&text));
    println!("cm vk={text}");

    let cap_ss = env_usize("EXP_SS_CAP", 1024);
    let m_mg = env_usize("EXP_M_MG", 4096);
    let mg = build_ss_full_leaf_commit(SsFullParams { capacity: cap_ss, batch: m_mg }, composition_expose(), mode);
    let vk = mg.vk_pin_values();
    let text = format!("{vk:?}");
    println!("mg cap={cap_ss} m={m_mg} tables={:?} vk_len={} vk_digest={:016x}", mg.table_rows(), vk.len(), digest(&text));
    println!("mg vk={text}");

    let gk = build_gkb2_leaf_rounds(
        GkbParams { capacity: cap, batch: m_gk, s },
        composition_expose(),
        default_binding(),
        mode,
        default_gk_rounds(),
    );
    let vk = gk.vk_pin_values();
    let text = format!("{vk:?}");
    println!("gk cap={cap} s={s} m={m_gk} tables={:?} vk_len={} vk_digest={:016x}", gk.table_rows(), vk.len(), digest(&text));
    println!("gk vk={text}");
}
