//! Temporary analysis helper: dump per-table (log2 height, main width) for the
//! HLL omc leaves (BabyBear vs Goldilocks) at the deployment shape.
//! Run with ZKS_DUMP_SHAPES=1.

fn main() {
    let b: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(14);
    let batch: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1 << 14);
    eprintln!("== shape b={b} batch={batch} expose=true ==");
    eprintln!("-- Goldilocks (hll_omc_gl) --");
    let _gl = zksketch::sketch::hll_omc_gl::build_hll_omc_leaf(
        zksketch::sketch::hll_omc_gl::HllOmcParams { b, batch },
        true,
    );
    eprintln!("-- BabyBear (hll_omc) --");
    let _bb = zksketch::sketch::hll_omc::build_hll_omc_leaf(
        zksketch::sketch::hll_omc::HllOmcParams { b, batch },
        true,
    );
    eprintln!("done");
}
