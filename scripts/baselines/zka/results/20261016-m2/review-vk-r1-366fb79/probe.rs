//! Reviewer probe (not committed): bloom_omc leaf / decoder / root VKs.
use zksketch::commitment::hiding::CommitMode;
use zksketch::decode::bloom::bloom_decode_vk_commit;
use zksketch::recursion::recursive::expose_forest::{leaf_vk, root_vk_deriver};
use zksketch::recursion::recursive::noop_leaf::bloom_omc_noop_leaf_commit;
use zksketch::recursion::recursive::root_vk::ForestShape;
use zksketch::recursion::recursive::statement::Expose;
use zksketch::sketch::bloom_omc::BloomOmcParams;

#[test]
fn rev_probe_bloom_omc_vks() {
    let p = BloomOmcParams { k: 3, log_w: 7, batch: 4 };
    for mode in [CommitMode::Plain, CommitMode::Hiding] {
        for e in [Expose::None, Expose::Boundary, Expose::Interval] {
            let pr = bloom_omc_noop_leaf_commit(p, e, mode);
            println!("PROBE leaf {mode:?} {e:?} {:?}", leaf_vk(&pr));
        }
        println!("PROBE decoder {mode:?} {:?}", bloom_decode_vk_commit(p, mode));
        for e in [Expose::Boundary, Expose::Interval] {
            let pr = bloom_omc_noop_leaf_commit(p, e, mode);
            let mut d = root_vk_deriver(pr);
            for (name, shape) in [
                ("forest2", ForestShape::dist_forest(2, 1)),
                ("chain3", ForestShape::chain(3)),
                ("dist3x2", ForestShape::dist_forest(3, 2)),
            ] {
                println!("PROBE root {mode:?} {e:?} {name} {:?}", d.root_vk(&shape));
            }
        }
    }
}
