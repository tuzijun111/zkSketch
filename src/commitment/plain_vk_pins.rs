//! Regression pins: the `Plain` (non-hiding) VKs are byte-identical to the
//! VKs of the tree before the hiding commitments (revision B2) were merged.
//!
//! The B2 merge routes every plain circuit through a `*_commit` builder or
//! VK derivation with [`CommitMode::Plain`] (no salt allocated,
//! `commit_hash_bound(None)` = the pre-B2 sponge). The other plain-VK tests
//! compare those paths with builders that delegate to the same code, so a
//! change to the shared commitment gadgets (`commit_hash_bound`,
//! `salted_hash_inputs`, the tag constants) that also moved the plain path
//! would pass them. These literals would not: each is the fingerprint
//! `(FNV-1a of the VK commitment's coefficients, FNV-1a of the postcard'd
//! BoundProofShape)` recorded on the pre-merge tree (main @ 3e911ff, built
//! side by side) through the APIs that existed there (`*_decode_vk`,
//! `*_noop_leaf_expose`), at small shapes. They cover the deployed decoders
//! (Count-Min, HLL omc, SpaceSaving, GK bandmerge2, Bloom) and the deployed
//! no-op leaves under both composable layouts and all three bindings. A
//! deliberate circuit change, a Plonky3-fork bump or a new `BoundProofShape`
//! field moves a pin too; re-pin only once that is confirmed as the cause.

use p3_circuit_prover::BatchStarkProof;
use p3_field::{BasedVectorSpace, PrimeField32};

use crate::commitment::hiding::CommitMode;
use crate::config::{Challenge, Val};
use crate::decode::bloom::{bloom_decode_vk, bloom_decode_vk_commit};
use crate::decode::countmin::{cm_decode_vk, cm_decode_vk_commit, CmDecodeParams};
use crate::decode::gk_bandmerge::{gk2_decode_vk, gk2_decode_vk_commit, Gkb2DecodeParams};
use crate::decode::hyperloglog::{hll_omc_decode_vk, hll_omc_decode_vk_commit, HllDecodeParams};
use crate::decode::spacesaving::{ss_decode_vk, ss_decode_vk_commit, SsDecodeParams};
use crate::decode::{DecodeVk, ReleasePolicy};
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::vk_pin_values;
use crate::recursion::recursive::noop_leaf::{
    bloom_omc_noop_leaf_commit, cm_omc_noop_leaf_commit, gk2_noop_leaf_commit,
    hll_omc_noop_leaf_commit, kmv_noop_leaf_expose, ss_full_noop_leaf_commit,
};
use crate::recursion::recursive::root_vk::{bound_proof_shape, BoundProofShape};
use crate::recursion::recursive::statement::Expose;
use crate::sketch::bind::Binding;
use crate::sketch::bloom_omc::BloomOmcParams;
use crate::sketch::countmin_omc::CmOmcParams;
use crate::sketch::gk_bandmerge::GkbParams;
use crate::sketch::hll_omc::HllOmcParams;
use crate::sketch::kmv::KmvParams;
use crate::sketch::ss_final_full::SsFullParams;

type Pin = (u64, u64);

fn fnv1a64(bytes: impl IntoIterator<Item = u8>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn fingerprint(commitment: &[Challenge], shape: &BoundProofShape) -> Pin {
    let c = fnv1a64(commitment.iter().flat_map(|c| {
        <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
            .iter()
            .flat_map(|x| x.as_canonical_u32().to_le_bytes())
            .collect::<Vec<u8>>()
    }));
    (c, fnv1a64(postcard::to_allocvec(shape).expect("serialize shape")))
}

fn of_vk(vk: &DecodeVk) -> Pin {
    fingerprint(&vk.commitment, vk.shape.as_ref().expect("a derived VK carries its shape"))
}

fn of_proof(p: &BatchStarkProof<ConfigWithFriParams>) -> Pin {
    fingerprint(&vk_pin_values(p), &bound_proof_shape(p))
}

fn check(what: &str, got: Pin, pin: Pin) {
    assert_eq!(
        got, pin,
        "{what}: Plain VK moved from its pre-B2 value (got (0x{:016x}, 0x{:016x}))",
        got.0, got.1
    );
}

const BLOOM: BloomOmcParams = BloomOmcParams { k: 3, log_w: 7, batch: 4 };
const BINDINGS: [Binding; 3] = [Binding::Legacy, Binding::Semantic, Binding::Bound];
const EXPOSES: [Expose; 2] = [Expose::Boundary, Expose::Interval];

/// Index of `b` in [`BINDINGS`].
fn bi(b: Binding) -> usize {
    BINDINGS.iter().position(|x| *x == b).unwrap()
}

/// Index of `e` in [`EXPOSES`].
fn ei(e: Expose) -> usize {
    EXPOSES.iter().position(|x| *x == e).unwrap()
}

/// The Plain decoder VKs (cm d=4 w=8; hll b=4; ss capacity=4 c=1; gk2
/// capacity=4; Bloom k=3 log_w=7), through the B2 `*_decode_vk_commit`
/// derivation with [`CommitMode::Plain`] and through the pre-B2 entry point.
#[test]
fn plain_decode_vks_are_pinned() {
    // Per binding [Legacy, Semantic, Bound].
    const CM: [Pin; 3] = [
        (0x0380_967e_cd80_c80f, 0x22ea_510a_ed75_b500),
        (0x75b3_fd42_f1f9_7cf6, 0x5bba_5323_64ff_a31e),
        (0x68c0_5982_e5fd_656f, 0xcdef_af16_b2aa_3adb),
    ];
    const HLL: [Pin; 3] = [
        (0x6ba3_8d13_fb73_225e, 0xe2c2_1843_7df2_4d29),
        (0x8636_a1a1_35f9_2dcd, 0x934d_6763_371d_1e41),
        (0xcfdb_4792_dfec_3b69, 0xf45f_b7a4_086f_8d86),
    ];
    const SS: [Pin; 3] = [
        (0xda12_d19d_4b94_bf85, 0xc67a_1da8_abce_3602),
        (0xd927_61c0_8478_0f4a, 0x5bc6_4477_0a29_1c80),
        (0xd927_61c0_8478_0f4a, 0x5bc6_4477_0a29_1c80),
    ];
    const GK2: [Pin; 3] = [
        (0x72d4_26a8_cffd_2c9a, 0x8915_e947_5caf_76ef),
        (0xa250_a733_9fcf_a893, 0xad53_7bad_6672_e995),
        (0xa250_a733_9fcf_a893, 0xad53_7bad_6672_e995),
    ];
    const BLOOM_DEC: Pin = (0xb714_98cf_245e_8b1c, 0x93c3_4097_d658_f723);

    let id = ReleasePolicy::Identity;
    let plain = CommitMode::Plain;
    check("bloom decoder (commit)", of_vk(&bloom_decode_vk_commit(BLOOM, plain)), BLOOM_DEC);
    check("bloom decoder", of_vk(&bloom_decode_vk(BLOOM)), BLOOM_DEC);
    for b in BINDINGS {
        let cm = CmDecodeParams { d: 4, w: 8, release: id };
        check(&format!("cm decoder {b:?} (commit)"), of_vk(&cm_decode_vk_commit(cm, b, plain)), CM[bi(b)]);
        check(&format!("cm decoder {b:?}"), of_vk(&cm_decode_vk(cm, b)), CM[bi(b)]);
        let hll = HllDecodeParams { b: 4, release: id };
        check(&format!("hll decoder {b:?} (commit)"), of_vk(&hll_omc_decode_vk_commit(hll, b, plain)), HLL[bi(b)]);
        check(&format!("hll decoder {b:?}"), of_vk(&hll_omc_decode_vk(hll, b)), HLL[bi(b)]);
        let ss = SsDecodeParams { capacity: 4, c: 1, release: id };
        check(&format!("ss decoder {b:?} (commit)"), of_vk(&ss_decode_vk_commit(ss, b, plain)), SS[bi(b)]);
        check(&format!("ss decoder {b:?}"), of_vk(&ss_decode_vk(ss, b)), SS[bi(b)]);
        let gk = Gkb2DecodeParams { capacity: 4, release: id };
        check(&format!("gk2 decoder {b:?} (commit)"), of_vk(&gk2_decode_vk_commit(gk, b, plain)), GK2[bi(b)]);
        check(&format!("gk2 decoder {b:?}"), of_vk(&gk2_decode_vk(gk, b)), GK2[bi(b)]);
    }
}

/// The Plain no-op leaf VKs (the VK of every real leaf of the shape) under
/// the composable layouts [Boundary, Interval], through the harness's B2
/// path (`*_noop_leaf_commit` with [`CommitMode::Plain`]): cm d=4 w=8, hll
/// b=4, gk2 capacity=4 s=2, ss capacity=4, Bloom k=3 log_w=7, KMV k=4, all
/// at batch 4. (On the pre-B2 tree GK's leaf took its binding from
/// `ZKSKETCH_BINDING`; its pins were recorded once per binding.)
#[test]
fn plain_noop_leaf_vks_are_pinned() {
    // [expose][binding].
    const CM: [[Pin; 3]; 2] = [
        [
            (0xd860_293f_3063_4d6f, 0x8437_d470_6774_eb55),
            (0x6bca_7f28_0630_886b, 0x92d6_810b_645d_9d2a),
            (0x61a3_6a7e_068f_f498, 0x1f8f_21d1_e5d0_e27e),
        ],
        [
            (0x7c13_5a8d_44a6_3f57, 0x917f_ceb2_cda3_d552),
            (0x876a_5133_3c1a_ecb9, 0xe8e9_fc04_633f_81a0),
            (0x2444_65d9_a664_0117, 0xddc4_b114_50ed_3764),
        ],
    ];
    const HLL: [[Pin; 3]; 2] = [
        [
            (0xde05_022f_7c51_52a3, 0x2a5d_4fd2_26e1_5a57),
            (0xaab8_33a3_851b_10dc, 0xb770_e70d_8789_15fa),
            (0xd42f_7abb_467b_17fc, 0xcb96_4746_40eb_3f9c),
        ],
        [
            (0x95d6_150e_f72e_005e, 0x9f50_d546_d9c5_d591),
            (0x4390_5c17_9f55_88cd, 0x9bb3_5d41_af97_c804),
            (0x5ed1_1b7f_c457_454f, 0x54e3_416d_8fe3_ff4e),
        ],
    ];
    const GK2: [[Pin; 3]; 2] = [
        [
            (0xc928_a4cd_0a04_86ce, 0xb2ba_cdbf_bf08_5515),
            (0x4e26_c2b7_f76a_72ae, 0xa56f_e2c6_f68c_c99b),
            (0x4e26_c2b7_f76a_72ae, 0xa56f_e2c6_f68c_c99b),
        ],
        [
            (0xff92_51d8_2504_fad9, 0xe889_db25_52dd_8b3c),
            (0x1b65_790c_9269_6713, 0x3600_52d3_2744_da3d),
            (0x1b65_790c_9269_6713, 0x3600_52d3_2744_da3d),
        ],
    ];
    const KMV: [[Pin; 3]; 2] = [
        [
            (0xce0b_5633_af82_58ad, 0x7a56_5484_532d_6ef8),
            (0xce0b_5633_af82_58ad, 0x7a56_5484_532d_6ef8),
            (0x0089_2179_7bdd_2282, 0x13fa_fc4c_890a_8b27),
        ],
        [
            (0xbc37_91ed_71b1_8c11, 0x68c4_7ade_4561_49d8),
            (0xbc37_91ed_71b1_8c11, 0x68c4_7ade_4561_49d8),
            (0xfd5a_bc10_a728_72e5, 0x03e8_22ac_588e_2f97),
        ],
    ];
    // [expose]; neither depends on the binding.
    const SS: [Pin; 2] = [
        (0xbc99_7939_79d9_097c, 0xc6bb_97b9_3580_ed22),
        (0xd1c6_1ed8_f8b6_d76d, 0x3d3d_d29f_33bb_ecdc),
    ];
    const BLOOM_LEAF: [Pin; 2] = [
        (0x29c8_fe41_ab7b_fccb, 0x5241_0950_c3f4_3623),
        (0xe063_6f18_af7a_6404, 0x86cd_6b7d_13c9_daf1),
    ];

    let plain = CommitMode::Plain;
    for e in EXPOSES {
        let ss = ss_full_noop_leaf_commit(SsFullParams { capacity: 4, batch: 4 }, e, plain);
        check(&format!("ss leaf {e:?}"), of_proof(&ss), SS[ei(e)]);
        let bl = bloom_omc_noop_leaf_commit(BLOOM, e, plain);
        check(&format!("bloom leaf {e:?}"), of_proof(&bl), BLOOM_LEAF[ei(e)]);
        for b in BINDINGS {
            let cm = cm_omc_noop_leaf_commit(CmOmcParams { d: 4, w: 8, batch: 4 }, e, b, plain);
            check(&format!("cm leaf {e:?} {b:?}"), of_proof(&cm), CM[ei(e)][bi(b)]);
            let hll = hll_omc_noop_leaf_commit(HllOmcParams { b: 4, batch: 4 }, e, b, plain);
            check(&format!("hll leaf {e:?} {b:?}"), of_proof(&hll), HLL[ei(e)][bi(b)]);
            let gk = gk2_noop_leaf_commit(GkbParams { capacity: 4, batch: 4, s: 2 }, e, b, plain);
            check(&format!("gk2 leaf {e:?} {b:?}"), of_proof(&gk), GK2[ei(e)][bi(b)]);
            let kmv = kmv_noop_leaf_expose(KmvParams { k: 4, batch: 4 }, e, b);
            check(&format!("kmv leaf {e:?} {b:?}"), of_proof(&kmv), KMV[ei(e)][bi(b)]);
        }
    }
}
