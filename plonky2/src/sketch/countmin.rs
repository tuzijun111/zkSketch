//! Plaintext Count-Min sketch (paper §5.1/§5.4, Pattern A linear).
//!
//! Port of `../src/sketch/countmin.rs`. Over Goldilocks each counter is
//! a single field element, so the commitment is just Poseidon over the row-major
//! flattened counters — no BabyBear cell-packing/alignment dance.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;

use crate::commitment::commit;
use crate::config::F;

/// Fixed per-row hash multipliers (odd 64-bit constants).
const HASH_PRIMES: [u64; 16] = [
    0x9E37_79B9_7F4A_7C15,
    0xC2B2_AE3D_27D4_EB4F,
    0x1656_67B1_9E37_79F9,
    0xD6E8_FEB8_6659_FD93,
    0xA0761D6478BD642F,
    0xE7037ED1A0B428DB,
    0x8EBC6AF09C88C6E3,
    0x5899_65CB_7174_8B01,
    0xBF58476D1CE4E5B9,
    0x94D0_49BB_1331_11EB,
    0x2545F4914F6CDD1D,
    0xFF51_AFD7_ED55_8CCD,
    0xC4CE_B9FE_1A85_EC53,
    0x1234_5678_9ABC_DEF1,
    0xDEAD_BEEF_CAFE_BABE,
    0xF00D_FACE_1357_9BDF,
];

/// Fixed per-row XOR offsets.
const HASH_OFFSETS: [u64; 16] = [
    0xDEAD_BEEF_DEAD_BEEF,
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0xA5A5_A5A5_A5A5_A5A5,
    0x5A5A_5A5A_5A5A_5A5A,
    0xCAFE_BABE_CAFE_BABE,
    0x1357_9BDF_2468_ACE0,
    0x0F0F_0F0F_0F0F_0F0F,
    0xF0F0_F0F0_F0F0_F0F0,
    0xAAAA_5555_AAAA_5555,
    0x3333_CCCC_3333_CCCC,
    0x7777_8888_7777_8888,
    0x9999_6666_9999_6666,
    0xBBBB_4444_BBBB_4444,
    0xDDDD_2222_DDDD_2222,
    0xEEEE_1111_EEEE_1111,
];

/// Map a key to its column in row `row` (mirrors the original `hash_cell`).
pub fn hash_cell(row: usize, key: u64, w: usize) -> usize {
    let mixed = key.wrapping_mul(HASH_PRIMES[row]) ^ HASH_OFFSETS[row];
    (mixed % w as u64) as usize
}

/// Count-Min shape: `d` rows × `w` columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountMinParams {
    pub d: usize,
    pub w: usize,
}

/// One streamed record: increment `key`'s cells by `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountMinUpdate {
    pub key: u64,
    pub value: u64,
}

/// A `d × w` counter matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountMinState {
    pub counters: Vec<Vec<u64>>,
    pub d: usize,
    pub w: usize,
}

impl CountMinState {
    pub fn new(p: &CountMinParams) -> Self {
        Self { counters: vec![vec![0u64; p.w]; p.d], d: p.d, w: p.w }
    }

    /// Apply one record: bump exactly `d` cells (one per row).
    pub fn update(&mut self, u: &CountMinUpdate) {
        for row in 0..self.d {
            let col = hash_cell(row, u.key, self.w);
            self.counters[row][col] = self.counters[row][col].saturating_add(u.value);
        }
    }

    /// Row-major flattened counters as field elements (the commit pre-image).
    pub fn cells(&self) -> Vec<F> {
        self.counters.iter().flatten().map(|&c| F::from_canonical_u64(c)).collect()
    }

    /// Poseidon commitment of the state.
    pub fn commit(&self) -> HashOut<F> {
        commit(&self.cells())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_increments_d_cells() {
        let mut s = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        s.update(&CountMinUpdate { key: 7, value: 3 });
        let total: u64 = s.counters.iter().flatten().sum();
        assert_eq!(total, 2 * 3); // d=2 cells each +3
    }

    #[test]
    fn commit_changes_with_state() {
        let s0 = CountMinState::new(&CountMinParams { d: 2, w: 4 });
        let mut s1 = s0.clone();
        s1.update(&CountMinUpdate { key: 1, value: 1 });
        assert_ne!(s0.commit(), s1.commit());
        assert_eq!(s0.commit(), CountMinState::new(&CountMinParams { d: 2, w: 4 }).commit());
    }
}
