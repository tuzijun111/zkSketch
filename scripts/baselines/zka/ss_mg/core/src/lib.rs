#![no_std]

// zkSketch's SpaceSaving batch transition (mergeable Misra-Gries, top-s
// retention) as plain Rust for a RISC Zero guest: the matched-semantics
// counterpart of ../../spacesaving (which runs textbook per-record
// SpaceSaving with a sum-and-truncate merge, NOT what zkSketch certifies).
//
// One guest run = one zkSketch SS leaf statement:
//
//   read (S_old, raw batch keys)                    -- env::read_slice (headline guest ss_mg)
//                                                      or risc0 serde env::read, as the zka
//                                                      guests read (sensitivity guest ss_mg_serde)
//   Com_old   = SHA-256(tag, s, m, S_old rows)      -- unsalted, risc0-accelerated SHA-256
//   map keys                                        -- zkSketch ss_updates_of
//   Com_batch = SHA-256(tag, m, mapped batch rows)
//   S_new     = zkSketch apply_batch_ss_full(S_old, batch)
//   Com_new   = SHA-256(tag, s, m, S_new rows)
//   journal   = Com_old || Com_batch || Com_new     -- 96 bytes
//
// The rule and the representation are zkSketch's, read from
// src/sketch/ss_final_full.rs (build_ss, group_by_key, compress_from_gsorted,
// apply_batch_ss_full) and src/experiments/stream_compose.rs (ss_updates_of):
//
//   * state: exactly `capacity` rows of (key_lo, key_hi, count, active), u32
//     each -- zkSketch's flat_state_vals layout. Dummy rows are (0, 0, 0, 0).
//     Order: dummies first, then active rows by (count asc, key asc).
//   * batch record for raw key k: PAD_KEY (u32::MAX) -> the dummy (0, 0, 0, 0);
//     otherwise ((k & 0x1FFF_FFFF) | 1, 0, 1, 1). zkSketch's plain batches
//     (examples/exp_compose.rs batches_from) do not remap a real u32::MAX key,
//     so such a key is a dummy there too.
//   * union old rows || batch rows, group by key summing counts, count-sort the
//     grouped table by (active, count, key) ascending, tau = the count just
//     below the top-`capacity` cut (the (s+1)-th largest grouped count; 0 when
//     the union has at most `capacity` distinct keys), keep the top
//     `capacity`, subtract tau, and turn every counter that reaches 0 into a
//     dummy.
//
// The implementation is not a line-by-line port of build_ss. It sorts only
// active rows (dummy rows contribute nothing to any group) and packs each row
// into one u64 sort key. Two interchangeable sorts, chosen by an input word:
//   * SortAlgo::Radix (headline): stable LSD radix sorts of at most 11-bit
//     digits over one u32 word: the union by key, then the key-ordered grouped
//     table by count only (stability keeps ties key-ascending);
//   * SortAlgo::Std (sensitivity): core's sort_unstable (pdqsort) and, when the
//     union overflows, select_nth_unstable for the cut before sorting the kept
//     rows.
// Both produce zkSketch's exact row sequence on well-formed input (the host
// driver checks every run field by field against
// zksketch::sketch::ss_final_full::apply_batch_ss_full). The guest asserts
// well-formedness:
//   * an inactive row (or record) is the all-zero dummy;
//   * an active row has active = 1, key_hi = 0 and key != 0.
// zkSketch's keys are < 2^29 (its circuit range-checks them) and its dummy key is
// 0, so honest states and batches always satisfy both.
//
// Nothing here is oblivious: cycles depend on the data, as in every zka guest.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
#[cfg(target_os = "zkvm")]
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
#[cfg(not(target_os = "zkvm"))]
use rust_crypto::{Digest as _, Sha256};
use serde::{Deserialize, Serialize};

// Commitments hash u32 words as their in-memory bytes; the guest (riscv32) is
// little-endian, so the host must be too.
#[cfg(not(target_endian = "little"))]
compile_error!("ss-mg-core hashes u32 words as little-endian bytes");

/// zkSketch's split-batch pad sentinel (`stream_compose::PAD_KEY`).
pub const PAD_KEY: u32 = u32::MAX;
/// zkSketch's SS key mask (`ss_updates_of`: 29-bit keys, low bit forced to 1).
pub const KEY_MASK: u32 = 0x1FFF_FFFF;
/// u32 words per state row / batch record: (key_lo, key_hi, count|value, active).
pub const ROW_WORDS: usize = 4;

// Domain separators (ours; the zka guests tag their commitments the same way).
const TAG_SS_MG_STATE: &[u8] = b"ZKA_PORT_SS_MG_STATE_V1";
const TAG_SS_MG_BATCH: &[u8] = b"ZKA_PORT_SS_MG_BATCH_V1";

pub type Commit = [u8; 32];

/// Which sort the transition uses. Not committed: both give the same S_new.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortAlgo {
    /// LSD radix sort (headline).
    Radix = 0,
    /// core sort_unstable + select_nth_unstable (sensitivity).
    Std = 1,
}

impl SortAlgo {
    pub fn from_word(w: u32) -> Self {
        match w {
            0 => SortAlgo::Radix,
            1 => SortAlgo::Std,
            _ => panic!("unknown sort algorithm word"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            SortAlgo::Radix => "radix",
            SortAlgo::Std => "std",
        }
    }
}

/// Guest input: the previous summary state and the epoch's raw dataset keys.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SsMgInput {
    /// SS capacity s (zkSketch `SsFullParams::capacity`).
    pub capacity: u32,
    /// Records per batch m (zkSketch `SsFullParams::batch`).
    pub batch: u32,
    /// [`SortAlgo`] as a word.
    pub sort: u32,
    /// S_old: `capacity` rows of ROW_WORDS words, zkSketch's flat_state_vals layout.
    pub old_rows: Vec<u32>,
    /// The epoch's raw u32 dataset keys, before ss_updates_of.
    pub keys: Vec<u32>,
}

/// Words before the state in the headline guest's raw input (see [`input_words`]).
pub const HEADER_WORDS: usize = 3;

/// The headline guest's input as raw words, read with env::read_slice:
/// `[capacity, batch, sort]`, then `capacity * ROW_WORDS` state words, then
/// `batch` raw keys. (The ss_mg_serde sensitivity guest reads [`SsMgInput`]
/// with env::read, i.e. risc0 serde.)
pub fn input_words(input: &SsMgInput) -> Vec<u32> {
    let mut w = Vec::with_capacity(HEADER_WORDS + input.old_rows.len() + input.keys.len());
    w.push(input.capacity);
    w.push(input.batch);
    w.push(input.sort);
    w.extend_from_slice(&input.old_rows);
    w.extend_from_slice(&input.keys);
    w
}

/// The journal: (Com_old, Com_batch, Com_new), committed as 96 raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsMgJournal {
    pub com_old: Commit,
    pub com_batch: Commit,
    pub com_new: Commit,
}

impl SsMgJournal {
    pub const BYTES: usize = 96;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut b = [0u8; Self::BYTES];
        b[..32].copy_from_slice(&self.com_old);
        b[32..64].copy_from_slice(&self.com_batch);
        b[64..].copy_from_slice(&self.com_new);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::BYTES {
            return None;
        }
        let mut j = SsMgJournal { com_old: [0; 32], com_batch: [0; 32], com_new: [0; 32] };
        j.com_old.copy_from_slice(&b[..32]);
        j.com_batch.copy_from_slice(&b[32..64]);
        j.com_new.copy_from_slice(&b[64..]);
        Some(j)
    }
}

/// By-products of one transition, for the host's CSV (the guest drops them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MgStats {
    /// active rows of S_old
    pub old_active: u32,
    /// active (non-pad) records of the batch
    pub batch_active: u32,
    /// distinct keys of the union (active grouped rows)
    pub union_distinct: u32,
    /// the subtracted threshold
    pub tau: u32,
    /// active rows of S_new
    pub new_active: u32,
}

/// Phases reported to the hook of [`run_hooked`], in order.
pub const PHASES: [&str; 5] = ["commit_old", "map", "commit_batch", "transition", "commit_new"];

/// zkSketch `SsFullParams::validate` (src/sketch/ss_final_full.rs).
pub fn check_params(capacity: u32, batch: u32) {
    assert!(capacity >= 2 && capacity % 2 == 0, "capacity must be even and >= 2");
    assert!(batch >= 2 && batch % 2 == 0, "batch must be even and >= 2");
}

/// One raw key -> one batch record, exactly zkSketch's `ss_updates_of`
/// (src/experiments/stream_compose.rs): PAD_KEY -> `SsFullUpdate::dummy()`,
/// otherwise `SsFullUpdate::real(((k & 0x1FFF_FFFF) | 1) as u64, 1)`.
#[inline]
pub fn update_words(k: u32) -> [u32; ROW_WORDS] {
    if k == PAD_KEY {
        [0, 0, 0, 0]
    } else {
        [(k & KEY_MASK) | 1, 0, 1, 1]
    }
}

/// The mapped batch, ROW_WORDS words per record (zkSketch's flat_batch_vals layout).
pub fn map_batch(keys: &[u32]) -> Vec<u32> {
    let mut w = Vec::with_capacity(keys.len() * ROW_WORDS);
    for &k in keys {
        w.extend_from_slice(&update_words(k));
    }
    w
}

fn sha256_parts(parts: &[&[u8]]) -> Commit {
    let mut sha = Sha256::new();
    for p in parts {
        sha.update(p);
    }
    sha.finalize().into()
}

/// Unsalted SHA-256 state commitment over the tag, (s, m) and every row.
pub fn state_commit(capacity: u32, batch: u32, rows: &[u32]) -> Commit {
    sha256_parts(&[
        TAG_SS_MG_STATE,
        &capacity.to_le_bytes(),
        &batch.to_le_bytes(),
        bytemuck::cast_slice::<u32, u8>(rows),
    ])
}

/// Unsalted SHA-256 batch commitment over the tag, m and every mapped record.
pub fn batch_commit(batch: u32, words: &[u32]) -> Commit {
    sha256_parts(&[TAG_SS_MG_BATCH, &batch.to_le_bytes(), bytemuck::cast_slice::<u32, u8>(words)])
}

const RADIX_BITS: u32 = 11;

/// The high (`HI`) or low u32 word of a packed row.
#[inline(always)]
fn word<const HI: bool>(x: u64) -> u32 {
    if HI {
        (x >> 32) as u32
    } else {
        x as u32
    }
}

/// Stable LSD radix sort of `v` by one u32 word of each element (the high
/// word if `HI`): elements with equal words keep their relative order. The
/// digits (at most 11 bits each, equal widths) cover only the bits set
/// somewhere in the input, and a digit with a single value over the whole
/// input is skipped.
fn radix_sort_by_word<const HI: bool>(v: &mut Vec<u64>) {
    let n = v.len();
    if n < 2 {
        return;
    }
    let used = v.iter().fold(0u32, |a, &x| a | word::<HI>(x));
    let bits = 32 - used.leading_zeros();
    if bits == 0 {
        return;
    }
    let digits = bits.div_ceil(RADIX_BITS);
    let width = bits.div_ceil(digits);
    let mask = (1u32 << width) - 1;
    let mut hist = vec![0u32; 1usize << width];
    let mut buf: Vec<u64> = vec![0u64; n];
    for p in 0..digits {
        let sh = p * width;
        hist.fill(0);
        for &x in v.iter() {
            hist[((word::<HI>(x) >> sh) & mask) as usize] += 1;
        }
        if hist.iter().any(|&c| c as usize == n) {
            continue; // every element has the same digit
        }
        let mut sum = 0u32;
        for c in hist.iter_mut() {
            let t = *c;
            *c = sum;
            sum += t;
        }
        for &x in v.iter() {
            let d = ((word::<HI>(x) >> sh) & mask) as usize;
            buf[hist[d] as usize] = x;
            hist[d] += 1;
        }
        core::mem::swap(v, &mut buf);
    }
}

/// Appends every active row of `words` to `union` as `key << 32 | count`,
/// asserting the well-formedness the packed sort relies on.
fn push_active(union: &mut Vec<u64>, words: &[u32], n_active: &mut u32) {
    assert!(words.len() % ROW_WORDS == 0, "row table is not a whole number of rows");
    for r in words.chunks_exact(ROW_WORDS) {
        let (lo, hi, count, active) = (r[0], r[1], r[2], r[3]);
        match active {
            0 => assert!(lo == 0 && hi == 0 && count == 0, "inactive row is not the all-zero dummy"),
            1 => {
                assert!(hi == 0 && lo != 0, "active key is 0 or does not fit in 32 bits");
                union.push(((lo as u64) << 32) | count as u64);
                *n_active += 1;
            }
            _ => panic!("active flag is neither 0 nor 1"),
        }
    }
}

/// zkSketch `apply_batch_ss_full(S_old, batch).0`: returns S_new as
/// `capacity` rows of ROW_WORDS words.
pub fn apply_batch_mg(capacity: usize, old_rows: &[u32], batch_words: &[u32], algo: SortAlgo) -> (Vec<u32>, MgStats) {
    assert!(old_rows.len() == capacity * ROW_WORDS, "S_old does not have `capacity` rows");
    let mut st = MgStats::default();

    // Union of the active old counters and the active batch records. Dummy rows
    // only ever form zkSketch's key-0 dummy segment, which groups to a dummy.
    let mut union: Vec<u64> = Vec::with_capacity(capacity + batch_words.len() / ROW_WORDS);
    push_active(&mut union, old_rows, &mut st.old_active);
    push_active(&mut union, batch_words, &mut st.batch_active);

    // Key sort, then one grouped row per key with the summed count
    // (zkSketch group_by_key: u64 running sum, stored `as u32`). Grouped rows
    // are packed `count << 32 | key`, so the u64 order is zkSketch's count-sort
    // order (count asc, key asc) over the active grouped rows. They come out in
    // ascending key order, so a STABLE sort by the count word alone (Radix)
    // yields (count asc, key asc).
    match algo {
        SortAlgo::Radix => radix_sort_by_word::<true>(&mut union), // by key; counts of equal keys in any order
        SortAlgo::Std => union.sort_unstable(),
    }
    let mut grouped: Vec<u64> = Vec::with_capacity(union.len());
    let mut i = 0;
    while i < union.len() {
        let key = union[i] >> 32;
        let mut sum = 0u64;
        while i < union.len() && union[i] >> 32 == key {
            sum += union[i] & 0xFFFF_FFFF;
            i += 1;
        }
        grouped.push(((sum as u32 as u64) << 32) | key);
    }
    drop(union);
    let d = grouped.len();
    st.union_distinct = d as u32;

    // zkSketch's count-sorted table is (s + m - d) dummies, then the d active
    // grouped rows ascending; S_new[i] = g_sorted[m + i] and tau =
    // g_sorted[m - 1].count. So with d > s the cut sits at active index
    // d - s - 1 (tau = its count) and S_new holds the top s; with d <= s,
    // g_sorted[m - 1] is a dummy (tau = 0) and S_new holds all d after s - d
    // dummies.
    let (tau, top): (u32, &[u64]) = match algo {
        SortAlgo::Radix => {
            radix_sort_by_word::<true>(&mut grouped); // by count, stable: ties stay key-ascending
            if d > capacity {
                ((grouped[d - capacity - 1] >> 32) as u32, &grouped[d - capacity..])
            } else {
                (0, &grouped[..])
            }
        }
        SortAlgo::Std => {
            if d > capacity {
                let (_, nth, top) = grouped.select_nth_unstable(d - capacity - 1);
                let tau = (*nth >> 32) as u32;
                top.sort_unstable();
                (tau, top)
            } else {
                grouped.sort_unstable();
                (0, &grouped[..])
            }
        }
    };
    st.tau = tau;

    // Subtract tau; a counter that reaches 0 becomes a dummy in place
    // (zkSketch compress_from_gsorted).
    let mut out = vec![0u32; capacity * ROW_WORDS];
    let base = capacity - top.len();
    for (j, &g) in top.iter().enumerate() {
        let c = ((g >> 32) as u32).saturating_sub(tau);
        if c > 0 {
            let r = (base + j) * ROW_WORDS;
            out[r] = g as u32;
            out[r + 1] = 0;
            out[r + 2] = c;
            out[r + 3] = 1;
            st.new_active += 1;
        }
    }
    (out, st)
}

/// The guest computation after the input read: commitments plus the
/// transition. `hook` is called after each phase of [`PHASES`] (the guest
/// records env::cycle_count() there; the host passes a no-op).
pub fn run_hooked(
    capacity: u32,
    batch: u32,
    algo: SortAlgo,
    old_rows: &[u32],
    keys: &[u32],
    mut hook: impl FnMut(&'static str),
) -> (SsMgJournal, Vec<u32>, MgStats) {
    check_params(capacity, batch);
    assert!(keys.len() == batch as usize, "batch does not hold m keys");
    let com_old = state_commit(capacity, batch, old_rows);
    hook(PHASES[0]);
    let batch_words = map_batch(keys);
    hook(PHASES[1]);
    let com_batch = batch_commit(batch, &batch_words);
    hook(PHASES[2]);
    let (new_rows, st) = apply_batch_mg(capacity as usize, old_rows, &batch_words, algo);
    hook(PHASES[3]);
    let com_new = state_commit(capacity, batch, &new_rows);
    hook(PHASES[4]);
    (SsMgJournal { com_old, com_batch, com_new }, new_rows, st)
}

/// The empty state: `capacity` dummy rows (zkSketch `SsFullState::empty`).
pub fn empty_rows(capacity: usize) -> Vec<u32> {
    vec![0u32; capacity * ROW_WORDS]
}
