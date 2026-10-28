// Independent host-side references for the SpaceSaving port; no code is shared with ss-core.
// NaiveSs evicts, among the minimum counters, the one whose count changed earliest (ss-core's rule).

use std::collections::{BTreeMap, HashMap};

use ss_core::{SsEntry, SsEpochState, SsItem, KEY_BYTES_LEN};

pub type Key = [u8; KEY_BYTES_LEN];

struct Slot {
    key: Key,
    count: u32,
    error: u32,
    touched: u64,
}

pub struct NaiveSs {
    capacity: usize,
    slots: Vec<Slot>,
    pos: HashMap<Key, usize>,
    clock: u64,
}

impl NaiveSs {
    pub fn new(capacity: usize) -> Self {
        NaiveSs { capacity, slots: Vec::new(), pos: HashMap::new(), clock: 0 }
    }

    pub fn update(&mut self, key: &Key) {
        self.clock += 1;
        if let Some(&i) = self.pos.get(key) {
            self.slots[i].count += 1;
            self.slots[i].touched = self.clock;
        } else if self.slots.len() < self.capacity {
            self.pos.insert(*key, self.slots.len());
            self.slots.push(Slot { key: *key, count: 1, error: 0, touched: self.clock });
        } else {
            let (i, _) = self
                .slots
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| (s.count, s.touched))
                .expect("capacity >= 1");
            let old = self.slots[i].key;
            self.pos.remove(&old);
            self.pos.insert(*key, i);
            let min = self.slots[i].count;
            self.slots[i] = Slot { key: *key, count: min + 1, error: min, touched: self.clock };
        }
    }

    pub fn entries_sorted(&self) -> Vec<SsEntry> {
        let mut v: Vec<SsEntry> =
            self.slots.iter().map(|s| SsEntry { key_id: s.key, count: s.count, error: s.error }).collect();
        v.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        v
    }
}

pub fn naive_merge(states: &[SsEpochState], capacity: usize) -> Vec<SsItem> {
    let mut m: BTreeMap<Key, (u64, u64)> = BTreeMap::new();
    for st in states {
        for e in &st.entries {
            let x = m.entry(e.key_id).or_insert((0, 0));
            x.0 += e.count as u64;
            x.1 += e.error as u64;
        }
    }
    let mut v: Vec<SsItem> = m.into_iter().map(|(k, (c, e))| SsItem { key_id: k, count: c, error: e }).collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.key_id.cmp(&b.key_id)));
    v.truncate(capacity);
    v
}

/// Summed (count, error) of `key` over the epochs that monitor it, and whether
/// any epoch does. Binary search per key-sorted epoch.
pub fn naive_point(states: &[SsEpochState], key: &Key) -> (u64, u64, bool) {
    let mut r = (0u64, 0u64, false);
    for st in states {
        if let Ok(i) = st.entries.binary_search_by(|e| e.key_id.cmp(key)) {
            r.0 += st.entries[i].count as u64;
            r.1 += st.entries[i].error as u64;
            r.2 = true;
        }
    }
    r
}

/// Sum of the minimum counter over the epochs whose summary is full and does not
/// monitor `key`. An unmonitored key's frequency in an epoch is at most that
/// epoch's minimum counter if the summary is full, and 0 if it never filled.
pub fn absent_min_sum(states: &[SsEpochState], key: &Key) -> u64 {
    states
        .iter()
        .filter(|st| st.entries.len() == st.capacity as usize)
        .filter(|st| st.entries.binary_search_by(|e| e.key_id.cmp(key)).is_err())
        .map(|st| st.entries.iter().map(|e| e.count as u64).min().unwrap_or(0))
        .sum()
}

pub fn exact_counts(keys: &[u32]) -> HashMap<u32, u64> {
    let mut c = HashMap::new();
    for &k in keys {
        *c.entry(k).or_insert(0u64) += 1;
    }
    c
}

/// (count desc, key asc) -- deterministic
pub fn exact_top(counts: &HashMap<u32, u64>, l: usize) -> Vec<(u32, u64)> {
    let mut v: Vec<(u32, u64)> = counts.iter().map(|(&k, &c)| (k, c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(l);
    v
}

// Stream-Summary edge cases the AOL runs do not reach (tiny capacities, long
// runs of one key, eviction storms): ss-core must agree with NaiveSs exactly.
#[cfg(test)]
mod tests {
    use super::*;
    use ss_core::{ss_merge, SpaceSaving};

    fn key(k: u64) -> Key {
        ss_core::Event::make_key_id(0, k)
    }
    // xorshift64*, deterministic
    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        seed.wrapping_mul(0x2545F4914F6CDD1D)
    }

    #[test]
    fn stream_summary_matches_linear_scan() {
        let mut seed = 0x9E3779B97F4A7C15u64;
        for &cap in &[1usize, 2, 3, 4, 5, 8, 17, 64, 256] {
            for &alphabet in &[1u64, 2, 3, 10, 100, 5000] {
                for &skew in &[false, true] {
                    let mut a = SpaceSaving::new(cap);
                    let mut b = NaiveSs::new(cap);
                    for i in 0..4000u64 {
                        let r = rng(&mut seed);
                        let k = if skew { (r % alphabet).min(r % 7) } else { r % alphabet };
                        let k = if i % 97 == 0 { 424242 } else { k }; // a recurring heavy key
                        a.update(&key(k));
                        b.update(&key(k));
                        if i % 499 == 0 {
                            assert_eq!(a.entries_sorted(), b.entries_sorted(), "cap={cap} alphabet={alphabet} i={i}");
                        }
                    }
                    assert_eq!(a.entries_sorted(), b.entries_sorted(), "cap={cap} alphabet={alphabet}");
                    assert_eq!(a.total(), 4000);
                }
            }
        }
    }

    // ss_bucket_index is a copy of their samples_bucket_index with the bucket count
    // as a parameter. It must equal their pub function, which is built at
    // aggregator-core's default SAMPLES_HT_BUCKETS = 1024; masking that result to
    // 6 bits is what their function returns when built with SAMPLES_HT_BUCKETS = 64
    // (both are powers of two).
    #[test]
    fn bucket_index_equals_their_function_at_64_and_1024() {
        assert_eq!(aggregator_core::SAMPLES_HT_BUCKETS, 1024);
        let mut seed = 99u64;
        for i in 0..100_000u64 {
            let k = key(if i % 2 == 0 { i } else { rng(&mut seed) & 0xFFFF_FFFF });
            let theirs = aggregator_core::samples_bucket_index(&k);
            assert_eq!(ss_core::ss_bucket_index(&k, 1024), theirs);
            assert_eq!(ss_core::ss_bucket_index(&k, 64), theirs & 63);
        }
    }

    // ss_root(Buckets64/1024) vs an independent grouping (BTreeMap of buckets,
    // leaves hashed here) folded by their samples_buckets_root_from_leaves.
    #[test]
    fn buckets_root_matches_independent_grouping() {
        use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
        use ss_core::{ss_root, SsRoot};
        let mut seed = 5u64;
        for &(cap, n) in &[(1usize, 10u64), (16, 50), (300, 5000), (4096, 20000)] {
            let mut s = SpaceSaving::new(cap);
            for _ in 0..n {
                let r = rng(&mut seed) % 3000;
                s.update(&key(r.min(rng(&mut seed) % 3000)));
            }
            let entries = s.entries_sorted();
            for (root, nb) in [(SsRoot::Buckets64, 64usize), (SsRoot::Buckets1024, 1024)] {
                let mut groups: BTreeMap<usize, Vec<SsEntry>> = BTreeMap::new();
                for e in &entries {
                    groups.entry(ss_core::ss_bucket_index(&e.key_id, nb)).or_default().push(*e);
                }
                let leaves_n = (groups.keys().max().copied().unwrap_or(0) + 1).next_power_of_two();
                let leaves: Vec<[u8; 32]> = (0..leaves_n)
                    .map(|b| {
                        let mut h = Sha256::new();
                        h.update(b"ZKA_PORT_SS_BUCKET_V1");
                        for e in groups.get(&b).map(|v| v.as_slice()).unwrap_or(&[]) {
                            h.update(e.key_id);
                            h.update(e.count.to_be_bytes());
                            h.update(e.error.to_be_bytes());
                        }
                        h.finalize().into()
                    })
                    .collect();
                assert_eq!(
                    ss_root(&entries, root),
                    aggregator_core::samples_buckets_root_from_leaves(&leaves),
                    "cap={cap} nb={nb}"
                );
            }
        }
    }

    // The Estimate scan answer (run through the query code) equals naive_point.
    #[test]
    fn estimate_scan_matches_binary_search() {
        use ss_core::{run_ss_query, SsQuery, SsQueryInput, SsQueryResult};
        let mut seed = 11u64;
        for &cap in &[1usize, 8, 100] {
            let states: Vec<SsEpochState> = (0..4)
                .map(|_| {
                    let mut s = SpaceSaving::new(cap);
                    for _ in 0..800 {
                        let r = rng(&mut seed) % 200;
                        s.update(&key(r.min(rng(&mut seed) % 200)));
                    }
                    SsEpochState { capacity: cap as u32, total_count: s.total(), entries: s.entries_sorted() }
                })
                .collect();
            for k in 0..220u64 {
                let q = SsQueryInput {
                    query: SsQuery::Estimate { key: key(k) },
                    epoch_states: states.clone(),
                    epoch_chain_links: Vec::new(),
                };
                let (c, e, mon) = naive_point(&states, &key(k));
                match run_ss_query(&q).result {
                    SsQueryResult::Estimate { count, error, monitored, .. } => {
                        assert_eq!((count, error, monitored), (c, e, mon), "cap={cap} k={k}")
                    }
                    _ => panic!("wrong result kind"),
                }
            }
        }
    }

    #[test]
    fn merge_matches_btreemap() {
        let mut seed = 7u64;
        for &cap in &[1usize, 3, 16, 200] {
            let states: Vec<SsEpochState> = (0..5)
                .map(|_| {
                    let mut s = SpaceSaving::new(cap);
                    for _ in 0..1000 {
                        let r = rng(&mut seed) % 300;
                        s.update(&key(r.min(rng(&mut seed) % 300)));
                    }
                    SsEpochState { capacity: cap as u32, total_count: s.total(), entries: s.entries_sorted() }
                })
                .collect();
            assert_eq!(ss_merge(&states, cap), naive_merge(&states, cap), "cap={cap}");
        }
    }
}
