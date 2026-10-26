// Independent host-side references for the Misra-Gries port. None of this code
// is shared with mg-core, so agreement is a real check, not a tautology.
//
//   NaiveMg       Misra-Gries with a BTreeMap and a plain decrement-all loop
//                 (mg-core uses parallel arrays, a hash index and in-place
//                 compaction). The states must be identical for every capacity.
//   naive_merge   BTreeMap sum of equal keys, then the mergeable Misra-Gries
//                 reduction (subtract the (capacity+1)-th largest sum, keep the
//                 positive counters) -- the specification of mg_core::mg_merge.
//   naive_point   per-epoch binary search (the guest scans linearly) -- the
//                 specification of the MgQuery::Estimate answer.
//   decrement_sum the slack of a per-epoch point answer: sum over the epochs of
//                 (N_e - C_e) / (capacity + 1), C_e the epoch's counter sum.
//   merged_slack  the slack of a merged answer: (N - C) / (capacity + 1).
//   exact_*       plain frequency counting for accuracy.

use std::collections::{BTreeMap, HashMap};

use mg_core::{MgEntry, MgEpochState, MgItem, KEY_BYTES_LEN};

pub type Key = [u8; KEY_BYTES_LEN];

pub struct NaiveMg {
    capacity: usize,
    counters: BTreeMap<Key, u32>,
}

impl NaiveMg {
    pub fn new(capacity: usize) -> Self {
        NaiveMg { capacity, counters: BTreeMap::new() }
    }

    pub fn update(&mut self, key: &Key) {
        if let Some(c) = self.counters.get_mut(key) {
            *c += 1;
        } else if self.counters.len() < self.capacity {
            self.counters.insert(*key, 1);
        } else {
            for c in self.counters.values_mut() {
                *c -= 1;
            }
            self.counters.retain(|_, c| *c > 0);
        }
    }

    pub fn entries_sorted(&self) -> Vec<MgEntry> {
        self.counters.iter().map(|(k, &c)| MgEntry { key_id: *k, count: c }).collect()
    }
}

pub fn naive_merge(states: &[MgEpochState], capacity: usize) -> Vec<MgItem> {
    let mut m: BTreeMap<Key, u64> = BTreeMap::new();
    for st in states {
        for e in &st.entries {
            *m.entry(e.key_id).or_insert(0) += e.count as u64;
        }
    }
    let mut v: Vec<MgItem> = m.into_iter().map(|(k, c)| MgItem { key_id: k, count: c }).collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.key_id.cmp(&b.key_id)));
    if v.len() > capacity {
        let tau = v[capacity].count;
        v = v[..capacity].iter().map(|i| MgItem { key_id: i.key_id, count: i.count - tau }).filter(|i| i.count > 0).collect();
    }
    v
}

/// Summed count of `key` over the epochs that monitor it, and whether any epoch
/// does. Binary search per key-sorted epoch.
pub fn naive_point(states: &[MgEpochState], key: &Key) -> (u64, bool) {
    let mut r = (0u64, false);
    for st in states {
        if let Ok(i) = st.entries.binary_search_by(|e| e.key_id.cmp(key)) {
            r.0 += st.entries[i].count as u64;
            r.1 = true;
        }
    }
    r
}

/// Number of decrement steps of one epoch: (N_e - C_e) / (capacity + 1). Exact:
/// every step removes capacity + 1 units of mass.
pub fn decrements(st: &MgEpochState) -> u64 {
    let c: u64 = st.entries.iter().map(|e| e.count as u64).sum();
    (st.total_count - c) / (st.capacity as u64 + 1)
}

/// Slack of a per-epoch point answer: f <= count + decrement_sum.
pub fn decrement_sum(states: &[MgEpochState]) -> u64 {
    states.iter().map(decrements).sum()
}

/// Slack of a merged answer (the Misra-Gries guarantee of the merged summary):
/// f <= count + (N - C) / (capacity + 1), C the sum of all merged counters.
pub fn merged_slack(total: u64, merged: &[MgItem], capacity: usize) -> u64 {
    let c: u64 = merged.iter().map(|i| i.count).sum();
    total.saturating_sub(c) / (capacity as u64 + 1)
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

// Edge cases the AOL runs do not reach (tiny capacities, long runs of one key,
// decrement storms): mg-core must agree with NaiveMg exactly.
#[cfg(test)]
mod tests {
    use super::*;
    use mg_core::{mg_merge, MisraGries};

    fn key(k: u64) -> Key {
        mg_core::Event::make_key_id(0, k)
    }
    // xorshift64*, deterministic
    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        seed.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn epoch(seed: &mut u64, cap: usize, n: u64, alphabet: u64) -> MgEpochState {
        let mut s = MisraGries::new(cap);
        for _ in 0..n {
            let r = rng(seed) % alphabet;
            s.update(&key(r.min(rng(seed) % alphabet)));
        }
        MgEpochState { capacity: cap as u32, total_count: s.total(), entries: s.entries_sorted() }
    }

    #[test]
    fn core_matches_naive() {
        let mut seed = 0x9E3779B97F4A7C15u64;
        for &cap in &[1usize, 2, 3, 4, 5, 8, 17, 64, 256] {
            for &alphabet in &[1u64, 2, 3, 10, 100, 5000] {
                for &skew in &[false, true] {
                    let mut a = MisraGries::new(cap);
                    let mut b = NaiveMg::new(cap);
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

    // count <= f <= count + d per key, d = (N - C) / (cap + 1) exactly.
    #[test]
    fn misra_gries_guarantee() {
        let mut seed = 3u64;
        for &cap in &[1usize, 4, 32, 300] {
            let keys: Vec<u64> = (0..6000).map(|_| { let r = rng(&mut seed) % 2000; r.min(rng(&mut seed) % 2000) }).collect();
            let mut s = MisraGries::new(cap);
            let mut f: HashMap<u64, u64> = HashMap::new();
            for &k in &keys {
                s.update(&key(k));
                *f.entry(k).or_insert(0) += 1;
            }
            let st = MgEpochState { capacity: cap as u32, total_count: s.total(), entries: s.entries_sorted() };
            let c: u64 = st.entries.iter().map(|e| e.count as u64).sum();
            assert_eq!((st.total_count - c) % (cap as u64 + 1), 0, "cap={cap}");
            let d = decrements(&st);
            for (&k, &fk) in &f {
                let (ck, _) = naive_point(std::slice::from_ref(&st), &key(k));
                assert!(ck <= fk && fk <= ck + d, "cap={cap} k={k} c={ck} f={fk} d={d}");
            }
        }
    }

    // mg_bucket_index is a copy of their samples_bucket_index with the bucket count
    // as a parameter. It must equal their pub function, which is built at
    // aggregator-core's default SAMPLES_HT_BUCKETS = 1024; masking that result to
    // 6 bits is what their function returns when built with SAMPLES_HT_BUCKETS = 64.
    #[test]
    fn bucket_index_equals_their_function_at_64_and_1024() {
        assert_eq!(aggregator_core::SAMPLES_HT_BUCKETS, 1024);
        let mut seed = 99u64;
        for i in 0..100_000u64 {
            let k = key(if i % 2 == 0 { i } else { rng(&mut seed) & 0xFFFF_FFFF });
            let theirs = aggregator_core::samples_bucket_index(&k);
            assert_eq!(mg_core::mg_bucket_index(&k, 1024), theirs);
            assert_eq!(mg_core::mg_bucket_index(&k, 64), theirs & 63);
        }
    }

    // mg_root(Buckets64/1024) vs an independent grouping (BTreeMap of buckets,
    // leaves hashed here) folded by their samples_buckets_root_from_leaves.
    #[test]
    fn buckets_root_matches_independent_grouping() {
        use mg_core::{mg_root, MgRoot};
        use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
        let mut seed = 5u64;
        for &(cap, n) in &[(1usize, 10u64), (16, 50), (300, 5000), (4096, 20000)] {
            let entries = epoch(&mut seed, cap, n, 3000).entries;
            for (root, nb) in [(MgRoot::Buckets64, 64usize), (MgRoot::Buckets1024, 1024)] {
                let mut groups: BTreeMap<usize, Vec<MgEntry>> = BTreeMap::new();
                for e in &entries {
                    groups.entry(mg_core::mg_bucket_index(&e.key_id, nb)).or_default().push(*e);
                }
                let leaves_n = (groups.keys().max().copied().unwrap_or(0) + 1).next_power_of_two();
                let leaves: Vec<[u8; 32]> = (0..leaves_n)
                    .map(|b| {
                        let mut h = Sha256::new();
                        h.update(b"ZKA_PORT_MG_BUCKET_V1");
                        for e in groups.get(&b).map(|v| v.as_slice()).unwrap_or(&[]) {
                            h.update(e.key_id);
                            h.update(e.count.to_be_bytes());
                        }
                        h.finalize().into()
                    })
                    .collect();
                assert_eq!(
                    mg_root(&entries, root),
                    aggregator_core::samples_buckets_root_from_leaves(&leaves),
                    "cap={cap} nb={nb}"
                );
            }
        }
    }

    // The Estimate scan answer (run through the query code) equals naive_point.
    #[test]
    fn estimate_scan_matches_binary_search() {
        use mg_core::{run_mg_query, MgQuery, MgQueryInput, MgQueryResult};
        let mut seed = 11u64;
        for &cap in &[1usize, 8, 100] {
            let states: Vec<MgEpochState> = (0..4).map(|_| epoch(&mut seed, cap, 800, 200)).collect();
            for k in 0..220u64 {
                let q = MgQueryInput {
                    query: MgQuery::Estimate { key: key(k) },
                    epoch_states: states.clone(),
                    epoch_chain_links: Vec::new(),
                };
                let (c, mon) = naive_point(&states, &key(k));
                match run_mg_query(&q).result {
                    MgQueryResult::Estimate { count, monitored, .. } => {
                        assert_eq!((count, monitored), (c, mon), "cap={cap} k={k}")
                    }
                    _ => panic!("wrong result kind"),
                }
            }
        }
    }

    // mg_merge equals the BTreeMap reference, and the merged summary keeps the
    // Misra-Gries guarantee against the exact counts of all epochs together.
    #[test]
    fn merge_matches_btreemap_and_keeps_the_guarantee() {
        let mut seed = 7u64;
        for &cap in &[1usize, 3, 16, 200] {
            let mut f: HashMap<Key, u64> = HashMap::new();
            let mut states = Vec::new();
            for _ in 0..5 {
                let mut s = MisraGries::new(cap);
                for _ in 0..1000 {
                    let r = rng(&mut seed) % 300;
                    let k = key(r.min(rng(&mut seed) % 300));
                    s.update(&k);
                    *f.entry(k).or_insert(0) += 1;
                }
                states.push(MgEpochState { capacity: cap as u32, total_count: s.total(), entries: s.entries_sorted() });
            }
            let merged = mg_merge(&states, cap);
            assert_eq!(merged, naive_merge(&states, cap), "cap={cap}");
            assert!(merged.len() <= cap);
            let slack = merged_slack(5000, &merged, cap);
            for (k, &fk) in &f {
                let c = merged.iter().find(|i| i.key_id == *k).map_or(0, |i| i.count);
                assert!(c <= fk && fk <= c + slack, "cap={cap} c={c} f={fk} slack={slack}");
            }
        }
    }
}
