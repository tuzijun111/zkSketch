//! anscheck <m> <T> <run log>...: recompute every Bloom query answer of an exp_compose run natively.
//! The stream is exp_compose's (`batches_from`: batch i = AOL keys [i·m, (i+1)·m)); after leaf n the
//! filter holds batches 1..n. For each `QLOG_KEY,at_leaf=n,bloom_key=K` + `QLOG_QUERY,at_leaf=n,...,answer=a`
//! it prints bloom_omc's native answer (bit array), bloom_packed's native answer (bytes), whether K was
//! inserted, and whether the logged (proven) answer equals both. It also checks bits_to_words(omc) == packed
//! after every leaf.
use std::collections::{BTreeMap, HashSet};
use zksketch::dataset::aol;
use zksketch::sketch::bloom_omc::{BloomOmcParams, bloom_contains, bloom_empty, bloom_insert};
use zksketch::sketch::bloom_packed::{BloomPackedParams, bits_to_words, packed_contains, packed_empty, packed_insert};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let m: usize = a[1].parse().unwrap();
    let t: usize = a[2].parse().unwrap();
    let base = aol().expect("data/aol.keys");
    let po = BloomOmcParams { k: 7, log_w: 14, batch: m };
    let pp = BloomPackedParams { k: 7, log_w: 14, batch: m };
    let (mut bits, mut words) = (bloom_empty(&po), packed_empty(&pp));
    let mut seen = HashSet::new();
    let mut states = Vec::new();
    for i in 0..t {
        let batch: Vec<u64> =
            (0..m).map(|j| base[(i * m + j) % base.len()]).filter(|&k| k != u32::MAX).map(|k| k as u64).collect();
        bloom_insert(&mut bits, &po, &batch);
        packed_insert(&mut words, &pp, &batch);
        assert_eq!(bits_to_words(&bits), words, "packed state != packed omc bits after leaf {}", i + 1);
        seen.extend(batch.iter().copied());
        let ones: usize = bits.iter().map(|&b| b as usize).sum();
        states.push((bits.clone(), words.clone(), seen.clone(), ones));
    }
    println!("ANSCHECK m={m} T={t} stream={} keys distinct_inserted={} filter_ones={} of {}", t * m, seen.len(), states[t - 1].3, bits.len());
    for log in &a[3..] {
        let txt = std::fs::read_to_string(log).unwrap();
        let mut keys = BTreeMap::new();
        let mut ans = BTreeMap::new();
        for l in txt.lines() {
            let f: BTreeMap<&str, &str> = l.split(',').filter_map(|kv| kv.split_once('=')).collect();
            if l.starts_with("QLOG_KEY,") {
                keys.insert(f["at_leaf"].parse::<usize>().unwrap(), f["bloom_key"].parse::<u64>().unwrap());
            } else if l.starts_with("QLOG_QUERY,") {
                ans.insert(f["at_leaf"].parse::<usize>().unwrap(), f["answer"].trim().to_string());
            }
        }
        let (mut ok, mut n, mut ones) = (0, 0, 0);
        for (&leaf, &key) in &keys {
            let (b, w, s, _) = &states[leaf - 1];
            let o = bloom_contains(b, &po, key);
            let p = packed_contains(w, &pp, key);
            let logged = ans.get(&leaf).map(String::as_str).unwrap_or("?");
            let good = o == p && logged == if o { "1" } else { "0" };
            n += 1;
            ok += good as usize;
            ones += o as usize;
            println!("  leaf={leaf:3} key={key:10} inserted={} omc={} packed={} proven={logged} {}", s.contains(&key) as u8, o as u8, p as u8, if good { "ok" } else { "MISMATCH" });
        }
        println!("SUMMARY {log}: {ok}/{n} proven answers == native bloom_omc == native packed; native ones={ones}, zeros={}", n - ones);
    }
}
