#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use gk_zka_core::{process_gk_aggr_marked, GkAggrInput, Mark};

risc0_zkvm::guest::entry!(main);

// PROFILING ONLY. Runs exactly the aggregation of guests/aggr, but reads the
// (host-provided, unchecked) cycle counter at each phase mark, and commits
// (GkAggrOutput, phase cycles). The counter reads are syscalls, so this guest's
// total differs slightly from aggr_gk; only the split is meant to be read.
//   phases[0] batch-chain verification      phases[1] flatten events
//   phases[2] GK inserts (excl. compress)   phases[3] GK compress (sum)
//   phases[4] Merkle root                   phases[5] state commitment
//   phases[6] epoch chain link              phases[7] number of compress calls
//   phases[8] env::read (input deserialisation)
//   phases[9] cycles before main's first instruction (runtime start-up)
// The journal commit after the last mark is not covered.
fn main() {
    let t_start = env::cycle_count();
    let input: GkAggrInput = env::read();
    let mut phases = [0u64; 10];
    let t0 = env::cycle_count();
    phases[8] = t0 - t_start;
    phases[9] = t_start;
    let mut last = t0;
    let mut compress_begin = 0u64;
    let mut compress_total = 0u64;
    let mut build_begin = 0u64;
    let (_, out) = process_gk_aggr_marked(&input, &mut |m| {
        let now = env::cycle_count();
        match m {
            Mark::ChainVerified => { phases[0] = now - last; last = now; }
            Mark::EventsFlattened => { phases[1] = now - last; last = now; build_begin = now; }
            Mark::CompressBegin => { compress_begin = now; }
            Mark::CompressEnd => { compress_total += now - compress_begin; phases[7] += 1; }
            Mark::SummaryBuilt => {
                phases[3] = compress_total;
                phases[2] = (now - build_begin) - compress_total;
                last = now;
            }
            Mark::RootDone => { phases[4] = now - last; last = now; }
            Mark::CommitDone => { phases[5] = now - last; last = now; }
            Mark::LinkDone => { phases[6] = now - last; last = now; }
        }
    });
    env::commit(&(out, phases));
}
