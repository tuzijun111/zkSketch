#![no_std]

//! zkSketch's two-sided Greenwald-Khanna band-merge BATCH TRANSITION, ported to
//! plain Rust for a RISC Zero guest (matched-semantics baseline, `gk_bm2`).
//!
//! The textbook-GK guest in `../../gk` (INSERT / COMPRESS per record, k-way
//! COMBINE at query time) is NOT what zkSketch's circuit certifies. This crate
//! ports what it does certify, `apply_batch2` of `src/sketch/gk_bandmerge.rs`
//! in the zkSketch checkout this harness sits in, so a zkVM guest computes
//! the SAME function `S_{t-1}, batch_t -> S_t` that one zkSketch GK leaf proves:
//!
//!   1. map the batch's raw u32 keys to values (`gk_vals_of`: drop `PAD_KEY`
//!      slots, mask to 21 bits);
//!   2. union = old tuples ++ one fresh singleton `(v,0,0,0,0,t)` per value,
//!      padded with `E_MAX` dummies to `capacity + m` rows, sorted by `(e, t)`;
//!   3. two-sided neighbour initialisation of the fresh rows' `Delta`, `Delta°`;
//!   4. `L_f = ceil(log2(capacity + m))` parity-0 fuse rounds under the threshold
//!      `theta = floor(N_t / s)`, re-sorting by `(e, t)` after each round;
//!   5. keep the first `capacity` rows; `n = N_t`.
//!
//! Four implementations of that one function are provided:
//!
//! - [`apply_batch2`] is the LITERAL port, statement for statement: the same
//!   fixed `capacity + m` table, every `L_f` round over every row (dummies
//!   included), the same stable `sort_by_key` on `(e, t)` through an index
//!   permutation, fresh tables allocated every round. Only the circuit-witness
//!   captures are left out: zkSketch keeps every round's `fused`, a clone of
//!   `resorted`, `sigma` and the direction / condition vectors, plus `union_raw`,
//!   `union_init`, the challenge-level `expand_sigma` and the `excess` slice; the
//!   port computes the same tables but retains none of them, and none feeds the
//!   output. `apply_batch2`'s `debug_assert!` on the excess
//!   is compiled out of release builds, which is what zkSketch's harness runs, so
//!   a capacity overflow truncates silently here exactly as there.
//! - [`apply_batch2_reuse`] is the same code with the per-round tables allocated
//!   once. risc0's default guest allocator never frees, so the literal port pays
//!   for every fresh page it touches; this variant separates that cost from the
//!   schedule's.
//! - [`apply_batch2_fixed`] keeps zkSketch's FIXED schedule (the full
//!   `capacity + m` table, every `L_f` round, every pair visited, every row
//!   rewritten every round) but drops the implementation costs the literal port
//!   carries on top of it: the union is built in linear time (the radix sort and
//!   merge of the fast variant, then padded with dummies), and each round fuses
//!   and compacts the survivors in place, in one table allocated once, instead of
//!   writing a fresh `fused` table and stable-sorting it by `(e, t)`. On a
//!   canonical old state the compaction IS that re-sort (see the function doc),
//!   and the variant refuses any other old state, as the fast one does.
//! - [`apply_batch2_fast`] computes the same output with a data-dependent
//!   schedule a zkVM may use (the circuit must be oblivious, a zkVM need not):
//!   radix-sort only the fresh values and merge them into the already-sorted old
//!   actives, fuse over the active prefix only, compact in place of the re-sort,
//!   and stop after the first round that changes nothing (every later round is
//!   then the identity). It refuses (panics on) an old state that is not in the
//!   canonical form `apply_batch2` produces, the one domain where the shortcuts
//!   could diverge; a chain of states starting at [`State::empty`] never leaves it.
//!
//! The host checks all four against zkSketch's own `apply_batch2`, tuple by
//! tuple (`../host`, `--mode check`, and its unit tests).
//!
//! Commitments are unsalted SHA-256 (risc0's accelerated SHA-256 in the guest),
//! in the style of `../../gk/core`: a domain tag, then the little-endian bytes of
//! the state's word encoding ([`state_to_words`]) or of the raw key batch.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
#[cfg(target_os = "zkvm")]
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
#[cfg(not(target_os = "zkvm"))]
use rust_crypto::{Digest as _, Sha256};

#[cfg(target_endian = "big")]
compile_error!("the commitments hash u32 words as their in-memory bytes, which must be little-endian");

// ===========================================================================
// Constants and types, field for field as in zkSketch.
// ===========================================================================

/// `gk_bandmerge.rs:66-67`. Value field width; the top value is reserved for
/// dummies so they sort to the back.
pub const E_BITS: u32 = 22;
pub const E_MAX: u32 = (1 << E_BITS) - 1;
/// `stream_compose.rs:510`. Pad sentinel of split (early-sealed) batches.
pub const PAD_KEY: u32 = u32::MAX;
/// `stream_compose.rs:550-555` (`gk_vals_of`): GK values are keys masked to 21 bits.
pub const VALUE_MASK: u32 = 0x001F_FFFF;

/// `gk_bandmerge.rs:1278-1308` (`Gk2Tuple`): `(e, g, g°, Delta, Delta°, t, active)`
/// with the same widths. A dummy is `(E_MAX, 0, 0, 0, 0, 0, 0)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Tuple {
    pub e: u32,
    pub g: u64,
    pub g_o: u64,
    pub delta: u64,
    pub delta_o: u64,
    pub t: u64,
    pub active: u32,
}

impl Tuple {
    pub const fn dummy() -> Self {
        Self { e: E_MAX, g: 0, g_o: 0, delta: 0, delta_o: 0, t: 0, active: 0 }
    }
    /// `Gk2Tuple::mass`: the representative's two sets plus itself.
    pub fn mass(&self) -> u64 {
        self.g + self.g_o + 1
    }
}

/// `gk_bandmerge.rs:94-101` (`GkbParams`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Public summary capacity `s'`.
    pub capacity: usize,
    /// Public per-batch capacity `m`.
    pub batch: usize,
    /// Accuracy parameter `s = 1/eps`; threshold `theta_t = floor(N_t / s)`.
    pub s: u64,
}

/// `gk_bandmerge.rs:1311-1327` (`Gk2State`): value-sorted actives padded to
/// `capacity` with dummies, and the cumulative record count `n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub tuples: Vec<Tuple>,
    pub params: Params,
    pub n: u64,
}

impl State {
    pub fn empty(params: Params) -> Self {
        Self { tuples: vec![Tuple::dummy(); params.capacity], params, n: 0 }
    }
    pub fn actives(&self) -> usize {
        self.tuples.iter().filter(|t| t.active == 1).count()
    }
    /// Sum of `g + g° + 1` over the actives; equals `n` unless a capacity
    /// overflow truncated active tuples.
    pub fn active_mass(&self) -> u64 {
        self.tuples.iter().filter(|t| t.active == 1).map(Tuple::mass).sum()
    }
}

/// `gk_bandmerge.rs:142-149`: `L_f = ceil(log2 total)`.
pub fn num_rounds(total: usize) -> usize {
    if total <= 1 {
        0
    } else {
        (usize::BITS - (total - 1).leading_zeros()) as usize
    }
}

/// `stream_compose.rs:550-555` (`gk_vals_of`): strip `PAD_KEY` slots, mask the
/// rest to 21 bits (`< E_MAX`).
pub fn vals_of(batch: &[u32]) -> Vec<u32> {
    batch.iter().filter(|&&k| k != PAD_KEY).map(|&k| k & VALUE_MASK).collect()
}

/// Progress marks for cycle probes (the guest reads its cycle counter at each).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mark {
    /// The `(e, t)`-sorted union of old tuples and fresh singletons is built.
    UnionBuilt,
    /// The fresh rows' `Delta` / `Delta°` are initialised.
    NeighborInit,
    /// One fuse round (and its re-sort / compaction) is done; its merges by
    /// direction (`fold_right`: zkSketch direction 1, the left tuple folds into the
    /// right one; `fold_left`: direction 2).
    RoundDone { fold_right: u32, fold_left: u32 },
}

// ===========================================================================
// LITERAL port of apply_batch2 (gk_bandmerge.rs:1426-1646).
// ===========================================================================

/// `apply_batch2` (`gk_bandmerge.rs:1426`), literal port. Same signature and output.
pub fn apply_batch2(s_old: &State, batch_vals: &[u32]) -> State {
    apply_batch2_marked(s_old, batch_vals, &mut |_| {})
}

/// [`apply_batch2`] with progress marks.
pub fn apply_batch2_marked(s_old: &State, batch_vals: &[u32], mark: &mut impl FnMut(Mark)) -> State {
    literal(s_old, batch_vals, mark, false)
}

/// [`apply_batch2`] with the per-round tables (`fused`, the sort permutation,
/// `resorted`) allocated once and overwritten every round, instead of freshly
/// allocated per round as in zkSketch. Same statements, same sorts, same output.
/// risc0's default guest allocator is a bump allocator that never frees, so the
/// verbatim port allocates (and zero-fills, and pages in) about 28 MB of fresh
/// tables over 15 rounds at the deployed shape; this variant removes that
/// allocation cost and keeps everything else, including the paging of its own
/// roughly 2.8 MB working set.
pub fn apply_batch2_reuse(s_old: &State, batch_vals: &[u32]) -> State {
    apply_batch2_reuse_marked(s_old, batch_vals, &mut |_| {})
}

/// [`apply_batch2_reuse`] with progress marks.
pub fn apply_batch2_reuse_marked(s_old: &State, batch_vals: &[u32], mark: &mut impl FnMut(Mark)) -> State {
    literal(s_old, batch_vals, mark, true)
}

fn literal(s_old: &State, batch_vals: &[u32], mark: &mut impl FnMut(Mark), reuse: bool) -> State {
    // ---- build_bm2 (gk_bandmerge.rs:1538-1573)
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;
    let n_prev = s_old.n;
    let n_t = n_prev + batch_vals.len() as u64;
    let theta = n_t / s_old.params.s;

    // combined = init ‖ fresh singletons (g₁=g₂=0, Δ=0), padded to `total`.
    let mut combined: Vec<Tuple> = s_old.tuples.clone();
    for j in 0..m {
        if j < batch_vals.len() {
            combined.push(Tuple {
                e: batch_vals[j],
                g: 0,
                g_o: 0,
                delta: 0,
                delta_o: 0,
                t: n_prev + 1 + j as u64,
                active: 1,
            });
        } else {
            combined.push(Tuple::dummy());
        }
    }

    // value-sort by (e, t): actives first (e < E_MAX), dummies last.
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| (combined[i].e, combined[i].t));
    let union_raw: Vec<Tuple> = idx.iter().map(|&i| combined[i]).collect();
    mark(Mark::UnionBuilt);

    // ---- finish_bm2 (gk_bandmerge.rs:1576-1646)
    let total = union_raw.len();

    // two-sided neighbor-init: Δ₁ from the right (right-to-left), Δ₂ from the
    // left (left-to-right). (zkSketch clones union_raw here to keep it as a
    // witness; nothing reads it afterwards, so the port moves it.)
    let mut union_init = union_raw;
    for i in (0..total).rev() {
        if union_init[i].active == 1 && union_init[i].t > n_prev {
            union_init[i].delta = if i + 1 < total { union_init[i + 1].g + union_init[i + 1].delta } else { 0 };
        }
    }
    for i in 0..total {
        if union_init[i].active == 1 && union_init[i].t > n_prev {
            union_init[i].delta_o = if i >= 1 { union_init[i - 1].g_o + union_init[i - 1].delta_o } else { 0 };
        }
    }
    mark(Mark::NeighborInit);

    // L_f parity-0 fuse + resort rounds.
    let lf = num_rounds(total);
    let mut cur = union_init;
    if !reuse {
        for _ in 0..lf {
            let mut fused = vec![Tuple::dummy(); total];
            let (fold_right, fold_left) = fuse_round_fixed2(&cur, theta, &mut fused);
            let mut ridx: Vec<usize> = (0..total).collect();
            ridx.sort_by_key(|&i| (fused[i].e, fused[i].t));
            let resorted: Vec<Tuple> = ridx.iter().map(|&i| fused[i]).collect();
            cur = resorted;
            mark(Mark::RoundDone { fold_right, fold_left });
        }
    } else {
        let mut fused = vec![Tuple::dummy(); total];
        let mut ridx: Vec<usize> = Vec::with_capacity(total);
        let mut next = vec![Tuple::dummy(); total];
        for _ in 0..lf {
            let (fold_right, fold_left) = fuse_round_fixed2(&cur, theta, &mut fused);
            ridx.clear();
            ridx.extend(0..total);
            ridx.sort_by_key(|&i| (fused[i].e, fused[i].t));
            for (dst, &i) in next.iter_mut().zip(&ridx) {
                *dst = fused[i];
            }
            core::mem::swap(&mut cur, &mut next);
            mark(Mark::RoundDone { fold_right, fold_left });
        }
    }

    // final = first cap rows (zkSketch also slices cur[cap..cap+m] as `excess`,
    // read only by apply_batch2's debug_assert, which release builds compile out).
    let final_tuples = cur[..cap].to_vec();
    State { tuples: final_tuples, params: s_old.params, n: n_t }
}

/// `fuse_round_fixed2` (`gk_bandmerge.rs:1445-1505`), literal port without the
/// witness vectors (`dirs`, `c1s`, `c2s`). Pairs `(2i, 2i+1)`; direction `1`
/// folds the left (younger) tuple into the right one, `2` the right (younger)
/// into the left one, `0` keeps both. For an odd `total` the last row is never
/// paired and, as in zkSketch, comes out a dummy. Writes every row of `fused`
/// (zkSketch starts from an all-dummy table; every row is overwritten either way).
/// Returns the number of direction-1 and direction-2 merges.
fn fuse_round_fixed2(cur: &[Tuple], theta: u64, fused: &mut [Tuple]) -> (u32, u32) {
    let total = cur.len();
    let (mut fold_right, mut fold_left) = (0u32, 0u32);
    assert_eq!(fused.len(), total);
    if total % 2 == 1 {
        fused[total - 1] = Tuple::dummy();
    }
    for i in 0..total / 2 {
        let a = cur[2 * i];
        let bb = cur[2 * i + 1];
        // sum1 = g₁ₐ+g₂ₐ+g₁_b+Δ₁_b+1 (case-1 / newer-left survivor's post-merge g₁+Δ₁);
        // sum2 = g₂_b+g₁_b+g₂ₐ+Δ₂ₐ+1 (case-2 / newer-right survivor's post-merge g₂+Δ₂).
        let sum1 = a.g + a.g_o + bb.g + bb.delta + 1;
        let sum2 = bb.g_o + bb.g + a.g_o + a.delta_o + 1;
        let cond1 = (sum1 <= theta) as u32;
        let cond2 = (sum2 <= theta) as u32;
        let both = a.active == 1 && bb.active == 1;
        let dir: u8 = if !both {
            0
        } else if a.t > bb.t {
            if cond1 == 1 { 1 } else { 0 }
        } else if cond2 == 1 {
            2
        } else {
            0
        };
        match dir {
            1 => {
                fold_right += 1;
                fused[2 * i] = Tuple::dummy();
                fused[2 * i + 1] = Tuple {
                    e: bb.e,
                    g: a.g + a.g_o + bb.g + 1,
                    g_o: bb.g_o,
                    delta: bb.delta,
                    delta_o: bb.delta_o,
                    t: bb.t,
                    active: 1,
                };
            }
            2 => {
                fold_left += 1;
                fused[2 * i] = Tuple {
                    e: a.e,
                    g: a.g,
                    g_o: bb.g_o + bb.g + a.g_o + 1,
                    delta: a.delta,
                    delta_o: a.delta_o,
                    t: a.t,
                    active: 1,
                };
                fused[2 * i + 1] = Tuple::dummy();
            }
            _ => {
                fused[2 * i] = a;
                fused[2 * i + 1] = bb;
            }
        }
    }
    (fold_right, fold_left)
}

// ===========================================================================
// FAST: the same function with a data-dependent schedule.
// ===========================================================================

/// Why `s` is not in the canonical form [`apply_batch2`] outputs, if it is not:
/// exactly `capacity` rows; a prefix of actives (`active == 1`, `e < E_MAX`,
/// `t <= n`) strictly increasing in `(e, t)`; then canonical dummies only.
pub fn canonical_violation(s: &State) -> Option<&'static str> {
    if s.tuples.len() != s.params.capacity {
        return Some("tuple count != capacity");
    }
    if s.params.s == 0 {
        return Some("s = 0");
    }
    let mut prev: Option<(u32, u64)> = None;
    let mut in_dummies = false;
    for t in &s.tuples {
        if !in_dummies && t.active == 1 {
            if t.e >= E_MAX {
                return Some("active value >= E_MAX");
            }
            if t.t > s.n {
                return Some("active insertion time > n");
            }
            if let Some(p) = prev {
                if (t.e, t.t) <= p {
                    return Some("actives not strictly increasing in (e, t)");
                }
            }
            prev = Some((t.e, t.t));
        } else if *t == Tuple::dummy() {
            in_dummies = true;
        } else {
            return Some("non-canonical dummy, or an active after a dummy");
        }
    }
    None
}

/// Radix digit width of the fresh-value sort in [`sorted_active_union`]: two
/// digits cover every value below `E_MAX < 2^22`.
const RADIX_BITS: u32 = 11;
const RADIX: usize = 1 << RADIX_BITS;

/// The `(e, t)`-sorted ACTIVE prefix of `apply_batch2`'s union: the old actives
/// merged with one fresh singleton per value. Only the first `m` values enter the
/// table, as in zkSketch. The fresh rows are sorted by `(e, t)` = (value, batch
/// position) with a stable LSD radix sort of the batch positions on the value,
/// two 11-bit digits (values < `E_MAX` < 2^22), then merged with the old actives,
/// which are already `(e, t)`-sorted; every old `t <= n_prev` is below every
/// fresh `t`, so an old row goes first on equal values. On a canonical `s_old`
/// the full union is this prefix followed by dummies. `extra` is spare capacity
/// reserved past the prefix (a caller that pads the table to `capacity + m`
/// rows asks for it here instead of reallocating).
fn sorted_active_union(s_old: &State, batch_vals: &[u32], extra: usize) -> Vec<Tuple> {
    let m = s_old.params.batch;
    let n_prev = s_old.n;
    let k = batch_vals.len().min(m);
    let vals = &batch_vals[..k];
    assert!(vals.iter().all(|&v| v < E_MAX), "sorted_active_union: batch value >= E_MAX");
    let mut order: Vec<u32> = (0..k as u32).collect();
    let mut tmp: Vec<u32> = vec![0; k];
    for shift in [0, RADIX_BITS] {
        let mut cnt = [0u32; RADIX + 1];
        for &v in vals {
            cnt[((v >> shift) as usize & (RADIX - 1)) + 1] += 1;
        }
        for b in 0..RADIX {
            cnt[b + 1] += cnt[b];
        }
        for &p in &order {
            let b = (vals[p as usize] >> shift) as usize & (RADIX - 1);
            tmp[cnt[b] as usize] = p;
            cnt[b] += 1;
        }
        core::mem::swap(&mut order, &mut tmp);
    }

    let old_n = s_old.tuples.iter().take_while(|t| t.active == 1).count();
    let old = &s_old.tuples[..old_n];
    let mut u: Vec<Tuple> = Vec::with_capacity(old_n + k + extra);
    let (mut i, mut j) = (0usize, 0usize);
    while i < old_n || j < k {
        let take_old = j == k || (i < old_n && old[i].e <= vals[order[j] as usize]);
        if take_old {
            u.push(old[i]);
            i += 1;
        } else {
            let p = order[j] as usize;
            u.push(Tuple { e: vals[p], g: 0, g_o: 0, delta: 0, delta_o: 0, t: n_prev + 1 + p as u64, active: 1 });
            j += 1;
        }
    }
    u
}

/// [`apply_batch2`]'s output, computed with a data-dependent schedule (see the
/// crate doc). Panics if `s_old` is not canonical ([`canonical_violation`]) or a
/// batch value is `>= E_MAX` (impossible after [`vals_of`]).
pub fn apply_batch2_fast(s_old: &State, batch_vals: &[u32]) -> State {
    apply_batch2_fast_marked(s_old, batch_vals, &mut |_| {})
}

/// [`apply_batch2_fast`] with progress marks.
pub fn apply_batch2_fast_marked(s_old: &State, batch_vals: &[u32], mark: &mut impl FnMut(Mark)) -> State {
    if let Some(why) = canonical_violation(s_old) {
        panic!("apply_batch2_fast: old state not canonical: {why}");
    }
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;
    let n_prev = s_old.n;
    let n_t = n_prev + batch_vals.len() as u64;
    let theta = n_t / s_old.params.s;

    let mut u = sorted_active_union(s_old, batch_vals, 0);
    mark(Mark::UnionBuilt);

    // Neighbour init over the active prefix. A dummy (or no) neighbour contributes
    // 0 in zkSketch, which is what the prefix bounds give here.
    let a = u.len();
    for i in (0..a).rev() {
        if u[i].t > n_prev {
            u[i].delta = if i + 1 < a { u[i + 1].g + u[i + 1].delta } else { 0 };
        }
    }
    for i in 0..a {
        if u[i].t > n_prev {
            u[i].delta_o = if i >= 1 { u[i - 1].g_o + u[i - 1].delta_o } else { 0 };
        }
    }
    mark(Mark::NeighborInit);

    // Fuse rounds over the active prefix. zkSketch's re-sort by (e, t) only moves
    // the merge-induced dummies to the back (actives stay in increasing (e, t)
    // order), so pushing survivors in order IS the re-sorted active prefix. A
    // round that changes nothing leaves the table unchanged, so every later round
    // does too: stop there.
    let lf = num_rounds(total);
    let mut cur = u;
    let mut next: Vec<Tuple> = Vec::with_capacity(cur.len());
    for _ in 0..lf {
        next.clear();
        let len = cur.len();
        let mut changed = false;
        let (mut fold_right, mut fold_left) = (0u32, 0u32);
        let mut p = 0;
        while p + 1 < len {
            let x = cur[p];
            let y = cur[p + 1];
            if x.t > y.t {
                if x.g + x.g_o + y.g + y.delta + 1 <= theta {
                    next.push(Tuple { g: x.g + x.g_o + y.g + 1, ..y });
                    fold_right += 1;
                    changed = true;
                } else {
                    next.push(x);
                    next.push(y);
                }
            } else if y.g_o + y.g + x.g_o + x.delta_o + 1 <= theta {
                next.push(Tuple { g_o: y.g_o + y.g + x.g_o + 1, ..x });
                fold_left += 1;
                changed = true;
            } else {
                next.push(x);
                next.push(y);
            }
            p += 2;
        }
        if p < len {
            // Unpaired last active: zkSketch pairs it with a dummy (kept), except
            // when it sits in the never-paired last row of an odd, full table.
            if len < total {
                next.push(cur[p]);
            } else {
                changed = true;
            }
        }
        mark(Mark::RoundDone { fold_right, fold_left });
        if !changed {
            break;
        }
        core::mem::swap(&mut cur, &mut next);
    }

    let mut tuples = Vec::with_capacity(cap);
    tuples.extend_from_slice(&cur[..cur.len().min(cap)]);
    tuples.resize(cap, Tuple::dummy());
    State { tuples, params: s_old.params, n: n_t }
}

// ===========================================================================
// FIXED: zkSketch's fixed schedule without the literal port's sorts/allocations.
// ===========================================================================

/// [`apply_batch2`]'s output on zkSketch's FIXED schedule, with linear-time
/// tables. Panics if `s_old` is not canonical ([`canonical_violation`]) or a batch
/// value is `>= E_MAX` (impossible after [`vals_of`]).
///
/// What is kept from zkSketch: the materialised `capacity + m` table, the
/// two-sided neighbour init over every row, all `L_f` rounds whatever the data,
/// every pair `(2i, 2i+1)` visited each round under `fuse_round_fixed2`'s rule,
/// every row rewritten each round, and the odd table's never-paired last row.
/// What changes: the union is [`sorted_active_union`] padded with dummies
/// (linear, where the literal port sorts all `capacity + m` rows by comparison),
/// and each round fuses and compacts in place in the one table, where the literal
/// port writes a fresh `fused` table and stable-sorts it by `(e, t)`. The set of
/// rows and rounds visited is fixed; the work per pair still branches on the data
/// (a dummy pair or a kept pair costs less than a merge), as in the literal port,
/// so the cycle count is not data-independent.
///
/// Why the compaction is that re-sort: from a canonical `s_old`, every row of the
/// table is either an active with `e < E_MAX` or the exact dummy `(E_MAX, 0, ..)`,
/// and the actives sit in a prefix in increasing `(e, t)` order. A fuse round only
/// turns actives into exact dummies; a survivor keeps its own `(e, t)`, so the
/// actives stay in increasing order. A stable sort by `(e, t)` therefore yields
/// the actives in their current order followed by identical dummies, which is
/// what writing the survivors to the front and refilling the rest with dummies
/// yields; the invariant then holds for the next round.
pub fn apply_batch2_fixed(s_old: &State, batch_vals: &[u32]) -> State {
    apply_batch2_fixed_marked(s_old, batch_vals, &mut |_| {})
}

/// [`apply_batch2_fixed`] with progress marks.
pub fn apply_batch2_fixed_marked(s_old: &State, batch_vals: &[u32], mark: &mut impl FnMut(Mark)) -> State {
    if let Some(why) = canonical_violation(s_old) {
        panic!("apply_batch2_fixed: old state not canonical: {why}");
    }
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;
    let n_prev = s_old.n;
    let n_t = n_prev + batch_vals.len() as u64;
    let theta = n_t / s_old.params.s;

    // The union, padded with dummies to the full table (one allocation).
    let mut cur = sorted_active_union(s_old, batch_vals, total);
    cur.resize(total, Tuple::dummy());
    mark(Mark::UnionBuilt);

    // Two-sided neighbour init over every row, statement for statement as in the
    // literal port.
    for i in (0..total).rev() {
        if cur[i].active == 1 && cur[i].t > n_prev {
            cur[i].delta = if i + 1 < total { cur[i + 1].g + cur[i + 1].delta } else { 0 };
        }
    }
    for i in 0..total {
        if cur[i].active == 1 && cur[i].t > n_prev {
            cur[i].delta_o = if i >= 1 { cur[i - 1].g_o + cur[i - 1].delta_o } else { 0 };
        }
    }
    mark(Mark::NeighborInit);

    for _ in 0..num_rounds(total) {
        let (fold_right, fold_left) = fuse_round_compact(&mut cur, theta);
        mark(Mark::RoundDone { fold_right, fold_left });
    }

    cur.truncate(cap);
    State { tuples: cur, params: s_old.params, n: n_t }
}

/// One `fuse_round_fixed2` round followed by the stable `(e, t)` re-sort, in place,
/// on a table in the invariant form of [`apply_batch2_fixed`]. Every pair is
/// evaluated with zkSketch's sums and conditions; the survivors are written to
/// the front in order (the write index never passes the pair being read), and
/// every remaining row, the never-paired last row of an odd table included, is
/// rewritten as a dummy. Returns the direction-1 and direction-2 merge counts.
fn fuse_round_compact(cur: &mut [Tuple], theta: u64) -> (u32, u32) {
    let total = cur.len();
    let (mut fold_right, mut fold_left) = (0u32, 0u32);
    let mut w = 0usize;
    for i in 0..total / 2 {
        let a = cur[2 * i];
        let bb = cur[2 * i + 1];
        let sum1 = a.g + a.g_o + bb.g + bb.delta + 1;
        let sum2 = bb.g_o + bb.g + a.g_o + a.delta_o + 1;
        let cond1 = sum1 <= theta;
        let cond2 = sum2 <= theta;
        let both = a.active == 1 && bb.active == 1;
        if both && a.t > bb.t && cond1 {
            fold_right += 1;
            cur[w] = Tuple { e: bb.e, g: a.g + a.g_o + bb.g + 1, g_o: bb.g_o, delta: bb.delta, delta_o: bb.delta_o, t: bb.t, active: 1 };
            w += 1;
        } else if both && a.t <= bb.t && cond2 {
            fold_left += 1;
            cur[w] = Tuple { e: a.e, g: a.g, g_o: bb.g_o + bb.g + a.g_o + 1, delta: a.delta, delta_o: a.delta_o, t: a.t, active: 1 };
            w += 1;
        } else {
            if a.active == 1 {
                cur[w] = a;
                w += 1;
            }
            if bb.active == 1 {
                cur[w] = bb;
                w += 1;
            }
        }
    }
    for r in &mut cur[w..] {
        *r = Tuple::dummy();
    }
    (fold_right, fold_left)
}

// ===========================================================================
// Word encoding (host <-> guest wire format) and SHA-256 commitments.
// ===========================================================================

/// State header: capacity, batch, s, n, tuple count, each a u64 as (lo, hi) words.
pub const STATE_HDR_WORDS: usize = 10;
/// Per tuple: e, g, g°, Delta, Delta°, t, active; u64 fields as (lo, hi) words.
pub const TUPLE_WORDS: usize = 12;

pub fn state_words_len(n_tuples: usize) -> usize {
    STATE_HDR_WORDS + TUPLE_WORDS * n_tuples
}

fn put64(w: &mut Vec<u32>, v: u64) {
    w.push(v as u32);
    w.push((v >> 32) as u32);
}

fn get64(w: &[u32], i: usize) -> u64 {
    w[i] as u64 | (w[i + 1] as u64) << 32
}

pub fn state_to_words(st: &State) -> Vec<u32> {
    let mut w = Vec::with_capacity(state_words_len(st.tuples.len()));
    put64(&mut w, st.params.capacity as u64);
    put64(&mut w, st.params.batch as u64);
    put64(&mut w, st.params.s);
    put64(&mut w, st.n);
    put64(&mut w, st.tuples.len() as u64);
    for t in &st.tuples {
        w.push(t.e);
        put64(&mut w, t.g);
        put64(&mut w, t.g_o);
        put64(&mut w, t.delta);
        put64(&mut w, t.delta_o);
        put64(&mut w, t.t);
        w.push(t.active);
    }
    w
}

pub fn state_from_words(w: &[u32]) -> State {
    assert!(w.len() >= STATE_HDR_WORDS, "state encoding shorter than its header");
    let usz = |v: u64| -> usize {
        assert!(v <= usize::MAX as u64, "state header field exceeds usize");
        v as usize
    };
    let params = Params { capacity: usz(get64(w, 0)), batch: usz(get64(w, 2)), s: get64(w, 4) };
    let n = get64(w, 6);
    let k = usz(get64(w, 8));
    assert_eq!(w.len(), state_words_len(k), "state encoding length != header tuple count");
    let mut tuples = Vec::with_capacity(k);
    for r in 0..k {
        let b = STATE_HDR_WORDS + TUPLE_WORDS * r;
        tuples.push(Tuple {
            e: w[b],
            g: get64(w, b + 1),
            g_o: get64(w, b + 3),
            delta: get64(w, b + 5),
            delta_o: get64(w, b + 7),
            t: get64(w, b + 9),
            active: w[b + 11],
        });
    }
    State { tuples, params, n }
}

/// Domain tags, named after zk-Analytics' TAG_* scheme like `../../gk/core`'s.
pub const TAG_STATE: &[u8] = b"ZKSK_GK_BM2_STATE_V1";
pub const TAG_BATCH: &[u8] = b"ZKSK_GK_BM2_BATCH_V1";

/// `Com(S)` = SHA-256(TAG_STATE || LE bytes of [`state_to_words`]`(S)`), unsalted.
pub fn state_commit_words(words: &[u32]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(TAG_STATE);
    sha.update(bytemuck::cast_slice::<u32, u8>(words));
    sha.finalize().into()
}

pub fn state_commit(st: &State) -> [u8; 32] {
    state_commit_words(&state_to_words(st))
}

/// `Com(batch)` = SHA-256(TAG_BATCH || u32 LE key count || LE bytes of the raw
/// keys), unsalted. The raw wire batch (PAD_KEY slots included) is committed,
/// before the `gk_vals_of` mapping.
pub fn batch_commit(keys: &[u32]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(TAG_BATCH);
    sha.update(&(keys.len() as u32).to_le_bytes());
    sha.update(bytemuck::cast_slice::<u32, u8>(keys));
    sha.finalize().into()
}

// ===========================================================================
// Guest I/O protocol (all u32 words; env::read_slice / env::write_slice).
// ===========================================================================

/// stdin: `[IN_MAGIC, variant, emit_state, n_state_words, n_keys]`, then the old
/// state's words, then the raw keys.
pub const IN_MAGIC: u32 = 0x4742_4D32; // "GBM2"
pub const IN_HDR_WORDS: usize = 5;
pub const VARIANT_LITERAL: u32 = 0;
pub const VARIANT_FAST: u32 = 1;
pub const VARIANT_LITERAL_REUSE: u32 = 2;
pub const VARIANT_FIXED_LINEAR: u32 = 3;

/// journal: `Com_old || Com_batch || Com_new` (96 raw bytes, `env::commit_slice`).
pub const JOURNAL_BYTES: usize = 96;

/// stdout (private, not in the receipt): `[OUT_MAGIC, N_PROBES]`, the probes as
/// (lo, hi) word pairs, then, if `emit_state`, the new state's words.
pub const OUT_MAGIC: u32 = 0x4742_4F55; // "GBOU"
/// Probe order: env::cycle_count() at main entry, after reading the input, after
/// committing the old state and the batch, after decoding + mapping, at
/// UnionBuilt, at NeighborInit, at the last RoundDone, after the transition,
/// after encoding + committing the new state, after the journal commit; then the
/// number of fuse rounds evaluated and the total direction-1 / direction-2 merges.
pub const N_PROBES: usize = 13;
pub const PROBE_NAMES: [&str; N_PROBES] = [
    "start",
    "read",
    "commit_in",
    "decode_map",
    "union_built",
    "neighbor_init",
    "rounds_done",
    "transition",
    "commit_out",
    "journal",
    "rounds_run",
    "fold_right",
    "fold_left",
];
