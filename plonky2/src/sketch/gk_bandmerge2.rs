//! Plaintext **two-sided** Greenwald–Khanna band-merge sketch (paper §5.2, the
//! Gribelyuk mirror construction) for plonky2 / Goldilocks.
//!
//! Port of `../src/sketch/gk_bandmerge.rs` `apply_batch2` / `build_bm2` (the
//! `bandmerge2` variant the streaming forest deploys), NOT the one-sided fusion
//! GK in [`super::greenwald_khanna`]. A representative tuple is
//! `(e, g, g°, Δ, Δ°, t)` — the mirror doubles the one-sided `(g, Δ)` into a
//! **left** pair `(g, Δ)` (mass/uncertainty of covered elements `≺ e`) and a
//! **right** pair `(g°, Δ°)` (covered elements `≻ e`), so `Σ_active (g+g°+1) = N`.
//!
//! The batched update (`apply_batch2`): union `S_old ‖ fresh`, value-sort by
//! `(e, t)`, two-sided neighbor-init the fresh tuples' `Δ, Δ°`, run
//! `L_f = ⌈log₂(cap+m)⌉` parity-0 fuse+resort rounds (each round tests every
//! adjacent pair for the two-sided merge threshold `g+…+Δ ≤ θ = ⌊N_t/s⌋` and
//! folds the newer tuple into the older, direction chosen by `t`), then compact
//! to `capacity`. [`build_bm2`] additionally captures every intermediate table
//! (union permutation, per-round decisions/fused/resorted) that the in-circuit
//! certificate ([`crate::leaf::gk_bandmerge2`]) binds.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::config::F;

/// Value-field width: real values `e < E_MAX`; `E_MAX` is the reserved dummy
/// sentinel (sorts to the back by `(e, t)`).
pub const E_BITS: usize = 22;
pub const E_MAX: u32 = (1 << E_BITS) - 1;
/// Mass/uncertainty field width (`g, g°, Δ, Δ°, t < 2^MASS_BITS`).
pub const MASS_BITS: usize = 24;
/// Cells committed per tuple: `(e, g, g°, Δ, Δ°, t)`. `active` is NOT committed —
/// it is derived in-circuit as `[e ≠ E_MAX]` (dummies are the only `e = E_MAX`
/// tuples), matching the plonky3 circuit's `force_nz(E_MAX − e)`.
pub const TUPLE_CELLS: usize = 6;

/// A two-sided GK representative tuple. A dummy is `(E_MAX,0,0,0,0,0)` inactive.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Gk2Tuple {
    pub e: u32,
    /// `g`  = |S_e|:  rank mass of covered elements `≺ e` (left).
    pub g: u64,
    /// `g°` = |S°_e|: rank mass of covered elements `≻ e` (right).
    pub g_o: u64,
    /// `Δ`:  uncertainty toward the value-successor (right) neighbor.
    pub delta: u64,
    /// `Δ°`: uncertainty toward the value-predecessor (left) neighbor.
    pub delta_o: u64,
    pub t: u64,
    pub active: u64,
}

impl Gk2Tuple {
    pub fn dummy() -> Self {
        Self { e: E_MAX, g: 0, g_o: 0, delta: 0, delta_o: 0, t: 0, active: 0 }
    }
    /// Total mass this representative accounts for: its two sets plus itself.
    pub fn mass(&self) -> u64 {
        self.g + self.g_o + 1
    }
    /// Flattened `(e, g, g°, Δ, Δ°, t)` — the commit / circuit cell layout
    /// (`active` derived from `e`).
    pub fn cells(&self) -> [F; TUPLE_CELLS] {
        [
            F::from_canonical_u64(self.e as u64),
            F::from_canonical_u64(self.g),
            F::from_canonical_u64(self.g_o),
            F::from_canonical_u64(self.delta),
            F::from_canonical_u64(self.delta_o),
            F::from_canonical_u64(self.t),
        ]
    }
}

/// GK shape: keep `capacity` value-sorted tuples; ingest `batch` records/epoch.
/// `s = 1/ε` sets the merge threshold `θ_t = ⌊N_t / s⌋`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Gk2Params {
    pub capacity: usize,
    pub batch: usize,
    pub s: u64,
}

impl Gk2Params {
    pub fn union_size(&self) -> usize {
        self.capacity + self.batch
    }
    pub fn validate(&self) {
        assert!(self.capacity >= 1, "capacity >= 1");
        assert!(self.batch >= 1, "batch >= 1");
        assert!(self.s >= 1, "s >= 1");
    }
}

/// A two-sided GK summary: `capacity` value-sorted tuples (dummies pad) + the
/// cumulative record count `N`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gk2State {
    pub tuples: Vec<Gk2Tuple>,
    pub params: Gk2Params,
    pub n: u64,
}

impl Gk2State {
    pub fn empty(params: Gk2Params) -> Self {
        Self { tuples: vec![Gk2Tuple::dummy(); params.capacity], params, n: 0 }
    }

    pub fn actives(&self) -> Vec<Gk2Tuple> {
        self.tuples.iter().copied().filter(|t| t.active == 1).collect()
    }

    /// S³ two-sided rank interval for `q`: the true rank of `q` lies in
    /// `[r_min, r_max]` with `r_min = P_i − g°_i − Δ°_i`,
    /// `r_max = P_i + g_{i+1} + Δ_{i+1}` for the bracket `e_i ≤ q`.
    pub fn rank_interval(&self, q: u32) -> (u64, u64) {
        let a = self.actives();
        let mut prefix = 0u64;
        let mut pi = 0u64;
        let mut bracket: Option<usize> = None;
        for (i, tup) in a.iter().enumerate() {
            prefix += tup.mass();
            if tup.e <= q {
                bracket = Some(i);
                pi = prefix;
            }
        }
        match bracket {
            None => (0, if a.is_empty() { 0 } else { a[0].g + a[0].delta }),
            Some(i) => {
                let r_min = pi.saturating_sub(a[i].g_o + a[i].delta_o);
                let r_max = if i + 1 < a.len() { pi + a[i + 1].g + a[i + 1].delta } else { pi };
                (r_min, r_max)
            }
        }
    }

    /// Midpoint rank estimate (true rank within additive `εN`).
    pub fn rank(&self, q: u32) -> u64 {
        let (lo, hi) = self.rank_interval(q);
        (lo + hi) / 2
    }

    /// Flattened tuple cells — the commit pre-image (matches the in-circuit
    /// `final_cells` layout).
    pub fn cells(&self) -> Vec<F> {
        self.tuples.iter().flat_map(|t| t.cells()).collect()
    }

    pub fn commit(&self) -> HashOut<F> {
        PoseidonHash::hash_no_pad(&self.cells())
    }
}

/// The fresh singletons a batch inserts: active value `v` → `(v,0,0,0,0,t)`;
/// padding → the `E_MAX` dummy. `t = n_prev + 1 + j`.
pub fn fresh_tuples2(vals: &[u32], m: usize, n_prev: u64) -> Vec<Gk2Tuple> {
    (0..m)
        .map(|j| {
            if j < vals.len() {
                Gk2Tuple { e: vals[j], g: 0, g_o: 0, delta: 0, delta_o: 0, t: n_prev + 1 + j as u64, active: 1 }
            } else {
                Gk2Tuple::dummy()
            }
        })
        .collect()
}

/// Batch commit pre-image: the fresh singletons' cells (the circuit binds the
/// same, so `Com(B_t)` fully determines the inserted values).
pub fn batch_commit(vals: &[u32], m: usize, n_prev: u64) -> HashOut<F> {
    let fresh = fresh_tuples2(vals, m, n_prev);
    let cells: Vec<F> = fresh.iter().flat_map(|t| t.cells()).collect();
    PoseidonHash::hash_no_pad(&cells)
}

/// Smallest `L` with `2^L ≥ total` (the §5.2 `⌈log₂ M⌉` fusion schedule).
pub fn num_rounds(total: usize) -> usize {
    if total <= 1 {
        0
    } else {
        (usize::BITS - (total - 1).leading_zeros()) as usize
    }
}

/// One fixed-size parity-0 two-sided fuse round over pairs `(2i, 2i+1)`. Returns
/// `(fused, dirs, cond1, cond2)`: `dir ∈ {0 none, 1 a→b, 2 b→a}` and the two
/// threshold booleans (the circuit re-derives the direction from these hints).
/// `theta = ⌊N_t/s⌋`.
pub fn fuse_round_fixed2(cur: &[Gk2Tuple], theta: u64) -> (Vec<Gk2Tuple>, Vec<u8>, Vec<u64>, Vec<u64>) {
    let total = cur.len();
    let mut fused = vec![Gk2Tuple::dummy(); total];
    let mut dirs = Vec::with_capacity(total / 2);
    let mut c1s = Vec::with_capacity(total / 2);
    let mut c2s = Vec::with_capacity(total / 2);
    for i in 0..total / 2 {
        let a = cur[2 * i];
        let bb = cur[2 * i + 1];
        // sum1 = case-1 (newer-left) survivor's post-merge g+Δ;
        // sum2 = case-2 (newer-right) survivor's post-merge g°+Δ°.
        let sum1 = a.g + a.g_o + bb.g + bb.delta + 1;
        let sum2 = bb.g_o + bb.g + a.g_o + a.delta_o + 1;
        let cond1 = (sum1 <= theta) as u64;
        let cond2 = (sum2 <= theta) as u64;
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
        c1s.push(cond1);
        c2s.push(cond2);
        dirs.push(dir);
        match dir {
            1 => {
                fused[2 * i] = Gk2Tuple::dummy();
                fused[2 * i + 1] = Gk2Tuple {
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
                fused[2 * i] = Gk2Tuple {
                    e: a.e,
                    g: a.g,
                    g_o: bb.g_o + bb.g + a.g_o + 1,
                    delta: a.delta,
                    delta_o: a.delta_o,
                    t: a.t,
                    active: 1,
                };
                fused[2 * i + 1] = Gk2Tuple::dummy();
            }
            _ => {
                fused[2 * i] = a;
                fused[2 * i + 1] = bb;
            }
        }
    }
    (fused, dirs, c1s, c2s)
}

/// Per-round witness the circuit binds.
pub struct Bm2Round {
    pub dir: Vec<u8>,
    pub cond1: Vec<u64>,
    pub cond2: Vec<u64>,
    pub fused: Vec<Gk2Tuple>,
    pub resorted: Vec<Gk2Tuple>,
    pub sigma: Vec<usize>,
}

/// The full witness-capturing replay of the two-sided band-merge.
pub struct Bm2Build {
    pub sigma_union: Vec<usize>,
    pub union_raw: Vec<Gk2Tuple>,
    pub union_init: Vec<Gk2Tuple>,
    pub rounds: Vec<Bm2Round>,
    pub final_tuples: Vec<Gk2Tuple>,
    pub excess: Vec<Gk2Tuple>,
    pub theta: u64,
    pub n_prev: u64,
    pub n_t: u64,
}

/// Fixed-size replay of `apply_batch2` capturing every intermediate table.
pub fn build_bm2(s_old: &Gk2State, batch_vals: &[u32]) -> Bm2Build {
    let cap = s_old.params.capacity;
    let m = s_old.params.batch;
    let total = cap + m;
    let n_prev = s_old.n;
    let n_t = n_prev + batch_vals.len() as u64;
    let theta = n_t / s_old.params.s;

    // combined = init ‖ fresh singletons, padded to `total`.
    let mut combined: Vec<Gk2Tuple> = s_old.tuples.clone();
    combined.extend(fresh_tuples2(batch_vals, m, n_prev));

    // value-sort by (e, t): actives first (e < E_MAX), dummies last.
    let mut idx: Vec<usize> = (0..total).collect();
    idx.sort_by_key(|&i| (combined[i].e, combined[i].t));
    let sigma_union = idx.clone();
    let union_raw: Vec<Gk2Tuple> = idx.iter().map(|&i| combined[i]).collect();

    // two-sided neighbor-init the FRESH tuples (t > n_prev): Δ from the right
    // (right-to-left pass), Δ° from the left (left-to-right pass).
    let mut union_init = union_raw.clone();
    for i in (0..total).rev() {
        if union_init[i].active == 1 && union_init[i].t > n_prev {
            union_init[i].delta =
                if i + 1 < total { union_init[i + 1].g + union_init[i + 1].delta } else { 0 };
        }
    }
    for i in 0..total {
        if union_init[i].active == 1 && union_init[i].t > n_prev {
            union_init[i].delta_o =
                if i >= 1 { union_init[i - 1].g_o + union_init[i - 1].delta_o } else { 0 };
        }
    }

    // L_f parity-0 fuse + resort rounds.
    let lf = num_rounds(total);
    let mut cur = union_init.clone();
    let mut rounds = Vec::with_capacity(lf);
    for _ in 0..lf {
        let (fused, dir, cond1, cond2) = fuse_round_fixed2(&cur, theta);
        let mut ridx: Vec<usize> = (0..total).collect();
        ridx.sort_by_key(|&i| (fused[i].e, fused[i].t));
        let resorted: Vec<Gk2Tuple> = ridx.iter().map(|&i| fused[i]).collect();
        rounds.push(Bm2Round { dir, cond1, cond2, fused, resorted: resorted.clone(), sigma: ridx });
        cur = resorted;
    }

    let final_tuples = cur[..cap].to_vec();
    let excess = cur[cap..cap + m].to_vec();
    Bm2Build { sigma_union, union_raw, union_init, rounds, final_tuples, excess, theta, n_prev, n_t }
}

/// Apply a batch of inserted values to the two-sided sketch.
pub fn apply_batch2(s_old: &Gk2State, batch_vals: &[u32]) -> Gk2State {
    let b = build_bm2(s_old, batch_vals);
    debug_assert!(
        b.excess.iter().all(|t| t.active == 0),
        "two-sided sketch exceeded capacity {} (declare s' ≥ 2s·ln(N/s+2)+2)",
        s_old.params.capacity
    );
    Gk2State { tuples: b.final_tuples, params: s_old.params, n: b.n_t }
}

/// The Gribelyuk §4 worst-case space bound `s'(N) = ⌈2s·ln(N/s + 2) + 2⌉`.
pub fn gribelyuk_space_bound(n: u64, s: u64) -> usize {
    (2.0 * s as f64 * ((n as f64 / s as f64) + 2.0).ln() + 2.0).ceil() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Gk2Params {
        Gk2Params { capacity: 8, batch: 4, s: 2 }
    }

    /// Mass conservation: every active insert adds exactly 1 to `Σ(g+g°+1)`.
    #[test]
    fn mass_conserved() {
        let s0 = Gk2State::empty(params());
        let s1 = apply_batch2(&s0, &[5, 5, 9, 5]);
        let total_mass: u64 = s1.actives().iter().map(|t| t.mass()).sum();
        assert_eq!(total_mass, 4, "4 active inserts ⇒ N = 4");
        assert_eq!(s1.n, 4);
    }

    /// Rank monotonicity + the two-sided estimate brackets the truth.
    #[test]
    fn rank_brackets_truth() {
        let s0 = Gk2State::empty(Gk2Params { capacity: 16, batch: 8, s: 2 });
        // insert 8 distinct-ish values; rank(q) ≈ #{inserted ≤ q}.
        let vals = [3u32, 1, 4, 1, 5, 9, 2, 6];
        let s1 = apply_batch2(&s0, &vals);
        let (lo, hi) = s1.rank_interval(5);
        let truth = vals.iter().filter(|&&v| v <= 5).count() as u64; // = 7
        assert!(lo <= truth && truth <= hi, "rank interval [{lo},{hi}] must bracket truth {truth}");
    }

    /// Commit changes with state; empty vs non-empty differ.
    #[test]
    fn commit_changes_with_state() {
        let s0 = Gk2State::empty(params());
        let s1 = apply_batch2(&s0, &[3, 0, 0, 0]);
        assert_ne!(s0.commit(), s1.commit());
    }

    /// Two-epoch chain: `S_0 → S_1 → S_2`, `n` accumulates, boundaries thread.
    #[test]
    fn two_epoch_chain() {
        let p = Gk2Params { capacity: 16, batch: 4, s: 2 };
        let s0 = Gk2State::empty(p);
        let s1 = apply_batch2(&s0, &[5, 7, 11, 13]);
        let s2 = apply_batch2(&s1, &[6, 7, 12, 14]);
        assert_eq!(s1.n, 4);
        assert_eq!(s2.n, 8);
        // The build's captured union/rounds are self-consistent (fixed size).
        let bm = build_bm2(&s1, &[6, 7, 12, 14]);
        assert_eq!(bm.union_raw.len(), p.union_size());
        assert_eq!(bm.rounds.len(), num_rounds(p.union_size()));
        assert_eq!(bm.final_tuples.len(), p.capacity);
    }
}
