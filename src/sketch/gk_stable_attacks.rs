//! **G-sound: trace-level forgeries against the StableCompact (G1) leaf.**
//!
//! A malicious prover is not bound by the honest witness runner: it may hand
//! `prove_all_tables` any traces. Every attack here builds a forged witness
//! with a field-exact mirror of [`build_gkb2_leaf_stable`] ([`simulate`],
//! checked bit for bit against `stable_rounds` / `pack_stable_out`) and turns
//! it into traces WITHOUT the honest runner's refusals:
//!
//! * forged permute outputs ([`forge_permute_outputs`]) — a permute op may
//!   emit anything; only the shared PermuteBus multiset can object;
//! * forged range decompositions ([`RangeBypass`]) — every `add_range_bits`
//!   byte hint writes bytes that recompose the (out-of-range) value exactly
//!   in the field, with a non-byte top limb; only the Range lookup can object;
//! * non-boolean "bits" — the runner records `assert_bool` rows unchecked;
//!   only the ALU BoolCheck constraint can object;
//! * forged recompose rows ([`ForgedRecompose`]) — the emitted row's packed
//!   value differs from its coefficient wires; only the recompose/coeff
//!   WitnessChecks receives can object;
//! * split wires ([`split_alu_conflicts`]) — where a `connect` would make the
//!   runner refuse (a row computes a value that differs from the merged wire's
//!   other occurrences), that ALU / hint / NPO output is re-pointed to a
//!   scratch slot. The trace then carries two values for one witness id, so
//!   only the WitnessChecks LogUp bus can object (the prover data, built from
//!   the unmodified circuit, still names the original witness id).
//!
//! Every tool is transparent on honest witnesses
//! (`attack_pipeline_is_transparent_on_honest_witnesses`: zero split rows,
//! the native state certified), so a rejection is caused by the forgery.
//!
//! Each attack has a **positive control**: the forgery against the leaf built
//! without the targeted check(s) ([`StableChecks`], or the crate's unbound
//! recompose lowering) must prove, self-verify and certify exactly the forged,
//! WRONG state. Against the deployed leaf it must be rejected by the prover or
//! the verifier, never by the runner (`Verdict::Runner` fails the test). Where
//! the check's own wiring fixes a value (an output pin, the liveness carry,
//! `α^L_cap = 0`), the deployed-leaf forger honours that wiring and breaks the
//! next constraint instead (stated per test).
//!
//! | attack | control removes | deployed leaf rejects by |
//! |---|---|---|
//! | survivors reordered (first / last round) | output pins | PermuteBus |
//! | survivor to the tail, dead row kept | output pins | PermuteBus |
//! | liveness: survivor dropped, folded row resurrected | liveness carry | PermuteBus |
//! | survivor duplicated | — (the permutation itself) | PermuteBus |
//! | non-boolean `α'` (lo halves traded) | `α'` boolean | ALU AIR (BoolCheck) |
//! | wrong direction bit | `lt` range | Range |
//! | under-merge via non-boolean `lt` | `lt` boolean | ALU AIR |
//! | over-budget merge / under-merge | threshold range | Range |
//! | both directions (`cond = 2`, `lt = 1/2`) | `lt` bool+range, `cond` bool, mass | ALU AIR |
//! | forged survivor update (`g₁, g₂, Δ₁, Δ₂, t`) | recompose/coeff binding | WitnessChecks |
//! | fresh tuple moved union → last round | source binding, pins, fresh count | Range + WitnessChecks |
//! | union halves re-paired | source binding | WitnessChecks |
//! | union out of order | union order | Range |
//! | init row `t > N_{t-1}` | init `t ≤ N_{t-1}` + fresh count (each alone rejects) | Range / WitnessChecks |
//! | poisoned dummy | canonical dead rows | WitnessChecks |
//! | crafted huge-`g` init | init ranges | Range |
//! | init `e` beyond `E_MAX` (live after the dummies) | init ranges | Range |
//! | `is_fresh` swapped | `is_fresh` range | Range |
//! | `θ` inflated / `±1` | `θ` binding | Range |
//! | phantom records (`N` shifted) / wrong `N_{t-1}` | mass / count+arrivals+fresh count | WitnessChecks |
//! | arrival positions shifted / swapped | arrival binding | WitnessChecks |
//! | `S = cap + 1` | `α^L_cap = 0` + mass | WitnessChecks (A), PermuteBus (B) |
//! | `S = cap + 1`, each check alone | — (`α^L_cap = 0` alone; mass alone) | WitnessChecks / PermuteBus |
//! | committed final not `α ⊙ R` | final binding | WitnessChecks |
//! | union liveness hint forged | — (`force_nz` is unconditional) | WitnessChecks |
//! | *round 2:* union equal values out of `t` order | union order (tiebreak) | Range |
//! | *round 2:* non-boolean `is_fresh` (`Δ` doubled / shrunk) | `is_fresh` boolean | ALU AIR (BoolCheck) |
//! | *round 2:* batch liveness hint forged | — (`force_nz` is unconditional) | WitnessChecks |
//! | *round 2:* `cond = 1` on a dead pair (probe: no wrong state) | threshold range (control certifies the HONEST state) | Range |
//!
//! Round 2 also re-runs EVERY attack against the deployed layout (`Interval`
//! statement + `Hiding` commitments, the config-B leaf's circuit;
//! `g1_attacks_on_the_deployed_layout*`, both shapes) and the core attacks at
//! the deployed shape itself (cap 768, m 512, `#[ignore]`d:
//! `g1_attacks_at_the_deployed_shape`).
//!
//! Findings recorded by the probes: `cond_bool` is implied by `lt_bool` and
//! the destination binding (a `cond = 2` forgery, which passes the 24-bit
//! threshold test on a fusible pair, is rejected with or without it); the
//! test-only switch combination {pins, carry, `α'` boolean} rejects even
//! honest witnesses (a WitnessChecks creator gap of that combination only),
//! so it is never used as a control.
//!
//! Run: `cargo test --release --lib -- gk_bandmerge::stable_attacks::` (a few
//! minutes; `g1_attacks_at_a_second_shape` repeats every attack at cap 16,
//! m 8, and `g1_attacks_on_the_deployed_layout*` repeat them on the
//! Interval + Hiding leaf).

use super::*;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};

use p3_circuit::ops::recompose::RecomposeExecutionState;
use p3_circuit::ops::{
    ExecutionContext, HintExecutor, NonPrimitiveExecutor, NpoPrivateData, OpStateMap,
    PreprocessedWriter, RecomposeCircuitRow,
};
use p3_circuit::{AluOpKind, Circuit, CircuitError, NpoTypeId, Op, WitnessId};
use p3_field::{BasedVectorSpace, Field, PrimeField64};

use crate::commitment::hiding::SaltSeed;
use crate::sketch::forge::catch_msg;
use crate::sketch::forge_permute::forge_permute_outputs;

const P: u64 = 2_013_265_921;

fn fv(x: u64) -> Val {
    Val::from_u64(x)
}
fn can(x: Val) -> u64 {
    x.as_canonical_u64()
}
/// A field element read as a "negative" small integer (`x > p/2`).
fn neg(x: Val) -> bool {
    can(x) > P / 2
}
fn bit(b: bool) -> Val {
    if b { Val::ONE } else { Val::ZERO }
}
fn inv0(x: Val) -> Val {
    if x == Val::ZERO { Val::ZERO } else { x.inverse() }
}
fn pack4(c: [Val; 4]) -> Challenge {
    Challenge::from_basis_coefficients_slice(&c).expect("4 coeffs")
}
fn unpack4(x: Challenge) -> [Val; 4] {
    let s = x.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}
fn emb(v: Val) -> Challenge {
    Challenge::from(v)
}
/// Committed (`enc2`) layout of a tuple: `e, g₁, g₂, Δ₁, Δ₂, t, 0, 0`.
fn row8(t: &Gk2Tuple) -> [Val; 8] {
    [
        Val::from_u32(t.e),
        fv(t.g),
        fv(t.g_o),
        fv(t.delta),
        fv(t.delta_o),
        fv(t.t),
        Val::ZERO,
        Val::ZERO,
    ]
}
thread_local! {
    /// The statement layout and commitment mode of the attacked leaf (per
    /// test thread): `Boundary` + `Plain` unless a test sets the deployed
    /// `Interval` + `Hiding` ([`on_deployed_layout`]).
    static MODE: std::cell::Cell<(Expose, CommitMode)> =
        const { std::cell::Cell::new((Expose::Boundary, CommitMode::Plain)) };
}
fn mode() -> (Expose, CommitMode) {
    MODE.with(|c| c.get())
}
/// Run `f` with the attacked leaves on the deployed layout: `Interval`
/// statement, `Hiding` commitments (secret salts), ZK proofs. Restores the
/// previous layout afterwards, also on a panic.
fn on_deployed_layout<R>(f: impl FnOnce() -> R) -> R {
    struct Restore((Expose, CommitMode));
    impl Drop for Restore {
        fn drop(&mut self) {
            MODE.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(MODE.with(|c| c.replace((Expose::Interval, CommitMode::Hiding))));
    f()
}
/// Batch index `t` of the attacked leaf (the `Interval` statement's
/// `lo = hi = t`; `t ≥ 2`, so the init opens a secret salt too).
const LEAF_T: u64 = 3;
/// The attacked leaf's commitment openings under `Hiding` (ignored under
/// `Plain`): the honest PRF salts of leaf [`LEAF_T`] of a test history.
fn openings() -> Openings {
    static O: std::sync::OnceLock<Openings> = std::sync::OnceLock::new();
    *O.get_or_init(|| Openings::for_leaf(&SaltSeed::for_tests(0xA77AC), CommitFamily::GreenwaldKhanna, LEAF_T))
}
/// `Com` over committed-layout rows under the attacked leaf's mode (`Plain`:
/// `commit_gk2_state` on tuples; `Hiding`: the salted commitment of `kind`).
fn com_with(rows: &[[Val; 8]], kind: CommitKind, salt: &SaltBb) -> [Val; 8] {
    let flat: Vec<Val> = rows.iter().flatten().copied().collect();
    commit_flat_bb(mode().1, kind, CommitFamily::GreenwaldKhanna, salt, &flat)
}
/// `Com(S_{t-1}; ρ^S_{t-1})` of an init table.
fn com_init(rows: &[[Val; 8]]) -> [Val; 8] {
    com_with(rows, CommitKind::State, &openings().init)
}
/// `Com(S_t; ρ^S_t)` of a final table.
fn com_final(rows: &[[Val; 8]]) -> [Val; 8] {
    com_with(rows, CommitKind::State, &openings().final_)
}
/// `Com(B_t; ρ^B_t)` of a batch table.
fn com_batch(rows: &[[Val; 8]]) -> [Val; 8] {
    com_with(rows, CommitKind::Batch, &openings().batch)
}
/// `Com(S_t)` of a state (as the attacked leaf's final).
fn com_state(s: &Gk2State) -> [Val; 8] {
    com_final(&s.tuples.iter().map(row8).collect::<Vec<_>>())
}
/// Mass `Σ (g₁ + g₂ + 1)` of the live rows of a committed table (the field
/// sum, as the circuit's check sees it).
fn mass_of(rows: &[[Val; 8]]) -> Val {
    rows.iter()
        .filter(|r| r[0] != fv(E_MAX as u64))
        .map(|r| r[1] + r[2] + Val::ONE)
        .sum()
}

// ══════════════════════════════════════════════════════════════════════
// The forged witness and its field-exact simulation
// ══════════════════════════════════════════════════════════════════════

/// Everything a prover chooses for one StableCompact epoch. Unset overrides
/// take the value an honest prover computes from the (possibly forged)
/// upstream values, so a forgery stays self-consistent downstream.
#[derive(Clone)]
struct Attack {
    params: GkbParams,
    /// Whether the leaf under attack carries the liveness carry.
    live_carry: bool,
    /// Committed init / batch tables (committed layout; may be crafted).
    init: Vec<[Val; 8]>,
    fresh: Vec<[Val; 8]>,
    theta: Val,
    n_prev: Val,
    n_t: Val,
    /// Union order: union row `r` = combined row `union_src[r]` (default the
    /// stable `(e, t)` sort).
    union_src: Option<Vec<usize>>,
    /// Forged union permute outputs (challenge index → value).
    union_patch: Vec<(usize, Challenge)>,
    is_fresh: HashMap<usize, Val>,
    /// Union liveness inverse hints `1/(E_MAX − e)` overridden.
    e_inv: HashMap<usize, Val>,
    /// Batch liveness inverse hints `1/(E_MAX − e_j)` overridden.
    e_inv_batch: HashMap<usize, Val>,
    lt: HashMap<(usize, usize), Val>,
    cond: HashMap<(usize, usize), Val>,
    /// Output liveness `α'` of round `r` at position `p`.
    alive: HashMap<(usize, usize), Val>,
    /// Round `r`'s emitted elements overridden (a forged recompose row).
    emit_patch: HashMap<usize, Vec<(usize, Challenge)>>,
    /// Round `r`'s permutation (challenge level, `out[q] = emitted[σ[q]]`).
    round_sigma: HashMap<usize, Vec<usize>>,
    /// Forged permute outputs of round `r` (challenge index → value).
    round_patch: HashMap<usize, Vec<(usize, Challenge)>>,
    /// The committed final (default `α^L ⊙ R^L`).
    final_: Option<Vec<[Val; 8]>>,
}

impl Attack {
    /// The honest epoch `init ⊎ batch` (native `build_bm2` values).
    fn honest(init: &Gk2State, batch: &[u32], live_carry: bool) -> Attack {
        let params = init.params;
        let b = build_bm2(init, batch);
        Attack {
            params,
            live_carry,
            init: init.tuples.iter().map(row8).collect(),
            fresh: fresh_tuples2(batch, params.batch, b.n_prev).iter().map(row8).collect(),
            theta: fv(b.theta),
            n_prev: fv(b.n_prev),
            n_t: fv(b.n_t),
            union_src: None,
            union_patch: Vec::new(),
            is_fresh: HashMap::new(),
            e_inv: HashMap::new(),
            e_inv_batch: HashMap::new(),
            lt: HashMap::new(),
            cond: HashMap::new(),
            alive: HashMap::new(),
            emit_patch: HashMap::new(),
            round_sigma: HashMap::new(),
            round_patch: HashMap::new(),
            final_: None,
        }
    }
}

/// One simulated round (introspection for building attacks).
#[derive(Clone)]
#[allow(dead_code)]
struct RoundSim {
    cur: Vec<[Val; 6]>,
    alive_in: Vec<Val>,
    lt: Vec<Val>,
    cond: Vec<Val>,
    /// `S − 1 − θ` per pair (ungated) and the gated `dm1c`.
    u_minus_theta: Vec<Val>,
    sflag: Vec<Val>,
    emitted: Vec<Challenge>,
    /// Integer destination of each input row (`None` if not in `[0, T)`).
    dest: Vec<Option<usize>>,
    sigma: Vec<usize>,
    out: Vec<Challenge>,
    out_rows: Vec<[Val; 6]>,
    alive_out: Vec<Val>,
}

/// A packed forged witness: runner inputs, permute hints, forged permute
/// outputs, and what the proof would certify.
#[derive(Clone)]
#[allow(dead_code)]
struct Sim {
    public: Vec<Challenge>,
    private: Vec<Challenge>,
    sigmas: Vec<Vec<usize>>,
    forged: Vec<(usize, Vec<Challenge>)>,
    final8: Vec<[Val; 8]>,
    final_commit: [Val; 8],
    init_commit: [Val; 8],
    batch_commit: [Val; 8],
    union_rows: Vec<[Val; 6]>,
    alpha0: Vec<Val>,
    is_fresh: Vec<Val>,
    rounds: Vec<RoundSim>,
}

/// Source-bound row of a packed table: `[e, g₁, g₂, Δ₁, Δ₂, t]` (`fld6b`).
fn brow(ch: &[Challenge], r: usize) -> [Val; 6] {
    let lo = unpack4(ch[2 * r]);
    let hi = unpack4(ch[2 * r + 1]);
    [lo[0], lo[1], lo[2], hi[2], hi[0], hi[1]]
}

/// Field-exact mirror of [`build_gkb2_leaf_stable`]'s wiring: every value the
/// circuit computes, from the prover's choices in `a`.
fn simulate(a: &Attack) -> Sim {
    let cap = a.params.capacity;
    let m = a.params.batch;
    let total = cap + m;
    let lf = num_rounds(total);
    let np = total / 2;
    let e_max = fv(E_MAX as u64);
    let cc = fv(LIVE_CARRY);

    // ── union: combined (bound layout, op 0) and its permutation ──
    let comb: Vec<[Val; 8]> = a.init.iter().chain(a.fresh.iter()).copied().collect();
    assert_eq!(comb.len(), total);
    let mut combined: Vec<Challenge> = Vec::with_capacity(2 * total);
    for (i, f) in comb.iter().enumerate() {
        combined.push(pack4([f[0], f[1], f[2], fv(bind_coord(0, 0, i))]));
        combined.push(pack4([f[4], f[5], f[3], fv(bind_coord(0, 1, i))]));
    }
    let src = a.union_src.clone().unwrap_or_else(|| {
        let mut idx: Vec<usize> = (0..total).collect();
        idx.sort_by_key(|&i| (can(comb[i][0]), can(comb[i][5])));
        idx
    });
    let sigma_u = expand_sigma(&src);
    let mut union_raw: Vec<Challenge> = sigma_u.iter().map(|&q| combined[q]).collect();
    for &(q, v) in &a.union_patch {
        union_raw[q] = v;
    }
    let mut forged = Vec::new();
    if !a.union_patch.is_empty() {
        forged.push((0usize, union_raw.clone()));
    }
    let uraw: Vec<[Val; 6]> = (0..total).map(|r| brow(&union_raw, r)).collect();
    let e_inv_union: Vec<Val> = (0..total)
        .map(|r| *a.e_inv.get(&r).unwrap_or(&inv0(e_max - uraw[r][0])))
        .collect();
    let alpha0: Vec<Val> = (0..total).map(|r| (e_max - uraw[r][0]) * e_inv_union[r]).collect();
    let e_inv_batch: Vec<Val> = (0..m)
        .map(|j| *a.e_inv_batch.get(&j).unwrap_or(&inv0(e_max - a.fresh[j][0])))
        .collect();
    let de_inv: Vec<Val> = (0..total - 1).map(|r| inv0(uraw[r + 1][0] - uraw[r][0])).collect();
    // is_fresh = [N_{t-1} + 1 ≤ t] ⟺ N_{t-1} − t "negative"
    let is_fresh: Vec<Val> = (0..total)
        .map(|r| *a.is_fresh.get(&r).unwrap_or(&bit(neg(a.n_prev - uraw[r][5]))))
        .collect();
    let mut d1 = vec![Val::ZERO; total];
    for r in (0..total).rev() {
        let base = if r + 1 < total { uraw[r + 1][1] + d1[r + 1] } else { Val::ZERO };
        d1[r] = is_fresh[r] * base + (Val::ONE - is_fresh[r]) * uraw[r][3];
    }
    let mut d2 = vec![Val::ZERO; total];
    for r in 0..total {
        let base = if r >= 1 { uraw[r - 1][2] + d2[r - 1] } else { Val::ZERO };
        d2[r] = is_fresh[r] * base + (Val::ONE - is_fresh[r]) * uraw[r][4];
    }
    let mut cur: Vec<[Val; 6]> = (0..total)
        .map(|r| [uraw[r][0], uraw[r][1], uraw[r][2], d1[r], d2[r], uraw[r][5]])
        .collect();
    let mut alive_in = alpha0.clone();
    let mut sigmas = vec![sigma_u];
    let mut rounds: Vec<RoundSim> = Vec::with_capacity(lf);

    for r in 0..lf {
        let k = r + 1;
        let mut emitted_rows = cur.clone();
        let mut sflag = alive_in.clone();
        let (mut lts, mut conds, mut umt) = (Vec::new(), Vec::new(), Vec::new());
        for j in 0..np {
            let (x, y) = (cur[2 * j], cur[2 * j + 1]);
            let (aa, ab) = (alive_in[2 * j], alive_in[2 * j + 1]);
            let lt = *a.lt.get(&(r, j)).unwrap_or(&bit(neg(y[5] - x[5])));
            let c = x[2] + y[1];
            let selg = lt * (x[1] - y[2]) + y[2];
            let mp = c + selg;
            let seld = lt * (y[3] - x[4]) + x[4];
            let u = mp + seld;
            let dm1c = (u - a.theta) * ab;
            let cond = *a.cond.get(&(r, j)).unwrap_or(&bit(neg(dm1c)));
            let merge = cond * ab;
            let dd1 = lt * merge;
            let dd2 = merge - dd1;
            sflag[2 * j] = aa - dd1;
            sflag[2 * j + 1] = ab - dd2;
            let mn = mp + Val::ONE;
            emitted_rows[2 * j + 1][1] = dd1 * (mn - y[1]) + y[1];
            emitted_rows[2 * j][2] = dd2 * (mn - x[2]) + x[2];
            lts.push(lt);
            conds.push(cond);
            umt.push(u - a.theta);
        }
        let base = fv(bind_coord(k, 0, 0));
        let gap = fv(bind_coord(k, 1, 0) - bind_coord(k, 0, 0));
        let mut rho = base;
        let mut emitted: Vec<Challenge> = Vec::with_capacity(2 * total);
        let mut dest = Vec::with_capacity(total);
        for i in 0..total {
            let v = emitted_rows[i];
            let dl = (Val::ONE - sflag[i]) * fv((total - 1 - i) as u64) + rho;
            let lo_c = if a.live_carry { sflag[i] * cc + dl } else { dl };
            emitted.push(pack4([v[0], v[1], v[2], lo_c]));
            emitted.push(pack4([v[4], v[5], v[3], dl + gap]));
            let p = can(dl - base);
            dest.push((p < total as u64).then_some(p as usize));
            rho += sflag[i];
        }
        if let Some(p) = a.emit_patch.get(&r) {
            for &(q, v) in p {
                emitted[q] = v;
            }
        }
        let sigma = a.round_sigma.get(&r).cloned().unwrap_or_else(|| {
            let mut s = vec![usize::MAX; 2 * total];
            for (i, d) in dest.iter().enumerate() {
                let p = d.unwrap_or_else(|| panic!("round {r}: row {i} has no integer destination (override σ)"));
                assert_eq!(s[2 * p], usize::MAX, "round {r}: colliding destinations (override σ)");
                s[2 * p] = 2 * i;
                s[2 * p + 1] = 2 * i + 1;
            }
            s
        });
        let mut out: Vec<Challenge> = sigma.iter().map(|&q| emitted[q]).collect();
        if let Some(p) = a.round_patch.get(&r) {
            for &(q, v) in p {
                out[q] = v;
            }
            forged.push((k, out.clone()));
        }
        sigmas.push(sigma.clone());
        let out_rows: Vec<[Val; 6]> = (0..total).map(|p| brow(&out, p)).collect();
        // α' an honest prover would claim for the element sitting at p: the
        // survivor flag of its source row.
        let alive_out: Vec<Val> = (0..total)
            .map(|p| *a.alive.get(&(r, p)).unwrap_or(&sflag[sigma[2 * p] / 2]))
            .collect();
        rounds.push(RoundSim {
            cur: cur.clone(),
            alive_in: alive_in.clone(),
            lt: lts,
            cond: conds,
            u_minus_theta: umt,
            sflag,
            emitted,
            dest,
            sigma,
            out,
            out_rows: out_rows.clone(),
            alive_out: alive_out.clone(),
        });
        cur = out_rows;
        alive_in = alive_out;
    }

    let final8: Vec<[Val; 8]> = a.final_.clone().unwrap_or_else(|| {
        (0..cap)
            .map(|i| {
                let (f, al) = (cur[i], alive_in[i]);
                [
                    al * (f[0] - e_max) + e_max,
                    al * f[1],
                    al * f[2],
                    al * f[3],
                    al * f[4],
                    al * f[5],
                    Val::ZERO,
                    Val::ZERO,
                ]
            })
            .collect()
    });
    let final_commit = com_final(&final8);
    let init_commit = com_init(&a.init);
    let batch_commit = com_batch(&a.fresh);

    let mut public: Vec<Challenge> = Vec::new();
    for c in [init_commit, final_commit, batch_commit] {
        public.extend(pack_commit_to_challenge(&crate::commitment::CountMinCommit(c)));
    }
    public.push(emb(a.theta));
    public.push(emb(a.n_prev));
    public.push(emb(a.n_t));
    if mode().0.is_interval() {
        public.push(emb(fv(LEAF_T)));
    }

    let tab = |rows: &[[Val; 8]]| -> Vec<Challenge> {
        rows.iter()
            .flat_map(|f| [pack4([f[0], f[1], f[2], f[3]]), pack4([f[4], f[5], f[6], f[7]])])
            .collect()
    };
    let mut private: Vec<Challenge> = Vec::new();
    if mode().1.is_hiding() {
        // the 9 salt Challenges come first (`pack_opened_stable`)
        private.extend(openings().private_inputs());
    }
    private.extend(tab(&a.init));
    private.extend(tab(&final8));
    private.extend(tab(&a.fresh));
    private.extend(union_raw.iter().copied());
    for rd in &rounds {
        private.extend(rd.out.iter().copied());
    }
    private.extend(is_fresh.iter().map(|&v| emb(v)));
    for rd in &rounds {
        private.extend(rd.lt.iter().map(|&v| emb(v)));
    }
    for rd in &rounds {
        private.extend(rd.cond.iter().map(|&v| emb(v)));
    }
    for rd in &rounds {
        private.extend(rd.alive_out.iter().map(|&v| emb(v)));
    }
    private.extend(e_inv_union.iter().map(|&v| emb(v)));
    private.extend(e_inv_batch.iter().map(|&v| emb(v)));
    private.extend(de_inv.iter().map(|&v| emb(v)));

    Sim {
        public,
        private,
        sigmas,
        forged,
        final8,
        final_commit,
        init_commit,
        batch_commit,
        union_rows: uraw,
        alpha0,
        is_fresh,
        rounds,
    }
}

// ══════════════════════════════════════════════════════════════════════
// Trace-forging tools
// ══════════════════════════════════════════════════════════════════════

/// `add_range_bits` byte hint of a malicious prover: honest bytes for an
/// in-range value; otherwise the low `k−1` bytes plus a top "byte" that makes
/// `Σ byte_i·256^i = value` hold exactly in the field (so the runner's
/// `connect(value, acc)` holds) — only the Range lookup can reject it.
#[derive(Debug, Clone)]
struct RangeBypass;

impl HintExecutor<Challenge> for RangeBypass {
    fn execute(
        &self,
        inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<Challenge>],
    ) -> Result<(), CircuitError> {
        let x = witness[inputs[0].0 as usize].ok_or(CircuitError::WitnessNotSet { witness_id: inputs[0] })?;
        let k = outputs.len();
        let c = unpack4(x);
        let v0 = can(c[0]);
        let in_range = c[1..].iter().all(|z| *z == Val::ZERO) && v0 < (1u64 << (8 * k));
        let mut vals: Vec<Challenge> = (0..k).map(|i| emb(fv((v0 >> (8 * i)) & 0xFF))).collect();
        if !in_range {
            let mut low = Challenge::ZERO;
            for (i, b) in vals.iter().enumerate().take(k - 1) {
                low += *b * emb(fv(1u64 << (8 * i)));
            }
            vals[k - 1] = (x - low) * emb(fv(1u64 << (8 * (k - 1)))).inverse();
        }
        for (i, &o) in outputs.iter().enumerate() {
            let slot = &mut witness[o.0 as usize];
            match slot {
                Some(e) if *e != vals[i] => {
                    return Err(CircuitError::WitnessConflict {
                        witness_id: o,
                        existing: format!("{e:?}"),
                        new: format!("{:?}", vals[i]),
                        expr_ids: vec![],
                    });
                }
                _ => *slot = Some(vals[i]),
            }
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn HintExecutor<Challenge>> {
        Box::new(self.clone())
    }
}

/// Install [`RangeBypass`] on every `add_range_bits` byte hint.
fn install_range_bypass(c: &mut Circuit<Challenge>) -> usize {
    let mut n = 0;
    for op in c.ops.iter_mut() {
        if let Op::Hint { executor, .. } = op
            && format!("{executor:?}").starts_with("ByteDecompositionHint")
        {
            *executor = Box::new(RangeBypass);
            n += 1;
        }
    }
    n
}

/// A recompose executor that, for the ONE row whose coefficients pack to
/// `target`, outputs `forged` instead and records `forged`'s coefficients as
/// the row (so the recompose AIR's own relation holds). The coefficient wires
/// keep their computed values: under the bound `recompose/coeff` lowering the
/// row's per-coefficient WitnessChecks receives then disagree with them.
#[derive(Debug)]
struct ForgedRecompose {
    inner: Box<dyn NonPrimitiveExecutor<Challenge>>,
    target: Challenge,
    forged: Challenge,
}

impl NonPrimitiveExecutor<Challenge> for ForgedRecompose {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, Challenge>,
    ) -> Result<(), CircuitError> {
        let mut coeffs = [Val::ZERO; 4];
        for (i, &w) in inputs[0].iter().enumerate() {
            coeffs[i] = unpack4(ctx.get_witness(w)?)[0];
        }
        if pack4(coeffs) != self.target {
            return self.inner.execute(inputs, outputs, ctx);
        }
        let out = outputs[0][0];
        ctx.set_witness(out, self.forged)?;
        let values: Vec<Challenge> = unpack4(self.forged).iter().map(|&c| emb(c)).collect();
        let op_type = self.inner.op_type().clone();
        let state = ctx.get_op_state_mut::<RecomposeExecutionState<Challenge>>(&op_type);
        state.rows.push(RecomposeCircuitRow { input_wids: inputs[0].clone(), output_wid: out, values });
        Ok(())
    }
    fn op_type(&self) -> &NpoTypeId {
        self.inner.op_type()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn PreprocessedWriter<Challenge>,
    ) -> Result<(), CircuitError> {
        self.inner.preprocess(inputs, outputs, preprocessed)
    }
    fn num_exposed_outputs(&self) -> Option<usize> {
        self.inner.num_exposed_outputs()
    }
    fn arbitrated_coeff_input_group(&self) -> Option<usize> {
        self.inner.arbitrated_coeff_input_group()
    }
    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<Challenge>> {
        Box::new(ForgedRecompose { inner: self.inner.boxed(), target: self.target, forged: self.forged })
    }
}

/// Wrap every recompose op so the row packing to `target` outputs `forged`.
fn forge_recompose(c: &mut Circuit<Challenge>, target: Challenge, forged: Challenge) {
    for op in c.ops.iter_mut() {
        if let Op::NonPrimitiveOpWithExecutor { executor, .. } = op
            && (*executor.op_type() == NpoTypeId::recompose()
                || *executor.op_type() == NpoTypeId::recompose_with_coeff_lookups())
        {
            let inner = executor.boxed();
            *executor = Box::new(ForgedRecompose { inner, target, forged });
        }
    }
}

/// Write `v` to `slot` unless it already holds a different value; then
/// re-point the operand to a fresh scratch slot (a split wire). Returns
/// whether it split.
fn write_or_split(w: &mut Vec<Option<Challenge>>, slot: &mut WitnessId, v: Challenge) -> bool {
    match w[slot.0 as usize] {
        Some(x) if x != v => {
            w.push(Some(v));
            *slot = WitnessId((w.len() - 1) as u32);
            true
        }
        _ => {
            w[slot.0 as usize] = Some(v);
            false
        }
    }
}

/// **Split every wire the runner would refuse.** Replays the
/// runner's execution order exactly (inputs, then every op with the real
/// hint / NPO executors); where an ALU row's computed value conflicts with
/// the value its (connect-merged) witness already holds, the row writes into
/// a fresh scratch slot instead. The prover data of the leaf still names the
/// original witness id for that row, so the forged trace carries two values
/// for one id: exactly what a prover that ignores the `connect` submits.
/// Conflicting hint / NPO outputs are re-pointed the same way.
fn split_alu_conflicts(c: &mut Circuit<Challenge>, public: &[Challenge], private: &[Challenge]) -> Result<usize, String> {
    let mut w: Vec<Option<Challenge>> = vec![None; c.witness_count as usize];
    let put = |w: &mut Vec<Option<Challenge>>, id: WitnessId, v: Challenge| -> bool {
        match w[id.0 as usize] {
            Some(x) if x != v => false,
            _ => {
                w[id.0 as usize] = Some(v);
                true
            }
        }
    };
    for (i, &v) in public.iter().enumerate() {
        if !put(&mut w, c.public_rows[i], v) {
            return Err(format!("public input {i} conflicts"));
        }
    }
    for (i, &v) in private.iter().enumerate() {
        if !put(&mut w, c.private_input_rows[i], v) {
            return Err(format!("private input {i} conflicts"));
        }
    }
    let enabled = c.enabled_ops.clone();
    let n_ids = c
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor { op_id, .. } => Some(op_id.0 as usize + 1),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let pd: Vec<Option<NpoPrivateData>> = (0..n_ids).map(|_| None).collect();
    let mut states: OpStateMap = BTreeMap::new();
    let mut splits = 0usize;
    let get = |w: &Vec<Option<Challenge>>, id: WitnessId| -> Result<Challenge, String> {
        w[id.0 as usize].ok_or_else(|| format!("unset {id:?}"))
    };
    for idx in 0..c.ops.len() {
        match &mut c.ops[idx] {
            Op::Const { out, val } => {
                if !put(&mut w, *out, *val) {
                    return Err(format!("op {idx}: const {out:?} conflicts"));
                }
            }
            Op::Public { out, .. } => {
                if w[out.0 as usize].is_none() {
                    return Err(format!("op {idx}: public unset"));
                }
            }
            Op::Alu { kind, a, b, c: cc, out, intermediate_out } => {
                let av = get(&w, *a)?;
                match kind {
                    AluOpKind::Add => {
                        if let Some(bv) = w[b.0 as usize] {
                            splits += write_or_split(&mut w, out, av + bv) as usize;
                        } else {
                            let ov = get(&w, *out)?;
                            splits += write_or_split(&mut w, b, ov - av) as usize;
                        }
                    }
                    AluOpKind::Mul => {
                        if let Some(bv) = w[b.0 as usize] {
                            splits += write_or_split(&mut w, out, av * bv) as usize;
                        } else {
                            let ov = get(&w, *out)?;
                            let inv = av.try_inverse().ok_or("division by zero")?;
                            splits += write_or_split(&mut w, b, ov * inv) as usize;
                        }
                    }
                    AluOpKind::BoolCheck => {
                        splits += write_or_split(&mut w, out, av) as usize;
                    }
                    AluOpKind::MulAdd => {
                        let bv = get(&w, *b)?;
                        let ab = av * bv;
                        if let Some(io) = intermediate_out {
                            splits += write_or_split(&mut w, io, ab) as usize;
                        }
                        let cv = match cc {
                            Some(id) => get(&w, *id)?,
                            None => Challenge::ZERO,
                        };
                        splits += write_or_split(&mut w, out, ab + cv) as usize;
                    }
                    AluOpKind::HornerAcc => return Err("HornerAcc not supported".into()),
                }
            }
            Op::Hint { inputs, outputs, executor } => loop {
                // A conflicting hint output (a decomposed coefficient merged
                // with a constant or an earlier wire) is re-pointed to a scratch
                // slot: hints are not table-backed, so the trace keeps the merged
                // wire's value and the consumers that read it (the recompose
                // reconnect row) disagree with the packed value instead.
                match executor.execute(inputs, outputs, &mut w) {
                    Ok(()) => break,
                    Err(CircuitError::WitnessConflict { witness_id, .. }) => {
                        let pos = outputs
                            .iter()
                            .position(|o| *o == witness_id)
                            .ok_or_else(|| format!("op {idx}: hint conflict on a non-output {witness_id:?}"))?;
                        w.push(None);
                        outputs[pos] = WitnessId((w.len() - 1) as u32);
                        splits += 1;
                    }
                    Err(e) => return Err(format!("op {idx}: hint: {e:?}")),
                }
            },
            Op::NonPrimitiveOpWithExecutor { inputs, outputs, executor, op_id } => {
                for &id in inputs.iter().flatten() {
                    let _ = get(&w, id).map_err(|e| format!("op {idx}: npo input {e}"))?;
                }
                loop {
                    // Same for an NPO output (e.g. a recompose row whose packed
                    // value disagrees with the permuted value of that wire): the
                    // row keeps its own value under the original witness id.
                    let r = {
                        let mut ctx = ExecutionContext::new(&mut w, &pd, &enabled, *op_id, &mut states);
                        executor.execute(inputs, outputs, &mut ctx)
                    };
                    match r {
                        Ok(()) => break,
                        Err(CircuitError::WitnessConflict { witness_id, .. }) => {
                            let hit = outputs
                                .iter_mut()
                                .flatten()
                                .find(|o| **o == witness_id)
                                .ok_or_else(|| format!("op {idx}: npo conflict on a non-output {witness_id:?}"))?;
                            w.push(None);
                            *hit = WitnessId((w.len() - 1) as u32);
                            splits += 1;
                        }
                        Err(e) => return Err(format!("op {idx}: npo {:?}: {e:?}", executor.op_type())),
                    }
                }
            }
        }
    }
    if let Some(rw) = &c.witness_rewrite {
        for (dup, canon) in rw {
            let mut r = *canon;
            while let Some(&n) = rw.get(&r) {
                r = n;
            }
            if let (Some(x), Some(y)) = (w[dup.0 as usize], w[r.0 as usize])
                && x != y
            {
                return Err(format!("dedup rewrite {dup:?} conflicts"));
            }
        }
    }
    c.witness_count = w.len() as u32;
    Ok(splits)
}

/// How a forged witness becomes traces.
#[derive(Clone, Default)]
struct Tools {
    /// Split the wires the runner would refuse at ALU rows.
    split: bool,
    /// Forged recompose rows: `(honest packed output, forged output)`.
    recompose: Vec<(Challenge, Challenge)>,
}

impl Tools {
    fn split() -> Tools {
        Tools { split: true, ..Tools::default() }
    }
}

/// What happened to a forged witness.
#[derive(Debug)]
enum Verdict {
    /// The honest runner (or the split pre-pass) refused it: NOT a trace-level
    /// rejection.
    Runner(String),
    /// The prover or the verifier rejected the traces.
    Rejected(String),
    /// Proved and self-verified; the exposed `(init, final)` commitments.
    Accepted { init: [Val; 8], final_: [Val; 8], splits: usize },
}

/// Turn `sim` into traces for `leaf` with `tools` and prove + verify.
fn attempt(leaf: &Gkb2LeafCircuit, sim: &Sim, tools: &Tools) -> Verdict {
    let mut c = leaf.circuit.clone();
    c.update_permute_witnesses(&sim.sigmas).expect("permute hints");
    for (op, outs) in &sim.forged {
        forge_permute_outputs(&mut c, *op, outs.clone());
    }
    install_range_bypass(&mut c);
    for &(t, f) in &tools.recompose {
        forge_recompose(&mut c, t, f);
    }
    let mut splits = 0;
    if tools.split {
        match catch_msg(|| split_alu_conflicts(&mut c, &sim.public, &sim.private)) {
            Ok(Ok(n)) => splits = n,
            Ok(Err(e)) => return Verdict::Runner(format!("split pre-pass: {e}")),
            Err(p) => return Verdict::Runner(format!("split pre-pass panicked: {p}")),
        }
    }
    let traces = match catch_msg(|| -> Result<p3_circuit::tables::Traces<Challenge>, CircuitError> {
        let mut r = c.runner();
        r.set_public_inputs(&sim.public)?;
        r.set_private_inputs(&sim.private)?;
        r.run()
    }) {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Verdict::Runner(format!("{e:?}")),
        Err(p) => return Verdict::Runner(format!("runner panicked: {p}")),
    };
    let res = catch_msg(|| -> Result<Vec<Val>, String> {
        let proof = leaf
            .prover
            .prove_all_tables(&traces, &leaf.circuit_prover_data)
            .map_err(|e| format!("prove: {e:?}"))?;
        leaf.prover.verify_all_tables(&proof).map_err(|e| format!("verify: {e:?}"))?;
        // Boundary: `init ‖ final` (16); Interval: `init ‖ final ‖ idx ‖ H` (28).
        let want = if mode().0.is_interval() { 28 } else { 16 };
        let pv = proof
            .non_primitives
            .iter()
            .map(|e| &e.public_values)
            .find(|v| v.len() == want)
            .cloned()
            .ok_or_else(|| "no exposed (init, final)".to_string())?;
        Ok(pv)
    });
    match res {
        Ok(Ok(pv)) => {
            // An accepted proof exposes the simulated statement: its init and,
            // under Interval, `idx = (t, t, 0, 0)` and `H = H(TAG_LEAF, t, Com(B_t))`.
            assert_eq!(&pv[..8], &sim.init_commit[..], "accepted proof exposes the simulated Com(S_{{t-1}})");
            if pv.len() == 28 {
                assert_eq!(&pv[16..20], &[fv(LEAF_T), fv(LEAF_T), Val::ZERO, Val::ZERO], "Interval idx");
                let h = statement::leaf_digest::<Val>(&statement::hash_bb, 4, LEAF_T, &sim.batch_commit);
                assert_eq!(&pv[20..28], &h[..], "Interval digest H(TAG_LEAF, t, Com(B_t))");
            }
            Verdict::Accepted {
                init: std::array::from_fn(|i| pv[i]),
                final_: std::array::from_fn(|i| pv[8 + i]),
                splits,
            }
        }
        Ok(Err(e)) => Verdict::Rejected(e),
        Err(p) => Verdict::Rejected(format!("prover panicked: {p}")),
    }
}

// ══════════════════════════════════════════════════════════════════════
// Leaves, scenarios, and the control / attack harness
// ══════════════════════════════════════════════════════════════════════

/// `StableChecks::ALL` without every check in `off`.
fn checks_without(off: &[&str]) -> StableChecks {
    let mut c = StableChecks::ALL;
    for n in off {
        let w = StableChecks::without(n);
        c = StableChecks {
            init_ranges: c.init_ranges && w.init_ranges,
            init_t_le_n_prev: c.init_t_le_n_prev && w.init_t_le_n_prev,
            union_source: c.union_source && w.union_source,
            union_order: c.union_order && w.union_order,
            dead_union_canonical: c.dead_union_canonical && w.dead_union_canonical,
            n_ranges: c.n_ranges && w.n_ranges,
            fresh_bool: c.fresh_bool && w.fresh_bool,
            fresh_range: c.fresh_range && w.fresh_range,
            fresh_count: c.fresh_count && w.fresh_count,
            lt_bool: c.lt_bool && w.lt_bool,
            lt_range: c.lt_range && w.lt_range,
            cond_bool: c.cond_bool && w.cond_bool,
            cond_range: c.cond_range && w.cond_range,
            alive_bool: c.alive_bool && w.alive_bool,
            out_pos_pins: c.out_pos_pins && w.out_pos_pins,
            live_carry: c.live_carry && w.live_carry,
            final_bind: c.final_bind && w.final_bind,
            alive_cap: c.alive_cap && w.alive_cap,
            mass: c.mass && w.mass,
            n_count: c.n_count && w.n_count,
            theta: c.theta && w.theta,
            arrivals: c.arrivals && w.arrivals,
        };
    }
    c
}

/// The StableCompact leaf (Semantic binding; the layout and commitment mode
/// of [`mode`]: Boundary + Plain, or the deployed Interval + Hiding) with
/// `checks`.
fn leaf(params: GkbParams, checks: StableChecks) -> Gkb2LeafCircuit {
    with_stable_checks(checks, || {
        let (expose, commit) = mode();
        build_gkb2_leaf_rounds(params, expose, Binding::Semantic, commit, GkRounds::StableCompact)
    })
}

/// Deterministic generator (no external RNG).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// An honest epoch to attack: a reachable init (`prior` random batches from
/// genesis) and the next batch.
#[derive(Clone)]
struct Scenario {
    init: Gk2State,
    batch: Vec<u32>,
}

impl Scenario {
    fn make(params: GkbParams, seed: u64, prior: usize, universe: u64) -> Option<Scenario> {
        let mut rng = Lcg(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5EED);
        let mut st = Gk2State::empty(params);
        for _ in 0..prior {
            let vals: Vec<u32> = (0..params.batch).map(|_| rng.below(universe) as u32).collect();
            st = try_apply_batch2(&st, &vals).ok()?;
        }
        let batch: Vec<u32> = (0..params.batch).map(|_| rng.below(universe) as u32).collect();
        try_apply_batch2(&st, &batch).ok()?;
        Some(Scenario { init: st, batch })
    }
    fn honest(&self, live_carry: bool) -> Attack {
        Attack::honest(&self.init, &self.batch, live_carry)
    }
    /// `Com` of the native `apply_batch2` successor.
    fn honest_final(&self) -> [Val; 8] {
        com_state(&apply_batch2(&self.init, &self.batch))
    }
}

/// Search scenarios (`seed` in `0..400`) for one where `pick` finds a target.
fn find<T>(what: &str, params: GkbParams, prior: usize, universe: u64, pick: impl Fn(&Scenario, &Sim) -> Option<T>) -> (Scenario, T) {
    for seed in 0..400u64 {
        let Some(sc) = Scenario::make(params, seed, prior, universe) else { continue };
        let hs = simulate(&sc.honest(true));
        if let Some(t) = pick(&sc, &hs) {
            return (sc, t);
        }
    }
    panic!("{what}: no scenario with a target found");
}

thread_local! {
    /// The leaf shape the attacks run at (per test thread).
    static SHAPE: std::cell::Cell<GkbParams> =
        const { std::cell::Cell::new(GkbParams { capacity: 8, batch: 8, s: 3 }) };
}
/// The attacked leaf shape (`cap 8, m 8, s 3` unless a test sets [`SHAPE`]).
fn params() -> GkbParams {
    SHAPE.with(|c| c.get())
}

/// The positive control: against `leaf_off` the forgery must prove,
/// self-verify and certify a final commitment different from `honest`.
/// Returns the certified final commitment.
fn expect_control(name: &str, v: Verdict, honest: [Val; 8]) -> [Val; 8] {
    match v {
        Verdict::Accepted { final_, .. } => {
            assert_ne!(final_, honest, "{name}: control accepted but certified the HONEST state (vacuous forgery)");
            final_
        }
        other => panic!("{name}: POSITIVE CONTROL NOT ACCEPTED (the forgery is broken, rejections would be vacuous): {other:?}"),
    }
}

/// The attack: against the deployed leaf the forgery must be rejected by the
/// prover/verifier (AIR, LogUp bus, range lookup), never by the runner.
fn expect_rejected(name: &str, v: Verdict) -> String {
    match v {
        Verdict::Rejected(m) => {
            let short: String = m.chars().take(160).collect();
            short
        }
        Verdict::Runner(m) => panic!("{name}: refused by the RUNNER, not at trace level: {m}"),
        Verdict::Accepted { final_, splits, .. } => {
            panic!("{name}: FORGERY ACCEPTED by the deployed leaf (BLOCKER): certified final {final_:?} ({splits} split rows)")
        }
    }
}

/// Control without `off`, then the same attack on the deployed leaf.
#[allow(clippy::too_many_arguments)]
fn duel(
    name: &str,
    params: GkbParams,
    off: &[&str],
    control: &Attack,
    control_tools: &Tools,
    attack: &Attack,
    attack_tools: &Tools,
    honest: [Val; 8],
) {
    let lo = leaf(params, checks_without(off));
    duel_on(name, &format!("without {off:?}"), &lo, params, control, control_tools, attack, attack_tools, honest);
}

/// [`duel`] with an explicit control leaf (`label` names what it lacks).
/// The control must certify exactly the simulated forged state.
#[allow(clippy::too_many_arguments)]
fn duel_on(
    name: &str,
    label: &str,
    control_leaf: &Gkb2LeafCircuit,
    params: GkbParams,
    control: &Attack,
    control_tools: &Tools,
    attack: &Attack,
    attack_tools: &Tools,
    honest: [Val; 8],
) {
    let cs = simulate(control);
    let wrong = expect_control(name, attempt(control_leaf, &cs, control_tools), honest);
    assert_eq!(wrong, cs.final_commit, "{name}: the control certifies exactly the forged final");
    let ld = leaf(params, StableChecks::ALL);
    let why = expect_rejected(name, attempt(&ld, &simulate(attack), attack_tools));
    eprintln!("[G-sound] {name}: control ({label}) ACCEPTED a wrong state; deployed leaf REJECTED: {why}");
}

/// The leaf with `checks` must reject `attack` at trace level (no control).
/// `sane` is an honest witness that the same leaf must accept first, so the
/// rejection is not the leaf rejecting everything.
fn reject_only(name: &str, params: GkbParams, checks: StableChecks, sane: &Attack, attack: &Attack, tools: &Tools) -> String {
    let l = leaf(params, checks);
    match attempt(&l, &simulate(sane), &Tools::split()) {
        Verdict::Accepted { splits: 0, .. } => {}
        other => panic!("{name}: the leaf {checks:?} does not accept an honest witness: {other:?}"),
    }
    expect_rejected(name, attempt(&l, &simulate(attack), tools))
}

// ══════════════════════════════════════════════════════════════════════
// Sanity: the simulator IS the circuit, the forging pipeline is clean
// ══════════════════════════════════════════════════════════════════════

/// The simulator reproduces the implementer's packer (`stable_rounds` /
/// `pack_stable_out`) bit for bit, and an honest witness through EVERY
/// forging tool (range bypass, ALU split pre-pass, a no-op recompose forge,
/// the honest permute outputs installed as "forged" outputs) proves on the
/// deployed leaf with zero split rows and certifies the native state: the
/// tools are transparent on honest traces, so every rejection below is
/// caused by the forgery alone.
#[test]
fn attack_pipeline_is_transparent_on_honest_witnesses() {
    for (seed, live_carry) in [(1u64, true), (2, true), (3, false)] {
        let sc = Scenario::make(params(), seed, 2, 1 << 12).expect("scenario");
        let a = sc.honest(live_carry);
        let s = simulate(&a);
        // Same rounds as the implementer's native replay.
        let b = build_bm2(&sc.init, &sc.batch);
        let sb = stable_rounds(&b.union_init, b.theta, params().capacity);
        for (r, (rd, nat)) in s.rounds.iter().zip(&sb.rounds).enumerate() {
            assert_eq!(rd.out, pack_stable_out(&nat.out, r + 1, &nat.alive, live_carry), "round {r} out table");
            assert_eq!(rd.alive_out, nat.alive.iter().map(|&x| bit(x == 1)).collect::<Vec<_>>());
        }
        assert_eq!(s.final8, sb.final_tuples.iter().map(row8).collect::<Vec<_>>());
        assert_eq!(s.final_commit, sc.honest_final());
        let checks = if live_carry { StableChecks::ALL } else { checks_without(&["live_carry"]) };
        let l = leaf(params(), checks);
        // honest permute outputs through the forged-output path, a no-op recompose forge
        let mut a2 = a.clone();
        a2.round_patch.insert(s.rounds.len() - 1, vec![(0, s.rounds.last().unwrap().out[0])]);
        let s2 = simulate(&a2);
        let e = s.rounds[0].emitted[0];
        let tools = Tools { split: true, recompose: vec![(e, e)] };
        match attempt(&l, &s2, &tools) {
            Verdict::Accepted { final_, splits, init } => {
                assert_eq!(splits, 0, "honest witness needs no split");
                assert_eq!(final_, sc.honest_final());
                assert_eq!(init, com_init(&a.init));
            }
            other => panic!("honest witness through the forging tools must verify: {other:?}"),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// Attack helpers
// ══════════════════════════════════════════════════════════════════════

/// `data_from`'s fields with `coord_from`'s binding coordinate.
fn recoord(data_from: Challenge, coord_from: Challenge) -> Challenge {
    let mut c = unpack4(data_from);
    c[3] = unpack4(coord_from)[3];
    pack4(c)
}
/// `x` with coefficient `i` replaced.
fn with_coeff(x: Challenge, i: usize, v: Val) -> Challenge {
    let mut c = unpack4(x);
    c[i] = v;
    pack4(c)
}
/// `g₁ + g₂ + 1` of a `[e, g₁, g₂, Δ₁, Δ₂, t]` row.
fn rmass(r: &[Val; 6]) -> Val {
    r[1] + r[2] + Val::ONE
}
fn last(hs: &Sim) -> (usize, &RoundSim) {
    let lr = hs.rounds.len() - 1;
    (lr, &hs.rounds[lr])
}
fn survivors(rd: &RoundSim) -> usize {
    rd.alive_out.iter().filter(|&&a| a == Val::ONE).count()
}
const EMAX: u64 = E_MAX as u64;
/// `θ` of the attacked epoch.
fn theta_of(sc: &Scenario) -> Val {
    sc.honest(true).theta
}
/// Every fusible live pair `(round, pair)` (honest `cond = 1`).
fn fusible(hs: &Sim) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    for (r, rd) in hs.rounds.iter().enumerate() {
        for j in 0..rd.cond.len() {
            if rd.alive_in[2 * j + 1] == Val::ONE && rd.cond[j] == Val::ONE {
                v.push((r, j));
            }
        }
    }
    v
}
/// Every live, NOT fusible pair (honest `cond = 0`, both rows alive).
fn unfusible(hs: &Sim) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    for (r, rd) in hs.rounds.iter().enumerate() {
        for j in 0..rd.cond.len() {
            if rd.alive_in[2 * j] == Val::ONE && rd.alive_in[2 * j + 1] == Val::ONE && rd.cond[j] == Val::ZERO {
                v.push((r, j));
            }
        }
    }
    v
}
/// The first attack variant (in `cands`) whose forged final differs from
/// the honest one.
fn first_wrong<T: Copy>(sc: &Scenario, cands: &[T], mk: impl Fn(T) -> Attack) -> Option<(T, Attack)> {
    let h = sc.honest_final();
    for &c in cands {
        let a = mk(c);
        let ok = catch_msg(|| simulate(&a).final_commit);
        if let Ok(f) = ok
            && f != h
        {
            return Some((c, a));
        }
    }
    None
}

// ══════════════════════════════════════════════════════════════════════
// A. Compaction / destination binding
// ══════════════════════════════════════════════════════════════════════

/// **Survivors reordered in the compaction** (two output rows of round `r`
/// swapped). Target: the output position pins (`lo[3] = B(k,0,p) + α'C`,
/// `hi[3] = B(k,1,p)`). Control: without the pins the swapped table is a
/// genuine permutation of the emitted rows, proves, and certifies an
/// out-of-order state (and, in the first round, different fusions). Deployed:
/// the forger keeps every output row's pinned coordinate and swaps only the
/// contents, so the PermuteBus multiset breaks.
#[test]
fn g1_attack_compaction_reorder_survivors() {
    for which in ["first", "last"] {
        let (sc, (r, p, q)) = find("two distinct survivors", params(), 2, 1 << 12, |sc, hs| {
            let r = if which == "first" { 0 } else { hs.rounds.len() - 1 };
            let rd = &hs.rounds[r];
            let s = survivors(rd);
            for p in 0..s {
                for q in p + 1..s {
                    if rd.out_rows[p] != rd.out_rows[q] {
                        let mut a = sc.honest(true);
                        let mut sig = rd.sigma.clone();
                        sig.swap(2 * p, 2 * q);
                        sig.swap(2 * p + 1, 2 * q + 1);
                        a.round_sigma.insert(r, sig);
                        if catch_msg(|| simulate(&a).final_commit).is_ok_and(|f| f != sc.honest_final()) {
                            return Some((r, p, q));
                        }
                    }
                }
            }
            None
        });
        let hs = simulate(&sc.honest(true));
        let rd = &hs.rounds[r];
        let mut ctrl = sc.honest(true);
        let mut sig = rd.sigma.clone();
        sig.swap(2 * p, 2 * q);
        sig.swap(2 * p + 1, 2 * q + 1);
        ctrl.round_sigma.insert(r, sig);
        let mut att = sc.honest(true);
        att.round_patch.insert(
            r,
            vec![
                (2 * p, recoord(rd.out[2 * q], rd.out[2 * p])),
                (2 * p + 1, recoord(rd.out[2 * q + 1], rd.out[2 * p + 1])),
                (2 * q, recoord(rd.out[2 * p], rd.out[2 * q])),
                (2 * q + 1, recoord(rd.out[2 * p + 1], rd.out[2 * q + 1])),
            ],
        );
        duel(
            &format!("compaction: survivors {p},{q} of the {which} round reordered"),
            params(),
            &["out_pos_pins"],
            &ctrl,
            &Tools::default(),
            &att,
            &Tools::default(),
            sc.honest_final(),
        );
    }
}

/// A last-round survivor `p` and a dead row `q ∈ [S, cap)` (a real folded
/// row, `e < E_MAX`) of equal mass `g₁ + g₂ + 1`, so trading them keeps `N_t`.
fn survivor_dead_pair(hs: &Sim) -> Option<(usize, usize)> {
    let (_, rd) = last(hs);
    let s = survivors(rd);
    for p in 0..s {
        for q in s..params().capacity {
            if rd.out_rows[q][0] != fv(EMAX) && rmass(&rd.out_rows[p]) == rmass(&rd.out_rows[q]) && rd.out_rows[p] != rd.out_rows[q] {
                return Some((p, q));
            }
        }
    }
    None
}

/// **A survivor sent to the tail and a dead row kept, by position.** The
/// last round's output places survivor `X` at a dead slot `q` and a
/// folded-away row `D` (same mass) at `X`'s rank `p`, the liveness flags
/// staying with the positions: `X` is dropped, `D` (whose mass a survivor
/// already absorbed) is resurrected. Target: the output pins. Deployed: the
/// contents are swapped under the pinned coordinates (PermuteBus).
#[test]
fn g1_attack_compaction_survivor_to_tail_dead_kept() {
    let (sc, (p, q)) = find("survivor/dead pair of equal mass", params(), 2, 1 << 12, |_, hs| survivor_dead_pair(hs));
    let hs = simulate(&sc.honest(true));
    let (lr, rd) = last(&hs);
    let mut ctrl = sc.honest(true);
    let mut sig = rd.sigma.clone();
    sig.swap(2 * p, 2 * q);
    sig.swap(2 * p + 1, 2 * q + 1);
    ctrl.round_sigma.insert(lr, sig);
    ctrl.alive.insert((lr, p), Val::ONE);
    ctrl.alive.insert((lr, q), Val::ZERO);
    let mut att = sc.honest(true);
    att.round_patch.insert(
        lr,
        vec![
            (2 * p, recoord(rd.out[2 * q], rd.out[2 * p])),
            (2 * p + 1, recoord(rd.out[2 * q + 1], rd.out[2 * p + 1])),
            (2 * q, recoord(rd.out[2 * p], rd.out[2 * q])),
            (2 * q + 1, recoord(rd.out[2 * p + 1], rd.out[2 * q + 1])),
        ],
    );
    duel(
        "compaction: survivor sent to the tail, dead row kept",
        params(),
        &["out_pos_pins"],
        &ctrl,
        &Tools::default(),
        &att,
        &Tools::default(),
        sc.honest_final(),
    );
}

/// **Liveness forged (prefix hint): a survivor marked dead, a folded row
/// marked live.** Positions stay honest; only `α'` lies (`α'_p = 0` for the
/// survivor, `α'_q = 1` for a folded-away row of equal mass, whose mass is
/// then counted twice). Target: the liveness carry (`+ sflag·C` on the
/// emitted coordinate, `+ α'·C` on the pin) — without it `α'` is a free
/// boolean. Deployed: `α'` is pinned through the coordinate; the forger moves
/// the carry onto the forged positions (PermuteBus).
#[test]
fn g1_attack_liveness_survivor_dropped_folded_row_resurrected() {
    let (sc, (p, q)) = find("survivor/dead pair of equal mass", params(), 2, 1 << 12, |_, hs| survivor_dead_pair(hs));
    let hs = simulate(&sc.honest(true));
    let (lr, rd) = last(&hs);
    let k = lr + 1;
    let mut ctrl = sc.honest(false);
    ctrl.alive.insert((lr, p), Val::ZERO);
    ctrl.alive.insert((lr, q), Val::ONE);
    let mut att = sc.honest(true);
    att.alive.insert((lr, p), Val::ZERO);
    att.alive.insert((lr, q), Val::ONE);
    att.round_patch.insert(
        lr,
        vec![
            (2 * p, with_coeff(rd.out[2 * p], 3, fv(bind_coord(k, 0, p)))),
            (2 * q, with_coeff(rd.out[2 * q], 3, fv(bind_coord(k, 0, q) + LIVE_CARRY))),
        ],
    );
    duel(
        "liveness: survivor dropped, folded row resurrected",
        params(),
        &["live_carry"],
        &ctrl,
        &Tools::default(),
        &att,
        &Tools::default(),
        sc.honest_final(),
    );
}

/// **A survivor duplicated in the compaction** (it overwrites another
/// survivor of equal mass, so `N_t` holds). No switch removes this check: it
/// is the permutation argument itself. The forger installs the duplicate as
/// the round's permute output; the deployed leaf rejects it, and so does the
/// leaf WITHOUT the output pins given an exact copy of the element: the
/// emitted multiset holds it once. Control: the same
/// forged-output path with the honest outputs proves and certifies the
/// honest state (the forger works), and the duplicate would certify a
/// different state. (A leaf without pins, carry AND `α'` booleanity rejects
/// even honest witnesses — a WitnessChecks creator gap of that test-only
/// combination — so it cannot serve as a control.)
#[test]
fn g1_attack_compaction_duplicate_survivor() {
    let (sc, (p, q)) = find("two survivors of equal mass", params(), 2, 1 << 12, |_, hs| {
        let (_, rd) = last(hs);
        let s = survivors(rd);
        (0..s)
            .flat_map(|p| (0..s).map(move |q| (p, q)))
            .find(|&(p, q)| p != q && rmass(&rd.out_rows[p]) == rmass(&rd.out_rows[q]) && rd.out_rows[p] != rd.out_rows[q])
    });
    let hs = simulate(&sc.honest(true));
    let (lr, rd) = last(&hs);
    // forger sanity: honest outputs through the forged-output path
    let mut same = sc.honest(true);
    same.round_patch.insert(lr, vec![(2 * q, rd.out[2 * q]), (2 * q + 1, rd.out[2 * q + 1])]);
    match attempt(&leaf(params(), StableChecks::ALL), &simulate(&same), &Tools::default()) {
        Verdict::Accepted { final_, .. } => assert_eq!(final_, sc.honest_final()),
        other => panic!("duplicate: forger sanity failed: {other:?}"),
    }
    // the duplicate, under the pinned coordinates
    let mut att = sc.honest(true);
    att.round_patch.insert(
        lr,
        vec![(2 * q, recoord(rd.out[2 * p], rd.out[2 * q])), (2 * q + 1, recoord(rd.out[2 * p + 1], rd.out[2 * q + 1]))],
    );
    assert_ne!(simulate(&att).final_commit, sc.honest_final(), "the duplicate would certify a wrong state");
    let why = reject_only("compaction: survivor duplicated", params(), StableChecks::ALL, &sc.honest(true), &att, &Tools::default());
    // the exact element copied, against the leaf without the output pins
    // (whose rows may then hold any element of the multiset)
    let mut bare = sc.honest(true);
    bare.round_patch.insert(lr, vec![(2 * q, rd.out[2 * p]), (2 * q + 1, rd.out[2 * p + 1])]);
    let why2 = reject_only(
        "compaction: survivor duplicated (no output pins)",
        params(),
        checks_without(&["out_pos_pins"]),
        &sc.honest(true),
        &bare,
        &Tools::default(),
    );
    eprintln!("[G-sound] compaction: survivor duplicated: deployed REJECTED: {why}; without the output pins (exact copy) still REJECTED: {why2}");
}

/// **Non-boolean liveness hint.** In the last round two live rows of equal
/// mass trade their lo halves: out row `p` takes the lo element emitted for
/// `q`, whose coordinate `B(k,0,q) + C` meets the pin `B(k,0,p) + α'_p·C` with
/// `α'_p = 1 + (q − p)/C` (and `α'_q = 1 − (q−p)/C`), a field element far from
/// `{0, 1}`. The hi halves stay; `Σ α'(g₁+g₂+1)` is unchanged because the
/// masses match. Target: `assert_bool(α')`. Control: without it the garbage
/// liveness proves and certifies a garbled state. Deployed: the identical
/// trace (the runner records BoolCheck rows unchecked) fails the ALU AIR.
#[test]
fn g1_attack_liveness_non_boolean_hint() {
    let (sc, (p, q)) = find("two survivors of equal mass", params(), 2, 1 << 12, |_, hs| {
        let (_, rd) = last(hs);
        let s = survivors(rd);
        (0..s)
            .flat_map(|p| (0..s).map(move |q| (p, q)))
            .find(|&(p, q)| p < q && rmass(&rd.out_rows[p]) == rmass(&rd.out_rows[q]) && rd.out_rows[p] != rd.out_rows[q])
    });
    let hs = simulate(&sc.honest(true));
    let (lr, rd) = last(&hs);
    let k = lr + 1;
    let mut a = sc.honest(true);
    let mut sig = rd.sigma.clone();
    sig.swap(2 * p, 2 * q);
    a.round_sigma.insert(lr, sig.clone());
    let cinv = fv(LIVE_CARRY).inverse();
    for x in [p, q] {
        let coord = unpack4(rd.emitted[sig[2 * x]])[3];
        let al = (coord - fv(bind_coord(k, 0, x))) * cinv;
        assert!(al != Val::ZERO && al != Val::ONE);
        a.alive.insert((lr, x), al);
    }
    duel("liveness: non-boolean α' (lo halves traded)", params(), &["alive_bool"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

// ══════════════════════════════════════════════════════════════════════
// B. Fusion decisions
// ══════════════════════════════════════════════════════════════════════

/// **Wrong direction bit.** On a fusible pair, flip `lt` so the OTHER Alg-4
/// sum is tested and the fold goes the wrong way (the newer row survives).
/// Target: the `lt = [a.t > b.t]` range test. Deployed: the same trace; the
/// forger's byte hint absorbs the wrapped slack into a non-byte top limb, so
/// only the Range lookup objects.
#[test]
fn g1_attack_fusion_wrong_direction_bit() {
    let (sc, a) = find("a fusible pair foldable the other way", params(), 2, 1 << 12, |sc, hs| {
        let th = theta_of(sc);
        let cands: Vec<(usize, usize)> = fusible(hs)
            .into_iter()
            .filter(|&(r, j)| {
                let rd = &hs.rounds[r];
                let (x, y) = (rd.cur[2 * j], rd.cur[2 * j + 1]);
                let lt = Val::ONE - rd.lt[j];
                let u = x[2] + y[1] + lt * (x[1] - y[2]) + y[2] + lt * (y[3] - x[4]) + x[4];
                neg(u - th)
            })
            .collect();
        first_wrong(sc, &cands, |(r, j)| {
            let mut a = sc.honest(true);
            a.lt.insert((r, j), Val::ONE - hs.rounds[r].lt[j]);
            a
        })
        .map(|(_, a)| a)
    });
    duel("fusion: wrong direction bit", params(), &["lt_range"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

/// A non-boolean `lt` on fusible pair `(r, j)` that passes the 24-bit `lt`
/// test AND makes the 24-bit threshold test pass with `cond = 0`: `lt =
/// (dm1t − w)/(2·dm1t + 1)` for some `w < 2^24`, scanning `w` until `dm1c(lt)
/// = A + lt·B ∈ [0, 2^24)`.
fn nonbool_lt_under_merge(rd: &RoundSim, j: usize, theta: Val) -> Option<Val> {
    let (x, y) = (rd.cur[2 * j], rd.cur[2 * j + 1]);
    let dm1t = y[5] - x[5];
    let inv_k = (dm1t + dm1t + Val::ONE).inverse();
    let a0 = x[2] + y[1] + y[2] + x[4] - theta;
    let bc = (x[1] - y[2]) + (y[3] - x[4]);
    if bc == Val::ZERO {
        return None;
    }
    let step = bc * inv_k;
    let mut lt = dm1t * inv_k;
    let mut dm1c = a0 + bc * lt;
    for _ in 0..(1u64 << 24) {
        if can(dm1c) < (1 << 24) && lt != Val::ZERO && lt != Val::ONE {
            return Some(lt);
        }
        lt -= inv_k;
        dm1c -= step;
    }
    None
}

/// **Under-merge through a non-boolean direction bit.** The 24-bit `lt`
/// test alone does not force `lt ∈ {0,1}`: `lt = (dm1t − w)/(2dm1t+1)` passes
/// it for every `w < 2^24`, and since `lt` also selects the threshold sum,
/// some such `lt` makes a FUSIBLE pair pass the threshold test with `cond =
/// 0` (left unfused). Target: `assert_bool(lt)`. Deployed: the same trace
/// fails the BoolCheck AIR.
#[test]
fn g1_attack_fusion_under_merge_non_boolean_lt() {
    let (sc, a) = find("a fusible pair with a non-boolean escape", params(), 2, 1 << 12, |sc, hs| {
        let th = theta_of(sc);
        let cands: Vec<(usize, usize, Val)> = fusible(hs)
            .into_iter()
            .take(6)
            .filter_map(|(r, j)| nonbool_lt_under_merge(&hs.rounds[r], j, th).map(|lt| (r, j, lt)))
            .collect();
        first_wrong(sc, &cands, |(r, j, lt)| {
            let mut a = sc.honest(true);
            a.lt.insert((r, j), lt);
            a
        })
        .map(|(_, a)| a)
    });
    duel("fusion: under-merge via non-boolean lt", params(), &["lt_bool"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

/// **Over-budget merge**: a live pair whose Alg-4 sum exceeds `θ` is fused
/// (`cond = 1`), breaking the rank-uncertainty budget. Target: the 24-bit
/// threshold test. Deployed: Range lookup on the wrapped slack.
#[test]
fn g1_attack_fusion_over_budget_merge() {
    let (sc, a) = find("an unfusible live pair", params(), 2, 1 << 12, |sc, hs| {
        first_wrong(sc, &unfusible(hs), |(r, j)| {
            let mut a = sc.honest(true);
            a.cond.insert((r, j), Val::ONE);
            a
        })
        .map(|(_, a)| a)
    });
    duel("fusion: over-budget merge", params(), &["cond_range"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

/// **Under-merge**: a fusible pair is left unfused (`cond = 0`). Target: the
/// 24-bit threshold test. Deployed: Range lookup.
#[test]
fn g1_attack_fusion_under_merge() {
    let (sc, a) = find("a fusible pair", params(), 2, 1 << 12, |sc, hs| {
        first_wrong(sc, &fusible(hs), |(r, j)| {
            let mut a = sc.honest(true);
            a.cond.insert((r, j), Val::ZERO);
            a
        })
        .map(|(_, a)| a)
    });
    duel("fusion: under-merge (fusible pair left unfused)", params(), &["cond_range"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

/// **Both directions at once**: `cond = 2`, `lt = 1/2` on a fusible pair, so
/// `d₁ = d₂ = 1`: each row absorbs the other (`g₁_b ← M`, `g₂_a ← M`) and
/// both die. `cond = 2` PASSES the 24-bit threshold test on a fusible pair
/// (`w = −3·dm1c − 2`), so the booleanity checks carry it; the vanished
/// pair also breaks the mass. Control: without `lt`/`cond` booleanity, the
/// `lt` test and the mass check, it proves (the pair's records vanish).
/// Deployed: BoolCheck AIR + Range + WitnessChecks.
#[test]
fn g1_attack_fusion_both_directions() {
    let (sc, a) = find("a fusible pair", params(), 2, 1 << 12, |sc, hs| {
        first_wrong(sc, &fusible(hs), |(r, j)| {
            let mut a = sc.honest(true);
            a.lt.insert((r, j), fv(2).inverse());
            a.cond.insert((r, j), fv(2));
            a
        })
        .map(|(_, a)| a)
    });
    // cond = 2 passes the threshold test on its own
    let s = simulate(&a);
    let (r, j) = (0..s.rounds.len())
        .flat_map(|r| (0..s.rounds[r].cond.len()).map(move |j| (r, j)))
        .find(|&(r, j)| s.rounds[r].cond[j] == fv(2))
        .unwrap();
    let dm1c = s.rounds[r].u_minus_theta[j];
    let w = dm1c - fv(2) * (dm1c + dm1c + Val::ONE);
    assert!(can(w) < (1 << 24), "cond = 2 passes the 24-bit threshold test (w = {})", can(w));
    duel(
        "fusion: both directions (cond = 2, lt = 1/2)",
        params(),
        &["lt_bool", "lt_range", "cond_bool", "mass"],
        &a,
        &Tools::default(),
        &a,
        &Tools::split(),
        sc.honest_final(),
    );
}

/// **Non-boolean `cond` alone** (`cond = 2` passes the threshold test, see
/// above): with `lt ∈ {0,1}` the survivor flags are `1 − cond` and `1`, so
/// the destinations stop being a bijection. It is rejected by the deployed
/// leaf AND by the leaf without `assert_bool(cond)`: the destination binding
/// forces `cond ∈ {0,1}` by itself, so `cond_bool` is defense in depth (no
/// single-switch forgery exists for it).
#[test]
fn g1_probe_cond_bool_is_implied() {
    let (sc, (r, j)) = find("a fusible pair", params(), 2, 1 << 12, |_, hs| fusible(hs).first().copied());
    let hs = simulate(&sc.honest(true));
    let mut a = sc.honest(true);
    a.cond.insert((r, j), fv(2));
    // the destinations are no longer a bijection: keep the honest σ and α'
    a.round_sigma.insert(r, hs.rounds[r].sigma.clone());
    for p in 0..params().capacity + params().batch {
        a.alive.insert((r, p), hs.rounds[r].alive_out[p]);
    }
    for checks in [StableChecks::ALL, checks_without(&["cond_bool"])] {
        let why = reject_only("fusion: cond = 2", params(), checks, &sc.honest(true), &a, &Tools::split());
        eprintln!("[G-sound] probe cond = 2 ({}): REJECTED: {why}", if checks == StableChecks::ALL { "deployed" } else { "without cond_bool" });
    }
}

// ══════════════════════════════════════════════════════════════════════
// C. Forged survivor update (the emitted row's packed value)
// ══════════════════════════════════════════════════════════════════════

/// **Forged survivor update**: the last round's emitted row of a survivor is
/// recomposed to a value whose fields differ from the computed update — `g₁`
/// (mass moved from `g₂`), `g₂` (mass moved from `g₁`), `Δ₁ + 7`, `Δ₂ + 7`,
/// `t + 3` — and the permute carries it into the final. Target: the
/// recompose/coeff binding of the emitted row (each coefficient on the
/// WitnessChecks bus). Control: the leaf under the unbound (pre-fix) recompose
/// lowering proves each forgery. Deployed: rejected.
#[test]
fn g1_attack_forged_survivor_update() {
    let (sc, (p_g1, p_g2)) = find("survivors with g₁ > 0 and g₂ > 0", params(), 2, 1 << 12, |_, hs| {
        let (_, rd) = last(hs);
        let s = survivors(rd);
        let a = (0..s).find(|&p| rd.out_rows[p][2] != Val::ZERO)?;
        let b = (0..s).find(|&p| rd.out_rows[p][1] != Val::ZERO)?;
        Some((a, b))
    });
    let hs = simulate(&sc.honest(true));
    let (lr, rd) = last(&hs);
    let unbound = crate::recompose_binding::with_unbound_recompose(|| leaf(params(), StableChecks::ALL));
    let src = |p: usize| rd.sigma[2 * p] / 2;
    // (label, emitted challenge index, forged value)
    let mut forgeries: Vec<(&str, usize, Challenge)> = Vec::new();
    {
        let i = src(p_g1);
        let lo = unpack4(rd.emitted[2 * i]);
        forgeries.push(("g₁ (g₂'s mass moved into g₁)", 2 * i, pack4([lo[0], lo[1] + lo[2], Val::ZERO, lo[3]])));
    }
    {
        let i = src(p_g2);
        let lo = unpack4(rd.emitted[2 * i]);
        forgeries.push(("g₂ (g₁'s mass moved into g₂)", 2 * i, pack4([lo[0], Val::ZERO, lo[1] + lo[2], lo[3]])));
    }
    let i = src(0);
    let hi = unpack4(rd.emitted[2 * i + 1]);
    forgeries.push(("Δ₁ + 7", 2 * i + 1, pack4([hi[0], hi[1], hi[2] + fv(7), hi[3]])));
    forgeries.push(("Δ₂ + 7", 2 * i + 1, pack4([hi[0] + fv(7), hi[1], hi[2], hi[3]])));
    forgeries.push(("t + 3", 2 * i + 1, pack4([hi[0], hi[1] + fv(3), hi[2], hi[3]])));
    for (label, idx, forged) in forgeries {
        let mut a = sc.honest(true);
        a.emit_patch.insert(lr, vec![(idx, forged)]);
        let tools = Tools { split: false, recompose: vec![(rd.emitted[idx], forged)] };
        duel_on(
            &format!("forged survivor update: {label}"),
            "unbound recompose lowering",
            &unbound,
            params(),
            &a,
            &tools,
            &a,
            &tools,
            sc.honest_final(),
        );
    }
}

// ══════════════════════════════════════════════════════════════════════
// D. Moving tuples between permute ops / halves (shared PermuteBus)
// ══════════════════════════════════════════════════════════════════════

/// **A tuple moved between permute ops (union ↔ last round).** A fresh
/// batch tuple `F` leaves the union op's output and re-enters directly in
/// the LAST round's output, skipping neighbour-init and every fusion round
/// (it lands in the final with `Δ = 0`, out of value order). The union op
/// takes, in exchange, the last-round element `Z` of a dummy's lineage — a
/// fixed point: `Z`'s data is the canonical dummy, its coordinate the one the
/// last round computes for that lineage — so the global PermuteBus multiset
/// balances (`union: combined − F + Z`, `round L: emitted − Z + F`).
/// Blocked by three checks, each sufficient: the union source binding (`Z`'s
/// coordinate is not a union source), the round output pins (`F`'s coordinate
/// is not a round position), and the fresh count (`F`'s slot is a dummy).
/// Control: the leaf without all three proves it. Deployed: Range lookup +
/// WitnessChecks.
#[test]
fn g1_attack_cross_op_trade_union_to_last_round() {
    let cap = params().capacity;
    let total = cap + params().batch;
    let (sc, a) = find("a fresh tuple and a dummy lineage ending inside the final", params(), 1, 1 << 12, |sc, _| {
        let base = sc.honest(true);
        let comb: Vec<[Val; 8]> = base.init.iter().chain(base.fresh.iter()).copied().collect();
        let mut src: Vec<usize> = (0..total).collect();
        src.sort_by_key(|&i| (can(comb[i][0]), can(comb[i][5])));
        for j in 0..sc.batch.len() {
            let i_f = cap + j;
            let wo: Vec<usize> = src.iter().copied().filter(|&i| i != i_f).collect();
            let live = wo.iter().filter(|&&i| comb[i][0] != fv(EMAX)).count();
            for x in live..total {
                let mut src2 = wo.clone();
                src2.insert(x, i_f);
                let mut a = base.clone();
                a.union_src = Some(src2);
                let ph = [pack4([fv(EMAX), Val::ZERO, Val::ZERO, Val::ZERO]), pack4([Val::ZERO; 4])];
                a.union_patch = vec![(2 * x, ph[0]), (2 * x + 1, ph[1])];
                let Ok(s1) = catch_msg(|| simulate(&a)) else { continue };
                let lf = s1.rounds.len();
                let mut row = x;
                let mut ok = true;
                for r in 0..lf - 1 {
                    match s1.rounds[r].dest[row] {
                        Some(d) => row = d,
                        None => ok = false,
                    }
                }
                let rl = &s1.rounds[lf - 1];
                let Some(d) = rl.dest[row] else { continue };
                if !ok || d >= cap || rl.alive_out[d] != Val::ZERO {
                    continue;
                }
                let z = (rl.emitted[2 * row], rl.emitted[2 * row + 1]);
                a.union_patch = vec![(2 * x, z.0), (2 * x + 1, z.1)];
                let s2 = simulate(&a);
                assert_eq!(s2.rounds[lf - 1].emitted[2 * row], z.0, "fixed point");
                assert_eq!(s2.rounds[lf - 1].emitted[2 * row + 1], z.1, "fixed point");
                let f = comb[i_f];
                a.round_patch.insert(
                    lf - 1,
                    vec![
                        (2 * d, pack4([f[0], f[1], f[2], fv(bind_coord(0, 0, i_f))])),
                        (2 * d + 1, pack4([f[4], f[5], f[3], fv(bind_coord(0, 1, i_f))])),
                    ],
                );
                a.alive.insert((lf - 1, d), Val::ONE);
                let s3 = simulate(&a);
                if s3.final_commit != sc.honest_final() && mass_of(&s3.final8) == a.n_t {
                    return Some(a);
                }
            }
        }
        None
    });
    duel(
        "cross-op trade: fresh tuple skips the rounds (union -> last round)",
        params(),
        &["union_source", "out_pos_pins", "fresh_count"],
        &a,
        &Tools::default(),
        &a,
        &Tools::split(),
        sc.honest_final(),
    );
}

/// **Tuple halves re-paired inside the union op.** A fresh row `F` and an
/// old row `O` swap their hi halves `(Δ₂, t, Δ₁)`: `F`'s value carries `O`'s
/// old timestamp (skipping neighbour-init) and `O`'s value is re-initialised
/// as fresh; the fresh count is unchanged and the union stays `e`-sorted.
/// Target: the union source binding (`hi[3] − lo[3] = 2^20`, `src < 2^20`).
/// Deployed: WitnessChecks on the gap wire.
#[test]
fn g1_attack_union_half_repairing() {
    let total = params().capacity + params().batch;
    let (sc, a) = find("a fresh and an old live union row", params(), 2, 1 << 12, |sc, hs| {
        let n_prev = sc.honest(true).n_prev;
        let rows = &hs.union_rows;
        let live: Vec<usize> = (0..total).filter(|&r| hs.alpha0[r] == Val::ONE).collect();
        let fresh: Vec<usize> = live.iter().copied().filter(|&r| neg(n_prev - rows[r][5])).collect();
        let old: Vec<usize> = live.iter().copied().filter(|&r| !neg(n_prev - rows[r][5])).collect();
        let base = sc.honest(true);
        let comb: Vec<[Val; 8]> = base.init.iter().chain(base.fresh.iter()).copied().collect();
        let mut src: Vec<usize> = (0..total).collect();
        src.sort_by_key(|&i| (can(comb[i][0]), can(comb[i][5])));
        let cands: Vec<(usize, usize)> = fresh
            .iter()
            .flat_map(|&f| old.iter().map(move |&o| (f, o)))
            .filter(|&(f, o)| rows[f][0] != rows[o][0])
            .collect();
        first_wrong(sc, &cands, |(f, o)| {
            let mut a = sc.honest(true);
            let mut sig = expand_sigma(&src);
            sig.swap(2 * f + 1, 2 * o + 1);
            let comb_ch: Vec<Challenge> = comb
                .iter()
                .enumerate()
                .flat_map(|(i, c)| {
                    [pack4([c[0], c[1], c[2], fv(bind_coord(0, 0, i))]), pack4([c[4], c[5], c[3], fv(bind_coord(0, 1, i))])]
                })
                .collect();
            a.union_patch = vec![(2 * f + 1, comb_ch[sig[2 * f + 1]]), (2 * o + 1, comb_ch[sig[2 * o + 1]])];
            a
        })
        .map(|(_, a)| a)
    });
    duel("union: tuple halves re-paired", params(), &["union_source"], &a, &Tools::default(), &a, &Tools::split(), sc.honest_final());
}

/// **Unsorted union**: two adjacent live union rows swapped, so
/// neighbour-init and the fusion rounds run on an out-of-order table.
/// Target: the union `(e, t)` order. Deployed: Range lookup.
#[test]
fn g1_attack_union_out_of_order() {
    let total = params().capacity + params().batch;
    let (sc, a) = find("two adjacent live union rows", params(), 2, 1 << 12, |sc, hs| {
        let base = sc.honest(true);
        let comb: Vec<[Val; 8]> = base.init.iter().chain(base.fresh.iter()).copied().collect();
        let mut src: Vec<usize> = (0..total).collect();
        src.sort_by_key(|&i| (can(comb[i][0]), can(comb[i][5])));
        let cands: Vec<usize> = (0..total - 1)
            .filter(|&r| hs.alpha0[r + 1] == Val::ONE && hs.union_rows[r][0] != hs.union_rows[r + 1][0])
            .collect();
        first_wrong(sc, &cands, |r| {
            let mut a = sc.honest(true);
            let mut s2 = src.clone();
            s2.swap(r, r + 1);
            a.union_src = Some(s2);
            a
        })
        .map(|(_, a)| a)
    });
    duel("union: rows out of (e,t) order", params(), &["union_order"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

// ══════════════════════════════════════════════════════════════════════
// E. Crafted inits, freshness, poisoned dummies
// ══════════════════════════════════════════════════════════════════════

/// **Init row with a live `t > N_{t-1}`** (here `t = N_t + 7`): the leaf
/// treats it as fresh (neighbour-init rewrites its `Δ`) and certifies a final
/// still carrying `t > N_t`, a state no chain from genesis reaches. Two
/// checks block it, each alone: `N_{t-1} − t ∈ [0, 2^24)` on init rows (Range
/// lookup) and `Σ is_fresh = #active(B_t)` (WitnessChecks). Control: without
/// both it proves; each single check rejects it at trace level.
#[test]
fn g1_attack_init_t_after_n_prev() {
    let (sc, a) = find("a surviving init row", params(), 2, 1 << 12, |sc, _| {
        let base = sc.honest(true);
        let n_t = can(base.n_t);
        let cands: Vec<usize> = (0..params().capacity).filter(|&i| sc.init.tuples[i].active == 1).collect();
        for i in cands {
            let mut a = base.clone();
            a.init[i][5] = fv(n_t + 7);
            let Ok(s) = catch_msg(|| simulate(&a)) else { continue };
            let late = s.final8.iter().any(|r| r[0] != fv(EMAX) && can(r[5]) > n_t);
            if late && s.final_commit != sc.honest_final() {
                return Some(a);
            }
        }
        None
    });
    duel(
        "init row with live t > N_prev",
        params(),
        &["init_t_le_n_prev", "fresh_count"],
        &a,
        &Tools::default(),
        &a,
        &Tools::split(),
        sc.honest_final(),
    );
    for (on, off) in [("init t ≤ N_prev", "fresh_count"), ("fresh count", "init_t_le_n_prev")] {
        let why = reject_only("init row with live t > N_prev", params(), checks_without(&[off]), &sc.honest(true), &a, &Tools::split());
        eprintln!("[G-sound] init row with live t > N_prev: {on} alone REJECTS: {why}");
    }
}

/// **Poisoned dummy**: a crafted init dummy row `(E_MAX, g₁ = 5, …, Δ₁ = 3,
/// t = 0)` right after the last live union row, a fresh one, whose
/// neighbour-init then reads `Δ₁ = 5 + 3` from the "empty" slot. The final
/// differs from the successor of the canonical init (the same sketch).
/// Target: dead union rows pinned to the canonical dummy. Deployed:
/// WitnessChecks.
#[test]
fn g1_attack_poisoned_dummy() {
    let total = params().capacity + params().batch;
    let (sc, a) = find("a fresh last live row followed by an init dummy", params(), 1, 1 << 12, |sc, hs| {
        let base = sc.honest(true);
        let n_prev = base.n_prev;
        let last_live = (0..total).rev().find(|&r| hs.alpha0[r] == Val::ONE)?;
        if !neg(n_prev - hs.union_rows[last_live][5]) {
            return None;
        }
        let d = (0..params().capacity).find(|&i| sc.init.tuples[i].active == 0)?;
        let mut a = base.clone();
        a.init[d][1] = fv(5);
        a.init[d][3] = fv(3);
        let s = catch_msg(|| simulate(&a)).ok()?;
        (s.final_commit != sc.honest_final()).then_some(a)
    });
    duel("poisoned init dummy", params(), &["dead_union_canonical"], &a, &Tools::default(), &a, &Tools::split(), sc.honest_final());
}

/// **Crafted huge-`g` init**: a live init row with `g₁ ≡ g₁ − 5 (mod p)`
/// (wrapping past `2^24`), another with `g₁ + 5`, so the init's mass is
/// unchanged mod p. The leaf certifies a final with a field-negative rank
/// mass. Target: the init range checks (moved onto the committed rows).
/// Deployed: Range lookup.
#[test]
fn g1_attack_crafted_huge_g_init() {
    let (sc, a) = find("two live init rows, one with g₁ < 5", params(), 2, 1 << 12, |sc, _| {
        let base = sc.honest(true);
        let live: Vec<usize> = (0..params().capacity).filter(|&i| sc.init.tuples[i].active == 1).collect();
        for &i in &live {
            if sc.init.tuples[i].g >= 5 {
                continue;
            }
            for &k in &live {
                if k == i {
                    continue;
                }
                let mut a = base.clone();
                a.init[i][1] -= fv(5);
                a.init[k][1] += fv(5);
                let Ok(s) = catch_msg(|| simulate(&a)) else { continue };
                let huge = s.final8.iter().any(|r| r[0] != fv(EMAX) && (can(r[1]) >= 1 << 24 || can(r[2]) >= 1 << 24));
                if huge && s.final_commit != sc.honest_final() && mass_of(&s.final8) == a.n_t {
                    return Some(a);
                }
            }
        }
        None
    });
    duel("crafted huge-g init", params(), &["init_ranges"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

/// **Init `e` beyond `E_MAX`** (review G1 r1): a live init row's value set
/// to `e = 2^22 + 5` (mass moved onto it from another live row so that it is
/// too heavy to fold, the init's total mass unchanged). The union `(e, t)`
/// sort puts it after every dummy while it stays live (`α⁰ = [e ≠ E_MAX] =
/// 1`), so `α⁰` is no longer a prefix; the round-0 compaction moves it into
/// the live prefix and the leaf certifies a final carrying a live `e ≥
/// 2^22`, outside the value domain. Target: the init range check `e <
/// 2^22`, a NON-byte-aligned width (exact only with the fork's full top-byte
/// check; the field-fraction top-byte forger is
/// `fork_soundness::add_range_bits_unaligned_22_bit_forgery_is_rejected`).
/// Deployed: Range lookup.
#[test]
fn g1_attack_init_e_beyond_e_max() {
    let beyond = (1u64 << 22) + 5;
    let (sc, a) = find("a live init row to push past E_MAX", params(), 2, 1 << 12, |sc, _| {
        let base = sc.honest(true);
        let live: Vec<usize> = (0..params().capacity).filter(|&i| sc.init.tuples[i].active == 1).collect();
        for &i in live.iter().rev() {
            for k in std::iter::once(None).chain(live.iter().filter(|&&k| k != i).map(|&k| Some(k))) {
                let mut a = base.clone();
                a.init[i][0] = fv(beyond);
                if let Some(k) = k {
                    let dg = sc.init.tuples[k].g;
                    if dg == 0 {
                        continue;
                    }
                    a.init[i][1] += fv(dg);
                    a.init[k][1] -= fv(dg);
                }
                let Ok(s) = catch_msg(|| simulate(&a)) else { continue };
                let out = s.final8.iter().any(|r| can(r[0]) == beyond);
                if out && s.final_commit != sc.honest_final() && mass_of(&s.final8) == a.n_t {
                    return Some(a);
                }
            }
        }
        None
    });
    duel("init e beyond E_MAX", params(), &["init_ranges"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

/// **Freshness swapped**: a fresh batch row is declared not fresh (it skips
/// neighbour-init) and an old init row fresh (its `Δ` re-initialised); the
/// fresh count is unchanged. Target: the `is_fresh = [N_{t-1}+1 ≤ t]` range
/// test. Deployed: Range lookup.
#[test]
fn g1_attack_is_fresh_swapped() {
    let total = params().capacity + params().batch;
    let (sc, a) = find("a fresh and an old live union row", params(), 2, 1 << 12, |sc, hs| {
        let live: Vec<usize> = (0..total).filter(|&r| hs.alpha0[r] == Val::ONE).collect();
        let fresh: Vec<usize> = live.iter().copied().filter(|&r| hs.is_fresh[r] == Val::ONE).collect();
        let old: Vec<usize> = live.iter().copied().filter(|&r| hs.is_fresh[r] == Val::ZERO).collect();
        let cands: Vec<(usize, usize)> = fresh.iter().flat_map(|&f| old.iter().map(move |&o| (f, o))).collect();
        first_wrong(sc, &cands, |(f, o)| {
            let mut a = sc.honest(true);
            a.is_fresh.insert(f, Val::ZERO);
            a.is_fresh.insert(o, Val::ONE);
            a
        })
        .map(|(_, a)| a)
    });
    duel("is_fresh swapped (fresh row skips neighbour-init)", params(), &["fresh_range"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
}

// ══════════════════════════════════════════════════════════════════════
// F. θ, N and arrival positions
// ══════════════════════════════════════════════════════════════════════

/// The epoch replayed under a claimed threshold `theta` (every fusion
/// decision consistent with it).
fn with_theta(sc: &Scenario, theta: Val) -> Attack {
    let mut a = sc.honest(true);
    a.theta = theta;
    a
}

/// **Inflated θ** (over-merging under a larger budget) and **θ off by one**
/// (`⌊N_t/s⌋ ± 1`). Target: `θ = ⌊N_t/s⌋` (`bind_theta`). Deployed: Range
/// lookup on the remainder / bound.
#[test]
fn g1_attack_theta() {
    for (label, delta) in [("inflated θ", 0i64), ("θ + 1", 1), ("θ − 1", -1)] {
        let (sc, a) = find(label, params(), 2, 1 << 12, |sc, _| {
            let th = can(theta_of(sc)) as i64;
            let tries: Vec<i64> = if delta == 0 { (2..=12).map(|d| th + d).collect() } else { vec![th + delta] };
            tries
                .into_iter()
                .filter(|&t| t >= 0)
                .find_map(|t| {
                    let a = with_theta(sc, fv(t as u64));
                    catch_msg(|| simulate(&a).final_commit).ok().filter(|f| *f != sc.honest_final()).map(|_| a)
                })
        });
        duel(&format!("θ binding: {label}"), params(), &["theta"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
    }
}

/// **Wrong `N_{t-1}`.** (a) Two phantom records claimed before the batch:
/// `N_{t-1}, N_t` shifted by 2, `θ` and the batch's arrival positions
/// consistent with them — only the mass `Σ α(g₁+g₂+1) = N_t` (which ties
/// `N` to the committed state) objects. (b) `N_{t-1}` alone shifted: two batch
/// rows then fall at or below it, skip neighbour-init — blocked by the
/// record count, the arrival positions and the fresh count. Controls without
/// those checks; deployed: WitnessChecks.
#[test]
fn g1_attack_wrong_n_prev() {
    // (a)
    let (sc, a) = find("an epoch", params(), 2, 1 << 12, |sc, _| {
        let mut a = sc.honest(true);
        let np = can(a.n_prev) + 2;
        a.n_prev = fv(np);
        a.n_t = fv(np + sc.batch.len() as u64);
        a.theta = fv((np + sc.batch.len() as u64) / params().s);
        a.fresh = fresh_tuples2(&sc.batch, params().batch, np).iter().map(row8).collect();
        catch_msg(|| simulate(&a).final_commit).ok().filter(|f| *f != sc.honest_final()).map(|_| a)
    });
    duel("N: two phantom records (N_prev, N_t, θ, arrivals shifted)", params(), &["mass"], &a, &Tools::default(), &a, &Tools::split(), sc.honest_final());
    // (b)
    let (sc, a) = find("an epoch", params(), 2, 1 << 12, |sc, _| {
        let mut a = sc.honest(true);
        a.n_prev = fv(can(a.n_prev) + 2);
        catch_msg(|| simulate(&a).final_commit).ok().filter(|f| *f != sc.honest_final()).map(|_| a)
    });
    duel(
        "N: wrong N_prev (two batch rows skip neighbour-init)",
        params(),
        &["n_count", "arrivals", "fresh_count"],
        &a,
        &Tools::default(),
        &a,
        &Tools::split(),
        sc.honest_final(),
    );
}

/// **Forged arrival positions**: (a) the batch's timestamps start 5 past
/// `N_{t-1}+1` (a gap: survivors carry `t > N_t` into the next epoch); (b)
/// two batch rows' arrival order swapped (the newer/older roles in `lt`
/// change). Target: `t_j = act_j·(N_{t-1} + 1 + j)`. Deployed: WitnessChecks.
#[test]
fn g1_attack_forged_arrival_positions() {
    let (sc, a) = find("a batch whose survivors keep their t", params(), 2, 1 << 12, |sc, _| {
        let mut a = sc.honest(true);
        for j in 0..sc.batch.len() {
            a.fresh[j][5] += fv(5);
        }
        catch_msg(|| simulate(&a).final_commit).ok().filter(|f| *f != sc.honest_final()).map(|_| a)
    });
    duel("arrivals: timestamps shifted past N_t", params(), &["arrivals"], &a, &Tools::default(), &a, &Tools::split(), sc.honest_final());
    let (sc, a) = find("a batch whose arrival order matters", params(), 2, 1 << 12, |sc, _| {
        let cands: Vec<(usize, usize)> =
            (0..sc.batch.len()).flat_map(|i| (i + 1..sc.batch.len()).map(move |k| (i, k))).collect();
        first_wrong(sc, &cands, |(i, k)| {
            let mut a = sc.honest(true);
            let (ti, tk) = (a.fresh[i][5], a.fresh[k][5]);
            a.fresh[i][5] = tk;
            a.fresh[k][5] = ti;
            a
        })
        .map(|(_, a)| a)
    });
    duel("arrivals: two arrival positions swapped", params(), &["arrivals"], &a, &Tools::default(), &a, &Tools::split(), sc.honest_final());
}

// ══════════════════════════════════════════════════════════════════════
// G. Capacity and the committed final
// ══════════════════════════════════════════════════════════════════════

/// **`S = cap + 1` smuggled through**: a full state (6 survivors at cap 6,
/// `θ = 0` so nothing fuses) plus one record leaves 7 survivors; the leaf
/// would certify the first 6 (a record vanishes). Control: without `α^L_cap
/// = 0` and the mass it proves the lossy state. Deployed, two forgers:
/// (A) honest liveness wired to 0 at `cap`, the pin and the mass ignored —
/// WitnessChecks; (B) the 7th survivor's carry dropped and its mass folded
/// into row 0 inside the last round's permute output (so `α'_cap = 0` and
/// the mass both hold) — PermuteBus.
#[test]
fn g1_attack_capacity_plus_one() {
    let params = GkbParams { capacity: 6, batch: 2, s: 1000 };
    let mut st = Gk2State::empty(params);
    let mut v = 100u32;
    for _ in 0..3 {
        st = apply_batch2(&st, &[v, v + 1]);
        v += 2;
    }
    assert_eq!(st.actives().len(), 6, "full state");
    let over = vec![50u32]; // the smallest value: the largest init row is the one pushed out
    assert!(try_apply_batch2(&st, &over).is_err(), "S = cap + 1 natively");
    let h = Attack::honest(&st, &over, true);
    let hs = simulate(&h);
    let (lr, rd) = last(&hs);
    let k = lr + 1;
    let cap = params.capacity;
    assert_eq!(survivors(rd), cap + 1);
    assert_eq!(rd.alive_out[cap], Val::ONE);
    assert_ne!(mass_of(&hs.final8), h.n_t, "the certified final would lose a record");
    let lossy = expect_control(
        "S = cap + 1",
        attempt(&leaf(params, checks_without(&["alive_cap", "mass"])), &hs, &Tools::default()),
        com_state(&st),
    );
    assert_eq!(lossy, hs.final_commit, "control certifies the lossy state");
    // (A)
    let mut a1 = h.clone();
    a1.alive.insert((lr, cap), Val::ZERO);
    let why_a = reject_only("S = cap + 1 (A)", params, StableChecks::ALL, &Attack::honest(&st, &[], true), &a1, &Tools::split());
    // (B)
    let mut a2 = h.clone();
    a2.alive.insert((lr, cap), Val::ZERO);
    let dropped = rmass(&rd.out_rows[cap]);
    let lo0 = unpack4(rd.out[0]);
    a2.round_patch.insert(
        lr,
        vec![
            (2 * cap, with_coeff(rd.out[2 * cap], 3, fv(bind_coord(k, 0, cap)))),
            (0, pack4([lo0[0], lo0[1] + dropped, lo0[2], lo0[3]])),
        ],
    );
    assert_eq!(mass_of(&simulate(&a2).final8), a2.n_t, "forger (B) keeps the mass");
    let why_b = reject_only("S = cap + 1 (B)", params, StableChecks::ALL, &Attack::honest(&st, &[], true), &a2, &Tools::default());
    eprintln!("[G-sound] S = cap + 1: control (without alive_cap + mass) ACCEPTED the lossy state; deployed REJECTED (A) {why_a}; (B) {why_b}");
    // Each check ALONE (review G1 r1), against every forger:
    // * `α^L_cap = 0` on, mass off: the pin is a `connect` to the Const zero,
    //   so `α'_cap = 1` cannot even be written; forgers (A) and (B) honour it
    //   and are rejected by the destination binding / the permutation;
    // * mass on, `α^L_cap = 0` off: the honest liveness (`α'_cap = 1`, the
    //   lossy final) is rejected by the mass (WitnessChecks), and forger (B)
    //   (mass folded into row 0) by the permutation.
    let sane = Attack::honest(&st, &[], true);
    for (label, off, attack, tools) in [
        ("α^L_cap = 0 alone, forger (A)", "mass", &a1, Tools::split()),
        ("α^L_cap = 0 alone, forger (B)", "mass", &a2, Tools::default()),
        ("mass alone, honest liveness (lossy final)", "alive_cap", &h, Tools::split()),
        ("mass alone, forger (B)", "alive_cap", &a2, Tools::default()),
    ] {
        let why = reject_only(&format!("S = cap + 1 ({label})"), params, checks_without(&[off]), &sane, attack, &tools);
        eprintln!("[G-sound] S = cap + 1: {label} (leaf without {off}) REJECTS: {why}");
    }
}

/// **Committed final not `α^L ⊙ R^L`**: the final commitment opens to the
/// honest final with one representative's value moved. Target: the final
/// binding. Deployed: WitnessChecks.
#[test]
fn g1_attack_final_not_bound() {
    let (sc, a) = find("an epoch", params(), 2, 1 << 12, |sc, hs| {
        let mut a = sc.honest(true);
        let mut f = hs.final8.clone();
        f[0][0] += Val::ONE;
        a.final_ = Some(f);
        Some(a)
    });
    duel("final not bound to the rounds", params(), &["final_bind"], &a, &Tools::default(), &a, &Tools::split(), sc.honest_final());
}

/// **Union liveness hint forged**: the inverse hint of a live union row is
/// set to 0, declaring it dead (`α⁰ = 0`): it would never fuse and the final
/// would mask it away. `force_nz` has no switch (`x·(1 − x·x⁻¹) = 0` is
/// unconditional), so this is rejection-only: the deployed leaf rejects the
/// split trace on the WitnessChecks bus; the same leaf accepts the honest
/// witness through the same tools.
#[test]
fn g1_probe_union_liveness_hint_forged() {
    let total = params().capacity + params().batch;
    // the LAST live row, so the forged liveness stays a prefix
    let (sc, r) = find("a live union row", params(), 2, 1 << 12, |_, hs| (0..total).rev().find(|&r| hs.alpha0[r] == Val::ONE));
    let mut a = sc.honest(true);
    a.e_inv.insert(r, Val::ZERO);
    assert_eq!(simulate(&a).alpha0[r], Val::ZERO);
    let why = reject_only("union liveness hint forged", params(), StableChecks::ALL, &sc.honest(true), &a, &Tools::split());
    eprintln!("[G-sound] union liveness hint forged (live row declared dead): deployed REJECTED: {why}");
}

// ══════════════════════════════════════════════════════════════════════
// H. Round 2 (independent attacker): the gaps of round 1
// ══════════════════════════════════════════════════════════════════════

/// `x ∈ [0, 2^24)`, as the leaf's 24-bit range checks see a field element.
fn in24(x: Val) -> bool {
    can(x) < 1 << 24
}

/// Whether every forced-comparison witness the leaf range-checks at 24 bits
/// — `is_fresh`, and every round's `lt` and `α_b`-gated `cond` — lies in
/// `[0, 2^24)` for the simulated values (`w = dm1 − b·(2·dm1 + 1)`,
/// [`force_le_dm1`]): the witness a control leaf without the targeted check
/// must accept.
fn comparisons_in_range(a: &Attack, s: &Sim) -> bool {
    let w = |dm1: Val, b: Val| in24(dm1 - b * (dm1 + dm1 + Val::ONE));
    s.union_rows.iter().zip(&s.is_fresh).all(|(r, &f)| w(a.n_prev - r[5], f))
        && s.rounds.iter().all(|rd| {
            (0..rd.lt.len()).all(|j| {
                let dm1t = rd.cur[2 * j + 1][5] - rd.cur[2 * j][5];
                let dm1c = rd.u_minus_theta[j] * rd.alive_in[2 * j + 1];
                w(dm1t, rd.lt[j]) && w(dm1c, rd.cond[j])
            })
        })
}

/// **Non-boolean freshness flag** (the `fresh_bool` check, which round 1
/// left without an attack). The 24-bit test `is_fresh = [N_{t-1}+1 ≤ t]`
/// alone admits, on a fresh row at distance `d = t − N_{t-1} ≥ 1`, every
/// `v = (d + w)/(2d − 1)` with `w ∈ [0, 2^24)` (the test's witness is then
/// exactly `w`), and neighbour-init gives that row `Δ₁ = v·(g₁ + Δ₁)` of its
/// right neighbour and `Δ₂ = v·(g₂ + Δ₂)` of its left one. The fresh count
/// `Σ is_fresh = #active(B_t)` is restored on the LAST union row (dead,
/// `t = 0`), which takes `1 − v`: its own test witness `N_{t-1} −
/// (1−v)(2N_{t-1}+1)` must be a 24-bit integer too, and its `Δ`s are never
/// read (its right neighbour does not exist, and liveness gates every
/// threshold test and merge of a dead row). Two forgeries:
///
/// * **inflated** — `v = 2` (`w = 3d − 2`; the dead row takes `−1`, witness
///   `3N_{t-1} + 1`): the fresh row's uncertainty doubled;
/// * **shrunk** — `v = (d + w)/(2d − 1) < 1` (`w ≤ d − 2`), chosen so both
///   `Δ`s stay integers: the fresh row's uncertainty UNDER-stated, so its
///   later fusions run against a smaller `Δ` than `apply_batch2`'s and the
///   certified rank interval is narrower than the truth.
///
/// Both keep every other range witness in range and certify a final other
/// than `apply_batch2`'s. Control: the leaf without `assert_bool(is_fresh)`
/// proves them. Deployed: the BoolCheck AIR.
#[test]
fn g1_attack_fresh_non_boolean() {
    let total = params().capacity + params().batch;
    for shrink in [false, true] {
        let label = if shrink {
            "is_fresh non-boolean: a fresh row's Δ shrunk"
        } else {
            "is_fresh non-boolean: a fresh row's Δ doubled"
        };
        let (sc, (f, a)) = find(label, params(), 2, 1 << 12, |sc, hs| {
            let c = total - 1;
            if hs.alpha0[c] != Val::ZERO {
                return None;
            }
            let base = sc.honest(true);
            let np = can(base.n_prev);
            let cur0 = &hs.rounds[0].cur;
            for f in 0..total {
                if hs.alpha0[f] != Val::ONE || hs.is_fresh[f] != Val::ONE {
                    continue;
                }
                // honest neighbour-init sums feeding row f (rows right of f
                // and left of f are untouched by the forgery)
                let b1 = if f + 1 < total { hs.union_rows[f + 1][1] + cur0[f + 1][3] } else { Val::ZERO };
                let b2 = if f >= 1 { hs.union_rows[f - 1][2] + cur0[f - 1][4] } else { Val::ZERO };
                let d = can(hs.union_rows[f][5]) - np;
                let ws: Vec<u64> = if shrink { (0..d.saturating_sub(1)).collect() } else { vec![3 * d - 2] };
                for w in ws {
                    let v = fv(d + w) * fv(2 * d - 1).inverse();
                    let (d1, d2) = (v * b1, v * b2);
                    let (h1, h2) = (cur0[f][3], cur0[f][4]);
                    if v == Val::ONE || !in24(d1) || !in24(d2) || (d1, d2) == (h1, h2) {
                        continue;
                    }
                    if shrink && (can(d1) > can(h1) || can(d2) > can(h2)) {
                        continue;
                    }
                    let dm1c = base.n_prev; // the dead row: N_{t-1} − 0
                    if !in24(dm1c - (Val::ONE - v) * (dm1c + dm1c + Val::ONE)) {
                        continue;
                    }
                    let mut a = base.clone();
                    a.is_fresh.insert(f, v);
                    a.is_fresh.insert(c, Val::ONE - v);
                    let Ok(s) = catch_msg(|| simulate(&a)) else { continue };
                    assert_eq!((s.rounds[0].cur[f][3], s.rounds[0].cur[f][4]), (d1, d2));
                    if comparisons_in_range(&a, &s) && s.final_commit != sc.honest_final() {
                        return Some((f, a));
                    }
                }
            }
            None
        });
        let (hs, s) = (simulate(&sc.honest(true)), simulate(&a));
        let (h, g) = (&hs.rounds[0].cur[f], &s.rounds[0].cur[f]);
        eprintln!(
            "[G-sound] {label}: union row {f} (t − N_prev = {}), is_fresh = {}, (Δ₁, Δ₂) {:?} -> {:?}",
            can(h[5] - a.n_prev),
            can(a.is_fresh[&f]),
            (can(h[3]), can(h[4])),
            (can(g[3]), can(g[4]))
        );
        duel(label, params(), &["fresh_bool"], &a, &Tools::default(), &a, &Tools::default(), sc.honest_final());
    }
}

/// **Equal values out of arrival order in the union** (the `t` tiebreak of
/// the union order, which round 1's out-of-order attack — two rows of
/// DIFFERENT value — never reaches). Two adjacent live union rows holding
/// the same value are swapped, so the newer one comes first: `e` stays
/// non-decreasing (the 22-bit difference test sees `0`), and only the
/// tiebreak `is_de_zero·(t_{r+1} − t_r) ∈ [0, 2^24)` objects. Neighbour-init
/// and the pairing then run on a table `finish_bm2` never builds, and the
/// final lists the equal-value representatives out of arrival order.
/// Control: the leaf without the union order proves it. Deployed: Range
/// lookup on the wrapped tiebreak.
#[test]
fn g1_attack_union_tiebreak() {
    let total = params().capacity + params().batch;
    let (sc, a) = find("two adjacent live union rows of equal value", params(), 2, 1 << 3, |sc, hs| {
        let base = sc.honest(true);
        let comb: Vec<[Val; 8]> = base.init.iter().chain(base.fresh.iter()).copied().collect();
        let mut src: Vec<usize> = (0..total).collect();
        src.sort_by_key(|&i| (can(comb[i][0]), can(comb[i][5])));
        let cands: Vec<usize> = (0..total - 1)
            .filter(|&r| {
                let (x, y) = (&hs.union_rows[r], &hs.union_rows[r + 1]);
                hs.alpha0[r + 1] == Val::ONE && x[0] == y[0] && x[5] != y[5]
            })
            .collect();
        first_wrong(sc, &cands, |r| {
            let mut a = sc.honest(true);
            let mut s2 = src.clone();
            s2.swap(r, r + 1);
            a.union_src = Some(s2);
            a
        })
        .map(|(_, a)| a)
    });
    let s = simulate(&a);
    assert!(
        s.union_rows.windows(2).all(|w| can(w[0][0]) <= can(w[1][0])),
        "the forged union is still value-sorted (only the tiebreak is broken)"
    );
    duel(
        "union: equal values out of arrival (t) order",
        params(),
        &["union_order"],
        &a,
        &Tools::default(),
        &a,
        &Tools::default(),
        sc.honest_final(),
    );
}

/// **Batch liveness hint forged**: the inverse hint of the last live batch
/// row set to 0, declaring that record absent (`#active(B_t)` one short, so
/// a record would vanish from `N_t`). Like the union liveness hint,
/// `force_nz` has no switch (`x·(1 − x·x⁻¹) = 0` is unconditional), so this
/// is rejection-only: the deployed leaf rejects the split trace on the
/// WitnessChecks bus; the same leaf accepts the honest witness through the
/// same tools.
#[test]
fn g1_probe_batch_liveness_hint_forged() {
    let (sc, j) = find("a live batch row", params(), 2, 1 << 12, |sc, _| sc.batch.len().checked_sub(1));
    let mut a = sc.honest(true);
    a.e_inv_batch.insert(j, Val::ZERO);
    let why = reject_only("batch liveness hint forged", params(), StableChecks::ALL, &sc.honest(true), &a, &Tools::split());
    eprintln!("[G-sound] batch liveness hint forged (live batch row {j} declared absent): deployed REJECTED: {why}");
}

/// **`cond` forged on a dead pair** (the review fix that gates the threshold
/// test by `α_b`, `dm1c = α_b·(S − 1 − θ)`): on a pair whose right row is
/// dead the gated test reads `dm1c = 0`, so `cond = 1` has witness `−1` and
/// the deployed leaf rejects it (Range lookup). The gate carries no
/// soundness weight of its own — `merge = cond·α_b` is gated again — so the
/// leaf WITHOUT the threshold range test accepts `cond = 1` there and
/// certifies exactly the honest state: the gate only keeps stale dead fields
/// from making honest witnesses unprovable. Probe (no wrong state exists).
#[test]
fn g1_probe_dead_pair_cond() {
    let (sc, (r, j)) = find("a pair with a dead right row", params(), 2, 1 << 12, |_, hs| {
        hs.rounds
            .iter()
            .enumerate()
            .find_map(|(r, rd)| (0..rd.cond.len()).find(|&j| rd.alive_in[2 * j + 1] == Val::ZERO).map(|j| (r, j)))
    });
    let mut a = sc.honest(true);
    a.cond.insert((r, j), Val::ONE);
    let s = simulate(&a);
    assert_eq!(s.final_commit, sc.honest_final(), "cond on a dead pair changes nothing (merge = cond·α_b)");
    match attempt(&leaf(params(), checks_without(&["cond_range"])), &s, &Tools::default()) {
        Verdict::Accepted { final_, .. } => assert_eq!(final_, sc.honest_final(), "the ungated leaf certifies the honest state"),
        other => panic!("dead-pair cond: the leaf without the threshold test must accept it: {other:?}"),
    }
    let why = reject_only("dead-pair cond = 1", params(), StableChecks::ALL, &sc.honest(true), &a, &Tools::default());
    eprintln!(
        "[G-sound] probe cond = 1 on a dead pair (round {r}, pair {j}): without cond_range ACCEPTED the HONEST state; deployed REJECTED: {why}"
    );
}

// ══════════════════════════════════════════════════════════════════════
// I. Every attack again: a second shape, the deployed layout, the deployed shape
// ══════════════════════════════════════════════════════════════════════

/// Every attack and probe of this suite, in sequence, at the current
/// [`SHAPE`] and [`MODE`] (the `S = cap + 1` attack uses its own shape).
fn run_every_attack() {
    attack_pipeline_is_transparent_on_honest_witnesses();
    g1_attack_compaction_reorder_survivors();
    g1_attack_compaction_survivor_to_tail_dead_kept();
    g1_attack_liveness_survivor_dropped_folded_row_resurrected();
    g1_attack_compaction_duplicate_survivor();
    g1_attack_liveness_non_boolean_hint();
    g1_attack_fusion_wrong_direction_bit();
    g1_attack_fusion_under_merge_non_boolean_lt();
    g1_attack_fusion_over_budget_merge();
    g1_attack_fusion_under_merge();
    g1_attack_fusion_both_directions();
    g1_probe_cond_bool_is_implied();
    g1_attack_forged_survivor_update();
    g1_attack_cross_op_trade_union_to_last_round();
    g1_attack_union_half_repairing();
    g1_attack_union_out_of_order();
    g1_attack_union_tiebreak();
    g1_attack_init_t_after_n_prev();
    g1_attack_poisoned_dummy();
    g1_attack_crafted_huge_g_init();
    g1_attack_init_e_beyond_e_max();
    g1_attack_is_fresh_swapped();
    g1_attack_fresh_non_boolean();
    g1_attack_theta();
    g1_attack_wrong_n_prev();
    g1_attack_forged_arrival_positions();
    g1_attack_capacity_plus_one();
    g1_attack_final_not_bound();
    g1_probe_union_liveness_hint_forged();
    g1_probe_batch_liveness_hint_forged();
    g1_probe_dead_pair_cond();
}

/// The attacks again at a second shape (`cap 16, m 8, s 4`: `T = 24`,
/// `L_f = 5`), so no verdict depends on one table size.
#[test]
fn g1_attacks_at_a_second_shape() {
    SHAPE.with(|c| c.set(GkbParams { capacity: 16, batch: 8, s: 4 }));
    run_every_attack();
}

/// **Every attack against the DEPLOYED layout** (round 2): the tests above
/// attack the `Boundary` + `Plain` leaf, a different circuit (VK) from the
/// one the harness runs. Here each control and each attacked leaf is the
/// `Interval` statement with `Hiding` commitments (secret salts of leaf
/// [`LEAF_T`]; the forged witness carries them as its first private inputs,
/// and every commitment is the salted one), the configuration of config B.
/// An accepted proof must expose the simulated `(init, final, idx = (t, t),
/// H(TAG_LEAF, t, Com(B_t)))`; every verdict must be the same as on the
/// Plain leaf: each control certifies its wrong state, the deployed leaf
/// rejects each forgery in the AIR / LogUp / range argument.
#[test]
fn g1_attacks_on_the_deployed_layout() {
    on_deployed_layout(run_every_attack);
}

/// [`g1_attacks_on_the_deployed_layout`] at the second shape (`cap 16, m 8,
/// s 4`).
#[test]
fn g1_attacks_on_the_deployed_layout_at_a_second_shape() {
    SHAPE.with(|c| c.set(GkbParams { capacity: 16, batch: 8, s: 4 }));
    on_deployed_layout(run_every_attack);
}

/// **The attacks at the deployed shape** (config B leaf: cap 768, m 512,
/// s 51, `T = 1280`, `L_f = 11`) on the deployed layout (`Interval` +
/// `Hiding`, ZK), each with its control at that shape, in two parts of
/// ~5 min each (~5.4 GB peak): this one the compaction / liveness / fusion /
/// union-order / freshness / θ / final-binding attacks,
/// [`g1_attacks_at_the_deployed_shape_part2`] the rest. Only the cross-op
/// trade stays at the small shapes (its search simulates `O(m·T)` forged
/// unions; the checks it meets are the same circuit code at every shape).
/// `cargo test --release --lib -- --ignored stable_attacks::g1_attacks_at_the_deployed_shape`.
#[test]
#[ignore = "config-B shape (cap 768, m 512): minutes and ~5 GB per proof; run explicitly"]
fn g1_attacks_at_the_deployed_shape() {
    SHAPE.with(|c| c.set(GkbParams { capacity: 768, batch: 512, s: 51 }));
    on_deployed_layout(|| {
        attack_pipeline_is_transparent_on_honest_witnesses();
        g1_attack_compaction_reorder_survivors();
        g1_attack_compaction_survivor_to_tail_dead_kept();
        g1_attack_liveness_survivor_dropped_folded_row_resurrected();
        g1_attack_liveness_non_boolean_hint();
        g1_attack_fusion_wrong_direction_bit();
        g1_attack_fusion_over_budget_merge();
        g1_attack_fusion_under_merge();
        g1_attack_fusion_both_directions();
        g1_attack_union_out_of_order();
        g1_attack_union_tiebreak();
        g1_attack_is_fresh_swapped();
        g1_attack_fresh_non_boolean();
        g1_attack_theta();
        g1_attack_final_not_bound();
    });
}

/// Part 2 of [`g1_attacks_at_the_deployed_shape`]: the forged survivor
/// update, the duplicate, the non-boolean `lt`, the union half re-pairing,
/// the crafted inits, `N` and arrival positions, `S = cap + 1` (its own
/// shape) and the probes, at cap 768, m 512 on the deployed layout.
#[test]
#[ignore = "config-B shape (cap 768, m 512): minutes and ~5 GB per proof; run explicitly"]
fn g1_attacks_at_the_deployed_shape_part2() {
    SHAPE.with(|c| c.set(GkbParams { capacity: 768, batch: 512, s: 51 }));
    on_deployed_layout(|| {
        g1_attack_compaction_duplicate_survivor();
        g1_attack_fusion_under_merge_non_boolean_lt();
        g1_probe_cond_bool_is_implied();
        g1_attack_forged_survivor_update();
        g1_attack_union_half_repairing();
        g1_attack_init_t_after_n_prev();
        g1_attack_poisoned_dummy();
        g1_attack_crafted_huge_g_init();
        g1_attack_init_e_beyond_e_max();
        g1_attack_wrong_n_prev();
        g1_attack_forged_arrival_positions();
        g1_attack_capacity_plus_one();
        g1_probe_union_liveness_hint_forged();
        g1_probe_batch_liveness_hint_forged();
        g1_probe_dead_pair_cond();
    });
}
