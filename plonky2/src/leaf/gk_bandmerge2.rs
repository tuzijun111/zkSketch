//! Two-sided Greenwald–Khanna band-merge leaf (`bandmerge2`), port of ../src/sketch/gk_bandmerge.rs.

use std::sync::Arc;

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;

use crate::config::{C, D, F};
use crate::leaf::gadgets::{assert_perm_cols, bind_commit, vhash};
use crate::recursion::Node;
use crate::sketch::gk_bandmerge2::{
    apply_batch2, build_bm2, fresh_tuples2, num_rounds, Gk2Params, Gk2State, E_BITS, E_MAX,
    MASS_BITS, TUPLE_CELLS,
};

/// Comparison window for the merge-threshold `≤ θ` tests. Sums are `< 5·2^MASS`
/// and the sketch keeps `θ` small, so 32 bits is ample over Goldilocks.
const CMP_BITS: usize = 32;

/// `cond = [x ≤ y]`, forced correct by the boolean hint `cond` and a range check
/// on `w = cond·(y−x) + (1−cond)·(x−y−1)` to `bits` (so `cond=1 ⇒ y≥x`,
/// `cond=0 ⇒ x≥y+1`). Operands must be `< 2^bits` for the range check to be sound.
fn force_le(b: &mut CircuitBuilder<F, D>, cond: Target, x: Target, y: Target, bits: usize) {
    let one = b.one();
    let zero = b.zero();
    let cm1 = b.sub(cond, one);
    let cbool = b.mul(cond, cm1);
    b.connect(cbool, zero); // cond ∈ {0,1}
    let ymx = b.sub(y, x);
    let hi = b.mul(cond, ymx);
    let xmy = b.sub(x, y);
    let xmym1 = b.sub(xmy, one);
    let omc = b.sub(one, cond);
    let lo = b.mul(omc, xmym1);
    let w = b.add(hi, lo);
    let _ = b.split_le(w, bits);
}

/// `nz = [x ≠ 0]`, forced correct by the inverse hint `inv`: `nz = x·inv` and
/// `x·(1−nz) = 0` (so `x ≠ 0 ⇒ inv = x⁻¹, nz = 1`; `x = 0 ⇒ nz = 0`).
fn force_nz(b: &mut CircuitBuilder<F, D>, x: Target, inv: Target) -> Target {
    let one = b.one();
    let zero = b.zero();
    let nz = b.mul(x, inv);
    let omn = b.sub(one, nz);
    let must0 = b.mul(x, omn);
    b.connect(must0, zero);
    nz
}

/// Tuple `r`'s six fields `(e, g, g°, Δ, Δ°, t)` from a flat cell vector.
fn tup(cells: &[Target], r: usize) -> [Target; TUPLE_CELLS] {
    core::array::from_fn(|c| cells[TUPLE_CELLS * r + c])
}

/// The six field-columns (each length `n`) of a flat cell vector, for
/// [`assert_perm_cols`].
fn cols6(cells: &[Target], n: usize) -> [Vec<Target>; TUPLE_CELLS] {
    core::array::from_fn(|c| (0..n).map(|r| cells[TUPLE_CELLS * r + c]).collect())
}

struct Tgt {
    init_commit: HashOutTarget,
    final_commit: HashOutTarget,
    batch_commit: HashOutTarget,
    theta: Target,
    n_prev: Target,
    n_t: Target,
    init_cells: Vec<Target>,
    final_cells: Vec<Target>,
    batch_cells: Vec<Target>,
    union_raw: Vec<Target>,
    fused: Vec<Vec<Target>>,
    resorted: Vec<Vec<Target>>,
    excess: Vec<Target>,
    is_fresh: Vec<Target>,
    lt: Vec<Vec<Target>>,
    cond1: Vec<Vec<Target>>,
    cond2: Vec<Vec<Target>>,
    ea_inv: Vec<Vec<Target>>,
    eb_inv: Vec<Vec<Target>>,
    e_inv_final: Vec<Target>,
    e_inv_batch: Vec<Target>,
    de_inv_union: Vec<Target>,
    de_inv_round: Vec<Vec<Target>>,
}

/// A built, reusable two-sided GK bandmerge2 leaf circuit.
pub struct Gk2Bm2Leaf {
    pub data: Arc<CircuitData<F, C, D>>,
    t: Tgt,
    pub params: Gk2Params,
}

/// Build the bandmerge2 circuit for the shape.
pub fn build_gk2_bm2_leaf(params: Gk2Params) -> Gk2Bm2Leaf {
    params.validate();
    let cap = params.capacity;
    let m = params.batch;
    let total = cap + m;
    assert_eq!(total % 2, 0, "total = cap+m must be even");
    let lf = num_rounds(total);
    let num_pairs = total / 2;

    let mut b = CircuitBuilder::<F, D>::new(crate::config::circuit_config());

    // ── Public inputs: (Com(S_{t-1}), Com(S_t), Com(B_t)), θ, N_prev, N_t ──
    let init_commit = vhash(&mut b);
    b.register_public_inputs(&init_commit.elements);
    let final_commit = vhash(&mut b);
    b.register_public_inputs(&final_commit.elements);
    let batch_commit = vhash(&mut b);
    b.register_public_inputs(&batch_commit.elements);
    let theta = b.add_virtual_public_input();
    let n_prev = b.add_virtual_public_input();
    let n_t = b.add_virtual_public_input();

    let one = b.one();
    let zero = b.zero();
    let e_max = b.constant(F::from_canonical_u64(E_MAX as u64));

    // ── Private witness ──
    let init_cells = b.add_virtual_targets(TUPLE_CELLS * cap);
    let final_cells = b.add_virtual_targets(TUPLE_CELLS * cap);
    let batch_cells = b.add_virtual_targets(TUPLE_CELLS * m);
    let union_raw = b.add_virtual_targets(TUPLE_CELLS * total);
    let fused: Vec<Vec<Target>> =
        (0..lf).map(|_| b.add_virtual_targets(TUPLE_CELLS * total)).collect();
    let resorted: Vec<Vec<Target>> =
        (0..lf).map(|_| b.add_virtual_targets(TUPLE_CELLS * total)).collect();
    let excess = b.add_virtual_targets(TUPLE_CELLS * m);
    let is_fresh = b.add_virtual_targets(total);
    let lt: Vec<Vec<Target>> = (0..lf).map(|_| b.add_virtual_targets(num_pairs)).collect();
    let cond1: Vec<Vec<Target>> = (0..lf).map(|_| b.add_virtual_targets(num_pairs)).collect();
    let cond2: Vec<Vec<Target>> = (0..lf).map(|_| b.add_virtual_targets(num_pairs)).collect();
    let ea_inv: Vec<Vec<Target>> = (0..lf).map(|_| b.add_virtual_targets(num_pairs)).collect();
    let eb_inv: Vec<Vec<Target>> = (0..lf).map(|_| b.add_virtual_targets(num_pairs)).collect();
    let e_inv_final = b.add_virtual_targets(cap);
    let e_inv_batch = b.add_virtual_targets(m);
    let de_inv_union = b.add_virtual_targets(total - 1);
    let de_inv_round: Vec<Vec<Target>> =
        (0..lf).map(|_| b.add_virtual_targets(total - 1)).collect();

    // ── Stage 1: commit bindings ──
    bind_commit(&mut b, init_cells.clone(), &init_commit);
    bind_commit(&mut b, final_cells.clone(), &final_commit);
    bind_commit(&mut b, batch_cells.clone(), &batch_commit);

    // ── Stage 3: union multiset ──
    // Fresh singletons are well-formed: g₁=g₂=Δ₁=Δ₂=0.
    for j in 0..m {
        let f = tup(&batch_cells, j);
        b.connect(f[1], zero);
        b.connect(f[2], zero);
        b.connect(f[3], zero);
        b.connect(f[4], zero);
    }
    // union_raw is a permutation of (init ‖ batch).
    let mut combined: Vec<Target> = init_cells.clone();
    combined.extend_from_slice(&batch_cells);
    let cc = cols6(&combined, total);
    let uu = cols6(&union_raw, total);
    assert_perm_cols(
        &mut b,
        &[&cc[0], &cc[1], &cc[2], &cc[3], &cc[4], &cc[5]],
        &[&uu[0], &uu[1], &uu[2], &uu[3], &uu[4], &uu[5]],
    );

    // ── Stage 4: union_raw range-checks + value sortedness + (e,t) tiebreak ──
    for r in 0..total {
        let f = tup(&union_raw, r);
        let _ = b.split_le(f[0], E_BITS);
        for c in 1..6 {
            let _ = b.split_le(f[c], MASS_BITS);
        }
    }
    for r in 0..total - 1 {
        let er = tup(&union_raw, r);
        let er1 = tup(&union_raw, r + 1);
        let diff = b.sub(er1[0], er[0]);
        let _ = b.split_le(diff, E_BITS); // e ascending
        // (e,t) tiebreak: if e_{r+1}=e_r then t_{r+1} ≥ t_r.
        let nz = force_nz(&mut b, diff, de_inv_union[r]);
        let is_de_zero = b.sub(one, nz);
        let dt = b.sub(er1[5], er[5]);
        let w = b.mul(is_de_zero, dt);
        let _ = b.split_le(w, MASS_BITS);
    }

    // ── Stage 5: two-sided neighbor-init ──
    let n_prev_p1 = b.add(n_prev, one);
    // is_fresh[r] = [t_r ≥ n_prev+1] = force_le(n_prev+1 ≤ t_r).
    for r in 0..total {
        let f = tup(&union_raw, r);
        force_le(&mut b, is_fresh[r], n_prev_p1, f[5], MASS_BITS);
    }
    // Δ₁_init right-to-left: fresh ? (g₁_{r+1}+Δ₁_init[r+1]) : Δ₁_raw[r].
    let mut d1: Vec<Target> = vec![zero; total];
    for r in (0..total).rev() {
        let base = if r + 1 < total {
            let f1 = tup(&union_raw, r + 1);
            b.add(f1[1], d1[r + 1])
        } else {
            zero
        };
        let f_part = b.mul(is_fresh[r], base);
        let omf = b.sub(one, is_fresh[r]);
        let fr = tup(&union_raw, r);
        let o_part = b.mul(omf, fr[3]);
        d1[r] = b.add(f_part, o_part);
    }
    // Δ₂_init left-to-right: fresh ? (g₂_{r-1}+Δ₂_init[r-1]) : Δ₂_raw[r].
    let mut d2: Vec<Target> = vec![zero; total];
    for r in 0..total {
        let base = if r >= 1 {
            let fm1 = tup(&union_raw, r - 1);
            b.add(fm1[2], d2[r - 1])
        } else {
            zero
        };
        let f_part = b.mul(is_fresh[r], base);
        let omf = b.sub(one, is_fresh[r]);
        let fr = tup(&union_raw, r);
        let o_part = b.mul(omf, fr[4]);
        d2[r] = b.add(f_part, o_part);
    }
    // uinit fields [e, g₁, g₂, Δ₁_init, Δ₂_init, t].
    let uinit_f: Vec<[Target; 6]> = (0..total)
        .map(|r| {
            let f = tup(&union_raw, r);
            [f[0], f[1], f[2], d1[r], d2[r], f[5]]
        })
        .collect();

    // ── Stage 6: L_f parity-0 two-sided fuse + resort rounds ──
    let mut cur_f: Vec<[Target; 6]> = uinit_f;
    for round in 0..lf {
        for k in 0..num_pairs {
            let a = cur_f[2 * k];
            let bb = cur_f[2 * k + 1];
            // lt = [a.t > b.t] = [b.t+1 ≤ a.t].
            let bt1 = b.add(bb[5], one);
            force_le(&mut b, lt[round][k], bt1, a[5], MASS_BITS);
            // cond1 = [g₁ₐ+g₂ₐ+g₁_b+Δ₁_b+1 ≤ θ].
            let s1a = b.add(a[1], a[2]);
            let s1b = b.add(bb[1], bb[3]);
            let s1 = b.add(s1a, s1b);
            let sum1 = b.add(s1, one);
            force_le(&mut b, cond1[round][k], sum1, theta, CMP_BITS);
            // cond2 = [g₂_b+g₁_b+g₂ₐ+Δ₂ₐ+1 ≤ θ].
            let s2a = b.add(bb[2], bb[1]);
            let s2b = b.add(a[2], a[4]);
            let s2 = b.add(s2a, s2b);
            let sum2 = b.add(s2, one);
            force_le(&mut b, cond2[round][k], sum2, theta, CMP_BITS);
            // active_a = [e_a ≠ E_MAX], active_b = [e_b ≠ E_MAX].
            let da = b.sub(e_max, a[0]);
            let active_a = force_nz(&mut b, da, ea_inv[round][k]);
            let db = b.sub(e_max, bb[0]);
            let active_b = force_nz(&mut b, db, eb_inv[round][k]);
            let ab = b.mul(active_a, active_b);
            // dir1 = lt·cond1·ab, dir2 = (1−lt)·cond2·ab.
            let l1 = b.mul(lt[round][k], cond1[round][k]);
            let dir1 = b.mul(l1, ab);
            let omlt = b.sub(one, lt[round][k]);
            let l2 = b.mul(omlt, cond2[round][k]);
            let dir2 = b.mul(l2, ab);
            let omdir1 = b.sub(one, dir1);
            let omdir2 = b.sub(one, dir2);
            let omd12 = b.sub(omdir1, dir2); // 1 − dir1 − dir2
            // survivor mass updates.
            let new_hi_g1 = {
                let t1 = b.add(a[1], a[2]);
                let t2 = b.add(t1, bb[1]);
                b.add(t2, one)
            };
            let new_lo_g2 = {
                let t1 = b.add(bb[2], bb[1]);
                let t2 = b.add(t1, a[2]);
                b.add(t2, one)
            };
            // f_lo (position 2k): dir1 ⇒ dummy, else pass a (dir2 grows a.g°).
            let lo_e = {
                let x = b.mul(dir1, e_max);
                let y = b.mul(omdir1, a[0]);
                b.add(x, y)
            };
            let lo_g1 = b.mul(omdir1, a[1]);
            let lo_g2 = {
                let x = b.mul(dir2, new_lo_g2);
                let y = b.mul(omd12, a[2]);
                b.add(x, y)
            };
            let lo_d1 = b.mul(omdir1, a[3]);
            let lo_d2 = b.mul(omdir1, a[4]);
            let lo_t = b.mul(omdir1, a[5]);
            let flo = tup(&fused[round], 2 * k);
            b.connect(flo[0], lo_e);
            b.connect(flo[1], lo_g1);
            b.connect(flo[2], lo_g2);
            b.connect(flo[3], lo_d1);
            b.connect(flo[4], lo_d2);
            b.connect(flo[5], lo_t);
            // f_hi (position 2k+1): dir2 ⇒ dummy, else pass b (dir1 grows b.g₁).
            let hi_e = {
                let x = b.mul(dir2, e_max);
                let y = b.mul(omdir2, bb[0]);
                b.add(x, y)
            };
            let hi_g1 = {
                let x = b.mul(dir1, new_hi_g1);
                let y = b.mul(omd12, bb[1]);
                b.add(x, y)
            };
            let hi_g2 = b.mul(omdir2, bb[2]);
            let hi_d1 = b.mul(omdir2, bb[3]);
            let hi_d2 = b.mul(omdir2, bb[4]);
            let hi_t = b.mul(omdir2, bb[5]);
            let fhi = tup(&fused[round], 2 * k + 1);
            b.connect(fhi[0], hi_e);
            b.connect(fhi[1], hi_g1);
            b.connect(fhi[2], hi_g2);
            b.connect(fhi[3], hi_d1);
            b.connect(fhi[4], hi_d2);
            b.connect(fhi[5], hi_t);
        }
        // resort: resorted is a permutation of fused.
        let ff = cols6(&fused[round], total);
        let rr = cols6(&resorted[round], total);
        assert_perm_cols(
            &mut b,
            &[&ff[0], &ff[1], &ff[2], &ff[3], &ff[4], &ff[5]],
            &[&rr[0], &rr[1], &rr[2], &rr[3], &rr[4], &rr[5]],
        );
        for r in 0..total {
            let f = tup(&resorted[round], r);
            let _ = b.split_le(f[0], E_BITS);
            for c in 1..6 {
                let _ = b.split_le(f[c], MASS_BITS);
            }
        }
        for r in 0..total - 1 {
            let er = tup(&resorted[round], r);
            let er1 = tup(&resorted[round], r + 1);
            let diff = b.sub(er1[0], er[0]);
            let _ = b.split_le(diff, E_BITS);
            let nz = force_nz(&mut b, diff, de_inv_round[round][r]);
            let is_de_zero = b.sub(one, nz);
            let dt = b.sub(er1[5], er[5]);
            let w = b.mul(is_de_zero, dt);
            let _ = b.split_le(w, MASS_BITS);
        }
        cur_f = (0..total).map(|r| tup(&resorted[round], r)).collect();
    }

    // ── Stage 7: compaction — final = cur[..cap], excess = cur[cap..] ──
    for i in 0..cap {
        let f = tup(&final_cells, i);
        let _ = b.split_le(f[0], E_BITS);
        for c in 1..6 {
            let _ = b.split_le(f[c], MASS_BITS);
        }
        for c in 0..6 {
            b.connect(f[c], cur_f[i][c]);
        }
    }
    // excess must be all-dummy: e=E_MAX, g₁=g₂=0, and equals cur[cap+j].
    for j in 0..m {
        let f = tup(&excess, j);
        for c in 0..6 {
            b.connect(f[c], cur_f[cap + j][c]);
        }
        b.connect(f[0], e_max);
        b.connect(f[1], zero);
        b.connect(f[2], zero);
    }

    // ── Stage 8: mass — Σ_active(g₁+g₂+1) = N_t, N_t = N_prev + #active_batch ──
    let mut mass = zero;
    let mut count = zero;
    for i in 0..cap {
        let f = tup(&final_cells, i);
        let di = b.sub(e_max, f[0]);
        let act = force_nz(&mut b, di, e_inv_final[i]);
        // Poisoned-dummy guard: a dummy final row (act=0) must carry no mass.
        let omact = b.sub(one, act);
        let z1 = b.mul(omact, f[1]);
        b.connect(z1, zero);
        let z2 = b.mul(omact, f[2]);
        b.connect(z2, zero);
        count = b.add(count, act);
        let gg = b.add(f[1], f[2]);
        mass = b.add(mass, gg);
    }
    mass = b.add(mass, count);
    b.connect(mass, n_t);
    let mut count_batch = zero;
    for j in 0..m {
        let f = tup(&batch_cells, j);
        let dj = b.sub(e_max, f[0]);
        let actj = force_nz(&mut b, dj, e_inv_batch[j]);
        count_batch = b.add(count_batch, actj);
    }
    let np_plus_b = b.add(n_prev, count_batch);
    b.connect(np_plus_b, n_t);

    let data = Arc::new(crate::config::build_circuit(b));
    Gk2Bm2Leaf {
        data,
        t: Tgt {
            init_commit, final_commit, batch_commit, theta, n_prev, n_t, init_cells, final_cells,
            batch_cells, union_raw, fused, resorted, excess, is_fresh, lt, cond1, cond2, ea_inv,
            eb_inv, e_inv_final, e_inv_batch, de_inv_union, de_inv_round,
        },
        params,
    }
}

/// Flatten tuples' 6 cells into an F vector.
fn flat(ts: &[crate::sketch::gk_bandmerge2::Gk2Tuple]) -> Vec<F> {
    ts.iter().flat_map(|t| t.cells()).collect()
}

impl Gk2Bm2Leaf {
    /// Prove one two-sided GK epoch from `initial` given the inserted `batch_vals`.
    pub fn prove(&self, initial: &Gk2State, batch_vals: &[u32], index: u64) -> Result<Node> {
        let build = build_bm2(initial, batch_vals);
        let final_state = apply_batch2(initial, batch_vals);
        let init_commit = initial.commit();
        let final_commit = final_state.commit();
        let pw = self.witness(initial, batch_vals, &build.final_tuples, final_commit)?;
        let proof = self.data.prove(pw)?;
        Ok(Node::leaf(self.data.clone(), proof, init_commit, final_commit, index))
    }

    /// Build the full witness. `final_tuples`/`final_commit` are passed
    /// explicitly (honest = the build's own) so tamper tests can inject a
    /// corrupted committed final and confirm the pipeline rejects it.
    fn witness(
        &self,
        initial: &Gk2State,
        batch_vals: &[u32],
        final_tuples: &[crate::sketch::gk_bandmerge2::Gk2Tuple],
        final_commit: plonky2::hash::hash_types::HashOut<F>,
    ) -> Result<PartialWitness<F>> {
        let cap = self.params.capacity;
        let m = self.params.batch;
        let total = cap + m;
        let lf = num_rounds(total);
        let num_pairs = total / 2;
        assert!(batch_vals.len() <= m);

        let build = build_bm2(initial, batch_vals);
        let init_commit = initial.commit();
        let fresh = fresh_tuples2(batch_vals, m, build.n_prev);
        let batch_commit = crate::sketch::gk_bandmerge2::batch_commit(batch_vals, m, build.n_prev);

        // curs[i] = the table round i fuses (union_init, then each round's resort).
        let mut curs: Vec<Vec<crate::sketch::gk_bandmerge2::Gk2Tuple>> = vec![build.union_init.clone()];
        for round in 0..lf {
            curs.push(build.rounds[round].resorted.clone());
        }
        let inv = |x: u64| if x == 0 { F::ZERO } else { F::from_canonical_u64(x).inverse() };

        let mut pw = PartialWitness::<F>::new();
        pw.set_hash_target(self.t.init_commit, init_commit)?;
        pw.set_hash_target(self.t.final_commit, final_commit)?;
        pw.set_hash_target(self.t.batch_commit, batch_commit)?;
        pw.set_target(self.t.theta, F::from_canonical_u64(build.theta))?;
        pw.set_target(self.t.n_prev, F::from_canonical_u64(build.n_prev))?;
        pw.set_target(self.t.n_t, F::from_canonical_u64(build.n_t))?;

        let set_cells = |pw: &mut PartialWitness<F>, tgt: &[Target], vals: &[F]| -> Result<()> {
            for (t, v) in tgt.iter().zip(vals) {
                pw.set_target(*t, *v)?;
            }
            Ok(())
        };
        set_cells(&mut pw, &self.t.init_cells, &flat(&initial.tuples))?;
        set_cells(&mut pw, &self.t.final_cells, &flat(final_tuples))?;
        set_cells(&mut pw, &self.t.batch_cells, &flat(&fresh))?;
        set_cells(&mut pw, &self.t.union_raw, &flat(&build.union_raw))?;
        for round in 0..lf {
            set_cells(&mut pw, &self.t.fused[round], &flat(&build.rounds[round].fused))?;
            set_cells(&mut pw, &self.t.resorted[round], &flat(&build.rounds[round].resorted))?;
        }
        set_cells(&mut pw, &self.t.excess, &flat(&build.excess))?;

        for r in 0..total {
            let fresh_r = build.union_raw[r].active == 1 && build.union_raw[r].t > build.n_prev;
            pw.set_target(self.t.is_fresh[r], F::from_canonical_u64(fresh_r as u64))?;
        }
        for round in 0..lf {
            for k in 0..num_pairs {
                let a = curs[round][2 * k];
                let bb = curs[round][2 * k + 1];
                pw.set_target(self.t.lt[round][k], F::from_canonical_u64((a.t > bb.t) as u64))?;
                pw.set_target(self.t.cond1[round][k], F::from_canonical_u64(build.rounds[round].cond1[k]))?;
                pw.set_target(self.t.cond2[round][k], F::from_canonical_u64(build.rounds[round].cond2[k]))?;
                pw.set_target(self.t.ea_inv[round][k], inv((E_MAX - a.e) as u64))?;
                pw.set_target(self.t.eb_inv[round][k], inv((E_MAX - bb.e) as u64))?;
            }
        }
        for i in 0..cap {
            pw.set_target(self.t.e_inv_final[i], inv((E_MAX - final_tuples[i].e) as u64))?;
        }
        for j in 0..m {
            pw.set_target(self.t.e_inv_batch[j], inv((E_MAX - fresh[j].e) as u64))?;
        }
        for r in 0..total - 1 {
            let de = (build.union_raw[r + 1].e - build.union_raw[r].e) as u64;
            pw.set_target(self.t.de_inv_union[r], inv(de))?;
        }
        for round in 0..lf {
            let rs = &build.rounds[round].resorted;
            for r in 0..total - 1 {
                let de = (rs[r + 1].e - rs[r].e) as u64;
                pw.set_target(self.t.de_inv_round[round][r], inv(de))?;
            }
        }

        let _ = (init_commit, final_commit);
        Ok(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::{merge, verify_node};

    fn params() -> Gk2Params {
        Gk2Params { capacity: 12, batch: 4, s: 2 }
    }

    /// Round-trip: honest two-sided band-merge transition proves + verifies, and
    /// the certified final commit equals the natively computed state.
    #[test]
    fn bandmerge2_round_trip() -> Result<()> {
        let p = params();
        let leaf = build_gk2_bm2_leaf(p);
        let s0 = Gk2State::empty(p);
        let vals = vec![5u32, 7, 11, 13];
        let node = leaf.prove(&s0, &vals, 1)?;
        let s1 = apply_batch2(&s0, &vals);
        assert_eq!(node.initial, s0.commit());
        assert_eq!(node.final_, s1.commit(), "certified final == native apply_batch2");
        assert_ne!(node.initial, node.final_);
        verify_node(&node)
    }

    /// Non-empty prior: a second epoch folds against the first's committed state.
    #[test]
    fn bandmerge2_nonempty_prior() -> Result<()> {
        let p = params();
        let leaf = build_gk2_bm2_leaf(p);
        let s0 = Gk2State::empty(p);
        let s1 = apply_batch2(&s0, &[5, 7, 11, 13]);
        let node = leaf.prove(&s1, &[6, 7, 12, 14], 2)?;
        let s2 = apply_batch2(&s1, &[6, 7, 12, 14]);
        assert_eq!(node.final_, s2.commit());
        verify_node(&node)
    }

    /// Two adjacent epochs thread by boundary and recursively merge in the forest.
    #[test]
    fn bandmerge2_two_leaf_merge() -> Result<()> {
        let p = params();
        let leaf = build_gk2_bm2_leaf(p);
        let s0 = Gk2State::empty(p);
        let n1 = leaf.prove(&s0, &[5, 7, 11, 13], 1)?;
        let s1 = apply_batch2(&s0, &[5, 7, 11, 13]);
        let n2 = leaf.prove(&s1, &[6, 7, 12, 14], 2)?;
        let root = merge(&n1, &n2)?;
        verify_node(&root)?;
        assert_eq!(root.num_leaves(), 2);
        Ok(())
    }

    use crate::sketch::gk_bandmerge2::{build_bm2, Gk2Tuple};
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    fn commit_of(ts: &[Gk2Tuple]) -> plonky2::hash::hash_types::HashOut<F> {
        let cells: Vec<F> = ts.iter().flat_map(|t| t.cells()).collect();
        PoseidonHash::hash_no_pad(&cells)
    }

    /// **Tamper (compaction bind).** Commit a corrupted final — a surviving
    /// tuple's `g` bumped — while the honest pipeline computes the true `cur[..cap]`;
    /// the `final_cells == cur` bind fails, so proving is rejected.
    #[test]
    fn tamper_corrupted_final_rejected() {
        let p = params();
        let leaf = build_gk2_bm2_leaf(p);
        let s0 = Gk2State::empty(p);
        let vals = vec![5u32, 7, 11, 13];
        let build = build_bm2(&s0, &vals);
        let mut bad = build.final_tuples.clone();
        // Bump the first active tuple's left mass g.
        let i = bad.iter().position(|t| t.e != E_MAX).expect("an active survivor");
        bad[i].g += 1;
        let bad_commit = commit_of(&bad);
        let pw = leaf.witness(&s0, &vals, &bad, bad_commit).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "corrupted final must break the compaction bind");
    }

    /// **Tamper (poisoned-dummy guard, audit fix #4A).** A dummy final slot
    /// (`e = E_MAX`, so `active = 0`) is given nonzero mass `g`; the
    /// `(1−active)·g = 0` guard rejects it (a poisoned dummy could otherwise
    /// inflate `N_t` while contributing 0 to the active count).
    #[test]
    fn tamper_poisoned_dummy_rejected() {
        let p = params();
        let leaf = build_gk2_bm2_leaf(p);
        let s0 = Gk2State::empty(p);
        let vals = vec![5u32, 7, 11, 13];
        let build = build_bm2(&s0, &vals);
        let mut bad = build.final_tuples.clone();
        let d = bad.iter().position(|t| t.e == E_MAX).expect("a dummy slot");
        bad[d].g = 5; // poison: E_MAX dummy carrying mass
        let bad_commit = commit_of(&bad);
        let pw = leaf.witness(&s0, &vals, &bad, bad_commit).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "poisoned dummy (1−act)·g≠0 must be rejected");
    }

    /// **Tamper (commit binding).** A final commit that does not match the
    /// witnessed final cells is rejected by `bind_commit`.
    #[test]
    fn tamper_wrong_commit_rejected() {
        let p = params();
        let leaf = build_gk2_bm2_leaf(p);
        let s0 = Gk2State::empty(p);
        let vals = vec![5u32, 7, 11, 13];
        let build = build_bm2(&s0, &vals);
        // Honest final cells, but a commit over a *different* state.
        let wrong_commit = commit_of(&Gk2State::empty(p).tuples);
        let pw = leaf.witness(&s0, &vals, &build.final_tuples, wrong_commit).unwrap();
        assert!(leaf.data.prove(pw).is_err(), "final commit not binding the cells must be rejected");
    }
}
