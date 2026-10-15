//! Test-only **trace forger** for the binding soundness tests.
//!
//! A malicious prover is not bound by the honest runner; it can hand
//! `prove_all_tables` any traces. The forgeries here are built by
//! *transplanting*: run the circuit honestly on modified data (a different
//! final state, a different record key, ...), so every constrained row is
//! consistent with the modified data. Then put the ORIGINAL value back into
//! the one witness the attack must not change (a hashed packed Challenge),
//! everywhere that witness appears ([`set_wid`]), and recompute every
//! Poseidon2 sponge chain from its patched inputs ([`rehash_all`]). The
//! resulting trace commits to data A while every downstream constraint was
//! evaluated on data B. It passes exactly when nothing binds the decomposed
//! coefficients to the hashed value. That is the case in `Binding::Legacy`
//! (only the Recompose NPO row reads the packed value, and [`set_wid`]
//! re-derives its row values) and not in `Binding::Bound` (the ALU
//! recomposition row breaks).

use p3_circuit::ops::{
    ExposeTrace, NpoTypeId, PermuteTrace, Poseidon2Config, Poseidon2Trace, RangeTrace,
    RecomposeTrace,
};
use p3_circuit::ops::{ExecutionContext, NpoPrivateData, OpStateMap};
use p3_circuit::tables::Traces;
use p3_circuit::{AluOpKind, Circuit, CircuitError, Op, WitnessId};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;
use std::collections::BTreeMap;

use crate::config::Challenge;

/// Replace the value of witness `wid` with `v` in every table that carries it
/// (ALU, Public, Recompose in/out, Range, Permute in/out, Expose, and
/// CTL-exposed Poseidon2 input limbs). Poseidon2 OUTPUTS are not stored in
/// the trace (the AIR recomputes them from the inputs); see [`rehash_all`].
pub(crate) fn set_wid<BF, EF>(traces: &mut Traces<EF>, wid: WitnessId, v: EF)
where
    BF: PrimeField64,
    EF: ExtensionField<BF>,
{
    let d = <EF as BasedVectorSpace<BF>>::DIMENSION;
    let coeffs: Vec<BF> = v.as_basis_coefficients_slice().to_vec();

    for (row, idx) in traces.alu_trace.indices.iter().enumerate() {
        for slot in 0..4 {
            if idx[slot] == wid {
                traces.alu_trace.values[row][slot] = v;
            }
        }
    }
    for (i, w) in traces.public_trace.index.iter().enumerate() {
        if *w == wid {
            traces.public_trace.values[i] = v;
        }
    }

    let keys: Vec<NpoTypeId> = traces.non_primitive_traces.keys().cloned().collect();
    for key in keys {
        let any = traces.non_primitive_traces[&key].as_any();
        if let Some(t) = any.downcast_ref::<RecomposeTrace<BF>>() {
            let mut t = t.clone();
            for row in t.operations.iter_mut() {
                if row.output_wid == wid {
                    row.values.copy_from_slice(&coeffs);
                }
                for (i, w) in row.input_wids.iter().enumerate() {
                    if *w == wid {
                        row.values[i] = coeffs[0];
                    }
                }
            }
            traces.non_primitive_traces.insert(key, Box::new(t));
        } else if let Some(t) = any.downcast_ref::<RangeTrace<BF>>() {
            let mut t = t.clone();
            for row in t.operations.iter_mut() {
                for (i, w) in row.input_wids.iter().enumerate() {
                    if *w == wid {
                        row.input_values[d * i..d * i + d].copy_from_slice(&coeffs);
                    }
                }
            }
            traces.non_primitive_traces.insert(key, Box::new(t));
        } else if let Some(t) = any.downcast_ref::<ExposeTrace<BF>>() {
            let mut t = t.clone();
            for row in t.operations.iter_mut() {
                for (i, w) in row.input_wids.iter().enumerate() {
                    if *w == wid {
                        row.input_values[d * i..d * i + d].copy_from_slice(&coeffs);
                    }
                }
            }
            traces.non_primitive_traces.insert(key, Box::new(t));
        } else if let Some(t) = any.downcast_ref::<PermuteTrace<BF>>() {
            let mut t = t.clone();
            for row in t.operations.iter_mut() {
                for (i, w) in row.input_wids.iter().enumerate() {
                    if *w == wid {
                        row.input_values[d * i..d * i + d].copy_from_slice(&coeffs);
                    }
                }
                for (i, w) in row.output_wids.iter().enumerate() {
                    if *w == wid {
                        row.output_values[d * i..d * i + d].copy_from_slice(&coeffs);
                    }
                }
            }
            traces.non_primitive_traces.insert(key, Box::new(t));
        } else if let Some(t) = any.downcast_ref::<Poseidon2Trace<BF>>() {
            let mut t = t.clone();
            for row in t.operations.iter_mut() {
                let limb_d = row.input_values.len() / row.in_ctl.len();
                for (limb, (&ctl, &idx)) in row.in_ctl.iter().zip(&row.input_indices).enumerate() {
                    if ctl && idx == wid.0 {
                        row.input_values[limb * limb_d..limb * limb_d + limb_d]
                            .copy_from_slice(&coeffs[..limb_d]);
                    }
                }
            }
            traces.non_primitive_traces.insert(key, Box::new(t));
        }
    }
}

/// Current value of `wid` as the trace records it (first table that carries
/// it), or `None`.
pub(crate) fn get_wid<BF, EF>(traces: &Traces<EF>, wid: WitnessId) -> Option<EF>
where
    BF: PrimeField64,
    EF: ExtensionField<BF>,
{
    for (row, idx) in traces.alu_trace.indices.iter().enumerate() {
        for slot in 0..4 {
            if idx[slot] == wid {
                return Some(traces.alu_trace.values[row][slot]);
            }
        }
    }
    for (i, w) in traces.public_trace.index.iter().enumerate() {
        if *w == wid {
            return Some(traces.public_trace.values[i]);
        }
    }
    None
}

/// Recompute every sponge chain of the Poseidon2 table `cfg` from its
/// CTL-exposed inputs, in row order. A `new_start` row keeps its non-CTL
/// limbs (the IV as recorded); a continuation row takes its non-CTL limbs
/// from the previous row's output, exactly as the AIR's `normal_chain_sel`
/// requires. Every CTL-exposed output is propagated with [`set_wid`]. It may
/// feed a later hash, so the pass repeats until the table stops changing.
pub(crate) fn rehash_all<BF, EF, P, const W: usize>(
    traces: &mut Traces<EF>,
    cfg: Poseidon2Config,
    perm: &P,
) where
    BF: PrimeField64,
    EF: ExtensionField<BF>,
    P: Permutation<[BF; W]>,
{
    let key = NpoTypeId::poseidon2_perm(cfg);
    let snapshot = |traces: &Traces<EF>| -> Option<Vec<BF>> {
        traces
            .non_primitive_traces
            .get(&key)
            .and_then(|t| t.as_any().downcast_ref::<Poseidon2Trace<BF>>())
            .map(|t| t.operations.iter().flat_map(|r| r.input_values.clone()).collect())
    };
    for _round in 0..8 {
        let Some(before) = snapshot(traces) else {
            return;
        };
        let mut t = traces.non_primitive_traces[&key]
            .as_any()
            .downcast_ref::<Poseidon2Trace<BF>>()
            .expect("poseidon2 trace")
            .clone();
        let mut outputs: Vec<(WitnessId, EF)> = Vec::new();
        let mut prev_out: Option<[BF; W]> = None;
        for row in t.operations.iter_mut() {
            assert!(!row.merkle_path, "rehash_all: Merkle rows unsupported");
            let limb_d = row.input_values.len() / row.in_ctl.len();
            if !row.new_start {
                let prev = prev_out.expect("continuation row without a predecessor");
                for (limb, &ctl) in row.in_ctl.iter().enumerate() {
                    if !ctl {
                        row.input_values[limb * limb_d..limb * limb_d + limb_d]
                            .copy_from_slice(&prev[limb * limb_d..limb * limb_d + limb_d]);
                    }
                }
            }
            let mut state: [BF; W] = row.input_values.clone().try_into().expect("permutation width");
            perm.permute_mut(&mut state);
            for (limb, (&ctl, &idx)) in row.out_ctl.iter().zip(&row.output_indices).enumerate() {
                if ctl {
                    let v = EF::from_basis_coefficients_slice(
                        &state[limb * limb_d..limb * limb_d + limb_d],
                    )
                    .expect("digest limb");
                    outputs.push((WitnessId(idx), v));
                }
            }
            prev_out = Some(state);
        }
        traces.non_primitive_traces.insert(key.clone(), Box::new(t));
        for (wid, v) in outputs {
            set_wid::<BF, EF>(traces, wid, v);
        }
        if snapshot(traces) == Some(before) {
            return;
        }
    }
    panic!("rehash_all: digests did not converge");
}

/// Run `f` (a prove + verify of forged traces) with panics silenced; `true`
/// iff it returned `Ok(())`. A forged trace may make the prover panic (e.g. a
/// debug constraint check) instead of emitting a bad proof — either way it is
/// rejected.
pub(crate) fn accepted(f: impl FnOnce() -> Result<(), String>) -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    matches!(r, Ok(Ok(())))
}

/// **Positive control for a transplant forger.** `forger(forge)` runs ONE
/// forging pipeline end to end: with `forge = false` it writes the HONEST
/// value back through exactly the same plumbing (same leaf and witnesses,
/// [`set_wid`], [`rehash_all`], prove + verify), so it must be accepted; with
/// `forge = true` it writes the forged value. The control runs first and
/// panics if it is rejected: a broken forger (a stale tag, the wrong witness,
/// a packing or rehash bug) rejects honest traces too, which would make every
/// "rejected" assertion vacuous. Returns whether the forgery was accepted.
pub(crate) fn accepted_with_control(what: &str, forger: impl Fn(bool) -> bool) -> bool {
    assert!(
        forger(false),
        "{what}: POSITIVE CONTROL rejected (the honest value through the same forger); the \
         forger is broken, so its rejections would be vacuous"
    );
    forger(true)
}

/// [`accepted_with_control`] for a forger that returns what the verified
/// proof exposes (`None` = rejected). `check_control` inspects the control's
/// value (e.g. that it exposes the honest commitment or answer).
pub(crate) fn forged_with_control<T>(
    what: &str,
    forger: impl Fn(bool) -> Option<T>,
    check_control: impl FnOnce(&T),
) -> Option<T> {
    let control = forger(false).unwrap_or_else(|| {
        panic!(
            "{what}: POSITIVE CONTROL rejected (the honest value through the same forger); the \
             forger is broken, so its rejections would be vacuous"
        )
    });
    check_control(&control);
    forger(true)
}

/// Silence-and-catch variant returning the value.
pub(crate) fn catch<T>(f: impl FnOnce() -> T) -> Option<T> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    r.ok()
}

/// Silence-and-catch variant returning the panic message on failure, so a
/// test can tell WHERE a forgery was rejected (runner witness conflict vs.
/// prover/verifier).
pub(crate) fn catch_msg<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    r.map_err(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
    })
}

// ─── Split wires (a prover that ignores `connect`) ──────────────────────────
//
// Copied from `gk_stable_attacks` (which keeps its own private copy, so that
// file is unchanged) and made crate-visible for the packed-Bloom attacks.

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
pub(crate) fn split_conflicting_wires(c: &mut Circuit<Challenge>, public: &[Challenge], private: &[Challenge]) -> Result<usize, String> {
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
