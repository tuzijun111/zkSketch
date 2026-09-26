//! Test-only **malicious-prover** tooling for soundness proofs-of-concept.
//!
//! A STARK only enforces what its AIRs and LogUp buses enforce. The executors
//! that fill the witness during `runner.run()` (the Permute op's σ, the
//! extension-decomposition hint, the recompose op) are prover-side
//! conveniences: a malicious prover may emit ANY trace the AIRs accept. These
//! helpers simulate such a prover by swapping the executor of individual ops in
//! an already-BUILT circuit. The verifier-side data (AIRs, preprocessed
//! columns, `ProverData`) is computed at build time and is untouched, so a test
//! that forges a witness this way and then runs the normal
//! `prove_all_tables` + `verify_all_tables` measures exactly whether the
//! constraint system rejects that witness.
//!
//! * [`forge_permute_outputs`] — make the `which`-th Permute op emit arbitrary
//!   output values (not necessarily a permutation of that op's own inputs).
//!   The PermuteAir only balances the `PermuteBus` over ALL permute rows of the
//!   circuit, so this is what a prover can do when two ops share an encoding.
//! * [`forge_decomposition`] — make `decompose_ext_to_base_coeffs(x)` return
//!   caller-chosen coefficients while the packed `x` keeps its real value.
//! * [`forge_hint`] — make any single-input hint (bit or byte decomposition)
//!   write caller-chosen outputs, e.g. the bits of `x + p` or an
//!   extension-valued "byte".

use std::any::Any;

use p3_circuit::ops::permute::{PermuteCircuitRow, PermuteExecutionState};
use p3_circuit::ops::recompose::{RecomposeCircuitRow, RecomposeExecutionState};
use p3_circuit::ops::{ExecutionContext, HintExecutor, NonPrimitiveExecutor, PreprocessedWriter};
use p3_circuit::{Circuit, CircuitError, NpoTypeId, Op, WitnessId};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};

use crate::config::{Challenge, Val};

/// Embed a base-field value as an extension element `(v, 0, 0, 0)`.
fn embed(v: Val) -> Challenge {
    Challenge::from_basis_coefficients_slice(&[v, Val::ZERO, Val::ZERO, Val::ZERO])
        .expect("4 coeffs")
}

/// A Permute executor that writes caller-chosen output values. Generic over
/// the circuit field so it serves both the BabyBear (D=4) and the Goldilocks
/// (D=2) circuits.
#[derive(Debug)]
struct ForgedPermute<F: Field> {
    inner: Box<dyn NonPrimitiveExecutor<F>>,
    outputs: Vec<F>,
}

impl<F: Field + 'static> NonPrimitiveExecutor<F> for ForgedPermute<F> {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        let input_wids = &inputs[0];
        let output_wids = &outputs[0];
        assert_eq!(
            output_wids.len(),
            self.outputs.len(),
            "forged permute output length"
        );
        let mut input_values = Vec::with_capacity(input_wids.len());
        for &w in input_wids {
            input_values.push(ctx.get_witness(w)?);
        }
        for (i, &w) in output_wids.iter().enumerate() {
            ctx.set_witness(w, self.outputs[i])?;
        }
        let state = ctx.get_op_state_mut::<PermuteExecutionState<F>>(&NpoTypeId::permute());
        state.rows.push(PermuteCircuitRow {
            input_wids: input_wids.clone(),
            output_wids: output_wids.clone(),
            input_values,
            output_values: self.outputs.clone(),
        });
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        self.inner.op_type()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Accept (and ignore) a new σ hint, so provers that re-install their
    /// sigmas via `update_permute_witnesses` keep the forged outputs.
    fn set_params(
        &mut self,
        _params: &p3_circuit::builder::NonPrimitiveOpParams<F>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn PreprocessedWriter<F>,
    ) -> Result<(), CircuitError> {
        self.inner.preprocess(inputs, outputs, preprocessed)
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        self.inner.num_exposed_outputs()
    }

    fn arbitrated_coeff_input_group(&self) -> Option<usize> {
        self.inner.arbitrated_coeff_input_group()
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(ForgedPermute {
            inner: self.inner.boxed(),
            outputs: self.outputs.clone(),
        })
    }
}

/// Replace the executor of the `which`-th Permute op (in builder order) so it
/// emits exactly `outputs`. Call AFTER `update_permute_witnesses` (the forged
/// executor has no replaceable σ). Works for any circuit field (BabyBear D=4,
/// Goldilocks D=2).
pub(crate) fn forge_permute_outputs<F: Field + 'static>(
    circuit: &mut Circuit<F>,
    which: usize,
    outputs: Vec<F>,
) {
    let mut k = 0usize;
    for op in circuit.ops.iter_mut() {
        if let Op::NonPrimitiveOpWithExecutor { executor, .. } = op
            && *executor.op_type() == NpoTypeId::permute()
        {
            if k == which {
                let inner = executor.boxed();
                *executor = Box::new(ForgedPermute { inner, outputs });
                return;
            }
            k += 1;
        }
    }
    panic!("forge_permute_outputs: circuit has only {k} permute ops (asked for #{which})");
}

/// A hint that writes fixed output values (decomposition coefficients, bits,
/// bytes). Generic over the circuit field (BabyBear D=4, Goldilocks D=2).
#[derive(Debug, Clone)]
struct FixedHint<F> {
    values: Vec<F>,
}

impl<F: Field> HintExecutor<F> for FixedHint<F> {
    fn execute(
        &self,
        _inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<F>],
    ) -> Result<(), CircuitError> {
        for (i, &w) in outputs.iter().enumerate() {
            let slot = &mut witness[w.0 as usize];
            if let Some(existing) = slot.as_ref()
                && *existing != self.values[i]
            {
                return Err(CircuitError::WitnessConflict {
                    witness_id: w,
                    existing: format!("{existing:?}"),
                    new: format!("{:?}", self.values[i]),
                    expr_ids: vec![],
                });
            }
            *slot = Some(self.values[i]);
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn HintExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Replace the executor of the unique `Op::Hint` that reads exactly `[input]`
/// and has `values.len()` outputs, so it writes `values` instead (refusing,
/// like every forged hint here, to overwrite a differently-valued slot, so a
/// forgery never silently wins a runner-side conflict). Hints have no AIR:
/// only the constraints downstream of the outputs can reject the forgery.
/// Returns the hint's output witness ids. Panics unless exactly one hint
/// matches.
pub(crate) fn forge_hint<F: Field>(
    circuit: &mut Circuit<F>,
    input: WitnessId,
    values: Vec<F>,
) -> Vec<WitnessId> {
    let n_out = values.len();
    let hits: Vec<usize> = circuit
        .ops
        .iter()
        .enumerate()
        .filter(|(_, op)| {
            matches!(op, Op::Hint { inputs, outputs, .. }
                if inputs.as_slice() == [input] && outputs.len() == n_out)
        })
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "forge_hint: expected exactly one hint reading {input:?} with {n_out} outputs"
    );
    let Op::Hint {
        outputs, executor, ..
    } = &mut circuit.ops[hits[0]]
    else {
        unreachable!()
    };
    *executor = Box::new(FixedHint { values });
    outputs.clone()
}

/// Witness id of an expression in a built circuit.
pub(crate) fn wid_of<F>(circuit: &Circuit<F>, e: p3_circuit::ExprId) -> WitnessId {
    *circuit
        .expr_to_widx
        .get(&e)
        .unwrap_or_else(|| panic!("expr {e:?} has no witness id"))
}

/// A recompose executor that does NOT recompute its output from its coefficient
/// inputs: it copies the current value of `source` (the packed witness) to the
/// output and records the recompose-table row as that value's true
/// coefficients. That is all the plain `recompose` row exposes on the
/// WitnessChecks bus; a `recompose/coeff` row also publishes each `v_i` against
/// its coefficient witness, which is what rejects the forgery.
#[derive(Debug)]
struct PassThroughRecompose {
    inner: Box<dyn NonPrimitiveExecutor<Challenge>>,
    source: WitnessId,
}

impl NonPrimitiveExecutor<Challenge> for PassThroughRecompose {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, Challenge>,
    ) -> Result<(), CircuitError> {
        let v = ctx.get_witness(self.source)?;
        let out = outputs[0][0];
        ctx.set_witness(out, v)?;
        let values: Vec<Challenge> = v
            .as_basis_coefficients_slice()
            .iter()
            .map(|&c| embed(c))
            .collect();
        let op_type = self.inner.op_type().clone();
        let state = ctx.get_op_state_mut::<RecomposeExecutionState<Challenge>>(&op_type);
        state.rows.push(RecomposeCircuitRow {
            input_wids: inputs[0].clone(),
            output_wid: out,
            values,
        });
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
        Box::new(PassThroughRecompose {
            inner: self.inner.boxed(),
            source: self.source,
        })
    }
}

/// Make `decompose_ext_to_base_coeffs(packed)` yield `coeffs` (base values)
/// while the packed witness keeps whatever value the private input gives it.
/// Swaps the decomposition hint (→ fixed coefficients) and the recompose op
/// that re-links the coefficients to `packed` (→ pass-through, no recompute).
/// Panics if the circuit has no such decomposition of `packed`.
pub(crate) fn forge_decomposition(
    circuit: &mut Circuit<Challenge>,
    packed: WitnessId,
    coeffs: [Val; 4],
) {
    let values: Vec<Challenge> = coeffs.iter().map(|&c| embed(c)).collect();
    let mut coeff_wids: Option<Vec<WitnessId>> = None;
    for op in circuit.ops.iter_mut() {
        if let Op::Hint {
            inputs,
            outputs,
            executor,
        } = op
            && inputs.len() == 1
            && inputs[0] == packed
            && outputs.len() == 4
        {
            *executor = Box::new(FixedHint {
                values: values.clone(),
            });
            coeff_wids = Some(outputs.clone());
            break;
        }
    }
    let coeff_wids = coeff_wids.expect("forge_decomposition: no decomposition hint for this witness");
    let mut found = false;
    for op in circuit.ops.iter_mut() {
        if let Op::NonPrimitiveOpWithExecutor {
            inputs, executor, ..
        } = op
            && (*executor.op_type() == NpoTypeId::recompose()
                || *executor.op_type() == NpoTypeId::recompose_with_coeff_lookups())
            && inputs.len() == 1
            && inputs[0] == coeff_wids
        {
            let inner = executor.boxed();
            *executor = Box::new(PassThroughRecompose {
                inner,
                source: packed,
            });
            found = true;
            break;
        }
    }
    assert!(found, "forge_decomposition: no recompose op re-linking the coefficients");
}
