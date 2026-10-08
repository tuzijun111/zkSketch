//! **Process-level distributed emulation** of the three composition modes —
//! the rigorous execution engine behind `EXP_COMPOSE_EXEC=procs`.
//!
//! `stream_compose::measure_compose` proves everything in ONE process and
//! reports the M-machine leaf split as a *work-partition makespan projection*.
//! That is honest but weak: the machines never exist, nothing is pinned, and
//! no byte ever crosses a machine boundary. This module replaces the
//! projection with a real execution one can defend in the paper:
//!
//! - **One OS process per machine.** The coordinator (the `exp_compose`
//!   example itself) re-executes its own binary in a `worker` role per
//!   machine, so "machine" = process: disjoint address spaces, no shared
//!   heap, no accidental data sharing. (The chain uses a single such worker.)
//! - **NUMA-aware physical-core pinning.** Each machine is pinned (via
//!   `numactl --physcpubind` when available, falling back to `taskset -c`) to a
//!   disjoint `cores`-wide block of physical cores and NUMA-membound to that
//!   block's node. Machines are spread round-robin across NUMA nodes
//!   (`machine_core_range`), so when the machine count does not exceed the node
//!   count each machine sits on its own node and DRAM controller — e.g. on a
//!   2-node EPYC, 2 machines × 32 cores land one per socket rather than both on
//!   node 0. Heavier counts pack an equal share onto each node. SMT siblings
//!   stay idle, so machines never contend for execution units or caches, and
//!   contend for DRAM bandwidth only when a node count forces node sharing.
//!   Containers add nothing on top of this: Docker's CPU isolation is the
//!   same cpuset/cgroup mechanism.
//! - **All inter-machine data crosses a real serialized channel.** States,
//!   batches, leaf proofs, and subtree roots travel as length-framed
//!   postcard bytes over sockets — the exact bytes a network deployment
//!   would ship. The coordinator records per-phase message counts, byte
//!   totals, and measured (loopback) transfer time, and additionally models
//!   the critical-path transfer time at a configurable link bandwidth
//!   (`EXP_NET_MBPS`, default 200 Mb/s) and per-message RTT
//!   (`EXP_NET_RTT_MS`), so a target-network number is derivable from the
//!   measured byte counts rather than trusted loopback speed.
//!
//! ## Scheduling per mode (who composes, and where)
//!
//! - `per_batch` — no composition. Each machine proves its contiguous slice
//!   of leaves and streams every leaf proof to the coordinator (the
//!   auditor's proof store): the Θ(t) artifact and Θ(t) transfer are real.
//! - `chain` — the **recursive linear chain is inherently sequential**
//!   (paper §Recursive-Linear-Proof-Chain: each fold verifies the previous
//!   prefix proof in-circuit and applies the new batch, "the batch is folded
//!   in directly, never proved standalone first"; "its proving schedule is
//!   inherently sequential"). It therefore runs on **one machine**, folding
//!   `Π⁽ᵗ⁾ = merge(Π⁽ᵗ⁻¹⁾, π_t)` left-leaning in place. The `machines` knob
//!   does NOT apply — giving the chain parallel leaf-gen would smuggle in the
//!   forest's whole contribution. No proof crosses a machine boundary (the
//!   fold is in-process); only the single O(1) root reaches the auditor, so
//!   cross-machine composition traffic is ~zero. (Our fold uses the same
//!   leaf+composition-atom as the forest, run linearly, so the chain↔forest
//!   comparison isolates the *schedule* as the single variable; the paper's
//!   deployed fused fold is cheaper per step but equally sequential, so it
//!   only strengthens the forest's parallel-speedup conclusion.)
//! - `forest` — **symmetric, in-place**: the leaf machines are the
//!   composers. Each machine folds its own slice Bentley–Saxe-style *as its
//!   leaves complete* (the paper's composition cascade — zero
//!   communication), then `⌈log₂ M⌉` cross-machine reduction rounds combine
//!   the M slice roots: machine k+2ʳ ships its root (one serialized proof)
//!   to machine k, which merges. Total cross-machine traffic is M−1 proofs,
//!   bought to unlock the M-way parallelism the sequential chain lacks.
//!
//! **Auditor (B6(b)).** Leaves carry the Interval statement by default (each
//! worker proves its slice's leaves at their GLOBAL batch indices, shipped as
//! `ToWorker::Task::first_index`); the coordinator's auditor pins the derived
//! root VK, verifies the root, and checks its statement against the public
//! batch log (`Com(S_0)`, `Com(S_T)`, `Com(B_1..B_T)` computed natively from
//! the batches, [`batch_commits`]) under `dist_tree_shape(mode, t, M)`.
//! Where the auditor receives LEAF proofs directly (per_batch, and the lone
//! leaf of a one-batch stream) it pins each one to the trusted leaf VK
//! (derived from a no-op leaf, [`derive_dist_leaf_vk`]), STARK-verifies it with
//! a verifier configured from public parameters, and checks its statement
//! against its log entry and the boundary chain ([`audit_leaf_bytes`]); the
//! reported verify time is that audit, not the workers' self-verify (except
//! under the legacy `EXP_ROOT_VK=self` opt-in).
//!
//! Cross-machine merging is possible because a merge consumes only the
//! children's `BatchStarkProof`s (see
//! [`prove_hiding_merge_proofs`](crate::recursion::recursive::expose_forest::prove_hiding_merge_proofs));
//! proofs are wire-portable and fold-of-fold outputs are uniform.
//!
//! ## The witness pass
//!
//! The coordinator runs the ordinary (plaintext) sketch update over the whole
//! stream once — the paper's "off-circuit plaintext witness pass" — records
//! the state at each machine's slice start, and ships machine `i` only its
//! start state + its own batches. Machines re-derive their interior per-batch
//! states by replaying their own slice (which leaf witness generation needs
//! anyway). The pass is timed (`witness_pass_ms`) and the shipped state bytes
//! are counted (`scatter_state_bytes`), substantiating the paper's claim that
//! the sequential dependency is cheap and O(state) per machine, not O(N).
//!
//! Message routing is a star through the coordinator (workers do not dial
//! each other); a forest round-root therefore traverses two loopback hops
//! but is **counted once** as cross-machine traffic, and the network models
//! use the direct-link topology.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, OnceLock};
use std::time::Instant;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::Val;
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::{
    check_leaves_against_log, leaf_vk, prove_hiding_merge, prove_hiding_merge_proofs, ForestCascade,
    read_exposed_boundary_proof, root_vk_deriver, verify_bound_stark_proof_against_log,
    verify_bound_stark_proof_pinned, verify_leaves_against_log, vk_pin_values,
};
use crate::recursion::recursive::root_vk::{ForestShape, RootVk};
use crate::recursion::recursive::statement::{
    BatchLog, Expose, composition_expose, warn_boundary_layout,
};
use crate::recursion::recursive::timing;
use p3_circuit_prover::BatchStarkProof;
use p3_recursion::RecursionOutput;

use crate::sketch::bloom_omc::{
    bloom_batch_commit, bloom_empty, bloom_insert, build_bloom_omc_leaf_expose, commit_bloom,
    BloomOmcLeafCircuit, BloomOmcParams,
};
use crate::sketch::countmin::{CountMinParams, CountMinState};
use crate::sketch::countmin_omc::{
    build_countmin_omc_leaf_expose, countmin_omc_advance, countmin_omc_batch_commit,
    CmOmcLeafCircuit, CmOmcParams,
};
use crate::sketch::gk_bandmerge::{
    apply_batch2, build_gkb2_leaf_expose, commit_gk2_batch, commit_gk2_state, Gk2State, Gk2Tuple,
    Gkb2LeafCircuit, GkbParams,
};
use crate::sketch::hll_omc::{
    build_hll_omc_leaf_expose, commit_hll_omc, hll_omc_advance, hll_omc_batch_commit,
    hll_omc_empty, HllOmcLeafCircuit, HllOmcParams,
};
use crate::sketch::ss_final_full::{
    apply_batch_ss_full, build_ss_full_leaf_expose, commit_ss_batch, commit_ss_state,
    SsFullLeafCircuit, SsFullParams, SsFullRow, SsFullState,
};

// ── Goldilocks (`_gl`) leaf + config imports, aliased so they never clash with
// the BabyBear types above. These back the parallel `FamStateGl` /
// `FamLeafCircuitGl` / `worker_main_gl` / `measure_compose_dist_gl` path.
use crate::recursion::recursive::config_gl::ConfigWithFriParamsGl;
use crate::sketch::gk_bandmerge_gl::{
    apply_batch2 as apply_batch2_gl, build_gkb2_leaf_expose as build_gkb2_leaf_expose_gl,
    commit_gk2_batch as commit_gk2_batch_gl, commit_gk2_state as commit_gk2_state_gl,
    Gk2State as Gk2StateGl, Gk2Tuple as Gk2TupleGl, Gkb2LeafCircuit as Gkb2LeafCircuitGl,
    GkbParams as GkbParamsGl,
};
use crate::sketch::countmin_omc_gl::{
    CmOmcLeafCircuit as CmOmcLeafCircuitGl, CmOmcParams as CmOmcParamsGl,
    apply_update_prf as apply_update_prf_gl,
    build_countmin_omc_leaf_expose as build_countmin_omc_leaf_expose_gl, cm_gl_empty,
    commit_batch as commit_batch_gl, commit_countmin as commit_countmin_gl,
};
use crate::sketch::hll_omc_gl::{
    build_hll_omc_leaf_expose as build_hll_omc_leaf_expose_gl, commit_hll_omc as commit_hll_omc_gl,
    hll_omc_advance as hll_omc_advance_gl, hll_omc_batch_commit as hll_omc_batch_commit_gl,
    hll_omc_empty as hll_omc_empty_gl, HllOmcLeafCircuit as HllOmcLeafCircuitGl,
    HllOmcParams as HllOmcParamsGl,
};
use crate::sketch::ss_final_full_gl::{
    apply_batch_ss_full as apply_batch_ss_full_gl,
    build_ss_full_leaf_expose as build_ss_full_leaf_expose_gl,
    commit_ss_batch as commit_ss_batch_gl, commit_ss_state as commit_ss_state_gl,
    SsFullLeafCircuit as SsFullLeafCircuitGl, SsFullParams as SsFullParamsGl,
    SsFullRow as SsFullRowGl, SsFullState as SsFullStateGl, SsFullUpdate as SsFullUpdateGl,
};

use super::families::cm_empty;
use super::stream_compose::{
    bloom_keys_of, cm_updates_of, gk_vals_of, hll_keys_of, measure_queries_dist, ss_updates_of,
    ContextStore, QueryAudit, QueryKeyMode, StreamFamily, StreamMode, StreamShape, PAD_KEY,
};

use crate::commitment::countmin::commit_countmin;

type Proof = BatchStarkProof<ConfigWithFriParams>;
/// Goldilocks analog of [`Proof`]: gl leaves/merges emit proofs over
/// [`ConfigWithFriParamsGl`], a distinct config type, so the gl path serializes
/// and deserializes `ProofGl` bytes.
type ProofGl = BatchStarkProof<ConfigWithFriParamsGl>;

// ─── Wire framing ────────────────────────────────────────────────────────────

/// Write one length-framed postcard message; returns the payload byte count.
fn send_msg<T: Serialize>(s: &mut UnixStream, v: &T) -> std::io::Result<u64> {
    let bytes = postcard::to_allocvec(v)
        .map_err(|e| std::io::Error::other(format!("postcard serialize: {e}")))?;
    s.write_all(&(bytes.len() as u32).to_le_bytes())?;
    s.write_all(&bytes)?;
    s.flush()?;
    Ok(bytes.len() as u64)
}

/// Read one length-framed postcard message; returns `(value, payload bytes)`.
fn recv_msg<T: DeserializeOwned>(s: &mut UnixStream) -> std::io::Result<(T, u64)> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    let v = postcard::from_bytes(&buf)
        .map_err(|e| std::io::Error::other(format!("postcard deserialize: {e}")))?;
    Ok((v, n as u64))
}

// ─── Sketch-state wire codec + plaintext ops ─────────────────────────────────

/// Family-agnostic plaintext state, serializable for the scatter phase. The
/// encoding is plain integers (no field elements cross the wire), so the byte
/// counts reported as `scatter_state_bytes` are the honest deployment cost of
/// shipping a slice-start state to a machine.
#[derive(Clone, Serialize, Deserialize)]
pub enum WireState {
    Cm { d: u32, w: u32, counters: Vec<u32> },
    Hll { b: u32, regs: Vec<u64> },
    /// `(key, count, active)` per row.
    Ss { capacity: u32, rows: Vec<(u64, u32, u32)> },
    /// `(e, g, g_o, delta, delta_o, t, active)` per tuple.
    Gk { capacity: u32, s: u64, n: u64, tuples: Vec<(u32, u64, u64, u64, u64, u64, u32)> },
    /// The `M = k·2^log_w` filter bits, packed 8 per byte (LSB first): the
    /// state is bits, so this is what a deployment ships.
    Bloom { k: u32, log_w: u32, cells: u32, packed: Vec<u8> },
}

/// Local plaintext state a machine advances and proves against. `advance`
/// mirrors `stream_compose::prove_leaves` exactly (incl. the per-family key
/// masks) — a divergence would break the in-circuit boundary bind.
enum FamState {
    Cm(CountMinState),
    Hll(Vec<u64>),
    Ss(SsFullState),
    Gk(Gk2State),
    /// The filter's parameters (shape + batch slots) and its `M` bits.
    Bloom(BloomOmcParams, Vec<u8>),
}

// The per-family record mappings (key masks + PAD_KEY no-op handling) are the
// CANONICAL `stream_compose::{cm_updates_of, hll_keys_of, ss_updates_of,
// gk_vals_of}` — shared with the sim engine and the query replay so the
// in-circuit boundary bind can never diverge between engines.

impl FamState {
    fn empty(family: StreamFamily, shape: &StreamShape, m: usize) -> Self {
        match family {
            StreamFamily::CmOmc => Self::Cm(cm_empty(shape.d, shape.w)),
            StreamFamily::HllOmc => Self::Hll(hll_omc_empty(shape.b)),
            StreamFamily::SsCertified => {
                Self::Ss(SsFullState::empty(SsFullParams { capacity: shape.capacity, batch: m }))
            }
            StreamFamily::GkBandmerge2 => Self::Gk(Gk2State::empty(GkbParams {
                capacity: shape.capacity,
                batch: m,
                s: shape.gk_s,
            })),
            StreamFamily::BloomOmc => {
                let p = shape.bloom_params(m);
                Self::Bloom(p, bloom_empty(&p))
            }
            StreamFamily::SsCertifiedGl
            | StreamFamily::GkBandmerge2Gl
            | StreamFamily::HllOmcGl
            | StreamFamily::CmOmcGl => {
                unreachable!("gl families use FamStateGl/FamLeafCircuitGl")
            }
        }
    }

    /// Apply one batch in plaintext (the witness-pass step).
    fn advance(&mut self, shape: &StreamShape, batch: &[u32]) {
        match self {
            // The omc leaf's native update under the process default binding
            // (the one `FamLeafCircuit::build` uses).
            Self::Cm(state) => countmin_omc_advance(state, &cm_updates_of(batch)),
            Self::Hll(regs) => hll_omc_advance(regs, &hll_keys_of(batch), 1usize << shape.b),
            Self::Ss(state) => *state = apply_batch_ss_full(state, &ss_updates_of(batch)).0,
            Self::Gk(state) => *state = apply_batch2(state, &gk_vals_of(batch)),
            Self::Bloom(p, bits) => bloom_insert(bits, p, &bloom_keys_of(batch)),
        }
    }

    /// Native state commitment (the auditor's anchor / final reference).
    fn commit(&self, shape: &StreamShape) -> [Val; 8] {
        match self {
            Self::Cm(state) => commit_countmin(state).0,
            Self::Hll(regs) => commit_hll_omc(regs, shape.b),
            Self::Ss(state) => commit_ss_state(state).0,
            Self::Gk(state) => commit_gk2_state(state).0,
            Self::Bloom(_, bits) => commit_bloom(bits),
        }
    }
}

/// `Com(B_t)` of every batch of a BabyBear stream, computed natively from the
/// raw batch records exactly as each family's leaf commits its batch
/// in-circuit — what the public log publishes. GK's batch commitment also
/// binds `n_prev` (the arrival count before the batch), which the log
/// follower derives from the batch lengths.
pub(crate) fn batch_commits(
    family: StreamFamily,
    m: usize,
    batches: &[Vec<u32>],
) -> Vec<[Val; 8]> {
    let mut n_prev = 0u64;
    batches
        .iter()
        .map(|b| match family {
            StreamFamily::CmOmc => countmin_omc_batch_commit(&cm_updates_of(b)),
            StreamFamily::HllOmc => hll_omc_batch_commit(&hll_keys_of(b)),
            StreamFamily::SsCertified => commit_ss_batch(&ss_updates_of(b)).0,
            StreamFamily::GkBandmerge2 => {
                let vals = gk_vals_of(b);
                let c = commit_gk2_batch(&vals, m, n_prev).0;
                n_prev += vals.len() as u64;
                c
            }
            // `m` record slots: the real keys, then canonical dummies.
            StreamFamily::BloomOmc => bloom_batch_commit(m, &bloom_keys_of(b)),
            _ => unreachable!("gl families use batch_commits_gl"),
        })
        .collect()
}

/// The public batch log of a BabyBear stream: `Com(S_0)` and `Com(S_T)` from
/// the plaintext witness pass plus [`batch_commits`].
pub(crate) fn stream_batch_log(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
    batches: &[Vec<u32>],
) -> BatchLog<Val> {
    let mut st = FamState::empty(family, shape, m);
    let init = st.commit(shape);
    for b in batches {
        st.advance(shape, b);
    }
    let commits = batch_commits(family, m, batches);
    crate::recursion::recursive::expose_forest::batch_log(&init, &st.commit(shape), &commits)
}

/// Goldilocks analog of [`batch_commits`].
pub(crate) fn batch_commits_gl(
    family: StreamFamily,
    m: usize,
    batches: &[Vec<u32>],
) -> Vec<[crate::config_gl::Val; 4]> {
    let mut n_prev = 0u64;
    batches
        .iter()
        .map(|b| match family {
            StreamFamily::CmOmcGl => commit_batch_gl(&cm_updates_of(b)).0,
            StreamFamily::HllOmcGl => hll_omc_batch_commit_gl(&hll_keys_of(b)),
            StreamFamily::SsCertifiedGl => {
                let ups: Vec<SsFullUpdateGl> = ss_updates_of(b)
                    .iter()
                    .map(|u| SsFullUpdateGl { key: u.key, value: u.value, active: u.active })
                    .collect();
                commit_ss_batch_gl(&ups).0
            }
            StreamFamily::GkBandmerge2Gl => {
                let vals = gk_vals_of(b);
                let c = commit_gk2_batch_gl(&vals, m, n_prev).0;
                n_prev += vals.len() as u64;
                c
            }
            _ => unreachable!("BabyBear families use batch_commits"),
        })
        .collect()
}

impl FamState {

    /// Prove one transition leaf — batch `t` (1-based, the global stream
    /// index; part of the Interval statement) — from the current state over
    /// `batch`, on the worker's prebuilt leaf circuit. Returns the
    /// statement-exposing output plus the prover's self-timings.
    fn prove_leaf(
        &self,
        leaf: &mut FamLeafCircuit,
        t: u64,
        batch: &[u32],
    ) -> (RecursionOutput<ConfigWithFriParams>, f64, f64) {
        let output = match (leaf, self) {
            (FamLeafCircuit::Cm(l), Self::Cm(state)) => {
                l.prove_epoch_at(t, state.clone(), cm_updates_of(batch)).output
            }
            (FamLeafCircuit::Hll(l), Self::Hll(regs)) => {
                l.prove_epoch_at(t, regs.clone(), hll_keys_of(batch)).output
            }
            (FamLeafCircuit::Ss(l), Self::Ss(state)) => {
                l.prove_epoch_at(t, state.clone(), ss_updates_of(batch)).output
            }
            (FamLeafCircuit::Gk(l), Self::Gk(state)) => {
                l.prove_epoch_at(t, state.clone(), gk_vals_of(batch)).output
            }
            (FamLeafCircuit::Bloom(l), Self::Bloom(_, bits)) => {
                l.prove_epoch_at(t, bits, &bloom_keys_of(batch)).output
            }
            _ => panic!("FamLeafCircuit/FamState family mismatch"),
        };
        let tm = timing::take();
        (
            output,
            (tm.witness + tm.prove).as_secs_f64() * 1000.0,
            tm.verify.as_secs_f64() * 1000.0,
        )
    }

    fn encode(&self) -> WireState {
        match self {
            Self::Cm(s) => WireState::Cm {
                d: s.params.d as u32,
                w: s.params.w as u32,
                counters: s.counters.iter().flatten().copied().collect(),
            },
            Self::Hll(regs) => WireState::Hll { b: 0, regs: regs.clone() }, // b re-derived from shape
            Self::Ss(s) => WireState::Ss {
                capacity: s.params.capacity as u32,
                rows: s.rows.iter().map(|r| (r.key, r.count, r.active)).collect(),
            },
            Self::Gk(s) => WireState::Gk {
                capacity: s.params.capacity as u32,
                s: s.params.s,
                n: s.n,
                tuples: s
                    .tuples
                    .iter()
                    .map(|t| (t.e, t.g, t.g_o, t.delta, t.delta_o, t.t, t.active))
                    .collect(),
            },
            Self::Bloom(p, bits) => {
                let mut packed = vec![0u8; bits.len().div_ceil(8)];
                for (i, &bit) in bits.iter().enumerate() {
                    packed[i / 8] |= (bit & 1) << (i % 8);
                }
                WireState::Bloom {
                    k: p.k as u32,
                    log_w: p.log_w as u32,
                    cells: bits.len() as u32,
                    packed,
                }
            }
        }
    }

    /// Decode a wire state. `m` re-supplies the batch param (public, fixed
    /// per deployment — a real system would not ship it per message).
    fn decode(wire: &WireState, m: usize) -> Self {
        match wire {
            WireState::Cm { d, w, counters } => {
                let (d, w) = (*d as usize, *w as usize);
                assert_eq!(counters.len(), d * w, "cm wire state size");
                Self::Cm(CountMinState {
                    counters: counters.chunks(w).map(|c| c.to_vec()).collect(),
                    params: CountMinParams { d, w },
                })
            }
            WireState::Hll { regs, .. } => Self::Hll(regs.clone()),
            WireState::Ss { capacity, rows } => Self::Ss(SsFullState {
                rows: rows
                    .iter()
                    .map(|&(key, count, active)| SsFullRow { key, count, active })
                    .collect(),
                params: SsFullParams { capacity: *capacity as usize, batch: m },
            }),
            WireState::Gk { capacity, s, n, tuples } => Self::Gk(Gk2State {
                tuples: tuples
                    .iter()
                    .map(|&(e, g, g_o, delta, delta_o, t, active)| Gk2Tuple {
                        e,
                        g,
                        g_o,
                        delta,
                        delta_o,
                        t,
                        active,
                    })
                    .collect(),
                params: GkbParams { capacity: *capacity as usize, batch: m, s: *s },
                n: *n,
            }),
            WireState::Bloom { k, log_w, cells, packed } => {
                let p = BloomOmcParams { k: *k as usize, log_w: *log_w as usize, batch: m };
                p.validate();
                let cells = *cells as usize;
                assert_eq!(cells, p.m_cells(), "bloom wire state size");
                assert_eq!(packed.len(), cells.div_ceil(8), "bloom wire state bytes");
                let bits: Vec<u8> = (0..cells).map(|i| (packed[i / 8] >> (i % 8)) & 1).collect();
                Self::Bloom(p, bits)
            }
        }
    }
}

/// The reusable per-family leaf circuit — built ONCE per worker and reused
/// every epoch. The graph build + AIR/`ProverData` prep dominate per-leaf wall
/// time (they roughly equal witness+prove at the deployed shapes), so hoisting
/// them out of the epoch loop nearly halves leafgen wall; each epoch only
/// swaps the Permute ops' sigma hints (`Circuit::update_permute_witnesses`).
enum FamLeafCircuit {
    Cm(CmOmcLeafCircuit),
    Hll(HllOmcLeafCircuit),
    Ss(SsFullLeafCircuit),
    Gk(Gkb2LeafCircuit),
    Bloom(BloomOmcLeafCircuit),
}

impl FamLeafCircuit {
    /// Build the family's composable leaf with the harness composition
    /// statement ([`composition_expose`]: Interval by default; Boundary for
    /// the explicit legacy opt-ins).
    fn build(family: StreamFamily, shape: &StreamShape, m: usize) -> Self {
        let expose = composition_expose();
        let binding = crate::sketch::bind::default_binding();
        match family {
            StreamFamily::CmOmc => Self::Cm(build_countmin_omc_leaf_expose(
                CmOmcParams { d: shape.d, w: shape.w, batch: m },
                expose,
                binding,
            )),
            StreamFamily::HllOmc => Self::Hll(build_hll_omc_leaf_expose(
                HllOmcParams { b: shape.b, batch: m },
                expose,
                binding,
            )),
            StreamFamily::SsCertified => Self::Ss(build_ss_full_leaf_expose(
                SsFullParams { capacity: shape.capacity, batch: m },
                expose,
            )),
            StreamFamily::GkBandmerge2 => Self::Gk(build_gkb2_leaf_expose(
                GkbParams { capacity: shape.capacity, batch: m, s: shape.gk_s },
                expose,
            )),
            // One (bound) construction: no binding switch.
            StreamFamily::BloomOmc => {
                Self::Bloom(build_bloom_omc_leaf_expose(shape.bloom_params(m), expose))
            }
            StreamFamily::SsCertifiedGl
            | StreamFamily::GkBandmerge2Gl
            | StreamFamily::HllOmcGl
            | StreamFamily::CmOmcGl => {
                unreachable!("gl families use FamStateGl/FamLeafCircuitGl")
            }
        }
    }
}

// ─── Goldilocks (`_gl`) parallel state/leaf path ─────────────────────────────

/// Goldilocks analog of [`FamState`] — `_gl` families ONLY (all four:
/// CM/SS/GK/HLL). Mirrors [`FamState`] method-for-method, but over the
/// Goldilocks leaf types whose leaves emit
/// `RecursionOutput<ConfigWithFriParamsGl>` (a different config than the
/// BabyBear path). The plaintext record mappings (`cm_updates_of`,
/// `ss_updates_of`, `gk_vals_of`, `hll_keys_of`) are the SHARED canonical
/// helpers, so the in-circuit boundary bind can never diverge from the
/// BabyBear engine. (CM and HLL route with the GOLDILOCKS hash natively —
/// distinct sketch instances from their BabyBear namesakes.)
enum FamStateGl {
    CmGl(CountMinState),
    SsGl(SsFullStateGl),
    GkGl(Gk2StateGl),
    HllGl(Vec<u64>),
}

impl FamStateGl {
    fn empty(family: StreamFamily, shape: &StreamShape, m: usize) -> Self {
        match family {
            StreamFamily::SsCertifiedGl => Self::SsGl(SsFullStateGl::empty(SsFullParamsGl {
                capacity: shape.capacity,
                batch: m,
            })),
            StreamFamily::GkBandmerge2Gl => Self::GkGl(Gk2StateGl::empty(GkbParamsGl {
                capacity: shape.capacity,
                batch: m,
                s: shape.gk_s,
            })),
            StreamFamily::HllOmcGl => Self::HllGl(hll_omc_empty_gl(shape.b)),
            StreamFamily::CmOmcGl => Self::CmGl(cm_gl_empty(shape.d, shape.w)),
            _ => unreachable!("FamStateGl only for gl families"),
        }
    }

    /// Apply one batch in plaintext (the witness-pass step).
    fn advance(&mut self, shape: &StreamShape, batch: &[u32]) {
        match self {
            // NOTE: routes with the GOLDILOCKS PRF — a distinct Count-Min
            // instance from the BabyBear path (statistically equivalent).
            Self::CmGl(state) => {
                for u in &cm_updates_of(batch) {
                    apply_update_prf_gl(state, u);
                }
            }
            Self::SsGl(state) => {
                // Convert the SHARED (BabyBear-typed) SsFullUpdate records into the
                // gl update type — the field values are field-agnostic integers.
                let ups: Vec<SsFullUpdateGl> = ss_updates_of(batch)
                    .iter()
                    .map(|u| SsFullUpdateGl { key: u.key, value: u.value, active: u.active })
                    .collect();
                *state = apply_batch_ss_full_gl(state, &ups).0;
            }
            // `gk_vals_of` is field-agnostic (`Vec<u32>`) — no conversion.
            Self::GkGl(state) => *state = apply_batch2_gl(state, &gk_vals_of(batch)),
            // NOTE: routes with the GOLDILOCKS hash — a distinct HLL instance
            // from the BabyBear path (statistically equivalent).
            Self::HllGl(regs) => {
                hll_omc_advance_gl(regs, &hll_keys_of(batch), 1usize << shape.b)
            }
        }
    }

    /// Native state commitment (Goldilocks digest width 4).
    fn commit(&self, shape: &StreamShape) -> [crate::config_gl::Val; 4] {
        match self {
            Self::CmGl(state) => commit_countmin_gl(state).0,
            Self::SsGl(state) => commit_ss_state_gl(state).0,
            Self::GkGl(state) => commit_gk2_state_gl(state).0,
            Self::HllGl(regs) => commit_hll_omc_gl(regs, shape.b),
        }
    }

    /// Prove one transition leaf (batch `t`), mirroring
    /// [`FamState::prove_leaf`] exactly.
    fn prove_leaf(
        &self,
        leaf: &mut FamLeafCircuitGl,
        t: u64,
        batch: &[u32],
    ) -> (RecursionOutput<ConfigWithFriParamsGl>, f64, f64) {
        let output = match (leaf, self) {
            (FamLeafCircuitGl::CmGl(l), Self::CmGl(state)) => {
                l.prove_epoch_at(t, state.clone(), cm_updates_of(batch)).output
            }
            (FamLeafCircuitGl::SsGl(l), Self::SsGl(state)) => {
                let ups: Vec<SsFullUpdateGl> = ss_updates_of(batch)
                    .iter()
                    .map(|u| SsFullUpdateGl { key: u.key, value: u.value, active: u.active })
                    .collect();
                l.prove_epoch_at(t, state.clone(), ups).output
            }
            (FamLeafCircuitGl::GkGl(l), Self::GkGl(state)) => {
                l.prove_epoch_at(t, state.clone(), gk_vals_of(batch)).output
            }
            (FamLeafCircuitGl::HllGl(l), Self::HllGl(regs)) => {
                l.prove_epoch_at(t, regs.clone(), hll_keys_of(batch)).output
            }
            _ => panic!("FamLeafCircuitGl/FamStateGl family mismatch"),
        };
        let tm = timing::take();
        (
            output,
            (tm.witness + tm.prove).as_secs_f64() * 1000.0,
            tm.verify.as_secs_f64() * 1000.0,
        )
    }

    fn encode(&self) -> WireState {
        match self {
            Self::CmGl(s) => WireState::Cm {
                d: s.params.d as u32,
                w: s.params.w as u32,
                counters: s.counters.iter().flatten().copied().collect(),
            },
            Self::SsGl(s) => WireState::Ss {
                capacity: s.params.capacity as u32,
                rows: s.rows.iter().map(|r| (r.key, r.count, r.active)).collect(),
            },
            Self::GkGl(s) => WireState::Gk {
                capacity: s.params.capacity as u32,
                s: s.params.s,
                n: s.n,
                tuples: s
                    .tuples
                    .iter()
                    .map(|t| (t.e, t.g, t.g_o, t.delta, t.delta_o, t.t, t.active))
                    .collect(),
            },
            Self::HllGl(regs) => WireState::Hll { b: 0, regs: regs.clone() }, // b re-derived from shape
        }
    }

    fn decode(wire: &WireState, m: usize) -> Self {
        match wire {
            WireState::Ss { capacity, rows } => Self::SsGl(SsFullStateGl {
                rows: rows
                    .iter()
                    .map(|&(key, count, active)| SsFullRowGl { key, count, active })
                    .collect(),
                params: SsFullParamsGl { capacity: *capacity as usize, batch: m },
            }),
            WireState::Gk { capacity, s, n, tuples } => Self::GkGl(Gk2StateGl {
                tuples: tuples
                    .iter()
                    .map(|&(e, g, g_o, delta, delta_o, t, active)| Gk2TupleGl {
                        e,
                        g,
                        g_o,
                        delta,
                        delta_o,
                        t,
                        active,
                    })
                    .collect(),
                params: GkbParamsGl { capacity: *capacity as usize, batch: m, s: *s },
                n: *n,
            }),
            WireState::Hll { regs, .. } => Self::HllGl(regs.clone()),
            WireState::Cm { d, w, counters } => {
                let (d, w) = (*d as usize, *w as usize);
                assert_eq!(counters.len(), d * w, "cm wire state size");
                Self::CmGl(CountMinState {
                    counters: counters.chunks(w).map(|c| c.to_vec()).collect(),
                    params: CountMinParams { d, w },
                })
            }
            WireState::Bloom { .. } => {
                panic!("the Bloom filter has no Goldilocks leaf (BabyBear engine only)")
            }
        }
    }
}

/// Goldilocks analog of [`FamLeafCircuit`] — the reusable per-family gl leaf
/// circuit, built ONCE per gl worker and reused every epoch.
enum FamLeafCircuitGl {
    CmGl(CmOmcLeafCircuitGl),
    SsGl(SsFullLeafCircuitGl),
    GkGl(Gkb2LeafCircuitGl),
    HllGl(HllOmcLeafCircuitGl),
}

impl FamLeafCircuitGl {
    /// Goldilocks analog of [`FamLeafCircuit::build`] (harness composition
    /// statement, [`composition_expose`]).
    fn build(family: StreamFamily, shape: &StreamShape, m: usize) -> Self {
        let expose = composition_expose();
        let binding = crate::sketch::bind::default_binding();
        match family {
            StreamFamily::SsCertifiedGl => Self::SsGl(build_ss_full_leaf_expose_gl(
                SsFullParamsGl { capacity: shape.capacity, batch: m },
                expose,
            )),
            StreamFamily::GkBandmerge2Gl => Self::GkGl(build_gkb2_leaf_expose_gl(
                GkbParamsGl { capacity: shape.capacity, batch: m, s: shape.gk_s },
                expose,
            )),
            StreamFamily::HllOmcGl => Self::HllGl(build_hll_omc_leaf_expose_gl(
                HllOmcParamsGl { b: shape.b, batch: m },
                expose,
                binding,
            )),
            StreamFamily::CmOmcGl => Self::CmGl(build_countmin_omc_leaf_expose_gl(
                CmOmcParamsGl { d: shape.d, w: shape.w, batch: m },
                expose,
                binding,
            )),
            _ => unreachable!("FamLeafCircuitGl only for gl families"),
        }
    }
}

// ─── Protocol messages ───────────────────────────────────────────────────────

/// Wire copy of [`StreamShape`] (usize is platform-dependent; fix widths).
#[derive(Clone, Copy, Serialize, Deserialize)]
struct WireShape {
    d: u32,
    w: u32,
    b: u32,
    capacity: u32,
    gk_s: u64,
    bloom_k: u32,
    bloom_log_w: u32,
}

impl WireShape {
    fn from(s: &StreamShape) -> Self {
        Self {
            d: s.d as u32,
            w: s.w as u32,
            b: s.b as u32,
            capacity: s.capacity as u32,
            gk_s: s.gk_s,
            bloom_k: s.bloom_k as u32,
            bloom_log_w: s.bloom_log_w as u32,
        }
    }
    fn to_shape(self) -> StreamShape {
        StreamShape {
            d: self.d as usize,
            w: self.w as usize,
            b: self.b as usize,
            capacity: self.capacity as usize,
            gk_s: self.gk_s,
            bloom_k: self.bloom_k as usize,
            bloom_log_w: self.bloom_log_w as usize,
        }
    }
}

/// One interval proof of a query's prefix certificate, as a worker ships it:
/// the batches `[lo, hi]` it covers and, unless already shipped, its bytes.
#[derive(Serialize, Deserialize)]
struct WireInterval {
    lo: u64,
    hi: u64,
    proof: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
enum ToWorker {
    /// The machine's whole job: its slice of batches + its slice-start state.
    /// `family`/`mode` are `StreamFamily`/`StreamMode` label strings.
    Task {
        family: String,
        mode: String,
        shape: WireShape,
        m: u32,
        start: WireState,
        batches: Vec<Vec<u32>>,
        /// Global 1-based stream index of `batches[0]` (the leaves' Interval
        /// statement carries the global batch index).
        first_index: u64,
        /// Mixed workload with the prefix binding on: local 0-based leaf
        /// indices after which a query fires. After each, the worker ships
        /// the interval proofs live at that version (forest: its peaks, each
        /// shipped once; chain: the running fold) in `LeafDone::context`.
        checkpoints: Vec<u32>,
        /// Forest: ship the finalized slice root in `SliceDone::root` (a
        /// query in a later slice needs this slice certified).
        ship_root: bool,
    },
    /// Forest reduction round: merge this (right-adjacent) peer root into the
    /// local root. Reply: `Merged`.
    MergeWith { right_proof: Vec<u8> },
    /// Ship the local root. Reply: `Root`.
    FetchRoot,
    /// Report peak RSS and exit. Reply: `Done`.
    Exit,
}

#[derive(Serialize, Deserialize)]
enum FromWorker {
    Hello {
        id: u32,
    },
    /// One leaf finished (and, forest, its cascade merges ran). For
    /// per_batch/chain the serialized leaf proof rides along.
    LeafDone {
        idx: u32,
        prove_ms: f64,
        verify_ms: f64,
        cascade_ms: f64,
        cascade_merges: u32,
        proof: Option<Vec<u8>>,
        /// At a query checkpoint: the interval proofs live after this leaf,
        /// left to right (bytes omitted for a peak shipped earlier).
        context: Option<Vec<WireInterval>>,
    },
    /// Slice complete (forest: after finalizing the local root).
    SliceDone {
        finalize_ms: f64,
        finalize_merges: u32,
        /// The serialized slice root when `Task::ship_root`.
        root: Option<Vec<u8>>,
    },
    Merged {
        ms: f64,
    },
    Root {
        proof: Vec<u8>,
    },
    Done {
        peak_rss_mb: f64,
    },
    Fatal {
        msg: String,
    },
}

// ─── Child process (worker role) ─────────────────────────────────────────────

const ENV_ROLE: &str = "ZKS_COMPOSE_ROLE";
const ENV_SOCK: &str = "ZKS_COMPOSE_SOCK";
const ENV_ID: &str = "ZKS_COMPOSE_ID";
const ENV_CORES: &str = "ZKS_COMPOSE_CORES";

/// Peak (high-water) RSS of this process, in MB — `VmHWM`, not the current
/// `VmRSS`, so a child can report after its proofs are dropped.
fn read_vmhwm_mb() -> f64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else { return 0.0 };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            if let Some(kb) = rest.trim().split_whitespace().next().and_then(|v| v.parse::<u64>().ok())
            {
                return kb as f64 / 1024.0;
            }
        }
    }
    0.0
}

/// Child-role dispatch. The `exp_compose` example calls this FIRST; when the
/// process was spawned as a worker it serves its role and exits (never returns
/// `false` in that case). There is only one child role: every mode — including
/// the sequential chain (pinned to a single machine) — proves and folds inside
/// the leaf worker.
pub fn maybe_run_child() -> bool {
    let Ok(role) = std::env::var(ENV_ROLE) else { return false };
    let sock = std::env::var(ENV_SOCK).expect("child needs ZKS_COMPOSE_SOCK");
    let cores: usize =
        std::env::var(ENV_CORES).ok().and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let id: u32 = std::env::var(ENV_ID).ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    match role.as_str() {
        "worker" => worker_main(&sock, id, cores),
        "worker_gl" => worker_main_gl(&sock, id, cores),
        other => {
            eprintln!("unknown {ENV_ROLE}='{other}'");
            std::process::exit(2);
        }
    }
}

/// Run `f` inside a `cores`-thread rayon pool, reporting a panic as a `Fatal`
/// message on the stream before exiting non-zero (so the coordinator fails
/// the cell instead of hanging).
fn serve_guarded(stream: UnixStream, cores: usize, f: impl FnOnce(&mut UnixStream) + Send) -> ! {
    let mut stream = stream;
    let mut err_stream = stream.try_clone().expect("clone for fatal path");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cores)
        .build()
        .expect("child rayon pool");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Each proof inside uses this pool (`install` scopes rayon's "current
        // pool"); the OS cpuset additionally fences the threads to the
        // machine's cores.
        pool.install(|| f(&mut stream));
    }));
    match r {
        Ok(()) => std::process::exit(0),
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".into());
            let _ = send_msg(&mut err_stream, &FromWorker::Fatal { msg });
            std::process::exit(1);
        }
    }
}

/// Leaf-machine role. Per mode:
/// - `per_batch`: prove each leaf and stream its serialized proof out (no fold).
/// - `chain`: **single machine, sequential.** Fold each fresh leaf into the
///   running prefix immediately (left-leaning `Π^(t)=merge(Π^(t-1),π_t)`),
///   the paper's "extend one batch at a time." No leaf leaves this process;
///   the fold is the sequential critical path. (The coordinator pins the chain
///   to one machine, so this worker owns the whole stream.)
/// - `forest`: fold the slice locally Bentley–Saxe (cascade as leaves complete,
///   finalize at slice end), then serve cross-machine reduction merges.
fn worker_main(sock: &str, id: u32, cores: usize) -> ! {
    let mut stream = UnixStream::connect(sock).expect("worker connect");
    send_msg(&mut stream, &FromWorker::Hello { id }).expect("hello");
    serve_guarded(stream, cores, move |s| {
        let (task, _) = recv_msg::<ToWorker>(s).expect("recv task");
        let ToWorker::Task {
            family, mode, shape, m, start, batches, first_index, checkpoints, ship_root,
        } = task
        else {
            panic!("first message must be Task");
        };
        let checkpoints: std::collections::BTreeSet<u32> = checkpoints.into_iter().collect();
        // The state's wire tag fixes the family; parse validates agreement.
        let family = StreamFamily::parse(&family).expect("family");
        let mode = StreamMode::parse(&mode).expect("mode");
        let shape = shape.to_shape();
        let m = m as usize;
        let mut state = FamState::decode(&start, m);
        // Build the leaf circuit ONCE; every epoch below reuses it.
        let mut leaf = FamLeafCircuit::build(family, &shape, m);

        // Forest: the online Bentley–Saxe cascade, folded as we go.
        let mut forest = ForestCascade::new(first_index);
        // Peaks already shipped to the coordinator (`(lo, hi)`).
        let mut shipped: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
        // Chain: the running left-leaning prefix proof.
        let mut chain_acc: Option<RecursionOutput<ConfigWithFriParams>> = None;
        let mut root: Option<RecursionOutput<ConfigWithFriParams>> = None;

        for (i, batch) in batches.iter().enumerate() {
            let (output, prove_ms, verify_ms) =
                state.prove_leaf(&mut leaf, first_index + i as u64, batch);
            state.advance(&shape, batch);

            let (mut cascade_ms, mut cascade_merges) = (0.0f64, 0u32);
            let proof_bytes = match mode {
                StreamMode::PerBatch => {
                    Some(postcard::to_allocvec(&output.0).expect("serialize leaf"))
                }
                StreamMode::Chain => {
                    // Sequential fold into the running prefix. The fold waits on
                    // the previous prefix proof (the chain's inherent bottleneck)
                    // — timed as this step's composition, not shipped anywhere.
                    let t0 = Instant::now();
                    chain_acc = Some(match chain_acc.take() {
                        None => output, // Π_{[1,1]}
                        Some(acc) => {
                            cascade_merges = 1;
                            prove_hiding_merge(&acc, &output)
                        }
                    });
                    cascade_ms = t0.elapsed().as_secs_f64() * 1000.0;
                    None
                }
                StreamMode::Forest => {
                    // The paper's composition cascade: merge equal-size peaks
                    // (binary-counter carry), off the leaf critical path but
                    // measured within the slice phase.
                    let t0 = Instant::now();
                    cascade_merges = forest.push(output);
                    cascade_ms = t0.elapsed().as_secs_f64() * 1000.0;
                    None
                }
            };
            // A query fires after this leaf: ship what certifies it (outside
            // the cascade timing; peaks are immutable, so each goes once).
            let ser = |p: &RecursionOutput<ConfigWithFriParams>| {
                postcard::to_allocvec(&p.0).expect("serialize context proof")
            };
            let context = checkpoints.contains(&(i as u32)).then(|| match mode {
                StreamMode::Forest => forest
                    .peaks()
                    .into_iter()
                    .map(|(lo, hi, p)| WireInterval {
                        lo,
                        hi,
                        proof: shipped.insert((lo, hi)).then(|| ser(p)),
                    })
                    .collect(),
                StreamMode::Chain => vec![WireInterval {
                    lo: first_index,
                    hi: first_index + i as u64,
                    proof: Some(ser(chain_acc.as_ref().expect("chain prefix"))),
                }],
                // per_batch: the leaf proofs themselves are the certificate.
                StreamMode::PerBatch => Vec::new(),
            });
            send_msg(
                s,
                &FromWorker::LeafDone {
                    idx: i as u32,
                    prove_ms,
                    verify_ms,
                    cascade_ms,
                    cascade_merges,
                    proof: proof_bytes,
                    context,
                },
            )
            .expect("send LeafDone");
        }

        match mode {
            StreamMode::Chain => {
                // The prefix proof is already the whole-stream root.
                root = chain_acc;
                send_msg(
                    s,
                    &FromWorker::SliceDone { finalize_ms: 0.0, finalize_merges: 0, root: None },
                )
                .expect("send SliceDone");
            }
            StreamMode::Forest => {
                // Finalize surviving peaks left-to-right into the slice root.
                let t0 = Instant::now();
                let (acc, merges) = forest.finalize();
                let finalize_ms = t0.elapsed().as_secs_f64() * 1000.0;
                let root_bytes =
                    ship_root.then(|| postcard::to_allocvec(&acc.0).expect("serialize slice root"));
                root = Some(acc);
                send_msg(
                    s,
                    &FromWorker::SliceDone {
                        finalize_ms,
                        finalize_merges: merges,
                        root: root_bytes,
                    },
                )
                .expect("send SliceDone");
            }
            StreamMode::PerBatch => {}
        }

        // Command loop: forest reduction merges / root shipping / exit.
        loop {
            let (cmd, _) = recv_msg::<ToWorker>(s).expect("recv cmd");
            match cmd {
                ToWorker::MergeWith { right_proof } => {
                    let right: Proof =
                        postcard::from_bytes(&right_proof).expect("deserialize peer root");
                    let t0 = Instant::now();
                    let left = root.take().expect("local root for merge");
                    root = Some(prove_hiding_merge_proofs(&left.0, &right));
                    send_msg(s, &FromWorker::Merged { ms: t0.elapsed().as_secs_f64() * 1000.0 })
                        .expect("send Merged");
                }
                ToWorker::FetchRoot => {
                    let r = root.as_ref().expect("local root to ship");
                    let bytes = postcard::to_allocvec(&r.0).expect("serialize root");
                    send_msg(s, &FromWorker::Root { proof: bytes }).expect("send Root");
                }
                ToWorker::Exit => {
                    send_msg(s, &FromWorker::Done { peak_rss_mb: read_vmhwm_mb() })
                        .expect("send Done");
                    break;
                }
                ToWorker::Task { .. } => panic!("duplicate Task"),
            }
        }
    })
}


/// Goldilocks leaf-machine role — a byte-for-byte copy of [`worker_main`] over
/// the gl state/leaf/config types. Mode logic, the peaks cascade, the message
/// loop, and the `Vec<u8>` proof serialization are IDENTICAL; only the
/// config-typed islands (`FamStateGl`, `FamLeafCircuitGl`,
/// `RecursionOutput<ConfigWithFriParamsGl>`, the `expose_forest_gl` merges, and
/// the `ProofGl` deserialize) differ.
fn worker_main_gl(sock: &str, id: u32, cores: usize) -> ! {
    let mut stream = UnixStream::connect(sock).expect("worker connect");
    send_msg(&mut stream, &FromWorker::Hello { id }).expect("hello");
    serve_guarded(stream, cores, move |s| {
        let (task, _) = recv_msg::<ToWorker>(s).expect("recv task");
        let ToWorker::Task { family, mode, shape, m, start, batches, first_index, .. } = task else {
            panic!("first message must be Task");
        };
        // The state's wire tag fixes the family; parse validates agreement.
        let family = StreamFamily::parse(&family).expect("family");
        let mode = StreamMode::parse(&mode).expect("mode");
        let shape = shape.to_shape();
        let m = m as usize;
        let mut state = FamStateGl::decode(&start, m);
        // Build the leaf circuit ONCE; every epoch below reuses it.
        let mut leaf = FamLeafCircuitGl::build(family, &shape, m);

        // Forest: Bentley–Saxe peak stack `(size, root)`, folded as we go.
        let mut peaks: Vec<(u64, RecursionOutput<ConfigWithFriParamsGl>)> = Vec::new();
        // Chain: the running left-leaning prefix proof.
        let mut chain_acc: Option<RecursionOutput<ConfigWithFriParamsGl>> = None;
        let mut root: Option<RecursionOutput<ConfigWithFriParamsGl>> = None;

        for (i, batch) in batches.iter().enumerate() {
            let (output, prove_ms, verify_ms) =
                state.prove_leaf(&mut leaf, first_index + i as u64, batch);
            state.advance(&shape, batch);

            let (mut cascade_ms, mut cascade_merges) = (0.0f64, 0u32);
            let proof_bytes = match mode {
                StreamMode::PerBatch => {
                    Some(postcard::to_allocvec(&output.0).expect("serialize leaf"))
                }
                StreamMode::Chain => {
                    // Sequential fold into the running prefix. The fold waits on
                    // the previous prefix proof (the chain's inherent bottleneck)
                    // — timed as this step's composition, not shipped anywhere.
                    let t0 = Instant::now();
                    chain_acc = Some(match chain_acc.take() {
                        None => output, // Π_{[1,1]}
                        Some(acc) => {
                            cascade_merges = 1;
                            crate::recursion::recursive::expose_forest_gl::prove_hiding_merge(
                                &acc, &output,
                            )
                        }
                    });
                    cascade_ms = t0.elapsed().as_secs_f64() * 1000.0;
                    None
                }
                StreamMode::Forest => {
                    // The paper's composition cascade: merge equal-size peaks
                    // (binary-counter carry), off the leaf critical path but
                    // measured within the slice phase.
                    let t0 = Instant::now();
                    let mut node = (1u64, output);
                    while peaks.last().is_some_and(|(sz, _)| *sz == node.0) {
                        let (_, left) = peaks.pop().unwrap();
                        node = (
                            node.0 * 2,
                            crate::recursion::recursive::expose_forest_gl::prove_hiding_merge(
                                &left, &node.1,
                            ),
                        );
                        cascade_merges += 1;
                    }
                    peaks.push(node);
                    cascade_ms = t0.elapsed().as_secs_f64() * 1000.0;
                    None
                }
            };
            send_msg(
                s,
                &FromWorker::LeafDone {
                    idx: i as u32,
                    prove_ms,
                    verify_ms,
                    cascade_ms,
                    cascade_merges,
                    proof: proof_bytes,
                    context: None,
                },
            )
            .expect("send LeafDone");
        }

        match mode {
            StreamMode::Chain => {
                // The prefix proof is already the whole-stream root.
                root = chain_acc;
                send_msg(
                    s,
                    &FromWorker::SliceDone { finalize_ms: 0.0, finalize_merges: 0, root: None },
                )
                .expect("send SliceDone");
            }
            StreamMode::Forest => {
                // Finalize surviving peaks left-to-right into the slice root.
                let t0 = Instant::now();
                let mut merges = 0u32;
                let mut acc = peaks.remove(0).1;
                for (_, r) in peaks.drain(..) {
                    acc = crate::recursion::recursive::expose_forest_gl::prove_hiding_merge(
                        &acc, &r,
                    );
                    merges += 1;
                }
                root = Some(acc);
                send_msg(
                    s,
                    &FromWorker::SliceDone {
                        finalize_ms: t0.elapsed().as_secs_f64() * 1000.0,
                        finalize_merges: merges,
                        root: None,
                    },
                )
                .expect("send SliceDone");
            }
            StreamMode::PerBatch => {}
        }

        // Command loop: forest reduction merges / root shipping / exit.
        loop {
            let (cmd, _) = recv_msg::<ToWorker>(s).expect("recv cmd");
            match cmd {
                ToWorker::MergeWith { right_proof } => {
                    let right: ProofGl =
                        postcard::from_bytes(&right_proof).expect("deserialize peer root");
                    let t0 = Instant::now();
                    let left = root.take().expect("local root for merge");
                    root = Some(
                        crate::recursion::recursive::expose_forest_gl::prove_hiding_merge_proofs(
                            &left.0, &right,
                        ),
                    );
                    send_msg(s, &FromWorker::Merged { ms: t0.elapsed().as_secs_f64() * 1000.0 })
                        .expect("send Merged");
                }
                ToWorker::FetchRoot => {
                    let r = root.as_ref().expect("local root to ship");
                    let bytes = postcard::to_allocvec(&r.0).expect("serialize root");
                    send_msg(s, &FromWorker::Root { proof: bytes }).expect("send Root");
                }
                ToWorker::Exit => {
                    send_msg(s, &FromWorker::Done { peak_rss_mb: read_vmhwm_mb() })
                        .expect("send Done");
                    break;
                }
                ToWorker::Task { .. } => panic!("duplicate Task"),
            }
        }
    })
}


// ─── CPU pinning ─────────────────────────────────────────────────────────────

/// NUMA node whose CPU list contains the whole range, from
/// `/sys/devices/system/node/node*/cpulist` (e.g. `0-63,128-191`).
fn numa_node_of(lo: usize, hi: usize) -> Option<usize> {
    let dir = std::fs::read_dir("/sys/devices/system/node").ok()?;
    for e in dir.flatten() {
        let name = e.file_name().into_string().ok()?;
        let Some(idx) = name.strip_prefix("node").and_then(|n| n.parse::<usize>().ok()) else {
            continue;
        };
        let Ok(list) = std::fs::read_to_string(e.path().join("cpulist")) else { continue };
        let mut covered = vec![false; hi + 1];
        for part in list.trim().split(',') {
            let (a, b) = match part.split_once('-') {
                Some((a, b)) => (a.parse().ok()?, b.parse().ok()?),
                None => {
                    let v: usize = part.parse().ok()?;
                    (v, v)
                }
            };
            for c in a..=b.min(hi) {
                if c >= lo {
                    covered[c] = true;
                }
            }
        }
        if (lo..=hi).all(|c| covered[c]) {
            return Some(idx);
        }
    }
    None
}

/// Physical-core block `[lo, hi]` of each NUMA node, read from
/// `/sys/devices/system/node/node*/cpulist`. The first comma-separated range of
/// a cpulist is the node's physical cores (any later ranges are SMT siblings),
/// e.g. `0-63,128-191` -> `(0, 63)`. Returned sorted by node id.
fn numa_phys_blocks() -> Vec<(usize, usize)> {
    let Ok(dir) = std::fs::read_dir("/sys/devices/system/node") else {
        return Vec::new();
    };
    let mut nodes: Vec<(usize, usize, usize)> = Vec::new();
    for e in dir.flatten() {
        let Ok(name) = e.file_name().into_string() else { continue };
        let Some(idx) = name.strip_prefix("node").and_then(|n| n.parse::<usize>().ok()) else {
            continue;
        };
        let Ok(list) = std::fs::read_to_string(e.path().join("cpulist")) else { continue };
        let first = list.trim().split(',').next().unwrap_or("");
        let range = match first.split_once('-') {
            Some((a, b)) => a.parse::<usize>().ok().zip(b.parse::<usize>().ok()),
            None => first.parse::<usize>().ok().map(|v| (v, v)),
        };
        if let Some((lo, hi)) = range {
            nodes.push((idx, lo, hi));
        }
    }
    nodes.sort_by_key(|&(id, _, _)| id);
    nodes.into_iter().map(|(_, lo, hi)| (lo, hi)).collect()
}

/// Physical-core range `[lo, hi]` for machine `i` of `machines`, spreading the
/// machines round-robin across NUMA nodes so that — whenever `machines` does not
/// exceed the node count — each machine gets its own node (hence its own memory
/// controller), instead of packing contiguous `[i·cores, ·)` blocks that would
/// stack the first machines onto node 0 (2 machines / 32 cores would both land
/// on a 64-core node 0, sharing its DRAM controller while node 1 sits idle).
/// Falls back to the contiguous block when NUMA topology is unavailable or the
/// round-robin layout would overflow a node.
///
/// `EXP_COMPOSE_NODE_OFFSET=k` rotates the node assignment (machine `i` →
/// node `i+k mod n`), letting a second, concurrent harness instance occupy a
/// different node — e.g. a background-load replica on the sibling node that
/// keeps each socket's package environment uniform across machine counts.
fn machine_core_range(i: usize, cores: usize, machines: usize) -> (usize, usize) {
    let contiguous = (i * cores, (i + 1) * cores - 1);
    let nodes = numa_phys_blocks();
    // `EXP_COMPOSE_NODES=a,b,...` pins machine `i` to the base of listed node
    // `i mod len` EXACTLY (successive machines wrap onto the same nodes — the
    // reuse is intentional for staged waves, where wave w+1 takes over the
    // cores wave w released). Falls through on any parse/topology mismatch.
    if let Ok(list) = std::env::var("EXP_COMPOSE_NODES") {
        let ids: Vec<usize> = list.split(',').filter_map(|s| s.trim().parse().ok()).collect();
        // Wrapping onto already-used nodes is only safe when staged waves
        // serialize the reuse; concurrently it would stack two live machines
        // on the same cores, so without a wave size the list must cover every
        // machine (else fall through to the default layout).
        let wrap_ok = staged_wave_size().is_some() || i < ids.len();
        if !ids.is_empty() && wrap_ok {
            if let Some(&(lo, hi)) = ids.get(i % ids.len()).and_then(|&id| nodes.get(id)) {
                if lo + cores - 1 <= hi {
                    return (lo, lo + cores - 1);
                }
            }
        }
    }
    if nodes.is_empty() {
        return contiguous;
    }
    let n = nodes.len();
    let offset = std::env::var("EXP_COMPOSE_NODE_OFFSET")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let block = |j: usize| -> (usize, usize) {
        let (lo, _) = nodes[(j + offset) % n];
        let base = lo + ((j + offset) / n) * cores;
        (base, base + cores - 1)
    };
    // Adopt the round-robin layout only if every machine's block fits its node.
    let fits = (0..machines).all(|j| block(j).1 <= nodes[(j + offset) % n].1);
    if fits { block(i) } else { contiguous }
}

fn have_cmd(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Run-private temp name for this coordinator's executable snapshot.
fn exe_snapshot_name() -> String {
    format!("zks_dc_exe_{}", std::process::id())
}

/// A rebuild-proof path to *this* executable for pinned child spawns.
///
/// A multi-family × multi-mode sweep spends hours per cell. If a concurrent
/// `cargo build`/`cargo run` of the same example relinks the binary, the
/// coordinator's running inode is unlinked and `std::env::current_exe()` then
/// returns a bogus `".../exp_compose (deleted)"` path. The next
/// `numactl <that path>` child spawn dies with "No such file or directory",
/// aborting the sweep partway (exactly the failure seen after the cm family).
///
/// So snapshot the executable ONCE, on first spawn, into a run-private temp copy
/// and exec that copy for every worker thereafter — immune to the on-disk binary
/// being rebuilt/removed later, and guaranteeing every worker runs byte-for-byte
/// the coordinator's build. The copy source is `/proc/self/exe` on Linux, which
/// serves the running inode's bytes even after the file is unlinked, so the
/// snapshot succeeds even if the binary was already replaced before this call.
///
/// Only a *successful* snapshot is memoized: if the first call hits a transient
/// error (a momentary `EINTR`/`ENOSPC` on copy, say), it is returned but NOT
/// cached, so the next cell retries — matching the old per-cell `current_exe()`
/// resilience instead of dooming the whole sweep on one blip.
fn stable_self_exe() -> Result<PathBuf, String> {
    static SNAPSHOT: OnceLock<PathBuf> = OnceLock::new();
    if let Some(p) = SNAPSHOT.get() {
        return Ok(p.clone());
    }
    let dst = take_exe_snapshot()?;
    // The coordinator spawns sequentially, but tolerate a race anyway: keep
    // whatever ended up stored.
    let _ = SNAPSHOT.set(dst.clone());
    Ok(SNAPSHOT.get().cloned().unwrap_or(dst))
}

/// Copy this executable to its run-private snapshot path and mark it executable.
fn take_exe_snapshot() -> Result<PathBuf, String> {
    let resolved = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    // Prefer /proc/self/exe (serves the running inode even if unlinked);
    // fall back to the resolved path on non-Linux.
    let proc_exe = PathBuf::from("/proc/self/exe");
    let src = if proc_exe.exists() { proc_exe } else { resolved.clone() };
    let dst = std::env::temp_dir().join(exe_snapshot_name());
    // Remove any stale same-named file (e.g. leaked by an earlier crashed run
    // with this PID) so the copy can't hit ETXTBSY truncating a busy file.
    let _ = std::fs::remove_file(&dst);
    std::fs::copy(&src, &dst)
        .map_err(|e| format!("snapshot exe {} -> {}: {e}", src.display(), dst.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod exe snapshot {}: {e}", dst.display()))?;
    }
    Ok(dst)
}

/// Remove the executable snapshot created by [`stable_self_exe`] (best effort).
/// A no-op when no pinned processes were spawned. Prefer holding an
/// [`ExeSnapshotGuard`] over calling this directly, so cleanup also runs on the
/// error/panic exit paths.
pub fn cleanup_exe_snapshot() {
    let _ = std::fs::remove_file(std::env::temp_dir().join(exe_snapshot_name()));
}

/// RAII guard that removes the exe snapshot on drop — covering *every* exit path
/// of a sweep (normal return, `?` error propagation, and panic unwinding), not
/// just the success path. Hold one for the lifetime of the sweep in `main`.
#[derive(Default)]
pub struct ExeSnapshotGuard(());
impl ExeSnapshotGuard {
    pub fn new() -> Self {
        Self(())
    }
}
impl Drop for ExeSnapshotGuard {
    fn drop(&mut self) {
        cleanup_exe_snapshot();
    }
}

/// Build the pinned child command for CPUs `[lo, hi]` (inclusive):
/// `numactl --physcpubind=lo-hi --membind=<node>` when available (and the
/// range sits in one NUMA node), else `taskset -c lo-hi`, else unpinned (with
/// a warning — the emulation is then best-effort).
fn pinned_command(exe: &Path, lo: usize, hi: usize) -> Command {
    if have_cmd("numactl") {
        let mut c = Command::new("numactl");
        c.arg(format!("--physcpubind={lo}-{hi}"));
        if let Some(node) = numa_node_of(lo, hi) {
            c.arg(format!("--membind={node}"));
        }
        c.arg(exe);
        c
    } else if have_cmd("taskset") {
        let mut c = Command::new("taskset");
        c.arg("-c").arg(format!("{lo}-{hi}")).arg(exe);
        c
    } else {
        eprintln!("warning: neither numactl nor taskset found — machines run UNPINNED");
        Command::new(exe)
    }
}

/// Kill-on-drop child guard: a coordinator panic/early-return never leaks
/// pinned prover processes.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ─── Auditor's trusted root VK ───────────────────────────────────────────────

/// Where the auditor's trusted root VK comes from (env `EXP_ROOT_VK`, parsed
/// by [`crate::recursion::recursive::root_vk::exp_root_vk`]). Fails closed:
/// * unset / empty / `derive` (the DEFAULT) — derived from public parameters
///   only: a no-op leaf of the family's leaf circuit plus this run's
///   merge-tree shape ([`ForestShape::dist_forest`] / [`ForestShape::chain`]);
///   costs `O(log t + log M)` dummy merges for the forest (`t - 1` for the
///   chain), outside every timed phase. `EXP_ROOT_VK_SAVE=<path>` also writes
///   it. A derivation failure aborts the run (no fallback to a self-pin).
/// * `self` — explicit opt-in to the LEGACY self-pin: the VK is read from the
///   received root itself, so the pin is vacuous (the pre-H2 behaviour, kept
///   only for side-by-side runs; a loud warning goes to stderr).
/// * anything else — a path to a postcard-encoded `RootVk` supplied
///   externally (e.g. saved by an earlier `derive` run); a read/decode error
///   aborts the run.
enum RootVkSource {
    SelfPinnedLegacy,
    Derive,
    File(PathBuf),
}

fn root_vk_source() -> RootVkSource {
    use crate::recursion::recursive::root_vk::{exp_root_vk, ExpRootVk};
    match exp_root_vk() {
        ExpRootVk::Derive => RootVkSource::Derive,
        ExpRootVk::SelfPinnedLegacy => RootVkSource::SelfPinnedLegacy,
        ExpRootVk::File(path) => RootVkSource::File(path),
    }
}

/// The merge tree a dist run folds its `t` leaves into.
fn dist_tree_shape(mode: StreamMode, t: usize, machines: usize) -> ForestShape {
    match mode {
        StreamMode::Chain => ForestShape::chain(t),
        StreamMode::Forest | StreamMode::PerBatch => ForestShape::dist_forest(t, machines),
    }
}

/// Public, data-free leaf input whose leaf proof is a NO-OP (initial ==
/// final boundary): `(setup, batch)` — advance the empty state by `setup`,
/// then prove `batch`. CM/SS/GK/Bloom: a batch of `PAD_KEY` no-op records
/// from the empty state (Bloom: all slots become `act = 0` dummies, the
/// `noop_leaf::bloom_omc_noop_leaf_expose` input); HLL: re-insert a key the
/// state already holds (`max` is idempotent), since HLL has no pad sentinel.
fn noop_leaf_input(family: StreamFamily, m: usize) -> (Vec<u32>, Vec<u32>) {
    if family.base_family() == StreamFamily::HllOmc {
        (vec![1], vec![1; m])
    } else {
        (Vec::new(), vec![PAD_KEY; m])
    }
}

/// Resolve the auditor's trusted VK (see [`RootVkSource`]): `Ok(None)` only
/// for the explicit legacy opt-in `EXP_ROOT_VK=self` (announced on stderr);
/// `derive` computes it from public parameters (and writes it to
/// `EXP_ROOT_VK_SAVE` when set); a file path reads it. Used for the composed
/// root and, on the paths where the auditor receives LEAF proofs directly
/// (per_batch; a one-batch stream), for the leaf VK.
fn resolve_trusted_vk<C: Serialize + DeserializeOwned>(
    derive: impl FnOnce() -> RootVk<C>,
) -> Result<Option<RootVk<C>>, String> {
    match root_vk_source() {
        RootVkSource::SelfPinnedLegacy => {
            crate::recursion::recursive::root_vk::warn_self_pinned_legacy("dist_compose auditor");
            Ok(None)
        }
        RootVkSource::Derive => {
            let t0 = Instant::now();
            let vk = derive();
            eprintln!(
                "    auditor: VK derived from public parameters in {:.1}s",
                t0.elapsed().as_secs_f64()
            );
            if let Ok(path) = std::env::var("EXP_ROOT_VK_SAVE") {
                let bytes = postcard::to_allocvec(&vk).map_err(|e| format!("encode root VK: {e}"))?;
                std::fs::write(&path, bytes).map_err(|e| format!("write root VK {path}: {e}"))?;
            }
            Ok(Some(vk))
        }
        RootVkSource::File(path) => {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("read root VK {}: {e}", path.display()))?;
            postcard::from_bytes(&bytes)
                .map(Some)
                .map_err(|e| format!("decode root VK {}: {e}", path.display()))
        }
    }
}

/// Resolve the auditor's trusted root VK (see [`RootVkSource`]); under the
/// legacy `self` opt-in the VK is `self_pin()` (read from the root itself).
fn resolve_root_vk<C: Serialize + DeserializeOwned>(
    self_pin: impl FnOnce() -> Vec<C>,
    derive: impl FnOnce() -> RootVk<C>,
) -> Result<RootVk<C>, String> {
    Ok(resolve_trusted_vk(derive)?.unwrap_or_else(|| RootVk::commitment_only(self_pin())))
}

/// The no-op leaf proof of the family's harness leaf circuit (built exactly as
/// the workers build it, [`FamLeafCircuit::build`]) over public, data-free
/// input ([`noop_leaf_input`]) at batch index 1 — the starting point of every
/// VK derivation.
pub(crate) fn prove_noop_leaf(family: StreamFamily, shape: &StreamShape, m: usize) -> Proof {
    let mut leaf = FamLeafCircuit::build(family, shape, m);
    let mut state = FamState::empty(family, shape, m);
    let (setup, batch) = noop_leaf_input(family, m);
    if !setup.is_empty() {
        state.advance(shape, &setup);
    }
    state.prove_leaf(&mut leaf, 1, &batch).0 .0
}

/// Goldilocks analog of [`prove_noop_leaf`].
fn prove_noop_leaf_gl(family: StreamFamily, shape: &StreamShape, m: usize) -> ProofGl {
    let mut leaf = FamLeafCircuitGl::build(family, shape, m);
    let mut state = FamStateGl::empty(family, shape, m);
    let (setup, batch) = noop_leaf_input(family, m);
    if !setup.is_empty() {
        state.advance(shape, &setup);
    }
    state.prove_leaf(&mut leaf, 1, &batch).0 .0
}

/// The trusted LEAF VK (commitment + metadata) of the family's harness leaf
/// circuit, from public parameters only: the no-op leaf's own VK. The auditor
/// pins every leaf proof it receives directly (per_batch; a one-batch stream)
/// to it ([`verify_leaves_against_log`]).
pub(crate) fn derive_dist_leaf_vk(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
) -> RootVk<crate::config::Challenge> {
    leaf_vk(&prove_noop_leaf(family, shape, m))
}

/// Goldilocks analog of [`derive_dist_leaf_vk`].
fn derive_dist_leaf_vk_gl(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
) -> RootVk<crate::config_gl::Challenge> {
    crate::recursion::recursive::expose_forest_gl::leaf_vk(&prove_noop_leaf_gl(family, shape, m))
}

/// Derive the BabyBear root VK of a dist run from public parameters only.
/// (Also used by `stream_compose::measure_compose` with `machines = 1`, whose
/// forest is `ForestShape::dist_forest(t, 1) == ForestShape::forest(t)`.)
pub(crate) fn derive_dist_root_vk(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
    mode: StreamMode,
    t: usize,
    machines: usize,
) -> RootVk<crate::config::Challenge> {
    root_vk_deriver(prove_noop_leaf(family, shape, m)).root_vk(&dist_tree_shape(mode, t, machines))
}

/// Goldilocks analog of [`derive_dist_root_vk`].
fn derive_dist_root_vk_gl(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
    mode: StreamMode,
    t: usize,
    machines: usize,
) -> RootVk<crate::config_gl::Challenge> {
    crate::recursion::recursive::expose_forest_gl::root_vk_deriver(prove_noop_leaf_gl(family, shape, m))
        .root_vk(&dist_tree_shape(mode, t, machines))
}

/// The auditor's check of LEAF proofs it receives directly, as postcard bytes
/// (per_batch: all `t` leaves; chain/forest with `t == 1`: the lone leaf).
///
/// Default (`EXP_ROOT_VK` unset / `derive`, or a VK file): the trusted leaf VK
/// is resolved OUTSIDE the timed verify ([`derive_dist_leaf_vk`]), the bytes
/// are decoded, and then every leaf is pinned to it, STARK-verified, and its
/// statement checked against `log` ([`verify_leaves_against_log`]); returns the
/// measured verify time in ms. Legacy `EXP_ROOT_VK=self` (warned): the leaves
/// are only decoded and their statements checked, which authenticates nothing,
/// and the workers' self-verify total `self_verify_ms` is reported, exactly as
/// before the pin existed.
#[allow(clippy::too_many_arguments)]
fn audit_leaf_bytes(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
    bytes: &[&[u8]],
    log: &BatchLog<Val>,
    layout: Expose,
    self_verify_ms: f64,
) -> Result<f64, String> {
    let vk = resolve_trusted_vk(|| derive_dist_leaf_vk(family, shape, m))?;
    let proofs: Vec<Proof> = bytes
        .iter()
        .map(|b| postcard::from_bytes(b))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("leaf decode: {e}"))?;
    let refs: Vec<&Proof> = proofs.iter().collect();
    match &vk {
        Some(vk) => {
            let v0 = Instant::now();
            verify_leaves_against_log(&refs, vk, log, layout)
                .map_err(|e| format!("leaf audit: {e}"))?;
            Ok(v0.elapsed().as_secs_f64() * 1000.0)
        }
        None => {
            check_leaves_against_log(&refs, log, layout)
                .map_err(|e| format!("leaf statements vs log: {e}"))?;
            Ok(self_verify_ms)
        }
    }
}

/// Goldilocks analog of [`audit_leaf_bytes`].
#[allow(clippy::too_many_arguments)]
fn audit_leaf_bytes_gl(
    family: StreamFamily,
    shape: &StreamShape,
    m: usize,
    bytes: &[&[u8]],
    log: &BatchLog<crate::config_gl::Val>,
    layout: Expose,
    self_verify_ms: f64,
) -> Result<f64, String> {
    use crate::recursion::recursive::expose_forest_gl as efg;
    let vk = resolve_trusted_vk(|| derive_dist_leaf_vk_gl(family, shape, m))?;
    let proofs: Vec<ProofGl> = bytes
        .iter()
        .map(|b| postcard::from_bytes(b))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("leaf decode: {e}"))?;
    let refs: Vec<&ProofGl> = proofs.iter().collect();
    match &vk {
        Some(vk) => {
            let v0 = Instant::now();
            efg::verify_leaves_against_log(&refs, vk, log, layout)
                .map_err(|e| format!("leaf audit: {e}"))?;
            Ok(v0.elapsed().as_secs_f64() * 1000.0)
        }
        None => {
            efg::check_leaves_against_log(&refs, log, layout)
                .map_err(|e| format!("leaf statements vs log: {e}"))?;
            Ok(self_verify_ms)
        }
    }
}

// ─── Coordinator ─────────────────────────────────────────────────────────────

/// One measured distributed-composition cell.
#[derive(Clone, Debug, Default)]
pub struct DistCell {
    /// Machines actually used: `min(machines, t)` for per_batch/forest, but
    /// pinned to `1` for the chain (its schedule is inherently sequential).
    pub machines_eff: usize,
    /// Total pinned prover processes (one per machine; the chain needs no
    /// separate composer — it folds in place on its single machine).
    pub procs: usize,
    /// Sequential plaintext witness pass over all N records (coordinator).
    pub witness_pass_ms: f64,
    /// Scatter phase: wall time + shipped bytes (slice-start states vs batch
    /// data, separated — in a source-partitioned deployment the data bytes
    /// are already resident and only the state bytes are composition-specific).
    pub scatter_ms: f64,
    pub scatter_state_bytes: u64,
    pub scatter_data_bytes: u64,
    /// Slice-phase wall (all machines in parallel): leaf proving, plus (for
    /// the forest) the in-slice cascade + finalize merges.
    pub leafgen_ms: f64,
    /// Σ per-leaf prove time across all machines (the 1-machine reference).
    pub leafgen_seq_ms: f64,
    /// Min/max per-machine busy time in the slice phase (imbalance).
    pub leaf_busy_min_ms: f64,
    pub leaf_busy_max_ms: f64,
    /// Forest only: max per-machine local fold time (cascades + finalize) —
    /// composition work that ran inside the slice phase, on-machine.
    pub local_fold_ms: f64,
    pub merges_local: u32,
    /// Cross-machine composition wall after the slice phase: the forest's
    /// reduction rounds (0 for the chain, which folds in place on 1 machine,
    /// and per_batch, which does not fold).
    pub merge_ms: f64,
    pub merges_cross: u32,
    pub cross_rounds: u32,
    /// Composition-path cross-machine traffic: forest round roots + final
    /// root, or per_batch's Θ(t) leaf proofs (scatter counted separately
    /// above). The chain folds in place, so this is just its single root.
    pub comm_msgs: u64,
    pub comm_bytes: u64,
    /// Coordinator-measured loopback wall spent in composition-path
    /// socket sends/recvs (excluding time waiting on proving).
    pub comm_ms_measured: f64,
    /// Critical-path network model (scatter + composition-path + root) at the
    /// modeled link bandwidth `EXP_NET_MBPS` Mb/s with `rtt_ms` per message.
    /// The measured `comm_bytes` make any other bandwidth derivable.
    pub comm_model_ms: f64,
    /// Verifier-facing artifact: Σ leaf proofs (per_batch) or the root.
    pub proof_bytes: u64,
    /// per_batch: Σ leaf self-verifies; chain/forest: root verify (measured
    /// at the coordinator from the received bytes).
    pub verify_ms: f64,
    /// End-to-end prover-side wall: witness pass → root received.
    pub total_time_ms: f64,
    /// Max child peak RSS (VmHWM) — the per-machine memory bound.
    pub peak_rss_mb: f64,
    // ── Mixed workload (non-empty query_at): the interleaved decode queries,
    // proved on the coordinator after the update makespan (θ(state) each,
    // NOT folded into total_time_ms). Zero when updates-only.
    pub n_queries: usize,
    pub query_prove_ms: f64,
    pub query_verify_ms: f64,
    pub query_proof_bytes: u64,
    pub query_ctx_verifies: u64,
    /// Σ measured cost of binding each answer to the certified history
    /// (see [`super::stream_compose::ComposeCell::query_bind_ms`]); `None`
    /// when unbound.
    pub query_bind_ms: Option<f64>,
}

/// Network-model transfer time for one message: serialization at `mbps`
/// megabits/second plus a fixed per-message RTT.
fn xfer_ms(bytes: u64, mbps: f64, rtt_ms: f64) -> f64 {
    bytes as f64 * 8.0 / (mbps * 1e6) * 1000.0 + rtt_ms
}

/// Contiguous work split: machine `i` gets `batches[i·per .. (i+1)·per]`.
fn slice_ranges(t: usize, machines: usize) -> Vec<(usize, usize)> {
    let per = t.div_ceil(machines.max(1));
    (0..machines).map(|i| (i * per, ((i + 1) * per).min(t))).filter(|(a, b)| a < b).collect()
}

/// Reader-thread event: worker id, message, arrival stamp, bytes.
enum Event {
    Worker(u32, FromWorker, Instant, u64),
    /// A child's socket closed (EOF/err) — fatal unless it already said Done.
    Gone(u32),
}

/// Coordinator side of the mixed workload's prefix binding (Property 3):
/// which leaves are query checkpoints for each worker, and the interval
/// proofs the workers ship there, assembled per query version into the
/// certificate [`QueryAudit::bind`] checks: forest, the finalized roots of
/// the earlier slices plus the query slice's live peaks (with one machine,
/// exactly the Bentley–Saxe peaks at `t'`); chain, the running fold
/// `Π_[1,t']`; per_batch, the leaf proofs `1..t'`.
struct CtxCollector {
    on: bool,
    mode: StreamMode,
    store: ContextStore,
    /// Per query version `g` (1-based): the worker-local parts shipped there.
    local: BTreeMap<usize, Vec<(u64, u64, ForestShape)>>,
    /// Forest: each slice's shipped root interval.
    slice_roots: Vec<Option<(u64, u64, ForestShape)>>,
}

impl CtxCollector {
    fn new(on: bool, mode: StreamMode, machines: usize) -> Self {
        Self {
            on,
            mode,
            store: ContextStore::default(),
            local: BTreeMap::new(),
            slice_roots: vec![None; machines],
        }
    }

    /// The bracketing of a worker-shipped interval `[lo, hi]`.
    fn shape_of(&self, lo: u64, hi: u64) -> ForestShape {
        let n = (hi - lo + 1) as usize;
        match self.mode {
            StreamMode::Chain => ForestShape::chain(n),
            _ => ForestShape::forest(n),
        }
    }

    /// Local 0-based leaf indices of slice `(a, b]` after which a query fires.
    fn checkpoints(&self, query_at: &[usize], (a, b): (usize, usize)) -> Vec<u32> {
        if !self.on || self.mode == StreamMode::PerBatch {
            return Vec::new();
        }
        query_at.iter().filter(|&&g| g > a && g <= b).map(|&g| (g - a - 1) as u32).collect()
    }

    /// Forest: a later slice holds a query, so this slice's root is needed.
    fn ship_root(&self, query_at: &[usize], (_, b): (usize, usize)) -> bool {
        self.on && self.mode == StreamMode::Forest && query_at.iter().any(|&g| g > b)
    }

    fn on_leaf(
        &mut self,
        mode: StreamMode,
        g: usize,
        context: Option<Vec<WireInterval>>,
    ) -> Result<(), String> {
        let Some(parts) = context else { return Ok(()) };
        if !self.on || mode != self.mode {
            return Err(format!("unrequested query context at leaf {g}"));
        }
        let mut list = Vec::with_capacity(parts.len());
        for wi in parts {
            let key = (wi.lo, wi.hi, self.shape_of(wi.lo, wi.hi));
            match wi.proof {
                Some(bytes) => self.store.insert(key.clone(), bytes)?,
                None if self.store.has(&key) => {}
                None => {
                    return Err(format!(
                        "interval [{}, {}] referenced before it was shipped",
                        wi.lo, wi.hi
                    ));
                }
            }
            list.push(key);
        }
        self.local.insert(g, list);
        Ok(())
    }

    fn on_slice(
        &mut self,
        w: usize,
        (a, b): (usize, usize),
        root: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let Some(bytes) = root else { return Ok(()) };
        let key = (a as u64 + 1, b as u64, ForestShape::forest(b - a));
        self.store.insert(key.clone(), bytes)?;
        self.slice_roots[w] = Some(key);
        Ok(())
    }

    /// Assemble every query's certificate (per_batch: from the leaf proofs).
    fn finish(
        mut self,
        query_at: &[usize],
        ranges: &[(usize, usize)],
        leaf_proofs: &[Option<Vec<u8>>],
    ) -> Result<ContextStore, String> {
        if !self.on {
            return Ok(self.store);
        }
        for &g in query_at {
            let parts = match self.mode {
                StreamMode::PerBatch => {
                    let mut v = Vec::with_capacity(g);
                    for k in 1..=g {
                        let key = (k as u64, k as u64, ForestShape::Leaf);
                        if !self.store.has(&key) {
                            let p = leaf_proofs[k - 1]
                                .clone()
                                .ok_or(format!("leaf {k} proof missing"))?;
                            self.store.insert(key.clone(), p)?;
                        }
                        v.push(key);
                    }
                    v
                }
                StreamMode::Chain => self
                    .local
                    .get(&g)
                    .cloned()
                    .ok_or(format!("no chain prefix shipped for t'={g}"))?,
                StreamMode::Forest => {
                    let i = ranges
                        .iter()
                        .position(|&(a, b)| g > a && g <= b)
                        .ok_or(format!("t'={g} lies in no slice"))?;
                    let mut v = Vec::new();
                    for j in 0..i {
                        let root = self.slice_roots[j].clone();
                        v.push(root.ok_or(format!("slice {j} root not shipped"))?);
                    }
                    let peaks = self.local.get(&g).cloned();
                    v.extend(peaks.ok_or(format!("no peaks shipped for t'={g}"))?);
                    v
                }
            };
            self.store.parts.insert(g, parts);
        }
        Ok(self.store)
    }
}

fn spawn_worker_reader(id: u32, mut stream: UnixStream, tx: mpsc::Sender<Event>) {
    std::thread::spawn(move || loop {
        match recv_msg::<FromWorker>(&mut stream) {
            Ok((msg, bytes)) => {
                let done = matches!(msg, FromWorker::Done { .. });
                if tx.send(Event::Worker(id, msg, Instant::now(), bytes)).is_err() || done {
                    return;
                }
            }
            Err(_) => {
                let _ = tx.send(Event::Gone(id));
                return;
            }
        }
    });
}

/// Receive the next event or fail the cell (child death / 30-min silence —
/// a single merge at these shapes is seconds, so silence means a wedge).
fn next_event(rx: &mpsc::Receiver<Event>) -> Result<Event, String> {
    match rx.recv_timeout(std::time::Duration::from_secs(1800)) {
        Ok(Event::Gone(id)) => Err(format!("machine {id} died (socket closed)")),
        Ok(ev) => Ok(ev),
        Err(_) => Err("timed out waiting for a machine".into()),
    }
}

fn fatal_msg(msg: &FromWorker) -> Option<String> {
    match msg {
        FromWorker::Fatal { msg } => Some(msg.clone()),
        _ => None,
    }
}

/// Measure one `(family, shape, mode)` cell under the process-level
/// distributed emulation: up to `machines` pinned worker processes × `cores`
/// CPUs each. The **chain is pinned to a single machine** regardless of
/// `machines` — its schedule is inherently sequential (each fold consumes the
/// previous prefix proof), so it cannot use more, and giving it parallel
/// leaf-gen would smuggle in the forest's advantage. Returns `Err(reason)` on
/// any machine failure (e.g. a too-large shape panicking a prover) — the
/// caller records the row's status.
#[allow(clippy::too_many_arguments)]
pub fn measure_compose_dist(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    machines: usize,
    proof_dir: &Path,
    mbps: f64,
    rtt_ms: f64,
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
) -> Result<DistCell, String> {
    // Staged-wave mode (forest only): machines execute in gated waves so each
    // gets a full NUMA node with no co-resident sibling from this experiment;
    // the makespan is composed from measured per-wave walls. See
    // [`measure_compose_dist_staged`].
    if mode == StreamMode::Forest {
        if let Some(ws) = staged_wave_size() {
            let eff = slice_ranges(batches.len(), machines).len();
            if ws >= 1 && ws < eff {
                return measure_compose_dist_staged(
                    family, shape, batches, cores, machines, proof_dir, mbps, rtt_ms, query_at,
                    query_key_mode, ws,
                );
            }
        }
    }
    assert!(!batches.is_empty(), "need at least one batch");
    let m = batches[0].len();
    let t = batches.len();
    let total_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    // The chain is inherently sequential — pin it to ONE machine (it folds in
    // place). per_batch/forest distribute leaves over up to `machines`.
    let machines = if mode == StreamMode::Chain { 1 } else { machines };
    let ranges = slice_ranges(t, machines);
    let machines_eff = ranges.len();
    if machines_eff * cores > total_cpus {
        return Err(format!(
            "oversubscribed: {machines_eff} machines x {cores} cores > {total_cpus} CPUs"
        ));
    }

    // Mixed workload: the query-side auditor (decode VK + prefix auditor),
    // derived from public parameters before the timed run; the workers then
    // ship each query's prefix certificate ([`CtxCollector`]).
    let mut audit = if query_at.is_empty() { None } else { QueryAudit::new(family, &shape, m) };
    let mut ctx = CtxCollector::new(audit.is_some(), mode, machines_eff);

    let t_start = Instant::now();

    // ── Witness pass: one sequential plaintext replay; record slice-start
    // states and the native anchor/final commitments.
    let wp0 = Instant::now();
    let mut state = FamState::empty(family, &shape, m);
    let anchor = state.commit(&shape);
    let mut slice_starts: Vec<WireState> = Vec::with_capacity(machines_eff);
    let mut next_slice = 0usize;
    for (i, batch) in batches.iter().enumerate() {
        if next_slice < ranges.len() && ranges[next_slice].0 == i {
            slice_starts.push(state.encode());
            next_slice += 1;
        }
        state.advance(&shape, batch);
    }
    let final_commit = state.commit(&shape);
    let witness_pass_ms = wp0.elapsed().as_secs_f64() * 1000.0;

    // ── Spawn the machines.
    let sock_path = std::env::temp_dir().join(format!(
        "zks_dc_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).map_err(|e| format!("bind socket: {e}"))?;
    let exe = stable_self_exe()?;

    let spawn_child = |role: &str, id: usize, lo: usize, hi: usize| -> Result<ChildGuard, String> {
        let mut cmd = pinned_command(&exe, lo, hi);
        cmd.env(ENV_ROLE, role)
            .env(ENV_SOCK, &sock_path)
            .env(ENV_ID, id.to_string())
            .env(ENV_CORES, cores.to_string())
            .stdout(Stdio::null()) // keep the coordinator's stdout clean
            .stderr(Stdio::inherit());
        cmd.spawn().map(ChildGuard).map_err(|e| format!("spawn {role} {id}: {e}"))
    };

    let mut children: Vec<ChildGuard> = Vec::new();
    for i in 0..machines_eff {
        let (lo, hi) = machine_core_range(i, cores, machines_eff);
        children.push(spawn_child("worker", i, lo, hi)?);
    }

    // Handshake: map connections by Hello id.
    let (tx, rx) = mpsc::channel::<Event>();
    let mut worker_tx: Vec<Option<UnixStream>> = (0..machines_eff).map(|_| None).collect();
    for _ in 0..machines_eff {
        let (mut s, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let (hello, _) = recv_msg::<FromWorker>(&mut s).map_err(|e| format!("hello: {e}"))?;
        let FromWorker::Hello { id } = hello else { return Err("bad hello".into()) };
        let reader = s.try_clone().map_err(|e| format!("clone: {e}"))?;
        spawn_worker_reader(id, reader, tx.clone());
        worker_tx[id as usize] = Some(s);
    }
    let mut worker_tx: Vec<UnixStream> =
        worker_tx.into_iter().map(|s| s.expect("all workers connected")).collect();

    // ── Scatter: each machine gets its slice-start state + its batches.
    let sc0 = Instant::now();
    let (mut scatter_state_bytes, mut scatter_data_bytes) = (0u64, 0u64);
    for (i, &(a, b)) in ranges.iter().enumerate() {
        let start = slice_starts[i].clone();
        scatter_state_bytes +=
            postcard::to_allocvec(&start).map(|v| v.len() as u64).unwrap_or(0);
        let slice: Vec<Vec<u32>> = batches[a..b].to_vec();
        scatter_data_bytes += postcard::to_allocvec(&slice).map(|v| v.len() as u64).unwrap_or(0);
        send_msg(
            &mut worker_tx[i],
            &ToWorker::Task {
                family: family.label().into(),
                mode: mode.label().into(),
                shape: WireShape::from(&shape),
                m: m as u32,
                start,
                batches: slice,
                first_index: a as u64 + 1,
                checkpoints: ctx.checkpoints(query_at, (a, b)),
                ship_root: ctx.ship_root(query_at, (a, b)),
            },
        )
        .map_err(|e| format!("scatter to {i}: {e}"))?;
    }
    let scatter_ms = sc0.elapsed().as_secs_f64() * 1000.0;

    // ── Slice phase: collect every LeafDone (+ forest SliceDone).
    let lp0 = Instant::now();
    let mut leaf_prove_ms = vec![0.0f64; t]; // by global leaf index
    let mut leaf_verify_sum = 0.0f64;
    let mut leaf_proofs: Vec<Option<Vec<u8>>> = (0..t).map(|_| None).collect();
    let mut busy = vec![0.0f64; machines_eff];
    let mut fold = vec![0.0f64; machines_eff];
    let mut merges_local = 0u32;
    let mut comm_msgs = 0u64;
    let mut comm_bytes = 0u64;
    let mut comm_ms_measured = 0.0f64;

    let mut pending_leaves = t;
    // Chain and forest both fold in-worker and send a SliceDone; per_batch
    // does not fold.
    let mut pending_slices = if mode == StreamMode::PerBatch { 0 } else { machines_eff };
    while pending_leaves > 0 || pending_slices > 0 {
        match next_event(&rx)? {
            Event::Worker(id, msg, _at, bytes) => {
                if let Some(f) = fatal_msg(&msg) {
                    return Err(f);
                }
                let w = id as usize;
                match msg {
                    FromWorker::LeafDone {
                        idx,
                        prove_ms,
                        verify_ms,
                        cascade_ms,
                        cascade_merges,
                        proof,
                        context,
                    } => {
                        let g = ranges[w].0 + idx as usize; // global leaf index
                        leaf_prove_ms[g] = prove_ms;
                        leaf_verify_sum += verify_ms;
                        busy[w] += prove_ms + cascade_ms;
                        fold[w] += cascade_ms;
                        merges_local += cascade_merges;
                        if let Some(p) = proof {
                            // per_batch only: a real cross-machine transfer
                            // (leaf → the auditor's proof store). Counted once.
                            comm_msgs += 1;
                            comm_bytes += bytes;
                            leaf_proofs[g] = Some(p);
                        }
                        ctx.on_leaf(mode, g + 1, context)?;
                        pending_leaves -= 1;
                    }
                    FromWorker::SliceDone { finalize_ms, finalize_merges, root } => {
                        busy[w] += finalize_ms;
                        fold[w] += finalize_ms;
                        merges_local += finalize_merges;
                        ctx.on_slice(w, ranges[w], root)?;
                        pending_slices -= 1;
                    }
                    other => {
                        let _ = other;
                        return Err("unexpected worker message in slice phase".into());
                    }
                }
            }
            Event::Gone(id) => return Err(format!("machine {id} died (socket closed)")),
        }
    }
    let leafgen_ms = lp0.elapsed().as_secs_f64() * 1000.0;
    let leafgen_seq_ms: f64 = leaf_prove_ms.iter().sum();

    // ── Composition phase.
    let mp0 = Instant::now();
    let mut merges_cross = 0u32;
    let mut cross_rounds = 0u32;
    let mut round_max_bytes: Vec<u64> = Vec::new();

    let root_bytes: Option<Vec<u8>> = match mode {
        StreamMode::PerBatch => {
            // Auditor's proof store: Θ(t) files. The auditor verifies every
            // stored leaf below (pinned leaf VK + STARK + statement vs log).
            let _ = std::fs::remove_dir_all(proof_dir);
            std::fs::create_dir_all(proof_dir).map_err(|e| format!("proof dir: {e}"))?;
            for (i, p) in leaf_proofs.iter().enumerate() {
                let p = p.as_ref().expect("per_batch leaf proof");
                std::fs::write(proof_dir.join(format!("leaf_{i:04}.bin")), p)
                    .map_err(|e| format!("write leaf: {e}"))?;
            }
            None
        }
        // Chain and forest both fold in-worker; the whole-stream root ends up
        // on machine 0. The chain (1 machine) needs no cross-machine rounds —
        // it folded the entire stream in place, so composition here is just
        // fetching the root. The forest first runs its log₂M reduction rounds.
        StreamMode::Chain | StreamMode::Forest => {
            // Reduction rounds over live slice roots (forest, machines_eff>1):
            // stride doubling; receiver k merges sender k+stride's root.
            // Transfers within a round go first (so receivers merge
            // concurrently), then all Merged replies are drained. (Chain:
            // machines_eff==1, so the loop body never runs — zero cross-machine
            // composition traffic.)
            let mut stride = 1usize;
            while stride < machines_eff {
                let pairs: Vec<(usize, usize)> = (0..machines_eff)
                    .step_by(2 * stride)
                    .filter_map(|k| (k + stride < machines_eff).then_some((k, k + stride)))
                    .collect();
                if pairs.is_empty() {
                    break;
                }
                cross_rounds += 1;
                let mut max_bytes = 0u64;
                for &(recv_id, send_id) in &pairs {
                    let x0 = Instant::now();
                    send_msg(&mut worker_tx[send_id], &ToWorker::FetchRoot)
                        .map_err(|e| format!("fetch root {send_id}: {e}"))?;
                    let root = loop {
                        match next_event(&rx)? {
                            Event::Worker(id, FromWorker::Root { proof }, _, bytes)
                                if id as usize == send_id =>
                            {
                                comm_msgs += 1;
                                comm_bytes += bytes;
                                max_bytes = max_bytes.max(bytes);
                                break proof;
                            }
                            Event::Worker(_, msg, ..) => {
                                if let Some(f) = fatal_msg(&msg) {
                                    return Err(f);
                                }
                                return Err("unexpected message awaiting round root".into());
                            }
                            Event::Gone(id) => return Err(format!("machine {id} died")),
                        }
                    };
                    send_msg(&mut worker_tx[recv_id], &ToWorker::MergeWith { right_proof: root })
                        .map_err(|e| format!("merge-with {recv_id}: {e}"))?;
                    comm_ms_measured += x0.elapsed().as_secs_f64() * 1000.0;
                }
                for _ in &pairs {
                    loop {
                        match next_event(&rx)? {
                            Event::Worker(_, FromWorker::Merged { .. }, ..) => {
                                merges_cross += 1;
                                break;
                            }
                            Event::Worker(_, msg, ..) => {
                                if let Some(f) = fatal_msg(&msg) {
                                    return Err(f);
                                }
                                return Err("unexpected message awaiting Merged".into());
                            }
                            Event::Gone(id) => return Err(format!("machine {id} died")),
                        }
                    }
                }
                round_max_bytes.push(max_bytes);
                stride *= 2;
            }
            // The whole-stream root lives on machine 0.
            send_msg(&mut worker_tx[0], &ToWorker::FetchRoot)
                .map_err(|e| format!("fetch final root: {e}"))?;
            let root = loop {
                match next_event(&rx)? {
                    Event::Worker(0, FromWorker::Root { proof }, _, bytes) => {
                        comm_msgs += 1;
                        comm_bytes += bytes;
                        break proof;
                    }
                    Event::Worker(_, msg, ..) => {
                        if let Some(f) = fatal_msg(&msg) {
                            return Err(f);
                        }
                        return Err("unexpected message awaiting final root".into());
                    }
                    Event::Gone(id) => return Err(format!("machine {id} died")),
                }
            };
            Some(root)
        }
    };
    let merge_ms = mp0.elapsed().as_secs_f64() * 1000.0;
    let total_time_ms = t_start.elapsed().as_secs_f64() * 1000.0;

    // ── Auditor: verify the received proof bytes against a trusted VK and
    // bind their exposed statement to the public batch log (Com(S_0),
    // Com(S_T), Com(B_1..B_T)), recomputed natively from the batches.
    let log = crate::recursion::recursive::expose_forest::batch_log(
        &anchor,
        &final_commit,
        &batch_commits(family, m, batches),
    );
    let layout = composition_expose();
    if layout != Expose::Interval {
        warn_boundary_layout("dist_compose auditor");
    }
    let (proof_bytes, verify_ms) = match &root_bytes {
        None => {
            // per_batch: the Θ(t) artifact. Every leaf proof is verified
            // against the trusted LEAF VK, derived from public parameters
            // outside the timed verify ([`audit_leaf_bytes`]).
            let bytes: Vec<&[u8]> = leaf_proofs
                .iter()
                .map(|p| p.as_deref().expect("per_batch leaf proof"))
                .collect();
            let sum: u64 = bytes.iter().map(|p| p.len() as u64).sum();
            (sum, audit_leaf_bytes(family, &shape, m, &bytes, &log, layout, leaf_verify_sum)?)
        }
        Some(bytes) => {
            let proof: Proof =
                postcard::from_bytes(bytes).map_err(|e| format!("root decode: {e}"))?;
            let (ini, fin) = read_exposed_boundary_proof(&proof);
            if ini.0 != anchor || fin.0 != final_commit {
                return Err("root boundary != native (Com(S_0), Com(S_E))".into());
            }
            // The bracketing the machines composed.
            let tree = dist_tree_shape(mode, t, machines);
            let interval = layout == Expose::Interval;
            if t == 1 {
                // A one-batch stream: the "root" is the lone LEAF proof. The
                // aggregation verifier cannot check it (it lacks the sketch's
                // tables), so it is verified like a per_batch leaf: pinned to
                // the trusted leaf VK, STARK-verified, statement vs the log.
                (bytes.len() as u64, audit_leaf_bytes(family, &shape, m, &[bytes], &log, layout, leaf_verify_sum)?)
            } else {
                // The auditor pins the root's VK (commitment + metadata) to a
                // trusted copy from `EXP_ROOT_VK` (see [`RootVkSource`]),
                // resolved outside the timed verify; the pin is a fixed-size
                // equality check, negligible next to STARK-table verification.
                // Interval layout (default): the root statement is then
                // checked against the log (lo = 1, hi = T, Com(S_0), Com(S_T),
                // and the ordered-batch digest recomputed natively under the
                // dist bracketing) — O(T) native hashes, inside the timed
                // verify.
                let expected_root_vk = resolve_root_vk(
                    || vk_pin_values(&proof),
                    || derive_dist_root_vk(family, &shape, m, mode, t, machines),
                )?;
                let v0 = Instant::now();
                if interval {
                    verify_bound_stark_proof_against_log(&proof, &expected_root_vk, &log, &tree);
                } else {
                    verify_bound_stark_proof_pinned(&proof, &expected_root_vk);
                }
                (bytes.len() as u64, v0.elapsed().as_secs_f64() * 1000.0)
            }
        }
    };

    // ── Wind down children; collect peak RSS.
    let mut peak_rss_mb = 0.0f64;
    for (i, s) in worker_tx.iter_mut().enumerate() {
        send_msg(s, &ToWorker::Exit).map_err(|e| format!("exit worker {i}: {e}"))?;
    }
    let mut done = machines_eff;
    while done > 0 {
        match next_event(&rx)? {
            Event::Worker(_, FromWorker::Done { peak_rss_mb: r }, ..) => {
                peak_rss_mb = peak_rss_mb.max(r);
                done -= 1;
            }
            Event::Gone(_) => done -= 1, // reader ended after Done
            _ => {}
        }
    }
    children.clear();
    let _ = std::fs::remove_file(&sock_path);

    // ── Mixed workload (non-empty query_at): prove the interleaved decode queries
    // on the coordinator — single-prover, θ(state) each — after the update
    // makespan. `total_time_ms` was captured at root-received above, so the
    // query cost stays in the separate `query_*` columns (S³'s sequential,
    // report-separately discipline), not folded into the distributed update
    // total. No-op (all zero) when the schedule is empty.
    // Each answer is pinned to the decode VK and bound to the certified
    // history by the certificates the workers shipped.
    let store = ctx.finish(query_at, &ranges, &leaf_proofs)?;
    let q = measure_queries_dist(
        family,
        shape,
        batches,
        mode,
        cores,
        query_at,
        query_key_mode,
        audit.as_mut().map(|a| (a, &store, &log)),
    )?;

    // ── Network models (critical path): scatter (parallel links, max) +
    // composition-path proof transfers + root delivery.
    let root_sz = root_bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    let leaf_sz_sum: u64 = leaf_proofs.iter().flatten().map(|p| p.len() as u64).sum();
    let per_worker_scatter: Vec<u64> = ranges
        .iter()
        .enumerate()
        .map(|(i, &(a, b))| {
            let st = postcard::to_allocvec(&slice_starts[i]).map(|v| v.len() as u64).unwrap_or(0);
            let da =
                postcard::to_allocvec(&batches[a..b].to_vec()).map(|v| v.len() as u64).unwrap_or(0);
            st + da
        })
        .collect();
    // Critical-path transfer time at the single modeled link bandwidth
    // `mbps` (Mb/s). Scatter uses parallel links (max); composition differs by
    // topology.
    let model = |mbps: f64| -> f64 {
        let scatter =
            per_worker_scatter.iter().map(|&b| xfer_ms(b, mbps, rtt_ms)).fold(0.0, f64::max);
        let compose = match mode {
            // Θ(t) leaf proofs funnel into the auditor's one store link.
            StreamMode::PerBatch => xfer_ms(leaf_sz_sum, mbps, rtt_ms * t as f64),
            // Chain folds in place on 1 machine — no leaf ever crosses; only
            // the single O(1) root is delivered to the auditor.
            StreamMode::Chain => xfer_ms(root_sz, mbps, rtt_ms),
            // Forest: log₂M reduction rounds (parallel pairwise links → max
            // transfer per round) + the O(1) root to the auditor.
            StreamMode::Forest => {
                round_max_bytes.iter().map(|&b| xfer_ms(b, mbps, rtt_ms)).sum::<f64>()
                    + xfer_ms(root_sz, mbps, rtt_ms)
            }
        };
        scatter + compose
    };

    Ok(DistCell {
        machines_eff,
        procs: machines_eff,
        witness_pass_ms,
        scatter_ms,
        scatter_state_bytes,
        scatter_data_bytes,
        leafgen_ms,
        leafgen_seq_ms,
        leaf_busy_min_ms: busy.iter().copied().fold(f64::INFINITY, f64::min),
        leaf_busy_max_ms: busy.iter().copied().fold(0.0, f64::max),
        local_fold_ms: fold.iter().copied().fold(0.0, f64::max),
        merges_local,
        merge_ms,
        merges_cross,
        cross_rounds,
        comm_msgs,
        comm_bytes,
        comm_ms_measured,
        comm_model_ms: model(mbps),
        proof_bytes,
        verify_ms,
        total_time_ms,
        peak_rss_mb,
        n_queries: q.n_queries,
        query_prove_ms: q.query_prove_ms,
        query_verify_ms: q.query_verify_ms,
        query_proof_bytes: q.query_proof_bytes,
        query_ctx_verifies: q.query_ctx_verifies,
        query_bind_ms: q.query_bind_ms,
    })
}

/// `EXP_COMPOSE_WAVE_SIZE=k` — number of machines that compute CONCURRENTLY in
/// staged-wave mode (must be a power of two; typically the NUMA-node count of
/// one "clean" placement, e.g. `2` with `EXP_COMPOSE_NODES=0,2`).
fn staged_wave_size() -> Option<usize> {
    std::env::var("EXP_COMPOSE_WAVE_SIZE").ok().and_then(|v| v.parse::<usize>().ok())
}

/// One reduction round's pair transfers + Merged drain (star relay through the
/// coordinator, identical accounting to the concurrent engine): per pair
/// `(recv, send)` — FetchRoot→send, Root→coordinator (counted once),
/// MergeWith→recv; then one `Merged` drained per pair. Returns the round's
/// largest transfer for the network model.
#[allow(clippy::too_many_arguments)]
fn run_round_pairs(
    pairs: &[(usize, usize)],
    worker_tx: &mut [UnixStream],
    rx: &mpsc::Receiver<Event>,
    comm_msgs: &mut u64,
    comm_bytes: &mut u64,
    comm_ms_measured: &mut f64,
    merges_cross: &mut u32,
) -> Result<u64, String> {
    let mut max_bytes = 0u64;
    for &(recv_id, send_id) in pairs {
        let x0 = Instant::now();
        send_msg(&mut worker_tx[send_id], &ToWorker::FetchRoot)
            .map_err(|e| format!("fetch root {send_id}: {e}"))?;
        let root = loop {
            match next_event(rx)? {
                Event::Worker(id, FromWorker::Root { proof }, _, bytes)
                    if id as usize == send_id =>
                {
                    *comm_msgs += 1;
                    *comm_bytes += bytes;
                    max_bytes = max_bytes.max(bytes);
                    break proof;
                }
                Event::Worker(_, msg, ..) => {
                    if let Some(f) = fatal_msg(&msg) {
                        return Err(f);
                    }
                    return Err("unexpected message awaiting round root".into());
                }
                Event::Gone(id) => return Err(format!("machine {id} died")),
            }
        };
        send_msg(&mut worker_tx[recv_id], &ToWorker::MergeWith { right_proof: root })
            .map_err(|e| format!("merge-with {recv_id}: {e}"))?;
        *comm_ms_measured += x0.elapsed().as_secs_f64() * 1000.0;
    }
    for _ in pairs {
        loop {
            match next_event(rx)? {
                Event::Worker(_, FromWorker::Merged { .. }, ..) => {
                    *merges_cross += 1;
                    break;
                }
                Event::Worker(_, msg, ..) => {
                    if let Some(f) = fatal_msg(&msg) {
                        return Err(f);
                    }
                    return Err("unexpected message awaiting Merged".into());
                }
                Event::Gone(id) => return Err(format!("machine {id} died")),
            }
        }
    }
    Ok(max_bytes)
}

/// Staged-wave variant of [`measure_compose_dist`] (FOREST only, BabyBear
/// only), dispatched when `EXP_COMPOSE_WAVE_SIZE=k < machines_eff`. Machine
/// `i` belongs to wave `i/k`; waves execute one after another, gated by
/// delaying each wave's `Task` scatter (workers block in [`worker_main`]
/// until their Task arrives), so with `EXP_COMPOSE_NODES=0,2` every emulated
/// machine computes on a full NUMA node with no co-resident sibling from this
/// experiment — the placement M physically separate servers would have.
///
/// Everything is REAL: leaf proofs, local cascades, intra-wave reduction
/// folds run inside each wave on live workers; cross-wave rounds and the
/// final root fetch run after the last wave on the same still-alive workers
/// (idle workers block on `recv` and consume no cycles). The root is fetched
/// and auditor-verified exactly as in the concurrent engine. Only the
/// SCHEDULE is time-shifted; the reported times are the makespan COMPOSED
/// over the merge DAG from measured spans:
///   `total = pre (witness+spawn+handshake) + max_w(wave_wall_w) + cross_wall`
/// which is what M concurrent machines would give, because waves have no
/// cross-wave dependency before the cross rounds (contiguous slices are
/// independent until their subtree roots meet). `wave_size` must be a power
/// of two so strides `< wave_size` are exactly the intra-wave rounds. The
/// serialized wall-clock is printed to stderr for transparency; the CSV
/// `exec` column records `staged`.
#[allow(clippy::too_many_arguments)]
fn measure_compose_dist_staged(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    cores: usize,
    machines: usize,
    proof_dir: &Path,
    mbps: f64,
    rtt_ms: f64,
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
    wave_size: usize,
) -> Result<DistCell, String> {
    assert!(!batches.is_empty(), "need at least one batch");
    assert!(wave_size.is_power_of_two(), "EXP_COMPOSE_WAVE_SIZE must be a power of two");
    let mode = StreamMode::Forest;
    let m = batches[0].len();
    let t = batches.len();
    let total_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    let ranges = slice_ranges(t, machines);
    let machines_eff = ranges.len();
    // Only one wave computes at a time — the concurrency budget is the wave.
    if wave_size * cores > total_cpus {
        return Err(format!(
            "oversubscribed: wave of {wave_size} machines x {cores} cores > {total_cpus} CPUs"
        ));
    }

    // Mixed workload: the query-side auditor (decode VK + prefix auditor),
    // derived from public parameters before the timed run; the workers then
    // ship each query's prefix certificate ([`CtxCollector`]).
    let mut audit = if query_at.is_empty() { None } else { QueryAudit::new(family, &shape, m) };
    let mut ctx = CtxCollector::new(audit.is_some(), mode, machines_eff);

    let t_start = Instant::now();

    // ── Witness pass (identical to the concurrent engine).
    let wp0 = Instant::now();
    let mut state = FamState::empty(family, &shape, m);
    let anchor = state.commit(&shape);
    let mut slice_starts: Vec<WireState> = Vec::with_capacity(machines_eff);
    let mut next_slice = 0usize;
    for (i, batch) in batches.iter().enumerate() {
        if next_slice < ranges.len() && ranges[next_slice].0 == i {
            slice_starts.push(state.encode());
            next_slice += 1;
        }
        state.advance(&shape, batch);
    }
    let final_commit = state.commit(&shape);
    let witness_pass_ms = wp0.elapsed().as_secs_f64() * 1000.0;

    // ── Spawn ALL machines up front; they block awaiting their Task.
    let sock_path = std::env::temp_dir().join(format!(
        "zks_dc_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).map_err(|e| format!("bind socket: {e}"))?;
    let exe = stable_self_exe()?;
    let spawn_child = |role: &str, id: usize, lo: usize, hi: usize| -> Result<ChildGuard, String> {
        let mut cmd = pinned_command(&exe, lo, hi);
        cmd.env(ENV_ROLE, role)
            .env(ENV_SOCK, &sock_path)
            .env(ENV_ID, id.to_string())
            .env(ENV_CORES, cores.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        cmd.spawn().map(ChildGuard).map_err(|e| format!("spawn {role} {id}: {e}"))
    };
    let mut children: Vec<ChildGuard> = Vec::new();
    for i in 0..machines_eff {
        let (lo, hi) = machine_core_range(i, cores, machines_eff);
        children.push(spawn_child("worker", i, lo, hi)?);
    }
    let (tx, rx) = mpsc::channel::<Event>();
    let mut worker_tx: Vec<Option<UnixStream>> = (0..machines_eff).map(|_| None).collect();
    for _ in 0..machines_eff {
        let (mut s, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let (hello, _) = recv_msg::<FromWorker>(&mut s).map_err(|e| format!("hello: {e}"))?;
        let FromWorker::Hello { id } = hello else { return Err("bad hello".into()) };
        let reader = s.try_clone().map_err(|e| format!("clone: {e}"))?;
        spawn_worker_reader(id, reader, tx.clone());
        worker_tx[id as usize] = Some(s);
    }
    let mut worker_tx: Vec<UnixStream> =
        worker_tx.into_iter().map(|s| s.expect("all workers connected")).collect();

    // Everything before the first wave would also precede concurrent leaves.
    let pre_ms = t_start.elapsed().as_secs_f64() * 1000.0;

    // ── Waves: scatter → collect → intra-wave reduction, one wave at a time.
    let mut scatter_ms = 0.0f64;
    let (mut scatter_state_bytes, mut scatter_data_bytes) = (0u64, 0u64);
    let mut leaf_prove_ms = vec![0.0f64; t];
    let mut leaf_verify_sum = 0.0f64;
    let mut busy = vec![0.0f64; machines_eff];
    let mut fold = vec![0.0f64; machines_eff];
    let mut merges_local = 0u32;
    let (mut comm_msgs, mut comm_bytes) = (0u64, 0u64);
    let mut comm_ms_measured = 0.0f64;
    let mut merges_cross = 0u32;
    let mut stride_max: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();
    let mut wave_leaf_walls: Vec<f64> = Vec::new();
    let mut wave_walls: Vec<f64> = Vec::new();

    let waves = machines_eff.div_ceil(wave_size);
    for wv in 0..waves {
        let wave_lo = wv * wave_size;
        let wave_hi = ((wv + 1) * wave_size).min(machines_eff);
        let wave_t0 = Instant::now();

        let sc0 = Instant::now();
        for i in wave_lo..wave_hi {
            let (a, b) = ranges[i];
            let start = slice_starts[i].clone();
            scatter_state_bytes +=
                postcard::to_allocvec(&start).map(|v| v.len() as u64).unwrap_or(0);
            let slice: Vec<Vec<u32>> = batches[a..b].to_vec();
            scatter_data_bytes +=
                postcard::to_allocvec(&slice).map(|v| v.len() as u64).unwrap_or(0);
            send_msg(
                &mut worker_tx[i],
                &ToWorker::Task {
                    family: family.label().into(),
                    mode: mode.label().into(),
                    shape: WireShape::from(&shape),
                    m: m as u32,
                    start,
                    batches: slice,
                    first_index: a as u64 + 1,
                    checkpoints: ctx.checkpoints(query_at, (a, b)),
                    ship_root: ctx.ship_root(query_at, (a, b)),
                },
            )
            .map_err(|e| format!("scatter to {i}: {e}"))?;
        }
        scatter_ms += sc0.elapsed().as_secs_f64() * 1000.0;

        let mut pending_leaves: usize = (wave_lo..wave_hi).map(|i| ranges[i].1 - ranges[i].0).sum();
        let mut pending_slices = wave_hi - wave_lo;
        while pending_leaves > 0 || pending_slices > 0 {
            match next_event(&rx)? {
                Event::Worker(id, msg, _at, _bytes) => {
                    if let Some(f) = fatal_msg(&msg) {
                        return Err(f);
                    }
                    let w = id as usize;
                    match msg {
                        FromWorker::LeafDone {
                            idx, prove_ms, verify_ms, cascade_ms, cascade_merges, context, ..
                        } => {
                            let g = ranges[w].0 + idx as usize;
                            leaf_prove_ms[g] = prove_ms;
                            leaf_verify_sum += verify_ms;
                            busy[w] += prove_ms + cascade_ms;
                            fold[w] += cascade_ms;
                            merges_local += cascade_merges;
                            ctx.on_leaf(mode, g + 1, context)?;
                            pending_leaves -= 1;
                        }
                        FromWorker::SliceDone { finalize_ms, finalize_merges, root } => {
                            busy[w] += finalize_ms;
                            fold[w] += finalize_ms;
                            merges_local += finalize_merges;
                            ctx.on_slice(w, ranges[w], root)?;
                            pending_slices -= 1;
                        }
                        _ => return Err("unexpected worker message in staged slice phase".into()),
                    }
                }
                Event::Gone(id) => return Err(format!("machine {id} died (socket closed)")),
            }
        }
        wave_leaf_walls.push(wave_t0.elapsed().as_secs_f64() * 1000.0);

        // Intra-wave reduction rounds: strides < wave_size stay inside an
        // aligned power-of-two wave block.
        let mut stride = 1usize;
        while stride < wave_size {
            let pairs: Vec<(usize, usize)> = (wave_lo..wave_hi)
                .step_by(2 * stride)
                .filter_map(|k| (k + stride < wave_hi).then_some((k, k + stride)))
                .collect();
            if !pairs.is_empty() {
                let mb = run_round_pairs(
                    &pairs,
                    &mut worker_tx,
                    &rx,
                    &mut comm_msgs,
                    &mut comm_bytes,
                    &mut comm_ms_measured,
                    &mut merges_cross,
                )?;
                let e = stride_max.entry(stride).or_insert(0);
                *e = (*e).max(mb);
            }
            stride *= 2;
        }
        wave_walls.push(wave_t0.elapsed().as_secs_f64() * 1000.0);
    }
    let leafgen_seq_ms: f64 = leaf_prove_ms.iter().sum();

    // ── Cross-wave rounds + final root fetch (workers still alive and idle;
    // the machines that fold here have released their cores' compute).
    let cx0 = Instant::now();
    let mut stride = wave_size;
    while stride < machines_eff {
        let pairs: Vec<(usize, usize)> = (0..machines_eff)
            .step_by(2 * stride)
            .filter_map(|k| (k + stride < machines_eff).then_some((k, k + stride)))
            .collect();
        if !pairs.is_empty() {
            let mb = run_round_pairs(
                &pairs,
                &mut worker_tx,
                &rx,
                &mut comm_msgs,
                &mut comm_bytes,
                &mut comm_ms_measured,
                &mut merges_cross,
            )?;
            let e = stride_max.entry(stride).or_insert(0);
            *e = (*e).max(mb);
        }
        stride *= 2;
    }
    send_msg(&mut worker_tx[0], &ToWorker::FetchRoot)
        .map_err(|e| format!("fetch final root: {e}"))?;
    let root = loop {
        match next_event(&rx)? {
            Event::Worker(0, FromWorker::Root { proof }, _, bytes) => {
                comm_msgs += 1;
                comm_bytes += bytes;
                break proof;
            }
            Event::Worker(_, msg, ..) => {
                if let Some(f) = fatal_msg(&msg) {
                    return Err(f);
                }
                return Err("unexpected message awaiting final root".into());
            }
            Event::Gone(id) => return Err(format!("machine {id} died")),
        }
    };
    let cross_ms = cx0.elapsed().as_secs_f64() * 1000.0;
    let root_bytes: Option<Vec<u8>> = Some(root);

    // ── Composed makespan: waves are independent until the cross rounds, so
    // concurrently they'd finish at max(wave walls).
    let max_wave_wall = wave_walls.iter().copied().fold(0.0, f64::max);
    let leafgen_ms = wave_leaf_walls.iter().copied().fold(0.0, f64::max);
    let intra_merge_max = wave_walls
        .iter()
        .zip(&wave_leaf_walls)
        .map(|(w, l)| w - l)
        .fold(0.0, f64::max);
    let merge_ms = intra_merge_max + cross_ms;
    let total_time_ms = pre_ms + max_wave_wall + cross_ms;
    let cross_rounds = stride_max.len() as u32;
    let round_max_bytes: Vec<u64> = stride_max.values().copied().collect();
    eprintln!(
        "    staged: {waves} waves x {wave_size} | wave walls {:?}s | composed total {:.1}s (serialized wall {:.1}s)",
        wave_walls.iter().map(|w| (w / 1000.0 * 10.0).round() / 10.0).collect::<Vec<_>>(),
        total_time_ms / 1000.0,
        t_start.elapsed().as_secs_f64(),
    );

    // ── Auditor verify (identical to the concurrent engine, forest root path).
    let (proof_bytes, verify_ms) = {
        let bytes = root_bytes.as_ref().expect("forest root");
        let proof: Proof = postcard::from_bytes(bytes).map_err(|e| format!("root decode: {e}"))?;
        let (ini, fin) = read_exposed_boundary_proof(&proof);
        if ini.0 != anchor || fin.0 != final_commit {
            return Err("root boundary != native (Com(S_0), Com(S_E))".into());
        }
        let log = crate::recursion::recursive::expose_forest::batch_log(
            &anchor,
            &final_commit,
            &batch_commits(family, m, batches),
        );
        let tree = dist_tree_shape(mode, t, machines);
        let layout = composition_expose();
        let interval = layout == Expose::Interval;
        if !interval {
            warn_boundary_layout("dist_compose (staged) auditor");
        }
        if t == 1 {
            // Lone leaf (unreachable in practice: staging needs >= 2 slices):
            // verified like a per_batch leaf ([`audit_leaf_bytes`]).
            (bytes.len() as u64, audit_leaf_bytes(family, &shape, m, &[bytes], &log, layout, leaf_verify_sum)?)
        } else {
            // Staged waves pair aligned power-of-two machine blocks, so the
            // tree is the concurrent engine's `dist_forest(t, machines)`.
            let expected_root_vk = resolve_root_vk(
                || vk_pin_values(&proof),
                || derive_dist_root_vk(family, &shape, m, mode, t, machines),
            )?;
            let v0 = Instant::now();
            if interval {
                verify_bound_stark_proof_against_log(&proof, &expected_root_vk, &log, &tree);
            } else {
                verify_bound_stark_proof_pinned(&proof, &expected_root_vk);
            }
            (bytes.len() as u64, v0.elapsed().as_secs_f64() * 1000.0)
        }
    };

    // ── Wind down; collect peak RSS.
    let mut peak_rss_mb = 0.0f64;
    for (i, s) in worker_tx.iter_mut().enumerate() {
        send_msg(s, &ToWorker::Exit).map_err(|e| format!("exit worker {i}: {e}"))?;
    }
    let mut done = machines_eff;
    while done > 0 {
        match next_event(&rx)? {
            Event::Worker(_, FromWorker::Done { peak_rss_mb: r }, ..) => {
                peak_rss_mb = peak_rss_mb.max(r);
                done -= 1;
            }
            Event::Gone(_) => done -= 1,
            _ => {}
        }
    }
    children.clear();
    let _ = std::fs::remove_file(&sock_path);

    // Each answer is pinned to the decode VK and bound to the certified
    // history by the certificates the workers shipped.
    let store = ctx.finish(query_at, &ranges, &[])?;
    let qlog = crate::recursion::recursive::expose_forest::batch_log(
        &anchor,
        &final_commit,
        &batch_commits(family, m, batches),
    );
    let q = measure_queries_dist(
        family,
        shape,
        batches,
        mode,
        cores,
        query_at,
        query_key_mode,
        audit.as_mut().map(|a| (a, &store, &qlog)),
    )?;

    // ── Network model (forest path only).
    let root_sz = root_bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    let per_worker_scatter: Vec<u64> = ranges
        .iter()
        .enumerate()
        .map(|(i, &(a, b))| {
            let st = postcard::to_allocvec(&slice_starts[i]).map(|v| v.len() as u64).unwrap_or(0);
            let da =
                postcard::to_allocvec(&batches[a..b].to_vec()).map(|v| v.len() as u64).unwrap_or(0);
            st + da
        })
        .collect();
    let model = |mbps: f64| -> f64 {
        let scatter =
            per_worker_scatter.iter().map(|&b| xfer_ms(b, mbps, rtt_ms)).fold(0.0, f64::max);
        let compose = round_max_bytes.iter().map(|&b| xfer_ms(b, mbps, rtt_ms)).sum::<f64>()
            + xfer_ms(root_sz, mbps, rtt_ms);
        scatter + compose
    };

    Ok(DistCell {
        machines_eff,
        procs: machines_eff,
        witness_pass_ms,
        scatter_ms,
        scatter_state_bytes,
        scatter_data_bytes,
        leafgen_ms,
        leafgen_seq_ms,
        leaf_busy_min_ms: busy.iter().copied().fold(f64::INFINITY, f64::min),
        leaf_busy_max_ms: busy.iter().copied().fold(0.0, f64::max),
        local_fold_ms: fold.iter().copied().fold(0.0, f64::max),
        merges_local,
        merge_ms,
        merges_cross,
        cross_rounds,
        comm_msgs,
        comm_bytes,
        comm_ms_measured,
        comm_model_ms: model(mbps),
        proof_bytes,
        verify_ms,
        total_time_ms,
        peak_rss_mb,
        n_queries: q.n_queries,
        query_prove_ms: q.query_prove_ms,
        query_verify_ms: q.query_verify_ms,
        query_proof_bytes: q.query_proof_bytes,
        query_ctx_verifies: q.query_ctx_verifies,
        query_bind_ms: q.query_bind_ms,
    })
}

/// Goldilocks (`_gl`) analog of [`measure_compose_dist`] — a copy with the SAME
/// signature, changing ONLY the config-typed islands: gl plaintext state
/// ([`FamStateGl`]), gl digest-width-4 commitments (`[crate::config_gl::Val; 4]`
/// instead of `[Val; 8]`), the `"worker_gl"` child role, `ProofGl` deserialize,
/// and the `expose_forest_gl` boundary/verify helpers. The gl families have no
/// query decode provers, so a non-empty `query_at` panics. Every other line
/// (scatter, slice phase, reduction rounds, timing, DistCell construction) is
/// byte/metric-identical to the BabyBear engine.
#[allow(clippy::too_many_arguments)]
pub fn measure_compose_dist_gl(
    family: StreamFamily,
    shape: StreamShape,
    batches: &[Vec<u32>],
    mode: StreamMode,
    cores: usize,
    machines: usize,
    proof_dir: &Path,
    mbps: f64,
    rtt_ms: f64,
    query_at: &[usize],
    query_key_mode: QueryKeyMode,
) -> Result<DistCell, String> {
    let _ = query_key_mode;
    if !family.is_gl() {
        return Err(format!(
            "{} has no Goldilocks leaf: the Goldilocks engine runs only the _gl families \
             (cm_gl, hll_gl, ss_gl, gk_gl); use measure_compose_dist for BabyBear",
            family.label()
        ));
    }
    assert!(!batches.is_empty(), "need at least one batch");
    let m = batches[0].len();
    let t = batches.len();
    let total_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    // The chain is inherently sequential — pin it to ONE machine (it folds in
    // place). per_batch/forest distribute leaves over up to `machines`.
    let machines = if mode == StreamMode::Chain { 1 } else { machines };
    let ranges = slice_ranges(t, machines);
    let machines_eff = ranges.len();
    if machines_eff * cores > total_cpus {
        return Err(format!(
            "oversubscribed: {machines_eff} machines x {cores} cores > {total_cpus} CPUs"
        ));
    }

    let t_start = Instant::now();

    // ── Witness pass: one sequential plaintext replay; record slice-start
    // states and the native anchor/final commitments.
    let wp0 = Instant::now();
    let mut state = FamStateGl::empty(family, &shape, m);
    let anchor = state.commit(&shape);
    let mut slice_starts: Vec<WireState> = Vec::with_capacity(machines_eff);
    let mut next_slice = 0usize;
    for (i, batch) in batches.iter().enumerate() {
        if next_slice < ranges.len() && ranges[next_slice].0 == i {
            slice_starts.push(state.encode());
            next_slice += 1;
        }
        state.advance(&shape, batch);
    }
    let final_commit = state.commit(&shape);
    let witness_pass_ms = wp0.elapsed().as_secs_f64() * 1000.0;

    // ── Spawn the machines.
    let sock_path = std::env::temp_dir().join(format!(
        "zks_dc_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).map_err(|e| format!("bind socket: {e}"))?;
    let exe = stable_self_exe()?;

    let spawn_child = |role: &str, id: usize, lo: usize, hi: usize| -> Result<ChildGuard, String> {
        let mut cmd = pinned_command(&exe, lo, hi);
        cmd.env(ENV_ROLE, role)
            .env(ENV_SOCK, &sock_path)
            .env(ENV_ID, id.to_string())
            .env(ENV_CORES, cores.to_string())
            .stdout(Stdio::null()) // keep the coordinator's stdout clean
            .stderr(Stdio::inherit());
        cmd.spawn().map(ChildGuard).map_err(|e| format!("spawn {role} {id}: {e}"))
    };

    let mut children: Vec<ChildGuard> = Vec::new();
    for i in 0..machines_eff {
        let (lo, hi) = machine_core_range(i, cores, machines_eff);
        children.push(spawn_child("worker_gl", i, lo, hi)?);
    }

    // Handshake: map connections by Hello id.
    let (tx, rx) = mpsc::channel::<Event>();
    let mut worker_tx: Vec<Option<UnixStream>> = (0..machines_eff).map(|_| None).collect();
    for _ in 0..machines_eff {
        let (mut s, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let (hello, _) = recv_msg::<FromWorker>(&mut s).map_err(|e| format!("hello: {e}"))?;
        let FromWorker::Hello { id } = hello else { return Err("bad hello".into()) };
        let reader = s.try_clone().map_err(|e| format!("clone: {e}"))?;
        spawn_worker_reader(id, reader, tx.clone());
        worker_tx[id as usize] = Some(s);
    }
    let mut worker_tx: Vec<UnixStream> =
        worker_tx.into_iter().map(|s| s.expect("all workers connected")).collect();

    // ── Scatter: each machine gets its slice-start state + its batches.
    let sc0 = Instant::now();
    let (mut scatter_state_bytes, mut scatter_data_bytes) = (0u64, 0u64);
    for (i, &(a, b)) in ranges.iter().enumerate() {
        let start = slice_starts[i].clone();
        scatter_state_bytes +=
            postcard::to_allocvec(&start).map(|v| v.len() as u64).unwrap_or(0);
        let slice: Vec<Vec<u32>> = batches[a..b].to_vec();
        scatter_data_bytes += postcard::to_allocvec(&slice).map(|v| v.len() as u64).unwrap_or(0);
        send_msg(
            &mut worker_tx[i],
            &ToWorker::Task {
                family: family.label().into(),
                mode: mode.label().into(),
                shape: WireShape::from(&shape),
                m: m as u32,
                start,
                batches: slice,
                first_index: a as u64 + 1,
                checkpoints: Vec::new(),
                ship_root: false,
            },
        )
        .map_err(|e| format!("scatter to {i}: {e}"))?;
    }
    let scatter_ms = sc0.elapsed().as_secs_f64() * 1000.0;

    // ── Slice phase: collect every LeafDone (+ forest SliceDone).
    let lp0 = Instant::now();
    let mut leaf_prove_ms = vec![0.0f64; t]; // by global leaf index
    let mut leaf_verify_sum = 0.0f64;
    let mut leaf_proofs: Vec<Option<Vec<u8>>> = (0..t).map(|_| None).collect();
    let mut busy = vec![0.0f64; machines_eff];
    let mut fold = vec![0.0f64; machines_eff];
    let mut merges_local = 0u32;
    let mut comm_msgs = 0u64;
    let mut comm_bytes = 0u64;
    let mut comm_ms_measured = 0.0f64;

    let mut pending_leaves = t;
    // Chain and forest both fold in-worker and send a SliceDone; per_batch
    // does not fold.
    let mut pending_slices = if mode == StreamMode::PerBatch { 0 } else { machines_eff };
    while pending_leaves > 0 || pending_slices > 0 {
        match next_event(&rx)? {
            Event::Worker(id, msg, _at, bytes) => {
                if let Some(f) = fatal_msg(&msg) {
                    return Err(f);
                }
                let w = id as usize;
                match msg {
                    FromWorker::LeafDone {
                        idx,
                        prove_ms,
                        verify_ms,
                        cascade_ms,
                        cascade_merges,
                        proof,
                        ..
                    } => {
                        let g = ranges[w].0 + idx as usize; // global leaf index
                        leaf_prove_ms[g] = prove_ms;
                        leaf_verify_sum += verify_ms;
                        busy[w] += prove_ms + cascade_ms;
                        fold[w] += cascade_ms;
                        merges_local += cascade_merges;
                        if let Some(p) = proof {
                            // per_batch only: a real cross-machine transfer
                            // (leaf → the auditor's proof store). Counted once.
                            comm_msgs += 1;
                            comm_bytes += bytes;
                            leaf_proofs[g] = Some(p);
                        }
                        pending_leaves -= 1;
                    }
                    FromWorker::SliceDone { finalize_ms, finalize_merges, .. } => {
                        busy[w] += finalize_ms;
                        fold[w] += finalize_ms;
                        merges_local += finalize_merges;
                        pending_slices -= 1;
                    }
                    other => {
                        let _ = other;
                        return Err("unexpected worker message in slice phase".into());
                    }
                }
            }
            Event::Gone(id) => return Err(format!("machine {id} died (socket closed)")),
        }
    }
    let leafgen_ms = lp0.elapsed().as_secs_f64() * 1000.0;
    let leafgen_seq_ms: f64 = leaf_prove_ms.iter().sum();

    // ── Composition phase.
    let mp0 = Instant::now();
    let mut merges_cross = 0u32;
    let mut cross_rounds = 0u32;
    let mut round_max_bytes: Vec<u64> = Vec::new();

    let root_bytes: Option<Vec<u8>> = match mode {
        StreamMode::PerBatch => {
            // Auditor's proof store: Θ(t) files. The auditor verifies every
            // stored leaf below (pinned leaf VK + STARK + statement vs log).
            let _ = std::fs::remove_dir_all(proof_dir);
            std::fs::create_dir_all(proof_dir).map_err(|e| format!("proof dir: {e}"))?;
            for (i, p) in leaf_proofs.iter().enumerate() {
                let p = p.as_ref().expect("per_batch leaf proof");
                std::fs::write(proof_dir.join(format!("leaf_{i:04}.bin")), p)
                    .map_err(|e| format!("write leaf: {e}"))?;
            }
            None
        }
        // Chain and forest both fold in-worker; the whole-stream root ends up
        // on machine 0. The chain (1 machine) needs no cross-machine rounds —
        // it folded the entire stream in place, so composition here is just
        // fetching the root. The forest first runs its log₂M reduction rounds.
        StreamMode::Chain | StreamMode::Forest => {
            // Reduction rounds over live slice roots (forest, machines_eff>1):
            // stride doubling; receiver k merges sender k+stride's root.
            // Transfers within a round go first (so receivers merge
            // concurrently), then all Merged replies are drained. (Chain:
            // machines_eff==1, so the loop body never runs — zero cross-machine
            // composition traffic.)
            let mut stride = 1usize;
            while stride < machines_eff {
                let pairs: Vec<(usize, usize)> = (0..machines_eff)
                    .step_by(2 * stride)
                    .filter_map(|k| (k + stride < machines_eff).then_some((k, k + stride)))
                    .collect();
                if pairs.is_empty() {
                    break;
                }
                cross_rounds += 1;
                let mut max_bytes = 0u64;
                for &(recv_id, send_id) in &pairs {
                    let x0 = Instant::now();
                    send_msg(&mut worker_tx[send_id], &ToWorker::FetchRoot)
                        .map_err(|e| format!("fetch root {send_id}: {e}"))?;
                    let root = loop {
                        match next_event(&rx)? {
                            Event::Worker(id, FromWorker::Root { proof }, _, bytes)
                                if id as usize == send_id =>
                            {
                                comm_msgs += 1;
                                comm_bytes += bytes;
                                max_bytes = max_bytes.max(bytes);
                                break proof;
                            }
                            Event::Worker(_, msg, ..) => {
                                if let Some(f) = fatal_msg(&msg) {
                                    return Err(f);
                                }
                                return Err("unexpected message awaiting round root".into());
                            }
                            Event::Gone(id) => return Err(format!("machine {id} died")),
                        }
                    };
                    send_msg(&mut worker_tx[recv_id], &ToWorker::MergeWith { right_proof: root })
                        .map_err(|e| format!("merge-with {recv_id}: {e}"))?;
                    comm_ms_measured += x0.elapsed().as_secs_f64() * 1000.0;
                }
                for _ in &pairs {
                    loop {
                        match next_event(&rx)? {
                            Event::Worker(_, FromWorker::Merged { .. }, ..) => {
                                merges_cross += 1;
                                break;
                            }
                            Event::Worker(_, msg, ..) => {
                                if let Some(f) = fatal_msg(&msg) {
                                    return Err(f);
                                }
                                return Err("unexpected message awaiting Merged".into());
                            }
                            Event::Gone(id) => return Err(format!("machine {id} died")),
                        }
                    }
                }
                round_max_bytes.push(max_bytes);
                stride *= 2;
            }
            // The whole-stream root lives on machine 0.
            send_msg(&mut worker_tx[0], &ToWorker::FetchRoot)
                .map_err(|e| format!("fetch final root: {e}"))?;
            let root = loop {
                match next_event(&rx)? {
                    Event::Worker(0, FromWorker::Root { proof }, _, bytes) => {
                        comm_msgs += 1;
                        comm_bytes += bytes;
                        break proof;
                    }
                    Event::Worker(_, msg, ..) => {
                        if let Some(f) = fatal_msg(&msg) {
                            return Err(f);
                        }
                        return Err("unexpected message awaiting final root".into());
                    }
                    Event::Gone(id) => return Err(format!("machine {id} died")),
                }
            };
            Some(root)
        }
    };
    let merge_ms = mp0.elapsed().as_secs_f64() * 1000.0;
    let total_time_ms = t_start.elapsed().as_secs_f64() * 1000.0;

    // ── Auditor: verify the received proof bytes against a trusted VK and
    // bind their exposed statement to the public batch log, recomputed
    // natively from the batches.
    let log = crate::recursion::recursive::expose_forest_gl::batch_log(
        &anchor,
        &final_commit,
        &batch_commits_gl(family, m, batches),
    );
    let layout = composition_expose();
    if layout != Expose::Interval {
        warn_boundary_layout("dist_compose (gl) auditor");
    }
    let (proof_bytes, verify_ms) = match &root_bytes {
        None => {
            // per_batch: the Θ(t) artifact; every leaf is verified against
            // the trusted leaf VK ([`audit_leaf_bytes_gl`]).
            let bytes: Vec<&[u8]> = leaf_proofs
                .iter()
                .map(|p| p.as_deref().expect("per_batch leaf proof"))
                .collect();
            let sum: u64 = bytes.iter().map(|p| p.len() as u64).sum();
            (sum, audit_leaf_bytes_gl(family, &shape, m, &bytes, &log, layout, leaf_verify_sum)?)
        }
        Some(bytes) => {
            let proof: ProofGl =
                postcard::from_bytes(bytes).map_err(|e| format!("root decode: {e}"))?;
            let (ini, fin) =
                crate::recursion::recursive::expose_forest_gl::read_exposed_boundary_proof(&proof);
            if ini.0 != anchor || fin.0 != final_commit {
                return Err("root boundary != native (Com(S_0), Com(S_E))".into());
            }
            let tree = dist_tree_shape(mode, t, machines);
            let interval = layout == Expose::Interval;
            if t == 1 {
                // A one-batch stream: the lone LEAF proof, verified like a
                // per_batch leaf (pinned leaf VK, STARK, statement vs log).
                (bytes.len() as u64, audit_leaf_bytes_gl(family, &shape, m, &[bytes], &log, layout, leaf_verify_sum)?)
            } else {
                // The auditor pins the root's VK (commitment + metadata) to a
                // trusted copy from `EXP_ROOT_VK` (see [`RootVkSource`]),
                // resolved outside the timed verify; Interval layout (default)
                // then checks the root statement against the batch log.
                let expected_root_vk = resolve_root_vk(
                    || crate::recursion::recursive::expose_forest_gl::vk_pin_values(&proof),
                    || derive_dist_root_vk_gl(family, &shape, m, mode, t, machines),
                )?;
                let v0 = Instant::now();
                if interval {
                    crate::recursion::recursive::expose_forest_gl::verify_bound_stark_proof_against_log(
                        &proof,
                        &expected_root_vk,
                        &log,
                        &tree,
                    );
                } else {
                    crate::recursion::recursive::expose_forest_gl::verify_bound_stark_proof_pinned(
                        &proof,
                        &expected_root_vk,
                    );
                }
                (bytes.len() as u64, v0.elapsed().as_secs_f64() * 1000.0)
            }
        }
    };

    // ── Wind down children; collect peak RSS.
    let mut peak_rss_mb = 0.0f64;
    for (i, s) in worker_tx.iter_mut().enumerate() {
        send_msg(s, &ToWorker::Exit).map_err(|e| format!("exit worker {i}: {e}"))?;
    }
    let mut done = machines_eff;
    while done > 0 {
        match next_event(&rx)? {
            Event::Worker(_, FromWorker::Done { peak_rss_mb: r }, ..) => {
                peak_rss_mb = peak_rss_mb.max(r);
                done -= 1;
            }
            Event::Gone(_) => done -= 1, // reader ended after Done
            _ => {}
        }
    }
    children.clear();
    let _ = std::fs::remove_file(&sock_path);

    // ── Mixed workload: the Goldilocks families have NO query decode provers,
    // so an empty schedule reports all-zero query metrics and a non-empty one
    // panics (use the non-`_gl` family token for query experiments).
    let q = if query_at.is_empty() {
        super::stream_compose::QueryAgg::default()
    } else {
        panic!("query workloads are not supported for the Goldilocks (_gl) families")
    };

    // ── Network models (critical path): scatter (parallel links, max) +
    // composition-path proof transfers + root delivery.
    let root_sz = root_bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    let leaf_sz_sum: u64 = leaf_proofs.iter().flatten().map(|p| p.len() as u64).sum();
    let per_worker_scatter: Vec<u64> = ranges
        .iter()
        .enumerate()
        .map(|(i, &(a, b))| {
            let st = postcard::to_allocvec(&slice_starts[i]).map(|v| v.len() as u64).unwrap_or(0);
            let da =
                postcard::to_allocvec(&batches[a..b].to_vec()).map(|v| v.len() as u64).unwrap_or(0);
            st + da
        })
        .collect();
    // Critical-path transfer time at the single modeled link bandwidth
    // `mbps` (Mb/s). Scatter uses parallel links (max); composition differs by
    // topology.
    let model = |mbps: f64| -> f64 {
        let scatter =
            per_worker_scatter.iter().map(|&b| xfer_ms(b, mbps, rtt_ms)).fold(0.0, f64::max);
        let compose = match mode {
            // Θ(t) leaf proofs funnel into the auditor's one store link.
            StreamMode::PerBatch => xfer_ms(leaf_sz_sum, mbps, rtt_ms * t as f64),
            // Chain folds in place on 1 machine — no leaf ever crosses; only
            // the single O(1) root is delivered to the auditor.
            StreamMode::Chain => xfer_ms(root_sz, mbps, rtt_ms),
            // Forest: log₂M reduction rounds (parallel pairwise links → max
            // transfer per round) + the O(1) root to the auditor.
            StreamMode::Forest => {
                round_max_bytes.iter().map(|&b| xfer_ms(b, mbps, rtt_ms)).sum::<f64>()
                    + xfer_ms(root_sz, mbps, rtt_ms)
            }
        };
        scatter + compose
    };

    Ok(DistCell {
        machines_eff,
        procs: machines_eff,
        witness_pass_ms,
        scatter_ms,
        scatter_state_bytes,
        scatter_data_bytes,
        leafgen_ms,
        leafgen_seq_ms,
        leaf_busy_min_ms: busy.iter().copied().fold(f64::INFINITY, f64::min),
        leaf_busy_max_ms: busy.iter().copied().fold(0.0, f64::max),
        local_fold_ms: fold.iter().copied().fold(0.0, f64::max),
        merges_local,
        merge_ms,
        merges_cross,
        cross_rounds,
        comm_msgs,
        comm_bytes,
        comm_ms_measured,
        comm_model_ms: model(mbps),
        proof_bytes,
        verify_ms,
        total_time_ms,
        peak_rss_mb,
        n_queries: q.n_queries,
        query_prove_ms: q.query_prove_ms,
        query_verify_ms: q.query_verify_ms,
        query_proof_bytes: q.query_proof_bytes,
        query_ctx_verifies: q.query_ctx_verifies,
        query_bind_ms: q.query_bind_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> StreamShape {
        StreamShape { d: 4, w: 8, b: 4, capacity: 4, gk_s: 2, bloom_k: 3, bloom_log_w: 7 }
    }

    /// Every family's state survives the wire codec mid-stream: encode after
    /// some batches, decode, and both sides advance to identical commitments.
    #[test]
    fn wire_state_round_trips_all_families() {
        let sh = shape();
        let batch_a: Vec<u32> = (1..=4).collect();
        let batch_b: Vec<u32> = (5..=8).collect();
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
            StreamFamily::BloomOmc,
        ] {
            let mut orig = FamState::empty(family, &sh, 4);
            orig.advance(&sh, &batch_a);
            let wire = orig.encode();
            let bytes = postcard::to_allocvec(&wire).unwrap();
            let decoded_wire: WireState = postcard::from_bytes(&bytes).unwrap();
            let mut copy = FamState::decode(&decoded_wire, 4);
            assert_eq!(copy.commit(&sh), orig.commit(&sh), "{family:?} decode == encode");
            copy.advance(&sh, &batch_b);
            orig.advance(&sh, &batch_b);
            assert_eq!(copy.commit(&sh), orig.commit(&sh), "{family:?} advance after round-trip");
        }
    }

    /// The witness-pass slice split is contiguous, covers [0, t), and honours
    /// the machine count.
    #[test]
    fn slice_ranges_cover_contiguously() {
        for (t, m) in [(8, 4), (7, 4), (3, 4), (1, 1), (64, 4), (10, 3)] {
            let r = slice_ranges(t, m);
            assert!(r.len() <= m);
            assert_eq!(r[0].0, 0);
            assert_eq!(r.last().unwrap().1, t);
            for w in r.windows(2) {
                assert_eq!(w[0].1, w[1].0, "contiguous");
            }
        }
    }

    /// The auditor's VK-derivation leaf input is a provable NO-OP for every
    /// family (native commitment unchanged), so the no-op leaf's boundary is
    /// self-contiguous — which `root_vk_deriver` requires.
    #[test]
    fn noop_leaf_input_is_a_noop_for_all_families() {
        let sh = shape();
        let m = 4;
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
            StreamFamily::BloomOmc,
        ] {
            let mut st = FamState::empty(family, &sh, m);
            let (setup, batch) = noop_leaf_input(family, m);
            if !setup.is_empty() {
                st.advance(&sh, &setup);
            }
            let before = st.commit(&sh);
            st.advance(&sh, &batch);
            assert_eq!(st.commit(&sh), before, "{family:?}: no-op leaf input must not move the state");
        }
        for family in [
            StreamFamily::CmOmcGl,
            StreamFamily::HllOmcGl,
            StreamFamily::SsCertifiedGl,
            StreamFamily::GkBandmerge2Gl,
        ] {
            let mut st = FamStateGl::empty(family, &sh, m);
            let (setup, batch) = noop_leaf_input(family, m);
            if !setup.is_empty() {
                st.advance(&sh, &setup);
            }
            let before = st.commit(&sh);
            st.advance(&sh, &batch);
            assert_eq!(st.commit(&sh), before, "{family:?}: no-op leaf input must not move the state");
        }
    }

    /// END-TO-END (auditor `EXP_ROOT_VK=derive` path): replay a dist forest
    /// in-process exactly as the workers fold it — per-machine slice cascades,
    /// then stride-doubling rounds over WIRE-ROUND-TRIPPED roots — and check
    /// that `derive_dist_root_vk` (public parameters only) reproduces the real
    /// root's VK and metadata, and that the auditor's pinned verify accepts it.
    /// `t = 3` leaves on `M = 2` machines: slices of 2 and 1 leaves.
    fn assert_dist_root_vk_derivable(family: StreamFamily) {
        let sh = shape();
        let m = 4;
        let (t, machines) = (3usize, 2usize);
        let batches: Vec<Vec<u32>> = (0..t as u32).map(|i| (1..=4).map(|k| k * 7 + i * 13).collect()).collect();
        let mut leaf = FamLeafCircuit::build(family, &sh, m);
        let mut st = FamState::empty(family, &sh, m);
        let mut outputs = Vec::new();
        for (i, b) in batches.iter().enumerate() {
            outputs.push(st.prove_leaf(&mut leaf, i as u64 + 1, b).0);
            st.advance(&sh, b);
        }
        let wire = |p: &Proof| -> Proof {
            postcard::from_bytes(&postcard::to_allocvec(p).unwrap()).unwrap()
        };
        // Machine 0 folds leaves [0, 2) (cascade), machine 1 holds leaf 2.
        let slice0 = prove_hiding_merge(&outputs[0], &outputs[1]);
        let root = prove_hiding_merge_proofs(&slice0.0, &wire(&outputs[2].0));
        let tree = dist_tree_shape(StreamMode::Forest, t, machines);
        assert_eq!(tree.num_leaves(), t);
        let derived = derive_dist_root_vk(family, &sh, m, StreamMode::Forest, t, machines);
        assert_eq!(derived.commitment, vk_pin_values(&root.0), "{family:?}: derived dist root VK");
        assert_eq!(
            derived.shape,
            Some(crate::recursion::recursive::root_vk::bound_proof_shape(&root.0)),
            "{family:?}: derived dist root metadata"
        );
        verify_bound_stark_proof_pinned(&wire(&root.0), &derived);
        // (e) The default auditor path: derived VK + the batch log the
        // harness computes natively (Interval statement, the default layout).
        assert_eq!(composition_expose(), Expose::Interval, "default layout");
        let log = stream_batch_log(family, &sh, m, &batches);
        verify_bound_stark_proof_against_log(&wire(&root.0), &derived, &log, &tree);
        // A log with batches 1 and 2 swapped is rejected.
        let mut swapped = batches.clone();
        swapped.swap(0, 1);
        let bad = BatchLog { batch_commits: batch_commits(family, m, &swapped).iter().map(|c| c.to_vec()).collect(), ..log.clone() };
        assert!(
            crate::recursion::recursive::expose_forest::check_root_against_log(&root.0, &bad, &tree)
                .is_err(),
            "{family:?}: a reordered log must not match the root"
        );
    }

    #[test]
    fn dist_root_vk_derivable_cm_omc() {
        assert_dist_root_vk_derivable(StreamFamily::CmOmc);
    }

    #[test]
    fn dist_root_vk_derivable_hll_omc() {
        assert_dist_root_vk_derivable(StreamFamily::HllOmc);
    }

    #[test]
    fn dist_root_vk_derivable_bloom_omc() {
        assert_dist_root_vk_derivable(StreamFamily::BloomOmc);
    }

    /// The Bloom wire state is packed 8 bits per byte (an exact round trip,
    /// including a partial last byte), and the Goldilocks engine rejects the
    /// BabyBear-only Bloom family cleanly instead of reaching a gl-only
    /// state constructor.
    #[test]
    fn bloom_wire_state_packs_bits_and_gl_engine_rejects_bloom() {
        let sh = shape();
        let m = 4;
        let mut st = FamState::empty(StreamFamily::BloomOmc, &sh, m);
        st.advance(&sh, &[3, 9, PAD_KEY, PAD_KEY]);
        let WireState::Bloom { cells, packed, .. } = st.encode() else { panic!("bloom wire state") };
        assert_eq!(cells as usize, sh.bloom_k << sh.bloom_log_w);
        assert_eq!(packed.len(), (cells as usize).div_ceil(8), "8 bits per byte");
        assert!(packed.iter().any(|&b| b != 0), "inserted bits survive packing");
        let mut odd = FamState::Bloom(BloomOmcParams { k: 1, log_w: 7, batch: m }, vec![0u8; 128]);
        if let FamState::Bloom(_, bits) = &mut odd {
            bits[127] = 1;
            bits[3] = 1;
        }
        let back = FamState::decode(&odd.encode(), m);
        assert_eq!(back.commit(&sh), odd.commit(&sh), "exact bit round trip");
        let r = measure_compose_dist_gl(
            StreamFamily::BloomOmc,
            sh,
            &[vec![1, 2, 3, 4]],
            StreamMode::Forest,
            1,
            1,
            &std::env::temp_dir(),
            200.0,
            0.2,
            &[],
            QueryKeyMode::First,
        );
        assert!(r.as_ref().is_err_and(|e| e.contains("no Goldilocks leaf")), "{:?}", r.err());
    }

    /// The coordinator's LEAF audit ([`audit_leaf_bytes`], per_batch and the
    /// lone leaf `t == 1`), for every family on both fields, over wire bytes:
    /// (1) the honest leaves (t = 1, 2) verify against the leaf VK derived
    /// from public parameters — so the one public-parameter leaf verifier
    /// serves each family's leaf circuit; (2) THE REVIEWED ATTACK: a toy
    /// circuit that only exposes leaf 1's honest statement passes the pre-fix
    /// statement-only check and is rejected by the audit; (3) a one-leaf log
    /// (the lone-leaf path) is audited the same way. Skipped when
    /// `EXP_ROOT_VK` overrides the derived VK.
    #[test]
    fn dist_leaf_audit_pins_leaf_vk_all_families() {
        if std::env::var("EXP_ROOT_VK").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "derive") {
            eprintln!("skipped: EXP_ROOT_VK overrides the derived VK");
            return;
        }
        use p3_field::BasedVectorSpace;
        let sh = shape();
        let m = 4;
        let batches: Vec<Vec<u32>> = (0..2u32).map(|i| (1..=4).map(|k| k * 7 + i * 13).collect()).collect();
        let layout = composition_expose();
        assert_eq!(layout, Expose::Interval, "default layout");
        for family in [
            StreamFamily::CmOmc,
            StreamFamily::HllOmc,
            StreamFamily::SsCertified,
            StreamFamily::GkBandmerge2,
            StreamFamily::BloomOmc,
        ] {
            let mut leaf = FamLeafCircuit::build(family, &sh, m);
            let mut st = FamState::empty(family, &sh, m);
            let mut bytes = Vec::new();
            for (i, b) in batches.iter().enumerate() {
                bytes.push(postcard::to_allocvec(&st.prove_leaf(&mut leaf, i as u64 + 1, b).0 .0).unwrap());
                st.advance(&sh, b);
            }
            let refs: Vec<&[u8]> = bytes.iter().map(|b| b.as_slice()).collect();
            let log = stream_batch_log(family, &sh, m, &batches);
            let ms = audit_leaf_bytes(family, &sh, m, &refs, &log, layout, -1.0);
            assert!(ms.as_ref().is_ok_and(|&ms| ms >= 0.0), "{family:?} honest per_batch: {ms:?}");
            let lone_log = stream_batch_log(family, &sh, m, &batches[..1]);
            assert!(audit_leaf_bytes(family, &sh, m, &refs[..1], &lone_log, layout, -1.0).is_ok(), "{family:?} lone leaf");
            // The toy mimicking leaf 1's statement.
            let l1: Proof = postcard::from_bytes(&bytes[0]).unwrap();
            let v = crate::recursion::recursive::expose_forest::read_exposed_statement(&l1).values();
            let cs: Vec<crate::config::Challenge> = v
                .chunks(4)
                .map(|c| crate::config::Challenge::from_basis_coefficients_slice(c).unwrap())
                .collect();
            let toy = crate::recursion::recursive::expose_forest::prove_exposing_leaf(&cs);
            let toy_bytes = postcard::to_allocvec(&toy.0).unwrap();
            assert_eq!(
                check_leaves_against_log(&[&toy.0], &lone_log, layout),
                Ok(()),
                "{family:?}: the pre-fix statement-only check accepts the toy"
            );
            for (what, set, lg) in [
                ("per_batch", vec![toy_bytes.as_slice(), refs[1]], &log),
                ("lone leaf", vec![toy_bytes.as_slice()], &lone_log),
            ] {
                let r = audit_leaf_bytes(family, &sh, m, &set, lg, layout, -1.0);
                println!("B6B dist leaf audit {family:?} {what} toy: {r:?}");
                assert!(r.is_err_and(|e| e.contains("leaf 1")), "{family:?} {what}");
            }
        }
        for family in [
            StreamFamily::CmOmcGl,
            StreamFamily::HllOmcGl,
            StreamFamily::SsCertifiedGl,
            StreamFamily::GkBandmerge2Gl,
        ] {
            use crate::recursion::recursive::expose_forest_gl as efg;
            let mut leaf = FamLeafCircuitGl::build(family, &sh, m);
            let mut st = FamStateGl::empty(family, &sh, m);
            let init = st.commit(&sh);
            let mut bytes = Vec::new();
            for (i, b) in batches.iter().enumerate() {
                bytes.push(postcard::to_allocvec(&st.prove_leaf(&mut leaf, i as u64 + 1, b).0 .0).unwrap());
                st.advance(&sh, b);
            }
            let refs: Vec<&[u8]> = bytes.iter().map(|b| b.as_slice()).collect();
            let commits = batch_commits_gl(family, m, &batches);
            let log = efg::batch_log(&init, &st.commit(&sh), &commits);
            let ms = audit_leaf_bytes_gl(family, &sh, m, &refs, &log, layout, -1.0);
            assert!(ms.as_ref().is_ok_and(|&ms| ms >= 0.0), "{family:?} honest per_batch: {ms:?}");
            let l1: ProofGl = postcard::from_bytes(&bytes[0]).unwrap();
            let v = efg::read_exposed_statement(&l1).values();
            let cs: Vec<crate::config_gl::Challenge> = v
                .chunks(2)
                .map(|c| crate::config_gl::Challenge::from_basis_coefficients_slice(c).unwrap())
                .collect();
            let toy_bytes = postcard::to_allocvec(&efg::prove_exposing_leaf(&cs).0).unwrap();
            let set = vec![toy_bytes.as_slice(), refs[1]];
            let decoded: Vec<ProofGl> = set.iter().map(|b| postcard::from_bytes(b).unwrap()).collect();
            let drefs: Vec<&ProofGl> = decoded.iter().collect();
            assert_eq!(efg::check_leaves_against_log(&drefs, &log, layout), Ok(()), "{family:?}: pre-fix accepts");
            let r = audit_leaf_bytes_gl(family, &sh, m, &set, &log, layout, -1.0);
            println!("B6B dist leaf audit {family:?} per_batch toy: {r:?}");
            assert!(r.is_err_and(|e| e.contains("leaf 1")), "{family:?}");
        }
    }

    /// Transfer model: bytes·8 / (Mb/s · 1e6) · 1000 + RTT.
    #[test]
    fn xfer_model_math() {
        // 25 MB at 200 Mb/s = 1.0 s (+0.2 ms rtt).
        let ms = xfer_ms(25_000_000, 200.0, 0.2);
        assert!((ms - 1000.2).abs() < 1e-6);
    }
}
