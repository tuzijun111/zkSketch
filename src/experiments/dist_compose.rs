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
//! - **Disjoint physical-core pinning.** Machine `i` is pinned (via
//!   `numactl --physcpubind` when available, falling back to `taskset -c`)
//!   to CPUs `[i·cores, (i+1)·cores)` and NUMA-membound to the socket that
//!   owns them. On a 2×64-core EPYC, 4 machines × 32 cores occupy exactly
//!   the 128 physical cores with every SMT sibling left idle — machines do
//!   not contend for execution units, caches, or (with membind) DRAM.
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
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, OnceLock};
use std::time::Instant;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::Val;
use crate::recursion::recursive::config::ConfigWithFriParams;
use crate::recursion::recursive::expose_forest::{
    prove_hiding_merge, prove_hiding_merge_proofs, read_exposed_boundary_proof,
    verify_bound_stark_proof,
};
use crate::recursion::recursive::timing;
use p3_circuit_prover::BatchStarkProof;
use p3_recursion::RecursionOutput;

use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::countmin_final::apply_update_prf;
use crate::sketch::countmin_omc::{prove_countmin_omc_exposed, CmOmcParams};
use crate::sketch::gk_bandmerge::{
    apply_batch2, commit_gk2_state, prove_gkb2_exposed, Gk2State, Gk2Tuple, GkbParams,
};
use crate::sketch::hll_omc::{
    commit_hll_omc, hll_omc_advance, hll_omc_empty, prove_hll_omc_exposed, HllOmcParams,
};
use crate::sketch::ss_final_full::{
    apply_batch_ss_full, commit_ss_state, prove_ss_full_exposed, SsFullParams, SsFullRow,
    SsFullState, SsFullUpdate,
};

use super::families::cm_empty;
use super::stream_compose::{StreamFamily, StreamMode, StreamShape};

use crate::commitment::countmin::commit_countmin;

type Proof = BatchStarkProof<ConfigWithFriParams>;

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
}

/// Local plaintext state a machine advances and proves against. `advance`
/// mirrors `stream_compose::prove_leaves` exactly (incl. the per-family key
/// masks) — a divergence would break the in-circuit boundary bind.
enum FamState {
    Cm(CountMinState),
    Hll(Vec<u64>),
    Ss(SsFullState),
    Gk(Gk2State),
}

/// The per-family key masks `stream_compose` applies before proving.
fn ss_updates(batch: &[u32]) -> Vec<SsFullUpdate> {
    batch.iter().map(|&k| SsFullUpdate::real(((k & 0x1FFF_FFFF) | 1) as u64, 1)).collect()
}
fn gk_vals(batch: &[u32]) -> Vec<u32> {
    batch.iter().map(|&k| k & 0x001F_FFFF).collect()
}
fn cm_updates(batch: &[u32]) -> Vec<CountMinUpdate> {
    batch.iter().map(|&k| CountMinUpdate { key: k as u64, value: 1 }).collect()
}
fn hll_keys(batch: &[u32]) -> Vec<u64> {
    batch.iter().map(|&k| k as u64).collect()
}

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
        }
    }

    /// Apply one batch in plaintext (the witness-pass step).
    fn advance(&mut self, shape: &StreamShape, batch: &[u32]) {
        match self {
            Self::Cm(state) => {
                for u in &cm_updates(batch) {
                    apply_update_prf(state, u);
                }
            }
            Self::Hll(regs) => hll_omc_advance(regs, &hll_keys(batch), 1usize << shape.b),
            Self::Ss(state) => *state = apply_batch_ss_full(state, &ss_updates(batch)).0,
            Self::Gk(state) => *state = apply_batch2(state, &gk_vals(batch)),
        }
    }

    /// Native state commitment (the auditor's anchor / final reference).
    fn commit(&self, shape: &StreamShape) -> [Val; 8] {
        match self {
            Self::Cm(state) => commit_countmin(state).0,
            Self::Hll(regs) => commit_hll_omc(regs, shape.b),
            Self::Ss(state) => commit_ss_state(state).0,
            Self::Gk(state) => commit_gk2_state(state).0,
        }
    }

    /// Prove one transition leaf from the current state over `batch`.
    /// Returns the boundary-exposing output plus the prover's self-timings.
    fn prove_leaf(
        &self,
        shape: &StreamShape,
        m: usize,
        batch: &[u32],
    ) -> (RecursionOutput<ConfigWithFriParams>, f64, f64) {
        let output = match self {
            Self::Cm(state) => {
                prove_countmin_omc_exposed(
                    CmOmcParams { d: shape.d, w: shape.w, batch: m },
                    state.clone(),
                    cm_updates(batch),
                )
                .output
            }
            Self::Hll(regs) => {
                prove_hll_omc_exposed(
                    HllOmcParams { b: shape.b, batch: m },
                    regs.clone(),
                    hll_keys(batch),
                )
                .output
            }
            Self::Ss(state) => {
                prove_ss_full_exposed(
                    SsFullParams { capacity: shape.capacity, batch: m },
                    state.clone(),
                    ss_updates(batch),
                )
                .output
            }
            Self::Gk(state) => {
                prove_gkb2_exposed(
                    GkbParams { capacity: shape.capacity, batch: m, s: shape.gk_s },
                    state.clone(),
                    gk_vals(batch),
                )
                .output
            }
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
}

impl WireShape {
    fn from(s: &StreamShape) -> Self {
        Self {
            d: s.d as u32,
            w: s.w as u32,
            b: s.b as u32,
            capacity: s.capacity as u32,
            gk_s: s.gk_s,
        }
    }
    fn to_shape(self) -> StreamShape {
        StreamShape {
            d: self.d as usize,
            w: self.w as usize,
            b: self.b as usize,
            capacity: self.capacity as usize,
            gk_s: self.gk_s,
        }
    }
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
    },
    /// Slice complete (forest: after finalizing the local root).
    SliceDone {
        finalize_ms: f64,
        finalize_merges: u32,
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
        let ToWorker::Task { family, mode, shape, m, start, batches } = task else {
            panic!("first message must be Task");
        };
        // The state's wire tag fixes the family; parse validates agreement.
        let _ = StreamFamily::parse(&family).expect("family");
        let mode = StreamMode::parse(&mode).expect("mode");
        let shape = shape.to_shape();
        let m = m as usize;
        let mut state = FamState::decode(&start, m);

        // Forest: Bentley–Saxe peak stack `(size, root)`, folded as we go.
        let mut peaks: Vec<(u64, RecursionOutput<ConfigWithFriParams>)> = Vec::new();
        // Chain: the running left-leaning prefix proof.
        let mut chain_acc: Option<RecursionOutput<ConfigWithFriParams>> = None;
        let mut root: Option<RecursionOutput<ConfigWithFriParams>> = None;

        for (i, batch) in batches.iter().enumerate() {
            let (output, prove_ms, verify_ms) = state.prove_leaf(&shape, m, batch);
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
                    let mut node = (1u64, output);
                    while peaks.last().is_some_and(|(sz, _)| *sz == node.0) {
                        let (_, left) = peaks.pop().unwrap();
                        node = (node.0 * 2, prove_hiding_merge(&left, &node.1));
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
                },
            )
            .expect("send LeafDone");
        }

        match mode {
            StreamMode::Chain => {
                // The prefix proof is already the whole-stream root.
                root = chain_acc;
                send_msg(s, &FromWorker::SliceDone { finalize_ms: 0.0, finalize_merges: 0 })
                    .expect("send SliceDone");
            }
            StreamMode::Forest => {
                // Finalize surviving peaks left-to-right into the slice root.
                let t0 = Instant::now();
                let mut merges = 0u32;
                let mut acc = peaks.remove(0).1;
                for (_, r) in peaks.drain(..) {
                    acc = prove_hiding_merge(&acc, &r);
                    merges += 1;
                }
                root = Some(acc);
                send_msg(
                    s,
                    &FromWorker::SliceDone {
                        finalize_ms: t0.elapsed().as_secs_f64() * 1000.0,
                        finalize_merges: merges,
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
) -> Result<DistCell, String> {
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
        children.push(spawn_child("worker", i, i * cores, (i + 1) * cores - 1)?);
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
                    FromWorker::SliceDone { finalize_ms, finalize_merges } => {
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
            // Auditor's proof store: Θ(t) files, plus the native anchor /
            // boundary-link checks over the exposed commitments.
            let _ = std::fs::remove_dir_all(proof_dir);
            std::fs::create_dir_all(proof_dir).map_err(|e| format!("proof dir: {e}"))?;
            let mut prev_final: Option<[Val; 8]> = None;
            for (i, p) in leaf_proofs.iter().enumerate() {
                let p = p.as_ref().expect("per_batch leaf proof");
                std::fs::write(proof_dir.join(format!("leaf_{i:04}.bin")), p)
                    .map_err(|e| format!("write leaf: {e}"))?;
                let proof: Proof =
                    postcard::from_bytes(p).map_err(|e| format!("leaf decode: {e}"))?;
                let (ini, fin) = read_exposed_boundary_proof(&proof);
                let expect = prev_final.unwrap_or(anchor);
                if ini.0 != expect {
                    return Err(format!("per-batch boundary/anchor break at leaf {i}"));
                }
                prev_final = Some(fin.0);
            }
            if prev_final != Some(final_commit) {
                return Err("per-batch final commitment mismatch".into());
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

    // ── Auditor: verify the received root bytes; bind its exposed boundary
    // to the natively recomputed (Com(S_0), Com(S_E)).
    let (proof_bytes, verify_ms) = match &root_bytes {
        None => {
            // per_batch: Θ(t) artifact; verify = Σ leaf self-verifies
            // (measured machine-side at prove time), links checked above.
            let sum: u64 = leaf_proofs.iter().flatten().map(|p| p.len() as u64).sum();
            (sum, leaf_verify_sum)
        }
        Some(bytes) => {
            let proof: Proof =
                postcard::from_bytes(bytes).map_err(|e| format!("root decode: {e}"))?;
            let (ini, fin) = read_exposed_boundary_proof(&proof);
            if ini.0 != anchor || fin.0 != final_commit {
                return Err("root boundary != native (Com(S_0), Com(S_E))".into());
            }
            if t == 1 {
                // Lone leaf: the aggregation verifier lacks the sketch's
                // Permute table (same caveat as the sim engine) — report the
                // leaf's own self-verify.
                (bytes.len() as u64, leaf_verify_sum)
            } else {
                let v0 = Instant::now();
                verify_bound_stark_proof(&proof);
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> StreamShape {
        StreamShape { d: 4, w: 8, b: 4, capacity: 4, gk_s: 2 }
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

    /// Transfer model: bytes·8 / (Mb/s · 1e6) · 1000 + RTT.
    #[test]
    fn xfer_model_math() {
        // 25 MB at 200 Mb/s = 1.0 s (+0.2 ms rtt).
        let ms = xfer_ms(25_000_000, 200.0, 0.2);
        assert!((ms - 1000.2).abs() < 1e-6);
    }
}
