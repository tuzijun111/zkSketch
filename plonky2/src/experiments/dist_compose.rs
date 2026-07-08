//! **Plonky2 streaming-composition runner** (four families + cross-family).
//!
//! - [`measure_fam`] — single-machine, in-process forest/chain/per_batch over
//!   any family (used by the unit tests).
//! - [`measure_compose_dist`] — the process-level distributed emulation: one
//!   pinned OS process per machine (`numactl`/`taskset`, disjoint physical
//!   cores + NUMA membind), serialized-socket IPC, the forest folding each
//!   machine's slice in place (Bentley–Saxe) then combining the `M` slice roots
//!   in `⌈log₂M⌉` reduction rounds shipping [`crate::recursion::MergeInput`]
//!   (proof + `CommonCircuitData` + verifier-only — plonky2's merge circuit is
//!   non-uniform, so the child's `common` travels with the proof). Communication
//!   bytes are measured; transfer time modeled at `EXP_NET_MBPS`/`EXP_NET_RTT_MS`.
//! - [`cross_family_pairs`] — compose four per-family forest roots pairwise via
//!   the §4.2 heterogeneous merge atom
//!   ([`merge_cross_family`](crate::recursion::topology::merge_cross_family)).
//!   That atom is pairwise (two `Node`s → a non-composable `CrossFamilyNode`),
//!   so all four families bind as two verified cross-family roots (cm⊕hll,
//!   ss⊕gk); a single root over all four would need a composable cross-family
//!   circuit (a follow-up, not the existing capability).

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, OnceLock};
use std::time::Instant;

use anyhow::{ensure, Result};
use plonky2::hash::hash_types::HashOut;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::F;
// CM composes via the SOUND offline-memory-checking leaf (`omc`, Θ(d·w)) — the
// same variant the plonky3 backend deploys — NOT the §5.1 one-hot strawman
// (Θ(batch·d·w)), which blows the selector budget at wide w (e.g. 7×16384).
// OMC threads the plaintext state via `apply_update_prf` (PRF column routing),
// which differs from the one-hot leaf's `state.update` (`hash_cell`).
use crate::leaf::countmin_final::apply_update_prf;
use crate::leaf::countmin_omc::{build_countmin_omc_leaf, CmOmcParams, CountMinOmcLeaf};
use crate::leaf::greenwald_khanna::{build_gk_leaf, GkLeafParams, GreenwaldKhannaLeaf};
// HLL likewise composes via its offline-memory-checking leaf (`hll_omc`,
// Θ(m + batch)) — the variant the plonky3 runner deploys as `hll_omc` — NOT the
// flat one-hot leaf (Θ(batch·m)), which blows the selector budget at large b
// (e.g. batch=16384 × m=2^14). Same routing (`hash_register`) and commit
// (Poseidon over the m registers), so `HllState` threads both variants.
use crate::leaf::hll_omc::{build_hll_omc_leaf, HllOmcLeaf, HllOmcParams};
use crate::leaf::spacesaving::{build_spacesaving_leaf, SpaceSavingLeaf, SsLeafParams};
use crate::recursion::topology::{compose_chain, merge_cross_family, verify_cross_family};
use crate::recursion::{merge, merge_wire, shrink_wire, verify_node, MergeInput, Node};
use crate::sketch::countmin::{CountMinParams, CountMinState, CountMinUpdate};
use crate::sketch::greenwald_khanna::{
    apply_batch as gk_apply_batch, GkParams, GkState, GkUpdate,
};
use crate::sketch::hyperloglog::{HllParams, HllState, HllUpdate};
use crate::sketch::spacesaving::{apply_batch as ss_apply_batch, SsParams, SsState, SsUpdate};

// ─── Family + shape ──────────────────────────────────────────────────────────

/// The four sketch families (each pinned to its deployed leaf variant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Cm,
    Hll,
    Ss,
    Gk,
}

impl Family {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cm" | "countmin" => Some(Self::Cm),
            "hll" | "hyperloglog" => Some(Self::Hll),
            "ss" | "spacesaving" => Some(Self::Ss),
            "gk" | "greenwald_khanna" | "greenwaldkhanna" => Some(Self::Gk),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Cm => "cm",
            Self::Hll => "hll",
            Self::Ss => "ss",
            Self::Gk => "gk",
        }
    }
}

/// Per-family shape knobs (only the relevant fields are used per family).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FamShape {
    pub d: usize,
    pub w: usize,
    pub b: usize,
    pub ss_cap: usize,
    pub gk_cap: usize,
    pub batch: usize,
}

// ─── Per-family key → update mapping (matches each leaf circuit's domain) ──────

fn cm_updates(keys: &[u64]) -> Vec<CountMinUpdate> {
    keys.iter().map(|&key| CountMinUpdate { key, value: 1 }).collect()
}
fn hll_updates(keys: &[u64]) -> Vec<HllUpdate> {
    keys.iter().map(|&key| HllUpdate { key }).collect()
}
fn ss_updates(keys: &[u64]) -> Vec<SsUpdate> {
    // SS key circuit range-checks keys to KEY_BITS=48; force non-zero so a real
    // key never collides with the 0 dummy.
    keys.iter().map(|&k| SsUpdate::real((k & 0xFFFF_FFFF_FFFF) | 1, 1)).collect()
}
fn gk_updates(keys: &[u64]) -> Vec<GkUpdate> {
    // GK is over values; the leaf range-checks values to VALUE_BITS=32.
    keys.iter().map(|&k| GkUpdate { value: k & 0xFFFF_FFFF, active: 1 }).collect()
}

// ─── FamState: plaintext state (witness pass + boundary commits) ──────────────

enum FamState {
    Cm(CountMinState),
    Hll(HllState),
    Ss(SsState),
    Gk(GkState),
}

impl FamState {
    fn empty(family: Family, sh: &FamShape) -> Self {
        match family {
            Family::Cm => Self::Cm(CountMinState::new(&CountMinParams { d: sh.d, w: sh.w })),
            Family::Hll => Self::Hll(HllState::new(&HllParams { b: sh.b })),
            Family::Ss => {
                Self::Ss(SsState::empty(SsParams { capacity: sh.ss_cap, batch: sh.batch }))
            }
            Family::Gk => {
                Self::Gk(GkState::empty(GkParams { capacity: sh.gk_cap, batch: sh.batch }))
            }
        }
    }

    fn advance(&mut self, keys: &[u64]) {
        match self {
            Self::Cm(s) => {
                // OMC routing (PRF), matching build_countmin_omc_leaf.
                for u in &cm_updates(keys) {
                    apply_update_prf(s, u);
                }
            }
            Self::Hll(s) => {
                for u in &hll_updates(keys) {
                    s.update(u);
                }
            }
            Self::Ss(s) => *s = ss_apply_batch(s, &ss_updates(keys)).0,
            Self::Gk(s) => *s = gk_apply_batch(s, &gk_updates(keys)).0,
        }
    }

    fn commit(&self) -> HashOut<F> {
        match self {
            Self::Cm(s) => s.commit(),
            Self::Hll(s) => s.commit(),
            Self::Ss(s) => s.commit(),
            Self::Gk(s) => s.commit(),
        }
    }

    fn encode(&self) -> WireState {
        match self {
            Self::Cm(s) => WireState::Cm {
                d: s.d as u32,
                w: s.w as u32,
                counters: s.counters.iter().flatten().copied().collect(),
            },
            Self::Hll(s) => WireState::Hll { b: s.b as u32, registers: s.registers.clone() },
            Self::Ss(s) => WireState::Ss {
                capacity: s.params.capacity as u32,
                batch: s.params.batch as u32,
                rows: s.rows.iter().map(|r| (r.key, r.count, r.active)).collect(),
            },
            Self::Gk(s) => WireState::Gk {
                capacity: s.params.capacity as u32,
                batch: s.params.batch as u32,
                tuples: s.tuples.iter().map(|t| (t.value, t.count, t.max_error, t.active)).collect(),
            },
        }
    }
}

// ─── FamLeaf: the built leaf circuit (one per worker, reused per epoch) ────────

enum FamLeaf {
    Cm(CountMinOmcLeaf),
    Hll(HllOmcLeaf),
    Ss(SpaceSavingLeaf),
    Gk(GreenwaldKhannaLeaf),
}

impl FamLeaf {
    fn build(family: Family, sh: &FamShape) -> Self {
        match family {
            Family::Cm => Self::Cm(build_countmin_omc_leaf(CmOmcParams { d: sh.d, w: sh.w, batch: sh.batch })),
            Family::Hll => Self::Hll(build_hll_omc_leaf(HllOmcParams { b: sh.b, batch: sh.batch })),
            Family::Ss => Self::Ss(build_spacesaving_leaf(SsLeafParams { capacity: sh.ss_cap, batch: sh.batch })),
            Family::Gk => Self::Gk(build_gk_leaf(GkLeafParams { capacity: sh.gk_cap, batch: sh.batch })),
        }
    }

    /// Prove one epoch from `state` over `keys`, returning the boundary node and
    /// its prove time (ms). `state` must be the same family as `self`.
    fn prove_leaf(&self, state: &FamState, keys: &[u64], index: u64) -> Result<(Node, f64)> {
        let t0 = Instant::now();
        let node = match (self, state) {
            (Self::Cm(l), FamState::Cm(s)) => l.prove(s, &cm_updates(keys), index)?,
            // omc takes raw keys (routes in-circuit) + the raw register array.
            (Self::Hll(l), FamState::Hll(s)) => l.prove(&s.registers, keys, index)?,
            (Self::Ss(l), FamState::Ss(s)) => l.prove(s, &ss_updates(keys), index)?,
            (Self::Gk(l), FamState::Gk(s)) => l.prove(s, &gk_updates(keys), index)?,
            _ => anyhow::bail!("FamLeaf/FamState family mismatch"),
        };
        Ok((node, t0.elapsed().as_secs_f64() * 1000.0))
    }
}

// ─── WireState: serializable plaintext state per family ───────────────────────

#[derive(Clone, Serialize, Deserialize)]
enum WireState {
    Cm { d: u32, w: u32, counters: Vec<u64> },
    Hll { b: u32, registers: Vec<u64> },
    Ss { capacity: u32, batch: u32, rows: Vec<(u64, u64, u64)> },
    Gk { capacity: u32, batch: u32, tuples: Vec<(u64, u64, u64, u64)> },
}

impl WireState {
    fn to_state(&self) -> FamState {
        match self {
            WireState::Cm { d, w, counters } => {
                let (d, w) = (*d as usize, *w as usize);
                FamState::Cm(CountMinState {
                    counters: counters.chunks(w).map(|c| c.to_vec()).collect(),
                    d,
                    w,
                })
            }
            WireState::Hll { b, registers } => {
                FamState::Hll(HllState { registers: registers.clone(), b: *b as usize })
            }
            WireState::Ss { capacity, batch, rows } => {
                use crate::sketch::spacesaving::SsRow;
                FamState::Ss(SsState {
                    rows: rows.iter().map(|&(key, count, active)| SsRow { key, count, active }).collect(),
                    params: SsParams { capacity: *capacity as usize, batch: *batch as usize },
                })
            }
            WireState::Gk { capacity, batch, tuples } => {
                use crate::sketch::greenwald_khanna::GkTuple;
                FamState::Gk(GkState {
                    tuples: tuples
                        .iter()
                        .map(|&(value, count, max_error, active)| GkTuple { value, count, max_error, active })
                        .collect(),
                    params: GkParams { capacity: *capacity as usize, batch: *batch as usize },
                })
            }
        }
    }
}

// ─── Modes + measured cell ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    PerBatch,
    Chain,
    Forest,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "per_batch" | "perbatch" | "per-batch" | "flat" => Some(Self::PerBatch),
            "chain" | "linear" => Some(Self::Chain),
            "forest" | "recursive" | "tree" => Some(Self::Forest),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::PerBatch => "per_batch",
            Self::Chain => "chain",
            Self::Forest => "forest",
        }
    }
}

/// One measured composition cell (schema aligned with the plonky3 `DistCell`).
#[derive(Clone, Debug, Default)]
pub struct DistCell {
    pub machines_eff: usize,
    pub procs: usize,
    pub t: u64,
    pub witness_pass_ms: f64,
    pub scatter_ms: f64,
    pub scatter_state_bytes: u64,
    pub scatter_data_bytes: u64,
    pub leafgen_seq_ms: f64,
    pub leafgen_ms: f64,
    pub local_fold_ms: f64,
    pub merges_local: u32,
    pub merge_ms: f64,
    pub merges_cross: u32,
    pub cross_rounds: u32,
    pub verify_ms: f64,
    pub proof_bytes: u64,
    pub peak_rss_mb: f64,
    pub total_time_ms: f64,
    pub comm_msgs: u64,
    pub comm_bytes: u64,
    pub comm_model_ms: f64,
}

/// Peak (high-water) RSS in MB, from `/proc/self/status:VmHWM`.
pub fn read_vmhwm_mb() -> f64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else { return 0.0 };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            if let Some(kb) = rest.trim().split_whitespace().next().and_then(|v| v.parse::<u64>().ok()) {
                return kb as f64 / 1024.0;
            }
        }
    }
    0.0
}

/// Platform limits of the plonky2 leaf circuits (clean error before spawning
/// workers / building a big circuit). The CM OMC leaf routes each row via one
/// element of plonky2's 4-element Poseidon digest, so `d <= 4` (plonky3's
/// width-16 Poseidon reaches `d <= 8`); the HLL OMC leaf is `Θ(m + batch)`
/// (dense commit/decompose of the `m = 2^b` registers), so `b` is bounded only
/// by the register-array cost, not by `batch·m` as the flat one-hot leaf was.
pub fn validate_shape(family: Family, sh: &FamShape) -> Result<()> {
    match family {
        Family::Cm => ensure!(
            (1..=8).contains(&sh.d),
            "plonky2 Count-Min: d must be in 1..=8 (the OMC leaf derives row routing \
             from two domain-separated Poseidon digests, 4 rows each). Set EXP_D<=8."
        ),
        Family::Hll => ensure!(
            sh.b >= 2,
            "plonky2 HyperLogLog: b={} but the OMC leaf needs b >= 2. Set EXP_HLL_B>=2.",
            sh.b
        ),
        _ => {}
    }
    Ok(())
}

/// Bentley–Saxe cascade over a contiguous run of leaf nodes → one slice root.
fn forest_over(nodes: Vec<Node>) -> Result<Node> {
    let mut peaks: Vec<Node> = Vec::new();
    for node in nodes {
        let mut node = node;
        while peaks.last().is_some_and(|l| l.num_leaves() == node.num_leaves()) {
            let left = peaks.pop().unwrap();
            node = merge(&left, &node)?;
        }
        peaks.push(node);
    }
    compose_chain(peaks)
}

// ══════════════════════ Single-machine, in-process ═══════════════════════════

/// Measure one `(family, mode)` cell in-process on a single machine, verifying
/// the composed root binds the natively recomputed `(Com(S_0), Com(S_t))`.
pub fn measure_fam(
    family: Family,
    shape: FamShape,
    batches: &[Vec<u64>],
    mode: Mode,
) -> Result<DistCell> {
    ensure!(!batches.is_empty(), "need at least one batch");
    validate_shape(family, &shape)?;
    let t = batches.len() as u64;
    let t_start = Instant::now();

    let wp0 = Instant::now();
    let mut s = FamState::empty(family, &shape);
    let anchor = s.commit();
    for keys in batches {
        s.advance(keys);
    }
    let final_commit = s.commit();
    let witness_pass_ms = wp0.elapsed().as_secs_f64() * 1000.0;

    let leaf = FamLeaf::build(family, &shape);
    let mut state = FamState::empty(family, &shape);
    let mut leafgen_ms = 0.0f64;
    let mut nodes = Vec::with_capacity(batches.len());
    for (i, keys) in batches.iter().enumerate() {
        let (node, ms) = leaf.prove_leaf(&state, keys, (i + 1) as u64)?;
        leafgen_ms += ms;
        state.advance(keys);
        nodes.push(node);
    }

    let (merge_ms, verify_ms, proof_bytes, num_leaves, root_initial, root_final) = match mode {
        Mode::PerBatch => {
            let v0 = Instant::now();
            for n in &nodes {
                verify_node(n)?;
            }
            for k in 1..nodes.len() {
                ensure!(nodes[k - 1].final_ == nodes[k].initial, "per-batch break at {k}");
            }
            let vm = v0.elapsed().as_secs_f64() * 1000.0;
            let bytes: u64 = nodes.iter().map(|n| n.proof.to_bytes().len() as u64).sum();
            (0.0, vm, bytes, t, nodes[0].initial, nodes.last().unwrap().final_)
        }
        Mode::Chain | Mode::Forest => {
            let mp = Instant::now();
            let root = if mode == Mode::Chain { compose_chain(nodes)? } else { forest_over(nodes)? };
            let merge_ms = mp.elapsed().as_secs_f64() * 1000.0;
            let v0 = Instant::now();
            verify_node(&root)?;
            let bytes = root.proof.to_bytes().len() as u64;
            (merge_ms, v0.elapsed().as_secs_f64() * 1000.0, bytes, root.num_leaves(), root.initial, root.final_)
        }
    };
    ensure!(num_leaves == t, "root covers {num_leaves} leaves, expected {t}");
    ensure!(root_initial == anchor, "root initial != native Com(S_0)");
    ensure!(root_final == final_commit, "root final != native Com(S_t)");

    Ok(DistCell {
        machines_eff: 1,
        procs: 1,
        t,
        witness_pass_ms,
        leafgen_seq_ms: leafgen_ms,
        leafgen_ms,
        merge_ms,
        verify_ms,
        proof_bytes,
        peak_rss_mb: read_vmhwm_mb(),
        total_time_ms: t_start.elapsed().as_secs_f64() * 1000.0,
        ..Default::default()
    })
}

// ══════════════════════ Cross-family composition ═════════════════════════════

/// One measured cross-family cell.
#[derive(Clone, Debug, Default)]
pub struct CrossFamilyCell {
    pub families: usize,
    pub t: u64,
    /// Σ per-family forest build time (leaves + local fold).
    pub family_roots_ms: f64,
    /// The pairwise cross-family merges.
    pub cross_merge_ms: f64,
    pub verify_ms: f64,
    pub pairs: usize,
    pub proof_bytes: u64,
    pub peak_rss_mb: f64,
    pub total_time_ms: f64,
}

/// Build a single-machine forest root per family over `batches`, then bind the
/// four heterogeneous roots pairwise (cm⊕hll, ss⊕gk) via the §4.2 cross-family
/// merge atom, verifying each. Every family's own forest root already binds its
/// `(Com(S_0), Com(S_t))`; the cross-family node re-exposes both families'
/// boundaries under one verified proof.
pub fn cross_family_pairs(shape: FamShape, batches: &[Vec<u64>]) -> Result<CrossFamilyCell> {
    ensure!(!batches.is_empty(), "need at least one batch");
    for f in [Family::Cm, Family::Hll, Family::Ss, Family::Gk] { validate_shape(f, &shape)?; }
    let t = batches.len() as u64;
    let t_start = Instant::now();

    // One forest root per family (each verified against its native boundary).
    let fr0 = Instant::now();
    let mut roots = Vec::new();
    for family in [Family::Cm, Family::Hll, Family::Ss, Family::Gk] {
        let mut s = FamState::empty(family, &shape);
        let anchor = s.commit();
        let leaf = FamLeaf::build(family, &shape);
        let mut nodes = Vec::with_capacity(batches.len());
        let mut adv = FamState::empty(family, &shape);
        for (i, keys) in batches.iter().enumerate() {
            let (node, _) = leaf.prove_leaf(&adv, keys, (i + 1) as u64)?;
            adv.advance(keys);
            nodes.push(node);
        }
        for keys in batches {
            s.advance(keys);
        }
        let root = forest_over(nodes)?;
        ensure!(root.initial == anchor && root.final_ == s.commit(), "{} root boundary", family.label());
        roots.push(root);
    }
    let family_roots_ms = fr0.elapsed().as_secs_f64() * 1000.0;

    // Pairwise cross-family binding: (cm ⊕ hll), (ss ⊕ gk).
    let cm0 = Instant::now();
    let cf1 = merge_cross_family(&roots[0], &roots[1])?;
    let cf2 = merge_cross_family(&roots[2], &roots[3])?;
    let cross_merge_ms = cm0.elapsed().as_secs_f64() * 1000.0;

    let v0 = Instant::now();
    verify_cross_family(&cf1)?;
    verify_cross_family(&cf2)?;
    let verify_ms = v0.elapsed().as_secs_f64() * 1000.0;
    let proof_bytes = (cf1.proof.to_bytes().len() + cf2.proof.to_bytes().len()) as u64;

    Ok(CrossFamilyCell {
        families: 4,
        t,
        family_roots_ms,
        cross_merge_ms,
        verify_ms,
        pairs: 2,
        proof_bytes,
        peak_rss_mb: read_vmhwm_mb(),
        total_time_ms: t_start.elapsed().as_secs_f64() * 1000.0,
    })
}

// ══════════════════════ Distributed emulation ════════════════════════════════

fn send_msg<T: Serialize>(s: &mut UnixStream, v: &T) -> std::io::Result<u64> {
    let bytes = postcard::to_allocvec(v)
        .map_err(|e| std::io::Error::other(format!("postcard serialize: {e}")))?;
    s.write_all(&(bytes.len() as u32).to_le_bytes())?;
    s.write_all(&bytes)?;
    s.flush()?;
    Ok(bytes.len() as u64)
}

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

#[derive(Serialize, Deserialize)]
enum ToWorker {
    Task {
        family: String,
        mode: String,
        shape: FamShape,
        slice_start: u64,
        start: WireState,
        batches: Vec<Vec<u64>>,
    },
    MergeWith { right_wire: Vec<u8> },
    FetchRoot,
    Exit,
}

#[derive(Serialize, Deserialize)]
enum FromWorker {
    Hello { id: u32 },
    LeafDone { idx: u32, prove_ms: f64, cascade_ms: f64, cascade_merges: u32, proof: Option<Vec<u8>> },
    SliceDone { finalize_ms: f64, finalize_merges: u32 },
    Merged { ms: f64 },
    Root { wire: Vec<u8> },
    Done { peak_rss_mb: f64 },
    Fatal { msg: String },
}

const ENV_ROLE: &str = "ZKS2_COMPOSE_ROLE";
const ENV_SOCK: &str = "ZKS2_COMPOSE_SOCK";
const ENV_ID: &str = "ZKS2_COMPOSE_ID";
const ENV_CORES: &str = "ZKS2_COMPOSE_CORES";

/// Child-role dispatch; the example calls this FIRST.
pub fn maybe_run_child() -> bool {
    let Ok(role) = std::env::var(ENV_ROLE) else { return false };
    let sock = std::env::var(ENV_SOCK).expect("child needs sock");
    let cores: usize = std::env::var(ENV_CORES).ok().and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let id: u32 = std::env::var(ENV_ID).ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    match role.as_str() {
        "worker" => worker_main(&sock, id, cores),
        other => {
            eprintln!("unknown {ENV_ROLE}='{other}'");
            std::process::exit(2);
        }
    }
}

fn worker_main(sock: &str, id: u32, cores: usize) -> ! {
    let _ = rayon::ThreadPoolBuilder::new().num_threads(cores).build_global();
    let mut stream = UnixStream::connect(sock).expect("worker connect");
    send_msg(&mut stream, &FromWorker::Hello { id }).expect("hello");
    let mut err = stream.try_clone().expect("clone");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker_serve(&mut stream)));
    match r {
        Ok(Ok(())) => std::process::exit(0),
        Ok(Err(e)) => {
            let _ = send_msg(&mut err, &FromWorker::Fatal { msg: format!("{e}") });
            std::process::exit(1);
        }
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".into());
            let _ = send_msg(&mut err, &FromWorker::Fatal { msg });
            std::process::exit(1);
        }
    }
}

fn worker_serve(s: &mut UnixStream) -> Result<()> {
    let (task, _) = recv_msg::<ToWorker>(s).map_err(|e| anyhow::anyhow!("recv task: {e}"))?;
    let ToWorker::Task { family, mode, shape, slice_start, start, batches } = task else {
        anyhow::bail!("first message must be Task");
    };
    let family = Family::parse(&family).ok_or_else(|| anyhow::anyhow!("bad family"))?;
    let mode = Mode::parse(&mode).ok_or_else(|| anyhow::anyhow!("bad mode"))?;
    let leaf = FamLeaf::build(family, &shape);
    let mut state = start.to_state();

    let mut peaks: Vec<Node> = Vec::new();
    let mut chain_acc: Option<Node> = None;
    let mut root: Option<Node> = None;

    for (i, keys) in batches.iter().enumerate() {
        let idx = slice_start + i as u64 + 1;
        let (node, prove_ms) = leaf.prove_leaf(&state, keys, idx)?;
        state.advance(keys);
        let (mut cascade_ms, mut cascade_merges) = (0.0f64, 0u32);
        let proof = match mode {
            Mode::PerBatch => Some(MergeInput::from_node(&node).to_wire_bytes()?),
            Mode::Chain => {
                let t0 = Instant::now();
                chain_acc = Some(match chain_acc.take() {
                    None => node,
                    Some(acc) => {
                        cascade_merges = 1;
                        merge(&acc, &node)?
                    }
                });
                cascade_ms = t0.elapsed().as_secs_f64() * 1000.0;
                None
            }
            Mode::Forest => {
                let t0 = Instant::now();
                let mut node = node;
                while peaks.last().is_some_and(|l| l.num_leaves() == node.num_leaves()) {
                    let left = peaks.pop().unwrap();
                    node = merge(&left, &node)?;
                    cascade_merges += 1;
                }
                peaks.push(node);
                cascade_ms = t0.elapsed().as_secs_f64() * 1000.0;
                None
            }
        };
        send_msg(s, &FromWorker::LeafDone { idx: i as u32, prove_ms, cascade_ms, cascade_merges, proof })
            .map_err(|e| anyhow::anyhow!("send LeafDone: {e}"))?;
    }

    match mode {
        Mode::Chain => {
            root = chain_acc;
            send_msg(s, &FromWorker::SliceDone { finalize_ms: 0.0, finalize_merges: 0 })
                .map_err(|e| anyhow::anyhow!("SliceDone: {e}"))?;
        }
        Mode::Forest => {
            let t0 = Instant::now();
            let merges = peaks.len().saturating_sub(1) as u32;
            root = Some(compose_chain(std::mem::take(&mut peaks))?);
            send_msg(s, &FromWorker::SliceDone { finalize_ms: t0.elapsed().as_secs_f64() * 1000.0, finalize_merges: merges })
                .map_err(|e| anyhow::anyhow!("SliceDone: {e}"))?;
        }
        Mode::PerBatch => {}
    }

    loop {
        let (cmd, _) = recv_msg::<ToWorker>(s).map_err(|e| anyhow::anyhow!("recv cmd: {e}"))?;
        match cmd {
            ToWorker::MergeWith { right_wire } => {
                let remote = MergeInput::from_wire_bytes(&right_wire)?;
                let t0 = Instant::now();
                let left = root.take().ok_or_else(|| anyhow::anyhow!("no local root"))?;
                root = Some(merge_wire(&left, &remote)?);
                send_msg(s, &FromWorker::Merged { ms: t0.elapsed().as_secs_f64() * 1000.0 })
                    .map_err(|e| anyhow::anyhow!("Merged: {e}"))?;
            }
            ToWorker::FetchRoot => {
                let r = root.as_ref().ok_or_else(|| anyhow::anyhow!("no root to ship"))?;
                let wire = MergeInput::from_node(r).to_wire_bytes()?;
                send_msg(s, &FromWorker::Root { wire }).map_err(|e| anyhow::anyhow!("Root: {e}"))?;
            }
            ToWorker::Exit => {
                send_msg(s, &FromWorker::Done { peak_rss_mb: read_vmhwm_mb() })
                    .map_err(|e| anyhow::anyhow!("Done: {e}"))?;
                break;
            }
            ToWorker::Task { .. } => anyhow::bail!("duplicate Task"),
        }
    }
    Ok(())
}

// ─── CPU pinning ─────────────────────────────────────────────────────────────

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
    Command::new(cmd).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

/// Run-private temp name for this coordinator's executable snapshot.
fn exe_snapshot_name() -> String {
    format!("zks_dc_exe_{}", std::process::id())
}

/// A rebuild-proof path to *this* executable for pinned child spawns.
///
/// A long multi-family/mode sweep spends minutes-to-hours per cell. If a
/// concurrent `cargo build`/`cargo run` of the same example relinks the binary,
/// the coordinator's running inode is unlinked and `std::env::current_exe()`
/// starts returning a bogus `".../exp_compose (deleted)"` path — the next
/// `numactl <that path>` child spawn then dies with "No such file or directory",
/// aborting the sweep partway. Snapshot the executable ONCE, on first spawn,
/// into a run-private temp copy and exec that copy for every worker thereafter:
/// immune to the on-disk binary being rebuilt/removed later, and guaranteeing
/// every worker runs byte-for-byte the coordinator's build. The copy source is
/// `/proc/self/exe` on Linux, which serves the running inode's bytes even after
/// the file is unlinked, so the snapshot succeeds even from a "(deleted)" state.
///
/// Only a *successful* snapshot is memoized: a transient first-call error is
/// returned but not cached, so the next cell retries instead of dooming the
/// whole sweep on one blip.
fn stable_self_exe() -> Result<PathBuf> {
    static SNAPSHOT: OnceLock<PathBuf> = OnceLock::new();
    if let Some(p) = SNAPSHOT.get() {
        return Ok(p.clone());
    }
    let dst = take_exe_snapshot().map_err(|e| anyhow::anyhow!(e))?;
    let _ = SNAPSHOT.set(dst.clone());
    Ok(SNAPSHOT.get().cloned().unwrap_or(dst))
}

/// Copy this executable to its run-private snapshot path and mark it executable.
fn take_exe_snapshot() -> std::result::Result<PathBuf, String> {
    let resolved = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let proc_exe = PathBuf::from("/proc/self/exe");
    let src = if proc_exe.exists() { proc_exe } else { resolved.clone() };
    let dst = std::env::temp_dir().join(exe_snapshot_name());
    // Remove any stale same-named file so the copy can't hit ETXTBSY.
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

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ─── Coordinator ─────────────────────────────────────────────────────────────

enum Event {
    Worker(u32, FromWorker, u64),
    Gone(u32),
}

fn spawn_worker_reader(id: u32, mut stream: UnixStream, tx: mpsc::Sender<Event>) {
    std::thread::spawn(move || loop {
        match recv_msg::<FromWorker>(&mut stream) {
            Ok((msg, bytes)) => {
                let done = matches!(msg, FromWorker::Done { .. });
                if tx.send(Event::Worker(id, msg, bytes)).is_err() || done {
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

fn next_event(rx: &mpsc::Receiver<Event>) -> Result<Event> {
    match rx.recv_timeout(std::time::Duration::from_secs(3600)) {
        Ok(Event::Gone(id)) => anyhow::bail!("machine {id} died (socket closed)"),
        Ok(ev) => Ok(ev),
        Err(_) => anyhow::bail!("timed out waiting for a machine"),
    }
}

fn fatal(msg: &FromWorker) -> Option<String> {
    match msg {
        FromWorker::Fatal { msg } => Some(msg.clone()),
        _ => None,
    }
}

fn slice_ranges(t: usize, machines: usize) -> Vec<(usize, usize)> {
    let per = t.div_ceil(machines.max(1));
    (0..machines).map(|i| (i * per, ((i + 1) * per).min(t))).filter(|(a, b)| a < b).collect()
}

fn xfer_ms(bytes: u64, mbps: f64, rtt_ms: f64) -> f64 {
    bytes as f64 * 8.0 / (mbps * 1e6) * 1000.0 + rtt_ms
}

/// Measure one `(family, mode)` cell under the distributed emulation. The chain
/// is pinned to one machine; forest/per_batch distribute leaves over `machines`.
#[allow(clippy::too_many_arguments)]
pub fn measure_compose_dist(
    family: Family,
    shape: FamShape,
    batches: &[Vec<u64>],
    mode: Mode,
    cores: usize,
    machines: usize,
    proof_dir: &Path,
    mbps: f64,
    rtt_ms: f64,
) -> Result<DistCell> {
    ensure!(!batches.is_empty(), "need at least one batch");
    validate_shape(family, &shape)?;
    let t = batches.len();
    let total_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let machines = if mode == Mode::Chain { 1 } else { machines };
    let ranges = slice_ranges(t, machines);
    let machines_eff = ranges.len();
    ensure!(machines_eff * cores <= total_cpus, "oversubscribed: {machines_eff}x{cores} > {total_cpus}");

    let t_start = Instant::now();

    let wp0 = Instant::now();
    let mut s = FamState::empty(family, &shape);
    let anchor = s.commit();
    let mut slice_starts: Vec<WireState> = Vec::with_capacity(machines_eff);
    let mut next = 0usize;
    for (i, keys) in batches.iter().enumerate() {
        if next < ranges.len() && ranges[next].0 == i {
            slice_starts.push(s.encode());
            next += 1;
        }
        s.advance(keys);
    }
    let final_commit = s.commit();
    let witness_pass_ms = wp0.elapsed().as_secs_f64() * 1000.0;

    let sock_path = std::env::temp_dir().join(format!("zks2_dc_{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).map_err(|e| anyhow::anyhow!("bind: {e}"))?;
    let exe = stable_self_exe()?;
    let mut children: Vec<ChildGuard> = Vec::new();
    for i in 0..machines_eff {
        let mut cmd = pinned_command(&exe, i * cores, (i + 1) * cores - 1);
        cmd.env(ENV_ROLE, "worker")
            .env(ENV_SOCK, &sock_path)
            .env(ENV_ID, i.to_string())
            .env(ENV_CORES, cores.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        children.push(ChildGuard(cmd.spawn().map_err(|e| anyhow::anyhow!("spawn {i}: {e}"))?));
    }

    let (tx, rx) = mpsc::channel::<Event>();
    let mut worker_tx: Vec<Option<UnixStream>> = (0..machines_eff).map(|_| None).collect();
    for _ in 0..machines_eff {
        let (mut sconn, _) = listener.accept().map_err(|e| anyhow::anyhow!("accept: {e}"))?;
        let (hello, _) = recv_msg::<FromWorker>(&mut sconn).map_err(|e| anyhow::anyhow!("hello: {e}"))?;
        let FromWorker::Hello { id } = hello else { anyhow::bail!("bad hello") };
        spawn_worker_reader(id, sconn.try_clone().map_err(|e| anyhow::anyhow!("clone: {e}"))?, tx.clone());
        worker_tx[id as usize] = Some(sconn);
    }
    let mut worker_tx: Vec<UnixStream> = worker_tx.into_iter().map(|s| s.expect("connected")).collect();

    let sc0 = Instant::now();
    let (mut scatter_state_bytes, mut scatter_data_bytes) = (0u64, 0u64);
    for (i, &(a, b)) in ranges.iter().enumerate() {
        let start = slice_starts[i].clone();
        scatter_state_bytes += postcard::to_allocvec(&start).map(|v| v.len() as u64).unwrap_or(0);
        let slice: Vec<Vec<u64>> = batches[a..b].to_vec();
        scatter_data_bytes += postcard::to_allocvec(&slice).map(|v| v.len() as u64).unwrap_or(0);
        send_msg(
            &mut worker_tx[i],
            &ToWorker::Task {
                family: family.label().into(),
                mode: mode.label().into(),
                shape,
                slice_start: a as u64,
                start,
                batches: slice,
            },
        )
        .map_err(|e| anyhow::anyhow!("scatter {i}: {e}"))?;
    }
    let scatter_ms = sc0.elapsed().as_secs_f64() * 1000.0;

    let lp0 = Instant::now();
    let mut leaf_prove_ms = vec![0.0f64; t];
    let mut leaf_wire: Vec<Option<Vec<u8>>> = (0..t).map(|_| None).collect();
    let mut fold = vec![0.0f64; machines_eff];
    let mut merges_local = 0u32;
    let (mut comm_msgs, mut comm_bytes) = (0u64, 0u64);
    let mut pending_leaves = t;
    let mut pending_slices = if mode == Mode::PerBatch { 0 } else { machines_eff };
    while pending_leaves > 0 || pending_slices > 0 {
        match next_event(&rx)? {
            Event::Worker(id, msg, bytes) => {
                if let Some(f) = fatal(&msg) {
                    anyhow::bail!(f);
                }
                let ww = id as usize;
                match msg {
                    FromWorker::LeafDone { idx, prove_ms, cascade_ms, cascade_merges, proof } => {
                        let g = ranges[ww].0 + idx as usize;
                        leaf_prove_ms[g] = prove_ms;
                        fold[ww] += cascade_ms;
                        merges_local += cascade_merges;
                        if let Some(p) = proof {
                            comm_msgs += 1;
                            comm_bytes += bytes;
                            leaf_wire[g] = Some(p);
                        }
                        pending_leaves -= 1;
                    }
                    FromWorker::SliceDone { finalize_ms, finalize_merges } => {
                        fold[ww] += finalize_ms;
                        merges_local += finalize_merges;
                        pending_slices -= 1;
                    }
                    _ => anyhow::bail!("unexpected message in slice phase"),
                }
            }
            Event::Gone(id) => anyhow::bail!("machine {id} died"),
        }
    }
    let leafgen_ms = lp0.elapsed().as_secs_f64() * 1000.0;
    let leafgen_seq_ms: f64 = leaf_prove_ms.iter().sum();

    let mp0 = Instant::now();
    let mut merges_cross = 0u32;
    let mut cross_rounds = 0u32;
    let mut round_max_bytes: Vec<u64> = Vec::new();
    let (proof_bytes, verify_ms) = match mode {
        Mode::PerBatch => {
            let _ = std::fs::remove_dir_all(proof_dir);
            std::fs::create_dir_all(proof_dir).map_err(|e| anyhow::anyhow!("proof dir: {e}"))?;
            let v0 = Instant::now();
            let mut prev: Option<HashOut<F>> = None;
            let mut total = 0u64;
            for (i, p) in leaf_wire.iter().enumerate() {
                let p = p.as_ref().ok_or_else(|| anyhow::anyhow!("missing leaf {i}"))?;
                std::fs::write(proof_dir.join(format!("leaf_{i:04}.bin")), p).ok();
                let mi = MergeInput::from_wire_bytes(p)?;
                mi.verify()?;
                let expect = prev.unwrap_or(anchor);
                ensure!(mi.initial() == expect, "per-batch boundary break at leaf {i}");
                prev = Some(mi.final_());
                total += p.len() as u64;
            }
            ensure!(prev == Some(final_commit), "per-batch final mismatch");
            (total, v0.elapsed().as_secs_f64() * 1000.0)
        }
        Mode::Chain | Mode::Forest => {
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
                    send_msg(&mut worker_tx[send_id], &ToWorker::FetchRoot)
                        .map_err(|e| anyhow::anyhow!("fetch {send_id}: {e}"))?;
                    let wire = loop {
                        match next_event(&rx)? {
                            Event::Worker(id, FromWorker::Root { wire }, bytes) if id as usize == send_id => {
                                comm_msgs += 1;
                                comm_bytes += bytes;
                                max_bytes = max_bytes.max(bytes);
                                break wire;
                            }
                            Event::Worker(_, msg, _) => {
                                if let Some(f) = fatal(&msg) {
                                    anyhow::bail!(f);
                                }
                                anyhow::bail!("unexpected msg awaiting round root");
                            }
                            Event::Gone(id) => anyhow::bail!("machine {id} died"),
                        }
                    };
                    send_msg(&mut worker_tx[recv_id], &ToWorker::MergeWith { right_wire: wire })
                        .map_err(|e| anyhow::anyhow!("merge-with {recv_id}: {e}"))?;
                }
                for _ in &pairs {
                    loop {
                        match next_event(&rx)? {
                            Event::Worker(_, FromWorker::Merged { .. }, _) => {
                                merges_cross += 1;
                                break;
                            }
                            Event::Worker(_, msg, _) => {
                                if let Some(f) = fatal(&msg) {
                                    anyhow::bail!(f);
                                }
                                anyhow::bail!("unexpected msg awaiting Merged");
                            }
                            Event::Gone(id) => anyhow::bail!("machine {id} died"),
                        }
                    }
                }
                round_max_bytes.push(max_bytes);
                stride *= 2;
            }
            send_msg(&mut worker_tx[0], &ToWorker::FetchRoot).map_err(|e| anyhow::anyhow!("fetch final: {e}"))?;
            let wire = loop {
                match next_event(&rx)? {
                    Event::Worker(0, FromWorker::Root { wire }, bytes) => {
                        comm_msgs += 1;
                        comm_bytes += bytes;
                        break wire;
                    }
                    Event::Worker(_, msg, _) => {
                        if let Some(f) = fatal(&msg) {
                            anyhow::bail!(f);
                        }
                        anyhow::bail!("unexpected msg awaiting final root");
                    }
                    Event::Gone(id) => anyhow::bail!("machine {id} died"),
                }
            };
            let mi = MergeInput::from_wire_bytes(&wire)?;
            // Normalize the published root to a fixed-shape wrapper so every
            // family reports one size (Plonky2's merge is non-uniform — a heavy
            // leaf like GK's yields a larger root; see recursion::shrink). Only
            // the final auditor-facing root is wrapped; cross-machine wires are
            // unchanged, so comm_bytes is unaffected.
            let root = shrink_wire(&mi)?;
            let root_wire = MergeInput::from_node(&root).to_wire_bytes()?;
            let v0 = Instant::now();
            verify_node(&root)?;
            let verify_ms = v0.elapsed().as_secs_f64() * 1000.0;
            ensure!(root.num_leaves() == t as u64, "root covers {} leaves, expected {t}", root.num_leaves());
            ensure!(root.initial == anchor, "root initial != native Com(S_0)");
            ensure!(root.final_ == final_commit, "root final != native Com(S_t)");
            (root_wire.len() as u64, verify_ms)
        }
    };
    let merge_ms = mp0.elapsed().as_secs_f64() * 1000.0;
    let total_time_ms = t_start.elapsed().as_secs_f64() * 1000.0;

    let mut peak_rss_mb = 0.0f64;
    for (i, sx) in worker_tx.iter_mut().enumerate() {
        send_msg(sx, &ToWorker::Exit).map_err(|e| anyhow::anyhow!("exit {i}: {e}"))?;
    }
    let mut done = machines_eff;
    while done > 0 {
        match next_event(&rx)? {
            Event::Worker(_, FromWorker::Done { peak_rss_mb: r }, _) => {
                peak_rss_mb = peak_rss_mb.max(r);
                done -= 1;
            }
            Event::Gone(_) => done -= 1,
            _ => {}
        }
    }
    children.clear();
    let _ = std::fs::remove_file(&sock_path);

    let per_worker_scatter: Vec<u64> = ranges
        .iter()
        .enumerate()
        .map(|(i, &(a, b))| {
            let st = postcard::to_allocvec(&slice_starts[i]).map(|v| v.len() as u64).unwrap_or(0);
            let da = postcard::to_allocvec(&batches[a..b].to_vec()).map(|v| v.len() as u64).unwrap_or(0);
            st + da
        })
        .collect();
    let scatter_model = per_worker_scatter.iter().map(|&x| xfer_ms(x, mbps, rtt_ms)).fold(0.0, f64::max);
    let compose_model = match mode {
        Mode::PerBatch => xfer_ms(comm_bytes, mbps, rtt_ms * t as f64),
        Mode::Chain => xfer_ms(proof_bytes, mbps, rtt_ms),
        Mode::Forest => {
            round_max_bytes.iter().map(|&x| xfer_ms(x, mbps, rtt_ms)).sum::<f64>() + xfer_ms(proof_bytes, mbps, rtt_ms)
        }
    };

    Ok(DistCell {
        machines_eff,
        procs: machines_eff,
        t: t as u64,
        witness_pass_ms,
        scatter_ms,
        scatter_state_bytes,
        scatter_data_bytes,
        leafgen_seq_ms,
        leafgen_ms,
        local_fold_ms: fold.iter().copied().fold(0.0, f64::max),
        merges_local,
        merge_ms,
        merges_cross,
        cross_rounds,
        verify_ms,
        proof_bytes,
        peak_rss_mb,
        total_time_ms,
        comm_msgs,
        comm_bytes,
        comm_model_ms: scatter_model + compose_model,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> FamShape {
        FamShape { d: 2, w: 4, b: 4, ss_cap: 4, gk_cap: 4, batch: 2 }
    }
    fn stream(t: usize, m: usize) -> Vec<Vec<u64>> {
        (0..t).map(|i| (0..m).map(|j| ((i * m + j) as u64) % 17 + 1).collect()).collect()
    }

    /// Every family composes a 4-leaf stream to a boundary-verified root under
    /// all three modes (single machine).
    #[test]
    fn all_families_single_machine() -> Result<()> {
        let batches = stream(4, 2);
        for family in [Family::Cm, Family::Hll, Family::Ss, Family::Gk] {
            for mode in [Mode::PerBatch, Mode::Chain, Mode::Forest] {
                let cell = measure_fam(family, shape(), &batches, mode)?;
                assert_eq!(cell.t, 4, "{:?} {:?}", family, mode);
                assert!(cell.proof_bytes > 0, "{:?} {:?}", family, mode);
            }
        }
        Ok(())
    }

    /// The four family forest roots bind pairwise cross-family and verify.
    #[test]
    fn cross_family_binds_all_four() -> Result<()> {
        let cell = cross_family_pairs(shape(), &stream(4, 2))?;
        assert_eq!(cell.families, 4);
        assert_eq!(cell.pairs, 2);
        assert!(cell.proof_bytes > 0);
        Ok(())
    }

    #[test]
    fn slice_ranges_cover_contiguously() {
        for (t, m) in [(8, 4), (7, 4), (3, 4), (64, 4)] {
            let r = slice_ranges(t, m);
            assert_eq!(r[0].0, 0);
            assert_eq!(r.last().unwrap().1, t);
        }
    }

    #[test]
    fn xfer_model_math() {
        assert!((xfer_ms(25_000_000, 200.0, 0.2) - 1000.2).abs() < 1e-6);
    }
}
