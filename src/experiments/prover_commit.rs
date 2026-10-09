//! **The PROVER's commitment context** for the measurement harness (revision
//! B2, [`crate::commitment::hiding`]).
//!
//! A [`ProverCommit`] is the commitment mode of a run plus, under
//! [`CommitMode::Hiding`], the prover's salt seed. It is read ONCE per run
//! ([`ProverCommit::from_env`]: `ZKSKETCH_COMMIT`, then `ZKSKETCH_SALT_SEED`
//! or the OS RNG) and handed explicitly to the prover-side code: the leaf
//! provers (openings of leaf `t`), the query decoders (the state randomizer of
//! version `t`), the published batch log (`Com(S_T; ρ_T)`, every
//! `Com(B_t; ρ^B_t)`) and the distributed engine's workers (the seed crosses
//! the coordinator → worker socket inside `ToWorker::Task`, the prover's own
//! machines only).
//!
//! Who holds the seed: the prover (the coordinator and its workers). The
//! auditor never does: every auditor entry point
//! ([`crate::experiments::audit`]) takes the published log, the proofs and
//! public parameters (the commitment MODE is public, since it changes the
//! VKs), never a `ProverCommit`. The seed is never printed; only its SOURCE
//! (`env` / `os`) is reported ([`ProverCommit::seed_label`]).
//!
//! Every stream the harness proves is the GENESIS history of the run's seed
//! (`Openings::for_leaf(seed, family, t)` at the global 1-based batch index
//! `t` of the interval statement; `ρ^S_0 = 0`, so the auditor recomputes
//! `Com(S_0; 0)` itself). A sweep re-proves the same stream under several
//! modes/core counts (identical commitments, by design) and proves distinct
//! streams (datasets, batch sizes) under the same `(seed, family, t)`; that
//! reuse is fine for a benchmark (no privacy claim across its cells), while
//! a deployment runs one history per stream under its seed.

use crate::commitment::hiding::{
    commit_mode_from_env, rho_batch_bb, rho_batch_gl, rho_state_bb, rho_state_gl, CommitFamily,
    CommitMode, Openings, OpeningsGl, SaltBb, SaltGl, SaltSeed, SaltSeedWire,
};

/// Where a run's salt seed came from (reported; the seed itself never is).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SeedSource {
    /// `ZKSKETCH_SALT_SEED` (64 hex characters): reproducible runs.
    Env,
    /// Drawn from the operating system's RNG (the default).
    Os,
    /// Supplied by the caller ([`ProverCommit::hiding`], tests) or received
    /// by a distributed worker from its coordinator.
    Given,
    /// `Plain` mode: no seed exists.
    None,
}

/// The prover's commitment mode and (under `Hiding`) its salt seed. `Debug`
/// never shows the seed ([`SaltSeed`]'s `Debug` is redacted).
#[derive(Clone, Debug)]
pub struct ProverCommit {
    mode: CommitMode,
    /// `Some` iff `mode` is `Hiding`.
    seed: Option<SaltSeed>,
    source: SeedSource,
}

impl ProverCommit {
    /// The run's context from the environment, read once:
    /// [`commit_mode_from_env`] (`ZKSKETCH_COMMIT`, default `Hiding` except
    /// under `ZKSKETCH_BINDING=legacy`), and under `Hiding` the seed from
    /// `ZKSKETCH_SALT_SEED` or else the OS RNG. `Plain` draws no seed.
    pub fn from_env() -> Self {
        match commit_mode_from_env() {
            CommitMode::Plain => Self::plain(),
            CommitMode::Hiding => match SaltSeed::from_env() {
                Some(seed) => Self { mode: CommitMode::Hiding, seed: Some(seed), source: SeedSource::Env },
                None => Self {
                    mode: CommitMode::Hiding,
                    seed: Some(SaltSeed::os_random()),
                    source: SeedSource::Os,
                },
            },
        }
    }

    /// `Plain`: today's commitments, circuits and code paths, byte for byte.
    pub fn plain() -> Self {
        Self { mode: CommitMode::Plain, seed: None, source: SeedSource::None }
    }

    /// `Hiding` under an explicit seed.
    pub fn hiding(seed: SaltSeed) -> Self {
        Self { mode: CommitMode::Hiding, seed: Some(seed), source: SeedSource::Given }
    }

    pub fn mode(&self) -> CommitMode {
        self.mode
    }

    pub fn is_hiding(&self) -> bool {
        self.mode.is_hiding()
    }

    /// `plain` / `hiding` (the CSV and env.json `commit` value).
    pub fn label(&self) -> &'static str {
        commit_mode_label(self.mode)
    }

    /// The seed's source (the CSV and env.json `salt_seed` value): `env`,
    /// `os`, `given`, or `n/a` under `Plain`. Never the seed.
    pub fn seed_label(&self) -> &'static str {
        match self.source {
            SeedSource::Env => "env",
            SeedSource::Os => "os",
            SeedSource::Given => "given",
            SeedSource::None => "n/a",
        }
    }

    fn seed(&self) -> &SaltSeed {
        self.seed.as_ref().expect("a Hiding ProverCommit carries a seed")
    }

    /// The openings of leaf `t` (1-based, genesis history):
    /// `(ρ^S_{t-1}, ρ^S_t, ρ^B_t)` under `Hiding`; [`Openings::plain`]
    /// (ignored by a `Plain` leaf) otherwise.
    pub fn openings(&self, family: CommitFamily, t: u64) -> Openings {
        match self.mode {
            CommitMode::Plain => Openings::plain(),
            CommitMode::Hiding => Openings::for_leaf(self.seed(), family, t),
        }
    }

    /// Goldilocks twin of [`Self::openings`].
    pub fn openings_gl(&self, family: CommitFamily, t: u64) -> OpeningsGl {
        match self.mode {
            CommitMode::Plain => OpeningsGl::plain(),
            CommitMode::Hiding => OpeningsGl::for_leaf(self.seed(), family, t),
        }
    }

    /// `ρ^S_t`, the randomizer of `Com(S_t)`: leaf `t`'s final, leaf
    /// `t + 1`'s init and every query at version `t`. The public zero at
    /// `t = 0` (genesis) and under `Plain`.
    pub fn state_salt(&self, family: CommitFamily, t: u64) -> SaltBb {
        match self.mode {
            CommitMode::Plain => SaltBb::ZERO,
            CommitMode::Hiding => rho_state_bb(self.seed(), family, t),
        }
    }

    /// `ρ^B_t`, the randomizer of `Com(B_t)` (`t ≥ 1`); zero under `Plain`.
    pub fn batch_salt(&self, family: CommitFamily, t: u64) -> SaltBb {
        match self.mode {
            CommitMode::Plain => SaltBb::ZERO,
            CommitMode::Hiding => rho_batch_bb(self.seed(), family, t),
        }
    }

    /// Goldilocks twin of [`Self::state_salt`].
    pub fn state_salt_gl(&self, family: CommitFamily, t: u64) -> SaltGl {
        match self.mode {
            CommitMode::Plain => SaltGl::ZERO,
            CommitMode::Hiding => rho_state_gl(self.seed(), family, t),
        }
    }

    /// Goldilocks twin of [`Self::batch_salt`].
    pub fn batch_salt_gl(&self, family: CommitFamily, t: u64) -> SaltGl {
        match self.mode {
            CommitMode::Plain => SaltGl::ZERO,
            CommitMode::Hiding => rho_batch_gl(self.seed(), family, t),
        }
    }

    /// The context as it crosses the coordinator → worker socket of the
    /// distributed PROVER (`ToWorker::Task`): the mode label and, under
    /// `Hiding`, the seed. Prover-internal only.
    pub(crate) fn to_prover_wire(&self) -> (String, Option<SaltSeedWire>) {
        (self.label().to_string(), self.seed.as_ref().map(SaltSeed::to_prover_wire))
    }

    /// Rebuild a worker's context from [`Self::to_prover_wire`].
    pub(crate) fn from_prover_wire(mode: &str, seed: Option<SaltSeedWire>) -> Self {
        match (parse_commit_mode(mode), seed) {
            (Some(CommitMode::Plain), None) => Self::plain(),
            (Some(CommitMode::Hiding), Some(w)) => Self::hiding(w.into_seed()),
            (m, s) => panic!(
                "inconsistent prover commitment context on the wire: mode {m:?}, seed present = {}",
                s.is_some()
            ),
        }
    }
}

/// `plain` / `hiding`.
pub fn commit_mode_label(mode: CommitMode) -> &'static str {
    match mode {
        CommitMode::Plain => "plain",
        CommitMode::Hiding => "hiding",
    }
}

/// Inverse of [`commit_mode_label`].
pub fn parse_commit_mode(s: &str) -> Option<CommitMode> {
    match s {
        "plain" => Some(CommitMode::Plain),
        "hiding" => Some(CommitMode::Hiding),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_context_has_no_seed_and_zero_openings() {
        let c = ProverCommit::plain();
        assert_eq!((c.label(), c.seed_label()), ("plain", "n/a"));
        assert_eq!(c.openings(CommitFamily::CountMin, 3), Openings::plain());
        assert_eq!(c.openings_gl(CommitFamily::GreenwaldKhanna, 3), OpeningsGl::plain());
        assert!(c.state_salt(CommitFamily::SpaceSaving, 5).is_zero());
        assert!(c.batch_salt_gl(CommitFamily::HyperLogLog, 5).is_zero());
        let (m, s) = c.to_prover_wire();
        assert_eq!(m, "plain");
        assert!(s.is_none());
    }

    /// The hiding context derives exactly the library's honest openings, the
    /// wire round trip preserves them (a worker derives the same `ρ_t` as its
    /// coordinator), and `Debug` never prints the seed.
    #[test]
    fn hiding_context_matches_library_openings_and_survives_the_wire() {
        let seed = SaltSeed::for_tests(77);
        let c = ProverCommit::hiding(seed.clone());
        assert_eq!((c.label(), c.seed_label()), ("hiding", "given"));
        for fam in [
            CommitFamily::CountMin,
            CommitFamily::HyperLogLog,
            CommitFamily::SpaceSaving,
            CommitFamily::GreenwaldKhanna,
            CommitFamily::Bloom,
            CommitFamily::Kmv,
        ] {
            for t in 1..=3u64 {
                assert_eq!(c.openings(fam, t), Openings::for_leaf(&seed, fam, t));
                assert_eq!(c.openings_gl(fam, t), OpeningsGl::for_leaf(&seed, fam, t));
                assert_eq!(c.state_salt(fam, t), rho_state_bb(&seed, fam, t));
                assert_eq!(c.batch_salt(fam, t), rho_batch_bb(&seed, fam, t));
                assert_eq!(c.state_salt_gl(fam, t), rho_state_gl(&seed, fam, t));
                assert_eq!(c.batch_salt_gl(fam, t), rho_batch_gl(&seed, fam, t));
            }
            assert!(c.state_salt(fam, 0).is_zero(), "genesis ρ^S_0 is the public zero");
        }
        let (m, w) = c.to_prover_wire();
        let bytes = postcard::to_allocvec(&(m.clone(), w.clone())).unwrap();
        let (m2, w2): (String, Option<SaltSeedWire>) = postcard::from_bytes(&bytes).unwrap();
        let back = ProverCommit::from_prover_wire(&m2, w2);
        assert_eq!(back.openings(CommitFamily::CountMin, 2), c.openings(CommitFamily::CountMin, 2));
        let dbg = format!("{c:?} {w:?}");
        assert!(dbg.contains("redacted"), "{dbg}");
        assert!(!dbg.contains("165"), "no seed byte (0xA5 = 165) in Debug: {dbg}");
    }

    #[test]
    #[should_panic(expected = "inconsistent prover commitment context")]
    fn wire_rejects_hiding_without_a_seed() {
        let _ = ProverCommit::from_prover_wire("hiding", None);
    }
}
