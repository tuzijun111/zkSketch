//! Poseidon2-backed commitment for a Count-Min update batch (Phase 9 — the
//! §5.2 privacy-preserving design).
//!
//! ### Why this exists
//!
//! v1, v2, and the original v3 leaf all expose per-record `(key, value, pos)`
//! tuples as public inputs — convenient for merge-compatibility but
//! **violating the paper's privacy guarantee** (§3.4: the verifier should
//! learn no more than what the declared aggregate reveals; raw keys
//! definitely leak). The paper's §5.2 PI surface is just
//! `(C_B, C_old, C_new, M)`: the batch is committed via `C_B` and never
//! disclosed. This module provides that commitment.
//!
//! ### Layout
//!
//! Each `CountMinUpdate` `(key: u64, value: u32)` is encoded as **4 base
//! field elements**:
//!
//! ```text
//! [key_lo: u32, key_hi: u32, value: u32, 0]
//! ```
//!
//! - Splitting `key` into two 32-bit chunks lets us embed it in `Val =
//!   BabyBear` (which is ~31 bits) without depending on field reduction
//!   for u64 → Val conversion. For our prototype workloads with small keys,
//!   `key_hi` is always zero.
//! - The trailing zero is alignment padding: 4 Vals per record means the
//!   total flattened input is always a multiple of `CELL_ALIGNMENT = 4`, so
//!   the in-circuit `add_hash_slice` (which packs 4 Vals into one Challenge
//!   element) and the native `MyHash::hash_iter` produce identical digests.
//!   Same trick as `commit_countmin` uses for state cells.
//!
//! ### Soundness
//!
//! `CountMinBatchCommit` binds the prover to a specific batch. In the
//! private-batch v3 leaf (Phase 9c), per-record `(key, value)` move from
//! public inputs to private witnesses; an in-circuit Poseidon2 hash gate
//! reproduces this commitment over the private witnesses and connects to
//! the `batch_commit` PI. A malicious prover cannot insert, drop, or
//! reorder records without breaking the commitment binding.

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::commitment::hiding::{CommitFamily, CommitKind, CommitMode, SaltBb, commit_flat_bb};
use crate::config::{MyHash, Val, make_perm};
use crate::sketch::countmin::CountMinUpdate;

/// Digest width — same as `commitment::countmin::DIGEST_W`. Matches both
/// `MyHash`'s output and the in-circuit `add_hash_slice` digest length.
pub const DIGEST_W: usize = 8;

/// Number of base-field cells emitted per record. Multiplied by `batch`
/// gives the total flattened input length, which is automatically a
/// multiple of the in-circuit hash's `CELL_ALIGNMENT = 4`.
pub const RECORD_WIDTH: usize = 4;

/// Fixed-width Count-Min batch commitment. Same shape as `CountMinCommit`
/// (`[Val; 8]`) so the §4.3 history-composition layer's digest functions
/// can pack it identically.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CountMinBatchCommit(pub [Val; DIGEST_W]);

impl AsRef<[Val]> for CountMinBatchCommit {
    fn as_ref(&self) -> &[Val] {
        &self.0
    }
}

/// Compute the batch commitment by hashing the per-record encoding under
/// the canonical `MyHash` (rate 8 / width 16 / digest 8 over `make_perm`) —
/// the same permutation the state commitment uses, so the in-circuit
/// `add_hash_slice` will reproduce the digest bit-for-bit.
pub fn commit_batch(records: &[CountMinUpdate]) -> CountMinBatchCommit {
    let hasher = MyHash::new(make_perm());
    let flat = records.iter().flat_map(|r| {
        let key_lo = (r.key & 0xFFFF_FFFF) as u32;
        let key_hi = (r.key >> 32) as u32;
        [
            Val::from_u32(key_lo),
            Val::from_u32(key_hi),
            Val::from_u32(r.value),
            Val::ZERO, // alignment padding
        ]
    });
    let digest: [Val; DIGEST_W] = hasher.hash_iter(flat);
    CountMinBatchCommit(digest)
}

/// Base values per record in the exact-limb layout ([`commit_batch_limbs`]).
pub const RECORD_WIDTH_LIMBS: usize = 8;

/// Batch commitment with the key as four EXACT 16-bit limbs:
///
/// ```text
/// [k0, k1, k2, k3, value, 0, 0, 0]      (key = Σ k_i·2^{16i})
/// ```
///
/// i.e. two Challenges per record: the key Challenge the `omc` leaf also
/// hashes for routing, then `[value, 0, 0, 0]`. [`commit_batch`]'s
/// `key_lo`/`key_hi` are 32-bit and BabyBear's `p < 2^31`, so its encoding
/// reduces them mod `p` and two batches whose keys agree mod `p` limb-wise
/// share a commitment. Every limb here is `< 2^16 < p`, so the encoding of
/// a batch is injective. Used by the `omc` Count-Min leaf under
/// `Binding::Semantic` / `Binding::Bound`; `Legacy` keeps [`commit_batch`].
pub fn commit_batch_limbs(records: &[CountMinUpdate]) -> CountMinBatchCommit {
    let hasher = MyHash::new(make_perm());
    let flat = records.iter().flat_map(|r| {
        let l = crate::sketch::bind::key_limbs::<Val>(r.key);
        [l[0], l[1], l[2], l[3], Val::from_u32(r.value), Val::ZERO, Val::ZERO, Val::ZERO]
    });
    CountMinBatchCommit(hasher.hash_iter(flat))
}

/// Per-record flat encoding of [`commit_batch`]: `[key_lo, key_hi, value, 0]`.
fn flat_batch(records: &[CountMinUpdate]) -> Vec<Val> {
    records
        .iter()
        .flat_map(|r| {
            [
                Val::from_u32((r.key & 0xFFFF_FFFF) as u32),
                Val::from_u32((r.key >> 32) as u32),
                Val::from_u32(r.value),
                Val::ZERO,
            ]
        })
        .collect()
}

/// Per-record flat encoding of [`commit_batch_limbs`]:
/// `[k0, k1, k2, k3, value, 0, 0, 0]`.
fn flat_batch_limbs(records: &[CountMinUpdate]) -> Vec<Val> {
    records
        .iter()
        .flat_map(|r| {
            let l = crate::sketch::bind::key_limbs::<Val>(r.key);
            [l[0], l[1], l[2], l[3], Val::from_u32(r.value), Val::ZERO, Val::ZERO, Val::ZERO]
        })
        .collect()
}

/// [`commit_batch`] under a [`CommitMode`]: `Plain` is exactly
/// [`commit_batch`]; `Hiding` prefixes the same encoding with
/// `[TAG_BATCH, CountMin, 0, 0, ρ…]` ([`crate::commitment::hiding`]).
pub fn commit_batch_with(records: &[CountMinUpdate], mode: CommitMode, salt: &SaltBb) -> CountMinBatchCommit {
    match mode {
        CommitMode::Plain => commit_batch(records),
        CommitMode::Hiding => CountMinBatchCommit(commit_flat_bb(
            mode,
            CommitKind::Batch,
            CommitFamily::CountMin,
            salt,
            &flat_batch(records),
        )),
    }
}

/// [`commit_batch_limbs`] under a [`CommitMode`] (see [`commit_batch_with`]).
pub fn commit_batch_limbs_with(
    records: &[CountMinUpdate],
    mode: CommitMode,
    salt: &SaltBb,
) -> CountMinBatchCommit {
    match mode {
        CommitMode::Plain => commit_batch_limbs(records),
        CommitMode::Hiding => CountMinBatchCommit(commit_flat_bb(
            mode,
            CommitKind::Batch,
            CommitFamily::CountMin,
            salt,
            &flat_batch_limbs(records),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_batch() -> Vec<CountMinUpdate> {
        vec![
            CountMinUpdate { key: 7, value: 3 },
            CountMinUpdate { key: 11, value: 5 },
            CountMinUpdate { key: 42, value: 1 },
            CountMinUpdate { key: 99, value: 9 },
        ]
    }

    #[test]
    fn commit_is_deterministic() {
        let b = sample_batch();
        let c1 = commit_batch(&b);
        let c2 = commit_batch(&b);
        assert_eq!(c1, c2);
    }

    /// Any single-field perturbation must change the commitment.
    #[test]
    fn commit_distinguishes_batches_by_key() {
        let b1 = sample_batch();
        let c1 = commit_batch(&b1);

        let mut b2 = b1.clone();
        b2[2].key = b2[2].key.wrapping_add(1);
        let c2 = commit_batch(&b2);

        assert_ne!(c1, c2, "key change must alter the batch commit");
    }

    #[test]
    fn commit_distinguishes_batches_by_value() {
        let b1 = sample_batch();
        let c1 = commit_batch(&b1);

        let mut b2 = b1.clone();
        b2[0].value = b2[0].value.wrapping_add(1);
        let c2 = commit_batch(&b2);

        assert_ne!(c1, c2, "value change must alter the batch commit");
    }

    /// Order matters — swapping two records changes the commitment.
    /// (This is important for the §5.2 design: the prover commits to a
    /// *specific ordering* of the batch, and key-grouping is checked
    /// against this ordering via PermuteAir.)
    #[test]
    fn commit_distinguishes_record_order() {
        let b1 = sample_batch();
        let c1 = commit_batch(&b1);

        let mut b2 = b1.clone();
        b2.swap(0, 2);
        let c2 = commit_batch(&b2);

        assert_ne!(c1, c2, "swapping record order must alter the batch commit");
    }

    /// Drift guard: the commit must be reproducible via
    /// `MyHash::new(make_perm()).hash_iter(...)` directly. If
    /// `commit_batch` ever diverges (adds framing, changes layout, etc.),
    /// this fires immediately. Same shape as `commit_countmin`'s
    /// drift guard.
    #[test]
    fn commit_matches_make_perm() {
        let b = sample_batch();
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = b
            .iter()
            .flat_map(|r| {
                let key_lo = (r.key & 0xFFFF_FFFF) as u32;
                let key_hi = (r.key >> 32) as u32;
                [
                    Val::from_u32(key_lo),
                    Val::from_u32(key_hi),
                    Val::from_u32(r.value),
                    Val::ZERO,
                ]
            })
            .collect();
        let expected: [Val; DIGEST_W] = hasher.hash_iter(flat);
        let actual = commit_batch(&b);
        assert_eq!(actual.0, expected);
    }

    /// The exact-limb layout separates keys congruent mod `p`, which the
    /// 32-bit layout collapses: `k` and `k + p` (both `< 2^32`) share
    /// [`commit_batch`] but not [`commit_batch_limbs`].
    #[test]
    fn limb_commit_separates_keys_congruent_mod_p() {
        let p = <Val as p3_field::PrimeField64>::ORDER_U64;
        let a = vec![CountMinUpdate { key: 12_345, value: 1 }];
        let b = vec![CountMinUpdate { key: 12_345 + p, value: 1 }];
        assert!(b[0].key < 1 << 32, "both keys are 32-bit");
        assert_eq!(commit_batch(&a), commit_batch(&b), "32-bit layout reduces mod p");
        assert_ne!(commit_batch_limbs(&a), commit_batch_limbs(&b));
        let hasher = MyHash::new(make_perm());
        let flat: Vec<Val> = b
            .iter()
            .flat_map(|r| {
                let k = |i: u32| Val::from_u64((r.key >> (16 * i)) & 0xFFFF);
                [k(0), k(1), k(2), k(3), Val::from_u32(r.value), Val::ZERO, Val::ZERO, Val::ZERO]
            })
            .collect();
        assert_eq!(commit_batch_limbs(&b).0, hasher.hash_iter(flat), "layout drift");
    }

    /// Empty batch is a valid input (just hashes nothing).
    #[test]
    fn commit_accepts_empty_batch() {
        let b: Vec<CountMinUpdate> = vec![];
        let c1 = commit_batch(&b);
        let c2 = commit_batch(&b);
        assert_eq!(c1, c2);
    }

    /// The `_with` variants: `Plain` is the old commitment whatever the salt;
    /// `Hiding` is `MyHash([TAG_BATCH, 1, 0, 0, ρ…] ‖ same encoding)` and
    /// differs per salt.
    #[test]
    fn commit_with_modes() {
        use crate::commitment::hiding::{SaltSeed, TAG_BATCH, rho_batch_bb};
        let b = sample_batch();
        let seed = SaltSeed::for_tests(11);
        let (r1, r2) = (rho_batch_bb(&seed, CommitFamily::CountMin, 1), rho_batch_bb(&seed, CommitFamily::CountMin, 2));
        assert_eq!(commit_batch_with(&b, CommitMode::Plain, &r1), commit_batch(&b));
        assert_eq!(commit_batch_limbs_with(&b, CommitMode::Plain, &r1), commit_batch_limbs(&b));
        let mut input = vec![Val::from_u64(TAG_BATCH), Val::ONE, Val::ZERO, Val::ZERO];
        input.extend_from_slice(&r1.0);
        input.extend(flat_batch_limbs(&b));
        let want: [Val; DIGEST_W] = MyHash::new(make_perm()).hash_iter(input);
        let h1 = commit_batch_limbs_with(&b, CommitMode::Hiding, &r1);
        assert_eq!(h1.0, want, "layout drift");
        assert_ne!(h1, commit_batch_limbs_with(&b, CommitMode::Hiding, &r2));
        assert_ne!(h1, commit_batch_limbs(&b));
        assert_ne!(commit_batch_with(&b, CommitMode::Hiding, &r1), commit_batch(&b));
        assert_eq!(flat_batch(&b).len(), RECORD_WIDTH * b.len());
        assert_eq!(flat_batch_limbs(&b).len(), RECORD_WIDTH_LIMBS * b.len());
    }
}
