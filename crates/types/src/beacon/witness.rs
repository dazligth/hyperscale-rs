//! Beacon-chain witness types.
//!
//! Every event the beacon applies — validator registrations, stake
//! adjustments, jail/unjail decisions, equivocation evidence — flows
//! through a [`Witness`] carried inside a
//! [`BeaconProposal`](crate::BeaconProposal). Witnesses split by *who
//! emitted them*:
//!
//! - [`Witness::Shard`] — lifted from a shard's VM via that shard's
//!   monotonic beacon-witness accumulator. Carries a
//!   [`ShardWitnessProof`] for provenance.
//!
//! Beacon-internal witnesses (cryptographic equivocation evidence)
//! aren't yet in this module — they depend on the prefix-consensus
//! vote/QC types, which land in a later round. The
//! [`Witness`] enum will gain a second variant then.

use sbor::prelude::*;

use crate::{Bls12381G1PublicKey, LeafIndex, ShardGroupId, Stake, StakePoolId, ValidatorId};

/// Why a validator was jailed.
///
/// Determines unjail eligibility — performance and recovery jails
/// unjail after a cooldown when an `Unjail` witness arrives;
/// equivocation jails are permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub enum JailReason {
    /// Performance failure: a shard's local miss-counter tripped, or
    /// the validator's own beacon proposal was rejected for a
    /// malformed VRF reveal. Unjails after a cooldown when an
    /// `Unjail` witness is lifted from a shard.
    Performance,
    /// Validator was on the dead committee at the time
    /// `apply_recovery_cert` ran. Unjails after a cooldown — a
    /// committee that fails to make progress isn't permanently
    /// hostile; the participants may have been honest-but-partitioned.
    Recovery,
    /// Cryptographic proof of byzantine signing. Permanent: the key
    /// is provably hostile, and no cooldown unjails it.
    Equivocation,
}

/// What the shard's VM observed. Beacon-relevant payload only —
/// provenance fields (shard, leaf-index, eventual Merkle path) live
/// in [`ShardWitnessProof`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ShardWitnessPayload {
    /// A net deposit landed for `pool_id`. Increases the pool's
    /// `total_stake`. If `pool_id` is unknown, creates the pool entry.
    StakeDeposit {
        /// Pool receiving the deposit.
        pool_id: StakePoolId,
        /// Aggregate amount added; delegator-level accounting lives on
        /// the shard.
        amount: Stake,
    },
    /// A withdrawal request was placed against `pool_id`. Appends a
    /// pending-withdrawal entry; `total_stake` is unchanged until the
    /// unbonding window completes, but `effective_stake` drops
    /// immediately and blocks new registrations relying on the
    /// withdrawn amount.
    StakeWithdraw {
        /// Pool the withdrawal targets.
        pool_id: StakePoolId,
        /// Amount the withdrawal removes from effective stake
        /// immediately and from total stake on unbonding completion.
        amount: Stake,
    },
    /// The pool registers a new validator node. The published pubkey
    /// is carried on the witness so the beacon can verify the
    /// validator's signed outputs without a side-channel registry.
    /// Rejected by `apply_slot` if the pool's effective stake doesn't
    /// support another activation at the current dynamic `min_stake`.
    RegisterValidator {
        /// Pool that operates this validator.
        pool_id: StakePoolId,
        /// Identifier the validator will be known by.
        validator_id: ValidatorId,
        /// 48-byte compressed BLS pubkey.
        pubkey: Bls12381G1PublicKey,
    },
    /// The pool operator deactivates one of their validator nodes.
    /// Transitions the validator out of any active role; if currently
    /// on a shard, frees the slot for a pool draw.
    DeactivateValidator {
        /// Validator being deactivated.
        validator_id: ValidatorId,
    },
    /// Shard's local performance tracking decided to jail `id`. The
    /// shard owns the policy (miss threshold, observed shard-level
    /// equivocation, etc.) and emits a single witness when it
    /// concludes the validator should be out. `reason` is recorded
    /// onto the resulting jailed status and determines unjail
    /// eligibility.
    Jail {
        /// Validator being jailed.
        id: ValidatorId,
        /// Cause; determines whether and when the jail can be lifted.
        reason: JailReason,
    },
    /// Validator took an unjail action on the staking contract.
    /// Beacon-side: if currently jailed under a fault-cause reason,
    /// the cooldown has elapsed, and the pool can still support the
    /// additional active slot at the current dynamic `min_stake`,
    /// transition back to the pool. Otherwise silently dropped.
    /// Equivocation jails are never unjailed.
    Unjail {
        /// Validator requesting unjail.
        id: ValidatorId,
    },
    /// A validator on a shard has signalled they've finished syncing
    /// the shard's state. Transitions the validator to ready;
    /// silently dropped if the validator's status doesn't match.
    Ready {
        /// Validator marking themselves ready.
        id: ValidatorId,
    },
}

/// Provenance for a [`ShardWitness`].
///
/// Today: just the `(shard_id, leaf_index)` pair — enough for the
/// watermark dedup of the per-shard high-water mark, and to render in
/// logs. Trusted as-presented for now; later additions will include a
/// Merkle inclusion path against the shard's beacon-witness accumulator
/// root plus a pointer to the `CommittedBlockHeader` that committed it.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardWitnessProof {
    /// Shard that emitted the witness.
    pub shard_id: ShardGroupId,
    /// Position in the shard's monotonic beacon-witness accumulator.
    pub leaf_index: LeafIndex,
}

/// A shard-emitted observation paired with proof of origin.
///
/// `payload` is the beacon-relevant fact; `proof` says where it came
/// from.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardWitness {
    /// What the shard observed.
    pub payload: ShardWitnessPayload,
    /// Where it came from.
    pub proof: ShardWitnessProof,
}

/// Observation submitted in a [`BeaconProposal`](crate::BeaconProposal).
///
/// Currently only [`Self::Shard`]; beacon-internal evidence (cryptographic
/// equivocation) will land as a second variant once the prefix-consensus
/// vote/QC types it depends on are in place.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum Witness {
    /// Lifted from a shard's VM.
    Shard(ShardWitness),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_shard_witness() -> ShardWitness {
        ShardWitness {
            payload: ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::new(1_000_000),
            },
            proof: ShardWitnessProof {
                shard_id: ShardGroupId::new(0),
                leaf_index: LeafIndex::new(42),
            },
        }
    }

    #[test]
    fn shard_witness_payload_sbor_round_trip_all_variants() {
        let pubkey = Bls12381G1PublicKey([0xAB; 48]);
        let payloads = vec![
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::new(100),
            },
            ShardWitnessPayload::StakeWithdraw {
                pool_id: StakePoolId::new(2),
                amount: Stake::new(50),
            },
            ShardWitnessPayload::RegisterValidator {
                pool_id: StakePoolId::new(3),
                validator_id: ValidatorId::new(7),
                pubkey,
            },
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(8),
            },
            ShardWitnessPayload::Jail {
                id: ValidatorId::new(9),
                reason: JailReason::Performance,
            },
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(11),
            },
        ];
        for p in payloads {
            let bytes = basic_encode(&p).unwrap();
            let decoded: ShardWitnessPayload = basic_decode(&bytes).unwrap();
            assert_eq!(p, decoded);
        }
    }

    #[test]
    fn shard_witness_sbor_round_trip() {
        let w = sample_shard_witness();
        let bytes = basic_encode(&w).unwrap();
        let decoded: ShardWitness = basic_decode(&bytes).unwrap();
        assert_eq!(w, decoded);
    }

    #[test]
    fn witness_sbor_round_trip() {
        let w = Witness::Shard(sample_shard_witness());
        let bytes = basic_encode(&w).unwrap();
        let decoded: Witness = basic_decode(&bytes).unwrap();
        assert_eq!(w, decoded);
    }

    #[test]
    fn jail_reason_sbor_round_trip_all_variants() {
        for r in [
            JailReason::Performance,
            JailReason::Recovery,
            JailReason::Equivocation,
        ] {
            let bytes = basic_encode(&r).unwrap();
            let decoded: JailReason = basic_decode(&bytes).unwrap();
            assert_eq!(r, decoded);
        }
    }
}
