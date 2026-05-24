//! Beacon-chain recovery: timeout attestations and the self-authenticating
//! certificate they assemble into.
//!
//! When the beacon chain stalls past the recovery timeout at a given
//! anchor, active validators broadcast individually signed
//! [`RecoveryRequest`]s naming `(last_block_hash, last_block_epoch,
//! recovery_round)`. Once ≥⅔ of the active set sign the same triple,
//! anyone can aggregate them into a [`RecoveryCertificate`] that triggers
//! deterministic committee replacement at the consensus layer.
//!
//! The cert's content hash rides inside the next [`BeaconBlockHeader`]'s
//! `recovery_cert_hash` field via [`recovery_cert_hash`], binding it into
//! the post-recovery committee's aggregate signature so the cert body
//! cannot be swapped post-hoc.

use sbor::prelude::*;

use crate::{
    BeaconBlockHash, BeaconBlockHeader, Bls12381G2Signature, BoundedVec, Epoch, Hash,
    MAX_EXCLUDED_VALIDATORS, RecoveryCertHash, RecoveryRound, SignerBitfield, ValidatorId,
};

/// One active validator's signed attestation that the beacon chain has
/// not progressed past `(last_block_hash, last_block_epoch)` within the
/// recovery timeout.
///
/// Gossiped across the full active validator set; ≥⅔ of active signers
/// (one validator one vote) signing the same `(anchor, epoch, round)`
/// triple assemble into a [`RecoveryCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryRequest {
    last_block_hash: BeaconBlockHash,
    last_block_epoch: Epoch,
    recovery_round: RecoveryRound,
    signer: ValidatorId,
    sig: Bls12381G2Signature,
}

impl RecoveryRequest {
    /// Build a `RecoveryRequest` from its parts.
    #[must_use]
    pub const fn new(
        last_block_hash: BeaconBlockHash,
        last_block_epoch: Epoch,
        recovery_round: RecoveryRound,
        signer: ValidatorId,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            last_block_hash,
            last_block_epoch,
            recovery_round,
            signer,
            sig,
        }
    }

    /// Hash of the anchor block the request claims is the latest finalized.
    #[must_use]
    pub const fn last_block_hash(&self) -> BeaconBlockHash {
        self.last_block_hash
    }

    /// Epoch of the anchor block.
    #[must_use]
    pub const fn last_block_epoch(&self) -> Epoch {
        self.last_block_epoch
    }

    /// Which recovery attempt at this anchor this request belongs to.
    #[must_use]
    pub const fn recovery_round(&self) -> RecoveryRound {
        self.recovery_round
    }

    /// Validator that signed this request.
    #[must_use]
    pub const fn signer(&self) -> ValidatorId {
        self.signer
    }

    /// BLS signature over the canonical signing message.
    #[must_use]
    pub const fn sig(&self) -> Bls12381G2Signature {
        self.sig
    }
}

/// Self-authenticating certificate: ≥⅔ of active signers (one validator
/// one vote) attested that no finalization had occurred past
/// `(last_block_hash, last_block_epoch)` within their recovery timeout.
///
/// Triggers deterministic committee replacement when the cert is
/// observed by the beacon state machine. The cert's content hash is
/// bound into the next [`BeaconBlockHeader`]'s `recovery_cert_hash` via
/// [`recovery_cert_hash`] so the post-recovery committee's aggregate
/// signature covers it.
///
/// Signer membership is positional against the active validator set at
/// the anchor block's epoch — [`signers`](Self::signers) is a bitfield
/// indexed into that enumeration, paired with a single aggregate
/// signature that verifies under the union of the corresponding pubkeys.
///
/// `excluded_validators` lists the cumulative set of dead committees
/// from every failed recovery round for this anchor's epoch — used by
/// the recovery-aware committee sampler to avoid landing on
/// already-failed validators. Bounded by
/// [`MAX_EXCLUDED_VALIDATORS`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryCertificate {
    last_block_hash: BeaconBlockHash,
    last_block_epoch: Epoch,
    recovery_round: RecoveryRound,
    excluded_validators: BoundedVec<ValidatorId, MAX_EXCLUDED_VALIDATORS>,
    signers: SignerBitfield,
    aggregate_sig: Bls12381G2Signature,
}

impl RecoveryCertificate {
    /// Build a `RecoveryCertificate` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `excluded_validators.len() > MAX_EXCLUDED_VALIDATORS`.
    #[must_use]
    pub fn new(
        last_block_hash: BeaconBlockHash,
        last_block_epoch: Epoch,
        recovery_round: RecoveryRound,
        excluded_validators: Vec<ValidatorId>,
        signers: SignerBitfield,
        aggregate_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            last_block_hash,
            last_block_epoch,
            recovery_round,
            excluded_validators: excluded_validators.into(),
            signers,
            aggregate_sig,
        }
    }

    /// Cumulative set of validators excluded from the post-recovery
    /// committee sampler — the union of all dead committees across
    /// failed recovery rounds for this anchor's epoch.
    #[must_use]
    pub const fn excluded_validators(&self) -> &BoundedVec<ValidatorId, MAX_EXCLUDED_VALIDATORS> {
        &self.excluded_validators
    }

    /// Hash of the anchor block the cert pins as the chain's latest
    /// finalized.
    #[must_use]
    pub const fn last_block_hash(&self) -> BeaconBlockHash {
        self.last_block_hash
    }

    /// Epoch of the anchor block.
    #[must_use]
    pub const fn last_block_epoch(&self) -> Epoch {
        self.last_block_epoch
    }

    /// Which recovery attempt at this anchor produced this cert.
    #[must_use]
    pub const fn recovery_round(&self) -> RecoveryRound {
        self.recovery_round
    }

    /// Bitfield indicating which validators (by position in the active
    /// set at the anchor's epoch) contributed signatures.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Aggregated BLS signature over the canonical signing message,
    /// verifying under the union of the [`signers`](Self::signers)'
    /// pubkeys.
    #[must_use]
    pub const fn aggregate_sig(&self) -> Bls12381G2Signature {
        self.aggregate_sig
    }

    /// Number of validators that contributed to the aggregate.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }
}

/// Content hash of an optional recovery certificate, used to bind the
/// cert into a [`BeaconBlockHeader`]'s
/// `recovery_cert_hash` field.
///
/// Returns [`RecoveryCertHash::ZERO`] for `None`. For `Some(cert)`,
/// returns the SBOR-encoded cert's hash under the workspace `Hash`
/// function.
///
/// # Cryptographic assumption
///
/// Aliasing condition: a `Some(cert)` whose SBOR hash happens to be all
/// zero would alias `None`. Under BLAKE3's pre-image resistance (~2^256)
/// and collision resistance (~2^128 birthday work for a 32-byte digest),
/// this is cryptographically infeasible — but if BLAKE3 were broken, an
/// attacker could swap the cert body to `None` while keeping the header
/// verifying against the same committee aggregate.
///
/// # Panics
///
/// Panics if SBOR encoding fails — `RecoveryCertificate` is a closed
/// SBOR type and encoding is infallible in practice.
#[must_use]
pub fn recovery_cert_hash(cert: Option<&RecoveryCertificate>) -> RecoveryCertHash {
    cert.map_or(RecoveryCertHash::ZERO, |c| {
        let bytes = basic_encode(c).expect("RecoveryCertificate serialization should never fail");
        RecoveryCertHash::from_raw(Hash::from_bytes(&bytes))
    })
}

/// Self-authenticating evidence that a single validator signed both:
///   1. a [`RecoveryRequest`] claiming `request.last_block_hash` was their
///      latest finalized view, AND
///   2. a finalized [`BeaconBlock`](crate::BeaconBlock) at a epoch
///      strictly greater than `request.last_block_epoch`.
///
/// The two attestations are semantically contradictory. The recovery
/// request is carried verbatim; the finalized block is collapsed to
/// just the header plus its committee aggregate (`block_signers` +
/// `block_aggregate_sig`) — enough for the verifier to confirm the
/// equivocator's BLS sig contributed to the aggregate without
/// shipping the full block body.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryEquivocation {
    /// Validator whose double-attestation is the evidence.
    pub validator: ValidatorId,
    /// Recovery request claiming the anchor was the validator's latest view.
    pub request: RecoveryRequest,
    /// Header of a beacon block finalized strictly past
    /// `request.last_block_epoch`.
    pub block_header: BeaconBlockHeader,
    /// Committee bitfield from the finalized block. The equivocator's
    /// position is set; the verifier confirms membership and reruns the
    /// aggregate-sig check.
    pub block_signers: SignerBitfield,
    /// Aggregate signature over `block_header`'s canonical bytes from
    /// the bits in `block_signers`.
    pub block_aggregate_sig: Bls12381G2Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert() -> RecoveryCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        RecoveryCertificate::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            RecoveryRound::new(1),
            Vec::new(),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    fn sample_request() -> RecoveryRequest {
        RecoveryRequest::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            RecoveryRound::new(1),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    #[test]
    fn cert_sbor_round_trip() {
        let original = sample_cert();
        let bytes = basic_encode(&original).unwrap();
        let decoded: RecoveryCertificate = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn request_sbor_round_trip() {
        let original = sample_request();
        let bytes = basic_encode(&original).unwrap();
        let decoded: RecoveryRequest = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_signer_count_reflects_bitfield() {
        let cert = sample_cert();
        assert_eq!(cert.signer_count(), 3);
    }

    #[test]
    fn recovery_cert_hash_of_none_is_zero() {
        assert_eq!(recovery_cert_hash(None), RecoveryCertHash::ZERO);
    }

    #[test]
    fn recovery_cert_hash_of_some_is_not_zero() {
        let cert = sample_cert();
        assert_ne!(recovery_cert_hash(Some(&cert)), RecoveryCertHash::ZERO);
    }

    #[test]
    fn recovery_cert_hash_is_content_sensitive() {
        let a = sample_cert();
        let b = RecoveryCertificate::new(
            a.last_block_hash(),
            a.last_block_epoch(),
            a.recovery_round().next(),
            Vec::new(),
            a.signers().clone(),
            a.aggregate_sig(),
        );
        assert_ne!(recovery_cert_hash(Some(&a)), recovery_cert_hash(Some(&b)));
    }

    #[test]
    fn recovery_cert_hash_is_deterministic() {
        let cert = sample_cert();
        assert_eq!(
            recovery_cert_hash(Some(&cert)),
            recovery_cert_hash(Some(&cert))
        );
    }

    fn sample_recovery_equivocation() -> RecoveryEquivocation {
        use crate::{BeaconProposalsRoot, BeaconStateRoot};
        let mut block_signers = SignerBitfield::new(4);
        block_signers.set(0);
        block_signers.set(1);
        block_signers.set(2);
        RecoveryEquivocation {
            validator: ValidatorId::new(2),
            request: sample_request(),
            block_header: BeaconBlockHeader::new(
                Epoch::new(8),
                BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
                BeaconProposalsRoot::from_raw(Hash::from_bytes(b"proposals")),
                BeaconStateRoot::from_raw(Hash::from_bytes(b"state")),
                RecoveryCertHash::ZERO,
            ),
            block_signers,
            block_aggregate_sig: Bls12381G2Signature([0x44; 96]),
        }
    }

    #[test]
    fn recovery_equivocation_sbor_round_trip() {
        let e = sample_recovery_equivocation();
        let bytes = basic_encode(&e).unwrap();
        let decoded: RecoveryEquivocation = basic_decode(&bytes).unwrap();
        assert_eq!(e, decoded);
    }
}
