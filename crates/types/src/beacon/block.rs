//! [`BeaconBlock`] — the committee-finalized record of one slot.
//!
//! A `BeaconBlock` pairs a constant-size [`BeaconBlockHeader`] with a BLS
//! aggregate signature from the slot's committee. The aggregate verifies
//! in O(1) against the union of the signers' pubkeys, so the block is
//! self-authenticating against any caller that holds the slot's committee
//! enumeration.
//!
//! Recovery certificates ride inline as `Option<RecoveryCertificate>`,
//! bound into the committee's aggregate signature via the header's
//! [`recovery_cert_hash`](BeaconBlockHeader::recovery_cert_hash) field —
//! the body cannot be swapped after the committee signs the header.

use sbor::prelude::*;

use crate::{
    BeaconBlockHash, BeaconBlockHeader, BeaconStateRoot, Bls12381G2Signature, RecoveryCertificate,
    SignerBitfield, Slot, zero_bls_signature,
};

/// A committee-finalized beacon block: header + BLS aggregate over the
/// header bytes, optionally carrying the recovery certificate that
/// justifies the slot's committee.
///
/// The aggregate verifies under the union of [`signers`](Self::signers)'
/// pubkeys, which the verifier resolves through the slot's committee
/// enumeration (positional bitfield).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconBlock {
    header: BeaconBlockHeader,
    signers: SignerBitfield,
    aggregate_sig: Bls12381G2Signature,
    recovery_cert: Option<RecoveryCertificate>,
}

impl BeaconBlock {
    /// Build a `BeaconBlock` from its parts.
    ///
    /// Field-level validation (signer count vs quorum, header
    /// `recovery_cert_hash` matching the cert's content hash, aggregate
    /// verifying under the committee) is the responsibility of the
    /// beacon consensus crate — this is a pure data constructor.
    #[must_use]
    pub const fn new(
        header: BeaconBlockHeader,
        signers: SignerBitfield,
        aggregate_sig: Bls12381G2Signature,
        recovery_cert: Option<RecoveryCertificate>,
    ) -> Self {
        Self {
            header,
            signers,
            aggregate_sig,
            recovery_cert,
        }
    }

    /// Genesis block (slot 0): genesis header with the given state root,
    /// empty signer set, zero aggregate signature, no recovery cert.
    #[must_use]
    pub const fn genesis(state_root: BeaconStateRoot) -> Self {
        Self {
            header: BeaconBlockHeader::genesis(state_root),
            signers: SignerBitfield::empty(),
            aggregate_sig: zero_bls_signature(),
            recovery_cert: None,
        }
    }

    /// Header — the committee-signed metadata.
    #[must_use]
    pub const fn header(&self) -> &BeaconBlockHeader {
        &self.header
    }

    /// Bitfield indicating which committee members contributed signatures.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Aggregated BLS signature over [`header`](Self::header)'s canonical
    /// bytes, verifying under the union of [`signers`](Self::signers)'
    /// pubkeys.
    #[must_use]
    pub const fn aggregate_sig(&self) -> Bls12381G2Signature {
        self.aggregate_sig
    }

    /// Recovery certificate that justifies this block, if any. `Some` for
    /// the first block produced by a freshly resampled committee after
    /// recovery; `None` otherwise.
    ///
    /// The cert's content hash is bound into
    /// [`BeaconBlockHeader::recovery_cert_hash`], which rides inside the
    /// committee's aggregate signature — verifiers reject any mismatch
    /// between header and body.
    #[must_use]
    pub const fn recovery_cert(&self) -> Option<&RecoveryCertificate> {
        self.recovery_cert.as_ref()
    }

    /// Slot this block finalizes (delegates to the header).
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.header.slot()
    }

    /// Hash of this block (delegates to [`BeaconBlockHeader::hash`]).
    #[must_use]
    pub fn block_hash(&self) -> BeaconBlockHash {
        self.header.hash()
    }

    /// Whether this is the genesis block (slot 0).
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.header.is_genesis()
    }

    /// Number of validators that contributed to the aggregate.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BeaconProposalsRoot, Hash, RecoveryCertHash, RecoveryRound, recovery_cert_hash};

    fn sample_header(recovery_cert_hash_value: RecoveryCertHash) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            Slot::new(7),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            BeaconProposalsRoot::from_raw(Hash::from_bytes(b"proposals")),
            BeaconStateRoot::from_raw(Hash::from_bytes(b"state")),
            recovery_cert_hash_value,
        )
    }

    fn sample_cert() -> RecoveryCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        RecoveryCertificate::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Slot::new(5),
            RecoveryRound::new(1),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    fn sample_signers() -> SignerBitfield {
        let mut s = SignerBitfield::new(8);
        s.set(0);
        s.set(2);
        s.set(5);
        s.set(7);
        s
    }

    #[test]
    fn sbor_round_trip_without_recovery_cert() {
        let original = BeaconBlock::new(
            sample_header(RecoveryCertHash::ZERO),
            sample_signers(),
            Bls12381G2Signature([0x11; 96]),
            None,
        );
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn sbor_round_trip_with_recovery_cert() {
        let cert = sample_cert();
        let original = BeaconBlock::new(
            sample_header(recovery_cert_hash(Some(&cert))),
            sample_signers(),
            Bls12381G2Signature([0x11; 96]),
            Some(cert),
        );
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconBlock = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn block_hash_delegates_to_header() {
        let block = BeaconBlock::new(
            sample_header(RecoveryCertHash::ZERO),
            sample_signers(),
            Bls12381G2Signature([0x11; 96]),
            None,
        );
        assert_eq!(block.block_hash(), block.header().hash());
    }

    #[test]
    fn signer_count_reflects_bitfield() {
        let block = BeaconBlock::new(
            sample_header(RecoveryCertHash::ZERO),
            sample_signers(),
            Bls12381G2Signature([0x11; 96]),
            None,
        );
        assert_eq!(block.signer_count(), 4);
    }

    #[test]
    fn genesis_has_empty_signers_and_no_recovery_cert() {
        let state_root = BeaconStateRoot::from_raw(Hash::from_bytes(b"genesis-state"));
        let g = BeaconBlock::genesis(state_root);
        assert!(g.is_genesis());
        assert_eq!(g.slot(), Slot::GENESIS);
        assert_eq!(g.signer_count(), 0);
        assert_eq!(g.aggregate_sig().0, [0u8; 96]);
        assert!(g.recovery_cert().is_none());
        assert_eq!(g.header().state_root(), state_root);
    }

    /// Constructor accepts mismatched header / body; binding-correctness
    /// is the consensus crate's job. This pin documents the type-level
    /// contract.
    #[test]
    fn constructor_does_not_check_header_body_binding() {
        let cert = sample_cert();
        // Header advertises ZERO but body carries Some(cert).
        let mismatched = BeaconBlock::new(
            sample_header(RecoveryCertHash::ZERO),
            sample_signers(),
            Bls12381G2Signature([0x11; 96]),
            Some(cert.clone()),
        );
        assert_ne!(
            mismatched.header().recovery_cert_hash(),
            recovery_cert_hash(Some(&cert)),
        );
        // But the struct decoded fine.
        let bytes = basic_encode(&mismatched).unwrap();
        let _round_tripped: BeaconBlock = basic_decode(&bytes).unwrap();
    }
}
