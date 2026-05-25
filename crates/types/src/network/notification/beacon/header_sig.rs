//! One committee member's BLS signature over a `BeaconBlockHeader`.

use sbor::prelude::BasicSbor;

use crate::{Bls12381G2Signature, Epoch, MessageClass, NetworkMessage, ValidatorId};

/// One committee member's BLS signature over the canonical bytes of
/// a beacon block header.
///
/// The header itself isn't carried on the wire — both the signer and
/// the verifier reach the same header bytes deterministically from
/// SPC's committed `OutputHigh`, the local view of admitted
/// `BeaconProposal`s, and the post-`apply_epoch` state. Receivers
/// reconstruct the expected header and verify `sig` against it under
/// `signer`'s pubkey for `(network.id, header_hash)` per
/// [`beacon_block_header_message`](crate::beacon_block_header_message).
///
/// A receiver that disagrees on the header (because they haven't
/// reached `OutputHigh` yet, or admitted a different proposal set)
/// either buffers the sig or rejects it on verification. Aggregating
/// ≥ ⅔ of committee sigs produces the `BeaconBlock`'s aggregate.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconBlockHeaderSigNotification {
    /// Epoch the signed header finalizes. Receivers look up the
    /// expected header by this key.
    pub epoch: Epoch,
    /// Validator that produced the signature.
    pub signer: ValidatorId,
    /// BLS signature over the canonical header bytes.
    pub sig: Bls12381G2Signature,
}

impl BeaconBlockHeaderSigNotification {
    /// Build a notification from its parts.
    #[must_use]
    pub const fn new(epoch: Epoch, signer: ValidatorId, sig: Bls12381G2Signature) -> Self {
        Self { epoch, signer, sig }
    }
}

impl NetworkMessage for BeaconBlockHeaderSigNotification {
    fn message_type_id() -> &'static str {
        "beacon.block_header_sig"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;

    #[test]
    fn sbor_round_trip() {
        let n = BeaconBlockHeaderSigNotification::new(
            Epoch::new(5),
            ValidatorId::new(2),
            Bls12381G2Signature([0x11; 96]),
        );
        let bytes = basic_encode(&n).unwrap();
        let decoded: BeaconBlockHeaderSigNotification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(
            BeaconBlockHeaderSigNotification::class(),
            MessageClass::Consensus,
        );
    }
}
