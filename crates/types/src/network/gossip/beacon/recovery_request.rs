//! Recovery-request gossip — broadcast to the active validator set.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{MessageClass, NetworkMessage, RecoveryRequest};

/// Broadcasts one active validator's signed recovery attestation.
///
/// Gossiped across the full active validator set; ≥⅔ of active signers
/// (one validator one vote) signing the same `(anchor, slot, round)`
/// triple assemble into a [`RecoveryCertificate`](crate::RecoveryCertificate)
/// that triggers deterministic committee replacement.
///
/// The inner [`RecoveryRequest`] is self-authenticating — it carries
/// the signer id and a BLS signature. Each validator publishes a
/// distinct request with their own signature, so per-publisher bytes
/// differ and gossipsub's bytes-id dedup handles accidental
/// re-publications without an explicit content-key dedup.
///
/// `MessageClass::Consensus` — recovery liveness is round-blocking by
/// definition: until ≥⅔ of active signers' requests assemble, the
/// chain doesn't make progress.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryRequestGossip {
    /// The signed recovery request.
    pub request: Arc<RecoveryRequest>,
}

impl RecoveryRequestGossip {
    /// Wrap a [`RecoveryRequest`] for gossip broadcast.
    #[must_use]
    pub fn new(request: impl Into<Arc<RecoveryRequest>>) -> Self {
        Self {
            request: request.into(),
        }
    }

    /// Get the inner request.
    #[must_use]
    pub fn request(&self) -> &RecoveryRequest {
        &self.request
    }

    /// Consume and return the inner request.
    #[must_use]
    pub fn into_request(self) -> Arc<RecoveryRequest> {
        self.request
    }
}

impl NetworkMessage for RecoveryRequestGossip {
    fn message_type_id() -> &'static str {
        "beacon.recovery_request"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl GossipMessage for RecoveryRequestGossip {
    const SCOPE: TopicScope = TopicScope::Global;
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::{BeaconBlockHash, Bls12381G2Signature, Hash, RecoveryRound, Slot, ValidatorId};

    fn sample_request() -> RecoveryRequest {
        RecoveryRequest::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Slot::new(7),
            RecoveryRound::new(1),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    #[test]
    fn sbor_round_trip() {
        let g = RecoveryRequestGossip::new(sample_request());
        let bytes = basic_encode(&g).unwrap();
        let decoded: RecoveryRequestGossip = basic_decode(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(RecoveryRequestGossip::class(), MessageClass::Consensus);
    }

    #[test]
    fn scope_is_global() {
        assert!(matches!(RecoveryRequestGossip::SCOPE, TopicScope::Global));
    }
}
