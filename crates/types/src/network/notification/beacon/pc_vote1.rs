//! Prefix Consensus round-1 vote notification.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, PcVote1};

/// PC round-1 vote sent via unicast to peers in the slot's committee.
///
/// The inner [`PcVote1`] is self-authenticating — it carries the signer
/// id and one BLS signature per prefix of `v_in`. The notification is a
/// thin envelope so the network layer can dispatch typed handlers.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcVote1Notification {
    /// The vote.
    pub vote: Arc<PcVote1>,
}

impl PcVote1Notification {
    /// Wrap a [`PcVote1`] for notification.
    #[must_use]
    pub fn new(vote: impl Into<Arc<PcVote1>>) -> Self {
        Self { vote: vote.into() }
    }

    /// Get the inner vote.
    #[must_use]
    pub fn vote(&self) -> &PcVote1 {
        &self.vote
    }

    /// Consume and return the inner vote.
    #[must_use]
    pub fn into_vote(self) -> Arc<PcVote1> {
        self.vote
    }
}

impl NetworkMessage for PcVote1Notification {
    fn message_type_id() -> &'static str {
        "beacon.pc.vote1"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::{Bls12381G2Signature, PcVector, ValidatorId};

    fn sample_vote() -> PcVote1 {
        PcVote1::new(
            ValidatorId::new(2),
            PcVector::empty(),
            vec![Bls12381G2Signature([0x11; 96])],
        )
    }

    #[test]
    fn sbor_round_trip() {
        let n = PcVote1Notification::new(sample_vote());
        let bytes = basic_encode(&n).unwrap();
        let decoded: PcVote1Notification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(PcVote1Notification::class(), MessageClass::Consensus);
    }
}
