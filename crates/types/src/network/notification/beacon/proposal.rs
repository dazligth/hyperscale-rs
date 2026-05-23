//! MSC slot proposal notification.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{
    BoundedVec, MAX_ACCUSATIONS_PER_PROPOSAL, MessageClass, MscEmptyLowAccusation, MscSlotProposal,
    NetworkMessage,
};

/// One committee member's slot proposal plus any empty-low accusations
/// they've accumulated from earlier slots' SPC views.
///
/// Sent via unicast notification to every other committee member.
/// MSC's pipeline ingests each peer's proposal, then runs PC over the
/// `(validator, content)` pairs to reach agreement on the slot's
/// committed set. PC's per-round votes are individually signed, so the
/// notification itself is unsigned — sender identity comes from the
/// authenticated transport, and bogus content is filtered out
/// downstream when the corresponding PC votes fail to verify or fail
/// to aggregate into a quorum.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct MscSlotProposalNotification {
    /// The slot proposal — slot id + opaque content.
    pub proposal: Arc<MscSlotProposal>,
    /// Empty-low accusations the sender accumulated from earlier
    /// slots' SPC views (paper §7.2.2). MSC's ranking update on
    /// accepting the proposal applies any new accusations to demote
    /// the accused validators.
    pub accusations: BoundedVec<MscEmptyLowAccusation, MAX_ACCUSATIONS_PER_PROPOSAL>,
}

impl MscSlotProposalNotification {
    /// Build a slot proposal notification from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `accusations.len() > MAX_ACCUSATIONS_PER_PROPOSAL`.
    #[must_use]
    pub fn new(
        proposal: impl Into<Arc<MscSlotProposal>>,
        accusations: Vec<MscEmptyLowAccusation>,
    ) -> Self {
        Self {
            proposal: proposal.into(),
            accusations: accusations.into(),
        }
    }

    /// The slot proposal.
    #[must_use]
    pub fn proposal(&self) -> &MscSlotProposal {
        &self.proposal
    }

    /// Empty-low accusations carried alongside the proposal.
    #[must_use]
    pub const fn accusations(
        &self,
    ) -> &BoundedVec<MscEmptyLowAccusation, MAX_ACCUSATIONS_PER_PROPOSAL> {
        &self.accusations
    }
}

impl NetworkMessage for MscSlotProposalNotification {
    fn message_type_id() -> &'static str {
        "beacon.proposal"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::{
        Bls12381G2Signature, PcQc2, PcQc3, PcValueElement, PcVector, PcXpProof, SignerBitfield,
        Slot, SpcView,
    };

    fn sample_pc_qc3() -> PcQc3 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            signers,
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full {
                length_multi_sig: Bls12381G2Signature([0x22; 96]),
            },
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            Vec::new(),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_notification() -> MscSlotProposalNotification {
        let content = PcVector::new([PcValueElement::new([0xCD; 32])]);
        let proposal = MscSlotProposal {
            slot: Slot::new(42),
            content,
        };
        let accusations = vec![MscEmptyLowAccusation {
            slot: Slot::new(41),
            view: SpcView::new(3),
            proof: sample_pc_qc3(),
        }];
        MscSlotProposalNotification::new(proposal, accusations)
    }

    #[test]
    fn sbor_round_trip() {
        let n = sample_notification();
        let bytes = basic_encode(&n).unwrap();
        let decoded: MscSlotProposalNotification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(
            MscSlotProposalNotification::class(),
            MessageClass::Consensus
        );
    }
}
