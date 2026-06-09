//! Async-verification bookkeeping for beacon-side crypto checks.
//!
//! Pure verifiers live alongside their wire types in
//! [`hyperscale_types::beacon`]; this module owns the in-flight slot
//! pools the coordinator uses to dedup crypto-check dispatch.

use std::collections::BTreeSet;

use hyperscale_types::{BeaconBlockHash, Epoch, PcVoteRound, SpcView, ValidatorId};

/// In-flight verification slots over an arbitrary key.
///
/// The coordinator marks a slot when it dispatches the verification
/// action and clears it when the result lands (or the slot is otherwise
/// no longer needed). A marked slot suppresses redundant redispatch of
/// the same check.
#[derive(Debug)]
struct VerificationSlots<K> {
    in_flight: BTreeSet<K>,
}

impl<K> Default for VerificationSlots<K> {
    fn default() -> Self {
        Self {
            in_flight: BTreeSet::new(),
        }
    }
}

impl<K: Ord> VerificationSlots<K> {
    /// Returns `true` when newly inserted, `false` when a slot for this
    /// key is already in flight.
    fn mark_in_flight(&mut self, key: K) -> bool {
        self.in_flight.insert(key)
    }

    fn clear(&mut self, key: &K) {
        self.in_flight.remove(key);
    }

    fn is_in_flight(&self, key: &K) -> bool {
        self.in_flight.contains(key)
    }

    fn len(&self) -> usize {
        self.in_flight.len()
    }
}

/// Slot key for a pending PC-vote verification.
///
/// Per-`(epoch, view, signer, round)` because a Byzantine signer may
/// dispatch divergent votes at the same round within a view; each gets
/// its own slot so the post-verify equivocation check sees both.
pub type PcVoteSlotKey = (Epoch, SpcView, ValidatorId, PcVoteRound);

/// Which SPC message kind a verification slot refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpcMsgKind {
    /// `NewView` cert verification.
    NewView,
    /// `NewCommit` embedded QC3 verification.
    NewCommit,
    /// `EmptyView` sig + embedded QC3 verification.
    EmptyView,
}

/// Slot key for a pending SPC message verification.
pub type SpcMsgSlotKey = (Epoch, SpcView, ValidatorId, SpcMsgKind);

/// Slot key for a pending skip-request sig verification.
///
/// Per-`(anchor, epoch_to_skip, signer)` — the canonical identity of a
/// skip request, independent of its signature bytes. Keying on identity
/// rather than the encoded-request hash bounds a Byzantine peer to one
/// in-flight slot per claimed signer: replaying the same triple with
/// forged signatures can't mint additional verification slots. The slot
/// clears on both verify arms (the key rides back in the result event),
/// so a failed forgery can't pin a signer's slot and block their later
/// honest request.
pub type SkipRequestSlotKey = (BeaconBlockHash, Epoch, ValidatorId);

/// Tracks asynchronous beacon verifications dispatched to the crypto
/// pool, suppressing redundant redispatch while a check is outstanding.
///
/// Four domains, each an independent in-flight slot pool:
/// - Block-cert verifications, keyed on [`BeaconBlockHash`].
/// - Skip-request sig verifications, keyed on
///   `(anchor, epoch_to_skip, signer)`.
/// - PC-vote verifications, keyed on `(epoch, view, signer, round)`.
/// - SPC message verifications, keyed on
///   `(epoch, view, sender, msg-kind)`.
///
/// Domains never share keys by construction — different `K` types per
/// slot pool.
#[derive(Debug, Default)]
pub struct BeaconVerificationPipeline {
    blocks: VerificationSlots<BeaconBlockHash>,
    skip_requests: VerificationSlots<SkipRequestSlotKey>,
    pc_votes: VerificationSlots<PcVoteSlotKey>,
    spc_msgs: VerificationSlots<SpcMsgSlotKey>,
}

impl BeaconVerificationPipeline {
    /// Empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a block-cert verification in flight. Returns `true` when
    /// newly inserted, `false` when a slot for this block is already in
    /// flight — caller treats `false` as "don't redispatch".
    pub fn mark_block_in_flight(&mut self, block_hash: BeaconBlockHash) -> bool {
        self.blocks.mark_in_flight(block_hash)
    }

    /// Clear the block slot once its verification result lands, or after
    /// the block is adopted.
    pub fn forget_block(&mut self, block_hash: BeaconBlockHash) {
        self.blocks.clear(&block_hash);
    }

    /// Mark a skip-request sig verification in flight. Same semantics as
    /// [`Self::mark_block_in_flight`].
    pub fn mark_skip_request_in_flight(&mut self, key: SkipRequestSlotKey) -> bool {
        self.skip_requests.mark_in_flight(key)
    }

    /// Clear the skip-request slot once its result lands.
    pub fn forget_skip_request(&mut self, key: SkipRequestSlotKey) {
        self.skip_requests.clear(&key);
    }

    /// Mark a PC-vote verification in flight. Same semantics as
    /// [`Self::mark_block_in_flight`].
    pub fn mark_pc_vote_in_flight(&mut self, key: PcVoteSlotKey) -> bool {
        self.pc_votes.mark_in_flight(key)
    }

    /// Clear the PC-vote slot once its result lands.
    pub fn forget_pc_vote(&mut self, key: PcVoteSlotKey) {
        self.pc_votes.clear(&key);
    }

    /// Mark an SPC message verification in flight.
    pub fn mark_spc_msg_in_flight(&mut self, key: SpcMsgSlotKey) -> bool {
        self.spc_msgs.mark_in_flight(key)
    }

    /// Clear the SPC message slot once its result lands.
    pub fn forget_spc_msg(&mut self, key: SpcMsgSlotKey) {
        self.spc_msgs.clear(&key);
    }
}

// Flat queries; names are the documentation.
#[allow(missing_docs)]
impl BeaconVerificationPipeline {
    #[must_use]
    pub fn is_block_in_flight(&self, block_hash: BeaconBlockHash) -> bool {
        self.blocks.is_in_flight(&block_hash)
    }

    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.blocks.len() + self.skip_requests.len() + self.pc_votes.len() + self.spc_msgs.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Hash;

    use super::*;

    fn block_hash(seed: u8) -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(&[seed]))
    }

    fn skip_key(seed: u8) -> SkipRequestSlotKey {
        (
            BeaconBlockHash::from_raw(Hash::from_bytes(&[seed])),
            Epoch::new(u64::from(seed)),
            ValidatorId::new(u64::from(seed)),
        )
    }

    #[test]
    fn empty_after_new() {
        let p = BeaconVerificationPipeline::new();
        assert_eq!(p.in_flight_count(), 0);
        assert!(!p.is_block_in_flight(block_hash(0)));
    }

    #[test]
    fn mark_block_in_flight_first_time_returns_true() {
        let mut p = BeaconVerificationPipeline::new();
        assert!(p.mark_block_in_flight(block_hash(1)));
        assert!(p.is_block_in_flight(block_hash(1)));
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn duplicate_mark_returns_false() {
        let mut p = BeaconVerificationPipeline::new();
        assert!(p.mark_block_in_flight(block_hash(1)));
        assert!(!p.mark_block_in_flight(block_hash(1)));
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn forget_clears_in_flight_and_allows_remark() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(2));
        p.forget_block(block_hash(2));
        assert!(!p.is_block_in_flight(block_hash(2)));
        // A cleared slot is markable again.
        assert!(p.mark_block_in_flight(block_hash(2)));
    }

    #[test]
    fn forget_unknown_slot_is_noop() {
        let mut p = BeaconVerificationPipeline::new();
        p.forget_block(block_hash(99));
        assert!(!p.is_block_in_flight(block_hash(99)));
        assert_eq!(p.in_flight_count(), 0);
    }

    #[test]
    fn domains_are_independent() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(5));
        p.mark_skip_request_in_flight(skip_key(5));
        assert_eq!(p.in_flight_count(), 2);
        p.forget_block(block_hash(5));
        assert_eq!(p.in_flight_count(), 1);
    }
}
