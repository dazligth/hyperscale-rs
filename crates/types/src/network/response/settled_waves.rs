//! Settled-waves window response for the split-boundary fence.

use sbor::prelude::BasicSbor;

use crate::{BoundedVec, MAX_FINALIZED_TX_PER_BLOCK, MessageClass, NetworkMessage, WaveId};

/// The complete settled-wave window list of a terminated shard.
///
/// `waves` is `S_P` in full: every wave-id `P` settled in
/// `[B − RETENTION_HORIZON, B]`. Verified, not trusted bare — the
/// requester recomputes `settled_waves_root_from_ids(waves)` and accepts
/// only when it equals the beacon-attested `settled_waves_root`. Because
/// the root commits the whole set, a server can neither hide a settled
/// wave (a missing leaf changes the root) nor fabricate one, so the
/// verified-complete set makes the absence of any wave from it sound.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetSettledWavesResponse {
    /// The terminated shard's complete settled-wave window list, or `None`
    /// when this peer doesn't hold the terminal block — the requester
    /// rotates to another terminal-committee member.
    pub waves: Option<BoundedVec<WaveId, MAX_FINALIZED_TX_PER_BLOCK>>,
}

impl GetSettledWavesResponse {
    /// A complete window list for the terminated shard.
    #[must_use]
    pub const fn found(waves: BoundedVec<WaveId, MAX_FINALIZED_TX_PER_BLOCK>) -> Self {
        Self { waves: Some(waves) }
    }

    /// This peer can't serve the requested terminal block.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { waves: None }
    }
}

impl NetworkMessage for GetSettledWavesResponse {
    fn message_type_id() -> &'static str {
        "settled_waves.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{BlockHeight, ShardId};

    #[test]
    fn test_sbor_roundtrip_not_found() {
        let response = GetSettledWavesResponse::not_found();
        let encoded = basic_encode(&response).unwrap();
        let decoded: GetSettledWavesResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_found() {
        let wave = WaveId::new(
            ShardId::ROOT,
            BlockHeight::new(7),
            std::iter::empty().collect(),
        );
        let response = GetSettledWavesResponse::found(vec![wave].into());
        let encoded = basic_encode(&response).unwrap();
        let decoded: GetSettledWavesResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
