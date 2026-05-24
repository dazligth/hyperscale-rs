//! Domain-separated signing for validator "ready on shard" signals.

use crate::{BlockHeight, NetworkDefinition, ValidatorId};

/// Domain tag for validator "ready on shard" signals.
///
/// Format: `HYPERSCALE_READY_SIGNAL_v1` || `network.id` || `validator_id` ||
/// `height_window_start` || `height_window_end`
///
/// Signed by the validator and broadcast to their shard committee. The
/// proposer includes valid dwell-eligible signals in the next block's
/// manifest; verifiers re-derive these bytes to check the BLS sig
/// before admitting the signal to their local pool. The window bounds
/// replay surface — a signal hoarded past `end` no longer validates.
pub const DOMAIN_READY_SIGNAL: &[u8] = b"HYPERSCALE_READY_SIGNAL_v1";

/// Build the canonical signing bytes for a
/// [`ReadySignal`](crate::ReadySignal).
#[must_use]
pub fn ready_signal_message(
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    height_window_start: BlockHeight,
    height_window_end: BlockHeight,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8);
    message.extend_from_slice(DOMAIN_READY_SIGNAL);
    message.push(network.id);
    message.extend_from_slice(&validator_id.to_le_bytes());
    message.extend_from_slice(&height_window_start.to_le_bytes());
    message.extend_from_slice(&height_window_end.to_le_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn ready_signal_message_byte_layout_is_pinned() {
        let network = net();
        let validator = ValidatorId::new(0x0123_4567_89AB_CDEF);
        let start = BlockHeight::new(100);
        let end = BlockHeight::new(228);

        let msg = ready_signal_message(&network, validator, start, end);
        let mut expected = Vec::with_capacity(DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8);
        expected.extend_from_slice(DOMAIN_READY_SIGNAL);
        expected.push(network.id);
        expected.extend_from_slice(&validator.to_le_bytes());
        expected.extend_from_slice(&start.to_le_bytes());
        expected.extend_from_slice(&end.to_le_bytes());

        assert_eq!(msg, expected);
        assert_eq!(msg.len(), DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8);
    }

    #[test]
    fn ready_signal_message_differs_by_window() {
        let validator = ValidatorId::new(7);
        let a = ready_signal_message(&net(), validator, BlockHeight::new(0), BlockHeight::new(1));
        let b = ready_signal_message(&net(), validator, BlockHeight::new(0), BlockHeight::new(2));
        assert_ne!(a, b);
    }
}
