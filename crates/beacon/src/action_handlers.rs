//! Delegated-action handlers for beacon-owned [`Action`] variants.
//!
//! Mirrors `crates/shard/src/action_handlers.rs` in shape — pure
//! dispatch off the `io_loop` thread for verification, signing, and
//! network broadcasts. Results return to the state machine via
//! `ctx.notify(ProtocolEvent::*)`.

use hyperscale_core::{Action, ActionContext};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use tracing::warn;

/// Process one beacon-owned action.
///
/// Variants owned by other coordinator crates hit `unreachable!()` —
/// the caller (node's dispatcher) routes by variant prefix.
///
/// Stub: handler bodies land in B.8 when sub-machine wiring goes in.
/// For now every variant just logs.
#[allow(clippy::needless_pass_by_value)] // ctx pattern shared with other handlers
pub fn handle_action<S, N>(action: Action, _ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    match action {
        Action::SignAndBroadcastPcVote { .. }
        | Action::SignAndBroadcastSpcMessage { .. }
        | Action::BroadcastBeaconBlock { .. }
        | Action::BroadcastRecoveryRequest { .. }
        | Action::FetchShardWitnesses { .. }
        | Action::VerifyBeaconRoot { .. } => {
            warn!(
                action = action.type_name(),
                "beacon action handler is a stub; B.8 wires the real handler",
            );
        }
        other => unreachable!(
            "beacon::handle_action called with non-beacon action: {}",
            other.type_name()
        ),
    }
}
