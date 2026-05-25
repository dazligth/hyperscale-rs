//! Delegated-action handlers for beacon-owned [`Action`] variants.
//!
//! Each handler runs off the `io_loop` thread on the Consensus
//! dispatch pool; results return to the state machine via
//! `ctx.notify(ProtocolEvent::*)`. The node's dispatcher matches the
//! `Action` variant and calls the corresponding handler directly.

// Handlers take owned payloads that real bodies consume (sign,
// broadcast, verify); stubs don't touch them yet.
#![allow(clippy::needless_pass_by_value)]
// Handler names mirror the Action variants they serve; redocumenting
// in prose adds no information over the signature.
#![allow(missing_docs)]

use std::sync::Arc;

use hyperscale_core::{ActionContext, BeaconVerificationKind};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{
    BeaconBlock, BlockHash, Epoch, Hash, LeafIndex, PcVector, PcVoteRound, RecoveryRequest,
    ShardGroupId, SpcView, ValidatorId,
};
use tracing::warn;

pub fn sign_and_broadcast_pc_vote<S: ShardStorage, N: Network>(
    _ctx: &ActionContext<'_, S, N>,
    epoch: Epoch,
    view: SpcView,
    _round: PcVoteRound,
    _value: PcVector,
    _recipients: Vec<ValidatorId>,
) {
    warn!(
        epoch = epoch.inner(),
        view = view.inner(),
        "SignAndBroadcastPcVote",
    );
}

pub fn sign_and_broadcast_spc_message<S: ShardStorage, N: Network>(
    _ctx: &ActionContext<'_, S, N>,
    epoch: Epoch,
    _payload: Vec<u8>,
    _recipients: Vec<ValidatorId>,
) {
    warn!(epoch = epoch.inner(), "SignAndBroadcastSpcMessage");
}

pub fn broadcast_beacon_block<S: ShardStorage, N: Network>(
    _ctx: &ActionContext<'_, S, N>,
    block: Arc<BeaconBlock>,
) {
    warn!(epoch = block.epoch().inner(), "BroadcastBeaconBlock");
}

pub fn broadcast_recovery_request<S: ShardStorage, N: Network>(
    _ctx: &ActionContext<'_, S, N>,
    request: Arc<RecoveryRequest>,
    _recipients: Vec<ValidatorId>,
) {
    warn!(
        anchor_epoch = request.last_block_epoch().inner(),
        round = request.recovery_round().inner(),
        "BroadcastRecoveryRequest",
    );
}

pub fn fetch_shard_witnesses<S: ShardStorage, N: Network>(
    _ctx: &ActionContext<'_, S, N>,
    shard_id: ShardGroupId,
    _committed_block_hash: BlockHash,
    leaf_indices: Vec<LeafIndex>,
    _peers: Vec<ValidatorId>,
) {
    warn!(
        shard = shard_id.inner(),
        leaves = leaf_indices.len(),
        "FetchShardWitnesses",
    );
}

pub fn verify_beacon_root<S: ShardStorage, N: Network>(
    _ctx: &ActionContext<'_, S, N>,
    kind: BeaconVerificationKind,
    _key: Hash,
    _payload: Vec<u8>,
) {
    warn!(kind = ?kind, "VerifyBeaconRoot");
}
