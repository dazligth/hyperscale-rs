//! Write interface for committed beacon blocks.

use std::sync::Arc;

use hyperscale_types::BeaconBlock;

/// Write access to the process-level beacon chain.
///
/// Beacon blocks are self-authenticating — the inline
/// [`BeaconBlock::aggregate_sig`](hyperscale_types::BeaconBlock::aggregate_sig)
/// over the [`signers`](hyperscale_types::BeaconBlock::signers) bitfield
/// is the committee QC — so no separate certificate parameter is
/// threaded through.
pub trait BeaconChainWriter: Send + Sync {
    /// Persist `block` at its `block.epoch()`.
    ///
    /// Idempotent on `(epoch, block_hash)` — committing the same block
    /// twice is a no-op. Multiple per-vnode `BeaconCoordinator`s
    /// converging on the same committed block independently emit
    /// `Action::CommitBeaconBlock`; this idempotency is the storage
    /// layer's contribution to the three-layer dedup pattern
    /// (state machine + `io_loop` `BeaconCommitCoordinator` + storage).
    ///
    /// Behavior under epoch-collision with a *different* block is
    /// implementation-defined: a well-behaved consensus never
    /// produces two distinct blocks at the same epoch, so a collision
    /// indicates either a programming bug or Byzantine activity.
    /// Implementations may panic, log, or overwrite — none of these
    /// is safety-critical because the BFT layer's dedup catches it
    /// first.
    fn commit_beacon_block(&self, block: &Arc<BeaconBlock>);
}
