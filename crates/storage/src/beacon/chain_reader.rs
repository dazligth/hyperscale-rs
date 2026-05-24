//! Read interface for committed beacon blocks.

use std::sync::Arc;

use hyperscale_types::{BeaconBlock, BeaconBlockHash, Slot};

/// Read access to the process-level beacon chain.
///
/// All methods are synchronous; backends may serialize internally
/// (e.g., `RocksDB` snapshot reads) but expose a thread-safe interface
/// so multiple `BeaconCoordinator`s (one per vnode) can read
/// concurrently against a single `Arc<dyn BeaconChainReader>`.
pub trait BeaconChainReader: Send + Sync {
    /// Block committed at `slot`, or `None` if absent.
    fn get_beacon_block_by_slot(&self, slot: Slot) -> Option<Arc<BeaconBlock>>;

    /// Block whose header hashes to `hash`, or `None` if absent.
    ///
    /// Implementations typically maintain a secondary `hash → slot`
    /// index and delegate to [`Self::get_beacon_block_by_slot`].
    fn get_beacon_block_by_hash(&self, hash: BeaconBlockHash) -> Option<Arc<BeaconBlock>>;

    /// Highest slot that has a committed block, or `None` if the chain
    /// is empty (no genesis yet).
    fn latest_committed_slot(&self) -> Option<Slot>;

    /// Iterate committed blocks at slots `>= from`, in ascending slot
    /// order. Used at startup by `BeaconCoordinator` to replay state
    /// from genesis.
    ///
    /// The returned iterator is `'static`-free of the storage handle
    /// (callers may hold it across other operations); backends that
    /// need a snapshot copy the relevant entries before returning.
    fn iter_beacon_blocks_from(
        &self,
        from: Slot,
    ) -> Box<dyn Iterator<Item = Arc<BeaconBlock>> + Send + '_>;
}
