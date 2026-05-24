//! `BeaconChainWriter` implementation for `SimBeaconStorage`.

use std::sync::Arc;

use hyperscale_storage::BeaconChainWriter;
use hyperscale_storage::lock_recover::write_or_recover;
use hyperscale_types::BeaconBlock;

use super::core::SimBeaconStorage;

impl BeaconChainWriter for SimBeaconStorage {
    fn commit_beacon_block(&self, block: &Arc<BeaconBlock>) {
        let mut inner = write_or_recover(&self.inner);
        let slot = block.slot();
        let hash = block.block_hash();
        inner.by_slot.insert(slot, Arc::clone(block));
        inner.hash_to_slot.insert(hash, slot);
    }
}
