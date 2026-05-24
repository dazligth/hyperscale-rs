//! `BeaconChainReader` implementation for `SimBeaconStorage`.

use std::sync::Arc;

use hyperscale_storage::BeaconChainReader;
use hyperscale_storage::lock_recover::read_or_recover;
use hyperscale_types::{BeaconBlock, BeaconBlockHash, Epoch};

use super::core::SimBeaconStorage;

impl BeaconChainReader for SimBeaconStorage {
    fn get_beacon_block_by_slot(&self, epoch: Epoch) -> Option<Arc<BeaconBlock>> {
        read_or_recover(&self.inner).by_slot.get(&epoch).cloned()
    }

    fn get_beacon_block_by_hash(&self, hash: BeaconBlockHash) -> Option<Arc<BeaconBlock>> {
        let inner = read_or_recover(&self.inner);
        let epoch = *inner.hash_to_slot.get(&hash)?;
        inner.by_slot.get(&epoch).cloned()
    }

    fn latest_committed_slot(&self) -> Option<Epoch> {
        read_or_recover(&self.inner)
            .by_slot
            .keys()
            .next_back()
            .copied()
    }

    fn iter_beacon_blocks_from(
        &self,
        from: Epoch,
    ) -> Box<dyn Iterator<Item = Arc<BeaconBlock>> + Send + '_> {
        // Materialise the range under the read lock so the returned
        // iterator outlives any subsequent commits without holding the
        // lock. Memory cost is bounded by the number of committed
        // blocks at or after `from`.
        let snapshot: Vec<Arc<BeaconBlock>> = {
            let inner = read_or_recover(&self.inner);
            inner
                .by_slot
                .range(from..)
                .map(|(_, b)| Arc::clone(b))
                .collect()
        };
        Box::new(snapshot.into_iter())
    }
}
