//! `BeaconChainReader` implementation for `RocksDbBeaconStorage`.

use std::sync::Arc;

use hyperscale_storage::BeaconChainReader;
use hyperscale_types::{BeaconBlock, BeaconBlockHash, Epoch};
use rocksdb::{IteratorMode, ReadOptions};

use super::column_families::{BeaconBlocksBySlotCf, BeaconHashToSlotCf};
use super::core::RocksDbBeaconStorage;
use crate::typed_cf::{DbCodec, TypedCf};

impl BeaconChainReader for RocksDbBeaconStorage {
    fn get_beacon_block_by_slot(&self, epoch: Epoch) -> Option<Arc<BeaconBlock>> {
        self.cf_get::<BeaconBlocksBySlotCf>(&epoch.inner())
            .map(Arc::new)
    }

    fn get_beacon_block_by_hash(&self, hash: BeaconBlockHash) -> Option<Arc<BeaconBlock>> {
        let epoch = self.cf_get::<BeaconHashToSlotCf>(&hash.into_raw())?;
        self.cf_get::<BeaconBlocksBySlotCf>(&epoch).map(Arc::new)
    }

    fn latest_committed_slot(&self) -> Option<Epoch> {
        // First entry in End-mode iteration is the largest key; keys
        // are big-endian u64 slots, so lex-max == numeric-max.
        let cf = BeaconBlocksBySlotCf::handle(&self.cf());
        let mut iter = self.db.iterator_cf(cf, IteratorMode::End);
        let (key, _) = iter.next()?.expect("BFT CRITICAL: beacon iter failed");
        let bytes: [u8; 8] = key
            .as_ref()
            .try_into()
            .expect("beacon epoch key must be 8 bytes");
        Some(Epoch::new(u64::from_be_bytes(bytes)))
    }

    fn iter_beacon_blocks_from(
        &self,
        from: Epoch,
    ) -> Box<dyn Iterator<Item = Arc<BeaconBlock>> + Send + '_> {
        let start = from.inner().to_be_bytes();
        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_lower_bound(start.to_vec());

        let cf = BeaconBlocksBySlotCf::handle(&self.cf());
        let iter = self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

        // Decode values via the SborCodec the CF declared, keeping the
        // type pin honest end-to-end.
        let codec = <BeaconBlocksBySlotCf as TypedCf>::ValueCodec::default();
        let blocks: Vec<Arc<BeaconBlock>> = iter
            .map(|entry| {
                let (_, value) = entry.expect("BFT CRITICAL: beacon iter failed");
                Arc::new(DbCodec::decode(&codec, &value))
            })
            .collect();

        Box::new(blocks.into_iter())
    }
}
