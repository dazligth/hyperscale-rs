//! Receipt storage for `RocksDB`.

use std::sync::Arc;

use hyperscale_types::{ConsensusReceipt, ExecutionMetadata, StoredReceipt, TxHash};
use rocksdb::WriteBatch;

use crate::column_families::{ConsensusReceiptsCf, ExecutionMetadataCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{TypedCf, batch_put};

impl RocksDbStorage {
    /// One-shot variant of [`Self::store_receipts`] for a single receipt.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipt(&self, receipt: &StoredReceipt) {
        let mut batch = WriteBatch::default();
        self.add_receipt_to_batch(&mut batch, receipt);
        self.db.write(batch).expect("failed to persist receipt");
    }

    /// Atomic batch persist — consensus and metadata land together so a
    /// crash mid-batch can't leave metadata referencing a missing receipt
    /// (or vice versa).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipts(&self, receipts: &[StoredReceipt]) {
        if receipts.is_empty() {
            return;
        }
        let mut batch = WriteBatch::default();
        for receipt in receipts {
            self.add_receipt_to_batch(&mut batch, receipt);
        }
        tracing::debug!(
            count = receipts.len(),
            tx_hashes = ?receipts.iter().map(|r| r.tx_hash).collect::<Vec<_>>(),
            "Persisting receipts to RocksDB"
        );
        self.db.write(batch).expect("failed to persist receipts");
    }

    /// Append the receipt's writes to a caller-owned `WriteBatch` so it
    /// can land atomically with the rest of the block commit (header,
    /// substate, JMT). Used by `commit_block` / `prepare_block_commit`.
    pub(crate) fn add_receipt_to_batch(&self, batch: &mut WriteBatch, receipt: &StoredReceipt) {
        let cf = self.cf();

        batch_put::<ConsensusReceiptsCf>(
            batch,
            ConsensusReceiptsCf::handle(&cf),
            receipt.tx_hash.as_raw(),
            &receipt.consensus,
        );

        if let Some(ref metadata) = receipt.metadata {
            batch_put::<ExecutionMetadataCf>(
                batch,
                ExecutionMetadataCf::handle(&cf),
                receipt.tx_hash.as_raw(),
                metadata,
            );
        }
    }

    /// Read the consensus portion. Present for any tx that committed
    /// (success or failure); absent for aborted txs and unknown hashes.
    pub fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        self.cf_get::<ConsensusReceiptsCf>(tx_hash.as_raw())
            .map(Arc::new)
    }

    /// Read the local-only metadata. `None` when the tx was synced from
    /// a peer (peers don't ship their metadata) or pruned earlier than
    /// the consensus portion.
    pub fn get_execution_metadata(&self, tx_hash: &TxHash) -> Option<ExecutionMetadata> {
        self.cf_get::<ExecutionMetadataCf>(tx_hash.as_raw())
    }
}
