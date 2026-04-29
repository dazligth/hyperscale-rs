//! Per-batch and per-transaction execution outputs.
//!
//! [`ExecutionOutput`] is the value returned by every [`Engine`](crate::Engine)
//! call — one [`ExecutedTx`] per input transaction, in input order.
//!
//! [`ExecutedTx`] carries two consumer-shaped projections of one tx's result:
//!
//! - `outcome` — lightweight summary that flows into wave vote aggregation
//!   (`ExecutionVote::tx_outcomes` → `ExecutionCertificate`).
//! - `entry` — full local receipt + execution metadata that flows into
//!   chain-state persistence when the wave's certificate commits.
//!
//! These types are I/O-shaped (no `Arc`s, no lifetimes) so they can be
//! moved across thread-pool boundaries between the executor (which
//! produces them) and the state machine (which consumes them).

use hyperscale_types::{
    ExecutionMetadata, ExecutionOutcome, GlobalReceiptHash, LocalExecutionEntry, LocalReceipt,
    TxHash, TxOutcome, WritesRoot,
};

/// Output from executing a batch of transactions.
#[derive(Debug, Clone)]
pub struct ExecutionOutput {
    /// Results for each transaction, in the same order as input.
    pub results: Vec<ExecutedTx>,
}

impl ExecutionOutput {
    /// Create a new execution output.
    #[must_use]
    pub const fn new(results: Vec<ExecutedTx>) -> Self {
        Self { results }
    }

    /// Create an empty output (no transactions).
    #[must_use]
    pub const fn empty() -> Self {
        Self { results: vec![] }
    }

    /// Get the number of results.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.results.len()
    }

    /// Check if the output is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Iterate over results.
    pub fn iter(&self) -> impl Iterator<Item = &ExecutedTx> {
        self.results.iter()
    }

    /// Get a reference to the results.
    #[must_use]
    pub fn results(&self) -> &[ExecutedTx] {
        &self.results
    }
}

/// One executed transaction's consumer-shaped output.
///
/// `outcome` flows into wave vote aggregation (`ExecutionVote::tx_outcomes` →
/// `ExecutionCertificate`). `entry` flows into chain-state persistence
/// (receipts written when the wave's certificate is committed).
#[derive(Debug, Clone)]
pub struct ExecutedTx {
    /// Lightweight summary for vote aggregation.
    pub outcome: TxOutcome,
    /// Full local receipt + execution metadata for persistence.
    pub entry: LocalExecutionEntry,
}

impl ExecutedTx {
    /// Create a successful executed-tx record.
    #[must_use]
    pub const fn success(
        tx_hash: TxHash,
        receipt_hash: GlobalReceiptHash,
        local_receipt: LocalReceipt,
        execution_output: ExecutionMetadata,
    ) -> Self {
        Self {
            outcome: TxOutcome {
                tx_hash,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash,
                    success: true,
                },
            },
            entry: LocalExecutionEntry {
                tx_hash,
                receipt_hash,
                local_receipt,
                execution_output,
            },
        }
    }

    /// Create a failed executed-tx record.
    ///
    /// `error` is logged at the construction site (it does not flow downstream
    /// — neither vote aggregation nor receipt persistence carry the message).
    #[must_use]
    pub fn failure(tx_hash: TxHash, error: impl Into<String>) -> Self {
        let error = error.into();
        tracing::warn!(?tx_hash, %error, "transaction execution failed");
        let local_receipt = LocalReceipt::failure();
        // Failures have no writes, so writes_root is ZERO.
        let receipt_hash = local_receipt
            .global_receipt(WritesRoot::ZERO)
            .receipt_hash();
        Self {
            outcome: TxOutcome {
                tx_hash,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash,
                    success: false,
                },
            },
            entry: LocalExecutionEntry {
                tx_hash,
                receipt_hash,
                local_receipt,
                execution_output: ExecutionMetadata::failure(None),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{Hash, TxHash};

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[byte]))
    }

    #[test]
    fn execution_output_empty_is_zero_len() {
        let out = ExecutionOutput::empty();
        assert!(out.is_empty());
        assert_eq!(out.len(), 0);
        assert_eq!(out.iter().count(), 0);
    }

    #[test]
    fn execution_output_preserves_input_order() {
        let a = ExecutedTx::failure(tx_hash(1), "err-a");
        let b = ExecutedTx::failure(tx_hash(2), "err-b");
        let c = ExecutedTx::failure(tx_hash(3), "err-c");
        let out = ExecutionOutput::new(vec![a, b, c]);

        let hashes: Vec<TxHash> = out.iter().map(|e| e.outcome.tx_hash).collect();
        assert_eq!(hashes, vec![tx_hash(1), tx_hash(2), tx_hash(3)]);
        assert_eq!(out.len(), 3);
        assert!(!out.is_empty());
    }

    #[test]
    fn failure_marks_outcome_unsuccessful_and_carries_tx_hash() {
        let h = tx_hash(7);
        let exec = ExecutedTx::failure(h, "boom");

        assert_eq!(exec.outcome.tx_hash, h);
        assert_eq!(exec.entry.tx_hash, h);
        // tx_hash and receipt_hash on `outcome` and `entry` must agree —
        // downstream vote aggregation matches them by hash.
        assert_eq!(exec.outcome.tx_hash, exec.entry.tx_hash);
        assert!(matches!(
            exec.outcome.outcome,
            ExecutionOutcome::Executed { success: false, .. }
        ));
    }

    #[test]
    fn failure_receipt_hash_is_canonical_across_failures() {
        // All failures share `LocalReceipt::failure()` + `WritesRoot::ZERO`,
        // so they share one receipt_hash. Validators in the same shard
        // can vote on the same (tx_hash, canonical_failure_hash) pair
        // regardless of why each saw the tx fail.
        let a = ExecutedTx::failure(tx_hash(1), "err");
        let b = ExecutedTx::failure(tx_hash(2), "different");
        assert_eq!(a.entry.receipt_hash, b.entry.receipt_hash);
        // Outcome on the wave-vote side is still keyed by tx_hash.
        assert_ne!(a.outcome.tx_hash, b.outcome.tx_hash);
    }
}
