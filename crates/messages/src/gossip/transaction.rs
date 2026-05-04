//! Transaction gossip message.
//!
//! Each gossip message carries a batch of transactions for a single
//! destination shard topic. Batching at this layer trades a small
//! tail-latency cost (the batch window) for substantially less wire
//! work: per-message gossipsub overhead, IHAVE digest size, and `mcache`
//! pressure all scale with message *count*, not bytes — and at gossipsub
//! v1.2's IDONTWANT threshold larger messages activate cross-mesh dedup
//! that single-tx messages were too small to trigger.

use std::sync::Arc;

use hyperscale_types::{MessageClass, NetworkMessage, RoutableTransaction, ShardMessage};
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::trace_context::TraceContext;

/// Gossips a batch of transactions to a single destination shard.
///
/// Each tx is broadcast on its declared (read ∪ write) shard set; a tx
/// touching multiple shards appears in multiple batches, one per audience.
/// `transactions` and `trace_contexts` are parallel vectors of equal length.
#[derive(Debug, Clone)]
pub struct TransactionGossip {
    /// The transactions in this batch.
    pub transactions: Vec<Arc<RoutableTransaction>>,
    /// Trace context per transaction (parallel to `transactions`).
    pub trace_contexts: Vec<TraceContext>,
}

impl TransactionGossip {
    /// Build a gossip batch from a vector of `Arc`-wrapped transactions.
    /// Each entry gets a default trace context.
    #[must_use]
    pub fn from_arcs(transactions: Vec<Arc<RoutableTransaction>>) -> Self {
        let trace_contexts = std::iter::repeat_with(TraceContext::default)
            .take(transactions.len())
            .collect();
        Self {
            transactions,
            trace_contexts,
        }
    }

    /// Build a single-transaction batch (convenience for tests / one-off
    /// publishes). Captures the current span into the trace context.
    #[must_use]
    pub fn from_one_with_trace(transaction: RoutableTransaction) -> Self {
        Self {
            transactions: vec![Arc::new(transaction)],
            trace_contexts: vec![TraceContext::from_current()],
        }
    }

    /// Number of transactions in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether the batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

// Manual PartialEq/Eq — compare by per-tx hash for efficiency.
impl PartialEq for TransactionGossip {
    fn eq(&self, other: &Self) -> bool {
        self.transactions.len() == other.transactions.len()
            && self
                .transactions
                .iter()
                .zip(&other.transactions)
                .all(|(a, b)| a.hash() == b.hash())
            && self.trace_contexts == other.trace_contexts
    }
}

impl Eq for TransactionGossip {}

// ============================================================================
// Manual SBOR implementation (Arc<RoutableTransaction> doesn't derive
// BasicSbor; we (de)serialize the inner data through parallel vecs).
// ============================================================================

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for TransactionGossip {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(2)?; // 2 fields

        encoder.write_value_kind(ValueKind::Array)?;
        encoder.write_value_kind(
            <RoutableTransaction as Categorize<NoCustomValueKind>>::value_kind(),
        )?;
        encoder.write_size(self.transactions.len())?;
        for tx in &self.transactions {
            encoder.encode_deeper_body(tx.as_ref())?;
        }

        encoder.write_value_kind(ValueKind::Array)?;
        encoder.write_value_kind(<TraceContext as Categorize<NoCustomValueKind>>::value_kind())?;
        encoder.write_size(self.trace_contexts.len())?;
        for trace in &self.trace_contexts {
            encoder.encode_deeper_body(trace)?;
        }

        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for TransactionGossip {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }

        decoder.read_and_check_value_kind(ValueKind::Array)?;
        let elem_kind = decoder.read_value_kind()?;
        let tx_count = decoder.read_size()?;
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let tx: RoutableTransaction = decoder.decode_deeper_body_with_value_kind(elem_kind)?;
            transactions.push(Arc::new(tx));
        }

        decoder.read_and_check_value_kind(ValueKind::Array)?;
        let trace_elem_kind = decoder.read_value_kind()?;
        let trace_count = decoder.read_size()?;
        if trace_count != tx_count {
            return Err(DecodeError::UnexpectedSize {
                expected: tx_count,
                actual: trace_count,
            });
        }
        let mut trace_contexts = Vec::with_capacity(trace_count);
        for _ in 0..trace_count {
            let trace: TraceContext =
                decoder.decode_deeper_body_with_value_kind(trace_elem_kind)?;
            trace_contexts.push(trace);
        }

        Ok(Self {
            transactions,
            trace_contexts,
        })
    }
}

impl Categorize<NoCustomValueKind> for TransactionGossip {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for TransactionGossip {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("TransactionGossip", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

// Network message implementation
impl NetworkMessage for TransactionGossip {
    fn message_type_id() -> &'static str {
        "transaction.gossip"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

// Transactions are filtered to shards that have state touched by the batch.
impl ShardMessage for TransactionGossip {}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{test_node, test_transaction_with_nodes};
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn from_arcs_carries_transactions_and_default_traces() {
        let tx1 = Arc::new(test_transaction_with_nodes(
            &[1, 2, 3],
            vec![test_node(1)],
            vec![test_node(2)],
        ));
        let tx2 = Arc::new(test_transaction_with_nodes(
            &[4, 5, 6],
            vec![test_node(3)],
            vec![test_node(4)],
        ));

        let gossip = TransactionGossip::from_arcs(vec![Arc::clone(&tx1), Arc::clone(&tx2)]);
        assert_eq!(gossip.len(), 2);
        assert!(!gossip.is_empty());
        assert_eq!(gossip.transactions[0].hash(), tx1.hash());
        assert_eq!(gossip.transactions[1].hash(), tx2.hash());
        assert_eq!(gossip.trace_contexts.len(), 2);
        for trace in &gossip.trace_contexts {
            assert!(!trace.has_trace());
        }
    }

    #[test]
    fn empty_batch() {
        let gossip = TransactionGossip::from_arcs(vec![]);
        assert!(gossip.is_empty());
        assert_eq!(gossip.len(), 0);
    }

    #[test]
    fn sbor_roundtrip_multi_tx() {
        let txs: Vec<Arc<RoutableTransaction>> = (0..5)
            .map(|i| {
                Arc::new(test_transaction_with_nodes(
                    &[i, i + 1, i + 2],
                    vec![test_node(i)],
                    vec![test_node(i + 1)],
                ))
            })
            .collect();
        let original = TransactionGossip::from_arcs(txs);

        let bytes = basic_encode(&original).expect("encode");
        let decoded: TransactionGossip = basic_decode(&bytes).expect("decode");

        assert_eq!(original, decoded);
        assert_eq!(decoded.len(), 5);
    }

    #[test]
    fn sbor_roundtrip_empty() {
        let original = TransactionGossip::from_arcs(vec![]);
        let bytes = basic_encode(&original).expect("encode");
        let decoded: TransactionGossip = basic_decode(&bytes).expect("decode");
        assert_eq!(original, decoded);
        assert!(decoded.is_empty());
    }
}
