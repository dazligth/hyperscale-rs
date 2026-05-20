//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_engine::fetch_state_entries;
use hyperscale_engine::sharding::expand_nodes_with_owned_at_height;
use hyperscale_storage::{ChainReader, SubstateStore};
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{
    MerkleInclusionProof, NodeId, ProvisionEntry, Provisions, ShardGroupId, SubstateEntry, TxHash,
    shard_for_node,
};
use tracing::warn;

/// Per-tx serve-side payload: `(tx_hash, entries, target_nodes, owned_nodes)`.
/// Mirrors the four-arg shape of [`ProvisionEntry::new`] so the assembly
/// loop and the final mapping stay symmetric.
type ServedProvisionEntry = (
    TxHash,
    Vec<SubstateEntry>,
    Vec<NodeId>,
    Vec<(NodeId, NodeId)>,
);

/// Serve an inbound provision request from a target shard needing our state.
///
/// Looks up the block at the requested height, identifies transactions
/// that involve the requesting shard, collects the local state entries
/// and merkle proofs, and returns them as `Provisions` bundles. Mirrors
/// the gossip path's per-tx assembly ([`fetch_and_broadcast_provision`])
/// so that receivers absorb identical `entries`, `target_nodes`, and
/// `owned_nodes` regardless of which transport delivered the provision —
/// without this, fetched-provision recipients would have empty
/// `owned_nodes` maps and diverge on `filter_updates_for_shard`
/// downstream, breaking `local_receipt_root` agreement.
///
/// [`fetch_and_broadcast_provision`]: hyperscale_provisions::fetch_and_broadcast_provision
///
/// Takes `local_shard` and `num_shards` instead of `&TopologyCoordinator`
/// to avoid topology dependency in the I/O layer.
pub fn serve_provision_request(
    storage: &(impl ChainReader + SubstateStore),
    local_shard: ShardGroupId,
    num_shards: u64,
    req: &GetProvisionsRequest,
) -> GetProvisionResponse {
    let Some(certified) = storage.get_block(req.block_height) else {
        warn!(
            block_height = req.block_height.inner(),
            "Provision request: block not found"
        );
        return GetProvisionResponse { provisions: None };
    };
    let (block, _qc) = certified.into_parts();

    let jmt_height = block.height();

    let all_txs = block.transactions().iter();

    // Phase 1: For each tx, build the full ProvisionEntry payload —
    // source-owned expanded substates, target-shard declared nodes for
    // conflict detection, and the authoritative `(vault, owner)` map.
    let mut per_tx: Vec<ServedProvisionEntry> = Vec::new();
    let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

    for tx in all_txs {
        let mut declared_source_nodes: Vec<NodeId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .filter(|&node_id| shard_for_node(node_id, num_shards) == local_shard)
            .copied()
            .collect();
        declared_source_nodes.sort();
        declared_source_nodes.dedup();
        if declared_source_nodes.is_empty() {
            continue;
        }

        let mut target_nodes: Vec<NodeId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .filter(|&node_id| shard_for_node(node_id, num_shards) == req.target_shard)
            .copied()
            .collect();
        target_nodes.sort();
        target_nodes.dedup();
        if target_nodes.is_empty() {
            continue;
        }

        let Some((expanded_nodes, ownership)) =
            expand_nodes_with_owned_at_height(storage, &declared_source_nodes, jmt_height)
        else {
            warn!(
                block_height = req.block_height.inner(),
                jmt_height = jmt_height.inner(),
                tx_hash = %tx.hash(),
                "Provision request: historical JMT version unavailable for ownership walk"
            );
            return GetProvisionResponse { provisions: None };
        };

        let Some(entries) = fetch_state_entries(storage, &expanded_nodes, jmt_height) else {
            warn!(
                block_height = req.block_height.inner(),
                jmt_height = jmt_height.inner(),
                "Provision request: historical JMT version unavailable for entries"
            );
            return GetProvisionResponse { provisions: None };
        };

        let mut owned_nodes: Vec<(NodeId, NodeId)> = ownership.into_iter().collect();
        owned_nodes.sort_by_key(|(k, _)| *k);

        for e in &entries {
            all_storage_keys.push(e.storage_key.0.clone());
        }
        per_tx.push((tx.hash(), entries, target_nodes, owned_nodes));
    }

    // Phase 2: Generate ONE batched proof covering all entries.
    // `Jmt::prove` sorts and dedups its keys internally, so we hand it the
    // raw accumulated list.
    let proof = if per_tx.is_empty() {
        MerkleInclusionProof::new(Vec::new())
    } else if let Some(p) = storage.generate_merkle_proofs(&all_storage_keys, jmt_height) {
        p
    } else {
        tracing::warn!(
            block_height = req.block_height.inner(),
            "Fallback provision: batched proof generation failed (version unavailable)"
        );
        return GetProvisionResponse { provisions: None };
    };

    // Phase 3: Build the bundle.
    let transactions = per_tx
        .into_iter()
        .map(|(tx_hash, entries, target_nodes, owned_nodes)| {
            ProvisionEntry::new(tx_hash, entries, target_nodes, owned_nodes)
        })
        .collect();

    GetProvisionResponse {
        provisions: Some(Arc::new(Provisions::new(
            local_shard,
            req.target_shard,
            req.block_height,
            proof,
            transactions,
        ))),
    }
}
