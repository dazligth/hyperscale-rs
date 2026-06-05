//! Canonical state-keying.
//!
//! The single definition of how a substate's flat storage key becomes a JMT
//! leaf, and how a `db_node_key` prefix decodes back to its [`NodeId`]. The
//! storage backend (JMT construction and merkle proof generation) and the
//! cross-shard provision proof verifier both derive leaves through these
//! functions, so the proving and verifying sides commit to one identical key,
//! value, and `NodeId` byte layout.

use blake3::hash as blake3_hash;

use crate::NodeId;

/// Length of the `SpreadPrefixKeyMapper` hash prefix that precedes the `NodeId`
/// in a `db_node_key`.
pub const DB_NODE_KEY_HASH_PREFIX_LEN: usize = 20;

/// Length of a `NodeId` in bytes.
pub const NODE_ID_LEN: usize = 30;

/// Length of a full `db_node_key`: hash prefix followed by the `NodeId`.
pub const DB_NODE_KEY_LEN: usize = DB_NODE_KEY_HASH_PREFIX_LEN + NODE_ID_LEN;

/// Hash a flat storage key (`db_node_key || partition_num || sort_key`) to its
/// 32-byte JMT leaf key.
///
/// The key is node-major: the high 16 bytes are `blake3(node_id)` and the low
/// 16 bytes are `blake3(partition_num || sort_key)`. Every substate of one
/// `NodeId` shares the high half, so an account's substates form a contiguous
/// JMT subtree and the account lands wholly under one shard prefix.
///
/// `storage_key` must begin with a `db_node_key` — every key the engine commits
/// and every key proof generation reads is `SpreadPrefixKeyMapper` encoded, so
/// this holds by construction. The one path taking untrusted keys (provision
/// proof verification) rejects malformed entries before keying.
///
/// # Panics
///
/// Panics if `storage_key` is shorter than a `db_node_key`.
#[must_use]
pub fn jmt_leaf_key(storage_key: &[u8]) -> [u8; 32] {
    let node_id = db_node_key_to_node_id(storage_key)
        .expect("jmt_leaf_key requires a db_node_key-prefixed storage key");
    let node_hash = blake3_hash(&node_id.0);
    let substate_hash = blake3_hash(&storage_key[DB_NODE_KEY_LEN..]);
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&node_hash.as_bytes()[..16]);
    key[16..].copy_from_slice(&substate_hash.as_bytes()[..16]);
    key
}

/// Hash a substate value to the 32-byte value hash held in its JMT leaf.
#[must_use]
pub fn jmt_value_hash(value: &[u8]) -> [u8; 32] {
    *blake3_hash(value).as_bytes()
}

/// Decode the [`NodeId`] embedded in a `db_node_key` (or any storage key that
/// begins with one). Returns `None` when the slice is shorter than a full
/// `db_node_key`.
///
/// Layout: `[hash prefix: DB_NODE_KEY_HASH_PREFIX_LEN][NodeId: NODE_ID_LEN]`.
#[must_use]
pub fn db_node_key_to_node_id(db_node_key: &[u8]) -> Option<NodeId> {
    if db_node_key.len() < DB_NODE_KEY_LEN {
        return None;
    }
    let mut id = [0u8; NODE_ID_LEN];
    id.copy_from_slice(&db_node_key[DB_NODE_KEY_HASH_PREFIX_LEN..DB_NODE_KEY_LEN]);
    Some(NodeId(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed storage key: zeroed hash prefix, then the node id,
    /// then a partition byte and sort key.
    fn storage_key(node: NodeId, partition: u8, sort: &[u8]) -> Vec<u8> {
        let mut key = vec![0u8; DB_NODE_KEY_HASH_PREFIX_LEN];
        key.extend_from_slice(&node.0);
        key.push(partition);
        key.extend_from_slice(sort);
        key
    }

    #[test]
    fn db_node_key_to_node_id_extracts_embedded_id() {
        let node = NodeId([7u8; NODE_ID_LEN]);
        assert_eq!(
            db_node_key_to_node_id(&storage_key(node, 0, b"sort")),
            Some(node)
        );
    }

    #[test]
    fn db_node_key_to_node_id_rejects_short_key() {
        assert_eq!(db_node_key_to_node_id(&[]), None);
        assert_eq!(db_node_key_to_node_id(&[0u8; DB_NODE_KEY_LEN - 1]), None);
    }

    #[test]
    fn jmt_leaf_key_is_node_major() {
        let a = NodeId([1u8; NODE_ID_LEN]);
        let b = NodeId([2u8; NODE_ID_LEN]);
        let a0 = jmt_leaf_key(&storage_key(a, 0, b"x"));
        let a1 = jmt_leaf_key(&storage_key(a, 7, b"yy"));
        // Two substates of one node share the node-major prefix but differ in
        // the substate half.
        assert_eq!(a0[..16], a1[..16]);
        assert_ne!(a0[16..], a1[16..]);
        // A different node lands under a different prefix.
        let b0 = jmt_leaf_key(&storage_key(b, 0, b"x"));
        assert_ne!(a0[..16], b0[..16]);
    }

    #[test]
    fn jmt_leaf_key_is_deterministic() {
        let key = storage_key(NodeId([9u8; NODE_ID_LEN]), 3, b"sort");
        assert_eq!(jmt_leaf_key(&key), jmt_leaf_key(&key));
    }
}
