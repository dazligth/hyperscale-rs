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
#[must_use]
pub fn jmt_leaf_key(storage_key: &[u8]) -> [u8; 32] {
    *blake3_hash(storage_key).as_bytes()
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

    #[test]
    fn db_node_key_to_node_id_extracts_embedded_id() {
        let node = NodeId([7u8; NODE_ID_LEN]);
        let mut key = vec![0u8; DB_NODE_KEY_HASH_PREFIX_LEN];
        key.extend_from_slice(&node.0);
        key.push(0); // partition_num
        key.extend_from_slice(b"sort"); // sort_key
        assert_eq!(db_node_key_to_node_id(&key), Some(node));
    }

    #[test]
    fn db_node_key_to_node_id_rejects_short_key() {
        assert_eq!(db_node_key_to_node_id(&[]), None);
        assert_eq!(db_node_key_to_node_id(&[0u8; DB_NODE_KEY_LEN - 1]), None);
    }

    #[test]
    fn jmt_leaf_key_is_deterministic_and_sensitive() {
        assert_eq!(jmt_leaf_key(b"abc"), jmt_leaf_key(b"abc"));
        assert_ne!(jmt_leaf_key(b"abc"), jmt_leaf_key(b"abd"));
    }
}
