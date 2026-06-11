//! Shared fixtures for the crate's tree and proof tests.

use std::collections::BTreeMap;

use crate::hasher::{Blake3Hasher, Hash};
use crate::node::{Key, NodeKey, ValueHash};
use crate::storage::{MemoryStore, TreeReader};
use crate::tree::Tree;

type Jmt = Tree<Blake3Hasher, 1>;

/// A 32-byte key with `b` as its leading byte.
pub fn k(b: u8) -> Key {
    let mut key = [0u8; 32];
    key[0] = b;
    key
}

/// A 32-byte value hash filled with `b`.
pub const fn v(b: u8) -> ValueHash {
    [b; 32]
}

/// A store populated with `entries` at version 1, returning its root
/// key and root hash.
pub fn build_store(entries: &[(Key, ValueHash)]) -> (MemoryStore, NodeKey, Hash) {
    let mut store = MemoryStore::new();
    let updates: BTreeMap<Key, Option<ValueHash>> =
        entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
    let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
    store.apply(&res);
    let root = store.get_root_key(1).unwrap();
    (store, root, res.root_hash)
}
