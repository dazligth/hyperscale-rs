//! Merkle multiproof generation.
//!
//! Thin adapter between `hyperscale_jmt`'s `MultiProof` and the on-wire
//! [`MerkleInclusionProof`] (opaque bytes wrapper). The wire format is
//! owned by the JMT crate; this module wraps it in the hyperscale type
//! system. Verification lives on `Verify<&ProvisionsContext<'_>> for
//! Provisions` in `crates/types/src/provisioning/provisions.rs`.

use std::collections::HashMap;

use hyperscale_jmt::{Key, NodeKey, TreeReader};
use hyperscale_types::{BlockHeight, MerkleInclusionProof, NodeId};

use super::{Jmt, hash_storage_key};

/// Generate a batched merkle multiproof for a set of storage keys against
/// a committed root.
///
/// Takes any `TreeReader` backed by the caller's storage. `owner_map`
/// owner-prefixes internal nodes' keys so the proof's leaf keys match the
/// owner-prefixed keys committed to the tree. Returns `None` if the root at
/// `block_height` is not in the store.
#[allow(clippy::implicit_hasher)] // call sites pass std `HashMap`s
pub fn generate_proof<S: TreeReader>(
    store: &S,
    storage_keys: &[Vec<u8>],
    owner_map: &HashMap<NodeId, NodeId>,
    block_height: BlockHeight,
) -> Option<MerkleInclusionProof> {
    let root_key = NodeKey::new(block_height.inner(), store.root_path());

    let jmt_keys: Vec<Key> = storage_keys
        .iter()
        .map(|sk| hash_storage_key(sk, owner_map))
        .collect();

    Jmt::prove(store, &root_key, &jmt_keys)
        .ok()
        .map(|proof| MerkleInclusionProof::new(proof.encode()))
}
