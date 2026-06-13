//! Reshape store adoption — the simulation mirror of the `RocksDB`
//! backend's checkpoint hard-link and subtree adoption.
//!
//! [`SimShardStorage::clone_for_split_child`] is the checkpoint: a deep
//! copy of the parent's substate and tree state re-rooted at the child's
//! prefix, with fresh consensus state (the parent's blocks stay with the
//! parent). [`SimShardStorage::adopt_split_child`] then re-points the
//! clone at the parent root's child-side slot;
//! [`SimShardStorage::adopt_followed_child`] re-points an observer's
//! followed store at the child root its own metadata names.
//! [`SimShardStorage::adopt_merge_parent`] is the inverse: a keeper's
//! `parent`-rooted store already holds both children's subtrees and the
//! stitched root, so adoption only records the merged genesis as the
//! committed tip.

use std::sync::{Arc, RwLock};

use hyperscale_jmt::{NibblePath, Node, NodeKey, TreeReader};
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::Jmt;
use hyperscale_types::{Block, CertifiedBlock, ChainOrigin, Hash, StateRoot, Verified};

use super::core::SimShardStorage;
use super::state::ConsensusState;

/// Leaves counted per tree-walk page while seeding the child's substate
/// count.
const COUNT_PAGE: usize = 1 << 16;

impl SimShardStorage {
    /// The simulation's checkpoint hard-link: a deep copy of this
    /// store's substate and tree state, re-rooted at `child_prefix`,
    /// with fresh consensus state. The sibling half rides along as dead
    /// weight outside the child's prefix, exactly as in the hard-linked
    /// production checkpoint.
    #[must_use]
    pub fn clone_for_split_child(&self, child_prefix: NibblePath) -> Self {
        let mut shared = read_or_recover(&self.state).clone();
        shared.tree_store.set_root_path(child_prefix);
        Self {
            state: Arc::new(RwLock::new(shared)),
            consensus: Arc::new(RwLock::new(ConsensusState::new())),
            jmt_history_length: self.jmt_history_length,
            boundary_pins: Arc::new(RwLock::new(std::collections::BTreeSet::new())),
        }
    }

    /// Re-point this child-prefix-rooted clone of the parent's store at
    /// its adopted subtree: the child root hangs off the parent root's
    /// child-side slot at the clone's tip version. The node is copied to
    /// the genesis version, the substate count seeded by walking the
    /// subtree, and the chain origin recorded for recovery.
    ///
    /// Returns the adopted child `state_root` — `ZERO` for an empty
    /// side. The caller asserts it against the beacon-verified child
    /// anchor; unlike the production backend there is no checkpoint
    /// vintage check, since the simulation harness supplies the stores.
    /// The `genesis` block records as the committed tip, mirroring the
    /// production batch. An observer's followed store adopts through
    /// [`Self::adopt_followed_child`] instead — the shapes are
    /// caller-distinguished.
    ///
    /// # Errors
    ///
    /// Fails when the store's root path is the trie root, when the
    /// genesis block does not sit at the origin's height, or when the
    /// clone resolves no parent root or child subtree node.
    pub fn adopt_split_child(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String> {
        if genesis.height() != origin.genesis_height {
            return Err(format!(
                "genesis block at height {} does not sit at the origin's {}",
                genesis.height(),
                origin.genesis_height,
            ));
        }
        let mut shared = write_or_recover(&self.state);
        let child_path = shared.tree_store.root_path();
        if child_path.is_empty() {
            return Err("split adoption requires a non-root child prefix".to_string());
        }

        // The metadata is the parent's; the child root hangs off the
        // parent root's child-side slot.
        let current_version = shared.current_block_height.inner();
        let mut parent_path = child_path.clone();
        parent_path.truncate(child_path.len() - 1);
        let side = usize::from(child_path.bits_at(child_path.len() - 1, 1));
        let parent_root = shared
            .tree_store
            .get_node(&NodeKey::new(current_version, parent_path))
            .ok_or("clone carries no parent root node")?;
        let Node::Internal(parent_root) = parent_root.as_ref() else {
            return Err(
                "parent root collapsed to a leaf; a ≤1-key parent cannot split".to_string(),
            );
        };
        let (child_node, child_root) = match &parent_root.children[side] {
            None => (None, StateRoot::ZERO),
            Some(slot) => {
                let node = shared
                    .tree_store
                    .get_node(&NodeKey::new(slot.version, child_path))
                    .ok_or("clone carries no child subtree root node")?;
                (
                    Some(node),
                    StateRoot::from_raw(Hash::from_hash_bytes(&slot.hash)),
                )
            }
        };
        install_adoption(&mut shared, origin, child_node, child_root)?;
        drop(shared);
        self.install_genesis_tip(origin, genesis);
        Ok(child_root)
    }

    /// Re-point an observer's followed store at its adopted subtree —
    /// the child root the store's own metadata names at its (sparse)
    /// tip version. The simulation mirror of the production backend's
    /// `adopt_followed_child`.
    ///
    /// Returns the adopted child `state_root` — `ZERO` for a store
    /// whose span held nothing (an empty half). The caller asserts it
    /// against the beacon-verified child anchor. The `genesis` block
    /// records as the committed tip, mirroring the production batch.
    ///
    /// # Errors
    ///
    /// Fails when the store's root path is the trie root, when the
    /// genesis block does not sit at the origin's height or carries a
    /// state root other than the followed one, or when the store's
    /// metadata names a root its tree doesn't hold.
    pub fn adopt_followed_child(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String> {
        if genesis.height() != origin.genesis_height {
            return Err(format!(
                "genesis block at height {} does not sit at the origin's {}",
                genesis.height(),
                origin.genesis_height,
            ));
        }
        let mut shared = write_or_recover(&self.state);
        let child_path = shared.tree_store.root_path();
        if child_path.is_empty() {
            return Err("split adoption requires a non-root child prefix".to_string());
        }

        let child_root = shared.current_root_hash;
        let child_node = if child_root == StateRoot::ZERO {
            // An empty half: the sync imported nothing and no follow
            // ever advanced the tip.
            None
        } else {
            let tip_version = shared.current_block_height.inner();
            Some(
                shared
                    .tree_store
                    .get_node(&NodeKey::new(tip_version, child_path))
                    .ok_or("followed store holds no root node at its tip version")?,
            )
        };
        if genesis.header().state_root() != child_root {
            return Err(format!(
                "followed root {child_root:?} does not match the genesis state root {:?}",
                genesis.header().state_root(),
            ));
        }
        install_adoption(&mut shared, origin, child_node, child_root)?;
        drop(shared);
        self.install_genesis_tip(origin, genesis);
        Ok(child_root)
    }

    /// Adopt a merged parent's store — a `parent`-rooted store already
    /// holding both children's subtrees and the stitched root `r_p` at
    /// its tip (the keeper imported them there). Unlike a split child
    /// this adopts a whole shard, whose prefix may be the trie root, so
    /// there is no child-slot re-pointing; the import already built the
    /// tree. Records the deterministic merged genesis as the committed
    /// tip.
    ///
    /// Returns the adopted `r_p`. The caller asserts it against the
    /// beacon-composed parent anchor.
    ///
    /// # Errors
    ///
    /// Fails when the genesis block does not sit at the origin's height,
    /// when the store's tip does not sit at that height, or when the
    /// store's root does not match the genesis state root.
    pub fn adopt_merge_parent(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String> {
        if genesis.height() != origin.genesis_height {
            return Err(format!(
                "genesis block at height {} does not sit at the origin's {}",
                genesis.height(),
                origin.genesis_height,
            ));
        }
        let merged_root = {
            let shared = read_or_recover(&self.state);
            if shared.current_block_height != origin.genesis_height {
                return Err(format!(
                    "merged store at version {} does not sit at the genesis height {}",
                    shared.current_block_height, origin.genesis_height,
                ));
            }
            shared.current_root_hash
        };
        if genesis.header().state_root() != merged_root {
            return Err(format!(
                "merged root {merged_root:?} does not match the genesis state root {:?}",
                genesis.header().state_root(),
            ));
        }
        self.install_genesis_tip(origin, genesis);
        Ok(merged_root)
    }

    /// Record the child's deterministic genesis as the committed tip —
    /// the consensus half of an adoption: the genesis block with its
    /// deterministic certified pairing, the committed height and hash,
    /// no latest QC (the child chain holds none at its genesis), and
    /// the chain origin for recovery.
    fn install_genesis_tip(&self, origin: ChainOrigin, genesis: &Block) {
        let pair = Verified::<CertifiedBlock>::genesis_certified(genesis.clone());
        let mut consensus = write_or_recover(&self.consensus);
        consensus
            .blocks
            .insert(genesis.height(), pair.as_ref().clone());
        consensus.committed_height = genesis.height();
        consensus.committed_hash = Some(genesis.hash());
        consensus.committed_qc = None;
        consensus.chain_origin = origin;
    }
}

/// Shared adoption tail: copy the child root node (when the side is
/// non-empty) to the genesis version, seed the substate count, and
/// move the tip to the genesis.
fn install_adoption(
    shared: &mut super::state::SharedState,
    origin: ChainOrigin,
    child_node: Option<Arc<Node>>,
    child_root: StateRoot,
) -> Result<(), String> {
    let genesis_version = origin.genesis_height.inner();
    let genesis_root_key = NodeKey::new(genesis_version, shared.tree_store.root_path());
    let count = match child_node {
        None => 0,
        Some(node) => {
            shared.tree_store.insert(genesis_root_key.clone(), node);
            count_subtree_leaves(&shared.tree_store, &genesis_root_key)?
        }
    };
    shared.substate_counts.insert(genesis_version, count);
    shared.current_block_height = origin.genesis_height;
    shared.current_root_hash = child_root;
    Ok(())
}

/// Count the live leaves under `root_key` by walking the tree in pages.
fn count_subtree_leaves(store: &impl TreeReader, root_key: &NodeKey) -> Result<u64, String> {
    let mut count: u64 = 0;
    let mut start = [0u8; 32];
    loop {
        let chunk = Jmt::collect_range(store, root_key, &start, &[0xFF; 32], COUNT_PAGE)
            .map_err(|e| format!("split adoption count: {e:?}"))?;
        count += chunk.leaves.len() as u64;
        let Some((last, _)) = chunk.leaves.last() else {
            break;
        };
        if !chunk.more {
            break;
        }
        start = *last;
        for byte in start.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::{BoundaryStore, ImportLeaf};
    use hyperscale_types::{
        Block, BlockHash, BlockHeight, ChainOrigin, Hash, ShardId, StateRoot, WeightedTimestamp,
    };

    use super::*;

    /// An import leaf whose top byte places it under one trie half.
    fn leaf(top: u8) -> ImportLeaf {
        let mut key = [0u8; 32];
        key[0] = top;
        ImportLeaf {
            leaf_key: key,
            storage_key: vec![top; 40],
            value: vec![top],
        }
    }

    /// A merged parent store: one leaf on each half so the root is the
    /// internal node `r_p`, imported at the genesis height the terminals
    /// continue (`max(9, 8) + 1 = 10`).
    fn merged_store() -> (SimShardStorage, StateRoot) {
        let store = SimShardStorage::default();
        let root = store
            .import_boundary_state(BlockHeight::new(10), vec![leaf(0x00), leaf(0x80)])
            .unwrap();
        (store, root)
    }

    fn merge_genesis(state_root: StateRoot) -> (Block, ChainOrigin) {
        let cut = WeightedTimestamp::from_millis(10_000);
        let genesis = Block::merge_parent_genesis(
            ShardId::ROOT,
            state_root,
            (
                BlockHash::from_raw(Hash::from_bytes(b"left terminal")),
                BlockHeight::new(9),
            ),
            (
                BlockHash::from_raw(Hash::from_bytes(b"right terminal")),
                BlockHeight::new(8),
            ),
            cut,
        );
        let origin = ChainOrigin {
            genesis_height: genesis.height(),
            anchor_wt: cut,
        };
        (genesis, origin)
    }

    /// Adoption records the merged genesis as the committed tip over the
    /// already-built tree: the recovered state names the genesis, its
    /// root, origin, and the imported substate count.
    #[test]
    fn merge_adoption_records_the_merged_genesis_tip() {
        let (store, root) = merged_store();
        assert_ne!(root, StateRoot::ZERO, "two halves compose an internal root");
        let (genesis, origin) = merge_genesis(root);
        assert_eq!(genesis.height(), BlockHeight::new(10));

        let adopted = store.adopt_merge_parent(origin, &genesis).unwrap();
        assert_eq!(adopted, root);

        let recovered = store.load_recovered_state();
        assert_eq!(recovered.committed_height, BlockHeight::new(10));
        assert_eq!(recovered.committed_hash, Some(genesis.hash()));
        assert_eq!(recovered.jmt_root, Some(root));
        assert_eq!(recovered.chain_origin, origin);
        assert_eq!(recovered.substate_count, 2);
    }

    /// A genesis claiming a different root than the store holds fails
    /// closed — the keeper's tree and the beacon's composition disagree.
    #[test]
    fn merge_adoption_rejects_a_root_mismatch() {
        let (store, root) = merged_store();
        let (_, origin) = merge_genesis(root);
        let (wrong, _) = merge_genesis(StateRoot::from_raw(Hash::from_bytes(b"forged root")));
        assert!(store.adopt_merge_parent(origin, &wrong).is_err());
    }
}
