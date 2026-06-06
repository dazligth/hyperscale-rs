//! Genesis install primitive.

use std::collections::HashMap;

use hyperscale_types::{NodeId, StateRoot};
use radix_substate_store_interface::interface::DatabaseUpdates;

/// Storage backends that can install a genesis snapshot in one shot.
///
/// Genesis bootstrap accumulates substate writes without recomputing the JMT
/// per commit, then computes the JMT once at version 0 from the merged
/// updates. Backends compose those two steps internally; the trait obligation
/// is the single composite operation callers actually want.
pub trait GenesisCommit {
    /// Install a fully-prepared genesis snapshot: write `substates`, then
    /// compute the JMT root at version 0 from `jmt_updates`. Returns the
    /// genesis state root.
    ///
    /// `substates` is the full genesis state, written to the substate store
    /// for read availability on every shard. `jmt_updates` is the
    /// shard-filtered subset (nodes routing to this shard) that builds the
    /// prefix-rooted JMT, so the committed `state_root` is exactly the global
    /// tree's subtree at the shard prefix. For a single-shard (empty-prefix)
    /// store the two are identical.
    ///
    /// `owner_map` owner-prefixes internal nodes (vaults, KV stores) under
    /// their owning global ancestor so each lands in its owner's prefix
    /// subtree.
    #[allow(clippy::implicit_hasher)] // call sites pass std `HashMap`s
    fn install_genesis(
        &self,
        substates: &DatabaseUpdates,
        jmt_updates: &DatabaseUpdates,
        owner_map: &HashMap<NodeId, NodeId>,
    ) -> StateRoot;
}
