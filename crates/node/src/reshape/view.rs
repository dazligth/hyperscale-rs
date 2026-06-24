//! Shared reshape decision predicates over a [`TopologySnapshot`].
//!
//! Both harnesses gate reshape on the same committed-state projection: a shard's
//! boundary anchor projects (`Some`) exactly once it seeds — the projection
//! drops zeroed genesis placeholders ([`BeaconState::derive_topology_snapshot`]
//! filters `block_hash == ZERO`), so `boundary(shard).is_some()` is equivalent to
//! the raw `BeaconState.boundaries[shard].block_hash != ZERO` the simulation used
//! to read directly. Routing both the production supervisor and the simulation
//! driver through these predicates gives one definition of the gate, so neither
//! hand-rolls it and they cannot silently diverge.
//!
//! [`BeaconState::derive_topology_snapshot`]: hyperscale_types::BeaconState::derive_topology_snapshot

use std::collections::{BTreeMap, HashMap};

use hyperscale_types::{ShardAnchor, ShardId, TopologySnapshot, ValidatorId};

/// Reshape gate predicates over one host's [`TopologySnapshot`] — the
/// identity-agnostic projection of the committed `BeaconState`.
pub struct ReshapeView<'a> {
    topology: &'a TopologySnapshot,
}

impl<'a> ReshapeView<'a> {
    /// View the reshape gate through `topology`.
    #[must_use]
    pub const fn new(topology: &'a TopologySnapshot) -> Self {
        Self { topology }
    }

    /// The shard's beacon-attested boundary anchor, or `None` until it seeds.
    #[must_use]
    pub fn boundary(&self, shard: ShardId) -> Option<ShardAnchor> {
        self.topology.boundary(shard)
    }

    /// The shard's full committee — the ready-signal broadcast recipients.
    #[must_use]
    pub fn committee(&self, shard: ShardId) -> &[ValidatorId] {
        self.topology.committee_for_shard(shard)
    }

    /// The split child `validator` syncs as an observer of `parent`'s pending
    /// split, or `None` when it holds no observer seat there.
    #[must_use]
    pub fn observer_child(&self, parent: ShardId, validator: ValidatorId) -> Option<ShardId> {
        self.topology.reshape_observer_child(parent, validator)
    }

    /// The parent `validator` reforms as a keeper of `child` in a pending
    /// merge, or `None` when it holds no keeper seat there.
    #[must_use]
    pub fn keeper_parent(&self, child: ShardId, validator: ValidatorId) -> Option<ShardId> {
        self.topology.reshape_keeper_parent(child, validator)
    }

    /// The pending-split observer cohorts, keyed by splitting parent — the
    /// orchestrator scans these for its host's observer seats.
    #[must_use]
    pub const fn observer_cohorts(&self) -> &HashMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
        self.topology.reshape_observer_cohorts()
    }

    /// Whether `shard` has seeded a beacon-attested boundary anchor. The
    /// projection drops zeroed genesis placeholders, so a projected anchor
    /// means the shard's boundary crossing committed.
    #[must_use]
    pub fn seeded(&self, shard: ShardId) -> bool {
        self.topology.boundary(shard).is_some()
    }

    /// Whether both of `parent`'s split children have seeded — the gate a
    /// splitting parent's observers flip on.
    #[must_use]
    pub fn children_seeded(&self, parent: ShardId) -> bool {
        let (left, right) = parent.children();
        self.seeded(left) && self.seeded(right)
    }

    /// Whether `parent`'s merge-composed anchor has seeded — the gate a
    /// merge's keepers flip on.
    #[must_use]
    pub fn parent_composed(&self, parent: ShardId) -> bool {
        self.seeded(parent)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use hyperscale_types::{
        BlockHash, BlockHeight, Hash, NetworkDefinition, ShardAnchor, ShardId, StateRoot,
        TopologySnapshot, ValidatorSet, WeightedTimestamp,
    };

    use super::ReshapeView;

    /// A non-zero anchor — the projection only carries seeded boundaries.
    fn seeded_anchor() -> ShardAnchor {
        ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"seeded-boundary")),
            height: BlockHeight::new(1),
            weighted_timestamp: WeightedTimestamp::ZERO,
            settled_waves_root: None,
        }
    }

    /// A snapshot whose projection carries exactly `seeded`'s boundaries — the
    /// shape `derive_topology_snapshot` produces after its zero-placeholder filter.
    fn snapshot_with_seeded(seeded: &[ShardId]) -> TopologySnapshot {
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(Vec::new()),
            HashMap::new(),
            HashMap::new(),
            seeded.iter().map(|&s| (s, seeded_anchor())).collect(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            BTreeSet::new(),
        )
    }

    #[test]
    fn children_seeded_requires_both_children() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();

        assert!(!ReshapeView::new(&snapshot_with_seeded(&[])).children_seeded(parent));
        assert!(!ReshapeView::new(&snapshot_with_seeded(&[left])).children_seeded(parent));
        assert!(ReshapeView::new(&snapshot_with_seeded(&[left, right])).children_seeded(parent));
    }

    #[test]
    fn parent_composed_tracks_the_parent_anchor() {
        let parent = ShardId::ROOT;
        assert!(!ReshapeView::new(&snapshot_with_seeded(&[])).parent_composed(parent));
        assert!(ReshapeView::new(&snapshot_with_seeded(&[parent])).parent_composed(parent));
    }
}
