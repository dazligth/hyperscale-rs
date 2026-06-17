//! Grow a single-shard genesis to a target topology by driving real splits.
//!
//! The simulation counterpart of a network that launches single-shard and
//! fans out under load: starting from one root shard, this walks each split
//! through its full lifecycle — the armed trigger folds and the beacon draws
//! the cohort from the pooled extras, every cohort member runs its observer
//! duty ([`SimulationRunner::observe_child`]) and re-asserts its ready signal
//! until the readiness gate reshapes the children into the lookahead, the
//! parent coasts to its crossing and seeds both child anchors, every store
//! follows the parent to its terminal root, and each member flips onto its
//! assigned child. Repeating one generation per trie level grows a power-of-two
//! target. The runner is left positioned exactly where a multi-shard genesis
//! used to leave it: every child at full committee strength, committing past
//! its genesis.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_storage::ShardChainReader;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconState, BlockHash, PendingReshape, ShardAnchor, ShardId, StateRoot, TopologySnapshot,
    ValidatorId, ValidatorStatus,
};

use super::SimulationRunner;

/// Epochs the standing trigger gets to fold and the admission to draw a cohort.
const ADMISSION_BUDGET_EPOCHS: u64 = 8;

/// Epochs the folded ready signals get to fire the readiness gate.
const GATE_BUDGET_EPOCHS: u64 = 8;

/// Epochs the parent gets to coast to its crossing and seed both child anchors.
const SEED_BUDGET_EPOCHS: u64 = 6;

/// Epochs the flipped children get to commit past their genesis.
const CHILD_RUN_BUDGET_EPOCHS: u64 = 4;

impl SimulationRunner {
    /// Grow the current single-shard topology until it holds `target_shards`
    /// leaves, splitting every frontier leaf once per generation.
    ///
    /// The caller must have run genesis first
    /// (`initialize_genesis` / `initialize_genesis_with_balances`) and armed
    /// the split trigger (`ReshapeThresholds { split_bytes: 0 }`) with one
    /// cohort of pooled extras per split — `(target_shards - 1) * shard_size`
    /// in total. Returns once every leaf at depth `log2(target_shards)` stands
    /// at full committee strength and commits past its child genesis.
    ///
    /// # Panics
    ///
    /// Panics if `target_shards` is not a power of two, or if any split fails
    /// to admit, gate, seed, or run within its epoch budget.
    pub fn grow_to(&mut self, target_shards: u32) {
        assert!(
            target_shards.is_power_of_two(),
            "grow_to target must be a power of two; got {target_shards}",
        );
        loop {
            let frontier = self.current_leaf_shards();
            if frontier.len() as u64 >= u64::from(target_shards) {
                break;
            }
            for parent in frontier {
                self.split_shard(parent);
            }
        }
    }

    /// Drive `parent`'s split through its full lifecycle, leaving both children
    /// seated at full strength and committing past genesis.
    fn split_shard(&mut self, parent: ShardId) {
        let (left, right) = parent.children();

        // The parent's pre-split committee — the members that partition across
        // the two children when the gate fires.
        let parent_members: Vec<ValidatorId> = self.snapshot().committee_for_shard(parent).to_vec();
        let cohort_size = parent_members.len();

        // Admission: the armed trigger folds and the beacon draws the cohort.
        let admit_deadline = self.now + self.epochs(ADMISSION_BUDGET_EPOCHS);
        let admitted = self.run_until_predicate(admit_deadline, |r| {
            r.pending_split_cohort(parent)
                .is_some_and(|cohort| cohort.len() == cohort_size)
        });
        assert!(
            admitted,
            "split of {parent:?} must draw a full cohort within \
             {ADMISSION_BUDGET_EPOCHS} epochs",
        );
        let cohort = self
            .pending_split_cohort(parent)
            .expect("cohort just admitted");

        // Observer duty: each cohort member syncs its assigned child span and
        // signals ready.
        let mut synced: Vec<(
            ValidatorId,
            ShardId,
            SimShardStorage,
            ShardAnchor,
            StateRoot,
        )> = Vec::with_capacity(cohort.len());
        for (validator, child) in &cohort {
            let (store, root, anchor) = self.observe_child(*validator, parent, *child);
            synced.push((*validator, *child, store, anchor, root));
        }

        // The readiness gate: re-assert each ready signal until the trie
        // reshapes the children into the lookahead.
        let gate_deadline = self.now + self.epochs(GATE_BUDGET_EPOCHS);
        let mut reshaped = false;
        while self.now < gate_deadline {
            if let Some(current) = self.pending_split_cohort(parent) {
                for (validator, _) in &current {
                    self.broadcast_observer_ready(*validator, parent);
                }
            }
            let next = self.now + Duration::from_secs(1);
            self.run_until(next);
            if self.committed_beacon_state().is_some_and(|state| {
                !state.pending_reshapes.contains_key(&parent)
                    && state.next_shard_committees.contains_key(&left)
            }) {
                reshaped = true;
                break;
            }
        }
        assert!(
            reshaped,
            "the ready signals must fire the split gate of {parent:?} within \
             {GATE_BUDGET_EPOCHS} epochs",
        );

        // Seed: the parent coasts to its crossing and the fold seeds both
        // children's anchors from its terminal contribution.
        let seed_deadline = self.now + self.epochs(SEED_BUDGET_EPOCHS);
        let seeded = self.run_until_predicate(seed_deadline, |r| {
            r.committed_beacon_state().is_some_and(|state| {
                [left, right].iter().all(|child| {
                    state
                        .boundaries
                        .get(child)
                        .is_some_and(|boundary| boundary.block_hash != BlockHash::ZERO)
                })
            })
        });
        assert!(
            seeded,
            "the split of {parent:?} must seed both child anchors within \
             {SEED_BUDGET_EPOCHS} epochs",
        );

        let state = self
            .committed_beacon_state()
            .expect("post-gate beacon state");

        // Each original parent member's assigned child, read from the reshaped
        // beacon state.
        let parent_halves: Vec<(ValidatorId, ShardId)> = parent_members
            .iter()
            .map(|member| {
                let status = state.validators[member].status;
                let ValidatorStatus::OnShard { shard, .. } = status else {
                    panic!("parent member {member:?} must land on a child of {parent:?}; got {status:?}")
                };
                (*member, shard)
            })
            .collect();

        // Stay-current duty: bring each synced store up to the parent's
        // terminal root before its child genesis adopts it.
        for (_, child, store, anchor, imported_root) in &synced {
            self.follow_child(store, parent, *child, *anchor, *imported_root);
        }

        self.flip_split_members(parent, &parent_halves, synced);

        // Both children run: blocks commit past their genesis on a seated
        // member, from state continuous with the parent's subtree.
        let genesis_height = state.boundaries[&left].height;
        let run_deadline = self.now + self.epochs(CHILD_RUN_BUDGET_EPOCHS);
        let progressed = self.run_until_predicate(run_deadline, |r| {
            [left, right].iter().all(|child| {
                (0..r.num_hosts()).any(|node| {
                    r.hosts_shard(node, *child)
                        .is_some_and(|storage| storage.committed_height() > genesis_height)
                })
            })
        });
        assert!(
            progressed,
            "both children of {parent:?} must commit past genesis within \
             {CHILD_RUN_BUDGET_EPOCHS} epochs",
        );
    }

    /// Flip every member onto its assigned child: parent halves clone-and-adopt
    /// on their own hosts, observers reopen their synced store on a host that
    /// flipped to the sibling child.
    fn flip_split_members(
        &mut self,
        parent: ShardId,
        parent_halves: &[(ValidatorId, ShardId)],
        synced: Vec<(
            ValidatorId,
            ShardId,
            SimShardStorage,
            ShardAnchor,
            StateRoot,
        )>,
    ) {
        for (member, child) in parent_halves {
            let node = self.network.validator_to_node(*member);
            self.flip_split_child(node, *member, parent, *child, None);
        }
        let mut sibling_hosts: Vec<NodeIndex> = Vec::new();
        for (validator, child, store, _, _) in synced {
            let node = parent_halves
                .iter()
                .map(|(member, member_child)| {
                    (self.network.validator_to_node(*member), *member_child)
                })
                .find(|(node, member_child)| {
                    *member_child != child && !sibling_hosts.contains(node)
                })
                .map(|(node, _)| node)
                .expect("a free host whose own vnode flipped to the sibling");
            sibling_hosts.push(node);
            self.flip_split_child(node, validator, parent, child, Some(store));
        }
    }

    /// The current live leaf shards, read from host 0's topology snapshot.
    fn current_leaf_shards(&self) -> Vec<ShardId> {
        self.snapshot().shard_trie().leaves().collect()
    }

    /// Host 0's latest topology snapshot.
    fn snapshot(&self) -> Arc<TopologySnapshot> {
        self.host_topology(0).expect("host 0 carries a topology")
    }

    /// Host 0's latest committed beacon state.
    fn committed_beacon_state(&self) -> Option<Arc<BeaconState>> {
        let (_, state) = self.beacon_storage(0)?.latest_committed()?;
        Some(state)
    }

    /// The pending split's cohort for `parent` as `(observer, child)` pairs,
    /// once admitted.
    fn pending_split_cohort(&self, parent: ShardId) -> Option<Vec<(ValidatorId, ShardId)>> {
        let state = self.committed_beacon_state()?;
        let PendingReshape::Split { cohort, .. } = state.pending_reshapes.get(&parent)? else {
            return None;
        };
        Some(
            cohort
                .iter()
                .map(|(validator, seat)| (*validator, seat.child))
                .collect(),
        )
    }

    /// Run in one-second slices until `predicate` holds or `deadline` passes.
    fn run_until_predicate(
        &mut self,
        deadline: Duration,
        mut predicate: impl FnMut(&Self) -> bool,
    ) -> bool {
        while self.now < deadline {
            let next = self.now + Duration::from_secs(1);
            self.run_until(next);
            if predicate(self) {
                return true;
            }
        }
        false
    }

    /// `n` beacon epochs as a duration, from the configured epoch length.
    const fn epochs(&self, n: u64) -> Duration {
        Duration::from_millis(self.epoch_duration_ms.saturating_mul(n))
    }
}
