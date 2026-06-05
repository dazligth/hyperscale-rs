//! Weighted-time-indexed schedule of per-epoch committee snapshots.
//!
//! A [`TopologySnapshot`] is one committee's view; a [`TopologySchedule`] is
//! those views indexed by the epoch each governs. It is the interface the rest
//! of the system resolves committees through — consensus artifacts are signed
//! by the committee for `epoch_for(weighted_timestamp)`, which may differ from
//! the current one, so verification keys on [`TopologySchedule::at`] while
//! routing keys on [`TopologySchedule::head`].
//!
//! The schedule is pure topology: it carries no consensus state and depends on
//! nothing above `hyperscale-types`. The beacon coordinator owns one and
//! advances it on each commit; shard and execution verification borrow it.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{Epoch, TopologySnapshot, WeightedTimestamp};

/// Per-epoch committee snapshots keyed by the epoch each governs, plus the
/// active head used for routing.
///
/// `committee_N` governs the weighted-time window `[N·ED, (N+1)·ED)`;
/// [`at`](Self::at) floors a timestamp to its epoch and returns that
/// committee. The map spans `[current − retention, current + lookahead]`: past
/// entries verify artifacts up to the retention horizon old, the lookahead
/// entry is finalized an epoch before its window opens.
///
/// A schedule built with [`single`](Self::single) carries one committee for
/// all time (`epoch_duration_ms == 0` folds every timestamp to genesis) — the
/// pre-rotation / single-epoch case used by tests and within-epoch callers.
#[derive(Clone)]
pub struct TopologySchedule {
    /// Window length in milliseconds; `epoch = floor(wt / epoch_duration_ms)`.
    /// Zero means a single fixed committee (every timestamp maps to genesis).
    epoch_duration_ms: u64,
    /// Past epochs retained behind the active one before eviction.
    retention_epochs: u64,
    /// Active committee for routing / gossip ("who is in the committee now?").
    head: Arc<TopologySnapshot>,
    /// Committee snapshots keyed by the epoch each governs.
    by_epoch: BTreeMap<Epoch, Arc<TopologySnapshot>>,
}

impl TopologySchedule {
    /// Build a schedule seeded with `head` as the committee governing
    /// `head_epoch`. The beacon coordinator inserts the lookahead and any
    /// retained past epochs afterward via [`insert`](Self::insert).
    #[must_use]
    pub fn new(
        epoch_duration_ms: u64,
        retention_epochs: u64,
        head_epoch: Epoch,
        head: Arc<TopologySnapshot>,
    ) -> Self {
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(head_epoch, Arc::clone(&head));
        Self {
            epoch_duration_ms,
            retention_epochs,
            head,
            by_epoch,
        }
    }

    /// A schedule of one committee for all time: every weighted timestamp
    /// resolves to `snapshot`, and it is also the head. Used by tests and by
    /// within-epoch callers that hold a single committee.
    #[must_use]
    pub fn single(snapshot: Arc<TopologySnapshot>) -> Self {
        // `epoch_duration_ms == 0` makes `epoch_for` fold every timestamp to
        // genesis, where the sole entry lives — so `at` always answers.
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(Epoch::GENESIS, Arc::clone(&snapshot));
        Self {
            epoch_duration_ms: 0,
            retention_epochs: u64::MAX,
            head: snapshot,
            by_epoch,
        }
    }

    /// Epoch whose window contains `wt` — `floor(wt / epoch_duration_ms)`,
    /// genesis-relative. A zero duration (single-committee schedule) folds
    /// every timestamp to genesis.
    #[must_use]
    pub const fn epoch_for(&self, wt: WeightedTimestamp) -> Epoch {
        match wt.as_millis().checked_div(self.epoch_duration_ms) {
            Some(epoch) => Epoch::new(epoch),
            None => Epoch::GENESIS,
        }
    }

    /// Committee that signed an artifact attested at `wt` — exact, for
    /// verification and quorum. `None` when that epoch is outside the retained
    /// window: past the retention horizon (artifact too old — drop), or beyond
    /// the lookahead (this node's beacon hasn't committed that epoch yet —
    /// buffer or stall). Hands out a shared handle: borrow it for verification,
    /// or clone it to move into an off-thread closure.
    #[must_use]
    pub fn at(&self, wt: WeightedTimestamp) -> Option<&Arc<TopologySnapshot>> {
        self.by_epoch.get(&self.epoch_for(wt))
    }

    /// Active head committee — for the chain's constant
    /// [`NetworkDefinition`](crate::NetworkDefinition) and self-healing routing
    /// (including the lock-free reads the `io_loop` serves through its
    /// `ArcSwap`). Never for committee-quorum verification, which must key on
    /// the artifact's own weighted timestamp via [`at`](Self::at).
    #[must_use]
    pub const fn head(&self) -> &Arc<TopologySnapshot> {
        &self.head
    }

    /// Record the committee governing `epoch`. The beacon coordinator inserts
    /// the just-applied epoch's active committee and the next epoch's
    /// lookahead on every commit.
    pub fn insert(&mut self, epoch: Epoch, snapshot: Arc<TopologySnapshot>) {
        self.by_epoch.insert(epoch, snapshot);
    }

    /// Replace the active head committee (routing view).
    pub fn set_head(&mut self, snapshot: Arc<TopologySnapshot>) {
        self.head = snapshot;
    }

    /// Drop entries older than `current_epoch − retention_epochs`, bounding the
    /// schedule to the retention window.
    pub fn evict_before(&mut self, current_epoch: Epoch) {
        let oldest = current_epoch.inner().saturating_sub(self.retention_epochs);
        self.by_epoch.retain(|epoch, _| epoch.inner() >= oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkDefinition, ValidatorSet};

    fn snapshot() -> Arc<TopologySnapshot> {
        Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        ))
    }

    #[test]
    fn epoch_for_floors_to_window() {
        let sched = TopologySchedule::new(1000, 4, Epoch::new(5), snapshot());
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(0)),
            Epoch::new(0)
        );
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(999)),
            Epoch::new(0)
        );
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(1000)),
            Epoch::new(1)
        );
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(2500)),
            Epoch::new(2)
        );
    }

    #[test]
    fn single_resolves_every_timestamp_to_the_one_committee() {
        let sched = TopologySchedule::single(snapshot());
        assert!(sched.at(WeightedTimestamp::from_millis(0)).is_some());
        assert!(
            sched
                .at(WeightedTimestamp::from_millis(1_000_000_000))
                .is_some()
        );
        // Head and `at` agree — one committee for all time.
        assert!(Arc::ptr_eq(
            sched.head(),
            sched.at(WeightedTimestamp::from_millis(42)).unwrap()
        ));
    }

    #[test]
    fn at_returns_none_for_epochs_outside_the_window() {
        // The window holds the active epoch 5 and its lookahead 6.
        let mut sched = TopologySchedule::new(1000, 1, Epoch::new(5), snapshot());
        sched.insert(Epoch::new(6), snapshot());
        assert!(sched.at(WeightedTimestamp::from_millis(5500)).is_some());
        assert!(sched.at(WeightedTimestamp::from_millis(6500)).is_some());
        // Below the window (too old to retain) and above the lookahead (the
        // beacon hasn't committed it yet) both resolve to `None`.
        assert!(sched.at(WeightedTimestamp::from_millis(3500)).is_none());
        assert!(sched.at(WeightedTimestamp::from_millis(7500)).is_none());
    }

    #[test]
    fn evict_before_drops_past_the_retention_window() {
        let mut sched = TopologySchedule::new(1000, 1, Epoch::new(4), snapshot());
        sched.insert(Epoch::new(5), snapshot());
        sched.insert(Epoch::new(6), snapshot());
        // Retain [current-1, ..]; committing epoch 6 evicts 4.
        sched.evict_before(Epoch::new(6));
        assert!(sched.at(WeightedTimestamp::from_millis(4500)).is_none());
        assert!(sched.at(WeightedTimestamp::from_millis(5500)).is_some());
        assert!(sched.at(WeightedTimestamp::from_millis(6500)).is_some());
    }
}
