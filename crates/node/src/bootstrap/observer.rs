//! Sans-io observer bootstrap sequencer.
//!
//! A cohort observer of a pending child syncs exactly the child's key
//! span out of the splitting shard's beacon-attested boundary anchor:
//! the child span is partitioned into parallel sub-range fetches served
//! by the splitting shard's committee, every chunk is verified into the
//! parent's attested `state_root`, and the assembled leaves import into
//! the observer's child-rooted store.
//!
//! There is no anchor to compare the imported root against — the beacon
//! holds only the parent's root, a one-way hash over the child
//! subtrees. The trust source is the chunks themselves: each one proves
//! its leaves into the attested parent root with completeness, so the
//! imported set is exactly the tree's leaves under the child prefix,
//! and prefix-rooted hashing makes the resulting store root the parent
//! tree's subtree node at that prefix by construction.
//!
//! Sans-io like [`ShardBootstrap`](super::ShardBootstrap): drivers own
//! transport, peer selection, and the import write, and pump it through
//! the same [`BootstrapRequest`] surface (the witness-history variant
//! never appears — the pending child's accumulator starts empty).

use hyperscale_storage::ImportLeaf;
use hyperscale_types::network::response::GetStateRangeResponse;
use hyperscale_types::{
    BlockHeight, Bls12381G1PrivateKey, MAX_READY_WINDOW_BLOCKS, NetworkDefinition, ReadySignal,
    ShardAnchor, ShardId, StateRoot, ValidatorId, ready_signal_message, shard_prefix_path,
};

use super::snap_sync::SnapSync;
use super::{BootstrapOutcome, BootstrapRequest, SPLIT_BITS, STATE_CHUNK_LIMIT};

/// The self-signed ready signal an observer broadcasts to the
/// splitting shard's committee on completing its child-span bootstrap.
///
/// Windowed from the splitting shard's attested anchor — the freshest
/// committed height the observer holds an authenticated view of. The
/// anchor refreshes every epoch boundary, so the window comfortably
/// covers the chain's progress since; a signal that somehow passes
/// uncollected is re-emitted against a newer anchor. At the committee,
/// the signal classifies as a `ReshapeReady` witness leaf — the
/// sender's observer seat rides the window's topology snapshot.
#[must_use]
pub fn observer_ready_signal(
    network: &NetworkDefinition,
    validator: ValidatorId,
    signing_key: &Bls12381G1PrivateKey,
    anchor: ShardAnchor,
) -> ReadySignal {
    let start = anchor.height + 1;
    let end = start + (MAX_READY_WINDOW_BLOCKS - 1);
    let msg = ready_signal_message(network, validator, start, end);
    ReadySignal::new(validator, start, end, signing_key.sign_v1(&msg))
}

enum Phase {
    /// Assembling the child span of the parent's committed state.
    State(SnapSync),
    /// Leaves assembled and chunk-verified, waiting for the driver to
    /// take them for the child store import.
    ImportReady(Vec<ImportLeaf>),
    /// Driver took the leaves; waiting for the imported root.
    Importing,
    /// Imported: the child store holds the parent tree's child subtree.
    Complete(StateRoot),
}

/// Sequencing state for one observer's pending-child bootstrap.
pub struct ObserverBootstrap {
    anchor: ShardAnchor,
    child: ShardId,
    phase: Phase,
    /// Leaves handed to the driver for the store import — the child
    /// half's substate population, seeding the count frontier the
    /// child chain starts from.
    imported_substate_count: u64,
}

impl ObserverBootstrap {
    /// Start a bootstrap of `child`'s span against `parent`'s attested
    /// boundary `anchor`.
    ///
    /// # Panics
    ///
    /// Panics unless `child` is a child of `parent` — an observer seat
    /// only ever names one of the splitting shard's two children.
    #[must_use]
    pub fn new(parent: ShardId, anchor: ShardAnchor, child: ShardId) -> Self {
        assert_eq!(
            child.parent(),
            Some(parent),
            "observer bootstrap target {child:?} is not a child of {parent:?}",
        );
        Self {
            anchor,
            child,
            phase: Phase::State(SnapSync::spanning(
                anchor,
                shard_prefix_path(parent),
                &shard_prefix_path(child),
                SPLIT_BITS,
                STATE_CHUNK_LIMIT,
            )),
            imported_substate_count: 0,
        }
    }

    /// The parent-shard anchor this bootstrap verifies against.
    #[must_use]
    pub const fn anchor(&self) -> ShardAnchor {
        self.anchor
    }

    /// The pending child whose span this bootstrap assembles.
    #[must_use]
    pub const fn child(&self) -> ShardId {
        self.child
    }

    /// Every request the current phase wants in flight. Empty while
    /// requests are outstanding, an import is pending, or the bootstrap
    /// is complete. Only [`BootstrapRequest::StateRange`] ever appears.
    pub fn next_requests(&mut self) -> Vec<BootstrapRequest> {
        match &mut self.phase {
            Phase::State(snap) => snap
                .next_requests()
                .into_iter()
                .map(|(id, request)| BootstrapRequest::StateRange(id, request))
                .collect(),
            Phase::ImportReady(_) | Phase::Importing | Phase::Complete(_) => Vec::new(),
        }
    }

    /// Feed one state range response for `sub_range`. After the final
    /// chunk the assembled leaves become available via
    /// [`Self::take_import`].
    pub fn on_state_range(
        &mut self,
        sub_range: usize,
        response: &GetStateRangeResponse,
    ) -> BootstrapOutcome {
        let Phase::State(snap) = &mut self.phase else {
            return BootstrapOutcome::Rejected("state response outside the state phase");
        };
        let outcome = snap.on_response(sub_range, response);
        if snap.is_complete() {
            self.phase = Phase::ImportReady(snap.take_leaves());
        }
        outcome
    }

    /// Re-arm a state sub-range after a transport-level failure.
    pub fn on_state_range_failure(&mut self, sub_range: usize) {
        if let Phase::State(snap) = &mut self.phase {
            snap.on_failure(sub_range);
        }
    }

    /// The fully assembled, chunk-verified child-span leaves, ready for
    /// `BoundaryStore::import_boundary_state` at the anchor height on
    /// the observer's child-rooted store. `Some` exactly once; the
    /// driver answers with the imported root via [`Self::on_imported`].
    pub fn take_import(&mut self) -> Option<(BlockHeight, Vec<ImportLeaf>)> {
        let Phase::ImportReady(leaves) = &mut self.phase else {
            return None;
        };
        let leaves = std::mem::take(leaves);
        self.phase = Phase::Importing;
        self.imported_substate_count = leaves.len() as u64;
        Some((self.anchor.height, leaves))
    }

    /// Record the imported child-subtree root and complete.
    ///
    /// # Panics
    ///
    /// Panics unless the import was taken via [`Self::take_import`].
    pub fn on_imported(&mut self, root: StateRoot) {
        assert!(
            matches!(self.phase, Phase::Importing),
            "on_imported outside the import phase",
        );
        self.phase = Phase::Complete(root);
    }

    /// Whether the bootstrap is still assembling state — the only
    /// phase that depends on serving peers retaining the targeted
    /// boundary pin, and the last at which restarting against a newer
    /// anchor is sound (nothing has been imported into the store yet).
    #[must_use]
    pub const fn is_assembling_state(&self) -> bool {
        matches!(self.phase, Phase::State(_))
    }

    /// Whether the child span is imported.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }

    /// The imported child-subtree root — the parent tree's node at the
    /// child prefix as of the anchor. `None` until complete.
    #[must_use]
    pub const fn imported_root(&self) -> Option<StateRoot> {
        match self.phase {
            Phase::Complete(root) => Some(root),
            _ => None,
        }
    }

    /// The imported substate population of the child half — the count
    /// frontier the child chain starts from. Zero until the import is
    /// taken.
    #[must_use]
    pub const fn imported_substate_count(&self) -> u64 {
        self.imported_substate_count
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_jmt::{Blake3Hasher, Hasher};
    use hyperscale_storage::test_helpers::pin_snap_sync_replica;
    use hyperscale_storage::{BoundaryStore, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::Hash;

    use super::*;
    use crate::shard_io::fetch::state_range_serve::serve_state_range_request;

    const ENTRIES: u8 = 12;

    /// A committed parent replica (whole-keyspace root shard), pinned at
    /// its boundary for serving.
    fn parent_replica() -> (Arc<SimShardStorage>, ShardAnchor) {
        let storage = SimShardStorage::default();
        let anchor = pin_snap_sync_replica(&storage, ENTRIES, &[]);
        (Arc::new(storage), anchor)
    }

    /// Drive one observer bootstrap to completion against `serving`,
    /// importing into a fresh store rooted at the child's prefix.
    /// Returns the child store and its imported root.
    fn observe(
        serving: &Arc<SimShardStorage>,
        anchor: ShardAnchor,
        child: ShardId,
    ) -> (SimShardStorage, StateRoot) {
        let store = SimShardStorage::new(shard_prefix_path(child));
        let mut bootstrap = ObserverBootstrap::new(ShardId::ROOT, anchor, child);
        for _ in 0..1_000 {
            if bootstrap.is_complete() {
                let root = bootstrap.imported_root().expect("complete");
                return (store, root);
            }
            for request in bootstrap.next_requests() {
                let BootstrapRequest::StateRange(id, request) = request else {
                    panic!("observer bootstrap emitted a non-state request");
                };
                let response = serve_state_range_request(serving, &request);
                assert_eq!(
                    bootstrap.on_state_range(id, &response),
                    BootstrapOutcome::Accepted,
                );
            }
            if let Some((height, leaves)) = bootstrap.take_import() {
                let root = store.import_boundary_state(height, leaves).unwrap();
                bootstrap.on_imported(root);
            }
        }
        panic!("observer bootstrap did not complete");
    }

    /// The keystone identity, end to end: each child store adopts
    /// exactly the parent tree's subtree at its prefix, the two halves
    /// partition the parent's substates, and the parent's attested root
    /// recomposes from the two imported roots.
    #[test]
    fn observer_bootstraps_adopt_the_child_subtrees() {
        let (serving, anchor) = parent_replica();
        let (left, right) = ShardId::ROOT.children();

        let (left_store, left_root) = observe(&serving, anchor, left);
        let (right_store, right_root) = observe(&serving, anchor, right);

        assert_eq!(left_store.state_root(), left_root);
        assert_eq!(right_store.state_root(), right_root);
        assert_eq!(
            StateRoot::from_raw(Hash::from_hash_bytes(&Blake3Hasher::hash_internal(&[
                *left_root.as_raw().as_bytes(),
                *right_root.as_raw().as_bytes(),
            ]))),
            anchor.state_root,
            "imported child roots must recompose to the parent's attested root",
        );
    }

    /// Both halves together hold every parent substate exactly once.
    #[test]
    fn child_spans_partition_the_parent_population() {
        let (serving, anchor) = parent_replica();
        let children: [ShardId; 2] = ShardId::ROOT.children().into();

        let mut counts = Vec::new();
        for child in children {
            let mut bootstrap = ObserverBootstrap::new(ShardId::ROOT, anchor, child);
            for _ in 0..1_000 {
                if bootstrap.take_import().is_some() {
                    break;
                }
                for request in bootstrap.next_requests() {
                    if let BootstrapRequest::StateRange(id, request) = request {
                        let response = serve_state_range_request(&serving, &request);
                        bootstrap.on_state_range(id, &response);
                    }
                }
            }
            counts.push(bootstrap.imported_substate_count());
        }
        assert_eq!(counts.iter().sum::<u64>(), u64::from(ENTRIES));
        assert!(
            counts.iter().all(|&c| c > 0),
            "fixture population must straddle the split bit; got {counts:?}",
        );
    }

    /// A tampered leaf value fails the chunk verification and rejects.
    #[test]
    fn tampered_chunk_is_rejected() {
        let (serving, anchor) = parent_replica();
        let (left, _) = ShardId::ROOT.children();
        let mut bootstrap = ObserverBootstrap::new(ShardId::ROOT, anchor, left);

        let mut rejected = false;
        'outer: for _ in 0..1_000 {
            for request in bootstrap.next_requests() {
                let BootstrapRequest::StateRange(id, request) = request else {
                    unreachable!();
                };
                let mut response = serve_state_range_request(&serving, &request);
                if let Some(chunk) = &mut response.chunk
                    && !chunk.leaves.is_empty()
                {
                    let mut leaves: Vec<_> = chunk.leaves.iter().cloned().collect();
                    let mut value = leaves[0].value.to_vec();
                    value[0] ^= 1;
                    leaves[0].value = value.into();
                    chunk.leaves = leaves.into();
                    rejected = matches!(
                        bootstrap.on_state_range(id, &response),
                        BootstrapOutcome::Rejected(_),
                    );
                    break 'outer;
                }
                bootstrap.on_state_range(id, &response);
            }
        }
        assert!(rejected, "tampered chunk must reject");
    }

    /// An observer seat only ever names a child of the splitting shard.
    #[test]
    #[should_panic(expected = "is not a child of")]
    fn rejects_a_target_outside_the_split() {
        let (_, anchor) = parent_replica();
        let _ = ObserverBootstrap::new(ShardId::ROOT, anchor, ShardId::leaf(2, 0b11));
    }
}
