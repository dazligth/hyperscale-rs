//! The sans-io reshape orchestrator.
//!
//! One per host. It owns the per-duty sequencing decisions of a split or merge —
//! when to sync, re-assert ready, follow, adopt, and seat — and drives them by
//! reading the committed-state projection ([`ReshapeView`]) and reacting to io
//! results. It holds the sans-io sequencers ([`ObserverBootstrap`],
//! [`ObserverTail`]) so both harnesses run the *same* sequencing; the adapter
//! owns all io (`RocksDB` opens, network fetch/notify, store writes, timers) and
//! the wall-clock pacing of [`ReshapeOrchestrator::step`].
//!
//! Each `step` reads the view, applies the io results the adapter feeds back,
//! advances every duty, and returns the io the adapter should perform. It is
//! idempotent: one-shot requests are guarded by duty flags, the sequencers gate
//! their own in-flight fetches, and the ready re-assert is deliberately repeated
//! each step (the adapter's step cadence paces it — production's 1s sleep,
//! simulation's per-slice pump).
//!
//! This module covers the **split observer** duty. The merge keeper duty and the
//! supervisor wiring land in later phases.

use std::collections::HashMap;

use hyperscale_storage::ImportLeaf;
use hyperscale_types::network::request::{GetBlockRequest, GetStateRangeRequest};
use hyperscale_types::network::response::{GetBlockResponse, GetStateRangeResponse};
use hyperscale_types::{
    Block, BlockHeight, ChainOrigin, ShardAnchor, ShardId, StateRoot, StoredReceipt, ValidatorId,
};

use crate::bootstrap::BootstrapRequest;
use crate::reshape::observer::{ObserverBootstrap, ObserverTail};
use crate::reshape::split_flip::split_genesis_from_terminal;
use crate::reshape::view::ReshapeView;

/// What a [`ReshapeRequest::Fetch`] asks the adapter to retrieve, forwarded from
/// a held sequencer.
#[derive(Debug, Clone)]
pub enum FetchKind {
    /// A snap-sync state sub-range, from [`ObserverBootstrap`].
    StateRange {
        /// The sub-range id the response must be paired back to.
        sub_range: usize,
        /// The range request itself.
        request: GetStateRangeRequest,
    },
    /// A single committed block by height, from [`ObserverTail`] or a terminal
    /// fetch.
    Block {
        /// The block request itself.
        request: GetBlockRequest,
    },
}

/// Which genesis derivation a [`ReshapeRequest::Adopt`] performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptKind {
    /// A split child adopts from its parent's terminal contribution.
    Split,
    /// A merge parent adopts from both children's terminal contributions.
    Merge,
}

/// A unit of io the orchestrator needs the adapter to perform. The adapter owns
/// the store handles, network, and timers; it answers with a [`ReshapeEvent`].
#[derive(Debug, Clone)]
pub enum ReshapeRequest {
    /// Open (wiping any stale directory) `shard`'s store and replicate the
    /// engine bootstrap into it. Answered by [`ReshapeEvent::Opened`].
    OpenStore {
        /// The duty's store shard.
        shard: ShardId,
    },
    /// Fetch from `peers` serving `from`, on behalf of `duty`. Answered by
    /// [`ReshapeEvent::Fetched`] (or [`ReshapeEvent::FetchFailed`]).
    Fetch {
        /// The duty this fetch belongs to (an observer's child).
        duty: ShardId,
        /// The shard whose committee serves the request.
        from: ShardId,
        /// The peers to ask.
        peers: Vec<ValidatorId>,
        /// What to fetch.
        kind: FetchKind,
    },
    /// Write `leaves` into `shard`'s store at `height`. Answered by
    /// [`ReshapeEvent::Imported`].
    ImportBoundary {
        /// The duty's store shard.
        shard: ShardId,
        /// The boundary height the leaves seed.
        height: BlockHeight,
        /// The assembled child-span leaves.
        leaves: Vec<ImportLeaf>,
    },
    /// Apply a followed parent block's child-prefix writes into `shard`'s store.
    /// Answered by [`ReshapeEvent::Applied`].
    ApplyFollow {
        /// The duty's store shard.
        shard: ShardId,
        /// The followed block's height.
        height: BlockHeight,
        /// The block's certified receipts.
        receipts: Vec<StoredReceipt>,
    },
    /// Sign a ready signal for `validator` anchored at `anchor` and notify
    /// `recipients`. No response.
    BroadcastReady {
        /// The seat holder signing the signal.
        validator: ValidatorId,
        /// The attested anchor the signal windows from.
        anchor: ShardAnchor,
        /// The committee the signal is broadcast to.
        recipients: Vec<ValidatorId>,
    },
    /// Adopt `shard`'s derived genesis, verifying the adopted root against the
    /// beacon anchor. Answered by [`ReshapeEvent::Adopted`].
    Adopt {
        /// The duty's store shard.
        shard: ShardId,
        /// Split vs merge derivation.
        kind: AdoptKind,
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
    },
    /// Seat the prepared `shard` — install its genesis and run consensus. No
    /// response (terminal).
    Seat {
        /// The duty's store shard.
        shard: ShardId,
    },
}

/// What a [`ReshapeEvent::Fetched`] carried back.
#[derive(Debug, Clone)]
pub enum FetchedKind {
    /// A state sub-range response, paired by `sub_range`.
    StateRange {
        /// The sub-range id this answers.
        sub_range: usize,
        /// The response.
        response: Box<GetStateRangeResponse>,
    },
    /// A block response.
    Block {
        /// The response.
        response: Box<GetBlockResponse>,
    },
}

/// An io result the adapter feeds back into [`ReshapeOrchestrator::step`].
#[derive(Debug, Clone)]
pub enum ReshapeEvent {
    /// A store open completed.
    Opened {
        /// The opened store shard.
        shard: ShardId,
    },
    /// A fetch returned a response.
    Fetched {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// The response.
        kind: FetchedKind,
    },
    /// A fetch failed at the transport level and should be re-armed.
    FetchFailed {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// What failed.
        kind: FetchKind,
    },
    /// A boundary import completed with the resulting store root.
    Imported {
        /// The store shard.
        shard: ShardId,
        /// The imported root.
        root: StateRoot,
    },
    /// A followed-block application completed with the resulting store root.
    Applied {
        /// The store shard.
        shard: ShardId,
        /// The applied root.
        root: StateRoot,
    },
    /// A genesis adoption completed (root already verified against the anchor).
    Adopted {
        /// The store shard.
        shard: ShardId,
    },
}

/// One observer's progress through its split duty.
enum ObserverPhase {
    /// Awaiting the child store open.
    Opening,
    /// Syncing the child span from the parent's attested anchor.
    Syncing(Box<ObserverBootstrap>),
    /// Synced; re-asserting ready and following the parent toward its terminal
    /// crossing, until the children seed.
    Following(Box<ObserverTail>),
    /// The children seeded; fetching the certified terminal to derive genesis.
    FetchingTerminal {
        /// The beacon-seeded child anchor the derivation verifies against.
        anchor: ShardAnchor,
        /// Whether the terminal fetch is already in flight.
        requested: bool,
    },
    /// Terminal fetched and genesis derived; awaiting the next `advance` to emit
    /// the adopt.
    Adopting {
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
    },
    /// Adopt emitted; awaiting the verified adopted root.
    AwaitingAdopt,
    /// Genesis adopted into the store; awaiting the placement that seats it.
    Prepared,
}

/// One split observer duty, keyed by the child it syncs.
struct ObserverDuty {
    parent: ShardId,
    child: ShardId,
    validator: ValidatorId,
    phase: ObserverPhase,
    open_requested: bool,
    store_opened: bool,
}

/// The per-host reshape orchestrator. See the module docs.
#[derive(Default)]
pub struct ReshapeOrchestrator {
    /// This host's validator ids — the seats it may hold.
    me: Vec<ValidatorId>,
    /// In-flight observer duties, keyed by child.
    observers: HashMap<ShardId, ObserverDuty>,
}

impl ReshapeOrchestrator {
    /// A fresh orchestrator for a host running `me`.
    #[must_use]
    pub fn new(me: Vec<ValidatorId>) -> Self {
        Self {
            me,
            observers: HashMap::new(),
        }
    }

    /// Advance every duty one step: apply the io results in `events`, discover
    /// new duties from `view`, and return the io the adapter should perform.
    pub fn step(&mut self, view: &ReshapeView, events: Vec<ReshapeEvent>) -> Vec<ReshapeRequest> {
        for event in events {
            self.apply_event(view, event);
        }
        self.discover_observer_duties(view);

        let mut requests = Vec::new();
        let children: Vec<ShardId> = self.observers.keys().copied().collect();
        for child in children {
            self.advance_observer(child, view, &mut requests);
        }
        requests
    }

    /// Route one io result to the duty and sequencer awaiting it.
    fn apply_event(&mut self, _view: &ReshapeView, event: ReshapeEvent) {
        match event {
            ReshapeEvent::Opened { shard } => {
                if let Some(duty) = self.observers.get_mut(&shard) {
                    duty.store_opened = true;
                }
            }
            ReshapeEvent::Fetched { duty, kind } => self.apply_fetched(duty, kind),
            ReshapeEvent::FetchFailed { duty, kind } => {
                let Some(duty) = self.observers.get_mut(&duty) else {
                    return;
                };
                match (&mut duty.phase, kind) {
                    (
                        ObserverPhase::Syncing(bootstrap),
                        FetchKind::StateRange { sub_range, .. },
                    ) => bootstrap.on_state_range_failure(sub_range),
                    (ObserverPhase::Following(tail), FetchKind::Block { .. }) => tail.on_failure(),
                    (ObserverPhase::FetchingTerminal { requested, .. }, _) => *requested = false,
                    _ => {}
                }
            }
            ReshapeEvent::Imported { shard, root } => {
                if let Some(duty) = self.observers.get_mut(&shard)
                    && let ObserverPhase::Syncing(bootstrap) = &mut duty.phase
                {
                    bootstrap.on_imported(root);
                }
            }
            ReshapeEvent::Applied { shard, root } => {
                if let Some(duty) = self.observers.get_mut(&shard)
                    && let ObserverPhase::Following(tail) = &mut duty.phase
                    && tail.on_applied(root).is_err()
                {
                    // A diverged follow fails closed: drop the duty so the
                    // adapter falls back to a fresh snap-sync join.
                    self.observers.remove(&shard);
                }
            }
            ReshapeEvent::Adopted { shard } => {
                if let Some(duty) = self.observers.get_mut(&shard)
                    && matches!(duty.phase, ObserverPhase::AwaitingAdopt)
                {
                    duty.phase = ObserverPhase::Prepared;
                }
            }
        }
    }

    /// Route a fetch response to its sequencer, deriving genesis once the
    /// terminal arrives.
    fn apply_fetched(&mut self, duty: ShardId, kind: FetchedKind) {
        let Some(duty) = self.observers.get_mut(&duty) else {
            return;
        };
        let child = duty.child;
        let mut next: Option<ObserverPhase> = None;
        match (&mut duty.phase, kind) {
            (
                ObserverPhase::Syncing(bootstrap),
                FetchedKind::StateRange {
                    sub_range,
                    response,
                },
            ) => {
                let _ = bootstrap.on_state_range(sub_range, &response);
            }
            (ObserverPhase::Following(tail), FetchedKind::Block { response }) => {
                let _ = tail.on_response(&response);
            }
            (
                ObserverPhase::FetchingTerminal { anchor, requested },
                FetchedKind::Block { response },
            ) => {
                *requested = false;
                let anchor = *anchor;
                if let Some(elided) = &response.certified
                    && let Ok((genesis, origin)) =
                        split_genesis_from_terminal(child, elided.header(), elided.qc(), &anchor)
                {
                    next = Some(ObserverPhase::Adopting {
                        origin,
                        genesis: Box::new(genesis),
                    });
                }
            }
            _ => {}
        }
        if let Some(phase) = next {
            duty.phase = phase;
        }
    }

    /// Open an observer duty for every cohort seat this host holds that it
    /// isn't already running.
    fn discover_observer_duties(&mut self, view: &ReshapeView) {
        for (&parent, cohort) in view.observer_cohorts() {
            for (&validator, &child) in cohort {
                if self.me.contains(&validator) && !self.observers.contains_key(&child) {
                    self.observers.insert(
                        child,
                        ObserverDuty {
                            parent,
                            child,
                            validator,
                            phase: ObserverPhase::Opening,
                            open_requested: false,
                            store_opened: false,
                        },
                    );
                }
            }
        }
    }

    /// Advance one observer duty, emitting its current io.
    #[allow(clippy::too_many_lines)] // single dispatch over ObserverPhase
    fn advance_observer(
        &mut self,
        child: ShardId,
        view: &ReshapeView,
        out: &mut Vec<ReshapeRequest>,
    ) {
        let Some(duty) = self.observers.get_mut(&child) else {
            return;
        };
        match &mut duty.phase {
            ObserverPhase::Opening => {
                if !duty.open_requested {
                    out.push(ReshapeRequest::OpenStore { shard: child });
                    duty.open_requested = true;
                }
                if duty.store_opened
                    && let Some(anchor) = view.boundary(duty.parent)
                {
                    duty.phase = ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(
                        duty.parent,
                        anchor,
                        child,
                    )));
                }
            }
            ObserverPhase::Syncing(bootstrap) => {
                for request in bootstrap.next_requests() {
                    // The pending child's witness accumulator starts empty, so
                    // an observer bootstrap only ever emits state ranges.
                    let BootstrapRequest::StateRange(sub_range, request) = request else {
                        continue;
                    };
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: duty.parent,
                        peers: view.committee(duty.parent).to_vec(),
                        kind: FetchKind::StateRange { sub_range, request },
                    });
                }
                if let Some((height, leaves)) = bootstrap.take_import() {
                    out.push(ReshapeRequest::ImportBoundary {
                        shard: child,
                        height,
                        leaves,
                    });
                }
                if let Some(root) = bootstrap.imported_root() {
                    let anchor = bootstrap.anchor();
                    duty.phase =
                        ObserverPhase::Following(Box::new(ObserverTail::new(anchor, child, root)));
                }
            }
            ObserverPhase::Following(tail) => {
                // Once the children seed, the parent terminated: stop following
                // and re-asserting, and derive genesis from its crossing.
                if view.children_seeded(duty.parent)
                    && let Some(anchor) = view.boundary(child)
                {
                    duty.phase = ObserverPhase::FetchingTerminal {
                        anchor,
                        requested: false,
                    };
                    return;
                }
                if let Some(anchor) = view.boundary(duty.parent) {
                    out.push(ReshapeRequest::BroadcastReady {
                        validator: duty.validator,
                        anchor,
                        recipients: recipients_for(view, duty.parent, duty.validator),
                    });
                }
                if let Some(request) = tail.next_request() {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: duty.parent,
                        peers: view.committee(duty.parent).to_vec(),
                        kind: FetchKind::Block { request },
                    });
                }
                if let Some((height, receipts)) = tail.take_apply() {
                    out.push(ReshapeRequest::ApplyFollow {
                        shard: child,
                        height,
                        receipts,
                    });
                }
            }
            ObserverPhase::FetchingTerminal { anchor, requested } => {
                if !*requested {
                    let terminal = anchor.height.prev().unwrap_or(anchor.height);
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: child,
                        peers: view.committee(child).to_vec(),
                        kind: FetchKind::Block {
                            request: GetBlockRequest::new(terminal, terminal),
                        },
                    });
                    *requested = true;
                }
            }
            ObserverPhase::Adopting { .. } => {
                if let ObserverPhase::Adopting { origin, genesis } =
                    std::mem::replace(&mut duty.phase, ObserverPhase::AwaitingAdopt)
                {
                    out.push(ReshapeRequest::Adopt {
                        shard: child,
                        kind: AdoptKind::Split,
                        origin,
                        genesis,
                    });
                }
            }
            ObserverPhase::AwaitingAdopt => {}
            ObserverPhase::Prepared => {
                if view.committee(child).contains(&duty.validator) {
                    out.push(ReshapeRequest::Seat { shard: child });
                    self.observers.remove(&child);
                }
            }
        }
    }
}

/// A ready signal's recipients — `shard`'s committee minus the signer.
fn recipients_for(view: &ReshapeView, shard: ShardId, validator: ValidatorId) -> Vec<ValidatorId> {
    view.committee(shard)
        .iter()
        .copied()
        .filter(|&v| v != validator)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_types::{
        BlockHash, BlockHeight, Hash, NetworkDefinition, ShardAnchor, ShardId, StateRoot,
        TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet, WeightedTimestamp,
        generate_bls_keypair,
    };

    use super::{FetchKind, ObserverDuty, ObserverPhase, ReshapeOrchestrator, ReshapeRequest};
    use crate::reshape::observer::{ObserverBootstrap, ObserverTail};
    use crate::reshape::view::ReshapeView;

    fn vid(id: u64) -> ValidatorId {
        ValidatorId::new(id)
    }

    /// A non-zero anchor whose `prev` height is a valid terminal.
    fn anchor() -> ShardAnchor {
        ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"seeded-boundary")),
            height: BlockHeight::new(8),
            weighted_timestamp: WeightedTimestamp::ZERO,
            settled_waves_root: None,
        }
    }

    /// Project a snapshot with the given committees, observer cohort seats
    /// `(parent, validator, child)`, and seeded boundaries.
    fn snapshot(
        committees: &[(ShardId, &[u64])],
        cohort: &[(ShardId, u64, ShardId)],
        seeded: &[ShardId],
    ) -> TopologySnapshot {
        let mut ids: BTreeSet<u64> = BTreeSet::new();
        for (_, members) in committees {
            ids.extend(members.iter().copied());
        }
        for (_, v, _) in cohort {
            ids.insert(*v);
        }
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| ValidatorInfo {
                validator_id: vid(id),
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        let committee_map: HashMap<ShardId, Vec<ValidatorId>> = committees
            .iter()
            .map(|(s, members)| (*s, members.iter().map(|&m| vid(m)).collect()))
            .collect();
        let mut cohorts: HashMap<ShardId, BTreeMap<ValidatorId, ShardId>> = HashMap::new();
        for (parent, v, child) in cohort {
            cohorts.entry(*parent).or_default().insert(vid(*v), *child);
        }
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            committee_map.clone(),
            committee_map,
            seeded.iter().map(|&s| (s, anchor())).collect(),
            HashMap::new(),
            cohorts,
            HashMap::new(),
            BTreeSet::new(),
        )
    }

    fn observer_duty(
        parent: ShardId,
        child: ShardId,
        validator: u64,
        phase: ObserverPhase,
    ) -> ObserverDuty {
        ObserverDuty {
            parent,
            child,
            validator: vid(validator),
            phase,
            open_requested: true,
            store_opened: true,
        }
    }

    #[test]
    fn detects_a_cohort_seat_and_opens_the_store() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[], &[(parent, 5, child)], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(&ReshapeView::new(&snap), Vec::new());

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::OpenStore { shard }] if *shard == child),
            "a held cohort seat must open the child store; got {requests:?}",
        );
    }

    #[test]
    fn ignores_a_cohort_seat_this_host_does_not_hold() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[], &[(parent, 9, child)], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        assert!(orch.step(&ReshapeView::new(&snap), Vec::new()).is_empty());
    }

    #[test]
    fn syncing_forwards_the_bootstrap_state_ranges() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 4])], &[], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(parent, anchor(), child))),
            ),
        );

        let requests = orch.step(&ReshapeView::new(&snap), Vec::new());

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::Fetch { from, kind: FetchKind::StateRange { .. }, .. } if *from == parent
            )),
            "a syncing duty must forward the bootstrap's state ranges; got {requests:?}",
        );
    }

    #[test]
    fn following_reasserts_ready_to_the_parent_committee() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                ObserverPhase::Following(Box::new(ObserverTail::new(
                    anchor(),
                    child,
                    StateRoot::ZERO,
                ))),
            ),
        );

        let requests = orch.step(&ReshapeView::new(&snap), Vec::new());

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::BroadcastReady { validator, recipients, .. }
                    if *validator == vid(5) && !recipients.contains(&vid(5)) && recipients.len() == 3
            )),
            "a following duty must re-assert ready to the parent committee minus self; got {requests:?}",
        );
    }

    #[test]
    fn the_gate_advances_a_follower_to_the_terminal_fetch() {
        let parent = ShardId::ROOT;
        let (child, sibling) = parent.children();
        // Both children seeded → the gate fires; the terminal fetch addresses
        // the child committee.
        let snap = snapshot(&[(child, &[1, 2])], &[], &[parent, child, sibling]);
        let view = ReshapeView::new(&snap);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                ObserverPhase::Following(Box::new(ObserverTail::new(
                    anchor(),
                    child,
                    StateRoot::ZERO,
                ))),
            ),
        );

        // First step fires the gate (Following → FetchingTerminal); the second
        // emits the terminal fetch.
        let _ = orch.step(&view, Vec::new());
        let requests = orch.step(&view, Vec::new());

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::Fetch { duty, from, kind: FetchKind::Block { .. }, .. }
                    if *duty == child && *from == child
            )),
            "the gate must drive a terminal fetch from the child committee; got {requests:?}",
        );
    }

    #[test]
    fn a_prepared_duty_seats_once_the_placement_lands() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The observer is now seated on the child committee.
        let snap = snapshot(&[(child, &[1, 5])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(parent, child, 5, ObserverPhase::Prepared),
        );

        let requests = orch.step(&ReshapeView::new(&snap), Vec::new());

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::Seat { shard }] if *shard == child),
            "a prepared duty must seat once placed on the child; got {requests:?}",
        );
    }

    #[test]
    fn a_prepared_duty_waits_until_placed() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // Child committee does not yet include the observer.
        let snap = snapshot(&[(child, &[1, 2])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(parent, child, 5, ObserverPhase::Prepared),
        );

        assert!(orch.step(&ReshapeView::new(&snap), Vec::new()).is_empty());
    }
}
