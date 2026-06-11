//! End-to-end split grow phase with real observers.
//!
//! Boots a single-shard network whose chain config arms the split
//! trigger from genesis, lets the shard's own quorum assert it and the
//! beacon fold admit it (drawing the four pooled extras as the observer
//! cohort), then runs each observer's real duty through the harness:
//! the sans-io child-span bootstrap served by the splitting shard's
//! committee, and the self-signed ready signal delivered over the
//! network — BLS-verified, pooled, drained into a block, classified as
//! a `ReshapeReady` witness leaf, and folded into the readiness gate.
//! The gate fires and the trie reshapes into the lookahead: the parent
//! membership partitions across the two children, every observer lands
//! on its assigned child, and each child stands at full committee
//! strength a full epoch before its window opens.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_node::shard_loop::{ProcessScopedInput, ShardEvent};
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::SubstateStore;
use hyperscale_types::test_utils::test_transaction;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, PendingReshape, ReshapeThresholds, ShardId, StateRoot,
    ValidatorId, ValidatorStatus,
};
use tracing_test::traced_test;

/// 2-second epochs: short enough to run the whole grow inside the
/// test budget, long enough that the beacon paces (one epoch per
/// `epoch_duration_ms`) rather than stalling against its
/// production-sized SPC/skip timeouts.
const TEST_EPOCH_MS: u64 = 2000;

/// Committee validators on the one shard — also the cohort size the
/// admission draws, so `pool_extra_validators` matches it exactly.
const PER_SHARD: u32 = 4;

/// Epochs the standing trigger gets to fold and the admission to draw.
const ADMISSION_BUDGET_EPOCHS: u64 = 8;

/// Epochs the folded `ReshapeReady` signals get to fire the gate —
/// well inside `RESHAPE_READY_TTL_EPOCHS`, so the reshape executes
/// rather than abandons.
const GATE_BUDGET_EPOCHS: u64 = 8;

/// The single-shard, paced-epoch network with the split trigger armed
/// from genesis (`split_substates: 0` — every committed count
/// satisfies the predicate) and exactly one cohort's worth of pooled
/// extras.
fn grow_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: PER_SHARD,
        intra_shard_latency: Duration::from_millis(50),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            num_shards: 1,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds { split_substates: 0 },
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: PER_SHARD,
        ..Default::default()
    }
}

/// Host 0's latest committed beacon state.
fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The pending split's cohort as `(observer, assigned child)` pairs,
/// once admitted.
fn pending_cohort(runner: &SimulationRunner) -> Option<Vec<(ValidatorId, ShardId)>> {
    let state = beacon_state(runner)?;
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&ShardId::ROOT)
    else {
        return None;
    };
    Some(
        cohort
            .iter()
            .map(|(validator, seat)| (*validator, seat.child))
            .collect(),
    )
}

/// Run in one-second slices until `predicate` holds or `deadline`
/// passes.
fn run_until(
    runner: &mut SimulationRunner,
    deadline: Duration,
    mut predicate: impl FnMut(&SimulationRunner) -> bool,
) -> bool {
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if predicate(runner) {
            return true;
        }
    }
    false
}

const fn epochs(n: u64) -> Duration {
    Duration::from_millis(TEST_EPOCH_MS * n)
}

#[traced_test]
#[test]
fn observers_grow_a_split_through_its_readiness_gate() {
    let mut runner = SimulationRunner::new(&grow_config(), 11);
    runner.initialize_genesis();
    // A handful of committed substates so the child spans the
    // observers sync carry real state, not just empty trees.
    for i in 0..6u8 {
        runner.schedule_initial_event(
            0,
            Duration::from_millis(50 + u64::from(i)),
            ShardEvent::process(ProcessScopedInput::SubmitTransaction {
                tx: Arc::new(test_transaction(i)),
            }),
        );
    }

    // ── Admission: the standing trigger folds and draws the cohort ──
    let admitted = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_cohort(r).is_some_and(|c| c.len() == PER_SHARD as usize)
    });
    assert!(
        admitted,
        "the armed trigger must fold and draw a full cohort within \
         {ADMISSION_BUDGET_EPOCHS} epochs",
    );
    let cohort = pending_cohort(&runner).expect("cohort just observed");
    let (left, right) = ShardId::ROOT.children();
    for child in [left, right] {
        assert_eq!(
            cohort.iter().filter(|(_, c)| *c == child).count(),
            2,
            "the cohort halves must split evenly; got {cohort:?}",
        );
    }

    // ── Observer duty: sync each child span, signal ready ──
    let mut synced: Vec<(ValidatorId, ShardId, StateRoot)> = Vec::new();
    for (validator, child) in &cohort {
        let (store, root) = runner.observe_child(*validator, ShardId::ROOT, *child);
        assert_eq!(
            store.state_root(),
            root,
            "the child-rooted store must hold exactly the imported subtree",
        );
        synced.push((*validator, *child, root));
    }
    // Same child, same anchor: the two observers of each half must have
    // assembled byte-identical subtrees.
    for child in [left, right] {
        let roots: Vec<StateRoot> = synced
            .iter()
            .filter(|(_, c, _)| *c == child)
            .map(|(_, _, root)| *root)
            .collect();
        assert_eq!(roots.len(), 2);
        assert_eq!(
            roots[0], roots[1],
            "co-observers of {child:?} synced against one anchor must agree",
        );
    }

    // ── The gate fires: the trie reshapes into the lookahead ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let reshaped = run_until(&mut runner, gate_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            s.pending_reshapes.is_empty() && s.next_shard_committees.contains_key(&left)
        })
    });
    assert!(
        reshaped,
        "the folded ReshapeReady signals must fire the gate within \
         {GATE_BUDGET_EPOCHS} epochs",
    );

    let state = beacon_state(&runner).expect("post-gate state");
    assert!(
        !state.next_shard_committees.contains_key(&ShardId::ROOT),
        "the lookahead must carry the children, not the parent",
    );
    for child in [left, right] {
        assert_eq!(
            state.next_shard_committees[&child].members.len(),
            PER_SHARD as usize,
            "each child must start at full committee strength",
        );
    }
    // Every observer landed on its assigned child — placed by the
    // execution, ready via its folded signal or the normal path after.
    for (validator, child, _) in &synced {
        let status = state.validators[validator].status;
        assert!(
            matches!(status, ValidatorStatus::OnShard { shard, .. } if shard == *child),
            "observer {validator:?} must land on {child:?}; got {status:?}",
        );
    }
    // The parent membership partitioned across the children: every
    // original member sits on exactly one child.
    for member in 0..u64::from(PER_SHARD) {
        let status = state.validators[&ValidatorId::new(member)].status;
        assert!(
            matches!(status, ValidatorStatus::OnShard { shard, .. }
                if shard.parent() == Some(ShardId::ROOT)),
            "parent member {member} must land on a child; got {status:?}",
        );
    }
}
