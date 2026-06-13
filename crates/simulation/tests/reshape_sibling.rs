//! A surviving sibling reconstructs a split shard's settled set.
//!
//! Two genesis shards, `leaf(1,0)` and `leaf(1,1)`. `leaf(1,1)` is funded
//! past the split threshold and splits into `leaf(2,2)`/`leaf(2,3)` while
//! `leaf(1,0)` stays under it and keeps running — the surviving-sibling
//! shape the split-boundary fence needs and that `reshape_straddle`
//! (a single ROOT split, both children fresh) cannot produce.
//!
//! This file builds the lifecycle first: the trigger fires for `leaf(1,1)`
//! alone, its observers grow the split through the readiness gate, the
//! children seed from its terminal contribution with subtree-root
//! continuity, and `leaf(1,0)` commits throughout. The straddler and the
//! fence assertions build on top.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, Ed25519PrivateKey, NodeId, PendingReshape,
    ReshapeThresholds, ShardAnchor, ShardId, SplitChildRoots, StateRoot, ValidatorId,
    ValidatorStatus, ed25519_keypair_from_seed, uniform_shard_for_node,
};
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;
use tracing_test::traced_test;

const TEST_EPOCH_MS: u64 = 2000;
const PER_SHARD: u32 = 4;

/// `leaf(1,1)`'s genesis count (~453 with 20 accounts) sits above this;
/// `leaf(1,0)`'s (~293 with 2 accounts) sits below — so the trigger fires
/// for `leaf(1,1)` alone. A cross-shard transfer moves no substates, so
/// `leaf(1,0)` stays under the threshold throughout.
const SPLIT_SUBSTATES: u64 = 380;

/// Bulk accounts funded into `leaf(1,1)` to carry it past the threshold.
const RIGHT_BULK: usize = 20;

const ADMISSION_BUDGET_EPOCHS: u64 = 8;
const GATE_BUDGET_EPOCHS: u64 = 8;
const SEED_BUDGET_EPOCHS: u64 = 6;
const CHILD_RUN_BUDGET_EPOCHS: u64 = 4;

fn sibling_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: PER_SHARD,
        intra_shard_latency: Duration::from_millis(50),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            num_shards: 2,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds {
                split_substates: SPLIT_SUBSTATES,
            },
            ..BeaconChainConfig::default()
        }),
        // One cohort's worth of pooled extras to staff leaf(1,1)'s split.
        pool_extra_validators: PER_SHARD,
        ..Default::default()
    }
}

fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The pending split's cohort for `parent` as `(observer, assigned child)`.
fn pending_cohort_for(
    runner: &SimulationRunner,
    parent: ShardId,
) -> Option<Vec<(ValidatorId, ShardId)>> {
    let state = beacon_state(runner)?;
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&parent) else {
        return None;
    };
    Some(
        cohort
            .iter()
            .map(|(validator, seat)| (*validator, seat.child))
            .collect(),
    )
}

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

/// A fresh keypair whose preallocated account routes to `shard` under a
/// `num_shards`-wide uniform trie — the same routing genesis uses.
fn account_in(
    shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, ComponentAddress) {
    for seed in 1u8..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let key = ed25519_keypair_from_seed(&[seed; 32]);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId(
            address.into_node_id().0[..30]
                .try_into()
                .expect("account address carries a 30-byte node id"),
        );
        if uniform_shard_for_node(&node, num_shards) == shard {
            taken.push(seed);
            return (key, address);
        }
    }
    panic!("no account seed routes to {shard:?}");
}

fn store_for(runner: &SimulationRunner, shard: ShardId) -> Option<&SimShardStorage> {
    (0..runner.num_hosts()).find_map(|node| runner.hosts_shard(node, shard))
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one surviving-sibling split lifecycle
fn sibling_survives_a_split_with_subtree_continuity() {
    let mut runner = SimulationRunner::new(&sibling_config(), 11);
    let survivor = ShardId::leaf(1, 0);
    let splitter = ShardId::leaf(1, 1);
    let (left_child, right_child) = splitter.children();

    // Fund leaf(1,1) past the threshold; keep leaf(1,0) lightly funded.
    let mut taken = Vec::new();
    let mut balances = Vec::new();
    for _ in 0..RIGHT_BULK {
        let (_, a) = account_in(splitter, 2, &mut taken);
        balances.push((a, Decimal::from(10_000)));
    }
    for _ in 0..2 {
        let (_, a) = account_in(survivor, 2, &mut taken);
        balances.push((a, Decimal::from(10_000)));
    }
    runner.initialize_genesis_with_balances(&balances);

    // ── Admission: leaf(1,1) folds its trigger and draws a cohort; the
    // under-threshold leaf(1,0) folds none ──
    let admitted = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_cohort_for(r, splitter).is_some_and(|c| c.len() == PER_SHARD as usize)
    });
    assert!(
        admitted,
        "leaf(1,1)'s trigger must fold and draw a full cohort"
    );
    assert!(
        pending_cohort_for(&runner, survivor).is_none(),
        "the under-threshold survivor must not split",
    );
    let cohort = pending_cohort_for(&runner, splitter).expect("cohort just observed");
    for child in [left_child, right_child] {
        assert_eq!(
            cohort.iter().filter(|(_, c)| *c == child).count(),
            2,
            "the cohort halves must split evenly; got {cohort:?}",
        );
    }

    // ── Observer duty: each cohort member syncs its child span ──
    let mut synced_stores: Vec<(
        ValidatorId,
        ShardId,
        SimShardStorage,
        ShardAnchor,
        StateRoot,
    )> = Vec::new();
    for (validator, child) in &cohort {
        let (store, root, anchor) = runner.observe_child(*validator, splitter, *child);
        synced_stores.push((*validator, *child, store, anchor, root));
    }

    // ── The gate fires: leaf(1,1) reshapes into the lookahead; leaf(1,0)
    // keeps its committee ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let reshaped = run_until(&mut runner, gate_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            s.pending_reshapes.is_empty() && s.next_shard_committees.contains_key(&left_child)
        })
    });
    assert!(
        reshaped,
        "leaf(1,1)'s ReshapeReady signals must fire the gate"
    );
    let state = beacon_state(&runner).expect("post-gate state");
    assert!(
        state.next_shard_committees.contains_key(&survivor)
            || state.shard_committees.contains_key(&survivor),
        "the survivor must keep its committee across leaf(1,1)'s split",
    );
    assert!(
        !state.next_shard_committees.contains_key(&splitter),
        "the lookahead must carry leaf(1,1)'s children, not leaf(1,1)",
    );
    let final_epoch = state.current_epoch;
    let _cut = Duration::from_millis((final_epoch.inner() + 1) * TEST_EPOCH_MS);
    // The parent halves are leaf(1,1)'s original members landing on a
    // child — excluding the synced cohort (the pooled extras), which the
    // observer flips handle separately.
    let cohort_validators: Vec<ValidatorId> = cohort.iter().map(|(v, _)| *v).collect();
    let parent_halves: Vec<(ValidatorId, ShardId)> = state
        .validators
        .iter()
        .filter_map(|(id, record)| match record.status {
            ValidatorStatus::OnShard { shard, .. }
                if shard.parent() == Some(splitter) && !cohort_validators.contains(id) =>
            {
                Some((*id, shard))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        parent_halves.len(),
        PER_SHARD as usize,
        "leaf(1,1)'s original members must each land on a child; got {parent_halves:?}",
    );

    // ── Through the boundary: leaf(1,1) coasts to its crossing and the
    // fold seeds both children from its terminal contribution ──
    let seed_deadline = runner.now() + epochs(SEED_BUDGET_EPOCHS);
    let seeded = run_until(&mut runner, seed_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            [left_child, right_child].iter().all(|c| {
                s.boundaries
                    .get(c)
                    .is_some_and(|b| b.block_hash != BlockHash::ZERO)
            })
        })
    });
    assert!(seeded, "the fold must seed both children from the terminal");
    let state = beacon_state(&runner).expect("post-seed state");
    let genesis_height = state.boundaries[&left_child].height;

    // Subtree-root continuity: the children's anchors compose to the
    // parent's terminal root.
    let parent_terminal_root = store_for(&runner, splitter)
        .expect("a host still carries leaf(1,1)")
        .state_root();
    let pair = SplitChildRoots {
        left: state.boundaries[&left_child].state_root,
        right: state.boundaries[&right_child].state_root,
    };
    assert!(
        pair.composes_to(parent_terminal_root),
        "the children's anchors must compose to leaf(1,1)'s terminal root",
    );

    // ── Follow + flip: observers reach the crossing, parent halves adopt,
    // observers reopen on a sibling-flipped host ──
    for (_, child, store, anchor, imported_root) in &synced_stores {
        let followed = runner.follow_child(store, splitter, *child, *anchor, *imported_root);
        assert_eq!(
            followed, state.boundaries[child].state_root,
            "a followed store must arrive at the beacon-seeded child anchor",
        );
    }
    for (validator, child) in &parent_halves {
        let node = u32::try_from(validator.inner()).expect("host per parent member");
        runner.flip_split_child(node, *validator, splitter, *child, None);
    }
    let observer_seats: Vec<(ValidatorId, ShardId)> =
        synced_stores.iter().map(|(v, c, ..)| (*v, *c)).collect();
    let mut sibling_hosts: Vec<u32> = Vec::new();
    for (validator, child) in &observer_seats {
        let (node, _) = parent_halves
            .iter()
            .map(|(v, c)| (u32::try_from(v.inner()).expect("host index"), *c))
            .find(|(node, host_child)| host_child != child && !sibling_hosts.contains(node))
            .expect("a free host whose own vnode flipped to the sibling");
        sibling_hosts.push(node);
        let store = synced_stores
            .iter()
            .position(|(v, ..)| v == validator)
            .map(|i| synced_stores.swap_remove(i).2)
            .expect("every observer synced a store");
        runner.flip_split_child(node, *validator, splitter, *child, Some(store));
    }

    // ── Both children run past genesis, and the survivor keeps committing ──
    let survivor_base = store_for(&runner, survivor)
        .expect("survivor store")
        .committed_height();
    let run_deadline = runner.now() + epochs(CHILD_RUN_BUDGET_EPOCHS);
    let progressed = run_until(&mut runner, run_deadline, |r| {
        let children_live = [left_child, right_child].iter().all(|child| {
            (0..r.num_hosts()).any(|node| {
                r.hosts_shard(node, *child)
                    .is_some_and(|s| s.committed_height() > genesis_height)
            })
        });
        let survivor_live =
            store_for(r, survivor).is_some_and(|s| s.committed_height() > survivor_base);
        children_live && survivor_live
    });
    if !progressed {
        let mut detail = String::new();
        for shard in [survivor, left_child, right_child] {
            for node in 0..runner.num_hosts() {
                if let Some(s) = runner.hosts_shard(node, shard) {
                    let _ = write!(
                        detail,
                        "\n  node {node} {shard:?}: committed {:?}",
                        s.committed_height(),
                    );
                }
            }
        }
        panic!(
            "children must commit past genesis (h{}) and the survivor past h{} \
             within {CHILD_RUN_BUDGET_EPOCHS} epochs:{detail}",
            genesis_height.inner(),
            survivor_base.inner(),
        );
    }
}
