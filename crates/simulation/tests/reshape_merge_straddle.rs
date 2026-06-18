//! Cross-shard atomicity across a merge — rebuilt from the property up.
//!
//! The subject under test is one invariant: when a shard merges away, a
//! cross-shard wave naming it resolves atomically on its surviving
//! counterpart — finalized iff the merging shard settled it by its terminal
//! block, aborted otherwise, never one-sided, never wedged.
//!
//! Everything else (admission, the readiness gate, the beacon's parent
//! composition, the keeper flip) is *machinery* that gets the merging shard
//! to its terminal. This test drives that machinery as plainly as it can and
//! asserts nothing about it beyond "the merging shard reached its terminal";
//! the keeper flip — leaf(1,1) coming alive — is a separate concern and is
//! deliberately not exercised here, since the survivor's resolution depends
//! only on the terminated child's attested `settled_waves_root`.
//!
//! Topology: `leaf(2,2)`/`leaf(2,3)` merge into `leaf(1,1)`; `leaf(2,0)` keeps
//! `leaf(1,0)` alive as the surviving counterpart. Cross-shard transfers run
//! from the survivor `leaf(2,0)` into the merging `leaf(2,2)`, so each wave
//! names a shard that terminates at the merge. The flow records a timestamped
//! timeline; every assertion prints it, so a failure shows the chronology.
//!
//! Ignored pending network-param governance: a grown (coherent) topology can't
//! reach `merge_threshold` without governance lowering the reshape trigger
//! after the grow, so it runs on a `num_shards` genesis — where each shard gets
//! its own bootstrap with colliding vault `NodeId`s, and the settling waves
//! reject rather than accept. The atomicity property holds either way; only the
//! accept path waits on a coherent topology that can also merge.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_node::shard_loop::{ProcessScopedInput, ShardEvent};
use hyperscale_simulation::{EPOCH_MS, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, Ed25519PrivateKey, KeeperSeat, NodeId,
    PendingReshape, ReshapeThresholds, RoutableTransaction, ShardId, TimestampRange,
    TransactionDecision, TransactionStatus, TxHash, ValidatorId, ValidatorStatus,
    WeightedTimestamp, ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
    uniform_shard_for_node,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;

const PER_SHARD: u32 = 4;

/// `merge_threshold = split_bytes / 8 = 420_000`. The cold genesis byte
/// totals leave only the `leaf(1,1)` pair under threshold, so it alone merges
/// while `leaf(2,0)` keeps `leaf(1,0)` alive as the surviving counterpart.
const SPLIT_BYTES: u64 = 3_360_000;

/// Offsets *before the merge cut* for the settling waves: far enough ahead
/// that the cross-shard 2PC finalizes on `leaf(2,2)` before its terminal, and
/// inside `RETENTION_HORIZON` of that terminal so the attested
/// `settled_waves_root` still commits the wave.
const SETTLE_OFFSETS_MS: [u64; 2] = [80_000, 60_000];

/// Offsets before the cut for the straddling waves: too close to the terminal
/// for the 2PC to finalize, so they commit on `leaf(2,2)` but never settle —
/// the survivor must counterpart-abort them.
const STRADDLE_OFFSETS_MS: [u64; 3] = [700, 400, 200];

const ADMISSION_BUDGET_EPOCHS: u64 = 5;
const GATE_BUDGET_EPOCHS: u64 = 5;
const TERMINAL_BUDGET_EPOCHS: u64 = 5;
const RESOLVE_BUDGET_EPOCHS: u64 = 6;

fn merge_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 4,
        validators_per_shard: PER_SHARD,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: 4,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds {
                split_bytes: SPLIT_BYTES,
            },
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: 0,
        ..Default::default()
    }
}

fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The pending merge's keepers as `(validator, the child it runs)` pairs.
fn pending_keepers(
    runner: &SimulationRunner,
    parent: ShardId,
) -> Option<Vec<(ValidatorId, ShardId)>> {
    let state = beacon_state(runner)?;
    let Some(PendingReshape::Merge {
        keepers,
        admitted_at: Some(_),
        ..
    }) = state.pending_reshapes.get(&parent)
    else {
        return None;
    };
    Some(
        keepers
            .iter()
            .map(|(validator, seat): (&ValidatorId, &KeeperSeat)| (*validator, seat.child))
            .collect(),
    )
}

/// A fresh keypair whose preallocated account routes to `shard`.
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

/// A validator currently seated on `shard`, per the committed beacon state.
fn member_of(runner: &SimulationRunner, shard: ShardId) -> ValidatorId {
    beacon_state(runner)
        .expect("beacon state")
        .validators
        .iter()
        .find_map(|(id, record)| match record.status {
            ValidatorStatus::OnShard { shard: seated, .. } if seated == shard => Some(*id),
            _ => None,
        })
        .expect("shard has a seated member")
}

/// A payer-to-recipient XRD transfer, with a validity window bracketing
/// `anchor` — the approximate weighted time it commits at.
fn transfer(
    payer_key: &Ed25519PrivateKey,
    payer: ComponentAddress,
    recipient: ComponentAddress,
    anchor: Duration,
) -> Arc<RoutableTransaction> {
    let manifest = ManifestBuilder::new()
        .lock_fee(payer, Decimal::from(10))
        .withdraw_from_account(payer, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(recipient, None)
        .build();
    let notarized =
        sign_and_notarize(manifest, &NetworkDefinition::simulator(), 1, payer_key).expect("signs");
    let validity = TimestampRange::new(
        WeightedTimestamp::ZERO.plus(anchor.saturating_sub(Duration::from_secs(5))),
        WeightedTimestamp::ZERO.plus(anchor + Duration::from_secs(150)),
    );
    Arc::new(routable_from_notarized_v1(notarized, validity).expect("routable"))
}

/// Walk a committed chain from height 1 to its tip: the heights at which
/// `hash` committed (rides `transactions`) and finalized (rides a
/// `FinalizedWave` certificate).
fn scan_chain(
    storage: &SimShardStorage,
    hash: TxHash,
) -> (Option<BlockHeight>, Option<BlockHeight>) {
    let mut committed = None;
    let mut finalized = None;
    let tip = storage.committed_height();
    let mut height = BlockHeight::new(1);
    while height <= tip {
        if let Some(certified) = storage.get_block(height) {
            let block = certified.block();
            if block.transactions().iter().any(|tx| tx.hash() == hash) {
                committed = Some(height);
            }
            if block
                .certificates()
                .iter()
                .any(|fw| fw.tx_hashes().any(|t| t == hash))
            {
                finalized = Some(height);
            }
        }
        height = height.next();
    }
    (committed, finalized)
}

const fn epochs(n: u64) -> Duration {
    Duration::from_millis(EPOCH_MS * n)
}

/// Run in one-second slices until `predicate` holds or `deadline` passes.
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

/// A timestamped phase log; printed by every assertion so a failure shows the
/// real chronology.
#[derive(Default)]
struct Timeline(String);

impl Timeline {
    fn mark(&mut self, now: Duration, event: &str) {
        let _ = writeln!(self.0, "  t={:>5}s  {event}", now.as_secs());
    }
}

// Waiting for network-param governance: the straddler waves need a coherent
// multi-shard topology (so cross-shard transfers accept rather than reject on
// the multi-shard-genesis vault collision), which only `grow_to` produces —
// but a grown leaf can't reach `merge_threshold` without governance lowering
// the reshape trigger after the grow. Until then this runs on a `num_shards`
// genesis, where the settling waves reject instead of accept, so `settled`
// stays zero. The property under test (settled ⇒ applied, unsettled ⇒ aborted,
// never one-sided) already holds; only the accept path is blocked.
#[ignore = "needs network-param governance to merge a grown topology"]
#[test]
#[allow(clippy::too_many_lines)] // one lifecycle asserted end to end
fn cross_shard_waves_resolve_atomically_across_a_merge() {
    let survivor = ShardId::leaf(2, 0);
    let merge_parent = ShardId::leaf(1, 1);
    let (merging, sibling) = merge_parent.children(); // leaf(2,2), leaf(2,3)

    let mut runner = SimulationRunner::new(&merge_config(), 7);
    let mut tl = Timeline::default();

    // Straddler accounts: payer in the survivor, recipient in the merging
    // shard. The transactions are submitted later, anchored to the cut.
    let mut taken = Vec::new();
    let mut balances = Vec::new();
    let waves: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)> = (0
        ..SETTLE_OFFSETS_MS.len() + STRADDLE_OFFSETS_MS.len())
        .map(|_| {
            let (payer_key, payer) = account_in(survivor, 4, &mut taken);
            let (_, recipient) = account_in(merging, 4, &mut taken);
            (payer_key, payer, recipient)
        })
        .collect();
    for (_, payer, recipient) in &waves {
        balances.push((*payer, Decimal::from(10_000)));
        balances.push((*recipient, Decimal::from(10_000)));
    }
    runner.initialize_genesis_with_balances(&balances);
    tl.mark(runner.now(), "genesis");

    // ── Machinery: admission ──
    let paired = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_keepers(r, merge_parent).is_some_and(|k| k.len() == PER_SHARD as usize)
    });
    assert!(
        paired,
        "the leaf(1,1) pair must pair a full keeper set\n{}",
        tl.0
    );
    let mut keepers = pending_keepers(&runner, merge_parent).expect("keepers paired");
    tl.mark(runner.now(), "keepers paired");

    // ── Machinery: keeper sibling-sync, then drive the readiness gate ──
    for (validator, own_child) in &keepers {
        let other = if *own_child == merging {
            sibling
        } else {
            merging
        };
        runner.merge_keeper(*validator, *own_child, other);
    }
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let mut reshaped = false;
    while runner.now() < gate_deadline {
        if let Some(current) = pending_keepers(&runner, merge_parent) {
            keepers = current;
            for (validator, own_child) in &keepers {
                runner.broadcast_keeper_ready(*validator, *own_child);
            }
        }
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if beacon_state(&runner).is_some_and(|s| {
            !s.pending_reshapes.contains_key(&merge_parent)
                && s.next_shard_committees.contains_key(&merge_parent)
        }) {
            reshaped = true;
            break;
        }
    }
    assert!(reshaped, "the readiness gate must fire the merge\n{}", tl.0);
    let final_epoch = beacon_state(&runner).expect("state").current_epoch;
    let cut = Duration::from_millis((final_epoch.inner() + 1) * EPOCH_MS);
    tl.mark(
        runner.now(),
        &format!("merge executed; cut at t={}s", cut.as_secs()),
    );

    // ── The waves, cut-anchored ──
    let mut probes: Vec<(u64, TxHash)> = Vec::new();
    for (offset_ms, pair) in SETTLE_OFFSETS_MS
        .iter()
        .chain(STRADDLE_OFFSETS_MS.iter())
        .zip(&waves)
    {
        let (payer_key, payer, recipient) = pair;
        let target = cut.saturating_sub(Duration::from_millis(*offset_ms));
        let tx = transfer(payer_key, *payer, *recipient, target);
        let hash = tx.hash();
        let delay = target
            .saturating_sub(runner.now())
            .max(Duration::from_millis(10));
        runner.schedule_initial_event(
            0,
            delay,
            ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
        probes.push((*offset_ms, hash));
    }
    tl.mark(runner.now(), &format!("{} waves submitted", probes.len()));

    // ── Machinery: leaf(2,2) terminates and its terminal folds (the beacon
    // attests its settled_waves_root) ──
    let terminal_deadline = runner.now() + epochs(TERMINAL_BUDGET_EPOCHS);
    let folded = run_until(&mut runner, terminal_deadline, |r| {
        beacon_state(r)
            .and_then(|s| {
                s.boundaries
                    .get(&merging)
                    .map(|b| b.settled_waves_root.is_some())
            })
            .unwrap_or(false)
    });
    if let Some(s) = beacon_state(&runner) {
        if let Some(b) = s.boundaries.get(&merging) {
            tl.mark(
                runner.now(),
                &format!(
                    "leaf(2,2) boundary: terminal_epoch={:?} settled_waves_root={} height={:?}",
                    b.terminal_epoch,
                    b.settled_waves_root.is_some(),
                    b.height,
                ),
            );
        } else {
            tl.mark(runner.now(), "leaf(2,2) boundary record absent");
        }
    }
    assert!(
        folded,
        "leaf(2,2)'s terminal must fold and attest a settled_waves_root\n{}",
        tl.0,
    );

    // ── The subject: the survivor reconstructs S_{leaf(2,2)} and resolves
    // every wave to a terminal decision ──
    let survivor_validator = member_of(&runner, survivor);
    let survivor_host = runner.network().validator_to_node(survivor_validator);
    let reconstructed_waves = |r: &SimulationRunner| {
        r.vnode_state(survivor_validator).and_then(|n| {
            n.shard_coordinator()
                .settled_set(merging)
                .map(|s| s.waves.len())
        })
    };
    let resolve_deadline = runner.now() + epochs(RESOLVE_BUDGET_EPOCHS);
    let resolved = run_until(&mut runner, resolve_deadline, |r| {
        reconstructed_waves(r).is_some_and(|n| n > 0)
            && probes.iter().all(|(_, hash)| {
                matches!(
                    r.tx_status(survivor_host, hash),
                    Some(TransactionStatus::Completed(_))
                )
            })
    });
    tl.mark(
        runner.now(),
        &format!(
            "survivor settled_set(leaf(2,2)) = {:?} waves",
            reconstructed_waves(&runner)
        ),
    );

    // ── Property: scan each wave's fate on both chains ──
    let merging_store = store_for(&runner, merging).expect("leaf(2,2) still served");
    let survivor_store = store_for(&runner, survivor).expect("survivor served");
    let terminal_height = beacon_state(&runner)
        .and_then(|s| s.boundaries.get(&merging).map(|b| b.height))
        .expect("leaf(2,2) terminal height");

    let mut settled = 0u32;
    let mut straddled = 0u32;
    let mut one_sided = 0u32;
    for (offset, hash) in &probes {
        let (m_committed, m_finalized) = scan_chain(merging_store, *hash);
        let (v_committed, v_finalized) = scan_chain(survivor_store, *hash);
        let settled_on_merging = m_finalized.is_some_and(|h| h <= terminal_height);
        let status = runner.tx_status(survivor_host, hash);
        let accepted = matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        );
        tl.mark(
            runner.now(),
            &format!(
                "wave cut-{offset}ms: leaf(2,2) committed={:?} finalized={:?} settled={settled_on_merging}; \
                 survivor committed={:?} finalized={:?} status={status:?}",
                m_committed.map(BlockHeight::inner),
                m_finalized.map(BlockHeight::inner),
                v_committed.map(BlockHeight::inner),
                v_finalized.map(BlockHeight::inner),
            ),
        );
        if settled_on_merging && accepted {
            settled += 1;
        }
        if m_committed.is_some() && !settled_on_merging {
            straddled += 1;
        }
        if accepted && !settled_on_merging {
            one_sided += 1;
        }
    }

    assert!(
        resolved,
        "every wave must resolve to a terminal decision\n{}",
        tl.0
    );
    assert_eq!(
        one_sided, 0,
        "the survivor accepted a wave leaf(2,2) never settled — one-sided application\n{}",
        tl.0,
    );
    assert!(
        settled > 0,
        "no wave settled cross-shard before the terminal\n{}",
        tl.0
    );
    assert!(
        straddled > 0,
        "no wave straddled the terminal unsettled\n{}",
        tl.0
    );
    for (offset, hash) in &probes {
        let settled_on_merging = scan_chain(merging_store, *hash)
            .1
            .is_some_and(|h| h <= terminal_height);
        if settled_on_merging {
            assert!(
                !matches!(
                    runner.tx_status(survivor_host, hash),
                    Some(TransactionStatus::Completed(TransactionDecision::Aborted))
                ),
                "wave cut-{offset}ms settled on leaf(2,2) yet aborted on the survivor\n{}",
                tl.0,
            );
        }
    }
}
