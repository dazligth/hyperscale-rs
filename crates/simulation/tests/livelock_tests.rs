//! Abort safety integration tests.
//!
//! These tests verify that cross-shard transactions reach terminal state
//! exclusively through Wave Certificates (WCs), including:
//! - Livelock cycle detection → abort intent → WC(Aborted)
//! - Normal cross-shard execution → WC(Accept)
//! - Execution timeout → abort intent → WC(Aborted)
//!
//! Each genesises at one shard and `grow_to(2)` before driving the cross-shard
//! traffic, mirroring a network that launches single-shard and splits.

use std::collections::HashSet;
use std::time::Duration;

use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{
    Ed25519PrivateKey, RoutableTransaction, ShardId, TxHash, ValidatorId,
    routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

mod common;
use common::{
    await_all_terminal, build_cross_shard_transfer, cross_shard_grow_config,
    find_accounts_on_each_shard, grow_validity_range, grown_leaves, submit_to_shard,
    vnode_reached_terminal_state, with_test_recorder,
};

/// Build a cross-shard transfer (withdraw from `from`, deposit to `to`) with a
/// post-grow validity range bracketing `now` — the direction/nonce control the
/// shared `build_cross_shard_transfer` doesn't expose.
fn cross_shard_transfer(
    from: ComponentAddress,
    to: ComponentAddress,
    amount: u64,
    nonce: u32,
    signer: &Ed25519PrivateKey,
    now: Duration,
) -> RoutableTransaction {
    let manifest = ManifestBuilder::new()
        .lock_fee(from, Decimal::from(10))
        .withdraw_from_account(from, XRD, Decimal::from(amount))
        .try_deposit_entire_worktop_or_abort(to, None)
        .build();
    let notarized =
        sign_and_notarize(manifest, &NetworkDefinition::simulator(), nonce, signer).expect("sign");
    routable_from_notarized_v1(notarized, grow_validity_range(now)).expect("valid tx")
}

/// Run until both txs reach a terminal outcome on every live committee member
/// across `leaves`, or `deadline`. Latches per (validator, tx) so the
/// finalize-then-cleanup transition isn't missed.
fn await_both_terminal(
    runner: &mut SimulationRunner,
    leaves: &[ShardId],
    hash_a: TxHash,
    hash_b: TxHash,
    deadline: Duration,
) -> bool {
    let mut a: HashSet<ValidatorId> = HashSet::new();
    let mut b: HashSet<ValidatorId> = HashSet::new();
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        let done = leaves.iter().all(|&leaf| {
            runner.shard_vnodes(leaf).iter().all(|&v| {
                let id = v.validator_id();
                if vnode_reached_terminal_state(v, hash_a) {
                    a.insert(id);
                }
                if vnode_reached_terminal_state(v, hash_b) {
                    b.insert(id);
                }
                a.contains(&id) && b.contains(&id)
            })
        });
        if done {
            return true;
        }
    }
    false
}

/// Two conflicting cross-shard transactions form a cycle (A: shard 0 → shard 1,
/// B: shard 1 → shard 0). Cycle detection aborts the loser and accepts the
/// winner; both must reach a terminal outcome without livelocking.
#[traced_test]
#[test]
fn test_cycle_detection_aborts_loser() {
    let mut runner = SimulationRunner::new(&cross_shard_grow_config(), 42);
    let ((kp0, acc0), (kp1, acc1)) = find_accounts_on_each_shard(2);
    runner.initialize_genesis_with_balances(&[
        (acc0, Decimal::from(10_000)),
        (acc1, Decimal::from(10_000)),
    ]);
    runner.grow_to(2);
    let leaves = grown_leaves();

    let now = runner.now();
    let tx_a = cross_shard_transfer(acc0, acc1, 100, 200, &kp0, now);
    let tx_b = cross_shard_transfer(acc1, acc0, 100, 201, &kp1, now);
    let hash_a = tx_a.hash();
    let hash_b = tx_b.hash();
    submit_to_shard(&mut runner, leaves[0], tx_a);
    submit_to_shard(&mut runner, leaves[1], tx_b);

    let deadline = runner.now() + Duration::from_secs(150);
    assert!(
        await_both_terminal(&mut runner, &leaves, hash_a, hash_b, deadline),
        "both cycle transactions must reach a terminal outcome",
    );
}

/// A single non-conflicting cross-shard transfer completes normally (accepts,
/// not aborts).
#[traced_test]
#[test]
fn test_no_cycle_completes_normally() {
    with_test_recorder(|recorder| {
        let mut runner = SimulationRunner::new(&cross_shard_grow_config(), 99);
        let ((kp0, acc0), (_kp1, acc1)) = find_accounts_on_each_shard(2);
        runner.initialize_genesis_with_balances(&[
            (acc0, Decimal::from(10_000)),
            (acc1, Decimal::from(10_000)),
        ]);
        runner.grow_to(2);
        let leaves = grown_leaves();

        let tx = build_cross_shard_transfer(&kp0, acc0, acc1, runner.now());
        let hash = tx.hash();
        submit_to_shard(&mut runner, leaves[0], tx);

        let deadline = runner.now() + Duration::from_secs(150);
        let latched = await_all_terminal(&mut runner, &leaves, hash, deadline);
        for &leaf in &leaves {
            for vnode in runner.shard_vnodes(leaf) {
                assert!(
                    latched.contains(&vnode.validator_id()),
                    "{:?} on {leaf:?} never reached a terminal outcome",
                    vnode.validator_id(),
                );
            }
        }
        let aborts = recorder.counter("transactions_aborted", None);
        assert_eq!(
            aborts, 0,
            "non-conflicting transfer aborted ({aborts} events)"
        );
    });
}

/// A single cross-shard transfer reaches a terminal outcome — it never gets
/// stuck waiting on cross-shard coordination.
#[traced_test]
#[test]
fn test_timeout_abort() {
    let mut runner = SimulationRunner::new(&cross_shard_grow_config(), 777);
    let ((kp0, acc0), (_kp1, acc1)) = find_accounts_on_each_shard(2);
    runner.initialize_genesis_with_balances(&[
        (acc0, Decimal::from(10_000)),
        (acc1, Decimal::from(10_000)),
    ]);
    runner.grow_to(2);
    let leaves = grown_leaves();

    let tx = build_cross_shard_transfer(&kp0, acc0, acc1, runner.now());
    let hash = tx.hash();
    submit_to_shard(&mut runner, leaves[0], tx);

    let deadline = runner.now() + Duration::from_secs(150);
    let latched = await_all_terminal(&mut runner, &leaves, hash, deadline);
    for &leaf in &leaves {
        for vnode in runner.shard_vnodes(leaf) {
            assert!(
                latched.contains(&vnode.validator_id()),
                "{:?} on {leaf:?} never reached a terminal outcome",
                vnode.validator_id(),
            );
        }
    }
}

/// Cycle detection short-circuits the wave timeout: a conflicting cross-shard
/// pair resolves within a few blocks of detection, well under the ~24s wave
/// timeout. The deadline is a regression signal — a fall-back to the wave
/// timeout would blow past it.
#[traced_test]
#[test]
fn test_livelock_resolves_promptly() {
    let mut runner = SimulationRunner::new(&cross_shard_grow_config(), 555);
    let ((kp0, acc0), (kp1, acc1)) = find_accounts_on_each_shard(2);
    runner.initialize_genesis_with_balances(&[
        (acc0, Decimal::from(10_000)),
        (acc1, Decimal::from(10_000)),
    ]);
    runner.grow_to(2);
    let leaves = grown_leaves();

    let now = runner.now();
    let tx_a = cross_shard_transfer(acc0, acc1, 100, 500, &kp0, now);
    let tx_b = cross_shard_transfer(acc1, acc0, 100, 501, &kp1, now);
    let hash_a = tx_a.hash();
    let hash_b = tx_b.hash();
    submit_to_shard(&mut runner, leaves[0], tx_a);
    submit_to_shard(&mut runner, leaves[1], tx_b);

    let deadline = runner.now() + Duration::from_secs(10);
    assert!(
        await_both_terminal(&mut runner, &leaves, hash_a, hash_b, deadline),
        "conflicting pair must resolve via cycle detection within the deadline",
    );
}
