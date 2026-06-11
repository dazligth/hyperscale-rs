//! Reshape-trigger behavior pinned by the shard sim: a shard whose
//! committed substate count satisfies the load predicate asserts the
//! trigger on its manifest, every replica re-derives and verifies the
//! assertion as part of the beacon-witness root, the committed
//! accumulator gains the trigger leaf, and re-assertion is suppressed
//! for the rest of the witness window.

mod common;

use common::ShardCoordinatorSim;
use hyperscale_types::{ReshapeThresholds, ShardWitnessPayload};

const MAX_STEPS: usize = 5_000;

/// With a zero split threshold every block's load predicate fires, so
/// the first committed block must carry exactly one `ScheduleSplit`
/// leaf — and the window dedup must keep every later block in the same
/// witness window from re-asserting. All replicas commit the same
/// chain, which means each one re-derived the assertion and accepted
/// it (a predicate mismatch rejects the block before voting).
#[test]
fn split_trigger_asserts_once_per_window_and_verifies() {
    let mut sim = ShardCoordinatorSim::new(4, 0x7E5A);
    sim.topology = sim
        .topology
        .clone()
        .with_reshape_thresholds(ReshapeThresholds { split_substates: 0 });
    sim.kick_off();

    let mut steps = 0;
    while steps < MAX_STEPS && sim.commits.iter().any(|c| c.len() < 3) {
        if !sim.step() {
            break;
        }
        steps += 1;
    }

    for (replica, commits) in sim.commits.iter().enumerate() {
        assert!(
            commits.len() >= 3,
            "replica {replica} expected >= 3 commits within step budget; got {}",
            commits.len(),
        );

        let asserting: Vec<u64> = commits
            .iter()
            .filter(|c| {
                c.witness_leaves
                    .iter()
                    .any(|l| matches!(l, ShardWitnessPayload::ScheduleSplit { .. }))
            })
            .map(|c| c.height.inner())
            .collect();
        assert_eq!(
            asserting,
            vec![1],
            "replica {replica}: exactly the first committed block asserts the \
             split; later blocks in the same witness window dedup",
        );
    }

    // Byte-identical chains across replicas — the assertion was
    // verified, not trusted.
    for replica in 1..4 {
        for i in 0..3 {
            assert_eq!(
                sim.commits[0][i].block_hash, sim.commits[replica][i].block_hash,
                "replica {replica} diverged at commit {i}",
            );
        }
    }
}

/// With reshaping disabled (the default schedule), no block ever
/// asserts a trigger and no `ScheduleSplit`/`ScheduleMerge` leaf
/// reaches the accumulator.
#[test]
fn disabled_thresholds_never_assert() {
    let mut sim = ShardCoordinatorSim::new(4, 0x7E5B);
    sim.kick_off();

    let mut steps = 0;
    while steps < MAX_STEPS && sim.commits[0].len() < 3 {
        if !sim.step() {
            break;
        }
        steps += 1;
    }
    assert!(sim.commits[0].len() >= 3);

    for commit in &sim.commits[0] {
        assert!(
            !commit.witness_leaves.iter().any(|l| matches!(
                l,
                ShardWitnessPayload::ScheduleSplit { .. }
                    | ShardWitnessPayload::ScheduleMerge { .. }
            )),
            "no reshape leaf may appear while thresholds are disabled",
        );
    }
}
