//! Multi-vnode cross-shard hosting smoke test.
//!
//! After growing to two shards, the split's observer seating leaves some hosts
//! running a vnode in *each* child shard — a single `IoLoop` servicing
//! different shards. Exercises gossip shard routing, fetch-callback tagging,
//! per-shard timer keying, and shared per-shard stores composing end to end,
//! the same machinery the same-shard variant in `multi_vnode_tests.rs` covers.

use std::time::Duration;

use hyperscale_simulation::SimulationRunner;
use hyperscale_types::ShardId;
use tracing_test::traced_test;

mod common;
use common::{cross_shard_grow_config, grown_leaves};

/// Lowest committed height across `leaf`'s live committee.
fn min_height(runner: &SimulationRunner, leaf: ShardId) -> u64 {
    runner
        .shard_vnodes(leaf)
        .iter()
        .map(|v| v.shard_coordinator().committed_height().inner())
        .min()
        .expect("leaf has a live committee")
}

/// Greatest committed-height spread across `leaf`'s live committee — the drift
/// between members on different hosts.
fn drift(runner: &SimulationRunner, leaf: ShardId) -> u64 {
    let heights: Vec<u64> = runner
        .shard_vnodes(leaf)
        .iter()
        .map(|v| v.shard_coordinator().committed_height().inner())
        .collect();
    let max = heights.iter().max().expect("live committee");
    let min = heights.iter().min().expect("live committee");
    max - min
}

#[traced_test]
#[test]
fn test_cross_shard_hosting_makes_progress() {
    let mut runner = SimulationRunner::new(&cross_shard_grow_config(), 7);
    runner.initialize_genesis();
    runner.grow_to(2);
    let leaves = grown_leaves();

    // The grow's observer seating must leave at least one host co-hosting a
    // vnode in each child — the cross-shard hosting under test.
    let cross_hosts = (0..runner.num_hosts())
        .filter(|&h| {
            leaves
                .iter()
                .all(|&leaf| runner.hosts_shard(h, leaf).is_some())
        })
        .count();
    assert!(
        cross_hosts >= 1,
        "grow must leave at least one host co-hosting both children",
    );

    // Both children keep advancing under the shared hosts: snapshot each leaf's
    // lowest committed height, run a burst, and require every member to climb.
    let before: Vec<u64> = leaves
        .iter()
        .map(|&leaf| min_height(&runner, leaf))
        .collect();
    let until = runner.now() + Duration::from_secs(8);
    runner.run_until(until);
    for (&leaf, &start) in leaves.iter().zip(&before) {
        let now = min_height(&runner, leaf);
        assert!(
            now > start,
            "{leaf:?} stalled under cross-shard hosting: {start} -> {now}",
        );
        // Members of one shard on different hosts stay closely synchronized —
        // cross-host drift bounded by a small window at the snapshot instant.
        assert!(
            drift(&runner, leaf) <= 2,
            "{leaf:?} committee drifted too far: {}",
            drift(&runner, leaf),
        );
    }
}
