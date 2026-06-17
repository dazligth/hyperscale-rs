//! The single-shard-to-target grow primitive, exercised as test setup.
//!
//! Boots a single-shard network with the split trigger armed from genesis,
//! grows it to two shards through the real split lifecycle, and asserts the
//! reached topology: two leaves the parent reshaped into, each at full
//! committee strength and committing past its child genesis on a seated host.

use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BeaconChainConfig, BlockHeight, ReshapeThresholds, ShardId};
use tracing_test::traced_test;

const TEST_EPOCH_MS: u64 = 2000;
const PER_SHARD: u32 = 4;

/// A single-shard, paced-epoch network with the split trigger armed from
/// genesis and one cohort of pooled extras per split.
fn grow_config(target_shards: u32) -> NetworkConfig {
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
            reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: (target_shards - 1) * PER_SHARD,
        ..Default::default()
    }
}

#[traced_test]
#[test]
fn grow_to_two_shards_reaches_topology() {
    let target = 2;
    let mut runner = SimulationRunner::new(&grow_config(target), 11);
    runner.initialize_genesis();
    runner.grow_to(target);

    let (left, right) = ShardId::ROOT.children();

    // Every host's snapshot now partitions into exactly the two children.
    for node in 0..runner.num_hosts() {
        let snapshot = runner.host_topology(node).expect("host carries a topology");
        assert_eq!(
            snapshot.num_shards(),
            u64::from(target),
            "host {node} must see {target} shards after the grow",
        );
        let leaves: Vec<ShardId> = snapshot.shard_trie().leaves().collect();
        assert_eq!(leaves, vec![left, right], "the leaves are the two children");
        for child in [left, right] {
            assert_eq!(
                snapshot.committee_for_shard(child).len(),
                PER_SHARD as usize,
                "child {child:?} must stand at full committee strength",
            );
        }
    }

    // Both children run a live chain past their genesis on a seated host.
    for child in [left, right] {
        let advanced = (0..runner.num_hosts()).any(|node| {
            runner
                .hosts_shard(node, child)
                .is_some_and(|storage| storage.committed_height() > BlockHeight::GENESIS)
        });
        assert!(advanced, "child {child:?} must commit past its genesis");
    }
}
