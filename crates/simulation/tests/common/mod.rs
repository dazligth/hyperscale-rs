//! Shared scaffolding for the shard-rotation simulation tests.
//!
//! `vnode_relocation` moves the vnode that `topology_rotation` only
//! observes; both need the same paced-epoch, refillable-pool network
//! shape, and shuffle reachability depends on these knobs staying
//! aligned.

use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_types::BeaconChainConfig;

/// 2-second epochs: short enough to reach the shuffle within the run
/// window, long enough that the beacon paces (one epoch per
/// `epoch_duration_ms`) rather than stalling against its
/// production-sized SPC/skip timeouts.
pub const TEST_EPOCH_MS: u64 = 2000;

/// Committee validators per shard. The shuffle retires one member at
/// the boundary; seven keeps both committees above quorum through the
/// rotation even where a replacement runs no host.
pub const PER_SHARD: u32 = 7;

/// Hostless `Pooled` validators registered in genesis. The shuffle
/// only rotates a shard it can refill, so an empty pool would mean no
/// rotation at all — these give each shard's draw stock.
pub const POOL_EXTRAS: u32 = 2;

/// The 2-shard, paced-epoch network both rotation tests run on.
#[must_use]
pub fn rotation_config() -> NetworkConfig {
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
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: POOL_EXTRAS,
        ..Default::default()
    }
}
