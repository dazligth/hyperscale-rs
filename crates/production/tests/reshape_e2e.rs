//! Production resharding end-to-end scenarios.
//!
//! Drives real beacon folds over a real libp2p cluster on real
//! `RocksDbShardStorage` to cover the production-only reshape wiring the
//! simulation suite never touches: the beacon fold → `ParticipationChange`
//! → `ShardSupervisor` duty chain and the `RocksDbShardStorage` flips.
//! Like the rest of the production e2e tests these are `#[serial]`,
//! real-time, and bounded by `timeout` — never fixed sleeps for the
//! wait-for-condition assertions.

mod cluster;

use std::sync::Arc;

use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_production::{LocalValidator, ProductionRunner};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage};
use hyperscale_storage_rocksdb::RocksDbBeaconStorage;
use hyperscale_test_helpers::fixtures::TestFixtures;
use hyperscale_types::{BeaconChainConfig, ReshapeThresholds, ValidatorId};
use serial_test::serial;
use tempfile::TempDir;
use tracing_subscriber::fmt;

fn validator(fixtures: &TestFixtures, idx: u32) -> LocalValidator {
    LocalValidator {
        validator_id: ValidatorId::new(u64::from(idx)),
        signing_key: fixtures.signing_key(idx),
    }
}

/// A custom `beacon_chain_config` threads through the builder into the
/// committed beacon genesis state. This is the single production hook the
/// rest of the suite depends on: the default path (every other production
/// e2e test) leaves the setter unused and is unaffected, so a custom
/// `epoch_duration_ms` + reshape `split_bytes` reach the genesis state
/// only when set explicitly.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[serial]
async fn beacon_chain_config_reaches_genesis() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    let temp_dir = TempDir::new().unwrap();
    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let beacon_storage =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: 400,
        reshape_thresholds: ReshapeThresholds {
            split_bytes: 50_000,
        },
        ..BeaconChainConfig::default()
    };

    let beacon_reader: Arc<dyn BeaconStorage> = beacon_storage.clone();
    let runner = ProductionRunner::builder(
        vec![validator(&fixtures, 0)],
        fixtures.topology(),
        ShardConsensusConfig::default(),
        beacon_reader,
        network_config,
        cluster::temp_storage_factory(&temp_dir),
        cluster::temp_storage_dir(&temp_dir),
    )
    .beacon_chain_config(chain_config)
    .build();
    assert!(
        runner.is_ok(),
        "runner builds with a custom beacon chain config"
    );

    // Build commits the genesis (block, state) pair into the beacon store.
    let (_block, state) = beacon_storage
        .latest_committed()
        .expect("genesis pair committed at build time");
    assert_eq!(
        state.chain_config.epoch_duration_ms, 400,
        "custom epoch duration reaches the beacon genesis state"
    );
    assert_eq!(
        state.params.reshape_thresholds.split_bytes, 50_000,
        "custom split threshold seeds the live network params at genesis"
    );
}
