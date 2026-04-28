//! Fetch-fallback simulation tests.
//!
//! Each test installs a [`FaultRule`] suppressing a primary delivery
//! channel, then asserts three layers of recovery:
//! 1. The fault rule actually fired (rule misconfiguration guard).
//! 2. The fallback fetch path engaged (`fetch_started` counter).
//! 3. End-to-end liveness: submitted transactions reach a terminal
//!    state on every node.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::NodeInput;
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, RoutableTransaction, ed25519_keypair_from_seed,
    routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::crypto::Ed25519PublicKey;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

fn single_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

fn keypair_from_seed(seed: u8) -> Ed25519PrivateKey {
    ed25519_keypair_from_seed(&[seed; 32])
}

fn account_from_seed(seed: u8) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&Ed25519PublicKey([seed; 32]))
}

fn build_transfer_tx(signer_seed: u8, recipient_seed: u8) -> RoutableTransaction {
    let signer = keypair_from_seed(signer_seed);
    let to = account_from_seed(recipient_seed);
    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .try_deposit_entire_worktop_or_abort(to, None)
        .build();
    let notarized = sign_and_notarize(
        manifest,
        &NetworkDefinition::simulator(),
        u32::from(signer_seed),
        &signer,
    )
    .expect("sign tx");
    routable_from_notarized_v1(notarized, test_validity_range()).expect("valid tx")
}

/// Returns `true` if the node has reached a terminal state for `tx_hash`
/// (executed or tombstoned post-eviction).
fn tx_reached_terminal_state(
    runner: &SimulationRunner,
    node_idx: u32,
    tx_hash: &hyperscale_types::TxHash,
) -> bool {
    let node = runner.node(node_idx).expect("node exists");
    node.execution().is_finalized(tx_hash) || node.mempool().is_tombstoned(tx_hash)
}

#[traced_test]
#[test]
fn transaction_fetch_fallback_when_gossip_dropped() {
    let recorder = MemoryRecorder::new();
    hyperscale_metrics::set_global_recorder(Box::new(recorder.clone()));

    let mut runner = SimulationRunner::new(&single_shard_config(), 42);
    runner.initialize_genesis();

    // Suppress all transaction.gossip across the network. The submitting
    // node (0) still admits the tx locally, includes it in any block it
    // proposes, and serves it to followers via GetTransactionsRequest.
    let rule = runner
        .network_mut()
        .fault()
        .drop_type("transaction.gossip")
        .install();

    let tx = build_transfer_tx(1, 2);
    let tx_hash = tx.hash();
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        NodeInput::SubmitTransaction { tx: Arc::new(tx) },
    );

    runner.run_until(Duration::from_secs(10));

    // Layer 1: fault rule actually intercepted gossip.
    assert!(
        rule.fired() >= 1,
        "expected drop_type(\"transaction.gossip\") rule to fire at least once, got {}",
        rule.fired()
    );

    // Layer 2: the fetch fallback path engaged. `fetch_items_sent` is
    // recorded by the serve handler when it answers a fetch request, so a
    // non-zero value proves at least one fetch round-trip completed
    // successfully. (`fetch_started`/`fetch_completed` are not yet wired
    // client-side; see `crates/node/src/protocol/fetch.rs`.)
    let fetch_items_sent = recorder.counter("fetch_items_sent", Some("transaction"));
    assert!(
        fetch_items_sent >= 1,
        "expected fetch_items_sent{{kind=\"transaction\"}} >= 1, got {fetch_items_sent}"
    );

    // Layer 3: end-to-end — every node finalized the tx and the chain
    // advanced past genesis.
    for node_idx in 0..4u32 {
        assert!(
            tx_reached_terminal_state(&runner, node_idx, &tx_hash),
            "node {node_idx} did not reach terminal state for tx {tx_hash:?}; \
             gossip drops fired {} times, fetch_items_sent={fetch_items_sent}",
            rule.fired()
        );
    }

    let max_height = (0..4)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .max()
        .unwrap();
    assert!(
        max_height > BlockHeight(0),
        "expected chain to advance past genesis, got max height {max_height}"
    );
}
