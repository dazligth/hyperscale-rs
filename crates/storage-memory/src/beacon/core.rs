//! Core `SimBeaconStorage` struct.
//!
//! In-memory beacon-chain storage for deterministic simulation testing.
//! Holds two maps under a single `RwLock`: a primary `epoch → block`
//! store and a secondary `block_hash → epoch` index. Both update
//! atomically on commit so the hash lookup is always consistent with
//! the primary store.
//!
//! Used by `SimulationRunner`; one `Arc<SimBeaconStorage>` per process
//! is shared across every vnode's `BeaconCoordinator`.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use hyperscale_types::{BeaconBlock, BeaconBlockHash, Epoch};

/// In-memory implementation of the beacon storage tier.
///
/// Backs `SimulationRunner`'s process-level beacon chain. One
/// `Arc<SimBeaconStorage>` is shared across every vnode's
/// `BeaconCoordinator`.
#[derive(Debug, Default)]
pub struct SimBeaconStorage {
    pub(super) inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
pub(super) struct Inner {
    /// Primary store keyed by epoch. `BTreeMap` so iteration is
    /// naturally epoch-ordered for replay.
    pub(super) by_slot: BTreeMap<Epoch, Arc<BeaconBlock>>,
    /// Secondary index `block_hash → epoch`.
    pub(super) hash_to_slot: BTreeMap<BeaconBlockHash, Epoch>,
}

impl SimBeaconStorage {
    /// Construct an empty in-memory beacon store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
