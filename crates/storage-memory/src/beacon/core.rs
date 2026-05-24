//! Core `SimBeaconStorage` struct.
//!
//! In-memory beacon-chain storage for deterministic simulation testing.
//! Holds two maps under a single `RwLock`: a primary `slot → block`
//! store and a secondary `block_hash → slot` index. Both update
//! atomically on commit so the hash lookup is always consistent with
//! the primary store.
//!
//! Used by `SimulationRunner`; one `Arc<SimBeaconStorage>` per process
//! is shared across every vnode's `BeaconCoordinator`.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use hyperscale_types::{BeaconBlock, BeaconBlockHash, Slot};

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
    /// Primary store keyed by slot. `BTreeMap` so iteration is
    /// naturally slot-ordered for replay.
    pub(super) by_slot: BTreeMap<Slot, Arc<BeaconBlock>>,
    /// Secondary index `block_hash → slot`.
    pub(super) hash_to_slot: BTreeMap<BeaconBlockHash, Slot>,
}

impl SimBeaconStorage {
    /// Construct an empty in-memory beacon store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
