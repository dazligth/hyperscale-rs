//! Column family definitions for the beacon `RocksDB` instance.
//!
//! Two CFs plus the default — the entire surface of beacon-side
//! persistence under the in-memory-replay model (committed block chain
//! is the only persisted artifact, `BeaconState` is rebuilt from it
//! at startup).
//!
//! `RocksDbBeaconStorage` opens its own database directory; this CF
//! set is disjoint from the per-shard tier.

use hyperscale_types::{BeaconBlock, Hash};
use rocksdb::{ColumnFamily, DB};

use crate::typed_cf::{BeU64Codec, HashCodec, SborCodec, TypedCf};

/// Default CF (presence required by `RocksDB`; unused by beacon today).
pub const DEFAULT_CF: &str = "default";

/// Primary store keyed by `Slot` (big-endian `u64` for lex ordering).
/// Value: SBOR-encoded [`BeaconBlock`](hyperscale_types::BeaconBlock).
/// Range scans naturally yield ascending-slot order — used by
/// `iter_beacon_blocks_from` for startup replay.
pub const BEACON_BLOCKS_BY_SLOT_CF: &str = "beacon_blocks_by_slot";

/// Secondary index `BeaconBlockHash → Slot` so hash lookups stay O(1)
/// without duplicating the block payload. Value: big-endian `u64`
/// slot.
pub const BEACON_HASH_TO_SLOT_CF: &str = "beacon_hash_to_slot";

/// Full CF set passed to `DB::open_cf_descriptors` when initialising the
/// beacon database.
pub const ALL_COLUMN_FAMILIES: &[&str] =
    &[DEFAULT_CF, BEACON_BLOCKS_BY_SLOT_CF, BEACON_HASH_TO_SLOT_CF];

// ─── CfHandles ───────────────────────────────────────────────────────────────

/// Beacon-side column-family handles resolved from a `DB` reference.
///
/// Distinct from the per-shard tier's `CfHandles` because beacon runs
/// its own `RocksDB` instance with a disjoint CF set.
pub struct CfHandles<'a> {
    blocks_by_slot: &'a ColumnFamily,
    hash_to_slot: &'a ColumnFamily,
}

impl<'a> CfHandles<'a> {
    /// Resolve all beacon column-family handles from the database.
    ///
    /// # Panics
    ///
    /// Panics if any expected column family is missing.
    pub fn resolve(db: &'a DB) -> Self {
        let resolve = |name: &str| -> &'a ColumnFamily {
            db.cf_handle(name)
                .unwrap_or_else(|| panic!("beacon column family '{name}' must exist"))
        };
        Self {
            blocks_by_slot: resolve(BEACON_BLOCKS_BY_SLOT_CF),
            hash_to_slot: resolve(BEACON_HASH_TO_SLOT_CF),
        }
    }
}

// ─── Typed CF definitions ────────────────────────────────────────────────────

/// Primary beacon-blocks-by-slot CF. Key: `u64` slot (BE-encoded for
/// lex ordering). Value: SBOR-encoded `BeaconBlock`.
pub struct BeaconBlocksBySlotCf;
impl TypedCf for BeaconBlocksBySlotCf {
    const NAME: &'static str = BEACON_BLOCKS_BY_SLOT_CF;
    type Key = u64;
    type Value = BeaconBlock;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<BeaconBlock>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.blocks_by_slot
    }
}

/// Secondary hash-to-slot index CF. Key: 32-byte block hash. Value:
/// `u64` slot (BE-encoded for consistency with the primary CF).
pub struct BeaconHashToSlotCf;
impl TypedCf for BeaconHashToSlotCf {
    const NAME: &'static str = BEACON_HASH_TO_SLOT_CF;
    type Key = Hash;
    type Value = u64;
    type KeyCodec = HashCodec;
    type ValueCodec = BeU64Codec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.hash_to_slot
    }
}
