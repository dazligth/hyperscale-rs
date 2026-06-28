//! Umbrella trait composing the beacon read + write halves.

use super::chain_reader::BeaconChainReader;
use super::chain_writer::BeaconChainWriter;

/// Process-level beacon storage. Composes [`BeaconChainReader`] and
/// [`BeaconChainWriter`] so a single `Arc<impl BeaconStorage>` can be
/// shared across every vnode's `BeaconCoordinator`.
///
/// Blanket-impl'd for any type satisfying both halves — concrete
/// backends just implement the two component traits.
pub trait BeaconStorage: BeaconChainReader + BeaconChainWriter {}

impl<S> BeaconStorage for S where S: BeaconChainReader + BeaconChainWriter {}
