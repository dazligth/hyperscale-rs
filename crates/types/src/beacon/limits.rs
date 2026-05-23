//! Beacon proposal content limits.
//!
//! Hard caps applied at decode time on peer-supplied proposal payloads.
//! Wire decoders enforce them on the [`BoundedVec`](crate::BoundedVec)
//! length prefix before any per-element work, so an oversized proposal
//! is rejected before allocator pressure builds.
//!
//! These are protocol invariants, not operator-tunable config.

/// Per-proposer fair-share cap on witnesses in a single
/// [`BeaconProposal`](crate::BeaconProposal).
///
/// Bounds the proposer's raw wire-bandwidth contribution and the
/// allocator pressure their proposal can impose at decode time. Sized
/// to cover legitimate committee turnover (registrations, jails,
/// unjails) plus headroom; a proposer that tries to crowd in more
/// loses everything past the cap before any per-witness work runs.
pub const MAX_WITNESSES_PER_PROPOSER: usize = 32;
