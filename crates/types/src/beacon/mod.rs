//! Beacon-chain consensus types.
//!
//! - [`block`]: [`BeaconBlock`] (header + committee aggregate + optional
//!   recovery cert).
//! - [`header`]: [`BeaconBlockHeader`] (committee-signed chain link).
//! - [`limits`]: protocol-level caps on per-proposal payload sizes.
//! - [`proposal`]: [`BeaconProposal`] (one committee member's slot
//!   submission: witnesses + VRF reveal).
//! - [`recovery`]: [`RecoveryRequest`] and [`RecoveryCertificate`] (committee
//!   replacement after stall).
//! - [`witness`]: [`Witness`] / [`ShardWitness`] / [`ShardWitnessPayload`] /
//!   [`ShardWitnessProof`] / [`JailReason`] (observations the beacon
//!   applies per slot).

pub mod block;
pub mod header;
pub mod limits;
pub mod proposal;
pub mod recovery;
pub mod witness;

pub use block::BeaconBlock;
pub use header::BeaconBlockHeader;
pub use limits::MAX_WITNESSES_PER_PROPOSER;
pub use proposal::BeaconProposal;
pub use recovery::{RecoveryCertificate, RecoveryRequest, recovery_cert_hash};
pub use witness::{JailReason, ShardWitness, ShardWitnessPayload, ShardWitnessProof, Witness};
