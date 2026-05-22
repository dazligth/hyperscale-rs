//! Beacon-chain consensus types.
//!
//! - [`block`]: [`BeaconBlock`] (header + committee aggregate + optional
//!   recovery cert).
//! - [`header`]: [`BeaconBlockHeader`] (committee-signed chain link).
//! - [`recovery`]: [`RecoveryRequest`] and [`RecoveryCertificate`] (committee
//!   replacement after stall).

pub mod block;
pub mod header;
pub mod recovery;

pub use block::BeaconBlock;
pub use header::BeaconBlockHeader;
pub use recovery::{RecoveryCertificate, RecoveryRequest, recovery_cert_hash};
