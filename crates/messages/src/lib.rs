//! Wire-level message types for the consensus protocol.
//!
//! Messages are grouped by transport semantics:
//!
//! - [`gossip`]: best-effort one-to-many fanout via gossipsub. Used for
//!   committed-block-header announcements and transaction broadcast.
//! - [`notification`]: targeted one-way pushes that don't expect a reply.
//!   Block headers, votes, execution votes/certificates, and cross-shard
//!   provisions all flow as notifications.
//! - [`request`] / [`response`]: paired request-reply messages used by the
//!   per-payload fetch protocols (block, transaction, execution-cert,
//!   finalized-wave, provision, local-provision, remote-header, sync).
//!
//! All messages are encoded with SBOR (not serde). Per-message wrappers
//! exist mostly to register typed handlers via the network registry; the
//! files in each subdirectory are thin SBOR wire-types — see the
//! containing struct for field semantics.

pub mod gossip;
pub mod notification;
pub mod request;
pub mod response;

// Re-export commonly used types
pub use gossip::{CommittedBlockHeaderGossip, TransactionGossip};
pub use notification::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionCertificatesNotification,
    ExecutionVotesNotification, ProvisionsNotification,
};
