//! Shard-side storage abstractions: per-shard chain reader/writer, JMT
//! state commitment, pending-chain overlay, Radix substate plumbing.
//!
//! Sibling [`crate::beacon`](crate::beacon) hosts the parallel
//! beacon-chain storage tier — independent traits, independent
//! backend impls, independent lifetime.

pub mod chain_reader;
pub mod chain_writer;
pub mod genesis;
pub mod keys;
pub mod lock_recover;
pub mod overlay;
pub mod pending_chain;
pub mod recovered_state;
pub mod store;
pub mod tree;
pub mod writes;
