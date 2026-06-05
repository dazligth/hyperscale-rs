//! Topology and validator set.
//!
//! - [`validator`]: [`ValidatorInfo`] / [`ValidatorSet`].
//! - [`snapshot`]: read-only [`TopologySnapshot`] view used by subsystems.
//! - [`schedule`]: per-epoch [`TopologySchedule`] resolving committees by
//!   weighted timestamp.

pub mod schedule;
pub mod snapshot;
pub mod validator;
