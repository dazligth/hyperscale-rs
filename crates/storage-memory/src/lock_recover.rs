//! Lock helpers that recover from poison rather than propagating it.
//!
//! `SimStorage` mutates its `RwLock`-guarded state through whole-entry
//! operations (insert / write / overwrite); a panic mid-mutation cannot
//! leave a torn invariant in either the substate maps or the consensus
//! metadata. Surfacing the poison as a panic on every subsequent test
//! that shares this storage is more disruptive than continuing — mirrors
//! the approach `PendingChain` already takes for its own RwLock/Mutex.

use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub fn read_or_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

pub fn write_or_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}
