//! The shared reshape-adoption acceptance gate.
//!
//! Every reshape duty — a split parent half, a split observer, a merge keeper —
//! installs its derived genesis into a prepared store, then checks the adopted
//! root against the beacon-attested anchor before trusting it: a match means the
//! local derivation and the beacon agree; a mismatch means they have diverged
//! and the duty must fail closed. The store-level adopt call differs per duty
//! (`adopt_split_child` / `adopt_followed_child` / `adopt_merge_parent`, each an
//! inherent backend method), but the acceptance check and the [`RecoveredState`]
//! the seat boots from are identical — so both harnesses funnel their adopt
//! results through here rather than re-deriving the gate.

use hyperscale_storage::RecoveredState;
use hyperscale_types::{ChainOrigin, StateRoot};

/// Accept a reshape adoption, gating it against the beacon anchor.
///
/// Checks the store's `adopted` root against the beacon-attested `expected`
/// anchor root and builds the [`RecoveredState`] the seat boots from over
/// `origin` and the adopted `substate_bytes`.
///
/// # Errors
///
/// Returns a description when `adopted` does not match `expected` — the local
/// derivation and the beacon disagree, so the duty must not seat.
pub fn verified_recovered_state(
    adopted: StateRoot,
    expected: StateRoot,
    origin: ChainOrigin,
    substate_bytes: u64,
) -> Result<RecoveredState, String> {
    if adopted != expected {
        return Err(format!(
            "adopted reshape root {adopted:?} does not match the anchor {expected:?}"
        ));
    }
    Ok(RecoveredState {
        substate_bytes,
        chain_origin: origin,
        ..RecoveredState::default()
    })
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, ChainOrigin, Hash, StateRoot, WeightedTimestamp};

    use super::verified_recovered_state;

    fn origin() -> ChainOrigin {
        ChainOrigin {
            genesis_height: BlockHeight::new(10),
            anchor_wt: WeightedTimestamp::ZERO,
        }
    }

    #[test]
    fn matching_root_yields_the_seat_state() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        let recovered = verified_recovered_state(root, root, origin(), 4_096).expect("matches");
        assert_eq!(recovered.substate_bytes, 4_096);
        assert_eq!(recovered.chain_origin, origin());
    }

    #[test]
    fn diverged_root_fails_closed() {
        let adopted = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        let expected = StateRoot::from_raw(Hash::from_bytes(b"beacon"));
        assert!(verified_recovered_state(adopted, expected, origin(), 0).is_err());
    }
}
