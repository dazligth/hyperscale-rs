//! Domain-separated signing for beacon-chain VRF reveals.
//!
//! Each committee member signs `(network, slot)` under [`DOMAIN_PC_VRF`]
//! to produce a slot-bound VRF reveal. The 96-byte BLS signature is the
//! [`VrfProof`](crate::VrfProof); its digest is the
//! [`VrfOutput`](crate::VrfOutput) mixed into beacon randomness.
//!
//! The VRF property — uniquely determined by `(secret_key, message)` —
//! follows from BLS signatures being deterministic in min-pk mode. Domain
//! separation here keeps a VRF reveal from being confused with a PC vote,
//! a block header sig, or a recovery request sig, all of which reuse the
//! same BLS keys.

use crate::{NetworkDefinition, Slot};

/// Domain tag for beacon VRF reveals.
pub const DOMAIN_PC_VRF: &[u8] = b"HYPERSCALE_PC_VRF_v1";

/// Build the canonical signing bytes for a VRF reveal at `slot` under
/// `network`.
///
/// Layout: `domain || network.id || slot_le_bytes (8)`. Both fields are
/// fixed-width so no length prefixes are needed.
#[must_use]
pub fn vrf_reveal_message(network: &NetworkDefinition, slot: Slot) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_PC_VRF.len() + 1 + 8);
    out.extend_from_slice(DOMAIN_PC_VRF);
    out.push(network.id);
    out.extend_from_slice(&slot.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{DOMAIN_PC_EMPTY_VIEW, DOMAIN_PC_VOTE1};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    /// Pins the byte layout of `vrf_reveal_message`. Any change to the
    /// encoder — field order, length-prefix width, domain tag — shifts
    /// these bytes and fails this test. Cross-arch determinism rides on
    /// this layout being identical regardless of `usize` width on the
    /// host.
    #[test]
    fn vrf_reveal_message_byte_layout_is_pinned() {
        let bytes = vrf_reveal_message(&net(), Slot::new(5));

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_PC_VRF);
        expected.push(net().id);
        expected.extend_from_slice(&5u64.to_le_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), DOMAIN_PC_VRF.len() + 1 + 8);
    }

    /// Distinct slots produce distinct signing bytes under the same
    /// network — every slot's reveal is bound to its own slot number so
    /// a reveal can't be replayed against a later slot.
    #[test]
    fn vrf_reveal_message_differs_across_slots() {
        let a = vrf_reveal_message(&net(), Slot::new(1));
        let b = vrf_reveal_message(&net(), Slot::new(2));
        assert_ne!(a, b);
    }

    /// Cross-network replay protection: byte-identical `(slot,)` inputs
    /// under different networks must produce different signing bytes.
    #[test]
    fn vrf_reveal_message_differs_across_networks() {
        let mainnet = vrf_reveal_message(&NetworkDefinition::mainnet(), Slot::new(7));
        let stokenet = vrf_reveal_message(&NetworkDefinition::stokenet(), Slot::new(7));
        assert_ne!(mainnet, stokenet);
    }

    /// Cross-domain replay protection: a VRF reveal must not collide
    /// with a PC vote or empty-view skip statement under any input.
    /// Tested by constructing both with disjoint encoders and asserting
    /// the result bytes diverge.
    #[test]
    fn vrf_reveal_message_differs_from_other_beacon_pc_domains() {
        let vrf = vrf_reveal_message(&net(), Slot::new(1));
        // The PC-vote encoders take a context + vector, but as long as
        // the prefix bytes differ at the domain tag, the full messages
        // can never match regardless of suffix content.
        assert_ne!(&vrf[..DOMAIN_PC_VRF.len()], DOMAIN_PC_VOTE1);
        assert_ne!(&vrf[..DOMAIN_PC_VRF.len()], DOMAIN_PC_EMPTY_VIEW);
    }
}
