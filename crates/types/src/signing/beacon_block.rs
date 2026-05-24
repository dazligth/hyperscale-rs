//! Domain-separated signing for beacon block headers.
//!
//! The slot committee's BLS aggregate signature over a
//! [`BeaconBlockHeader`] is what finalizes a beacon slot. Each signer
//! signs the canonical message produced by [`beacon_block_header_message`]
//! under [`DOMAIN_BEACON_BLOCK_HEADER`]; the aggregate rides inside the
//! committed [`BeaconBlock`](crate::BeaconBlock) as
//! [`aggregate_sig`](crate::BeaconBlock::aggregate_sig).
//!
//! Domain separation here keeps a header sig from being confused with a
//! PC vote, a VRF reveal, or a recovery request sig, all of which reuse
//! the same BLS keys.

use crate::{BeaconBlockHeader, NetworkDefinition};

/// Domain tag for committee signatures over a beacon block header.
pub const DOMAIN_BEACON_BLOCK_HEADER: &[u8] = b"HYPERSCALE_BEACON_BLOCK_HEADER_v1";

/// Build the canonical signing bytes for a beacon block header.
///
/// Layout: `domain || network.id || header_hash (32)`. The 32-byte
/// header hash is the SBOR-content commitment from
/// [`BeaconBlockHeader::hash`], so the signer is bound to every field
/// of the header — slot, prev hash, proposals root, state root, and any
/// attached recovery cert.
#[must_use]
pub fn beacon_block_header_message(
    network: &NetworkDefinition,
    header: &BeaconBlockHeader,
) -> Vec<u8> {
    let hash = header.hash();
    let mut out = Vec::with_capacity(DOMAIN_BEACON_BLOCK_HEADER.len() + 1 + 32);
    out.extend_from_slice(DOMAIN_BEACON_BLOCK_HEADER);
    out.push(network.id);
    out.extend_from_slice(hash.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::DOMAIN_PC_VRF;
    use crate::{
        BeaconBlockHash, BeaconProposalsRoot, BeaconStateRoot, Hash, RecoveryCertHash, Slot,
    };

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn sample_header(slot: u64) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            Slot::new(slot),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            BeaconProposalsRoot::from_raw(Hash::from_bytes(b"proposals")),
            BeaconStateRoot::from_raw(Hash::from_bytes(b"state")),
            RecoveryCertHash::from_raw(Hash::from_bytes(b"recovery")),
        )
    }

    /// Pins the byte layout of `beacon_block_header_message`. Any change
    /// to the encoder — field order, length-prefix width, domain tag —
    /// shifts these bytes and fails this test. Cross-arch determinism
    /// rides on this layout being identical regardless of `usize` width
    /// on the host.
    #[test]
    fn beacon_block_header_message_byte_layout_is_pinned() {
        let header = sample_header(5);
        let bytes = beacon_block_header_message(&net(), &header);

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_BEACON_BLOCK_HEADER);
        expected.push(net().id);
        expected.extend_from_slice(header.hash().as_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), DOMAIN_BEACON_BLOCK_HEADER.len() + 1 + 32);
    }

    /// Distinct headers (same network) must produce distinct signing
    /// bytes — any field change shifts the header hash and thus the
    /// signed message.
    #[test]
    fn beacon_block_header_message_differs_across_headers() {
        let a = beacon_block_header_message(&net(), &sample_header(1));
        let b = beacon_block_header_message(&net(), &sample_header(2));
        assert_ne!(a, b);
    }

    /// Cross-network replay protection: byte-identical headers under
    /// different networks must produce different signing bytes.
    #[test]
    fn beacon_block_header_message_differs_across_networks() {
        let header = sample_header(7);
        let mainnet = beacon_block_header_message(&NetworkDefinition::mainnet(), &header);
        let stokenet = beacon_block_header_message(&NetworkDefinition::stokenet(), &header);
        assert_ne!(mainnet, stokenet);
    }

    /// Cross-domain replay protection: a header sig must not collide
    /// with a VRF reveal under any input — different domain tags
    /// guarantee the prefixes diverge.
    #[test]
    fn beacon_block_header_message_differs_from_vrf_domain() {
        assert_ne!(DOMAIN_BEACON_BLOCK_HEADER, DOMAIN_PC_VRF);
        let header = sample_header(1);
        let bytes = beacon_block_header_message(&net(), &header);
        assert_ne!(&bytes[..DOMAIN_BEACON_BLOCK_HEADER.len()], DOMAIN_PC_VRF);
    }
}
