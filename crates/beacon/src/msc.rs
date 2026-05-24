//! Multi-Slot Consensus — pure helpers + verifiers.
//!
//! MSC composes per-slot [`SpcInstance`](crate::spc::SpcInstance)s
//! into the beacon's slot pipeline. Each slot's SPC committee submits
//! their [`MscSlotProposal`] payloads; MSC hashes them into a
//! [`PcVector`] input that the slot's SPC then drives to consensus.
//!
//! This module hosts the **verify** side of MSC — pure functions over
//! the wire types in `hyperscale_types::beacon::msc`. The FSM
//! ([`MscInstance`](`crate::msc::MscInstance`)), per-slot SPC plumbing,
//! and accusation/rank bookkeeping live in their own sub-modules.
//!
//! # `update_rank` and the demotion rule
//!
//! Each slot starts with a `rank^MC_{i,s}` ranking that determines the
//! slot's proposer-rotation. The slot's high output `b_i,s^out` then
//! drives `update_rank` to compute `rank^MC_{i,s+1}`:
//!
//! - Validators in `accused` (empty-low witnesses from the prior
//!   slot's inner SPC views) get demoted to the end of the ranking.
//! - If the prior slot's high vector is shorter than the committee
//!   (`|prev_high| < n`), the validator at position `|prev_high|` is
//!   also demoted (their proposal didn't make the cut).
//! - Non-demoted validators preserve their relative order.
//!
//! Refuses to demote everyone: with `≥ n` demotions the next slot
//! would have no head for its cyclic rotation, breaking liveness. By
//! the protocol's safety theorem an honest committee never produces
//! more than `f` empty-low accusations per slot, so even with the
//! first-excluded fold-in we have at most `f + 1 ≤ n - 1` demotions
//! in honest execution.

use std::collections::BTreeSet;

use blake3::Hasher;
use hyperscale_types::{
    Bls12381G1PublicKey, MscEmptyLowAccusation, MscSlotProposal, NetworkDefinition,
    PC_VALUE_ELEMENT_BYTES, PcValueElement, PcVector, SpcEmptyLowEvidence, ValidatorId,
    spc_context,
};
use sbor::basic_encode;

use crate::spc::{rank_shift_for_view, verify_empty_low_evidence};

/// Domain tag for the canonical encoding of an [`MscSlotProposal`]
/// when hashing into a [`PcValueElement`] for the slot's SPC input.
const SLOT_PROPOSAL_DOMAIN: &[u8] = b"hyperscale-msc-slot-proposal-v1";

/// Domain tag for the bottom-collision rehash fallback in
/// [`hash_proposal_msc`].
const SLOT_PROPOSAL_BOTTOM_DOMAIN: &[u8] = b"hyperscale-msc-slot-proposal-bottom-collision-v1";

/// All-zero sentinel for "no proposal from this position" in a slot's
/// SPC input vector. Distinct from
/// [`crate::spc::HASH_BOTTOM`](crate::spc) at the byte level only —
/// both are the same `[0; 32]` value but used in different namespaces.
const HASH_BOTTOM: PcValueElement = PcValueElement::new([0u8; PC_VALUE_ELEMENT_BYTES]);

/// Canonical bytes for an [`MscSlotProposal`] — the preimage of
/// [`hash_proposal_msc`]. Layout: `domain || slot (8 LE) || content
/// (SBOR)`. Not signed; consumed only by the proposal-hash pipeline.
fn slot_proposal_message(p: &MscSlotProposal) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SLOT_PROPOSAL_DOMAIN.len() + 8 + 256);
    buf.extend_from_slice(SLOT_PROPOSAL_DOMAIN);
    buf.extend_from_slice(&p.slot.to_le_bytes());
    let content_bytes = basic_encode(&p.content).expect("PcVector SBOR encoding should never fail");
    buf.extend_from_slice(&content_bytes);
    buf
}

/// Blake3-hash an [`MscSlotProposal`] into a [`PcValueElement`]
/// suitable for the slot's SPC input vector.
///
/// Fallback rehash avoids accidental collision with [`HASH_BOTTOM`]:
/// if the natural digest happens to land on all-zeros, a tag-prefixed
/// rehash moves it elsewhere while preserving full collision
/// resistance against other inputs.
#[must_use]
pub fn hash_proposal_msc(p: &MscSlotProposal) -> PcValueElement {
    let bytes = slot_proposal_message(p);
    let mut raw = [0u8; PC_VALUE_ELEMENT_BYTES];
    raw.copy_from_slice(Hasher::new().update(&bytes).finalize().as_bytes());
    if PcValueElement::new(raw) == HASH_BOTTOM {
        let mut h2 = Hasher::new();
        h2.update(SLOT_PROPOSAL_BOTTOM_DOMAIN);
        h2.update(&raw);
        raw.copy_from_slice(h2.finalize().as_bytes());
    }
    PcValueElement::new(raw)
}

/// Verify an [`MscEmptyLowAccusation`]: the embedded `PcQc3` verifies
/// under the SPC context for `accusation.slot` and certifies an
/// empty low at `accusation.view` (which must be `> 1`).
///
/// The accusation's `slot` field determines the SPC context, so a
/// `PcQc3` produced under a different slot's SPC won't verify here —
/// peers can't cross-pollute accusations between slots.
#[must_use]
pub fn verify_empty_low_accusation(
    accusation: &MscEmptyLowAccusation,
    network: &NetworkDefinition,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let spc_ctx = spc_context(accusation.slot);
    let evidence = SpcEmptyLowEvidence {
        view: accusation.view,
        proof: accusation.proof.clone(),
    };
    verify_empty_low_evidence(&evidence, network, &spc_ctx, committee)
}

/// Compute the validator the accusation demotes — the cyclic-first
/// party in the accused view's ranking within the slot's SPC instance.
///
/// `slot_initial_rank` is the slot's SPC initial ranking; the accused
/// validator is at position `rank_shift_for_view(accusation.view, n)`
/// after the rotation. Returns `None` only if `slot_initial_rank` is
/// empty.
#[must_use]
pub fn accusation_demotes(
    accusation: &MscEmptyLowAccusation,
    slot_initial_rank: &[ValidatorId],
) -> Option<ValidatorId> {
    if slot_initial_rank.is_empty() {
        return None;
    }
    let shifts = rank_shift_for_view(accusation.view, slot_initial_rank.len());
    Some(slot_initial_rank[shifts])
}

/// Compute the next slot's ranking from the prior slot's `(rank,
/// high_output, accused)` triple.
///
/// Validators in `accused` get demoted to the end of the ranking. If
/// `prev_high.len() < prev_rank.len()`, the validator at position
/// `prev_high.len()` is also demoted (their proposal didn't make the
/// cut). Non-demoted validators preserve their relative order.
///
/// **Refuses to demote everyone:** if the computed demoted-set would
/// cover the entire `prev_rank`, returns `prev_rank` unchanged. This
/// preserves liveness — an honest committee never produces `≥ n`
/// accusations per slot, so this branch only fires on a Byzantine-
/// constructed accusation stream that's already evidence on its own.
#[must_use]
pub fn update_rank(
    prev_rank: &[ValidatorId],
    prev_high: &PcVector,
    accused: &BTreeSet<ValidatorId>,
) -> Vec<ValidatorId> {
    let n = prev_rank.len();
    let l = prev_high.len();

    let mut demoted: BTreeSet<ValidatorId> = accused.iter().copied().collect();
    if l < n {
        demoted.insert(prev_rank[l]);
    }
    if demoted.len() >= n || demoted.is_empty() {
        return prev_rank.to_vec();
    }

    let mut kept = Vec::with_capacity(n);
    let mut tail = Vec::with_capacity(demoted.len());
    for &p in prev_rank {
        if demoted.contains(&p) {
            tail.push(p);
        } else {
            kept.push(p);
        }
    }
    kept.extend(tail);
    kept
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        PcQc2, PcQc3, PcXpProof, SignerBitfield, Slot, SpcView, generate_bls_keypair,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn committee(n: usize) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        (0..n as u64)
            .map(|i| (ValidatorId::new(i), generate_bls_keypair().public_key()))
            .collect()
    }

    fn dummy_pc_qc3() -> PcQc3 {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full {
                length_multi_sig: generate_bls_keypair().sign_v1(b"unused"),
            },
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            Vec::new(),
            generate_bls_keypair().sign_v1(b"unused"),
        )
    }

    fn elem(b: u8) -> PcValueElement {
        PcValueElement::new([b; PC_VALUE_ELEMENT_BYTES])
    }

    /// `hash_proposal_msc` is deterministic + avoids `HASH_BOTTOM`.
    #[test]
    fn hash_proposal_msc_deterministic_and_avoids_bottom() {
        let p = MscSlotProposal {
            slot: Slot::new(7),
            content: PcVector::new([elem(1), elem(2)]),
        };
        let h1 = hash_proposal_msc(&p);
        let h2 = hash_proposal_msc(&p);
        assert_eq!(h1, h2);
        assert_ne!(h1, HASH_BOTTOM);
    }

    /// Different slots or different content produce distinct hashes —
    /// the slot field is bound into the canonical bytes so two
    /// identical-content proposals at different slots don't collide.
    #[test]
    fn hash_proposal_msc_differs_across_slots_and_content() {
        let content = PcVector::new([elem(0xAA)]);
        let a = hash_proposal_msc(&MscSlotProposal {
            slot: Slot::new(1),
            content: content.clone(),
        });
        let b = hash_proposal_msc(&MscSlotProposal {
            slot: Slot::new(2),
            content,
        });
        let c = hash_proposal_msc(&MscSlotProposal {
            slot: Slot::new(1),
            content: PcVector::new([elem(0xBB)]),
        });
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    /// `verify_empty_low_accusation` rejects accusations whose view
    /// is `<= 1` (view 1 is excused).
    #[test]
    fn verify_empty_low_accusation_rejects_view_one() {
        let c = committee(4);
        let acc = MscEmptyLowAccusation {
            slot: Slot::new(5),
            view: SpcView::new(1),
            proof: dummy_pc_qc3(),
        };
        assert!(!verify_empty_low_accusation(&acc, &net(), &c));
    }

    /// `update_rank` is the identity when `accused` is empty and
    /// `prev_high.len() == prev_rank.len()`.
    #[test]
    fn update_rank_identity_when_no_demotions() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let high = PcVector::new([elem(1), elem(2), elem(3), elem(4)]);
        let accused = BTreeSet::new();
        assert_eq!(update_rank(&rank, &high, &accused), rank);
    }

    /// When `prev_high.len() < n`, the validator at position
    /// `prev_high.len()` gets demoted to the end.
    #[test]
    fn update_rank_demotes_first_excluded_when_high_short() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        // Short high: only the first 2 entries are filled, so the
        // validator at position 2 (id=2) gets demoted.
        let high = PcVector::new([elem(1), elem(2)]);
        let accused = BTreeSet::new();
        let next = update_rank(&rank, &high, &accused);
        assert_eq!(
            next,
            vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(3),
                ValidatorId::new(2),
            ],
        );
    }

    /// Explicit accusations move named validators to the tail; their
    /// relative order is preserved among kept and among demoted.
    #[test]
    fn update_rank_demotes_accused_to_tail() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let high = PcVector::new([elem(1), elem(2), elem(3), elem(4)]); // full-length
        let mut accused = BTreeSet::new();
        accused.insert(ValidatorId::new(1));
        accused.insert(ValidatorId::new(3));
        let next = update_rank(&rank, &high, &accused);
        // 0, 2 kept; 1, 3 to tail in original order.
        assert_eq!(
            next,
            vec![
                ValidatorId::new(0),
                ValidatorId::new(2),
                ValidatorId::new(1),
                ValidatorId::new(3),
            ],
        );
    }

    /// Refuses to demote the entire committee — preserves liveness
    /// against Byzantine-built accusation streams that would otherwise
    /// leave no head for the next slot's rotation.
    #[test]
    fn update_rank_refuses_to_demote_everyone() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let high = PcVector::empty(); // length 0 ⇒ position-0 demotion folds in
        let mut accused = BTreeSet::new();
        accused.insert(ValidatorId::new(1));
        accused.insert(ValidatorId::new(2));
        accused.insert(ValidatorId::new(3));
        // Demoted would be {0, 1, 2, 3} — entire committee. Refuse.
        let next = update_rank(&rank, &high, &accused);
        assert_eq!(next, rank);
    }

    /// `accusation_demotes` returns the cyclic-first party in the
    /// accused view's ranking, derived from `rank_shift_for_view`.
    #[test]
    fn accusation_demotes_resolves_via_rank_shift() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        // view 3 in a 4-party committee → shift = 1 → demotes rank[1].
        let acc = MscEmptyLowAccusation {
            slot: Slot::new(1),
            view: SpcView::new(3),
            proof: dummy_pc_qc3(),
        };
        assert_eq!(accusation_demotes(&acc, &rank), Some(ValidatorId::new(1)));
    }

    /// Empty rank → `None`.
    #[test]
    fn accusation_demotes_empty_rank_returns_none() {
        let acc = MscEmptyLowAccusation {
            slot: Slot::new(1),
            view: SpcView::new(3),
            proof: dummy_pc_qc3(),
        };
        assert_eq!(accusation_demotes(&acc, &[]), None);
    }
}
