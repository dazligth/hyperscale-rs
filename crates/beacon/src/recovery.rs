//! Recovery-cert handling for the beacon chain.
//!
//! Today: [`verify_recovery_equivocation`], the cryptographic predicate
//! that turns a [`RecoveryEquivocation`] into "yes, this validator
//! double-attested." Future work in this module: [`RecoveryCertificate`]
//! verification (signature aggregate against the active-duty pool,
//! quorum threshold, round monotonicity) and the recovery-aware
//! committee sampler that consumes `excluded_validators`.

use hyperscale_types::{
    BeaconBlock, Bls12381G1PublicKey, NetworkDefinition, RecoveryCertificate, RecoveryEquivocation,
    ValidatorId, aggregate_verify_bls_different_messages, beacon_block_header_message,
    recovery_request_message,
};

/// Verify that a [`RecoveryEquivocation`] is a genuine double-attestation
/// by the named validator:
///
/// 1. They signed a [`RecoveryRequest`](hyperscale_types::RecoveryRequest)
///    claiming `request.last_block_hash` was their latest finalized
///    view at `request.last_block_epoch`.
/// 2. They also contributed to the BLS aggregate that finalized
///    `block_header` at a strictly later epoch.
///
/// Returns `true` only when:
/// - `block_header.epoch() > request.last_block_epoch()` (the semantic
///   contradiction — claiming "X is my latest" is incompatible with
///   having signed a later block).
/// - `request.signer() == validator` (the request claims to come from
///   this validator).
/// - The request's signature verifies under the validator's pubkey
///   over the canonical recovery-request signing bytes.
/// - The validator's bit is set in `block_signers` at their position
///   in `lookup`.
/// - The block aggregate signature verifies under the union of pubkeys
///   at the set bits in `block_signers`, indexed positionally against
///   `lookup`.
///
/// # `lookup` indexing convention
///
/// `lookup` is the current validator-set pubkey table — `state.validators`
/// iterated in sorted-id order. The bitfield positions encode an
/// enumeration against the same sorted ordering at the time the block
/// was signed. Validator records persist indefinitely, so the
/// equivocator's position is stable as long as no smaller-id validator
/// has been registered after the block — true under the
/// monotonic-id registration our genesis + admission flow produces.
///
/// Future work: when the active validator set drifts in ways that
/// shuffle positions, the equivocation type needs to commit to the
/// historical committee enumeration directly. Out of scope today.
#[must_use]
pub fn verify_recovery_equivocation(
    ev: &RecoveryEquivocation,
    network: &NetworkDefinition,
    lookup: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    // Semantic contradiction — the block was finalized strictly past
    // the request's anchor epoch.
    if ev.block_header.epoch() <= ev.request.last_block_epoch() {
        return false;
    }
    // Request must claim to come from the named validator.
    if ev.request.signer() != ev.validator {
        return false;
    }
    // Equivocator must be in the current validator set so we can read
    // their pubkey and compute their bitfield position.
    let Some(position) = lookup.iter().position(|(id, _)| *id == ev.validator) else {
        return false;
    };
    let validator_pk = lookup[position].1;

    // Verify the recovery-request signature under the validator's key.
    let req_msg = recovery_request_message(
        network,
        &ev.request.last_block_hash(),
        ev.request.last_block_epoch(),
        ev.request.recovery_round(),
    );
    if !aggregate_verify_bls_different_messages(
        &[req_msg.as_slice()],
        &ev.request.sig(),
        &[validator_pk],
    ) {
        return false;
    }

    // The equivocator's bit must be set; otherwise they didn't sign
    // the block and the claim is incoherent.
    if !ev.block_signers.is_set(position) {
        return false;
    }

    // Reject if the bitfield indexes past the known validator set —
    // structurally invalid evidence (or evidence from a future
    // larger-N set we can't enumerate).
    if ev.block_signers.num_validators() > lookup.len() {
        return false;
    }

    // Verify the block aggregate signature under the union of pubkeys
    // at the set bits.
    let signer_pks: Vec<Bls12381G1PublicKey> = ev
        .block_signers
        .set_indices()
        .map(|i| lookup[i].1)
        .collect();
    if signer_pks.is_empty() {
        return false;
    }
    let block_msg = beacon_block_header_message(network, &ev.block_header);
    let block_msgs: Vec<&[u8]> =
        std::iter::repeat_n(block_msg.as_slice(), signer_pks.len()).collect();
    aggregate_verify_bls_different_messages(&block_msgs, &ev.block_aggregate_sig, &signer_pks)
}

// ─── RecoveryCertificate verification ──────────────────────────────────────

/// Verify a [`RecoveryCertificate`] against the current active-duty
/// pool.
///
/// `active_pool` is the validators currently in
/// `OnShard { ready: true, .. }` across any shard, paired with their
/// BLS pubkeys, sorted by `ValidatorId` (the enumeration the cert's
/// `signers` bitfield is indexed against). `last_cert` is the most
/// recently applied recovery cert, if any.
///
/// Returns `true` only when:
/// - `cert.signers().num_validators() == active_pool.len()` — the
///   bitfield must be sized to the current pool; positional indexing
///   breaks if these diverge.
/// - Signer count meets the quorum threshold `⌈2 × pool_size / 3⌉ + 1`.
/// - When `last_cert` shares the same anchor (block hash + epoch), the
///   new `recovery_round` is strictly greater. Round monotonicity
///   clears implicitly on anchor change.
/// - The aggregate signature verifies under the union of pubkeys at
///   the set bits, over the canonical signing bytes
///   `recovery_request_message(network, anchor, epoch, round)`.
///
/// The `excluded_validators` size cap is enforced structurally by the
/// `BoundedVec<_, MAX_EXCLUDED_VALIDATORS>` field on
/// `RecoveryCertificate`; the wire decoder rejects oversize lists
/// before they reach this verifier.
///
/// # Active-pool drift
///
/// `active_pool` is the pool *at verification time*. If the active set
/// has shifted between cert signing and verification (a validator
/// jailed or readied in between), the bitfield's positional indices
/// may map to a pool that's a near-superset of the original — the
/// aggregate signature still verifies as long as the signer set
/// hasn't lost any members. Larger drifts produce a false-negative
/// rejection rather than a false-positive acceptance, preserving
/// safety.
#[must_use]
pub fn verify_recovery_cert(
    cert: &RecoveryCertificate,
    network: &NetworkDefinition,
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
    last_cert: Option<&RecoveryCertificate>,
) -> bool {
    let pool_size = active_pool.len();
    if cert.signers().num_validators() != pool_size {
        return false;
    }

    // Quorum threshold: ⌈2N/3⌉ + 1.
    let signer_count = cert.signers().count_ones();
    let quorum = (2 * pool_size).div_ceil(3) + 1;
    if signer_count < quorum {
        return false;
    }

    // Round monotonicity at the anchor.
    if let Some(prev) = last_cert
        && prev.last_block_hash() == cert.last_block_hash()
        && prev.last_block_epoch() == cert.last_block_epoch()
        && cert.recovery_round() <= prev.recovery_round()
    {
        return false;
    }

    let signer_pks: Vec<Bls12381G1PublicKey> = cert
        .signers()
        .set_indices()
        .map(|i| active_pool[i].1)
        .collect();
    if signer_pks.is_empty() {
        return false;
    }
    let msg = recovery_request_message(
        network,
        &cert.last_block_hash(),
        cert.last_block_epoch(),
        cert.recovery_round(),
    );
    let msgs: Vec<&[u8]> = std::iter::repeat_n(msg.as_slice(), signer_pks.len()).collect();
    aggregate_verify_bls_different_messages(&msgs, &cert.aggregate_sig(), &signer_pks)
}

// ─── Block-selection rule ──────────────────────────────────────────────────

/// Pick the winning [`BeaconBlock`] when two valid candidates exist for
/// the same epoch.
///
/// Race source: a slow original committee can finalize a block while a
/// recovery cert is being assembled in parallel. Both blocks pass their
/// own header / aggregate checks, but the chain can only commit one per
/// epoch, and every honest validator must converge on the same choice.
///
/// Selection order:
///
/// 1. A cert-bearing block wins over a no-cert block. The cert is
///    on-chain proof that the active-duty quorum deemed the prior
///    committee's attempt inadequate at this epoch.
/// 2. Among two cert-bearing blocks, the higher [`RecoveryRound`]
///    wins. Within an epoch, recovery rounds chain on failure with
///    cumulative exclusions, so the higher-round cert reflects the
///    fuller picture.
/// 3. Final tie-break: lower [`BeaconBlockHash`]. Deterministic so
///    every honest validator picks the same winner regardless of
///    network-arrival order.
///
/// # Panics
///
/// Panics if `a.epoch() != b.epoch()`. The rule is scoped to
/// same-epoch race resolution; callers must align the candidates'
/// epochs before invoking.
///
/// [`RecoveryRound`]: hyperscale_types::RecoveryRound
/// [`BeaconBlockHash`]: hyperscale_types::BeaconBlockHash
#[must_use]
pub fn select_winning_block<'a>(a: &'a BeaconBlock, b: &'a BeaconBlock) -> &'a BeaconBlock {
    assert_eq!(
        a.epoch(),
        b.epoch(),
        "select_winning_block: cross-epoch comparison",
    );
    match (a.recovery_cert(), b.recovery_cert()) {
        (Some(_), None) => a,
        (None, Some(_)) => b,
        (Some(ca), Some(cb)) => match ca.recovery_round().cmp(&cb.recovery_round()) {
            std::cmp::Ordering::Greater => a,
            std::cmp::Ordering::Less => b,
            std::cmp::Ordering::Equal => tie_break_by_hash(a, b),
        },
        (None, None) => tie_break_by_hash(a, b),
    }
}

/// Tie-break: lower [`BeaconBlockHash`] wins. Deterministic across
/// replicas.
fn tie_break_by_hash<'a>(a: &'a BeaconBlock, b: &'a BeaconBlock) -> &'a BeaconBlock {
    if a.block_hash() <= b.block_hash() {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconBlockHash, BeaconBlockHeader, BeaconProposalsRoot, BeaconStateRoot,
        Bls12381G1PrivateKey, Bls12381G2Signature, Epoch, Hash, RecoveryCertHash, RecoveryRequest,
        RecoveryRound, SignerBitfield, bls_keypair_from_seed,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn sample_header(epoch: u64) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            Epoch::new(epoch),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            BeaconProposalsRoot::from_raw(Hash::from_bytes(b"proposals")),
            BeaconStateRoot::from_raw(Hash::from_bytes(b"state")),
            RecoveryCertHash::ZERO,
        )
    }

    /// Build a genuine equivocation: validator `i` signs both a recovery
    /// request at `anchor_epoch` AND contributes to the BLS aggregate
    /// on `header` (the other signers are validators at the remaining
    /// positions in `lookup`).
    fn genuine_equivocation(
        anchor_epoch: u64,
        recovery_round: u32,
        header_epoch: u64,
        equivocator_position: usize,
        num_validators: usize,
    ) -> (
        RecoveryEquivocation,
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) {
        assert!(equivocator_position < num_validators);
        let keys: Vec<Bls12381G1PrivateKey> =
            (0..num_validators).map(|i| keypair(i as u64)).collect();
        let lookup: Vec<(ValidatorId, Bls12381G1PublicKey)> = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (ValidatorId::new(i as u64), sk.public_key()))
            .collect();
        let validator = lookup[equivocator_position].0;

        let req_msg = recovery_request_message(
            &net(),
            &anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
        );
        let req_sig = keys[equivocator_position].sign_v1(&req_msg);
        let request = RecoveryRequest::new(
            anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
            validator,
            req_sig,
        );

        let header = sample_header(header_epoch);
        let block_msg = beacon_block_header_message(&net(), &header);
        // All `num_validators` sign — bit set for everyone.
        let block_sigs: Vec<Bls12381G2Signature> =
            keys.iter().map(|sk| sk.sign_v1(&block_msg)).collect();
        let block_aggregate_sig =
            Bls12381G2Signature::aggregate(&block_sigs, true).expect("aggregate succeeds");
        let mut block_signers = SignerBitfield::new(num_validators);
        for i in 0..num_validators {
            block_signers.set(i);
        }

        let ev = RecoveryEquivocation {
            validator,
            request,
            block_header: header,
            block_signers,
            block_aggregate_sig,
        };
        (ev, lookup)
    }

    #[test]
    fn accepts_genuine_equivocation() {
        let (ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        assert!(verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// `block_header.epoch <= request.last_block_epoch` means no
    /// contradiction — the validator's request claim and their later
    /// block contribution are consistent.
    #[test]
    fn rejects_no_semantic_contradiction() {
        // Block at the same epoch as the request anchor — not strictly
        // greater, so no equivocation.
        let (ev, lookup) = genuine_equivocation(5, 0, 5, 2, 4);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// `request.signer != validator` is an internally incoherent
    /// equivocation — the named equivocator never signed the request.
    #[test]
    fn rejects_request_signer_mismatch() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Re-sign a request as validator 3 but keep `ev.validator` at 2.
        let other = ValidatorId::new(3);
        let req_msg =
            recovery_request_message(&net(), &anchor(), Epoch::new(5), RecoveryRound::new(0));
        let req_sig = keypair(3).sign_v1(&req_msg);
        ev.request = RecoveryRequest::new(
            anchor(),
            Epoch::new(5),
            RecoveryRound::new(0),
            other,
            req_sig,
        );
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// A request signature that doesn't match the validator's pubkey
    /// is rejected. Tampering the sig bytes after signing breaks
    /// verification.
    #[test]
    fn rejects_tampered_request_signature() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        let mut sig = ev.request.sig();
        sig.0[0] ^= 1;
        ev.request = RecoveryRequest::new(
            ev.request.last_block_hash(),
            ev.request.last_block_epoch(),
            ev.request.recovery_round(),
            ev.request.signer(),
            sig,
        );
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// If the equivocator's bit isn't set in `block_signers`, the
    /// claim "they signed both" doesn't hold internally.
    #[test]
    fn rejects_validator_bit_unset() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        ev.block_signers.clear(2);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// An equivocator absent from `lookup` can't be verified — we have
    /// no pubkey to check the request signature against.
    #[test]
    fn rejects_unknown_validator() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Substitute a validator id that isn't in `lookup`.
        ev.validator = ValidatorId::new(99);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// A block aggregate over the wrong header bytes won't verify.
    #[test]
    fn rejects_tampered_block_header() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Swap the header to a different epoch; the aggregate sig is
        // bound to the original header's bytes.
        ev.block_header = sample_header(10);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// Bitfield indexing past the lookup is structurally invalid.
    #[test]
    fn rejects_bitfield_wider_than_lookup() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Build a wider bitfield (8 slots) — exceeds the 4-validator
        // lookup.
        let mut wide = SignerBitfield::new(8);
        for i in 0..4 {
            wide.set(i);
        }
        ev.block_signers = wide;
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    // ─── verify_recovery_cert ────────────────────────────────────────────

    /// Build a recovery cert with `signer_count` of `pool_size`
    /// validators signing. Returns the cert and the active pool.
    fn genuine_cert(
        anchor_epoch: u64,
        recovery_round: u32,
        pool_size: usize,
        signer_count: usize,
    ) -> (RecoveryCertificate, Vec<(ValidatorId, Bls12381G1PublicKey)>) {
        assert!(signer_count <= pool_size);
        let keys: Vec<Bls12381G1PrivateKey> = (0..pool_size).map(|i| keypair(i as u64)).collect();
        let pool: Vec<(ValidatorId, Bls12381G1PublicKey)> = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (ValidatorId::new(i as u64), sk.public_key()))
            .collect();

        let msg = recovery_request_message(
            &net(),
            &anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
        );
        let sigs: Vec<Bls12381G2Signature> = keys
            .iter()
            .take(signer_count)
            .map(|sk| sk.sign_v1(&msg))
            .collect();
        let aggregate_sig =
            Bls12381G2Signature::aggregate(&sigs, true).expect("aggregate succeeds");

        let mut signers = SignerBitfield::new(pool_size);
        for i in 0..signer_count {
            signers.set(i);
        }

        let cert = RecoveryCertificate::new(
            anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
            Vec::new(),
            signers,
            aggregate_sig,
        );
        (cert, pool)
    }

    #[test]
    fn cert_accepts_genuine_quorum() {
        // Pool of 7, quorum = ⌈14/3⌉ + 1 = 5 + 1 = 6.
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        assert!(verify_recovery_cert(&cert, &net(), &pool, None));
    }

    #[test]
    fn cert_rejects_below_quorum() {
        // Pool of 7, quorum = 6. 5 signers — one short.
        let (cert, pool) = genuine_cert(5, 0, 7, 5);
        assert!(!verify_recovery_cert(&cert, &net(), &pool, None));
    }

    /// Bitfield sized to a different pool than the verifier sees —
    /// positional indexing breaks and the cert must be rejected.
    #[test]
    fn cert_rejects_bitfield_size_mismatch() {
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        // Trim the pool to 6 entries; bitfield still claims 7.
        let trimmed: Vec<_> = pool.into_iter().take(6).collect();
        assert!(!verify_recovery_cert(&cert, &net(), &trimmed, None));
    }

    /// A cert at round N for an anchor where the last applied cert was
    /// already at round N (or higher) is rejected — round must strictly
    /// advance to supersede.
    #[test]
    fn cert_rejects_non_monotonic_round_at_same_anchor() {
        let (prev, pool) = genuine_cert(5, 1, 7, 6);
        // Same anchor, same round — must reject.
        let (same_round, _) = genuine_cert(5, 1, 7, 6);
        assert!(!verify_recovery_cert(
            &same_round,
            &net(),
            &pool,
            Some(&prev)
        ));
        // Same anchor, lower round — must reject.
        let (lower_round, _) = genuine_cert(5, 0, 7, 6);
        assert!(!verify_recovery_cert(
            &lower_round,
            &net(),
            &pool,
            Some(&prev)
        ));
    }

    /// Round monotonicity is scoped per-anchor: a round-0 cert at a
    /// new anchor is fine even if a higher-round cert was applied at a
    /// different anchor.
    #[test]
    fn cert_accepts_round_zero_at_different_anchor() {
        let (prev, pool) = genuine_cert(5, 5, 7, 6);
        // Different anchor epoch — clears the monotonicity gate.
        let (new_anchor, _) = genuine_cert(6, 0, 7, 6);
        assert!(verify_recovery_cert(
            &new_anchor,
            &net(),
            &pool,
            Some(&prev)
        ));
    }

    /// Tampering the aggregate sig bytes breaks verification.
    #[test]
    fn cert_rejects_tampered_aggregate_sig() {
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        let mut bad_sig = cert.aggregate_sig();
        bad_sig.0[0] ^= 1;
        let tampered = RecoveryCertificate::new(
            cert.last_block_hash(),
            cert.last_block_epoch(),
            cert.recovery_round(),
            Vec::new(),
            cert.signers().clone(),
            bad_sig,
        );
        assert!(!verify_recovery_cert(&tampered, &net(), &pool, None));
    }

    /// Changing the round in the cert body without re-signing produces
    /// a sig over the wrong canonical message — verifier rejects.
    #[test]
    fn cert_rejects_rebadged_round() {
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        let rebadged = RecoveryCertificate::new(
            cert.last_block_hash(),
            cert.last_block_epoch(),
            RecoveryRound::new(1),
            Vec::new(),
            cert.signers().clone(),
            cert.aggregate_sig(),
        );
        assert!(!verify_recovery_cert(&rebadged, &net(), &pool, None));
    }

    // ─── select_winning_block ────────────────────────────────────────────

    use hyperscale_types::{BeaconBlock, recovery_cert_hash};

    /// Build a `BeaconBlock` for `epoch` whose header's
    /// `state_root` is keyed off `state_byte` (so two callers can
    /// build distinct blocks at the same epoch with predictable
    /// hash ordering). Aggregate sig is zero — the selection rule
    /// doesn't re-verify signatures, only inspects the
    /// `recovery_cert` field and the block hash.
    fn block(epoch: u64, state_byte: u8, cert: Option<RecoveryCertificate>) -> BeaconBlock {
        let header = BeaconBlockHeader::new(
            Epoch::new(epoch),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            BeaconProposalsRoot::from_raw(Hash::from_bytes(b"proposals")),
            BeaconStateRoot::from_raw(Hash::from_bytes(&[state_byte; 8])),
            recovery_cert_hash(cert.as_ref()),
        );
        BeaconBlock::new(
            header,
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
            cert,
        )
    }

    /// Helper: synthesize a cert at the given round. Signature bytes
    /// are zero — selection doesn't re-verify.
    fn cert(round: u32) -> RecoveryCertificate {
        RecoveryCertificate::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(0),
            RecoveryRound::new(round),
            Vec::new(),
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
        )
    }

    /// A cert-bearing block wins over a no-cert block at the same epoch
    /// regardless of argument order.
    #[test]
    fn select_cert_bearing_wins_over_no_cert() {
        let with_cert = block(7, 0xAA, Some(cert(0)));
        let no_cert = block(7, 0xBB, None);
        assert_eq!(
            select_winning_block(&with_cert, &no_cert).block_hash(),
            with_cert.block_hash(),
        );
        assert_eq!(
            select_winning_block(&no_cert, &with_cert).block_hash(),
            with_cert.block_hash(),
        );
    }

    /// Among two cert-bearing blocks at the same epoch, the higher
    /// `recovery_round` wins regardless of argument order.
    #[test]
    fn select_higher_round_wins_among_cert_bearing() {
        let round_0 = block(7, 0xAA, Some(cert(0)));
        let round_3 = block(7, 0xBB, Some(cert(3)));
        assert_eq!(
            select_winning_block(&round_0, &round_3).block_hash(),
            round_3.block_hash(),
        );
        assert_eq!(
            select_winning_block(&round_3, &round_0).block_hash(),
            round_3.block_hash(),
        );
    }

    /// Final tie-break: lower block hash wins, regardless of argument
    /// order. The chosen winner is the same block whichever order the
    /// caller supplies.
    #[test]
    fn select_tie_break_by_lower_block_hash() {
        let a = block(7, 0x01, None);
        let b = block(7, 0xFE, None);
        let lower = a.block_hash().min(b.block_hash());
        assert_eq!(select_winning_block(&a, &b).block_hash(), lower);
        assert_eq!(select_winning_block(&b, &a).block_hash(), lower);
    }

    /// Tie on `recovery_round` (both cert-bearing at same round) falls
    /// through to the lower-hash tie-break.
    #[test]
    fn select_tie_break_among_same_round_cert_bearing() {
        let a = block(7, 0x01, Some(cert(2)));
        let b = block(7, 0xFE, Some(cert(2)));
        let lower = a.block_hash().min(b.block_hash());
        assert_eq!(select_winning_block(&a, &b).block_hash(), lower);
        assert_eq!(select_winning_block(&b, &a).block_hash(), lower);
    }

    /// Cross-epoch comparison is a programmer error — the rule is
    /// scoped to same-epoch race resolution.
    #[test]
    #[should_panic(expected = "cross-epoch comparison")]
    fn select_panics_on_cross_epoch() {
        let a = block(7, 0xAA, None);
        let b = block(8, 0xBB, None);
        let _ = select_winning_block(&a, &b);
    }
}
