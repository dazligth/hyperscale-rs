//! Split observer-cohort lifecycle: the admission-time draw and the
//! release that returns a cancelled reshape's cohort to the pool.
//!
//! A pending split is staffed before it executes: admission draws a
//! committee-size cohort from the free pool, assigns each member the
//! child it will sync, and carries them on the splitting shard's
//! lookahead committee as `Observing` members — visible to serving and
//! gossip, never to the consensus subset, so the shard's quorum stays
//! at target size for the whole grow.

use std::collections::BTreeMap;

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, CohortSeat, PendingReshape, ShardId, ValidatorId, ValidatorStatus,
};
use rand::RngExt;

use crate::sampling::prng_from;

/// Domain tag for the cohort draw + child assignment seed. Distinct
/// from the pool-draw and shuffle-exit tags so the three PRNG streams
/// never collide on the same `(randomness, epoch, shard)` input.
const DOMAIN_RESHAPE_COHORT: &[u8] = b"hyperscale-reshape-cohort-v1";

/// Draw a committee-size observer cohort for the pending split of
/// `target` from the free pool, assigning the first shuffled half to
/// the left child and the rest to the right.
///
/// The caller has already passed the pool gate (`pooled_validators() ≥
/// shard_size`). Each drawn validator becomes `Observing { shard:
/// target }` and joins the target's lookahead committee; the returned
/// seats record the child assignments with `ready: false`.
pub(super) fn draw_split_cohort(
    state: &mut BeaconState,
    target: ShardId,
) -> BTreeMap<ValidatorId, CohortSeat> {
    let mut pool = state.pooled_validators();
    let size = state.chain_config.shard_size as usize;
    debug_assert!(pool.len() >= size, "caller enforces the pool gate");

    let mut h = Hasher::new();
    h.update(DOMAIN_RESHAPE_COHORT);
    h.update(state.randomness.as_bytes());
    h.update(&state.current_epoch.inner().to_le_bytes());
    h.update(&target.inner().to_le_bytes());
    let mut prng = prng_from(h.finalize().as_bytes());
    for i in (1..pool.len()).rev() {
        let j = prng.random_range(0..=i);
        pool.swap(i, j);
    }
    pool.truncate(size);

    let (left, right) = target.children();
    let mut cohort = BTreeMap::new();
    for (i, id) in pool.into_iter().enumerate() {
        let child = if i < size.div_ceil(2) { left } else { right };
        cohort.insert(
            id,
            CohortSeat {
                child,
                ready: false,
            },
        );
        state
            .validators
            .get_mut(&id)
            .expect("drawn from the derived pool, must be in validators")
            .status = ValidatorStatus::Observing {
            shard: target,
            placed_at_epoch: state.current_epoch,
        };
        state
            .next_shard_committees
            .entry(target)
            .or_default()
            .members
            .push(id);
    }
    cohort
}

/// Return a cancelled or abandoned reshape's cohort to the pool: each
/// observer leaves the target's lookahead committee and goes back to
/// `Pooled`. Merges carry no cohort and release nothing.
pub(super) fn release_cohort(state: &mut BeaconState, target: ShardId, reshape: &PendingReshape) {
    let PendingReshape::Split { cohort, .. } = reshape else {
        return;
    };
    if let Some(committee) = state.next_shard_committees.get_mut(&target) {
        committee.members.retain(|m| !cohort.contains_key(m));
    }
    for id in cohort.keys() {
        let Some(rec) = state.validators.get_mut(id) else {
            continue;
        };
        if matches!(rec.status, ValidatorStatus::Observing { shard, .. } if shard == target) {
            rec.status = ValidatorStatus::Pooled;
        }
    }
}
