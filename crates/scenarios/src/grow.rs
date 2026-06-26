//! Growing a cluster to a starting topology.
//!
//! Genesis is always a single ROOT shard; a deeper partition exists only once
//! the network has split into it. [`grow_to`] is the harness-agnostic step that
//! drives that growth, so a scenario (or a harness's `with_grown_balances`
//! constructor) reaches a multi-shard starting point the only way the network
//! ever does — by splitting — and then runs an identical body on either harness.

use std::sync::Arc;

use hyperscale_types::{BlockHeight, Epoch, ShardId};
use radix_common::network::NetworkDefinition;

use crate::query::beacon_epoch;
use crate::tx::{build_reshape_threshold_vote_tx, merge_vote_payer, validity_around};
use crate::{Budget, Cluster, epochs};

/// Epochs of lead before the threshold vote activates — enough for the vote
/// transaction to commit and fold into the tally before it is read.
const VOTE_ACTIVATE_LEAD: u64 = 4;

/// Grow the single-shard root into a uniform `target`-leaf partition through the
/// organic split lifecycle, then install `split_bytes` as the live reshape
/// threshold so the grown topology stabilizes.
///
/// Genesis is always a single ROOT shard; a deeper partition exists only once
/// the network has split into it. A scenario that needs `target` shards calls
/// this once to grow there the only way the network ever does — by splitting —
/// and then runs an identical body on either harness.
///
/// The cluster must start at a single ROOT shard with `split_bytes = 0` armed,
/// so every generation splits. This drives [`Cluster::run_until`] until all
/// `target` leaves serve and commit past genesis, then votes the threshold up to
/// `split_bytes` (activating after a short lead) so no leaf re-splits and any
/// pair a scenario later merges falls under the derived merge threshold.
///
/// `target` must be a power of two. The pump-vs-poll difference between harnesses
/// is absorbed by `run_until`, so this one definition serves both.
///
/// # Panics
///
/// Panics if `target` is not a power of two, or if the grow or threshold
/// activation misses its budget.
pub fn grow_to(c: &mut impl Cluster, target: u32, split_bytes: u64) {
    assert!(
        target.is_power_of_two(),
        "grow target must be a power of two; got {target}",
    );
    let depth = target.trailing_zeros();
    if depth > 0 {
        let leaves: Vec<ShardId> = (0..u64::from(target))
            .map(|i| ShardId::leaf(depth, i))
            .collect();
        // One generation per level of depth, budgeted generously over the
        // admission → gate → seed → child-run phases each split walks through.
        let budget = Budget((depth * 40).max(40));
        assert!(
            c.run_until(budget, |c| leaves.iter().all(|&leaf| {
                c.committed_height(leaf)
                    .is_some_and(|h| h > BlockHeight::GENESIS)
            })),
            "grow to {target} leaves did not complete within budget",
        );
    }

    // Stabilize the grown topology: vote the threshold up to `split_bytes` so the
    // grown leaves stop splitting and a later merge's derived threshold brackets
    // their byte totals.
    let payer = merge_vote_payer();
    let current = beacon_epoch(c).expect("the grow committed a beacon epoch");
    let activate_at = Epoch::new(current.inner() + VOTE_ACTIVATE_LEAD);
    let vote = build_reshape_threshold_vote_tx(
        &payer,
        split_bytes,
        activate_at,
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    c.submit(Arc::new(vote));
    assert!(
        c.run_until(epochs(12), |c| c.beacon_state().is_some_and(|state| state
            .params
            .reshape_thresholds
            .split_bytes
            == split_bytes)),
        "the reshape threshold did not activate to {split_bytes} within budget",
    );
}
