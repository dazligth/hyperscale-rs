//! Conflicting-commit (fork) reproduction for the shard consensus
//! vote-unlock + commit rule.
//!
//! Two honest coordinators commit different blocks at the same height
//! under an adversarial — but honest-validator — delivery schedule.
//! This falsifies the "conflicting blocks cannot both get QCs by quorum
//! intersection" claim in `lib.rs`: the height-level vote lock is
//! released on a local timeout (no timeout certificate), so an
//! overlapping honest quorum signs two sibling blocks at one height,
//! and the round-agnostic two-chain commit then finalizes both.
//!
//! The test asserts the fork IS observed — it pins the current unsafe
//! behaviour. When the consensus rule is hardened (locked-QC + safe-vote
//! rule + round-contiguous commit), this reproduction stops forking;
//! flip the final assertion to require no fork at that point.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::{HoldFilter, ShardCoordinatorSim};
use hyperscale_types::{BlockHash, BlockHeight, Round, ValidatorId};

const MAX_STEPS: usize = 5_000;
const PAST_TIMEOUT: Duration = Duration::from_secs(12);

/// First height at which two replicas committed different blocks.
fn find_fork(sim: &ShardCoordinatorSim) -> Option<(BlockHeight, BlockHash, BlockHash)> {
    let mut seen: HashMap<BlockHeight, BlockHash> = HashMap::new();
    for replica in &sim.commits {
        for c in replica {
            match seen.insert(c.height, c.block_hash) {
                Some(prev) if prev != c.block_hash => return Some((c.height, prev, c.block_hash)),
                _ => {}
            }
        }
    }
    None
}

/// Committed `block_hash` at `height` on `replica`, if any.
fn committed_block(
    sim: &ShardCoordinatorSim,
    replica: usize,
    height: BlockHeight,
) -> Option<BlockHash> {
    sim.commits[replica]
        .iter()
        .find(|c| c.height == height)
        .map(|c| c.block_hash)
}

/// n=4 (f=1, quorum=3). Validators are all honest; the adversary is the
/// scheduler. Proposer for `(height, round)` is `committee[(height+round) % 4]`.
///
/// Branch A is led by V1, branch B by V2; V0 and V3 are the swing voters
/// forced into the overlap of every quorum. The schedule:
///
/// 1. V1 proposes A at (1,0); V0/V1/V3 vote it; V1 aggregates `QC_A`.
/// 2. A local timeout releases V0/V3's h=1 lock with no QC seen. V2
///    proposes B at (1,1); V0/V2/V3 vote it; V2 aggregates `QC_B`. Two QCs
///    now certify sibling blocks A != B at height 1.
/// 3. V1 proposes A2 (child of A) at (2,3); V0/V3 adopt `QC_A` and vote A2;
///    V1 aggregates `QC_A2` and two-chain-commits A at height 1.
/// 4. A timeout releases V0/V3's h=2 lock; V2 proposes B2 (child of B) at
///    (2,4); V0/V3 vote B2; V2 aggregates `QC_B2` and commits B at height 1.
#[test]
fn vote_unlock_admits_conflicting_commits_at_one_height() {
    let mut sim = ShardCoordinatorSim::new(4, 0xF0_4B);
    let v: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
    let (h1, h2) = (BlockHeight::new(1), BlockHeight::new(2));

    // Branch isolation: V1 never sees branch B's headers, V2 never sees
    // branch A's — so neither leader adopts the other's QC and abandons
    // its branch.
    sim.hold_matching(v[1], HoldFilter::BlockHeaderFromProposer(v[2]));
    sim.hold_matching(v[2], HoldFilter::BlockHeaderFromProposer(v[1]));
    // Per-QC aggregation isolation: each block's votes reach only its
    // intended aggregator, so exactly one QC forms per block.
    let route = |sim: &mut ShardCoordinatorSim, height, round: u64, except: usize| {
        for (idx, &val) in v.iter().enumerate() {
            if idx != except {
                sim.hold_matching(
                    val,
                    HoldFilter::VoteAtHeightRound(height, Round::new(round)),
                );
            }
        }
    };
    route(&mut sim, h1, 0, 1); // A  votes -> V1
    route(&mut sim, h1, 1, 2); // B  votes -> V2
    route(&mut sim, h2, 3, 1); // A2 votes -> V1
    route(&mut sim, h2, 4, 2); // B2 votes -> V2

    // Round 0: V1 proposes A; V0/V1/V3 vote; V1 forms QC_A.
    sim.kick_off();
    sim.run_for_at_most(MAX_STEPS);

    // Round 1: timeout unlocks V0/V3 at h=1; V2 proposes B; V2 forms QC_B.
    sim.advance_clock(PAST_TIMEOUT);
    sim.fire_view_change_timer_all();
    sim.propose_on(v[2]);
    sim.run_for_at_most(MAX_STEPS);

    let qc_a = sim.coordinators[1].latest_qc().map(|q| q.block_hash());
    let qc_b = sim.coordinators[2].latest_qc().map(|q| q.block_hash());
    assert_eq!(
        sim.coordinators[1].latest_qc().map(|q| q.height()),
        Some(h1)
    );
    assert_eq!(
        sim.coordinators[2].latest_qc().map(|q| q.height()),
        Some(h1)
    );
    assert!(
        qc_a.is_some() && qc_a != qc_b,
        "expected two distinct QCs at height 1 (got {qc_a:?} / {qc_b:?})",
    );

    // Branch A child: V1 -> view 3 (its h=2 slot), proposes A2; V0/V3 adopt
    // QC_A and vote A2; V1 forms QC_A2 and commits A.
    for _ in 0..2 {
        sim.advance_clock(PAST_TIMEOUT);
        sim.fire_view_change_timer(v[1]);
    }
    sim.propose_on(v[1]);
    sim.run_for_at_most(MAX_STEPS);

    // Branch B child: release V0/V3's h=2 lock (one round each keeps them off
    // their own h=2 proposer slots), advance V2 to its h=2 slot (view 4),
    // propose B2; V0/V3 vote it; V2 forms QC_B2 and commits B.
    sim.advance_clock(PAST_TIMEOUT);
    sim.fire_view_change_timer(v[0]);
    sim.fire_view_change_timer(v[3]);
    for _ in 0..3 {
        sim.advance_clock(PAST_TIMEOUT);
        sim.fire_view_change_timer(v[2]);
    }
    sim.propose_on(v[2]);
    sim.run_for_at_most(MAX_STEPS);

    // V1 committed block A at height 1; V2 committed a different block B.
    let v1_h1 = committed_block(&sim, 1, h1);
    let v2_h1 = committed_block(&sim, 2, h1);
    assert_eq!(v1_h1, qc_a, "V1 should have committed branch A at height 1");
    assert_eq!(v2_h1, qc_b, "V2 should have committed branch B at height 1");

    let fork = find_fork(&sim);
    assert!(
        fork.is_some(),
        "expected the vote-unlock fork to reproduce — two honest replicas \
         committing different blocks at one height. None observed: the safety \
         gap may now be closed, in which case this assertion should require \
         find_fork(&sim).is_none() instead.",
    );
    let (height, a, b) = fork.unwrap();
    assert_eq!(height, h1);
    assert_ne!(a, b);
}
