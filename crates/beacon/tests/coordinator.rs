//! End-to-end multi-coordinator integration tests.
//!
//! Drives an n=4 cluster of [`BeaconCoordinator`]s through several
//! epochs and pins the load-bearing invariants of the local commit
//! loop: every replica commits the same block per epoch, advances to a
//! byte-identical [`BeaconState`], and the SPC instance bootstraps the
//! next epoch automatically once `OutputHigh` fires.

mod common;

use std::sync::Arc;

use common::{ByzantineBehaviour, CoordinatorSim};
use hyperscale_core::Action;
use hyperscale_types::{
    BlockHash, BoundedVec, Epoch, LeafIndex, ShardGroupId, ShardWitness, ShardWitnessPayload,
    ShardWitnessProof, ValidatorId, Witness,
};

/// Three epochs is enough to exercise the closed loop more than once:
/// the first epoch's commit chains into the second epoch's
/// `try_propose`, which only happens correctly if the post-commit
/// committee re-bootstrap and proposal-pool reset are sound.
const TARGET_COMMITS: usize = 3;

/// Step budget tuned to the cost of one epoch's traffic: per epoch
/// every replica fans out 4 proposals plus 3 PC vote rounds, with the
/// SPC cert ride-along on the broadcast block. ~300 deliveries per
/// epoch comfortably under this cap.
const MAX_STEPS: usize = 10_000;

#[test]
fn four_party_cluster_converges_on_per_epoch_state() {
    let mut sim = CoordinatorSim::new(4, 0xC0_0D);
    sim.kick_off();
    let steps = sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    let counts: Vec<usize> = sim.commits.iter().map(Vec::len).collect();
    assert!(
        counts.iter().all(|c| *c >= TARGET_COMMITS),
        "not every replica reached {TARGET_COMMITS} commits in {steps} steps: {counts:?}",
    );

    // Per-epoch consensus invariants: every replica committed the
    // same epoch, the same `committed_proposals` set (sorted by
    // validator id), and lands at byte-identical `BeaconState`. The
    // wrapping SPC cert is a different aggregate per replica (each
    // assembles its own QC3 from the first quorum it sees, so the
    // BLS aggregate differs) and therefore the surrounding
    // `block_hash` also differs — but the consensus output and
    // post-apply state are what the chain depends on.
    for e in 0..TARGET_COMMITS {
        let reference = &sim.commits[0][e];
        let expected_epoch = Epoch::new(e as u64 + 1);
        assert_eq!(
            reference.epoch, expected_epoch,
            "replica 0's commit {e} is not at expected epoch {expected_epoch:?}",
        );
        let mut ref_proposals: Vec<_> = reference.block.committed_proposals().to_vec();
        ref_proposals.sort_by_key(|(id, _)| id.inner());
        for r in 1..sim.n() {
            let cmp = &sim.commits[r][e];
            assert_eq!(
                cmp.epoch, reference.epoch,
                "replica {r} committed epoch {:?} at slot {e}, expected {:?}",
                cmp.epoch, reference.epoch,
            );
            let mut cmp_proposals: Vec<_> = cmp.block.committed_proposals().to_vec();
            cmp_proposals.sort_by_key(|(id, _)| id.inner());
            assert_eq!(
                cmp_proposals, ref_proposals,
                "replica {r} committed proposal set differs from replica 0 at epoch {:?}",
                reference.epoch,
            );
            assert_eq!(
                cmp.state, reference.state,
                "replica {r} state differs from replica 0 at epoch {:?}",
                reference.epoch,
            );
        }
    }
}

#[test]
fn cluster_commits_non_empty_proposal_set_per_epoch() {
    // The two-tier queue ordering is what makes view-1 PC inputs full
    // vectors instead of per-validator singletons. This test pins the
    // resulting protocol property: every committed beacon block carries
    // every honest replica's proposal. If the sim ever regresses to
    // "self-first" delivery, view-1 PC collapses to all-`HASH_BOTTOM`s,
    // `committed_proposals` empties, and this test catches it.
    let mut sim = CoordinatorSim::new(4, 0xBE_AC);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    let first_commit = &sim.commits[0][0];
    assert!(
        first_commit.state.last_recovery_cert.is_none(),
        "honest-path commit unexpectedly carries a recovery cert",
    );
    assert_eq!(
        first_commit.block.committed_proposals().len(),
        sim.n(),
        "committed block dropped proposals — view-1 PC may have collapsed",
    );
}

#[test]
fn adoption_path_advances_non_participating_replica() {
    // Sim A: full honest path → capture the committed block to feed
    // into a stand-alone replica B.
    let seed = 0xADD0;
    let mut sim_a = CoordinatorSim::new(4, seed);
    sim_a.kick_off();
    sim_a.run_until_committed(1, MAX_STEPS);
    let peer_block = Arc::clone(&sim_a.commits[0][0].block);
    let expected_state = sim_a.commits[0][0].state.clone();

    // Sim B: byte-identical setup so the genesis state and committee
    // match. Don't kick off — replica 0 should adopt the broadcast
    // block straight from the inbound handler without ever running its
    // own SPC.
    let mut sim_b = CoordinatorSim::new(4, seed);
    assert!(sim_b.commits[0].is_empty());
    let actions = sim_b.deliver_block_to(0, Arc::clone(&peer_block));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
        "expected CommitBeaconBlock in {actions:?}",
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBeaconBlock { .. })),
        "adoption path must not re-broadcast: {actions:?}",
    );
    assert_eq!(sim_b.commits[0].len(), 1);
    let adopted = &sim_b.commits[0][0];
    assert_eq!(adopted.block.block_hash(), peer_block.block_hash());
    assert_eq!(adopted.state, expected_state);
}

// ─── Byzantine + topology-change primitive hooks ──────────────────────────────
//
// These tests prove each adversarial hook fires when set; the protocol-level
// scenarios that exercise the resulting Byzantine state machine paths live in
// the broader Phase 3 sim suite.

#[test]
fn drop_for_consumes_envelopes_addressed_to_target_without_delivery() {
    let mut sim = CoordinatorSim::new(4, 0xD_0_0_0);
    // Schedule 10 drops for replica 1 — comfortably more than will land
    // during a kick-off-only run, so the counter must end below the
    // budget by however many envelopes the network queue routed there.
    sim.drop_for(ValidatorId::new(1), 10);
    sim.kick_off();
    // Step a few times to drain proposals addressed to replica 1.
    for _ in 0..8 {
        if !sim.step() {
            break;
        }
    }
    assert!(
        sim.drop_counters[1] < 10,
        "drop_for didn't fire — drop_counters[1] = {} (expected < 10)",
        sim.drop_counters[1],
    );
    assert_eq!(
        sim.drop_counters[0], 0,
        "untargeted replica's counter moved"
    );
}

#[test]
fn with_byzantine_equivocate_proposal_fires_once_and_clears() {
    let mut sim = CoordinatorSim::new(4, 0xEB_AD);
    sim.with_byzantine(ValidatorId::new(0), ByzantineBehaviour::EquivocateProposal);
    sim.kick_off();
    // Kick-off triggers each replica's epoch-1 `BuildAndBroadcastBeaconProposal`,
    // so the byzantine transform fires inside replica 0's `absorb_one`.
    assert_eq!(
        sim.byzantine_fires[0], 1,
        "equivocating proposer didn't fire on kick-off",
    );
    assert_eq!(
        sim.byzantine_fires[1], 0,
        "byzantine fire counter leaked to a non-flagged replica",
    );
    // Second kick-off-equivalent event would NOT re-fire — the
    // transform is one-shot. Re-flag and verify a second fire is
    // possible.
    sim.with_byzantine(ValidatorId::new(0), ByzantineBehaviour::EquivocateProposal);
    // Drain the queue so a fresh `BuildAndBroadcastBeaconProposal` for
    // epoch 2 surfaces via the natural commit-and-roll-forward path.
    sim.run_until_committed(2, 10_000);
    assert_eq!(
        sim.byzantine_fires[0], 2,
        "re-flagged byzantine didn't fire on the next proposal",
    );
}

#[test]
fn with_byzantine_equivocate_pc_vote1_fires_once() {
    let mut sim = CoordinatorSim::new(4, 0xEBE1);
    sim.with_byzantine(ValidatorId::new(0), ByzantineBehaviour::EquivocatePcVote1);
    sim.kick_off();
    // Run until replica 0 has emitted a round-1 vote — usually within
    // a few steps after the SPC instance bootstraps view 1.
    let mut steps = 0;
    while sim.byzantine_fires[0] == 0 {
        assert!(steps < 200, "byzantine PC vote1 never fired");
        assert!(sim.step(), "sim went quiescent before vote1 emission");
        steps += 1;
    }
    assert_eq!(sim.byzantine_fires[0], 1, "fired more than once");
}

#[test]
fn inject_topology_change_splices_witnesses_into_epoch_one_proposal() {
    let mut sim = CoordinatorSim::new(4, 0x_E_1_C_4);
    // Use a Ready witness for validator 0 — purely structural; the
    // assertion is on the witness being present in the committed
    // block's proposal set, not on its semantic effect.
    let witness = Witness::Shard(make_dummy_ready_witness(0));
    sim.inject_topology_change(Epoch::new(1), vec![witness.clone()]);
    sim.kick_off();
    sim.run_until_committed(1, 10_000);

    let commit = &sim.commits[0][0];
    let any_proposal_has_witness = commit
        .block
        .committed_proposals()
        .iter()
        .any(|(_, prop)| {
            prop.witnesses()
                .iter()
                .any(|w| matches!(w, Witness::Shard(sw) if sw.proof.leaf_index == witness_leaf_index_of(&witness)))
        });
    assert!(
        any_proposal_has_witness,
        "scheduled witness didn't survive into any committed proposal at epoch 1",
    );
}

const fn make_dummy_ready_witness(leaf_index: u64) -> ShardWitness {
    ShardWitness {
        payload: ShardWitnessPayload::Ready {
            id: ValidatorId::new(0),
        },
        proof: ShardWitnessProof {
            shard_id: ShardGroupId::new(0),
            committed_block_hash: BlockHash::ZERO,
            leaf_index: LeafIndex::new(leaf_index),
            siblings: BoundedVec::new(),
        },
    }
}

fn witness_leaf_index_of(w: &Witness) -> LeafIndex {
    match w {
        Witness::Shard(sw) => sw.proof.leaf_index,
        Witness::Beacon(_) => panic!("expected a shard witness"),
    }
}
