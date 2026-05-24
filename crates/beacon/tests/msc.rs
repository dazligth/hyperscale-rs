//! MSC integration tests — multi-party, multi-slot honest-path
//! convergence + Agreement on the committed slot output set.

mod common;

use std::time::Duration;

use common::{CommittedSet, MscSim};
use hyperscale_types::{PC_VALUE_ELEMENT_BYTES, PcValueElement, PcVector, Slot};

const fn elem(byte: u8) -> PcValueElement {
    PcValueElement::new([byte; PC_VALUE_ELEMENT_BYTES])
}

/// Assert that every party in `sim` committed the same `(sender,
/// content)` set for `slot`.
fn assert_agreement(sim: &MscSim, slot: Slot, n: usize) {
    let baseline: &CommittedSet = sim
        .committed_at(0, slot)
        .expect("party 0 should have committed");
    for i in 1..n {
        let other = sim
            .committed_at(i, slot)
            .unwrap_or_else(|| panic!("party {i} should have committed slot {slot:?}"));
        assert_eq!(
            other, baseline,
            "party {i}'s commit for slot {slot:?} disagrees with party 0's",
        );
    }
}

/// Honest 4-party sim, one slot. Each party feeds an input, all
/// converge on the same `SlotCommitted` set.
#[test]
fn sim_n4_single_slot_converges() {
    let mut sim = MscSim::new(4, 0xC0, Duration::from_mins(1), Duration::from_mins(1));
    for i in 0..4 {
        sim.input(i, PcVector::new([elem(u8::try_from(i).unwrap())]));
    }
    sim.run_until_quiescent(50_000);
    assert!(
        sim.all_committed(Slot::new(1)),
        "all 4 parties should commit slot 1"
    );
    assert_agreement(&sim, Slot::new(1), 4);
}

/// Honest 4-party sim, two consecutive slots. Each party feeds two
/// inputs; slot 1 commits, slot 2 auto-starts from the queued input,
/// slot 2 commits.
#[test]
fn sim_n4_two_slots_chain() {
    let mut sim = MscSim::new(4, 0xC1, Duration::from_mins(1), Duration::from_mins(1));
    for i in 0..4 {
        sim.input(i, PcVector::new([elem(0xA0_u8 + u8::try_from(i).unwrap())]));
        sim.input(i, PcVector::new([elem(0xB0_u8 + u8::try_from(i).unwrap())]));
    }
    sim.run_until_quiescent(100_000);
    assert!(sim.all_committed(Slot::new(1)));
    assert!(sim.all_committed(Slot::new(2)));
    assert_agreement(&sim, Slot::new(1), 4);
    assert_agreement(&sim, Slot::new(2), 4);
    // Sanity: the two slots committed distinct sets.
    let s1 = sim.committed_at(0, Slot::new(1)).unwrap();
    let s2 = sim.committed_at(0, Slot::new(2)).unwrap();
    assert_ne!(s1, s2);
}

/// 7-party (n=7, f=2, q=5) — catches sizing assumptions baked into
/// n=4 across the MSC + SPC + PC stack.
#[test]
fn sim_n7_single_slot_converges() {
    let mut sim = MscSim::new(7, 0xC2, Duration::from_mins(1), Duration::from_mins(1));
    for i in 0..7 {
        sim.input(i, PcVector::new([elem(0x50_u8 + u8::try_from(i).unwrap())]));
    }
    sim.run_until_quiescent(200_000);
    assert!(sim.all_committed(Slot::new(1)));
    assert_agreement(&sim, Slot::new(1), 7);
}
