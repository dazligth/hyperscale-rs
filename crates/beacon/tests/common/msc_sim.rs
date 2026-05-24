//! Minimal multi-party MSC sim — drives a set of [`MscInstance`]s
//! by fan-out-broadcasting their emitted effects.
//!
//! Honest-path only: ignores `SetTimer` (no timer firing — proposals
//! always arrive before a timeout would kick in), drops
//! `Equivocation` (no equivocators), and tracks `SlotCommitted` per
//! party per slot.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_beacon::msc::{MscEffect, MscEvent, MscInstance};
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, NetworkDefinition, PcVector, Slot, ValidatorId,
    bls_keypair_from_seed,
};

struct Envelope {
    to: ValidatorId,
    event: MscEvent,
}

/// A single party's view of a committed slot — the `(sender, content)`
/// pairs it observed via [`MscEffect::SlotCommitted`].
pub type CommittedSet = Vec<(ValidatorId, PcVector)>;

pub struct MscSim {
    pub instances: Vec<MscInstance>,
    pub members: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    pub sks: Vec<Arc<Bls12381G1PrivateKey>>,
    pending: VecDeque<Envelope>,
    /// `commits[party_idx][slot]` → committed `(sender, content)` list.
    pub commits: Vec<BTreeMap<Slot, CommittedSet>>,
}

impl MscSim {
    /// Build an `n`-party sim. Each party gets a deterministic BLS
    /// keypair seeded from `(seed, validator_id)` and a fresh
    /// [`MscInstance`] with `initial_rank = [0..n]`.
    #[must_use]
    pub fn new(n: usize, seed: u64, slot_timeout: Duration, view_timeout: Duration) -> Self {
        let network = NetworkDefinition::simulator();
        let mut sks = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            let sk = bls_keypair_from_seed(&bytes);
            members.push((ValidatorId::new(i as u64), sk.public_key()));
            sks.push(Arc::new(sk));
        }
        let initial_rank: Vec<ValidatorId> = members.iter().map(|(id, _)| *id).collect();
        let instances: Vec<MscInstance> = (0..n)
            .map(|i| {
                MscInstance::new(
                    network.clone(),
                    members.clone(),
                    members[i].0,
                    Arc::clone(&sks[i]),
                    initial_rank.clone(),
                    slot_timeout,
                    view_timeout,
                )
            })
            .collect();
        let commits = vec![BTreeMap::new(); n];
        Self {
            instances,
            members,
            sks,
            pending: VecDeque::new(),
            commits,
        }
    }

    /// Feed party `idx`'s application input.
    pub fn input(&mut self, idx: usize, v: PcVector) {
        let effects = self.instances[idx].handle(MscEvent::Input(v));
        self.absorb(idx, effects);
    }

    /// Drive one pending event.
    pub fn step(&mut self) -> bool {
        let Some(env) = self.pending.pop_front() else {
            return false;
        };
        let idx = self
            .members
            .iter()
            .position(|(id, _)| *id == env.to)
            .expect("addressed party in committee");
        let effects = self.instances[idx].handle(env.event);
        self.absorb(idx, effects);
        true
    }

    /// Drive until the pending queue drains or `max_steps` is exceeded.
    ///
    /// # Panics
    ///
    /// Panics if `max_steps` is exceeded — typically a liveness bug.
    pub fn run_until_quiescent(&mut self, max_steps: usize) -> usize {
        let mut steps = 0;
        while self.step() {
            steps += 1;
            assert!(
                steps <= max_steps,
                "sim exceeded {max_steps} steps without quiescence"
            );
        }
        steps
    }

    /// Whether every party has committed `slot`.
    #[must_use]
    pub fn all_committed(&self, slot: Slot) -> bool {
        self.commits.iter().all(|c| c.contains_key(&slot))
    }

    /// Read party `idx`'s committed `(sender, content)` list for
    /// `slot`, if any.
    #[must_use]
    pub fn committed_at(&self, idx: usize, slot: Slot) -> Option<&CommittedSet> {
        self.commits[idx].get(&slot)
    }

    fn absorb(&mut self, sender_idx: usize, effects: Vec<MscEffect>) {
        for effect in effects {
            match effect {
                MscEffect::BroadcastProposal {
                    slot,
                    content,
                    accusations,
                } => {
                    let from = self.members[sender_idx].0;
                    self.fanout(sender_idx, |_| MscEvent::Proposal {
                        from,
                        slot,
                        content: content.clone(),
                        accusations: accusations.clone(),
                    });
                }
                MscEffect::BroadcastSpcMsg { slot, msg } => {
                    let from = self.members[sender_idx].0;
                    self.fanout(sender_idx, |_| MscEvent::SpcMsg {
                        from,
                        slot,
                        msg: msg.clone(),
                    });
                }
                MscEffect::SetTimer { .. } | MscEffect::Equivocation { .. } => {
                    // Honest path: no timer-driven slot starts, no
                    // equivocations to absorb.
                }
                MscEffect::SlotCommitted { slot, included } => {
                    self.commits[sender_idx].insert(slot, included);
                }
            }
        }
    }

    fn fanout(&mut self, sender_idx: usize, mut mk_event: impl FnMut(ValidatorId) -> MscEvent) {
        for (id, _) in &self.members {
            if self.members[sender_idx].0 == *id {
                continue;
            }
            self.pending.push_back(Envelope {
                to: *id,
                event: mk_event(*id),
            });
        }
    }
}
