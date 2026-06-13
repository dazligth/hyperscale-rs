//! Per-shard settled-set reconstruction host.
//!
//! When a remote shard P terminates at a split, a surviving counterpart
//! must learn `S_P` — the wave-ids P settled at or before its terminal
//! block — so the split-boundary fence can resolve cross-shard
//! `FinalizedWave`s naming P (see [`SettledSetBuilder`]). This host owns
//! one [`SettledSetBuilder`] per past-terminal shard and the scheduling
//! around it: which peer to ask, when to re-arm a stalled walk, and when
//! the walk is complete.
//!
//! Sans-io like the [`Sync`](super::sync) FSMs: methods fold an input and
//! return [`SettledSetOutput`]s the I/O glue turns into network requests
//! and a `SettledWavesReconstructed` event. A healthy walk advances at
//! network round-trip speed — each accepted block immediately fetches the
//! next — while a stall (peer doesn't hold the height, transport failure)
//! rotates the peer and waits for the next `FetchTick` rather than
//! spinning.
//!
//! [`SettledSetBuilder`]: crate::bootstrap::settled_set::SettledSetBuilder

use std::collections::{BTreeSet, HashMap};

use hyperscale_types::network::request::GetSettledWavesRequest;
use hyperscale_types::network::response::GetSettledWavesResponse;
use hyperscale_types::{BlockHash, BlockHeight, ShardId, ValidatorId, WaveId, WeightedTimestamp};

use crate::bootstrap::settled_set::{SettledOutcome, SettledSetBuilder};

/// One in-flight reconstruction of a terminated shard's settled set.
struct SettledSetDriver {
    /// The backward-walk sequencer over P's tail chain.
    builder: SettledSetBuilder,
    /// P's terminal block hash — identifies which terminal this driver
    /// targets, so a duplicate start for the same terminal is a no-op.
    terminal_block_hash: BlockHash,
    /// P's terminal committee, asked in rotation. Empty falls back to
    /// shard-routed peer selection.
    peers: Vec<ValidatorId>,
    /// P's terminal weighted timestamp — carried into the completion
    /// event to bound the fence's retention cutoff.
    terminal_wt: WeightedTimestamp,
    /// Rotates through `peers` on each stall.
    cursor: usize,
}

impl SettledSetDriver {
    /// The next fetch this driver wants, or `None` while a request is
    /// outstanding or the walk is complete.
    fn next_fetch(&mut self, shard: ShardId) -> Option<SettledSetOutput> {
        let request = self.builder.next_request()?;
        let peer = if self.peers.is_empty() {
            None
        } else {
            Some(self.peers[self.cursor % self.peers.len()])
        };
        Some(SettledSetOutput::Fetch {
            shard,
            peer,
            request,
        })
    }
}

/// What the I/O glue should do after folding an input into the host.
pub enum SettledSetOutput {
    /// Issue this settled-waves fetch against `shard`'s terminal
    /// committee, biased to `peer`.
    Fetch {
        /// The terminated shard being reconstructed.
        shard: ShardId,
        /// Preferred terminal-committee member, or `None` to route by
        /// shard alone.
        peer: Option<ValidatorId>,
        /// The block fetch the builder wants next.
        request: GetSettledWavesRequest,
    },
    /// The walk reached the start height — `S_P` is complete.
    Complete {
        /// The terminated shard whose settled set this is.
        shard: ShardId,
        /// Wave-ids `shard` settled at or before its terminal block.
        waves: BTreeSet<WaveId>,
        /// `shard`'s terminal weighted timestamp.
        terminal_wt: WeightedTimestamp,
    },
}

/// Drives a [`SettledSetBuilder`] per past-terminal shard. One per
/// [`ShardIo`](super::ShardIo); shared across the shard's vnodes, so a
/// duplicate start for an already-targeted terminal is deduplicated.
#[derive(Default)]
pub struct SettledSetSyncHost {
    drivers: HashMap<ShardId, SettledSetDriver>,
}

impl SettledSetSyncHost {
    /// An empty host.
    #[must_use]
    pub fn new() -> Self {
        Self {
            drivers: HashMap::new(),
        }
    }

    /// True while any reconstruction is unfinished — keeps the shard's
    /// `FetchTick` alive so stalled walks re-arm.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.drivers.is_empty()
    }

    /// Begin reconstructing `shard`'s settled set from its terminal
    /// anchor. A start for a terminal already in flight is a no-op (the
    /// shard's vnodes each emit the trigger). A start naming a different
    /// terminal block — the earliest coast header revised which block is
    /// `B` — replaces the running driver.
    pub fn start(
        &mut self,
        shard: ShardId,
        terminal_height: BlockHeight,
        terminal_block_hash: BlockHash,
        terminal_wt: WeightedTimestamp,
        peers: Vec<ValidatorId>,
        start_height: BlockHeight,
    ) -> Vec<SettledSetOutput> {
        if self
            .drivers
            .get(&shard)
            .is_some_and(|d| d.terminal_block_hash == terminal_block_hash)
        {
            return vec![];
        }
        let mut driver = SettledSetDriver {
            builder: SettledSetBuilder::new(
                shard,
                terminal_height,
                terminal_block_hash,
                start_height,
            ),
            terminal_block_hash,
            peers,
            terminal_wt,
            cursor: 0,
        };
        let first = driver.next_fetch(shard);
        self.drivers.insert(shard, driver);
        first.into_iter().collect()
    }

    /// Fold a settled-waves response into `shard`'s walk. Accepting the
    /// last block emits `Complete`; an accepted intermediate block
    /// immediately fetches the next; a not-yet-available or rejected
    /// response rotates the peer and waits for the next tick.
    pub fn on_response(
        &mut self,
        shard: ShardId,
        response: &GetSettledWavesResponse,
    ) -> Vec<SettledSetOutput> {
        let Some(driver) = self.drivers.get_mut(&shard) else {
            return vec![];
        };
        match driver.builder.on_response(response) {
            SettledOutcome::Accepted => {
                if !driver.builder.is_complete() {
                    return driver.next_fetch(shard).into_iter().collect();
                }
            }
            SettledOutcome::NotYetAvailable | SettledOutcome::Rejected(_) => {
                driver.cursor = driver.cursor.wrapping_add(1);
                return vec![];
            }
        }
        let driver = self
            .drivers
            .remove(&shard)
            .expect("just matched as present");
        vec![SettledSetOutput::Complete {
            shard,
            waves: driver.builder.into_settled(),
            terminal_wt: driver.terminal_wt,
        }]
    }

    /// A transport-level failure of the outstanding fetch. Re-arms the
    /// builder and rotates the peer; the next tick re-issues.
    pub fn on_failure(&mut self, shard: ShardId) {
        if let Some(driver) = self.drivers.get_mut(&shard) {
            driver.builder.on_failure();
            driver.cursor = driver.cursor.wrapping_add(1);
        }
    }

    /// Re-issue every stalled walk's next fetch. Drivers with an
    /// outstanding request emit nothing (the builder withholds while
    /// in-flight).
    pub fn on_tick(&mut self) -> Vec<SettledSetOutput> {
        let mut outputs = Vec::new();
        for (&shard, driver) in &mut self.drivers {
            if let Some(out) = driver.next_fetch(shard) {
                outputs.push(out);
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::make_test_certified;
    use hyperscale_storage::{PendingChain, ShardChainWriter};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::response::GetSettledWavesResponse;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash,
        BlockHeader, Bls12381G2Signature, BoundedVec, CertificateRoot, ChainOrigin,
        ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, Round, ShardId, SignerBitfield, StateRoot,
        TransactionRoot, TxHash, TxOutcome, ValidatorId, Verifiable, Verified, WaveCertificate,
        WaveId, WeightedTimestamp,
    };

    use super::*;
    use crate::shard_io::sync::settled_waves_serve::serve_settled_waves_request;

    const SHARD: ShardId = ShardId::ROOT;

    fn finalized_wave(height: u64) -> Arc<Verifiable<FinalizedWave>> {
        let wave = WaveId::new(SHARD, BlockHeight::new(height), BTreeSet::new());
        let ec = ExecutionCertificate::new(
            wave.clone(),
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                TxHash::from_raw(Hash::from_bytes(b"tx")),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        Arc::new(Verifiable::from(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave, vec![Arc::new(ec)])),
            vec![],
        )))
    }

    /// Commit `height` blocks (1..=count), each carrying its own settled
    /// wave, and return the storage plus the terminal block's hash.
    fn served_chain(count: u64) -> (Arc<SimShardStorage>, BlockHash) {
        let storage = Arc::new(SimShardStorage::default());
        let mut parent = BlockHash::ZERO;
        let mut terminal = BlockHash::ZERO;
        for h in 1..=count {
            let certs = [finalized_wave(h)];
            let header = BlockHeader::new(
                SHARD,
                BlockHeight::new(h),
                parent,
                QuorumCertificate::genesis(SHARD, ChainOrigin::ROOT),
                ValidatorId::new(0),
                ProposerTimestamp::from_millis(1_000 * h),
                Round::INITIAL,
                false,
                StateRoot::ZERO,
                TransactionRoot::ZERO,
                *Verified::<CertificateRoot>::compute(&certs).as_ref(),
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                std::collections::BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
            );
            let block = Block::Live {
                header,
                transactions: Arc::new(BoundedVec::new()),
                certificates: Arc::new(certs.to_vec().into()),
                provisions: Arc::new(BoundedVec::new()),
            };
            parent = block.hash();
            terminal = block.hash();
            storage.commit_block(
                &make_test_certified(block),
                &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
            );
        }
        (storage, terminal)
    }

    fn local_wave(height: u64) -> WaveId {
        WaveId::new(SHARD, BlockHeight::new(height), BTreeSet::new())
    }

    /// Drive the host against a served chain: each `Fetch` is answered by
    /// the serve handler, and the walk completes with every block's
    /// settled wave.
    #[test]
    fn reconstructs_and_completes_against_a_served_chain() {
        let (storage, terminal) = served_chain(3);
        let pending_chain = PendingChain::new(storage);

        let mut host = SettledSetSyncHost::new();
        let mut outputs = host.start(
            SHARD,
            BlockHeight::new(3),
            terminal,
            WeightedTimestamp::from_millis(9_000),
            vec![ValidatorId::new(7)],
            BlockHeight::GENESIS.next(),
        );

        let mut completed = None;
        // The walk is a chain of single fetches; answer each in turn.
        while let Some(output) = outputs.pop() {
            match output {
                SettledSetOutput::Fetch { shard, request, .. } => {
                    assert_eq!(shard, SHARD);
                    let response = serve_settled_waves_request(&pending_chain, &request);
                    outputs.extend(host.on_response(SHARD, &response));
                }
                SettledSetOutput::Complete {
                    shard,
                    waves,
                    terminal_wt,
                } => {
                    assert_eq!(shard, SHARD);
                    assert_eq!(terminal_wt, WeightedTimestamp::from_millis(9_000));
                    completed = Some(waves);
                }
            }
        }

        assert_eq!(
            completed.expect("walk completes"),
            BTreeSet::from([local_wave(1), local_wave(2), local_wave(3)]),
        );
        assert!(!host.has_pending(), "the driver is dropped on completion");
    }

    /// A not-found response parks the walk; the next tick re-issues the
    /// same height.
    #[test]
    fn not_found_parks_until_the_next_tick() {
        let mut host = SettledSetSyncHost::new();
        let outputs = host.start(
            SHARD,
            BlockHeight::new(2),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1),
            vec![ValidatorId::new(0), ValidatorId::new(1)],
            BlockHeight::GENESIS.next(),
        );
        assert!(matches!(
            outputs.as_slice(),
            [SettledSetOutput::Fetch { .. }]
        ));

        // The peer doesn't hold the height: no immediate re-issue.
        let parked = host.on_response(SHARD, &GetSettledWavesResponse::not_found());
        assert!(parked.is_empty(), "a not-found parks rather than spins");
        assert!(host.has_pending());

        // The tick re-arms the fetch (now biased to the rotated peer).
        let ticked = host.on_tick();
        assert!(matches!(
            ticked.as_slice(),
            [SettledSetOutput::Fetch { .. }]
        ));
    }

    /// A duplicate start for the same terminal is a no-op; a start for a
    /// different terminal replaces the running driver.
    #[test]
    fn dedupes_by_terminal_block() {
        let mut host = SettledSetSyncHost::new();
        let _ = host.start(
            SHARD,
            BlockHeight::new(2),
            BlockHash::from_raw(Hash::from_bytes(b"terminal-a")),
            WeightedTimestamp::from_millis(1),
            vec![],
            BlockHeight::GENESIS.next(),
        );
        let dup = host.start(
            SHARD,
            BlockHeight::new(2),
            BlockHash::from_raw(Hash::from_bytes(b"terminal-a")),
            WeightedTimestamp::from_millis(1),
            vec![],
            BlockHeight::GENESIS.next(),
        );
        assert!(dup.is_empty(), "same terminal does not restart the walk");

        let replaced = host.start(
            SHARD,
            BlockHeight::new(3),
            BlockHash::from_raw(Hash::from_bytes(b"terminal-b")),
            WeightedTimestamp::from_millis(1),
            vec![],
            BlockHeight::GENESIS.next(),
        );
        assert!(
            matches!(replaced.as_slice(), [SettledSetOutput::Fetch { request, .. }] if request.height == BlockHeight::new(3)),
            "a revised terminal restarts the walk from the new block",
        );
    }
}
