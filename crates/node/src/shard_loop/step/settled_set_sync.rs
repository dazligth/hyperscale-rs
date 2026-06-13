//! Settled-set reconstruction I/O glue.
//!
//! Bridges [`SettledSetSyncHost`](crate::shard_io::settled_set::SettledSetSyncHost)'s
//! scheduling to the network and to the state machine. The host owns the
//! backward walk; this layer turns its [`SettledSetOutput`]s into
//! `GetSettledWavesRequest` fetches and the terminal `Complete` into a
//! `SettledWavesReconstructed` event for the fence.

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::response::GetSettledWavesResponse;
use hyperscale_types::{
    BlockHash, BlockHeight, SettledWavesReveal, ShardId, ValidatorId, WeightedTimestamp,
};

use crate::shard_io::settled_set::SettledSetOutput;
use crate::shard_loop::{ShardLoop, ShardScopedInput, push_shard_input};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── Action dispatch ────────────────────────────────────────────────

    /// Handle `Action::StartSettledSetSync`: begin (or dedup) a terminated
    /// shard's settled-set reconstruction from its terminal anchor and
    /// dispatch the first fetch.
    pub(in crate::shard_loop) fn process_start_settled_set_sync(
        &mut self,
        shard: ShardId,
        terminal_height: BlockHeight,
        terminal_block_hash: BlockHash,
        terminal_wt: WeightedTimestamp,
        peers: Vec<ValidatorId>,
    ) {
        // The walk covers `[first real block, terminal]`; genesis carries
        // no certificates, so the lowest height worth fetching is the
        // first block past it.
        let start_height = BlockHeight::GENESIS.next();
        let outputs = self.io.settled_set_sync.start(
            shard,
            terminal_height,
            terminal_block_hash,
            terminal_wt,
            peers,
            start_height,
        );
        self.process_settled_set_outputs(outputs);
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Network callback: a settled-waves reveal arrived for `source_shard`
    /// (`None` when the peer didn't hold the height).
    pub(in crate::shard_loop) fn handle_settled_waves_response_received(
        &mut self,
        source_shard: ShardId,
        reveal: Option<SettledWavesReveal>,
    ) {
        let response = reveal.map_or_else(
            GetSettledWavesResponse::not_found,
            GetSettledWavesResponse::found,
        );
        let outputs = self
            .io
            .settled_set_sync
            .on_response(source_shard, &response);
        self.process_settled_set_outputs(outputs);
    }

    /// Network callback: a settled-waves fetch failed at the transport
    /// level. The host re-arms and the next `FetchTick` retries.
    pub(in crate::shard_loop) fn handle_settled_waves_fetch_failed(
        &mut self,
        source_shard: ShardId,
    ) {
        self.io.settled_set_sync.on_failure(source_shard);
    }

    /// Re-issue every stalled reconstruction's next fetch on the periodic
    /// tick.
    pub(in crate::shard_loop) fn settled_set_tick(&mut self) {
        let outputs = self.io.settled_set_sync.on_tick();
        self.process_settled_set_outputs(outputs);
    }

    // ─── Output processing ──────────────────────────────────────────────

    /// Route host outputs: `Fetch` → network request, `Complete` →
    /// `SettledWavesReconstructed` event for the fence.
    fn process_settled_set_outputs(&mut self, outputs: Vec<SettledSetOutput>) {
        let local_shard = self.shard;
        for output in outputs {
            match output {
                SettledSetOutput::Fetch {
                    shard,
                    peer,
                    request,
                } => {
                    let es = self.event_sender().clone();
                    self.process.network.request(
                        shard,
                        peer,
                        request,
                        None,
                        Box::new(move |result: Result<GetSettledWavesResponse, _>| {
                            match result {
                                Ok(response) => push_shard_input(
                                    &es,
                                    local_shard,
                                    ShardScopedInput::SettledWavesResponseReceived {
                                        source_shard: shard,
                                        reveal: response.reveal.map(Box::new),
                                    },
                                ),
                                Err(_) => push_shard_input(
                                    &es,
                                    local_shard,
                                    ShardScopedInput::SettledWavesFetchFailed {
                                        source_shard: shard,
                                    },
                                ),
                            }
                            ResponseVerdict::Accept
                        }),
                    );
                }
                SettledSetOutput::Complete {
                    shard,
                    waves,
                    terminal_wt,
                } => {
                    self.dispatch_event(ProtocolEvent::SettledWavesReconstructed {
                        shard,
                        waves,
                        terminal_wt,
                    });
                }
            }
        }
    }
}
