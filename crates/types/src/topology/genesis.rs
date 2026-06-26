//! Genesis validator placement a runner projects its initial
//! [`TopologySnapshot`](super::snapshot::TopologySnapshot) from.

use std::collections::BTreeMap;

use crate::{NetworkDefinition, ShardId, ValidatorId, ValidatorSet};

/// The genesis validator placement: the Radix network, the global validator
/// set (every registered validator, seated or pooled), and the per-shard
/// seated committees.
///
/// A runner builds the genesis `BeaconState` from this and projects the
/// `TopologySnapshot` from that state, so genesis follows the same
/// `BeaconState → TopologySnapshot` direction the runtime `ArcSwap` update does.
/// The topology is always derived, never supplied alongside a beacon state it
/// has to be kept in agreement with.
#[derive(Clone, Debug)]
pub struct GenesisTopology {
    /// Radix network bound into the projected topology (the consensus-signature
    /// domain) and the genesis beacon config hash.
    pub network: NetworkDefinition,
    /// Every registered validator at genesis — seated committee members and
    /// the pooled surplus a later reshape draws its child cohort from.
    pub global_validator_set: ValidatorSet,
    /// Each genesis shard's seated committee. The keys are the genesis shard
    /// partition.
    pub shard_committees: BTreeMap<ShardId, Vec<ValidatorId>>,
}

impl GenesisTopology {
    /// Genesis with a single ROOT shard — the shape every real beacon genesis
    /// takes. The network launches at one shard and reaches a multi-shard
    /// partition only by splitting, so production never configures more than
    /// the ROOT committee here.
    ///
    /// `seated` is the ROOT committee; any registered validator absent from it
    /// starts `Pooled`. Pass every validator id to seat the whole set.
    #[must_use]
    pub fn single_shard(
        network: NetworkDefinition,
        global_validator_set: ValidatorSet,
        seated: Vec<ValidatorId>,
    ) -> Self {
        Self {
            network,
            global_validator_set,
            shard_committees: std::iter::once((ShardId::ROOT, seated)).collect(),
        }
    }

    /// Number of seated shards at genesis.
    #[must_use]
    pub fn num_shards(&self) -> u64 {
        self.shard_committees.len() as u64
    }
}
