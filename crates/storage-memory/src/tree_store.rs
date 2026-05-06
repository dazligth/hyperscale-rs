//! Simple in-memory JMT tree store for simulation.
//!
//! Implements [`TreeReader`] directly over hydrated `Arc<Node>` entries —
//! no serialization layer. Thread safety is provided by the outer
//! `RwLock<SharedState>`.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_jmt::{Node, NodeKey, TreeReader};

/// Simple in-memory tree store that implements `TreeReader`.
///
/// Stores hydrated JMT nodes directly (no serialization layer).
/// Thread safety is handled by the outer `RwLock<SharedState>`.
pub struct SimTreeStore {
    nodes: HashMap<NodeKey, Arc<Node>>,
}

impl SimTreeStore {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: NodeKey, node: Arc<Node>) {
        self.nodes.insert(key, node);
    }

    pub fn remove(&mut self, key: &NodeKey) {
        self.nodes.remove(key);
    }
}

impl TreeReader for SimTreeStore {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        self.nodes.get(key).cloned()
    }

    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        let root = NodeKey::root(version);
        if self.nodes.contains_key(&root) {
            Some(root)
        } else {
            None
        }
    }
}
