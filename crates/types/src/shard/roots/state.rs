//! State-root verification typestate.
//!
//! [`StateRoot`] is verified by replaying a block's finalized waves
//! against the JMT rooted at the parent's state root and comparing the
//! resulting root against the header's claim. The JMT replay itself
//! happens inside the storage backend's `prepare_block_commit`; the
//! verifier here is a thin equality check.
//!
//! The replay's other byproduct — the [`PreparedCommit`] closure — is
//! orthogonal `IoLoop` pipeline data, not part of the verification
//! predicate. The action handler routes it through `commit_prepared`
//! separately from the verified handle. Predicate at
//! [`impl Verify<StateRootContext>`](Verify::verify) below.
//!
//! [`StateRoot`]: crate::StateRoot
//! [`PreparedCommit`]: crate::PreparedCommit

use thiserror::Error;

use crate::{StateRoot, Verified, Verify};

/// Inputs the [`StateRoot`] verifier checks against.
///
/// [`StateRoot`]: crate::StateRoot
pub struct StateRootContext {
    /// Root produced by replaying the block's finalized waves against
    /// the JMT.
    pub computed_root: StateRoot,
}

/// Failure modes of [`StateRoot`] verification.
///
/// [`StateRoot`]: crate::StateRoot
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum StateRootVerifyError {
    /// JMT replay computed a different root than the header claimed.
    /// Distinguishes a Byzantine proposer from an honest one; the
    /// receipt-root pre-flight check (run before this verifier on the
    /// shared dispatch path) already eliminates the
    /// receipts-don't-match case.
    #[error("computed state root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed state root.
        expected: StateRoot,
        /// Root produced by replaying receipts against the JMT.
        computed: StateRoot,
    },
}

impl Verified<StateRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: an earlier verifier
    /// run already accepted `root` (success path of
    /// [`<StateRoot as Verify>::verify`](Verify::verify)).
    #[must_use]
    pub const fn from_pipeline_attestation(root: StateRoot) -> Self {
        Self::new_unchecked(root)
    }
}

/// Construction asserts: the supplied `computed_root` (produced by
/// replaying the block's finalized waves against the JMT rooted at the
/// parent's state root) equals the wrapped [`StateRoot`].
impl Verify<StateRootContext> for StateRoot {
    type Error = StateRootVerifyError;

    fn verify(&self, ctx: StateRootContext) -> Result<Verified<Self>, Self::Error> {
        if ctx.computed_root != *self {
            return Err(StateRootVerifyError::Mismatch {
                expected: *self,
                computed: ctx.computed_root,
            });
        }
        Ok(Verified::new_unchecked(*self))
    }
}
