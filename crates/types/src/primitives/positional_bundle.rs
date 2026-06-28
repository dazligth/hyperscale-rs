//! Positional `(SignerBitfield, parallel-item)` bundle.

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::primitives::signer_bitfield::MAX_SIGNERS;
use crate::{BoundedVec, SignerBitfield};

/// A signer bitfield paired with one item per set bit, in set-bit order.
///
/// Replaces `Vec<(ValidatorId, T)>` shapes whose validator field is
/// purely positional metadata against the committee enumeration. The
/// bitfield carries identity; the parallel `items` vector carries
/// per-signer payload. Consumers iterate via [`iter`](Self::iter),
/// resolving each `(committee_index, &item)` pair through the committee
/// they already hold.
///
/// # Invariants
///
/// - `items.len() == signers.count_ones()`. Enforced at decode time.
/// - Pairing is positional: the k-th item belongs to the k-th set bit
///   in `signers.set_indices()` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionalBundle<T> {
    signers: SignerBitfield,
    items: BoundedVec<T, MAX_SIGNERS>,
}

impl<T> PositionalBundle<T> {
    /// Build a `PositionalBundle` from a bitfield and matching items.
    ///
    /// # Panics
    ///
    /// Panics if `items.len() != signers.count_ones()` or if `items.len() > MAX_SIGNERS`.
    #[must_use]
    pub fn new(signers: SignerBitfield, items: Vec<T>) -> Self {
        assert_eq!(
            items.len(),
            signers.count_ones(),
            "PositionalBundle: items length must match signer count",
        );
        Self {
            signers,
            items: items.into(),
        }
    }

    /// Empty bundle (no signers, no items).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            signers: SignerBitfield::empty(),
            items: BoundedVec::new(),
        }
    }

    /// Signer bitfield.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Number of `(index, item)` pairs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the bundle is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterate `(committee_index, &item)` pairs in set-bit order.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> + '_ {
        self.signers.set_indices().zip(self.items.iter())
    }

    /// Borrow the items as a slice, in set-bit order.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }
}

// Manual SBOR impl — the cross-field invariant `items.len() ==
// signers.count_ones()` doesn't fit a derive. Without the check a peer
// can supply mismatched lengths and downstream `iter()` produces a
// silently truncated stream.

impl<T, E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for PositionalBundle<T>
where
    T: Encode<NoCustomValueKind, E> + Categorize<NoCustomValueKind>,
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.signers)?;
        encoder.encode(&self.items)?;
        Ok(())
    }
}

impl<T, D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for PositionalBundle<T>
where
    T: Decode<NoCustomValueKind, D> + Categorize<NoCustomValueKind>,
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let signers: SignerBitfield = decoder.decode()?;
        let items: BoundedVec<T, MAX_SIGNERS> = decoder.decode()?;
        if items.len() != signers.count_ones() {
            return Err(DecodeError::InvalidCustomValue);
        }
        Ok(Self { signers, items })
    }
}

impl<T> Categorize<NoCustomValueKind> for PositionalBundle<T> {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl<T> Describe<NoCustomTypeKind> for PositionalBundle<T> {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("PositionalBundle", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    fn bitfield(num_validators: usize, set: &[usize]) -> SignerBitfield {
        let mut bf = SignerBitfield::new(num_validators);
        for &i in set {
            bf.set(i);
        }
        bf
    }

    #[test]
    fn new_pairs_items_with_set_bits_in_order() {
        let bf = bitfield(10, &[1, 4, 7]);
        let bundle = PositionalBundle::new(bf, vec!["a", "b", "c"]);
        let pairs: Vec<_> = bundle.iter().collect();
        assert_eq!(pairs, vec![(1, &"a"), (4, &"b"), (7, &"c")]);
    }

    #[test]
    #[should_panic(expected = "items length must match signer count")]
    fn new_panics_on_length_mismatch() {
        let bf = bitfield(10, &[1, 4, 7]);
        let _ = PositionalBundle::new(bf, vec!["a", "b"]);
    }

    #[test]
    fn empty_bundle_iterates_nothing() {
        let bundle: PositionalBundle<u32> = PositionalBundle::empty();
        assert!(bundle.is_empty());
        assert_eq!(bundle.iter().count(), 0);
    }

    #[test]
    fn sbor_round_trip() {
        let bf = bitfield(100, &[3, 50, 99]);
        let bundle = PositionalBundle::new(bf, vec![10u32, 20, 30]);
        let bytes = basic_encode(&bundle).unwrap();
        let decoded: PositionalBundle<u32> = basic_decode(&bytes).unwrap();
        assert_eq!(bundle, decoded);
        let pairs: Vec<_> = decoded.iter().collect();
        assert_eq!(pairs, vec![(3, &10), (50, &20), (99, &30)]);
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // Forge a tuple with bitfield count_ones=3 but items.len()=2.
        let bf = bitfield(10, &[0, 1, 2]);
        let items: BoundedVec<u32, MAX_SIGNERS> = vec![1u32, 2].into();
        let attacker = ManualBundle { signers: bf, items };
        let bytes = basic_encode(&attacker).unwrap();
        let err = basic_decode::<PositionalBundle<u32>>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    #[test]
    fn decode_accepts_canonical_match() {
        let bf = bitfield(10, &[0, 1, 2]);
        let items: BoundedVec<u32, MAX_SIGNERS> = vec![1u32, 2, 3].into();
        let canonical = ManualBundle { signers: bf, items };
        let bytes = basic_encode(&canonical).unwrap();
        let decoded: PositionalBundle<u32> = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 3);
    }

    /// Mirror of `PositionalBundle`'s wire layout for forging test
    /// payloads.
    #[derive(BasicSbor)]
    struct ManualBundle {
        signers: SignerBitfield,
        items: BoundedVec<u32, MAX_SIGNERS>,
    }
}
