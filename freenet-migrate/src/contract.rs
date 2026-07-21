//! Contract state carry-forward.
//!
//! Two ways to obtain a predecessor's state:
//!
//! * **Backward-probe** (proven, UI-side): [`predecessor_ids`] reconstructs each
//!   predecessor `ContractInstanceId` from `(code_hash, params)` with no old
//!   WASM bytes; the UI GETs each, folds the first non-empty one forward, and
//!   re-PUTs under the current key.
//! * **In-contract pull** (richer, opt-in): [`resolve_predecessors`] returns a
//!   [`ValidateResult::RequestRelated`] so the node fetches the predecessor
//!   states and re-runs `validate_state`.
//!
//! Either way the fold goes through [`CarryForward::carry_forward`], whose
//! fail-closed `verify()` gate is the self-authorizing precondition made
//! mechanical.

use freenet_scaffold::ComposableState;
use freenet_stdlib::prelude::{
    ContractInstanceId, Parameters, RelatedContracts, RelatedMode, ValidateResult,
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;

use crate::error::MigrateError;
use crate::lineage::ContractLineageEntry;

/// Blanket carry-forward for any mergeable, self-authorizing contract state.
///
/// The bound `ComposableState` is the **mergeable** precondition made a compile
/// error: a contract with no defined fold cannot implement it and therefore
/// cannot call [`carry_forward`](CarryForward::carry_forward). The forced
/// `verify()` after `merge()` is the **self-authorizing** precondition: the
/// merged state must pass the successor's *own* validator, or the carry-forward
/// is refused (fail-closed). `Serialize + DeserializeOwned` are required because
/// carry-forward exists to move serializable state forward onto a new key.
///
/// # A non-`ComposableState` type cannot carry forward
///
/// ```compile_fail
/// use freenet_migrate::CarryForward;
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct NotMergeable(u32);
/// let mut a = NotMergeable(1);
/// let b = NotMergeable(2);
/// // No `ComposableState` impl for `NotMergeable`, so `CarryForward` is not
/// // implemented for it and this does not compile:
/// a.carry_forward(&b, &(), &()).unwrap();
/// ```
pub trait CarryForward: ComposableState + Serialize + DeserializeOwned {
    /// Fold `predecessor` into `self`, then re-validate `self` against its own
    /// validator. The `verify()` failure path is [`MigrateError::Verify`] — the
    /// carry-forward is rejected rather than a bad state adopted.
    ///
    /// **Atomic on `self`.** The fold and verify run against a candidate *copy*
    /// (cloned via serde, which the trait bounds guarantee); `self` is mutated
    /// only after `verify()` passes. On **any** error path — merge failure,
    /// verify failure, or a serialization error building the candidate — `self`
    /// is left byte-for-byte unchanged. So a caller that ignores the `Result`
    /// still holds its original state and cannot accidentally PUT a half-merged
    /// or invalid one.
    fn carry_forward(
        &mut self,
        predecessor: &Self,
        parent: &Self::ParentState,
        params: &Self::Parameters,
    ) -> Result<(), MigrateError> {
        let mut candidate = serde_clone(self)?;
        candidate
            .merge(parent, params, predecessor)
            .map_err(MigrateError::Merge)?;
        // Self-authorizing gate, fail-closed: the successor's validator is the
        // only integrity check on a permissionless carry-forward PUT.
        candidate
            .verify(parent, params)
            .map_err(MigrateError::Verify)?;
        // Commit only after verify passed — `self` was untouched until here.
        *self = candidate;
        Ok(())
    }

    /// Fold `predecessor` into `self` **without** the fail-closed `verify()`
    /// gate. Requires a [`PermissiveValidatorAck`], which is un-`Default`,
    /// `#[must_use]`, and only constructible through a visibly-unsafe-named
    /// function — so opting out of the gate is loud, not silent.
    ///
    /// Only correct for a contract whose validator is *known* permissive and
    /// which has some other out-of-band authorization for the incoming state.
    /// Atomic on `self` in the same sense as [`carry_forward`](Self::carry_forward):
    /// a merge failure leaves `self` unchanged.
    fn carry_forward_unverified(
        &mut self,
        predecessor: &Self,
        parent: &Self::ParentState,
        params: &Self::Parameters,
        _ack: PermissiveValidatorAck,
    ) -> Result<(), MigrateError> {
        let mut candidate = serde_clone(self)?;
        candidate
            .merge(parent, params, predecessor)
            .map_err(MigrateError::Merge)?;
        *self = candidate;
        Ok(())
    }
}

impl<T: ComposableState + Serialize + DeserializeOwned> CarryForward for T {}

/// Clone a state through serde (CBOR), so carry-forward can fold+verify a
/// candidate copy and commit to `self` only on success. Uses only the
/// `Serialize + DeserializeOwned` bounds `CarryForward` already requires (no
/// added `Clone` bound). A serialization failure surfaces as
/// [`MigrateError::Codec`], leaving `self` untouched.
fn serde_clone<T: Serialize + DeserializeOwned>(value: &T) -> Result<T, MigrateError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| MigrateError::Codec(e.to_string()))?;
    ciborium::de::from_reader(&buf[..]).map_err(|e| MigrateError::Codec(e.to_string()))
}

/// Opt-out token for [`CarryForward::carry_forward_unverified`].
///
/// Deliberately not `Default` and `#[must_use]`: holding one is an explicit
/// acknowledgement that you are skipping the self-authorizing `verify()` gate.
#[must_use = "a PermissiveValidatorAck acknowledges skipping the fail-closed verify() gate; \
              construct it only if you really intend to carry state forward unverified"]
#[derive(Debug)]
pub struct PermissiveValidatorAck(());

impl PermissiveValidatorAck {
    /// Construct the opt-out. The name is intentionally unwieldy: a permissive
    /// validator means a malicious node can PUT crafted state under the new key
    /// first, so unverified carry-forward is only safe with other guarantees.
    pub fn i_understand_carry_forward_will_not_be_verified() -> Self {
        Self(())
    }
}

/// Reconstruct a predecessor `ContractInstanceId` from a 32-byte code hash and
/// the (stable) parameters, **without** the old WASM bytes.
///
/// Mirrors stdlib key derivation exactly:
/// * `code_hash = blake3(wasm)`            (stdlib `CodeHash::from_code`)
/// * `id        = blake3(code_hash ‖ params)` (stdlib `generate_id`, code hash first)
///
/// Infallible: the lineage's hashes were decoded and validated at build time.
pub fn contract_id_from_code_hash(code_hash: &[u8; 32], params: &Parameters) -> ContractInstanceId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(code_hash);
    hasher.update(params.as_ref());
    let id = *hasher.finalize().as_bytes();
    ContractInstanceId::new(id)
}

/// [`contract_id_from_code_hash`] for a base58 string, for callers holding
/// stdlib's string form rather than a lineage entry.
pub fn contract_id_from_code_hash_b58(
    code_hash_b58: &str,
    params: &Parameters,
) -> Result<ContractInstanceId, MigrateError> {
    let code_hash = decode_b58_32(code_hash_b58)?;
    Ok(contract_id_from_code_hash(&code_hash, params))
}

/// Reconstruct every predecessor contract id for a backward probe. Ordered as
/// the registry is (oldest-first); probe newest-first by iterating in reverse.
///
/// Infallible: a generated lineage's hashes cannot be malformed (they were
/// decoded and validated at build time).
pub fn predecessor_ids(
    params: &Parameters,
    lineage: &[ContractLineageEntry],
) -> Vec<ContractInstanceId> {
    lineage
        .iter()
        .map(|e| contract_id_from_code_hash(&e.code_hash, params))
        .collect()
}

/// The result of [`resolve_predecessors`]: the predecessor ids the node should
/// fetch, plus the intended [`RelatedMode`].
///
/// Not `Clone` because stdlib's [`RelatedMode`] is not `Clone`.
#[derive(Debug)]
pub struct Resolution {
    /// Predecessor ids not already supplied by the node.
    pub ids: Vec<ContractInstanceId>,
    /// `StateThenSubscribe`, so the node keeps the old key's late updates
    /// flowing (and, against shipped eviction, pins the old key) during the
    /// migration window.
    pub mode: RelatedMode,
}

impl Resolution {
    /// Whether there is nothing left to request (all predecessors already
    /// present, or an empty lineage) — the contract can proceed to fold.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// The raw-interface result to return from `validate_state`: ask the node
    /// to retrieve the predecessor states and re-invoke validation.
    ///
    /// Note: the raw [`ValidateResult::RequestRelated`] does not itself carry a
    /// [`RelatedMode`]; that is expressed on the typed encoding path
    /// (`RelatedContractsContainer` / `RelatedContract { mode }`). See
    /// [`Resolution::mode`] for the intended mode a typed contract should
    /// attach.
    pub fn as_validate_result(&self) -> ValidateResult {
        ValidateResult::RequestRelated(self.ids.clone())
    }
}

/// Compute the predecessor states a successor's `validate_state` should pull in,
/// skipping any the node has already populated in `related`.
///
/// Wraps [`predecessor_ids`] and pairs it with [`RelatedMode::StateThenSubscribe`].
pub fn resolve_predecessors(
    params: &Parameters,
    lineage: &[ContractLineageEntry],
    related: &RelatedContracts<'static>,
) -> Resolution {
    let already: HashSet<ContractInstanceId> = related.states().map(|(id, _)| *id).collect();
    let ids = predecessor_ids(params, lineage)
        .into_iter()
        .filter(|id| !already.contains(id))
        .collect();
    Resolution {
        ids,
        mode: RelatedMode::StateThenSubscribe,
    }
}

/// Decode a base58 (Bitcoin alphabet) string into exactly 32 bytes.
pub(crate) fn decode_b58_32(s: &str) -> Result<[u8; 32], MigrateError> {
    let mut out = [0u8; 32];
    let n = bs58::decode(s)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut out)
        .map_err(|e| MigrateError::BadCodeHash(format!("{s:?}: {e}")))?;
    if n != 32 {
        return Err(MigrateError::BadCodeHash(format!(
            "{s:?}: decoded {n} bytes, expected 32"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::{ContractCode, ContractInstanceId};
    use serde::Deserialize;

    /// Known vector: our from-scratch reconstruction must reproduce exactly the
    /// id stdlib derives from the real (code, params).
    #[test]
    fn predecessor_ids_matches_stdlib_key_derivation() {
        let wasm = b"pretend this is room_contract v1 wasm bytes";
        let params = Parameters::from(b"stable-owner-parameters".to_vec());
        let code = ContractCode::from(wasm.to_vec());

        let expected = ContractInstanceId::from_params_and_code(&params, &code);
        let code_hash: [u8; 32] = **code.hash();

        let reconstructed = contract_id_from_code_hash(&code_hash, &params);
        assert_eq!(
            reconstructed, expected,
            "blake3(code_hash ‖ params) reconstruction diverged from stdlib generate_id"
        );

        // The base58-string path agrees.
        let via_b58 = contract_id_from_code_hash_b58(&code.hash().encode(), &params).unwrap();
        assert_eq!(via_b58, expected);

        // And via the lineage entry path.
        let lineage = [ContractLineageEntry {
            generation: 0,
            code_hash,
            note: "v1",
        }];
        let ids = predecessor_ids(&params, &lineage);
        assert_eq!(ids, vec![expected]);
    }

    #[test]
    fn bad_code_hash_string_is_rejected() {
        let params = Parameters::from(Vec::new());
        // "0OIl" contains base58-illegal chars.
        let err = contract_id_from_code_hash_b58("0OIl", &params).unwrap_err();
        assert!(matches!(err, MigrateError::BadCodeHash(_)));
        // Valid base58 but too short.
        let err = contract_id_from_code_hash_b58("abc", &params).unwrap_err();
        assert!(matches!(err, MigrateError::BadCodeHash(_)));
    }

    // A tiny self-authorizing, mergeable state to exercise the verify() gate.
    #[derive(Clone, Debug, serde::Serialize, Deserialize)]
    struct Counter {
        value: i64,
    }

    impl ComposableState for Counter {
        type ParentState = ();
        type Summary = i64;
        type Delta = i64;
        type Parameters = ();

        fn verify(&self, _p: &(), _params: &()) -> Result<(), String> {
            // Self-authorizing invariant: value must be non-negative.
            if self.value >= 0 {
                Ok(())
            } else {
                Err(format!("invariant violated: value {} < 0", self.value))
            }
        }
        fn summarize(&self, _p: &(), _params: &()) -> i64 {
            self.value
        }
        fn delta(&self, _p: &(), _params: &(), old: &i64) -> Option<i64> {
            Some(self.value - old)
        }
        fn apply_delta(
            &mut self,
            _p: &(),
            _params: &(),
            delta: &Option<i64>,
        ) -> Result<(), String> {
            if let Some(d) = delta {
                self.value += d;
            }
            Ok(())
        }
    }

    #[test]
    fn carry_forward_folds_and_passes_verify() {
        let mut new_state = Counter { value: 0 };
        let predecessor = Counter { value: 7 };
        new_state
            .carry_forward(&predecessor, &(), &())
            .expect("valid state carries forward");
        assert_eq!(new_state.value, 7);
    }

    #[test]
    fn carry_forward_is_fail_closed_on_verify() {
        let mut new_state = Counter { value: 0 };
        let predecessor = Counter { value: -5 }; // would violate the invariant
        let err = new_state.carry_forward(&predecessor, &(), &()).unwrap_err();
        assert!(
            matches!(err, MigrateError::Verify(_)),
            "merge that fails verify must be refused, got {err:?}"
        );
    }

    #[test]
    fn carry_forward_leaves_self_unchanged_on_verify_failure() {
        // Atomicity regression (finding 1a): on a verify() failure `self` must be
        // byte-for-byte unchanged, so a caller that ignores the Result never
        // holds (and never PUTs) the invalid merged state.
        let mut new_state = Counter { value: 5 };
        // merge sets value := predecessor.value (-3), which then fails verify.
        let predecessor = Counter { value: -3 };
        let err = new_state.carry_forward(&predecessor, &(), &()).unwrap_err();
        assert!(matches!(err, MigrateError::Verify(_)));
        assert_eq!(
            new_state.value, 5,
            "self must retain its pre-merge value when verify() rejects the fold"
        );
    }

    #[test]
    fn unverified_opt_out_skips_the_gate() {
        let mut new_state = Counter { value: 0 };
        let predecessor = Counter { value: -5 };
        new_state
            .carry_forward_unverified(
                &predecessor,
                &(),
                &(),
                PermissiveValidatorAck::i_understand_carry_forward_will_not_be_verified(),
            )
            .expect("unverified fold ignores the invariant");
        assert_eq!(new_state.value, -5);
    }
}
