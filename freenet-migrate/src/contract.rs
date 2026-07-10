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
    fn carry_forward(
        &mut self,
        predecessor: &Self,
        parent: &Self::ParentState,
        params: &Self::Parameters,
    ) -> Result<(), MigrateError> {
        self.merge(parent, params, predecessor)
            .map_err(MigrateError::Merge)?;
        // Self-authorizing gate, fail-closed: the successor's validator is the
        // only integrity check on a permissionless carry-forward PUT.
        self.verify(parent, params).map_err(MigrateError::Verify)?;
        Ok(())
    }

    /// Fold `predecessor` into `self` **without** the fail-closed `verify()`
    /// gate. Requires a [`PermissiveValidatorAck`], which is un-`Default`,
    /// `#[must_use]`, and only constructible through a visibly-unsafe-named
    /// function — so opting out of the gate is loud, not silent.
    ///
    /// Only correct for a contract whose validator is *known* permissive and
    /// which has some other out-of-band authorization for the incoming state.
    fn carry_forward_unverified(
        &mut self,
        predecessor: &Self,
        parent: &Self::ParentState,
        params: &Self::Parameters,
        _ack: PermissiveValidatorAck,
    ) -> Result<(), MigrateError> {
        self.merge(parent, params, predecessor)
            .map_err(MigrateError::Merge)
    }
}

impl<T: ComposableState + Serialize + DeserializeOwned> CarryForward for T {}

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

/// Reconstruct a predecessor `ContractInstanceId` from a base58 code hash and
/// the (stable) parameters, **without** the old WASM bytes.
///
/// Mirrors stdlib key derivation exactly:
/// * `code_hash = blake3(wasm)`            (stdlib `CodeHash::from_code`)
/// * `id        = blake3(code_hash ‖ params)` (stdlib `generate_id`, code hash first)
pub fn contract_id_from_code_hash(
    code_hash_b58: &str,
    params: &Parameters,
) -> Result<ContractInstanceId, MigrateError> {
    let code_hash = decode_b58_32(code_hash_b58)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&code_hash);
    hasher.update(params.as_ref());
    let id = *hasher.finalize().as_bytes();
    Ok(ContractInstanceId::new(id))
}

/// Reconstruct every predecessor contract id for a backward probe. Ordered as
/// the registry is (oldest-first); probe newest-first by iterating in reverse.
pub fn predecessor_ids(
    params: &Parameters,
    lineage: &[ContractLineageEntry],
) -> Result<Vec<ContractInstanceId>, MigrateError> {
    lineage
        .iter()
        .map(|e| contract_id_from_code_hash(e.code_hash, params))
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
) -> Result<Resolution, MigrateError> {
    let already: HashSet<ContractInstanceId> = related.states().map(|(id, _)| *id).collect();
    let ids = predecessor_ids(params, lineage)?
        .into_iter()
        .filter(|id| !already.contains(id))
        .collect();
    Ok(Resolution {
        ids,
        mode: RelatedMode::StateThenSubscribe,
    })
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
        let code_hash_b58 = code.hash().encode();

        let reconstructed = contract_id_from_code_hash(&code_hash_b58, &params).unwrap();
        assert_eq!(
            reconstructed, expected,
            "blake3(code_hash ‖ params) reconstruction diverged from stdlib generate_id"
        );

        // And via the lineage entry path.
        let ch: &'static str = Box::leak(code_hash_b58.into_boxed_str());
        let lineage = [ContractLineageEntry {
            generation: 0,
            code_hash: ch,
            note: "v1",
        }];
        let ids = predecessor_ids(&params, &lineage).unwrap();
        assert_eq!(ids, vec![expected]);
    }

    #[test]
    fn bad_code_hash_is_rejected() {
        let params = Parameters::from(Vec::new());
        // "0OIl" contains base58-illegal chars.
        let err = contract_id_from_code_hash("0OIl", &params).unwrap_err();
        assert!(matches!(err, MigrateError::BadCodeHash(_)));
        // Valid base58 but too short.
        let err = contract_id_from_code_hash("abc", &params).unwrap_err();
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
