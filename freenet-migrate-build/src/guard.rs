//! The CI hash-guard: "WASM hash changed ⇒ old hash must be registered."
//!
//! Generalizes River's `check-*-migration.sh` (base-vs-head git diff) and
//! Delta's `check-migration.sh` (rebuild-vs-committed): both reduce to *if the
//! WASM code hash changed, the previous hash must be present in the registry* so
//! the migration probe can still find the old key.

use crate::registry::Registry;

/// Which registry component a guard/lookup targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// The `[[contract]]` list.
    Contract,
    /// The `[[delegate]]` list.
    Delegate,
}

impl Component {
    fn label(self) -> &'static str {
        match self {
            Component::Contract => "contract",
            Component::Delegate => "delegate",
        }
    }
}

/// Compute the base58 code hash of some WASM bytes: `blake3(wasm)`, base58
/// (Bitcoin alphabet) — matching stdlib `CodeHash::from_code(..).encode()`.
pub fn code_hash_b58(wasm: &[u8]) -> String {
    bs58::encode(blake3::hash(wasm).as_bytes())
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

/// The result of the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// The WASM hash did not change; nothing to do.
    Unchanged,
    /// The WASM changed and the previous (base) hash is registered — safe.
    PredecessorRegistered {
        /// The generation the base hash is registered under.
        generation: u32,
    },
    /// The WASM changed but the previous (base) hash is **not** registered —
    /// the migration would strand the old key. CI must fail.
    PredecessorMissing {
        /// The unregistered base hash.
        base: String,
    },
}

impl GuardOutcome {
    /// Whether the guard passes (only [`GuardOutcome::PredecessorMissing`] fails).
    pub fn is_ok(&self) -> bool {
        !matches!(self, GuardOutcome::PredecessorMissing { .. })
    }

    /// A human-actionable message for CI logs, if the guard failed.
    pub fn advice(&self, component: Component) -> Option<String> {
        match self {
            GuardOutcome::PredecessorMissing { base } => Some(format!(
                "the {} WASM changed but its previous code hash {base:?} is not in the registry; \
                 add it as a predecessor generation before merging, or migration will strand \
                 state under the old key",
                component.label()
            )),
            _ => None,
        }
    }
}

/// Guard a component against a change: given the previously-committed code hash
/// (`base`, e.g. `blake3` of the WASM at the PR base / the committed artifact)
/// and the current built code hash (`head`), require that a change is
/// accompanied by the base hash being registered.
///
/// `base` and `head` are base58 (see [`code_hash_b58`]).
pub fn check_migration_guard(
    component: Component,
    base_code_hash_b58: &str,
    head_code_hash_b58: &str,
    registry: &Registry,
) -> GuardOutcome {
    if base_code_hash_b58 == head_code_hash_b58 {
        return GuardOutcome::Unchanged;
    }
    let found = match component {
        Component::Contract => registry.find_contract_code_hash(base_code_hash_b58),
        Component::Delegate => registry.find_delegate_code_hash(base_code_hash_b58),
    };
    match found {
        Some(generation) => GuardOutcome::PredecessorRegistered { generation },
        None => GuardOutcome::PredecessorMissing {
            base: base_code_hash_b58.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{ContractRow, Registry};

    fn registry_with_contract(code_hash_b58: &str, generation: u32) -> Registry {
        Registry {
            contract: vec![ContractRow {
                generation,
                code_hash: code_hash_b58.to_string(),
                note: String::new(),
            }],
            delegate: vec![],
        }
    }

    #[test]
    fn code_hash_b58_is_deterministic_and_32_bytes() {
        let a = code_hash_b58(b"some wasm");
        let b = code_hash_b58(b"some wasm");
        assert_eq!(a, b);
        // base58 of 32 bytes decodes back to 32 bytes.
        let mut out = [0u8; 32];
        let n = bs58::decode(&a)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .onto(&mut out)
            .unwrap();
        assert_eq!(n, 32);
        assert_ne!(a, code_hash_b58(b"different wasm"));
    }

    #[test]
    fn unchanged_wasm_passes() {
        let h = code_hash_b58(b"v1");
        let reg = Registry::default();
        let outcome = check_migration_guard(Component::Contract, &h, &h, &reg);
        assert_eq!(outcome, GuardOutcome::Unchanged);
        assert!(outcome.is_ok());
    }

    #[test]
    fn changed_wasm_with_registered_predecessor_passes() {
        let base = code_hash_b58(b"v1");
        let head = code_hash_b58(b"v2");
        let reg = registry_with_contract(&base, 0);
        let outcome = check_migration_guard(Component::Contract, &base, &head, &reg);
        assert_eq!(
            outcome,
            GuardOutcome::PredecessorRegistered { generation: 0 }
        );
        assert!(outcome.is_ok());
        assert!(outcome.advice(Component::Contract).is_none());
    }

    #[test]
    fn changed_wasm_without_registered_predecessor_fails() {
        let base = code_hash_b58(b"v1");
        let head = code_hash_b58(b"v2");
        let reg = Registry::default(); // base not registered
        let outcome = check_migration_guard(Component::Contract, &base, &head, &reg);
        assert_eq!(
            outcome,
            GuardOutcome::PredecessorMissing { base: base.clone() }
        );
        assert!(!outcome.is_ok());
        assert!(outcome.advice(Component::Contract).unwrap().contains(&base));
    }

    #[test]
    fn guard_is_component_scoped() {
        // A hash registered only under contract must not satisfy a delegate guard.
        let base = code_hash_b58(b"shared");
        let head = code_hash_b58(b"changed");
        let reg = registry_with_contract(&base, 0);
        let outcome = check_migration_guard(Component::Delegate, &base, &head, &reg);
        assert!(matches!(outcome, GuardOutcome::PredecessorMissing { .. }));
    }
}
