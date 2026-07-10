//! Delegate secret carry-forward.
//!
//! The export enumerates **every** secret generically via
//! [`SecretStore::list_secrets`], which structurally eliminates the per-type
//! export omission that cost Delta its per-site state in April 2026 (a new
//! `Store*`/`Get*` pair was silently left out of the typed migration fan-out).
//! Copying all secrets by construction cannot omit a type.
//!
//! The v2 side ([`import_secrets_once`]) writes a `"migrated:<gen>"`
//! anti-resurrection marker so a stray re-run of the old WASM cannot re-import
//! (and thereby resurrect) data the user has since deleted.
//!
//! The transport that actually reaches into a predecessor delegate is behind
//! [`SecretTransport`]; the only impl today is the [`ReRunOldWasm`] **stub**
//! (see its docs for the fragility and the Horizon-B `NodeCopyForward` seam).

use freenet_stdlib::prelude::{
    ApplicationMessage, ContractInstanceId, DelegateKey, MessageOrigin, OutboundDelegateMsg,
    Parameters,
};
use serde::{Deserialize, Serialize};

use crate::error::MigrateError;
use crate::lineage::DelegateLineageEntry;

/// The subset of a delegate's secret store this crate needs.
///
/// Implemented over `freenet_stdlib::prelude::DelegateCtx` on wasm targets when
/// the `delegate` feature is on (see the bottom of this module); an in-memory
/// implementation is used in tests. Keeping the handlers generic over this
/// trait is what makes them testable off-wasm.
pub trait SecretStore {
    /// All secret keys under `prefix` (`b""` = every secret).
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>>;
    /// The value stored under `key`, if any.
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// Whether `key` is present.
    fn has_secret(&self, key: &[u8]) -> bool;
    /// Store `value` under `key`, returning whether it succeeded.
    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool;
}

/// A predecessor delegate's exported secrets, ready to hand to
/// [`import_secrets_once`] on the successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedSecrets {
    /// Generation being migrated *from*. Stamped into the successor's
    /// anti-resurrection marker.
    pub source_generation: u32,
    /// Every `(key, value)` secret pair from the predecessor.
    pub secrets: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ExportedSecrets {
    /// CBOR-encode for carriage inside an `ApplicationMessage` payload.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MigrateError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|e| MigrateError::Codec(e.to_string()))?;
        Ok(buf)
    }

    /// CBOR-decode from an `ApplicationMessage` payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MigrateError> {
        ciborium::de::from_reader(bytes).map_err(|e| MigrateError::Codec(e.to_string()))
    }
}

/// Who a v1 delegate will answer an export request for.
#[derive(Debug, Clone)]
pub enum OriginPolicy {
    /// Only the same web-app origin (successor under the same app). The safe
    /// default for app-scoped migration.
    SameWebApp(ContractInstanceId),
    /// Only a specific calling delegate key.
    FromDelegate(DelegateKey),
    /// Any origin — unsafe; for local/testing only.
    Any,
}

impl OriginPolicy {
    /// Authorize `origin` under this policy.
    pub fn authorize(&self, origin: &MessageOrigin) -> Result<(), MigrateError> {
        match (self, origin) {
            (OriginPolicy::Any, _) => Ok(()),
            (OriginPolicy::SameWebApp(id), MessageOrigin::WebApp(o)) if o == id => Ok(()),
            (OriginPolicy::FromDelegate(k), MessageOrigin::Delegate(o)) if o == k => Ok(()),
            // `MessageOrigin` is #[non_exhaustive]; this also covers mismatches.
            _ => Err(MigrateError::UnauthorizedOrigin),
        }
    }
}

/// A request to a v1 delegate to export its secrets to a successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRequest {
    /// Generation of the predecessor being migrated from (echoed into
    /// [`ExportedSecrets::source_generation`]).
    pub source_generation: u32,
}

/// v1 side: authorize the requesting origin, enumerate **all** secrets
/// generically, and package them into an outbound `ApplicationMessage`.
///
/// Runs inside the old delegate's WASM. The reply is an
/// `OutboundDelegateMsg::ApplicationMessage` carrying the CBOR-encoded
/// [`ExportedSecrets`]; the app-level envelope/routing (which request variant,
/// how the successor recognizes the reply) is the consuming app's protocol —
/// this returns the raw outbound message(s).
pub fn handle_export_request<S: SecretStore + ?Sized>(
    store: &S,
    origin: &MessageOrigin,
    policy: &OriginPolicy,
    req: &ExportRequest,
) -> Result<Vec<OutboundDelegateMsg>, MigrateError> {
    policy.authorize(origin)?;
    let exported = ExportedSecrets {
        source_generation: req.source_generation,
        secrets: export_all(store),
    };
    let payload = exported.to_bytes()?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(payload).processed(true),
    )])
}

/// Collect every `(key, value)` secret. Generic by construction — cannot omit a
/// secret type (the Delta April-2026 lesson).
fn export_all<S: SecretStore + ?Sized>(store: &S) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for key in store.list_secrets(b"") {
        if let Some(val) = store.get_secret(&key) {
            out.push((key, val));
        }
    }
    out
}

/// Outcome of [`import_secrets_once`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Import ran; `imported` new secrets written, `skipped` left untouched
    /// because a value already existed under that key (never clobbered).
    Imported {
        /// Generation migrated from.
        generation: u32,
        /// Number of secrets written.
        imported: usize,
        /// Number of secrets skipped because the key already existed.
        skipped: usize,
    },
    /// The `"migrated:<gen>"` marker was already present; nothing was written.
    AlreadyMigrated {
        /// Generation that was already migrated.
        generation: u32,
    },
}

/// v2 side: import a predecessor's secrets exactly once.
///
/// Idempotent via the `"migrated:<gen>"` anti-resurrection marker: a second call
/// (or a stray old-WASM re-run that re-exports) sees the marker and writes
/// nothing. Existing keys on the successor are never clobbered.
pub fn import_secrets_once<S: SecretStore + ?Sized>(
    store: &mut S,
    exported: &ExportedSecrets,
) -> Result<ImportOutcome, MigrateError> {
    let marker = migration_marker(exported.source_generation);
    if store.has_secret(&marker) {
        return Ok(ImportOutcome::AlreadyMigrated {
            generation: exported.source_generation,
        });
    }
    let mut imported = 0usize;
    let mut skipped = 0usize;
    for (k, v) in &exported.secrets {
        if store.has_secret(k) {
            // Successor already has data under this key — do not clobber it.
            skipped += 1;
            continue;
        }
        store.set_secret(k, v);
        imported += 1;
    }
    store.set_secret(&marker, b"1");
    Ok(ImportOutcome::Imported {
        generation: exported.source_generation,
        imported,
        skipped,
    })
}

/// The anti-resurrection marker key for a given source generation.
pub(crate) fn migration_marker(generation: u32) -> Vec<u8> {
    format!("migrated:{generation}").into_bytes()
}

/// A swappable way to reach a predecessor delegate's secrets.
pub trait SecretTransport {
    /// Export all secrets from `predecessor`.
    fn export_from(&self, predecessor: &DelegateKey) -> Result<ExportedSecrets, MigrateError>;
}

/// **Stub.** The shipped-today transport: the node loads and *re-runs the old
/// delegate's WASM* to answer the export.
///
/// This is the exact path a stdlib/ABI bump breaks (River V4–V6 / #204 data
/// loss) — running old WASM against a newer host is fragile by construction.
/// This increment does **not** wire it: today apps carry the export app-side as
/// `DelegateRequest::ApplicationMessages` round-trips (see River/Delta), so this
/// returns [`MigrateError::TransportUnavailable`] rather than pretend to work.
///
/// The crate *contains* the fragility: [`import_secrets_once`]'s marker bounds
/// the damage, and [`SecretTransport`] is the seam. When Horizon-B B1 lands a
/// node-mediated `SecretsStore::migrate_secrets`, add
/// `struct NodeCopyForward; impl SecretTransport for NodeCopyForward { .. }` and
/// callers written against the trait pick it up with **no API break**. (Hosted
/// per-user secrets stay un-migratable at rest even under B1 — such a transport
/// should return [`MigrateError::UserScopeNotAtRest`].)
pub struct ReRunOldWasm;

impl SecretTransport for ReRunOldWasm {
    fn export_from(&self, _predecessor: &DelegateKey) -> Result<ExportedSecrets, MigrateError> {
        // TODO(Horizon-B / freenet-core#2776): node-side re-run of the
        // predecessor delegate WASM to answer an export is not wired here.
        Err(MigrateError::TransportUnavailable(
            "ReRunOldWasm is a stub: re-running the predecessor delegate's WASM to answer an \
             export is not implemented in this increment. Carry the export app-side via \
             DelegateRequest::ApplicationMessages (see River/Delta), or supply a NodeCopyForward \
             transport once Horizon-B B1 lands."
                .to_string(),
        ))
    }
}

/// Reconstruct every predecessor `DelegateKey` from the lineage, for addressing
/// old delegates during a probe.
///
/// Uses stdlib `DelegateKey::from_params` = `blake3(code_hash ‖ params)`. For
/// the empty delegate params River and Delta use, this equals the stored
/// `delegate_key`; the reconstruction and the stored value can be cross-checked
/// with [`predecessor_delegate_keys_checked`].
pub fn predecessor_delegate_keys(
    params: &Parameters,
    lineage: &[DelegateLineageEntry],
) -> Result<Vec<DelegateKey>, MigrateError> {
    lineage
        .iter()
        .map(|e| {
            DelegateKey::from_params(e.code_hash, params)
                .map_err(|err| MigrateError::BadCodeHash(format!("{:?}: {err}", e.code_hash)))
        })
        .collect()
}

/// Like [`predecessor_delegate_keys`], but also asserts each reconstructed key's
/// base58 equals the registry's stored `delegate_key` (a build/data-integrity
/// guard, mirroring Delta's build-time assert).
pub fn predecessor_delegate_keys_checked(
    params: &Parameters,
    lineage: &[DelegateLineageEntry],
) -> Result<Vec<DelegateKey>, MigrateError> {
    let keys = predecessor_delegate_keys(params, lineage)?;
    for (entry, key) in lineage.iter().zip(keys.iter()) {
        if key.encode() != entry.delegate_key {
            return Err(MigrateError::BadCodeHash(format!(
                "delegate gen {}: reconstructed key {} != registered {}",
                entry.generation,
                key.encode(),
                entry.delegate_key
            )));
        }
    }
    Ok(keys)
}

// The wasm-only bridge over the real delegate context. Double-gated on
// `target_family = "wasm"` so `--all-features` builds/tests/clippy on native
// never try to link the `__frnt__delegate__*` FFI symbols.
#[cfg(all(feature = "delegate", target_family = "wasm"))]
impl SecretStore for freenet_stdlib::prelude::DelegateCtx {
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        freenet_stdlib::prelude::DelegateCtx::list_secrets(self, prefix)
    }
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        freenet_stdlib::prelude::DelegateCtx::get_secret(self, key)
    }
    fn has_secret(&self, key: &[u8]) -> bool {
        freenet_stdlib::prelude::DelegateCtx::has_secret(self, key)
    }
    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        freenet_stdlib::prelude::DelegateCtx::set_secret(self, key, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::{CodeHash, ContractInstanceId};
    use std::collections::BTreeMap;

    /// In-memory `SecretStore` for tests (the wasm `DelegateCtx` bridge is not
    /// linkable natively).
    #[derive(Default)]
    struct MemStore(BTreeMap<Vec<u8>, Vec<u8>>);

    impl SecretStore for MemStore {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.0
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get(key).cloned()
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.0.contains_key(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            self.0.insert(key.to_vec(), value.to_vec());
            true
        }
    }

    fn v1_store() -> MemStore {
        let mut s = MemStore::default();
        // Three heterogeneous secret "types" — a per-type export could omit one;
        // the generic list_secrets export cannot.
        s.set_secret(b"rooms_data", b"room-blob");
        s.set_secret(b"outbound_dms", b"dm-blob");
        s.set_secret(b"signing_key:site-a", b"key-bytes");
        s
    }

    fn extract_exported(msgs: &[OutboundDelegateMsg]) -> ExportedSecrets {
        match &msgs[0] {
            OutboundDelegateMsg::ApplicationMessage(am) => {
                ExportedSecrets::from_bytes(&am.payload).unwrap()
            }
            other => panic!("expected ApplicationMessage, got {other:?}"),
        }
    }

    #[test]
    fn export_enumerates_every_secret_generically() {
        let store = v1_store();
        let origin = MessageOrigin::WebApp(ContractInstanceId::new([7u8; 32]));
        let policy = OriginPolicy::Any;
        let req = ExportRequest {
            source_generation: 3,
        };

        let msgs = handle_export_request(&store, &origin, &policy, &req).unwrap();
        assert_eq!(msgs.len(), 1);
        let exported = extract_exported(&msgs);
        assert_eq!(exported.source_generation, 3);
        assert_eq!(exported.secrets.len(), 3, "all three secret types exported");
    }

    #[test]
    fn export_respects_origin_policy() {
        let store = v1_store();
        let app = ContractInstanceId::new([7u8; 32]);
        let other = ContractInstanceId::new([8u8; 32]);
        let req = ExportRequest {
            source_generation: 1,
        };

        // Same-webapp: allowed for the matching origin, rejected otherwise.
        let policy = OriginPolicy::SameWebApp(app);
        handle_export_request(&store, &MessageOrigin::WebApp(app), &policy, &req).unwrap();
        let err = handle_export_request(&store, &MessageOrigin::WebApp(other), &policy, &req)
            .unwrap_err();
        assert!(matches!(err, MigrateError::UnauthorizedOrigin));
    }

    #[test]
    fn import_secrets_once_is_idempotent_via_marker() {
        let exported = ExportedSecrets {
            source_generation: 4,
            secrets: vec![
                (b"rooms_data".to_vec(), b"room-blob".to_vec()),
                (b"outbound_dms".to_vec(), b"dm-blob".to_vec()),
            ],
        };

        let mut v2 = MemStore::default();

        // First import writes both secrets + the marker.
        let first = import_secrets_once(&mut v2, &exported).unwrap();
        assert_eq!(
            first,
            ImportOutcome::Imported {
                generation: 4,
                imported: 2,
                skipped: 0
            }
        );
        assert!(v2.has_secret(&migration_marker(4)));
        let after_first = v2.list_secrets(b"").len();

        // Second import (e.g. a stray old-WASM re-run) writes nothing.
        let second = import_secrets_once(&mut v2, &exported).unwrap();
        assert_eq!(second, ImportOutcome::AlreadyMigrated { generation: 4 });
        assert_eq!(
            v2.list_secrets(b"").len(),
            after_first,
            "re-import must not resurrect or duplicate any data"
        );
    }

    #[test]
    fn import_never_clobbers_existing_secrets() {
        let exported = ExportedSecrets {
            source_generation: 2,
            secrets: vec![
                (b"rooms_data".to_vec(), b"OLD".to_vec()),
                (b"new_key".to_vec(), b"fresh".to_vec()),
            ],
        };
        let mut v2 = MemStore::default();
        v2.set_secret(b"rooms_data", b"NEWER"); // successor already has newer data

        let outcome = import_secrets_once(&mut v2, &exported).unwrap();
        assert_eq!(
            outcome,
            ImportOutcome::Imported {
                generation: 2,
                imported: 1,
                skipped: 1
            }
        );
        assert_eq!(v2.get_secret(b"rooms_data").unwrap(), b"NEWER");
        assert_eq!(v2.get_secret(b"new_key").unwrap(), b"fresh");
    }

    #[test]
    fn export_then_import_roundtrips() {
        let store = v1_store();
        let msgs = handle_export_request(
            &store,
            &MessageOrigin::WebApp(ContractInstanceId::new([7u8; 32])),
            &OriginPolicy::Any,
            &ExportRequest {
                source_generation: 9,
            },
        )
        .unwrap();
        let exported = extract_exported(&msgs);

        let mut v2 = MemStore::default();
        import_secrets_once(&mut v2, &exported).unwrap();
        assert_eq!(v2.get_secret(b"rooms_data").unwrap(), b"room-blob");
        assert_eq!(v2.get_secret(b"signing_key:site-a").unwrap(), b"key-bytes");
    }

    #[test]
    fn predecessor_delegate_keys_reconstructs_blake3_of_code_hash() {
        // River/Delta delegates use empty params, so key = blake3(code_hash).
        let params = Parameters::from(Vec::new());
        let wasm = b"delegate wasm v1";
        let code_hash = CodeHash::from_code(wasm);
        let ch_b58 = code_hash.encode();

        // Independent expected derivation: blake3(code_hash ‖ params).
        let mut h = blake3::Hasher::new();
        h.update(&*code_hash);
        h.update(params.as_ref());
        let expected_key = *h.finalize().as_bytes();
        let expected_key_b58 = bs58::encode(expected_key)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string();

        let ch_static: &'static str = Box::leak(ch_b58.into_boxed_str());
        let dk_static: &'static str = Box::leak(expected_key_b58.clone().into_boxed_str());
        let lineage = [DelegateLineageEntry {
            generation: 0,
            code_hash: ch_static,
            delegate_key: dk_static,
            note: "v1",
        }];

        let keys = predecessor_delegate_keys(&params, &lineage).unwrap();
        assert_eq!(keys[0].bytes(), expected_key);
        // The checked variant agrees because the stored key matches.
        predecessor_delegate_keys_checked(&params, &lineage).unwrap();
    }

    #[test]
    fn predecessor_delegate_keys_checked_flags_mismatch() {
        let params = Parameters::from(Vec::new());
        let wasm = b"delegate wasm v2";
        let ch_b58 = CodeHash::from_code(wasm).encode();
        let ch_static: &'static str = Box::leak(ch_b58.into_boxed_str());
        let lineage = [DelegateLineageEntry {
            generation: 0,
            code_hash: ch_static,
            // Deliberately wrong stored key.
            delegate_key: "11111111111111111111111111111111",
            note: "",
        }];
        let err = predecessor_delegate_keys_checked(&params, &lineage).unwrap_err();
        assert!(matches!(err, MigrateError::BadCodeHash(_)));
    }
}
