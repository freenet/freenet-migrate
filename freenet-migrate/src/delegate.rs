//! Delegate secret carry-forward.
//!
//! The export enumerates secrets generically via [`SecretStore::list_secrets`]
//! rather than a hand-maintained per-type fan-out, which removes the *per-type*
//! omission class that cost Delta its per-site state in April 2026 (a new
//! `Store*`/`Get*` pair was silently left out of the typed migration).
//!
//! It does **not** claim to copy literally every stored secret unconditionally:
//! the host caps key enumeration per scope at
//! [`HOST_ENUMERATION_CAP`] and silently truncates beyond it, and keys written
//! before the host key-registry feature are not enumerable until rewritten. For
//! an open-ended key family (stdlib's own example is `room:<owner_vk>`, River's
//! shape) an export past the cap would drop the overflow. The export therefore
//! **detects** cap saturation and refuses with [`MigrateError::TruncatedExport`]
//! rather than silently dropping keys and then writing a completion marker that
//! would permanently block a corrected re-import. The pre-registry-keys caveat
//! cannot be detected and is documented on [`handle_export_request`].
//!
//! The v2 side ([`import_secrets_once`]) uses a **two-phase** anti-resurrection
//! marker: an in-progress marker written *before* any write, upgraded to a
//! completion marker only after *every* write succeeds. A completed migration
//! is never re-imported, so a stray re-run of the old WASM cannot resurrect data
//! the user has since deleted. See [`import_secrets_once`] for the two-phase
//! scheme and its one residual limit (an interrupted-then-retried import).
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

/// The host's per-scope key-enumeration cap, mirroring freenet-core's
/// `MAX_REGISTERED_KEYS_PER_SCOPE`. [`SecretStore::list_secrets`] truncates
/// silently at this many keys with **no** truncation signal, so an export that
/// sees this many keys must treat the set as possibly-incomplete.
///
/// Kept in sync by hand with the host constant; if the host raises its cap this
/// only becomes conservative (it may refuse an export that would in fact have
/// been complete), never unsafe (it never lets a truncated export through).
pub const HOST_ENUMERATION_CAP: usize = 4096;

/// Reserved key-namespace prefix for this crate's bookkeeping markers.
///
/// The crate **reserves** every secret key beginning with these bytes; an app's
/// own secret keys must not start with them. The leading NUL keeps the
/// namespace out of the printable-ASCII key space real apps use (River
/// `room:<vk>`, Delta `signing_key:*`), so a collision cannot happen in
/// practice. Marker keys are filtered out of every export and are never
/// writable from an import payload.
const MARKER_NS: &[u8] = b"\0freenet-migrate/";
/// In-progress marker sub-prefix: `MARKER_NS ++ b"wip:" ++ <gen decimal>`.
const WIP_PREFIX: &[u8] = b"\0freenet-migrate/wip:";
/// Completion marker sub-prefix: `MARKER_NS ++ b"done:" ++ <gen decimal>`.
const DONE_PREFIX: &[u8] = b"\0freenet-migrate/done:";

/// One exported secret: `(raw key, value)`.
type SecretPair = (Vec<u8>, Vec<u8>);

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
    ///
    /// **Not authenticated.** It is echoed from the (unsigned) [`ExportRequest`]
    /// and travels in an app-level envelope the crate does not sign, so an
    /// attacker who can inject an export controls this value. [`import_secrets_once`]
    /// therefore bounds it against the successor's own generation
    /// ([`MigrateError::ImplausibleGeneration`]) so an injected export cannot
    /// stamp a marker for an implausibly-high generation and block real
    /// migrations. Full authentication (signing `ExportedSecrets`) is future
    /// work — see the crate README "Known limitations".
    pub source_generation: u32,
    /// Every `(key, value)` secret pair from the predecessor, minus this crate's
    /// reserved bookkeeping markers (filtered by [`handle_export_request`]).
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
    /// Authorize `origin` under this policy, **failing closed on `None`**.
    ///
    /// The stdlib delegate entry point hands `process` an `origin:
    /// Option<MessageOrigin>` — the runtime supplies `None` when it cannot
    /// attest a caller. A migration export must never treat an unattested caller
    /// as trusted, so `None` is rejected here rather than left for a caller to
    /// `unwrap_or(trusted)`. Only [`OriginPolicy::Any`] (explicitly unsafe,
    /// local/testing) accepts an unattested caller.
    pub fn authorize(&self, origin: Option<&MessageOrigin>) -> Result<(), MigrateError> {
        match (self, origin) {
            // `Any` is the sole policy that accepts an unattested (`None`)
            // origin; it is documented as unsafe / local-testing only.
            (OriginPolicy::Any, _) => Ok(()),
            // Fail closed: no attested origin ⇒ not authorized under any real policy.
            (_, None) => Err(MigrateError::UnauthorizedOrigin),
            (OriginPolicy::SameWebApp(id), Some(MessageOrigin::WebApp(o))) if o == id => Ok(()),
            (OriginPolicy::FromDelegate(k), Some(MessageOrigin::Delegate(o))) if o == k => Ok(()),
            // `MessageOrigin` is #[non_exhaustive]; this also covers cross-type
            // mismatches (a WebApp origin under a FromDelegate policy, etc.).
            _ => Err(MigrateError::UnauthorizedOrigin),
        }
    }
}

/// How much of a delegate's secret store an export covers.
///
/// A single `(delegate, Local-scope)` namespace is **shared** by every web-app
/// that uses the delegate; exporting the whole scope hands the requesting origin
/// *every* app's secrets. Because the host does not namespace secrets by origin,
/// per-origin slicing is not expressible generically — so this makes the choice
/// explicit and fail-safe:
///
/// * [`ExportScope::Prefix`] restricts the export to keys under a caller-chosen
///   prefix (pass the requesting origin's own key prefix on a delegate that
///   namespaces secrets per app), so one app cannot exfiltrate another's slice.
/// * [`ExportScope::EntireDelegate`] exports the whole scope and is safe **only**
///   on a single-app delegate; it is gated behind a loudly-named, un-`Default`
///   acknowledgement so multi-app misuse cannot happen silently.
#[derive(Debug)]
pub enum ExportScope {
    /// Export only secrets whose raw key begins with `prefix`.
    Prefix(Vec<u8>),
    /// Export every secret in the delegate's Local scope. Single-app only.
    EntireDelegate(SingleAppDelegateAck),
}

/// Acknowledgement that a delegate serves a **single** web-app, required to
/// export its entire secret scope via [`ExportScope::EntireDelegate`].
///
/// Deliberately not `Default` and `#[must_use]`, with a single loudly-named
/// constructor: exporting the whole scope of a delegate shared by more than one
/// web-app leaks every other app's secrets to the requesting origin, so opting
/// into a whole-scope export is explicit and visibly load-bearing.
#[must_use = "constructing a SingleAppDelegateAck certifies the delegate serves ONE web-app; \
              a whole-scope export on a multi-app delegate leaks other apps' secrets"]
#[derive(Debug)]
pub struct SingleAppDelegateAck(());

impl SingleAppDelegateAck {
    /// Construct the acknowledgement. The name is intentionally unwieldy: only
    /// a delegate that serves exactly one web-app may export its whole scope.
    pub fn i_certify_this_delegate_serves_a_single_web_app() -> Self {
        Self(())
    }
}

/// A request to a v1 delegate to export its secrets to a successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRequest {
    /// Generation of the predecessor being migrated from (echoed into
    /// [`ExportedSecrets::source_generation`]).
    pub source_generation: u32,
}

/// v1 side: authorize the requesting origin, enumerate the requested secret
/// scope generically, and package it into an outbound `ApplicationMessage`.
///
/// Runs inside the old delegate's WASM. The reply is an
/// `OutboundDelegateMsg::ApplicationMessage` carrying the CBOR-encoded
/// [`ExportedSecrets`]; the app-level envelope/routing (which request variant,
/// how the successor recognizes the reply) is the consuming app's protocol —
/// this returns the raw outbound message(s).
///
/// `origin` is `Option<&MessageOrigin>` exactly as the stdlib delegate entry
/// point supplies it; `None` (an unattested caller) is rejected fail-closed by
/// [`OriginPolicy::authorize`].
///
/// `scope` selects how much of the store to export — a caller-chosen key prefix,
/// or the whole (single-app) delegate scope. See [`ExportScope`].
///
/// # Errors
///
/// * [`MigrateError::UnauthorizedOrigin`] — `origin` is not permitted by `policy`
///   (including `None`).
/// * [`MigrateError::TruncatedExport`] — the host enumeration hit its cap (see
///   [`HOST_ENUMERATION_CAP`]); the export is refused rather than shipping a
///   possibly-incomplete set.
///
/// # Caveat: pre-registry keys
///
/// Secrets written before the host gained its key-enumeration registry (#4355)
/// are **not** returned by [`SecretStore::list_secrets`] until they are rewritten,
/// and this is undetectable from inside the delegate. A migration off a delegate
/// that predates the registry must rewrite (touch) such keys before relying on a
/// whole-scope export, or carry them via an app-side per-key path. This is a
/// genuine residual limit, not covered by the truncation check.
pub fn handle_export_request<S: SecretStore + ?Sized>(
    store: &S,
    origin: Option<&MessageOrigin>,
    policy: &OriginPolicy,
    scope: &ExportScope,
    req: &ExportRequest,
) -> Result<Vec<OutboundDelegateMsg>, MigrateError> {
    policy.authorize(origin)?;
    let exported = ExportedSecrets {
        source_generation: req.source_generation,
        secrets: export_scoped(store, scope)?,
    };
    let payload = exported.to_bytes()?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(payload).processed(true),
    )])
}

/// Collect the `(key, value)` secrets in `scope`, refusing if the host's
/// enumeration was truncated at its cap.
///
/// Cap saturation is a **whole-scope** property: the host caps the per-scope key
/// registry and *then* filters by prefix, so a truncated scope may have silently
/// dropped keys that fall under a requested prefix. We therefore check the full
/// scope count even for a prefix export. Reserved marker keys are never exported.
fn export_scoped<S: SecretStore + ?Sized>(
    store: &S,
    scope: &ExportScope,
) -> Result<Vec<SecretPair>, MigrateError> {
    // Whole-scope key names (not values) — used only to detect cap saturation.
    let all_keys = store.list_secrets(b"");
    if all_keys.len() >= HOST_ENUMERATION_CAP {
        return Err(MigrateError::TruncatedExport {
            returned: all_keys.len(),
            cap: HOST_ENUMERATION_CAP,
        });
    }

    let keys = match scope {
        ExportScope::EntireDelegate(_ack) => all_keys,
        ExportScope::Prefix(prefix) => store.list_secrets(prefix),
    };

    let mut out = Vec::new();
    for key in keys {
        if is_marker(&key) {
            // Reserved bookkeeping marker — never part of an app's secret set.
            continue;
        }
        if let Some(val) = store.get_secret(&key) {
            out.push((key, val));
        }
    }
    Ok(out)
}

/// Outcome of [`import_secrets_once`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Import completed; `imported` new secrets written, `skipped` left untouched
    /// because a value already existed under that key (never clobbered). The
    /// completion marker is now set, so no future call re-imports this generation.
    Imported {
        /// Generation migrated from.
        generation: u32,
        /// Number of secrets written.
        imported: usize,
        /// Number of secrets skipped because the key already existed.
        skipped: usize,
    },
    /// The completion marker for this generation was already present; nothing
    /// was written.
    AlreadyMigrated {
        /// Generation that was already migrated.
        generation: u32,
    },
    /// A strictly-newer generation has already been imported, so this older
    /// export was refused (anti-rollback / monotonicity). Nothing was written.
    StaleGeneration {
        /// The older generation the export tried to import.
        attempted: u32,
        /// The newest generation already completed on this successor.
        newest_completed: u32,
    },
}

/// v2 side: import a predecessor's secrets exactly once, with a two-phase
/// anti-resurrection marker.
///
/// `successor_generation` is the importing delegate's **own** generation; a
/// legitimate migration always carries state forward from a strictly-older
/// generation, so `exported.source_generation` must be `< successor_generation`
/// (otherwise [`MigrateError::ImplausibleGeneration`]). This bounds the
/// attacker-controlled `source_generation` (see [`ExportedSecrets`]).
///
/// # Two-phase marker (why ordering matters)
///
/// The marker exists so a stray re-run of the *old* WASM cannot re-import — and
/// thereby resurrect — secrets the user deleted on the successor after a
/// completed migration. Two markers make that guarantee honest:
///
/// 1. An **in-progress** marker is written *before* any secret write.
/// 2. Each `set_secret` result is checked; a failed write is counted as `failed`,
///    never as `imported`.
/// 3. The **completion** marker is written *only if every write succeeded*. On
///    any failure the completion marker is withheld and
///    [`MigrateError::PartialImport`] is returned, leaving the in-progress marker
///    so a retry re-runs and re-attempts the missing writes.
///
/// Because the completion marker means "fully imported", a stray re-run after a
/// *completed* migration is fully blocked (no resurrection). Existing keys are
/// never clobbered.
///
/// ## Residual limit (documented, not eliminable here)
///
/// The one window this cannot close: if an import is *interrupted* (a write
/// fails or the process crashes mid-import) and later *retried*, the retry
/// re-imports the keys that are missing on the successor — and it cannot
/// distinguish "this key was never imported" from "this key was imported, then
/// the user deleted it in between". So a key the user deletes *during* an
/// interrupted migration can be resurrected by the completing retry. We take
/// this over the alternative (refusing to complete an interrupted migration,
/// which would silently lose the un-migrated secrets). The window exists only
/// between a partial import and its retry; once the completion marker is written
/// it is closed for good.
pub fn import_secrets_once<S: SecretStore + ?Sized>(
    store: &mut S,
    exported: &ExportedSecrets,
    successor_generation: u32,
) -> Result<ImportOutcome, MigrateError> {
    let generation = exported.source_generation;

    // Bound the attacker-echoed source_generation (see `ExportedSecrets`): a
    // successor can only legitimately import from a strictly-older generation.
    if generation >= successor_generation {
        return Err(MigrateError::ImplausibleGeneration {
            source: generation,
            ceiling: successor_generation,
        });
    }

    // Already fully migrated at this generation? Direct key lookup, immune to the
    // enumeration cap.
    if store.has_secret(&done_marker(generation)) {
        return Ok(ImportOutcome::AlreadyMigrated { generation });
    }

    // Monotonicity: refuse to import an OLDER generation once a strictly-NEWER
    // one has completed, so a replayed older export cannot roll state back.
    if let Some(newest) = newest_completed_generation(store) {
        if newest > generation {
            return Ok(ImportOutcome::StaleGeneration {
                attempted: generation,
                newest_completed: newest,
            });
        }
    }

    // Phase 1: record intent BEFORE writing any secret. If even this fails, we
    // could not record migration state at all — surface a partial import.
    if !store.set_secret(&wip_marker(generation), b"1") {
        return Err(MigrateError::PartialImport {
            generation,
            imported: 0,
            skipped: 0,
            failed: 0,
        });
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for (k, v) in &exported.secrets {
        if is_marker(k) {
            // Reserved namespace — an export payload must never write a marker.
            continue;
        }
        if store.has_secret(k) {
            // Successor already has data under this key — do not clobber it.
            skipped += 1;
            continue;
        }
        if store.set_secret(k, v) {
            imported += 1;
        } else {
            // Honor the storage/host failure: do NOT count it as imported, do
            // NOT write the completion marker below. A retry will re-attempt it.
            failed += 1;
        }
    }

    // Phase 2: upgrade to the completion marker ONLY if every write succeeded.
    // (Short-circuits: a prior failure skips the marker write entirely.)
    if failed > 0 || !store.set_secret(&done_marker(generation), b"1") {
        return Err(MigrateError::PartialImport {
            generation,
            imported,
            skipped,
            failed,
        });
    }

    Ok(ImportOutcome::Imported {
        generation,
        imported,
        skipped,
    })
}

/// Whether `key` is in this crate's reserved marker namespace.
fn is_marker(key: &[u8]) -> bool {
    key.starts_with(MARKER_NS)
}

/// The in-progress marker key for a source generation.
fn wip_marker(generation: u32) -> Vec<u8> {
    let mut k = WIP_PREFIX.to_vec();
    k.extend_from_slice(generation.to_string().as_bytes());
    k
}

/// The completion marker key for a source generation.
pub(crate) fn done_marker(generation: u32) -> Vec<u8> {
    let mut k = DONE_PREFIX.to_vec();
    k.extend_from_slice(generation.to_string().as_bytes());
    k
}

/// The newest generation with a completion marker on this successor, if any.
///
/// Enumerates the reserved completion-marker prefix. Markers are few (one per
/// migrated generation) and crate-written, so they enumerate fully in practice;
/// the enumeration cap is not a concern for this handful of keys.
fn newest_completed_generation<S: SecretStore + ?Sized>(store: &S) -> Option<u32> {
    store
        .list_secrets(DONE_PREFIX)
        .iter()
        .filter_map(|k| {
            k.strip_prefix(DONE_PREFIX)
                .and_then(|rest| std::str::from_utf8(rest).ok())
                .and_then(|s| s.parse::<u32>().ok())
        })
        .max()
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
    use freenet_stdlib::prelude::{CodeHash, ContractInstanceId, DelegateKey};
    use std::collections::{BTreeMap, BTreeSet};

    /// In-memory `SecretStore` for tests (the wasm `DelegateCtx` bridge is not
    /// linkable natively).
    ///
    /// `fail_keys` models a host/storage write failure: `set_secret` for a key
    /// in this set returns `false` and stores nothing, exercising the two-phase
    /// import's failure handling.
    #[derive(Default)]
    struct MemStore {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
        fail_keys: BTreeSet<Vec<u8>>,
    }

    impl MemStore {
        fn fail_writes_to(&mut self, key: &[u8]) {
            self.fail_keys.insert(key.to_vec());
        }
        fn stop_failing(&mut self) {
            self.fail_keys.clear();
        }
    }

    impl SecretStore for MemStore {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.data.get(key).cloned()
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.data.contains_key(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            if self.fail_keys.contains(key) {
                return false;
            }
            self.data.insert(key.to_vec(), value.to_vec());
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

    fn whole_scope() -> ExportScope {
        ExportScope::EntireDelegate(
            SingleAppDelegateAck::i_certify_this_delegate_serves_a_single_web_app(),
        )
    }

    #[test]
    fn export_enumerates_every_secret_generically() {
        let store = v1_store();
        let origin = MessageOrigin::WebApp(ContractInstanceId::new([7u8; 32]));
        let policy = OriginPolicy::Any;
        let req = ExportRequest {
            source_generation: 3,
        };

        let msgs =
            handle_export_request(&store, Some(&origin), &policy, &whole_scope(), &req).unwrap();
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
        handle_export_request(
            &store,
            Some(&MessageOrigin::WebApp(app)),
            &policy,
            &whole_scope(),
            &req,
        )
        .unwrap();
        let err = handle_export_request(
            &store,
            Some(&MessageOrigin::WebApp(other)),
            &policy,
            &whole_scope(),
            &req,
        )
        .unwrap_err();
        assert!(matches!(err, MigrateError::UnauthorizedOrigin));
    }

    #[test]
    fn authorize_fails_closed_on_missing_origin() {
        // The stdlib entry point hands `origin: Option<MessageOrigin>`; `None`
        // (an unattested caller) must be rejected under every real policy.
        let app = ContractInstanceId::new([7u8; 32]);
        let dk = DelegateKey::new([3u8; 32], CodeHash::from_code(b"d"));
        for policy in [
            OriginPolicy::SameWebApp(app),
            OriginPolicy::FromDelegate(dk.clone()),
        ] {
            assert!(
                matches!(
                    policy.authorize(None),
                    Err(MigrateError::UnauthorizedOrigin)
                ),
                "policy {policy:?} must fail closed on a missing origin"
            );
        }
        // `Any` (explicitly unsafe / testing) is the sole policy accepting None.
        assert!(OriginPolicy::Any.authorize(None).is_ok());
    }

    #[test]
    fn authorize_from_delegate_and_cross_type() {
        let dk = DelegateKey::new([3u8; 32], CodeHash::from_code(b"caller"));
        let other_dk = DelegateKey::new([9u8; 32], CodeHash::from_code(b"other"));
        let app = ContractInstanceId::new([7u8; 32]);
        let policy = OriginPolicy::FromDelegate(dk.clone());

        // Matching delegate origin allowed.
        policy
            .authorize(Some(&MessageOrigin::Delegate(dk.clone())))
            .unwrap();
        // Non-matching delegate rejected.
        assert!(matches!(
            policy.authorize(Some(&MessageOrigin::Delegate(other_dk))),
            Err(MigrateError::UnauthorizedOrigin)
        ));
        // Cross-type: a WebApp origin under a FromDelegate policy is rejected.
        assert!(matches!(
            policy.authorize(Some(&MessageOrigin::WebApp(app))),
            Err(MigrateError::UnauthorizedOrigin)
        ));
        // Cross-type the other way: a Delegate origin under a SameWebApp policy.
        assert!(matches!(
            OriginPolicy::SameWebApp(app).authorize(Some(&MessageOrigin::Delegate(dk))),
            Err(MigrateError::UnauthorizedOrigin)
        ));
    }

    #[test]
    fn export_prefix_scoping_isolates_web_apps() {
        // A delegate shared by two web-apps that namespace their keys. An export
        // scoped to app A's prefix must not include app B's secrets (finding 3b).
        let mut store = MemStore::default();
        store.set_secret(b"appA:token", b"a-secret");
        store.set_secret(b"appA:pref", b"a-pref");
        store.set_secret(b"appB:token", b"b-secret");
        let origin = MessageOrigin::WebApp(ContractInstanceId::new([7u8; 32]));
        let req = ExportRequest {
            source_generation: 1,
        };

        let msgs = handle_export_request(
            &store,
            Some(&origin),
            &OriginPolicy::Any,
            &ExportScope::Prefix(b"appA:".to_vec()),
            &req,
        )
        .unwrap();
        let exported = extract_exported(&msgs);
        let keys: Vec<&[u8]> = exported.secrets.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(exported.secrets.len(), 2, "only appA's two secrets");
        assert!(keys.contains(&b"appA:token".as_slice()));
        assert!(keys.contains(&b"appA:pref".as_slice()));
        assert!(
            !keys.contains(&b"appB:token".as_slice()),
            "appB's secret must NOT leak to an appA-scoped export"
        );

        // The whole-scope (single-app) export, by contrast, includes both.
        let all = handle_export_request(
            &store,
            Some(&origin),
            &OriginPolicy::Any,
            &whole_scope(),
            &req,
        )
        .unwrap();
        assert_eq!(extract_exported(&all).secrets.len(), 3);
    }

    #[test]
    fn export_refuses_when_enumeration_truncated() {
        // Model host cap saturation: the store reports exactly the cap's worth of
        // keys (the truncated view). The export must refuse, never ship a subset.
        let mut store = MemStore::default();
        for i in 0..HOST_ENUMERATION_CAP {
            store.set_secret(format!("room:{i}").as_bytes(), b"v");
        }
        let origin = MessageOrigin::WebApp(ContractInstanceId::new([7u8; 32]));
        let err = handle_export_request(
            &store,
            Some(&origin),
            &OriginPolicy::Any,
            &whole_scope(),
            &ExportRequest {
                source_generation: 1,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                MigrateError::TruncatedExport { cap, .. } if cap == HOST_ENUMERATION_CAP
            ),
            "a truncated enumeration must refuse, got {err:?}"
        );
    }

    #[test]
    fn export_filters_reserved_markers() {
        // A leftover marker in the store must never appear in an export.
        let mut store = v1_store();
        store.set_secret(&done_marker(1), b"1");
        let origin = MessageOrigin::WebApp(ContractInstanceId::new([7u8; 32]));
        let msgs = handle_export_request(
            &store,
            Some(&origin),
            &OriginPolicy::Any,
            &whole_scope(),
            &ExportRequest {
                source_generation: 2,
            },
        )
        .unwrap();
        let exported = extract_exported(&msgs);
        assert_eq!(
            exported.secrets.len(),
            3,
            "the 3 real secrets, not the marker"
        );
        assert!(
            exported.secrets.iter().all(|(k, _)| !is_marker(k)),
            "no reserved marker key may be exported"
        );
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

        // First import writes both secrets + the completion marker.
        let first = import_secrets_once(&mut v2, &exported, 5).unwrap();
        assert_eq!(
            first,
            ImportOutcome::Imported {
                generation: 4,
                imported: 2,
                skipped: 0
            }
        );
        assert!(v2.has_secret(&done_marker(4)));
        let after_first = v2.list_secrets(b"").len();

        // Second import (e.g. a stray old-WASM re-run) writes nothing.
        let second = import_secrets_once(&mut v2, &exported, 5).unwrap();
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

        let outcome = import_secrets_once(&mut v2, &exported, 3).unwrap();
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
    fn import_two_phase_partial_write_then_retry() {
        // Regression for finding 1: a failed `set_secret` must NOT be counted as
        // imported and must NOT write the completion marker; a retry re-runs and
        // completes, and the missing secret is not lost forever.
        let exported = ExportedSecrets {
            source_generation: 4,
            secrets: vec![
                (b"a".to_vec(), b"va".to_vec()),
                (b"b".to_vec(), b"vb".to_vec()),
                (b"c".to_vec(), b"vc".to_vec()),
            ],
        };

        let mut v2 = MemStore::default();
        v2.fail_writes_to(b"b"); // storage/host error on one secret

        // Attempt 1: partial — one write fails.
        let err = import_secrets_once(&mut v2, &exported, 5).unwrap_err();
        assert_eq!(
            err,
            MigrateError::PartialImport {
                generation: 4,
                imported: 2,
                skipped: 0,
                failed: 1,
            }
        );
        assert!(
            !v2.has_secret(&done_marker(4)),
            "completion marker must be WITHHELD on a partial import"
        );
        assert!(
            v2.has_secret(&wip_marker(4)),
            "in-progress marker must be present so a retry re-runs"
        );
        assert_eq!(v2.get_secret(b"a").unwrap(), b"va");
        assert_eq!(v2.get_secret(b"c").unwrap(), b"vc");
        assert!(v2.get_secret(b"b").is_none(), "failed write stored nothing");

        // Retry after the storage error clears: the previously-failed key is
        // re-attempted (not silently lost), and the migration now completes.
        v2.stop_failing();
        let retry = import_secrets_once(&mut v2, &exported, 5).unwrap();
        assert_eq!(
            retry,
            ImportOutcome::Imported {
                generation: 4,
                imported: 1, // only `b` remained to write
                skipped: 2,  // `a` and `c` already present
            }
        );
        assert_eq!(v2.get_secret(b"b").unwrap(), b"vb");
        assert!(v2.has_secret(&done_marker(4)), "completion marker now set");

        // And a subsequent stray re-run is a no-op.
        assert_eq!(
            import_secrets_once(&mut v2, &exported, 5).unwrap(),
            ImportOutcome::AlreadyMigrated { generation: 4 }
        );
    }

    #[test]
    fn import_phase1_wip_marker_write_failure_imports_nothing() {
        // The phase-1 branch: if the in-progress marker itself can't be written
        // we cannot record migration state, so nothing is imported and a partial
        // import is surfaced (a retry re-runs from scratch).
        let exported = ExportedSecrets {
            source_generation: 4,
            secrets: vec![(b"a".to_vec(), b"va".to_vec())],
        };
        let mut v2 = MemStore::default();
        v2.fail_writes_to(&wip_marker(4)); // storage error on the intent marker

        let err = import_secrets_once(&mut v2, &exported, 5).unwrap_err();
        assert_eq!(
            err,
            MigrateError::PartialImport {
                generation: 4,
                imported: 0,
                skipped: 0,
                failed: 0,
            }
        );
        assert!(
            v2.list_secrets(b"").is_empty(),
            "no secret and no marker may be written when phase 1 fails"
        );

        // Once the store recovers, a retry runs the full import to completion.
        v2.stop_failing();
        let retry = import_secrets_once(&mut v2, &exported, 5).unwrap();
        assert_eq!(
            retry,
            ImportOutcome::Imported {
                generation: 4,
                imported: 1,
                skipped: 0,
            }
        );
        assert_eq!(v2.get_secret(b"a").unwrap(), b"va");
        assert!(v2.has_secret(&done_marker(4)));
    }

    #[test]
    fn import_done_marker_write_failure_withholds_completion() {
        // The phase-2 branch with `failed == 0`: every secret wrote fine, but the
        // completion marker write itself fails, so completion must be WITHHELD
        // (the in-progress marker stays, a retry completes) — never reported as
        // a successful import.
        let exported = ExportedSecrets {
            source_generation: 4,
            secrets: vec![(b"a".to_vec(), b"va".to_vec())],
        };
        let mut v2 = MemStore::default();
        v2.fail_writes_to(&done_marker(4)); // secrets + wip marker write; done marker fails

        let err = import_secrets_once(&mut v2, &exported, 5).unwrap_err();
        assert_eq!(
            err,
            MigrateError::PartialImport {
                generation: 4,
                imported: 1,
                skipped: 0,
                failed: 0,
            }
        );
        assert_eq!(v2.get_secret(b"a").unwrap(), b"va", "the secret did land");
        assert!(v2.has_secret(&wip_marker(4)), "in-progress marker remains");
        assert!(
            !v2.has_secret(&done_marker(4)),
            "completion must be withheld when the done-marker write fails"
        );

        // Retry after recovery: the secret is already present (skipped) and the
        // completion marker is now written.
        v2.stop_failing();
        let retry = import_secrets_once(&mut v2, &exported, 5).unwrap();
        assert_eq!(
            retry,
            ImportOutcome::Imported {
                generation: 4,
                imported: 0,
                skipped: 1,
            }
        );
        assert!(v2.has_secret(&done_marker(4)));
    }

    #[test]
    fn import_rejects_implausible_source_generation() {
        // Finding 10: a source_generation >= the successor's own generation is
        // implausible and must be refused, so it can't stamp a poisoning marker.
        let exported = ExportedSecrets {
            source_generation: u32::MAX,
            secrets: vec![(b"k".to_vec(), b"v".to_vec())],
        };
        let mut v2 = MemStore::default();
        let err = import_secrets_once(&mut v2, &exported, 5).unwrap_err();
        assert!(matches!(
            err,
            MigrateError::ImplausibleGeneration {
                source: u32::MAX,
                ceiling: 5
            }
        ));
        // Nothing was written — no marker to block a real future migration.
        assert!(v2.list_secrets(b"").is_empty());
    }

    #[test]
    fn import_refuses_older_generation_after_newer() {
        // Finding 2d: once generation 3 has been imported, a replayed older
        // generation-2 export must be refused (monotonicity), not applied.
        let mut v2 = MemStore::default();
        import_secrets_once(
            &mut v2,
            &ExportedSecrets {
                source_generation: 3,
                secrets: vec![(b"k3".to_vec(), b"v3".to_vec())],
            },
            5,
        )
        .unwrap();

        let older = ExportedSecrets {
            source_generation: 2,
            secrets: vec![(b"k2".to_vec(), b"v2".to_vec())],
        };
        let outcome = import_secrets_once(&mut v2, &older, 5).unwrap();
        assert_eq!(
            outcome,
            ImportOutcome::StaleGeneration {
                attempted: 2,
                newest_completed: 3,
            }
        );
        assert!(
            v2.get_secret(b"k2").is_none(),
            "the stale older export must not write anything"
        );
    }

    #[test]
    fn export_then_import_roundtrips() {
        let store = v1_store();
        let msgs = handle_export_request(
            &store,
            Some(&MessageOrigin::WebApp(ContractInstanceId::new([7u8; 32]))),
            &OriginPolicy::Any,
            &whole_scope(),
            &ExportRequest {
                source_generation: 9,
            },
        )
        .unwrap();
        let exported = extract_exported(&msgs);

        let mut v2 = MemStore::default();
        import_secrets_once(&mut v2, &exported, 10).unwrap();
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
