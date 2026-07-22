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
//! The import side uses a **two-phase** anti-resurrection marker: an in-progress
//! marker written *before* any write, upgraded to a completion marker only after
//! *every* write succeeds. A completed migration is never re-imported, so a stray
//! re-run of the old WASM cannot resurrect data the user has since deleted.
//!
//! There are **two** import primitives over a shared, private two-phase core:
//!
//! * [`import_predecessor_secrets_once`] keys its marker by the **predecessor
//!   delegate key** (plan §0). This is the seam-safe primitive the high-level
//!   entry points ([`crate::migrate_delegate_secrets`]) drive, and the one a
//!   future node-side `NodeCopyForward` copy writes too — the node knows delegate
//!   keys, not app-level generations, so the marker must be keyed by the key.
//! * [`import_secrets_once`] keys its marker by app-level **generation** and adds
//!   generation monotonicity. It is the lower-level single-generation primitive
//!   (retained; not on the seam — a node-side copy cannot write its markers).
//!
//! The app-facing migration entry points and the redesigned (sans-IO) transport
//! seam live in [`crate::delegate_migrate`]; this module holds the delegate-side
//! export/import primitives they build on.

use freenet_stdlib::prelude::{
    ApplicationMessage, CodeHash, ContractInstanceId, DelegateKey, MessageOrigin,
    OutboundDelegateMsg, Parameters,
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
/// Generation-keyed in-progress marker sub-prefix:
/// `MARKER_NS ++ b"wip:" ++ <gen decimal>` (used by [`import_secrets_once`]).
const WIP_PREFIX: &[u8] = b"\0freenet-migrate/wip:";
/// Generation-keyed completion marker sub-prefix:
/// `MARKER_NS ++ b"done:" ++ <gen decimal>` (used by [`import_secrets_once`]).
const DONE_PREFIX: &[u8] = b"\0freenet-migrate/done:";
/// Predecessor-delegate-key-keyed **in-progress** marker sub-prefix (private;
/// internal to the two-phase import): `MARKER_NS ++ b"v1/pred-wip:" ++ <32 raw
/// delegate-key bytes>`. The WIP marker's value carries the data/empty decision
/// so a retry is **sticky-data** — it keeps a data flag and upgrades an empty one
/// if the retry brings data (see [`import_predecessor_secrets_once`]).
const PRED_WIP_PREFIX: &[u8] = b"\0freenet-migrate/v1/pred-wip:";

/// Version of the **public** predecessor completion-marker format (below). The
/// version is embedded in [`PRED_DONE_MARKER_KEY_PREFIX`]; a breaking format
/// change bumps both.
pub const PRED_DONE_MARKER_VERSION: u8 = 1;

/// **Public, versioned, stable** completion-marker key prefix. The full marker
/// key is this prefix followed by the predecessor's 32-byte
/// [`DelegateKey::bytes()`]. See [`predecessor_done_marker`] for the cross-crate
/// contract with a node-side copy-forward.
pub const PRED_DONE_MARKER_KEY_PREFIX: &[u8] = b"\0freenet-migrate/v1/pred-done:";
/// Completion-marker VALUE for a **data-bearing** predecessor (≥1 real secret).
pub const PRED_DONE_MARKER_VALUE_DATA: &[u8] = b"1";
/// Completion-marker VALUE for an **empty** (NoData) predecessor.
pub const PRED_DONE_MARKER_VALUE_EMPTY: &[u8] = b"0";

/// One exported secret: `(raw key, value)`.
pub type SecretPair = (Vec<u8>, Vec<u8>);

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

    let w = write_secrets_two_phase(
        store,
        &wip_marker(generation),
        &done_marker(generation),
        b"1",
        &exported.secrets,
    );
    if !w.completed {
        return Err(MigrateError::PartialImport {
            generation,
            imported: w.imported,
            skipped: w.skipped,
            failed: w.failed,
        });
    }

    Ok(ImportOutcome::Imported {
        generation,
        imported: w.imported,
        skipped: w.skipped,
    })
}

/// Outcome of the shared two-phase write core ([`write_secrets_two_phase`]).
struct TwoPhaseWrite {
    /// Secrets written on this attempt.
    imported: usize,
    /// Secrets skipped because the successor already held that key.
    skipped: usize,
    /// Secrets whose write failed.
    failed: usize,
    /// Whether the completion marker was written (every secret wrote AND the
    /// done-marker write itself succeeded). `false` leaves the in-progress
    /// marker so a retry re-runs.
    completed: bool,
}

/// The shared two-phase never-clobber write, parameterized by its marker keys so
/// both the generation-keyed ([`import_secrets_once`]) and delegate-key-keyed
/// ([`import_predecessor_secrets_once`]) primitives share one implementation.
///
/// 1. Write `wip_marker` (intent) BEFORE any secret. If it fails, nothing is
///    written and `completed` is `false` with zero counts.
/// 2. For each secret: skip reserved markers, skip keys the successor already
///    holds (never clobber), attempt the write, count imported / failed.
/// 3. Write `done_marker` ONLY if every secret wrote. `completed` is `true` only
///    then. (Short-circuits: a prior failure never writes the done marker.)
///
/// Both markers are written with `marker_value`. For the delegate-key path this
/// is the data/empty flag, written on the WIP marker at phase 1 so a *retry* can
/// read it back and apply the sticky-data rule (keep data, upgrade empty→data);
/// the generation path passes `b"1"`.
fn write_secrets_two_phase<S: SecretStore + ?Sized>(
    store: &mut S,
    wip_marker: &[u8],
    done_marker: &[u8],
    marker_value: &[u8],
    secrets: &[(Vec<u8>, Vec<u8>)],
) -> TwoPhaseWrite {
    // Phase 1: record intent (and the data/empty flag) BEFORE writing any secret.
    // If even this fails, we could not record migration state at all — nothing is
    // written.
    if !store.set_secret(wip_marker, marker_value) {
        return TwoPhaseWrite {
            imported: 0,
            skipped: 0,
            failed: 0,
            completed: false,
        };
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for (k, v) in secrets {
        if is_marker(k) {
            // Reserved namespace — an import payload must never write a marker.
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
    // (`&&` short-circuits: a prior failure skips the marker write entirely.)
    let completed = failed == 0 && store.set_secret(done_marker, marker_value);
    TwoPhaseWrite {
        imported,
        skipped,
        failed,
        completed,
    }
}

/// Outcome of [`import_predecessor_secrets_once`] — the delegate-key-keyed
/// import primitive.
///
/// Unlike [`ImportOutcome`] there is no `generation` (the migration is keyed by
/// the predecessor **delegate key**, not a generation) and no `StaleGeneration`
/// (cross-predecessor precedence is handled by the newest-first walk in the
/// [`crate::migrate_delegate_secrets`] driver plus never-clobber, so an older
/// predecessor can never overwrite a newer one's value). A two-phase partial
/// write is reported as [`PredecessorImportOutcome::Incomplete`] (an outcome, so
/// one predecessor's storage failure does not abort a multi-predecessor
/// migration) rather than as an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredecessorImportOutcome {
    /// Import completed; `imported` new secrets written, `skipped` left untouched
    /// because a value already existed under that key (never clobbered). The
    /// predecessor-key completion marker is now set, so no future call
    /// re-imports from this predecessor.
    Imported {
        /// Number of secrets written.
        imported: usize,
        /// Number of secrets skipped because the key already existed.
        skipped: usize,
    },
    /// The predecessor-key completion marker was already present; nothing was
    /// written (idempotent re-run, no resurrection).
    AlreadyMigrated,
    /// At least one `set_secret` write failed (or the completion marker could
    /// not be written). The completion marker was deliberately withheld, so the
    /// migration is left in its in-progress state and a retry re-runs it. A
    /// failed write is never counted as imported.
    Incomplete {
        /// Secrets successfully written on this attempt.
        imported: usize,
        /// Secrets skipped because the successor already held that key.
        skipped: usize,
        /// Secrets whose write failed.
        failed: usize,
    },
}

/// Import a predecessor's secrets into the successor exactly once, keyed by the
/// **predecessor delegate key** (plan §0).
///
/// This is the seam-safe import primitive the high-level entry point
/// ([`crate::migrate_delegate_secrets`]) drives. The two-phase anti-resurrection
/// marker is keyed by `predecessor`'s delegate-key bytes rather than an app-level
/// generation, precisely so a future node-side `NodeCopyForward` copy — which
/// knows delegate keys, not generations — writes and recognizes the **same**
/// marker. That is what lets the node primitive slot under the unchanged entry
/// points with no re-adoption and no double-import / resurrection.
///
/// Never clobbers a key the successor already holds. Idempotent: once the
/// predecessor-key completion marker is set, a re-run returns
/// [`PredecessorImportOutcome::AlreadyMigrated`] and writes nothing, so a stray
/// re-run cannot resurrect a secret the user deleted after a completed migration.
///
/// The `source_generation` echo and the generation-monotonicity guard of
/// [`import_secrets_once`] are deliberately absent: the predecessor key comes
/// from the build-time-validated lineage (not an attacker-echoed field), and
/// cross-predecessor precedence is decided by the caller's
/// [`crate::SecretSelectionPolicy`] plus never-clobber.
///
/// The completion marker records whether the migrated predecessor was
/// **data-bearing or empty**, so a re-run can reconstruct the same selection
/// decision (a `NewestSnapshotWins` walk stops at the newest *data-bearing*
/// predecessor — see the crate-internal `predecessor_migration_had_data`). A
/// NoData predecessor is imported through here with an empty `secrets` slice
/// precisely so its marker is written and a later re-run is a true no-op even if
/// the old delegate later gains data.
///
/// ## Residual limits
///
/// **Interrupted-then-retried (per-predecessor).** The same window as
/// [`import_secrets_once`]: a key the user deletes *during* an interrupted
/// migration can be resurrected by the completing retry. It exists only between a
/// partial import and its retry, and closing it is scoped **to this predecessor's
/// marker** — once *this predecessor's* completion marker is written the window is
/// closed for that predecessor (it says nothing about other predecessors).
///
/// **Lineage growth.** Because the marker is per-predecessor, appending a *new,
/// older* predecessor to the lineage after a completed migration presents an
/// unmarked predecessor whose keys have never been imported — re-opening the
/// resurrection window for keys unique to it (a key the user deleted that lives
/// only in that late-added generation could come back when it is imported). How
/// the driver handles it depends on the [`crate::SecretSelectionPolicy`]:
///
/// * `NewestSnapshotWins` (default) **closes this window** whenever a newer
///   predecessor already yielded data: on the re-run the newer predecessor's
///   data-bearing `pred-done` marker re-establishes authority, so the late-added
///   older predecessor is `Superseded` and never imported. It is imported only if
///   no newer predecessor has yet yielded data (the ordinary "recover from the
///   older generation" case).
/// * `UnionAllGenerations` imports the late-added older predecessor (never-clobber,
///   so only keys the successor lacks), which is exactly the ack'd
///   delete-by-absence resurrection that policy opts into.
pub fn import_predecessor_secrets_once<S: SecretStore + ?Sized>(
    store: &mut S,
    predecessor: &DelegateKey,
    secrets: &[(Vec<u8>, Vec<u8>)],
) -> PredecessorImportOutcome {
    // Already fully migrated from this predecessor? Direct key lookup, immune to
    // the enumeration cap. This is THE anti-resurrection gate (plan §0).
    if predecessor_already_migrated(store, predecessor) {
        return PredecessorImportOutcome::AlreadyMigrated;
    }

    // The data/empty decision is **sticky-data** across a retry: a predecessor is
    // sealed data-bearing if ANY attempt saw real data. A surviving WIP marker
    // from an earlier (Incomplete) attempt carries that attempt's flag; this
    // attempt ORs its own observation onto it. So BOTH retry directions are safe —
    // data-then-empty keeps its data flag, and empty-then-data upgrades to data —
    // and neither can seal the marker "empty" while data was imported, which would
    // make NewestSnapshotWins misclassify NoData and fall through to older
    // generations (resurrection). First attempt: just this call's observation.
    let wip_marker = pred_wip_marker(predecessor);
    let current_had_data = secrets.iter().any(|(k, _)| !is_marker(k));
    let had_data = match store.get_secret(&wip_marker) {
        Some(flag) => (flag != PRED_DONE_MARKER_VALUE_EMPTY) || current_had_data,
        None => current_had_data,
    };
    let marker_value = if had_data {
        PRED_DONE_MARKER_VALUE_DATA
    } else {
        PRED_DONE_MARKER_VALUE_EMPTY
    };

    let w = write_secrets_two_phase(
        store,
        &wip_marker,
        &pred_done_marker(predecessor),
        marker_value,
        secrets,
    );
    if !w.completed {
        return PredecessorImportOutcome::Incomplete {
            imported: w.imported,
            skipped: w.skipped,
            failed: w.failed,
        };
    }
    PredecessorImportOutcome::Imported {
        imported: w.imported,
        skipped: w.skipped,
    }
}

/// Whether a completed migration from `predecessor` is already recorded (its
/// delegate-key completion marker is present). Lets the migration driver skip a
/// preflight/fetch round-trip for an already-migrated predecessor.
pub(crate) fn predecessor_already_migrated<S: SecretStore + ?Sized>(
    store: &S,
    predecessor: &DelegateKey,
) -> bool {
    store.has_secret(&pred_done_marker(predecessor))
}

/// Reconstruct a completed predecessor migration's data/empty state from its
/// marker value: `Some(true)` = it was data-bearing, `Some(false)` = it executed
/// empty (NoData), `None` = no completed migration recorded.
///
/// A `NewestSnapshotWins` walk uses this so a re-run stops at the same newest
/// *data-bearing* predecessor it did the first time (an empty AlreadyMigrated
/// predecessor is fallen through, a data-bearing one is authoritative). An
/// unrecognized value is treated conservatively as data-bearing.
pub(crate) fn predecessor_migration_had_data<S: SecretStore + ?Sized>(
    store: &S,
    predecessor: &DelegateKey,
) -> Option<bool> {
    store
        .get_secret(&pred_done_marker(predecessor))
        .map(|v| v != PRED_DONE_MARKER_VALUE_EMPTY)
}

/// The legacy-marker bridge (P1#3): whether a **generation-keyed**
/// ([`import_secrets_once`]) migration has already covered `generation` — i.e.
/// some `done:<gen>` marker exists with `gen >= generation`. Used under
/// `NewestSnapshotWins`, where a newer legacy snapshot is authoritative and the
/// conservative seal is correct.
///
/// The two import APIs must never be mixed on one store (the delegate-key path is
/// the seam-safe one; see the crate README). This bridge makes the delegate-key
/// path *defensively* honor a store that a prior generation-keyed migration
/// already wrote to.
pub(crate) fn legacy_generation_migrated<S: SecretStore + ?Sized>(
    store: &S,
    generation: u32,
) -> bool {
    newest_completed_generation(store).is_some_and(|newest| newest >= generation)
}

/// The legacy-marker bridge under `UnionAllGenerations`: only the **exact**
/// generation counts as already-migrated. A generation *below* the newest legacy
/// done marker was **barred** by the legacy path's monotonicity (it was never
/// imported), so Union should still recover it rather than treat it as done.
pub(crate) fn legacy_generation_migrated_exact<S: SecretStore + ?Sized>(
    store: &S,
    generation: u32,
) -> bool {
    store.has_secret(&done_marker(generation))
}

/// The predecessor-key in-progress marker: `PRED_WIP_PREFIX ++ key bytes`.
fn pred_wip_marker(predecessor: &DelegateKey) -> Vec<u8> {
    let mut k = PRED_WIP_PREFIX.to_vec();
    k.extend_from_slice(predecessor.bytes());
    k
}

/// The predecessor-key completion marker key: `PRED_DONE_MARKER_KEY_PREFIX ++
/// key bytes` — the same bytes [`predecessor_done_marker`] publishes.
///
/// `pub(crate)` so the migration driver's tests can seed an already-migrated
/// predecessor; the real gate is [`predecessor_already_migrated`].
pub(crate) fn pred_done_marker(predecessor: &DelegateKey) -> Vec<u8> {
    let mut k = PRED_DONE_MARKER_KEY_PREFIX.to_vec();
    k.extend_from_slice(predecessor.bytes());
    k
}

/// Build the `(key, value)` **completion-marker secret** that a node-side
/// copy-forward (freenet-core#2776) must write, under the successor delegate's
/// Local secret scope, for each predecessor it has **fully** copied.
///
/// This is the public, versioned cross-crate contract (see
/// [`PRED_DONE_MARKER_KEY_PREFIX`] / [`PRED_DONE_MARKER_VERSION`]): once this
/// exact secret is present, [`crate::migrate_delegate_secrets`] short-circuits
/// that predecessor to `AlreadyMigrated` and does no app-side round-trip. Seal
/// only completed predecessors — a partially-copied one must have **no** marker,
/// so the app-side fallback retries it.
///
/// `had_data` is whether at least one real secret was copied from the predecessor
/// ([`PRED_DONE_MARKER_VALUE_DATA`] vs [`PRED_DONE_MARKER_VALUE_EMPTY`]).
///
/// # Contract: markers are per-successor and MUST NOT be swept forward
///
/// A marker is written under the successor's Local scope, but a copy-forward
/// **must not carry the reserved `\0freenet-migrate/` namespace onward** when it
/// later copies this successor to a *further* successor — skip every registered
/// key with that prefix during the copy walk. The app-side path already does:
/// [`import_predecessor_secrets_once`] skips every reserved-namespace key on
/// import, so it structurally cannot sweep a marker forward. Excluding them
/// node-side gives both transports **identical completion-marker semantics** (a
/// `pred-done` marker means "this exact migration completed," never "an ancestor's
/// data is transitively present"), so a later chained migration behaves the same
/// however each generation was migrated. (The app path additionally leaves a
/// crate-internal `pred-wip` marker behind; that is not part of the shared
/// completion contract and is never read once the `pred-done` marker exists.)
pub fn predecessor_done_marker(predecessor: &DelegateKey, had_data: bool) -> (Vec<u8>, Vec<u8>) {
    let value = if had_data {
        PRED_DONE_MARKER_VALUE_DATA
    } else {
        PRED_DONE_MARKER_VALUE_EMPTY
    };
    (pred_done_marker(predecessor), value.to_vec())
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

// The swappable transport that reaches into a predecessor delegate's secrets was
// re-altituded in plan v2. The old `SecretTransport { export_from -> ExportedSecrets }`
// (synchronous, returns bytes) could host neither real transport: the interim
// path is app-side async request/response round-trips through a shared,
// uncorrelated response handler, and a future node-side copy returns *nothing*
// app-side (it copies secrets internally — a security win). So the redesigned,
// sans-IO transport (`migrate_from(predecessors) -> Outcome`) and the stable
// app-facing entry points now live in `crate::delegate_migrate`; the transport
// is an internal seam there, not part of the app-facing contract.

/// The predecessor `DelegateKey`s to address old delegates during a probe.
///
/// Built from each entry's **stored** `delegate_key` — the key the old delegate
/// actually had on the network — never by re-deriving from `code_hash`. The
/// distinction is load-bearing for `irregular_key` rows (e.g. River's V1/V2,
/// whose recorded keys predate the standard derivation): re-derivation would
/// target a key that never existed, so the probe would silently find nothing
/// and strand that generation's data. Regular rows' stored keys are
/// cross-checked against the derivation at build time (and again in
/// [`predecessor_delegate_keys_checked`]), so using the stored key never
/// weakens the regular case.
///
/// Infallible: a generated lineage's keys cannot be malformed (decoded and
/// validated at build time).
pub fn predecessor_delegate_keys(lineage: &[DelegateLineageEntry]) -> Vec<DelegateKey> {
    lineage
        .iter()
        .map(|e| DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash)))
        .collect()
}

/// Like [`predecessor_delegate_keys`], but re-derives
/// `blake3(code_hash ‖ params)` for every **regular** entry and asserts it
/// equals the stored `delegate_key` (a data-integrity guard mirroring Delta's
/// build-time assert; `irregular_key` rows are exempt by definition — their
/// recorded keys deliberately do not derive).
///
/// The single `params` is applied to every entry, so this check only holds for
/// lineages whose generations all share the caller's params (the empty-params
/// River/Delta case). A registry with per-row `params_hex` values is instead
/// cross-checked per-row at build time by `freenet-migrate-build`'s
/// `Registry::validate`; the probe itself ([`predecessor_delegate_keys`]) is
/// params-independent either way, since it targets stored keys.
pub fn predecessor_delegate_keys_checked(
    params: &Parameters,
    lineage: &[DelegateLineageEntry],
) -> Result<Vec<DelegateKey>, MigrateError> {
    for entry in lineage.iter().filter(|e| !e.irregular_key) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entry.code_hash);
        hasher.update(params.as_ref());
        let derived = *hasher.finalize().as_bytes();
        if derived != entry.delegate_key {
            return Err(MigrateError::BadCodeHash(format!(
                "delegate gen {}: derived key {} != registered {}",
                entry.generation,
                bs58::encode(derived)
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .into_string(),
                entry.delegate_key_b58(),
            )));
        }
    }
    Ok(predecessor_delegate_keys(lineage))
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

    fn dk(n: u8) -> DelegateKey {
        DelegateKey::new([n; 32], CodeHash::from_code(&[n]))
    }

    #[test]
    fn import_predecessor_secrets_is_idempotent_via_delegate_key_marker() {
        // The plan §0 anti-resurrection guarantee, keyed by DELEGATE KEY: a first
        // import writes the secrets and the pred-done marker; a stray re-run (a
        // node-side copy or an old-WASM replay) is a no-op.
        let key = dk(1);
        let secrets = vec![
            (b"rooms_data".to_vec(), b"room-blob".to_vec()),
            (b"outbound_dms".to_vec(), b"dm-blob".to_vec()),
        ];
        let mut v2 = MemStore::default();

        let first = import_predecessor_secrets_once(&mut v2, &key, &secrets);
        assert_eq!(
            first,
            PredecessorImportOutcome::Imported {
                imported: 2,
                skipped: 0
            }
        );
        assert!(v2.has_secret(&pred_done_marker(&key)));
        let after_first = v2.list_secrets(b"").len();

        let second = import_predecessor_secrets_once(&mut v2, &key, &secrets);
        assert_eq!(second, PredecessorImportOutcome::AlreadyMigrated);
        assert_eq!(
            v2.list_secrets(b"").len(),
            after_first,
            "re-import from the same predecessor must not resurrect or duplicate"
        );
        assert!(predecessor_already_migrated(&v2, &key));
    }

    #[test]
    fn import_predecessor_markers_are_per_key_not_shared() {
        // Two distinct predecessors migrate independently: completing one must
        // NOT mark the other as done (markers are per delegate key).
        let (a, b) = (dk(1), dk(2));
        let mut v2 = MemStore::default();
        import_predecessor_secrets_once(&mut v2, &a, &[(b"ka".to_vec(), b"va".to_vec())]);
        assert!(predecessor_already_migrated(&v2, &a));
        assert!(
            !predecessor_already_migrated(&v2, &b),
            "a's completion must not mark b migrated"
        );
        // b still imports its own data.
        let out = import_predecessor_secrets_once(&mut v2, &b, &[(b"kb".to_vec(), b"vb".to_vec())]);
        assert_eq!(
            out,
            PredecessorImportOutcome::Imported {
                imported: 1,
                skipped: 0
            }
        );
        assert_eq!(v2.get_secret(b"ka").unwrap(), b"va");
        assert_eq!(v2.get_secret(b"kb").unwrap(), b"vb");
    }

    #[test]
    fn import_predecessor_never_clobbers_and_filters_markers() {
        let key = dk(3);
        let mut v2 = MemStore::default();
        v2.set_secret(b"rooms_data", b"NEWER"); // successor already has newer data
        let secrets = vec![
            (b"rooms_data".to_vec(), b"OLD".to_vec()),
            (b"new_key".to_vec(), b"fresh".to_vec()),
            // A stray reserved marker in the payload must never be written.
            (pred_done_marker(&dk(9)), b"1".to_vec()),
        ];
        let out = import_predecessor_secrets_once(&mut v2, &key, &secrets);
        assert_eq!(
            out,
            PredecessorImportOutcome::Imported {
                imported: 1, // only new_key
                skipped: 1,  // rooms_data already present
            }
        );
        assert_eq!(v2.get_secret(b"rooms_data").unwrap(), b"NEWER");
        assert_eq!(v2.get_secret(b"new_key").unwrap(), b"fresh");
        assert!(
            !v2.has_secret(&pred_done_marker(&dk(9))),
            "a marker key in the payload must never be written"
        );
    }

    #[test]
    fn import_predecessor_two_phase_partial_then_retry() {
        // A failed write withholds the completion marker (Incomplete), leaves the
        // in-progress marker, and a retry re-runs and completes.
        let key = dk(4);
        let secrets = vec![
            (b"a".to_vec(), b"va".to_vec()),
            (b"b".to_vec(), b"vb".to_vec()),
            (b"c".to_vec(), b"vc".to_vec()),
        ];
        let mut v2 = MemStore::default();
        v2.fail_writes_to(b"b");

        let out = import_predecessor_secrets_once(&mut v2, &key, &secrets);
        assert_eq!(
            out,
            PredecessorImportOutcome::Incomplete {
                imported: 2,
                skipped: 0,
                failed: 1,
            }
        );
        assert!(
            !v2.has_secret(&pred_done_marker(&key)),
            "completion marker withheld on a partial import"
        );
        assert!(
            v2.has_secret(&pred_wip_marker(&key)),
            "in-progress marker present so a retry re-runs"
        );
        assert!(!predecessor_already_migrated(&v2, &key));

        v2.stop_failing();
        let retry = import_predecessor_secrets_once(&mut v2, &key, &secrets);
        assert_eq!(
            retry,
            PredecessorImportOutcome::Imported {
                imported: 1, // only b remained
                skipped: 2,  // a and c already present
            }
        );
        assert_eq!(v2.get_secret(b"b").unwrap(), b"vb");
        assert!(predecessor_already_migrated(&v2, &key));
        // A subsequent stray re-run is a no-op.
        assert_eq!(
            import_predecessor_secrets_once(&mut v2, &key, &secrets),
            PredecessorImportOutcome::AlreadyMigrated
        );
    }

    #[test]
    fn predecessor_markers_are_filtered_from_a_whole_scope_export() {
        // A pred-* marker left in a delegate's store must never be exported (it
        // is under the reserved MARKER_NS like the generation markers).
        let mut store = v1_store();
        store.set_secret(&pred_done_marker(&dk(7)), b"1");
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
        assert!(exported.secrets.iter().all(|(k, _)| !is_marker(k)));
    }

    #[test]
    fn pred_done_marker_format_is_stable() {
        // The public marker format is a cross-crate contract with freenet-core's
        // copy-forward. Pin the EXACT bytes so any drift breaks CI (a node writing
        // a different marker would silently defeat the short-circuit).
        assert_eq!(PRED_DONE_MARKER_VERSION, 1);
        assert_eq!(
            PRED_DONE_MARKER_KEY_PREFIX,
            b"\0freenet-migrate/v1/pred-done:"
        );
        assert_eq!(PRED_DONE_MARKER_VALUE_DATA, b"1");
        assert_eq!(PRED_DONE_MARKER_VALUE_EMPTY, b"0");

        let key = DelegateKey::new([7u8; 32], CodeHash::from_code(b"x"));
        let (mk, mv) = predecessor_done_marker(&key, true);
        let mut expected_key = b"\0freenet-migrate/v1/pred-done:".to_vec();
        expected_key.extend_from_slice(&[7u8; 32]);
        assert_eq!(
            mk, expected_key,
            "marker key = prefix ++ 32 delegate-key bytes"
        );
        assert_eq!(mv, b"1");
        assert_eq!(predecessor_done_marker(&key, false).1, b"0");
        assert!(is_marker(&mk), "marker is under the reserved namespace");

        // A marker written via the PUBLIC format is recognized by the reader path.
        let mut store = MemStore::default();
        store.set_secret(&mk, &mv);
        assert!(predecessor_already_migrated(&store, &key));
        assert_eq!(predecessor_migration_had_data(&store, &key), Some(true));
    }

    #[test]
    fn import_predecessor_retry_preserves_data_flag_after_incomplete() {
        // P1 retry-flip (exact Codex order): attempt 1 is data-bearing but a write
        // FAILS (Incomplete); the retry's re-export is EMPTY. The completion marker
        // must stay DATA-bearing (preserved from the WIP marker written on attempt
        // 1), NOT flip to empty — otherwise the predecessor would lose its
        // NewestSnapshotWins authority on a later re-run.
        let key = dk(2);
        let mut store = MemStore::default();
        store.fail_writes_to(b"x");

        let attempt1 =
            import_predecessor_secrets_once(&mut store, &key, &[(b"x".to_vec(), b"vx".to_vec())]);
        assert!(matches!(
            attempt1,
            PredecessorImportOutcome::Incomplete { failed: 1, .. }
        ));
        assert!(
            !predecessor_already_migrated(&store, &key),
            "no done marker yet"
        );

        // Retry with an EMPTY re-export (the old delegate lost its data meanwhile).
        let retry = import_predecessor_secrets_once(&mut store, &key, &[]);
        assert!(matches!(retry, PredecessorImportOutcome::Imported { .. }));
        assert!(predecessor_already_migrated(&store, &key));
        assert_eq!(
            predecessor_migration_had_data(&store, &key),
            Some(true),
            "the data flag must be preserved across a data-then-empty retry"
        );
    }

    #[test]
    fn import_predecessor_retry_upgrades_empty_flag_to_data() {
        // P1 sticky-data (the mirror-image order): attempt 1 is EMPTY and the
        // DONE-marker write FAILS → Incomplete, recording an empty WIP flag. The
        // retry brings DATA → the flag must UPGRADE to data-bearing, or
        // NewestSnapshotWins would misclassify NoData and fall through to older
        // generations (resurrection).
        let key = dk(2);
        let mut store = MemStore::default();
        // Fail the DONE-marker write so an EMPTY first attempt goes Incomplete
        // (with the empty WIP flag persisted) rather than completing as NoData.
        store.fail_writes_to(&pred_done_marker(&key));

        let attempt1 = import_predecessor_secrets_once(&mut store, &key, &[]);
        assert!(matches!(
            attempt1,
            PredecessorImportOutcome::Incomplete { .. }
        ));
        assert_eq!(
            store.get_secret(&pred_wip_marker(&key)),
            Some(b"0".to_vec()),
            "attempt 1 recorded an EMPTY WIP flag"
        );

        // Retry brings data; the DONE-marker write now succeeds.
        store.stop_failing();
        let retry =
            import_predecessor_secrets_once(&mut store, &key, &[(b"x".to_vec(), b"vx".to_vec())]);
        assert!(matches!(
            retry,
            PredecessorImportOutcome::Imported { imported: 1, .. }
        ));
        assert_eq!(store.get_secret(b"x").unwrap(), b"vx");
        assert_eq!(
            predecessor_migration_had_data(&store, &key),
            Some(true),
            "the empty flag must UPGRADE to data-bearing when the retry brings data"
        );
    }

    #[test]
    fn predecessor_delegate_keys_uses_stored_key_and_checked_agrees() {
        // River/Delta delegates use empty params, so key = blake3(code_hash).
        let params = Parameters::from(Vec::new());
        let wasm = b"delegate wasm v1";
        let code_hash = CodeHash::from_code(wasm);

        // Independent expected derivation: blake3(code_hash ‖ params).
        let mut h = blake3::Hasher::new();
        h.update(&*code_hash);
        h.update(params.as_ref());
        let expected_key = *h.finalize().as_bytes();

        let lineage = [DelegateLineageEntry {
            generation: 0,
            code_hash: *code_hash,
            delegate_key: expected_key,
            irregular_key: false,
            note: "v1",
        }];

        let keys = predecessor_delegate_keys(&lineage);
        assert_eq!(keys[0].bytes(), expected_key);
        assert_eq!(keys[0].code_hash(), &code_hash);
        // Cross-check against stdlib's own derivation from the b58 string.
        let stdlib_key = DelegateKey::from_params(code_hash.encode(), &params).unwrap();
        assert_eq!(keys[0], stdlib_key);
        // The checked variant agrees because the stored key derives correctly.
        assert_eq!(
            predecessor_delegate_keys_checked(&params, &lineage).unwrap(),
            keys
        );
    }

    #[test]
    fn predecessor_delegate_keys_checked_flags_mismatch() {
        let params = Parameters::from(Vec::new());
        let lineage = [DelegateLineageEntry {
            generation: 0,
            code_hash: *CodeHash::from_code(b"delegate wasm v2"),
            // Deliberately wrong stored key on a row NOT marked irregular.
            delegate_key: [7u8; 32],
            irregular_key: false,
            note: "",
        }];
        let err = predecessor_delegate_keys_checked(&params, &lineage).unwrap_err();
        assert!(matches!(err, MigrateError::BadCodeHash(_)));
    }

    #[test]
    fn irregular_rows_probe_recorded_key_and_pass_checked() {
        // River V1/V2 class: the recorded key does NOT derive from code_hash.
        // The probe must target the recorded key (re-derivation would target a
        // key that never existed on the network), and `_checked` must exempt
        // the row rather than fail the whole lineage.
        let params = Parameters::from(Vec::new());
        let recorded_key = [9u8; 32]; // not blake3(code_hash ‖ params)
        let lineage = [DelegateLineageEntry {
            generation: 1,
            code_hash: *CodeHash::from_code(b"ancient delegate wasm"),
            delegate_key: recorded_key,
            irregular_key: true,
            note: "V1: pre-standard derivation",
        }];
        let keys = predecessor_delegate_keys(&lineage);
        assert_eq!(keys[0].bytes(), recorded_key);
        // The full DelegateKey addresses by (key, code_hash) — the code_hash
        // field must carry the entry's real code hash, not a derived one.
        assert_eq!(
            keys[0].code_hash(),
            &CodeHash::from_code(b"ancient delegate wasm")
        );
        let checked = predecessor_delegate_keys_checked(&params, &lineage).unwrap();
        assert_eq!(checked[0].bytes(), recorded_key);
    }
}
