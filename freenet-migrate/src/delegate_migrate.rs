//! Delegate secret migration — the app-facing entry points (plan G1.7 delegate
//! half + G1.8) and the redesigned, sans-IO transport seam Gap 3 swaps under.
//!
//! # The altitude decision (plan v2's central correction)
//!
//! The **stable app-facing contract is the high-level entry points**
//! ([`migrate_delegate_secrets`], [`register_delegate_with_migration`]), with
//! consent ([`MigrationAuthorization`]) baked in from day one. The transport that
//! actually moves the secrets — app-side round-trips today, a node-side copy
//! tomorrow — is an **internal, redesigned detail** (the crate-private
//! `SecretTransport` seam), not something apps program against.
//!
//! This is the load-bearing correction over v1. The old
//! `SecretTransport::export_from(predecessor) -> ExportedSecrets` (synchronous,
//! returns bytes) could host *neither* real transport:
//!
//! * the **interim** path is app-side async request/response round-trips through
//!   a shared, uncorrelated response handler (the browser's `WebApi` delivers
//!   every response to one app-registered handler — correlation is the app's
//!   job, so the crate cannot drive the loop and cannot unwrap a response
//!   synchronously); and
//! * a future **node copy-forward** returns *nothing* app-side — the node copies
//!   secrets between namespaces internally, without executing old code (a
//!   security win, and the fix for the `ReRunOldWasm` / #204 landmine).
//!
//! So the seam moved up one level: apps call the entry points; the transport is
//! swapped under them. Getting this wrong would recreate adoption friction one
//! layer up — the exact failure Gap 1 exists to prevent.
//!
//! # sans-IO decomposition
//!
//! The crate owns the **decisions** — which predecessors, newest-first, the
//! executability preflight before ever concluding "no data" (G1.8), when a
//! predecessor is already migrated, how to classify each outcome — and the app
//! owns the **I/O** through a thin [`PredecessorSecretsIo`] adapter (modeled on
//! the contract side's [`crate::ProbeIo`]): one round-trip per call, correlation
//! and transport left to the app.
//!
//! ```text
//! for predecessor in newest_first(predecessors) {
//!     if already_migrated(predecessor) { record AlreadyMigrated; continue }
//!     match io.probe_executable(predecessor).await? {          // G1.8 preflight
//!         false => { record Unresponsive; continue }           // data may exist,
//!         true  => {                                           //   can't migrate
//!             let secrets = io.fetch_secrets(predecessor).await?;
//!             import_predecessor_secrets_once(store, predecessor, &secrets)  // §0 marker
//!         }
//!     }
//! }
//! ```
//!
//! Honest limits — what stays app code the crate cannot verify: the I/O adapter
//! itself (send / correlate / time out); what a "cheap no-op probe" is in the
//! app's own delegate protocol; and (until Gap 3) the dependence on the node
//! still having the **old delegate WASM registered** so the preflight can reach
//! it at all (see [`PredecessorSecretsIo::probe_executable`]).

use core::future::Future;

use freenet_stdlib::prelude::{CodeHash, DelegateKey};

use crate::delegate::{
    import_predecessor_secrets_once, predecessor_already_migrated, PredecessorImportOutcome,
    SecretPair, SecretStore,
};
use crate::lineage::DelegateLineageEntry;

/// Consent / authorization for a secret migration — a **required** parameter of
/// the app-facing entry points from day one (plan §0).
///
/// It is an `enum` with room to grow, deliberately **not a `bool`**: Gap 3's
/// per-transition user consent plus the node-recorded same-origin binding slot in
/// as a new variant *without changing any entry-point signature*, so landing the
/// node copy-forward needs no app re-adoption.
///
/// The interim variant [`AppAuthorAck`](Self::AppAuthorAck) is an explicit,
/// loudly-constructed **no-op**: the app author vouches for the migration. It is
/// NOT user consent and NOT an origin binding — those are the real gates that
/// arrive with the node primitive. Requiring a value here today is what makes the
/// stronger gate a drop-in later.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationAuthorization {
    /// Interim no-op: the app author authorizes this migration. There is no
    /// per-transition user consent and no node-recorded same-origin binding yet
    /// (those arrive with Gap 3's `NodeCopyForward`). Construct it via the loud
    /// [`MigrationAuthorization::app_author_ack`].
    AppAuthorAck,
}

impl MigrationAuthorization {
    /// The interim authorization: the app author vouches for this migration.
    ///
    /// Named to be read at the call site as exactly what it is — an app-author
    /// acknowledgement, not user consent. Under Gap 3 a caller chooses a stronger
    /// variant here; the entry-point signature does not change.
    pub fn app_author_ack() -> Self {
        MigrationAuthorization::AppAuthorAck
    }
}

/// The thin per-environment I/O adapter for reaching **predecessor** delegates
/// during an interim migration. Modeled on [`crate::ProbeIo`]: one round-trip per
/// call, awaited, with the app's own timeout and its own response correlation
/// (the browser's shared-handler `WebApi` has none — the app supplies it, e.g.
/// River's per-request `oneshot` side-table).
///
/// The app implements each method by sending `DelegateRequest::ApplicationMessages`
/// to the predecessor's delegate key and returning the response — in the app's
/// *own* delegate protocol, because interim predecessors are old delegates built
/// before this crate's generic export protocol existed.
pub trait PredecessorSecretsIo {
    /// The app's transport error type (for the abort path only).
    type Error;

    /// **G1.8 executability preflight.** Send a cheap no-op to `predecessor` in
    /// the app's own delegate protocol (e.g. River's `ListRequest`) and report
    /// whether it *executed and replied*.
    ///
    /// * `Ok(true)` — the predecessor delegate ran and answered, so a subsequent
    ///   empty [`fetch_secrets`](Self::fetch_secrets) genuinely means "no data".
    /// * `Ok(false)` — no reply within the app's bound: the old WASM could not
    ///   execute, or the node no longer has it registered, or the request was
    ///   lost. The driver records [`PredecessorMigration::Unresponsive`] so the
    ///   app can surface "your data may exist but can't auto-migrate" instead of
    ///   silently treating the predecessor as empty and fresh-installing (the
    ///   freenet/river#204 UX bug).
    /// * `Err` — abort the whole migration (the caller sees the error).
    ///
    /// **Dependency (document honestly):** this can only distinguish "can't
    /// execute" from "has no data" while the node still has the old delegate WASM
    /// registered. If the old WASM has been dropped, an unregistered predecessor
    /// is indistinguishable from a broken one — both surface as `Ok(false)` /
    /// `Unresponsive`. Old-delegate-WASM retention is the hard platform
    /// prerequisite (the queued A4 item); the node-side copy-forward removes the
    /// dependency entirely by reading storage directly.
    fn probe_executable(
        &mut self,
        predecessor: &DelegateKey,
    ) -> impl Future<Output = Result<bool, Self::Error>>;

    /// Enumerate `predecessor`'s secrets as raw `(key, value)` pairs, via the
    /// app's own delegate protocol. Called only after
    /// [`probe_executable`](Self::probe_executable) returned `Ok(true)`.
    ///
    /// An empty `Vec` means "executed, no data" (a genuine no-data predecessor,
    /// since the preflight already confirmed executability). `Err` aborts the
    /// whole migration.
    ///
    /// The pairs are imported into the successor with never-clobber semantics;
    /// the adapter should already exclude the app's own reserved keys if any.
    /// (This crate's own reserved markers are filtered on import regardless.)
    fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey,
    ) -> impl Future<Output = Result<Vec<SecretPair>, Self::Error>>;
}

/// A [`PredecessorSecretsIo`] that can also **register the successor delegate**,
/// for [`register_delegate_with_migration`].
///
/// Split from the base trait so [`migrate_delegate_secrets`] (migration only)
/// does not force callers to implement registration.
pub trait RegisterAndMigrateIo: PredecessorSecretsIo {
    /// Register the successor delegate with the node.
    ///
    /// `predecessors` and `authorization` are passed through so that Gap 3's
    /// `RegisterDelegate { predecessor: [..] }` wire change can have the node do
    /// the copy-forward *at registration time* — at which point
    /// [`migrate_delegate_secrets`] finds the delegate-key markers already
    /// written and reports every predecessor as already-migrated, a no-op. The
    /// wrapper's signature does not change.
    fn register_successor(
        &mut self,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

/// What happened for one predecessor. `key`/`generation` come from the
/// build-time-validated lineage entry (never re-derived).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredecessorMigration {
    /// The predecessor executed and its secrets were imported (first migration).
    Imported {
        /// The predecessor delegate key that was migrated from.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
        /// Secrets written.
        imported: usize,
        /// Secrets skipped because the successor already held that key.
        skipped: usize,
    },
    /// The predecessor executed but had no secrets to migrate.
    NoData {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
    },
    /// A completed migration from this predecessor was already recorded (its
    /// delegate-key marker is present); nothing was re-imported. Also the shape
    /// of a re-run.
    AlreadyMigrated {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
    },
    /// **G1.8**: the predecessor could not be confirmed executable (the preflight
    /// got no reply). Its data may exist but cannot be auto-migrated. The app
    /// MUST surface this and MUST NOT treat the migration as a fresh install
    /// (freenet/river#204). See [`PredecessorSecretsIo::probe_executable`] for
    /// the old-WASM-retention dependency this rests on.
    Unresponsive {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
    },
    /// A two-phase partial write: at least one secret failed to store, so the
    /// completion marker was withheld and a retry will re-run this predecessor.
    /// Never counts a failed write as imported.
    Incomplete {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
        /// Secrets written on this attempt.
        imported: usize,
        /// Secrets skipped because the successor already held that key.
        skipped: usize,
        /// Secrets whose write failed.
        failed: usize,
    },
}

impl PredecessorMigration {
    /// The predecessor delegate key this outcome is for.
    pub fn key(&self) -> &DelegateKey {
        match self {
            PredecessorMigration::Imported { key, .. }
            | PredecessorMigration::NoData { key, .. }
            | PredecessorMigration::AlreadyMigrated { key, .. }
            | PredecessorMigration::Unresponsive { key, .. }
            | PredecessorMigration::Incomplete { key, .. } => key,
        }
    }
}

/// The aggregate result of a delegate secret migration.
///
/// Carries only **metadata** — counts and per-predecessor classifications, never
/// exported secret bytes. This is deliberate: a future node-side copy-forward
/// moves the secrets internally and hands the app nothing, so an outcome that
/// structurally required bytes could not represent it. Same report shape, both
/// transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateMigrationReport {
    /// Per-predecessor outcomes, in processing (newest-first) order.
    pub predecessors: Vec<PredecessorMigration>,
}

impl DelegateMigrationReport {
    /// Whether any predecessor was [`Unresponsive`](PredecessorMigration::Unresponsive).
    ///
    /// **The freenet/river#204 gate:** if this is `true`, the app must surface
    /// "your data may exist but can't auto-migrate" and must NOT silently
    /// fresh-install — some predecessor's data could not be reached.
    pub fn any_unresponsive(&self) -> bool {
        self.predecessors
            .iter()
            .any(|p| matches!(p, PredecessorMigration::Unresponsive { .. }))
    }

    /// The unresponsive predecessors (for surfacing which generations are
    /// stranded).
    pub fn unresponsive(&self) -> impl Iterator<Item = &PredecessorMigration> {
        self.predecessors
            .iter()
            .filter(|p| matches!(p, PredecessorMigration::Unresponsive { .. }))
    }

    /// Total secrets written across all predecessors.
    pub fn imported_total(&self) -> usize {
        self.predecessors
            .iter()
            .map(|p| match p {
                PredecessorMigration::Imported { imported, .. }
                | PredecessorMigration::Incomplete { imported, .. } => *imported,
                _ => 0,
            })
            .sum()
    }

    /// Whether every predecessor fully resolved — none unresponsive and none left
    /// incomplete. When `true` it is safe to proceed as a clean migration (which,
    /// if every predecessor was `NoData`/absent, is an ordinary fresh install).
    /// When `false`, do NOT fresh-install: check [`any_unresponsive`](Self::any_unresponsive).
    pub fn is_complete(&self) -> bool {
        !self.predecessors.iter().any(|p| {
            matches!(
                p,
                PredecessorMigration::Unresponsive { .. } | PredecessorMigration::Incomplete { .. }
            )
        })
    }
}

/// **The app-facing delegate-migration entry point** (plan G1.7 delegate half).
///
/// Carry each predecessor delegate's secrets forward into the successor
/// `store`, driving the interim app-side round-trip through `io` and importing
/// with the delegate-key-keyed, seam-safe primitive
/// ([`import_predecessor_secrets_once`]). Returns a [`DelegateMigrationReport`];
/// the app decides what to do with each predecessor's classification (crucially,
/// it must not fresh-install if any predecessor is `Unresponsive` — see
/// [`DelegateMigrationReport::any_unresponsive`]).
///
/// * `store` — the successor delegate's secret store (`DelegateCtx` on wasm; the
///   import target and where the anti-resurrection markers live). This is the
///   store a future node-side copy-forward writes into directly.
/// * `io` — reaches the **predecessors** (preflight + fetch). See
///   [`PredecessorSecretsIo`].
/// * `predecessors` — the predecessor **list** from the build-time-validated
///   lineage (`DELEGATE_LINEAGE`). Users skip generations (#204 was V4–V6), so
///   this is always a list; keys come from each entry's stored `delegate_key`,
///   never re-derived.
/// * `authorization` — required consent (see [`MigrationAuthorization`]).
///
/// **`no-delete` invariant (plan §0):** predecessor data is never deleted — this
/// only *reads* predecessors (via `io`) and *writes* markers + imported secrets on
/// the successor. The marker, not deletion, is the anti-resurrection mechanism,
/// and keeping the predecessor intact is the rollback story. There is no code
/// path here (or in `io`, which has no delete method) that removes predecessor
/// data.
///
/// Predecessors are processed **newest-generation-first**, so with never-clobber
/// import the newest generation's value wins on any key present in more than one
/// generation.
///
/// # Errors
///
/// Returns `IO::Error` only when `io` aborts (a `probe_executable` / `fetch_secrets`
/// `Err`). A per-predecessor storage write failure is not an abort — it is
/// reported as [`PredecessorMigration::Incomplete`] so one predecessor's failure
/// does not lose the others.
///
/// # The authorization parameter is required
///
/// [`MigrationAuthorization`] has no `Default`, so a caller cannot migrate secrets
/// without explicitly constructing one — the consent gate is enforced at compile
/// time. This does not compile:
///
/// ```compile_fail
/// // `MigrationAuthorization` has no `Default` impl — there is no way to obtain
/// // one implicitly, so the consent parameter cannot be omitted.
/// let _authz: freenet_migrate::MigrationAuthorization = Default::default();
/// ```
pub async fn migrate_delegate_secrets<S, IO>(
    store: &mut S,
    io: &mut IO,
    predecessors: &[DelegateLineageEntry],
    authorization: MigrationAuthorization,
) -> Result<DelegateMigrationReport, IO::Error>
where
    S: SecretStore + ?Sized,
    IO: PredecessorSecretsIo,
{
    let mut transport = AppSideRoundTrip { io };
    transport
        .migrate_from(store, predecessors, &authorization)
        .await
}

/// Register the successor delegate **and** carry its predecessors' secrets
/// forward, in one call (plan G1.7).
///
/// A thin wrapper: [`register_successor`](RegisterAndMigrateIo::register_successor)
/// then [`migrate_delegate_secrets`]. Under Gap 3 the registration itself carries
/// the predecessor list to the node (which does the copy-forward), and the
/// migration step becomes a no-op — the signature is unchanged.
pub async fn register_delegate_with_migration<S, IO>(
    store: &mut S,
    io: &mut IO,
    predecessors: &[DelegateLineageEntry],
    authorization: MigrationAuthorization,
) -> Result<DelegateMigrationReport, IO::Error>
where
    S: SecretStore + ?Sized,
    IO: RegisterAndMigrateIo,
{
    io.register_successor(predecessors, &authorization).await?;
    migrate_delegate_secrets(store, io, predecessors, authorization).await
}

/// The redesigned, sans-IO secret transport — **the internal seam Gap 3 swaps
/// under** (plan G1.7 / G3.6).
///
/// Replaces v1's `export_from(predecessor) -> ExportedSecrets`: `migrate_from`
/// takes the predecessor **list** and returns a metadata-only
/// [`DelegateMigrationReport`] (never bytes), so it can host *both* the interim
/// app-side round-trip ([`AppSideRoundTrip`]) and a future `NodeCopyForward` that
/// copies secrets internally and returns nothing app-side.
///
/// Intentionally `pub(crate)`: it is NOT the app-facing contract (the entry
/// points are). When the node primitive lands, add `struct NodeCopyForward; impl
/// SecretTransport for NodeCopyForward { .. }` and route to it (with capability
/// detection + the interim as fallback) inside the *unchanged*
/// [`migrate_delegate_secrets`].
pub(crate) trait SecretTransport<S: SecretStore + ?Sized> {
    /// The transport's error type (the app's `io` error, or a node error).
    type Error;

    /// Migrate the secrets of every predecessor in `predecessors` into `store`,
    /// once each. Returns a per-predecessor report; never returns exported bytes.
    fn migrate_from(
        &mut self,
        store: &mut S,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
    ) -> impl Future<Output = Result<DelegateMigrationReport, Self::Error>>;
}

/// The interim [`SecretTransport`]: app-side request/response round-trips through
/// the [`PredecessorSecretsIo`] adapter, importing with the delegate-key-keyed
/// primitive. This supersedes v1's `ReRunOldWasm` stub — there is no node re-run
/// of old WASM here; the app ferries the export round-trip.
struct AppSideRoundTrip<'a, IO> {
    io: &'a mut IO,
}

impl<S, IO> SecretTransport<S> for AppSideRoundTrip<'_, IO>
where
    S: SecretStore + ?Sized,
    IO: PredecessorSecretsIo,
{
    type Error = IO::Error;

    async fn migrate_from(
        &mut self,
        store: &mut S,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
    ) -> Result<DelegateMigrationReport, Self::Error> {
        // Interim: the app-author ack is a no-op gate — its PRESENCE authorizes
        // the migration. Gap 3's stronger variant (per-transition user consent +
        // node-recorded same-origin binding) is checked here without changing any
        // signature. Matching exhaustively (no wildcard) means a new variant
        // forces this site to decide how to handle it.
        match authorization {
            MigrationAuthorization::AppAuthorAck => {}
        }

        // Newest-generation-first, so never-clobber gives the newest generation's
        // value precedence on any key present in more than one generation. Built
        // from each entry's STORED delegate_key (never re-derived — irregular
        // rows' recorded keys don't derive).
        let mut ordered: Vec<(DelegateKey, u32)> = predecessors
            .iter()
            .map(|e| {
                (
                    DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash)),
                    e.generation,
                )
            })
            .collect();
        ordered.sort_by_key(|(_, generation)| core::cmp::Reverse(*generation));

        let mut results = Vec::with_capacity(ordered.len());
        for (key, generation) in ordered {
            // Already migrated from this predecessor? Skip the round-trips
            // entirely (cheap, marker-gated re-run). This is the §0 marker check.
            if predecessor_already_migrated(store, &key) {
                results.push(PredecessorMigration::AlreadyMigrated { key, generation });
                continue;
            }

            // G1.8: confirm executability BEFORE concluding "no data".
            if !self.io.probe_executable(&key).await? {
                results.push(PredecessorMigration::Unresponsive { key, generation });
                continue;
            }

            let secrets = self.io.fetch_secrets(&key).await?;
            if secrets.is_empty() {
                // The preflight confirmed it executes, so empty is genuine.
                results.push(PredecessorMigration::NoData { key, generation });
                continue;
            }

            let outcome = import_predecessor_secrets_once(store, &key, &secrets);
            results.push(classify_import(key, generation, outcome));
        }

        Ok(DelegateMigrationReport {
            predecessors: results,
        })
    }
}

/// Map a per-predecessor import outcome to its report entry.
fn classify_import(
    key: DelegateKey,
    generation: u32,
    outcome: PredecessorImportOutcome,
) -> PredecessorMigration {
    match outcome {
        PredecessorImportOutcome::Imported { imported, skipped } => {
            PredecessorMigration::Imported {
                key,
                generation,
                imported,
                skipped,
            }
        }
        // The driver already gated on the marker, so this is only reachable if the
        // marker appeared concurrently; treat it as the no-op it is.
        PredecessorImportOutcome::AlreadyMigrated => {
            PredecessorMigration::AlreadyMigrated { key, generation }
        }
        PredecessorImportOutcome::Incomplete {
            imported,
            skipped,
            failed,
        } => PredecessorMigration::Incomplete {
            key,
            generation,
            imported,
            skipped,
            failed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegate::pred_done_marker;
    use std::collections::{BTreeMap, HashMap, HashSet};

    // ---- test successor store -------------------------------------------------

    #[derive(Default)]
    struct MemStore {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
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
            self.data.insert(key.to_vec(), value.to_vec());
            true
        }
    }

    // ---- mock predecessor I/O -------------------------------------------------

    /// Scripts each predecessor key's preflight + secrets. Records the calls so a
    /// test can assert an already-migrated predecessor is never round-tripped.
    #[derive(Default)]
    struct MockIo {
        /// key bytes -> executable?
        executable: HashMap<Vec<u8>, bool>,
        /// key bytes -> secrets (only consulted when executable)
        secrets: HashMap<Vec<u8>, Vec<SecretPair>>,
        /// key bytes actually probed / fetched, for call-tracking assertions.
        probed: HashSet<Vec<u8>>,
        fetched: HashSet<Vec<u8>>,
        /// registration calls, for the wrapper test.
        registered: usize,
        /// force an abort from probe_executable for these keys.
        abort_on_probe: HashSet<Vec<u8>>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct IoAbort;

    impl MockIo {
        fn executable_with(mut self, key: &DelegateKey, secrets: &[(&[u8], &[u8])]) -> Self {
            self.executable.insert(key.bytes().to_vec(), true);
            self.secrets.insert(
                key.bytes().to_vec(),
                secrets
                    .iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect(),
            );
            self
        }
        fn dead(mut self, key: &DelegateKey) -> Self {
            self.executable.insert(key.bytes().to_vec(), false);
            self
        }
        fn abort_probe(mut self, key: &DelegateKey) -> Self {
            self.abort_on_probe.insert(key.bytes().to_vec());
            self
        }
    }

    impl PredecessorSecretsIo for MockIo {
        type Error = IoAbort;
        async fn probe_executable(&mut self, predecessor: &DelegateKey) -> Result<bool, IoAbort> {
            let k = predecessor.bytes().to_vec();
            if self.abort_on_probe.contains(&k) {
                return Err(IoAbort);
            }
            self.probed.insert(k.clone());
            Ok(*self.executable.get(&k).unwrap_or(&false))
        }
        async fn fetch_secrets(
            &mut self,
            predecessor: &DelegateKey,
        ) -> Result<Vec<SecretPair>, IoAbort> {
            let k = predecessor.bytes().to_vec();
            self.fetched.insert(k.clone());
            Ok(self.secrets.get(&k).cloned().unwrap_or_default())
        }
    }

    impl RegisterAndMigrateIo for MockIo {
        async fn register_successor(
            &mut self,
            _predecessors: &[DelegateLineageEntry],
            _authorization: &MigrationAuthorization,
        ) -> Result<(), IoAbort> {
            self.registered += 1;
            Ok(())
        }
    }

    // ---- helpers --------------------------------------------------------------

    fn entry(generation: u32, tag: u8) -> DelegateLineageEntry {
        DelegateLineageEntry {
            generation,
            code_hash: [tag; 32],
            delegate_key: [tag.wrapping_add(100); 32],
            irregular_key: false,
            note: "test",
        }
    }

    fn key_of(e: &DelegateLineageEntry) -> DelegateKey {
        DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash))
    }

    fn ack() -> MigrationAuthorization {
        MigrationAuthorization::app_author_ack()
    }

    /// Minimal single-future block_on (no async runtime): all mock futures are
    /// immediately ready. Mirrors the driver-side test executor.
    fn block_on<F: Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = core::pin::pin!(fut);
        for _ in 0..10_000 {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
        panic!("future never became ready; the mock io must stay awaitless");
    }

    // ---- outcome classification matrix ---------------------------------------

    #[test]
    fn imports_secrets_from_an_executable_predecessor_with_data() {
        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(
            &key_of(&e),
            &[(b"rooms", b"blob"), (b"signing_key:a", b"kb")],
        );
        let report = block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap();
        assert_eq!(report.predecessors.len(), 1);
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported {
                imported: 2,
                skipped: 0,
                ..
            }
        ));
        assert_eq!(report.imported_total(), 2);
        assert!(report.is_complete());
        assert!(!report.any_unresponsive());
        assert_eq!(store.get_secret(b"rooms").unwrap(), b"blob");
    }

    #[test]
    fn executable_predecessor_with_no_data_is_nodata_not_unresponsive() {
        // The disambiguation the preflight buys: executes + empty = genuine
        // NoData (a safe fresh-install), NOT Unresponsive.
        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
        let report = block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap();
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::NoData { .. }
        ));
        assert!(report.is_complete(), "no-data is a clean, complete outcome");
        assert!(!report.any_unresponsive());
    }

    #[test]
    fn unexecutable_predecessor_is_unresponsive_never_silent_fresh_install() {
        // freenet/river#204: a broken/absent old WASM must surface, not read as
        // "no data → fresh install".
        let e = entry(4, 4);
        let mut store = MemStore::default();
        let mut io = MockIo::default().dead(&key_of(&e));
        let report = block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap();
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(report.any_unresponsive(), "the #204 gate must trip");
        assert!(!report.is_complete());
        assert_eq!(report.unresponsive().count(), 1);
        // Never fetched (no point enumerating a dead delegate).
        assert!(!io.fetched.contains(key_of(&e).bytes()));
    }

    #[test]
    fn already_migrated_predecessor_skips_round_trips() {
        // A predecessor whose marker is already set is reported AlreadyMigrated
        // WITHOUT any preflight/fetch (efficient, marker-gated re-run).
        let e = entry(1, 1);
        let mut store = MemStore::default();
        store.set_secret(&pred_done_marker(&key_of(&e)), b"1");
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"x", b"y")]);
        let report = block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap();
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert!(
            !io.probed.contains(key_of(&e).bytes()),
            "an already-migrated predecessor must not be probed"
        );
        assert!(store.get_secret(b"x").is_none(), "nothing re-imported");
    }

    #[test]
    fn migrate_then_rerun_is_a_no_op() {
        // Deliverable-6 end-to-end: v1 with secrets -> import once -> re-run no-op.
        let e = entry(1, 1);
        let mut store = MemStore::default();

        let first = {
            let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"v")]);
            block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap()
        };
        assert!(matches!(
            first.predecessors[0],
            PredecessorMigration::Imported { imported: 1, .. }
        ));
        assert_eq!(store.get_secret(b"k").unwrap(), b"v");
        let n_after_first = store.list_secrets(b"").len();

        // Re-run (fresh io that would re-import if asked): must be a no-op.
        let second = {
            let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"RESURRECT")]);
            block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap()
        };
        assert!(matches!(
            second.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert_eq!(store.get_secret(b"k").unwrap(), b"v", "value not clobbered");
        assert_eq!(store.list_secrets(b"").len(), n_after_first, "no new keys");
    }

    #[test]
    fn newest_generation_wins_on_key_conflict() {
        // Predecessors listed oldest-first; processed newest-first so never-clobber
        // gives the newest generation's value precedence.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&old), &[(b"shared", b"OLD"), (b"only_old", b"o")])
            .executable_with(&key_of(&new), &[(b"shared", b"NEW"), (b"only_new", b"n")]);
        // Registry order is oldest-first; the driver must still take the newest.
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
        ))
        .unwrap();
        assert_eq!(report.predecessors.len(), 2);
        // Newest processed first.
        assert_eq!(
            report.predecessors[0].key().bytes(),
            key_of(&entry(2, 2)).bytes()
        );
        assert_eq!(store.get_secret(b"shared").unwrap(), b"NEW", "newest wins");
        assert_eq!(store.get_secret(b"only_old").unwrap(), b"o");
        assert_eq!(store.get_secret(b"only_new").unwrap(), b"n");
    }

    #[test]
    fn mixed_list_classifies_each_predecessor_independently() {
        // A realistic V4-V6 skip: one has data, one is empty, one is dead.
        let has = entry(6, 6);
        let empty = entry(5, 5);
        let dead = entry(4, 4);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&has), &[(b"a", b"1")])
            .executable_with(&key_of(&empty), &[])
            .dead(&key_of(&dead));
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[dead, empty, has],
            ack(),
        ))
        .unwrap();
        // Newest-first order: 6 (has), 5 (empty), 4 (dead).
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::NoData { .. }
        ));
        assert!(matches!(
            report.predecessors[2],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(
            report.any_unresponsive(),
            "the dead V4 must trip the #204 gate"
        );
        assert!(!report.is_complete());
        assert_eq!(report.imported_total(), 1);
    }

    #[test]
    fn empty_predecessor_list_is_a_clean_empty_report() {
        let mut store = MemStore::default();
        let mut io = MockIo::default();
        let report = block_on(migrate_delegate_secrets(&mut store, &mut io, &[], ack())).unwrap();
        assert!(report.predecessors.is_empty());
        assert!(report.is_complete());
        assert!(
            !report.any_unresponsive(),
            "no predecessors = safe fresh install"
        );
    }

    #[test]
    fn io_abort_propagates_as_error() {
        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut io = MockIo::default().abort_probe(&key_of(&e));
        let err = block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap_err();
        assert_eq!(err, IoAbort);
    }

    #[test]
    fn register_wrapper_registers_then_migrates() {
        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"v")]);
        let report = block_on(register_delegate_with_migration(
            &mut store,
            &mut io,
            &[e],
            ack(),
        ))
        .unwrap();
        assert_eq!(io.registered, 1, "the successor must be registered");
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(store.get_secret(b"k").unwrap(), b"v");
    }

    #[test]
    fn authorization_is_a_non_default_enum_with_a_loud_constructor() {
        // Pins the consent shape: the only way to obtain one is the loud
        // constructor (there is no Default — see the compile_fail doctest on
        // migrate_delegate_secrets), and it is an enum with room to grow.
        assert_eq!(
            MigrationAuthorization::app_author_ack(),
            MigrationAuthorization::AppAuthorAck
        );
    }

    // ---- the seam: a non-io transport (NodeCopyForward shape) fits ------------

    #[test]
    fn secret_transport_seam_hosts_a_non_io_transport() {
        // Proves the redesigned seam can host a transport that does NOT use `io`
        // and returns no bytes app-side — the NodeCopyForward shape. It writes the
        // SAME delegate-key markers via the shared primitive, so a later
        // migrate_delegate_secrets over the same predecessor is AlreadyMigrated.
        struct NodeCopyForwardMock {
            /// canned "storage" the node would copy directly, per predecessor key.
            store: HashMap<Vec<u8>, Vec<SecretPair>>,
        }
        impl<S: SecretStore + ?Sized> SecretTransport<S> for NodeCopyForwardMock {
            type Error = core::convert::Infallible;
            async fn migrate_from(
                &mut self,
                store: &mut S,
                predecessors: &[DelegateLineageEntry],
                _authorization: &MigrationAuthorization,
            ) -> Result<DelegateMigrationReport, Self::Error> {
                let mut out = Vec::new();
                for e in predecessors {
                    let key = DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash));
                    let secrets = self.store.get(key.bytes()).cloned().unwrap_or_default();
                    // Same seam-safe primitive the app-side path uses.
                    let outcome = import_predecessor_secrets_once(store, &key, &secrets);
                    out.push(classify_import(key, e.generation, outcome));
                }
                Ok(DelegateMigrationReport { predecessors: out })
            }
        }

        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut node = NodeCopyForwardMock {
            store: HashMap::from([(
                key_of(&e).bytes().to_vec(),
                vec![(b"nk".to_vec(), b"nv".to_vec())],
            )]),
        };
        let report = block_on(node.migrate_from(&mut store, &[e], &ack())).unwrap();
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported { imported: 1, .. }
        ));
        assert_eq!(store.get_secret(b"nk").unwrap(), b"nv");

        // The app-side path now sees the node's markers and re-imports nothing.
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"nk", b"RESURRECT")]);
        let after = block_on(migrate_delegate_secrets(&mut store, &mut io, &[e], ack())).unwrap();
        assert!(
            matches!(
                after.predecessors[0],
                PredecessorMigration::AlreadyMigrated { .. }
            ),
            "the interim path must recognize the node-written delegate-key marker"
        );
        assert_eq!(
            store.get_secret(b"nk").unwrap(),
            b"nv",
            "not resurrected/clobbered"
        );
    }
}
