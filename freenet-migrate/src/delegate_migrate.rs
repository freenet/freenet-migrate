//! Delegate secret migration — the app-facing entry points (plan G1.7 delegate
//! half + G1.8) and the redesigned, sans-IO transport seam Gap 3 swaps under.
//!
//! # The altitude decision (plan v2's central correction)
//!
//! The **stable app-facing contract is the high-level entry points**
//! ([`migrate_delegate_secrets`], [`register_delegate_with_migration`]), with
//! consent ([`MigrationAuthorization`]) baked in from day one, plus the
//! delegate-key `pred-done` markers as the cross-transport interoperability
//! contract. The transport that actually moves the secrets — the interim app-side
//! round-trips today, a node-internal copy at *registration* tomorrow (writing
//! those same markers) — is a detail apps do not program against.
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
//! Unlike the contract side there is deliberately **no hand-pumped raw driver**
//! here — the adopter's delegate path is already awaitable (River drives each
//! delegate round-trip to completion through a per-request `oneshot` side-table,
//! unlike its fire-and-forget contract probe), so a single async entry point over
//! this adapter is all that is needed.
//!
//! ```text
//! for predecessor in newest_first(predecessors) {   // stop early per policy
//!     if already_migrated(predecessor) { record AlreadyMigrated; maybe stop }
//!     match io.probe_executable(predecessor).await {           // G1.8 preflight
//!         Ok(false) | Err(_) => { record Unresponsive; maybe stop }  // data may
//!         Ok(true) => {                                              // exist,
//!             let secrets = io.fetch_secrets(predecessor).await?;    // can't migrate
//!             import_predecessor_secrets_once(store, predecessor, &secrets)  // §0 marker
//!         }
//!     }
//! }
//! ```
//!
//! Cross-generation selection is an explicit [`SecretSelectionPolicy`]
//! (`NewestSnapshotWins` default, or `UnionAllGenerations`), the delegate-side
//! analogue of the contract driver's `NewestFirstWins` / `FoldAll`.
//!
//! Honest limits — what stays app code the crate cannot verify: the I/O adapter
//! itself (send / correlate / time out); and what a "cheap no-op probe" is in the
//! app's own delegate protocol. The preflight distinguishes "can't execute" from
//! "no data" only while the node the request reaches actually has the predecessor
//! delegate registered/available (see [`PredecessorSecretsIo::probe_executable`]).

use core::future::Future;

use freenet_stdlib::prelude::{CodeHash, DelegateKey};

use crate::delegate::{
    import_predecessor_secrets_once, legacy_generation_migrated, legacy_generation_migrated_exact,
    predecessor_migration_had_data, PredecessorImportOutcome, SecretPair, SecretStore,
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
    /// (those arrive with Gap 3's `NodeCopyForward`).
    ///
    /// The variant carries a private token, so [`MigrationAuthorization::app_author_ack`]
    /// is the *only* way to construct it — a caller cannot bypass the loud
    /// constructor by naming the variant directly.
    AppAuthorAck(AppAuthorAckToken),
}

/// Private witness that gates [`MigrationAuthorization::AppAuthorAck`] behind the
/// loud [`MigrationAuthorization::app_author_ack`] constructor. It has no public
/// constructor, so the variant cannot be built outside this crate any other way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAuthorAckToken(());

impl MigrationAuthorization {
    /// The interim authorization: the app author vouches for this migration.
    ///
    /// Named to be read at the call site as exactly what it is — an app-author
    /// acknowledgement, not user consent. Under Gap 3 a caller chooses a stronger
    /// variant here; the entry-point signature does not change.
    pub fn app_author_ack() -> Self {
        MigrationAuthorization::AppAuthorAck(AppAuthorAckToken(()))
    }
}

/// How secrets are selected across predecessor **generations** (the delegate-side
/// analogue of the contract driver's [`crate::SelectionPolicy`]). Passed
/// explicitly to the entry points — no implicit default — so the cross-generation
/// behavior is visible at every call site.
///
/// The two modes trade delete-by-absence safety against stranded-data recovery,
/// the same tension the contract side resolves with `NewestFirstWins` vs
/// `FoldAll`.
#[derive(Debug)]
pub enum SecretSelectionPolicy {
    /// **Default / safe.** Walk predecessors newest-first; the newest predecessor
    /// that yields data is the authoritative snapshot, and OLDER predecessors are
    /// NOT imported after it. Preserves delete-by-absence: a key the authoritative
    /// (newer) generation dropped can never be resurrected from an older one.
    ///
    /// Documented cost: a key that only ever existed in a generation *older* than
    /// the authoritative one stays unrecovered. Use [`UnionAllGenerations`](Self::UnionAllGenerations)
    /// when recovering such stranded data matters more than delete-by-absence.
    ///
    /// **Scope:** these semantics are **app-side** (the interim round-trip path).
    /// A Gap-3 copy-forward node copies union-with-newest-precedence and does not
    /// honor this stop-at-first-data-bearing / delete-by-absence guarantee, because
    /// the v1 wire carries no generations/policy — see `SecretTransport`.
    NewestSnapshotWins,
    /// **Opt-in recovery.** Import *every* predecessor newest-first with
    /// never-clobber (so the newest generation's value still wins any key
    /// conflict). This is the freenet/river#204 stranded-older-generation recovery
    /// mode.
    ///
    /// It **resurrects delete-by-absence data**: a key deleted in a newer
    /// generation but still present in an older one is re-imported. Hence the loud
    /// [`UnionAck`].
    UnionAllGenerations(UnionAck),
}

/// Opt-in token for [`SecretSelectionPolicy::UnionAllGenerations`]. Deliberately
/// not `Default`: holding one acknowledges that union import can resurrect
/// secrets a newer generation deleted by absence.
#[must_use = "a UnionAck acknowledges that union import resurrects secrets a newer \
              generation deleted by absence; construct it only if that is intended"]
#[derive(Debug)]
pub struct UnionAck(());

impl UnionAck {
    /// Construct the opt-in. Only sound when re-importing secrets that a newer
    /// generation deleted (by their absence) is acceptable — e.g. recovering
    /// genuinely stranded data from a skipped older generation (river#204).
    pub fn i_understand_union_resurrects_deleted_by_absence_secrets() -> Self {
        Self(())
    }
}

impl SecretSelectionPolicy {
    /// Whether an already-migrated *data-bearing* (or unknown-state) predecessor
    /// terminates a `NewestSnapshotWins` walk. Union never terminates on it.
    fn already_migrated_is_authoritative(&self, had_data: bool) -> bool {
        matches!(self, SecretSelectionPolicy::NewestSnapshotWins) && had_data
    }

    /// Whether a freshly-imported data-bearing predecessor terminates the walk.
    fn imported_is_authoritative(&self) -> bool {
        matches!(self, SecretSelectionPolicy::NewestSnapshotWins)
    }

    /// Whether an `Unresponsive` predecessor terminates the walk. Under
    /// `NewestSnapshotWins` it does — falling through to import an older snapshot
    /// past an unknown newer state would risk resurrecting keys the newer
    /// generation deleted. Union keeps going (it wants every generation).
    fn unresponsive_terminates(&self) -> bool {
        matches!(self, SecretSelectionPolicy::NewestSnapshotWins)
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
    /// execute" from "has no data" while the node the request reaches actually has
    /// the predecessor delegate **registered and available**. (freenet-core retains
    /// delegate WASM indefinitely — only an explicit `UnregisterDelegate` removes
    /// it — so this is NOT time-decay/WASM-GC; it is per-node registration and
    /// availability.) A predecessor the reached node never registered is
    /// indistinguishable from a broken one — both surface as `Ok(false)` /
    /// `Unresponsive`. The node-side copy-forward removes the dependency by reading
    /// storage directly.
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
    /// `predecessors`, `authorization`, and `policy` are passed through so that
    /// Gap 3's `RegisterDelegateWithPredecessors` wire change can have the node do
    /// the copy-forward *at registration time* — at which point
    /// [`migrate_delegate_secrets`] finds the delegate-key markers already
    /// written and reports every predecessor as already-migrated, a no-op. The
    /// wrapper's signature does not change.
    ///
    /// **`predecessors` is supplied newest-generation-first** (guaranteed by
    /// [`register_delegate_with_migration`]). Send the keys to the node in that
    /// order: the v1 wire carries only the key list and the node copies with
    /// first-writer-wins, so newest-first yields newest-precedence. The v1 node
    /// copy is union-with-newest-precedence and does NOT honor `policy` (which is
    /// forwarded only for a future wire evolution) — see `SecretTransport`.
    fn register_successor(
        &mut self,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
        policy: &SecretSelectionPolicy,
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
    /// **G1.8**: the predecessor could not be confirmed executable — the preflight
    /// got no reply, or a probe/fetch round-trip errored (the error is stringified
    /// into `error`). Its data may exist but cannot be auto-migrated. The app MUST
    /// surface this and MUST NOT treat the migration as a fresh install
    /// (freenet/river#204). See [`PredecessorSecretsIo::probe_executable`] for the
    /// registration/availability dependency this rests on.
    Unresponsive {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
        /// The stringified transport error, if the round-trip errored (vs. a
        /// clean "no reply", which is `None`).
        error: Option<String>,
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
    /// The predecessor was **not imported** because a higher-priority predecessor
    /// decided the outcome: under [`SecretSelectionPolicy::NewestSnapshotWins`] a
    /// newer predecessor supplied the authoritative snapshot, OR an earlier
    /// predecessor halted the walk (`Incomplete`, or `Unresponsive` under
    /// `NewestSnapshotWins`). Whether this is a *clean* skip or a *retry-me* skip
    /// is told by [`DelegateMigrationReport::is_complete`] (an earlier
    /// `Incomplete`/`Unresponsive` makes the whole report incomplete).
    Superseded {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
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
            | PredecessorMigration::Incomplete { key, .. }
            | PredecessorMigration::Superseded { key, .. } => key,
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
/// * `policy` — cross-generation selection (see [`SecretSelectionPolicy`]);
///   explicit at the call site, no implicit default.
///
/// **`no-delete` invariant (plan §0):** predecessor data is never deleted — this
/// only *reads* predecessors (via `io`) and *writes* markers + imported secrets on
/// the successor. The marker, not deletion, is the anti-resurrection mechanism,
/// and keeping the predecessor intact is the rollback story. There is no code
/// path here (or in `io`, which has no delete method) that removes predecessor
/// data.
///
/// Predecessors are processed **newest-generation-first**; `policy` decides
/// whether an older predecessor is imported after a newer one already yielded
/// data (see [`SecretSelectionPolicy`]).
///
/// # The report is the source of truth (no bare error)
///
/// This returns a [`DelegateMigrationReport`], not a `Result`: once the walk
/// begins it never fails outright. A `probe_executable`/`fetch_secrets` transport
/// error is captured as [`PredecessorMigration::Unresponsive`] with the error
/// stringified into its `error` field (a fetch timeout is a clean `Ok(false)` →
/// `Unresponsive { error: None }`); a storage write failure is
/// [`PredecessorMigration::Incomplete`]. So an error mid-run never discards the
/// predecessors already migrated — the app inspects the report and retries.
///
/// # The authorization parameter is required
///
/// [`MigrationAuthorization`] has no `Default` and its only variant carries a
/// private token, so a caller cannot migrate secrets without explicitly calling
/// [`MigrationAuthorization::app_author_ack`] — the consent gate is enforced at
/// compile time. This does not compile:
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
    policy: SecretSelectionPolicy,
) -> DelegateMigrationReport
where
    S: SecretStore + ?Sized,
    IO: PredecessorSecretsIo,
    IO::Error: core::fmt::Debug,
{
    let mut transport = AppSideRoundTrip { io };
    transport
        .migrate_from(store, predecessors, &authorization, &policy)
        .await
}

/// Register the successor delegate **and** carry its predecessors' secrets
/// forward, in one call (plan G1.7).
///
/// A thin wrapper: [`register_successor`](RegisterAndMigrateIo::register_successor)
/// then [`migrate_delegate_secrets`]. Under Gap 3 the registration itself carries
/// the predecessor list to the node (which does the copy-forward), and the
/// migration step becomes a no-op — the signature is unchanged.
///
/// The predecessors handed to `register_successor` are sorted **newest-first**
/// here, because a copy-forward node copies in supplied order with
/// first-writer-wins (newest-first ⇒ newest-precedence). See
/// [`RegisterAndMigrateIo::register_successor`] and the `SecretTransport` docs
/// for what the v1 node copy does and does NOT guarantee (it is
/// union-with-newest-precedence, not `NewestSnapshotWins`).
///
/// # Errors
///
/// Returns `IO::Error` only if the pre-migration `register_successor` fails (no
/// secrets have moved at that point). Once registration succeeds the migration
/// runs and its result is always an `Ok(report)` — see [`migrate_delegate_secrets`].
pub async fn register_delegate_with_migration<S, IO>(
    store: &mut S,
    io: &mut IO,
    predecessors: &[DelegateLineageEntry],
    authorization: MigrationAuthorization,
    policy: SecretSelectionPolicy,
) -> Result<DelegateMigrationReport, IO::Error>
where
    S: SecretStore + ?Sized,
    IO: RegisterAndMigrateIo,
    IO::Error: core::fmt::Debug,
{
    // The lineage is oldest-first by convention; the node needs newest-first
    // (first-writer-wins ⇒ newest-precedence), so sort here and guarantee the
    // contract rather than trusting the caller's slice order.
    let mut newest_first = predecessors.to_vec();
    newest_first.sort_by_key(|e| core::cmp::Reverse(e.generation));
    io.register_successor(&newest_first, &authorization, &policy)
        .await?;
    Ok(migrate_delegate_secrets(store, io, predecessors, authorization, policy).await)
}

/// The redesigned, sans-IO secret transport — the internal factoring of the
/// **interim** app-side migration (plan G1.7 / G3.6).
///
/// Replaces v1's `export_from(predecessor) -> ExportedSecrets`: `migrate_from`
/// takes the predecessor **list** and returns a metadata-only
/// [`DelegateMigrationReport`] (never bytes, never a bare error). The one impl is
/// the interim app-side round-trip ([`AppSideRoundTrip`]).
///
/// # How Gap 3 (the node copy-forward) actually lands
///
/// **Not** by adding a second `SecretTransport` impl routed inside
/// [`migrate_delegate_secrets`] — the `io` here reaches *predecessors*, and
/// nothing on the migrate path can trigger a node-internal copy, so that
/// mechanism is non-viable. The real seam is **register-time copy + shared
/// markers**:
///
/// 1. [`register_delegate_with_migration`] passes the predecessor list
///    (**newest-first**) + authorization to [`RegisterAndMigrateIo::register_successor`].
/// 2. On a node with the copy-forward primitive, registration copies each
///    predecessor's secrets into the successor **internally, without executing
///    old code**, and writes the **same** public `pred-done` marker
///    ([`crate::predecessor_done_marker`]) for each predecessor it *fully* copies.
/// 3. The subsequent [`migrate_delegate_secrets`] then finds every completed
///    predecessor already marked and short-circuits each to `AlreadyMigrated` — a
///    no-op. A predecessor the node only partially copied has **no** marker, so
///    the interim app-side round-trip retries it.
///
/// ## What the v1 node copy does — and does NOT — guarantee
///
/// The v1 wire carries only `Vec<DelegateKey>` (no generations, no policy). The
/// node copies in the supplied order, **first-writer-wins**, so with a
/// newest-first list it is **union-with-newest-precedence**: every predecessor is
/// copied, the newest value wins a key conflict. It therefore does **not**
/// implement [`SecretSelectionPolicy::NewestSnapshotWins`]'s
/// stop-at-first-data-bearing / delete-by-absence preservation — that is an
/// **app-side-only** semantic in v1. So on a copy-forward node the effective
/// cross-generation behavior is Union regardless of the `policy` argument;
/// `policy`'s finer semantics apply only to the app-side fallback path. (A future
/// wire evolution could carry generations/policy and close the gap.) This does
/// not promise policy preservation node-side.
///
/// So the app-facing entry points are unchanged, the shared `pred-done` markers
/// are the interoperability contract, and this interim app-side round-trip is the
/// **fallback** for nodes that predate the copy-forward primitive. Intentionally
/// `pub(crate)`: the transport is not the app-facing contract (the entry points
/// and the markers are).
pub(crate) trait SecretTransport<S: SecretStore + ?Sized> {
    /// Migrate the secrets of every predecessor in `predecessors` into `store`,
    /// once each, under `policy`. Returns a per-predecessor report; never returns
    /// exported bytes and never a bare error (transport failures are captured as
    /// report rows).
    fn migrate_from(
        &mut self,
        store: &mut S,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
        policy: &SecretSelectionPolicy,
    ) -> impl Future<Output = DelegateMigrationReport>;
}

/// The interim `SecretTransport`: app-side request/response round-trips through
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
    IO::Error: core::fmt::Debug,
{
    async fn migrate_from(
        &mut self,
        store: &mut S,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
        policy: &SecretSelectionPolicy,
    ) -> DelegateMigrationReport {
        // Interim: the app-author ack is a no-op gate — its PRESENCE authorizes
        // the migration. Gap 3's stronger variant (per-transition user consent +
        // node-recorded same-origin binding) is checked here without changing any
        // signature. Matching exhaustively (no wildcard) means a new variant
        // forces this site to decide how to handle it.
        match authorization {
            MigrationAuthorization::AppAuthorAck(_) => {}
        }

        // Newest-generation-first: under NewestSnapshotWins the first data-bearing
        // predecessor is authoritative; under Union never-clobber gives the newest
        // generation's value precedence on any shared key. Built from each entry's
        // STORED delegate_key (never re-derived — irregular rows' recorded keys
        // don't derive).
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
        // Once set, every remaining (older) predecessor is Superseded: either a
        // newer authoritative snapshot was found (NewestSnapshotWins) or the walk
        // halted (P1#1: never import an older predecessor after a newer one
        // imported partially or was unreachable).
        let mut terminated = false;

        for (key, generation) in ordered {
            if terminated {
                results.push(PredecessorMigration::Superseded { key, generation });
                continue;
            }

            // Already migrated? The delegate-key marker (with its data/empty flag),
            // OR — defensively — a legacy generation-keyed marker (P1#3 bridge),
            // which is policy-aware: under NewestSnapshotWins a newer legacy
            // snapshot is authoritative so `>=` seals older generations; under
            // Union only the EXACT generation is done (generations *below* the
            // legacy done marker were barred by monotonicity, never copied, so
            // Union must still recover them). Skip the round-trips entirely.
            let legacy = match policy {
                SecretSelectionPolicy::NewestSnapshotWins => {
                    legacy_generation_migrated(store, generation)
                }
                SecretSelectionPolicy::UnionAllGenerations(_) => {
                    legacy_generation_migrated_exact(store, generation)
                }
            };
            let already =
                predecessor_migration_had_data(store, &key).or_else(|| legacy.then_some(true));
            if let Some(had_data) = already {
                if policy.already_migrated_is_authoritative(had_data) {
                    terminated = true;
                }
                results.push(PredecessorMigration::AlreadyMigrated { key, generation });
                continue;
            }

            // G1.8: confirm executability BEFORE concluding "no data". A transport
            // error or a clean no-reply are both Unresponsive (error attached only
            // for the former); under NewestSnapshotWins an unknown newer state must
            // not be fallen through (would risk resurrecting deleted keys).
            match self.io.probe_executable(&key).await {
                Ok(true) => {}
                Ok(false) => {
                    results.push(PredecessorMigration::Unresponsive {
                        key,
                        generation,
                        error: None,
                    });
                    terminated = policy.unresponsive_terminates();
                    continue;
                }
                Err(e) => {
                    results.push(PredecessorMigration::Unresponsive {
                        key,
                        generation,
                        error: Some(format!("{e:?}")),
                    });
                    terminated = policy.unresponsive_terminates();
                    continue;
                }
            }

            let secrets = match self.io.fetch_secrets(&key).await {
                Ok(secrets) => secrets,
                Err(e) => {
                    results.push(PredecessorMigration::Unresponsive {
                        key,
                        generation,
                        error: Some(format!("{e:?}")),
                    });
                    terminated = policy.unresponsive_terminates();
                    continue;
                }
            };

            // NoData is imported through here too (empty slice), so its marker is
            // written and a re-run is a true no-op (P1#2).
            let outcome = import_predecessor_secrets_once(store, &key, &secrets);
            let migration = match outcome {
                PredecessorImportOutcome::Imported { imported, skipped } => {
                    // Classify by the PERSISTED marker flag (the source of truth a
                    // retry preserves), not the raw counts: a data-then-empty retry
                    // writes 0 secrets but keeps its data-bearing marker, so it is
                    // still Imported (authoritative), not NoData (P1 retry-flip).
                    if predecessor_migration_had_data(store, &key) == Some(true) {
                        PredecessorMigration::Imported {
                            key,
                            generation,
                            imported,
                            skipped,
                        }
                    } else {
                        PredecessorMigration::NoData { key, generation }
                    }
                }
                // Concurrent marker appearance; the driver already gated on it.
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
            };
            match &migration {
                // Data-bearing snapshot: authoritative under NewestSnapshotWins.
                PredecessorMigration::Imported { .. } => {
                    if policy.imported_is_authoritative() {
                        terminated = true;
                    }
                }
                // Concurrent marker appearance; classify by its recorded flag.
                PredecessorMigration::AlreadyMigrated { .. } => {
                    let had_data =
                        predecessor_migration_had_data(store, migration.key()).unwrap_or(true);
                    if policy.already_migrated_is_authoritative(had_data) {
                        terminated = true;
                    }
                }
                // Partial write: never process an older predecessor after it (P1#1).
                PredecessorMigration::Incomplete { .. } => terminated = true,
                // NoData falls through to older predecessors under both policies.
                _ => {}
            }
            results.push(migration);
        }

        DelegateMigrationReport {
            predecessors: results,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegate::{done_marker, pred_done_marker, predecessor_done_marker};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    // ---- test successor store -------------------------------------------------

    #[derive(Default)]
    struct MemStore {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
        /// `set_secret` fails (stores nothing) for keys in this set, modelling a
        /// storage write error for the two-phase / Incomplete tests.
        fail_keys: BTreeSet<Vec<u8>>,
    }
    impl MemStore {
        fn fail_writes_to(&mut self, key: &[u8]) {
            self.fail_keys.insert(key.to_vec());
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
        /// force a transport error from probe_executable for these keys.
        error_on_probe: HashSet<Vec<u8>>,
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
        fn error_probe(mut self, key: &DelegateKey) -> Self {
            self.error_on_probe.insert(key.bytes().to_vec());
            self
        }
    }

    impl PredecessorSecretsIo for MockIo {
        type Error = IoAbort;
        async fn probe_executable(&mut self, predecessor: &DelegateKey) -> Result<bool, IoAbort> {
            let k = predecessor.bytes().to_vec();
            if self.error_on_probe.contains(&k) {
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
            _policy: &SecretSelectionPolicy,
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

    fn newest() -> SecretSelectionPolicy {
        SecretSelectionPolicy::NewestSnapshotWins
    }

    fn union() -> SecretSelectionPolicy {
        SecretSelectionPolicy::UnionAllGenerations(
            UnionAck::i_understand_union_resurrects_deleted_by_absence_secrets(),
        )
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

    // ---- single-predecessor outcome classification ---------------------------

    #[test]
    fn imports_secrets_from_an_executable_predecessor_with_data() {
        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(
            &key_of(&e),
            &[(b"rooms", b"blob"), (b"signing_key:a", b"kb")],
        );
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
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
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::NoData { .. }
        ));
        assert!(report.is_complete(), "no-data is a clean, complete outcome");
        assert!(!report.any_unresponsive());
    }

    #[test]
    fn unexecutable_predecessor_is_unresponsive_never_silent_fresh_install() {
        // freenet/river#204: a broken/absent old delegate must surface, not read
        // as "no data → fresh install".
        let e = entry(4, 4);
        let mut store = MemStore::default();
        let mut io = MockIo::default().dead(&key_of(&e));
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Unresponsive { error: None, .. }
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
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
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
            block_on(migrate_delegate_secrets(
                &mut store,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
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
            block_on(migrate_delegate_secrets(
                &mut store,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        assert!(matches!(
            second.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert_eq!(store.get_secret(b"k").unwrap(), b"v", "value not clobbered");
        assert_eq!(store.list_secrets(b"").len(), n_after_first, "no new keys");
    }

    #[test]
    fn empty_predecessor_list_is_a_clean_empty_report() {
        let mut store = MemStore::default();
        let mut io = MockIo::default();
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[],
            ack(),
            newest(),
        ));
        assert!(report.predecessors.is_empty());
        assert!(report.is_complete());
        assert!(
            !report.any_unresponsive(),
            "no predecessors = safe fresh install"
        );
    }

    // ---- SecretSelectionPolicy matrix ----------------------------------------

    #[test]
    fn newest_snapshot_wins_supersedes_older_after_a_data_bearing_newer() {
        // Newest data-bearing predecessor is authoritative; the older one is
        // Superseded (never imported), so a key that lives ONLY in the older
        // generation stays unrecovered — the documented cost of the safe default.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&old), &[(b"shared", b"OLD"), (b"only_old", b"o")])
            .executable_with(&key_of(&new), &[(b"shared", b"NEW"), (b"only_new", b"n")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        // Newest first (gen 2 Imported), then gen 1 Superseded.
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(report.is_complete(), "a clean supersede is still complete");
        assert_eq!(store.get_secret(b"shared").unwrap(), b"NEW");
        assert_eq!(store.get_secret(b"only_new").unwrap(), b"n");
        assert!(
            store.get_secret(b"only_old").is_none(),
            "older-only key is NOT recovered under NewestSnapshotWins (documented cost)"
        );
        // The older predecessor was never even probed.
        assert!(!io.probed.contains(key_of(&old).bytes()));
    }

    #[test]
    fn newest_snapshot_wins_does_not_resurrect_a_deleted_key() {
        // THE delete-by-absence case. Newer generation (gen 2) deleted key `k`
        // (it has only `a`); older generation (gen 1) still has `k`. Under
        // NewestSnapshotWins the newer snapshot is authoritative, so `k` must NOT
        // come back.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&old), &[(b"a", b"1"), (b"k", b"deleted-value")])
            .executable_with(&key_of(&new), &[(b"a", b"1")]);
        block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        assert_eq!(store.get_secret(b"a").unwrap(), b"1");
        assert!(
            store.get_secret(b"k").is_none(),
            "NewestSnapshotWins must NOT resurrect a key the newer generation deleted"
        );
    }

    #[test]
    fn union_resurrects_a_deleted_key_documented() {
        // Same setup as above, but UnionAllGenerations DOES import the older
        // generation, so the deleted-by-absence `k` comes back. This is the
        // documented, ack-gated resurrection (river#204 stranded-data recovery).
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&old), &[(b"a", b"1"), (b"k", b"deleted-value")])
            .executable_with(&key_of(&new), &[(b"a", b"1")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
            union(),
        ));
        // Both generations imported (newest-first).
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(
            store.get_secret(b"k").unwrap(),
            b"deleted-value",
            "Union DOES resurrect the older generation's key (documented)"
        );
    }

    #[test]
    fn union_newest_generation_still_wins_a_key_conflict() {
        // Union imports all, but never-clobber + newest-first means the newest
        // generation's value wins any shared key.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&old), &[(b"shared", b"OLD"), (b"only_old", b"o")])
            .executable_with(&key_of(&new), &[(b"shared", b"NEW"), (b"only_new", b"n")]);
        block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
            union(),
        ));
        assert_eq!(store.get_secret(b"shared").unwrap(), b"NEW", "newest wins");
        assert_eq!(
            store.get_secret(b"only_old").unwrap(),
            b"o",
            "older-only recovered"
        );
        assert_eq!(store.get_secret(b"only_new").unwrap(), b"n");
    }

    #[test]
    fn newest_snapshot_wins_falls_through_an_empty_newer_to_an_older_with_data() {
        // The common migration shape: the NEW generation's delegate is empty
        // (freshly registered), so NewestSnapshotWins falls through to the older
        // generation that actually holds the data.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[]) // newest: empty
            .executable_with(&key_of(&old), &[(b"data", b"v")]); // older: has data
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::NoData { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(store.get_secret(b"data").unwrap(), b"v");
    }

    #[test]
    fn newest_snapshot_wins_halts_on_unresponsive_newest_no_fall_through() {
        // Newest generation unreachable → NewestSnapshotWins must NOT fall through
        // to import the older snapshot (that could resurrect keys the unknown
        // newer state deleted). It halts; the app surfaces #204 and can retry.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .dead(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"data", b"v")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(report.any_unresponsive());
        assert!(!report.is_complete());
        assert!(
            store.get_secret(b"data").is_none(),
            "must not fall through past an unknown newer state"
        );
        assert!(
            !io.probed.contains(key_of(&old).bytes()),
            "older not probed"
        );
    }

    #[test]
    fn union_recovers_older_data_past_an_unresponsive_newest() {
        // Under Union the unreachable newest does not stop the walk; the older
        // generation's data is recovered (its unresponsiveness is still reported).
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .dead(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"data", b"v")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[old, new],
            ack(),
            union(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert!(report.any_unresponsive());
        assert_eq!(store.get_secret(b"data").unwrap(), b"v");
    }

    #[test]
    fn union_classifies_each_predecessor_independently() {
        // A realistic V4-V6 skip under Union: has-data / empty / dead each land
        // as their own row (Union walks every generation).
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
            union(),
        ));
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
        assert!(report.any_unresponsive(), "the dead V4 trips the #204 gate");
        assert!(!report.is_complete());
        assert_eq!(report.imported_total(), 1);
    }

    // ---- stop-after-incomplete (P1#1) ----------------------------------------

    #[test]
    fn incomplete_newer_halts_before_older_under_both_policies() {
        // P1#1 / Codex G2-shared-key: a partial import of the NEWER predecessor
        // must halt the walk before the OLDER one, or a retry's newest-wins value
        // could be shadowed by the older one under never-clobber.
        for policy in [newest(), union()] {
            let old = entry(1, 1);
            let new = entry(2, 2);
            let mut store = MemStore::default();
            store.fail_writes_to(b"x"); // the newer generation's write fails
            let mut io = MockIo::default()
                .executable_with(&key_of(&new), &[(b"x", b"NEW")])
                .executable_with(&key_of(&old), &[(b"x", b"OLD"), (b"only_old", b"o")]);
            let report = block_on(migrate_delegate_secrets(
                &mut store,
                &mut io,
                &[old, new],
                ack(),
                policy,
            ));
            assert!(
                matches!(
                    report.predecessors[0],
                    PredecessorMigration::Incomplete { .. }
                ),
                "newer predecessor is Incomplete"
            );
            assert!(
                matches!(
                    report.predecessors[1],
                    PredecessorMigration::Superseded { .. }
                ),
                "older predecessor must be Superseded (not imported) after an Incomplete newer"
            );
            assert!(!report.is_complete());
            assert!(
                store.get_secret(b"x").is_none(),
                "the failed key must not be back-filled from the older generation"
            );
            assert!(
                store.get_secret(b"only_old").is_none(),
                "older predecessor must not be imported after the halt"
            );
        }
    }

    // ---- NoData writes a marker (P1#2) ---------------------------------------

    #[test]
    fn nodata_writes_a_marker_so_rerun_is_a_noop_even_if_delegate_gains_data() {
        // P1#2: an empty predecessor still records a (empty) marker, so a later
        // re-run does not import data the old delegate somehow gained afterwards.
        let e = entry(1, 1);
        let mut store = MemStore::default();

        let first = {
            let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
            block_on(migrate_delegate_secrets(
                &mut store,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        assert!(matches!(
            first.predecessors[0],
            PredecessorMigration::NoData { .. }
        ));
        assert!(
            store.has_secret(&pred_done_marker(&key_of(&e))),
            "empty marker written"
        );

        // Re-run: the old delegate now "has data", but the marker blocks re-import.
        let second = {
            let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"late", b"data")]);
            block_on(migrate_delegate_secrets(
                &mut store,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        assert!(matches!(
            second.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert!(
            store.get_secret(b"late").is_none(),
            "a NoData predecessor's later data must not be imported on re-run"
        );
    }

    #[test]
    fn newest_snapshot_wins_rerun_does_not_import_previously_superseded_older() {
        // The data/empty marker's reason for existing: on re-run, an older
        // predecessor that was Superseded (never imported, no marker) must stay
        // Superseded — the newer data-bearing predecessor's AlreadyMigrated marker
        // must re-establish authority so the older one is not imported (which would
        // resurrect its keys).
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let run = |store: &mut MemStore| {
            let mut io = MockIo::default()
                .executable_with(&key_of(&new), &[(b"newkey", b"v")])
                .executable_with(&key_of(&old), &[(b"oldkey", b"resurrect-me")]);
            block_on(migrate_delegate_secrets(
                store,
                &mut io,
                &[old, new],
                ack(),
                newest(),
            ))
        };
        run(&mut store); // newer authoritative, older superseded
        assert!(store.get_secret(b"oldkey").is_none());

        let report = run(&mut store); // re-run
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(
            store.get_secret(b"oldkey").is_none(),
            "a re-run must NOT import a previously-superseded older predecessor"
        );
    }

    // ---- legacy generation-marker bridge (P1#3) ------------------------------

    #[test]
    fn legacy_generation_marker_bridges_to_the_delegate_key_path() {
        // If a store carries a legacy generation-keyed done marker (a prior
        // `import_secrets_once` migration), the delegate-key path defensively
        // treats predecessors it covers as AlreadyMigrated and does not re-import.
        let covered = entry(3, 3);
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1"); // legacy migration up to gen 5
        let mut io = MockIo::default().executable_with(&key_of(&covered), &[(b"x", b"y")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[covered],
            ack(),
            newest(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert!(
            !io.probed.contains(key_of(&covered).bytes()),
            "a legacy-covered predecessor must not be re-probed/imported"
        );
        assert!(store.get_secret(b"x").is_none());
    }

    // ---- io errors captured as report rows (P1#4) ----------------------------

    #[test]
    fn io_error_midrun_is_captured_as_a_row_not_a_bare_error() {
        // A transport error mid-walk must not discard the predecessors already
        // migrated: it becomes an Unresponsive row carrying the error, and the
        // report (not an Err) is the source of truth.
        let errs = entry(1, 1);
        let ok = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&ok), &[(b"k", b"v")])
            .error_probe(&key_of(&errs));
        // Union so the walk continues past the ok row to the erroring older one.
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[errs, ok],
            ack(),
            union(),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::Imported { .. }
            ),
            "the completed row before the error is preserved"
        );
        assert!(
            matches!(
                &report.predecessors[1],
                PredecessorMigration::Unresponsive { error: Some(_), .. }
            ),
            "the transport error is captured with detail, not returned bare"
        );
        assert!(report.any_unresponsive());
        assert_eq!(
            store.get_secret(b"k").unwrap(),
            b"v",
            "the ok import survived"
        );
    }

    // ---- register wrapper -----------------------------------------------------

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
            newest(),
        ))
        .unwrap();
        assert_eq!(io.registered, 1, "the successor must be registered");
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(store.get_secret(b"k").unwrap(), b"v");
    }

    // ---- consent shape (P1#5) ------------------------------------------------

    #[test]
    fn authorization_is_a_non_default_enum_with_a_loud_constructor() {
        // Pins the consent shape: the only route is the loud constructor (the
        // variant carries a private token, so `AppAuthorAck` cannot be named/built
        // directly, and there is no Default — see the compile_fail doctest on
        // migrate_delegate_secrets).
        assert!(matches!(
            MigrationAuthorization::app_author_ack(),
            MigrationAuthorization::AppAuthorAck(_)
        ));
    }

    // ---- Gap 3 seam: register-time node copy + shared markers ----------------

    #[test]
    fn node_register_time_copy_via_public_marker_short_circuits_migrate() {
        // The real Gap-3 realization (fidelity F1 + Codex P1): a node copies a
        // predecessor's secrets at REGISTER time — internally, no io, no old-WASM
        // execution — and seals it by writing the completion marker through the
        // PUBLIC, versioned format (`predecessor_done_marker`), the exact contract
        // surface core uses. The unchanged app-facing migrate then finds the marker
        // and short-circuits to AlreadyMigrated. NOT a second SecretTransport impl.
        let e = entry(1, 1);
        let mut store = MemStore::default();

        // The node's register-time copy: copy the secret + seal via the public
        // marker format (had_data = true, ≥1 secret copied).
        store.set_secret(b"nk", b"nv");
        let (marker_key, marker_value) = predecessor_done_marker(&key_of(&e), true);
        store.set_secret(&marker_key, &marker_value);

        // The unchanged app-facing entry point sees the node-written marker and is
        // a no-op — no predecessor round-trip, no resurrection.
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"nk", b"RESURRECT")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::AlreadyMigrated { .. }
            ),
            "the interim path must recognize the node-written public marker"
        );
        assert!(
            !io.probed.contains(key_of(&e).bytes()),
            "a register-time node copy means migrate does no predecessor round-trip"
        );
        assert_eq!(
            store.get_secret(b"nk").unwrap(),
            b"nv",
            "not resurrected/clobbered"
        );
    }

    #[test]
    fn legacy_bridge_under_union_only_seals_the_exact_generation() {
        // P2 (legacy bridge vs Union): with a legacy done:5 marker, Union treats
        // ONLY gen 5 as already-migrated; gen 3 (below) was BARRED by the legacy
        // path's monotonicity (never copied), so Union must still recover it.
        let g5 = entry(5, 5);
        let g3 = entry(3, 3);
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        let mut io = MockIo::default()
            .executable_with(&key_of(&g5), &[(b"a", b"5")])
            .executable_with(&key_of(&g3), &[(b"b", b"3")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store,
            &mut io,
            &[g3, g5],
            ack(),
            union(),
        ));
        // Newest-first: g5 (exact legacy → AlreadyMigrated), g3 (below → imported).
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(
            store.get_secret(b"b").unwrap(),
            b"3",
            "a generation below the legacy done marker IS recovered under Union"
        );
        assert!(
            store.get_secret(b"a").is_none(),
            "the exact legacy generation is not re-imported"
        );
    }
}
