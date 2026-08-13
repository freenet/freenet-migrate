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
//! # The crate decides WHAT; the app does the WRITING (0.5.0)
//!
//! Both ends of the migration are app-supplied I/O adapters:
//! [`PredecessorSecretsIo`] reads the **predecessors**, [`SuccessorSecretsIo`]
//! writes the **successor**. The crate owns only the decisions in between.
//!
//! Before 0.5.0 the successor end was a raw `(key, value)` copy into a
//! [`SecretStore`], one pair at a time, never-clobber. That is
//! wrong for any app whose stored items carry **cross-entry invariants**, and it
//! fails *silently*:
//!
//! * **A derived index.** ghostkeys stores each credential as several entries plus
//!   one `gk:index` entry listing which credentials exist; its UI reads that index
//!   to know what to display. A pair copier finds an index already on the successor
//!   (the user made one key on the new version before the sweep ran), skips it
//!   never-clobber, and the recovered credential's bytes land in the store while
//!   nothing lists them: permanently invisible, no error. **No
//!   [`SecretSelectionPolicy`] fixes this** — `UnionAllGenerations` recovers both
//!   generations' bytes and the older index write is still clobber-skipped — because
//!   the mover cannot know that entry needs *merging* rather than *replacing*
//!   (freenet/ghostkeys#32 finding D3).
//! * **Permission grants.** ghostkeys' own `ImportGhostKey` handler ends by
//!   recording a grant for the requesting app, and its list/sign/export paths skip
//!   any fingerprint the requestor lacks a grant on. Grants are not among the
//!   exported pairs at all, so a raw pair copy produces entries that are dead for
//!   every requestor even when the index *does* survive.
//! * **Verification and derivation.** That same handler verifies a certificate
//!   chain and derives the fingerprint itself, and declines to copy a predecessor's
//!   permission grants verbatim. A raw pair copy does none of it.
//!
//! A raw `(key, value)` copy skips exactly four things ghostkeys' own
//! `ImportGhostKey` handler does: it records no **permission grant** (so the item
//! is unusable even when listed), it does not add to the **index** the UI reads (so
//! it is invisible), it does not **verify the certificate chain** against the
//! compiled-in master key, and it does not **derive the fingerprint** delegate-side.
//! An index-merge hook would have fixed one of the four. Routing the write through
//! the app's own handler fixes all four — which is the argument for the seam. It is
//! not a patch for the index bug; it is the observation that **the mover can never
//! know an app's invariants and should not try**.
//!
//! The measured differential (freenet/ghostkeys#32, re-run) puts 13 of 14 scenarios
//! in disagreement between a raw-pair copy and the app's own import path; the single
//! agreement is the case where nothing is recovered at all.
//!
//! Apps whose secrets genuinely have no cross-entry invariants keep the old
//! behaviour in one line with [`SecretStoreIo`], which is the raw-pair,
//! never-clobber writer over a [`SecretStore`] — gated behind
//! the loud [`NoCrossEntryInvariantsAck`] so the choice is visible at the call site.
//!
//! # sans-IO decomposition
//!
//! The crate owns the **decisions** — which predecessors, newest-first, the
//! executability preflight before ever concluding "no data" (G1.8), when a
//! predecessor is already migrated, which recovered items to offer, how to classify
//! each outcome, and the two-phase marker discipline — and the app owns the **I/O**
//! at both ends through thin adapters (modeled on the contract side's
//! [`crate::ProbeIo`]): one round-trip per call, correlation and transport left to
//! the app.
//!
//! Unlike the contract side there is deliberately **no hand-pumped raw driver**
//! here — the adopter's delegate path is already awaitable (River drives each
//! delegate round-trip to completion through a per-request `oneshot` side-table,
//! unlike its fire-and-forget contract probe), so a single async entry point over
//! these adapters is all that is needed.
//!
//! ```text
//! for predecessor in newest_first(predecessors) {   // stop early per policy
//!     match successor.migration_marker(..).await {              // §0 marker
//!         Err(..)              => record WriterUnavailable; STOP
//!         Ok(Some(Done { .. })) => { record AlreadyMigrated; maybe stop }
//!         Ok(in_progress_or_none) => {
//!             match io.probe_executable(predecessor).await {    // G1.8 preflight
//!                 Ok(false) | Err(_) => { record Unresponsive; maybe stop }
//!                 Ok(true) => {
//!                     // Err (incl. a silent export) => record Unresponsive; maybe stop
//!                     let secrets = io.fetch_secrets(predecessor).await?;
//!                     successor.record_marker(InProgress { saw_data }).await?;
//!                     for item in secrets minus reserved markers minus withheld {
//!                         successor.write_secret(item).await   // the APP's import path
//!                     }
//!                     successor.flush_predecessor(..).await
//!                     if nothing failed { successor.record_marker(Done { .. }).await }
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! Cross-generation selection is an explicit [`SecretSelectionPolicy`]
//! (`NewestSnapshotWins` default, or `UnionAllGenerations`), the delegate-side
//! analogue of the contract driver's `NewestFirstWins` / `FoldAll`.
//!
//! # Termination is a POLICY question, not a failure question (0.5.0)
//!
//! Before 0.5.0 a partial write halted the walk under **both** policies, so one
//! storage failure on one key of the newest predecessor marked every older
//! generation `Superseded` and recovered nothing from them — even under
//! `UnionAllGenerations`, whose entire purpose is to walk every generation. That is
//! the same silent-data-loss class as the index bug, and it survived the policy
//! switch.
//!
//! 0.5.0 derives termination from the policy and the predecessor's **data-bearing**
//! state, never from whether a write succeeded:
//!
//! | outcome | `NewestSnapshotWins` | `UnionAllGenerations` |
//! |---|---|---|
//! | `Imported` / data-bearing `Incomplete` / data-bearing `AlreadyMigrated` | stop (authoritative snapshot) | continue |
//! | `NoData` / empty `Incomplete` | continue | continue |
//! | `Unresponsive` | stop (unknown newer state) | continue |
//! | `WriterUnavailable` | stop | stop (successor-side bookkeeping is broken) |
//!
//! A data-bearing predecessor is authoritative under `NewestSnapshotWins` whether or
//! not its writes all landed, so that column is unchanged. What changes is Union: a
//! failed write no longer abandons the older generations.
//!
//! The one thing the old halt genuinely bought is kept by a narrower mechanism:
//! a key whose write **failed retryably** on a newer predecessor is **withheld**
//! from older predecessors for the rest of the run (counted as
//! [`ImportTally::withheld`]), so an older generation can never shadow a newer
//! value that is merely awaiting a retry. A key the successor **permanently
//! rejected** is *not* withheld — an older generation's copy of it may well be
//! acceptable. A predecessor with withheld items does not get a completion marker,
//! so the retry re-walks it.
//!
//! The same withholding covers a **failed flush**, which is the durability
//! boundary for the buffering writer [`SuccessorSecretsIo::flush_predecessor`]
//! exists for. Such a writer answers `Written` optimistically and loses the batch
//! at flush time, so a flush failure withholds *every* key that predecessor
//! resolved — `Written` and `AlreadyAuthoritative` alike, since "the successor's
//! value is authoritative" can itself be unflushed buffer state — and re-counts
//! its optimistic [`ImportTally::written`] as [`ImportTally::failed`], so the
//! report never claims data the discarded buffer took with it.
//!
//! **Withholding is scoped to a single call.** The withheld-key set is built fresh
//! each run and never persisted, so it protects only within the run that created
//! it. Under `UnionAllGenerations` that boundary can permanently shadow the newest
//! generation's value across a retry, with a clean report — the sequence is on
//! [`UnionAck`], and closing it is freenet/freenet-migrate#15.
//!
//! Honest limits — what stays app code the crate cannot verify: both I/O adapters
//! (send / correlate / time out; and what the app's import path does with an item);
//! what a "cheap no-op probe" is in the app's own delegate protocol; and
//! **idempotency of the app's writer** — the crate will not re-run a *completed*
//! predecessor, but a retry after a partial run re-offers items, so a writer that
//! appends to a list must insert into a set (see [`SuccessorSecretsIo::write_secret`]).
//! The preflight distinguishes "can't execute" from "no data" only while the node the
//! request reaches actually has the predecessor delegate registered/available (see
//! [`PredecessorSecretsIo::probe_executable`]).

use core::future::Future;
use std::collections::BTreeSet;

use freenet_stdlib::prelude::{CodeHash, DelegateKey};

use crate::delegate::{
    is_marker, legacy_generation_migrated, legacy_generation_migrated_exact, pred_done_marker,
    pred_wip_marker, SecretPair, SecretStore, PRED_DONE_MARKER_VALUE_DATA,
    PRED_DONE_MARKER_VALUE_EMPTY,
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
    /// **Opt-in recovery.** Import *every* predecessor newest-first, with the
    /// newest generation's value winning any key conflict **only because the app's
    /// writer declines a key it already holds** ([`SecretStoreIo`] does so
    /// never-clobber). An overwriting writer inverts that guarantee silently and
    /// installs the *oldest* generation's value — see the never-clobber bullet on
    /// [`SuccessorSecretsIo`] before choosing this policy.
    /// This is the freenet/river#204 stranded-older-generation recovery mode.
    ///
    /// It **resurrects delete-by-absence data**: a key deleted in a newer
    /// generation but still present in an older one is re-imported. Hence the loud
    /// [`UnionAck`].
    UnionAllGenerations(UnionAck),
}

/// Opt-in token for [`SecretSelectionPolicy::UnionAllGenerations`]. Deliberately
/// not `Default`: holding one acknowledges that union import can resurrect
/// secrets a newer generation deleted by absence.
///
/// # The second hazard: withholding is run-scoped
///
/// The withheld-key set that stops an older generation from shadowing a newer
/// value lives **only for the duration of one [`migrate_delegate_secrets`] call**.
/// It is built fresh each call and never persisted, so a retry starts with it
/// empty. Under Union, where neither an `Unresponsive` newest generation nor a
/// failed flush halts the walk, that boundary can lose the newest generation's
/// value for good:
///
/// 1. **Run 1.** The newest generation resolves key `k` and its flush fails. `k`
///    is withheld, so no older generation may supply it. Nothing is sealed.
/// 2. **Run 2.** The newest generation is *transiently* unreachable. Union does
///    not terminate on `Unresponsive`, and the withheld set is empty again, so an
///    older generation writes its own `k = v1`, flushes clean, and earns
///    `Done { had_data: true }`.
/// 3. **Run 3.** The newest generation is back and offers `k = v2`. The successor
///    already holds `v1`, so a never-clobber writer declines it as
///    [`ItemWrite::AlreadyAuthoritative`]. The tally is clean, the marker seals,
///    and the report reads
///    [`is_complete`](DelegateMigrationReport::is_complete)` == true` with
///    [`retry_may_help`](DelegateMigrationReport::retry_may_help)` == false`.
///
/// The durable value is the older `v1`, the newest generation's `v2` is shadowed
/// permanently, and nothing in the report says so.
///
/// This is a **different** loss from the delete-by-absence resurrection above:
/// there the newer generation's *deletion* is undone, here its *value* is, and
/// unlike the resurrection case the report afterwards reads clean. The trigger is
/// mundane rather than adversarial, and its two halves are correlated: a flush
/// fails because the app is degraded, and the retry lands while the predecessor is
/// still not answering.
///
/// Closing it means persisting withheld keys across runs, a design change tracked
/// in freenet/freenet-migrate#15. Until then: prefer
/// [`NewestSnapshotWins`](SecretSelectionPolicy::NewestSnapshotWins) unless
/// stranded-generation recovery is specifically what you need, and retry a run
/// that reports [`ImportTally::withheld`] items promptly, before the predecessor
/// can go unreachable.
#[must_use = "a UnionAck acknowledges that union import resurrects secrets a newer \
              generation deleted by absence, AND that withholding is run-scoped so a \
              retry can let an older generation shadow the newest value (see the docs); \
              construct it only if that is intended"]
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
    /// Whether a **data-bearing** predecessor terminates the walk: under
    /// `NewestSnapshotWins` the newest data-bearing generation is the authoritative
    /// snapshot, so older ones are `Superseded`. Union always walks on.
    ///
    /// This is asked of `Imported`, data-bearing `Incomplete`, and data-bearing
    /// `AlreadyMigrated` alike — a snapshot's authority comes from its **data**, not
    /// from whether every write of it landed (see the module docs, "Termination is a
    /// POLICY question").
    fn data_bearing_is_authoritative(&self, had_data: bool) -> bool {
        matches!(self, SecretSelectionPolicy::NewestSnapshotWins) && had_data
    }

    /// Whether an `Unresponsive` predecessor terminates the walk. Under
    /// `NewestSnapshotWins` it does — falling through to import an older snapshot
    /// past an unknown newer state would risk resurrecting keys the newer
    /// generation deleted. Union keeps going (it wants every generation).
    fn unresponsive_terminates(&self) -> bool {
        matches!(self, SecretSelectionPolicy::NewestSnapshotWins)
    }

    /// How a **legacy generation-keyed** done marker (from the older
    /// [`crate::import_secrets_once`] API) seals a predecessor. See
    /// [`LegacyBridge`].
    fn legacy_bridge(&self) -> LegacyBridge {
        match self {
            SecretSelectionPolicy::NewestSnapshotWins => LegacyBridge::AtOrAboveGeneration,
            SecretSelectionPolicy::UnionAllGenerations(_) => LegacyBridge::ExactGenerationOnly,
        }
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
    /// * `Ok(true)` — the predecessor delegate ran and answered. This makes an
    ///   *answered* empty [`fetch_secrets`](Self::fetch_secrets) trustworthy; it
    ///   does **not** license `fetch_secrets` to report its own silence as an
    ///   empty export. A delegate that answers a cheap no-op and then never
    ///   answers the export is positive evidence of stranded data, and
    ///   `fetch_secrets` must return `Err` for it (see that method).
    /// * `Ok(false)` — no reply within the app's bound: the old WASM could not
    ///   execute, or the node no longer has it registered, or the request was
    ///   lost. The driver records [`PredecessorMigration::Unresponsive`] so the
    ///   app can surface "your data may exist but can't auto-migrate" instead of
    ///   silently treating the predecessor as empty and fresh-installing (the
    ///   freenet/river#204 UX bug).
    /// * `Err` — a transport fault. Also [`PredecessorMigration::Unresponsive`]
    ///   (with the error attached), and the walk continues or stops per
    ///   [`SecretSelectionPolicy`]. This does **not** abort the whole run:
    ///   [`migrate_delegate_secrets`] returns a report, not a `Result`.
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
    /// **`Ok(vec![])` is a positive claim: "I asked, and it has nothing."** It
    /// seals the predecessor with a `Done { had_data: false }` marker that is
    /// never revisited, so returning it for a request that merely went
    /// unanswered records a slow or temporarily unreachable predecessor as
    /// permanently empty — silently, with the report reading complete. That is
    /// the data-loss default freenet/freenet-migrate#19 exists to stop.
    ///
    /// * `Ok(pairs)` / `Ok(vec![])` — the predecessor **answered**. Only an
    ///   answer.
    /// * `Err` — anything that left the export unestablished: a timeout, a
    ///   transport failure, an unexpected or undecodable reply, an answered
    ///   error. The driver records [`PredecessorMigration::Unresponsive`], the
    ///   predecessor earns **no marker**, and the next run re-walks it. `Err`
    ///   does **not** abort the whole migration — the walk continues or stops
    ///   per [`SecretSelectionPolicy`], and
    ///   [`migrate_delegate_secrets`] still returns a report.
    ///
    /// So `Err` is the right answer for silence, and it is cheap: the cost of a
    /// wrong `Err` is one retry, the cost of a wrong `Ok(vec![])` is the user's
    /// data.
    ///
    /// The pairs are offered to the successor's own writer
    /// ([`SuccessorSecretsIo::write_secret`]) one at a time; the adapter should
    /// already exclude the app's own reserved keys if any. (This crate's own
    /// reserved markers are filtered by the driver regardless.)
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

// ---------------------------------------------------------------------------
// The successor-side writer seam (0.5.0)
// ---------------------------------------------------------------------------

/// The two-phase migration marker for one predecessor, as the successor stores it.
///
/// The crate decides *when* each state is recorded; the app decides *where* it
/// lives. [`SecretStoreIo`] persists it in the crate's public, versioned marker
/// format ([`crate::predecessor_done_marker`]) — the cross-transport
/// interoperability contract a future node-side copy-forward writes and reads —
/// and an app implementing this trait itself SHOULD use the same format for the
/// `Done` state, so a node copy-forward and the app agree on what is already
/// migrated.
///
/// Why two states: the in-progress marker is recorded *before* any item is
/// written, and only ever upgraded to `Done` once every item landed. A run that
/// dies in the middle therefore leaves `InProgress`, so a retry re-runs the
/// predecessor; a completed `Done` is never re-imported, so a stray re-run cannot
/// resurrect secrets the user deleted afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationMarker {
    /// An import from this predecessor started and did not complete. `saw_data`
    /// records whether *any* attempt so far saw real secrets, so the data/empty
    /// decision is **sticky-data** across retries (a data-then-empty retry keeps
    /// its data flag; an empty-then-data retry upgrades to data).
    InProgress {
        /// Whether any attempt so far saw at least one real secret.
        saw_data: bool,
    },
    /// The import from this predecessor completed. `had_data` records whether it
    /// was data-bearing, which is what a re-run needs to reconstruct the same
    /// [`SecretSelectionPolicy`] decision.
    Done {
        /// Whether the completed migration was data-bearing.
        had_data: bool,
    },
}

/// How a **legacy generation-keyed** done marker (written by the older
/// [`crate::import_secrets_once`] API) seals a predecessor, for the defensive
/// P1#3 bridge. Only meaningful for a successor whose store was previously written
/// by that API; an app implementing [`SuccessorSecretsIo`] from scratch can ignore
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyBridge {
    /// `NewestSnapshotWins`: a legacy marker at **or above** this generation seals
    /// it (a newer legacy snapshot is authoritative, so the conservative seal is
    /// correct).
    AtOrAboveGeneration,
    /// `UnionAllGenerations`: only a legacy marker for the **exact** generation
    /// seals it. A generation *below* the newest legacy marker was barred by the
    /// legacy path's monotonicity — never copied — so Union must still recover it.
    ExactGenerationOnly,
}

/// What the driver needs to know about a predecessor's recorded migration state.
#[derive(Debug)]
#[non_exhaustive]
pub struct MarkerQuery<'a> {
    /// The predecessor delegate key.
    pub predecessor: &'a DelegateKey,
    /// The predecessor's lineage generation.
    pub generation: u32,
    /// How a legacy generation-keyed marker seals this predecessor (see
    /// [`LegacyBridge`]). Ignore unless the successor's store was previously
    /// written by [`crate::import_secrets_once`].
    pub legacy_bridge: LegacyBridge,
}

/// One secret recovered from a predecessor, offered to the successor's own import
/// path.
///
/// The crate has already decided this item is worth offering: the predecessor was
/// selected by the policy, the item is not one of the crate's reserved bookkeeping
/// markers, and no newer predecessor is holding a retryable failure on this key.
#[derive(Debug)]
#[non_exhaustive]
pub struct RecoveredSecret<'a> {
    /// The predecessor delegate key this item came from.
    pub predecessor: &'a DelegateKey,
    /// The predecessor's lineage generation.
    pub generation: u32,
    /// The raw secret key, as stored on the predecessor.
    pub key: &'a [u8],
    /// The raw secret value.
    pub value: &'a [u8],
    /// Whether this predecessor is being **re-attempted** after an earlier run left
    /// it in progress. Informational: a writer must be idempotent regardless (see
    /// [`SuccessorSecretsIo::write_secret`]), but a writer that cannot cheaply
    /// re-derive "do I already have this?" can use it.
    pub retry: bool,
}

/// Whether re-running the migration could make a failed item succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryAdvice {
    /// Transient — storage was unavailable, the round-trip timed out, and so on.
    /// The item is counted in [`ImportTally::failed`], the completion marker is
    /// withheld so a retry re-runs the predecessor, and the key is **withheld from
    /// older predecessors** for the rest of this run so an older generation cannot
    /// shadow the newer value that is merely awaiting a retry.
    Retryable,
    /// Permanent — the successor's import path refuses this item and always will
    /// (a certificate that does not verify, an item the successor's schema rejects).
    /// It is counted in [`ImportTally::rejected`], the completion marker is still
    /// withheld (the crate does not decide on the app's behalf to give up on data),
    /// and the key is **not** withheld from older predecessors: an older
    /// generation's copy of the same key may well be acceptable.
    ///
    /// **The verdict must hold across future versions of your app.** Because the key
    /// is not withheld, an older generation's copy can land and seal that predecessor
    /// clean — after which a never-clobber writer declines the newer value forever,
    /// even if a later app version would have accepted it. Return `Permanent` only
    /// for a refusal that is stable over time (a malformed value, a signature that
    /// can never verify), not for one that is merely "this version cannot handle it".
    /// If the refusal might not be stable, either keep the item `Retryable` or make
    /// the writer generation-aware via [`RecoveredSecret::generation`] so it can
    /// prefer the newer generation's value when it later becomes acceptable.
    Permanent,
}

/// What the successor's import path did with one [`RecoveredSecret`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ItemWrite<E> {
    /// The app applied the item (however it chooses to: merged into an index,
    /// re-derived, re-signed, granted).
    Written,
    /// The successor's own value stands, so the item was deliberately not applied
    /// — a **complete, correct** outcome, not a failure. Two reasons, both real:
    ///
    /// * the successor already holds an authoritative value for it (never-clobber,
    ///   which is what [`SecretStoreIo`] does); or
    /// * it is not the app's to copy verbatim — ghostkeys' import handler refuses
    ///   a predecessor's `gk:perms:` permission grants and records its own.
    ///
    /// # This is NOT an error channel — never map a write error here
    ///
    /// Returning this for a write that *failed* is silent, unrecoverable data
    /// loss, and it is a one-token mistake: an `Err(_) => …` arm in a writer's
    /// `match` is exactly where it happens. This variant is counted in
    /// [`ImportTally::skipped`], which [`ImportTally::is_clean`] treats as
    /// success, so the predecessor earns its `Done` marker and is **never walked
    /// again** — the data is gone with no failure anywhere in the report. The
    /// variant is named for the assertion it makes about the *successor's* state
    /// (its value is authoritative) precisely so that mapping an error onto it
    /// reads as the false claim it is.
    ///
    /// A failed write is [`ItemWrite::retryable`] or [`ItemWrite::permanent`].
    /// When in doubt, `retryable`: it costs a re-walk, not the data.
    AlreadyAuthoritative,
    /// The app could not apply the item.
    Failed {
        /// The app's error.
        error: E,
        /// Whether a retry could succeed (see [`RetryAdvice`]).
        retry: RetryAdvice,
    },
}

impl<E> ItemWrite<E> {
    /// The item was applied.
    pub fn written() -> Self {
        ItemWrite::Written
    }
    /// The successor's own value stands; the item was deliberately not applied.
    /// **Not an error channel** — see [`ItemWrite::AlreadyAuthoritative`].
    pub fn already_authoritative() -> Self {
        ItemWrite::AlreadyAuthoritative
    }
    /// The write failed transiently; a retry may succeed.
    pub fn retryable(error: E) -> Self {
        ItemWrite::Failed {
            error,
            retry: RetryAdvice::Retryable,
        }
    }
    /// The successor's import path refuses this item and always will.
    pub fn permanent(error: E) -> Self {
        ItemWrite::Failed {
            error,
            retry: RetryAdvice::Permanent,
        }
    }
}

/// **The successor-side I/O adapter: the app's own import path.** The mirror of
/// [`PredecessorSecretsIo`] — that one reads the predecessors, this one writes the
/// successor.
///
/// The crate hands over *what* to migrate, one [`RecoveredSecret`] at a time, and
/// the app applies each item however its own storage requires. That is the whole
/// point: an app whose stored items carry cross-entry invariants (a derived index,
/// permission grants, a verified certificate chain, a derived fingerprint) keeps
/// every one of them for free, because its own handler is what runs. See the module
/// docs for the ghostkeys evidence.
///
/// Apps with no such invariants use [`SecretStoreIo`] and write nothing.
///
/// # Contract
///
/// * **Idempotency is the implementer's job.** The crate never re-offers items from
///   a *completed* predecessor, but a retry after a partial run re-offers them. A
///   writer that appends to a list must insert into a set. [`RecoveredSecret::retry`]
///   says when a re-attempt is in progress.
/// * **Never-clobber is the implementer's choice, and Union's newest-wins guarantee
///   rests entirely on it.** The crate does not check whether the successor already
///   holds an item; return [`ItemWrite::AlreadyAuthoritative`] to skip it, which is
///   what [`SecretStoreIo`] does for a key it already has.
///
///   Under [`SecretSelectionPolicy::UnionAllGenerations`] the *only* mechanism
///   making the newest generation's value win a shared key is that predecessors are
///   offered newest-first and the writer declines a key it already holds. Nothing
///   else enforces it: the crate cannot read the successor, so it cannot tell a
///   decline from an overwrite. A writer with ordinary overwrite semantics — which
///   this contract permits, and which is the natural shape of an app's own
///   `import` handler — receives the newest value first and then lets every older
///   generation overwrite it in turn, ending with the **oldest** generation's value
///   installed and a completely clean report. That is the exact inversion of what
///   Union promises, it is silent, and no [`SecretSelectionPolicy`] setting detects
///   it.
///
///   So if your import path overwrites: either read the successor's current value
///   and return [`ItemWrite::AlreadyAuthoritative`] when it already holds the key,
///   or do not use `UnionAllGenerations`. (An *aggregate* item is the separate case
///   below: merge it, do not resolve it either way by key precedence.)
/// * **Aggregate secrets are read-merge-write, and that is yours to get right.** An
///   item whose value is a *collection* — an index, a list, a set, a count, a
///   signature over the set — must be merged into what the successor already holds,
///   never written over it. This seam makes that possible; it does not make it
///   automatic, and the crate cannot tell an aggregate from a standalone secret.
///
///   Both ways of getting it wrong are real, and they are mirror images. Skipping
///   the write hides entries: ghostkeys' `gk:index` under never-clobber leaves
///   recovered credentials in the store with nothing listing them. Overwriting
///   deletes them: Delta's `StoreKnownSites { sites }` replaces the entire list, so
///   an adapter that forwards a predecessor's `known_sites` straight into it
///   destroys every site the user added on the new version. Read the successor's
///   current value, merge, then write.
/// * **Marker fidelity.** Record `Done` only once the item writes are durable. The
///   crate calls [`flush_predecessor`](Self::flush_predecessor) before asking for
///   the `Done` marker, so a buffering writer has a place to fail honestly instead
///   of letting the marker outrun the data.
pub trait SuccessorSecretsIo {
    /// The app's successor-side error type.
    type Error;

    /// The recorded migration state for `query.predecessor`, if any.
    ///
    /// `Err` aborts this predecessor with
    /// [`PredecessorMigration::WriterUnavailable`] and stops the walk under every
    /// policy: without a marker read the crate cannot tell migrated from
    /// not-migrated, and guessing either way risks a double import or a silent skip.
    fn migration_marker(
        &mut self,
        query: &MarkerQuery<'_>,
    ) -> impl Future<Output = Result<Option<MigrationMarker>, Self::Error>>;

    /// Persist `marker` for `predecessor`.
    ///
    /// Called twice per imported predecessor: [`MigrationMarker::InProgress`]
    /// before the first item, [`MigrationMarker::Done`] only after every item and
    /// the flush succeeded.
    ///
    /// **Markers must be durable when this returns, not batched.**
    /// [`flush_predecessor`](Self::flush_predecessor) is specified as flushing what
    /// the *items* were buffered into, and the crate never flushes a marker on its
    /// own path. A writer that routes markers through the same batch as its items
    /// therefore breaks in two ways:
    ///
    /// * The [`InProgress`](MigrationMarker::InProgress) marker is lost exactly when
    ///   that batch's flush fails, which silently drops the **sticky-data flag**. The
    ///   retry then finds no in-progress marker and computes `saw_data` from that
    ///   run's items alone, so a predecessor that answers empty on the retry can seal
    ///   `Done { had_data: false }`. Under
    ///   [`SecretSelectionPolicy::NewestSnapshotWins`] that misclassifies a
    ///   data-bearing generation as `NoData` and falls through to older generations,
    ///   resurrecting keys it had deleted — the exact failure the sticky-data rule
    ///   exists to prevent.
    /// * The [`Done`](MigrationMarker::Done) marker is recorded *after* the only
    ///   flush the crate performs, so a batched one is never flushed by the crate at
    ///   all. It would need the app's next unrelated flush to land, and until then
    ///   the predecessor is re-walked and re-imported on every run.
    ///
    /// Persist the marker synchronously, on its own path if necessary.
    fn record_marker(
        &mut self,
        predecessor: &DelegateKey,
        marker: MigrationMarker,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Apply one recovered secret through the successor's own import path.
    ///
    /// This is the seam the whole 0.5.0 change exists for. Do here exactly what the
    /// app does when it imports that item natively — including the parts a raw pair
    /// copy cannot know about: merging a derived index, recording permission grants,
    /// verifying a certificate chain, deriving a fingerprint, refusing to copy a
    /// predecessor's grants verbatim.
    ///
    /// Must be idempotent (see the trait contract).
    fn write_secret(
        &mut self,
        item: &RecoveredSecret<'_>,
    ) -> impl Future<Output = ItemWrite<Self::Error>>;

    /// Flush anything this predecessor's items were buffered into, before the
    /// completion marker is recorded.
    ///
    /// The default is a no-op, which is right for a writer that persists each item
    /// as it goes. A writer that batches (the shape forced on a UI-side adopter
    /// whose only route to the successor store is an awaited round-trip) MUST flush
    /// here and report failure, or the `Done` marker would outrun the data and seal
    /// a migration that never landed.
    fn flush_predecessor(
        &mut self,
        predecessor: &DelegateKey,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        let _ = predecessor;
        core::future::ready(Ok(()))
    }
}

/// Acknowledgement that an app's secrets have **no cross-entry invariants**,
/// required to use the raw-pair [`SecretStoreIo`] writer.
///
/// Deliberately not `Default` and `#[must_use]`, with a single loudly-named
/// constructor, because getting this wrong is silent: if any stored entry is
/// derived from the others — an index of which items exist, a permission grant, a
/// count, a signature over the set — a raw pair copy leaves the successor
/// internally inconsistent with **no error at all** (freenet/ghostkeys#32 D3), and
/// no [`SecretSelectionPolicy`] setting changes that. Implement
/// [`SuccessorSecretsIo`] over the app's own import path instead.
#[must_use = "constructing a NoCrossEntryInvariantsAck certifies that NO stored secret is \
              derived from the others (no index, no permission grant, no count, no signature \
              over the set); if one is, a raw pair copy corrupts the successor silently — \
              implement SuccessorSecretsIo over your own import path instead"]
#[derive(Debug)]
pub struct NoCrossEntryInvariantsAck(());

impl NoCrossEntryInvariantsAck {
    /// Construct the acknowledgement. The name is intentionally unwieldy: a raw
    /// pair copy is only safe when every secret stands alone.
    pub fn i_certify_these_secrets_have_no_cross_entry_invariants() -> Self {
        Self(())
    }
}

/// The raw-pair, never-clobber [`SuccessorSecretsIo`] over a plain
/// [`SecretStore`] — the pre-0.5.0 behaviour, kept for apps whose secrets stand
/// alone, and the natural writer for a delegate-side import (`DelegateCtx`).
///
/// It writes each recovered pair verbatim under its own key, declining any key the
/// successor already holds, and persists markers in the crate's public, versioned
/// format ([`crate::predecessor_done_marker`]) — byte-for-byte what a node-side
/// copy-forward writes and reads.
///
/// **Only sound when no stored entry is derived from the others** — hence the
/// [`NoCrossEntryInvariantsAck`] in the constructor. See the module docs.
///
/// # Unbounded-retry limit
///
/// [`SecretStore::set_secret`] reports only `bool`, so this writer cannot tell a
/// transient storage refusal from a permanent one and reports **every** refusal as
/// [`RetryAdvice::Retryable`] — it can never produce
/// [`ImportTally::rejected`](ImportTally::rejected). Against a store that refuses
/// some key deterministically (a size cap, a reserved prefix, a quota), the report's
/// [`retry_may_help`](DelegateMigrationReport::retry_may_help) stays `true` forever,
/// so a caller that retries while it is `true` never terminates. **Bound the retry
/// count** and surface the residue; the `rejected`-is-not-retryable path only saves
/// a caller from that loop for a writer that can actually say `Permanent`. A writer
/// implementing [`SuccessorSecretsIo`] over the app's own import path can, via
/// [`ItemWrite::permanent`] — but note its shelf-life contract on
/// [`RetryAdvice::Permanent`] before reaching for it.
#[derive(Debug)]
pub struct SecretStoreIo<'a, S: ?Sized> {
    store: &'a mut S,
}

impl<'a, S: SecretStore + ?Sized> SecretStoreIo<'a, S> {
    /// Wrap `store` as a raw-pair writer, certifying that its secrets have no
    /// cross-entry invariants.
    pub fn new(store: &'a mut S, ack: NoCrossEntryInvariantsAck) -> Self {
        let NoCrossEntryInvariantsAck(()) = ack;
        Self { store }
    }
}

/// A [`SecretStoreIo`] write rejected by the underlying [`SecretStore`]
/// (`set_secret` returned `false`), carrying the key it could not write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretStoreWriteFailed {
    /// The secret key whose write the store refused.
    pub key: Vec<u8>,
}

impl<S: SecretStore + ?Sized> SuccessorSecretsIo for SecretStoreIo<'_, S> {
    type Error = SecretStoreWriteFailed;

    fn migration_marker(
        &mut self,
        query: &MarkerQuery<'_>,
    ) -> impl Future<Output = Result<Option<MigrationMarker>, Self::Error>> {
        let done = pred_done_marker(query.predecessor);
        let marker = if let Some(value) = self.store.get_secret(&done) {
            // An unrecognized value is treated conservatively as data-bearing.
            Some(MigrationMarker::Done {
                had_data: value != PRED_DONE_MARKER_VALUE_EMPTY,
            })
        } else if match query.legacy_bridge {
            // Defensive P1#3 bridge: honor a store a prior generation-keyed
            // migration already wrote to.
            LegacyBridge::AtOrAboveGeneration => {
                legacy_generation_migrated(self.store, query.generation)
            }
            LegacyBridge::ExactGenerationOnly => {
                legacy_generation_migrated_exact(self.store, query.generation)
            }
        } {
            Some(MigrationMarker::Done { had_data: true })
        } else {
            self.store
                .get_secret(&pred_wip_marker(query.predecessor))
                .map(|value| MigrationMarker::InProgress {
                    saw_data: value != PRED_DONE_MARKER_VALUE_EMPTY,
                })
        };
        core::future::ready(Ok(marker))
    }

    fn record_marker(
        &mut self,
        predecessor: &DelegateKey,
        marker: MigrationMarker,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        let (key, data) = match marker {
            MigrationMarker::InProgress { saw_data } => (pred_wip_marker(predecessor), saw_data),
            MigrationMarker::Done { had_data } => (pred_done_marker(predecessor), had_data),
        };
        let value = if data {
            PRED_DONE_MARKER_VALUE_DATA
        } else {
            PRED_DONE_MARKER_VALUE_EMPTY
        };
        let ok = self.store.set_secret(&key, value);
        core::future::ready(if ok {
            Ok(())
        } else {
            Err(SecretStoreWriteFailed { key })
        })
    }

    fn write_secret(
        &mut self,
        item: &RecoveredSecret<'_>,
    ) -> impl Future<Output = ItemWrite<Self::Error>> {
        let outcome = if self.store.has_secret(item.key) {
            // Successor already has data under this key — do not clobber it.
            ItemWrite::AlreadyAuthoritative
        } else if self.store.set_secret(item.key, item.value) {
            ItemWrite::Written
        } else {
            // `SecretStore::set_secret` reports only a bool, so a refusal that will
            // never succeed is indistinguishable from one that will. This writer
            // therefore NEVER emits `RetryAdvice::Permanent` — see the
            // "unbounded-retry limit" section on `SecretStoreIo`. Reporting a
            // deterministic refusal as `Permanent` would be worse: `Permanent` does
            // not withhold the key, so an older generation could shadow it.
            ItemWrite::retryable(SecretStoreWriteFailed {
                key: item.key.to_vec(),
            })
        };
        core::future::ready(outcome)
    }
}

/// Per-predecessor write counts. Every item the crate offered the successor's
/// writer lands in exactly one bucket, so `written + skipped + failed + rejected +
/// withheld` is the number of real secrets the predecessor exported (reserved
/// bookkeeping markers are filtered before counting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImportTally {
    /// Items the app's writer applied **and whose durability
    /// [`SuccessorSecretsIo::flush_predecessor`] confirmed**.
    ///
    /// A buffering writer legitimately answers [`ItemWrite::Written`] for an item
    /// it has only buffered, so this count is not final until the flush returns.
    /// If the flush fails, every such item is re-counted in [`failed`](Self::failed)
    /// instead, so this field never claims data that a discarded buffer took with
    /// it.
    ///
    /// **It under-reports in the other direction, and can read zero for a migration
    /// that fully succeeded.** The reclassification cannot tell a buffering writer
    /// (whose items really are gone) from a **write-through** writer whose
    /// [`SuccessorSecretsIo::flush_predecessor`] failed at something *after* the
    /// items were already durable: committing an index, closing a transaction,
    /// fsyncing a manifest. For that writer the items are counted `failed` even
    /// though they landed, and the retry that succeeds finds them already present
    /// and counts them [`skipped`](Self::skipped). `written` is then `0` on both
    /// runs, so [`DelegateMigrationReport::imported_total`] reads **0 across the
    /// whole migration**. [`SecretStoreIo`] is exactly this shape, so it is the
    /// default writer's behaviour, not an exotic one.
    ///
    /// The direction is the safe one (it never overstates), but do **not** render
    /// this to a user as an unqualified "recovered N secrets": a successful
    /// recovery can report zero. Gate the message on
    /// [`DelegateMigrationReport::is_complete`], and read [`offered`](Self::offered)
    /// for how many items the predecessor actually had. Tracked in
    /// freenet/freenet-migrate#16.
    pub written: usize,
    /// Items the app deliberately did not apply ([`ItemWrite::AlreadyAuthoritative`])
    /// — the successor's own value stands, or the item is not the app's to copy
    /// verbatim. Not a failure.
    pub skipped: usize,
    /// Items whose write failed **retryably** ([`RetryAdvice::Retryable`]), plus —
    /// when [`SuccessorSecretsIo::flush_predecessor`] fails — every item that
    /// predecessor's writer had accepted, since a buffering writer's failed flush
    /// discards them.
    pub failed: usize,
    /// Items the successor's import path **permanently refused**
    /// ([`RetryAdvice::Permanent`]). Re-running will not change this.
    pub rejected: usize,
    /// Items never offered to the writer because a **newer** predecessor left the
    /// same key unresolved: it failed retryably there, or that predecessor's flush
    /// failed after resolving it (so the successor-side outcome — written, or
    /// "already authoritative" — went down with the discarded buffer). Importing
    /// an older generation's value into that hole would shadow the newer one under
    /// never-clobber. A retry re-attempts the newer predecessor first (see the
    /// module docs).
    pub withheld: usize,
}

impl ImportTally {
    /// Total items offered by this predecessor (every bucket).
    pub fn offered(&self) -> usize {
        self.written + self.skipped + self.failed + self.rejected + self.withheld
    }

    /// Whether every offered **item** resolved: nothing failed, was rejected, or
    /// was withheld. A clean tally is necessary for a completion marker.
    ///
    /// **It is not sufficient, and a clean tally does not mean the predecessor
    /// completed.** Completion also requires that no *stage* failed, and a stage
    /// failure can leave every item clean. If
    /// [`SuccessorSecretsIo::flush_predecessor`] fails for a predecessor whose items
    /// were all [`ItemWrite::AlreadyAuthoritative`], nothing was written, so nothing
    /// is re-counted: the tally is `{ skipped: n }`, this returns `true`, and
    /// [`retry_may_help`](Self::retry_may_help) returns `false`, while the
    /// predecessor is still reported
    /// [`Incomplete`](PredecessorMigration::Incomplete) and did not earn its marker.
    /// The same holds when the `Done` marker write itself fails.
    ///
    /// Judge completion from [`DelegateMigrationReport::is_complete`] and
    /// retryability from [`DelegateMigrationReport::retry_may_help`], both of which
    /// fold in the stage failure. Never from this alone.
    pub fn is_clean(&self) -> bool {
        self.failed == 0 && self.rejected == 0 && self.withheld == 0
    }

    /// Whether re-running could make progress here: something failed retryably or
    /// was withheld pending a newer predecessor's retry. A tally whose only
    /// blemish is [`rejected`](Self::rejected) is **not** retryable — the successor
    /// refuses those items and always will.
    ///
    /// **This is per-item, not per-predecessor.** A predecessor whose items were all
    /// clean but whose flush or completion marker failed has a tally that answers
    /// `false` here while a retry genuinely would help (see
    /// [`is_clean`](Self::is_clean)).
    /// [`DelegateMigrationReport::retry_may_help`] folds the stage failure in and is
    /// the one to drive a retry loop from.
    pub fn retry_may_help(&self) -> bool {
        self.failed > 0 || self.withheld > 0
    }
}

/// Where a successor-side failure happened, for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriterStage {
    /// [`SuccessorSecretsIo::migration_marker`].
    ReadMarker,
    /// [`SuccessorSecretsIo::record_marker`] for [`MigrationMarker::InProgress`].
    BeginMarker,
    /// [`SuccessorSecretsIo::write_secret`] (the first failing item; the counts are
    /// in the [`ImportTally`]).
    Item,
    /// [`SuccessorSecretsIo::flush_predecessor`].
    Flush,
    /// [`SuccessorSecretsIo::record_marker`] for [`MigrationMarker::Done`].
    CompleteMarker,
}

/// The first successor-side failure of a predecessor's import: where it happened
/// and what the app reported. The error is stringified because the report is
/// metadata-only (see [`DelegateMigrationReport`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterFailure {
    /// Which step failed.
    pub stage: WriterStage,
    /// The app's error, stringified.
    pub error: String,
}

/// What happened for one predecessor. `key`/`generation` come from the
/// build-time-validated lineage entry (never re-derived).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredecessorMigration {
    /// The predecessor executed and every recovered secret was applied by the
    /// successor's writer (first migration). The completion marker is recorded.
    Imported {
        /// The predecessor delegate key that was migrated from.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
        /// Per-item counts.
        tally: ImportTally,
    },
    /// The predecessor executed but had no secrets to migrate.
    NoData {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
    },
    /// A completed migration from this predecessor was already recorded (its
    /// marker is `Done`); nothing was re-imported. Also the shape of a re-run.
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
    /// The predecessor was reached and its items were offered, but at least one did
    /// not land: an item failed or was permanently rejected, an item was withheld
    /// pending a newer predecessor's retry, the flush failed, or the completion
    /// marker itself could not be recorded. **The completion marker is withheld**, so
    /// a retry re-runs this predecessor. A failed write is never counted as written.
    ///
    /// `tally` says what was written and what was not, and `failure` carries the
    /// first successor-side failure and where it happened. For whether retrying can
    /// change anything, read [`DelegateMigrationReport::retry_may_help`] and not
    /// [`ImportTally::retry_may_help`]: the tally is per-item, so a row that failed
    /// only at the flush or completion-marker stage has a clean, non-retryable-looking
    /// tally (see [`ImportTally::is_clean`]) while the report correctly says a retry
    /// may help.
    Incomplete {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
        /// Per-item counts.
        tally: ImportTally,
        /// The first successor-side failure, if one occurred. `None` when the only
        /// reason for incompleteness is withheld items.
        failure: Option<WriterFailure>,
    },
    /// The successor's writer could not be used at all for this predecessor: its
    /// marker could not be read, or the in-progress marker could not be recorded.
    /// **Nothing was imported**, and the walk stops under every policy — with no
    /// marker bookkeeping the crate cannot tell migrated from not-migrated, and the
    /// successor side is evidently broken.
    WriterUnavailable {
        /// The predecessor delegate key.
        key: DelegateKey,
        /// The predecessor's lineage generation.
        generation: u32,
        /// Which step failed, and the app's stringified error.
        failure: WriterFailure,
    },
    /// The predecessor was **not imported** because a higher-priority predecessor
    /// decided the outcome: under [`SecretSelectionPolicy::NewestSnapshotWins`] a
    /// newer data-bearing predecessor supplied the authoritative snapshot, OR an
    /// earlier predecessor halted the walk (`Unresponsive` under
    /// `NewestSnapshotWins`, or `WriterUnavailable` under any policy). Whether this
    /// is a *clean* skip or a *retry-me* skip is told by
    /// [`DelegateMigrationReport::is_complete`].
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
            | PredecessorMigration::WriterUnavailable { key, .. }
            | PredecessorMigration::Superseded { key, .. } => key,
        }
    }

    /// The predecessor's lineage generation.
    pub fn generation(&self) -> u32 {
        match self {
            PredecessorMigration::Imported { generation, .. }
            | PredecessorMigration::NoData { generation, .. }
            | PredecessorMigration::AlreadyMigrated { generation, .. }
            | PredecessorMigration::Unresponsive { generation, .. }
            | PredecessorMigration::Incomplete { generation, .. }
            | PredecessorMigration::WriterUnavailable { generation, .. }
            | PredecessorMigration::Superseded { generation, .. } => *generation,
        }
    }

    /// This predecessor's per-item counts, for the outcomes that have any.
    pub fn tally(&self) -> Option<&ImportTally> {
        match self {
            PredecessorMigration::Imported { tally, .. }
            | PredecessorMigration::Incomplete { tally, .. } => Some(tally),
            _ => None,
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
    ///
    /// **Under-reports after a recovered flush failure, sometimes all the way to
    /// zero for a migration that recovered everything** — see [`ImportTally::written`]
    /// for why, and freenet/freenet-migrate#16. Never present this as "recovered N
    /// secrets" without checking [`is_complete`](Self::is_complete) first.
    pub fn imported_total(&self) -> usize {
        self.predecessors
            .iter()
            .filter_map(|p| p.tally())
            .map(|t| t.written)
            .sum()
    }

    /// Total items the successor's import path **permanently refused**. These will
    /// not improve on a retry; surface them.
    pub fn rejected_total(&self) -> usize {
        self.predecessors
            .iter()
            .filter_map(|p| p.tally())
            .map(|t| t.rejected)
            .sum()
    }

    /// Total items whose write failed retryably.
    pub fn failed_total(&self) -> usize {
        self.predecessors
            .iter()
            .filter_map(|p| p.tally())
            .map(|t| t.failed)
            .sum()
    }

    /// Whether every predecessor fully resolved — none unresponsive, none left
    /// incomplete, and the successor's writer never went unavailable. When `true` it
    /// is safe to proceed as a clean migration (which, if every predecessor was
    /// `NoData`/absent, is an ordinary fresh install). When `false`, do NOT
    /// fresh-install: check [`any_unresponsive`](Self::any_unresponsive) and
    /// [`retry_may_help`](Self::retry_may_help).
    pub fn is_complete(&self) -> bool {
        !self.predecessors.iter().any(|p| {
            matches!(
                p,
                PredecessorMigration::Unresponsive { .. }
                    | PredecessorMigration::Incomplete { .. }
                    | PredecessorMigration::WriterUnavailable { .. }
            )
        })
    }

    /// Whether re-running the migration could make progress.
    ///
    /// `true` when something was unreachable, failed retryably, was withheld pending
    /// a newer predecessor's retry, or the successor's writer was unavailable.
    /// `false` on a complete report — and, importantly, also on an **incomplete**
    /// report whose only blemish is permanently-rejected items: those will be
    /// refused identically forever, so a retry loop would spin. Surface them to the
    /// user instead.
    ///
    /// **Bound your retries anyway.** This says a retry *could* help, not that it
    /// *will*: a deterministic successor-side fault reported as retryable keeps it
    /// `true` indefinitely, and [`SecretStoreIo`] cannot report anything else (see
    /// its "unbounded-retry limit"). Retry a few times, then surface what is left.
    pub fn retry_may_help(&self) -> bool {
        self.predecessors.iter().any(|p| match p {
            PredecessorMigration::Unresponsive { .. }
            | PredecessorMigration::WriterUnavailable { .. } => true,
            // An `Item`-stage failure is already classified by the tally
            // (`failed` = retryable, `rejected` = permanent), so it must NOT
            // independently imply retryability — otherwise a report whose only
            // blemish is a permanent rejection would spin a retry loop forever.
            // A flush / marker failure is a successor-side fault worth retrying.
            PredecessorMigration::Incomplete { tally, failure, .. } => {
                tally.retry_may_help()
                    || failure
                        .as_ref()
                        .is_some_and(|f| !matches!(f.stage, WriterStage::Item))
            }
            _ => false,
        })
    }
}

/// **The app-facing delegate-migration entry point** (plan G1.7 delegate half).
///
/// Carry each predecessor delegate's secrets forward into the successor, driving
/// the interim app-side round-trip through `io` and applying each recovered secret
/// through the successor's **own import path** (`successor`). Returns a
/// [`DelegateMigrationReport`]; the app decides what to do with each predecessor's
/// classification (crucially, it must not fresh-install if any predecessor is
/// `Unresponsive` — see [`DelegateMigrationReport::any_unresponsive`]).
///
/// * `successor` — the successor's write side ([`SuccessorSecretsIo`]): the app's
///   own import path plus marker bookkeeping. For secrets with no cross-entry
///   invariants, wrap a [`SecretStore`] in [`SecretStoreIo`]. **This is the seam
///   that keeps an app's invariants intact — see the module docs.**
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
/// data (see [`SecretSelectionPolicy`] and the module docs on termination).
///
/// # The report is the source of truth (no bare error)
///
/// This returns a [`DelegateMigrationReport`], not a `Result`: once the walk
/// begins it never fails outright. A `probe_executable`/`fetch_secrets` transport
/// error is captured as [`PredecessorMigration::Unresponsive`] with the error
/// stringified into its `error` field (a fetch timeout is a clean `Ok(false)` →
/// `Unresponsive { error: None }`); a successor-side item/flush/marker failure is
/// [`PredecessorMigration::Incomplete`] or
/// [`PredecessorMigration::WriterUnavailable`]. So an error mid-run never discards
/// the predecessors already migrated — the app inspects the report and retries.
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
pub async fn migrate_delegate_secrets<W, IO>(
    successor: &mut W,
    io: &mut IO,
    predecessors: &[DelegateLineageEntry],
    authorization: MigrationAuthorization,
    policy: SecretSelectionPolicy,
) -> DelegateMigrationReport
where
    W: SuccessorSecretsIo,
    W::Error: core::fmt::Debug,
    IO: PredecessorSecretsIo,
    IO::Error: core::fmt::Debug,
{
    let mut transport = AppSideRoundTrip { io };
    transport
        .migrate_from(successor, predecessors, &authorization, &policy)
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
pub async fn register_delegate_with_migration<W, IO>(
    successor: &mut W,
    io: &mut IO,
    predecessors: &[DelegateLineageEntry],
    authorization: MigrationAuthorization,
    policy: SecretSelectionPolicy,
) -> Result<DelegateMigrationReport, IO::Error>
where
    W: SuccessorSecretsIo,
    W::Error: core::fmt::Debug,
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
    Ok(migrate_delegate_secrets(successor, io, predecessors, authorization, policy).await)
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
/// A node-side copy is a raw namespace copy, so it carries the same cross-entry
/// invariant hazard the app-side writer seam exists to fix (module docs): an app
/// whose entries are interdependent should not adopt the node copy for those
/// entries until the wire can express "run the successor's import path".
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
pub(crate) trait SecretTransport<W: SuccessorSecretsIo> {
    /// Migrate the secrets of every predecessor in `predecessors` into `successor`,
    /// once each, under `policy`. Returns a per-predecessor report; never returns
    /// exported bytes and never a bare error (transport failures are captured as
    /// report rows).
    fn migrate_from(
        &mut self,
        successor: &mut W,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
        policy: &SecretSelectionPolicy,
    ) -> impl Future<Output = DelegateMigrationReport>;
}

/// The interim `SecretTransport`: app-side request/response round-trips through
/// the [`PredecessorSecretsIo`] adapter, applying each recovered secret through the
/// [`SuccessorSecretsIo`] writer. This supersedes v1's `ReRunOldWasm` stub — there
/// is no node re-run of old WASM here; the app ferries the export round-trip.
struct AppSideRoundTrip<'a, IO> {
    io: &'a mut IO,
}

impl<W, IO> SecretTransport<W> for AppSideRoundTrip<'_, IO>
where
    W: SuccessorSecretsIo,
    W::Error: core::fmt::Debug,
    IO: PredecessorSecretsIo,
    IO::Error: core::fmt::Debug,
{
    async fn migrate_from(
        &mut self,
        successor: &mut W,
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
        // predecessor is authoritative; under Union the newest generation's value
        // wins any shared key because the writer sees it first. Built from each
        // entry's STORED delegate_key (never re-derived — irregular rows' recorded
        // keys don't derive).
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
        // newer data-bearing snapshot was found (NewestSnapshotWins), the newer
        // state is unknown (Unresponsive under NewestSnapshotWins), or the
        // successor's writer is unusable (any policy).
        let mut terminated = false;
        // Keys a NEWER predecessor failed to write RETRYABLY. An older generation
        // must not supply them: under never-clobber its value would shadow the newer
        // one that is merely awaiting a retry. Permanently-rejected keys are NOT in
        // here — an older copy of such a key may be acceptable.
        //
        // A set, not a Vec: this is membership-tested once per offered item of every
        // older generation, and it can hold every key of several generations at the
        // enumeration cap. Scoped to this call only — see `UnionAck` and #15.
        let mut withheld_keys: BTreeSet<Vec<u8>> = BTreeSet::new();

        for (key, generation) in ordered {
            if terminated {
                results.push(PredecessorMigration::Superseded { key, generation });
                continue;
            }

            // Already migrated? The marker (with its data/empty flag), which for a
            // store-backed successor also covers the defensive legacy
            // generation-keyed bridge (P1#3). Skip the round-trips entirely.
            let query = MarkerQuery {
                predecessor: &key,
                generation,
                legacy_bridge: policy.legacy_bridge(),
            };
            let marker = match successor.migration_marker(&query).await {
                Ok(marker) => marker,
                Err(e) => {
                    results.push(PredecessorMigration::WriterUnavailable {
                        key,
                        generation,
                        failure: WriterFailure {
                            stage: WriterStage::ReadMarker,
                            error: format!("{e:?}"),
                        },
                    });
                    // No marker bookkeeping ⇒ cannot tell migrated from not.
                    terminated = true;
                    continue;
                }
            };
            match marker {
                Some(MigrationMarker::Done { had_data }) => {
                    if policy.data_bearing_is_authoritative(had_data) {
                        terminated = true;
                    }
                    results.push(PredecessorMigration::AlreadyMigrated { key, generation });
                    continue;
                }
                Some(MigrationMarker::InProgress { .. }) | None => {}
            }
            // A surviving in-progress marker means this is a re-attempt, and it
            // carries the earlier attempt's data/empty observation — the sticky-data
            // rule (keep data, upgrade empty→data), so a data-then-empty retry can
            // never seal the marker "empty" and make NewestSnapshotWins misclassify
            // NoData and fall through to older generations (resurrection).
            let (retry, prior_saw_data) = match marker {
                Some(MigrationMarker::InProgress { saw_data }) => (true, saw_data),
                _ => (false, false),
            };

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

            // The crate's own reserved namespace is never handed to the app's
            // writer and never counted: an import payload must not be able to write
            // (or forge) a migration marker.
            let items: Vec<&SecretPair> = secrets.iter().filter(|(k, _)| !is_marker(k)).collect();
            let saw_data = prior_saw_data || !items.is_empty();

            // Phase 1: record intent (and the data/empty flag) BEFORE any item.
            if let Err(e) = successor
                .record_marker(&key, MigrationMarker::InProgress { saw_data })
                .await
            {
                results.push(PredecessorMigration::WriterUnavailable {
                    key,
                    generation,
                    failure: WriterFailure {
                        stage: WriterStage::BeginMarker,
                        error: format!("{e:?}"),
                    },
                });
                terminated = true;
                continue;
            }

            let mut tally = ImportTally::default();
            let mut failure: Option<WriterFailure> = None;
            let mut newly_withheld: Vec<Vec<u8>> = Vec::new();
            // Keys this predecessor resolved without an error, whose durability the
            // flush has not confirmed yet. A buffering writer answers per item
            // optimistically and only finds out at flush time, so if the flush
            // fails these are exactly the keys whose successor-side state is a lie.
            let mut unflushed: Vec<Vec<u8>> = Vec::new();
            for (item_key, item_value) in items {
                if withheld_keys.contains(item_key) {
                    tally.withheld += 1;
                    continue;
                }
                let item = RecoveredSecret {
                    predecessor: &key,
                    generation,
                    key: item_key,
                    value: item_value,
                    retry,
                };
                // THE seam: the app's own import path applies the item, so every
                // invariant it maintains at import time (index membership,
                // permission grants, certificate verification, fingerprint
                // derivation) is preserved for free.
                match successor.write_secret(&item).await {
                    ItemWrite::Written => {
                        tally.written += 1;
                        unflushed.push(item_key.clone());
                    }
                    ItemWrite::AlreadyAuthoritative => {
                        tally.skipped += 1;
                        // "The successor's value is authoritative" can itself be
                        // unflushed buffer state — including a value THIS run wrote
                        // for an earlier duplicate key. If the flush discards it,
                        // the claim evaporates with it, so this key is as unproven
                        // as a written one.
                        unflushed.push(item_key.clone());
                    }
                    ItemWrite::Failed {
                        error,
                        retry: advice,
                    } => {
                        match advice {
                            RetryAdvice::Retryable => {
                                tally.failed += 1;
                                // An older generation must not shadow this key while
                                // the newer value is awaiting a retry.
                                newly_withheld.push(item_key.clone());
                            }
                            // Permanent: an older generation's copy may still be
                            // acceptable, so it is NOT withheld.
                            RetryAdvice::Permanent => tally.rejected += 1,
                        }
                        if failure.is_none() {
                            failure = Some(WriterFailure {
                                stage: WriterStage::Item,
                                error: format!("{error:?}"),
                            });
                        }
                    }
                }
            }
            withheld_keys.extend(newly_withheld);

            // Give a buffering writer its chance to fail honestly before the
            // completion marker claims the data landed.
            if let Err(e) = successor.flush_predecessor(&key).await {
                // A flush failure OUTRANKS an item failure for the reported
                // `failure`. Item failures are already fully described by the tally
                // (`failed` = retryable, `rejected` = permanent), but a stage
                // failure is not described anywhere else — and it is what
                // `retry_may_help` reads. Keeping the first-seen item failure here
                // would hide a retryable flush fault behind a permanent rejection
                // and tell the app not to bother retrying.
                if failure
                    .as_ref()
                    .is_none_or(|f| matches!(f.stage, WriterStage::Item))
                {
                    failure = Some(WriterFailure {
                        stage: WriterStage::Flush,
                        error: format!("{e:?}"),
                    });
                }

                // The flush is the DURABILITY BOUNDARY, and this is the arm that
                // makes the withholding rule sound for the writer shape
                // `flush_predecessor` exists for. A buffering writer answers
                // `Written` optimistically and loses the whole batch here, so
                // without this the run would have withheld NOTHING: an older
                // generation would then be offered the same key, write its value
                // into the hole, flush clean, earn its `Done` marker — and on the
                // next run the newer value would be declined under never-clobber
                // and the older generation would shadow it permanently, with the
                // report reading `is_complete()`.
                //
                // So a failed flush un-does the optimism two ways:
                //   * every optimistically-`Written` item is re-counted as a
                //     retryable failure, so `imported_total()` never reports data
                //     that a discarded buffer took with it; and
                //   * every key this predecessor resolved (written OR
                //     already-authoritative) is withheld from older generations for
                //     the rest of the run.
                //
                // Withholding rather than halting the walk is deliberate: halting
                // is the pre-0.5.0 behaviour this release removed, where one
                // storage fault on the newest generation abandoned every older one
                // even under `UnionAllGenerations`. Withholding keeps the walk and
                // protects only the affected keys.
                tally.failed += tally.written;
                tally.written = 0;
                withheld_keys.extend(unflushed);
            }

            // Phase 2: upgrade to the completion marker ONLY if everything landed.
            let mut complete = tally.is_clean() && failure.is_none();
            if complete {
                if let Err(e) = successor
                    .record_marker(&key, MigrationMarker::Done { had_data: saw_data })
                    .await
                {
                    failure = Some(WriterFailure {
                        stage: WriterStage::CompleteMarker,
                        error: format!("{e:?}"),
                    });
                    complete = false;
                }
            }

            let migration = if !complete {
                PredecessorMigration::Incomplete {
                    key,
                    generation,
                    tally,
                    failure,
                }
            } else if saw_data {
                PredecessorMigration::Imported {
                    key,
                    generation,
                    tally,
                }
            } else {
                PredecessorMigration::NoData { key, generation }
            };

            // Termination is a POLICY question, not a failure question (module
            // docs): a data-bearing predecessor is the authoritative snapshot under
            // NewestSnapshotWins whether or not every write of it landed, and Union
            // always walks on. A failed write costs the completion marker (so the
            // retry re-runs) and withholds the affected keys from older
            // generations — it does not abandon those generations.
            terminated = policy.data_bearing_is_authoritative(saw_data);
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
    use crate::delegate::{
        done_marker, import_predecessor_secrets_once, pred_done_marker, pred_wip_marker,
        predecessor_done_marker, PredecessorImportOutcome, PRED_DONE_MARKER_KEY_PREFIX,
    };
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
        /// The generations `register_successor` was handed, in the order it got
        /// them. The ordering is a documented guarantee of
        /// `RegisterAndMigrateIo::register_successor`, so it needs an assertion of
        /// its own — the internal walk re-sorts independently, so nothing else here
        /// would notice if the guarantee were dropped.
        registered_generations: Vec<u32>,
        /// force a transport error from probe_executable for these keys.
        error_on_probe: HashSet<Vec<u8>>,
        /// force a transport error from fetch_secrets for these keys: the
        /// predecessor answered the cheap preflight and then went silent on the
        /// export. Before freenet/freenet-migrate#19 this double could not
        /// express that at all — it only failed at the PROBE — so the one
        /// scenario an adapter is most likely to get wrong (`Ok(vec![])` for a
        /// silent export) had no test that could see it.
        error_on_fetch: HashSet<Vec<u8>>,
        /// force `register_successor` to fail, for the wrapper's error path.
        fail_register: bool,
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
        /// Answers the preflight, then never answers the export.
        fn silent_export(mut self, key: &DelegateKey) -> Self {
            self.executable.insert(key.bytes().to_vec(), true);
            self.error_on_fetch.insert(key.bytes().to_vec());
            self
        }
        fn failing_registration(mut self) -> Self {
            self.fail_register = true;
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
            if self.error_on_fetch.contains(&k) {
                return Err(IoAbort);
            }
            Ok(self.secrets.get(&k).cloned().unwrap_or_default())
        }
    }

    impl RegisterAndMigrateIo for MockIo {
        async fn register_successor(
            &mut self,
            predecessors: &[DelegateLineageEntry],
            _authorization: &MigrationAuthorization,
            _policy: &SecretSelectionPolicy,
        ) -> Result<(), IoAbort> {
            self.registered += 1;
            self.registered_generations
                .extend(predecessors.iter().map(|e| e.generation));
            if self.fail_register {
                return Err(IoAbort);
            }
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

    /// The raw-pair successor writer over the in-memory store — the pre-0.5.0
    /// behaviour, and the writer an app with no cross-entry invariants uses.
    fn store_io(store: &mut MemStore) -> SecretStoreIo<'_, MemStore> {
        SecretStoreIo::new(
            store,
            NoCrossEntryInvariantsAck::i_certify_these_secrets_have_no_cross_entry_invariants(),
        )
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
            &mut store_io(&mut store),
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert_eq!(report.predecessors.len(), 1);
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported {
                tally: ImportTally {
                    written: 2,
                    skipped: 0,
                    ..
                },
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
            &mut store_io(&mut store),
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

    /// freenet/freenet-migrate#19, delegate half: a predecessor that answers the
    /// cheap preflight and then goes silent on the export must NOT be sealed.
    ///
    /// The preflight makes `Ok(vec![])` from `fetch_secrets` trustworthy, which
    /// is exactly why an adapter is tempted to answer a timed-out export with
    /// it. The contrast with
    /// `executable_predecessor_with_no_data_is_nodata_not_unresponsive` above is
    /// the whole point: same preflight, same empty result, opposite meaning —
    /// there the predecessor ANSWERED "nothing", here it never answered. Only
    /// the first earns a completion marker.
    #[test]
    fn a_silent_export_is_unresponsive_and_earns_no_done_marker() {
        let e = entry(1, 1);
        let k = key_of(&e);
        let mut store = MemStore::default();
        let mut io = MockIo::default().silent_export(&k);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::Unresponsive { error: Some(_), .. }
            ),
            "a silent export must not read as NoData, got {:?}",
            report.predecessors[0]
        );
        assert!(report.any_unresponsive());
        assert!(
            !report.is_complete(),
            "an unestablished export must not report a complete migration"
        );
        // THE seal check: no marker of any kind, so the next run re-walks this
        // predecessor instead of skipping it forever as already-migrated.
        assert!(
            store.get_secret(&pred_done_marker(&k)).is_none(),
            "a predecessor that never answered must not be sealed Done"
        );
        assert!(
            store.get_secret(&pred_wip_marker(&k)).is_none(),
            "the in-progress marker is only recorded once an export was received"
        );
    }

    #[test]
    fn unexecutable_predecessor_is_unresponsive_never_silent_fresh_install() {
        // freenet/river#204: a broken/absent old delegate must surface, not read
        // as "no data → fresh install".
        let e = entry(4, 4);
        let mut store = MemStore::default();
        let mut io = MockIo::default().dead(&key_of(&e));
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
                &mut store_io(&mut store),
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        assert!(matches!(
            first.predecessors[0],
            PredecessorMigration::Imported {
                tally: ImportTally { written: 1, .. },
                ..
            }
        ));
        assert_eq!(store.get_secret(b"k").unwrap(), b"v");
        let n_after_first = store.list_secrets(b"").len();

        // Re-run (fresh io that would re-import if asked): must be a no-op.
        let second = {
            let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"RESURRECT")]);
            block_on(migrate_delegate_secrets(
                &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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

    /// The fetch-level sibling of the test above, and the delegate half's
    /// counterpart to the contract driver's
    /// `silence_on_the_newest_generation_does_not_adopt_an_older_one`.
    ///
    /// The test above kills the newest generation at the *preflight*
    /// (`dead`), which is the easy case: the walk never even fetches. Here the
    /// newest generation **answers the preflight and then goes silent on the
    /// export** — ghostkeys' `present_but_silent`, and the case an adapter is
    /// most likely to get wrong. It must halt exactly the same way: the older
    /// generation's real data must not be adopted past a newer state we could
    /// not read.
    ///
    /// Without a second generation this is unfalsifiable — a single-entry
    /// lineage can only assert "no marker was written" and never exercises
    /// fall-through at all.
    #[test]
    fn newest_snapshot_wins_halts_on_a_silent_export_no_fall_through() {
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .silent_export(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"data", b"v")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::Unresponsive { error: Some(_), .. }
            ),
            "a silent export must be Unresponsive, got {:?}",
            report.predecessors[0]
        );
        // THE fall-through check, asserted before the bookkeeping ones so a
        // regression names the data loss rather than a classification detail.
        assert!(
            store.get_secret(b"data").is_none(),
            "must not adopt an older snapshot past a newer one whose export we could not read"
        );
        assert!(
            !io.fetched.contains(key_of(&old).bytes()),
            "the older generation must not even be enumerated"
        );
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(report.any_unresponsive());
        assert!(!report.is_complete());
        // And nothing is sealed, so the next run re-walks both.
        assert!(store.get_secret(&pred_done_marker(&key_of(&new))).is_none());
        assert!(store.get_secret(&pred_wip_marker(&key_of(&new))).is_none());
    }

    /// The contrast that makes the halt above non-vacuous: under Union the
    /// SAME script does fall through and import the older generation's data.
    /// So the halt is the policy deciding, not the walk being incapable of
    /// reaching an older generation after a silent export.
    #[test]
    fn union_recovers_older_data_past_a_silent_export() {
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .silent_export(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"data", b"v")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[old, new],
            ack(),
            union(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Unresponsive { error: Some(_), .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(
            store.get_secret(b"data").unwrap(),
            b"v",
            "Union wants every generation, so the silent newest does not stop it"
        );
        assert!(
            report.any_unresponsive(),
            "the unreadable newest generation is still reported"
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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

    // ---- a partial write does not abandon older generations (0.5.0) ---------

    #[test]
    fn incomplete_data_bearing_newer_still_supersedes_older_under_newest_snapshot_wins() {
        // Under NewestSnapshotWins a DATA-BEARING predecessor is the authoritative
        // snapshot whether or not every write of it landed, so the older generation
        // is Superseded exactly as it would be for a clean Imported. Unchanged from
        // 0.4.0 — termination here comes from the POLICY, not from the failure.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        store.fail_writes_to(b"x"); // the newer generation's write fails
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"x", b"NEW")])
            .executable_with(&key_of(&old), &[(b"x", b"OLD"), (b"only_old", b"o")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::Incomplete {
                    tally: ImportTally { failed: 1, .. },
                    ..
                }
            ),
            "newer predecessor is Incomplete with one retryable failure"
        );
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(!report.is_complete());
        assert!(report.retry_may_help());
        assert!(store.get_secret(b"x").is_none());
        assert!(
            store.get_secret(b"only_old").is_none(),
            "NewestSnapshotWins does not import past an authoritative data-bearing newer"
        );
    }

    #[test]
    fn incomplete_newer_does_not_abandon_older_generations_under_union() {
        // THE 0.5.0 correction. 0.4.0 set `terminated = true` on Incomplete under
        // BOTH policies, so one failed write on one key of the newest predecessor
        // marked every older generation Superseded and recovered nothing from them —
        // even under Union, whose entire purpose is to walk every generation. That is
        // silent data loss of the same class as the raw-pair index bug.
        //
        // Union now walks on. The one thing the old halt genuinely bought is kept by
        // a narrower mechanism: the key whose write failed RETRYABLY is WITHHELD from
        // the older generation, so an older value cannot shadow the newer one that is
        // merely awaiting a retry.
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut store = MemStore::default();
        store.fail_writes_to(b"x"); // the newer generation's write fails
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"x", b"NEW")])
            .executable_with(&key_of(&old), &[(b"x", b"OLD"), (b"only_old", b"o")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[old, new],
            ack(),
            union(),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::Incomplete {
                    tally: ImportTally { failed: 1, .. },
                    ..
                }
            ),
            "newer predecessor is Incomplete"
        );
        // The older generation is walked — NOT Superseded.
        let older = &report.predecessors[1];
        assert!(
            matches!(
                older,
                PredecessorMigration::Incomplete {
                    tally: ImportTally {
                        written: 1,
                        withheld: 1,
                        failed: 0,
                        rejected: 0,
                        ..
                    },
                    failure: None,
                    ..
                }
            ),
            "older predecessor is walked, imports its own key, and has `x` withheld; got {older:?}"
        );
        assert_eq!(
            store.get_secret(b"only_old").unwrap(),
            b"o",
            "0.4.0 lost this entirely: one failed write abandoned the whole older generation"
        );
        assert!(
            store.get_secret(b"x").is_none(),
            "the retryably-failed key must NOT be back-filled from the older generation"
        );
        // Withheld items leave the older predecessor unsealed, so the retry re-walks
        // it once the newer key lands.
        assert!(!report.is_complete());
        assert!(report.retry_may_help());
        assert!(
            !store.has_secret(&pred_done_marker(&key_of(&old))),
            "a predecessor with withheld items must not be sealed"
        );
    }

    #[test]
    fn a_permanently_rejected_key_is_not_withheld_from_older_generations() {
        // Withholding exists so an older value cannot shadow a newer one awaiting a
        // RETRY. A permanently-rejected item is not awaiting anything — the successor
        // refuses that exact item and always will — so an older generation's copy of
        // the same key MUST still be offered; it may well be acceptable.
        let old = entry(1, 1);
        let new = entry(2, 2);
        // The newer copy of the certificate does not verify; the older one does.
        let mut writer = ScriptedWriter::default().permanently_reject_value(b"NEW-BROKEN");
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"cert", b"NEW-BROKEN")])
            .executable_with(&key_of(&old), &[(b"cert", b"OLD-GOOD")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[old, new],
            ack(),
            union(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Incomplete {
                tally: ImportTally {
                    rejected: 1,
                    withheld: 0,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            report.rejected_total(),
            1,
            "the newer copy is permanently refused"
        );
        assert_eq!(
            writer
                .offered
                .iter()
                .filter(|(k, _)| k.as_slice() == b"cert")
                .count(),
            2,
            "the older generation's copy of the same key must still be offered: {:?}",
            writer.offered
        );
        assert_eq!(
            writer.applied.get(b"cert".as_slice()).map(Vec::as_slice),
            Some(b"OLD-GOOD".as_slice()),
            "and the older, acceptable copy is what lands"
        );
    }

    #[test]
    fn a_report_whose_only_blemish_is_permanent_rejection_is_not_retryable() {
        // The distinction partial-failure reporting exists for: incomplete, but
        // retrying cannot change anything, so an app must surface it rather than
        // spin a retry loop.
        let e = entry(1, 1);
        let mut writer = ScriptedWriter::default().permanently_reject(b"bad");
        let mut io =
            MockIo::default().executable_with(&key_of(&e), &[(b"good", b"1"), (b"bad", b"2")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::Incomplete {
                    tally: ImportTally {
                        written: 1,
                        rejected: 1,
                        failed: 0,
                        withheld: 0,
                        ..
                    },
                    failure: Some(WriterFailure {
                        stage: WriterStage::Item,
                        ..
                    }),
                    ..
                }
            ),
            "got {:?}",
            report.predecessors[0]
        );
        assert!(!report.is_complete(), "one item never landed");
        assert!(
            !report.retry_may_help(),
            "a permanent rejection will be refused identically forever"
        );
        assert_eq!(report.rejected_total(), 1);
        assert_eq!(report.failed_total(), 0);
    }

    #[test]
    fn data_then_empty_retry_keeps_the_data_flag_and_still_supersedes_older() {
        // The OTHER sticky-data direction, and the dangerous one. B (newest) is
        // data-bearing on attempt 1 but a write fails, so it stays unsealed. On the
        // retry B answers EMPTY. If the flag were recomputed from this attempt alone,
        // B would seal as NoData, NewestSnapshotWins would fall through, and the
        // older A's keys — which B's generation may have deliberately deleted —
        // would be resurrected. The in-progress marker's flag is what prevents it.
        let a = entry(1, 1);
        let b = entry(2, 2);
        let mut store = MemStore::default();
        store.fail_writes_to(b"x");

        // Run 1: B has data, its write fails → Incomplete, in-progress flag = data.
        let mut io1 = MockIo::default()
            .executable_with(&key_of(&b), &[(b"x", b"NEW")])
            .executable_with(&key_of(&a), &[(b"a_only", b"va")]);
        let r1 = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io1,
            &[a, b],
            ack(),
            newest(),
        ));
        assert!(matches!(
            r1.predecessors[0],
            PredecessorMigration::Incomplete { .. }
        ));
        assert_eq!(
            store.get_secret(&pred_wip_marker(&key_of(&b))).unwrap(),
            PRED_DONE_MARKER_VALUE_DATA,
            "the in-progress marker records that this attempt saw data"
        );

        // Run 2: B now answers EMPTY. The flag is sticky, so B is still the
        // authoritative data-bearing snapshot and A is never imported.
        store.stop_failing();
        let mut io2 = MockIo::default()
            .executable_with(&key_of(&b), &[])
            .executable_with(&key_of(&a), &[(b"a_only", b"va")]);
        let r2 = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io2,
            &[a, b],
            ack(),
            newest(),
        ));
        assert!(
            matches!(r2.predecessors[0], PredecessorMigration::Imported { .. }),
            "a data-then-empty retry stays Imported, never NoData; got {:?}",
            r2.predecessors[0]
        );
        assert_eq!(
            store
                .get_secret(&predecessor_done_marker(&key_of(&b), true).0)
                .unwrap(),
            PRED_DONE_MARKER_VALUE_DATA,
            "the sealed marker must keep the data flag"
        );
        assert!(
            matches!(r2.predecessors[1], PredecessorMigration::Superseded { .. }),
            "the older A must stay Superseded; got {:?}",
            r2.predecessors[1]
        );
        assert!(
            store.get_secret(b"a_only").is_none(),
            "a data-then-empty retry must not resurrect the older generation's keys"
        );
    }

    #[test]
    fn empty_incomplete_then_data_retry_seals_the_marker_data_bearing() {
        // P1 sticky-data: the newer predecessor B is EMPTY on attempt 1 and its DONE
        // marker write fails (Incomplete); on the retry B brings DATA. The marker
        // must seal DATA-bearing, so B is authoritative under NewestSnapshotWins from
        // then on. If the flag were sealed "empty", a later re-run would misclassify
        // B as NoData and fall through to older generations (resurrection).
        //
        // 0.5.0 note: on attempt 1 the older A IS imported, because an EMPTY newer
        // predecessor falls through under NewestSnapshotWins — exactly as it does for
        // a clean NoData (see
        // `newest_snapshot_wins_falls_through_an_empty_newer_to_an_older_with_data`).
        // In 0.4.0 the Incomplete happened to halt the walk and hide that; the
        // fall-through is the policy's own behaviour for an empty newest, not
        // something a write failure should decide.
        let a = entry(1, 1);
        let b = entry(2, 2);
        let mut store = MemStore::default();
        let (b_done_key, _) = predecessor_done_marker(&key_of(&b), true);
        store.fail_writes_to(&b_done_key);

        // Run 1: B empty → its DONE write fails → Incomplete; A falls through.
        let mut io1 = MockIo::default()
            .executable_with(&key_of(&b), &[])
            .executable_with(&key_of(&a), &[(b"a_only", b"va")]);
        let r1 = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io1,
            &[a, b],
            ack(),
            newest(),
        ));
        assert!(matches!(
            r1.predecessors[0],
            PredecessorMigration::Incomplete {
                failure: Some(WriterFailure {
                    stage: WriterStage::CompleteMarker,
                    ..
                }),
                ..
            }
        ));
        assert!(
            matches!(r1.predecessors[1], PredecessorMigration::Imported { .. }),
            "an EMPTY newer predecessor falls through under NewestSnapshotWins"
        );
        assert_eq!(store.get_secret(b"a_only").unwrap(), b"va");
        // B's in-progress marker recorded "empty" so far.
        assert_eq!(
            store.get_secret(&pred_wip_marker(&key_of(&b))).unwrap(),
            PRED_DONE_MARKER_VALUE_EMPTY
        );

        // Run 2: DONE writes succeed; B now has data → the sticky-data rule upgrades
        // empty→data, so the sealed marker is DATA-bearing.
        store.stop_failing();
        let mut io2 = MockIo::default()
            .executable_with(&key_of(&b), &[(b"b_only", b"vb")])
            .executable_with(&key_of(&a), &[(b"a_only", b"va")]);
        let r2 = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io2,
            &[a, b],
            ack(),
            newest(),
        ));
        assert!(
            matches!(r2.predecessors[0], PredecessorMigration::Imported { .. }),
            "B seals data-bearing on the retry"
        );
        assert_eq!(
            store.get_secret(&b_done_key).unwrap(),
            PRED_DONE_MARKER_VALUE_DATA,
            "the sealed marker must be DATA-bearing (sticky-data upgrade), not empty"
        );
        assert!(
            matches!(r2.predecessors[1], PredecessorMigration::Superseded { .. }),
            "B is authoritative once sealed data-bearing, so A is not revisited \
             (the terminated check precedes the marker read); either way run 2 is a \
             no-op for A"
        );
        assert!(
            store.has_secret(&pred_done_marker(&key_of(&a))),
            "A stays sealed from run 1"
        );
        assert_eq!(store.get_secret(b"b_only").unwrap(), b"vb");
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
                &mut store_io(&mut store),
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
                &mut store_io(&mut store),
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
                &mut store_io(store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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

    #[test]
    fn register_successor_is_handed_predecessors_newest_generation_first() {
        // `RegisterAndMigrateIo::register_successor` documents newest-first ordering
        // as a GUARANTEE, because a copy-forward node copies in the supplied order
        // with first-writer-wins — so newest-first is what makes the node copy
        // newest-precedence. Nothing else in this suite would notice if the sort were
        // dropped: the internal walk sorts again on its own, and the outcome is
        // identical. The guarantee is inert today (no node copy-forward exists), which
        // is exactly why it needs its own assertion rather than an incidental one.
        let a = entry(1, 1);
        let b = entry(2, 2);
        let c = entry(3, 3);
        let mut writer = ScriptedWriter::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&a), &[])
            .executable_with(&key_of(&b), &[])
            .executable_with(&key_of(&c), &[]);
        // Deliberately NOT already sorted, and not merely reversed.
        block_on(register_delegate_with_migration(
            &mut writer,
            &mut io,
            &[b, a, c],
            ack(),
            union(),
        ))
        .unwrap();
        assert_eq!(
            io.registered_generations,
            vec![3, 2, 1],
            "register_successor must receive predecessors newest-generation-first"
        );
    }

    #[test]
    fn a_failed_registration_returns_err_and_moves_no_secrets() {
        // `register_delegate_with_migration` documents "no secrets have moved at
        // that point" for a failed registration. That rests on one `?`, and nothing
        // else in the suite exercises the error path — swallowing it (running the
        // migration against a successor the node never registered) left all tests
        // green. Assert both halves: the error propagates, and no predecessor was
        // round-tripped and no successor state touched.
        let a = entry(1, 1);
        let b = entry(2, 2);
        let mut writer = ScriptedWriter::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&a), &[(b"k1", b"v1")])
            .executable_with(&key_of(&b), &[(b"k2", b"v2")])
            .failing_registration();

        let result = block_on(register_delegate_with_migration(
            &mut writer,
            &mut io,
            &[a, b],
            ack(),
            union(),
        ));

        assert!(
            result.is_err(),
            "a failed register_successor must propagate, not be swallowed"
        );
        assert_eq!(io.registered, 1, "registration was in fact attempted");
        assert!(
            io.probed.is_empty() && io.fetched.is_empty(),
            "no predecessor may be round-tripped once registration failed"
        );
        assert!(
            writer.applied.is_empty() && writer.markers.is_empty(),
            "no successor state may be written once registration failed"
        );
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
            &mut store_io(&mut store),
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
            &mut store_io(&mut store),
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

    // =======================================================================
    // The writer seam (0.5.0)
    // =======================================================================

    /// An error a scripted successor writer reports.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct WriterErr(&'static str);

    /// A [`SuccessorSecretsIo`] double that can fail at every stage, so a test can
    /// exercise the failure paths a store-backed double cannot reach. (0.4.0's
    /// delegate tests ran entirely against a store whose writes almost always
    /// succeeded, which is how the halt-on-Incomplete bug stayed hidden.)
    #[derive(Default)]
    struct ScriptedWriter {
        /// Items the writer applied.
        applied: BTreeMap<Vec<u8>, Vec<u8>>,
        /// Markers, keyed by predecessor key bytes.
        markers: BTreeMap<Vec<u8>, MigrationMarker>,
        /// Secret keys the writer permanently refuses.
        reject: BTreeSet<Vec<u8>>,
        /// Secret VALUES the writer permanently refuses (a certificate that does
        /// not verify is a property of the value, not the key).
        reject_values: BTreeSet<Vec<u8>>,
        /// Secret keys whose write fails retryably.
        fail: BTreeSet<Vec<u8>>,
        /// Predecessors whose marker read / begin-marker / flush / done-marker fail.
        fail_marker_read: BTreeSet<Vec<u8>>,
        fail_begin: BTreeSet<Vec<u8>>,
        fail_flush: BTreeSet<Vec<u8>>,
        fail_done: BTreeSet<Vec<u8>>,
        /// Every item the driver offered, in order.
        offered: Vec<(Vec<u8>, Vec<u8>)>,
        /// Flush calls, for ordering assertions.
        flushes: Vec<Vec<u8>>,
    }

    impl ScriptedWriter {
        fn permanently_reject(mut self, key: &[u8]) -> Self {
            self.reject.insert(key.to_vec());
            self
        }
        fn permanently_reject_value(mut self, value: &[u8]) -> Self {
            self.reject_values.insert(value.to_vec());
            self
        }
        fn fail_write(mut self, key: &[u8]) -> Self {
            self.fail.insert(key.to_vec());
            self
        }
        fn fail_marker_read(mut self, predecessor: &DelegateKey) -> Self {
            self.fail_marker_read.insert(predecessor.bytes().to_vec());
            self
        }
        fn fail_begin_marker(mut self, predecessor: &DelegateKey) -> Self {
            self.fail_begin.insert(predecessor.bytes().to_vec());
            self
        }
        fn fail_flush(mut self, predecessor: &DelegateKey) -> Self {
            self.fail_flush.insert(predecessor.bytes().to_vec());
            self
        }
        fn fail_done_marker(mut self, predecessor: &DelegateKey) -> Self {
            self.fail_done.insert(predecessor.bytes().to_vec());
            self
        }
    }

    impl SuccessorSecretsIo for ScriptedWriter {
        type Error = WriterErr;

        async fn migration_marker(
            &mut self,
            query: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, WriterErr> {
            if self.fail_marker_read.contains(query.predecessor.bytes()) {
                return Err(WriterErr("marker read"));
            }
            Ok(self.markers.get(query.predecessor.bytes()).copied())
        }

        async fn record_marker(
            &mut self,
            predecessor: &DelegateKey,
            marker: MigrationMarker,
        ) -> Result<(), WriterErr> {
            let k = predecessor.bytes().to_vec();
            match marker {
                MigrationMarker::InProgress { .. } if self.fail_begin.contains(&k) => {
                    Err(WriterErr("begin marker"))
                }
                MigrationMarker::Done { .. } if self.fail_done.contains(&k) => {
                    Err(WriterErr("done marker"))
                }
                _ => {
                    self.markers.insert(k, marker);
                    Ok(())
                }
            }
        }

        async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<WriterErr> {
            self.offered.push((item.key.to_vec(), item.value.to_vec()));
            if self.reject.contains(item.key) || self.reject_values.contains(item.value) {
                return ItemWrite::permanent(WriterErr("refused"));
            }
            if self.fail.contains(item.key) {
                return ItemWrite::retryable(WriterErr("storage"));
            }
            if self.applied.contains_key(item.key) {
                return ItemWrite::already_authoritative();
            }
            self.applied.insert(item.key.to_vec(), item.value.to_vec());
            ItemWrite::written()
        }

        async fn flush_predecessor(&mut self, predecessor: &DelegateKey) -> Result<(), WriterErr> {
            self.flushes.push(predecessor.bytes().to_vec());
            if self.fail_flush.contains(predecessor.bytes()) {
                return Err(WriterErr("flush"));
            }
            Ok(())
        }
    }

    // ---- a BUFFERING successor writer ----------------------------------------

    /// A writer whose per-item `Written` is **optimistic**: items land in a pending
    /// batch and only become durable when `flush_predecessor` succeeds. A failing
    /// flush **discards** the batch.
    ///
    /// This is the writer shape `flush_predecessor` exists for — a UI-side adopter
    /// whose only route to the successor store is an awaited round-trip, which is
    /// what Delta will be. `ScriptedWriter` cannot model it: it applies to
    /// `applied` inside `write_secret`, so its flush failure loses nothing and every
    /// flush test written against it is blind to what a real buffering writer does.
    #[derive(Default)]
    struct BufferingWriter {
        /// Durable state (post-flush).
        applied: BTreeMap<Vec<u8>, Vec<u8>>,
        /// Accepted but not yet durable. Dropped by a failed flush.
        pending: BTreeMap<Vec<u8>, Vec<u8>>,
        markers: HashMap<Vec<u8>, MigrationMarker>,
        fail_flush: BTreeSet<Vec<u8>>,
    }

    impl BufferingWriter {
        fn fail_flush(mut self, predecessor: &DelegateKey) -> Self {
            self.fail_flush.insert(predecessor.bytes().to_vec());
            self
        }
        /// Seed unflushed app-side state, so a never-clobber `AlreadyAuthoritative`
        /// can be a claim about buffer contents rather than durable storage.
        fn pending_before_migration(mut self, key: &[u8], value: &[u8]) -> Self {
            self.pending.insert(key.to_vec(), value.to_vec());
            self
        }
        fn stop_failing_flush(&mut self) {
            self.fail_flush.clear();
        }
        fn durable(&self, key: &[u8]) -> Option<&Vec<u8>> {
            self.applied.get(key)
        }
    }

    impl SuccessorSecretsIo for BufferingWriter {
        type Error = WriterErr;

        async fn migration_marker(
            &mut self,
            query: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, WriterErr> {
            Ok(self.markers.get(query.predecessor.bytes()).copied())
        }

        async fn record_marker(
            &mut self,
            predecessor: &DelegateKey,
            marker: MigrationMarker,
        ) -> Result<(), WriterErr> {
            self.markers.insert(predecessor.bytes().to_vec(), marker);
            Ok(())
        }

        async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<WriterErr> {
            // Never-clobber over BOTH durable and pending state — the honest thing
            // for a batching writer, and the reason a failed flush can invalidate
            // an `AlreadyAuthoritative` answer as well as a `Written` one.
            if self.applied.contains_key(item.key) || self.pending.contains_key(item.key) {
                return ItemWrite::already_authoritative();
            }
            self.pending.insert(item.key.to_vec(), item.value.to_vec());
            // Optimistic: nothing is durable until the flush.
            ItemWrite::written()
        }

        async fn flush_predecessor(&mut self, predecessor: &DelegateKey) -> Result<(), WriterErr> {
            if self.fail_flush.contains(predecessor.bytes()) {
                self.pending.clear();
                return Err(WriterErr("flush"));
            }
            self.applied.append(&mut self.pending);
            Ok(())
        }
    }

    #[test]
    fn a_failed_flush_withholds_its_keys_so_an_older_generation_cannot_shadow_the_newer_value() {
        // THE bug this fix exists for. Under Union the walk continues past a failed
        // flush, so unless the flush withholds what it lost, the older generation
        // writes its value into the hole, flushes clean, and earns a `Done` marker
        // — after which never-clobber declines the newer value forever and the
        // report reads clean. `written` is only ever incremented in the item loop,
        // so before this fix NOTHING was withheld for a buffering writer.
        let older = entry(1, 1);
        let newer = entry(2, 2);
        let mut writer = BufferingWriter::default().fail_flush(&key_of(&newer));
        let mut io = MockIo::default()
            .executable_with(&key_of(&older), &[(b"k", b"v1")])
            .executable_with(&key_of(&newer), &[(b"k", b"v2")]);

        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[older, newer],
            ack(),
            union(),
        ));

        // The older generation's value must NOT have landed.
        assert_eq!(
            writer.durable(b"k"),
            None,
            "the older generation must not fill the hole a failed flush left"
        );
        // ... and the older predecessor must NOT be sealed, or the retry would skip it.
        assert!(
            !matches!(
                writer.markers.get(key_of(&older).bytes()),
                Some(MigrationMarker::Done { .. })
            ),
            "a predecessor with withheld items must not earn a completion marker"
        );

        let newer_tally = report
            .predecessors
            .iter()
            .find_map(|p| match p {
                PredecessorMigration::Incomplete {
                    key,
                    tally,
                    failure,
                    ..
                } if *key == key_of(&newer) => Some((*tally, failure.clone())),
                _ => None,
            })
            .expect("the flush-failing predecessor is Incomplete");
        assert_eq!(newer_tally.0.written, 0, "a discarded batch is not written");
        assert_eq!(newer_tally.0.failed, 1);
        assert_eq!(
            newer_tally.1.map(|f| f.stage),
            Some(WriterStage::Flush),
            "the flush is the reported failure stage"
        );

        let older_tally = report
            .predecessors
            .iter()
            .find_map(|p| match p {
                PredecessorMigration::Incomplete { key, tally, .. } if *key == key_of(&older) => {
                    Some(*tally)
                }
                _ => None,
            })
            .expect("the older predecessor is Incomplete (its key was withheld)");
        assert_eq!(older_tally.withheld, 1, "the newer key is withheld");
        assert_eq!(older_tally.written, 0);

        assert!(!report.is_complete());
        assert!(report.retry_may_help());
        assert_eq!(report.imported_total(), 0);
    }

    #[test]
    fn the_retry_after_a_failed_flush_lands_the_newer_value_not_the_older_one() {
        // End-to-end consequence of the withholding: run 1 loses the batch, run 2
        // recovers the NEWER generation's value. Without the withholding, run 1
        // durably lands `v1` from the older generation and seals it, so run 2
        // declines `v2` under never-clobber and the user is left on the older value
        // with a report that says the migration completed.
        let older = entry(1, 1);
        let newer = entry(2, 2);
        let preds = [older, newer];
        let mut writer = BufferingWriter::default().fail_flush(&key_of(&newer));
        let secrets = |io: MockIo| {
            io.executable_with(&key_of(&older), &[(b"k", b"v1")])
                .executable_with(&key_of(&newer), &[(b"k", b"v2")])
        };

        let first = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut secrets(MockIo::default()),
            &preds,
            ack(),
            union(),
        ));
        assert!(first.retry_may_help());

        writer.stop_failing_flush();
        let second = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut secrets(MockIo::default()),
            &preds,
            ack(),
            union(),
        ));

        assert_eq!(
            writer.durable(b"k").map(Vec::as_slice),
            Some(b"v2".as_slice()),
            "the retry must land the NEWER generation's value"
        );
        assert!(second.is_complete(), "the retry completes cleanly");
        assert!(!second.retry_may_help());
    }

    #[test]
    fn a_failed_flush_withholds_already_authoritative_keys_too() {
        // `AlreadyAuthoritative` can be a claim about UNFLUSHED buffer state: this
        // writer never-clobbers over its pending batch, so the successor's own
        // not-yet-durable `v0` is what declines the newer generation's `v2`. When
        // the flush then discards that batch, the claim evaporates — and if the key
        // were not withheld, the OLDER generation's `v1` would land durably and
        // shadow a value the successor itself considered authoritative.
        let older = entry(1, 1);
        let newer = entry(2, 2);
        let mut writer = BufferingWriter::default()
            .pending_before_migration(b"k", b"v0")
            .fail_flush(&key_of(&newer));
        let mut io = MockIo::default()
            .executable_with(&key_of(&older), &[(b"k", b"v1")])
            .executable_with(&key_of(&newer), &[(b"k", b"v2")]);

        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[older, newer],
            ack(),
            union(),
        ));

        assert_eq!(writer.durable(b"k"), None);
        let newer_tally = report
            .predecessors
            .iter()
            .find_map(|p| match p {
                PredecessorMigration::Incomplete { key, tally, .. } if *key == key_of(&newer) => {
                    Some(*tally)
                }
                _ => None,
            })
            .expect("Incomplete");
        assert_eq!(
            newer_tally.skipped, 1,
            "the item was declined, not written — so nothing is re-counted as failed"
        );
        assert_eq!(newer_tally.written, 0);
        assert_eq!(newer_tally.failed, 0);

        let older_tally = report
            .predecessors
            .iter()
            .find_map(|p| match p {
                PredecessorMigration::Incomplete { key, tally, .. } if *key == key_of(&older) => {
                    Some(*tally)
                }
                _ => None,
            })
            .expect("the older predecessor is Incomplete");
        assert_eq!(
            older_tally.withheld, 1,
            "a declined-against-unflushed key must be withheld too"
        );
        assert!(report.retry_may_help());
    }

    #[test]
    fn a_failed_flush_never_reports_buffered_items_as_imported() {
        // `imported_total()` is what an adopter surfaces as "recovered N secrets".
        // A buffering writer answers `Written` for items it has only buffered, so
        // counting those after a failed flush tells the user data landed precisely
        // when it did not.
        let only = entry(1, 1);
        let mut writer = BufferingWriter::default().fail_flush(&key_of(&only));
        let mut io = MockIo::default()
            .executable_with(&key_of(&only), &[(b"a", b"1"), (b"b", b"2"), (b"c", b"3")]);

        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            core::slice::from_ref(&only),
            ack(),
            union(),
        ));

        assert_eq!(
            report.imported_total(),
            0,
            "nothing was flushed, so nothing was imported"
        );
        assert_eq!(report.failed_total(), 3);
        let tally = report
            .predecessors
            .iter()
            .find_map(|p| match p {
                PredecessorMigration::Incomplete { tally, .. } => Some(*tally),
                _ => None,
            })
            .expect("Incomplete");
        assert_eq!(tally.offered(), 3, "the bucket sum is preserved");
        assert!(!tally.is_clean());
        assert!(tally.retry_may_help());
    }

    #[test]
    fn a_clean_flush_still_reports_its_buffered_items_as_imported() {
        // The counterweight: the re-classification must fire ONLY on a failed
        // flush. A mutation that always moved `written` into `failed` would pass
        // every test above.
        let only = entry(1, 1);
        let mut writer = BufferingWriter::default();
        let mut io =
            MockIo::default().executable_with(&key_of(&only), &[(b"a", b"1"), (b"b", b"2")]);

        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            core::slice::from_ref(&only),
            ack(),
            union(),
        ));

        assert_eq!(report.imported_total(), 2);
        assert_eq!(report.failed_total(), 0);
        assert!(report.is_complete());
        assert_eq!(
            writer.durable(b"a").map(Vec::as_slice),
            Some(b"1".as_slice())
        );
    }

    // ---- the successor writer is actually what writes ------------------------

    #[test]
    fn every_recovered_secret_goes_through_the_app_writer() {
        // The seam's basic promise: the crate never writes app data itself. Each
        // recovered pair is offered to the app's own import path, with the
        // predecessor identity and generation attached.
        let e = entry(3, 7);
        let mut writer = ScriptedWriter::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"a", b"1"), (b"b", b"2")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported {
                tally: ImportTally { written: 2, .. },
                ..
            }
        ));
        assert_eq!(
            writer.offered,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"2".to_vec())
            ]
        );
        assert_eq!(writer.applied.len(), 2);
        assert_eq!(
            writer.markers.get(key_of(&e).bytes()),
            Some(&MigrationMarker::Done { had_data: true }),
            "the completion marker is recorded through the app's writer"
        );
        assert_eq!(
            writer.flushes,
            vec![key_of(&e).bytes().to_vec()],
            "the flush hook runs before the completion marker"
        );
    }

    #[test]
    fn the_crates_reserved_markers_are_never_offered_to_the_app_writer() {
        // An import payload must not be able to write — or forge — a migration
        // marker, so the reserved namespace is filtered before the writer sees it
        // and is not counted in the tally.
        let e = entry(1, 1);
        let forged = pred_done_marker(&key_of(&entry(9, 9)));
        let mut writer = ScriptedWriter::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&e), &[(b"real", b"1"), (forged.as_slice(), b"1")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert_eq!(
            writer.offered,
            vec![(b"real".to_vec(), b"1".to_vec())],
            "the reserved marker must never reach the app's import path"
        );
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported {
                tally: ImportTally { written: 1, .. },
                ..
            }
        ));
    }

    #[test]
    fn a_completed_predecessor_is_never_re_offered_to_the_writer() {
        // Idempotency at the crate's level: the Done marker short-circuits before
        // any round-trip, so a re-run offers the writer nothing at all. (The
        // writer's own idempotency is its contract; this is the crate's half.)
        let e = entry(1, 1);
        let mut writer = ScriptedWriter::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"v")]);
        block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert_eq!(writer.offered.len(), 1);

        let mut io2 = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"RESURRECT")]);
        let second = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io2,
            &[e],
            ack(),
            newest(),
        ));
        assert!(matches!(
            second.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ));
        assert_eq!(writer.offered.len(), 1, "nothing re-offered on the re-run");
        assert!(!io2.probed.contains(key_of(&e).bytes()));
        assert_eq!(writer.applied.get(b"k".as_slice()).unwrap(), b"v");
    }

    // ---- partial failure is expressible --------------------------------------

    #[test]
    fn a_writer_that_fails_on_item_three_of_ten_reports_exactly_what_landed() {
        // Partial failure must say what was written, what was not, and whether a
        // retry can help — not collapse into a bool.
        let e = entry(1, 1);
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            (0..10u8).map(|i| (vec![b'k', i], vec![b'v', i])).collect();
        let refs: Vec<(&[u8], &[u8])> = pairs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        let mut writer = ScriptedWriter::default().fail_write(b"k\x02");
        let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        let PredecessorMigration::Incomplete { tally, failure, .. } = &report.predecessors[0]
        else {
            panic!("expected Incomplete, got {:?}", report.predecessors[0]);
        };
        assert_eq!(tally.written, 9);
        assert_eq!(tally.failed, 1);
        assert_eq!(tally.rejected, 0);
        assert_eq!(tally.skipped, 0);
        assert_eq!(
            tally.offered(),
            10,
            "every item lands in exactly one bucket"
        );
        assert_eq!(
            failure.as_ref().map(|f| f.stage),
            Some(WriterStage::Item),
            "the first failure's stage is reported"
        );
        assert!(!report.is_complete());
        assert!(report.retry_may_help(), "a transient failure is retryable");
        assert_eq!(report.imported_total(), 9);
        assert_eq!(report.failed_total(), 1);
        // The walk does NOT stop at the failing item: the other nine were offered.
        assert_eq!(writer.offered.len(), 10);
        // And the completion marker is withheld, so a retry re-runs this predecessor.
        assert_eq!(
            writer.markers.get(key_of(&e).bytes()),
            Some(&MigrationMarker::InProgress { saw_data: true }),
            "an incomplete predecessor keeps its in-progress marker, never Done"
        );
    }

    #[test]
    fn a_failed_flush_withholds_the_completion_marker() {
        // A writer that buffers must be able to fail honestly at the end, or the
        // Done marker seals a migration whose data never landed.
        let e = entry(1, 1);
        let mut writer = ScriptedWriter::default().fail_flush(&key_of(&e));
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"v")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                &report.predecessors[0],
                PredecessorMigration::Incomplete {
                    // The item was accepted by the writer, but the flush is the
                    // durability boundary: an unflushed item is a retryable
                    // failure, never a `written`.
                    tally: ImportTally {
                        written: 0,
                        failed: 1,
                        ..
                    },
                    failure: Some(WriterFailure {
                        stage: WriterStage::Flush,
                        ..
                    }),
                    ..
                }
            ),
            "got {:?}",
            report.predecessors[0]
        );
        assert!(!report.is_complete());
        assert!(report.retry_may_help());
        assert!(
            !matches!(
                writer.markers.get(key_of(&e).bytes()),
                Some(MigrationMarker::Done { .. })
            ),
            "a failed flush must not be sealed"
        );
    }

    #[test]
    fn a_flush_failure_is_reported_even_when_an_item_was_permanently_rejected() {
        // Item failures are described by the tally; a stage failure is not, and it
        // is what `retry_may_help` reads. If the first-seen item failure won the
        // `failure` slot, a retryable flush fault would hide behind a permanent
        // rejection and the app would be told not to bother retrying.
        let e = entry(1, 1);
        let mut writer = ScriptedWriter::default()
            .permanently_reject(b"bad")
            .fail_flush(&key_of(&e));
        let mut io =
            MockIo::default().executable_with(&key_of(&e), &[(b"bad", b"1"), (b"good", b"2")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                &report.predecessors[0],
                PredecessorMigration::Incomplete {
                    tally: ImportTally {
                        // `good` was accepted but never flushed, so it is a
                        // retryable failure rather than a `written`; `bad` stays
                        // permanently rejected.
                        written: 0,
                        rejected: 1,
                        failed: 1,
                        ..
                    },
                    failure: Some(WriterFailure {
                        stage: WriterStage::Flush,
                        ..
                    }),
                    ..
                }
            ),
            "the flush failure must outrank the item rejection: {:?}",
            report.predecessors[0]
        );
        assert!(
            report.retry_may_help(),
            "the flush fault is retryable even though the rejected item is not"
        );
    }

    #[test]
    fn a_failed_marker_read_halts_the_walk_under_every_policy() {
        // Without a marker read the crate cannot tell migrated from not-migrated, so
        // guessing either way risks a double import or a silent skip. Nothing is
        // imported and the walk stops — under Union too, unlike an Unresponsive
        // predecessor, because it is the SUCCESSOR side that is broken.
        for policy in [newest(), union()] {
            let old = entry(1, 1);
            let new = entry(2, 2);
            let mut writer = ScriptedWriter::default().fail_marker_read(&key_of(&new));
            let mut io = MockIo::default()
                .executable_with(&key_of(&new), &[(b"n", b"1")])
                .executable_with(&key_of(&old), &[(b"o", b"1")]);
            let report = block_on(migrate_delegate_secrets(
                &mut writer,
                &mut io,
                &[old, new],
                ack(),
                policy,
            ));
            assert!(
                matches!(
                    &report.predecessors[0],
                    PredecessorMigration::WriterUnavailable {
                        failure: WriterFailure {
                            stage: WriterStage::ReadMarker,
                            ..
                        },
                        ..
                    }
                ),
                "got {:?}",
                report.predecessors[0]
            );
            assert!(matches!(
                report.predecessors[1],
                PredecessorMigration::Superseded { .. }
            ));
            assert!(writer.applied.is_empty(), "nothing imported");
            assert!(writer.offered.is_empty(), "nothing even offered");
            assert!(!io.probed.contains(key_of(&new).bytes()), "no round-trip");
            assert!(!report.is_complete());
            assert!(report.retry_may_help());
        }
    }

    #[test]
    fn a_failed_begin_marker_imports_nothing() {
        // Phase 1 records intent BEFORE any item. If even that fails, no item may be
        // offered — otherwise a crash mid-import would leave written data with no
        // marker at all, and a later re-run could not tell it had happened.
        let e = entry(1, 1);
        let mut writer = ScriptedWriter::default().fail_begin_marker(&key_of(&e));
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"v")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                &report.predecessors[0],
                PredecessorMigration::WriterUnavailable {
                    failure: WriterFailure {
                        stage: WriterStage::BeginMarker,
                        ..
                    },
                    ..
                }
            ),
            "got {:?}",
            report.predecessors[0]
        );
        assert!(writer.offered.is_empty(), "no item may be written");
        assert!(writer.applied.is_empty());
    }

    #[test]
    fn a_failed_completion_marker_is_incomplete_not_imported() {
        let e = entry(1, 1);
        let mut writer = ScriptedWriter::default().fail_done_marker(&key_of(&e));
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"v")]);
        let report = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(
            matches!(
                &report.predecessors[0],
                PredecessorMigration::Incomplete {
                    tally: ImportTally { written: 1, .. },
                    failure: Some(WriterFailure {
                        stage: WriterStage::CompleteMarker,
                        ..
                    }),
                    ..
                }
            ),
            "got {:?}",
            report.predecessors[0]
        );
        assert!(!report.is_complete());
    }

    #[test]
    fn a_retry_after_a_partial_run_tells_the_writer_it_is_a_retry() {
        // The writer's own idempotency is its contract, but the crate knows —
        // and only the crate knows — that a predecessor is being re-attempted.
        let e = entry(1, 1);
        let mut writer = ScriptedWriter::default().fail_write(b"b");
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"a", b"1"), (b"b", b"2")]);
        block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert!(matches!(
            writer.markers.get(key_of(&e).bytes()),
            Some(MigrationMarker::InProgress { saw_data: true })
        ));

        // Retry: the writer stops failing and observes `retry == true`.
        writer.fail.clear();
        let seen_retry = std::cell::Cell::new(None);
        {
            struct RetryProbe<'a> {
                inner: &'a mut ScriptedWriter,
                seen: &'a std::cell::Cell<Option<bool>>,
            }
            impl SuccessorSecretsIo for RetryProbe<'_> {
                type Error = WriterErr;
                async fn migration_marker(
                    &mut self,
                    q: &MarkerQuery<'_>,
                ) -> Result<Option<MigrationMarker>, WriterErr> {
                    self.inner.migration_marker(q).await
                }
                async fn record_marker(
                    &mut self,
                    p: &DelegateKey,
                    m: MigrationMarker,
                ) -> Result<(), WriterErr> {
                    self.inner.record_marker(p, m).await
                }
                async fn write_secret(
                    &mut self,
                    item: &RecoveredSecret<'_>,
                ) -> ItemWrite<WriterErr> {
                    self.seen.set(Some(item.retry));
                    self.inner.write_secret(item).await
                }
            }
            let mut probe = RetryProbe {
                inner: &mut writer,
                seen: &seen_retry,
            };
            let mut io2 =
                MockIo::default().executable_with(&key_of(&e), &[(b"a", b"1"), (b"b", b"2")]);
            let report = block_on(migrate_delegate_secrets(
                &mut probe,
                &mut io2,
                &[e],
                ack(),
                newest(),
            ));
            assert!(
                matches!(
                    report.predecessors[0],
                    PredecessorMigration::Imported { .. }
                ),
                "the retry completes: {:?}",
                report.predecessors[0]
            );
            assert!(report.is_complete());
        }
        assert_eq!(
            seen_retry.get(),
            Some(true),
            "a re-attempted predecessor's items are flagged as a retry"
        );
        assert_eq!(writer.applied.get(b"b".as_slice()).unwrap(), b"2");
    }

    // ---- SecretStoreIo is exactly the pre-0.5.0 behaviour ---------------------

    #[test]
    fn secret_store_io_matches_the_legacy_raw_pair_primitive_byte_for_byte() {
        // The raw-pair writer is the pre-0.5.0 behaviour, kept for apps whose
        // secrets stand alone. Pinned against the still-public primitive the 0.4.0
        // driver used (`import_predecessor_secrets_once`) so the two cannot drift:
        // same inputs, byte-identical store, including the marker keys and values a
        // node-side copy-forward reads.
        let e = entry(1, 1);
        let secrets: Vec<SecretPair> = vec![
            (b"fresh".to_vec(), b"v".to_vec()),
            (b"existing".to_vec(), b"NEW".to_vec()),
            (pred_done_marker(&key_of(&entry(9, 9))), b"1".to_vec()),
        ];
        let refs: Vec<(&[u8], &[u8])> = secrets
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();

        let mut via_driver = MemStore::default();
        via_driver.set_secret(b"existing", b"OLD");
        let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut via_driver),
            &mut io,
            &[e],
            ack(),
            newest(),
        ));

        let mut via_primitive = MemStore::default();
        via_primitive.set_secret(b"existing", b"OLD");
        let outcome = import_predecessor_secrets_once(&mut via_primitive, &key_of(&e), &secrets);

        assert_eq!(
            outcome,
            PredecessorImportOutcome::Imported {
                imported: 1,
                skipped: 1
            }
        );
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported {
                tally: ImportTally {
                    written: 1,
                    skipped: 1,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            via_driver.data, via_primitive.data,
            "the raw-pair writer must be byte-identical to the legacy primitive"
        );
    }

    #[test]
    fn secret_store_io_writes_the_public_versioned_marker_format() {
        // The marker is the cross-transport interoperability contract with a future
        // node-side copy-forward, so its bytes must not move.
        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"k", b"v")]);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        let (expected_key, expected_value) = predecessor_done_marker(&key_of(&e), true);
        assert!(expected_key.starts_with(PRED_DONE_MARKER_KEY_PREFIX));
        assert_eq!(store.get_secret(&expected_key).unwrap(), expected_value);
        assert_eq!(expected_value, PRED_DONE_MARKER_VALUE_DATA);
    }

    // =======================================================================
    // Regression: the ghostkeys index bug (freenet/ghostkeys#32, finding D3)
    // =======================================================================
    //
    // ghostkeys stores each credential as several entries — `gk:cert:<fp>`,
    // `gk:sk:<fp>` — plus ONE `gk:index` entry (a CBOR list of fingerprints) that
    // says which credentials exist, and a `gk:perms:<fp>` grant per requestor. Its
    // UI lists a credential only if the index names it AND the requestor holds a
    // grant on it.
    //
    // A raw pair copy finds an index already on the successor (the user made a key
    // on the new version before the sweep ran), skips it never-clobber, and copies
    // no grants at all — because grants are not among the exported pairs. The
    // recovered credential's bytes land in the store while nothing lists them and
    // nothing may read them: permanently invisible, no error.

    const GK_INDEX: &[u8] = b"gk:index";

    fn gk_cert(fp: &str) -> Vec<u8> {
        format!("gk:cert:{fp}").into_bytes()
    }
    fn gk_sk(fp: &str) -> Vec<u8> {
        format!("gk:sk:{fp}").into_bytes()
    }
    fn gk_perms(fp: &str) -> Vec<u8> {
        format!("gk:perms:{fp}").into_bytes()
    }

    fn index_bytes(fps: &[&str]) -> Vec<u8> {
        let list: Vec<String> = fps.iter().map(|s| s.to_string()).collect();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&list, &mut buf).unwrap();
        buf
    }
    fn index_of(store: &MemStore) -> Vec<String> {
        match store.get_secret(GK_INDEX) {
            Some(bytes) => ciborium::de::from_reader(bytes.as_slice()).unwrap(),
            None => Vec::new(),
        }
    }

    /// What ghostkeys' `ListGhostKeys` would show: a fingerprint the index names,
    /// whose certificate loads, and which the requestor holds a grant on.
    fn visible_credentials(store: &MemStore) -> Vec<String> {
        index_of(store)
            .into_iter()
            .filter(|fp| store.has_secret(&gk_cert(fp)) && store.has_secret(&gk_perms(fp)))
            .collect()
    }

    /// The successor store as a user who already made one credential on the NEW
    /// version would have it: one credential, listed and granted.
    fn ghostkeys_successor() -> MemStore {
        let mut store = MemStore::default();
        store.set_secret(&gk_cert("fp-new"), b"cert-new");
        store.set_secret(&gk_sk("fp-new"), b"sk-new");
        store.set_secret(&gk_perms("fp-new"), b"read+sign");
        store.set_secret(GK_INDEX, &index_bytes(&["fp-new"]));
        store
    }

    /// The predecessor's raw namespace dump, holding one purchased credential.
    ///
    /// Permission grants are deliberately absent: they are not among the pairs a
    /// predecessor exports, which is precisely why a raw pair copy can never record
    /// one. (`ghostkeys_predecessor_dump_with_stale_grant` covers the variant where
    /// one IS in the dump.)
    fn ghostkeys_predecessor_dump() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (gk_cert("fp-old"), b"cert-old".to_vec()),
            (gk_sk("fp-old"), b"sk-old".to_vec()),
            (GK_INDEX.to_vec(), index_bytes(&["fp-old"])),
        ]
    }

    /// A dump that DOES carry the predecessor's own grant, addressed to the old app.
    fn ghostkeys_predecessor_dump_with_stale_grant() -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut dump = ghostkeys_predecessor_dump();
        dump.push((gk_perms("fp-old"), b"grant-for-the-OLD-app".to_vec()));
        dump
    }

    /// ghostkeys' own `ImportGhostKey` handler, as a [`SuccessorSecretsIo`]: it
    /// merges the derived index, records its own grant, and declines to copy the
    /// predecessor's grants verbatim.
    struct GhostkeysWriter<'a> {
        store: &'a mut MemStore,
    }

    impl GhostkeysWriter<'_> {
        fn add_to_index(&mut self, fp: &str) {
            let mut fps = index_of(self.store);
            if !fps.iter().any(|f| f == fp) {
                fps.push(fp.to_string());
            }
            let refs: Vec<&str> = fps.iter().map(String::as_str).collect();
            self.store.set_secret(GK_INDEX, &index_bytes(&refs));
        }
    }

    impl SuccessorSecretsIo for GhostkeysWriter<'_> {
        type Error = WriterErr;

        async fn migration_marker(
            &mut self,
            query: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, WriterErr> {
            Ok(
                match self.store.get_secret(&pred_done_marker(query.predecessor)) {
                    Some(v) => Some(MigrationMarker::Done {
                        had_data: v != PRED_DONE_MARKER_VALUE_EMPTY,
                    }),
                    None => self
                        .store
                        .get_secret(&pred_wip_marker(query.predecessor))
                        .map(|v| MigrationMarker::InProgress {
                            saw_data: v != PRED_DONE_MARKER_VALUE_EMPTY,
                        }),
                },
            )
        }

        async fn record_marker(
            &mut self,
            predecessor: &DelegateKey,
            marker: MigrationMarker,
        ) -> Result<(), WriterErr> {
            let (key, data) = match marker {
                MigrationMarker::InProgress { saw_data } => {
                    (pred_wip_marker(predecessor), saw_data)
                }
                MigrationMarker::Done { had_data } => (pred_done_marker(predecessor), had_data),
            };
            let value = if data {
                PRED_DONE_MARKER_VALUE_DATA
            } else {
                PRED_DONE_MARKER_VALUE_EMPTY
            };
            self.store.set_secret(&key, value);
            Ok(())
        }

        async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<WriterErr> {
            let key = item.key;
            if key.starts_with(b"gk:perms:") {
                // Never copy a predecessor's grants verbatim; this app records its
                // own below.
                return ItemWrite::already_authoritative();
            }
            if key == GK_INDEX {
                // MERGE, never replace — the whole point. The successor's own
                // credentials must survive, and the predecessor's must appear.
                let incoming: Vec<String> = ciborium::de::from_reader(item.value)
                    .map_err(|_| ())
                    .unwrap();
                for fp in incoming {
                    self.add_to_index(&fp);
                }
                return ItemWrite::written();
            }
            let fp = match core::str::from_utf8(key) {
                Ok(s) if s.starts_with("gk:cert:") => s.trim_start_matches("gk:cert:").to_string(),
                Ok(s) if s.starts_with("gk:sk:") => s.trim_start_matches("gk:sk:").to_string(),
                _ => return ItemWrite::permanent(WriterErr("not a ghostkeys secret")),
            };
            if self.store.has_secret(key) {
                return ItemWrite::already_authoritative();
            }
            self.store.set_secret(key, item.value);
            // The invariants a raw pair copy cannot know about:
            self.add_to_index(&fp);
            self.store.set_secret(&gk_perms(&fp), b"read+sign");
            ItemWrite::written()
        }
    }

    #[test]
    fn raw_pair_import_leaves_a_recovered_ghostkey_invisible_and_says_nothing() {
        // THE BUG, against the pre-0.5.0 behaviour (which `SecretStoreIo` still is).
        // Expected before running: the credential's BYTES land, the report says
        // Imported and complete, and yet the user sees only the credential they
        // already had — under BOTH selection policies.
        for (label, policy) in [("NewestSnapshotWins", newest()), ("Union", union())] {
            let e = entry(1, 1);
            let mut store = ghostkeys_successor();
            let dump = ghostkeys_predecessor_dump();
            let refs: Vec<(&[u8], &[u8])> = dump
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();
            let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
            let report = block_on(migrate_delegate_secrets(
                &mut store_io(&mut store),
                &mut io,
                &[e],
                ack(),
                policy,
            ));

            // The bytes are there...
            assert_eq!(
                store.get_secret(&gk_cert("fp-old")).unwrap(),
                b"cert-old",
                "{label}: the recovered certificate IS in the store"
            );
            assert_eq!(store.get_secret(&gk_sk("fp-old")).unwrap(), b"sk-old");
            // ...and the crate reports total success.
            assert!(
                report.is_complete(),
                "{label}: the failure is SILENT — the report is clean"
            );
            assert!(matches!(
                report.predecessors[0],
                PredecessorMigration::Imported { .. }
            ));
            // ...but the index was skipped never-clobber, so nothing lists it,
            assert_eq!(
                index_of(&store),
                vec!["fp-new".to_string()],
                "{label}: the successor's index was never merged (ghostkeys#32 D3)"
            );
            // ...and no grant was recorded, so nothing may read it either.
            assert!(
                !store.has_secret(&gk_perms("fp-old")),
                "{label}: a raw pair copy records no permission grant"
            );
            assert_eq!(
                visible_credentials(&store),
                vec!["fp-new".to_string()],
                "{label}: the recovered credential is permanently invisible — \
                 and NO policy setting changes that"
            );
        }
    }

    #[test]
    fn the_writer_seam_recovers_a_ghostkey_the_user_can_actually_see() {
        // THE FIX, same fixture, same driver, same policy — only the writer changes.
        // Expected before running: the credential is listed AND granted, because
        // ghostkeys' own import path is what ran.
        let e = entry(1, 1);
        let mut store = ghostkeys_successor();
        let dump = ghostkeys_predecessor_dump();
        let refs: Vec<(&[u8], &[u8])> = dump
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
        let report = {
            let mut writer = GhostkeysWriter { store: &mut store };
            block_on(migrate_delegate_secrets(
                &mut writer,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        assert!(report.is_complete());
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        let mut visible = visible_credentials(&store);
        visible.sort();
        assert_eq!(
            visible,
            vec!["fp-new".to_string(), "fp-old".to_string()],
            "the recovered credential is listed AND readable, and the pre-existing \
             one survived"
        );
        assert_eq!(store.get_secret(&gk_sk("fp-old")).unwrap(), b"sk-old");
        assert_eq!(
            store.get_secret(&gk_perms("fp-old")).unwrap(),
            b"read+sign",
            "the app's own handler recorded its own grant"
        );
    }

    #[test]
    fn a_predecessors_own_permission_grant_is_copied_verbatim_by_raw_pairs_and_declined_by_the_app()
    {
        // When a grant IS in the dump, the two writers differ again: the raw copy
        // installs the predecessor's grant verbatim (addressed to the OLD app), while
        // the app's handler declines it and records its own. `Declined` is a complete,
        // correct outcome — the report stays clean.
        let e = entry(1, 1);
        let dump = ghostkeys_predecessor_dump_with_stale_grant();
        let refs: Vec<(&[u8], &[u8])> = dump
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();

        let mut raw = ghostkeys_successor();
        let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut raw),
            &mut io,
            &[e],
            ack(),
            newest(),
        ));
        assert_eq!(
            raw.get_secret(&gk_perms("fp-old")).unwrap(),
            b"grant-for-the-OLD-app",
            "a raw pair copy installs the predecessor's grant verbatim"
        );

        let mut app = ghostkeys_successor();
        let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
        let report = {
            let mut writer = GhostkeysWriter { store: &mut app };
            block_on(migrate_delegate_secrets(
                &mut writer,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        assert_eq!(
            app.get_secret(&gk_perms("fp-old")).unwrap(),
            b"read+sign",
            "the app declines the predecessor's grant and records its own"
        );
        assert!(
            report.is_complete(),
            "a deliberate decline is a complete outcome, not a failure"
        );
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Imported {
                tally: ImportTally { skipped: 1, .. },
                ..
            }
        ));
    }

    #[test]
    fn re_running_the_writer_seam_does_not_duplicate_the_ghostkeys_index() {
        // Idempotency, end to end: a partial run (the sk write is interrupted) then a
        // completing retry must leave exactly one index entry per credential — the
        // failure mode of an append-based index under a re-offered item.
        let e = entry(1, 1);
        let mut store = ghostkeys_successor();
        let dump = ghostkeys_predecessor_dump();
        let refs: Vec<(&[u8], &[u8])> = dump
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();

        // Run 1: the store refuses the sk write, so the predecessor stays unsealed.
        store.fail_writes_to(&gk_sk("fp-old"));
        let r1 = {
            let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
            let mut writer = GhostkeysWriter { store: &mut store };
            block_on(migrate_delegate_secrets(
                &mut writer,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        // The GhostkeysWriter ignores the store's refusal, so this run reports
        // complete; the point of the retry below is the index, not the report.
        assert!(matches!(
            r1.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        assert!(store.get_secret(&gk_sk("fp-old")).is_none());

        // Force a genuine re-offer by clearing the completion marker (as an
        // interrupted run would leave it).
        store.stop_failing();
        store.data.remove(&pred_done_marker(&key_of(&e)));
        let r2 = {
            let mut io = MockIo::default().executable_with(&key_of(&e), &refs);
            let mut writer = GhostkeysWriter { store: &mut store };
            block_on(migrate_delegate_secrets(
                &mut writer,
                &mut io,
                &[e],
                ack(),
                newest(),
            ))
        };
        assert!(r2.is_complete());
        assert_eq!(
            store.get_secret(&gk_sk("fp-old")).unwrap(),
            b"sk-old",
            "the retry completes the interrupted write"
        );
        let mut idx = index_of(&store);
        idx.sort();
        assert_eq!(
            idx,
            vec!["fp-new".to_string(), "fp-old".to_string()],
            "the index must not accumulate duplicates across the retry"
        );
        assert_eq!(visible_credentials(&store).len(), 2);
    }
}
