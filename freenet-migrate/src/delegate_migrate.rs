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
//!         Ok(Some(Done { .. })) => { record AlreadyMigrated; maybe stop }  // (*)
//!         Ok(in_progress_or_none) => {
//!             match io.probe_verdict(predecessor).await {       // G1.8 preflight
//!                 NoReply | NotInstalled | Err(_) => { record Unresponsive; maybe stop }
//!                 Executable => {
//!                     // Err (incl. a silent export) => record Unresponsive; maybe stop
//!                     let secrets = io.fetch_secrets(predecessor).await?;
//!                     // nothing, after an earlier attempt saw data => Unresponsive
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
//! (*) A journaled walk also skips a predecessor its journal resolved with its
//! data in the successor, and re-asks one sealed empty that its journal says an
//! import started from.
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
//! | outcome | `NewestSnapshotWins` | `...ContinuePastUnresponsive` | `UnionAllGenerations` |
//! |---|---|---|---|
//! | `Imported` / data-bearing `Incomplete` / data-bearing `AlreadyMigrated` | stop (authoritative snapshot) | stop (authoritative snapshot) | continue |
//! | `NoData` / empty `Incomplete` | continue | continue | continue |
//! | `Unresponsive` | stop (unknown newer state) | continue (opted into the rollback risk — freenet/freenet-migrate#14), unless an earlier attempt saw data | continue |
//! | `WriterUnavailable` | stop | stop | stop (successor-side bookkeeping is broken) |
//!
//! A data-bearing predecessor is authoritative under either `NewestSnapshotWins`
//! variant whether or not its writes all landed, so that column is unchanged. What
//! changes is Union: a failed write no longer abandons the older generations.
//!
//! `NewestSnapshotWinsContinuePastUnresponsive` (0.7.0,
//! [`SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive`]) exists
//! because the `Unresponsive`/`NewestSnapshotWins` cell above is the **common**
//! case, not a rare fault: a predecessor delegate is simply not registered on most
//! nodes for most legacy generations, so plain `NewestSnapshotWins` halts on the
//! very first one and never even asks the older generations that may hold the
//! user's data. See its doc and [`RollbackRiskAck`] for the trade it makes.
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
use std::collections::{BTreeMap, BTreeSet};

use freenet_stdlib::prelude::{CodeHash, DelegateKey};

use crate::delegate::{
    is_marker, legacy_generation_migrated, legacy_generation_migrated_exact, pred_done_marker,
    pred_wip_marker, SecretPair, SecretStore, PRED_DONE_MARKER_VALUE_DATA,
    PRED_DONE_MARKER_VALUE_EMPTY,
};
use crate::driver::RollbackRiskAck;
use crate::journal::{
    JournalBinding, JournalDecodeError, JournalError, JournalResolution, JournalState,
    JournalStatus, JournaledSuccessorIo, MigrationJournal, RunOutcome,
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
#[non_exhaustive]
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
    /// **Scope:** these semantics are **app-side** (the round-trip path, the only
    /// one that exists). A node-side copy-forward, if one is ever added, would
    /// need a wire that carries generations and policy to honor this
    /// stop-at-first-data-bearing / delete-by-absence guarantee; the removed v1
    /// wire carried neither — see `SecretTransport`.
    NewestSnapshotWins,
    /// **Opt-in fall-through.** Same authoritative-newest-data-bearing-wins rule
    /// as [`NewestSnapshotWins`](Self::NewestSnapshotWins), except an
    /// `Unresponsive` predecessor does not halt the walk: the search continues to
    /// the next older predecessor instead of marking every remaining generation
    /// `Superseded`. This is the freenet/freenet-migrate#14 fix — under plain
    /// `NewestSnapshotWins`, silence is the **normal** case for almost every
    /// legacy generation on almost every node (the predecessor delegate is simply
    /// not registered there any more), so the first silent generation halting the
    /// walk disables migration in practice.
    ///
    /// The predecessor that went unresponsive is still recorded as
    /// [`PredecessorMigration::Unresponsive`] and still trips
    /// [`DelegateMigrationReport::any_unresponsive`] — the app must still not
    /// treat the migration as a clean fresh install (freenet/river#204) — but
    /// older generations are no longer abandoned on that account alone.
    ///
    /// **This forfeits the anti-rollback guarantee for those older
    /// generations** — hence the [`RollbackRiskAck`]. If the unresponsive
    /// predecessor actually holds a newer, authoritative snapshot (rather than
    /// simply being unregistered on this node), an older generation's data-bearing
    /// answer becomes authoritative in its place. Two distinct consequences, both
    /// real, not just the first:
    ///
    /// * **Delete-by-absence resurrection** — a key the true newest generation
    ///   deleted could reappear, sourced from the older generation.
    /// * **Silent, permanent value-shadowing (the worse one).** The successor's
    ///   writer is never-clobber, so once the older generation's value for a key
    ///   lands and its `Done` marker seals, a *later* run in which the newest
    ///   predecessor becomes reachable and offers its own (different, real,
    ///   newer) value for that same key gets `ItemWrite::AlreadyAuthoritative` —
    ///   the true value is silently discarded, not written, not reported as a
    ///   conflict. That later run's report reads completely clean
    ///   ([`DelegateMigrationReport::is_complete`]` == true`,
    ///   [`any_unresponsive`](DelegateMigrationReport::any_unresponsive)` ==
    ///   false`): there is **no signal anywhere** that the durable value is the
    ///   wrong one. This can happen from ordinary transient unreachability alone
    ///   — no flush failure or storage fault required — and is pinned by
    ///   `continue_past_unresponsive_can_permanently_shadow_a_later_recovered_true_value`
    ///   in this module's tests.
    ///
    ///   One case is narrowed for free: if an earlier run already left a
    ///   surviving [`MigrationMarker::InProgress`] with `saw_data: true` for the
    ///   unresponsive predecessor — positive proof, not mere silence, that it
    ///   holds real data — a later `Unresponsive` result on that SAME predecessor
    ///   still halts the walk rather than falling through, closing the shadowing
    ///   path for any predecessor this app has ever successfully reached before.
    ///   It does not and cannot help on a predecessor's very first attempt, which
    ///   is indistinguishable from "never registered" — the ordinary case this
    ///   variant exists to fall through on. Fully closing that residual needs the
    ///   `probe_executable -> Result<bool, E>` classification work
    ///   freenet/freenet-migrate#14 explicitly defers as a separate follow-up.
    ///
    /// Construct the ack only if this risk is acceptable for this app, or if
    /// silence has already been established as the ordinary case (an
    /// unregistered legacy delegate) rather than a transient fault.
    ///
    /// With a migration journal: a transient silence of the newest generation
    /// lets an older one start importing; if that import is interrupted and the
    /// newest then answers, the older one is superseded with its import
    /// [`Started`](crate::ImportFlag::Started), and
    /// [`JournalStatus::interrupted_import`] stays true (no call abandons it yet,
    /// freenet/freenet-migrate#39).
    NewestSnapshotWinsContinuePastUnresponsive(RollbackRiskAck),
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
        matches!(
            self,
            SecretSelectionPolicy::NewestSnapshotWins
                | SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(_)
        ) && had_data
    }

    /// Whether an `Unresponsive` predecessor terminates the walk. Under plain
    /// `NewestSnapshotWins` it always does — falling through to import an older
    /// snapshot past an unknown newer state would risk resurrecting keys the newer
    /// generation deleted, or shadowing a value it holds. Union never does (it
    /// wants every generation regardless).
    ///
    /// `NewestSnapshotWinsContinuePastUnresponsive` opts out of the halt (see its
    /// docs and [`RollbackRiskAck`]) — **except** when `prior_saw_data` is `true`:
    /// a surviving [`MigrationMarker::InProgress`] with `saw_data: true` is
    /// positive proof, from an earlier run, that this predecessor holds real data,
    /// not merely silence on this attempt. Falling through in that case would
    /// let an older, definitely-inferior generation seal a `Done` marker while the
    /// known-data-bearing generation is only transiently unreachable — under the
    /// successor's never-clobber writer that seal can then permanently shadow the
    /// true value even after this predecessor becomes reachable again on a later
    /// run (see the variant's doc for the full scenario). A predecessor with no
    /// such history (the common case — a legacy generation that was simply never
    /// registered) still falls through, which is the whole point of the variant.
    fn unresponsive_terminates(&self, prior_saw_data: bool) -> bool {
        match self {
            SecretSelectionPolicy::NewestSnapshotWins => true,
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(_) => prior_saw_data,
            SecretSelectionPolicy::UnionAllGenerations(_) => false,
        }
    }

    /// How a **legacy generation-keyed** done marker (from the older
    /// [`crate::import_secrets_once`] API) seals a predecessor. See
    /// [`LegacyBridge`].
    fn legacy_bridge(&self) -> LegacyBridge {
        match self {
            SecretSelectionPolicy::NewestSnapshotWins
            | SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(_) => {
                LegacyBridge::AtOrAboveGeneration
            }
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

    /// The executability preflight with a third answer: **definitively not
    /// installed** (freenet/freenet-migrate#37). The walk calls this, not
    /// [`probe_executable`](Self::probe_executable).
    ///
    /// The default forwards to `probe_executable` and can only answer
    /// [`ProbeVerdict::Executable`] or [`ProbeVerdict::NoReply`] (`Ok(false)`), so
    /// an adapter that does not override it behaves exactly as before.
    ///
    /// Override it if the app's transport can tell "this node has no such
    /// delegate" from "it did not answer" — a typed node error, never a timeout.
    /// The walk treats [`ProbeVerdict::NotInstalled`] **exactly like a silence**
    /// (`Unresponsive`, same termination rule): a node answering "not installed"
    /// is not proof the predecessor holds nothing, since freenet-core unregisters
    /// a delegate without deleting its secrets and reports a failed WASM read the
    /// same way. The only difference is bookkeeping: a
    /// [`crate::MigrationJournal`] counts consecutive "not installed" answers, so
    /// the app can decide when to stop re-probing (see
    /// [`crate::JournalStatus::pending_all_absent`]).
    fn probe_verdict(
        &mut self,
        predecessor: &DelegateKey,
    ) -> impl Future<Output = Result<ProbeVerdict, Self::Error>> {
        let probe = self.probe_executable(predecessor);
        async move {
            probe.await.map(|executable| {
                if executable {
                    ProbeVerdict::Executable
                } else {
                    ProbeVerdict::NoReply
                }
            })
        }
    }

    /// Enumerate `predecessor`'s secrets as raw `(key, value)` pairs, via the
    /// app's own delegate protocol. Called only after
    /// [`probe_verdict`](Self::probe_verdict) answered
    /// [`ProbeVerdict::Executable`].
    ///
    /// **`Ok(vec![])` is a positive claim: "I asked, and it has nothing."** On a
    /// predecessor no earlier attempt saw data in, it seals the predecessor with a
    /// `Done { had_data: false }` marker that is never revisited, so returning it
    /// for a request that merely went unanswered records a slow or temporarily
    /// unreachable predecessor as permanently empty — silently, with the report
    /// reading complete. That is the data-loss default
    /// freenet/freenet-migrate#19 exists to stop. (After an attempt that saw data,
    /// the walk does not believe it: see
    /// [`PredecessorMigration::exported_nothing_after_data`].)
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

/// What the executability preflight established about a predecessor (see
/// [`PredecessorSecretsIo::probe_verdict`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeVerdict {
    /// It executed and answered the cheap no-op.
    Executable,
    /// No answer within the app's bound — the old WASM could not execute, the node
    /// does not have it, or the request was lost. Recorded as
    /// [`PredecessorMigration::Unresponsive`].
    NoReply,
    /// The node answered, definitively, that it has no such delegate installed.
    /// Only for a typed node answer, never for a timeout or an empty reply.
    /// Recorded as [`PredecessorMigration::Unresponsive`] exactly like
    /// [`NoReply`](Self::NoReply): it resolves nothing. A journal counts it in the
    /// predecessor's absent streak (see [`PredecessorSecretsIo::probe_verdict`]).
    NotInstalled,
}

/// A [`PredecessorSecretsIo`] that can also **register the successor delegate**,
/// for [`register_delegate_with_migration`].
///
/// Split from the base trait so [`migrate_delegate_secrets`] (migration only)
/// does not force callers to implement registration.
pub trait RegisterAndMigrateIo: PredecessorSecretsIo {
    /// Register the successor delegate with the node.
    ///
    /// Register with a plain `DelegateRequest::RegisterDelegate`; the copy-forward
    /// is then done client-side by [`migrate_delegate_secrets`].
    ///
    /// `predecessors`, `authorization`, and `policy` are passed through so that a
    /// future node-side copy-forward could run *at registration time*, at which
    /// point [`migrate_delegate_secrets`] would find the delegate-key markers
    /// already written and report every predecessor as already-migrated, a no-op,
    /// with no change to this wrapper's signature. No such wire exists today: the
    /// earlier `RegisterDelegateWithPredecessors` variant was removed in
    /// freenet-stdlib 0.9.0 because its authorization check was not effective
    /// (freenet-core#5199).
    ///
    /// **`predecessors` is supplied newest-generation-first** (guaranteed by
    /// [`register_delegate_with_migration`]); a node-side copy, if one is ever
    /// added, would need that order for newest-precedence.
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
    /// decision is **sticky-data** across retries: an empty-then-data retry
    /// upgrades to data, and a data-then-empty retry is not believed at all (it is
    /// reported `Unresponsive` and the marker stays, so a later run asks again).
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
    ///
    /// A journaled migration resolves a predecessor whose only blemish is
    /// permanent rejections, so it is not retried. If a `Permanent` verdict turns
    /// out to have been wrong, see [`crate::JournaledSuccessorIo::import_revision`].
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
    /// When both a `Done` and an `InProgress` marker are stored, `Done` wins —
    /// with one exception every implementation must honour: an
    /// `InProgress { saw_data: true }` beside a `Done { had_data: false }` reads
    /// as `InProgress { saw_data: true }`. A walk never writes that pair on its
    /// own account (its data flag is sticky); it means an import started after
    /// the empty seal
    /// ([`crate::note_app_import_started`], or a walk re-asking a predecessor a
    /// journal knows holds data), so the empty seal is wrong. Reading it as done
    /// would let a lost journal seal that import's missing items away.
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
    /// The walk calls it twice per imported predecessor:
    /// [`MigrationMarker::InProgress`] before the first item,
    /// [`MigrationMarker::Done`] only after every item and the flush succeeded.
    /// [`crate::note_app_import_started`] also records
    /// `InProgress { saw_data: true }`, possibly while a `Done { had_data: false }`
    /// is stored. Two rules for every implementation:
    ///
    /// * Recording `InProgress` must not erase a stored `Done` (keep them as
    ///   separate records): see [`migration_marker`](Self::migration_marker) for
    ///   how the pair reads back.
    /// * `InProgress { saw_data: false }` must not downgrade a stored
    ///   `InProgress { saw_data: true }`: another session may have recorded it
    ///   since this walk read the marker.
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
        let marker = if crate::delegate::empty_seal_contradicted(self.store, query.predecessor) {
            // An import started after an empty seal: the seal is wrong.
            Some(MigrationMarker::InProgress { saw_data: true })
        } else if let Some(value) = self.store.get_secret(&done) {
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
        // Sticky data: an in-progress marker that saw data is never downgraded
        // (another session may have recorded it since this walk read the marker).
        if matches!(marker, MigrationMarker::InProgress { saw_data: false })
            && self
                .store
                .get_secret(&key)
                .is_some_and(|v| v != PRED_DONE_MARKER_VALUE_EMPTY)
        {
            return core::future::ready(Ok(()));
        }
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
    /// [`crate::JournaledSuccessorIo::store_journal`] for the import-in-progress
    /// flag a journaled walk stores before a predecessor's first item. Nothing of
    /// that predecessor was written. (The flag may still be recorded by the run's
    /// final journal store: the predecessor did hold data.)
    JournalFlag,
    /// The journal could not be read or established, so
    /// [`crate::migrate_delegate_secrets_journaled`] did not walk at all. Every
    /// predecessor carries this, so a refused run never reads as complete.
    JournalUnavailable,
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
    /// got no reply or answered "not installed", or a probe/fetch round-trip
    /// errored (the error is stringified into `error`) — or it exported nothing
    /// although an earlier attempt saw data in it (see
    /// [`exported_nothing_after_data`](Self::exported_nothing_after_data): the
    /// successor may then hold a partial copy of it). Its data may exist but cannot
    /// be auto-migrated now. The app MUST surface this and MUST NOT treat the
    /// migration as a fresh install (freenet/river#204). See
    /// [`PredecessorSecretsIo::probe_executable`] for the registration/availability
    /// dependency this rests on.
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

/// The `Unresponsive` error the walk reports for a predecessor that exported
/// nothing although an earlier attempt saw data in it.
const EXPORTED_NOTHING_AFTER_DATA: &str = "exported nothing, but an earlier attempt saw data";
const EXPORTED_FEWER_AFTER_DATA: &str =
    "exported fewer items than an earlier attempt that started an import saw";

impl PredecessorMigration {
    /// Whether this is a predecessor that exported nothing although an earlier
    /// attempt saw data in it (its in-progress marker, or a migration journal,
    /// says so). Reported [`Unresponsive`](Self::Unresponsive) and never sealed,
    /// because a frozen predecessor does not lose data: the empty answer is the
    /// fault. Unlike an ordinary silence, the successor may hold a **partial
    /// copy** of this predecessor right now. Under `UnionAllGenerations` the walk
    /// still goes on to older generations, as for any unresponsive predecessor;
    /// an app that relies on halting there must check this.
    pub fn exported_nothing_after_data(&self) -> bool {
        matches!(
            self,
            PredecessorMigration::Unresponsive { error: Some(e), .. }
                if e == EXPORTED_NOTHING_AFTER_DATA
        )
    }

    /// Whether this is a predecessor that exported some items, but fewer than an
    /// earlier attempt that started an import from it saw (a migration journal
    /// records that count). Reported [`Unresponsive`](Self::Unresponsive) and
    /// never resolved, for the same reason as
    /// [`exported_nothing_after_data`](Self::exported_nothing_after_data): the
    /// successor may hold a partial copy, and the short answer is the fault.
    pub fn exported_fewer_after_data(&self) -> bool {
        matches!(
            self,
            PredecessorMigration::Unresponsive { error: Some(e), .. }
                if e.starts_with(EXPORTED_FEWER_AFTER_DATA)
        )
    }

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
/// then [`migrate_delegate_secrets`]. If a node-side copy-forward is ever added,
/// the registration would carry the predecessor list to the node and the
/// migration step would become a no-op, with this signature unchanged. No such
/// wire exists today (see [`RegisterAndMigrateIo::register_successor`]).
///
/// The predecessors handed to `register_successor` are sorted **newest-first**
/// here, the order a first-writer-wins node copy would need for
/// newest-precedence. The `SecretTransport` docs record what the removed v1
/// node copy did and did not guarantee.
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

/// Durably start a successor's [`MigrationJournal`] before the app's first
/// migration write (freenet/freenet-migrate#37).
///
/// Call it on **every** load, **before** anything — the walk, or an app's own
/// sweep — writes migrated data to the successor, or merges it into state a
/// later save would persist, and decide whether to run the walk from its status.
/// From then on
/// an interruption at any point leaves a pending journal behind, which is how
/// the next load knows the migration must run again. See the [`crate::journal`]
/// module docs.
///
/// * Nothing stored: stores a journal read off the markers. A predecessor with
///   a `Done` marker is resolved by it, one an earlier plain walk left mid-import
///   (a surviving [`MigrationMarker::InProgress`] that saw data) is flagged as an
///   import [`Started`](crate::ImportFlag::Started), and the rest are pending.
///   This reads one marker per predecessor (two behind a legacy seal), and a
///   marker that cannot be read refuses the start.
/// * A corrupt journal stored: rebuilds it the same way from the markers, which
///   record every import that started (the app's too, see
///   [`note_app_import_started`]).
/// * A readable journal stored: never reset, so resolutions and import flags
///   survive. It reads the marker of each predecessor resolved as holding
///   nothing of its data (one read each per call) and reopens one whose marker
///   records an import under way (a flag another session's stale store
///   overwrote). A marker that cannot be read there refuses nothing: the entry
///   is left as stored, and the returned status counts it as an import under way
///   for this load. Lineage entries it has never seen are read off their markers
///   and added. It stores only if it reopened or added something.
///
/// Returns the journal's status under `policy` and the successor's
/// [`import_revision`](JournaledSuccessorIo::import_revision).
///
/// # Errors
///
/// The journal (or, starting one or adding a lineage entry, a predecessor's
/// marker) could not be read or stored, or the journal was written by a build
/// with a different journal
/// encoding version (which this build never overwrites). Do not proceed with a
/// migration write: nothing durable would record it.
pub async fn begin_migration_journal<W>(
    successor: &mut W,
    predecessors: &[DelegateLineageEntry],
    policy: &SecretSelectionPolicy,
) -> Result<JournalStatus, JournalError>
where
    W: JournaledSuccessorIo,
    W::Error: core::fmt::Debug,
{
    let binding = JournalBinding::new(policy, successor.import_revision());
    let (started, checks) = start_journal(successor, predecessors, policy, &binding).await?;
    let mut journal = match started {
        Started::Existing(journal) => {
            return Ok(status_with_unverified(
                &journal,
                &checks.unverified,
                predecessors,
                &binding,
            ))
        }
        Started::New(journal) => journal,
    };
    store_merged(
        successor,
        &mut journal,
        Some(&binding),
        Some((predecessors, policy)),
    )
    .await?;
    Ok(status_with_unverified(
        &journal,
        &checks.unverified,
        predecessors,
        &binding,
    ))
}

/// The status to report: `journal`'s, with each predecessor whose marker could
/// not be read this load counted as an import under way. Never stored: the read
/// is retried on a later load, and a recovered read decides it.
fn status_with_unverified(
    journal: &MigrationJournal,
    unverified: &[(DelegateKey, u32)],
    predecessors: &[DelegateLineageEntry],
    binding: &JournalBinding,
) -> JournalStatus {
    if unverified.is_empty() {
        return journal.status(predecessors, binding);
    }
    let mut view = journal.clone();
    for (key, generation) in unverified {
        view.mark_import_started(key, *generation);
    }
    view.status(predecessors, binding)
}

/// Durably flag `predecessor` as having an import
/// [`Started`](crate::ImportFlag::Started) before the app writes data migrated
/// from it **outside** the walk (River's hand-rolled sweep), or merges it into
/// state a later save would persist. Call it only once the app holds data read
/// from the predecessor: a predecessor flagged this way that then answers
/// "nothing" is not believed. `predecessors` is the lineage the app passes to
/// [`begin_migration_journal`] and the walk: it decides the predecessor's
/// generation and which generations are newer, never the stored journal (which
/// a tab running another build may have numbered differently). Once per
/// predecessor per session is enough; each call costs two journal loads, a
/// journal store, two marker reads and a marker write, plus under a snapshot
/// policy one marker read per newer generation the journal does not already
/// show holding data.
///
/// `items`: how many items the app read from the predecessor, **in the walk's
/// unit**: the number of pairs the app's
/// [`PredecessorSecretsIo::fetch_secrets`] returns for it, not counting reserved
/// keys ([`crate::is_reserved_key`]). The journal keeps the largest count it is
/// given, and a later walk export with fewer items is not believed (#44). A
/// lower bound is safe (count only what you read for certain); a count larger
/// than the walk's export, in another unit (rooms where the export holds keys,
/// say) or counting an overridden journal key, keeps the predecessor pending
/// for good. Pass `None` if the app cannot count in that unit; its interrupted
/// import is then not protected against a short retry.
///
/// Records it twice: in the journal, and as the predecessor's in-progress
/// migration marker (`InProgress { saw_data: true }`), exactly as the walk does
/// before its own first item. So the walk treats the predecessor as known to
/// hold data, and a lost or corrupt journal is rebuilt with the flag (see the
/// marker contract on [`SuccessorSecretsIo::migration_marker`]). Until a
/// journaled walk resolves the predecessor as imported,
/// [`JournalStatus::interrupted_import`] reports that the successor may hold a
/// partial copy.
///
/// Returns [`AppImport::Flagged`](crate::AppImport::Flagged) when it recorded the
/// flag: write the data. For a predecessor whose import already completed (its
/// `Done` marker records data, or the journal resolves it with its data) it
/// records nothing and returns
/// [`AppImport::AlreadyImported`](crate::AppImport::AlreadyImported): the walk will
/// not offer it again, and whether to write it again (filling a gap, or bringing
/// back a key deleted since) is the app's call, set out on that variant.
///
/// Under a snapshot policy this holds the app to what the walk would import,
/// with one gap: under `NewestSnapshotWinsContinuePastUnresponsive` it refuses
/// past a newer generation only when it knows that generation holds data, while
/// the walk asks it first. So a sweep reads newer generations itself, newest
/// first, and stops at the first that holds data or that this errs on.
///
/// # Errors
///
/// No journal is stored, or it has no entry for the predecessor (call
/// [`begin_migration_journal`] with this lineage first); it cannot be read, is
/// corrupt or from a different encoding version; a marker cannot be read; or the
/// flag or the marker could not be stored. Do not write: a kill mid-write would
/// leave a partial copy nothing records.
///
/// [`JournalError::NotImportable`]: do not write from the predecessor on this
/// call. It is not in `predecessors` (permanent: check the app's lineage); a
/// snapshot policy supersedes it, because a newer generation holds data (the journal
/// shows it resolved with data, an import from it under way, or a rejection a
/// higher revision reopened; or its own marker records data) or only a legacy
/// seal for a newer generation covers this one; or, under plain
/// `NewestSnapshotWins`, a newer generation has not answered that it holds
/// nothing. The last clears once that generation answers "nothing" (its empty
/// seal); if it never answers, it never clears, and the walk halts there too.
/// Treat every `Err` alike: skip this predecessor now, and try again on a later
/// load. Under a snapshot policy, skip every older one for this load too: the
/// walk does not go past a newer generation it has not dealt with.
pub async fn note_app_import_started<W>(
    successor: &mut W,
    predecessors: &[DelegateLineageEntry],
    predecessor: &DelegateKey,
    policy: &SecretSelectionPolicy,
    items: Option<u32>,
) -> Result<crate::journal::AppImport, JournalError>
where
    W: JournaledSuccessorIo,
    W::Error: core::fmt::Debug,
{
    let begin_first =
        |why: &str| JournalError::Successor(format!("{why}; call begin_migration_journal first"));
    let Some(generation) = predecessors
        .iter()
        .find(|e| lineage_key(e) == *predecessor)
        .map(|e| e.generation)
    else {
        return Err(JournalError::NotImportable(
            "the predecessor is not in the lineage".to_string(),
        ));
    };
    let mut journal = match successor
        .load_journal()
        .await
        .map_err(|e| JournalError::Successor(format!("journal load failed: {e:?}")))?
    {
        Some(bytes) => match MigrationJournal::decode(&bytes) {
            Ok(journal) => journal,
            Err(JournalDecodeError::UnknownVersion(v)) => {
                return Err(JournalError::ForeignVersion(v))
            }
            Err(JournalDecodeError::Corrupt(e)) => {
                return Err(begin_first(&format!("stored journal is corrupt ({e})")))
            }
        },
        // Starting one here would skip `begin`'s marker seeding.
        None => return Err(begin_first("no journal is stored")),
    };
    if journal.entry(predecessor).is_none() {
        return Err(begin_first("the journal has no entry for the predecessor"));
    }
    // Under a snapshot policy the app may import from this generation only where
    // the walk would. A newer generation that holds data is the authoritative
    // snapshot: the walk imports it instead, and the app's older values would
    // shadow it under a never-clobber writer. And under plain `NewestSnapshotWins`
    // the walk does not look past a newer generation until it has answered that
    // it holds nothing. The journal is read first, as stored (before this binding
    // reopens anything: a rejection a higher revision reopened still holds the
    // rest of its data), so a marker is read only where the journal does not
    // decide; then each undecided generation's own marker (a flag another
    // session's stale store erased, or a seal the journal never recorded).
    if matches!(
        crate::journal::PolicyFamily::of(policy),
        crate::journal::PolicyFamily::NewestSnapshot
    ) {
        let superseded = |newer: u32| {
            Err(JournalError::NotImportable(format!(
                "generation {newer} holds the authoritative snapshot under the snapshot policy"
            )))
        };
        let mut undecided = Vec::new();
        for newer in predecessors.iter().filter(|e| e.generation > generation) {
            let state = journal.entry(&lineage_key(newer)).map(|e| e.state);
            match state {
                Some(JournalState::Resolved(r)) if r.is_data_bearing() => {
                    return superseded(newer.generation)
                }
                Some(JournalState::Pending {
                    import, rejected, ..
                }) if import == crate::journal::ImportFlag::Started || rejected > 0 => {
                    return superseded(newer.generation)
                }
                _ => undecided.push(newer),
            }
        }
        for newer in undecided {
            let marker = exact_marker(successor, &lineage_key(newer), newer.generation)
                .await
                .map_err(|e| {
                    JournalError::Successor(format!(
                        "marker read failed for a newer generation: {e:?}"
                    ))
                })?;
            // Only its empty seal says it answered "nothing": the walk asks again
            // wherever that seal is missing, whatever the journal says.
            let answered_empty = match marker {
                Some(
                    MigrationMarker::InProgress { saw_data: true }
                    | MigrationMarker::Done { had_data: true },
                ) => return superseded(newer.generation),
                Some(MigrationMarker::Done { had_data: false }) => true,
                _ => false,
            };
            if !answered_empty && policy.unresponsive_terminates(false) {
                return Err(JournalError::NotImportable(format!(
                    "generation {} has not answered that it holds nothing, and \
                     NewestSnapshotWins does not import past it (until it does, which it \
                     may never)",
                    newer.generation
                )));
            }
        }
    }
    let binding = JournalBinding::new(policy, successor.import_revision());
    journal.rebind(&binding);
    // Already imported, as the journal records it under this binding (an import
    // with rejections at the current revision has no `Done` marker): the walk does
    // not offer it again. Nothing is recorded; whether to write it again is the
    // app's call (see `AppImport::AlreadyImported`).
    if matches!(
        journal.entry(predecessor).map(|e| e.state),
        Some(JournalState::Resolved(r)) if r.is_data_bearing()
    ) {
        return Ok(crate::journal::AppImport::AlreadyImported);
    }
    let query = MarkerQuery {
        predecessor,
        generation,
        legacy_bridge: policy.legacy_bridge(),
    };
    let marker = successor
        .migration_marker(&query)
        .await
        .map_err(|e| JournalError::Successor(format!("marker read failed: {e:?}")))?;
    if matches!(marker, Some(MigrationMarker::Done { had_data: true })) {
        if policy.legacy_bridge() == LegacyBridge::AtOrAboveGeneration
            && !matches!(
                exact_marker(successor, predecessor, generation)
                    .await
                    .map_err(|e| JournalError::Successor(format!("marker read failed: {e:?}")))?,
                Some(MigrationMarker::Done { had_data: true })
            )
        {
            // A legacy seal for a NEWER generation: under this snapshot policy
            // this generation is superseded, not imported. Writing its data would
            // leave a partial copy nothing can record (the flag's read-back would
            // read the seal again).
            return Err(JournalError::NotImportable(
                "a legacy seal for a newer generation supersedes it under the snapshot \
                 policy"
                    .to_string(),
            ));
        }
        return Ok(crate::journal::AppImport::AlreadyImported);
    }
    // The journal first: a kill before the marker leaves the flag, which the walk
    // honours on its own; the other order would leave a journal still reading the
    // predecessor resolved.
    let flagged = journal.mark_import_started(predecessor, generation);
    let counted = items.is_some_and(|n| journal.note_items_seen(predecessor, n));
    if flagged || counted {
        store_merged(successor, &mut journal, Some(&binding), None).await?;
        // The store's re-read can bring in another session's resolution of it.
        if matches!(
            journal.entry(predecessor).map(|e| e.state),
            Some(JournalState::Resolved(r)) if r.is_data_bearing()
        ) {
            return Ok(crate::journal::AppImport::AlreadyImported);
        }
    }
    successor
        .record_marker(predecessor, MigrationMarker::InProgress { saw_data: true })
        .await
        .map_err(|e| JournalError::Successor(format!("in-progress marker failed: {e:?}")))?;
    // The marker must read back as recorded (the `migration_marker` contract), or
    // a lost journal would strand what the app is about to write.
    match successor.migration_marker(&query).await {
        Ok(Some(MigrationMarker::InProgress { saw_data: true })) => {
            Ok(crate::journal::AppImport::Flagged)
        }
        other => Err(JournalError::Successor(format!(
            "the marker store reads {other:?} after recording an in-progress data marker \
             (see the SuccessorSecretsIo::migration_marker contract)"
        ))),
    }
}

/// The result of [`migrate_delegate_secrets_journaled`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournaledMigrationReport {
    /// What the walk did, exactly as [`migrate_delegate_secrets`] reports it. When
    /// the walk was refused, every predecessor is `WriterUnavailable` (see
    /// [`journal_error`](Self::journal_error)), so it never reads as complete.
    pub report: DelegateMigrationReport,
    /// The stored journal's completeness after this run, under the run's policy
    /// and the successor's import revision, with any predecessor whose marker
    /// could not be read to check it counted as an import under way. `None` when
    /// it is not known to be stored: the walk was refused, or the final store
    /// failed. Treat `None` as possibly incomplete.
    pub status: Option<JournalStatus>,
    /// The first journal failure, if any.
    ///
    /// * The journal could not be read or started, or is from a different
    ///   encoding version: **the walk was refused** (nothing written), every
    ///   predecessor is `WriterUnavailable` (stage
    ///   [`WriterStage::JournalUnavailable`]) and `status` is `None`.
    /// * A predecessor's import flag could not be stored: that predecessor is
    ///   `WriterUnavailable` (stage [`WriterStage::JournalFlag`]), nothing of it
    ///   was written, and the walk stopped there.
    /// * The final store failed: the migration ran, but what it resolved was not
    ///   recorded, so `status` is `None` and the next load re-runs.
    pub journal_error: Option<String>,
}

/// [`migrate_delegate_secrets`], recording each predecessor's resolution in the
/// successor's [`MigrationJournal`] (freenet/freenet-migrate#37).
///
/// The walk is the ordinary one — same order, policy, markers, writer seam and
/// report. What this adds is durable bookkeeping around it:
///
/// 1. The journal is loaded, or started (as [`begin_migration_journal`] does),
///    before the walk writes anything. If that fails the walk does not run.
/// 2. Resolutions that do not hold under this run's policy family and
///    [`import_revision`](JournaledSuccessorIo::import_revision) are reopened.
/// 3. Before a data-bearing predecessor's first item its entry is durably flagged
///    as an import started; if that store fails, the walk stops before writing
///    anything of it.
/// 4. After the walk each predecessor's outcome resolves its entry or counts an
///    unresolved attempt (table in the [`crate::journal`] module docs). Every
///    predecessor whose marker neither the walk nor the start read (behind a
///    halt, a failed read, a legacy-bridged seal, a supersession) is then
///    checked against its own marker, so a flag another session's stale store
///    overwrote is restored, and one that cannot be read counts as an import
///    under way in the returned status. The journal is stored with
///    read-merge-write.
///
/// The app calls [`begin_migration_journal`] on every load, and this while the
/// status is incomplete. That is safe to repeat:
/// completed predecessors are skipped by their markers, and a retried predecessor
/// re-offers its items to a writer that must merge (see [`SuccessorSecretsIo`]).
///
/// Parameters are those of [`migrate_delegate_secrets`].
pub async fn migrate_delegate_secrets_journaled<W, IO>(
    successor: &mut W,
    io: &mut IO,
    predecessors: &[DelegateLineageEntry],
    authorization: MigrationAuthorization,
    policy: SecretSelectionPolicy,
) -> JournaledMigrationReport
where
    W: JournaledSuccessorIo,
    W::Error: core::fmt::Debug,
    IO: PredecessorSecretsIo,
    IO::Error: core::fmt::Debug,
{
    // A refused run never reads as complete: every predecessor is reported
    // unmigrated, newest first like the walk.
    let refused = |error: String| {
        let mut rows: Vec<&DelegateLineageEntry> = predecessors.iter().collect();
        rows.sort_by_key(|e| core::cmp::Reverse(e.generation));
        JournaledMigrationReport {
            report: DelegateMigrationReport {
                predecessors: rows
                    .into_iter()
                    .map(|e| PredecessorMigration::WriterUnavailable {
                        key: DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash)),
                        generation: e.generation,
                        failure: WriterFailure {
                            stage: WriterStage::JournalUnavailable,
                            error: error.clone(),
                        },
                    })
                    .collect(),
            },
            status: None,
            journal_error: Some(error),
        }
    };
    let binding = JournalBinding::new(&policy, successor.import_revision());

    // 1. Load or start, failing closed.
    let (started, mut checks) =
        match start_journal(successor, predecessors, &policy, &binding).await {
            Err(e) => return refused(e.to_string()),
            Ok(started) => started,
        };
    let mut journal = match started {
        Started::Existing(journal) => journal,
        Started::New(mut journal) => {
            if let Err(e) = store_merged(
                successor,
                &mut journal,
                Some(&binding),
                Some((predecessors, &policy)),
            )
            .await
            {
                return refused(format!("journal start failed: {e}"));
            }
            journal
        }
    };

    // 2. The working copy, as it applies under this run's binding.
    journal.rebind(&binding);

    // 3. The walk, flagging each data-bearing import durably before it writes.
    let mut journal_error: Option<String> = None;
    let mut observer = JournalObserver {
        journal_key: successor.journal_key().to_vec(),
        journal: &mut journal,
        binding,
        predecessors,
        policy: &policy,
        first_error: &mut journal_error,
    };
    let mut transport = AppSideRoundTrip { io };
    let outcome = transport
        .walk(
            successor,
            predecessors,
            &authorization,
            &policy,
            &mut observer,
        )
        .await;

    // 4. Resolve.
    let outcomes = resolve_outcomes(&outcome, &policy, binding.import_revision);
    for (row, run_outcome) in outcome.report.predecessors.iter().zip(&outcomes) {
        journal.record(row.key(), row.generation(), *run_outcome);
    }

    // 5. Check against its own marker every predecessor whose marker neither the
    // walk nor the start read: rows behind a halt, the row whose read failed, a
    // seal read only through a legacy bridge, and rows the journal short-cut.
    // One that says no import is under way, or that its data is not in the
    // successor, while its marker records an import (a journal flag another
    // session's stale store overwrote) is flagged again. A marker that cannot be
    // read is unverified, as at the start.
    let mut reached = Vec::new();
    for row in &outcome.report.predecessors {
        let key = row.key();
        let key_bytes = crate::journal::key_bytes(key);
        let walk_read_it = !matches!(row, PredecessorMigration::Superseded { .. })
            && !matches!(
                row,
                PredecessorMigration::WriterUnavailable { failure, .. }
                    if failure.stage == WriterStage::ReadMarker
            )
            && !outcome.bridged.contains(&key_bytes)
            && !outcome.journal_resolved.contains_key(&key_bytes);
        if walk_read_it {
            reached.push(key.clone());
            continue;
        }
        if checks.read.contains(key) {
            continue;
        }
        let unchecked = match journal.entry(key).map(|e| e.state) {
            Some(JournalState::Pending {
                import: crate::journal::ImportFlag::None,
                ..
            }) => true,
            Some(JournalState::Resolved(r)) => !r.is_data_bearing(),
            _ => false,
        };
        if !unchecked {
            continue;
        }
        match exact_marker(successor, key, row.generation()).await {
            Ok(marker) => {
                checks.unverified.retain(|(k, _)| k != key);
                if matches!(marker, Some(MigrationMarker::InProgress { saw_data: true })) {
                    journal.mark_import_started(key, row.generation());
                }
            }
            Err(_) => {
                if !checks.unverified.iter().any(|(k, _)| k == key) {
                    checks.unverified.push((key.clone(), row.generation()));
                }
            }
        }
    }
    checks.unverified.retain(|(key, _)| !reached.contains(key));

    // 6. Store with read-merge-write.
    let status = match store_merged(
        successor,
        &mut journal,
        Some(&binding),
        Some((predecessors, &policy)),
    )
    .await
    {
        Ok(()) => Some(status_with_unverified(
            &journal,
            &checks.unverified,
            predecessors,
            &binding,
        )),
        Err(e) => {
            if journal_error.is_none() {
                journal_error = Some(e.to_string());
            }
            None
        }
    };

    JournaledMigrationReport {
        status,
        report: outcome.report,
        journal_error,
    }
}

/// Whether a `Done { had_data: true }` read under a snapshot policy holds only
/// through the legacy at-or-above bridge: a pre-0.5 generation-keyed marker for
/// a NEWER generation, standing for "a newer authoritative snapshot was
/// migrated", not "this generation was imported". Such a seal is journalled as
/// superseded (which reopens under Union), never as imported. A read error counts
/// as bridged, the reopenable side.
async fn seal_is_bridged<W: SuccessorSecretsIo>(
    successor: &mut W,
    predecessor: &DelegateKey,
    generation: u32,
    policy: &SecretSelectionPolicy,
) -> bool {
    if policy.legacy_bridge() != LegacyBridge::AtOrAboveGeneration {
        return false;
    }
    !matches!(
        exact_marker(successor, predecessor, generation).await,
        Ok(Some(MigrationMarker::Done { had_data: true }))
    )
}

/// `predecessor`'s own marker, ignoring any legacy at-or-above seal: what is
/// recorded for THIS generation (an in-progress import the bridge would hide,
/// say).
async fn exact_marker<W: SuccessorSecretsIo>(
    successor: &mut W,
    predecessor: &DelegateKey,
    generation: u32,
) -> Result<Option<MigrationMarker>, W::Error> {
    let exact = MarkerQuery {
        predecessor,
        generation,
        legacy_bridge: LegacyBridge::ExactGenerationOnly,
    };
    successor.migration_marker(&exact).await
}

fn lineage_key(e: &DelegateLineageEntry) -> DelegateKey {
    DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash))
}

/// What [`start_journal`] found.
enum Started {
    /// A readable journal is stored, and nothing in it needs changing.
    Existing(MigrationJournal),
    /// None (or a corrupt one) is stored, or the stored one needed entries added
    /// or reopened from the markers: this one must be stored before any migration
    /// write.
    New(MigrationJournal),
}

/// Which predecessors' markers [`start_journal`] read to check the journal.
#[derive(Default)]
struct MarkerChecks {
    /// Read: the journal agrees with them.
    read: Vec<DelegateKey>,
    /// Could not be read to check a stored resolution: the caller reports each as
    /// an import under way for this load, without storing that.
    unverified: Vec<(DelegateKey, u32)>,
}

/// Load the stored journal, or build the one to start with, for `begin` and the
/// journaled walk alike. Never stores anything.
async fn start_journal<W>(
    successor: &mut W,
    predecessors: &[DelegateLineageEntry],
    policy: &SecretSelectionPolicy,
    binding: &JournalBinding,
) -> Result<(Started, MarkerChecks), JournalError>
where
    W: JournaledSuccessorIo,
    W::Error: core::fmt::Debug,
{
    match successor
        .load_journal()
        .await
        .map_err(|e| JournalError::Successor(format!("journal load failed: {e:?}")))?
    {
        Some(bytes) => match MigrationJournal::decode(&bytes) {
            Ok(mut journal) => {
                // A resolution saying the predecessor's data is NOT in the
                // successor, contradicted by its marker (an import started since,
                // whose journal flag another session's store overwrote): reopen it.
                // Only such entries are read, one marker each per call. A read
                // that fails refuses nothing (a stuck marker on an older
                // predecessor must not stop the newer ones migrating; the walk
                // itself still halts at a pending one it cannot read); the entry is
                // left as stored and reported unverified.
                let mut changed = false;
                let mut checks = MarkerChecks::default();
                for e in predecessors {
                    let key = DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash));
                    let non_data = matches!(
                        journal.entry(&key).map(|x| x.state),
                        Some(JournalState::Resolved(r)) if !r.is_data_bearing()
                    );
                    if !non_data {
                        continue;
                    }
                    match exact_marker(successor, &key, e.generation).await {
                        Ok(marker) => {
                            if matches!(
                                marker,
                                Some(MigrationMarker::InProgress { saw_data: true })
                            ) {
                                changed |= journal.mark_import_started(&key, e.generation);
                            }
                            checks.read.push(key);
                        }
                        Err(_) => checks.unverified.push((key, e.generation)),
                    }
                }
                // Lineage entries the stored journal has never seen (the lineage
                // grew) are read off their markers, as a fresh journal's are, and
                // the loaded journal is merged in (so a store whose re-read misses
                // cannot drop what it held).
                let unseen: Vec<DelegateLineageEntry> = predecessors
                    .iter()
                    .filter(|e| {
                        journal
                            .entry(&DelegateKey::new(
                                e.delegate_key,
                                CodeHash::new(e.code_hash),
                            ))
                            .is_none()
                    })
                    .copied()
                    .collect();
                if unseen.is_empty() {
                    return Ok((
                        if changed {
                            Started::New(journal)
                        } else {
                            Started::Existing(journal)
                        },
                        checks,
                    ));
                }
                let mut seeded = fresh_journal(successor, &unseen, policy).await?;
                seeded.merge_stored(&journal, Some(binding));
                checks.read.extend(unseen.iter().map(lineage_key));
                Ok((Started::New(seeded), checks))
            }
            Err(JournalDecodeError::UnknownVersion(v)) => Err(JournalError::ForeignVersion(v)),
            // A fresh journal is read off every predecessor's marker.
            Err(JournalDecodeError::Corrupt(_)) => Ok((
                Started::New(fresh_journal(successor, predecessors, policy).await?),
                MarkerChecks {
                    read: predecessors.iter().map(lineage_key).collect(),
                    unverified: Vec::new(),
                },
            )),
        },
        None => Ok((
            Started::New(fresh_journal(successor, predecessors, policy).await?),
            MarkerChecks {
                read: predecessors.iter().map(lineage_key).collect(),
                unverified: Vec::new(),
            },
        )),
    }
}

/// The journal a successor with none (or a corrupt one) stored starts from, read
/// off the migration markers: a predecessor with a `Done` marker resolved as the
/// walk resolves `AlreadyMigrated`; one whose marker says an import saw data and
/// did not finish (an earlier plain walk's, a journaled walk's, or the app's, see
/// [`note_app_import_started`]) pending with an import
/// [`Started`](crate::ImportFlag::Started); the rest pending. That is the state of
/// a successor adopting the journal after [`migrate_delegate_secrets`] runs, and
/// all a corrupt journal said about partial copies.
async fn fresh_journal<W>(
    successor: &mut W,
    predecessors: &[DelegateLineageEntry],
    policy: &SecretSelectionPolicy,
) -> Result<MigrationJournal, JournalError>
where
    W: JournaledSuccessorIo,
    W::Error: core::fmt::Debug,
{
    let mut journal = MigrationJournal::new_pending(predecessors);
    for e in predecessors {
        let key = DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash));
        let query = MarkerQuery {
            predecessor: &key,
            generation: e.generation,
            legacy_bridge: policy.legacy_bridge(),
        };
        // A marker that cannot be read leaves the start undecidable: fail closed
        // rather than guess, as the walk itself does on a marker fault.
        match successor.migration_marker(&query).await {
            Ok(Some(MigrationMarker::InProgress { saw_data: true })) => {
                journal.mark_import_started(&key, e.generation);
            }
            // A completion an earlier (plain) walk sealed, resolved as the walk
            // would resolve its `AlreadyMigrated`, so nothing treats it as owed.
            Ok(Some(MigrationMarker::Done { had_data: false })) => journal.record(
                &key,
                e.generation,
                RunOutcome::Resolved(JournalResolution::NoData),
            ),
            Ok(Some(MigrationMarker::Done { had_data: true })) => {
                // Under a snapshot policy the seal may hold only through a legacy
                // marker for a NEWER generation (superseded, not imported), and that
                // seal can hide this generation's own in-progress import. One exact
                // read decides; it fails closed like the read above.
                let exact = if policy.legacy_bridge() == LegacyBridge::AtOrAboveGeneration {
                    exact_marker(successor, &key, e.generation)
                        .await
                        .map_err(|err| {
                            JournalError::Successor(format!(
                                "marker read failed while starting the journal: {err:?}"
                            ))
                        })?
                } else {
                    Some(MigrationMarker::Done { had_data: true })
                };
                match exact {
                    Some(MigrationMarker::Done { had_data: true }) => journal.record(
                        &key,
                        e.generation,
                        RunOutcome::Resolved(JournalResolution::Imported),
                    ),
                    Some(MigrationMarker::InProgress { saw_data: true }) => {
                        journal.mark_import_started(&key, e.generation);
                    }
                    _ => journal.record(
                        &key,
                        e.generation,
                        RunOutcome::Resolved(JournalResolution::SupersededByAuthoritative),
                    ),
                }
            }
            Ok(_) => {}
            Err(err) => {
                return Err(JournalError::Successor(format!(
                    "marker read failed while starting the journal: {err:?}"
                )))
            }
        }
    }
    Ok(journal)
}

/// Store `journal` after merging in whatever is stored now (read-merge-write),
/// so a concurrent session's flags and resolutions are not erased.
///
/// With a `binding`, both sides merge as they apply under it, so a resolution
/// that no longer holds cannot win. Refuses to overwrite a journal from a
/// different encoding version, and to store over one that could not be read. A
/// journal found corrupt at the re-read may have held another session's flags:
/// with the lineage and policy known it is rebuilt from the markers and merged
/// in, and otherwise the store is refused.
async fn store_merged<W>(
    successor: &mut W,
    journal: &mut MigrationJournal,
    binding: Option<&JournalBinding>,
    rebuild: Option<(&[DelegateLineageEntry], &SecretSelectionPolicy)>,
) -> Result<(), JournalError>
where
    W: JournaledSuccessorIo,
    W::Error: core::fmt::Debug,
{
    match successor.load_journal().await {
        Err(e) => {
            return Err(JournalError::Successor(format!(
                "journal re-read before store failed: {e:?}"
            )))
        }
        Ok(Some(bytes)) => match MigrationJournal::decode(&bytes) {
            Ok(stored) => journal.merge_stored(&stored, binding),
            Err(JournalDecodeError::UnknownVersion(v)) => {
                return Err(JournalError::ForeignVersion(v))
            }
            Err(JournalDecodeError::Corrupt(e)) => match rebuild {
                Some((lineage, policy)) => {
                    let rebuilt = fresh_journal(successor, lineage, policy).await?;
                    journal.merge_stored(&rebuilt, binding)
                }
                None => {
                    return Err(JournalError::Successor(format!(
                        "stored journal is corrupt ({e}); call begin_migration_journal first"
                    )))
                }
            },
        },
        Ok(None) => {}
    }
    successor
        .store_journal(&journal.encode())
        .await
        .map_err(|e| JournalError::Successor(format!("journal store failed: {e:?}")))
}

struct JournalObserver<'j> {
    journal: &'j mut MigrationJournal,
    journal_key: Vec<u8>,
    binding: JournalBinding,
    predecessors: &'j [DelegateLineageEntry],
    policy: &'j SecretSelectionPolicy,
    first_error: &'j mut Option<String>,
}

impl<W> WalkObserver<W> for JournalObserver<'_>
where
    W: JournaledSuccessorIo,
    W::Error: core::fmt::Debug,
{
    fn journaled(&self) -> bool {
        true
    }

    fn withholds(&self, key: &[u8]) -> bool {
        self.journal_key == key
    }

    fn resolved_with_data(&self, predecessor: &DelegateKey) -> Option<JournalResolution> {
        // The working copy is already evaluated under the run's binding.
        match self.journal.entry(predecessor).map(|e| e.state) {
            Some(JournalState::Resolved(r)) if r.is_data_bearing() => Some(r),
            _ => None,
        }
    }

    fn import_started(&self, predecessor: &DelegateKey) -> bool {
        matches!(
            self.journal.entry(predecessor).map(|e| e.state),
            Some(JournalState::Pending {
                import: crate::journal::ImportFlag::Started,
                ..
            })
        )
    }

    fn items_seen(&self, predecessor: &DelegateKey) -> u32 {
        self.journal.items_seen(predecessor)
    }

    async fn before_import(
        &mut self,
        successor: &mut W,
        predecessor: &DelegateKey,
        generation: u32,
        items: Option<u32>,
    ) -> Result<(), String> {
        // A retry (an import already under way) re-reads the stored journal before
        // its first item even when nothing here changes, so a larger count
        // another session stored since this run loaded the journal holds it.
        let retry = items.is_some()
            && matches!(
                self.journal.entry(predecessor).map(|e| e.state),
                Some(JournalState::Pending {
                    import: crate::journal::ImportFlag::Started,
                    ..
                })
            );
        let flagged = self.journal.mark_import_started(predecessor, generation);
        let counted = items.is_some_and(|n| self.journal.note_items_seen(predecessor, n));
        if !flagged && !counted && !retry {
            return Ok(());
        }
        match store_merged(
            successor,
            self.journal,
            Some(&self.binding),
            Some((self.predecessors, self.policy)),
        )
        .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                let e = format!("journal import flag failed: {e}");
                if self.first_error.is_none() {
                    *self.first_error = Some(e.clone());
                }
                Err(e)
            }
        }
    }
}

/// Map one walk's rows to journal outcomes, newest first, per the table in the
/// [`crate::journal`] module docs.
fn resolve_outcomes(
    outcome: &WalkOutcome,
    policy: &SecretSelectionPolicy,
    import_revision: u32,
) -> Vec<RunOutcome> {
    let snapshot_policy = matches!(
        crate::journal::PolicyFamily::of(policy),
        crate::journal::PolicyFamily::NewestSnapshot
    );
    let mut resolved: Vec<Option<JournalResolution>> = Vec::new();
    let mut outcomes = Vec::new();
    for row in &outcome.report.predecessors {
        let key = crate::journal::key_bytes(row.key());
        // Short-circuited by the journal's own resolution: keep it as it is.
        if let Some(r) = outcome.journal_resolved.get(&key) {
            outcomes.push(RunOutcome::Unexamined);
            resolved.push(Some(*r));
            continue;
        }
        // A legacy at-or-above seal: this generation is superseded by the newer
        // authoritative snapshot the legacy marker stands for, which also
        // supersedes everything older behind it in this run.
        if outcome.bridged.contains(&key) {
            outcomes.push(RunOutcome::Resolved(
                JournalResolution::SupersededByAuthoritative,
            ));
            resolved.push(Some(JournalResolution::Imported));
            continue;
        }
        let resolution = match row {
            PredecessorMigration::Imported { .. } => Some(JournalResolution::Imported),
            PredecessorMigration::NoData { .. } => Some(JournalResolution::NoData),
            PredecessorMigration::AlreadyMigrated { .. } => {
                Some(if outcome.done_with_data.contains(&key) {
                    JournalResolution::Imported
                } else {
                    JournalResolution::NoData
                })
            }
            // Only permanent rejection may resolve an incomplete import: a retry
            // would be refused identically, so pending would loop forever. A
            // retryable failure, a withheld key, or a flush / marker fault is
            // exactly what a retry fixes, so those stay pending.
            PredecessorMigration::Incomplete { tally, failure, .. }
                if tally.rejected > 0
                    && tally.failed == 0
                    && tally.withheld == 0
                    && failure
                        .as_ref()
                        .is_none_or(|f| matches!(f.stage, WriterStage::Item)) =>
            {
                Some(JournalResolution::ImportedWithRejections {
                    rejected: u32::try_from(tally.rejected).unwrap_or(u32::MAX),
                    revision: import_revision,
                    items_seen: 0,
                })
            }
            // Superseded only resolves when THIS run proves why: under a snapshot
            // policy, a newer predecessor resolved data-bearing. A snapshot policy
            // terminates at its FIRST data-bearing predecessor, so if one is newer
            // than this row it is what superseded it, and this generation would
            // never be imported however the rest resolve. Anything else (an
            // unresponsive newer one under plain `NewestSnapshotWins`, a
            // `WriterUnavailable` halt) left it unexamined. Union never supersedes
            // for authority, only behind a `WriterUnavailable` halt, so it never
            // resolves here even when a newer generation imported.
            PredecessorMigration::Superseded { .. }
                if snapshot_policy && resolved.iter().flatten().any(|r| r.is_data_bearing()) =>
            {
                Some(JournalResolution::SupersededByAuthoritative)
            }
            _ => None,
        };
        outcomes.push(match (resolution, row) {
            (Some(r), _) => RunOutcome::Resolved(r),
            // Never asked: behind a halt, or the successor failed before the probe.
            (
                None,
                PredecessorMigration::Superseded { .. }
                | PredecessorMigration::WriterUnavailable { .. },
            ) => RunOutcome::Unexamined,
            (None, _) => RunOutcome::Unresolved {
                absent: matches!(row, PredecessorMigration::Unresponsive { .. })
                    && outcome.not_installed.contains(&key),
            },
        });
        resolved.push(resolution);
    }
    outcomes
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
/// 2. On a node with a copy-forward primitive (none exists today; see below),
///    registration would copy each
///    predecessor's secrets into the successor **internally, without executing
///    old code**, and write the **same** public `pred-done` marker
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
/// ## What the removed v1 node copy did — and did NOT — guarantee
///
/// History, kept because it constrains any successor design. The v1 wire
/// (`RegisterDelegateWithPredecessors`, stdlib 0.8.4 and 0.8.5, removed in 0.9.0)
/// carried only `Vec<DelegateKey>` (no generations, no policy). The node copied
/// in the supplied order, **first-writer-wins**, so with a newest-first list it
/// was **union-with-newest-precedence**: every predecessor copied, the newest
/// value winning a key conflict. It therefore did **not** implement
/// [`SecretSelectionPolicy::NewestSnapshotWins`]'s stop-at-first-data-bearing /
/// delete-by-absence preservation. A future node-side copy would need a wire
/// that carries generations and policy to close that gap. Today the app-side
/// round-trip is the only path, so `policy` always applies.
///
/// So the app-facing entry points are unchanged, the shared `pred-done` markers
/// are the interoperability contract, and the app-side round-trip is the only
/// path today: no node offers a copy-forward primitive, and none is planned
/// until a new authorization design exists (freenet-core#5199). Intentionally
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
pub(crate) struct AppSideRoundTrip<'a, IO> {
    pub(crate) io: &'a mut IO,
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
        self.walk(
            successor,
            predecessors,
            authorization,
            policy,
            &mut NoObserver,
        )
        .await
        .report
    }
}

/// Hook into the walk for the journaled entry point. The plain entry points use
/// [`NoObserver`].
pub(crate) trait WalkObserver<W> {
    /// Whether a journal records this walk's outcomes (so a legacy seal must be
    /// told apart from an import, at the cost of one extra marker read).
    fn journaled(&self) -> bool;

    /// Whether an item with this key must never be offered to the writer (beyond
    /// the crate's reserved namespace, which is always withheld).
    fn withholds(&self, key: &[u8]) -> bool;

    /// A resolution a journal holds for `predecessor` that puts its data in the
    /// successor, valid under the run's binding. The walk then does not walk it
    /// again.
    fn resolved_with_data(&self, predecessor: &DelegateKey) -> Option<JournalResolution>;

    /// Whether an import from `predecessor` is already known to have started,
    /// though no in-progress marker may say so (the app announced it, or a tab
    /// died between the journal flag and the marker).
    fn import_started(&self, predecessor: &DelegateKey) -> bool;

    /// The most items an earlier attempt that started an import from
    /// `predecessor` saw it export (`0` when unknown). An export with fewer is
    /// not believed.
    fn items_seen(&self, predecessor: &DelegateKey) -> u32;

    /// Called before anything is written from a predecessor known to hold data:
    /// before probing one known to hold data from an earlier import (its
    /// import started, or a count was kept; `items` unknown), and
    /// before the in-progress marker and first item of every data-bearing import
    /// (`items`: how many this export holds). `Err` vetoes it.
    fn before_import(
        &mut self,
        successor: &mut W,
        predecessor: &DelegateKey,
        generation: u32,
        items: Option<u32>,
    ) -> impl Future<Output = Result<(), String>>;
}

pub(crate) struct NoObserver;

impl<W> WalkObserver<W> for NoObserver {
    fn journaled(&self) -> bool {
        false
    }

    fn withholds(&self, _key: &[u8]) -> bool {
        false
    }

    fn resolved_with_data(&self, _predecessor: &DelegateKey) -> Option<JournalResolution> {
        None
    }

    fn import_started(&self, _predecessor: &DelegateKey) -> bool {
        false
    }

    fn items_seen(&self, _predecessor: &DelegateKey) -> u32 {
        0
    }

    fn before_import(
        &mut self,
        _successor: &mut W,
        _predecessor: &DelegateKey,
        _generation: u32,
        _items: Option<u32>,
    ) -> impl Future<Output = Result<(), String>> {
        core::future::ready(Ok(()))
    }
}

/// What the walk reports, plus the facts the journal needs that the public report
/// does not carry.
pub(crate) struct WalkOutcome {
    pub(crate) report: DelegateMigrationReport,
    /// Predecessors whose probe answered [`ProbeVerdict::NotInstalled`] (reported
    /// as `Unresponsive`).
    pub(crate) not_installed: BTreeSet<[u8; 32]>,
    /// Predecessors short-circuited as `AlreadyMigrated` by a data-bearing
    /// completion marker.
    pub(crate) done_with_data: BTreeSet<[u8; 32]>,
    /// Predecessors short-circuited as `AlreadyMigrated` by a journal resolution,
    /// with that resolution.
    pub(crate) journal_resolved: BTreeMap<[u8; 32], JournalResolution>,
    /// Predecessors short-circuited as `AlreadyMigrated` by a legacy at-or-above
    /// seal only (see [`seal_is_bridged`]).
    pub(crate) bridged: BTreeSet<[u8; 32]>,
}

impl<IO> AppSideRoundTrip<'_, IO>
where
    IO: PredecessorSecretsIo,
    IO::Error: core::fmt::Debug,
{
    pub(crate) async fn walk<W, O>(
        &mut self,
        successor: &mut W,
        predecessors: &[DelegateLineageEntry],
        authorization: &MigrationAuthorization,
        policy: &SecretSelectionPolicy,
        observer: &mut O,
    ) -> WalkOutcome
    where
        W: SuccessorSecretsIo,
        W::Error: core::fmt::Debug,
        O: WalkObserver<W>,
    {
        let mut not_installed: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut done_with_data: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut journal_resolved: BTreeMap<[u8; 32], JournalResolution> = BTreeMap::new();
        let mut bridged: BTreeSet<[u8; 32]> = BTreeSet::new();
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

            // A journal that resolved this predecessor with its data in the
            // successor is not walked again, and its marker is not read (so a
            // stuck one cannot halt the walk). An import whose only blemish was
            // permanent rejections has no `Done` marker, so without this every
            // later walk would re-offer its items and bring back keys deleted
            // since. (A rejection reopened by a higher import revision is not
            // "resolved" under the run's binding, and is asked again.)
            if let Some(resolution) = observer.resolved_with_data(&key) {
                journal_resolved.insert(crate::journal::key_bytes(&key), resolution);
                if policy.data_bearing_is_authoritative(true) {
                    terminated = true;
                }
                results.push(PredecessorMigration::AlreadyMigrated { key, generation });
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
            // A journal may know an import from this predecessor started where no
            // marker says so. Then a `Done { had_data: false }` seal contradicts it
            // and is not believed: the predecessor is asked again.
            let journal_started = observer.import_started(&key);
            // So is a count the journal kept from an import that saw items (a
            // rejection a higher revision reopened, whose marker may be gone).
            let known_data = journal_started || observer.items_seen(&key) > 0;
            match marker {
                Some(MigrationMarker::Done { had_data }) if had_data || !known_data => {
                    if had_data {
                        if observer.journaled()
                            && seal_is_bridged(successor, &key, generation, policy).await
                        {
                            bridged.insert(crate::journal::key_bytes(&key));
                        } else {
                            done_with_data.insert(crate::journal::key_bytes(&key));
                        }
                    }
                    if policy.data_bearing_is_authoritative(had_data) {
                        terminated = true;
                    }
                    results.push(PredecessorMigration::AlreadyMigrated { key, generation });
                    continue;
                }
                _ => {}
            }
            // A surviving in-progress marker means this is a re-attempt, and it
            // carries the earlier attempt's data/empty observation — the sticky-data
            // rule (keep data, upgrade empty→data), so a data-then-empty retry can
            // never seal the marker "empty" and make NewestSnapshotWins misclassify
            // NoData and fall through to older generations (resurrection). A
            // journal's started import is the same evidence.
            let (retry, prior_saw_data) = match marker {
                Some(MigrationMarker::InProgress { saw_data }) => (true, saw_data || known_data),
                Some(MigrationMarker::Done { .. }) => (true, true),
                None => (known_data, known_data),
            };

            // A predecessor known to hold data may be partially written to the
            // successor right now, whatever this attempt's probe answers: make sure
            // a journal says so before going further.
            if prior_saw_data {
                if let Err(e) = observer
                    .before_import(successor, &key, generation, None)
                    .await
                {
                    results.push(PredecessorMigration::WriterUnavailable {
                        key,
                        generation,
                        failure: WriterFailure {
                            stage: WriterStage::JournalFlag,
                            error: e,
                        },
                    });
                    terminated = true;
                    continue;
                }
            }

            // G1.8: confirm executability BEFORE concluding "no data". A transport
            // error or a clean no-reply are both Unresponsive (error attached only
            // for the former); under NewestSnapshotWins an unknown newer state must
            // not be fallen through (would risk resurrecting deleted keys).
            match self.io.probe_verdict(&key).await {
                Ok(ProbeVerdict::Executable) => {}
                // "Not installed" is handled exactly like a silence: it is not proof
                // of absence (an unregistered delegate keeps its secrets). It is
                // only recorded, for the journal's absent streak.
                Ok(ProbeVerdict::NotInstalled) => {
                    not_installed.insert(crate::journal::key_bytes(&key));
                    results.push(PredecessorMigration::Unresponsive {
                        key,
                        generation,
                        error: Some("not installed on this node".to_string()),
                    });
                    terminated = policy.unresponsive_terminates(prior_saw_data);
                    continue;
                }
                Ok(ProbeVerdict::NoReply) => {
                    results.push(PredecessorMigration::Unresponsive {
                        key,
                        generation,
                        error: None,
                    });
                    terminated = policy.unresponsive_terminates(prior_saw_data);
                    continue;
                }
                Err(e) => {
                    results.push(PredecessorMigration::Unresponsive {
                        key,
                        generation,
                        error: Some(format!("{e:?}")),
                    });
                    terminated = policy.unresponsive_terminates(prior_saw_data);
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
                    terminated = policy.unresponsive_terminates(prior_saw_data);
                    continue;
                }
            };

            // The crate's own reserved namespace is never handed to the app's
            // writer and never counted: an import payload must not be able to write
            // (or forge) a migration marker.
            let items: Vec<&SecretPair> = secrets
                .iter()
                .filter(|(k, _)| !is_marker(k) && !observer.withholds(k))
                .collect();
            let saw_data = prior_saw_data || !items.is_empty();

            // An earlier attempt saw data and this one exports nothing, or fewer
            // items than an earlier attempt that started an import saw (#44). A
            // frozen predecessor does not lose data, so the short answer is the
            // fault (a secret, or an index, the node failed to read; an unreliable
            // reply). Believing it would seal `Done { had_data: true }` over
            // whatever the interrupted attempt left partially written, and the
            // rest would never be asked for again. Treat it as a silence: no
            // marker change, so the in-progress marker survives and a later run
            // asks again.
            // Distinct keys: a key listed twice in one export must not raise the
            // count every later export is held to.
            let items_seen = observer.items_seen(&key);
            let exported = u32::try_from(
                items
                    .iter()
                    .map(|(k, _)| k.as_slice())
                    .collect::<BTreeSet<_>>()
                    .len(),
            )
            .unwrap_or(u32::MAX);
            if prior_saw_data && (items.is_empty() || exported < items_seen) {
                results.push(PredecessorMigration::Unresponsive {
                    key,
                    generation,
                    error: Some(if items.is_empty() {
                        EXPORTED_NOTHING_AFTER_DATA.to_string()
                    } else {
                        format!("{EXPORTED_FEWER_AFTER_DATA}: {exported} of {items_seen}")
                    }),
                });
                terminated = policy.unresponsive_terminates(prior_saw_data);
                continue;
            }

            // A data-bearing import is about to write: let the journal (if any)
            // record durably that this predecessor may be partially imported from
            // here on, before the first item lands. (Already done above for a
            // predecessor known to hold data; this is then a no-op.)
            //
            // Fails closed: if that flag cannot be made durable, nothing of this
            // predecessor is written this run (a kill mid-import would otherwise
            // leave a partial copy no load can see).
            if saw_data {
                if let Err(e) = observer
                    .before_import(successor, &key, generation, Some(exported))
                    .await
                {
                    results.push(PredecessorMigration::WriterUnavailable {
                        key,
                        generation,
                        failure: WriterFailure {
                            stage: WriterStage::JournalFlag,
                            error: e,
                        },
                    });
                    terminated = true;
                    continue;
                }
                // That store re-read the journal: another session may have seen
                // more since this run loaded it.
                let items_seen = observer.items_seen(&key);
                if exported < items_seen {
                    results.push(PredecessorMigration::Unresponsive {
                        key,
                        generation,
                        error: Some(format!(
                            "{EXPORTED_FEWER_AFTER_DATA}: {exported} of {items_seen}"
                        )),
                    });
                    terminated = policy.unresponsive_terminates(true);
                    continue;
                }
            }

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
            // Re-asking a predecessor sealed empty: the marker just recorded must
            // outrank that seal (the `migration_marker` contract), or a lost
            // journal would later read the seal and strand what this run writes.
            if matches!(marker, Some(MigrationMarker::Done { had_data: false })) {
                let query = MarkerQuery {
                    predecessor: &key,
                    generation,
                    legacy_bridge: policy.legacy_bridge(),
                };
                let read_back = successor.migration_marker(&query).await;
                if !matches!(
                    read_back,
                    Ok(Some(MigrationMarker::InProgress { saw_data: true }))
                ) {
                    results.push(PredecessorMigration::WriterUnavailable {
                        key,
                        generation,
                        failure: WriterFailure {
                            stage: WriterStage::BeginMarker,
                            error: format!(
                                "the marker store reads {read_back:?} after an in-progress data \
                                 marker over an empty seal (see the \
                                 SuccessorSecretsIo::migration_marker contract)"
                            ),
                        },
                    });
                    terminated = true;
                    continue;
                }
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

        WalkOutcome {
            report: DelegateMigrationReport {
                predecessors: results,
            },
            not_installed,
            done_with_data,
            journal_resolved,
            bridged,
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
    use crate::AppImport;

    /// A test-only pin: an `Ok` from `note_app_import_started` that the test treats
    /// as "flagged, write it" must BE `AppImport::Flagged`, not merely `Ok`.
    trait ExpectFlagged {
        fn expect_flagged(self, why: &str);
    }
    impl ExpectFlagged for Result<AppImport, JournalError> {
        #[track_caller]
        fn expect_flagged(self, why: &str) {
            assert_eq!(self.expect(why), AppImport::Flagged, "{why}");
        }
    }
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    // ---- test successor store -------------------------------------------------

    #[derive(Default, Clone)]
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
        /// keys the node definitively reports as not installed (the
        /// `probe_verdict` override; `probe_executable` is not consulted).
        not_installed: HashSet<Vec<u8>>,
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
        /// The node answers "no such delegate" for this key (a typed answer).
        fn not_installed(mut self, key: &DelegateKey) -> Self {
            self.not_installed.insert(key.bytes().to_vec());
            self
        }
        fn failing_registration(mut self) -> Self {
            self.fail_register = true;
            self
        }
    }

    impl PredecessorSecretsIo for MockIo {
        type Error = IoAbort;
        async fn probe_verdict(
            &mut self,
            predecessor: &DelegateKey,
        ) -> Result<ProbeVerdict, IoAbort> {
            if self.not_installed.contains(predecessor.bytes()) {
                self.probed.insert(predecessor.bytes().to_vec());
                return Ok(ProbeVerdict::NotInstalled);
            }
            Ok(if self.probe_executable(predecessor).await? {
                ProbeVerdict::Executable
            } else {
                ProbeVerdict::NoReply
            })
        }
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

    /// freenet/freenet-migrate#14: `NewestSnapshotWinsContinuePastUnresponsive` is
    /// the opt-in escape hatch from the halt pinned above. Same script as
    /// `newest_snapshot_wins_halts_on_a_silent_export_no_fall_through` — a silent
    /// export on the newest generation, real data on the older one — but this
    /// policy variant reaches and imports the older generation's data instead of
    /// abandoning it. The unresponsive newest generation is still reported (the
    /// river#204 gate: an app must not treat this as a clean fresh install), so
    /// the fall-through is never silently clean.
    #[test]
    fn continue_past_unresponsive_recovers_older_data_but_still_reports_the_unresponsive_newest() {
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
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            ),
        ));
        assert!(
            matches!(
                report.predecessors[0],
                PredecessorMigration::Unresponsive { error: Some(_), .. }
            ),
            "the newest generation is still Unresponsive, got {:?}",
            report.predecessors[0]
        );
        assert!(
            matches!(
                report.predecessors[1],
                PredecessorMigration::Imported { .. }
            ),
            "the older generation must be reached and imported, got {:?}",
            report.predecessors[1]
        );
        assert_eq!(
            store.get_secret(b"data").unwrap(),
            b"v",
            "the opt-in must fall through to the older generation's real data"
        );
        assert!(
            io.fetched.contains(key_of(&old).bytes()),
            "the older generation must actually be enumerated, not skipped"
        );
        assert!(
            report.any_unresponsive(),
            "the app must still be told a newer generation could not be confirmed"
        );
        assert!(
            !report.is_complete(),
            "an unresolved newest generation must not read as a complete migration"
        );
    }

    /// `NewestSnapshotWinsContinuePastUnresponsive` stays `NewestSnapshotWins`
    /// once it finds data — it is not Union wearing a different name. A
    /// three-generation lineage: newest silent, middle data-bearing, oldest also
    /// data-bearing. The middle generation's data becomes authoritative and the
    /// oldest is `Superseded`, never imported — the contrast with Union, which
    /// would import both.
    #[test]
    fn continue_past_unresponsive_still_stops_at_the_first_data_bearing_generation() {
        let oldest = entry(1, 1);
        let middle = entry(2, 2);
        let newest = entry(3, 3);
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .dead(&key_of(&newest))
            .executable_with(&key_of(&middle), &[(b"data", b"middle")])
            .executable_with(&key_of(&oldest), &[(b"data", b"oldest")]);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[oldest, middle, newest],
            ack(),
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            ),
        ));
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert!(
            matches!(
                report.predecessors[2],
                PredecessorMigration::Superseded { .. }
            ),
            "the oldest generation must stay Superseded once a data-bearing \
             generation was found, got {:?}",
            report.predecessors[2]
        );
        assert_eq!(store.get_secret(b"data").unwrap(), b"middle");
        assert!(
            !io.fetched.contains(key_of(&oldest).bytes()),
            "the oldest generation must not even be enumerated"
        );
    }

    /// The `prior_saw_data` guard on `unresponsive_terminates`: once a
    /// predecessor's `InProgress { saw_data: true }` marker survives a run (proof
    /// it holds real data, even though this run's write didn't land), a LATER
    /// run's mere transient unreachability must not be treated as "safe to walk
    /// past" — that would let an older, definitely-inferior generation seal a
    /// `Done` marker while the known-data-bearing generation is only temporarily
    /// unreachable, permanently shadowing it under a never-clobber writer (a
    /// skeptical-review finding on this PR). Without the guard this test's run 2
    /// would let `old`'s "wrong" value land and seal.
    #[test]
    fn a_predecessor_proven_data_bearing_by_a_surviving_marker_still_halts_when_later_unresponsive()
    {
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut writer = ScriptedWriter::default().fail_write(b"data");

        // Run 1: `new` is reached and IS data-bearing, but its write fails
        // retryably — Incomplete, with an InProgress{saw_data:true} marker left
        // behind. Being data-bearing (even with a failed write) is already
        // authoritative under this policy, so `old` is Superseded without ever
        // being touched — unaffected by this PR.
        let mut io1 = MockIo::default().executable_with(&key_of(&new), &[(b"data", b"newval")]);
        let report1 = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io1,
            &[old, new],
            ack(),
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            ),
        ));
        assert!(matches!(
            report1.predecessors[0],
            PredecessorMigration::Incomplete { .. }
        ));
        assert!(
            matches!(
                writer.markers.get(key_of(&new).bytes()),
                Some(MigrationMarker::InProgress { saw_data: true })
            ),
            "run 1 must leave proof that `new` holds real data"
        );
        assert!(
            !io1.fetched.contains(key_of(&old).bytes()),
            "old untouched in run 1"
        );

        // Run 2: the write fault is gone, but now `new` is merely unreachable
        // (a probe failure, not a write failure) — indistinguishable, on this
        // attempt alone, from a predecessor that never existed. `old` DOES have
        // real (different, wrong) data for the same key.
        writer.fail.clear();
        let mut io2 = MockIo::default()
            .dead(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"data", b"oldval")]);
        let report2 = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io2,
            &[old, new],
            ack(),
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            ),
        ));
        assert!(matches!(
            report2.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(
            matches!(
                report2.predecessors[1],
                PredecessorMigration::Superseded { .. }
            ),
            "the guard must stop the walk at `new`, so `old` stays Superseded, got {:?}",
            report2.predecessors[1]
        );
        assert!(
            !io2.fetched.contains(key_of(&old).bytes()),
            "old must never even be enumerated — that is what the guard buys"
        );
        assert_eq!(
            writer.applied.get(b"data".as_slice()),
            None,
            "old's wrong value must never land while `new` is only proven-but-unreachable"
        );
        assert!(report2.any_unresponsive());
        assert!(!report2.is_complete());
    }

    /// The residual risk `RollbackRiskAck` accepts, pinned rather than left as a
    /// surprise: unlike the test above, a predecessor `new` that has NEVER
    /// before been reached carries no marker to consult, so its FIRST-ever
    /// `Unresponsive` result is indistinguishable from "never registered" — the
    /// common case this whole policy variant exists to fall through. If `new`
    /// later turns out to have held real (different) data all along, the
    /// already-sealed older generation's value is never-clobber and permanently
    /// wins: the second run's report reads completely clean
    /// (`is_complete() == true`, `any_unresponsive() == false`) while the true
    /// value is silently discarded. Closing this fully needs the
    /// probe-classification work the issue explicitly defers
    /// (freenet/freenet-migrate#14's "separate follow-up"), so this test exists
    /// to make the accepted trade a checked fact rather than an assumption — the
    /// same role `union_resurrects_a_deleted_key_documented` plays for Union's
    /// analogous hazard.
    #[test]
    fn continue_past_unresponsive_can_permanently_shadow_a_later_recovered_true_value() {
        let old = entry(1, 1);
        let new = entry(2, 2);
        let mut writer = ScriptedWriter::default();
        let policy = || {
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            )
        };

        // Run 1: `new` has never been reached before (no marker) and is
        // unresponsive on this, its first, attempt. `old` supplies real data for
        // the same key and is accepted as authoritative.
        let mut io1 = MockIo::default()
            .dead(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"data", b"old-real-value")]);
        let report1 = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io1,
            &[old, new],
            ack(),
            policy(),
        ));
        assert!(matches!(
            report1.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(matches!(
            report1.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(
            writer.applied.get(b"data".as_slice()).map(Vec::as_slice),
            Some(b"old-real-value".as_slice())
        );

        // Run 2: `new` is reachable now and turns out to hold its OWN real,
        // different value for the same key — proof it was never actually empty,
        // merely unlucky in run 1.
        let mut io2 =
            MockIo::default().executable_with(&key_of(&new), &[(b"data", b"new-real-value")]);
        let report2 = block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io2,
            &[old, new],
            ack(),
            policy(),
        ));

        assert_eq!(
            writer.applied.get(b"data".as_slice()).map(Vec::as_slice),
            Some(b"old-real-value".as_slice()),
            "the true, newer value must be silently and permanently discarded under \
             never-clobber — THE accepted risk this ack exists to name"
        );
        assert!(
            matches!(
                report2.predecessors[0],
                PredecessorMigration::Imported { .. }
            ),
            "`new` reads as a normal, successful import this run, got {:?}",
            report2.predecessors[0]
        );
        assert!(
            report2.is_complete() && !report2.any_unresponsive(),
            "THE hazard: the report reads fully clean even though the durable value \
             is the wrong (older) one"
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
    fn data_then_empty_retry_is_not_believed_and_still_supersedes_older() {
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

        // Run 2: B now answers EMPTY. An empty answer after data was seen is not
        // believed (a frozen predecessor does not lose data): B stays unsealed, as
        // a silence, with its in-progress flag intact, and A is still never
        // imported.
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
            matches!(
                r2.predecessors[0],
                PredecessorMigration::Unresponsive { .. }
            ),
            "a data-then-empty retry is neither Imported nor NoData; got {:?}",
            r2.predecessors[0]
        );
        assert!(
            store
                .get_secret(&predecessor_done_marker(&key_of(&b), true).0)
                .is_none(),
            "an empty answer must not seal the predecessor over the missing `x`"
        );
        assert_eq!(
            store.get_secret(&pred_wip_marker(&key_of(&b))).unwrap(),
            PRED_DONE_MARKER_VALUE_DATA,
            "the in-progress marker keeps the data flag"
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

        // Run 3: B answers with its data again, and `x` finally lands.
        let mut io3 = MockIo::default()
            .executable_with(&key_of(&b), &[(b"x", b"NEW")])
            .executable_with(&key_of(&a), &[(b"a_only", b"va")]);
        let r3 = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io3,
            &[a, b],
            ack(),
            newest(),
        ));
        assert!(matches!(
            r3.predecessors[0],
            PredecessorMigration::Imported { .. }
        ));
        assert_eq!(store.get_secret(b"x").as_deref(), Some(&b"NEW"[..]));
        assert!(store.get_secret(b"a_only").is_none());
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
        // imported and the walk stops — under every policy, including the
        // continue-past-unresponsive variant, unlike an Unresponsive predecessor,
        // because it is the SUCCESSOR side that is broken.
        for policy in [
            newest(),
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            ),
            union(),
        ] {
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

    // ---- the completeness journal (freenet/freenet-migrate#37) -----------------
    //
    // Each test below is named for a failure the in-session completeness
    // inference produced in freenet/river#758 rounds 1-4, for a finding of the
    // #38 review, or for a property the journal's data-loss argument rests on.

    use crate::journal::{
        journal_status, ImportFlag, JournalBinding, JournalDecodeError, JournalError,
        JournalResolution, JournalState, JournalStatus, MigrationJournal, RunOutcome,
    };

    use crate::journal::MIGRATION_JOURNAL_KEY;

    impl<S: SecretStore + ?Sized> JournaledSuccessorIo for SecretStoreIo<'_, S> {
        fn load_journal(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> {
            core::future::ready(Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY)))
        }

        fn store_journal(
            &mut self,
            journal: &[u8],
        ) -> impl Future<Output = Result<(), Self::Error>> {
            let ok = self.store.set_secret(MIGRATION_JOURNAL_KEY, journal);
            core::future::ready(if ok {
                Ok(())
            } else {
                Err(SecretStoreWriteFailed {
                    key: MIGRATION_JOURNAL_KEY.to_vec(),
                })
            })
        }

        fn journal_key(&self) -> &[u8] {
            MIGRATION_JOURNAL_KEY
        }
    }

    fn union_binding() -> JournalBinding {
        JournalBinding::new(&union(), 0)
    }

    fn stored_status(store: &MemStore, lineage: &[DelegateLineageEntry]) -> JournalStatus {
        journal_status(
            store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
            lineage,
            &union_binding(),
        )
    }

    fn stored_journal(store: &MemStore) -> MigrationJournal {
        MigrationJournal::decode(
            &store
                .get_secret(MIGRATION_JOURNAL_KEY)
                .expect("journal stored"),
        )
        .expect("journal decodes")
    }

    fn state_of(store: &MemStore, e: &DelegateLineageEntry) -> JournalState {
        stored_journal(store)
            .entry(&key_of(e))
            .expect("entry present")
            .state
    }

    fn resolved(r: JournalResolution) -> RunOutcome {
        RunOutcome::Resolved(r)
    }

    fn journaled(
        store: &mut MemStore,
        io: &mut MockIo,
        lineage: &[DelegateLineageEntry],
        policy: SecretSelectionPolicy,
    ) -> JournaledMigrationReport {
        block_on(migrate_delegate_secrets_journaled(
            &mut store_io(store),
            io,
            lineage,
            ack(),
            policy,
        ))
    }

    fn complete(run: &JournaledMigrationReport) -> bool {
        run.status.as_ref().is_some_and(JournalStatus::is_complete)
    }

    /// A refused journaled run: every predecessor `WriterUnavailable` with stage
    /// `JournalUnavailable`, so it never reads as complete.
    fn refused(run: &JournaledMigrationReport) -> bool {
        !run.report.predecessors.is_empty()
            && !run.report.is_complete()
            && run.report.predecessors.iter().all(|p| {
                matches!(
                    p,
                    PredecessorMigration::WriterUnavailable {
                        failure: WriterFailure {
                            stage: WriterStage::JournalUnavailable,
                            ..
                        },
                        ..
                    }
                )
            })
    }

    fn interrupted(run: &JournaledMigrationReport) -> bool {
        run.status
            .as_ref()
            .is_some_and(JournalStatus::interrupted_import)
    }

    /// A successor writer that can inspect the STORED journal at chosen instants,
    /// and inject faults: failed items, a failed flush, a failed Nth journal
    /// store, a failed journal load, a concurrent session's journal write, and an
    /// import revision. It is what lets a test see the durable state a kill at
    /// that instant would leave behind.
    struct InspectingWriter {
        store: MemStore,
        lineage: Vec<DelegateLineageEntry>,
        /// The stored journal's status at every `migration_marker` call.
        status_at_marker_reads: Vec<JournalStatus>,
        status_at_first_item: Option<JournalStatus>,
        retryable_fail: BTreeSet<Vec<u8>>,
        permanent_fail: BTreeSet<Vec<u8>>,
        offered: Vec<Vec<u8>>,
        /// `RecoveredSecret::retry` of each offered item.
        retries: Vec<bool>,
        /// Every `record_marker` call.
        markers_recorded: Vec<MigrationMarker>,
        fail_marker_read: BTreeSet<Vec<u8>>,
        fail_flush: bool,
        journal_stores: usize,
        fail_journal_store_number: Option<usize>,
        fail_journal_load: bool,
        journal_loads: usize,
        fail_journal_load_number: Option<usize>,
        /// The Nth journal load answers `None` (a read the store could not tell
        /// from absence).
        none_on_load_number: Option<usize>,
        /// Stored over the journal (a concurrent session's write) at the first item.
        inject_at_first_item: Option<Vec<u8>>,
        /// Stored over the journal at the first marker read.
        inject_at_first_marker_read: Option<Vec<u8>>,
        /// Marker reads that pass before `inject_at_first_marker_read` fires (the
        /// walk's own read of a predecessor comes after `begin`'s).
        marker_reads_before_inject: usize,
        revision: u32,
    }

    impl InspectingWriter {
        fn new(lineage: &[DelegateLineageEntry]) -> Self {
            Self {
                store: MemStore::default(),
                lineage: lineage.to_vec(),
                status_at_marker_reads: Vec::new(),
                status_at_first_item: None,
                retryable_fail: BTreeSet::new(),
                permanent_fail: BTreeSet::new(),
                offered: Vec::new(),
                retries: Vec::new(),
                markers_recorded: Vec::new(),
                fail_marker_read: BTreeSet::new(),
                fail_flush: false,
                journal_stores: 0,
                fail_journal_store_number: None,
                fail_journal_load: false,
                journal_loads: 0,
                fail_journal_load_number: None,
                none_on_load_number: None,
                inject_at_first_item: None,
                inject_at_first_marker_read: None,
                marker_reads_before_inject: 0,
                revision: 0,
            }
        }
        fn raw(&mut self) -> SecretStoreIo<'_, MemStore> {
            store_io(&mut self.store)
        }
        fn run(
            &mut self,
            io: &mut MockIo,
            policy: SecretSelectionPolicy,
        ) -> JournaledMigrationReport {
            let lineage = self.lineage.clone();
            block_on(migrate_delegate_secrets_journaled(
                self,
                io,
                &lineage,
                ack(),
                policy,
            ))
        }
    }

    impl SuccessorSecretsIo for InspectingWriter {
        type Error = SecretStoreWriteFailed;
        async fn migration_marker(
            &mut self,
            query: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, Self::Error> {
            let status = stored_status(&self.store, &self.lineage);
            self.status_at_marker_reads.push(status);
            if self.status_at_marker_reads.len() > self.marker_reads_before_inject {
                if let Some(bytes) = self.inject_at_first_marker_read.take() {
                    self.store.set_secret(MIGRATION_JOURNAL_KEY, &bytes);
                }
            }
            if self.fail_marker_read.contains(query.predecessor.bytes()) {
                return Err(SecretStoreWriteFailed {
                    key: query.predecessor.bytes().to_vec(),
                });
            }
            self.raw().migration_marker(query).await
        }
        async fn record_marker(
            &mut self,
            predecessor: &DelegateKey,
            marker: MigrationMarker,
        ) -> Result<(), Self::Error> {
            self.markers_recorded.push(marker);
            self.raw().record_marker(predecessor, marker).await
        }
        async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
            self.offered.push(item.key.to_vec());
            self.retries.push(item.retry);
            if self.status_at_first_item.is_none() {
                self.status_at_first_item = Some(stored_status(&self.store, &self.lineage));
                if let Some(bytes) = self.inject_at_first_item.take() {
                    self.store.set_secret(MIGRATION_JOURNAL_KEY, &bytes);
                }
            }
            if self.retryable_fail.contains(item.key) {
                return ItemWrite::retryable(SecretStoreWriteFailed {
                    key: item.key.to_vec(),
                });
            }
            if self.permanent_fail.contains(item.key) {
                return ItemWrite::permanent(SecretStoreWriteFailed {
                    key: item.key.to_vec(),
                });
            }
            self.raw().write_secret(item).await
        }
        async fn flush_predecessor(
            &mut self,
            predecessor: &DelegateKey,
        ) -> Result<(), Self::Error> {
            if self.fail_flush {
                return Err(SecretStoreWriteFailed {
                    key: predecessor.bytes().to_vec(),
                });
            }
            Ok(())
        }
    }

    impl JournaledSuccessorIo for InspectingWriter {
        async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            self.journal_loads += 1;
            if self.fail_journal_load || self.fail_journal_load_number == Some(self.journal_loads) {
                return Err(SecretStoreWriteFailed {
                    key: MIGRATION_JOURNAL_KEY.to_vec(),
                });
            }
            if self.none_on_load_number == Some(self.journal_loads) {
                return Ok(None);
            }
            self.raw().load_journal().await
        }
        async fn store_journal(&mut self, journal: &[u8]) -> Result<(), Self::Error> {
            self.journal_stores += 1;
            if self.fail_journal_store_number == Some(self.journal_stores) {
                return Err(SecretStoreWriteFailed {
                    key: MIGRATION_JOURNAL_KEY.to_vec(),
                });
            }
            self.raw().store_journal(journal).await
        }
        fn journal_key(&self) -> &[u8] {
            MIGRATION_JOURNAL_KEY
        }
        fn import_revision(&self) -> u32 {
            self.revision
        }
    }

    // -- begin, and the durable-before-the-first-write property -----------------

    /// The journal must be durable (read off the markers) BEFORE the
    /// app's first migration write — that is the whole point of `begin`.
    #[test]
    fn begin_stores_every_predecessor_pending_before_anything_is_written() {
        let lineage = [entry(1, 1), entry(2, 2)];
        let mut store = MemStore::default();
        assert_eq!(stored_status(&store, &lineage), JournalStatus::NotStarted);
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(
            matches!(status, JournalStatus::Incomplete { ref pending, .. } if pending.len() == 2)
        );
        assert_eq!(stored_status(&store, &lineage), status);
        assert_eq!(store.data.len(), 1, "only the journal was written");
    }

    /// `begin` must never reset a readable journal: an import flag or a
    /// resolution recorded by an earlier session survives a later `begin`.
    #[test]
    fn begin_never_resets_an_existing_journal() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&k, 1);
        store.set_secret(MIGRATION_JOURNAL_KEY, &journal.encode());
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(
            status.interrupted_import(),
            "the import flag survived begin"
        );
    }

    /// The journaled walk starts the journal before it asks the successor about
    /// any predecessor, so a kill before the first import flag still leaves a
    /// pending journal, not `NotStarted`.
    #[test]
    fn the_journal_is_started_before_the_walk_touches_any_predecessor() {
        let lineage = [entry(1, 1)];
        let mut writer = InspectingWriter::new(&lineage);
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[]);
        writer.run(&mut io, union());
        // One read per predecessor seeds the fresh journal; nothing is written
        // before it is stored. The walk's own first marker read comes next.
        let reads = &writer.status_at_marker_reads;
        assert_eq!(
            reads.len(),
            2 * lineage.len(),
            "seed reads, then the walk's"
        );
        assert!(reads[..lineage.len()]
            .iter()
            .all(|s| *s == JournalStatus::NotStarted));
        let at_walk = &reads[lineage.len()];
        assert!(
            matches!(at_walk, JournalStatus::Incomplete { .. }),
            "got {at_walk:?}"
        );
    }

    /// The tab dies after the first item of a data-bearing predecessor. The
    /// durable state at that instant must already say "interrupted import", so
    /// the next load re-runs instead of trusting the partial successor
    /// (freenet/river#760: 1 of 4 rooms survived a kill at the first write).
    #[test]
    fn an_interrupted_write_is_already_flagged_durably_at_the_first_item() {
        let lineage = [entry(1, 1)];
        let mut writer = InspectingWriter::new(&lineage);
        let mut io = MockIo::default().executable_with(
            &key_of(&lineage[0]),
            &[(b"room:a", b"A"), (b"room:b", b"B")],
        );
        writer.run(&mut io, union());
        let at_first = writer.status_at_first_item.expect("an item was written");
        assert!(at_first.interrupted_import(), "got {at_first:?}");
    }

    /// Kill-point sweep. The successor accepts only the first N writes of a run
    /// (a tab dying after N writes); for every N the state left behind must
    /// never read `Complete` while data is missing, and a healthy later load must
    /// converge with every item present.
    #[test]
    fn no_kill_point_reads_complete_with_data_missing_and_every_one_recovers() {
        let lineage = [entry(1, 1), entry(2, 2), entry(3, 3)];
        let io_for = || {
            MockIo::default()
                .executable_with(
                    &key_of(&lineage[2]),
                    &[(b"room:c", b"C"), (b"room:d", b"D")],
                )
                .executable_with(&key_of(&lineage[1]), &[(b"room:b", b"B")])
                .executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")])
        };
        // What each policy owes the successor: Union every generation, a snapshot
        // policy only the newest data-bearing one.
        type Case = (fn() -> SecretSelectionPolicy, &'static [&'static [u8]]);
        let cases: [Case; 2] = [
            (union, &[b"room:a", b"room:b", b"room:c", b"room:d"]),
            (newest, &[b"room:c", b"room:d"]),
        ];
        let run_killed = |store: MemStore, budget: usize, policy: fn() -> SecretSelectionPolicy| {
            let mut killable = KillableStore {
                inner: store,
                budget,
            };
            let _ = block_on(migrate_delegate_secrets_journaled(
                &mut SecretStoreIo::new(
                    &mut killable,
                    NoCrossEntryInvariantsAck::i_certify_these_secrets_have_no_cross_entry_invariants(),
                ),
                &mut io_for(),
                &lineage,
                ack(),
                policy(),
            ));
            killable.inner
        };
        for (policy, owed) in cases {
            let name = format!("{:?}", policy());
            let binding = JournalBinding::new(&policy(), 0);
            let check = |left: &MemStore, at: &str| {
                let status = journal_status(
                    left.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
                    &lineage,
                    &binding,
                );
                let all_present = owed.iter().all(|k| left.has_secret(k));
                let any_present = owed.iter().any(|k| left.has_secret(k));
                assert!(
                    !status.is_complete() || all_present,
                    "{name}, {at}: Complete with data missing"
                );
                assert!(
                    !any_present || all_present || status.interrupted_import(),
                    "{name}, {at}: a partial copy is not flagged: {status:?}"
                );
            };
            for writes in 0..40 {
                let left = run_killed(MemStore::default(), writes, policy);
                check(&left, &format!("kill after {writes} writes"));
                // The recovery is itself killed half-way, then a healthy load.
                let again = run_killed(left, writes / 2, policy);
                check(&again, &format!("second kill after {writes}/2 writes"));
                let mut recovered = again;
                let run = journaled(&mut recovered, &mut io_for(), &lineage, policy());
                assert!(
                    complete(&run),
                    "{name}: kill after {writes} writes did not converge"
                );
                assert!(owed.iter().all(|k| recovered.has_secret(k)));
            }
        }
    }

    /// A store that accepts its first `budget` writes and silently refuses every
    /// write after (reads keep working) — the durable state a tab killed after
    /// that many writes leaves behind.
    struct KillableStore {
        inner: MemStore,
        budget: usize,
    }
    impl SecretStore for KillableStore {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.inner.list_secrets(prefix)
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.get_secret(key)
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.inner.has_secret(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            if self.budget == 0 {
                return false;
            }
            self.budget -= 1;
            self.inner.set_secret(key, value)
        }
    }

    // -- failing closed ------------------------------------------------------------

    /// If the import flag cannot be stored, the predecessor's items must not be
    /// written: a kill mid-import would leave a partial copy no load can see.
    #[test]
    fn a_failed_import_flag_store_imports_nothing() {
        let lineage = [entry(1, 1)];
        let mut writer = InspectingWriter::new(&lineage);
        // Store #1 starts the journal; #2 is the import flag.
        writer.fail_journal_store_number = Some(2);
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")]);
        let run = writer.run(&mut io, union());
        assert!(writer.offered.is_empty(), "no item may be offered");
        assert!(matches!(
            run.report.predecessors[0],
            PredecessorMigration::WriterUnavailable {
                failure: WriterFailure {
                    stage: WriterStage::JournalFlag,
                    ..
                },
                ..
            }
        ));
        assert!(run
            .journal_error
            .as_deref()
            .is_some_and(|e| e.contains("journal import flag failed")));
        assert!(!complete(&run));
    }

    /// A successor adopting the journal after a plain walk was interrupted mid-import
    /// starts with that predecessor flagged, so `interrupted_import()` is right
    /// from the first load.
    #[test]
    fn adopting_after_an_interrupted_plain_walk_starts_flagged() {
        let lineage = [entry(1, 1), entry(2, 2)];
        let mut writer = InspectingWriter::new(&lineage);
        writer.retryable_fail.insert(b"room:b".to_vec());
        let mut io = MockIo::default()
            .executable_with(
                &key_of(&lineage[1]),
                &[(b"room:a", b"A"), (b"room:b", b"B")],
            )
            .executable_with(&key_of(&lineage[0]), &[]);
        block_on(migrate_delegate_secrets(
            &mut writer,
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        let status =
            block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        assert!(status.interrupted_import(), "got {status:?}");
        assert!(matches!(
            state_of(&writer.store, &lineage[1]),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
        // The older generation the plain walk sealed empty is resolved from its
        // marker, not owed again.
        assert_eq!(
            state_of(&writer.store, &lineage[0]),
            JournalState::Resolved(JournalResolution::NoData)
        );
    }

    /// If the journal cannot even be started, the walk does not run at all.
    #[test]
    fn a_failed_journal_start_refuses_the_walk() {
        let lineage = [entry(1, 1)];
        let mut store = MemStore::default();
        store.fail_writes_to(MIGRATION_JOURNAL_KEY);
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(refused(&run), "{:?}", run.report);
        assert!(run.status.is_none());
        assert!(run.journal_error.is_some());
        assert!(
            !store.has_secret(b"room:a"),
            "nothing migrated without a journal"
        );

        assert!(
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &union()
            ))
            .is_err(),
            "begin must fail loudly too"
        );
    }

    /// A journal that cannot be READ is never overwritten: the walk is refused
    /// and the stored flags survive.
    #[test]
    fn a_failed_journal_load_refuses_the_walk_and_leaves_the_journal_alone() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&k, 1);
        let before = journal.encode();
        writer.store.set_secret(MIGRATION_JOURNAL_KEY, &before);
        writer.fail_journal_load = true;
        let mut io = MockIo::default().silent_export(&k);
        let run = writer.run(&mut io, union());
        assert!(refused(&run), "{:?}", run.report);
        assert_eq!(writer.store.get_secret(MIGRATION_JOURNAL_KEY), Some(before));
    }

    /// The final journal store failing on its own is reported, and the stored
    /// journal stays pending, so the next load re-runs.
    #[test]
    fn a_failed_final_journal_store_is_reported() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        store.set_secret(
            MIGRATION_JOURNAL_KEY,
            &MigrationJournal::new_pending(&lineage).encode(),
        );
        store.fail_writes_to(MIGRATION_JOURNAL_KEY);
        let mut io = MockIo::default().executable_with(&k, &[]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(
            run.journal_error
                .as_deref()
                .is_some_and(|e| e.contains("journal store failed")),
            "got {:?}",
            run.journal_error
        );
        assert!(!stored_status(&store, &lineage).is_complete());
    }

    /// A journal from a different encoding version (a newer build) is never
    /// overwritten by this one: `begin` and the walk both refuse.
    #[test]
    fn a_journal_from_another_encoding_version_is_never_overwritten() {
        let lineage = [entry(1, 1)];
        let mut wire = MigrationJournal::new_pending(&lineage).encode();
        let pos = wire.windows(2).position(|w| w == [0x61, b'v']).unwrap() + 2;
        wire[pos] = 0x02;
        let mut store = MemStore::default();
        store.set_secret(MIGRATION_JOURNAL_KEY, &wire);
        assert_eq!(
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &union()
            )),
            Err(JournalError::ForeignVersion(2))
        );
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(refused(&run), "{:?}", run.report);
        assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), Some(wire));
        assert!(!store.has_secret(b"room:a"));
    }

    /// A corrupt journal is rebuilt from the markers, which record every import
    /// that started.
    #[test]
    fn a_corrupt_journal_is_rebuilt_from_the_markers() {
        let (partial, untouched) = (entry(1, 1), entry(2, 2));
        let lineage = [partial, untouched];
        let mut store = MemStore::default();
        // An import from `partial` started (the walk's, or the app's: both write
        // this marker) and did not finish.
        store.set_secret(
            &pred_wip_marker(&key_of(&partial)),
            PRED_DONE_MARKER_VALUE_DATA,
        );
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(status.interrupted_import());
        assert!(matches!(
            state_of(&store, &partial),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
        assert!(matches!(
            state_of(&store, &untouched),
            JournalState::Pending {
                import: ImportFlag::None,
                ..
            }
        ));
    }

    // -- the failure cases from #37 ----------------------------------------------

    /// An interrupted import is re-run by the next load and converges.
    #[test]
    fn an_interrupted_import_is_rerun_and_converges() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.retryable_fail.insert(b"room:b".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]);
        let first = writer.run(&mut io, union());
        assert!(interrupted(&first));
        assert_eq!(
            stored_status(&writer.store, &lineage),
            first.status.clone().unwrap(),
            "the returned status is the stored one"
        );
        writer.retryable_fail.clear();
        let second = writer.run(&mut io, union());
        assert!(complete(&second));
        assert_eq!(
            writer.store.get_secret(b"room:b").as_deref(),
            Some(&b"B"[..])
        );
        assert_eq!(
            state_of(&writer.store, &lineage[0]),
            JournalState::Resolved(JournalResolution::Imported)
        );
    }

    /// Two generations each hold different data. Completeness requires BOTH to
    /// resolve: one finishing must not seal the other.
    #[test]
    fn two_generations_must_each_resolve_before_complete() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:new", b"N")])
            .silent_export(&key_of(&old));
        let first = journaled(&mut store, &mut io, &lineage, union());
        assert!(!complete(&first), "the old generation never answered");
        assert_eq!(
            state_of(&store, &new),
            JournalState::Resolved(JournalResolution::Imported)
        );
        assert!(matches!(
            state_of(&store, &old),
            JournalState::Pending { attempts: 1, .. }
        ));
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:new", b"N")])
            .executable_with(&key_of(&old), &[(b"room:old", b"O")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        assert_eq!(store.get_secret(b"room:old").as_deref(), Some(&b"O"[..]));
    }

    /// An item the successor permanently refuses must RESOLVE the predecessor,
    /// with the count, not loop. `Complete` carries the count.
    #[test]
    fn a_permanently_rejected_item_converges_and_is_counted() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:corrupt".to_vec());
        let mut io =
            MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:corrupt", b"?")]);
        let run = writer.run(&mut io, union());
        assert_eq!(
            run.status,
            Some(JournalStatus::Complete { rejected_items: 1 })
        );
        assert!(matches!(
            state_of(&writer.store, &lineage[0]),
            JournalState::Resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 0,
                ..
            })
        ));
    }

    /// The writer's import revision rising reopens a predecessor resolved with
    /// rejections, so a fixed import path gets to retry — it is not sealed away.
    #[test]
    fn a_higher_import_revision_reopens_rejections_and_the_fix_imports_them() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:corrupt".to_vec());
        let mut io =
            MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:corrupt", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));

        // The app ships a decoder fix and bumps its revision.
        writer.permanent_fail.clear();
        writer.revision = 1;
        let reopened = journal_status(
            writer.store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
            &lineage,
            &JournalBinding::new(&union(), 1),
        );
        assert!(
            !reopened.is_complete(),
            "reopened under the higher revision"
        );
        assert_eq!(reopened.rejected_items(), 1, "the count is still reported");
        assert!(
            !reopened.interrupted_import(),
            "the rest of its data is in the successor: not a partial import"
        );
        let run = writer.run(&mut io, union());
        assert_eq!(
            run.status,
            Some(JournalStatus::Complete { rejected_items: 0 })
        );
        assert_eq!(
            writer.store.get_secret(b"room:corrupt").as_deref(),
            Some(&b"?"[..])
        );
    }

    /// A rejection alongside a RETRYABLE failure, a flush fault, or a withheld key
    /// is not resolution: a retry can still land the rest.
    #[test]
    fn a_rejection_with_any_retryable_blemish_stays_pending() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);

        let mut retryable = InspectingWriter::new(&lineage);
        retryable.permanent_fail.insert(b"room:corrupt".to_vec());
        retryable.retryable_fail.insert(b"room:b".to_vec());
        let mut io =
            MockIo::default().executable_with(&k, &[(b"room:b", b"B"), (b"room:corrupt", b"?")]);
        let run = retryable.run(&mut io, union());
        assert!(
            matches!(run.status, Some(JournalStatus::Incomplete { .. })),
            "stored and still pending: {:?}",
            run.status
        );

        let mut flush = InspectingWriter::new(&lineage);
        flush.permanent_fail.insert(b"room:corrupt".to_vec());
        flush.fail_flush = true;
        let mut io = MockIo::default().executable_with(&k, &[(b"room:corrupt", b"?")]);
        let run = flush.run(&mut io, union());
        assert!(
            matches!(run.status, Some(JournalStatus::Incomplete { .. })),
            "a flush fault is retryable: {:?}",
            run.status
        );
    }

    /// Under Union a key whose newer write failed retryably is withheld from an
    /// older generation; that older predecessor is not resolved by the run.
    #[test]
    fn a_withheld_key_leaves_the_older_generation_pending() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut writer = InspectingWriter::new(&lineage);
        writer.retryable_fail.insert(b"room:x".to_vec());
        // The older generation also has a permanently rejected item, so only the
        // withheld key stands between it and an `ImportedWithRejections`
        // resolution that would seal `room:x` away.
        writer.permanent_fail.insert(b"room:corrupt".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:x", b"new")])
            .executable_with(
                &key_of(&old),
                &[(b"room:x", b"old"), (b"room:corrupt", b"?")],
            );
        let run = writer.run(&mut io, union());
        assert!(matches!(
            state_of(&writer.store, &old),
            JournalState::Pending { .. }
        ));
        assert!(!complete(&run));
    }

    /// A timed-out export is retried on every later load and never sealed.
    #[test]
    fn a_timed_out_fetch_stays_pending_and_is_retried_until_it_answers() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        for attempt in 1..=3 {
            let mut io = MockIo::default().silent_export(&k);
            let run = journaled(&mut store, &mut io, &lineage, union());
            assert!(!complete(&run), "silence is never resolution");
            assert!(io.fetched.contains(k.bytes()), "attempt {attempt} re-asked");
            assert!(matches!(
                state_of(&store, &lineage[0]),
                JournalState::Pending { attempts, absent_streak: 0, .. } if attempts == attempt
            ));
            assert!(store.get_secret(&pred_done_marker(&k)).is_none());
        }
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        assert_eq!(store.get_secret(b"room:a").as_deref(), Some(&b"A"[..]));
    }

    /// "Not installed" is NOT proof of absence — freenet-core unregisters a
    /// delegate without deleting its secrets — so it never resolves anything and
    /// cannot complete the migration, however fast it answers (the round-4 race
    /// against the generation actually holding the data).
    #[test]
    fn not_installed_never_resolves_and_cannot_complete_the_migration() {
        let (holder, absent) = (entry(1, 1), entry(2, 2));
        let lineage = [holder, absent];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .not_installed(&key_of(&absent))
            .silent_export(&key_of(&holder));
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(!complete(&run));
        assert!(matches!(
            state_of(&store, &absent),
            JournalState::Pending {
                absent_streak: 1,
                ..
            }
        ));
        assert!(matches!(
            run.report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
    }

    /// Under NewestSnapshotWins "not installed" halts exactly like a silence: an
    /// absent-looking newer generation may still hold newer data.
    #[test]
    fn not_installed_halts_newest_snapshot_wins_like_a_silence() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .not_installed(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"room:a", b"A")]);
        let run = journaled(&mut store, &mut io, &lineage, newest());
        assert!(matches!(
            run.report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(!store.has_secret(b"room:a"));
        assert!(!complete(&run));
    }

    /// The absent streak counts consecutive "not installed" answers, a silence
    /// resets it, and an app policy can read it — but it never resolves.
    #[test]
    fn the_absent_streak_counts_consecutive_not_installed_answers() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        for _ in 0..2 {
            journaled(
                &mut store,
                &mut MockIo::default().not_installed(&k),
                &lineage,
                union(),
            );
        }
        let status = stored_status(&store, &lineage);
        assert!(status.pending_all_absent(2));
        assert!(!status.pending_all_absent(3));
        assert!(!status.is_complete());

        // A predecessor that may hold a partial import is never "absent", however
        // long its streak: the successor may already hold part of it.
        let mut flagged = stored_journal(&store);
        flagged.mark_import_started(&k, 1);
        flagged.record(&k, 1, RunOutcome::Unresolved { absent: true });
        assert!(!flagged
            .status(&lineage, &union_binding())
            .pending_all_absent(1));
        journaled(
            &mut store,
            &mut MockIo::default().dead(&k),
            &lineage,
            union(),
        );
        assert!(
            !stored_status(&store, &lineage).pending_all_absent(1),
            "a silence resets the streak"
        );
    }

    /// An adapter written before `probe_verdict` existed (only the boolean
    /// probe) never reports "not installed".
    #[test]
    fn an_adapter_without_the_override_never_reports_not_installed() {
        struct BoolOnlyIo;
        impl PredecessorSecretsIo for BoolOnlyIo {
            type Error = IoAbort;
            async fn probe_executable(&mut self, _p: &DelegateKey) -> Result<bool, IoAbort> {
                Ok(false)
            }
            async fn fetch_secrets(
                &mut self,
                _p: &DelegateKey,
            ) -> Result<Vec<SecretPair>, IoAbort> {
                Ok(vec![])
            }
        }
        let lineage = [entry(1, 1)];
        let mut store = MemStore::default();
        block_on(migrate_delegate_secrets_journaled(
            &mut store_io(&mut store),
            &mut BoolOnlyIo,
            &lineage,
            ack(),
            union(),
        ));
        assert!(matches!(
            state_of(&store, &lineage[0]),
            JournalState::Pending {
                absent_streak: 0,
                ..
            }
        ));
        assert_eq!(
            block_on(BoolOnlyIo.probe_verdict(&key_of(&lineage[0]))),
            Ok(ProbeVerdict::NoReply)
        );
    }

    /// Superseded resolves only behind a resolved, data-bearing newer snapshot
    /// under a snapshot policy — never behind a halt.
    #[test]
    fn superseded_resolves_only_behind_an_authoritative_snapshot() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .dead(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"room:a", b"A")]);
        journaled(&mut store, &mut io, &lineage, newest());
        assert!(matches!(
            state_of(&store, &old),
            JournalState::Pending { .. }
        ));

        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        assert!(complete(&journaled(
            &mut store,
            &mut io,
            &lineage,
            newest()
        )));
        assert_eq!(
            state_of(&store, &old),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
    }

    /// Switching from a snapshot policy to Union reopens what the snapshot
    /// policy superseded: Union owes those generations an import.
    #[test]
    fn a_policy_switch_reopens_superseded_generations() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        journaled(&mut store, &mut io, &lineage, newest());
        assert!(
            !stored_status(&store, &lineage).is_complete(),
            "pending under Union"
        );
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(complete(&run));
        assert_eq!(store.get_secret(b"room:o").as_deref(), Some(&b"O"[..]));
    }

    /// Under `...ContinuePastUnresponsive` a silent newest generation stays
    /// pending while what the authoritative snapshot below it supersedes is
    /// resolved.
    #[test]
    fn continue_past_unresponsive_resolves_what_the_authoritative_snapshot_supersedes() {
        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let lineage = [g1, g2, g3];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .dead(&key_of(&g3))
            .executable_with(&key_of(&g2), &[(b"room:2", b"2")])
            .executable_with(&key_of(&g1), &[(b"room:1", b"1")]);
        let policy = SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
            RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
        );
        let run = journaled(&mut store, &mut io, &lineage, policy);
        assert!(matches!(
            state_of(&store, &g3),
            JournalState::Pending { .. }
        ));
        assert_eq!(
            state_of(&store, &g1),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
        assert!(!complete(&run));
    }

    /// Under Union a generation behind a `WriterUnavailable` halt stays pending
    /// even when an even newer generation imported.
    #[test]
    fn union_keeps_a_generation_behind_a_halt_pending_even_after_a_newer_import() {
        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let lineage = [g1, g2, g3];
        let mut writer = InspectingWriter::new(&lineage);
        // Started first: a marker fault while STARTING the journal refuses the
        // walk outright (`a_marker_fault_while_starting_the_journal_refuses`).
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        writer.fail_marker_read.insert(key_of(&g2).bytes().to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:3", b"3")])
            .executable_with(&key_of(&g1), &[(b"room:1", b"1")]);
        let run = writer.run(&mut io, union());
        assert!(matches!(
            run.report.predecessors[2],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(matches!(
            state_of(&writer.store, &g1),
            JournalState::Pending { .. }
        ));
        assert!(!complete(&run));
    }

    /// A successor that already ran the plain walk (every adopter upgrading)
    /// adopts the journal and completes from its existing markers.
    #[test]
    fn adopting_the_journal_after_the_plain_walk_completes_from_markers() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &lineage,
            ack(),
            newest(),
        ));
        let run = journaled(&mut store, &mut io, &lineage, newest());
        assert!(complete(&run));
        assert_eq!(
            state_of(&store, &new),
            JournalState::Resolved(JournalResolution::Imported)
        );
    }

    /// Re-running on a complete journal changes nothing.
    #[test]
    fn a_rerun_on_a_complete_journal_changes_nothing() {
        let (empty, holder) = (entry(1, 1), entry(2, 2));
        let lineage = [empty, holder];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&empty), &[])
            .executable_with(&key_of(&holder), &[(b"room:a", b"A")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        let before = store.get_secret(MIGRATION_JOURNAL_KEY);
        store.set_secret(b"room:a", b"A-edited");
        let mut io = MockIo::default()
            .dead(&key_of(&empty))
            .executable_with(&key_of(&holder), &[(b"room:a", b"A")]);
        let rerun = journaled(&mut store, &mut io, &lineage, union());
        assert!(complete(&rerun), "a resolution never regresses");
        assert!(!io.fetched.contains(key_of(&holder).bytes()));
        assert_eq!(
            store.get_secret(b"room:a").as_deref(),
            Some(&b"A-edited"[..])
        );
        assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), before);
    }

    /// The user keeps using the app between an interrupted import and the
    /// recovery run; the recovery must merge, never clobber.
    #[test]
    fn recovery_after_user_activity_never_clobbers_newer_successor_data() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.retryable_fail.insert(b"room:b".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]);
        writer.run(&mut io, union());
        writer.store.set_secret(b"room:a", b"A-newer");
        writer.store.set_secret(b"room:new", b"made since");
        writer.retryable_fail.clear();
        assert!(complete(&writer.run(&mut io, union())));
        assert_eq!(
            writer.store.get_secret(b"room:a").as_deref(),
            Some(&b"A-newer"[..])
        );
        assert_eq!(
            writer.store.get_secret(b"room:b").as_deref(),
            Some(&b"B"[..])
        );
        assert_eq!(
            writer.store.get_secret(b"room:new").as_deref(),
            Some(&b"made since"[..])
        );
    }

    // -- concurrency, and writes outside the walk ----------------------------------

    /// Read-merge-write: another session's journal store between our load and our
    /// final store keeps its import flag; a stale session cannot erase it.
    #[test]
    fn a_concurrent_sessions_import_flag_survives_our_store() {
        let (ours, theirs) = (entry(1, 1), entry(2, 2));
        let lineage = [ours, theirs];
        let mut writer = InspectingWriter::new(&lineage);
        let mut other = MigrationJournal::new_pending(&lineage);
        other.mark_import_started(&key_of(&theirs), 2);
        writer.inject_at_first_item = Some(other.encode());
        let mut io = MockIo::default()
            .executable_with(&key_of(&ours), &[(b"room:a", b"A")])
            .silent_export(&key_of(&theirs));
        let run = writer.run(&mut io, union());
        assert!(matches!(
            state_of(&writer.store, &theirs),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
        assert!(interrupted(&run));
    }

    /// An app writing migrated data outside the walk announces it; until a walk
    /// resolves the predecessor the journal reports an interrupted import.
    #[test]
    fn an_app_import_outside_the_walk_is_flagged_until_the_walk_resolves_it() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        assert!(stored_status(&store, &lineage).interrupted_import());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
    }

    /// An import starting on a predecessor resolved as holding nothing reopens
    /// it, and a failed write then keeps it pending.
    #[test]
    fn an_import_starting_on_a_no_data_resolution_reopens_it() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.record(&k, 1, resolved(JournalResolution::NoData));
        assert!(journal.mark_import_started(&k, 1));
        assert!(journal
            .status(&lineage, &union_binding())
            .interrupted_import());
    }

    /// A predecessor's stored journal is never offered to the successor's writer.
    #[test]
    fn a_predecessors_journal_is_never_imported() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        let mut io = MockIo::default()
            .executable_with(&k, &[(MIGRATION_JOURNAL_KEY, b"forged"), (b"room:a", b"A")]);
        writer.run(&mut io, union());
        assert_eq!(writer.offered, vec![b"room:a".to_vec()]);
        assert_ne!(
            writer.store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
            Some(&b"forged"[..])
        );
    }

    // -- the stored form -------------------------------------------------------------

    /// The pure read of stored bytes is conservative.
    #[test]
    fn journal_status_reads_the_stored_bytes_conservatively() {
        let (a, b) = (entry(1, 1), entry(2, 2));
        let binding = union_binding();
        assert_eq!(
            journal_status(None, &[a], &binding),
            JournalStatus::NotStarted
        );
        let garbage = journal_status(Some(b"not cbor"), &[a], &binding);
        assert!(matches!(garbage, JournalStatus::Unreadable(_)));
        assert!(garbage.interrupted_import());
        let mut only_a = MigrationJournal::new_pending(&[a]);
        only_a.record(&key_of(&a), 1, resolved(JournalResolution::NoData));
        let bytes = only_a.encode();
        assert!(journal_status(Some(&bytes), &[a], &binding).is_complete());
        assert!(!journal_status(Some(&bytes), &[a, b], &binding).is_complete());
        assert!(journal_status(Some(&bytes), &[], &binding).is_complete());
    }

    /// Every state round-trips; versions, unknown states, policies and trailing
    /// bytes are rejected; duplicate entries merge conservatively.
    #[test]
    fn the_journal_encoding_round_trips_and_rejects_what_it_does_not_know() {
        let lineage: Vec<_> = (1..=5).map(|g| entry(g, g as u8)).collect();
        let mut journal = MigrationJournal::new_pending(&lineage);
        let outcomes = [
            resolved(JournalResolution::Imported),
            resolved(JournalResolution::NoData),
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 7,
                revision: 3,
                items_seen: 0,
            }),
            resolved(JournalResolution::SupersededByAuthoritative),
            RunOutcome::Unresolved { absent: true },
        ];
        for (e, o) in lineage.iter().zip(outcomes) {
            journal.record(&key_of(e), e.generation, o);
        }
        journal.mark_import_started(&key_of(&lineage[4]), 5);
        assert_eq!(
            MigrationJournal::decode(&journal.encode()).unwrap(),
            journal
        );

        let wire = journal.encode();
        for v in [0u8, 2, 255] {
            let mut w = wire.clone();
            let pos = w.windows(2).position(|x| x == [0x61, b'v']).unwrap() + 2;
            w[pos] = if v < 24 { v } else { 0x18 };
            if v >= 24 {
                w.insert(pos + 1, v);
            }
            assert_eq!(
                MigrationJournal::decode(&w),
                Err(JournalDecodeError::UnknownVersion(u64::from(v))),
                "version {v}"
            );
        }
        // A version that does not fit the byte this build writes is still a
        // version, never "corrupt" (which would license overwriting it).
        {
            let mut w = wire.clone();
            let pos = w.windows(2).position(|x| x == [0x61, b'v']).unwrap() + 2;
            w.splice(pos..=pos, [0x19, 0x01, 0x00]);
            assert_eq!(
                MigrationJournal::decode(&w),
                Err(JournalDecodeError::UnknownVersion(256))
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0x00);
        assert!(matches!(
            MigrationJournal::decode(&trailing),
            Err(JournalDecodeError::Corrupt(_))
        ));
        let mut bad_state = wire;
        let pos = bad_state
            .windows(6)
            .position(|x| x == b"\x65state")
            .unwrap()
            + 6;
        bad_state[pos] = 0x03;
        assert!(matches!(
            MigrationJournal::decode(&bad_state),
            Err(JournalDecodeError::Corrupt(_))
        ));
    }

    /// Resolution is sticky; the only change allowed is towards data, and a
    /// non-data resolution never overrides an import in progress.
    #[test]
    fn a_resolution_only_ever_upgrades_towards_data() {
        let e = entry(1, 1);
        let k = key_of(&e);
        let mut j = MigrationJournal::new_pending(&[e]);
        j.record(&k, 1, resolved(JournalResolution::NoData));
        j.record(&k, 1, RunOutcome::Unresolved { absent: false });
        assert_eq!(
            j.entry(&k).unwrap().state,
            JournalState::Resolved(JournalResolution::NoData)
        );
        j.record(&k, 1, resolved(JournalResolution::Imported));
        assert_eq!(
            j.entry(&k).unwrap().state,
            JournalState::Resolved(JournalResolution::Imported)
        );
        j.record(&k, 1, resolved(JournalResolution::NoData));
        assert_eq!(
            j.entry(&k).unwrap().state,
            JournalState::Resolved(JournalResolution::Imported)
        );

        let mut flagged = MigrationJournal::new_pending(&[e]);
        flagged.mark_import_started(&k, 1);
        flagged.record(&k, 1, resolved(JournalResolution::NoData));
        assert!(matches!(
            flagged.entry(&k).unwrap().state,
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    // -- round 2 of the #38 review --------------------------------------------------

    /// A switch from a snapshot policy to Union must reopen what the snapshot
    /// policy superseded even when the reopened generation does NOT answer on the
    /// switch run. Before the fix the stale stored `SupersededByAuthoritative` won
    /// the merge and the journal read `Complete` with that generation's data never
    /// imported.
    #[test]
    fn a_policy_switch_with_a_silent_superseded_generation_stays_incomplete() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        assert!(complete(&journaled(
            &mut store,
            &mut io,
            &lineage,
            newest()
        )));
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .silent_export(&key_of(&old));
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(!complete(&run), "in-run status: {:?}", run.status);
        assert!(!stored_status(&store, &lineage).is_complete());
        // And it stays open on the next silent load too.
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(!complete(&run));
        assert!(!store.has_secret(b"room:o"));
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        assert_eq!(store.get_secret(b"room:o").as_deref(), Some(&b"O"[..]));
    }

    /// The same, through a mid-walk flag store (which also merges the stored
    /// journal) on a third generation.
    #[test]
    fn a_policy_switch_survives_a_mid_walk_flag_store() {
        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let lineage = [g1, g2, g3];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:3", b"3")])
            .executable_with(&key_of(&g2), &[(b"room:2", b"2")])
            .executable_with(&key_of(&g1), &[(b"room:1", b"1")]);
        assert!(complete(&journaled(
            &mut store,
            &mut io,
            &lineage,
            newest()
        )));
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:3", b"3")])
            .executable_with(&key_of(&g2), &[(b"room:2", b"2")])
            .silent_export(&key_of(&g1));
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(!complete(&run), "{:?}", run.status);
        assert!(!stored_status(&store, &lineage).is_complete());
    }

    /// A revision bump whose retry still rejects the item converges at the new
    /// revision instead of reopening on every load.
    #[test]
    fn a_revision_bump_with_a_persisting_rejection_converges() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        writer.revision = 1;
        let run = writer.run(&mut io, union());
        assert_eq!(
            run.status,
            Some(JournalStatus::Complete { rejected_items: 1 })
        );
        assert!(matches!(
            state_of(&writer.store, &lineage[0]),
            JournalState::Resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 1,
                ..
            })
        ));
    }

    /// After a revision bump, a silent predecessor keeps the reopened rejection
    /// open (and still counted).
    #[test]
    fn a_revision_bump_with_a_silent_predecessor_stays_incomplete() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        writer.revision = 1;
        let run = writer.run(&mut MockIo::default().silent_export(&k), union());
        assert!(!complete(&run));
        assert!(!journal_status(
            writer.store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
            &lineage,
            &JournalBinding::new(&union(), 1),
        )
        .is_complete());
    }

    /// Rejections are counted and stamped with the run's revision.
    #[test]
    fn rejections_are_counted_and_stamped_at_the_runs_revision() {
        let lineage = [entry(1, 1)];
        let mut writer = InspectingWriter::new(&lineage);
        writer.revision = 2;
        writer.permanent_fail.insert(b"room:x".to_vec());
        writer.permanent_fail.insert(b"room:y".to_vec());
        let mut io = MockIo::default().executable_with(
            &key_of(&lineage[0]),
            &[(b"room:a", b"A"), (b"room:x", b"?"), (b"room:y", b"?")],
        );
        let run = writer.run(&mut io, union());
        assert_eq!(
            run.status,
            Some(JournalStatus::Complete { rejected_items: 2 })
        );
        assert!(matches!(
            state_of(&writer.store, &lineage[0]),
            JournalState::Resolved(JournalResolution::ImportedWithRejections {
                rejected: 2,
                revision: 2,
                ..
            })
        ));
        assert_eq!(
            journal_status(
                writer.store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
                &lineage,
                &JournalBinding::new(&union(), 2),
            ),
            JournalStatus::Complete { rejected_items: 2 }
        );
    }

    /// `rejected_items` is reported while the journal is still incomplete, so a
    /// lineage with a never-installed generation does not hide it.
    #[test]
    fn rejections_are_reported_while_incomplete() {
        let (absent, holder) = (entry(1, 1), entry(2, 2));
        let lineage = [absent, holder];
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&holder), &[(b"room:a", b"A"), (b"room:x", b"?")])
            .not_installed(&key_of(&absent));
        let run = writer.run(&mut io, union());
        let status = run.status.expect("stored");
        assert!(!status.is_complete());
        assert_eq!(status.rejected_items(), 1);
    }

    /// After a corrupt journal, a predecessor that answers "nothing" resolves:
    /// a corrupt journal is rebuilt from the markers, and nothing marked it.
    #[test]
    fn a_corrupt_journal_then_an_empty_predecessor_converges() {
        let (empty, holder) = (entry(1, 1), entry(2, 2));
        let lineage = [empty, holder];
        let mut store = MemStore::default();
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        let mut io = MockIo::default()
            .executable_with(&key_of(&empty), &[])
            .executable_with(&key_of(&holder), &[(b"room:a", b"A")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(complete(&run), "{:?}", run.status);
        assert!(!interrupted(&run));
    }

    /// The same under a snapshot policy, where the older generation can only ever
    /// resolve as superseded.
    #[test]
    fn a_corrupt_journal_converges_under_a_snapshot_policy() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        let run = journaled(&mut store, &mut io, &lineage, newest());
        assert!(complete(&run), "{:?}", run.status);
    }

    /// The walk, like `begin`, rebuilds a corrupt journal from the markers.
    #[test]
    fn the_walk_rebuilds_a_corrupt_journal_from_the_markers() {
        let (partial, absent) = (entry(1, 1), entry(2, 2));
        let lineage = [partial, absent];
        let mut store = MemStore::default();
        store.set_secret(
            &pred_wip_marker(&key_of(&partial)),
            PRED_DONE_MARKER_VALUE_DATA,
        );
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        let mut io = MockIo::default()
            .silent_export(&key_of(&partial))
            .not_installed(&key_of(&absent));
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(interrupted(&run), "{:?}", run.status);
        assert!(matches!(
            state_of(&store, &partial),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
        // Nothing marked the never-installed generation, so a corrupt journal
        // leaves no stuck flag on it.
        assert!(matches!(
            state_of(&store, &absent),
            JournalState::Pending {
                import: ImportFlag::None,
                ..
            }
        ));
    }

    /// ...and refuses the walk if that replacement cannot be stored.
    #[test]
    fn the_walk_refuses_when_a_corrupt_journal_cannot_be_replaced() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        store.fail_writes_to(MIGRATION_JOURNAL_KEY);
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(run.status.is_none());
        assert!(refused(&run), "{:?}", run.report);
        assert!(!store.has_secret(b"room:a"));
    }

    /// A journal that turns corrupt between our load and our store (a torn write)
    /// may have held another session's flags: it is rebuilt from the markers and
    /// merged in, never silently overwritten by our view.
    #[test]
    fn a_journal_found_corrupt_at_the_reread_is_rebuilt_from_the_markers() {
        let (other, holder) = (entry(1, 1), entry(2, 2));
        let lineage = [other, holder];
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        // Then another session started importing `other` (its marker says so),
        // and its journal write is what will be found corrupt.
        writer.store.set_secret(
            &pred_wip_marker(&key_of(&other)),
            PRED_DONE_MARKER_VALUE_DATA,
        );
        writer.inject_at_first_item = Some(b"\xa1\x61v\x01garbage".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&holder), &[(b"room:a", b"A")])
            .silent_export(&key_of(&other));
        let run = writer.run(&mut io, union());
        assert!(matches!(
            state_of(&writer.store, &other),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
        assert_eq!(
            state_of(&writer.store, &holder),
            JournalState::Resolved(JournalResolution::Imported)
        );
        assert!(interrupted(&run));
    }

    /// An app-announced import followed by a "nothing" answer stays pending: the
    /// predecessor had data when the app read it, so the empty answer is not
    /// believed. (By design; the walk must see what the app's sweep saw.)
    #[test]
    fn an_app_import_followed_by_an_empty_answer_stays_pending() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[]),
            &lineage,
            union(),
        );
        assert!(!complete(&run));
        assert!(interrupted(&run));
    }

    /// `note_app_import_started` fails closed on every journal fault, and never
    /// overwrites what it could not read.
    #[test]
    fn note_app_import_started_fails_closed() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);

        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).unwrap();
        w.fail_journal_store_number = Some(w.journal_stores + 1);
        assert!(block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None
        ))
        .is_err());

        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).unwrap();
        let before = w.store.get_secret(MIGRATION_JOURNAL_KEY);
        w.fail_journal_load = true;
        assert!(block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None
        ))
        .is_err());
        assert_eq!(w.store.get_secret(MIGRATION_JOURNAL_KEY), before);

        // The re-read before the store fails.
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).unwrap();
        let before = w.store.get_secret(MIGRATION_JOURNAL_KEY);
        w.fail_journal_load_number = Some(w.journal_loads + 2);
        assert!(block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None
        ))
        .is_err());
        assert_eq!(w.store.get_secret(MIGRATION_JOURNAL_KEY), before);

        let mut wire = MigrationJournal::new_pending(&lineage).encode();
        let pos = wire.windows(2).position(|w| w == [0x61, b'v']).unwrap() + 2;
        wire[pos] = 0x02;
        let mut store = MemStore::default();
        store.set_secret(MIGRATION_JOURNAL_KEY, &wire);
        assert_eq!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &k,
                &union(),
                None
            )),
            Err(JournalError::ForeignVersion(2))
        );
        assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), Some(wire));

        let mut store = MemStore::default();
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        assert!(block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None
        ))
        .is_err());
        assert_eq!(
            store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
            Some(&b"\xa1\x61v\x01garbage"[..])
        );
    }

    /// `begin` never overwrites a journal it could not read.
    #[test]
    fn begin_never_overwrites_a_journal_it_could_not_read() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = InspectingWriter::new(&lineage);
        let mut j = MigrationJournal::new_pending(&lineage);
        j.mark_import_started(&k, 1);
        let before = j.encode();
        w.store.set_secret(MIGRATION_JOURNAL_KEY, &before);
        w.fail_journal_load = true;
        assert!(block_on(begin_migration_journal(&mut w, &lineage, &union())).is_err());
        assert_eq!(w.store.get_secret(MIGRATION_JOURNAL_KEY), Some(before));
    }

    /// A marker that cannot be read while starting a journal makes the start
    /// undecidable: `begin` errs and the walk is refused, nothing stored.
    #[test]
    fn a_marker_fault_while_starting_the_journal_refuses() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = InspectingWriter::new(&lineage);
        w.fail_marker_read.insert(k.bytes().to_vec());
        assert!(block_on(begin_migration_journal(&mut w, &lineage, &union())).is_err());
        assert!(w.store.get_secret(MIGRATION_JOURNAL_KEY).is_none());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        let run = w.run(&mut io, union());
        assert!(run.status.is_none() && refused(&run));
        assert!(w.offered.is_empty());
    }

    /// Two sessions both find no journal. One starts it and flags an import while
    /// the other is still reading markers; the other's first store must merge,
    /// not erase the flag.
    #[test]
    fn a_first_store_merges_a_journal_another_session_started_meanwhile() {
        let lineage = [entry(1, 1), entry(2, 2)];
        let mut w = InspectingWriter::new(&lineage);
        let mut theirs = MigrationJournal::new_pending(&lineage);
        theirs.mark_import_started(&key_of(&lineage[0]), 1);
        w.inject_at_first_marker_read = Some(theirs.encode());
        let status = block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        assert!(status.interrupted_import(), "{status:?}");
        assert!(matches!(
            state_of(&w.store, &lineage[0]),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// A failed re-read before the import-flag store imports nothing.
    #[test]
    fn a_failed_reread_before_the_flag_store_imports_nothing() {
        let lineage = [entry(1, 1)];
        let mut w = InspectingWriter::new(&lineage);
        // Load #1: the walk's start (none stored). #2: the start store's re-read.
        // #3: the flag store's re-read.
        w.fail_journal_load_number = Some(3);
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")]);
        let run = w.run(&mut io, union());
        assert!(w.offered.is_empty(), "offered {:?}", w.offered);
        assert!(run
            .journal_error
            .as_deref()
            .is_some_and(|e| e.contains("journal import flag failed")));
    }

    /// A vetoed import flag on the newest generation must stop the walk, or an
    /// older generation writes its value for the same key first and a
    /// never-clobber writer then declines the newer one.
    #[test]
    fn a_vetoed_flag_on_a_newer_generation_stops_older_ones_writing() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut w = InspectingWriter::new(&lineage);
        // Store #1 starts the journal; #2 is the newest generation's flag.
        w.fail_journal_store_number = Some(2);
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:x", b"new")])
            .executable_with(&key_of(&old), &[(b"room:x", b"old")]);
        let run = w.run(&mut io, union());
        assert!(w.offered.is_empty(), "{:?}", w.offered);
        assert!(!complete(&run));
    }

    /// When the final store fails, the run does not report a status it did not
    /// store.
    #[test]
    fn a_failed_final_store_reports_no_status() {
        let lineage = [entry(1, 1)];
        let mut w = InspectingWriter::new(&lineage);
        // #1 start, #2 flag, #3 final.
        w.fail_journal_store_number = Some(3);
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")]);
        let run = w.run(&mut io, union());
        assert!(run.status.is_none());
        assert!(run.journal_error.is_some());
        assert!(!stored_status(&w.store, &lineage).is_complete());
    }

    /// Three generations under a snapshot policy: the two older ones resolve as
    /// superseded behind the newest.
    #[test]
    fn three_generations_under_a_snapshot_policy_complete() {
        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let lineage = [g1, g2, g3];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:3", b"3")])
            .executable_with(&key_of(&g2), &[(b"room:2", b"2")])
            .executable_with(&key_of(&g1), &[(b"room:1", b"1")]);
        assert!(complete(&journaled(
            &mut store,
            &mut io,
            &lineage,
            newest()
        )));
    }

    /// An empty newest generation and a silent middle one: the oldest is behind an
    /// unresolved predecessor, not an authoritative one, and stays pending.
    #[test]
    fn superseded_behind_an_empty_newest_and_a_silent_middle_stays_pending() {
        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let lineage = [g1, g2, g3];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[])
            .dead(&key_of(&g2))
            .executable_with(&key_of(&g1), &[(b"room:1", b"1")]);
        let run = journaled(&mut store, &mut io, &lineage, newest());
        assert!(matches!(
            run.report.predecessors[2],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(matches!(
            state_of(&store, &g1),
            JournalState::Pending { .. }
        ));
    }

    /// An empty executable predecessor resolves as `NoData` and is not an
    /// interrupted import; a complete journal never reads interrupted.
    #[test]
    fn an_empty_predecessor_resolves_no_data_and_complete_is_never_interrupted() {
        let lineage = [entry(1, 1)];
        let mut store = MemStore::default();
        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&key_of(&lineage[0]), &[]),
            &lineage,
            union(),
        );
        assert_eq!(
            state_of(&store, &lineage[0]),
            JournalState::Resolved(JournalResolution::NoData)
        );
        assert!(complete(&run) && !interrupted(&run));
    }

    /// Rows never examined (behind a halt) keep their attempts and absent streak.
    #[test]
    fn an_unexamined_predecessor_keeps_its_attempts_and_absent_streak() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        // Under NewestSnapshotWins a silent newest generation halts the walk, so the
        // older one is never asked.
        let mut store = MemStore::default();
        for _ in 0..2 {
            journaled(
                &mut store,
                &mut MockIo::default()
                    .not_installed(&key_of(&old))
                    .dead(&key_of(&new)),
                &lineage,
                union(),
            );
        }
        journaled(
            &mut store,
            &mut MockIo::default().dead(&key_of(&new)),
            &lineage,
            newest(),
        );
        assert!(matches!(
            state_of(&store, &old),
            JournalState::Pending {
                attempts: 2,
                absent_streak: 2,
                ..
            }
        ));
    }

    /// A zero streak threshold still needs a "not installed" answer.
    #[test]
    fn pending_all_absent_needs_at_least_one_answer() {
        let lineage = [entry(1, 1)];
        let j = MigrationJournal::new_pending(&lineage);
        assert!(!j.status(&lineage, &union_binding()).pending_all_absent(0));
    }

    /// The encoder writes each predecessor once; a journal listing one twice is
    /// not this crate's, and is corrupt.
    #[test]
    fn a_journal_listing_a_predecessor_twice_is_corrupt() {
        let lineage = [entry(1, 1)];
        let mut j = MigrationJournal::new_pending(&lineage);
        j.record(
            &key_of(&lineage[0]),
            1,
            resolved(JournalResolution::Imported),
        );
        let wire = j.encode();
        let at = wire.windows(8).position(|x| x == b"\x67entries").unwrap() + 8;
        assert_eq!(wire[at], 0x81, "a one-entry array");
        let entry_bytes = wire[at + 1..].to_vec();
        let mut twice = wire[..at].to_vec();
        twice.push(0x82);
        twice.extend_from_slice(&entry_bytes);
        twice.extend_from_slice(&entry_bytes);
        assert!(matches!(
            MigrationJournal::decode(&twice),
            Err(JournalDecodeError::Corrupt(_))
        ));
    }

    /// A generation reopened by a policy switch is counted like any pending one:
    /// its "not installed" answers build an absent streak, rather than being lost
    /// to the stale resolution it was reopened from.
    #[test]
    fn a_reopened_superseded_generation_counts_its_absent_streak() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        assert!(complete(&journaled(
            &mut store,
            &mut io,
            &lineage,
            newest()
        )));
        for _ in 0..2 {
            let mut io = MockIo::default()
                .executable_with(&key_of(&new), &[(b"room:n", b"N")])
                .not_installed(&key_of(&old));
            journaled(&mut store, &mut io, &lineage, union());
        }
        assert!(matches!(
            state_of(&store, &old),
            JournalState::Pending {
                attempts: 2,
                absent_streak: 2,
                ..
            }
        ));
        assert!(stored_status(&store, &lineage).pending_all_absent(2));
    }

    /// An older build of the app (a lower import revision) running after a newer
    /// one must not downgrade a rejection's revision, or the newer build would
    /// reopen it on every load.
    #[test]
    fn an_older_build_does_not_downgrade_a_rejection_revision() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        writer.revision = 1;
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        // An older tab, at revision 0, still running. Its walk re-imports nothing new
        // (the predecessor has no done marker, so it is retried) and rejects again.
        writer.revision = 0;
        writer.run(&mut io, union());
        assert!(matches!(
            state_of(&writer.store, &lineage[0]),
            JournalState::Resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 1,
                ..
            })
        ));
    }

    // -- round 3 of the #38 review --------------------------------------------------

    /// Store `journal` as the successor's journal.
    fn put_journal(store: &mut MemStore, journal: &MigrationJournal) {
        store.set_secret(MIGRATION_JOURNAL_KEY, &journal.encode());
    }

    /// A journal flag with no marker behind it (a tab died between the journal
    /// flag and the in-progress marker) is still proof the predecessor holds data:
    /// an empty answer is a silence, not `NoData`, and nothing is sealed. When the
    /// data comes back, it imports.
    #[test]
    fn a_journal_flag_without_a_marker_is_not_sealed_by_an_empty_answer() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&k, 1);
        put_journal(&mut store, &journal);

        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[]),
            &lineage,
            union(),
        );
        assert!(matches!(
            run.report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(
            store.get_secret(&pred_done_marker(&k)).is_none(),
            "not sealed"
        );
        assert!(interrupted(&run));

        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(complete(&run), "{:?}", run.status);
        assert_eq!(store.get_secret(b"room:a").as_deref(), Some(&b"A"[..]));
    }

    /// A `Done { had_data: false }` seal that contradicts a started import (the
    /// app flagged a predecessor an earlier walk had sealed empty) is not
    /// believed: the predecessor is asked again, and its data imports.
    #[test]
    fn an_empty_seal_contradicting_a_started_import_is_asked_again() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[]),
            &lineage,
            union(),
        );
        assert!(complete(&run));
        assert_eq!(
            store.get_secret(&pred_done_marker(&k)).as_deref(),
            Some(PRED_DONE_MARKER_VALUE_EMPTY)
        );
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(io.fetched.contains(k.bytes()), "asked again");
        assert!(complete(&run), "{:?}", run.status);
        assert_eq!(store.get_secret(b"room:a").as_deref(), Some(&b"A"[..]));
    }

    /// Under `ContinuePastUnresponsive`, an app-flagged newer generation that goes
    /// silent halts the walk, exactly as a data-bearing in-progress marker does:
    /// an older generation must not land first and shadow it.
    #[test]
    fn an_app_flagged_silent_generation_halts_continue_past_unresponsive() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let policy = || {
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            )
        };
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &policy(),
        ))
        .expect("begin");
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &key_of(&new),
            &policy(),
            None,
        ))
        .expect_flagged("flag");
        store.set_secret(b"room:b", b"new");
        let mut io = MockIo::default()
            .dead(&key_of(&new))
            .executable_with(&key_of(&old), &[(b"room:b", b"old"), (b"room:c", b"old")]);
        let run = journaled(&mut store, &mut io, &lineage, policy());
        assert!(matches!(
            run.report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(
            !store.has_secret(b"room:c"),
            "the older generation was not imported"
        );
        assert!(!complete(&run));
    }

    /// The empty-after-data rule follows each policy's termination rule: it halts
    /// `ContinuePastUnresponsive` (the predecessor is proven data-bearing) and
    /// walks on under Union, like any unresponsive predecessor there.
    #[test]
    fn an_empty_answer_after_data_terminates_per_policy() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let interrupted_newer = |store: &mut MemStore| {
            store.set_secret(&pred_wip_marker(&key_of(&new)), PRED_DONE_MARKER_VALUE_DATA);
        };
        let io = || {
            MockIo::default()
                .executable_with(&key_of(&new), &[])
                .executable_with(&key_of(&old), &[(b"room:o", b"O")])
        };

        let mut store = MemStore::default();
        interrupted_newer(&mut store);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io(),
            &lineage,
            ack(),
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            ),
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(!store.has_secret(b"room:o"));

        let mut store = MemStore::default();
        interrupted_newer(&mut store);
        let report = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io(),
            &lineage,
            ack(),
            union(),
        ));
        assert!(matches!(
            report.predecessors[1],
            PredecessorMigration::Imported { .. }
        ));
        assert!(store.has_secret(b"room:o"));
        // A plain-walk adopter sees why, and that it is worth retrying.
        assert!(report.predecessors[0].exported_nothing_after_data());
        assert!(!report.predecessors[1].exported_nothing_after_data());
        assert!(report.retry_may_help());
        assert!(!report.is_complete());
    }

    /// A predecessor whose in-progress marker saw data is flagged in the journal
    /// before anything else happens, even when the journal predates the marker
    /// (an older tab's plain walk) and the probe then fails.
    #[test]
    fn a_data_marker_flags_the_journal_whatever_the_probe_answers() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_DATA);
        let run = journaled(
            &mut store,
            &mut MockIo::default().dead(&k),
            &lineage,
            union(),
        );
        assert!(interrupted(&run), "{:?}", run.status);
    }

    /// An in-progress marker that saw NO data is not a started import.
    #[test]
    fn an_empty_in_progress_marker_is_not_a_started_import() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(!status.interrupted_import());
        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[]),
            &lineage,
            union(),
        );
        assert!(complete(&run), "{:?}", run.status);
    }

    /// `note_app_import_started` before any journal is stored is refused: it would
    /// otherwise start a journal that skips `begin`'s marker seeding.
    #[test]
    fn note_app_import_started_needs_a_journal() {
        let lineage = [entry(1, 1), entry(2, 2)];
        let mut store = MemStore::default();
        assert!(block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &key_of(&lineage[0]),
            &union(),
            None
        ))
        .is_err());
        assert!(store.get_secret(MIGRATION_JOURNAL_KEY).is_none());
        assert!(store
            .get_secret(&pred_wip_marker(&key_of(&lineage[0])))
            .is_none());
    }

    /// A rejection reopened by a higher revision keeps its count while it stays
    /// pending, even after a run that could not reach the predecessor.
    #[test]
    fn a_reopened_rejection_keeps_its_count_until_it_resolves() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        writer.revision = 1;
        let run = writer.run(&mut MockIo::default().silent_export(&k), union());
        assert_eq!(run.status.expect("stored").rejected_items(), 1);
    }

    /// Rejection counts add up across predecessors.
    #[test]
    fn rejections_sum_across_predecessors() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        writer.permanent_fail.insert(b"room:y".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[(b"room:a", b"A"), (b"room:x", b"?")])
            .executable_with(&key_of(&g1), &[(b"room:b", b"B"), (b"room:y", b"?")]);
        let run = writer.run(&mut io, union());
        assert_eq!(
            run.status,
            Some(JournalStatus::Complete { rejected_items: 2 })
        );
    }

    /// At the same revision, a retry that now imports everything upgrades a
    /// rejection resolution to `Imported`, and a retry with fewer rejections
    /// updates the count.
    #[test]
    fn a_same_revision_retry_updates_a_rejection() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.record(
            &k,
            1,
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 2,
                revision: 0,
                items_seen: 0,
            }),
        );
        journal.record(
            &k,
            1,
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 0,
                items_seen: 0,
            }),
        );
        assert_eq!(
            journal.status(&lineage, &union_binding()).rejected_items(),
            1
        );
        journal.record(&k, 1, resolved(JournalResolution::Imported));
        assert_eq!(
            journal.entry(&k).unwrap().state,
            JournalState::Resolved(JournalResolution::Imported)
        );
    }

    /// `begin` reports status under the writer's own import revision.
    #[test]
    fn begin_reports_status_at_the_writers_revision() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        writer.revision = 1;
        let status =
            block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        assert!(!status.is_complete(), "reopened at the higher revision");
    }

    /// A `WriterUnavailable` row was not examined: no attempt is counted.
    #[test]
    fn a_writer_unavailable_row_counts_no_attempt() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        writer.fail_marker_read.insert(k.bytes().to_vec());
        writer.run(
            &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A")]),
            union(),
        );
        assert!(matches!(
            state_of(&writer.store, &lineage[0]),
            JournalState::Pending { attempts: 0, .. }
        ));
    }

    /// `pending_all_absent` needs EVERY pending predecessor absent.
    #[test]
    fn pending_all_absent_needs_every_pending_predecessor() {
        let (absent, silent) = (entry(1, 1), entry(2, 2));
        let lineage = [absent, silent];
        let mut store = MemStore::default();
        for _ in 0..3 {
            let mut io = MockIo::default()
                .not_installed(&key_of(&absent))
                .silent_export(&key_of(&silent));
            journaled(&mut store, &mut io, &lineage, union());
        }
        assert!(!stored_status(&store, &lineage).pending_all_absent(1));
    }

    /// An entry only another session's journal has (a newer lineage) survives our
    /// store.
    #[test]
    fn an_entry_only_the_stored_journal_has_survives_our_store() {
        let lineage = [entry(1, 1)];
        let extra = entry(9, 9);
        let mut store = MemStore::default();
        let mut theirs = MigrationJournal::new_pending(&[lineage[0], extra]);
        theirs.mark_import_started(&key_of(&extra), 9);
        put_journal(&mut store, &theirs);
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")]);
        journaled(&mut store, &mut io, &lineage, union());
        assert!(matches!(
            state_of(&store, &extra),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// An app flag on an already imported predecessor is reported as such (the app
    /// decides whether to write it again) and changes nothing.
    #[test]
    fn an_app_flag_does_not_reopen_an_imported_predecessor() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        assert!(matches!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &k,
                &union(),
                None
            )),
            Ok(AppImport::AlreadyImported)
        ));
        assert!(stored_status(&store, &lineage).is_complete());
    }

    /// A foreign-version journal appearing between our load and our store is not
    /// overwritten, and the run reports no status.
    #[test]
    fn a_foreign_version_found_at_the_reread_is_not_overwritten() {
        let lineage = [entry(1, 1)];
        let mut wire = MigrationJournal::new_pending(&lineage).encode();
        let pos = wire.windows(2).position(|w| w == [0x61, b'v']).unwrap() + 2;
        wire[pos] = 0x02;
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        writer.inject_at_first_item = Some(wire.clone());
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")]);
        let run = writer.run(&mut io, union());
        assert!(run.status.is_none());
        assert_eq!(writer.store.get_secret(MIGRATION_JOURNAL_KEY), Some(wire));
    }

    /// An import flag value the decoder does not know is corrupt, not "none".
    #[test]
    fn an_unknown_import_flag_value_is_corrupt() {
        let lineage = [entry(1, 1)];
        let mut j = MigrationJournal::new_pending(&lineage);
        j.mark_import_started(&key_of(&lineage[0]), 1);
        let mut wire = j.encode();
        let at = wire.windows(7).position(|x| x == b"\x66import").unwrap() + 7;
        assert_eq!(wire[at], 0x01);
        wire[at] = 0x07;
        assert!(matches!(
            MigrationJournal::decode(&wire),
            Err(JournalDecodeError::Corrupt(_))
        ));
    }

    /// A journal's started import outweighs an in-progress marker that saw no
    /// data (an empty attempt whose marker a later import did not overwrite).
    #[test]
    fn a_journal_flag_outweighs_an_empty_in_progress_marker() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&k, 1);
        put_journal(&mut store, &journal);
        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[]),
            &lineage,
            union(),
        );
        assert!(matches!(
            run.report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(store.get_secret(&pred_done_marker(&k)).is_none());
    }

    /// The app's flag is also its predecessor's in-progress marker, so it survives
    /// a corrupt journal: the rebuilt journal still refuses an empty answer.
    #[test]
    fn an_app_flag_survives_a_corrupt_journal() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[]),
            &lineage,
            union(),
        );
        assert!(!complete(&run));
        assert!(interrupted(&run));
        assert!(store.get_secret(&pred_done_marker(&k)).is_none());
    }

    /// A corrupt journal found at the re-read leaves a predecessor this walk never
    /// examined (behind a snapshot policy's halt) flagged from its marker. Both the
    /// rebuild and the post-walk marker check put it there;
    /// `r11_p9_begin_rebuilds_a_journal_found_corrupt_at_its_store` pins the
    /// rebuild alone.
    #[test]
    fn a_corrupt_reread_is_rebuilt_for_unexamined_predecessors_too() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &newest())).expect("begin");
        // Another session's import from g1 started meanwhile.
        writer
            .store
            .set_secret(&pred_wip_marker(&key_of(&g1)), PRED_DONE_MARKER_VALUE_DATA);
        writer.inject_at_first_item = Some(b"\xa1\x61v\x01garbage".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[(b"room:2", b"2")])
            .executable_with(&key_of(&g1), &[(b"room:1", b"1")]);
        let run = writer.run(&mut io, newest());
        assert!(matches!(
            run.report.predecessors[1],
            PredecessorMigration::Superseded { .. }
        ));
        assert!(matches!(
            state_of(&writer.store, &g1),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// Merging keeps the larger rejection count of two pending entries.
    #[test]
    fn a_merge_keeps_a_reopened_rejection_count() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut stored = MigrationJournal::new_pending(&lineage);
        stored.record(
            &k,
            1,
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 3,
                revision: 0,
                items_seen: 0,
            }),
        );
        let mut ours = MigrationJournal::new_pending(&lineage);
        let rev1 = JournalBinding::new(&union(), 1);
        ours.merge_stored(&stored, Some(&rev1));
        assert_eq!(ours.status(&lineage, &rev1).rejected_items(), 3);
    }

    // -- round 4 of the #38 review --------------------------------------------------

    /// `store` with its journal removed: a lost journal, or one `SecretStoreIo`
    /// failed to read (it reads back as absent).
    fn without_journal(store: &MemStore) -> MemStore {
        let mut copy = MemStore::default();
        for (k, v) in &store.data {
            if k.as_slice() != MIGRATION_JOURNAL_KEY {
                copy.data.insert(k.clone(), v.clone());
            }
        }
        copy
    }

    /// The marker contract: an in-progress marker that saw data, recorded after an
    /// empty seal, reads back as in progress; and a data in-progress marker is
    /// never downgraded.
    #[test]
    fn a_data_in_progress_marker_outranks_an_empty_seal_and_is_never_downgraded() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let query = MarkerQuery {
            predecessor: &k,
            generation: 1,
            legacy_bridge: LegacyBridge::ExactGenerationOnly,
        };
        let mut store = MemStore::default();
        block_on(store_io(&mut store).record_marker(&k, MigrationMarker::Done { had_data: false }))
            .unwrap();
        block_on(
            store_io(&mut store).record_marker(&k, MigrationMarker::InProgress { saw_data: true }),
        )
        .unwrap();
        assert_eq!(
            block_on(store_io(&mut store).migration_marker(&query)).unwrap(),
            Some(MigrationMarker::InProgress { saw_data: true })
        );
        assert!(!crate::delegate::predecessor_already_migrated(&store, &k));
        assert_eq!(crate::predecessor_migration_had_data(&store, &k), None);
        block_on(
            store_io(&mut store).record_marker(&k, MigrationMarker::InProgress { saw_data: false }),
        )
        .unwrap();
        assert_eq!(
            block_on(store_io(&mut store).migration_marker(&query)).unwrap(),
            Some(MigrationMarker::InProgress { saw_data: true }),
            "not downgraded"
        );
        // A data seal still wins over everything.
        block_on(store_io(&mut store).record_marker(&k, MigrationMarker::Done { had_data: true }))
            .unwrap();
        assert_eq!(
            block_on(store_io(&mut store).migration_marker(&query)).unwrap(),
            Some(MigrationMarker::Done { had_data: true })
        );
    }

    /// An app flag over an empty seal survives a lost or corrupt journal: the
    /// marker it wrote is read, the predecessor is asked again, and the rest of its
    /// data imports.
    #[test]
    fn an_app_flag_over_an_empty_seal_survives_a_lost_or_corrupt_journal() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        for corrupt in [false, true] {
            let mut store = MemStore::default();
            assert!(complete(&journaled(
                &mut store,
                &mut MockIo::default().executable_with(&k, &[]),
                &lineage,
                union()
            )));
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &k,
                &union(),
                None,
            ))
            .expect_flagged("flag");
            store.set_secret(b"room:a", b"A");
            let mut store = if corrupt {
                store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
                store
            } else {
                without_journal(&store)
            };
            let mut io =
                MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]);
            let run = journaled(&mut store, &mut io, &lineage, union());
            assert!(
                io.fetched.contains(k.bytes()),
                "corrupt={corrupt}: asked again"
            );
            assert!(complete(&run), "corrupt={corrupt}: {:?}", run.status);
            assert_eq!(store.get_secret(b"room:b").as_deref(), Some(&b"B"[..]));
        }
    }

    /// A walk's own re-ask over an empty seal, killed part-way, is likewise backed
    /// by its marker when the journal is then lost.
    #[test]
    fn a_reask_killed_part_way_survives_a_lost_journal() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        store.set_secret(&pred_done_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&k, 1);
        put_journal(&mut store, &journal);
        // The re-ask writes its in-progress marker and one item, then dies.
        block_on(
            store_io(&mut store).record_marker(&k, MigrationMarker::InProgress { saw_data: true }),
        )
        .unwrap();
        store.set_secret(b"room:a", b"A");
        let mut store = without_journal(&store);
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(complete(&run), "{:?}", run.status);
        assert_eq!(store.get_secret(b"room:b").as_deref(), Some(&b"B"[..]));
    }

    /// `note_app_import_started` on a rejection a higher revision reopened records
    /// the flag (the stale resolution does not win the merge).
    #[test]
    fn an_app_flag_on_a_revision_reopened_rejection_is_recorded() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        writer.revision = 1;
        block_on(note_app_import_started(
            &mut writer,
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        let status = journal_status(
            writer.store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
            &lineage,
            &JournalBinding::new(&union(), 1),
        );
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// `note_app_import_started` on a predecessor already imported with data
    /// records nothing.
    #[test]
    fn an_app_flag_on_a_completed_import_records_nothing() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        let journal_before = store.get_secret(MIGRATION_JOURNAL_KEY);
        assert!(matches!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &k,
                &union(),
                None
            )),
            Ok(AppImport::AlreadyImported)
        ));
        assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), journal_before);
        assert!(stored_status(&store, &lineage).is_complete());
        let mut j = MigrationJournal::decode(&journal_before.unwrap()).unwrap();
        assert!(
            !j.mark_import_started(&k, 1),
            "an Imported entry is not reopened"
        );
    }

    /// A failed marker write makes `note_app_import_started` fail, with no journal
    /// flag recorded.
    #[test]
    fn note_app_import_started_fails_closed_on_the_marker_write() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        store.fail_writes_to(&pred_wip_marker(&k));
        assert!(block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None
        ))
        .is_err());
        // The journal flag was stored first, so the walk still treats the
        // predecessor as holding data (the safe direction).
        assert!(stored_status(&store, &lineage).interrupted_import());
    }

    /// A fresh journal reads completions off the markers: a successor that ran the
    /// plain walk to completion begins `Complete`, not owing anything.
    #[test]
    fn begin_after_a_completed_plain_walk_is_complete() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:n", b"N")])
            .executable_with(&key_of(&old), &[]);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert_eq!(status, JournalStatus::Complete { rejected_items: 0 });
    }

    /// `begin` on an existing journal reads a lineage entry it has never seen off
    /// its marker.
    #[test]
    fn begin_seeds_an_unseen_lineage_entry_from_its_marker() {
        let (grown, known) = (entry(1, 1), entry(2, 2));
        let mut store = MemStore::default();
        put_journal(&mut store, &MigrationJournal::new_pending(&[known]));
        store.set_secret(
            &pred_wip_marker(&key_of(&grown)),
            PRED_DONE_MARKER_VALUE_DATA,
        );
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[grown, known],
            &union(),
        ))
        .expect("begin");
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// `ContinuePastUnresponsive` halts after a predecessor proven data-bearing on
    /// every kind of silence, not only a missing reply.
    #[test]
    fn continue_past_halts_on_every_silence_after_data() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let policy = || {
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            )
        };
        let silences: [fn(MockIo, &DelegateKey) -> MockIo; 4] = [
            |io, k| io.dead(k),
            |io, k| io.not_installed(k),
            |io, k| io.error_probe(k),
            |io, k| io.silent_export(k),
        ];
        for (i, silence) in silences.iter().enumerate() {
            let mut store = MemStore::default();
            store.set_secret(&pred_wip_marker(&key_of(&new)), PRED_DONE_MARKER_VALUE_DATA);
            let mut io = silence(
                MockIo::default().executable_with(&key_of(&old), &[(b"room:o", b"O")]),
                &key_of(&new),
            );
            let report = block_on(migrate_delegate_secrets(
                &mut store_io(&mut store),
                &mut io,
                &lineage,
                ack(),
                policy(),
            ));
            assert!(
                matches!(
                    report.predecessors[1],
                    PredecessorMigration::Superseded { .. }
                ),
                "silence #{i}: {:?}",
                report.predecessors[1]
            );
            assert!(!store.has_secret(b"room:o"), "silence #{i}");
        }
    }

    /// A predecessor whose in-progress marker saw data is flagged before probing,
    /// and a failure to store that flag stops the walk before anything is written.
    #[test]
    fn the_early_flag_store_failing_vetoes_the_predecessor() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        writer
            .store
            .set_secret(&pred_wip_marker(&key_of(&new)), PRED_DONE_MARKER_VALUE_DATA);
        writer.fail_journal_store_number = Some(writer.journal_stores + 1);
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(b"room:x", b"new")])
            .executable_with(&key_of(&old), &[(b"room:x", b"old")]);
        let run = writer.run(&mut io, union());
        assert!(matches!(
            run.report.predecessors[0],
            PredecessorMigration::WriterUnavailable {
                failure: WriterFailure {
                    stage: WriterStage::JournalFlag,
                    ..
                },
                ..
            }
        ));
        assert!(writer.offered.is_empty(), "{:?}", writer.offered);
        assert!(
            !io.probed.contains(key_of(&new).bytes()),
            "vetoed before the probe"
        );
    }

    /// A data seal beside a journal flag (a tab died between the done marker and
    /// the journal's final store) is believed: no re-fetch, no resurrection.
    #[test]
    fn a_data_seal_beside_a_started_flag_is_not_reimported() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        store.set_secret(&pred_done_marker(&k), PRED_DONE_MARKER_VALUE_DATA);
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&k, 1);
        put_journal(&mut store, &journal);
        let mut io = MockIo::default().executable_with(&k, &[(b"room:deleted", b"X")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(!io.fetched.contains(k.bytes()));
        assert!(!store.has_secret(b"room:deleted"));
        assert!(complete(&run), "{:?}", run.status);
    }

    /// An empty seal beside a journal flag, answered empty again, stays pending as
    /// a silence; it is not re-sealed `NoData` (which under NSW would fall through
    /// to an older generation).
    #[test]
    fn an_empty_seal_beside_a_started_flag_answered_empty_stays_pending() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        store.set_secret(
            &pred_done_marker(&key_of(&new)),
            PRED_DONE_MARKER_VALUE_EMPTY,
        );
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&key_of(&new), 2);
        put_journal(&mut store, &journal);
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        let run = journaled(&mut store, &mut io, &lineage, newest());
        assert!(run.report.predecessors[0].exported_nothing_after_data());
        assert!(
            !store.has_secret(b"room:o"),
            "no fall-through to the older generation"
        );
        assert!(!complete(&run));
    }

    /// Under NSW an empty-sealed newer generation (no journal flag) is fallen
    /// through to the older one, as before.
    #[test]
    fn an_empty_seal_falls_through_to_the_older_generation_under_nsw() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let mut store = MemStore::default();
        store.set_secret(
            &pred_done_marker(&key_of(&new)),
            PRED_DONE_MARKER_VALUE_EMPTY,
        );
        let mut io = MockIo::default().executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &lineage,
            ack(),
            newest(),
        ));
        assert!(store.has_secret(b"room:o"));
    }

    /// The stored bytes keep a reopened rejection's count.
    #[test]
    fn a_pending_rejection_count_survives_the_stored_bytes() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut j = MigrationJournal::new_pending(&lineage);
        j.record(
            &k,
            1,
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 4,
                revision: 0,
                items_seen: 0,
            }),
        );
        let rev1 = JournalBinding::new(&union(), 1);
        j.rebind(&rev1);
        let decoded = MigrationJournal::decode(&j.encode()).unwrap();
        assert_eq!(decoded.status(&lineage, &rev1).rejected_items(), 4);
    }

    /// Under a revision bump the import flag, stored before the re-import, is not
    /// beaten by the stale stored rejection in the flag store's merge: the durable
    /// state at the first item says an import is under way.
    #[test]
    fn the_import_flag_survives_a_stale_rejection_in_the_merge() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        writer.revision = 1;
        writer.permanent_fail.clear();
        writer.status_at_first_item = None;
        let run = writer.run(&mut io, union());
        let at_first = writer.status_at_first_item.expect("an item was offered");
        assert!(at_first.interrupted_import(), "{at_first:?}");
        assert!(complete(&run), "{:?}", run.status);
    }

    /// Ranking: a rejection resolution beats a `NoData` one in a merge.
    #[test]
    fn a_rejection_outranks_no_data_in_a_merge() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut j = MigrationJournal::new_pending(&lineage);
        j.record(
            &k,
            1,
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 0,
                items_seen: 0,
            }),
        );
        j.record(&k, 1, resolved(JournalResolution::NoData));
        assert_eq!(j.status(&lineage, &union_binding()).rejected_items(), 1);
    }

    /// The writer is told a retry is a retry: false on a first attempt, true when
    /// a journal (with no marker) says an import already started.
    #[test]
    fn the_retry_hint_follows_the_evidence() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        writer.run(&mut io, union());
        assert_eq!(writer.retries, vec![false]);

        let mut writer = InspectingWriter::new(&lineage);
        let mut journal = MigrationJournal::new_pending(&lineage);
        journal.mark_import_started(&k, 1);
        writer
            .store
            .set_secret(MIGRATION_JOURNAL_KEY, &journal.encode());
        writer.run(&mut io, union());
        assert_eq!(writer.retries, vec![true]);
    }

    /// The accessor is specific to the empty-after-data case.
    #[test]
    fn exported_nothing_after_data_is_specific() {
        let k = key_of(&entry(1, 1));
        let other = PredecessorMigration::Unresponsive {
            key: k,
            generation: 1,
            error: Some("transport fault".to_string()),
        };
        assert!(!other.exported_nothing_after_data());
    }

    /// Small contracts: nothing pending is not "all absent"; an unseen lineage
    /// entry is pending with no import flag; a version above 255 is foreign.
    #[test]
    fn small_status_and_decode_contracts() {
        let (a, b) = (entry(1, 1), entry(2, 2));
        let mut j = MigrationJournal::new_pending(&[a]);
        j.record(&key_of(&a), 1, resolved(JournalResolution::NoData));
        let status = j.status(&[a], &union_binding());
        assert!(status.is_complete() && !status.pending_all_absent(1));
        let status = j.status(&[a, b], &union_binding());
        assert!(matches!(
            status,
            JournalStatus::Incomplete { ref pending, .. }
                if pending.len() == 1 && pending[0].import == ImportFlag::None
        ));
        let mut w = j.encode();
        let pos = w.windows(2).position(|x| x == [0x61, b'v']).unwrap() + 2;
        w.splice(pos..=pos, [0x19, 0x01, 0x01]);
        assert_eq!(
            MigrationJournal::decode(&w),
            Err(JournalDecodeError::UnknownVersion(257))
        );
    }

    /// `note_app_import_started` writes no marker over a completed data import (a
    /// store keeping one marker per predecessor would otherwise demote `Done`, and
    /// a later walk would re-import, resurrecting deleted keys).
    #[test]
    fn an_app_flag_writes_no_marker_over_a_completed_import() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        assert!(complete(&writer.run(&mut io, union())));
        let before = writer.markers_recorded.len();
        assert!(matches!(
            block_on(note_app_import_started(
                &mut writer,
                &lineage,
                &k,
                &union(),
                None
            )),
            Ok(AppImport::AlreadyImported)
        ));
        assert_eq!(writer.markers_recorded.len(), before);
    }

    // -- round 5 of the #38 review --------------------------------------------------
    //
    // Several of these are the round-5 testing lens's probes, kept as written.

    /// P-A: a contradicted empty seal must not make the primitive say AlreadyMigrated.
    #[test]
    fn r5_primitive_reimports_over_a_contradicted_empty_seal() {
        let k = key_of(&entry(1, 1));
        let mut store = MemStore::default();
        store.set_secret(&pred_done_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_DATA);
        let out =
            import_predecessor_secrets_once(&mut store, &k, &[(b"room:a".to_vec(), b"A".to_vec())]);
        assert!(
            matches!(out, PredecessorImportOutcome::Imported { imported: 1, .. }),
            "{out:?}"
        );
        assert_eq!(store.get_secret(b"room:a").as_deref(), Some(&b"A"[..]));
    }

    /// P-B: a legacy `done:<n>` marker above a generation must not make `begin`
    /// resolve a lower generation under Union (it was barred, never imported).
    #[test]
    fn r5_begin_under_union_does_not_resolve_a_generation_the_legacy_path_barred() {
        let (g3, g5) = (entry(3, 3), entry(5, 5));
        let lineage = [g3, g5];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(!status.is_complete(), "g3 was never imported: {status:?}");
    }

    /// P-C: `note_app_import_started` for a barred generation under Union must flag it.
    #[test]
    fn r5_app_flag_for_a_legacy_barred_generation_is_recorded() {
        let (g3, g5) = (entry(3, 3), entry(5, 5));
        let lineage = [g3, g5];
        let k3 = key_of(&g3);
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k3,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        assert!(
            stored_status(&store, &lineage).interrupted_import(),
            "{:?}",
            stored_status(&store, &lineage)
        );
        assert!(store.has_secret(&pred_wip_marker(&k3)));
    }

    /// P-D: a marker READ fault in `note_app_import_started` refuses.
    #[test]
    fn r5_app_flag_marker_read_fault_refuses() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        writer.fail_marker_read.insert(k.bytes().to_vec());
        let r = block_on(note_app_import_started(
            &mut writer,
            &lineage,
            &k,
            &union(),
            None,
        ));
        assert!(r.is_err(), "{r:?}");
        assert!(writer.markers_recorded.is_empty());
    }

    /// P-E: `begin` over a plain walk's data seal records the predecessor Imported.
    #[test]
    fn r5_begin_records_a_data_seal_as_imported_not_no_data() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert_eq!(
            state_of(&store, &lineage[0]),
            JournalState::Resolved(JournalResolution::Imported)
        );
    }

    /// P-F: an empty-seal predecessor adopted via `begin`, then flagged by the app:
    /// the journal must carry the flag (not just the marker).
    #[test]
    fn r5_app_flag_after_begin_over_an_empty_seal_is_in_the_journal() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[]);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        assert!(block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union()
        ))
        .expect("begin")
        .is_complete());
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        assert!(stored_status(&store, &lineage).interrupted_import());
    }

    /// P-G: `begin` on an existing journal writes nothing.
    #[test]
    fn r5_begin_on_an_existing_journal_writes_nothing() {
        let lineage = [entry(1, 1)];
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        let stores = writer.journal_stores;
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin again");
        assert_eq!(writer.journal_stores, stores);
    }

    /// P-H: note_app with a corrupt journal at the re-read must refuse and not overwrite.
    #[test]
    fn r5_app_flag_corrupt_at_reread_refuses_and_keeps_bytes() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        writer.inject_at_first_marker_read = Some(b"\xa1\x61v\x01garbage".to_vec());
        let r = block_on(note_app_import_started(
            &mut writer,
            &lineage,
            &k,
            &union(),
            None,
        ));
        assert!(r.is_err(), "{r:?}");
        assert_eq!(
            writer.store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
            Some(&b"\xa1\x61v\x01garbage"[..])
        );
    }

    /// P-J: unrecognised marker values read as data-bearing (the documented conservative rule).
    #[test]
    fn r5_unrecognised_marker_values_read_as_data() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let query = MarkerQuery {
            predecessor: &k,
            generation: 1,
            legacy_bridge: LegacyBridge::ExactGenerationOnly,
        };
        let mut store = MemStore::default();
        store.set_secret(&pred_done_marker(&k), b"7");
        assert_eq!(
            block_on(store_io(&mut store).migration_marker(&query)).unwrap(),
            Some(MigrationMarker::Done { had_data: true })
        );
        let mut store = MemStore::default();
        store.set_secret(&pred_wip_marker(&k), b"7");
        assert_eq!(
            block_on(store_io(&mut store).migration_marker(&query)).unwrap(),
            Some(MigrationMarker::InProgress { saw_data: true })
        );
    }

    /// P-L: NSW + a legacy `done:5` marker: a generation ABOVE it (7) was never
    /// covered by the legacy migration and must not read resolved.
    #[test]
    fn r5_nsw_begin_and_flag_do_not_resolve_a_generation_above_the_legacy_marker() {
        let (g3, g7) = (entry(3, 3), entry(7, 7));
        let lineage = [g3, g7];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        match &status {
            JournalStatus::Incomplete { pending, .. } => {
                assert!(pending.iter().any(|p| p.generation == 7), "{status:?}")
            }
            other => panic!("g7 was never imported: {other:?}"),
        }
    }

    /// P-M: same, via the app flag: g7 above the legacy marker must be flagged.
    #[test]
    fn r5_nsw_app_flag_above_the_legacy_marker_is_recorded() {
        let (g3, g7) = (entry(3, 3), entry(7, 7));
        let lineage = [g3, g7];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &key_of(&g7),
            &newest(),
            None,
        ))
        .expect_flagged("flag");
        assert!(stored_status(&store, &lineage).interrupted_import());
    }

    /// P-N: kill sweep where, after each kill, the JOURNAL is also lost (or corrupt):
    /// `begin` must flag a partial copy from the markers, and a healthy load converges.
    #[test]
    fn r5_kill_sweep_with_a_lost_or_corrupt_journal() {
        let lineage = [entry(1, 1), entry(2, 2), entry(3, 3)];
        let io_for = || {
            MockIo::default()
                .executable_with(
                    &key_of(&lineage[2]),
                    &[(b"room:c", b"C"), (b"room:d", b"D")],
                )
                .executable_with(&key_of(&lineage[1]), &[(b"room:b", b"B")])
                .executable_with(&key_of(&lineage[0]), &[(b"room:a", b"A")])
        };
        type Case = (fn() -> SecretSelectionPolicy, &'static [&'static [u8]]);
        let cases: [Case; 2] = [
            (union, &[b"room:a", b"room:b", b"room:c", b"room:d"]),
            (newest, &[b"room:c", b"room:d"]),
        ];
        for (policy, owed) in cases {
            for corrupt in [false, true] {
                for writes in 0..40 {
                    let mut killable = KillableStore {
                        inner: MemStore::default(),
                        budget: writes,
                    };
                    let _ = block_on(migrate_delegate_secrets_journaled(
                        &mut SecretStoreIo::new(
                            &mut killable,
                            NoCrossEntryInvariantsAck::i_certify_these_secrets_have_no_cross_entry_invariants(),
                        ),
                        &mut io_for(),
                        &lineage,
                        ack(),
                        policy(),
                    ));
                    let mut left = if corrupt {
                        let mut s = killable.inner;
                        if s.has_secret(MIGRATION_JOURNAL_KEY) {
                            s.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
                        }
                        s
                    } else {
                        without_journal(&killable.inner)
                    };
                    let all = owed.iter().all(|k| left.has_secret(k));
                    // A predecessor is partially copied when some but not all of ITS items landed (only gen 3 has two).
                    let any = left.has_secret(b"room:c") != left.has_secret(b"room:d");
                    let status = block_on(begin_migration_journal(
                        &mut store_io(&mut left),
                        &lineage,
                        &policy(),
                    ))
                    .expect("begin");
                    assert!(
                        !status.is_complete() || all,
                        "corrupt={corrupt} writes={writes}: Complete with data missing"
                    );
                    assert!(
                        !any || status.interrupted_import(),
                        "corrupt={corrupt} writes={writes}: partial copy unflagged after begin: {status:?}"
                    );
                    let run = journaled(&mut left, &mut io_for(), &lineage, policy());
                    assert!(
                        complete(&run),
                        "corrupt={corrupt} writes={writes}: {:?}",
                        run.status
                    );
                    assert!(owed.iter().all(|k| left.has_secret(k)));
                }
            }
        }
    }

    /// P-O: kill sweep over the APP's flow on an empty-sealed predecessor:
    /// note_app_import_started, then the app writes its items; killed after N writes;
    /// journal lost or not. Never Complete with the data missing; a healthy walk converges.
    #[test]
    fn r5_kill_sweep_over_the_apps_own_import_on_an_empty_seal() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let io_for = || {
            MockIo::default().executable_with(
                &k,
                &[(b"room:a", b"A"), (b"room:b", b"B"), (b"room:c", b"C")],
            )
        };
        for lose_journal in [false, true] {
            for writes in 0..12 {
                // Healthy start: the predecessor was sealed empty by a journaled walk.
                let mut store = MemStore::default();
                let mut empty_io = MockIo::default().executable_with(&k, &[]);
                assert!(complete(&journaled(
                    &mut store,
                    &mut empty_io,
                    &lineage,
                    union()
                )));
                let mut killable = KillableStore {
                    inner: store,
                    budget: writes,
                };
                let flagged = block_on(note_app_import_started(&mut SecretStoreIo::new(
                        &mut killable,
                        NoCrossEntryInvariantsAck::i_certify_these_secrets_have_no_cross_entry_invariants(),
                    ), &lineage, &k, &union(), None));
                // The app writes only if the flag succeeded.
                if flagged.is_ok() {
                    for (key, v) in [(&b"room:a"[..], &b"A"[..]), (b"room:b", b"B")] {
                        killable.set_secret(key, v);
                    }
                }
                let mut left = if lose_journal {
                    without_journal(&killable.inner)
                } else {
                    killable.inner
                };
                let any = left.has_secret(b"room:a");
                let status = stored_status(&left, &lineage);
                let begun = block_on(begin_migration_journal(
                    &mut store_io(&mut left),
                    &lineage,
                    &union(),
                ))
                .expect("begin");
                let all = left.has_secret(b"room:c");
                if any && !all {
                    assert!(
                        begun.interrupted_import() || status.interrupted_import(),
                        "lose={lose_journal} writes={writes}: partial copy unflagged: {status:?} / {begun:?}"
                    );
                }
                let run = journaled(&mut left, &mut io_for(), &lineage, union());
                assert!(
                    complete(&run),
                    "lose={lose_journal} writes={writes}: {:?}",
                    run.status
                );
                if flagged.is_ok()
                    || left.get_secret(&pred_wip_marker(&k)).as_deref()
                        == Some(PRED_DONE_MARKER_VALUE_DATA)
                {
                    assert!(
                        left.has_secret(b"room:c"),
                        "lose={lose_journal} writes={writes}"
                    );
                }
            }
        }
    }

    /// A successor whose marker READ follows the pre-round-4 order (Done first, in-progress
    /// only when no Done), as `GhostkeysWriter` in this file does. Everything else is `SecretStoreIo`.
    struct DoneFirst {
        store: MemStore,
    }
    impl SuccessorSecretsIo for DoneFirst {
        type Error = SecretStoreWriteFailed;
        async fn migration_marker(
            &mut self,
            query: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, Self::Error> {
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
            p: &DelegateKey,
            m: MigrationMarker,
        ) -> Result<(), Self::Error> {
            store_io(&mut self.store).record_marker(p, m).await
        }
        async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
            store_io(&mut self.store).write_secret(item).await
        }
    }
    impl JournaledSuccessorIo for DoneFirst {
        async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            store_io(&mut self.store).load_journal().await
        }
        async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
            store_io(&mut self.store).store_journal(j).await
        }
        fn journal_key(&self) -> &[u8] {
            MIGRATION_JOURNAL_KEY
        }
    }

    /// A marker store that does not honour the precedence rule is refused rather
    /// than trusted: the app's flag errs (so the app writes nothing), and the
    /// walk's re-ask over an empty seal stops before writing anything.
    #[test]
    fn a_marker_store_breaking_the_precedence_rule_is_refused() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = DoneFirst {
            store: MemStore::default(),
        };
        let mut empty = MockIo::default().executable_with(&k, &[]);
        let r = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut empty,
            &lineage,
            ack(),
            union(),
        ));
        assert!(complete(&r));
        assert!(block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None
        ))
        .is_err());
        // The journal flag landed first, so the walk re-asks, and refuses to write
        // over a seal its store will not let it outrank.
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        let r = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        assert!(matches!(
            r.report.predecessors[0],
            PredecessorMigration::WriterUnavailable {
                failure: WriterFailure {
                    stage: WriterStage::BeginMarker,
                    ..
                },
                ..
            }
        ));
        assert!(!w.store.has_secret(b"room:a"));
        assert!(!complete(&r));
    }

    /// A predecessor resolved with permanent rejections has no `Done` marker; the
    /// journaled walk must not re-walk it (that brought back keys the user deleted
    /// on every load while anything else kept the journal incomplete).
    #[test]
    fn a_rejection_resolved_predecessor_is_not_walked_again() {
        let (absent, holder) = (entry(1, 1), entry(2, 2));
        let lineage = [absent, holder];
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&holder), &[(b"room:a", b"A"), (b"room:x", b"?")])
            .not_installed(&key_of(&absent));
        writer.run(&mut io, union());
        assert!(matches!(
            state_of(&writer.store, &holder),
            JournalState::Resolved(JournalResolution::ImportedWithRejections { .. })
        ));
        // The user deletes room:a.
        writer.store.data.remove(b"room:a".as_slice());
        let mut io = MockIo::default()
            .executable_with(&key_of(&holder), &[(b"room:a", b"A"), (b"room:x", b"?")])
            .not_installed(&key_of(&absent));
        let run = writer.run(&mut io, union());
        assert!(
            !io.fetched.contains(key_of(&holder).bytes()),
            "not walked again"
        );
        assert!(!writer.store.has_secret(b"room:a"), "not resurrected");
        assert_eq!(run.status.expect("stored").rejected_items(), 1);
    }

    /// The journaled walk (not only `begin`) reads a lineage entry the stored
    /// journal has never seen off its marker, even if it then never examines it.
    #[test]
    fn the_walk_seeds_an_unseen_lineage_entry_from_its_marker() {
        let (grown, known) = (entry(1, 1), entry(2, 2));
        let lineage = [grown, known];
        let mut store = MemStore::default();
        put_journal(&mut store, &MigrationJournal::new_pending(&[known]));
        store.set_secret(
            &pred_wip_marker(&key_of(&grown)),
            PRED_DONE_MARKER_VALUE_DATA,
        );
        store.set_secret(b"room:a", b"A");
        // A silent newest generation halts NSW before `grown` is examined.
        let mut io = MockIo::default().dead(&key_of(&known));
        let run = journaled(&mut store, &mut io, &lineage, newest());
        assert!(interrupted(&run), "{:?}", run.status);
    }

    /// Seeding unseen entries never drops what the stored journal held, even if
    /// the store's re-read then comes back empty.
    #[test]
    fn seeding_unseen_entries_keeps_the_loaded_journal() {
        let (grown, known) = (entry(1, 1), entry(2, 2));
        let lineage = [grown, known];
        let mut writer = InspectingWriter::new(&lineage);
        let mut journal = MigrationJournal::new_pending(&[known]);
        journal.mark_import_started(&key_of(&known), 2);
        writer
            .store
            .set_secret(MIGRATION_JOURNAL_KEY, &journal.encode());
        // Load #1 is begin's own read; #2 is the store's re-read: it misses.
        writer.none_on_load_number = Some(2);
        block_on(begin_migration_journal(&mut writer, &lineage, &union())).expect("begin");
        assert!(matches!(
            state_of(&writer.store, &known),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// `JournalError` is a std error, so `?` into a boxed error works.
    #[test]
    fn journal_error_is_a_std_error() {
        fn boxed() -> Result<(), Box<dyn std::error::Error>> {
            Err(JournalError::ForeignVersion(2))?
        }
        assert!(boxed().is_err());
    }

    /// Under a snapshot policy, a generation behind a predecessor the journal
    /// resolved with rejections (and the walk short-circuits on) resolves as
    /// superseded by it: the journal's resolution is the authoritative snapshot.
    #[test]
    fn a_grown_lineage_behind_a_rejection_resolved_snapshot_resolves() {
        let (older, newer) = (entry(1, 1), entry(2, 2));
        let mut writer = InspectingWriter::new(&[newer]);
        writer.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&newer), &[(b"room:a", b"A"), (b"room:x", b"?")])
            .executable_with(&key_of(&older), &[(b"room:o", b"O")]);
        assert!(complete(&writer.run(&mut io, newest())));
        // The lineage grows by an older generation.
        writer.lineage = vec![older, newer];
        let run = writer.run(&mut io, newest());
        assert_eq!(
            run.status,
            Some(JournalStatus::Complete { rejected_items: 1 })
        );
        assert_eq!(
            state_of(&writer.store, &older),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
    }

    // -- round 6 of the #38 review --------------------------------------------------
    //
    // The lenses' probes, kept as written (the migration lens's loss probes are
    // inverted into the regression they now pin).

    /// R6S-A: NSW adoption with a pre-0.5 legacy `done:5` marker resolves g3
    /// `Imported` (AtOrAboveGeneration). The app then switches to Union. g3 was
    /// barred by the legacy path's monotonicity and never copied; the plain Union
    /// walk would import it. Does the journaled walk?
    #[test]
    fn r6s_a_legacy_nsw_resolution_then_union_switch_imports_the_barred_generation() {
        let (g3, g5) = (entry(3, 3), entry(5, 5));
        let lineage = [g3, g5];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        // The legacy seal stands for g5's authoritative snapshot, not an import of
        // g3, so g3 is superseded (which reopens under Union), never "imported".
        assert_eq!(
            state_of(&store, &g3),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:old", b"O")])
            .executable_with(&key_of(&g5), &[(b"room:new", b"N")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(
            store.has_secret(b"room:old"),
            "g3's data was never imported, journal says {:?}",
            run.status
        );
    }

    /// R6S-A control: the plain Union walk from the same store imports g3.
    #[test]
    fn r6s_a_control_plain_union_walk_imports_the_barred_generation() {
        let (g3, g5) = (entry(3, 3), entry(5, 5));
        let lineage = [g3, g5];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:old", b"O")])
            .executable_with(&key_of(&g5), &[(b"room:new", b"N")]);
        block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        assert!(store.has_secret(b"room:old"));
    }

    /// R6S-A2: same, but the app also flags g3 for its own sweep under Union
    /// (River's shape) and dies mid-sweep. Does anything report the partial copy?
    #[test]
    fn r6s_a2_app_sweep_of_a_legacy_nsw_resolved_generation_after_switch() {
        let (g3, g5) = (entry(3, 3), entry(5, 5));
        let lineage = [g3, g5];
        let k3 = key_of(&g3);
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        // Now Union.
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k3,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        // The app writes one of two rooms, then the tab dies.
        store.set_secret(b"room:old1", b"O1");
        assert!(stored_status(&store, &lineage).interrupted_import());
        let mut io = MockIo::default()
            .executable_with(&k3, &[(b"room:old1", b"O1"), (b"room:old2", b"O2")])
            .executable_with(&key_of(&g5), &[(b"room:new", b"N")]);
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(
            store.has_secret(b"room:old2"),
            "room:old2 never imported; status {:?}",
            run.status
        );
    }

    /// A JournaledSuccessorIo that keeps the default `journal_key()`.
    struct NoKeyWriter {
        store: MemStore,
    }
    impl SuccessorSecretsIo for NoKeyWriter {
        type Error = SecretStoreWriteFailed;
        async fn migration_marker(
            &mut self,
            query: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, Self::Error> {
            store_io(&mut self.store).migration_marker(query).await
        }
        async fn record_marker(
            &mut self,
            predecessor: &DelegateKey,
            marker: MigrationMarker,
        ) -> Result<(), Self::Error> {
            store_io(&mut self.store)
                .record_marker(predecessor, marker)
                .await
        }
        async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
            store_io(&mut self.store).write_secret(item).await
        }
    }
    impl JournaledSuccessorIo for NoKeyWriter {
        async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY))
        }
        async fn store_journal(&mut self, journal: &[u8]) -> Result<(), Self::Error> {
            self.store.set_secret(MIGRATION_JOURNAL_KEY, journal);
            Ok(())
        }
    }

    /// What a node would export from a store: everything outside the node's
    /// reserved migration-marker namespace (the journal namespace is the crate's,
    /// so a node exports it).
    fn export_of(store: &MemStore) -> Vec<(Vec<u8>, Vec<u8>)> {
        store
            .data
            .iter()
            .filter(|(k, _)| !k.starts_with(b"\0freenet-migrate/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn continue_past() -> SecretSelectionPolicy {
        SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
            crate::RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
        )
    }

    /// gen2 ran the journaled code while gen1 was silent: gen2 holds ONLY its
    /// journal. gen3 then walks [gen1 (now has data), gen2 (journal only)].
    fn r6_journal_only_middle(
        policy: fn() -> SecretSelectionPolicy,
        forget_key: bool,
        plain: bool,
    ) -> (MemStore, JournaledMigrationReport) {
        let g1 = entry(1, 1);
        let g2 = entry(2, 2);
        // gen 2's lifetime: lineage [g1], g1 silent.
        let mut gen2 = MemStore::default();
        {
            let mut io = MockIo::default().dead(&key_of(&g1));
            let run = journaled(&mut gen2, &mut io, &[g1], policy());
            assert!(!complete(&run));
        }
        let gen2_export = export_of(&gen2);
        assert_eq!(
            gen2_export.len(),
            1,
            "gen2 holds only its journal: {gen2_export:?}"
        );
        let pairs: Vec<(&[u8], &[u8])> =
            gen2_export.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        // gen 3: g1 now answers with the user's data.
        let mut io = MockIo::default()
            .executable_with(&key_of(&g1), &[(b"room:a", b"A")])
            .executable_with(&key_of(&g2), &pairs);
        let lineage = [g1, g2];
        if plain {
            let mut store = MemStore::default();
            let report = block_on(migrate_delegate_secrets(
                &mut store_io(&mut store),
                &mut io,
                &lineage,
                ack(),
                policy(),
            ));
            return (
                store,
                JournaledMigrationReport {
                    report,
                    status: None,
                    journal_error: None,
                },
            );
        }
        if forget_key {
            let mut w = NoKeyWriter {
                store: MemStore::default(),
            };
            let run = block_on(migrate_delegate_secrets_journaled(
                &mut w,
                &mut io,
                &lineage,
                ack(),
                policy(),
            ));
            (w.store, run)
        } else {
            let mut store = MemStore::default();
            let run = journaled(&mut store, &mut io, &lineage, policy());
            (store, run)
        }
    }

    #[test]
    fn r6_control_with_journal_key_imports_the_older_generation() {
        for policy in [newest as fn() -> SecretSelectionPolicy, continue_past] {
            let (store, run) = r6_journal_only_middle(policy, false, false);
            assert_eq!(
                store.get_secret(b"room:a").as_deref(),
                Some(&b"A"[..]),
                "{run:?}"
            );
        }
    }

    /// A predecessor holding only its journal is not a data-bearing snapshot: the
    /// older generation holding the user's data is still imported, whether the
    /// writer keeps the default `journal_key()` or the walk is a plain one.
    #[test]
    fn a_journal_only_predecessor_never_supersedes_real_data() {
        for policy in [newest as fn() -> SecretSelectionPolicy, continue_past] {
            for (forget_key, plain) in [(true, false), (false, true)] {
                let (store, run) = r6_journal_only_middle(policy, forget_key, plain);
                assert_eq!(
                    store.get_secret(b"room:a").as_deref(),
                    Some(&b"A"[..]),
                    "plain={plain}: {:?}",
                    run.report.predecessors
                );
            }
        }
    }

    /// A successor whose marker store has configurable rule violations.
    #[derive(Default)]
    struct Quirky {
        store: MemStore,
        /// After any `record_marker`, every later marker read fails.
        fail_reads_after_record: bool,
        recorded: bool,
        /// `InProgress { saw_data: true }` is recorded as `{ saw_data: false }`.
        drop_data_flag: bool,
        /// Reads the in-progress marker first (like a store with a single slot).
        wip_first: bool,
    }
    impl SuccessorSecretsIo for Quirky {
        type Error = SecretStoreWriteFailed;
        async fn migration_marker(
            &mut self,
            query: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, Self::Error> {
            if self.fail_reads_after_record && self.recorded {
                return Err(SecretStoreWriteFailed {
                    key: b"read".to_vec(),
                });
            }
            if self.wip_first && self.recorded {
                if let Some(v) = self.store.get_secret(&pred_wip_marker(query.predecessor)) {
                    return Ok(Some(MigrationMarker::InProgress {
                        saw_data: v != PRED_DONE_MARKER_VALUE_EMPTY,
                    }));
                }
            }
            store_io(&mut self.store).migration_marker(query).await
        }
        async fn record_marker(
            &mut self,
            p: &DelegateKey,
            m: MigrationMarker,
        ) -> Result<(), Self::Error> {
            self.recorded = true;
            let m = match m {
                MigrationMarker::InProgress { saw_data: true } if self.drop_data_flag => {
                    MigrationMarker::InProgress { saw_data: false }
                }
                other => other,
            };
            store_io(&mut self.store).record_marker(p, m).await
        }
        async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
            store_io(&mut self.store).write_secret(item).await
        }
    }
    impl JournaledSuccessorIo for Quirky {
        async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            store_io(&mut self.store).load_journal().await
        }
        async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
            store_io(&mut self.store).store_journal(j).await
        }
        fn journal_key(&self) -> &[u8] {
            MIGRATION_JOURNAL_KEY
        }
    }

    fn run_q(
        w: &mut Quirky,
        io: &mut MockIo,
        lineage: &[DelegateLineageEntry],
        p: SecretSelectionPolicy,
    ) -> JournaledMigrationReport {
        block_on(migrate_delegate_secrets_journaled(w, io, lineage, ack(), p))
    }

    /// PROBE B19: a refused re-ask (marker store breaks the precedence rule) must
    /// halt the walk so an OLDER generation cannot shadow the newer one's keys.
    fn setup_empty_sealed_then_flagged(
        policy: fn() -> SecretSelectionPolicy,
    ) -> (Quirky, DelegateLineageEntry, DelegateLineageEntry) {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let mut w = Quirky::default();
        // Newest alone, answers empty -> Done{false}.
        let mut io = MockIo::default().executable_with(&key_of(&new), &[]);
        run_q(&mut w, &mut io, &[new], policy());
        (w, old, new)
    }

    #[test]
    fn probe_b19_refused_reask_halts_older_generations() {
        for policy in [union as fn() -> SecretSelectionPolicy, newest] {
            let (mut w, old, new) = setup_empty_sealed_then_flagged(policy);
            // The app flags `new` (journal first), but the store reads Done first.
            let mut df = DoneFirst {
                store: core::mem::take(&mut w.store),
            };
            assert!(block_on(note_app_import_started(
                &mut df,
                &[new],
                &key_of(&new),
                &policy(),
                None
            ))
            .is_err());
            w.store = df.store;
            // The lineage grows by an older generation holding other values.
            let mut df = DoneFirst {
                store: core::mem::take(&mut w.store),
            };
            let mut io = MockIo::default()
                .executable_with(&key_of(&new), &[(b"room:a", b"NEW")])
                .executable_with(&key_of(&old), &[(b"room:a", b"OLD"), (b"room:b", b"B")]);
            let r = block_on(migrate_delegate_secrets_journaled(
                &mut df,
                &mut io,
                &[old, new],
                ack(),
                policy(),
            ));
            assert!(
                matches!(
                    r.report.predecessors[0],
                    PredecessorMigration::WriterUnavailable { .. }
                ),
                "{:?}",
                r.report
            );
            assert!(!df.store.has_secret(b"room:a"), "newer value not written");
            assert!(
                !df.store.has_secret(b"room:b"),
                "older generation must not import behind a refused newer one: {:?}",
                r.report
            );
            assert!(matches!(
                r.report.predecessors[1],
                PredecessorMigration::Superseded { .. }
            ));
        }
    }

    /// PROBE B20/D11: a marker read that FAILS after the in-progress record is not
    /// a pass.
    #[test]
    fn probe_d11_note_app_read_back_error_refuses() {
        let e = entry(1, 1);
        let mut w = Quirky::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
        run_q(&mut w, &mut io, &[e], union());
        w.fail_reads_after_record = true;
        w.recorded = false;
        assert!(block_on(note_app_import_started(
            &mut w,
            &[e],
            &key_of(&e),
            &union(),
            None
        ))
        .is_err());
    }

    #[test]
    fn probe_b20_walk_read_back_error_refuses() {
        let e = entry(1, 1);
        let mut w = Quirky::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
        run_q(&mut w, &mut io, &[e], union());
        // flag in the journal only (journal first), marker unchanged.
        let mut j = stored_journal(&w.store);
        j.mark_import_started(&key_of(&e), 1);
        put_journal(&mut w.store, &j);
        w.fail_reads_after_record = true;
        w.recorded = false;
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"room:a", b"A")]);
        let r = run_q(&mut w, &mut io, &[e], union());
        assert!(
            matches!(
                r.report.predecessors[0],
                PredecessorMigration::WriterUnavailable { .. }
            ),
            "{:?}",
            r.report
        );
        assert!(!w.store.has_secret(b"room:a"));
    }

    /// PROBE D9/B23: a store that records the in-progress marker WITHOUT its data
    /// flag is refused.
    #[test]
    fn probe_d9_note_app_dropped_data_flag_refuses() {
        let e = entry(1, 1);
        let mut w = Quirky::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
        run_q(&mut w, &mut io, &[e], union());
        // fresh predecessor entry w/ no marker: new lineage entry
        let f = entry(2, 2);
        block_on(begin_migration_journal(&mut w, &[e, f], &union())).unwrap();
        w.drop_data_flag = true;
        assert!(block_on(note_app_import_started(
            &mut w,
            &[e, f],
            &key_of(&f),
            &union(),
            None
        ))
        .is_err());
    }

    #[test]
    fn probe_b23_walk_dropped_data_flag_refuses() {
        let e = entry(1, 1);
        let mut w = Quirky::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
        run_q(&mut w, &mut io, &[e], union());
        let mut j = stored_journal(&w.store);
        j.mark_import_started(&key_of(&e), 1);
        put_journal(&mut w.store, &j);
        w.drop_data_flag = true;
        w.wip_first = true;
        w.recorded = false;
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"room:a", b"A")]);
        let r = run_q(&mut w, &mut io, &[e], union());
        assert!(
            matches!(
                r.report.predecessors[0],
                PredecessorMigration::WriterUnavailable { .. }
            ),
            "{:?}",
            r.report
        );
        assert!(!w.store.has_secret(b"room:a"));
    }

    /// PROBE A1: a journal NoData resolution is not an import; if the marker is
    /// gone the predecessor is asked again, and its data imports.
    #[test]
    fn probe_a1_journal_no_data_resolution_without_marker_is_reasked() {
        let e = entry(1, 1);
        let mut j = MigrationJournal::new_pending(&[e]);
        j.record(&key_of(&e), 1, resolved(JournalResolution::NoData));
        for policy in [union(), newest()] {
            let mut s = MemStore::default();
            put_journal(&mut s, &j);
            let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"room:a", b"A")]);
            journaled(&mut s, &mut io, &[e], policy);
            assert!(s.has_secret(b"room:a"));
        }
    }

    /// PROBE A1b: newest policy; newer NoData-resolved in journal, no marker; older holds data.
    #[test]
    fn probe_a1b_no_data_resolution_does_not_supersede_older_generation() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let mut store = MemStore::default();
        let mut j = MigrationJournal::new_pending(&[old, new]);
        j.record(&key_of(&new), 2, resolved(JournalResolution::NoData));
        put_journal(&mut store, &j);
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        journaled(&mut store, &mut io, &[old, new], newest());
        assert!(store.has_secret(b"room:o"));
    }

    /// PROBE A3: a journal Imported resolution with the Done marker gone is not
    /// walked again (no resurrection).
    #[test]
    fn probe_a3_journal_imported_without_done_marker_is_not_rewalked() {
        let e = entry(1, 1);
        let mut store = MemStore::default();
        let mut j = MigrationJournal::new_pending(&[e]);
        j.record(&key_of(&e), 1, resolved(JournalResolution::Imported));
        put_journal(&mut store, &j);
        let mut io = MockIo::default().executable_with(&key_of(&e), &[(b"room:a", b"A")]);
        journaled(&mut store, &mut io, &[e], union());
        assert!(!io.fetched.contains(key_of(&e).bytes()));
        assert!(!store.has_secret(b"room:a"));
    }

    /// PROBE E: refused rows carry the lineage's identity, newest first.
    #[test]
    fn probe_e_refused_rows_identify_the_lineage() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let mut store = MemStore::default();
        store.set_secret(MIGRATION_JOURNAL_KEY, &[0xFF; 4]);
        // foreign version
        let mut j = MigrationJournal::new_pending(&[old, new]).encode();
        let pos = j.windows(2).position(|w| w == [0x61, b'v']).unwrap() + 2;
        j[pos] = 0x02;
        store.set_secret(MIGRATION_JOURNAL_KEY, &j);
        let mut io = MockIo::default();
        let r = journaled(&mut store, &mut io, &[old, new], union());
        assert!(refused(&r), "{:?}", r.report);
        let rows: Vec<(u32, DelegateKey)> = r
            .report
            .predecessors
            .iter()
            .map(|p| (p.generation(), p.key().clone()))
            .collect();
        assert_eq!(rows, vec![(2, key_of(&new)), (1, key_of(&old))]);
        assert!(r.journal_error.as_deref().is_some_and(|m| !m.is_empty()));
    }

    /// PROBE W2: the newest generation's in-progress marker cannot be written; an
    /// older generation must not import behind it.
    #[test]
    fn probe_w2_begin_marker_failure_halts_older_generations() {
        for policy in [union as fn() -> SecretSelectionPolicy, newest] {
            let (old, new) = (entry(1, 1), entry(2, 2));
            let mut store = MemStore::default();
            store.fail_writes_to(&pred_wip_marker(&key_of(&new)));
            let mut io = MockIo::default()
                .executable_with(&key_of(&new), &[(b"room:a", b"NEW")])
                .executable_with(&key_of(&old), &[(b"room:a", b"OLD")]);
            let r = journaled(&mut store, &mut io, &[old, new], policy());
            assert!(
                matches!(
                    r.report.predecessors[0],
                    PredecessorMigration::WriterUnavailable { .. }
                ),
                "{:?}",
                r.report
            );
            assert!(
                !store.has_secret(b"room:a"),
                "older generation imported behind a failed newer one"
            );
            assert!(matches!(
                r.report.predecessors[1],
                PredecessorMigration::Superseded { .. }
            ));
        }
    }

    /// PROBE K5: an empty in-progress marker (an earlier attempt saw nothing) does
    /// not make a later empty answer "data then empty"; the primitive seals empty.
    #[test]
    fn probe_k5_primitive_seals_empty_over_an_empty_wip() {
        let k = key_of(&entry(1, 1));
        let mut store = MemStore::default();
        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        let out = import_predecessor_secrets_once(&mut store, &k, &[]);
        assert!(
            !matches!(out, PredecessorImportOutcome::Incomplete { .. }),
            "{out:?}"
        );
        assert_eq!(
            crate::delegate::predecessor_migration_had_data(&store, &k),
            Some(false)
        );
    }

    /// PROBE W8 (plain walk, no journal): an empty newest generation is sealed
    /// EMPTY, so under NewestSnapshotWins a still-incomplete older generation is
    /// retried on the next run rather than superseded by the empty seal.
    #[test]
    fn probe_w8_plain_walk_empty_seal_does_not_supersede_an_incomplete_older_generation() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let mut store = MemStore::default();
        store.fail_writes_to(b"room:o");
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        let r1 = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        assert!(!r1.is_complete());
        store.stop_failing();
        let r2 = block_on(migrate_delegate_secrets(
            &mut store_io(&mut store),
            &mut io,
            &[old, new],
            ack(),
            newest(),
        ));
        assert!(
            store.has_secret(b"room:o"),
            "older generation must be retried: {:?}",
            r2
        );
        assert_eq!(
            crate::delegate::predecessor_migration_had_data(&store, &key_of(&new)),
            Some(false)
        );
    }

    /// PROBE NJ1/NJ3: under Union (and ContinuePast with no data seen) a newest
    /// generation that is NOT INSTALLED, or whose probe ERRORS, must not halt the
    /// walk: the older generation holding the data is still imported. (River's
    /// shape: absent generations.)
    #[test]
    fn probe_nj_absent_or_erroring_newest_does_not_block_older_generations() {
        let cont = || {
            SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
            )
        };
        for policy in [union as fn() -> SecretSelectionPolicy, cont] {
            for variant in 0..2 {
                let (old, new) = (entry(1, 1), entry(2, 2));
                let mut store = MemStore::default();
                let mut io = MockIo::default().executable_with(&key_of(&old), &[(b"room:o", b"O")]);
                io = if variant == 0 {
                    io.not_installed(&key_of(&new))
                } else {
                    io.error_probe(&key_of(&new))
                };
                let r = journaled(&mut store, &mut io, &[old, new], policy());
                assert!(
                    store.has_secret(b"room:o"),
                    "variant {variant}: {:?}",
                    r.report
                );
                // and the plain walk
                let mut store = MemStore::default();
                let r = block_on(migrate_delegate_secrets(
                    &mut store_io(&mut store),
                    &mut io,
                    &[old, new],
                    ack(),
                    policy(),
                ));
                assert!(
                    store.has_secret(b"room:o"),
                    "plain variant {variant}: {:?}",
                    r
                );
            }
        }
    }

    /// PROBE Y1: a newest generation exporting NOTHING BUT its own journal is
    /// empty, not a data-bearing snapshot: the older generation still imports.
    #[test]
    fn probe_y1_a_journal_only_export_is_empty_not_authoritative() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let mut writer = InspectingWriter::new(&[old, new]);
        let mut io = MockIo::default()
            .executable_with(&key_of(&new), &[(MIGRATION_JOURNAL_KEY, b"their-journal")])
            .executable_with(&key_of(&old), &[(b"room:o", b"O")]);
        writer.run(&mut io, newest());
        assert!(writer.store.has_secret(b"room:o"));
        assert_eq!(
            crate::delegate::predecessor_migration_had_data(&writer.store, &key_of(&new)),
            Some(false)
        );
    }

    /// PROBE Y2: after data was seen, an export holding nothing but the
    /// predecessor's own journal is still "exported nothing": no seal.
    #[test]
    fn probe_y2_a_journal_only_export_after_data_is_not_believed() {
        let e = entry(1, 1);
        let mut writer = InspectingWriter::new(&[e]);
        writer.retryable_fail.insert(b"room:a".to_vec());
        let mut io =
            MockIo::default().executable_with(&key_of(&e), &[(b"room:a", b"A"), (b"room:b", b"B")]);
        writer.run(&mut io, union());
        writer.retryable_fail.clear();
        let mut io = MockIo::default()
            .executable_with(&key_of(&e), &[(MIGRATION_JOURNAL_KEY, b"their-journal")]);
        let run = writer.run(&mut io, union());
        assert!(!complete(&run), "{:?}", run.report);
        assert_eq!(
            crate::delegate::predecessor_migration_had_data(&writer.store, &key_of(&e)),
            None,
            "sealed over a partial copy"
        );
    }

    /// The walk (not only a fresh journal) tells a legacy at-or-above seal from an
    /// import, and a bridged row still supersedes what is older behind it.
    #[test]
    fn the_walk_journals_a_legacy_bridged_seal_as_superseded() {
        let (g2, g3) = (entry(2, 2), entry(3, 3));
        let lineage = [g2, g3];
        let mut store = MemStore::default();
        // A journal already exists (begun before the legacy marker was visible).
        put_journal(&mut store, &MigrationJournal::new_pending(&lineage));
        store.set_secret(&done_marker(5), b"1");
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:3", b"3")])
            .executable_with(&key_of(&g2), &[(b"room:2", b"2")]);
        let run = journaled(&mut store, &mut io, &lineage, newest());
        assert_eq!(
            state_of(&store, &g3),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
        assert_eq!(
            state_of(&store, &g2),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
        assert!(complete(&run), "{:?}", run.status);
        // Under Union both reopen and are imported.
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(complete(&run), "{:?}", run.status);
        assert!(store.has_secret(b"room:3") && store.has_secret(b"room:2"));
    }

    /// A writer that stores its journal under its own key, reported from
    /// `journal_key()`: the journaled walk withholds that key too.
    #[test]
    fn an_overridden_journal_key_is_withheld() {
        struct OwnKey {
            store: MemStore,
        }
        impl SuccessorSecretsIo for OwnKey {
            type Error = SecretStoreWriteFailed;
            async fn migration_marker(
                &mut self,
                query: &MarkerQuery<'_>,
            ) -> Result<Option<MigrationMarker>, Self::Error> {
                store_io(&mut self.store).migration_marker(query).await
            }
            async fn record_marker(
                &mut self,
                p: &DelegateKey,
                m: MigrationMarker,
            ) -> Result<(), Self::Error> {
                store_io(&mut self.store).record_marker(p, m).await
            }
            async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
                store_io(&mut self.store).write_secret(item).await
            }
        }
        impl JournaledSuccessorIo for OwnKey {
            async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.store.get_secret(b"app/journal"))
            }
            async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
                self.store.set_secret(b"app/journal", j);
                Ok(())
            }
            fn journal_key(&self) -> &[u8] {
                b"app/journal"
            }
        }
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = OwnKey {
            store: MemStore::default(),
        };
        let mut io = MockIo::default()
            .executable_with(&k, &[(b"app/journal", b"forged"), (b"room:a", b"A")]);
        let run = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        assert!(complete(&run), "{:?}", run.status);
        assert!(MigrationJournal::decode(&w.store.get_secret(b"app/journal").unwrap()).is_ok());
        assert!(matches!(
            run.report.predecessors[0],
            PredecessorMigration::Imported {
                tally: ImportTally {
                    written: 1,
                    skipped: 0,
                    ..
                },
                ..
            }
        ));
    }

    // ---- round-7 probes -----------------------------------------------------

    fn r7_own_key_writer_walk(
        journal_key: &'static [u8],
        exports: &[(&[u8], &[u8])],
    ) -> (MemStore, JournaledMigrationReport) {
        struct OwnKey {
            store: MemStore,
            key: &'static [u8],
        }
        impl SuccessorSecretsIo for OwnKey {
            type Error = SecretStoreWriteFailed;
            async fn migration_marker(
                &mut self,
                query: &MarkerQuery<'_>,
            ) -> Result<Option<MigrationMarker>, Self::Error> {
                store_io(&mut self.store).migration_marker(query).await
            }
            async fn record_marker(
                &mut self,
                p: &DelegateKey,
                m: MigrationMarker,
            ) -> Result<(), Self::Error> {
                store_io(&mut self.store).record_marker(p, m).await
            }
            async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
                store_io(&mut self.store).write_secret(item).await
            }
        }
        impl JournaledSuccessorIo for OwnKey {
            async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.store.get_secret(self.key))
            }
            async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
                self.store.set_secret(self.key, j);
                Ok(())
            }
            fn journal_key(&self) -> &[u8] {
                self.key
            }
        }
        let lineage = [entry(1, 1)];
        let mut w = OwnKey {
            store: MemStore::default(),
            key: journal_key,
        };
        let mut io = MockIo::default().executable_with(&key_of(&lineage[0]), exports);
        let run = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        (w.store, run)
    }

    /// Only the exact journal key is withheld; a sibling key sharing its prefix is
    /// the user's data.
    #[test]
    fn r7_a_key_sharing_the_journal_keys_prefix_is_still_imported() {
        let (store, run) = r7_own_key_writer_walk(
            b"app/journal",
            &[
                (b"app/journal-notes", b"N"),
                (b"app/journal", b"forged"),
                (b"room:a", b"A"),
            ],
        );
        assert!(complete(&run), "{:?}", run.status);
        assert!(
            store.has_secret(b"app/journal-notes"),
            "sibling key dropped"
        );
    }

    /// Keys adjacent to the crate's reserved namespaces are the user's data.
    #[test]
    fn r7_keys_adjacent_to_the_reserved_namespaces_are_imported() {
        let adjacent: [&[u8]; 5] = [
            b"\0freenet-migrate-journal",
            b"freenet-migrate-journal/v1",
            b"\0freenet-migrate",
            b"\0other",
            b"\0freenet-migrat",
        ];
        for k in adjacent {
            let (store, run) = r7_own_key_writer_walk(b"app/journal", &[(k, b"V")]);
            assert!(complete(&run), "{k:?}: {:?}", run.status);
            assert!(store.has_secret(k), "{k:?} was dropped");
        }
    }

    /// A legacy generation-keyed marker for EXACTLY this generation is an import of
    /// it, not "superseded by a newer snapshot".
    #[test]
    fn r7_a_legacy_exact_marker_journals_imported_not_superseded() {
        let (g2, g3) = (entry(2, 2), entry(3, 3));
        let lineage = [g2, g3];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(3), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        assert_eq!(
            state_of(&store, &g3),
            JournalState::Resolved(JournalResolution::Imported)
        );
        assert_eq!(
            state_of(&store, &g2),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
    }

    /// The same under the continue-past policy, which shares NSW's legacy bridge.
    #[test]
    fn r7_legacy_bridge_under_continue_past() {
        let (g3, g5) = (entry(3, 3), entry(5, 5));
        let lineage = [g3, g5];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &continue_past(),
        ))
        .expect("begin");
        assert_eq!(
            state_of(&store, &g3),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
        // The walk itself, continue-past, with no journal entry yet for g3's seal.
        let mut io = MockIo::default()
            .executable_with(&key_of(&g3), &[(b"room:old", b"O")])
            .executable_with(&key_of(&g5), &[(b"room:new", b"N")]);
        let run = journaled(&mut store, &mut io, &lineage, continue_past());
        assert!(
            !store.has_secret(b"room:old"),
            "barred generation imported under a snapshot policy"
        );
        assert!(complete(&run), "{:?}", run.status);
    }

    /// A read error on the second (exact) marker query counts as bridged.
    #[test]
    fn r7_a_failed_exact_read_while_starting_the_journal_fails_closed() {
        struct FailExact {
            store: MemStore,
        }
        impl SuccessorSecretsIo for FailExact {
            type Error = SecretStoreWriteFailed;
            async fn migration_marker(
                &mut self,
                q: &MarkerQuery<'_>,
            ) -> Result<Option<MigrationMarker>, Self::Error> {
                if q.legacy_bridge == LegacyBridge::ExactGenerationOnly {
                    return Err(SecretStoreWriteFailed {
                        key: b"exact".to_vec(),
                    });
                }
                store_io(&mut self.store).migration_marker(q).await
            }
            async fn record_marker(
                &mut self,
                p: &DelegateKey,
                m: MigrationMarker,
            ) -> Result<(), Self::Error> {
                store_io(&mut self.store).record_marker(p, m).await
            }
            async fn write_secret(&mut self, i: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
                store_io(&mut self.store).write_secret(i).await
            }
        }
        impl JournaledSuccessorIo for FailExact {
            async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY))
            }
            async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
                self.store.set_secret(MIGRATION_JOURNAL_KEY, j);
                Ok(())
            }
        }
        let (g3, g5) = (entry(3, 3), entry(5, 5));
        let lineage = [g3, g5];
        let mut w = FailExact {
            store: MemStore::default(),
        };
        w.store.set_secret(&done_marker(5), b"1");
        // Starting the journal cannot tell a superseded generation from a hidden
        // import in progress without that read: it fails closed, storing nothing.
        assert!(block_on(begin_migration_journal(&mut w, &lineage, &newest())).is_err());
        assert!(w.store.get_secret(MIGRATION_JOURNAL_KEY).is_none());
    }

    /// A plain walk pays no extra marker read for the bridge check.
    #[test]
    fn r7_a_plain_walk_reads_each_marker_once() {
        struct Counting {
            store: MemStore,
            reads: usize,
        }
        impl SuccessorSecretsIo for Counting {
            type Error = SecretStoreWriteFailed;
            async fn migration_marker(
                &mut self,
                q: &MarkerQuery<'_>,
            ) -> Result<Option<MigrationMarker>, Self::Error> {
                self.reads += 1;
                store_io(&mut self.store).migration_marker(q).await
            }
            async fn record_marker(
                &mut self,
                p: &DelegateKey,
                m: MigrationMarker,
            ) -> Result<(), Self::Error> {
                store_io(&mut self.store).record_marker(p, m).await
            }
            async fn write_secret(&mut self, i: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
                store_io(&mut self.store).write_secret(i).await
            }
        }
        let g5 = entry(5, 5);
        let mut w = Counting {
            store: MemStore::default(),
            reads: 0,
        };
        w.store
            .set_secret(&pred_done_marker(&key_of(&g5)), PRED_DONE_MARKER_VALUE_DATA);
        let mut io = MockIo::default();
        block_on(migrate_delegate_secrets(
            &mut w,
            &mut io,
            &[g5],
            ack(),
            newest(),
        ));
        assert_eq!(w.reads, 1, "a plain walk read the marker more than once");
    }

    /// A legacy seal for a newer generation must not hide this generation's own
    /// in-progress data marker when a journal is rebuilt under a snapshot policy:
    /// a partial copy stays flagged.
    #[test]
    fn a_rebuilt_journal_keeps_a_started_import_behind_a_legacy_seal() {
        let (g3, g4) = (entry(3, 3), entry(4, 4));
        let lineage = [g3, g4];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        // A Union import of g3 started (and died part-way).
        store.set_secret(&pred_wip_marker(&key_of(&g3)), PRED_DONE_MARKER_VALUE_DATA);
        store.set_secret(b"g3:a", b"A");
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        assert!(matches!(
            state_of(&store, &g3),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// Under a snapshot policy, a predecessor sealed only by a legacy marker for a
    /// newer generation is superseded, not imported: the app's flag is refused
    /// (the app must not write it), never silently accepted.
    #[test]
    fn an_app_flag_on_a_legacy_superseded_generation_is_refused() {
        let g3 = entry(3, 3);
        let k3 = key_of(&g3);
        let lineage = [g3];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        assert!(block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k3,
            &newest(),
            None
        ))
        .is_err());
        assert!(!store.has_secret(&pred_wip_marker(&k3)));
        // Under Union the same predecessor is owed, and the flag is recorded.
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k3,
            &union(),
            None,
        ))
        .expect_flagged("flag under Union");
        assert!(stored_status(&store, &lineage).interrupted_import());
    }

    /// The journal key sits in the crate's journal namespace and outside the
    /// node's marker namespace (which a node restricts to marker shapes), and
    /// every key in the journal namespace is withheld, not only the current one.
    #[test]
    fn the_journal_namespace_is_reserved_and_node_storable() {
        assert!(MIGRATION_JOURNAL_KEY.starts_with(crate::delegate::JOURNAL_NS));
        assert!(!MIGRATION_JOURNAL_KEY.starts_with(b"\0freenet-migrate/"));
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        let mut io = MockIo::default().executable_with(
            &k,
            &[(b"\0freenet-migrate-journal/x", b"j"), (b"room:a", b"A")],
        );
        writer.run(&mut io, union());
        assert_eq!(writer.offered, vec![b"room:a".to_vec()]);
    }

    /// `is_reserved_key` answers for both reserved namespaces, and for nothing
    /// else.
    #[test]
    fn is_reserved_key_covers_markers_and_the_journal() {
        assert!(crate::is_reserved_key(MIGRATION_JOURNAL_KEY));
        assert!(crate::is_reserved_key(&pred_wip_marker(&key_of(&entry(
            1, 1
        )))));
        assert!(!crate::is_reserved_key(b"room:a"));
        assert!(!crate::is_reserved_key(b"\0freenet-migrat"));
    }

    // -- round 8 probes (testing lens) ------------------------------------------------

    fn r8_merge(older: JournalResolution, newer: JournalResolution) -> JournalState {
        let e = entry(1, 1);
        let k = key_of(&e);
        let mut ours = MigrationJournal::new_pending(&[e]);
        ours.record(&k, 1, resolved(newer));
        let mut theirs = MigrationJournal::new_pending(&[e]);
        theirs.record(&k, 1, resolved(older));
        ours.merge_stored(&theirs, None);
        ours.entry(&k).unwrap().state
    }

    #[test]
    fn r8_data_bearing_resolutions_outrank_non_data_in_both_merge_orders() {
        use JournalResolution::*;
        let iwr = ImportedWithRejections {
            rejected: 1,
            revision: 1,
            items_seen: 0,
        };
        for non_data in [NoData, SupersededByAuthoritative] {
            for data in [iwr, Imported] {
                assert_eq!(
                    r8_merge(non_data, data),
                    JournalState::Resolved(data),
                    "{non_data:?} then {data:?}"
                );
                assert_eq!(
                    r8_merge(data, non_data),
                    JournalState::Resolved(data),
                    "{data:?} then {non_data:?}"
                );
            }
        }
        assert_eq!(r8_merge(iwr, Imported), JournalState::Resolved(Imported));
        assert_eq!(r8_merge(Imported, iwr), JournalState::Resolved(Imported));
    }

    #[test]
    fn r8_the_higher_rejection_revision_wins_in_both_merge_orders() {
        use JournalResolution::*;
        let lo = ImportedWithRejections {
            rejected: 5,
            revision: 2,
            items_seen: 0,
        };
        let hi = ImportedWithRejections {
            rejected: 2,
            revision: 3,
            items_seen: 0,
        };
        assert_eq!(r8_merge(lo, hi), JournalState::Resolved(hi));
        assert_eq!(r8_merge(hi, lo), JournalState::Resolved(hi));
    }

    #[test]
    fn r8_rejected_items_sum_over_resolved_and_reopened_predecessors() {
        use JournalResolution::*;
        let (e1, e2, e3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let lineage = [e1, e2, e3];
        let mut j = MigrationJournal::new_pending(&lineage);
        j.record(
            &key_of(&e1),
            1,
            resolved(ImportedWithRejections {
                rejected: 5,
                revision: 1,
                items_seen: 0,
            }),
        );
        j.record(
            &key_of(&e2),
            2,
            resolved(ImportedWithRejections {
                rejected: 3,
                revision: 0,
                items_seen: 0,
            }),
        );
        // e3 stays pending with no rejections (a silent predecessor).
        let b = JournalBinding {
            policy: crate::journal::PolicyFamily::Union,
            import_revision: 1,
        };
        // e1 resolved (5), e2 reopened (3), e3 pending (0): the later pending must not erase the sum.
        assert_eq!(j.status(&lineage, &b).rejected_items(), 8);
        assert_eq!(j.status(&[e3, e1, e2], &b).rejected_items(), 8);
    }

    #[test]
    fn r8_an_older_build_really_does_not_rewalk_a_rejection_resolved_predecessor() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut writer = InspectingWriter::new(&lineage);
        writer.permanent_fail.insert(b"room:x".to_vec());
        writer.revision = 1;
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        assert!(complete(&writer.run(&mut io, union())));
        let offered = writer.offered.len();
        writer.revision = 0;
        writer.run(&mut io, union());
        assert_eq!(
            writer.offered.len(),
            offered,
            "the older build re-offered items"
        );
    }

    /// An empty in-progress marker behind a legacy seal is not a partial copy.
    #[test]
    fn r8_an_empty_wip_behind_a_legacy_seal_is_superseded_not_started() {
        let (g3, g4) = (entry(3, 3), entry(4, 4));
        let lineage = [g3, g4];
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        store.set_secret(&pred_wip_marker(&key_of(&g3)), PRED_DONE_MARKER_VALUE_EMPTY);
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        assert_eq!(
            state_of(&store, &g3),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
    }

    /// The legacy seal sits at generation + 1 (not further away): still refused.
    #[test]
    fn r8_an_app_flag_behind_a_seal_one_generation_up_is_refused() {
        let g3 = entry(3, 3);
        let k3 = key_of(&g3);
        let mut store = MemStore::default();
        store.set_secret(&done_marker(4), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g3],
            &newest(),
        ))
        .expect("begin");
        assert!(block_on(note_app_import_started(
            &mut store_io(&mut store),
            &[g3],
            &k3,
            &newest(),
            None
        ))
        .is_err());
        assert!(!store.has_secret(&pred_wip_marker(&k3)));
    }

    /// A failed SECOND exact read in the rebuild must not drop the partial-copy flag
    /// (the first one saw the in-progress data marker).
    #[test]
    fn r8_a_failed_second_exact_read_does_not_drop_a_started_import() {
        struct FailSecondExact {
            store: MemStore,
            exact_reads: usize,
        }
        impl SuccessorSecretsIo for FailSecondExact {
            type Error = SecretStoreWriteFailed;
            async fn migration_marker(
                &mut self,
                q: &MarkerQuery<'_>,
            ) -> Result<Option<MigrationMarker>, Self::Error> {
                if q.legacy_bridge == LegacyBridge::ExactGenerationOnly {
                    self.exact_reads += 1;
                    if self.exact_reads >= 2 {
                        return Err(SecretStoreWriteFailed {
                            key: b"exact".to_vec(),
                        });
                    }
                }
                store_io(&mut self.store).migration_marker(q).await
            }
            async fn record_marker(
                &mut self,
                p: &DelegateKey,
                m: MigrationMarker,
            ) -> Result<(), Self::Error> {
                store_io(&mut self.store).record_marker(p, m).await
            }
            async fn write_secret(&mut self, i: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
                store_io(&mut self.store).write_secret(i).await
            }
        }
        impl JournaledSuccessorIo for FailSecondExact {
            async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY))
            }
            async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
                self.store.set_secret(MIGRATION_JOURNAL_KEY, j);
                Ok(())
            }
        }
        let g3 = entry(3, 3);
        // Only g3 is in the lineage, so its exact read is the first; a second
        // one (the fail-open shape round 8 removed) would be the one that fails.
        // The legacy seal below is generation 5's.
        let lineage = [g3];
        let mut w = FailSecondExact {
            store: MemStore::default(),
            exact_reads: 0,
        };
        w.store.set_secret(&done_marker(5), b"1");
        w.store
            .set_secret(&pred_wip_marker(&key_of(&g3)), PRED_DONE_MARKER_VALUE_DATA);
        let r = block_on(begin_migration_journal(&mut w, &lineage, &newest()));
        let flagged = matches!(r.as_ref().map(|s| s.interrupted_import()), Ok(true));
        assert!(
            flagged,
            "a possible partial copy was silently unflagged: {r:?}"
        );
    }

    /// A flag that is already durable costs no further flag store; a retried
    /// import re-reads the journal once before its first item (#44: another
    /// session's larger count holds it), and stores the final resolution.
    #[test]
    fn r8_an_already_durable_flag_costs_no_further_journal_store() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"?")]);
        w.run(&mut io, union());
        assert!(stored_status(&w.store, &lineage).interrupted_import());
        let before = w.journal_stores;
        w.retryable_fail.clear();
        let run = w.run(&mut io, union());
        assert!(complete(&run), "{:?}", run.status);
        assert_eq!(
            w.journal_stores - before,
            2,
            "the retry's re-read before its first item, and the final resolution"
        );
    }

    #[test]
    fn r8_repeating_the_app_flag_stores_the_journal_once() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        let before = w.journal_stores;
        block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag again");
        assert_eq!(w.journal_stores, before);
    }

    /// A journal that turns corrupt between the walk's start and its flag store is
    /// rebuilt from the markers there too, not left to veto the import.
    #[test]
    fn r8_a_journal_corrupted_before_the_flag_store_is_rebuilt() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = InspectingWriter::new(&lineage);
        // A started import from an earlier session, so the flag is stored before the probe.
        w.store
            .set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_DATA);
        put_journal(&mut w.store, &MigrationJournal::new_pending(&lineage));
        w.inject_at_first_marker_read = Some(b"garbage".to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        let run = w.run(&mut io, union());
        assert!(complete(&run), "{:?} {:?}", run.status, run.journal_error);
        assert!(w.store.has_secret(b"room:a"));
    }

    /// The no-compare-and-swap window: a stale session's store overwrites the app's
    /// flag on a predecessor already resolved as holding nothing, and the journal
    /// reads `Complete` over the app's partial copy. The predecessor's marker still
    /// says an import started, and the next `begin` reopens it.
    #[test]
    fn a_flag_lost_to_a_stale_store_is_recovered_at_the_next_begin() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        // Load 1: the predecessor answered "nothing" (a #5857 read fault, say).
        assert!(complete(&journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[]),
            &lineage,
            union()
        )));
        let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        // Tab A flags it (journal and marker) and writes part of it, then dies.
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        store.set_secret(b"room:a", b"A");
        // Tab B, which read the journal before A's flag, stores its stale view.
        store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        assert!(
            stored_status(&store, &lineage).is_complete(),
            "the window: Complete over a partial copy"
        );
        // The next begin reads the contradicted marker and reopens it.
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(status.interrupted_import(), "{status:?}");
        assert!(
            stored_status(&store, &lineage).interrupted_import(),
            "the reopened entry is stored, not only reported"
        );
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        assert_eq!(store.get_secret(b"room:b").as_deref(), Some(&b"B"[..]));
    }

    /// `note_app_import_started` refuses what it could never resolve: a predecessor
    /// outside the lineage, and one a snapshot policy supersedes by a newer
    /// generation's data.
    #[test]
    fn an_app_flag_is_refused_where_it_could_never_resolve() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[(b"room:n", b"N")])
            .executable_with(&key_of(&g1), &[(b"room:o", b"O")]);
        assert!(complete(&journaled(
            &mut store,
            &mut io,
            &lineage,
            newest()
        )));
        assert!(matches!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &key_of(&entry(9, 9)),
                &newest(),
                None
            )),
            Err(JournalError::NotImportable(_))
        ));
        assert!(matches!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &key_of(&g1),
                &newest(),
                None
            )),
            Err(JournalError::NotImportable(_))
        ));
        assert!(
            journal_status(
                store.get_secret(MIGRATION_JOURNAL_KEY).as_deref(),
                &lineage,
                &JournalBinding::new(&newest(), 0),
            )
            .is_complete(),
            "nothing recorded"
        );
        // Under Union the older generation is owed, and the flag is recorded.
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &key_of(&g1),
            &union(),
            None,
        ))
        .expect_flagged("flag under Union");
    }

    // ---- round-9 probes ---------------------------------------------------------

    fn r9_flag(
        store: &mut MemStore,
        lineage: &[DelegateLineageEntry],
        k: &DelegateKey,
        policy: SecretSelectionPolicy,
    ) {
        assert_eq!(
            block_on(note_app_import_started(
                &mut store_io(store),
                lineage,
                k,
                &policy,
                None
            ))
            .expect("flag"),
            AppImport::Flagged
        );
    }

    /// The no-CAS recovery must cover every predecessor, not just the first or
    /// the only one, and must leave the uncontradicted neighbours resolved.
    #[test]
    fn r9_p1_the_reopen_loop_covers_every_predecessor() {
        for flagged in 0..3usize {
            let lineage = [entry(1, 1), entry(2, 2), entry(3, 3)];
            let mut store = MemStore::default();
            let mut io = MockIo::default();
            for e in &lineage {
                io = io.executable_with(&key_of(e), &[]);
            }
            assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
            let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
            r9_flag(&mut store, &lineage, &key_of(&lineage[flagged]), union());
            store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
            assert!(stored_status(&store, &lineage).is_complete());
            let status = block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &union(),
            ))
            .expect("begin");
            assert!(status.interrupted_import(), "flagged {flagged}: {status:?}");
            for (i, e) in lineage.iter().enumerate() {
                let st = state_of(&store, e);
                if i == flagged {
                    assert!(
                        matches!(
                            st,
                            JournalState::Pending {
                                import: ImportFlag::Started,
                                ..
                            }
                        ),
                        "{i} {st:?}"
                    );
                } else {
                    assert_eq!(st, JournalState::Resolved(JournalResolution::NoData), "{i}");
                }
            }
        }
    }

    /// Two predecessors contradicted at once.
    #[test]
    fn r9_p1b_two_contradicted_at_once() {
        let lineage = [entry(1, 1), entry(2, 2), entry(3, 3)];
        let mut store = MemStore::default();
        let mut io = MockIo::default();
        for e in &lineage {
            io = io.executable_with(&key_of(e), &[]);
        }
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut store, &lineage, &key_of(&lineage[0]), union());
        r9_flag(&mut store, &lineage, &key_of(&lineage[2]), union());
        store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        for i in [0usize, 2] {
            assert!(
                matches!(
                    state_of(&store, &lineage[i]),
                    JournalState::Pending {
                        import: ImportFlag::Started,
                        ..
                    }
                ),
                "{i}"
            );
        }
        assert_eq!(
            state_of(&store, &lineage[1]),
            JournalState::Resolved(JournalResolution::NoData)
        );
    }

    /// A marker fault while checking a stored no-data resolution refuses nothing:
    /// the newer predecessor that now holds data still migrates, the faulted entry
    /// reads as an import under way for that load (never stored), and a recovered
    /// read decides it.
    #[test]
    fn r9_p2_a_stuck_marker_on_a_resolved_empty_predecessor_blocks_nothing() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let (k1, k2) = (key_of(&g1), key_of(&g2));
        let mut w = InspectingWriter::new(&lineage);
        let mut io = MockIo::default()
            .executable_with(&k1, &[])
            .not_installed(&k2);
        let _ = w.run(&mut io, union());
        assert_eq!(
            state_of(&w.store, &g1),
            JournalState::Resolved(JournalResolution::NoData)
        );
        // g2 is installed now, holding the user's data; g1's marker read fails.
        w.fail_marker_read.insert(k1.bytes().to_vec());
        let mut io = MockIo::default()
            .executable_with(&k1, &[])
            .executable_with(&k2, &[(b"room:a", b"A")]);
        let begun = block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        assert!(begun.interrupted_import(), "{begun:?}");
        let run = w.run(&mut io, union());
        assert!(!refused(&run), "{run:?}");
        assert_eq!(w.store.get_secret(b"room:a").as_deref(), Some(&b"A"[..]));
        let status = run.status.expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
        assert_eq!(
            state_of(&w.store, &g1),
            JournalState::Resolved(JournalResolution::NoData),
            "an unread marker is never stored as a started import"
        );
        // The read recovers: nothing contradicts the resolution.
        w.fail_marker_read.clear();
        let begun = block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        assert!(begun.is_complete(), "{begun:?}");
    }

    /// The same under the walk alone, with nothing else pending: the run's status
    /// is not `Complete` while a resolution it could not check stands.
    #[test]
    fn a_stuck_marker_keeps_the_walks_status_from_reading_complete() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut w = InspectingWriter::new(&lineage);
        let mut io = MockIo::default().executable_with(&k, &[]);
        assert!(complete(&w.run(&mut io, union())));
        w.fail_marker_read.insert(k.bytes().to_vec());
        let run = w.run(&mut io, union());
        assert!(!refused(&run), "{run:?}");
        let status = run.status.expect("stored");
        assert!(
            !status.is_complete() && status.interrupted_import(),
            "{status:?}"
        );
    }

    /// An app flag lost to a stale store on a predecessor still PENDING (not
    /// resolved), behind a newer generation the snapshot walk halts at: the walk
    /// never reaches it, so it reads the predecessor's marker after the halt and
    /// restores the flag.
    #[test]
    fn a_lost_flag_on_a_pending_predecessor_behind_a_halt_is_restored_by_the_walk() {
        let (g2, g3) = (entry(2, 2), entry(3, 3));
        let lineage = [g2, g3];
        let k2 = key_of(&g2);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut store, &lineage, &k2, r10_cpu());
        store.set_secret(b"g2:a", b"A");
        store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        assert!(matches!(
            state_of(&store, &g2),
            JournalState::Pending {
                import: ImportFlag::None,
                ..
            }
        ));
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"g2:a", b"A"), (b"g2:b", b"B")])
            .not_installed(&key_of(&g3));
        let run = journaled(&mut store, &mut io, &lineage, newest());
        let status = run.status.expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
        assert!(
            matches!(
                state_of(&store, &g2),
                JournalState::Pending {
                    import: ImportFlag::Started,
                    ..
                }
            ),
            "restored durably"
        );
        assert!(!store.has_secret(b"g2:b"), "halted: not imported yet");
    }

    /// Behind a halt, an EMPTY in-progress marker (an attempt that saw nothing)
    /// is not a started import: flagging it would wedge the entry. (No journal is
    /// stored here, so the start reads it;
    /// `r11_p1_an_empty_wip_behind_a_halt_flags_nothing_on_an_existing_journal`
    /// covers the post-walk check.)
    #[test]
    fn an_empty_in_progress_marker_behind_a_halt_flags_nothing() {
        let (g2, g3) = (entry(2, 2), entry(3, 3));
        let lineage = [g2, g3];
        let k2 = key_of(&g2);
        let mut store = MemStore::default();
        store.set_secret(&pred_wip_marker(&k2), PRED_DONE_MARKER_VALUE_EMPTY);
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"g2:a", b"A")])
            .not_installed(&key_of(&g3));
        let status = journaled(&mut store, &mut io, &lineage, newest())
            .status
            .expect("stored");
        assert!(!status.interrupted_import(), "{status:?}");
    }

    /// Behind a halt, a pending predecessor whose marker cannot be read reads as
    /// an import under way for that load.
    #[test]
    fn a_pending_predecessor_behind_a_halt_with_an_unreadable_marker_is_unverified() {
        let (g2, g3) = (entry(2, 2), entry(3, 3));
        let lineage = [g2, g3];
        let k2 = key_of(&g2);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &newest())).expect("begin");
        w.fail_marker_read.insert(k2.bytes().to_vec());
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"g2:a", b"A")])
            .not_installed(&key_of(&g3));
        let status = w.run(&mut io, newest()).status.expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
        assert!(matches!(
            state_of(&w.store, &g2),
            JournalState::Pending {
                import: ImportFlag::None,
                ..
            }
        ));
    }

    /// An EMPTY in-progress marker beside a NoData resolution is not a started import.
    #[test]
    fn r9_p3_an_empty_wip_does_not_reopen_a_no_data_entry() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        store.data.remove(&pred_done_marker(&k));
        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(status.is_complete(), "{status:?}");
    }

    /// A superseded entry whose own marker says an import started is reopened.
    #[test]
    fn r9_p4_a_superseded_entry_with_a_data_marker() {
        for begin_policy in [union as fn() -> SecretSelectionPolicy, newest] {
            let (g1, g2) = (entry(1, 1), entry(2, 2));
            let lineage = [g1, g2];
            let mut store = MemStore::default();
            let mut io = MockIo::default()
                .executable_with(&key_of(&g2), &[(b"room:n", b"N")])
                .executable_with(&key_of(&g1), &[(b"room:o", b"O")]);
            assert!(complete(&journaled(
                &mut store,
                &mut io,
                &lineage,
                newest()
            )));
            assert_eq!(
                state_of(&store, &g1),
                JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
            );
            store.set_secret(&pred_wip_marker(&key_of(&g1)), PRED_DONE_MARKER_VALUE_DATA);
            let st = block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &begin_policy(),
            ))
            .expect("begin");
            assert!(st.interrupted_import(), "{st:?}");
            assert!(matches!(
                state_of(&store, &g1),
                JournalState::Pending {
                    import: ImportFlag::Started,
                    ..
                }
            ));
        }
    }

    /// Under a snapshot policy: a completed own-generation import is reported as
    /// already imported, a newer NoData does not supersede, a newer
    /// rejection-resolved one does.
    #[test]
    fn r9_p5_note_app_under_a_snapshot_policy() {
        // (a) own generation completed with data
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[(b"room:n", b"N")])
            .executable_with(&key_of(&g1), &[(b"room:o", b"O")]);
        assert!(journaled(&mut store, &mut io, &lineage, newest())
            .status
            .is_some());
        let before = store.get_secret(MIGRATION_JOURNAL_KEY);
        let r = block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &key_of(&g2),
            &newest(),
            None,
        ));
        assert!(
            matches!(r, Ok(AppImport::AlreadyImported)),
            "a completed own-generation import is reported as already imported: {r:?}"
        );
        assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), before);
        // (b) a newer NoData resolution does not supersede an older generation
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .unwrap();
        let mut j = stored_journal(&store);
        j.record(
            &key_of(&g2),
            2,
            RunOutcome::Resolved(JournalResolution::NoData),
        );
        put_journal(&mut store, &j);
        store.set_secret(
            &pred_done_marker(&key_of(&g2)),
            PRED_DONE_MARKER_VALUE_EMPTY,
        );
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &key_of(&g1),
            &newest(),
            None,
        ))
        .expect_flagged("a newer EMPTY generation does not supersede");
        assert!(stored_status(&store, &lineage).interrupted_import());
        // (c) a newer rejection-resolved generation holds data and does supersede
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .unwrap();
        let mut j = stored_journal(&store);
        j.record(
            &key_of(&g2),
            2,
            RunOutcome::Resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 0,
                items_seen: 0,
            }),
        );
        put_journal(&mut store, &j);
        assert!(matches!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &key_of(&g1),
                &newest(),
                None
            )),
            Err(JournalError::NotImportable(_))
        ));
    }

    /// The legacy-seal refusals are typed too.
    #[test]
    fn r9_p7_typed_refusal_for_a_legacy_seal() {
        let g3 = entry(3, 3);
        let k3 = key_of(&g3);
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g3],
            &newest(),
        ))
        .expect("begin");
        assert!(matches!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &[g3],
                &k3,
                &newest(),
                None
            )),
            Err(JournalError::NotImportable(_))
        ));
    }

    /// Fixed r8 fixture: only g3 in the lineage, so the one exact read the
    /// rebuild may do for it is the first, and a SECOND (fail-open) read would be the one
    /// that fails.
    #[test]
    fn r9_p8_a_failing_second_exact_read_cannot_drop_a_started_import() {
        struct FailSecondExact {
            store: MemStore,
            exact_reads: usize,
        }
        impl SuccessorSecretsIo for FailSecondExact {
            type Error = SecretStoreWriteFailed;
            async fn migration_marker(
                &mut self,
                q: &MarkerQuery<'_>,
            ) -> Result<Option<MigrationMarker>, Self::Error> {
                if q.legacy_bridge == LegacyBridge::ExactGenerationOnly {
                    self.exact_reads += 1;
                    if self.exact_reads >= 2 {
                        return Err(SecretStoreWriteFailed {
                            key: b"exact".to_vec(),
                        });
                    }
                }
                store_io(&mut self.store).migration_marker(q).await
            }
            async fn record_marker(
                &mut self,
                p: &DelegateKey,
                m: MigrationMarker,
            ) -> Result<(), Self::Error> {
                store_io(&mut self.store).record_marker(p, m).await
            }
            async fn write_secret(&mut self, i: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
                store_io(&mut self.store).write_secret(i).await
            }
        }
        impl JournaledSuccessorIo for FailSecondExact {
            async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY))
            }
            async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
                self.store.set_secret(MIGRATION_JOURNAL_KEY, j);
                Ok(())
            }
        }
        let g3 = entry(3, 3);
        let mut w = FailSecondExact {
            store: MemStore::default(),
            exact_reads: 0,
        };
        w.store.set_secret(&done_marker(5), b"1");
        w.store
            .set_secret(&pred_wip_marker(&key_of(&g3)), PRED_DONE_MARKER_VALUE_DATA);
        let r = block_on(begin_migration_journal(&mut w, &[g3], &newest()));
        assert!(
            matches!(r.as_ref().map(|s| s.interrupted_import()), Ok(true)),
            "{r:?}"
        );
    }

    /// Lineage grew AND an old entry is contradicted: both land in the stored journal.
    #[test]
    fn r9_p9_grown_lineage_and_a_contradicted_entry() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&key_of(&g1), &[]);
        assert!(complete(&journaled(&mut store, &mut io, &[g1], union())));
        let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut store, &[g1], &key_of(&g1), union());
        store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        // g2 has an in-progress data marker (an old plain walk's)
        store.set_secret(&pred_wip_marker(&key_of(&g2)), PRED_DONE_MARKER_VALUE_DATA);
        let lineage = [g1, g2];
        let st = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert!(st.interrupted_import());
        for g in [&g1, &g2] {
            assert!(
                matches!(
                    state_of(&store, g),
                    JournalState::Pending {
                        import: ImportFlag::Started,
                        ..
                    }
                ),
                "{g:?}"
            );
        }
    }

    /// The journaled walk itself (no begin) recovers a lost flag: the predecessor
    /// answering empty is not believed, and the entry does not seal NoData.
    #[test]
    fn r9_p10_walk_without_begin_recovers_a_lost_flag() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut store, &lineage, &k, union());
        store.set_secret(b"room:a", b"A");
        store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        // the predecessor answers empty again (a #5857 read fault)
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(
            !complete(&run),
            "sealed Complete over a partial copy: {run:?}"
        );
        assert!(interrupted(&run));
        assert!(stored_status(&store, &lineage).interrupted_import());
        // and when it answers properly, it completes
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        assert_eq!(store.get_secret(b"room:b").as_deref(), Some(&b"B"[..]));
    }

    /// The reopen loop reads the predecessor's OWN marker, as the rebuild does:
    /// a legacy seal for a newer generation must not hide its in-progress import.
    #[test]
    fn r9_p11_the_reopen_loop_sees_through_a_legacy_seal() {
        let g3 = entry(3, 3);
        let mut store = MemStore::default();
        store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g3],
            &newest(),
        ))
        .expect("begin");
        assert_eq!(
            state_of(&store, &g3),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
        );
        store.set_secret(&pred_wip_marker(&key_of(&g3)), PRED_DONE_MARKER_VALUE_DATA);
        let st = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g3],
            &newest(),
        ))
        .expect("begin");
        assert!(st.interrupted_import(), "{st:?}");
    }

    /// begin on an existing journal reads a marker only for the entries it might reopen.
    #[test]
    fn r9_p12_begin_on_an_existing_journal_reads_only_non_data_entries() {
        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let lineage = [g1, g2, g3];
        let mut w = InspectingWriter::new(&lineage);
        let mut io = MockIo::default()
            .executable_with(&key_of(&g1), &[])
            .executable_with(&key_of(&g2), &[(b"room:a", b"A")])
            .executable_with(&key_of(&g3), &[(b"room:b", b"B")]);
        assert!(complete(&w.run(&mut io, union())));
        let before = w.status_at_marker_reads.len();
        block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        assert_eq!(
            w.status_at_marker_reads.len() - before,
            1,
            "one NoData entry, one read"
        );
    }

    #[test]
    fn r9_p13_a_grown_lineage_reads_only_the_unseen_entries() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let mut w = InspectingWriter::new(&[g1]);
        let mut io = MockIo::default().executable_with(&key_of(&g1), &[(b"room:a", b"A")]);
        assert!(complete(&w.run(&mut io, union())));
        let before = w.status_at_marker_reads.len();
        block_on(begin_migration_journal(&mut w, &[g1, g2], &union())).expect("begin");
        assert_eq!(w.status_at_marker_reads.len() - before, 1);
    }

    /// Adapter whose EXACT marker reads can be switched to fail after the journal is started.
    struct ExactFault {
        store: MemStore,
        fail_exact: bool,
        /// Fail only the Nth and later exact reads while `fail_exact` is set.
        skip_exact: usize,
    }
    impl SuccessorSecretsIo for ExactFault {
        type Error = SecretStoreWriteFailed;
        async fn migration_marker(
            &mut self,
            q: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, Self::Error> {
            if self.fail_exact && q.legacy_bridge == LegacyBridge::ExactGenerationOnly {
                if self.skip_exact == 0 {
                    return Err(SecretStoreWriteFailed {
                        key: b"exact".to_vec(),
                    });
                }
                self.skip_exact -= 1;
            }
            store_io(&mut self.store).migration_marker(q).await
        }
        async fn record_marker(
            &mut self,
            p: &DelegateKey,
            m: MigrationMarker,
        ) -> Result<(), Self::Error> {
            store_io(&mut self.store).record_marker(p, m).await
        }
        async fn write_secret(&mut self, i: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
            store_io(&mut self.store).write_secret(i).await
        }
    }
    impl JournaledSuccessorIo for ExactFault {
        async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY))
        }
        async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
            self.store.set_secret(MIGRATION_JOURNAL_KEY, j);
            Ok(())
        }
    }

    /// seal_is_bridged: a failed exact read counts as BRIDGED (the reopenable side),
    /// in the journaled walk ...
    #[test]
    fn r9_p14_walk_a_failed_exact_read_does_not_journal_a_bridged_seal_as_imported() {
        let g3 = entry(3, 3);
        let mut w = ExactFault {
            store: MemStore::default(),
            fail_exact: false,
            skip_exact: 1,
        };
        w.store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(&mut w, &[g3], &newest())).expect("begin");
        w.fail_exact = true;
        let mut io = MockIo::default().executable_with(&key_of(&g3), &[(b"room:o", b"O")]);
        let run = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut io,
            &[g3],
            ack(),
            newest(),
        ));
        assert_eq!(
            state_of(&w.store, &g3),
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative),
            "{run:?}"
        );
    }

    /// ... and in note_app_import_started.
    #[test]
    fn r9_p15_note_app_a_failed_exact_read_is_a_refusal() {
        let g3 = entry(3, 3);
        let mut w = ExactFault {
            store: MemStore::default(),
            fail_exact: false,
            skip_exact: 0,
        };
        w.store.set_secret(&done_marker(5), b"1");
        block_on(begin_migration_journal(&mut w, &[g3], &newest())).expect("begin");
        w.fail_exact = true;
        let r = block_on(note_app_import_started(
            &mut w,
            &[g3],
            &key_of(&g3),
            &newest(),
            None,
        ));
        assert!(r.is_err(), "{r:?}");
    }

    #[test]
    fn r9_p16_a_resolved_entry_survives_a_later_silence() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        store.data.remove(&pred_done_marker(&k));
        let mut silent = MockIo::default().dead(&k);
        let run = journaled(&mut store, &mut silent, &lineage, union());
        assert!(complete(&run), "{run:?}");
        assert_eq!(
            state_of(&store, &lineage[0]),
            JournalState::Resolved(JournalResolution::NoData)
        );
    }

    #[test]
    fn r9_p17_a_reopened_no_data_entry_carries_no_rejection_count() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        r9_flag(&mut store, &lineage, &k, union());
        let st = stored_status(&store, &lineage);
        assert_eq!(st.rejected_items(), 0);
    }

    // ---- round-10 probes --------------------------------------------------------

    fn r10_started(st: &JournalStatus) -> Vec<u32> {
        let mut v: Vec<u32> = match st {
            JournalStatus::Incomplete { pending, .. } => pending
                .iter()
                .filter(|p| p.import == ImportFlag::Started)
                .map(|p| p.generation)
                .collect(),
            _ => Vec::new(),
        };
        v.sort_unstable();
        v
    }

    fn r10_resolved_empty(lineage: &[DelegateLineageEntry]) -> InspectingWriter {
        let mut w = InspectingWriter::new(lineage);
        let mut io = MockIo::default();
        for e in lineage {
            io = io.executable_with(&key_of(e), &[]);
        }
        assert!(complete(&w.run(&mut io, union())));
        w
    }

    /// A stuck marker EARLIER in the lineage must not stop the loop reaching a later,
    /// readable, contradicted entry: that one is reopened and stored, and both show
    /// as imports under way.
    #[test]
    fn r10_p1_a_stuck_marker_does_not_stop_a_later_reopen() {
        let lineage = [entry(1, 1), entry(2, 2)];
        let mut w = r10_resolved_empty(&lineage);
        let stale = w.store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut w.store, &lineage, &key_of(&lineage[1]), union());
        w.store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        w.fail_marker_read
            .insert(key_of(&lineage[0]).bytes().to_vec());
        let status = block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        assert_eq!(r10_started(&status), vec![1, 2], "{status:?}");
        assert!(
            matches!(
                state_of(&w.store, &lineage[1]),
                JournalState::Pending {
                    import: ImportFlag::Started,
                    ..
                }
            ),
            "the readable contradicted entry is reopened and stored"
        );
        assert_eq!(
            state_of(&w.store, &lineage[0]),
            JournalState::Resolved(JournalResolution::NoData),
            "the unread one is never stored as started"
        );
    }

    /// Two stuck markers at once are both reported, by begin.
    #[test]
    fn r10_p2_two_stuck_markers_are_both_reported() {
        let lineage = [entry(1, 1), entry(2, 2), entry(3, 3)];
        let mut w = r10_resolved_empty(&lineage);
        for i in [0usize, 2] {
            w.fail_marker_read
                .insert(key_of(&lineage[i]).bytes().to_vec());
        }
        let status = block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        assert_eq!(r10_started(&status), vec![1, 3], "{status:?}");
    }

    /// A stuck marker beside a lineage that GREW: the unseen entry is read and
    /// added, and the stuck one is still reported (begin, then the walk).
    #[test]
    fn r10_p3_a_stuck_marker_beside_a_grown_lineage_is_reported() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let mut w = r10_resolved_empty(&[g1]);
        w.fail_marker_read.insert(key_of(&g1).bytes().to_vec());
        let status = block_on(begin_migration_journal(&mut w, &[g1, g2], &union())).expect("begin");
        assert!(status.interrupted_import(), "begin: {status:?}");
        assert_eq!(r10_started(&status), vec![1], "{status:?}");
        // The walk, too (it halts at the unreadable g1).
        let mut w = r10_resolved_empty(&[g1]);
        w.fail_marker_read.insert(key_of(&g1).bytes().to_vec());
        w.lineage = vec![g1, g2];
        let mut io = MockIo::default()
            .executable_with(&key_of(&g1), &[])
            .executable_with(&key_of(&g2), &[]);
        let run = w.run(&mut io, union());
        let status = run.status.expect("stored");
        assert!(status.interrupted_import(), "walk: {status:?}");
    }

    /// begin New path (a reopen happened) still reports a different stuck entry.
    /// (covered by p1; this one checks the REPORTED status only, no stored asserts)
    #[test]
    fn r10_p3b_begin_new_path_reports_the_stuck_entry() {
        let lineage = [entry(1, 1), entry(2, 2)];
        let mut w = r10_resolved_empty(&lineage);
        let stale = w.store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut w.store, &lineage, &key_of(&lineage[1]), union());
        w.store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        w.fail_marker_read
            .insert(key_of(&lineage[0]).bytes().to_vec());
        let status = block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        assert!(r10_started(&status).contains(&1), "{status:?}");
    }

    /// Marker reads that fail only the first N times.
    struct FlakyMarker {
        store: MemStore,
        fail_first: usize,
    }
    impl SuccessorSecretsIo for FlakyMarker {
        type Error = SecretStoreWriteFailed;
        async fn migration_marker(
            &mut self,
            q: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, Self::Error> {
            if self.fail_first > 0 {
                self.fail_first -= 1;
                return Err(SecretStoreWriteFailed {
                    key: b"flaky".to_vec(),
                });
            }
            store_io(&mut self.store).migration_marker(q).await
        }
        async fn record_marker(
            &mut self,
            p: &DelegateKey,
            m: MigrationMarker,
        ) -> Result<(), Self::Error> {
            store_io(&mut self.store).record_marker(p, m).await
        }
        async fn write_secret(&mut self, i: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
            store_io(&mut self.store).write_secret(i).await
        }
    }
    impl JournaledSuccessorIo for FlakyMarker {
        async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY))
        }
        async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
            self.store.set_secret(MIGRATION_JOURNAL_KEY, j);
            Ok(())
        }
    }

    /// The start's read of a resolved-empty entry's marker fails, the walk's own
    /// read of the SAME marker succeeds: the walk verified it, so the run's status
    /// is Complete (documented: "the walk drops an entry once it has read the
    /// marker itself").
    #[test]
    fn r10_p4_a_walk_that_reads_the_marker_clears_the_unverified_entry() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let mut io = MockIo::default().executable_with(&k, &[]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        let mut w = FlakyMarker {
            store,
            fail_first: 1,
        };
        let run = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut io,
            &lineage,
            ack(),
            union(),
        ));
        assert!(!refused(&run), "{run:?}");
        let status = run.status.expect("stored");
        assert!(status.is_complete(), "{status:?}");
    }

    /// The HALTING row itself: a pending entry whose journal flag was lost, whose
    /// marker cannot be read. Behind a halt such an entry is reported as an import
    /// under way; at the halt it should be too.
    #[test]
    fn r10_p5_a_pending_entry_at_the_halt_with_an_unreadable_marker_is_unverified() {
        let g1 = entry(1, 1);
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&[g1]);
        block_on(begin_migration_journal(&mut w, &[g1], &union())).expect("begin");
        let stale = w.store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut w.store, &[g1], &k, union());
        w.store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        w.fail_marker_read.insert(k.bytes().to_vec());
        let mut io = MockIo::default().executable_with(&k, &[(b"room:a", b"A")]);
        let run = w.run(&mut io, union());
        let status = run.status.expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// Behind a halt, a legacy at-or-above seal for the entry's OWN generation must
    /// not hide its exact in-progress marker from the post-walk check.
    #[test]
    fn r10_p6_the_post_walk_check_sees_through_a_legacy_seal() {
        let (g2, g3) = (entry(2, 2), entry(4, 4));
        let lineage = [g2, g3];
        let k2 = key_of(&g2);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut store, &lineage, &k2, r10_cpu());
        store.set_secret(&done_marker(3), b"1");
        store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"g2:a", b"A")])
            .not_installed(&key_of(&g3));
        let status = journaled(&mut store, &mut io, &lineage, newest())
            .status
            .expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// The post-walk check reads nothing for an entry already flagged.
    #[test]
    fn r10_p7_the_post_walk_check_skips_a_flagged_entry() {
        let (g2, g3) = (entry(2, 2), entry(3, 3));
        let lineage = [g2, g3];
        let k2 = key_of(&g2);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &newest())).expect("begin");
        r9_flag(&mut w.store, &lineage, &k2, r10_cpu());
        let before = w.status_at_marker_reads.len();
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"g2:a", b"A")])
            .not_installed(&key_of(&g3));
        let _ = w.run(&mut io, newest());
        assert_eq!(
            w.status_at_marker_reads.len() - before,
            1,
            "only g3's walk read"
        );
    }

    // ---- round-10 fixes ---------------------------------------------------------

    fn r10_cpu() -> SecretSelectionPolicy {
        SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
            RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
        )
    }

    /// The first `fail_first_exact` exact marker reads fail; later ones succeed.
    struct FirstExactFails {
        store: MemStore,
        fail_first_exact: usize,
    }
    impl SuccessorSecretsIo for FirstExactFails {
        type Error = SecretStoreWriteFailed;
        async fn migration_marker(
            &mut self,
            q: &MarkerQuery<'_>,
        ) -> Result<Option<MigrationMarker>, Self::Error> {
            if q.legacy_bridge == LegacyBridge::ExactGenerationOnly && self.fail_first_exact > 0 {
                self.fail_first_exact -= 1;
                return Err(SecretStoreWriteFailed {
                    key: b"exact".to_vec(),
                });
            }
            store_io(&mut self.store).migration_marker(q).await
        }
        async fn record_marker(
            &mut self,
            p: &DelegateKey,
            m: MigrationMarker,
        ) -> Result<(), Self::Error> {
            store_io(&mut self.store).record_marker(p, m).await
        }
        async fn write_secret(&mut self, i: &RecoveredSecret<'_>) -> ItemWrite<Self::Error> {
            store_io(&mut self.store).write_secret(i).await
        }
    }
    impl JournaledSuccessorIo for FirstExactFails {
        async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.store.get_secret(MIGRATION_JOURNAL_KEY))
        }
        async fn store_journal(&mut self, j: &[u8]) -> Result<(), Self::Error> {
            self.store.set_secret(MIGRATION_JOURNAL_KEY, j);
            Ok(())
        }
    }

    /// A predecessor resolved as holding nothing whose marker records an app
    /// import under way (its flag lost to a stale store) and whose marker read
    /// fails, superseded by a newer generation under a snapshot policy: the walk
    /// never read its marker, so the run's status counts it as an import under way.
    #[test]
    fn an_unverified_entry_the_snapshot_supersedes_stays_unverified() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let (k1, k2) = (key_of(&g1), key_of(&g2));
        let mut w = InspectingWriter::new(&lineage);
        let mut io = MockIo::default()
            .executable_with(&k1, &[])
            .not_installed(&k2);
        let _ = w.run(&mut io, r10_cpu());
        let stale = w.store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut w.store, &lineage, &k1, r10_cpu());
        w.store.set_secret(b"g1:a", b"A");
        w.store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        w.fail_marker_read.insert(k1.bytes().to_vec());
        let mut io = MockIo::default()
            .executable_with(&k1, &[(b"g1:a", b"A"), (b"g1:b", b"B")])
            .executable_with(&k2, &[(b"g2:a", b"A2")]);
        let status = w.run(&mut io, r10_cpu()).status.expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// A seal read only through a legacy bridge is checked against the entry's own
    /// marker after the walk: an import under way there is flagged again.
    #[test]
    fn a_legacy_bridged_row_is_checked_against_its_own_marker() {
        let g3 = entry(3, 3);
        let k3 = key_of(&g3);
        let lineage = [g3];
        let mut store = MemStore::default();
        let mut j = MigrationJournal::new_pending(&lineage);
        j.record(&k3, 3, RunOutcome::Resolved(JournalResolution::NoData));
        store.set_secret(MIGRATION_JOURNAL_KEY, &j.encode());
        store.set_secret(&pred_wip_marker(&k3), PRED_DONE_MARKER_VALUE_DATA);
        store.set_secret(&done_marker(5), b"1");
        store.set_secret(b"g3:a", b"A");
        // The start's exact read fails once; the later ones succeed.
        let mut w = FirstExactFails {
            store,
            fail_first_exact: 1,
        };
        let mut io = MockIo::default().executable_with(&k3, &[(b"g3:a", b"A"), (b"g3:b", b"B")]);
        let run = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut io,
            &lineage,
            ack(),
            newest(),
        ));
        let status = run.status.expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
        assert!(matches!(
            state_of(&w.store, &g3),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// The row the walk halts on because its own marker read failed, pending with
    /// its flag lost: the run's status counts it as an import under way.
    #[test]
    fn the_row_a_failed_marker_read_halts_on_is_unverified() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k1 = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        let stale = w.store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut w.store, &lineage, &k1, union());
        w.store.set_secret(b"g1:a", b"A");
        w.store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        w.fail_marker_read.insert(k1.bytes().to_vec());
        let mut io = MockIo::default().executable_with(&k1, &[(b"g1:a", b"A"), (b"g1:b", b"B")]);
        let status = w.run(&mut io, union()).status.expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// A stuck marker on a generation the journal already resolved as imported does
    /// not halt the walk: its marker is not read, and older generations migrate.
    #[test]
    fn a_stuck_marker_on_an_imported_generation_does_not_halt_the_walk() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let (k1, k2) = (key_of(&g1), key_of(&g2));
        let mut w = InspectingWriter::new(&lineage);
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"room:n", b"N")])
            .not_installed(&k1);
        let _ = w.run(&mut io, union());
        assert_eq!(
            state_of(&w.store, &g2),
            JournalState::Resolved(JournalResolution::Imported)
        );
        w.fail_marker_read.insert(k2.bytes().to_vec());
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"room:n", b"N")])
            .executable_with(&k1, &[(b"room:o", b"O")]);
        let status = w.run(&mut io, union()).status.expect("stored");
        assert_eq!(w.store.get_secret(b"room:o").as_deref(), Some(&b"O"[..]));
        assert!(status.is_complete(), "{status:?}");
    }

    /// The caller's lineage, not the stored journal, decides which generations are
    /// newer: a journal another build numbered differently (an old tab during a
    /// rollout that inserted a forgotten generation) cannot let an older app flag
    /// past a newer import under a snapshot policy.
    #[test]
    fn the_callers_lineage_decides_what_is_newer() {
        let (a, x, c) = (entry(0, 10), entry(1, 11), entry(2, 12));
        let new = [a, x, c];
        let mut store = MemStore::default();
        // Stored by the old build, which numbers c as 1 (it never had x).
        let mut old_c = c;
        old_c.generation = 1;
        let mut j = MigrationJournal::new_pending(&[a, x, old_c]);
        j.mark_import_started(&key_of(&c), 1);
        put_journal(&mut store, &j);
        assert!(matches!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &new,
                &key_of(&x),
                &newest(),
                None
            )),
            Err(JournalError::NotImportable(_))
        ));
        // Under Union x is owed.
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &new,
            &key_of(&x),
            &union(),
            None,
        ))
        .expect_flagged("owed under Union");
    }

    /// An entry the start could not check, re-read successfully after the walk and
    /// found uncontradicted, is verified: the run's status can read `Complete`.
    #[test]
    fn a_marker_read_that_recovers_after_the_walk_verifies_the_entry() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let (k1, k2) = (key_of(&g1), key_of(&g2));
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&k1, &[])
            .not_installed(&k2);
        let _ = journaled(&mut store, &mut io, &lineage, r10_cpu());
        assert_eq!(
            state_of(&store, &g1),
            JournalState::Resolved(JournalResolution::NoData)
        );
        let mut w = FirstExactFails {
            store,
            fail_first_exact: 1,
        };
        let mut io = MockIo::default()
            .executable_with(&k1, &[])
            .executable_with(&k2, &[(b"g2:a", b"A2")]);
        let run = block_on(migrate_delegate_secrets_journaled(
            &mut w,
            &mut io,
            &lineage,
            ack(),
            r10_cpu(),
        ));
        let status = run.status.expect("stored");
        assert!(status.is_complete(), "{status:?}");
    }

    /// Marker reads per run under a snapshot policy: the start's checks are not
    /// repeated after the walk, and a journal-resolved import's marker is not read.
    #[test]
    fn a_snapshot_walk_reads_each_marker_at_most_once() {
        let lineage = [entry(1, 1), entry(2, 2), entry(3, 3)];
        let mut w = InspectingWriter::new(&lineage);
        let mut io = MockIo::default();
        for e in &lineage {
            io = io.executable_with(&key_of(e), &[(b"k", b"v")]);
        }
        // No journal yet: the start reads all three (one each), the walk reads g3's
        // (it imports) and stops; g2 and g1 are superseded, already read.
        assert!(complete(&w.run(&mut io, newest())));
        let first = w.status_at_marker_reads.len();
        // A stored journal: the start reads g2 and g1 (resolved as superseded); g3
        // is resolved imported, so neither it nor the post-walk check reads again.
        w.status_at_marker_reads.clear();
        assert!(complete(&w.run(&mut io, newest())));
        assert_eq!(first, 4, "first run");
        assert_eq!(w.status_at_marker_reads.len(), 2, "second run");
    }

    // ---- round-11 probes --------------------------------------------------------

    /// An EMPTY in-progress marker written after the journal was stored is read
    /// only by the post-walk check (the start reads no pending entry): it must not
    /// flag the entry, or a legitimately empty predecessor wedges for ever.
    #[test]
    fn r11_p1_an_empty_wip_behind_a_halt_flags_nothing_on_an_existing_journal() {
        let (g2, g3) = (entry(2, 2), entry(3, 3));
        let lineage = [g2, g3];
        let k2 = key_of(&g2);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        store.set_secret(&pred_wip_marker(&k2), PRED_DONE_MARKER_VALUE_EMPTY);
        let mut io = MockIo::default()
            .executable_with(&k2, &[(b"g2:a", b"A")])
            .not_installed(&key_of(&g3));
        let status = journaled(&mut store, &mut io, &lineage, newest())
            .status
            .expect("stored");
        assert!(!status.interrupted_import(), "{status:?}");
        assert!(matches!(
            state_of(&store, &g2),
            JournalState::Pending {
                import: ImportFlag::None,
                ..
            }
        ));
    }

    /// The lineage grows while a pending entry's flag is lost and the walk halts
    /// short of it: only the NEW entry was read at the start, so the old pending
    /// one must still be checked after the walk.
    #[test]
    fn r11_p2_a_grown_lineage_does_not_exempt_a_pending_entry_from_the_post_walk_check() {
        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let old = [g1, g2];
        let grown = [g1, g2, g3];
        let k1 = key_of(&g1);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &old,
            &newest(),
        ))
        .expect("begin");
        let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
        r9_flag(&mut store, &old, &k1, r10_cpu());
        store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
        let mut io = MockIo::default()
            .executable_with(&k1, &[(b"g1:a", b"A")])
            .executable_with(&key_of(&g2), &[(b"g2:a", b"A")])
            .not_installed(&key_of(&g3));
        let status = journaled(&mut store, &mut io, &grown, newest())
            .status
            .expect("stored");
        assert!(status.interrupted_import(), "{status:?}");
        assert!(matches!(
            state_of(&store, &g1),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// `begin`'s reopen loop must query THIS generation's exact marker: a legacy
    /// seal for the next generation must not hide the entry's own import.
    #[test]
    fn r11_p3_the_reopen_loop_reads_the_entrys_own_generation() {
        let g2 = entry(2, 2);
        let lineage = [g2];
        let k2 = key_of(&g2);
        let mut store = MemStore::default();
        // A journal resolving g2 as NoData with no completion marker (an empty seal
        // beside the wip marker would be read as contradicted before the legacy
        // seal is consulted).
        let mut j = MigrationJournal::new_pending(&lineage);
        j.record(&k2, 2, RunOutcome::Resolved(JournalResolution::NoData));
        store.set_secret(MIGRATION_JOURNAL_KEY, &j.encode());
        store.set_secret(&pred_wip_marker(&k2), PRED_DONE_MARKER_VALUE_DATA);
        store.set_secret(&done_marker(3), b"1");
        let status = block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        assert!(status.interrupted_import(), "{status:?}");
    }

    /// The lineage grows with an entry OLDER than the one the walk halts at: the
    /// start's read of the new entry is not repeated after the walk.
    #[test]
    fn r11_p4_a_grown_lineage_entry_is_read_once_per_walk() {
        let (g0, g1, g2) = (entry(1, 1), entry(2, 2), entry(3, 3));
        let old = [g1, g2];
        let grown = [g0, g1, g2];
        let mut w = InspectingWriter::new(&old);
        block_on(begin_migration_journal(&mut w, &old, &newest())).expect("begin");
        w.status_at_marker_reads.clear();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g0), &[(b"g0:a", b"A")])
            .executable_with(&key_of(&g1), &[(b"g1:a", b"A")])
            .not_installed(&key_of(&g2));
        w.lineage = grown.to_vec();
        let _ = w.run(&mut io, newest());
        // start: g0; walk: g2 (halts); post-walk: g1 (pending, never read). g0 is
        // not read again.
        assert_eq!(w.status_at_marker_reads.len(), 3);
    }

    /// A corrupt journal is rebuilt from the markers it reads once; the walk and
    /// the post-walk check do not read them again.
    #[test]
    fn r11_p5_a_corrupt_journal_start_counts_as_a_marker_read() {
        let lineage = [entry(1, 1), entry(2, 2), entry(3, 3)];
        let mk = || {
            let mut io = MockIo::default();
            for e in &lineage {
                io = io.executable_with(&key_of(e), &[(b"k", b"v")]);
            }
            io
        };
        let mut w = InspectingWriter::new(&lineage);
        let mut fresh = InspectingWriter::new(&lineage);
        assert!(complete(&fresh.run(&mut mk(), newest())));
        w.store.set_secret(MIGRATION_JOURNAL_KEY, b"garbage");
        assert!(complete(&w.run(&mut mk(), newest())));
        assert_eq!(
            w.status_at_marker_reads.len(),
            fresh.status_at_marker_reads.len() + lineage.len(),
            "a corrupt journal costs the fresh start's reads plus the rebuild's, no more"
        );
    }

    /// A journal-resolved import is reported as `AlreadyMigrated`.
    #[test]
    fn r11_p6_a_journal_resolved_row_is_reported_already_migrated() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[(b"room:n", b"N")])
            .executable_with(&key_of(&g1), &[(b"room:o", b"O")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        let run = journaled(&mut store, &mut io, &lineage, union());
        assert!(
            run.report
                .predecessors
                .iter()
                .all(|r| matches!(r, PredecessorMigration::AlreadyMigrated { .. })),
            "{:?}",
            run.report
        );
    }

    /// `note_app_import_started` refuses a key outside the caller's lineage, and
    /// records nothing.
    #[test]
    fn r11_p7_an_app_flag_is_refused_for_a_foreign_key() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[(b"room:n", b"N")])
            .executable_with(&key_of(&g1), &[(b"room:o", b"O")]);
        assert!(complete(&journaled(&mut store, &mut io, &lineage, union())));
        let before = store.get_secret(MIGRATION_JOURNAL_KEY);
        for (lin, k) in [
            (&lineage[..], key_of(&entry(9, 9))),
            (&lineage[1..], key_of(&g1)),
        ] {
            assert!(matches!(
                block_on(note_app_import_started(
                    &mut store_io(&mut store),
                    lin,
                    &k,
                    &union(),
                    None
                )),
                Err(JournalError::NotImportable(_))
            ));
        }
        assert_eq!(
            store.get_secret(MIGRATION_JOURNAL_KEY),
            before,
            "nothing recorded"
        );
    }

    /// `NotImportable` tells the app "do not import from this predecessor". A missing
    /// or corrupt journal is not that: it is "begin first", a plain failure.
    #[test]
    fn r11_p8_a_missing_or_corrupt_journal_is_not_reported_as_not_importable() {
        let lineage = [entry(1, 1)];
        let k = key_of(&lineage[0]);
        let mut store = MemStore::default();
        let r = block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ));
        assert!(matches!(r, Err(JournalError::Successor(_))), "{r:?}");
        store.set_secret(MIGRATION_JOURNAL_KEY, b"\xa1\x61v\x01garbage");
        let r = block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            None,
        ));
        assert!(matches!(r, Err(JournalError::Successor(_))), "{r:?}");
    }

    /// `begin` stores over a journal found corrupt at its re-read only after
    /// rebuilding it from the markers (the walk's post-walk check now masks this
    /// for the walk, so the rebuild's merge needs its own pin).
    #[test]
    fn r11_p9_begin_rebuilds_a_journal_found_corrupt_at_its_store() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let mut w = InspectingWriter::new(&[g1]);
        block_on(begin_migration_journal(&mut w, &[g1], &newest())).expect("begin");
        // Another session's import from g1 started; its journal flag is what the
        // corrupt write loses, its marker survives.
        w.store
            .set_secret(&pred_wip_marker(&key_of(&g1)), PRED_DONE_MARKER_VALUE_DATA);
        w.inject_at_first_marker_read = Some(b"\xa1\x61v\x01garbage".to_vec());
        let status =
            block_on(begin_migration_journal(&mut w, &[g1, g2], &newest())).expect("grown");
        assert!(status.interrupted_import(), "{status:?}");
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// A retryable write failure is an unresolved attempt: it is counted, not
    /// treated as a predecessor the run never examined.
    #[test]
    fn r11_p10_a_retryable_failure_counts_an_attempt() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:x".to_vec());
        for expected in 1..=2u32 {
            let mut io = MockIo::default()
                .executable_with(&key_of(&g1), &[(b"room:a", b"A"), (b"room:x", b"X")]);
            let status = w.run(&mut io, union()).status.expect("stored");
            match status {
                JournalStatus::Incomplete { pending, .. } => {
                    assert_eq!(pending[0].attempts, expected, "{pending:?}")
                }
                other => panic!("{other:?}"),
            }
        }
    }

    // ---- round-11 fixes ---------------------------------------------------------

    /// Under a snapshot policy, a newer generation with an import from it under
    /// way holds the authoritative snapshot (the walk finishes it before looking
    /// at older ones): an app flag on an older one is refused. Under Union it is
    /// owed.
    #[test]
    fn a_newer_import_under_way_supersedes_an_older_app_flag_under_a_snapshot_policy() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            let policy = make();
            let (g1, g2) = (entry(1, 1), entry(2, 2));
            let lineage = [g1, g2];
            // A newer generation that has not answered: plain NewestSnapshotWins
            // does not import past it (the walk halts there), the continue-past
            // variant does.
            let mut quiet = MemStore::default();
            block_on(begin_migration_journal(
                &mut store_io(&mut quiet),
                &lineage,
                &policy,
            ))
            .expect("begin");
            let r = block_on(note_app_import_started(
                &mut store_io(&mut quiet),
                &lineage,
                &key_of(&g1),
                &policy,
                None,
            ));
            if policy.unresponsive_terminates(false) {
                assert!(matches!(r, Err(JournalError::NotImportable(_))), "{r:?}");
            } else {
                r.expect_flagged("the continue-past policy imports past a silent newer generation");
            }
            let mut store = MemStore::default();
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &policy,
            ))
            .expect("begin");
            r9_flag(&mut store, &lineage, &key_of(&g2), make());
            store.set_secret(b"room:n", b"N");
            assert!(matches!(
                block_on(note_app_import_started(
                    &mut store_io(&mut store),
                    &lineage,
                    &key_of(&g1),
                    &policy,
                    None
                )),
                Err(JournalError::NotImportable(_))
            ));
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &key_of(&g1),
                &union(),
                None,
            ))
            .expect_flagged("owed under Union");
        }
    }

    /// A lineage renumbered after the journal was written (a forgotten generation
    /// inserted ahead): the app's flag goes by the caller's lineage, so it is
    /// accepted without the stored generations changing.
    #[test]
    fn an_app_flag_after_a_lineage_renumber_goes_by_the_callers_lineage() {
        let (a0, b1) = (entry(0, 10), entry(1, 11));
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[a0, b1],
            &union(),
        ))
        .expect("begin");
        let x0 = entry(0, 9);
        let mut a1 = a0;
        a1.generation = 1;
        let mut b2 = b1;
        b2.generation = 2;
        let lineage = [x0, a1, b2];
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &key_of(&a1),
            &union(),
            None,
        ))
        .expect_flagged("accepted");
        assert!(matches!(
            state_of(&store, &a1),
            JournalState::Pending {
                import: ImportFlag::Started,
                ..
            }
        ));
    }

    /// A pure renumber (the same keys, numbered differently) stores nothing: two
    /// builds with different numbering do not rewrite the journal on every load.
    #[test]
    fn begin_does_not_store_a_pure_renumber() {
        let (a0, b1) = (entry(0, 10), entry(1, 11));
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[a0, b1],
            &union(),
        ))
        .expect("begin");
        let before = store.get_secret(MIGRATION_JOURNAL_KEY);
        let (mut a5, mut b6) = (a0, b1);
        a5.generation = 5;
        b6.generation = 6;
        for lineage in [[a5, b6], [a0, b1], [a5, b6]] {
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &union(),
            ))
            .expect("begin");
            assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), before);
        }
    }

    // ---- round-12 fixes: the snapshot guard reads the caller's lineage ---------

    fn r12_flag(
        store: &mut MemStore,
        lineage: &[DelegateLineageEntry],
        k: &DelegateKey,
        policy: &SecretSelectionPolicy,
    ) -> Result<AppImport, JournalError> {
        block_on(note_app_import_started(
            &mut store_io(store),
            lineage,
            k,
            policy,
            None,
        ))
    }

    /// A newer generation's journal flag erased by another session's stale store,
    /// its own marker still recording the import: an older flag is refused under a
    /// snapshot policy, and nothing is recorded for it.
    #[test]
    fn a_newer_marker_recording_an_import_refuses_an_older_flag() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            let (g1, g2) = (entry(1, 1), entry(2, 2));
            let lineage = [g1, g2];
            let mut store = MemStore::default();
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &make(),
            ))
            .expect("begin");
            let stale = store.get_secret(MIGRATION_JOURNAL_KEY).unwrap();
            r12_flag(&mut store, &lineage, &key_of(&g2), &make()).expect_flagged("flag g2");
            store.set_secret(MIGRATION_JOURNAL_KEY, &stale);
            let before = (
                store.get_secret(MIGRATION_JOURNAL_KEY),
                store.get_secret(&pred_wip_marker(&key_of(&g1))),
            );
            assert!(matches!(
                r12_flag(&mut store, &lineage, &key_of(&g1), &make()),
                Err(JournalError::NotImportable(_))
            ));
            assert_eq!(
                (
                    store.get_secret(MIGRATION_JOURNAL_KEY),
                    store.get_secret(&pred_wip_marker(&key_of(&g1))),
                ),
                before,
                "a refusal records nothing"
            );
        }
    }

    /// A newer generation sealed with its data only in its marker (the walk's final
    /// journal store failed): an older flag is refused under a snapshot policy.
    #[test]
    fn a_newer_seal_with_data_refuses_an_older_flag() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        store.set_secret(&pred_done_marker(&key_of(&g2)), PRED_DONE_MARKER_VALUE_DATA);
        assert!(matches!(
            r12_flag(&mut store, &lineage, &key_of(&g1), &newest()),
            Err(JournalError::NotImportable(_))
        ));
        // An empty seal supersedes nothing.
        store.set_secret(
            &pred_done_marker(&key_of(&g2)),
            PRED_DONE_MARKER_VALUE_EMPTY,
        );
        r12_flag(&mut store, &lineage, &key_of(&g1), &newest()).expect_flagged("not superseded");
    }

    /// A newer generation imported with permanent rejections, reopened by a higher
    /// import revision, still holds the rest of its data: an older flag is refused
    /// under a snapshot policy.
    #[test]
    fn a_newer_reopened_rejection_refuses_an_older_flag() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut w = InspectingWriter::new(&lineage);
        w.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[(b"room:x", b"NEWX"), (b"room:y", b"Y")])
            .executable_with(&key_of(&g1), &[(b"room:x", b"OLDX")]);
        let _ = w.run(&mut io, newest());
        assert!(matches!(
            state_of(&w.store, &g2),
            JournalState::Resolved(JournalResolution::ImportedWithRejections { .. })
        ));
        w.permanent_fail.clear();
        w.revision = 1;
        assert!(matches!(
            block_on(note_app_import_started(
                &mut w,
                &lineage,
                &key_of(&g1),
                &newest(),
                None
            )),
            Err(JournalError::NotImportable(_))
        ));
    }

    /// A newer generation's marker that cannot be read, or a legacy seal whose
    /// exact read fails, is a plain failure, never "do not import" (a transient
    /// fault is not a verdict) and never an acceptance.
    #[test]
    fn an_unreadable_marker_in_the_guard_is_a_plain_failure() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &newest())).expect("begin");
        w.fail_marker_read.insert(key_of(&g2).bytes().to_vec());
        assert!(matches!(
            block_on(note_app_import_started(
                &mut w,
                &lineage,
                &key_of(&g1),
                &newest(),
                None
            )),
            Err(JournalError::Successor(_))
        ));
        // A legacy seal for gen 5 covers g3; its exact read fails.
        let g3 = entry(3, 3);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g3],
            &newest(),
        ))
        .expect("begin");
        store.set_secret(&done_marker(5), b"1");
        let mut f = FirstExactFails {
            store,
            fail_first_exact: 1,
        };
        assert!(matches!(
            block_on(note_app_import_started(
                &mut f,
                &[g3],
                &key_of(&g3),
                &newest(),
                None
            )),
            Err(JournalError::Successor(_))
        ));
    }

    /// A predecessor in the caller's lineage that the journal has no entry for
    /// (the lineage grew and `begin` has not run with it): "begin first", a plain
    /// failure, and nothing is recorded.
    #[test]
    fn an_app_flag_before_begin_saw_the_grown_lineage_is_a_plain_failure() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g1],
            &union(),
        ))
        .expect("begin");
        let before = store.get_secret(MIGRATION_JOURNAL_KEY);
        assert!(matches!(
            r12_flag(&mut store, &[g1, g2], &key_of(&g2), &union()),
            Err(JournalError::Successor(_))
        ));
        assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), before);
        assert!(store.get_secret(&pred_wip_marker(&key_of(&g2))).is_none());
    }

    // ---- round-13 probes --------------------------------------------------------

    /// A generation OLDER than the one flagged holding data does not make the newest
    /// refusable: the guard looks only at newer generations. Over-refusing here
    /// strands the authoritative snapshot's app-side import.
    #[test]
    fn r13_p1_an_older_generation_holding_data_does_not_refuse_a_newer_flag() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            for older_state in 0..3 {
                let (g1, g2) = (entry(1, 1), entry(2, 2));
                let lineage = [g1, g2];
                let mut store = MemStore::default();
                block_on(begin_migration_journal(
                    &mut store_io(&mut store),
                    &lineage,
                    &make(),
                ))
                .expect("begin");
                match older_state {
                    // journal resolved with data (and its seal)
                    0 => {
                        let mut j = MigrationJournal::new_pending(&lineage);
                        j.record(
                            &key_of(&g1),
                            1,
                            RunOutcome::Resolved(JournalResolution::Imported),
                        );
                        put_journal(&mut store, &j);
                        store.set_secret(
                            &pred_done_marker(&key_of(&g1)),
                            PRED_DONE_MARKER_VALUE_DATA,
                        );
                    }
                    // an import under way
                    // (flagged under the continue-past policy, which imports past a
                    // newer generation that has not answered)
                    1 => {
                        r12_flag(&mut store, &lineage, &key_of(&g1), &r10_cpu())
                            .expect_flagged("g1");
                    }
                    // only its marker records data
                    _ => {
                        store.set_secret(
                            &pred_wip_marker(&key_of(&g1)),
                            PRED_DONE_MARKER_VALUE_DATA,
                        );
                    }
                }
                r12_flag(&mut store, &lineage, &key_of(&g2), &make())
                    .expect_flagged("the newest generation is never superseded by an older one");
                assert!(matches!(
                    state_of(&store, &g2),
                    JournalState::Pending {
                        import: ImportFlag::Started,
                        ..
                    }
                ));
            }
        }
    }

    /// A newer generation whose in-progress marker saw NO data does not hold the
    /// authoritative snapshot. The continue-past policy accepts the older flag;
    /// plain NewestSnapshotWins defers it only because the newer one has not
    /// answered yet, not as superseded.
    #[test]
    fn r13_p2_a_newer_empty_in_progress_marker_does_not_refuse_an_older_flag() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            let (g1, g2) = (entry(1, 1), entry(2, 2));
            let lineage = [g1, g2];
            let mut store = MemStore::default();
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &make(),
            ))
            .expect("begin");
            store.set_secret(&pred_wip_marker(&key_of(&g2)), PRED_DONE_MARKER_VALUE_EMPTY);
            let r = r12_flag(&mut store, &lineage, &key_of(&g1), &make());
            if make().unresponsive_terminates(false) {
                assert!(
                    matches!(&r, Err(JournalError::NotImportable(m)) if m.contains("has not answered")),
                    "{r:?}"
                );
            } else {
                r.expect_flagged("a newer generation that saw nothing supersedes nothing");
            }
        }
    }

    /// A legacy GENERATION-KEYED seal written for the newer generation AFTER the
    /// journal was begun, while the older one has its own data seal: the guard must
    /// read the NEWER generation's number for it (not the flagged one's), or the
    /// older flag returns Ok and the app re-merges older values over the newer.
    #[test]
    fn r13_p3_a_legacy_exact_seal_for_a_newer_generation_refuses_an_older_flag() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &newest(),
        ))
        .expect("begin");
        store.set_secret(&pred_done_marker(&key_of(&g1)), PRED_DONE_MARKER_VALUE_DATA);
        store.set_secret(&done_marker(2), b"1");
        let before = store.get_secret(MIGRATION_JOURNAL_KEY);
        assert!(matches!(
            r12_flag(&mut store, &lineage, &key_of(&g1), &newest()),
            Err(JournalError::NotImportable(_))
        ));
        assert_eq!(store.get_secret(MIGRATION_JOURNAL_KEY), before);
    }

    /// A legacy at-or-above seal for a newer generation hides this generation's own
    /// in-progress import: the flag is still refused (superseded), not returned Ok
    /// with nothing recorded.
    #[test]
    fn r13_p4_a_legacy_seal_over_an_own_in_progress_marker_is_refused() {
        let g3 = entry(3, 3);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g3],
            &newest(),
        ))
        .expect("begin");
        store.set_secret(&pred_wip_marker(&key_of(&g3)), PRED_DONE_MARKER_VALUE_DATA);
        store.set_secret(&done_marker(5), b"1");
        assert!(matches!(
            r12_flag(&mut store, &[g3], &key_of(&g3), &newest()),
            Err(JournalError::NotImportable(_))
        ));
    }

    /// A newer lineage entry the journal has never seen and whose marker is clean
    /// supersedes nothing: the continue-past policy accepts, and plain
    /// NewestSnapshotWins defers only because it has not answered.
    #[test]
    fn r13_p5_an_unjournaled_newer_entry_with_a_clean_marker_refuses_nothing() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g1],
            &newest(),
        ))
        .expect("begin");
        r12_flag(&mut store, &[g1, g2], &key_of(&g1), &r10_cpu()).expect_flagged("accepted");
        let r = r12_flag(&mut store, &[g1, g2], &key_of(&g1), &newest());
        assert!(
            matches!(&r, Err(JournalError::NotImportable(m)) if m.contains("has not answered")),
            "{r:?}"
        );
    }

    /// The same delegate key with another code hash is not in the lineage.
    #[test]
    fn r13_p6_a_known_delegate_key_with_a_foreign_code_hash_is_not_importable() {
        let g1 = entry(1, 1);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &[g1],
            &union(),
        ))
        .expect("begin");
        let foreign = DelegateKey::new(g1.delegate_key, CodeHash::new([0xEE; 32]));
        assert!(matches!(
            r12_flag(&mut store, &[g1], &foreign, &union()),
            Err(JournalError::NotImportable(_))
        ));
    }

    /// Every newer generation counts, not just the first one the caller's slice
    /// lists: with three generations, data on only the newest or only the middle
    /// one refuses the oldest, in either slice order, whatever the way the data is
    /// recorded (journal flag, or marker only).
    #[test]
    fn r13_p7_any_newer_generation_holding_data_refuses_an_older_flag() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            for descending in [false, true] {
                for holder in [2usize, 3] {
                    for via_marker in [false, true] {
                        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
                        let mut lineage = vec![g1, g2, g3];
                        if descending {
                            lineage.reverse();
                        }
                        let mut store = MemStore::default();
                        block_on(begin_migration_journal(
                            &mut store_io(&mut store),
                            &lineage,
                            &make(),
                        ))
                        .expect("begin");
                        let h = if holder == 2 { g2 } else { g3 };
                        if via_marker {
                            store.set_secret(
                                &pred_wip_marker(&key_of(&h)),
                                PRED_DONE_MARKER_VALUE_DATA,
                            );
                        } else {
                            r12_flag(&mut store, &lineage, &key_of(&h), &r10_cpu())
                                .expect_flagged("holder");
                        }
                        let r = r12_flag(&mut store, &lineage, &key_of(&g1), &make());
                        assert!(
                            matches!(r, Err(JournalError::NotImportable(_))),
                            "descending={descending} holder={holder} via_marker={via_marker}: {r:?}"
                        );
                    }
                }
            }
        }
    }

    /// A newer generation the journal already shows holding data refuses without a
    /// marker read: a fault on that marker cannot turn the refusal into a failure
    /// (the documented cost reads only the markers the journal does not settle).
    #[test]
    fn r13_p8_a_journal_settled_newer_generation_is_not_re_read() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &newest())).expect("begin");
        block_on(note_app_import_started(
            &mut w,
            &lineage,
            &key_of(&g2),
            &newest(),
            None,
        ))
        .expect_flagged("g2");
        w.fail_marker_read.insert(key_of(&g2).bytes().to_vec());
        let r = block_on(note_app_import_started(
            &mut w,
            &lineage,
            &key_of(&g1),
            &newest(),
            None,
        ));
        assert!(matches!(r, Err(JournalError::NotImportable(_))), "{r:?}");
    }

    /// Under plain NewestSnapshotWins, a newer generation resolved as holding
    /// nothing lets an older flag through, as the walk goes past it; unless its
    /// own marker contradicts the resolution (an import from it since, whose flag
    /// a stale store erased).
    #[test]
    fn a_newer_generation_answered_empty_lets_an_older_flag_through_unless_contradicted() {
        let (g1, g2) = (entry(1, 1), entry(2, 2));
        let lineage = [g1, g2];
        let mut store = MemStore::default();
        let mut io = MockIo::default()
            .executable_with(&key_of(&g2), &[])
            .not_installed(&key_of(&g1));
        let _ = journaled(&mut store, &mut io, &lineage, newest());
        assert_eq!(
            state_of(&store, &g2),
            JournalState::Resolved(JournalResolution::NoData)
        );
        let mut contradicted = store.clone();
        let mut unsealed = store.clone();
        r12_flag(&mut store, &lineage, &key_of(&g1), &newest()).expect_flagged("accepted");
        contradicted.set_secret(&pred_wip_marker(&key_of(&g2)), PRED_DONE_MARKER_VALUE_DATA);
        // The reason matters: plain NSW would also refuse this as "has not answered"
        // if the data arm were broken, which would hide it.
        let r = r12_flag(&mut contradicted, &lineage, &key_of(&g1), &newest());
        assert!(
            matches!(&r, Err(JournalError::NotImportable(m)) if m.contains("authoritative snapshot")),
            "{r:?}"
        );
        // Without its empty seal the walk would ask it again: so does the guard,
        // whatever the journal says.
        unsealed.data.remove(&pred_done_marker(&key_of(&g2)));
        let r = r12_flag(&mut unsealed, &lineage, &key_of(&g1), &newest());
        assert!(
            matches!(&r, Err(JournalError::NotImportable(m)) if m.contains("has not answered")),
            "{r:?}"
        );
    }

    /// A predecessor resolved as imported with rejections at the current revision
    /// has no `Done` marker; an app flag on it is still reported as already
    /// imported (the walk does not offer it again either), and nothing is
    /// recorded. A higher revision reopens it, and then the flag is taken.
    #[test]
    fn an_app_flag_on_an_import_with_rejections_at_the_current_revision_is_already_imported() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let mut w = InspectingWriter::new(&lineage);
        w.permanent_fail.insert(b"room:x".to_vec());
        let mut io = MockIo::default()
            .executable_with(&key_of(&g1), &[(b"room:x", b"X"), (b"room:y", b"Y")]);
        let _ = w.run(&mut io, union());
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Resolved(JournalResolution::ImportedWithRejections { .. })
        ));
        let before = (
            w.store.get_secret(MIGRATION_JOURNAL_KEY),
            w.markers_recorded.len(),
        );
        let r = block_on(note_app_import_started(
            &mut w,
            &lineage,
            &key_of(&g1),
            &union(),
            None,
        ));
        assert!(matches!(r, Ok(AppImport::AlreadyImported)), "{r:?}");
        assert_eq!(
            (
                w.store.get_secret(MIGRATION_JOURNAL_KEY),
                w.markers_recorded.len()
            ),
            before
        );
        w.revision = 1;
        block_on(note_app_import_started(
            &mut w,
            &lineage,
            &key_of(&g1),
            &union(),
            None,
        ))
        .expect_flagged("reopened by the higher revision");
    }

    // ---- round-14 probes --------------------------------------------------------

    /// Plain NewestSnapshotWins refuses an older flag behind ANY newer generation
    /// that has not answered, so a bare `NotImportable` from it proves nothing about
    /// the data checks. These probes therefore make every other newer generation
    /// known-empty and assert the refusal REASON is the data, under both snapshot
    /// policies, for every way the guard can learn a newer generation holds data.
    fn r14_reason(r: Result<AppImport, JournalError>, ctx: &str) {
        match r {
            Err(JournalError::NotImportable(m)) => assert!(
                m.contains("authoritative snapshot"),
                "{ctx}: refused for the wrong reason: {m}"
            ),
            other => panic!("{ctx}: expected a data refusal, got {other:?}"),
        }
    }

    #[test]
    fn r14_p1_every_way_a_newer_generation_holds_data_refuses_under_both_policies() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            for three in [false, true] {
                for holder_is_top in [true, false] {
                    if !three && !holder_is_top {
                        continue;
                    }
                    for source in 0..9u8 {
                        let (g1, g2, g3) = (entry(1, 1), entry(2, 2), entry(3, 3));
                        let lineage: Vec<_> = if three {
                            vec![g1, g2, g3]
                        } else {
                            vec![g1, g2]
                        };
                        let holder = if !three || !holder_is_top { g2 } else { g3 };
                        let other: Option<DelegateLineageEntry> = if three {
                            Some(if holder_is_top { g2 } else { g3 })
                        } else {
                            None
                        };
                        let ctx = format!(
                            "policy_nsw={} three={three} top={holder_is_top} source={source}",
                            make().unresponsive_terminates(false)
                        );
                        let mut store = MemStore::default();
                        block_on(begin_migration_journal(
                            &mut store_io(&mut store),
                            &lineage,
                            &make(),
                        ))
                        .expect("begin");
                        let hk = key_of(&holder);
                        let mut j = MigrationJournal::new_pending(&lineage);
                        if let Some(o) = other {
                            j.record(
                                &key_of(&o),
                                1,
                                RunOutcome::Resolved(JournalResolution::NoData),
                            );
                            store.set_secret(
                                &pred_done_marker(&key_of(&o)),
                                PRED_DONE_MARKER_VALUE_EMPTY,
                            );
                        }
                        match source {
                            0 => {
                                j.record(&hk, 1, RunOutcome::Resolved(JournalResolution::Imported))
                            }
                            1 => j.record(
                                &hk,
                                1,
                                RunOutcome::Resolved(JournalResolution::ImportedWithRejections {
                                    rejected: 1,
                                    revision: 0,
                                    items_seen: 0,
                                }),
                            ),
                            _ => {}
                        }
                        put_journal(&mut store, &j);
                        match source {
                            2 => {
                                // a journal flag with no marker behind it
                                r12_flag(&mut store, &lineage, &hk, &r10_cpu())
                                    .expect_flagged("holder");
                                store.data.remove(&pred_wip_marker(&hk));
                            }
                            3 => {
                                store
                                    .set_secret(&pred_wip_marker(&hk), PRED_DONE_MARKER_VALUE_DATA);
                            }
                            4 => {
                                store.set_secret(
                                    &pred_done_marker(&hk),
                                    PRED_DONE_MARKER_VALUE_DATA,
                                );
                            }
                            5 => {
                                store.set_secret(&done_marker(holder.generation), b"1");
                            }
                            6 => {
                                // resolved empty, contradicted by an in-progress data marker
                                let mut j2 = stored_journal(&store);
                                j2.record(&hk, 1, RunOutcome::Resolved(JournalResolution::NoData));
                                put_journal(&mut store, &j2);
                                store
                                    .set_secret(&pred_wip_marker(&hk), PRED_DONE_MARKER_VALUE_DATA);
                            }
                            7 => {
                                // resolved empty, contradicted by a data seal
                                let mut j2 = stored_journal(&store);
                                j2.record(&hk, 1, RunOutcome::Resolved(JournalResolution::NoData));
                                put_journal(&mut store, &j2);
                                store.set_secret(
                                    &pred_done_marker(&hk),
                                    PRED_DONE_MARKER_VALUE_DATA,
                                );
                            }
                            8 => {
                                // a legacy seal AND the flagged generation's own data seal
                                store.set_secret(&done_marker(holder.generation), b"1");
                                store.set_secret(
                                    &pred_done_marker(&key_of(&g1)),
                                    PRED_DONE_MARKER_VALUE_DATA,
                                );
                            }
                            _ => {}
                        }
                        let before = store.get_secret(MIGRATION_JOURNAL_KEY);
                        let r = r12_flag(&mut store, &lineage, &key_of(&g1), &make());
                        r14_reason(r, &ctx);
                        assert_eq!(
                            store.get_secret(MIGRATION_JOURNAL_KEY),
                            before,
                            "{ctx}: wrote"
                        );
                    }
                }
            }
        }
    }

    /// A newer rejection a higher import revision reopened still holds the rest of
    /// its data. The guard's JOURNAL pass must say so by itself: the marker pass is
    /// a second line of defence, so the markers are removed here. Both policies,
    /// and the reason must be the data (plain NewestSnapshotWins would otherwise
    /// refuse the unanswered entry for a different reason and hide a broken arm).
    #[test]
    fn r14_p2_a_reopened_rejection_refuses_on_the_journal_alone() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            let (g1, g2) = (entry(1, 1), entry(2, 2));
            let lineage = [g1, g2];
            let mut w = InspectingWriter::new(&lineage);
            w.permanent_fail.insert(b"room:x".to_vec());
            let mut io = MockIo::default()
                .executable_with(&key_of(&g2), &[(b"room:x", b"NEWX"), (b"room:y", b"Y")])
                .executable_with(&key_of(&g1), &[(b"room:x", b"OLDX")]);
            let _ = w.run(&mut io, make());
            w.permanent_fail.clear();
            w.revision = 1;
            // What a walk at the higher revision stores: the resolution reopened.
            let mut reopened = stored_journal(&w.store);
            reopened.rebind(&JournalBinding::new(&make(), 1));
            put_journal(&mut w.store, &reopened);
            assert!(
                matches!(
                    state_of(&w.store, &g2),
                    JournalState::Pending { rejected, .. } if rejected > 0
                ),
                "{:?}",
                state_of(&w.store, &g2)
            );
            w.store.data.remove(&pred_done_marker(&key_of(&g2)));
            w.store.data.remove(&pred_wip_marker(&key_of(&g2)));
            let r = block_on(note_app_import_started(
                &mut w,
                &lineage,
                &key_of(&g1),
                &make(),
                None,
            ));
            r14_reason(r, "reopened rejection, no markers");
        }
    }

    /// A predecessor sealed with its data in the successor while its journal entry
    /// is still pending (the walk's final journal store failed): an app flag is
    /// reported as already imported, and nothing is recorded.
    #[test]
    fn an_app_flag_on_a_sealed_import_the_journal_missed_is_already_imported() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        store.set_secret(&pred_done_marker(&key_of(&g1)), PRED_DONE_MARKER_VALUE_DATA);
        let before = store.data.clone();
        let r = r12_flag(&mut store, &lineage, &key_of(&g1), &union());
        assert!(matches!(r, Ok(AppImport::AlreadyImported)), "{r:?}");
        assert_eq!(store.data, before, "nothing recorded");
    }

    // ---- round-15 probes --------------------------------------------------------

    fn r15_already_completed(r: &Result<AppImport, JournalError>, ctx: &str) {
        assert!(
            matches!(r, Ok(AppImport::AlreadyImported)),
            "{ctx}: expected AlreadyImported, got {r:?}"
        );
    }

    /// Own `Done { had_data: true }` seal, journal entry still pending (the walk's
    /// final journal store failed), under EVERY policy. The existing
    /// `..._the_journal_missed_is_already_imported` pin uses Union only, so the
    /// `AtOrAboveGeneration` arm of the seal branch (the two snapshot policies)
    /// was reachable only with a resolved journal entry, which the journal check
    /// refuses first.
    #[test]
    fn r15_p1_a_sealed_import_the_journal_missed_is_already_imported_under_every_policy() {
        for (name, make) in [
            ("union", union as fn() -> SecretSelectionPolicy),
            ("nsw", newest),
            ("nsw_cpu", r10_cpu),
        ] {
            for with_newer_empty in [false, true] {
                let g1 = entry(1, 1);
                let g2 = entry(2, 2);
                let lineage: Vec<_> = if with_newer_empty {
                    vec![g1, g2]
                } else {
                    vec![g1]
                };
                let mut store = MemStore::default();
                block_on(begin_migration_journal(
                    &mut store_io(&mut store),
                    &lineage,
                    &make(),
                ))
                .expect("begin");
                store.set_secret(&pred_done_marker(&key_of(&g1)), PRED_DONE_MARKER_VALUE_DATA);
                if with_newer_empty {
                    // The newer generation has answered "nothing" (empty seal), so
                    // the snapshot guard passes and only the seal can refuse.
                    store.set_secret(
                        &pred_done_marker(&key_of(&g2)),
                        PRED_DONE_MARKER_VALUE_EMPTY,
                    );
                }
                assert!(matches!(
                    state_of(&store, &g1),
                    JournalState::Pending { .. }
                ));
                let before = store.data.clone();
                let r = r12_flag(&mut store, &lineage, &key_of(&g1), &make());
                r15_already_completed(&r, &format!("{name} newer_empty={with_newer_empty}"));
                assert_eq!(store.data, before, "{name}: nothing recorded");
            }
        }
    }

    /// The journal resolves the predecessor `Imported` but no marker says so (a
    /// stale store erased the seal). Only `ImportedWithRejections` was pinned
    /// through the journal check; a plain `Imported` was covered only by its seal.
    #[test]
    fn r15_p2_a_journal_resolved_import_without_markers_is_already_imported_under_every_policy() {
        for (name, make) in [
            ("union", union as fn() -> SecretSelectionPolicy),
            ("nsw", newest),
            ("nsw_cpu", r10_cpu),
        ] {
            let g1 = entry(1, 1);
            let lineage = [g1];
            let mut store = MemStore::default();
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &make(),
            ))
            .expect("begin");
            let mut j = MigrationJournal::new_pending(&lineage);
            j.record(
                &key_of(&g1),
                1,
                RunOutcome::Resolved(JournalResolution::Imported),
            );
            put_journal(&mut store, &j);
            store.data.remove(&pred_done_marker(&key_of(&g1)));
            store.data.remove(&pred_wip_marker(&key_of(&g1)));
            let before = store.data.clone();
            let r = r12_flag(&mut store, &lineage, &key_of(&g1), &make());
            r15_already_completed(&r, name);
            assert_eq!(store.data, before, "{name}: nothing recorded");
        }
    }

    // ---- round-16 probes ----------------------------------------------------------

    /// A fresh flag returns `Flagged` (not `AlreadyImported`) over every marker
    /// state the predecessor can already be in, under every policy, and records
    /// the flag in the journal and as a data-bearing in-progress marker. Before
    /// this, a flag over an EMPTY in-progress marker (an import that saw nothing
    /// and died) could return the wrong variant with every test green: an app
    /// that skips `AlreadyImported` would then never write data the journal now
    /// says is being written.
    #[test]
    fn r16_p1_a_fresh_flag_returns_flagged_over_every_prior_marker_state() {
        for (name, make) in [
            ("union", union as fn() -> SecretSelectionPolicy),
            ("nsw", newest),
            ("nsw_cpu", r10_cpu),
        ] {
            for prior in ["none", "wip_empty", "wip_data", "done_empty"] {
                let g1 = entry(1, 1);
                let lineage = [g1];
                let k = key_of(&g1);
                let mut store = MemStore::default();
                match prior {
                    "wip_empty" => {
                        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
                    }
                    "wip_data" => {
                        store.set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_DATA);
                    }
                    "done_empty" => {
                        store.set_secret(&pred_done_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
                    }
                    _ => {}
                }
                block_on(begin_migration_journal(
                    &mut store_io(&mut store),
                    &lineage,
                    &make(),
                ))
                .expect("begin");
                let r = r12_flag(&mut store, &lineage, &k, &make());
                assert_eq!(
                    r.as_ref().ok(),
                    Some(&AppImport::Flagged),
                    "{name}/{prior}: {r:?}"
                );
                assert_eq!(
                    store.get_secret(&pred_wip_marker(&k)).as_deref(),
                    Some(PRED_DONE_MARKER_VALUE_DATA),
                    "{name}/{prior}: data-bearing in-progress marker"
                );
                assert!(
                    stored_status(&store, &lineage).interrupted_import(),
                    "{name}/{prior}"
                );
            }
        }
    }

    /// A legacy `done:<n>` seal for the predecessor's OWN generation is its own
    /// seal (`AlreadyImported`, nothing recorded), under every policy, with the
    /// journal entry still pending; a legacy seal for a NEWER generation is a
    /// supersession (`NotImportable`) under the snapshot policies and the
    /// predecessor's own seal under Union. The pre-existing legacy tests only
    /// pin the `Err` side, so a change that turned the own-generation legacy
    /// seal into `NotImportable` (an app then never re-fills a short export from
    /// a pre-journal build's import) passed.
    #[test]
    fn r16_p2_a_legacy_seal_for_the_own_generation_is_already_imported_one_above_is_not() {
        for (name, make) in [
            ("union", union as fn() -> SecretSelectionPolicy),
            ("nsw", newest),
            ("nsw_cpu", r10_cpu),
        ] {
            for seal_gen in [3u32, 4, 7] {
                let g3 = entry(3, 3);
                let lineage = [g3];
                let k = key_of(&g3);
                let mut store = MemStore::default();
                block_on(begin_migration_journal(
                    &mut store_io(&mut store),
                    &lineage,
                    &make(),
                ))
                .expect("begin");
                // The journal missed the seal (written after `begin`, or its store failed).
                store.set_secret(&done_marker(seal_gen), b"1");
                let before = store.data.clone();
                let r = r12_flag(&mut store, &lineage, &k, &make());
                match (name == "union", seal_gen == 3) {
                    (_, true) => r15_already_completed(&r, &format!("{name} seal {seal_gen}")),
                    // Union: a legacy seal for another generation seals nothing here.
                    (true, false) => {
                        assert_eq!(
                            r.as_ref().ok(),
                            Some(&AppImport::Flagged),
                            "{name} seal {seal_gen}: {r:?}"
                        );
                        continue;
                    }
                    (false, false) => assert!(
                        matches!(&r, Err(JournalError::NotImportable(m)) if m.contains("legacy seal")),
                        "{name} seal {seal_gen}: {r:?}"
                    ),
                }
                assert_eq!(
                    store.data, before,
                    "{name} seal {seal_gen}: nothing recorded"
                );
            }
        }
    }

    /// The "rejections at the current revision" completed import, under EVERY
    /// policy (the pin above is Union only): `AlreadyImported`, nothing recorded; a
    /// higher revision reopens the rejection and the flag is `Flagged`.
    #[test]
    fn r16_p3_an_import_with_rejections_is_already_imported_under_every_policy() {
        for (name, make) in [
            ("union", union as fn() -> SecretSelectionPolicy),
            ("nsw", newest),
            ("nsw_cpu", r10_cpu),
        ] {
            let g1 = entry(1, 1);
            let lineage = [g1];
            let mut w = InspectingWriter::new(&lineage);
            w.permanent_fail.insert(b"room:x".to_vec());
            let mut io = MockIo::default()
                .executable_with(&key_of(&g1), &[(b"room:x", b"X"), (b"room:y", b"Y")]);
            let _ = w.run(&mut io, make());
            assert!(
                matches!(
                    state_of(&w.store, &g1),
                    JournalState::Resolved(JournalResolution::ImportedWithRejections { .. })
                ),
                "{name}"
            );
            let before = w.store.data.clone();
            let r = block_on(note_app_import_started(
                &mut w,
                &lineage,
                &key_of(&g1),
                &make(),
                None,
            ));
            r15_already_completed(&r, name);
            assert_eq!(w.store.data, before, "{name}: nothing recorded");
            w.revision = 1;
            block_on(note_app_import_started(
                &mut w,
                &lineage,
                &key_of(&g1),
                &make(),
                None,
            ))
            .expect_flagged(name);
        }
    }

    /// A legacy `done:5` seal sits above a two-generation lineage. Under both
    /// snapshot policies the newest listed generation (g4) is superseded by it
    /// (`legacy seal`), and so is g3 (under the continue-past policy the legacy
    /// branch is the only thing that refuses it; plain NewestSnapshotWins refuses
    /// it earlier, as behind a generation that has not answered). Every existing
    /// legacy-refusal pin used a one-entry lineage, so a legacy refusal that only
    /// fires for `predecessors.len() == 1` passed, and an app would be told
    /// `AlreadyImported` (re-merge it) for a generation a newer one supersedes.
    #[test]
    fn r16_p4_a_legacy_seal_above_a_longer_lineage_refuses_every_listed_generation() {
        for (name, make) in [
            ("nsw", newest as fn() -> SecretSelectionPolicy),
            ("nsw_cpu", r10_cpu),
        ] {
            let (g3, g4) = (entry(3, 3), entry(4, 4));
            let lineage = [g3, g4];
            let mut store = MemStore::default();
            block_on(begin_migration_journal(
                &mut store_io(&mut store),
                &lineage,
                &make(),
            ))
            .expect("begin");
            store.set_secret(&done_marker(5), b"1");
            let before = store.data.clone();
            for g in [g4, g3] {
                let r = r12_flag(&mut store, &lineage, &key_of(&g), &make());
                assert!(
                    matches!(&r, Err(JournalError::NotImportable(_))),
                    "{name} g{}: {r:?}",
                    g.generation
                );
                if g.generation == 4 || name == "nsw_cpu" {
                    assert!(
                        matches!(&r, Err(JournalError::NotImportable(m)) if m.contains("legacy seal")),
                        "{name} g{}: {r:?}",
                        g.generation
                    );
                }
            }
            assert_eq!(store.data, before, "{name}: nothing recorded");
        }
    }

    /// A read-back fault after the flag was recorded is a store fault
    /// (`JournalError::Successor`), never a `NotImportable` verdict about the
    /// predecessor: the two are told apart by variant, and the existing pins use
    /// `.is_err()` for these paths, so reclassifying either passed.
    #[test]
    fn r16_p5_a_marker_store_fault_is_a_successor_error_not_a_refusal() {
        // read-back read fails
        let e = entry(1, 1);
        let mut w = Quirky::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
        run_q(&mut w, &mut io, &[e], union());
        w.fail_reads_after_record = true;
        w.recorded = false;
        let r = block_on(note_app_import_started(
            &mut w,
            &[e],
            &key_of(&e),
            &union(),
            None,
        ));
        assert!(matches!(r, Err(JournalError::Successor(_))), "{r:?}");
        // read-back reads a dropped data flag
        let e = entry(1, 1);
        let mut w = Quirky::default();
        let mut io = MockIo::default().executable_with(&key_of(&e), &[]);
        run_q(&mut w, &mut io, &[e], union());
        let f = entry(2, 2);
        block_on(begin_migration_journal(&mut w, &[e, f], &union())).unwrap();
        w.drop_data_flag = true;
        let r = block_on(note_app_import_started(
            &mut w,
            &[e, f],
            &key_of(&f),
            &union(),
            None,
        ));
        assert!(matches!(r, Err(JournalError::Successor(_))), "{r:?}");
    }

    /// Another session completes the predecessor's import (with rejections: no
    /// `Done` marker) after this call loaded the journal: the store's re-read
    /// brings that resolution in, and the call reports `AlreadyImported` without
    /// recording a marker.
    #[test]
    fn a_completion_brought_in_by_the_flags_own_store_is_already_imported() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        let mut theirs = MigrationJournal::new_pending(&lineage);
        theirs.record(
            &k,
            1,
            RunOutcome::Resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 0,
                items_seen: 0,
            }),
        );
        w.inject_at_first_marker_read = Some(theirs.encode());
        let markers_before = w.markers_recorded.len();
        let r = block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None,
        ));
        assert!(matches!(r, Ok(AppImport::AlreadyImported)), "{r:?}");
        assert_eq!(
            w.markers_recorded.len(),
            markers_before,
            "no marker recorded"
        );
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Resolved(JournalResolution::ImportedWithRejections { .. })
        ));
    }

    // ---- round-17 probes ----------------------------------------------------------

    /// Another session's completion brought in by the flag's own store is
    /// `AlreadyImported` whichever data-bearing resolution it is (the round-16 test
    /// pins only `ImportedWithRejections`, so a check narrowed to it passed), under
    /// every policy. A rejection resolution from a LOWER revision is reopened by the
    /// store's merge under the binding, so it is flagged and the marker is recorded.
    #[test]
    fn r17_p1_a_completion_brought_in_by_the_flags_own_store_is_already_imported_whatever_its_kind()
    {
        for (name, make) in [
            ("union", union as fn() -> SecretSelectionPolicy),
            ("nsw", newest),
            ("nsw_cpu", r10_cpu),
        ] {
            for kind in ["imported", "rejections", "stale_rejections"] {
                let g1 = entry(1, 1);
                let lineage = [g1];
                let k = key_of(&g1);
                let mut w = InspectingWriter::new(&lineage);
                block_on(begin_migration_journal(&mut w, &lineage, &make())).expect("begin");
                if kind == "stale_rejections" {
                    w.revision = 1;
                }
                let resolution = match kind {
                    "imported" => JournalResolution::Imported,
                    _ => JournalResolution::ImportedWithRejections {
                        rejected: 1,
                        revision: 0,
                        items_seen: 0,
                    },
                };
                let mut theirs = MigrationJournal::new_pending(&lineage);
                theirs.record(&k, 1, RunOutcome::Resolved(resolution));
                w.inject_at_first_marker_read = Some(theirs.encode());
                let markers_before = w.markers_recorded.len();
                let r = block_on(note_app_import_started(&mut w, &lineage, &k, &make(), None));
                if kind == "stale_rejections" {
                    assert!(matches!(r, Ok(AppImport::Flagged)), "{name}/{kind}: {r:?}");
                    assert!(w.markers_recorded.len() > markers_before, "{name}/{kind}");
                    assert!(
                        matches!(state_of(&w.store, &g1), JournalState::Pending { .. }),
                        "{name}/{kind}"
                    );
                } else {
                    assert!(
                        matches!(r, Ok(AppImport::AlreadyImported)),
                        "{name}/{kind}: {r:?}"
                    );
                    assert_eq!(w.markers_recorded.len(), markers_before, "{name}/{kind}");
                    assert!(
                        matches!(state_of(&w.store, &g1), JournalState::Resolved(r) if r.is_data_bearing()),
                        "{name}/{kind}"
                    );
                }
            }
        }
    }

    /// `AppImport` stays `#[must_use]`: dropping the outcome of
    /// `note_app_import_started(.., None)` (`.await?;`, `.expect("..");`) must trip
    /// `unused_must_use`. `#[expect]` fails the build if the lint does not fire.
    #[test]
    fn r17_p2_dropping_an_app_import_trips_unused_must_use() {
        #[deny(unfulfilled_lint_expectations)]
        #[expect(unused_must_use)]
        fn drops(f: fn() -> AppImport) {
            f();
        }
        #[deny(unfulfilled_lint_expectations)]
        #[expect(unused_must_use)]
        fn drops_call(w: &mut InspectingWriter, l: &[DelegateLineageEntry], k: &DelegateKey) {
            block_on(note_app_import_started(w, l, k, &union(), None)).expect("flag");
        }
        let _ = (drops, drops_call);
    }

    // ---- #44: a shorter export after an import started is not believed --------

    /// River's history (river#760, then freenet-core#5857): an import is
    /// interrupted after its first item, and the retry's export comes back short
    /// (an index read that failed). The short export is not believed: the
    /// predecessor stays pending with its import flagged, and the full export on a
    /// later run completes it. Under every policy.
    #[test]
    fn a_shorter_export_after_an_import_started_is_not_believed() {
        for make in [union as fn() -> SecretSelectionPolicy, newest, r10_cpu] {
            let g1 = entry(1, 1);
            let lineage = [g1];
            let k = key_of(&g1);
            let full: &[(&[u8], &[u8])] =
                &[(b"room:a", b"A"), (b"room:b", b"B"), (b"room:c", b"C")];
            let mut w = InspectingWriter::new(&lineage);
            // Attempt 1: sees three items, writes room:a, fails the rest (a kill).
            w.retryable_fail.insert(b"room:b".to_vec());
            w.retryable_fail.insert(b"room:c".to_vec());
            let _ = w.run(&mut MockIo::default().executable_with(&k, full), make());
            assert!(matches!(
                state_of(&w.store, &g1),
                JournalState::Pending {
                    import: ImportFlag::Started,
                    items_seen: 3,
                    ..
                }
            ));
            w.retryable_fail.clear();
            // Attempt 2: the index read fails; only room:a comes back.
            let run = w.run(
                &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A")]),
                make(),
            );
            assert!(
                run.report.predecessors[0].exported_fewer_after_data(),
                "{run:?}"
            );
            let status = run.status.expect("stored");
            assert!(
                !status.is_complete() && status.interrupted_import(),
                "{status:?}"
            );
            assert!(w.store.get_secret(b"room:b").is_none());
            // Attempt 3: the full export completes it.
            let status = w
                .run(&mut MockIo::default().executable_with(&k, full), make())
                .status
                .expect("stored");
            assert!(status.is_complete(), "{status:?}");
            assert_eq!(w.store.get_secret(b"room:c").as_deref(), Some(&b"C"[..]));
        }
    }

    /// An export with as many items as before, or more, is believed, and the
    /// count rises to the larger one.
    #[test]
    fn an_export_as_large_as_before_is_believed_and_the_count_only_rises() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:b".to_vec());
        let two: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:b", b"B")];
        let _ = w.run(&mut MockIo::default().executable_with(&k, two), union());
        let _ = w.run(
            &mut MockIo::default().executable_with(
                &k,
                &[(b"room:a", b"A"), (b"room:b", b"B"), (b"room:c", b"C")],
            ),
            union(),
        );
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Pending { items_seen: 3, .. }
        ));
        w.retryable_fail.clear();
        let status = w
            .run(
                &mut MockIo::default().executable_with(
                    &k,
                    &[(b"room:a", b"A"), (b"room:b", b"B"), (b"room:c", b"C")],
                ),
                union(),
            )
            .status
            .expect("stored");
        assert!(status.is_complete(), "{status:?}");
    }

    /// The count an app passes with its flag is kept, and a later walk export
    /// below it is not believed. Without a count, nothing is recorded.
    #[test]
    fn an_app_counted_import_holds_the_walk_to_that_count() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut store = MemStore::default();
        block_on(begin_migration_journal(
            &mut store_io(&mut store),
            &lineage,
            &union(),
        ))
        .expect("begin");
        assert_eq!(
            block_on(note_app_import_started(
                &mut store_io(&mut store),
                &lineage,
                &k,
                &union(),
                Some(3)
            ))
            .expect("flag"),
            AppImport::Flagged
        );
        assert!(matches!(
            state_of(&store, &g1),
            JournalState::Pending { items_seen: 3, .. }
        ));
        store.set_secret(b"room:a", b"A");
        let run = journaled(
            &mut store,
            &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]),
            &lineage,
            union(),
        );
        assert!(
            run.report.predecessors[0].exported_fewer_after_data(),
            "{run:?}"
        );
        // A second flag with a smaller count does not lower it.
        let _ = block_on(note_app_import_started(
            &mut store_io(&mut store),
            &lineage,
            &k,
            &union(),
            Some(1),
        ));
        assert!(matches!(
            state_of(&store, &g1),
            JournalState::Pending { items_seen: 3, .. }
        ));
    }

    /// The count survives a merge (the larger wins) and the stored form.
    #[test]
    fn the_count_merges_by_maximum_and_round_trips() {
        let g1 = entry(1, 1);
        let k = key_of(&g1);
        let mut a = MigrationJournal::new_pending(&[g1]);
        a.mark_import_started(&k, 1);
        a.note_items_seen(&k, 2);
        let mut b = MigrationJournal::new_pending(&[g1]);
        b.mark_import_started(&k, 1);
        b.note_items_seen(&k, 5);
        a.merge_stored(&b, None);
        assert_eq!(a.items_seen(&k), 5);
        let back = MigrationJournal::decode(&a.encode()).expect("decode");
        assert_eq!(back.items_seen(&k), 5);
        // Not counted on an entry whose import has not started.
        let mut c = MigrationJournal::new_pending(&[g1]);
        assert!(!c.note_items_seen(&k, 4));
        assert_eq!(c.items_seen(&k), 0);
    }

    // ---- fm47 probes -------------------------------------------------------------

    fn pending_of(
        store: &MemStore,
        lineage: &[DelegateLineageEntry],
    ) -> Vec<crate::journal::PendingPredecessor> {
        match stored_status(store, lineage) {
            JournalStatus::Incomplete { pending, .. } => pending,
            other => panic!("{other:?}"),
        }
    }

    /// A larger export than the recorded count is made durable BEFORE its first
    /// item is written (a kill mid-import must not leave the old, smaller count).
    #[test]
    fn p1_a_larger_export_raises_the_stored_count_before_the_first_write() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:b".to_vec());
        let two: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:b", b"B")];
        let _ = w.run(&mut MockIo::default().executable_with(&k, two), union());
        assert_eq!(pending_of(&w.store, &lineage)[0].items_seen, 2);
        w.status_at_first_item = None;
        let three: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:b", b"B"), (b"room:c", b"C")];
        let _ = w.run(&mut MockIo::default().executable_with(&k, three), union());
        match w.status_at_first_item.clone().expect("first item") {
            JournalStatus::Incomplete { pending, .. } => assert_eq!(pending[0].items_seen, 3),
            other => panic!("{other:?}"),
        }
    }

    /// An app that re-flags (already flagged) with a count has it recorded.
    #[test]
    fn p2_a_count_on_an_already_flagged_predecessor_is_recorded() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            None,
        ))
        .expect_flagged("flag");
        assert_eq!(pending_of(&w.store, &lineage)[0].items_seen, 0);
        block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            Some(3),
        ))
        .expect_flagged("flag");
        assert_eq!(pending_of(&w.store, &lineage)[0].items_seen, 3);
    }

    /// A smaller or equal count costs no journal store.
    #[test]
    fn p3_a_smaller_count_costs_no_store() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            Some(3),
        ))
        .expect_flagged("flag");
        let before = w.journal_stores;
        for n in [1, 3] {
            block_on(note_app_import_started(
                &mut w,
                &lineage,
                &k,
                &union(),
                Some(n),
            ))
            .expect_flagged("flag");
        }
        assert_eq!(w.journal_stores, before);
        assert_eq!(pending_of(&w.store, &lineage)[0].items_seen, 3);
    }

    /// A journal written before #44 has no `items_seen` field and must decode.
    #[test]
    fn p4_a_pre_44_journal_decodes() {
        use ciborium::value::Value;
        let g1 = entry(1, 1);
        let k = key_of(&g1);
        let t = |s: &str| Value::Text(s.to_string());
        let i = |n: u32| Value::Integer(n.into());
        let e = Value::Map(vec![
            (t("key"), Value::Bytes(k.bytes().to_vec())),
            (t("generation"), i(1)),
            (t("state"), i(0)),
            (t("attempts"), i(2)),
            (t("import"), i(1)),
            (t("absent_streak"), i(0)),
            (t("rejected"), i(0)),
            (t("revision"), i(0)),
        ]);
        let j = Value::Map(vec![(t("v"), i(1)), (t("entries"), Value::Array(vec![e]))]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&j, &mut bytes).unwrap();
        let back = MigrationJournal::decode(&bytes).expect("old journal decodes");
        assert_eq!(back.items_seen(&k), 0);
        assert!(matches!(
            back.entry(&k).map(|e| e.state),
            Some(JournalState::Pending {
                attempts: 2,
                import: ImportFlag::Started,
                items_seen: 0,
                ..
            })
        ));
    }

    /// Reserved keys are not counted: a retry without them is not short.
    #[test]
    fn p5_reserved_keys_do_not_count_toward_the_export() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:b".to_vec());
        let with_journal: &[(&[u8], &[u8])] = &[
            (b"room:a", b"A"),
            (b"room:b", b"B"),
            (MIGRATION_JOURNAL_KEY, b"j"),
        ];
        let _ = w.run(
            &mut MockIo::default().executable_with(&k, with_journal),
            union(),
        );
        assert_eq!(pending_of(&w.store, &lineage)[0].items_seen, 2);
        w.retryable_fail.clear();
        let two: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:b", b"B")];
        let run = w.run(&mut MockIo::default().executable_with(&k, two), union());
        assert!(complete(&run), "{run:?}");
    }

    /// The two accessors are disjoint.
    #[test]
    fn p6_the_short_export_accessors_are_disjoint() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:b".to_vec());
        let two: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:b", b"B")];
        let _ = w.run(&mut MockIo::default().executable_with(&k, two), union());
        let none: &[(&[u8], &[u8])] = &[];
        let run = w.run(&mut MockIo::default().executable_with(&k, none), union());
        assert!(run.report.predecessors[0].exported_nothing_after_data());
        assert!(!run.report.predecessors[0].exported_fewer_after_data());
        let run = w.run(
            &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A")]),
            union(),
        );
        assert!(run.report.predecessors[0].exported_fewer_after_data());
        assert!(!run.report.predecessors[0].exported_nothing_after_data());
        let other = PredecessorMigration::Unresponsive {
            key: k.clone(),
            generation: 1,
            error: Some("transport fault".to_string()),
        };
        assert!(!other.exported_fewer_after_data());
        let none_err = PredecessorMigration::Unresponsive {
            key: k,
            generation: 1,
            error: None,
        };
        assert!(!none_err.exported_fewer_after_data());
        // the message carries both counts
        if let PredecessorMigration::Unresponsive { error: Some(e), .. } =
            &run.report.predecessors[0]
        {
            assert!(e.ends_with(": 1 of 2"), "{e}");
        } else {
            panic!()
        }
    }

    /// A reopened entry starts uncounted.
    #[test]
    fn p7_reopened_entries_start_uncounted_except_a_reopened_rejection() {
        let g1 = entry(1, 1);
        let k = key_of(&g1);
        let mut j = MigrationJournal::new_pending(&[g1]);
        j.record(&k, 1, resolved(JournalResolution::NoData));
        assert!(j.mark_import_started(&k, 1));
        assert_eq!(j.items_seen(&k), 0);
        // status of an entry absent from the journal
        let empty = MigrationJournal::default();
        match empty.status(&[g1], &union_binding()) {
            JournalStatus::Incomplete { pending, .. } => assert_eq!(pending[0].items_seen, 0),
            other => panic!("{other:?}"),
        }
        // rejections reopened by a higher import revision keep the count their
        // import saw (so a short export on the reopen is not believed)
        let mut j = MigrationJournal::new_pending(&[g1]);
        j.mark_import_started(&k, 1);
        j.note_items_seen(&k, 3);
        j.record(
            &k,
            1,
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 0,
                items_seen: 0,
            }),
        );
        let j = MigrationJournal::decode(&j.encode()).expect("round trip");
        let mut b = union_binding();
        b.import_revision = 1;
        match j.status(&[g1], &b) {
            JournalStatus::Incomplete { pending, .. } => assert_eq!(pending[0].items_seen, 3),
            other => panic!("{other:?}"),
        }
    }

    /// An import with rejections, reopened by a higher import revision, holds the
    /// retry to the count its import saw: a short export on the reopen is not
    /// believed, so the rejected item is still recovered once the read heals.
    #[test]
    fn a_reopened_rejection_holds_the_retry_to_its_count() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let full: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:b", b"B"), (b"room:x", b"X")];
        let mut w = InspectingWriter::new(&lineage);
        w.permanent_fail.insert(b"room:x".to_vec());
        let _ = w.run(&mut MockIo::default().executable_with(&k, full), union());
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Resolved(JournalResolution::ImportedWithRejections { items_seen: 3, .. })
        ));
        w.permanent_fail.clear();
        w.revision = 1;
        let run = w.run(
            &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]),
            union(),
        );
        assert!(
            run.report.predecessors[0].exported_fewer_after_data(),
            "{run:?}"
        );
        assert!(!run.status.expect("stored").is_complete());
        let status = w
            .run(&mut MockIo::default().executable_with(&k, full), union())
            .status
            .expect("stored");
        assert!(status.is_complete(), "{status:?}");
        assert_eq!(w.store.get_secret(b"room:x").as_deref(), Some(&b"X"[..]));
    }

    /// Another session stores a larger count after this run loaded the journal:
    /// the retry's re-read before its first item holds it to that count.
    #[test]
    fn a_count_stored_by_another_session_mid_run_holds_the_retry() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        block_on(begin_migration_journal(&mut w, &lineage, &union())).expect("begin");
        // This session's own count matches the short export, so nothing it does
        // raises it: only the re-read before the first item sees the other's.
        let _ = block_on(note_app_import_started(
            &mut w,
            &lineage,
            &k,
            &union(),
            Some(1),
        ))
        .expect("flag");
        w.store.set_secret(b"room:a", b"A");
        let mut theirs =
            MigrationJournal::decode(&w.store.get_secret(MIGRATION_JOURNAL_KEY).unwrap())
                .expect("decode");
        theirs.note_items_seen(&k, 3);
        w.inject_at_first_marker_read = Some(theirs.encode());
        let run = w.run(
            &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A")]),
            union(),
        );
        assert!(
            run.report.predecessors[0].exported_fewer_after_data(),
            "{run:?}"
        );
        assert!(!run.status.expect("stored").is_complete());
    }

    /// A key listed twice in one export counts once, so a later export listing
    /// it once is not held short.
    #[test]
    fn a_duplicated_key_counts_once() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:b".to_vec());
        let _ = w.run(
            &mut MockIo::default().executable_with(
                &k,
                &[(b"room:a", b"A"), (b"room:a", b"A"), (b"room:b", b"B")],
            ),
            union(),
        );
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Pending { items_seen: 2, .. }
        ));
        w.retryable_fail.clear();
        let status = w
            .run(
                &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:b", b"B")]),
                union(),
            )
            .status
            .expect("stored");
        assert!(status.is_complete(), "{status:?}");
    }

    // ---- fm47b probes (testing lens, re-review) ---------------------------------

    /// The journal as another session left it: `key` flagged with `n` items seen.
    fn their_flagged_journal(
        lineage: &[DelegateLineageEntry],
        key: &DelegateKey,
        generation: u32,
        n: u32,
    ) -> Vec<u8> {
        let mut theirs = MigrationJournal::new_pending(lineage);
        theirs.mark_import_started(key, generation);
        theirs.note_items_seen(key, n);
        theirs.encode()
    }

    /// The re-read check does not depend on the marker having recorded data: the
    /// other session stored its count and flag, but its marker is not there yet when
    /// this run reads it (`prior_saw_data` is false). A short export must still not
    /// be sealed.
    #[test]
    fn b1_a_count_stored_mid_run_holds_a_first_attempt_with_no_marker() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.inject_at_first_marker_read = Some(their_flagged_journal(&lineage, &k, 1, 3));
        w.marker_reads_before_inject = lineage.len();
        let run = w.run(
            &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A")]),
            union(),
        );
        assert!(
            run.report.predecessors[0].exported_fewer_after_data(),
            "{run:?}"
        );
        assert!(!w.store.has_secret(b"room:a"), "a short export was written");
        assert!(!run.status.expect("stored").is_complete());
    }

    /// The mid-run hold terminates (or not) the walk exactly as the earlier hold
    /// does, and says which counts it compared.
    #[test]
    fn b2_the_mid_run_hold_follows_the_policy_and_names_both_counts() {
        let (old, new) = (entry(1, 1), entry(2, 2));
        let lineage = [old, new];
        let (ko, kn) = (key_of(&old), key_of(&new));
        let io = || {
            MockIo::default()
                .executable_with(&kn, &[(b"room:n", b"N")])
                .executable_with(&ko, &[(b"room:o", b"O")])
        };
        for (policy, older_imported) in [
            (union(), true),
            (
                SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
                    RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
                ),
                false,
            ),
        ] {
            let mut w = InspectingWriter::new(&lineage);
            w.inject_at_first_marker_read = Some(their_flagged_journal(&lineage, &kn, 2, 3));
            w.marker_reads_before_inject = lineage.len();
            let run = w.run(&mut io(), policy);
            match &run.report.predecessors[0] {
                PredecessorMigration::Unresponsive { error: Some(e), .. } => {
                    assert!(e.ends_with(": 1 of 3"), "{e}")
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(
                w.store.has_secret(b"room:o"),
                older_imported,
                "older generation"
            );
            assert!(!w.store.has_secret(b"room:n"));
        }
    }

    /// Distinct means distinct KEYS: one key exported twice with different values
    /// is one item, so a later export listing it once is not short.
    #[test]
    fn b3_a_key_listed_twice_with_different_values_counts_once() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.retryable_fail.insert(b"room:b".to_vec());
        let _ = w.run(
            &mut MockIo::default().executable_with(
                &k,
                &[(b"room:a", b"A1"), (b"room:a", b"A2"), (b"room:b", b"B")],
            ),
            union(),
        );
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Pending { items_seen: 2, .. }
        ));
        w.retryable_fail.clear();
        let status = w
            .run(
                &mut MockIo::default()
                    .executable_with(&k, &[(b"room:a", b"A2"), (b"room:b", b"B")]),
                union(),
            )
            .status
            .expect("stored");
        assert!(status.is_complete(), "{status:?}");
    }

    /// Two sessions resolve one predecessor with rejections at the same revision,
    /// having seen different counts: the merge keeps the larger, whichever side is
    /// newer (the count only rises, #44).
    #[test]
    fn b4_merging_two_rejection_resolutions_keeps_the_larger_count() {
        let e = entry(1, 1);
        let k = key_of(&e);
        let resolved_with = |n: u32| {
            let mut j = MigrationJournal::new_pending(&[e]);
            j.mark_import_started(&k, 1);
            j.note_items_seen(&k, n);
            j.record(
                &k,
                1,
                resolved(JournalResolution::ImportedWithRejections {
                    rejected: 1,
                    revision: 0,
                    items_seen: 0,
                }),
            );
            j
        };
        let mut reopened = union_binding();
        reopened.import_revision = 1;
        for (ours_n, theirs_n) in [(2, 3), (3, 2)] {
            let mut ours = resolved_with(ours_n);
            ours.merge_stored(&resolved_with(theirs_n), Some(&union_binding()));
            match ours.status(&[e], &reopened) {
                JournalStatus::Incomplete { pending, .. } => {
                    assert_eq!(pending[0].items_seen, 3, "ours {ours_n}, theirs {theirs_n}")
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// `record` keeps the larger of the pending count and the resolution's own.
    #[test]
    fn b5_record_keeps_the_larger_of_the_two_rejection_counts() {
        let e = entry(1, 1);
        let k = key_of(&e);
        for (pending_n, resolved_n) in [(5, 2), (2, 5)] {
            let mut j = MigrationJournal::new_pending(&[e]);
            j.mark_import_started(&k, 1);
            j.note_items_seen(&k, pending_n);
            j.record(
                &k,
                1,
                resolved(JournalResolution::ImportedWithRejections {
                    rejected: 1,
                    revision: 0,
                    items_seen: resolved_n,
                }),
            );
            assert!(matches!(
                j.entry(&k).map(|e| e.state),
                Some(JournalState::Resolved(
                    JournalResolution::ImportedWithRejections { items_seen: 5, .. }
                ))
            ));
        }
    }

    /// A walk recording a rejection resolution over one another session already
    /// stored (brought in by its re-read) keeps that resolution's count.
    #[test]
    fn recording_a_rejection_over_a_stored_one_keeps_its_count() {
        let g1 = entry(1, 1);
        let k = key_of(&g1);
        let mut j = MigrationJournal::new_pending(&[g1]);
        j.mark_import_started(&k, 1);
        j.note_items_seen(&k, 3);
        let iwr = |seen| {
            resolved(JournalResolution::ImportedWithRejections {
                rejected: 1,
                revision: 1,
                items_seen: seen,
            })
        };
        j.record(&k, 1, iwr(0));
        j.record(&k, 1, iwr(0));
        assert!(matches!(
            j.entry(&k).map(|e| e.state),
            Some(JournalState::Resolved(
                JournalResolution::ImportedWithRejections { items_seen: 3, .. }
            ))
        ));
    }

    /// A pending attempt that saw more items, merged with another session's
    /// rejection resolution that saw fewer, keeps the larger count, in either
    /// merge order.
    #[test]
    fn a_rejection_resolution_merged_with_a_pending_attempt_keeps_the_larger_count() {
        let g1 = entry(1, 1);
        let k = key_of(&g1);
        let pending = || {
            let mut j = MigrationJournal::new_pending(&[g1]);
            j.mark_import_started(&k, 1);
            j.note_items_seen(&k, 3);
            j
        };
        let resolved_two = || {
            let mut j = MigrationJournal::new_pending(&[g1]);
            j.record(
                &k,
                1,
                resolved(JournalResolution::ImportedWithRejections {
                    rejected: 1,
                    revision: 0,
                    items_seen: 2,
                }),
            );
            j
        };
        for (mut ours, theirs) in [(pending(), resolved_two()), (resolved_two(), pending())] {
            ours.merge_stored(&theirs, None);
            assert!(matches!(
                ours.entry(&k).map(|e| e.state),
                Some(JournalState::Resolved(
                    JournalResolution::ImportedWithRejections { items_seen: 3, .. }
                ))
            ));
        }
    }

    /// #48: a rejection reopened by a higher import revision whose in-progress
    /// marker was lost still holds data by the count its import kept, so an empty
    /// retry is not believed and the rejected item is recovered later.
    #[test]
    fn a_reopened_rejection_without_its_marker_does_not_believe_an_empty_retry() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let full: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:x", b"X")];
        let mut w = InspectingWriter::new(&lineage);
        w.permanent_fail.insert(b"room:x".to_vec());
        let _ = w.run(&mut MockIo::default().executable_with(&k, full), union());
        assert!(matches!(
            state_of(&w.store, &g1),
            JournalState::Resolved(JournalResolution::ImportedWithRejections { .. })
        ));
        w.store.data.remove(&pred_wip_marker(&k));
        w.permanent_fail.clear();
        w.revision = 1;
        let run = w.run(&mut MockIo::default().executable_with(&k, &[]), union());
        assert!(
            run.report.predecessors[0].exported_nothing_after_data(),
            "{run:?}"
        );
        assert!(!run.status.expect("stored").is_complete());
        let status = w
            .run(&mut MockIo::default().executable_with(&k, full), union())
            .status
            .expect("stored");
        assert!(status.is_complete(), "{status:?}");
        assert_eq!(w.store.get_secret(b"room:x").as_deref(), Some(&b"X"[..]));
    }

    /// #48: an empty seal beside a counted, reopened rejection is not believed:
    /// the predecessor is asked again.
    #[test]
    fn an_empty_seal_beside_a_counted_reopened_rejection_is_asked_again() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let full: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:x", b"X")];
        let mut w = InspectingWriter::new(&lineage);
        w.permanent_fail.insert(b"room:x".to_vec());
        let _ = w.run(&mut MockIo::default().executable_with(&k, full), union());
        w.store.data.remove(&pred_wip_marker(&k));
        w.store
            .set_secret(&pred_done_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        w.permanent_fail.clear();
        w.revision = 1;
        let status = w
            .run(&mut MockIo::default().executable_with(&k, full), union())
            .status
            .expect("stored");
        assert!(status.is_complete(), "{status:?}");
        assert_eq!(w.store.get_secret(b"room:x").as_deref(), Some(&b"X"[..]));
    }

    /// #48: an empty in-progress marker beside a counted, reopened rejection does
    /// not make an empty retry believable.
    #[test]
    fn an_empty_in_progress_marker_beside_a_counted_rejection_is_not_believed() {
        let g1 = entry(1, 1);
        let lineage = [g1];
        let k = key_of(&g1);
        let mut w = InspectingWriter::new(&lineage);
        w.permanent_fail.insert(b"room:x".to_vec());
        let _ = w.run(
            &mut MockIo::default().executable_with(&k, &[(b"room:a", b"A"), (b"room:x", b"X")]),
            union(),
        );
        w.store
            .set_secret(&pred_wip_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
        w.permanent_fail.clear();
        w.revision = 1;
        let run = w.run(&mut MockIo::default().executable_with(&k, &[]), union());
        assert!(
            run.report.predecessors[0].exported_nothing_after_data(),
            "{run:?}"
        );
    }

    fn pol(i: usize) -> SecretSelectionPolicy {
        match i {
            0 => union(),
            1 => newest(),
            _ => cont(),
        }
    }

    fn cont() -> SecretSelectionPolicy {
        SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(
            RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
        )
    }

    /// PROBE (#48 gap A): a single-item predecessor whose only item was rejected
    /// has items_seen == 1. `> 0` vs `> 1` boundary.
    #[test]
    fn probe_single_item_rejection_without_marker_is_known_data() {
        for pi in 0..3usize {
            let g1 = entry(1, 1);
            let lineage = [g1];
            let k = key_of(&g1);
            let one: &[(&[u8], &[u8])] = &[(b"room:x", b"X")];
            let mut w = InspectingWriter::new(&lineage);
            w.permanent_fail.insert(b"room:x".to_vec());
            let _ = w.run(&mut MockIo::default().executable_with(&k, one), pol(pi));
            w.store.data.remove(&pred_wip_marker(&k));
            w.permanent_fail.clear();
            w.revision = 1;
            let run = w.run(&mut MockIo::default().executable_with(&k, &[]), pol(pi));
            assert!(
                run.report.predecessors[0].exported_nothing_after_data(),
                "{run:?}"
            );
            let status = w
                .run(&mut MockIo::default().executable_with(&k, one), pol(pi))
                .status
                .expect("stored");
            assert!(status.is_complete(), "{status:?}");
        }
    }

    /// PROBE (gap B): the writer is told retry == true on the re-offer after a
    /// reopened rejection whose marker was lost (no marker, journal import flag None).
    #[test]
    fn probe_reopened_rejection_without_marker_tells_writer_it_is_a_retry() {
        for pi in 0..3usize {
            let g1 = entry(1, 1);
            let lineage = [g1];
            let k = key_of(&g1);
            let full: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:x", b"X")];
            let mut w = InspectingWriter::new(&lineage);
            w.permanent_fail.insert(b"room:x".to_vec());
            let _ = w.run(&mut MockIo::default().executable_with(&k, full), pol(pi));
            w.store.data.remove(&pred_wip_marker(&k));
            w.permanent_fail.clear();
            w.revision = 1;
            w.retries.clear();
            let _ = w.run(&mut MockIo::default().executable_with(&k, full), pol(pi));
            assert!(!w.retries.is_empty());
            assert!(w.retries.iter().all(|r| *r), "{:?}", w.retries);
        }
    }

    /// PROBE (gap C): two generations, newest is a reopened rejection with lost
    /// marker and now answers empty / silent. The older generation (data) must NOT
    /// be imported/shadow under the NSW policies.
    #[test]
    fn probe_reopened_newest_rejection_empty_or_silent_does_not_fall_through() {
        for pi in 1..3usize {
            let name = pi;
            for silent in [false, true] {
                let (old, new) = (entry(1, 1), entry(2, 2));
                let lineage = [old, new];
                let (ko, kn) = (key_of(&old), key_of(&new));
                let full: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:x", b"X")];
                let mut w = InspectingWriter::new(&lineage);
                w.permanent_fail.insert(b"room:x".to_vec());
                let mk = |silent_new: bool| {
                    let io = MockIo::default().executable_with(&ko, &[(b"old", b"O")]);
                    if silent_new {
                        io.silent_export(&kn)
                    } else {
                        io.executable_with(&kn, &[])
                    }
                };
                let _ = w.run(
                    &mut MockIo::default()
                        .executable_with(&ko, &[(b"old", b"O")])
                        .executable_with(&kn, full),
                    pol(pi),
                );
                w.store.data.remove(&pred_wip_marker(&kn));
                w.permanent_fail.clear();
                w.revision = 1;
                w.offered.clear();
                let _ = w.run(&mut mk(silent), pol(pi));
                assert!(
                    !w.offered.contains(&b"old".to_vec()),
                    "{name} silent={silent}: older generation was offered {:?}",
                    w.offered
                );
            }
        }
    }

    /// PROBE (gap D): the empty-seal case under every policy.
    #[test]
    fn probe_empty_seal_beside_counted_rejection_all_policies() {
        for pi in 0..3usize {
            let g1 = entry(1, 1);
            let lineage = [g1];
            let k = key_of(&g1);
            let full: &[(&[u8], &[u8])] = &[(b"room:a", b"A"), (b"room:x", b"X")];
            let mut w = InspectingWriter::new(&lineage);
            w.permanent_fail.insert(b"room:x".to_vec());
            let _ = w.run(&mut MockIo::default().executable_with(&k, full), pol(pi));
            w.store.data.remove(&pred_wip_marker(&k));
            w.store
                .set_secret(&pred_done_marker(&k), PRED_DONE_MARKER_VALUE_EMPTY);
            w.permanent_fail.clear();
            w.revision = 1;
            let status = w
                .run(&mut MockIo::default().executable_with(&k, full), pol(pi))
                .status
                .expect("stored");
            assert!(status.is_complete(), "{pi} {status:?}");
            assert_eq!(
                w.store.get_secret(b"room:x").as_deref(),
                Some(&b"X"[..]),
                "{pi}"
            );
        }
    }

    /// #48 under a snapshot policy: the newest generation is a reopened rejection
    /// whose marker was lost and now answers empty. Its kept count says it holds
    /// data, so the walk stops there, and the older generation it superseded is
    /// not imported over it (a rollback).
    #[test]
    fn a_counted_newest_generation_answering_empty_does_not_let_an_older_one_roll_back() {
        for make in [newest as fn() -> SecretSelectionPolicy, r10_cpu] {
            let (g1, g2) = (entry(1, 1), entry(2, 2));
            let lineage = [g1, g2];
            let (k1, k2) = (key_of(&g1), key_of(&g2));
            let mut w = InspectingWriter::new(&lineage);
            w.permanent_fail.insert(b"room:x".to_vec());
            let _ = w.run(
                &mut MockIo::default()
                    .executable_with(&k2, &[(b"room:a", b"A"), (b"room:x", b"X")])
                    .executable_with(&k1, &[(b"room:old", b"O")]),
                make(),
            );
            w.store.data.remove(&pred_wip_marker(&k2));
            w.permanent_fail.clear();
            w.revision = 1;
            let _ = w.run(
                &mut MockIo::default()
                    .executable_with(&k2, &[])
                    .executable_with(&k1, &[(b"room:old", b"O")]),
                make(),
            );
            assert!(w.store.get_secret(b"room:old").is_none());
        }
    }
}
