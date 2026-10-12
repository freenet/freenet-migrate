//! Durable, verifiable delegate-migration **completeness** (freenet/freenet-migrate#37).
//!
//! # The problem
//!
//! The delegate walk ([`crate::migrate_delegate_secrets`]) is already durable
//! *within* one predecessor: an in-progress marker is recorded before the first
//! item and upgraded to done only after every item and the flush landed. What no
//! release before this one recorded durably is the question an app has to answer
//! on **every page load**: *has every predecessor been dealt with, or must the
//! walk run again?*
//!
//! Apps answered it in-session — "the probe fan-out went quiet", "no re-save is in
//! flight", "a flag in `localStorage` says done" — and every one of those answers
//! fails in a browser app served by the gateway. The app runs in an iframe whose
//! sandbox omits `allow-same-origin`, so `localStorage` throws; and a tab can die
//! between any two writes. freenet/river#760 measured the result: a tab closed
//! right after the first per-room write left 1 of 4 rooms on every later load,
//! the rest stranded in the predecessor, because the next load saw a non-empty
//! successor and treated it as authoritative. Four review rounds of in-session
//! fixes each found a new hole (freenet/freenet-migrate#37 lists them), because
//! "done" was still a guess.
//!
//! # The fix: a journal the successor stores and the app reads
//!
//! A [`MigrationJournal`] lists every predecessor in the lineage with a durable
//! [`JournalState`]: [`Pending`](JournalState::Pending) until the walk resolves
//! it, [`Resolved`](JournalState::Resolved) after. It lives in the successor
//! (through [`JournaledSuccessorIo`]), so it survives a dead tab and needs no
//! client-side storage.
//!
//! * [`crate::begin_migration_journal`], called on **every** load before
//!   anything migrated is written, stores it (read off the migration markers) the
//!   first time, so an interruption at any point afterwards leaves a pending
//!   journal behind; on later loads it adds lineage entries it has never seen and
//!   reopens a resolution a lost flag left wrong.
//! * [`crate::migrate_delegate_secrets_journaled`] runs the ordinary walk,
//!   durably flags a predecessor as *import in progress* before its first item,
//!   and records what each predecessor resolved to.
//! * [`crate::note_app_import_started`] lets an app that writes migrated data
//!   **outside** the walk (River's hand-rolled sweep) raise the same flag before
//!   its own first write.
//! * On every load the app runs the walk while `begin`'s status is incomplete,
//!   and decides from the status the last call returned. The walk is idempotent
//!   (completed predecessors are skipped by their markers; a retried one
//!   re-offers its items to a writer that must merge), so an extra run is cheap
//!   and safe.
//!
//! Completeness is decided by **arithmetic over durable state** — every lineage
//! entry has a resolved journal entry — never by timing. There is no quiescence
//! window, no in-flight counter and no "first definitive answer" seal.
//!
//! **Why per predecessor and not per item.** Item completeness inside one
//! predecessor already exists: its done marker is recorded only after every item
//! the predecessor exported and the flush landed. A per-item expected set (the
//! shape #37 first sketched) would add an app-specific mapping from predecessor
//! keys to successor keys — River's `rooms_data` blob becomes N `room:` keys —
//! for no extra guarantee. What it would add, a check against a predecessor
//! whose export is itself incomplete, belongs in the app's
//! [`crate::PredecessorSecretsIo::fetch_secrets`], which must return `Err` rather
//! than a partial set.
//!
//! # What resolves a predecessor, and what never does
//!
//! | Walk outcome | Journal |
//! |---|---|
//! | `Imported`, or `AlreadyMigrated` with a data-bearing marker | [`JournalResolution::Imported`] |
//! | `AlreadyMigrated` only through a legacy marker for a NEWER generation (snapshot policies) | [`JournalResolution::SupersededByAuthoritative`] — or an import [`Started`](ImportFlag::Started) if this generation's own marker says one is under way |
//! | `NoData` (it answered "nothing"), or `AlreadyMigrated` with an empty marker | [`JournalResolution::NoData`] — but an empty marker contradicted by a started import, or by a count the journal kept, is not believed: the predecessor is asked again |
//! | `Incomplete` whose only blemish is permanently rejected items | [`JournalResolution::ImportedWithRejections`], stamped with the writer's [`import_revision`](JournaledSuccessorIo::import_revision) |
//! | `Superseded` behind a resolved, data-bearing newer predecessor, under a `NewestSnapshotWins` policy | [`JournalResolution::SupersededByAuthoritative`] |
//! | `Unresponsive` — silence, a timeout, a transport fault, **a definitive "not installed"**, or an empty export from a predecessor an earlier attempt saw data in | stays pending; `attempts + 1` |
//! | `Incomplete` with a retryable failure, a withheld key, or a flush or marker fault | stays pending; `attempts + 1` |
//! | `WriterUnavailable`, or `Superseded` behind an unresolved predecessor or under Union (not examined) | stays pending; attempts unchanged (a `JournalFlag` failure may still record the import as started: the predecessor did hold data) |
//! | `AlreadyMigrated` because the journal already resolved it with its data in the successor (not walked again) | unchanged |
//!
//! The rules the data-loss argument rests on:
//!
//! * **Absence never resolves.** Neither silence nor a typed "not installed"
//!   ([`crate::ProbeVerdict::NotInstalled`]) is proof a predecessor holds nothing:
//!   freenet-core unregisters a delegate without deleting its secrets, and a
//!   failed WASM read surfaces as the same "not found". So both stay pending. A
//!   "not installed" answer is *recorded* (the pending entry's `absent_streak`)
//!   so an app can decide, as its own policy, to probe less often
//!   ([`JournalStatus::pending_all_absent`]). The crate itself never gives up.
//! * **"Nothing" after "something" is not believed.** Once an import from a
//!   predecessor has [`Started`](ImportFlag::Started), or the journal kept a
//!   count of the items an import from it saw, a later answer that it holds
//!   nothing (or fewer items) leaves it pending rather than resolving it: a
//!   frozen predecessor does not lose data, so the short answer is the fault.
//! * **A permanent rejection resolves, and can be reopened.** A retry would be
//!   refused identically, so leaving it pending would re-run the whole
//!   migration on every load forever. The resolution is stamped with the
//!   writer's [`import_revision`](JournaledSuccessorIo::import_revision): an app
//!   that finds and fixes a wrong rejection bumps the revision, and every such
//!   predecessor reopens. The count is reported in [`JournalStatus::Complete`]
//!   and [`JournalStatus::Incomplete`] alike.
//! * **A resolution depends on what it was resolved under.** A
//!   `SupersededByAuthoritative` entry holds only under a `NewestSnapshotWins`
//!   policy; under `UnionAllGenerations` it reads as pending. Both this and the
//!   revision are evaluated against the app's [`JournalBinding`] on every read
//!   and every merge, never stored as journal-wide state a stale copy could
//!   carry back.
//! * **Resolution is otherwise sticky.** Once resolved, an entry only changes
//!   towards more of its data in the successor (`NoData` to `Imported`, say),
//!   with one exception: an import STARTING from a predecessor resolved as not
//!   in the successor (`NoData`, `SupersededByAuthoritative`) reopens it as an
//!   import in progress. (A rejection a higher revision reopened is pending, not
//!   resolved, so a concurrent stale session's `NoData` can still replace it.)
//!
//! # Concurrency and failure
//!
//! The journal is one stored value. Every store is a **read-merge-write**: the
//! stored journal is re-read and merged (the rules are on [`MigrationJournal`])
//! before writing, so a second tab or session cannot erase
//! a flag or a resolution the first one recorded — except inside the window
//! between one session's reads and its write, which a successor without
//! compare-and-swap cannot close. For a walk that window runs from its marker
//! reads to its final store. A stale store there can overwrite another session's
//! import flag, and the stored journal can then read `Complete` over a partial
//! copy. The predecessor's marker still records the import:
//! [`crate::begin_migration_journal`] reopens such a resolution, and the walk
//! restores a flag on any predecessor it reaches, and after it on any whose
//! marker neither it nor the start read (behind a halt, a failed read, a legacy
//! seal, a supersession). So decide from the status those calls return, not
//! from a raw [`journal_status`] read. The same window lets a walk's import
//! flag store bring in another session's completion of that predecessor and
//! still write its items: under a never-clobber writer that rewrites the same
//! data, and brings back only a key deleted inside the window. And it lets
//! [`crate::note_app_import_started`] flag a predecessor that another session
//! made superseded in the meantime, under a snapshot policy: the app's write
//! can then shadow the newer generation's values, and the flag never clears
//! ([`JournalStatus::interrupted_import`] stays true).
//!
//! Every store a walk relies on **fails closed**:
//! if the journal cannot be read or established, or the import flag cannot be
//! stored before a predecessor's first item, that predecessor is not imported
//! this run. A journal from a different encoding version is never overwritten.
//! A corrupt one is rebuilt from the migration markers, which record every
//! import that started (the app's too: [`crate::note_app_import_started`] writes
//! the predecessor's in-progress marker), so nothing it said about a partial copy
//! is lost.
//!
//! # When not to adopt it
//!
//! Do not adopt the journal unless the app's `fetch_secrets` fails loudly (a
//! partial export that returns `Ok` is certified complete), its successor store
//! is durable, its marker store follows the contract on
//! [`crate::SuccessorSecretsIo::migration_marker`], its predecessors are frozen
//! once superseded, and no older build of it walks the same successor. Under a
//! snapshot policy, every predecessor must also have finished its own migration
//! before it became one. The CHANGELOG has the reasons.
//!
//! # What this does not do
//!
//! * It does not cover data the app writes outside the walk *unless* the app
//!   calls [`crate::begin_migration_journal`] first and
//!   [`crate::note_app_import_started`] before each such write, and the walk
//!   imports the same data (so the walk resolving the predecessor means the data is
//!   there). River's sweep and walk read the same predecessor keys.
//! * It does not detect a predecessor whose export is itself partial: that must
//!   be an `Err` from the app's [`crate::PredecessorSecretsIo::fetch_secrets`].
//!   A retry after an interrupted import is held to the count the interrupted
//!   attempt saw (an export with fewer items is not believed, #44), but a first
//!   attempt that is already short is believed, and so is a retry after the
//!   journal was lost, corrupt or overwritten by a stale store: the count lives
//!   only in the journal, and a rebuild from the markers starts it again at 0. An app that enumerates through an index the predecessor itself
//!   reads (and freenet/freenet-core#5857 can make that read come back empty)
//!   must not let an unreadable index become a short list. For a predecessor
//!   already deployed, an index read that failed may look exactly like an
//!   absent index; cross-check it (an index absent while keys it should list
//!   are present is an `Err`).
//! * It cannot tell a predecessor that genuinely holds nothing from one whose
//!   storage the node failed to read **on the first attempt**: freenet-core
//!   reports a failed secret read as "not found" (freenet/freenet-core#5857), so
//!   the export is empty and the predecessor resolves `NoData`. Only once an
//!   attempt has seen data is a later "nothing" refused.
//! * It does not bind a journal to the successor it is stored in. The crate
//!   withholds [`MIGRATION_JOURNAL_KEY`] (its whole namespace) from every walk
//!   and export; an app copying predecessor data itself must skip it too
//!   ([`crate::is_reserved_key`]).

use std::collections::BTreeMap;
use std::future::Future;

use freenet_stdlib::prelude::{CodeHash, DelegateKey};
use serde::{Deserialize, Serialize};

use crate::delegate_migrate::{SecretSelectionPolicy, SuccessorSecretsIo};
use crate::lineage::DelegateLineageEntry;

/// Version of the stored journal encoding. A journal with a different version
/// reads as [`JournalStatus::Unreadable`] and is never overwritten by a build
/// that cannot read it. Bump it for ANY change to the stored form, including an
/// added field: a build that decodes a same-version journal it does not fully
/// understand drops what it does not know when it stores it again.
pub const MIGRATION_JOURNAL_VERSION: u8 = 1;

/// How a predecessor was dealt with. See the module docs for which walk outcome
/// maps to which resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalResolution {
    /// Its secrets were imported (now, or by an earlier run whose completion
    /// marker the walk found).
    Imported,
    /// It executed and answered that it holds nothing.
    NoData,
    /// Its secrets were imported except for items the successor's import path
    /// permanently refuses. Surface the count. Reopens when the writer's
    /// [`import_revision`](JournaledSuccessorIo::import_revision) rises above
    /// `revision`.
    #[non_exhaustive]
    ImportedWithRejections {
        /// How many items were permanently rejected on the resolving run.
        rejected: u32,
        /// The writer's import revision on that run.
        revision: u32,
        /// The most items an attempt that started this import saw the
        /// predecessor export, carried into the pending entry a higher revision
        /// reopens it as (#44).
        items_seen: u32,
    },
    /// It was not imported because a newer predecessor, itself resolved and
    /// data-bearing (or a legacy generation-keyed seal for one), supplied the
    /// authoritative snapshot under a `NewestSnapshotWins` policy. Holds only
    /// while the app migrates under that policy family; under
    /// `UnionAllGenerations` it reads as pending.
    SupersededByAuthoritative,
}

impl JournalResolution {
    /// Whether this resolution means the predecessor's data now lives in the
    /// successor.
    pub fn is_data_bearing(self) -> bool {
        matches!(
            self,
            JournalResolution::Imported | JournalResolution::ImportedWithRejections { .. }
        )
    }
}

/// Whether an import from a pending predecessor may have left a **partial** copy
/// of its data in the successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportFlag {
    /// No import from it is known to have started.
    None,
    /// An import from it started and has not completed: the walk's own, an
    /// earlier plain walk's (its in-progress marker survives), or the app's,
    /// announced with [`crate::note_app_import_started`]. Every one of these is
    /// also recorded in the predecessor's in-progress migration marker, so a
    /// corrupt journal is rebuilt with it.
    ///
    /// Cleared only by a resolution that puts the predecessor's data in the
    /// successor. A predecessor that held data when the import started and
    /// answers "nothing" now is not believed: the walk treats the answer as a
    /// silence, and the entry stays pending. So does one a snapshot policy then
    /// supersedes: the successor still holds part of it, and
    /// [`JournalStatus::interrupted_import`] keeps saying so.
    Started,
}

impl ImportFlag {
    fn max(self, other: Self) -> Self {
        if other == ImportFlag::Started {
            other
        } else {
            self
        }
    }
}

/// One predecessor's durable state in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalState {
    /// Not yet resolved. The walk must run again.
    #[non_exhaustive]
    Pending {
        /// How many journaled walks examined it and left it unresolved.
        attempts: u32,
        /// Whether its items may be **partially** written to the successor right
        /// now.
        import: ImportFlag,
        /// Items permanently rejected by the resolution this entry was reopened
        /// from (a higher [`import_revision`](JournaledSuccessorIo::import_revision)
        /// reopens an [`ImportedWithRejections`](JournalResolution::ImportedWithRejections)),
        /// still not in the successor. `0` otherwise.
        rejected: u32,
        /// How many consecutive journaled walks that examined it found it
        /// definitively not installed on the node
        /// ([`crate::ProbeVerdict::NotInstalled`]). Reset by any other unresolved
        /// outcome. Information for the app's own policy; it never resolves the
        /// entry.
        absent_streak: u32,
        /// The most items an attempt that started an import from it has seen it
        /// export (the walk's own count, or one the app passed to
        /// [`crate::note_app_import_started`]); `0` when none was counted. A frozen
        /// predecessor does not lose items, so a later export with fewer is not
        /// believed: the walk treats it as a silence (#44).
        items_seen: u32,
    },
    /// Resolved.
    Resolved(JournalResolution),
}

impl JournalState {
    fn fresh() -> Self {
        JournalState::Pending {
            attempts: 0,
            import: ImportFlag::None,
            absent_streak: 0,
            rejected: 0,
            items_seen: 0,
        }
    }
}

/// One journal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalEntry {
    /// The predecessor's generation as the last build to write the entry
    /// numbered it. Informational: every decision takes the generation from the
    /// lineage the caller passes.
    pub generation: u32,
    /// Its state.
    pub state: JournalState,
}

/// The selection-policy family a `SupersededByAuthoritative` resolution holds
/// under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyFamily {
    /// `NewestSnapshotWins` or `NewestSnapshotWinsContinuePastUnresponsive`.
    NewestSnapshot,
    /// `UnionAllGenerations`.
    Union,
}

impl PolicyFamily {
    /// The family of `policy`.
    pub fn of(policy: &SecretSelectionPolicy) -> Self {
        match policy {
            SecretSelectionPolicy::NewestSnapshotWins
            | SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(_) => {
                PolicyFamily::NewestSnapshot
            }
            SecretSelectionPolicy::UnionAllGenerations(_) => PolicyFamily::Union,
        }
    }
}

/// What the app currently migrates under. A stored resolution made under
/// something else may no longer hold, so it reads as pending: a
/// `SupersededByAuthoritative` under the Union family, an
/// `ImportedWithRejections` under a higher import revision. Every read and every
/// merge is evaluated against the binding, so a stale stored copy cannot bring
/// such a resolution back. Build it with [`JournalBinding::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalBinding {
    /// The selection policy family.
    pub policy: PolicyFamily,
    /// The writer's [`import_revision`](JournaledSuccessorIo::import_revision).
    pub import_revision: u32,
}

impl JournalBinding {
    /// The binding for `policy` and a writer at `import_revision`.
    pub fn new(policy: &SecretSelectionPolicy, import_revision: u32) -> Self {
        Self {
            policy: PolicyFamily::of(policy),
            import_revision,
        }
    }
}

/// The durable completeness record for one successor. See the module docs.
///
/// Every store merges the stored copy in first, each entry evaluated under the
/// app's [`JournalBinding`]:
///
/// * Between two resolutions, the one recording more of the data in the
///   successor wins (`Imported` over `ImportedWithRejections` over `NoData` and
///   `SupersededByAuthoritative`); between two rejection resolutions, the higher
///   import revision.
/// * A resolution putting the data in the successor beats a pending entry. One
///   that does not beats a pending entry unless an import from it
///   [`Started`](ImportFlag::Started).
/// * Between two pending entries, the import flag is `Started` if either is,
///   attempts and rejection counts take the maximum, and the absent streak is
///   the newer observation's.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationJournal {
    entries: BTreeMap<[u8; 32], JournalEntry>,
}

/// A stored journal that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalDecodeError {
    /// Written by a build with a different journal encoding version. Never
    /// overwritten by this build.
    UnknownVersion(u64),
    /// Not a journal at all (corrupt, truncated, an unknown entry state, or a
    /// predecessor listed twice).
    Corrupt(String),
}

#[derive(Serialize, Deserialize)]
struct WireJournal {
    v: u8,
    entries: Vec<WireEntry>,
}

#[derive(Serialize, Deserialize)]
struct WireEntry {
    #[serde(with = "serde_bytes_32")]
    key: [u8; 32],
    generation: u32,
    /// 0 = pending, 1 = imported, 2 = no data, 4 = imported with rejections,
    /// 5 = superseded by authoritative. (3 is retired and rejected.)
    state: u8,
    attempts: u32,
    /// 0 = none, 1 = started.
    import: u8,
    absent_streak: u32,
    rejected: u32,
    revision: u32,
    /// Pending and imported-with-rejections entries only; absent (0) in a journal
    /// written before #44.
    #[serde(default)]
    items_seen: u32,
}

/// Fixed-size byte strings as CBOR byte strings (not 32-element integer arrays).
mod serde_bytes_32 {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("32 bytes")
            }
            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_bytes(V)
    }
}

/// The version of a stored journal, read without decoding the rest, so a journal
/// from a different encoding version is recognised as such rather than as
/// corrupt. Wider than the `u8` this build writes, so a future version number
/// that does not fit a byte is still recognised.
#[derive(Deserialize)]
struct WireVersion {
    v: u64,
}

impl MigrationJournal {
    /// A journal with every predecessor in `predecessors` pending.
    pub fn new_pending(predecessors: &[DelegateLineageEntry]) -> Self {
        let mut journal = Self::default();
        for e in predecessors {
            journal.entries.insert(
                e.delegate_key,
                JournalEntry {
                    generation: e.generation,
                    state: JournalState::fresh(),
                },
            );
        }
        journal
    }

    /// The state recorded for `predecessor`, if the journal has an entry for it.
    /// This is the stored state; [`status`](Self::status) is what applies under a
    /// binding.
    pub fn entry(&self, predecessor: &DelegateKey) -> Option<&JournalEntry> {
        self.entries.get(predecessor.bytes())
    }

    /// Every entry, keyed by predecessor delegate-key bytes.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; 32], &JournalEntry)> {
        self.entries.iter()
    }

    /// The journal's completeness against the lineage `predecessors`, for an app
    /// currently migrating under `binding`.
    ///
    /// A lineage entry the journal has no record of counts as pending, and an
    /// entry for a key no longer in the lineage is ignored, so a journal can never
    /// read complete for a predecessor it never saw. A resolution that does not
    /// hold under `binding` reads as pending (see [`JournalBinding`]).
    pub fn status(
        &self,
        predecessors: &[DelegateLineageEntry],
        binding: &JournalBinding,
    ) -> JournalStatus {
        let mut pending = Vec::new();
        let mut rejected = 0u32;
        for e in predecessors {
            match self.effective_state(&e.delegate_key, binding) {
                Some(JournalState::Resolved(r)) => {
                    if let JournalResolution::ImportedWithRejections { rejected: n, .. } = r {
                        rejected = rejected.saturating_add(n);
                    }
                }
                Some(JournalState::Pending {
                    attempts,
                    import,
                    absent_streak,
                    rejected: n,
                    items_seen,
                }) => {
                    rejected = rejected.saturating_add(n);
                    pending.push(PendingPredecessor {
                        key: lineage_key(e),
                        generation: e.generation,
                        attempts,
                        import,
                        absent_streak,
                        items_seen,
                    });
                }
                None => pending.push(PendingPredecessor {
                    key: lineage_key(e),
                    generation: e.generation,
                    attempts: 0,
                    import: ImportFlag::None,
                    absent_streak: 0,
                    items_seen: 0,
                }),
            }
        }
        if pending.is_empty() {
            JournalStatus::Complete {
                rejected_items: rejected,
            }
        } else {
            JournalStatus::Incomplete {
                pending,
                rejected_items: rejected,
            }
        }
    }

    /// The entry's state as it applies under `binding`.
    fn effective_state(&self, key: &[u8; 32], binding: &JournalBinding) -> Option<JournalState> {
        self.entries.get(key).map(|e| effective(e.state, binding))
    }

    /// Replace every entry with its state under `binding`: the working copy a
    /// journaled walk records into.
    pub(crate) fn rebind(&mut self, binding: &JournalBinding) {
        for entry in self.entries.values_mut() {
            entry.state = effective(entry.state, binding);
        }
    }

    /// Encode for storage.
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireJournal {
            v: MIGRATION_JOURNAL_VERSION,
            entries: self
                .entries
                .iter()
                .map(|(key, e)| {
                    let mut w = WireEntry {
                        key: *key,
                        generation: e.generation,
                        state: 0,
                        attempts: 0,
                        import: 0,
                        absent_streak: 0,
                        rejected: 0,
                        revision: 0,
                        items_seen: 0,
                    };
                    match e.state {
                        JournalState::Pending {
                            attempts,
                            import,
                            absent_streak,
                            rejected,
                            items_seen,
                        } => {
                            w.items_seen = items_seen;
                            w.attempts = attempts;
                            w.import = u8::from(import == ImportFlag::Started);
                            w.absent_streak = absent_streak;
                            w.rejected = rejected;
                        }
                        JournalState::Resolved(JournalResolution::Imported) => w.state = 1,
                        JournalState::Resolved(JournalResolution::NoData) => w.state = 2,
                        JournalState::Resolved(JournalResolution::ImportedWithRejections {
                            rejected,
                            revision,
                            items_seen,
                        }) => {
                            w.state = 4;
                            w.rejected = rejected;
                            w.revision = revision;
                            w.items_seen = items_seen;
                        }
                        JournalState::Resolved(JournalResolution::SupersededByAuthoritative) => {
                            w.state = 5
                        }
                    }
                    w
                })
                .collect(),
        };
        let mut out = Vec::new();
        ciborium::ser::into_writer(&wire, &mut out)
            .expect("serializing a journal into a Vec cannot fail");
        out
    }

    /// Decode a stored journal.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalDecodeError> {
        // The version first, so a different encoding version is distinguishable
        // from corruption (only the latter may ever be overwritten).
        let version: WireVersion = ciborium::de::from_reader(bytes)
            .map_err(|e| JournalDecodeError::Corrupt(format!("{e}")))?;
        if version.v != u64::from(MIGRATION_JOURNAL_VERSION) {
            return Err(JournalDecodeError::UnknownVersion(version.v));
        }
        let mut reader = bytes;
        let wire: WireJournal = ciborium::de::from_reader(&mut reader)
            .map_err(|e| JournalDecodeError::Corrupt(format!("{e}")))?;
        if !reader.is_empty() {
            return Err(JournalDecodeError::Corrupt(format!(
                "{} trailing byte(s) after the journal",
                reader.len()
            )));
        }
        let mut journal = Self::default();
        for w in wire.entries {
            let state = match w.state {
                0 => JournalState::Pending {
                    attempts: w.attempts,
                    import: match w.import {
                        0 => ImportFlag::None,
                        1 => ImportFlag::Started,
                        other => {
                            return Err(JournalDecodeError::Corrupt(format!(
                                "unknown import flag {other}"
                            )))
                        }
                    },
                    absent_streak: w.absent_streak,
                    rejected: w.rejected,
                    items_seen: w.items_seen,
                },
                1 => JournalState::Resolved(JournalResolution::Imported),
                2 => JournalState::Resolved(JournalResolution::NoData),
                4 => JournalState::Resolved(JournalResolution::ImportedWithRejections {
                    rejected: w.rejected,
                    revision: w.revision,
                    items_seen: w.items_seen,
                }),
                5 => JournalState::Resolved(JournalResolution::SupersededByAuthoritative),
                other => {
                    return Err(JournalDecodeError::Corrupt(format!(
                        "unknown journal entry state {other}"
                    )))
                }
            };
            let entry = JournalEntry {
                generation: w.generation,
                state,
            };
            // The encoder writes each predecessor once. Two entries for one key
            // mean the bytes are not this crate's: which of them to believe is
            // unknowable, so the whole journal is corrupt.
            if journal.entries.insert(w.key, entry).is_some() {
                return Err(JournalDecodeError::Corrupt(
                    "a predecessor is listed twice".to_string(),
                ));
            }
        }
        Ok(journal)
    }

    /// Flag `predecessor` as having an import [`Started`](ImportFlag::Started)
    /// (its items may now be partially written). A resolution saying its data is
    /// not in the successor is contradicted by that, and reopens. Returns whether
    /// the entry changed.
    pub(crate) fn mark_import_started(
        &mut self,
        predecessor: &DelegateKey,
        generation: u32,
    ) -> bool {
        let entry = self
            .entries
            .entry(key_bytes(predecessor))
            .or_insert(JournalEntry {
                generation,
                state: JournalState::fresh(),
            });
        match &mut entry.state {
            JournalState::Pending { import, .. } if *import != ImportFlag::Started => {
                *import = ImportFlag::Started;
                true
            }
            JournalState::Pending { .. } => false,
            JournalState::Resolved(r) if !r.is_data_bearing() => {
                entry.state = JournalState::Pending {
                    attempts: 0,
                    import: ImportFlag::Started,
                    absent_streak: 0,
                    rejected: 0,
                    items_seen: 0,
                };
                true
            }
            JournalState::Resolved(_) => false,
        }
    }

    /// The most items an attempt that started an import from `predecessor` has
    /// seen it export, as this journal records it (`0` when none was counted, or
    /// it is not pending).
    pub(crate) fn items_seen(&self, predecessor: &DelegateKey) -> u32 {
        match self.entry(predecessor).map(|e| e.state) {
            Some(JournalState::Pending { items_seen, .. }) => items_seen,
            _ => 0,
        }
    }

    /// Raise `predecessor`'s [`items_seen`](JournalState::Pending::items_seen) to
    /// `items` on a pending entry whose import has started. Whether it changed.
    pub(crate) fn note_items_seen(&mut self, predecessor: &DelegateKey, items: u32) -> bool {
        match self
            .entries
            .get_mut(&key_bytes(predecessor))
            .map(|e| &mut e.state)
        {
            Some(JournalState::Pending {
                import: ImportFlag::Started,
                items_seen,
                ..
            }) if *items_seen < items => {
                *items_seen = items;
                true
            }
            _ => false,
        }
    }

    /// Record one journaled walk's outcome for `predecessor`, on a journal already
    /// [`rebind`](Self::rebind)-ed to the run's binding.
    pub(crate) fn record(
        &mut self,
        predecessor: &DelegateKey,
        generation: u32,
        outcome: RunOutcome,
    ) {
        let entry = self
            .entries
            .entry(key_bytes(predecessor))
            .or_insert(JournalEntry {
                generation,
                state: JournalState::fresh(),
            });
        let ours = match (entry.state, outcome) {
            // An import with rejections keeps the count its import saw (a
            // resolution already stored keeps its own through the merge).
            (
                JournalState::Pending { items_seen, .. },
                RunOutcome::Resolved(JournalResolution::ImportedWithRejections {
                    rejected,
                    revision,
                    items_seen: resolved_seen,
                }),
            ) => JournalState::Resolved(JournalResolution::ImportedWithRejections {
                rejected,
                revision,
                items_seen: items_seen.max(resolved_seen),
            }),
            (_, RunOutcome::Resolved(r)) => JournalState::Resolved(r),
            (
                JournalState::Pending {
                    attempts,
                    import,
                    absent_streak,
                    rejected,
                    items_seen,
                },
                RunOutcome::Unresolved { absent },
            ) => JournalState::Pending {
                attempts: attempts.saturating_add(1),
                import,
                absent_streak: if absent {
                    absent_streak.saturating_add(1)
                } else {
                    0
                },
                rejected,
                items_seen,
            },
            (current, _) => current,
        };
        entry.generation = generation;
        entry.state = merge_states(entry.state, ours);
    }

    /// Merge the journal currently stored into this one (read-merge-write), so a
    /// concurrent session's flags and resolutions survive this store.
    ///
    /// With a `binding`, both sides are first evaluated under it, so a resolution
    /// that no longer holds cannot win the merge. Without one (a caller that does
    /// not know the policy), states merge as stored.
    pub(crate) fn merge_stored(
        &mut self,
        stored: &MigrationJournal,
        binding: Option<&JournalBinding>,
    ) {
        let eval = |s: JournalState| match binding {
            Some(b) => effective(s, b),
            None => s,
        };
        for (key, theirs) in &stored.entries {
            let merged = match self.entries.get(key) {
                Some(ours) => JournalEntry {
                    generation: ours.generation,
                    state: merge_states(eval(theirs.state), eval(ours.state)),
                },
                None => JournalEntry {
                    generation: theirs.generation,
                    state: eval(theirs.state),
                },
            };
            self.entries.insert(*key, merged);
        }
    }
}

/// `state` as it applies under `binding`.
fn effective(state: JournalState, binding: &JournalBinding) -> JournalState {
    match state {
        JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
            if binding.policy != PolicyFamily::NewestSnapshot =>
        {
            JournalState::fresh()
        }
        // Reopened so the fixed import path retries the rejected items. The rest of
        // its data is already in the successor, so the journal flags no partial
        // import; the rejected items are still missing, so their count carries
        // over. (Its in-progress marker survives, so once such an entry resolves
        // without its data, `begin` reads that marker as an import under way.)
        JournalState::Resolved(JournalResolution::ImportedWithRejections {
            revision,
            rejected,
            items_seen,
        }) if revision < binding.import_revision => JournalState::Pending {
            attempts: 0,
            import: ImportFlag::None,
            absent_streak: 0,
            rejected,
            items_seen,
        },
        other => other,
    }
}

/// What one journaled walk established for one predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    /// Resolved.
    Resolved(JournalResolution),
    /// Examined and not resolved.
    Unresolved {
        /// The probe answered "not installed".
        absent: bool,
    },
    /// Not examined (behind a halt). Counts as no attempt.
    Unexamined,
}

/// How much of a predecessor's data a resolution says reached the successor:
/// none, all but permanently rejected items, or all of it.
fn completeness_rank(r: JournalResolution) -> u8 {
    match r {
        JournalResolution::NoData | JournalResolution::SupersededByAuthoritative => 0,
        JournalResolution::ImportedWithRejections { .. } => 1,
        JournalResolution::Imported => 2,
    }
}

/// Merge two states of one predecessor, `newer` being the more recent
/// observation. The rules:
/// * Between two resolutions, the one recording more of the data in the
///   successor wins ([`completeness_rank`]); between two rejection resolutions,
///   the higher import revision; otherwise the older stands.
/// * A resolution that puts the data in the successor beats a pending entry. One
///   that does not (`NoData`, `SupersededByAuthoritative`) beats a pending entry
///   unless an import from it [`Started`](ImportFlag::Started): data was seen, so
///   "nothing" is not believed and the entry stays pending.
/// * Between two pending entries: the import flag is `Started` if either is,
///   attempts and rejection counts take the maximum, and the absent streak the
///   newer observation's (a silence resets it).
fn merge_states(older: JournalState, newer: JournalState) -> JournalState {
    use JournalState::{Pending, Resolved};
    match (older, newer) {
        (Resolved(a), Resolved(b)) => match (a, b) {
            (
                JournalResolution::ImportedWithRejections {
                    revision: ra,
                    items_seen: ia,
                    ..
                },
                JournalResolution::ImportedWithRejections {
                    revision: rb,
                    items_seen: ib,
                    ..
                },
            ) => {
                // The higher revision wins; the count only rises (#44).
                let JournalResolution::ImportedWithRejections {
                    rejected, revision, ..
                } = (if rb >= ra { b } else { a })
                else {
                    unreachable!()
                };
                Resolved(JournalResolution::ImportedWithRejections {
                    rejected,
                    revision,
                    items_seen: ia.max(ib),
                })
            }
            _ if completeness_rank(b) > completeness_rank(a) => Resolved(b),
            _ => Resolved(a),
        },
        (
            Resolved(r),
            p @ Pending {
                import,
                items_seen: seen,
                ..
            },
        )
        | (
            p @ Pending {
                import,
                items_seen: seen,
                ..
            },
            Resolved(r),
        ) => {
            if !r.is_data_bearing() && import == ImportFlag::Started {
                p
            } else if let JournalResolution::ImportedWithRejections {
                rejected,
                revision,
                items_seen,
            } = r
            {
                // The count only rises: a pending attempt may have seen more.
                Resolved(JournalResolution::ImportedWithRejections {
                    rejected,
                    revision,
                    items_seen: items_seen.max(seen),
                })
            } else {
                Resolved(r)
            }
        }
        (
            Pending {
                attempts: a1,
                import: f1,
                rejected: r1,
                items_seen: i1,
                ..
            },
            Pending {
                attempts: a2,
                import: f2,
                absent_streak,
                rejected: r2,
                items_seen: i2,
            },
        ) => Pending {
            attempts: a1.max(a2),
            import: f1.max(f2),
            absent_streak,
            rejected: r1.max(r2),
            items_seen: i1.max(i2),
        },
    }
}

/// A delegate key's 32 bytes.
pub(crate) fn key_bytes(key: &DelegateKey) -> [u8; 32] {
    key.bytes()
        .try_into()
        .expect("a DelegateKey is always 32 bytes")
}

fn lineage_key(e: &DelegateLineageEntry) -> DelegateKey {
    DelegateKey::new(e.delegate_key, CodeHash::new(e.code_hash))
}

/// A predecessor the journal does not yet consider resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PendingPredecessor {
    /// The predecessor delegate key.
    pub key: DelegateKey,
    /// Its lineage generation.
    pub generation: u32,
    /// How many journaled walks examined it and left it unresolved.
    pub attempts: u32,
    /// Whether its items may be partially written to the successor.
    pub import: ImportFlag,
    /// How many consecutive journaled walks that examined it found it
    /// definitively not installed.
    pub absent_streak: u32,
    /// The most items an attempt that started an import from it has seen it
    /// export (`0` when none was counted).
    pub items_seen: u32,
}

/// Completeness of a successor's migration, as its stored journal records it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalStatus {
    /// No journal is stored: a journaled migration has never begun on this
    /// successor. An earlier plain walk may still have left a partial copy:
    /// [`crate::begin_migration_journal`] returns the status that accounts for it.
    NotStarted,
    /// A journal is stored but cannot be decoded. Treat as incomplete and as a
    /// possibly interrupted import. [`crate::migrate_delegate_secrets_journaled`]
    /// rebuilds a corrupt one from the migration markers and never touches one from a
    /// different encoding version.
    Unreadable(JournalDecodeError),
    /// Every predecessor in the lineage is resolved. There is nothing to probe.
    Complete {
        /// Items the successor's import path permanently refused across all
        /// predecessors. Non-zero means data the user had did NOT migrate:
        /// surface it.
        rejected_items: u32,
    },
    /// At least one predecessor is unresolved. Re-run the migration.
    Incomplete {
        /// The unresolved predecessors, in lineage order.
        pending: Vec<PendingPredecessor>,
        /// Items the successor's import path permanently refused, as last
        /// recorded, including those of predecessors a higher import revision
        /// reopened that have not been re-imported yet. Non-zero means data the
        /// user had is not in the successor.
        rejected_items: u32,
    },
}

impl JournalStatus {
    /// Whether every predecessor is resolved.
    pub fn is_complete(&self) -> bool {
        matches!(self, JournalStatus::Complete { .. })
    }

    /// Items the successor's import path permanently refused, as last recorded.
    /// `0` when nothing is known (not started, unreadable).
    pub fn rejected_items(&self) -> u32 {
        match self {
            JournalStatus::Complete { rejected_items }
            | JournalStatus::Incomplete { rejected_items, .. } => *rejected_items,
            _ => 0,
        }
    }

    /// Whether the successor may hold a **partial** copy of some predecessor's
    /// data right now: an import from it [`Started`](ImportFlag::Started) and has
    /// not been resolved. While this is true, do not treat the successor's
    /// contents as everything the user had.
    ///
    /// Use this, not `!is_complete()`, to gate such decisions: a predecessor
    /// that is simply not installed on this node keeps the journal incomplete
    /// indefinitely without anything being partially written. It only knows about
    /// imports announced to the journal — the walk's own, and the app's via
    /// [`crate::note_app_import_started`].
    ///
    /// An unreadable journal says nothing reliable, so it counts as interrupted.
    pub fn interrupted_import(&self) -> bool {
        match self {
            JournalStatus::Unreadable(_) => true,
            JournalStatus::Incomplete { pending, .. } => {
                pending.iter().any(|p| p.import == ImportFlag::Started)
            }
            _ => false,
        }
    }

    /// Whether every unresolved predecessor answered "not installed" on at least
    /// `min_streak` (at least 1) consecutive journaled walks that examined it, and
    /// none has an import [`Started`](ImportFlag::Started). `false` when nothing
    /// is pending.
    ///
    /// An app MAY use this to run the migration less often than every load. It
    /// is not a seal, and the crate never treats it as one: "not installed" is
    /// not proof a predecessor holds nothing (see the module docs), and the
    /// streak counts walks, not time. So keep re-running it on some cadence, and
    /// at least whenever the node may have changed. Under plain
    /// `NewestSnapshotWins` an absent newest predecessor halts the walk, the older
    /// ones are never examined, and this stays `false`; each such walk then costs
    /// one probe.
    ///
    /// On a load that skips the walk, the status left is `begin`'s, and `begin`
    /// reads no pending predecessor's marker: a flag lost in the no-compare-and-
    /// swap window on such a predecessor (one that went absent mid-import) is not
    /// seen until the walk next runs.
    pub fn pending_all_absent(&self, min_streak: u32) -> bool {
        match self {
            JournalStatus::Incomplete { pending, .. } => pending
                .iter()
                .all(|p| p.import != ImportFlag::Started && p.absent_streak >= min_streak.max(1)),
            _ => false,
        }
    }
}

/// The completeness of a successor whose stored journal bytes are `stored`
/// (`None` when nothing is stored), against the lineage `predecessors`, for an
/// app migrating under `binding`. A pure function: it reads no markers, so it
/// cannot see a flag another session's stale store overwrote (see the
/// concurrency section of the module docs). Gate on the status
/// [`crate::begin_migration_journal`] or the walk returned, not on this.
pub fn journal_status(
    stored: Option<&[u8]>,
    predecessors: &[DelegateLineageEntry],
    binding: &JournalBinding,
) -> JournalStatus {
    match stored {
        None => JournalStatus::NotStarted,
        Some(bytes) => match MigrationJournal::decode(bytes) {
            Ok(journal) => journal.status(predecessors, binding),
            Err(e) => JournalStatus::Unreadable(e),
        },
    }
}

/// The key to store the journal under. It is in a namespace the crate reserves
/// (`\0freenet-migrate-journal/`) but a node does not: a node refuses any key
/// in the migration-marker namespace (`\0freenet-migrate/`) that is not a
/// marker. Every key in the journal namespace is withheld from every walk (the
/// plain one included) and from [`crate::handle_export_request`], so a
/// predecessor's journal is never imported, nor counted as its data.
pub const MIGRATION_JOURNAL_KEY: &[u8] = b"\0freenet-migrate-journal/v1";

/// A [`SuccessorSecretsIo`] that can also persist the [`MigrationJournal`], for
/// [`crate::begin_migration_journal`], [`crate::note_app_import_started`] and
/// [`crate::migrate_delegate_secrets_journaled`].
///
/// Store the bytes under [`MIGRATION_JOURNAL_KEY`] in the successor's secrets.
/// The crate withholds it from every walk and export, so a predecessor's
/// journal is never imported over this one nor counted as its data. (An app
/// that stores it anywhere else reports that key from
/// [`journal_key`](Self::journal_key), which only the journaled walk withholds;
/// a plain walk would then count a predecessor's journal as its data.) Keep it
/// out of any copying the app does itself, such as a hand-rolled sweep.
///
/// Like a migration marker, the journal must be **durable when
/// [`store_journal`](Self::store_journal) returns**, not batched with items.
///
/// Within one session, drive the journal operations
/// ([`crate::begin_migration_journal`], [`crate::note_app_import_started`],
/// [`crate::migrate_delegate_secrets_journaled`]) one at a time. Each is a
/// read-merge-write of the whole journal, which protects against another session
/// but not against an interleaving inside this one, and a transport that
/// correlates replies by key may deliver one call's reply to another.
pub trait JournaledSuccessorIo: SuccessorSecretsIo {
    /// The stored journal bytes, or `None` if none is stored. `Err` for a read that
    /// did not establish either: a timeout or an empty reply is not an absence,
    /// and answering `None` for one makes a later store start the journal afresh.
    fn load_journal(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>>;

    /// Durably store `journal`, replacing any stored journal.
    fn store_journal(&mut self, journal: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;

    /// The secret key the journal is stored under. The journaled walk never
    /// offers a predecessor's item with this key (or any key in the crate's
    /// journal namespace) to the writer. Defaults to [`MIGRATION_JOURNAL_KEY`];
    /// override it only if the journal is stored under another key.
    fn journal_key(&self) -> &[u8] {
        MIGRATION_JOURNAL_KEY
    }

    /// A number the app raises when it finds that its import path refused items
    /// permanently that it should have accepted (a decoder bug, say) and has
    /// fixed it. Predecessors resolved with permanent rejections under a lower
    /// revision reopen, so the fixed import path gets to retry them. Defaults
    /// to 0.
    ///
    /// This is a repair valve for a wrong [`crate::RetryAdvice::Permanent`]
    /// verdict, not a license to return `Permanent` for "this version cannot
    /// handle it" (see its docs): under a never-clobber writer, an older
    /// generation's copy of a rejected key may already have landed and will
    /// decline the newer value when it is retried. Only rejection resolutions
    /// reopen on a revision bump (a `NoData` entry reopens only when an import
    /// from it starts; `Imported` is final).
    fn import_revision(&self) -> u32 {
        0
    }
}

/// What [`crate::note_app_import_started`] did. Decide the write from it; treat a
/// variant this build does not know as "do not write".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "decide whether to write the predecessor's data from this"]
pub enum AppImport {
    /// The import is flagged, in the journal and as the predecessor's in-progress
    /// marker: write the data.
    Flagged,
    /// Its import already completed (its `Done` marker records data, or the
    /// journal resolves it with data, which an import with rejections at the
    /// current revision is): nothing was recorded, and the walk will not offer it
    /// again (until a higher import revision reopens a rejection). As far as the
    /// crate knows its data is in the successor, but that can be partial, or
    /// missing altogether: a short first export, a write an old tab made to it
    /// during a rollout, the items an import path rejected, or a legacy
    /// generation-keyed seal that never covered this data. Writing it again
    /// (unflagged) fills such a gap, and also brings back any key the user deleted
    /// since. Skipping it leaves the gap for good, and no status reports it
    /// (except rejected items, which `rejected_items()` counts and a higher
    /// import revision reopens). So an
    /// app whose merge cannot resurrect a deleted key (ranked tombstones, say)
    /// writes it again; an app that can tolerate a resurrected key should too; any
    /// other skips it, and should at least log that it did. (Under the
    /// continue-past snapshot policy a write here can also land ahead of a newer
    /// generation that has not answered yet, as the walk's own can.)
    AlreadyImported,
}

/// Why a journal operation could not proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalError {
    /// The successor could not read or store the journal (the app's error,
    /// stringified).
    Successor(String),
    /// The stored journal was written by a build with a different journal encoding
    /// version. This build never overwrites it.
    ForeignVersion(u64),
    /// [`crate::note_app_import_started`] was asked to flag a predecessor the app
    /// must not write from now: one not in the lineage the app passed, one a newer
    /// generation's data supersedes under a snapshot policy, or, under plain
    /// `NewestSnapshotWins`, one behind a newer generation that has not answered
    /// that it holds nothing (that one clears once it does, and never if it never
    /// does). Skip it on this call; the reason is in the string.
    NotImportable(String),
}

impl std::error::Error for JournalError {}

impl core::fmt::Display for JournalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JournalError::Successor(e) => f.write_str(e),
            JournalError::ForeignVersion(v) => write!(
                f,
                "stored journal has encoding version {v}; this build does not overwrite it"
            ),
            JournalError::NotImportable(why) => write!(f, "not importable: {why}"),
        }
    }
}
