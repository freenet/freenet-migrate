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
//! * [`crate::begin_migration_journal`] stores it (every predecessor pending)
//!   **before** the app's first migration write, so an interruption at any point
//!   afterwards leaves a pending journal behind.
//! * [`crate::migrate_delegate_secrets_journaled`] runs the ordinary walk,
//!   durably flags a predecessor as *import in progress* before its first item,
//!   and records what each predecessor resolved to.
//! * [`crate::note_app_import_started`] lets an app that writes migrated data
//!   **outside** the walk (River's hand-rolled sweep) raise the same flag before
//!   its own first write.
//! * On every load the app reads it ([`journal_status`]) and re-runs the walk
//!   while it is incomplete. The walk is idempotent (completed predecessors are
//!   skipped by their markers; a retried one re-offers its items to a writer that
//!   must merge), so an extra run is cheap and safe.
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
//! | `NoData` (it answered "nothing"), or `AlreadyMigrated` with an empty marker | [`JournalResolution::NoData`] |
//! | `Incomplete` whose only blemish is permanently rejected items | [`JournalResolution::ImportedWithRejections`], stamped with the writer's [`import_revision`](JournaledSuccessorIo::import_revision) |
//! | `Superseded` behind a resolved, data-bearing newer predecessor, under a `NewestSnapshotWins` policy | [`JournalResolution::SupersededByAuthoritative`] |
//! | `Unresponsive` — silence, a timeout, a transport fault, **or a definitive "not installed"** | stays pending; `attempts + 1` |
//! | `Incomplete` with a retryable failure, a withheld key, or a flush or marker fault | stays pending |
//! | `WriterUnavailable`, or `Superseded` behind an unresolved predecessor or under Union | stays pending |
//!
//! The rules the data-loss argument rests on:
//!
//! * **Absence never resolves.** Neither silence nor a typed "not installed"
//!   ([`crate::ProbeVerdict::NotInstalled`]) is proof a predecessor holds nothing:
//!   freenet-core unregisters a delegate without deleting its secrets, and a
//!   failed WASM read surfaces as the same "not found". So both stay pending. A
//!   "not installed" answer is *recorded* (the pending entry's `absent_streak`)
//!   so an app can decide, as its own policy, to stop re-probing a predecessor
//!   that has answered "not installed" on several separate loads
//!   ([`JournalStatus::pending_all_absent`]). The crate itself never gives up.
//! * **A permanent rejection resolves, and reopens when the writer changes.** A
//!   retry would be refused identically, so leaving it pending would re-run the
//!   whole migration on every load forever. But a later release of the app may
//!   accept the item, so the resolution is stamped with the writer's
//!   [`import_revision`](JournaledSuccessorIo::import_revision): an app that fixes
//!   its import path bumps the revision, and every such predecessor reopens.
//! * **A resolution depends on what it was resolved under.** A
//!   `SupersededByAuthoritative` entry is only right under a snapshot policy;
//!   the journal records the policy family, and switching it reopens those
//!   entries.
//! * **Resolution is otherwise sticky**, and a non-data resolution never
//!   overrides a predecessor already flagged *import in progress*.
//!
//! # Concurrency and failure
//!
//! The journal is one stored value. Every store is a **read-merge-write**: the
//! stored journal is re-read and merged (resolutions stick, the import flag is
//! OR-ed, attempt counts take the maximum) before writing, so a second tab or
//! session cannot erase a flag the first one raised — except inside the window
//! between one session's re-read and its write, which a successor without
//! compare-and-swap cannot close. Every store a walk relies on **fails closed**:
//! if the journal cannot be established, or the import flag cannot be stored
//! before a predecessor's first item, that predecessor is not imported this run.
//! A journal that cannot be read is never overwritten, except a corrupt one,
//! which is replaced by a pessimistic one (every predecessor pending and flagged
//! as possibly partially imported).
//!
//! # What this does not do
//!
//! * It does not cover data the app writes outside the walk *unless* the app
//!   calls [`crate::begin_migration_journal`] first and
//!   [`crate::note_app_import_started`] before each such write, and the walk
//!   imports the same data (so the walk resolving the predecessor means the data is
//!   there). River's sweep and walk read the same predecessor keys.
//! * It does not bind a journal to the successor it is stored in. Store it under
//!   a key the predecessor adapter never offers for import
//!   ([`crate::SecretStoreIo`] uses the reserved [`MIGRATION_JOURNAL_KEY`]).

use std::collections::BTreeMap;
use std::future::Future;

use freenet_stdlib::prelude::{CodeHash, DelegateKey};
use serde::{Deserialize, Serialize};

use crate::delegate_migrate::{SecretSelectionPolicy, SuccessorSecretsIo};
use crate::lineage::DelegateLineageEntry;

/// Version of the stored journal encoding. A journal with a different version
/// reads as [`JournalStatus::Unreadable`] and is never overwritten by a build
/// that cannot read it.
pub const MIGRATION_JOURNAL_VERSION: u8 = 1;

/// Storage key [`crate::SecretStoreIo`] uses for the journal, inside the crate's
/// reserved marker namespace (so it is filtered out of every export and can
/// never be written by an import payload). An app implementing
/// [`JournaledSuccessorIo`] itself chooses its own key, and must keep that key
/// out of what its predecessor adapter offers for import.
pub const MIGRATION_JOURNAL_KEY: &[u8] = b"\0freenet-migrate/v1/journal";

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
    ImportedWithRejections {
        /// How many items were permanently rejected on the resolving run.
        rejected: u32,
        /// The writer's import revision on that run.
        revision: u32,
    },
    /// It was not imported because a newer predecessor, itself resolved and
    /// data-bearing, supplied the authoritative snapshot under a
    /// `NewestSnapshotWins` policy. Reopens if the journal's policy changes.
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

/// One predecessor's durable state in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalState {
    /// Not yet resolved. The walk must run again.
    Pending {
        /// How many journaled walks left it unresolved.
        attempts: u32,
        /// Whether an import from it has started: its items may be **partially**
        /// written to the successor right now. This is the "interrupted import"
        /// signal an app gates destructive actions on.
        data_bearing: bool,
        /// How many consecutive journaled walks found it definitively not
        /// installed on the node ([`crate::ProbeVerdict::NotInstalled`]). Reset by
        /// any other unresolved outcome. Information for the app's own policy;
        /// it never resolves the entry.
        absent_streak: u32,
    },
    /// Resolved.
    Resolved(JournalResolution),
}

impl JournalState {
    fn fresh() -> Self {
        JournalState::Pending {
            attempts: 0,
            data_bearing: false,
            absent_streak: 0,
        }
    }
}

/// One journal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalEntry {
    /// The predecessor's lineage generation.
    pub generation: u32,
    /// Its state.
    pub state: JournalState,
}

/// The policy family a journal's `SupersededByAuthoritative` resolutions were
/// made under.
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
/// something else may no longer hold, so [`journal_status`] reopens it: a
/// `SupersededByAuthoritative` under a different policy family, an
/// `ImportedWithRejections` under an older import revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationJournal {
    entries: BTreeMap<[u8; 32], JournalEntry>,
    /// The policy family the stored resolutions were made under, once a walk has
    /// recorded any.
    policy: Option<PolicyFamily>,
}

/// A stored journal that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalDecodeError {
    /// Written by a build with a different journal encoding version. Never
    /// overwritten by this build.
    UnknownVersion(u8),
    /// Not a journal at all (corrupt, truncated, or an unknown entry state).
    Corrupt(String),
}

#[derive(Serialize, Deserialize)]
struct WireJournal {
    v: u8,
    /// 0 = none recorded, 1 = newest-snapshot, 2 = union.
    policy: u8,
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
    data_bearing: bool,
    absent_streak: u32,
    rejected: u32,
    revision: u32,
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

/// The version byte of a stored journal, read without decoding the rest, so a
/// journal from a different encoding version is recognised as such rather than
/// as corrupt.
#[derive(Deserialize)]
struct WireVersion {
    v: u8,
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

    /// The journal that replaces a corrupt one: every predecessor pending AND
    /// flagged as possibly partially imported, because the corrupt one may have
    /// said so and nothing can tell which.
    pub(crate) fn pessimistic(predecessors: &[DelegateLineageEntry]) -> Self {
        let mut journal = Self::new_pending(predecessors);
        for entry in journal.entries.values_mut() {
            entry.state = JournalState::Pending {
                attempts: 0,
                data_bearing: true,
                absent_streak: 0,
            };
        }
        journal
    }

    /// The state recorded for `predecessor`, if the journal has an entry for it.
    pub fn entry(&self, predecessor: &DelegateKey) -> Option<&JournalEntry> {
        self.entries.get(predecessor.bytes())
    }

    /// Every entry, keyed by predecessor delegate-key bytes.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; 32], &JournalEntry)> {
        self.entries.iter()
    }

    /// The policy family recorded resolutions were made under, if any.
    pub fn policy(&self) -> Option<PolicyFamily> {
        self.policy
    }

    /// The journal's completeness against the lineage `predecessors`, for an app
    /// currently migrating under `binding`.
    ///
    /// A lineage entry the journal has no record of counts as pending, and an
    /// entry for a key no longer in the lineage is ignored, so a journal can never
    /// read complete for a predecessor it never saw. A resolution made under a
    /// different binding is reopened (see [`JournalBinding`]).
    pub fn status(
        &self,
        predecessors: &[DelegateLineageEntry],
        binding: &JournalBinding,
    ) -> JournalStatus {
        let mut pending = Vec::new();
        let mut rejected = 0u32;
        for e in predecessors {
            let state = self.effective_state(&e.delegate_key, binding);
            match state {
                Some(JournalState::Resolved(r)) => {
                    if let JournalResolution::ImportedWithRejections { rejected: n, .. } = r {
                        rejected = rejected.saturating_add(n);
                    }
                }
                Some(JournalState::Pending {
                    attempts,
                    data_bearing,
                    absent_streak,
                }) => pending.push(PendingPredecessor {
                    key: lineage_key(e),
                    generation: e.generation,
                    attempts,
                    data_bearing,
                    absent_streak,
                }),
                None => pending.push(PendingPredecessor {
                    key: lineage_key(e),
                    generation: e.generation,
                    attempts: 0,
                    data_bearing: false,
                    absent_streak: 0,
                }),
            }
        }
        if pending.is_empty() {
            JournalStatus::Complete {
                rejected_items: rejected,
            }
        } else {
            JournalStatus::Incomplete { pending }
        }
    }

    /// The entry's state as it applies under `binding`: a resolution made under a
    /// different policy family or an older import revision reads as pending.
    fn effective_state(&self, key: &[u8; 32], binding: &JournalBinding) -> Option<JournalState> {
        let state = self.entries.get(key)?.state;
        Some(match state {
            JournalState::Resolved(JournalResolution::SupersededByAuthoritative)
                if self.policy != Some(binding.policy) =>
            {
                JournalState::fresh()
            }
            JournalState::Resolved(JournalResolution::ImportedWithRejections {
                revision, ..
            }) if revision < binding.import_revision => JournalState::Pending {
                attempts: 0,
                // Its accepted items are in the successor and its rejected ones are
                // not: the successor holds a partial copy of it.
                data_bearing: true,
                absent_streak: 0,
            },
            other => other,
        })
    }

    /// Reopen every resolution that no longer holds under `binding` (see
    /// [`effective_state`](Self::effective_state)), and record `binding`'s policy.
    pub(crate) fn rebind(&mut self, binding: &JournalBinding) {
        let keys: Vec<[u8; 32]> = self.entries.keys().copied().collect();
        for key in keys {
            if let Some(state) = self.effective_state(&key, binding) {
                if let Some(entry) = self.entries.get_mut(&key) {
                    entry.state = state;
                }
            }
        }
        self.policy = Some(binding.policy);
    }

    /// Encode for storage.
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireJournal {
            v: MIGRATION_JOURNAL_VERSION,
            policy: match self.policy {
                None => 0,
                Some(PolicyFamily::NewestSnapshot) => 1,
                Some(PolicyFamily::Union) => 2,
            },
            entries: self
                .entries
                .iter()
                .map(|(key, e)| {
                    let mut w = WireEntry {
                        key: *key,
                        generation: e.generation,
                        state: 0,
                        attempts: 0,
                        data_bearing: false,
                        absent_streak: 0,
                        rejected: 0,
                        revision: 0,
                    };
                    match e.state {
                        JournalState::Pending {
                            attempts,
                            data_bearing,
                            absent_streak,
                        } => {
                            w.attempts = attempts;
                            w.data_bearing = data_bearing;
                            w.absent_streak = absent_streak;
                        }
                        JournalState::Resolved(JournalResolution::Imported) => w.state = 1,
                        JournalState::Resolved(JournalResolution::NoData) => w.state = 2,
                        JournalState::Resolved(JournalResolution::ImportedWithRejections {
                            rejected,
                            revision,
                        }) => {
                            w.state = 4;
                            w.rejected = rejected;
                            w.revision = revision;
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
        if version.v != MIGRATION_JOURNAL_VERSION {
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
        let policy = match wire.policy {
            0 => None,
            1 => Some(PolicyFamily::NewestSnapshot),
            2 => Some(PolicyFamily::Union),
            other => {
                return Err(JournalDecodeError::Corrupt(format!(
                    "unknown journal policy {other}"
                )))
            }
        };
        let mut journal = Self {
            entries: BTreeMap::new(),
            policy,
        };
        for w in wire.entries {
            let state = match w.state {
                0 => JournalState::Pending {
                    attempts: w.attempts,
                    data_bearing: w.data_bearing,
                    absent_streak: w.absent_streak,
                },
                1 => JournalState::Resolved(JournalResolution::Imported),
                2 => JournalState::Resolved(JournalResolution::NoData),
                4 => JournalState::Resolved(JournalResolution::ImportedWithRejections {
                    rejected: w.rejected,
                    revision: w.revision,
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
            // Duplicate keys merge rather than last-wins, so a duplicated entry can
            // only ever make the journal more conservative.
            let merged = match journal.entries.get(&w.key).copied() {
                Some(existing) => merge_entry(existing, entry, MergeOrder::Peer),
                None => entry,
            };
            journal.entries.insert(w.key, merged);
        }
        Ok(journal)
    }

    /// Flag `predecessor` as having started an import (its items may now be
    /// partially written). Returns whether the entry changed.
    pub(crate) fn mark_data_bearing(&mut self, predecessor: &DelegateKey, generation: u32) -> bool {
        let entry = self
            .entries
            .entry(key_bytes(predecessor))
            .or_insert(JournalEntry {
                generation,
                state: JournalState::fresh(),
            });
        match &mut entry.state {
            JournalState::Pending { data_bearing, .. } if !*data_bearing => {
                *data_bearing = true;
                true
            }
            JournalState::Pending { .. } => false,
            // A resolution that says the data is NOT in the successor (no data,
            // superseded) is contradicted by an import starting: reopen it.
            JournalState::Resolved(r) if !r.is_data_bearing() => {
                entry.state = JournalState::Pending {
                    attempts: 0,
                    data_bearing: true,
                    absent_streak: 0,
                };
                true
            }
            JournalState::Resolved(_) => false,
        }
    }

    /// Record one journaled walk's outcome for `predecessor`.
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
            (_, RunOutcome::Resolved(r)) => JournalEntry {
                generation,
                state: JournalState::Resolved(r),
            },
            (
                JournalState::Pending {
                    attempts,
                    data_bearing,
                    absent_streak,
                },
                RunOutcome::Unresolved { absent },
            ) => JournalEntry {
                generation,
                state: JournalState::Pending {
                    attempts: attempts.saturating_add(1),
                    data_bearing,
                    absent_streak: if absent {
                        absent_streak.saturating_add(1)
                    } else {
                        0
                    },
                },
            },
            (JournalState::Resolved(_), RunOutcome::Unresolved { .. }) => *entry,
        };
        *entry = merge_entry(*entry, ours, MergeOrder::Newer);
    }

    /// Merge a journal another session stored into this one (read-merge-write).
    /// Resolutions stick, the import flag is OR-ed, and counts take the larger
    /// value, so a stale writer can only make the result more conservative.
    pub(crate) fn merge_stored(&mut self, stored: &MigrationJournal) {
        for (key, theirs) in &stored.entries {
            let merged = match self.entries.get(key) {
                Some(ours) => merge_entry(*theirs, *ours, MergeOrder::Newer),
                None => *theirs,
            };
            self.entries.insert(*key, merged);
        }
        if self.policy.is_none() {
            self.policy = stored.policy;
        }
    }
}

/// What one journaled walk established for one predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    Resolved(JournalResolution),
    Unresolved {
        /// The probe answered "not installed".
        absent: bool,
    },
}

/// Whether the second entry is a newer observation of the same predecessor
/// (this session's, over a stored one) or an equal peer (a duplicate wire entry).
#[derive(Clone, Copy)]
enum MergeOrder {
    Newer,
    Peer,
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

/// Merge two states of one predecessor. The rules, in order:
/// * A resolution beats a pending entry — unless the pending entry is flagged
///   *import in progress* and the resolution says the data is not in the
///   successor, a contradiction kept pending.
/// * Between two resolutions, the one recording more of the data in the
///   successor wins ([`completeness_rank`]); on a tie the first stands.
/// * Between two pending entries: the import flag is OR-ed and attempts take the
///   maximum; the absent streak is the newer observation's (reset by a silence),
///   or the smaller for peers.
fn merge_entry(first: JournalEntry, second: JournalEntry, order: MergeOrder) -> JournalEntry {
    use JournalState::{Pending, Resolved};
    let state = match (first.state, second.state) {
        (Resolved(a), Resolved(b)) => {
            if completeness_rank(b) > completeness_rank(a) {
                Resolved(b)
            } else {
                Resolved(a)
            }
        }
        (Resolved(r), p @ Pending { data_bearing, .. })
        | (p @ Pending { data_bearing, .. }, Resolved(r)) => {
            if data_bearing && !r.is_data_bearing() {
                p
            } else {
                Resolved(r)
            }
        }
        (
            Pending {
                attempts: a1,
                data_bearing: d1,
                absent_streak: s1,
            },
            Pending {
                attempts: a2,
                data_bearing: d2,
                absent_streak: s2,
            },
        ) => Pending {
            attempts: a1.max(a2),
            data_bearing: d1 || d2,
            absent_streak: match order {
                MergeOrder::Newer => s2,
                MergeOrder::Peer => s1.min(s2),
            },
        },
    };
    JournalEntry {
        generation: second.generation,
        state,
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
pub struct PendingPredecessor {
    /// The predecessor delegate key.
    pub key: DelegateKey,
    /// Its lineage generation.
    pub generation: u32,
    /// How many journaled walks left it unresolved.
    pub attempts: u32,
    /// Whether an import from it has started, so its items may be partially
    /// written to the successor.
    pub data_bearing: bool,
    /// How many consecutive journaled walks found it definitively not installed.
    pub absent_streak: u32,
}

/// Completeness of a successor's migration, as its stored journal records it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalStatus {
    /// No journal is stored: a journaled migration has never begun on this
    /// successor.
    NotStarted,
    /// A journal is stored but cannot be decoded. Treat as incomplete and as a
    /// possibly interrupted import. [`crate::migrate_delegate_secrets_journaled`]
    /// replaces a corrupt one pessimistically and never touches one from a
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
    },
}

impl JournalStatus {
    /// Whether every predecessor is resolved.
    pub fn is_complete(&self) -> bool {
        matches!(self, JournalStatus::Complete { .. })
    }

    /// Whether an import from some predecessor started and has not been resolved,
    /// so the successor may hold a **partial** copy of its data right now. An app
    /// must not treat the successor's contents as authoritative while this is
    /// true.
    ///
    /// This only knows about imports announced to the journal — the walk's own,
    /// and the app's via [`crate::note_app_import_started`]. An app with writes of
    /// its own that it does not announce must gate on `!is_complete()` instead.
    ///
    /// An unreadable journal says nothing reliable, so it counts as interrupted.
    pub fn interrupted_import(&self) -> bool {
        match self {
            JournalStatus::Unreadable(_) => true,
            JournalStatus::Incomplete { pending } => pending.iter().any(|p| p.data_bearing),
            _ => false,
        }
    }

    /// Whether every unresolved predecessor has answered "not installed" on at
    /// least `min_streak` consecutive journaled walks, and none has an import in
    /// progress. An app MAY use this to stop re-running the migration on every
    /// load; that is a policy decision the crate does not make for it, because
    /// "not installed" is not proof a predecessor holds nothing (see the module
    /// docs). `false` when there is nothing pending.
    pub fn pending_all_absent(&self, min_streak: u32) -> bool {
        match self {
            JournalStatus::Incomplete { pending } => pending
                .iter()
                .all(|p| !p.data_bearing && p.absent_streak >= min_streak.max(1)),
            _ => false,
        }
    }
}

/// The completeness of a successor whose stored journal bytes are `stored`
/// (`None` when nothing is stored), against the lineage `predecessors`, for an
/// app migrating under `binding`. A pure function, for the app's load path.
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

/// A [`SuccessorSecretsIo`] that can also persist the [`MigrationJournal`], for
/// [`crate::begin_migration_journal`], [`crate::note_app_import_started`] and
/// [`crate::migrate_delegate_secrets_journaled`].
///
/// Store the bytes under one fixed key in the successor, and keep that key out of
/// anything the app's predecessor adapter offers for import — a journal copied
/// into the next generation would claim a migration that never ran there.
/// [`crate::SecretStoreIo`] uses [`MIGRATION_JOURNAL_KEY`], which is in the crate's
/// reserved namespace and filtered automatically.
///
/// Like a migration marker, the journal must be **durable when
/// [`store_journal`](Self::store_journal) returns**, not batched with items.
pub trait JournaledSuccessorIo: SuccessorSecretsIo {
    /// The stored journal bytes, or `None` if none is stored. `Err` for a read that
    /// did not establish either (a timeout is not an absence).
    fn load_journal(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>>;

    /// Durably store `journal`, replacing any stored journal.
    fn store_journal(&mut self, journal: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;

    /// A number the app raises whenever its import path starts accepting items
    /// it used to refuse permanently (a decoder fix, say). Predecessors resolved
    /// with permanent rejections under a lower revision reopen, so the fixed
    /// import path gets to retry them. Defaults to 0.
    fn import_revision(&self) -> u32 {
        0
    }
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
    ForeignVersion(u8),
}

impl core::fmt::Display for JournalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JournalError::Successor(e) => f.write_str(e),
            JournalError::ForeignVersion(v) => write!(
                f,
                "stored journal has encoding version {v}; this build does not overwrite it"
            ),
        }
    }
}
