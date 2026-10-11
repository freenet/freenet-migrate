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
//! * [`crate::begin_migration_journal`] writes it (every predecessor pending)
//!   **before** the app's first migration write, so an interruption at any point
//!   afterwards leaves a pending journal behind.
//! * [`crate::migrate_delegate_secrets_journaled`] runs the ordinary walk and
//!   records what each predecessor resolved to.
//! * On every load the app reads it ([`journal_status`]) and re-runs the walk
//!   while it is incomplete. The walk is idempotent (done predecessors are
//!   skipped, retried ones re-offer items to a writer that must merge), so an
//!   extra run is cheap and safe.
//! * Once every predecessor is resolved the journal reads
//!   [`JournalStatus::Complete`], durably, and the app need never probe the
//!   predecessors again on that successor.
//!
//! Completeness is decided by **arithmetic over durable state** — every lineage
//! entry has a resolved journal entry — never by timing. There is no quiescence
//! window, no in-flight counter and no "first definitive answer" seal, so the
//! failure modes those produced have nothing to act on.
//!
//! # What resolves a predecessor, and what never does
//!
//! | Walk outcome | Journal |
//! |---|---|
//! | `Imported` / `AlreadyMigrated` | [`JournalResolution::Imported`] / [`JournalResolution::NoData`] |
//! | `NoData` (answered "nothing") | [`JournalResolution::NoData`] |
//! | the probe said **not installed** ([`crate::ProbeVerdict::NotInstalled`]) | [`JournalResolution::NotInstalled`] |
//! | `Incomplete` whose only blemish is permanently rejected items | [`JournalResolution::ImportedWithRejections`] |
//! | `Superseded` behind a resolved, data-bearing newer predecessor | [`JournalResolution::SupersededByAuthoritative`] |
//! | `Unresponsive` (silence, timeout, transport fault) | stays pending, `attempts + 1` |
//! | `Incomplete` with a retryable failure, a withheld key or a flush/marker fault | stays pending |
//! | `WriterUnavailable`, or `Superseded` behind an unresolved predecessor | stays pending |
//!
//! Three rules carry the data-loss argument:
//!
//! * **Silence is never resolution.** A predecessor that timed out is retried on
//!   the next load, as many times as it takes; [`JournalState::Pending`] counts
//!   the attempts so an app can surface a long-unreachable generation, but the
//!   crate never gives up on it by itself.
//! * **Only a definitive "not installed" resolves an absent predecessor.** An app
//!   opts in by implementing [`crate::PredecessorSecretsIo::probe_verdict`]; the
//!   default maps the old boolean probe, which cannot say "not installed", so an
//!   app that does not opt in keeps every absent predecessor pending.
//! * **A permanently rejected item resolves, it does not loop.** The rejection is
//!   counted in [`JournalResolution::ImportedWithRejections`] for the app to surface. A
//!   retry would be refused identically (that is what
//!   [`crate::RetryAdvice::Permanent`] asserts), so leaving it pending would re-run
//!   the whole migration on every load forever.
//!
//! JournalResolution is **sticky**: a later run never turns a resolved entry back into a
//! pending one. That is what makes `Complete` a seal. The one upgrade allowed is
//! towards *more* data: a run that imports from a predecessor records it as
//! imported whatever it said before.
//!
//! # What this does not do
//!
//! It does not make an interrupted *app* write safe by itself. An app that writes
//! migrated data outside the walk (River's hand-rolled sweep) must call
//! [`crate::begin_migration_journal`] before that write, and must re-run the walk
//! — whose writer merges, never clobbers — while the journal is incomplete. The
//! journal is what tells the app a re-run is owed; the writer's merge is what makes
//! the re-run safe over data the user changed in between.

use std::collections::BTreeMap;
use std::future::Future;

use freenet_stdlib::prelude::{CodeHash, DelegateKey};
use serde::{Deserialize, Serialize};

use crate::delegate_migrate::SuccessorSecretsIo;
use crate::lineage::DelegateLineageEntry;

/// Version of the stored journal encoding. Bumped only on an incompatible change;
/// a journal with a version this build does not know reads as
/// [`JournalStatus::Unreadable`], which an app treats as incomplete.
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
    /// The app's probe answered, definitively, that this predecessor is not
    /// installed on the node (see [`crate::ProbeVerdict::NotInstalled`]).
    NotInstalled,
    /// Its secrets were imported except for items the successor's import path
    /// permanently refuses. Surface the count: those items will never migrate.
    ImportedWithRejections {
        /// How many items were permanently rejected on the resolving run.
        rejected: u32,
    },
    /// It was not imported because a newer predecessor, itself resolved and
    /// data-bearing, supplied the authoritative snapshot under a
    /// `NewestSnapshotWins` policy.
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
        /// How many journaled walks have tried and failed to resolve it.
        attempts: u32,
        /// Whether a walk has already started importing data from it: its items
        /// may be **partially** written to the successor right now. This is the
        /// "interrupted import" signal an app gates destructive actions on.
        data_bearing: bool,
    },
    /// Resolved; never revisited.
    Resolved(JournalResolution),
}

impl JournalState {
    fn fresh() -> Self {
        JournalState::Pending {
            attempts: 0,
            data_bearing: false,
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

/// The durable completeness record for one successor. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationJournal {
    entries: BTreeMap<[u8; 32], JournalEntry>,
}

/// A stored journal that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalDecodeError(pub String);

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
    /// 0 = pending, 1..=5 = resolved (see `JournalResolution`).
    state: u8,
    attempts: u32,
    data_bearing: bool,
    rejected: u32,
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
    pub fn entry(&self, predecessor: &DelegateKey) -> Option<&JournalEntry> {
        self.entries.get(predecessor.bytes())
    }

    /// Every entry, keyed by predecessor delegate-key bytes.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; 32], &JournalEntry)> {
        self.entries.iter()
    }

    /// The journal's completeness against the lineage `predecessors`.
    ///
    /// A lineage entry the journal has no record of counts as pending, and an
    /// entry for a key no longer in the lineage is ignored, so a journal can never
    /// read complete for a predecessor it never saw.
    pub fn status(&self, predecessors: &[DelegateLineageEntry]) -> JournalStatus {
        let mut pending = Vec::new();
        for e in predecessors {
            match self.entries.get(&e.delegate_key).map(|j| j.state) {
                Some(JournalState::Resolved(_)) => {}
                Some(JournalState::Pending {
                    attempts,
                    data_bearing,
                }) => pending.push(PendingPredecessor {
                    key: lineage_key(e),
                    generation: e.generation,
                    attempts,
                    data_bearing,
                }),
                None => pending.push(PendingPredecessor {
                    key: lineage_key(e),
                    generation: e.generation,
                    attempts: 0,
                    data_bearing: false,
                }),
            }
        }
        if pending.is_empty() {
            JournalStatus::Complete
        } else {
            JournalStatus::Incomplete { pending }
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
                    let (state, attempts, data_bearing, rejected) = match e.state {
                        JournalState::Pending {
                            attempts,
                            data_bearing,
                        } => (0, attempts, data_bearing, 0),
                        JournalState::Resolved(r) => match r {
                            JournalResolution::Imported => (1, 0, true, 0),
                            JournalResolution::NoData => (2, 0, false, 0),
                            JournalResolution::NotInstalled => (3, 0, false, 0),
                            JournalResolution::ImportedWithRejections { rejected } => {
                                (4, 0, true, rejected)
                            }
                            JournalResolution::SupersededByAuthoritative => (5, 0, false, 0),
                        },
                    };
                    WireEntry {
                        key: *key,
                        generation: e.generation,
                        state,
                        attempts,
                        data_bearing,
                        rejected,
                    }
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
        let wire: WireJournal =
            ciborium::de::from_reader(bytes).map_err(|e| JournalDecodeError(format!("{e}")))?;
        if wire.v != MIGRATION_JOURNAL_VERSION {
            return Err(JournalDecodeError(format!(
                "journal version {} is not {MIGRATION_JOURNAL_VERSION}",
                wire.v
            )));
        }
        let mut journal = Self::default();
        for w in wire.entries {
            let state = match w.state {
                0 => JournalState::Pending {
                    attempts: w.attempts,
                    data_bearing: w.data_bearing,
                },
                1 => JournalState::Resolved(JournalResolution::Imported),
                2 => JournalState::Resolved(JournalResolution::NoData),
                3 => JournalState::Resolved(JournalResolution::NotInstalled),
                4 => JournalState::Resolved(JournalResolution::ImportedWithRejections {
                    rejected: w.rejected,
                }),
                5 => JournalState::Resolved(JournalResolution::SupersededByAuthoritative),
                other => {
                    return Err(JournalDecodeError(format!(
                        "unknown journal entry state {other}"
                    )))
                }
            };
            journal.entries.insert(
                w.key,
                JournalEntry {
                    generation: w.generation,
                    state,
                },
            );
        }
        Ok(journal)
    }

    /// Mark `predecessor` as having started a data-bearing import (its items may
    /// now be partially written). Returns whether the entry changed.
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
            _ => false,
        }
    }

    /// Record the outcome of one journaled walk for `predecessor`: `Some` resolves
    /// it, `None` counts a failed attempt. JournalResolution is sticky (see the module
    /// docs): an already-resolved entry only ever changes to a data-bearing
    /// resolution.
    pub(crate) fn record(
        &mut self,
        predecessor: &DelegateKey,
        generation: u32,
        outcome: Option<JournalResolution>,
    ) {
        let entry = self
            .entries
            .entry(key_bytes(predecessor))
            .or_insert(JournalEntry {
                generation,
                state: JournalState::fresh(),
            });
        entry.state = match (entry.state, outcome) {
            (JournalState::Resolved(old), Some(new)) => {
                if new.is_data_bearing() && !old.is_data_bearing() {
                    JournalState::Resolved(new)
                } else {
                    JournalState::Resolved(old)
                }
            }
            (JournalState::Resolved(old), None) => JournalState::Resolved(old),
            (JournalState::Pending { .. }, Some(new)) => JournalState::Resolved(new),
            (
                JournalState::Pending {
                    attempts,
                    data_bearing,
                },
                None,
            ) => JournalState::Pending {
                attempts: attempts.saturating_add(1),
                data_bearing,
            },
        };
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
    /// How many journaled walks have failed to resolve it.
    pub attempts: u32,
    /// Whether an import from it has started, so its items may be partially
    /// written to the successor.
    pub data_bearing: bool,
}

/// Completeness of a successor's migration, as its stored journal records it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalStatus {
    /// No journal is stored: a journaled migration has never begun on this
    /// successor.
    NotStarted,
    /// A journal is stored but cannot be decoded. Treat as incomplete: re-run the
    /// migration, which rewrites it.
    Unreadable(JournalDecodeError),
    /// Every predecessor in the lineage is resolved. The migration is over for this
    /// successor; there is nothing to probe.
    Complete,
    /// At least one predecessor is unresolved. Re-run the migration.
    Incomplete {
        /// The unresolved predecessors, in lineage order.
        pending: Vec<PendingPredecessor>,
    },
}

impl JournalStatus {
    /// Whether the migration is known to be complete.
    pub fn is_complete(&self) -> bool {
        matches!(self, JournalStatus::Complete)
    }

    /// Whether an import from some predecessor started and has not been resolved,
    /// so the successor may hold a **partial** copy of its data right now. An app
    /// should not treat the successor's contents as authoritative while this is
    /// true (River gates importing an identity on it).
    ///
    /// An unreadable journal says nothing reliable, so it counts as interrupted.
    pub fn interrupted_import(&self) -> bool {
        match self {
            JournalStatus::Unreadable(_) => true,
            JournalStatus::Incomplete { pending } => pending.iter().any(|p| p.data_bearing),
            _ => false,
        }
    }
}

/// The completeness of a successor whose stored journal bytes are `stored`
/// (`None` when nothing is stored), against the lineage `predecessors`. A pure
/// function, for the app's load path: read the journal once, decide whether the
/// walk must run.
pub fn journal_status(
    stored: Option<&[u8]>,
    predecessors: &[DelegateLineageEntry],
) -> JournalStatus {
    match stored {
        None => JournalStatus::NotStarted,
        Some(bytes) => match MigrationJournal::decode(bytes) {
            Ok(journal) => journal.status(predecessors),
            Err(e) => JournalStatus::Unreadable(e),
        },
    }
}

/// A [`SuccessorSecretsIo`] that can also persist the [`MigrationJournal`], for
/// [`crate::begin_migration_journal`] and
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
}
