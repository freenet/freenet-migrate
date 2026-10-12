# Changelog

## freenet-migrate 0.7.0

**Unreleased; publish gated on #43** (River's real-node rehearsal, the #41
marker-store conformance check, #39 or an app override, and whether this ships
as 0.7.0 or 0.8.0).

**Delegate half only.** Two features and one behaviour change:

* `SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive`
  ([#14](https://github.com/freenet/freenet-migrate/issues/14)), below.
* A durable, opt-in **completeness journal**
  ([#37](https://github.com/freenet/freenet-migrate/issues/37)), so an app knows
  on every load whether every predecessor has been dealt with. See "Durable,
  verifiable migration completeness" below.
* **Behaviour change, for every adopter of the delegate walk:** a predecessor
  that exports nothing although an earlier attempt saw data in it is no longer
  sealed as done. See "An empty answer after data is a silence" below; read it
  before upgrading if your app keys anything off the walk's `Done` markers or
  relies on the walk halting.

The minor version bump (not a patch) is the conventional pre-1.0 signal for new
public enum variants. `SecretSelectionPolicy` was not `#[non_exhaustive]` before
this release (it is now), so an external exhaustive `match` over it, though none
is known to exist, would need a new arm; that is technically breaking.
`WriterStage::JournalFlag` and `WriterStage::JournalUnavailable` join an enum that
was already `#[non_exhaustive]`.
No known adopter's code needs to change to compile: every one constructs the
policy rather than matching it exhaustively, and the journal is new API. The
behaviour change above is the one thing to audit.

**Upgrading from 0.5.** 0.6.0 (the contract half: silence is no longer absence)
sits between, and is breaking on the contract half. Read "Upgrading to 0.6.0" in
the README first.

### The problem

Under `NewestSnapshotWins` (the default), a predecessor that cannot be
confirmed executable is recorded as `PredecessorMigration::Unresponsive` and
**terminates the walk**. In isolation that is the right call — falling through
past an unknown newer state risks resurrecting a key the newer generation
deleted. But silence is the **normal** case for almost every legacy generation
on almost every node (the predecessor delegate is simply not registered there
any more), so the first silent generation stopped the walk and every older
generation was never even asked. In practice, `NewestSnapshotWins` disabled
migration for any lineage with more than one generation.

`UnionAllGenerations` already walks past an unresponsive predecessor, so it was
the only available workaround — at the cost of Union's own semantics (a
deleted key can be resurrected from an older generation).

### The fix

`SecretSelectionPolicy::NewestSnapshotWinsContinuePastUnresponsive(RollbackRiskAck)`
is a new, additive enum variant (existing `NewestSnapshotWins` and
`UnionAllGenerations` call sites are unaffected — this cannot break an
adopter that constructs the policy but does not exhaustively match it, which
is every known adopter as of this release). It keeps `NewestSnapshotWins`'s
authoritative-newest-data-bearing-wins rule, but an `Unresponsive` predecessor
no longer halts the walk: the search continues to the next older predecessor
instead of marking every remaining generation `Superseded`.

The unresponsive predecessor is still recorded as `PredecessorMigration::
Unresponsive` and still trips `DelegateMigrationReport::any_unresponsive` — an
adopter gating fresh-install on that flag (as river#204 requires) still sees
it, so the fall-through is never silently clean.

**This forfeits the anti-rollback guarantee for older generations**, hence the
loud `RollbackRiskAck` (reused from the contract driver's identical trade-off —
see 0.6.0 below). If the unresponsive predecessor actually held a newer,
authoritative snapshot rather than simply being unregistered on this node, an
older generation's data-bearing answer becomes authoritative in its place —
either as delete-by-absence resurrection, or as **silent, permanent
value-shadowing**: the successor's never-clobber writer means a later run in
which the newest predecessor becomes reachable and offers its own different,
real value for the same key gets declined as `AlreadyAuthoritative`, with the
report reading completely clean (`is_complete() == true`,
`any_unresponsive() == false`). There is no signal anywhere that the durable
value is the wrong one. Ordinary transient unreachability is enough to trigger
it — no storage fault required.

One case is closed for free: a predecessor already proven data-bearing by a
surviving marker from an earlier run (`MigrationMarker::InProgress { saw_data:
true }`) still halts the walk on a *later* unresponsive result, rather than
falling through — `unresponsive_terminates` now takes that history into
account. It cannot help on a predecessor's first-ever attempt, which is
indistinguishable from "never registered," the ordinary case this variant
exists to fall through on; closing that fully needs the
`probe_executable -> Result<bool, E>` classification work #14 explicitly
defers as a separate follow-up. Construct the ack only when the residual risk
is acceptable, or when silence has already been established as the ordinary
case rather than a transient fault.

Plain `NewestSnapshotWins`'s halting behavior is unchanged — the new variant is
opt-in. Both the closed case and the accepted residual are pinned by tests:
`a_predecessor_proven_data_bearing_by_a_surviving_marker_still_halts_when_later_unresponsive`
and
`continue_past_unresponsive_can_permanently_shadow_a_later_recovered_true_value`.

### Durable, verifiable migration completeness ([#37](https://github.com/freenet/freenet-migrate/issues/37))

**Opt-in.** Apps that do not call the journal API get nothing new from this
section. (The walk's one behaviour change, which every adopter gets, is in its own
section below.)

**The problem.** The walk was already durable *within* a predecessor (in-progress
marker before the first item, done marker after the flush). What nothing recorded
durably was whether *every* predecessor had been dealt with, which an app has to
answer on every load to decide whether the walk must run again. Apps answered it
in-session (quiescence of the probe fan-out, in-flight counters, a `localStorage`
flag), and in a browser app served by the gateway every one of those fails: the
app iframe has no `localStorage`, and a tab can die between any two writes.
freenet/river#760 measured it: a tab closed after the first per-room write left 1
of 4 rooms on every later load. Four review rounds of in-session fixes
(freenet/river#758) each found a new hole, because "done" was still a guess.

**The fix.** A `MigrationJournal`, stored in the successor through the new
`JournaledSuccessorIo` trait, lists every predecessor as `Pending` or
`Resolved`:

* `begin_migration_journal` stores it before the app's first migration write.
  It never resets a readable journal. A fresh one, and any lineage entry an
  existing one has never seen, is read off the migration markers: a `Done`
  resolves as the walk would, and `InProgress { saw_data: true }` is an import
  `Started`.
* `migrate_delegate_secrets_journaled` runs the ordinary walk, durably flags a
  data-bearing predecessor's import as started before its first item, and
  records what each predecessor resolved to. It does not walk a predecessor
  again once the journal resolves it with its data in the successor (an import
  whose only blemish was permanent rejections has no `Done` marker). A refused
  run reports every predecessor `WriterUnavailable`
  (`WriterStage::JournalUnavailable`), so it never reads complete.
* `note_app_import_started(successor, lineage, predecessor, policy)` raises the
  same flag for an app that writes migrated data outside the walk (River's
  hand-rolled sweep), once it holds data read from the predecessor and before
  it writes or merges it. It takes the same lineage as `begin` and the walk,
  which decides the predecessor's generation and which ones are newer (never
  the stored journal, which a tab on another build may have numbered
  differently). It refuses (`JournalError::NotImportable`) a predecessor outside
  the lineage, or one a snapshot policy supersedes: a newer generation holds
  data by the journal (resolved with it, an import under way, or a rejection a
  higher revision reopened) or by its own marker, or only a legacy seal for a
  newer generation covers it. A marker read that fails there is a plain
  `Successor` error, never a verdict. Under a snapshot policy, an app's sweep
  should also stop where the walk would (at a newer generation it cannot read):
  the guard refuses only what it knows holds data.
* Inside the no-compare-and-swap window between two sessions' stores, a stale
  session can overwrite an app's flag, and the stored journal can then say no
  import is under way over the app's partial copy (even `Complete`, if the
  predecessor had been resolved as holding nothing). The predecessor's marker
  still records the import: `begin_migration_journal` reopens such a resolution,
  and the walk restores the flag on any predecessor it reaches, and after it on
  any whose marker neither it nor the start read (behind a halt, a failed read,
  a legacy seal, a supersession). Call `begin` on every load, and decide from the status the last
  call returned, never from a raw `journal_status` read.
* `begin` costs one marker read per predecessor resolved as holding nothing, per
  call. A marker it cannot read there refuses nothing: the predecessor reads as
  an import under way for that load, nothing is stored, and the read is retried
  on the next.
* `JournalStatus` is `NotStarted`, `Unreadable`,
  `Incomplete { pending, rejected_items }` (re-run the walk) or
  `Complete { rejected_items }` (nothing left to probe). Decide from the one
  `begin` or the walk returned; `journal_status` is a pure read of stored bytes
  that reads no markers.
  `interrupted_import()` says the successor may hold a partial copy right now.
  True means "do not treat the successor as everything the user had"; false
  does not mean it is (a silent predecessor, or `rejected_items() > 0`, still
  says otherwise). Never gate on `!is_complete()`, which absent generations keep
  true for ever.

**Store it in the successor's secrets under `MIGRATION_JOURNAL_KEY`**
(`\0freenet-migrate-journal/v1`). That namespace is the crate's, not the
node's: a node refuses any key in the marker namespace `\0freenet-migrate/` that
is not a marker, but accepts this one. Every walk, the plain one included, and
`handle_export_request` withhold it, so a predecessor's journal is never
imported nor counted as its data; `is_reserved_key` tells an app's own code the
same. Keep it out of any copying your app does itself (a hand-rolled sweep).
The crate does not ship a delegate-side store (`SecretStoreIo` does not
implement `JournaledSuccessorIo`; #40).

This reserves a second namespace for every adopter, not only journal users: a
key beginning with `\0freenet-migrate-journal/` is never exported or imported.

**Do not adopt the journal unless:**

* **your `fetch_secrets` fails loudly.** A resolution is as permanent as a `Done`
  marker, so an export that can come back partial without an `Err` (one that
  silently skips what it cannot read, or a sub-request whose timeout reads as
  "nothing", as in freenet/delta#100) gets a partial import certified complete.
  That includes a shorter answer on the retry after an interrupted import (only
  an empty one is refused, #44), and an index the predecessor reads for itself
  that a failed read (freenet-core#5857) turns into a short list;
* **your successor store is durable** (a page-memory marker store cannot hold a
  journal);
* **your marker store follows the new contract** below;
* **your predecessors are frozen**: nothing writes to an old generation once its
  successor is in use, or `Imported` and `NoData` seal over data written later;
* **no older build of your app walks the same successor** while the journaled
  one is in use (old tabs during a UI-only rollout): it still seals over partial
  copies the journal then believes. Ship the journal with a delegate re-key.
  (Even then, an old tab keeps writing to what is now a predecessor until it is
  closed, so "frozen" holds only after the rollout; data written there in the
  window is the app's to reconcile.)
* **under a snapshot policy, every predecessor finished its own migration**
  before it became one. A newer predecessor that was itself interrupted
  mid-migration is still taken as the authoritative snapshot, and what it never
  received from older generations is not asked for. Union does not have this
  limit.

**`import_revision` is part of adopting, not optional.** Any change to how the
import path decodes items (River's byte-string change, say) must bump it, or
predecessors it rejected before stay resolved and their items stay missing.

`Complete` needs every predecessor resolved, and a predecessor that is not
installed on the node never resolves. An account whose lineage includes
generations this node never had therefore stays `Incomplete`, and the walk keeps
probing them; with a typed "not installed" answer each probe is cheap.
`pending_all_absent(n)` lets an app probe less often, as its own policy.

Completeness is arithmetic over durable state; there is no timing anywhere in it.
The rules the data-loss argument rests on:

* **Absence never resolves.** Silence, a timeout, and a definitive "not
  installed" all stay pending: freenet-core unregisters a delegate without
  deleting its secrets, so "not installed" is not proof of "holds nothing". A
  "not installed" answer is counted (`absent_streak`); the crate never gives up.
* **"Nothing" after "something" is not believed.** A predecessor whose import
  `Started` and which then answers that it holds nothing stays pending. (The
  walk itself now does the same; see below.)
* **A permanent rejection resolves with a count, and can be reopened** when the
  writer's `JournaledSuccessorIo::import_revision` rises, so an app that finds
  and fixes a wrong rejection retries it. An older build of the app never
  downgrades the revision.
* **`SupersededByAuthoritative` holds only under a snapshot policy.** Under
  `UnionAllGenerations` it reads as pending. Both this and the revision are
  evaluated against the app's `JournalBinding` on every read and every merge,
  so a stale stored copy cannot bring a reopened resolution back.
* **Every store is read-merge-write and fails closed.** A second session's import
  flag survives our store, including the very first store. If the journal, or a
  predecessor's marker while starting one, cannot be read, or the journal cannot
  be started or (before a predecessor's first item) flagged, nothing of that
  predecessor is written. A journal from a different encoding version is never
  overwritten; a corrupt or lost one is rebuilt from the migration markers.
* **Markers back every started import.** `note_app_import_started` also writes
  the predecessor's `InProgress { saw_data: true }` marker, so a rebuilt journal
  still knows about every import that started, the app's included.

**The marker-store contract, for journal adopters** (on
`SuccessorSecretsIo::migration_marker` / `record_marker`; `SecretStoreIo`
follows it). The compiler does not check it, and River's, Harvest's and Delta's
own stores do not follow it today:

1. `InProgress { saw_data: true }` stored beside `Done { had_data: false }` reads
   as `InProgress { saw_data: true }`.
2. Recording `InProgress` never erases a stored `Done` (keep them separate).
3. `InProgress { saw_data: false }` never downgrades a stored
   `InProgress { saw_data: true }`, including one another session records
   between your check and your write: do both inside one delegate message, or
   the check does not hold.

Break rule 1 and a lost or corrupt journal certifies `Complete` over a partial
copy. The crate checks rule 1 where it matters (`note_app_import_started` and a
walk re-asking an empty seal read the marker back after recording it, and refuse
with nothing written if it does not read as recorded); it checks rule 3
nowhere. A conformance check adopters can run is tracked in #41.

`predecessor_already_migrated` and the public `predecessor_migration_had_data`
follow rule 1 too: an empty seal contradicted by a data in-progress marker reads
as not migrated (`None`).

New `WriterStage` variants: `JournalFlag` (a failed import-flag store; nothing
of that predecessor was written) and `JournalUnavailable` (the journaled walk was
refused).

**`ProbeVerdict` and `PredecessorSecretsIo::probe_verdict`.** A new default trait
method with a third answer, `NotInstalled`, for an adapter whose transport can tell
"this node has no such delegate" from silence (a typed node error, never a
timeout or an empty reply). The default forwards to `probe_executable` and never
answers `NotInstalled`, so existing adapters are unaffected. The walk treats
`NotInstalled` exactly like silence (`Unresponsive`, same termination rule under
every policy); the only difference is the journal's absent streak.


### An empty answer after data is a silence (behaviour change, every adopter)

A predecessor whose in-progress marker says an earlier attempt saw data, and
which now exports nothing, is reported `Unresponsive` (with
`PredecessorMigration::exported_nothing_after_data()` true) and keeps its
in-progress marker. Before, it was sealed `Done { had_data: true }`, and the
interrupted attempt's missing items were never asked for again.
`import_predecessor_secrets_once` likewise returns `Incomplete` with zero counts
instead of sealing.

**Why.** A frozen predecessor does not lose data, so the empty answer is the
fault: freenet-core reports a secret it failed to read the same way as one that
is not there (freenet/freenet-core#5857).

**What changes for an adopter.**

* **No data is dropped.** What was a silent seal is now a retry on every run.
* **A predecessor that really did become empty is retried forever.** That
  includes one an old-version tab emptied, so "frozen" is an assumption your app
  must actually hold.
* **Termination follows each policy's rule for an unresponsive predecessor, with
  the earlier data as evidence:**
  * `NewestSnapshotWins` and `...ContinuePastUnresponsive` stop there.
  * `UnionAllGenerations` goes on to older generations, as for any unresponsive
    predecessor, and a never-clobber writer may then keep an older generation's
    value for a key the newer one also holds (an opt-in halt is tracked in #42).
* **If your app relies on the walk halting there under Union**, it has to do it
  in its adapter: once a predecessor exports nothing while the successor's
  marker for it says `InProgress { saw_data: true }`, return `Err` from
  `fetch_secrets` for every OLDER predecessor for the rest of that run. (Erring
  for the empty one alone changes nothing: Union walks past any unresponsive
  predecessor.) `exported_nothing_after_data()` reports the case afterwards, by
  which time an older generation may already have been written.
* **If your app keys anything off the predecessor's `Done` marker** (promoting
  staged records when it is written, say), that now waits until the predecessor
  answers with data again.
* **Seals written by earlier releases stay as they are,** and an older build
  still running against the same successor (an old tab during a UI-only
  rollout) keeps writing them, and reads the new contradicted-seal pair as a
  plain empty `Done`. A predecessor sealed `Done { had_data: true }` over a
  partial copy cannot be told apart from a complete one. Ship the journal with
  a delegate re-key, or accept that window knowingly.
* **Do not renumber a lineage over a successor holding legacy generation-keyed
  markers.** Those markers (pre-0.5 `import_secrets_once`, and the at-or-above
  bridge) are keyed by generation number, so a renumber points them at a
  different predecessor: one can then read as migrated without ever being
  imported, and the journal certifies it. A successor that only ever saw the
  per-predecessor markers is unaffected.
* **A legacy generation-keyed import (`import_secrets_once`) interrupted part-way
  is invisible to the journal,** which reads only the per-predecessor markers.
  Do not mix the two APIs on one successor. A legacy at-or-above seal (a
  generation-keyed marker for a NEWER generation) is journalled as superseded,
  never as imported, so it reopens under Union.
* **A lost journal re-walks a predecessor resolved with rejections.** It has no
  `Done` marker, so its rebuilt entry is an import in progress and its items are
  offered again, which can bring back keys deleted since.
* **A re-asked predecessor cannot undo what ran in the meantime.** Under a
  snapshot policy, a predecessor first answering empty lets the same run import
  an older generation; when the newer one is later re-asked (it held data after
  all), a never-clobber writer keeps the older values. That is the first-attempt
  residual (freenet/freenet-core#5857): only an attempt that has already seen
  data is protected.

## freenet-migrate 0.6.0

**Breaking, contract half only.** Silence is no longer absence
([#19](https://github.com/freenet/freenet-migrate/issues/19)). The delegate-half
surface is untouched.

### The mechanism

A backward probe classified a candidate that never answered exactly as it
classified one that answered "I have nothing". Both were `on_timeout` → a miss →
the walk advanced. Two consequences, both silent:

* A lineage whose candidates were merely unreachable produced
  `Outcome::SeedLocal` — the outcome an app reads as "the predecessors were
  reached and had nothing", at which point it seeds its local snapshot forward
  and stops asking. A predecessor that was slow, or on a node that had not yet
  answered, was recorded as permanently empty. No error, no crash: the migration
  reported success and the data stayed under the old key.
* One timeout on the newest generation let an older one be adopted — the
  "generation-blind selection" rollback the driver's own module docs claim is
  inexpressible. The pre-0.6.0 test suite pinned that as correct behaviour.

Absence now requires a positive answer.

### Changes

* **New: `ProbeAnswer`** (`State` / `Absent` / `Unknown`), the return type of
  `ProbeIo::get` in place of `Option<Vec<u8>>`. An adapter cannot express "I
  never heard back" as "the predecessor has nothing" without typing `Absent` and
  being wrong on purpose. Map stdlib's `ContractResponse::NotFound` to `Absent`
  and everything else non-answering to `Unknown`.
* **New: `ProbeDriver::on_absent`** (answered "nothing here") and
  **`ProbeDriver::on_unknown`** (timeout, send failure, dropped transport).
* **Deprecated: `ProbeDriver::on_timeout`**, now forwarding to `on_unknown`. It
  can never seal a predecessor as empty, but it is **not a drop-in** for a call
  site that also routed positive not-founds through it. Because an unknown halts
  the walk under `NewestFirstWins`, an app whose only failure path is a watchdog
  — one that never handles `NotFound`, so an absent generation arrives as a
  timeout — will stop at its first empty generation and never ask the older
  ones. If the data lives further down the lineage it is never probed. **That is
  a recovery outage, not a conservative degradation: recovering becomes never
  recovering.** River is this shape today, so upgrading its call site is
  mandatory, not advisory.
* **New: `Outcome::Indeterminate { local, unresolved }`** — nothing was
  recovered and at least one candidate's state was not established. Adopt
  nothing, seal nothing, retry. `unresolved` covers candidates that were asked
  and never answered **and** candidates the walk never reached, because the hop
  cap fired or the policy halted earlier. Its `local` is passed through
  `prepare_forward` like every other outgoing snapshot, since the docs
  explicitly allow an app to seed it after enough failed attempts and
  `prepare_forward` is where a stale upgrade pointer gets stripped
  (freenet/river#427).
* **Fixed: the hop cap no longer produces a clean `SeedLocal`.** Candidates cut
  off by the cap were leaving no trace, so a capped walk returned the outcome
  whose contract is "every candidate answered" for candidates it never asked.
  They are now folded into `unresolved`, making the result `Indeterminate`.
* **`Outcome` is now `#[non_exhaustive]`.** Note the limit: it forces a wildcard
  arm on a `match`, but a `matches!(outcome, Outcome::Recovered { .. })` still
  absorbs a new variant silently. Delta's only production consumption is exactly
  that shape (`operations.rs:1355-1362`), so nothing in this crate can make its
  compiler flag the new variant — Delta needs a deliberate read of the
  `Indeterminate` path.
* **New: `Outcome::Recovered::unresolved`** — generations that never answered.
  Under `FoldAll` the fold is missing their contributions; under
  `NewestFirstWins` (only reachable via the new
  `ProbeDriver::continue_past_unknown`) they are generations *newer* than
  `source` that were never ruled out, so the adoption may be a rollback.
* **Behaviour: under `SelectionPolicy::NewestFirstWins` an unanswered candidate
  stops the probe** rather than falling through to an older generation, matching
  the delegate half's `SecretSelectionPolicy::unresponsive_terminates`. Opt out
  with `ProbeDriver::continue_past_unknown(RollbackRiskAck::…)`, which forfeits
  the anti-rollback guarantee for that probe and says so in the type.
* `ConservativeProbeIo` is no longer lossy: with `ProbeAnswer` three-way it
  passes a real negative through, so a pointer resolved through it can now reach
  `PointerOutcome::NeverPublished`. It still keeps silence and absence apart.
* **Delegate half: docs corrected, and the silent-export path tested for the
  first time.** No signature change; the production path was already correct.
  But `MockIo::fetch_secrets` had no way to return `Err` at all — it could only
  fail at the *preflight* — so "answered the preflight, then went silent on the
  export" was a correct-but-entirely-untested path. The double can now express
  it, and three tests pin it: no marker is written, an older generation is not
  adopted past it under `NewestSnapshotWins`, and Union still walks on.

  The docs that steered adapters wrong: `fetch_secrets` documented `Err` as
  "aborts the whole migration" — it does not; the driver records `Unresponsive`
  and the walk continues or stops per policy. That error pushed adapter authors
  away from `Err` and toward `Ok(vec![])`, which seals a
  `Done { had_data: false }` marker that is never revisited. `Ok(vec![])` is now
  documented as the positive claim it is, `Err` as the right answer for silence,
  and `probe_executable`'s `Ok(true)` no longer claims to make a *later* empty
  export trustworthy.

### What this release does NOT fix: `NotFound` is not proof of absence

0.6.0 stops a predecessor's *silence* being read as its absence. It does not —
and this crate cannot — make the network's "not found" trustworthy.

Absence on Freenet is unauthenticated, and a contract that exists answers
`NotFound` while it is momentarily unfindable. **At the time of writing that is
the common case, not a corner case:** with the placement migration disabled
(freenet-core#4440), present-but-unfindable dead-ends measured ~99.6% of all
`get_not_found` traffic in production telemetry, and a live-network check found
20 of 25 apparent failures had a `NotFound` logged for a key that exists.

So an all-`Absent` walk is, today, more likely to be reporting a routing failure
than an empty lineage. `Outcome::SeedLocal` therefore **no longer claims to be
safe to record as finished** — its previous doc said exactly that, which would
have moved the #19 shape from a timeout trigger to a dead-end trigger rather
than removing it. The crate now reports what it established and leaves sealing
to the app, which is the only place that can weigh it.

`Outcome::SeedLocal` also still absorbs an undecodable answer (`decode -> None`,
`is_real -> false`), so a schema break across a whole lineage lands there with
every generation intact underneath — freenet/freenet-migrate#8.

Hardening that actually holds, for an app that must seal something: make the
operation idempotent so a later run recovers a momentarily-unfindable
generation, require the same answer across separate attempts spread in time,
and/or require a connectivity witness before trusting a negative. See
"Upgrading to 0.6.0" in the README.

### Blast radius: four of the five adopters need a code change

**Three crates will not compile until they are updated**, and `on_timeout`
forwarding does not help them — it preserves *behaviour*, not *compilation*.
Verified against each app's `origin/main`:

| App | What breaks | Why |
|-----|-------------|-----|
| Atlas (`cli/src/main.rs:840`) | **E0271** | implements `ProbeIo`; `async fn get(..) -> Result<Option<Vec<u8>>>` no longer matches `Result<ProbeAnswer, _>` |
| Atlas (`cli/src/main.rs:588`) | **E0004** | exhaustive `match outcome` over `Recovered` / `SeedLocal` / `NoLegacy`, no catch-all |
| River UI (`ui/…/backward_probe.rs:362`) | **E0004** | same shape, `Some(..)` arms plus `None` |
| River CLI (`cli/src/api.rs:426`) | **E0004** | same shape |
| Delta (`ui/…/operations.rs:2294`) | test failure | `driver_all_miss_seeds_local_snapshot` asserts `SeedLocal` after an all-`None` response map, which is now `Indeterminate` |

**Two of them fail CI on the deprecation alone**, as a hard error rather than a
warning: Delta runs `cargo clippy --all-targets -- -D warnings`
(`.github/workflows/ci.yml:41`) and Atlas sets `RUSTFLAGS: -D warnings`
(`ci.yml:10`). So `on_timeout` is not a soft landing for either — they must
classify their call site to build at all.

freenet-git is genuinely unaffected: it takes the build half only
(`freenet-migrate-build`), which this release does not touch.

The `Outcome` breakage is deliberate rather than incidental. An app that seeds
its local snapshot forward on `SeedLocal` has to look at `Indeterminate` before
it ships, and a compile error is the only reliable way to make that happen.

**What each contract-half adopter should do:** map the network's real
"not found" to `ProbeAnswer::Absent` and everything else non-answering to
`ProbeAnswer::Unknown` — see "Upgrading to 0.6.0" in the README.

**Atlas is the adopter this most helps**, which is worth stating alongside the
fact that it is also the one the signature change breaks. Its `classify_probe`
already sorts a legacy GET into `Absent` / `Empty` / `Failed`
(`cli/src/main.rs:765`) — a finer classification than the crate could accept —
and then its `ProbeIo::get` has to flatten **four** distinct situations into one
`Ok(None)`: a real not-found, an empty body, a failed pre-flight under
`--dry-run`, and a transport failure under `--dry-run`. That last one is a
latent instance of exactly this bug living in an adopter today: a dry-run
transport failure currently reads as absence. With `ProbeAnswer` the mapping is
a per-arm change and the distinction survives.

Note the version pin: Atlas depends on `freenet-migrate = "0.5.0"`
(`cli/Cargo.toml:27`) with the `ProbeIo` impl on its **`main`** branch, merged as
`cddb360` (atlas#42) — not on a branch. It stays on 0.5.0 until it chooses to
bump.

## freenet-migrate 0.5.0

**Breaking, delegate half only.** The contract-side surface (`ProbeDriver`,
`SelectionPolicy`, `ProbeIo`, `migrate_contract`, `contract_probe`, `CarryForward`,
`SuccessorPointer`, `ReleaseSigner`, the lineage types) is **untouched**, so apps
pinned at 0.3.x/0.4.x for the contract half are unaffected by this change. The
delegate half had no adopters when 0.5.0 shipped, so it is changed for the right
shape rather than for compatibility. (River, Delta and ghostkeys have adopted the
delegate half since; see the Adopters table in `README.md`.)

### The crate decides what to migrate; the app does the writing

`migrate_delegate_secrets` / `register_delegate_with_migration` now take a
`&mut impl SuccessorSecretsIo` in place of the `&mut impl SecretStore` they used to
write raw `(key, value)` pairs into.

A raw pair copy is wrong for any app whose stored items have cross-entry
invariants, and it fails silently. The measured case is ghostkeys
([freenet/ghostkeys#32]): each credential is several entries plus one `gk:index`
entry listing which credentials exist, plus a permission grant. A pair copier finds
an index already on the successor, skips it never-clobber, and records no grants at
all — so recovered credentials sit in the store while nothing lists them and
nothing may read them. No `SecretSelectionPolicy` fixes it. A raw copy skips four
things the app's own handler does (grant, index merge, certificate-chain
verification, fingerprint derivation); an index-merge hook would have fixed one of
them, routing the write through the app's own import path fixes all four.

* **New:** `SuccessorSecretsIo` (`migration_marker` / `record_marker` /
  `write_secret` / `flush_predecessor`), with `MigrationMarker`, `MarkerQuery`,
  `LegacyBridge`, `RecoveredSecret`, `ItemWrite`, `RetryAdvice`.
* **New:** `SecretStoreIo` — the raw-pair, never-clobber writer over a
  `SecretStore`, i.e. exactly the pre-0.5.0 behaviour, kept for apps whose secrets
  stand alone and for delegate-side imports over `DelegateCtx`. Gated behind
  `NoCrossEntryInvariantsAck`. Pinned byte-for-byte against the still-public
  `import_predecessor_secrets_once` primitive so the two cannot drift.
* **New:** `flush_predecessor`, so a writer that must batch (the shape forced on a
  UI-side adopter whose only route to the successor store is an awaited round-trip)
  can fail honestly before the completion marker claims the data landed.
* `migration_marker` failing, or the in-progress marker failing to record, is the
  new `PredecessorMigration::WriterUnavailable`: nothing imported, walk halted under
  every policy.

### Partial failure is expressible

* `PredecessorMigration::Imported` / `Incomplete` now carry an `ImportTally`
  (`written` / `skipped` / `failed` / `rejected` / `withheld`) in place of the bare
  `imported` / `skipped` / `failed` counts, and `Incomplete` carries the first
  `WriterFailure` (`stage` + stringified error).
* `RetryAdvice::Permanent` distinguishes an item the successor will refuse forever
  (a certificate that does not verify) from a transient failure.
  `DelegateMigrationReport::retry_may_help` is `false` for a report whose only
  blemish is permanent rejections, so an app surfaces them instead of spinning a
  retry loop. `rejected_total` / `failed_total` are new.
* `ItemWrite::AlreadyAuthoritative` covers both "already held" and "not mine to copy
  verbatim" (ghostkeys refuses a predecessor's permission grants and records its own)
  and is a complete, correct outcome. It is named for the assertion it makes about
  the *successor's* state because it is **not an error channel**: an
  `Err(_) => ItemWrite::…` arm mapped onto it counts as `skipped`, which
  `is_clean()` treats as success, so the predecessor earns its `Done` marker and is
  never walked again — silent, unrecoverable loss from a one-token mistake.
* A **failed `flush_predecessor`** withholds every key that predecessor resolved and
  re-counts its optimistic `written` as `failed`. The flush is the durability
  boundary: a buffering writer answers `Written` for items it has only buffered and
  loses the batch on failure, so without this a run withheld *nothing*, an older
  generation wrote its value into the hole and sealed itself clean, and the newest
  generation's value was permanently shadowed by a report reading `is_complete()`.
  `AlreadyAuthoritative` keys are withheld too, since that claim can itself be
  unflushed buffer state. `ImportTally::written` therefore means "applied *and*
  flushed", which is what makes `imported_total()` safe to show a user.
* `SecretStoreIo` can never emit `RetryAdvice::Permanent` — `SecretStore::set_secret`
  reports only `bool`, so a deterministic refusal is indistinguishable from a
  transient one and `retry_may_help()` stays `true` forever against such a store.
  Documented, with the instruction to bound retry counts.

### Termination is a policy question, not a failure question

Before 0.5.0 a partial write set `terminated = true` under **both** policies, so one
storage failure on one key of the newest predecessor marked every older generation
`Superseded` and recovered nothing from them — even under `UnionAllGenerations`,
whose entire purpose is to walk every generation. This was pinned by
`incomplete_newer_halts_before_older_under_both_policies`; that pin is deliberately
inverted.

Termination now derives from the policy and the predecessor's data-bearing state:

| outcome | `NewestSnapshotWins` | `UnionAllGenerations` |
|---|---|---|
| `Imported` / data-bearing `Incomplete` / data-bearing `AlreadyMigrated` | stop | continue |
| `NoData` / empty `Incomplete` | continue | continue |
| `Unresponsive` | stop | continue |
| `WriterUnavailable` | stop | stop |

The `NewestSnapshotWins` column is unchanged. What the old halt genuinely bought is
kept by a narrower mechanism: a key whose write failed **retryably** is withheld
from older predecessors for the rest of the run (`ImportTally::withheld`), so an
older generation cannot shadow a newer value awaiting a retry. A **permanently
rejected** key is not withheld. A **failed flush** withholds everything it lost (see
"Partial failure is expressible"), which is what makes the walk-on safe for a
buffering writer.

### Unchanged

The `pred-done` marker bytes (`PRED_DONE_MARKER_KEY_PREFIX`, `..._VALUE_DATA`,
`..._VALUE_EMPTY`) — the cross-transport interoperability contract with a future
node-side copy-forward — are identical, and `SecretStoreIo` writes them. The
`no-delete` invariant, the G1.8 executability preflight, `MigrationAuthorization`,
the sticky-data marker rule, the legacy generation-keyed bridge, and the
reserved-namespace filter all behave as before.
`predecessor_migration_had_data` is now public, so an implementer of the marker
contract can read back the same flag `predecessor_done_marker` writes.

### Known limitations

Read these before writing a `SuccessorSecretsIo` adapter. Each is documented at the
API it affects; the first two are tracked for a later release.

* **Withholding is scoped to one call** ([#15]). The withheld-key set is never
  persisted, so it protects only within the run that built it. Under
  `UnionAllGenerations` a failed flush followed by a retry while the predecessor is
  transiently unreachable lets an older generation install its value and seal it,
  after which never-clobber declines the newest generation's value permanently — and
  the report reads complete. See `UnionAck`.
* **`imported_total()` under-reports, sometimes to zero** ([#16]). A failed flush
  re-counts optimistic writes as `failed`, which is right for a buffering writer but
  wrong for a write-through one whose flush failed *after* the items were durable.
  The retry then counts them `skipped`, so a fully successful migration can report 0
  recovered secrets. Do not render it to a user unqualified. See `ImportTally::written`.
* **`NewestSnapshotWins` falls through an unsealed empty predecessor** ([#17]).
  Emptiness that was never sealed by a completion marker still authorises importing
  and sealing older generations, so a predecessor that reports data on the retry has
  already had its delete-by-absence overridden.
* **Union's newest-wins guarantee is the writer's to keep.** It holds *only* because
  a never-clobber writer declines a key the successor already has. An overwriting
  writer, which the trait contract permits, ends with the **oldest** generation's
  value installed and a clean report. See the never-clobber bullet on
  `SuccessorSecretsIo`.
* **Markers must be durable on return, not batched.** `flush_predecessor` flushes the
  *items*; a writer that batches markers alongside them can lose the `InProgress`
  marker and with it the sticky-data flag. See `SuccessorSecretsIo::record_marker`.
* **`ImportTally::is_clean` / `retry_may_help` are per-item, not per-predecessor.** A
  flush or completion-marker failure leaves a clean-looking tally on an `Incomplete`
  row. Drive retries from `DelegateMigrationReport::retry_may_help`.

[freenet/ghostkeys#32]: https://github.com/freenet/ghostkeys/pull/32
[#15]: https://github.com/freenet/freenet-migrate/issues/15
[#16]: https://github.com/freenet/freenet-migrate/issues/16
[#17]: https://github.com/freenet/freenet-migrate/issues/17
