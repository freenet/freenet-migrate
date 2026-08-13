# Changelog

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
