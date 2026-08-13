# Changelog

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
