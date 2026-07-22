# freenet-migrate

Reusable **upgrade-migration** machinery for [Freenet](https://freenet.org) dApps:
carry a contract's state and a delegate's secrets *forward* across a WASM version
change, instead of stranding them under the old content-addressed key.

Two crates:

| Crate | Role | Depend on it as |
|---|---|---|
| [`freenet-migrate`](./freenet-migrate) | Runtime carry-forward: contract backward-probe + fold, author-signed successor pointer, generic delegate secret export/import. | a normal `[dependencies]` entry (in your contract / delegate / UI crate) |
| [`freenet-migrate-build`](./freenet-migrate-build) | Build-time codegen of the predecessor registry + a CI hash-guard. | a `[build-dependencies]` entry (in your `build.rs`) |

They are independent — `freenet-migrate-build` is a build-dependency for
consumers, not a runtime dependency of `freenet-migrate`.

Horizon-A step A3 of the graceful-upgrades design,
[freenet-core#2776](https://github.com/freenet/freenet-core/issues/2776).

**Design & rationale: [docs/design.md](./docs/design.md)** — why the crate is
shaped this way (backward-probe over signed-pointer, preconditions as
compile-time bounds, the `SecretTransport` seam) and the field-validated River
0.6 → 0.8 re-key outcome.

## The problem

A Freenet contract's identity is **content-addressed**:

```
code_hash            = blake3(wasm)
ContractInstanceId   = blake3(code_hash ‖ params)
DelegateKey          = blake3(code_hash ‖ params)   // for a delegate
```

So *any* rebuild that changes the WASM — a code change, a transitive dependency
bump, a newer compiler — produces a **new key**. The old state and the old
delegate's secrets are still on the network, but under the previous key, which
nothing points at anymore. From the user's perspective the data silently
disappears on upgrade.

River and Delta each hand-rolled the same carry-forward machinery to cope with
this (a committed legacy-code-hash registry, build-time codegen, a CI hash-guard,
backward-probe reconstruction, delegate secret export). Delta still lost
per-site data in April 2026 to a *per-type* secret export that omitted one
variant. This crate packages what they actually ship, with the safety
preconditions made mechanical rather than assumed, so third-party dApps get the
tooling (and the guard-rails) for free.

## Preconditions (design §3) — made first-class

Carry-forward is only *safe* under three preconditions. This crate turns each
one into something the compiler or the API enforces, rather than a footnote:

| Precondition | What it means | How it's enforced |
|---|---|---|
| **mergeable** | the state has a defined fold, so two versions can be combined deterministically | the compile-time `CarryForward: `[`ComposableState`](https://docs.rs/freenet-scaffold) bound — a state with no fold can't call `carry_forward` |
| **self-authorizing** | the merged state must pass the successor's own validator; a permissionless PUT can't smuggle in bad state | the crate's carry-forward **path** enforces a **fail-closed** `verify()` after `merge()`, applied atomically (a failed verify leaves your state unchanged); the opt-out (`carry_forward_unverified`) needs a `#[must_use]`, un-`Default` `PermissiveValidatorAck` whose only constructor is loudly named |
| **signing identity** | a successor release is vouched for by the app author, not anyone who can build WASM | `ReleaseSigner::from_key(SigningKey)` is the *only* constructor for the author-signed `SuccessorPointer` |

If your state is not a `ComposableState` (not mergeable) or your contract has no
meaningful validator (not self-authorizing), carry-forward is **not** safe and
this crate will not paper over that.

> **Scope of the verify guarantee.** `ComposableState::merge` is itself a
> *public* trait method, so this crate cannot make skipping `verify()`
> physically impossible — a consumer can always call `merge` directly. What it
> guarantees is that the crate's own carry-forward *path* (`carry_forward`)
> always runs the fail-closed `verify()`, and that the only in-crate way to skip
> it is the loudly-named `PermissiveValidatorAck` opt-out. Stay on the
> carry-forward path and the gate is unavoidable.

## Usage sketch: v1 → v2

### 1. Register the predecessor (build side)

When you cut v2, record v1's code hash in a `legacy.toml` at your crate root:

```toml
# legacy.toml — the predecessor registry. Hashes may be base58 (stdlib's string
# form) or 64-char hex (what b3sum prints); both decode at BUILD time.
[[contract]]
generation = 1
code_hash  = "9xF...v1codehash..."     # blake3(v1 wasm)
note       = "v1: initial release"

[[delegate]]
generation = 1
code_hash    = "7kQ...v1codehash..."
delegate_key = "7kQ...v1delegatekey..." # blake3(code_hash ‖ params)
note         = "v1: initial delegate"
```

Validation happens at build time: hashes decode to a canonical `[u8; 32]` (a
typo is a build failure, not a runtime probe miss), and each delegate row's
`delegate_key` is re-derived from `code_hash` and cross-checked — the
wrong-derivation incident class (River, Feb 2026) cannot enter a registry.
Grandfathered rows whose recorded key predates the standard derivation mark
themselves `irregular_key = true` (the recorded key is what the probe targets);
delegates with non-empty params record them as `params_hex`.

In `build.rs`, codegen the lineage consts and (optionally) run the CI hash-guard:

```rust,no_run
// build.rs
fn main() {
    freenet_migrate_build::codegen()
        .registry("legacy.toml")
        .emit()
        .expect("codegen lineage consts");
}
```

This emits `CONTRACT_LINEAGE` / `DELEGATE_LINEAGE` consts into `$OUT_DIR`. The
guard (`check_migration_guard`) asserts the rule "if the built WASM's hash
changed, the old hash must be registered as a predecessor" — wire it into a test
or a small xtask so an unregistered re-key fails CI instead of stranding data.

**Adopting in an existing app**: the codegen also reads River-style `[[entry]]`
TOMLs and can emit plain byte-array *view* consts matching hand-rolled const
shapes/types/values, with no `freenet-migrate` runtime dependency — call sites,
scripts, and CI stay unchanged. The one registry edit the validation may demand:
a delegate row whose recorded key predates the standard derivation needs
`irregular_key = true` added (in River's registry that is V1, one line; the
`DelegateKeyMismatch` build error says exactly which row and what to do). Build
scripts with extra behaviors keep them via `.rerun_if_changed(false)` (preserve
Cargo's re-run-every-build heuristic, e.g. for a `BUILD_TIMESTAMP`) and
`.allow_missing_registry(true)` (empty consts when the registry file isn't
shipped, e.g. docs.rs builds):

```rust,no_run
// e.g. River's common/build.rs — same file, same consumers, crate-owned codegen
use freenet_migrate_build::Component;
freenet_migrate_build::codegen()
    .entry_registry("legacy_room_contracts.toml", Component::Contract)
    .canonical_consts(false)                              // views only
    .contract_hash_view("LEGACY_ROOM_CONTRACT_CODE_HASHES") // &[[u8; 32]]
    .out_file("legacy_room_contracts.rs")
    .emit()
    .expect("codegen legacy room-contract hashes");
// ui/build.rs: .delegate_pair_view("LEGACY_DELEGATES")
//   → &[([u8; 32], [u8; 32])] in (delegate_key, code_hash) order
```

### 2. Contract state carry-forward (runtime)

`predecessor_ids` reconstructs each old `ContractInstanceId` from
`(code_hash, params)` with **no old WASM bytes**. The UI GETs each, folds the
first non-empty one forward through the fail-closed gate, and re-PUTs under the
current key:

```rust,ignore
use freenet_migrate::{predecessor_ids, CarryForward};

// Reconstruct predecessor keys from the codegen'd lineage + your stable params.
let old_ids = predecessor_ids(&params, CONTRACT_LINEAGE); // infallible: hashes were validated at build time

// GET each old id (app-side); fold the recovered state forward.
let mut current = MyState::default();
if let Some(old_state) = fetch_first_non_empty(&old_ids)? {
    // merge() then a forced verify() — refused (fail-closed) if the fold
    // wouldn't pass the successor's own validator.
    current.carry_forward(&old_state, &parent, &params)?;
}
// re-PUT `current` under the v2 key
```

A contract that wants the node to pull predecessor state during
`validate_state` (instead of an app-side probe) can use `resolve_predecessors`,
which returns a `ValidateResult::RequestRelated` with `StateThenSubscribe`.

### 2b. The sans-IO probe decision driver

The crate owns the probe **decisions** — order, hit criteria, advance/stop,
what to adopt — while the app pumps I/O through a thin adapter (browsers have
no request/response correlation, so the crate cannot drive the loop itself):

```rust,ignore
use freenet_migrate::{contract_probe, Outcome, SelectionPolicy, Step};

let mut driver = contract_probe(ops, local_snapshot, &params, CONTRACT_LINEAGE,
                                SelectionPolicy::NewestFirstWins);
loop {
    match driver.next_action() {
        Step::Get(id) => { /* send GET(id), arm a ~12s timer; deliver via
                              driver.on_response(id, &bytes) / driver.on_timeout(id) */ }
        Step::Done => break,
    }
}
match driver.take_outcome().unwrap() {
    Outcome::Recovered { merged, .. } => { /* adopt + PUT under the CURRENT key */ }
    Outcome::SeedLocal { local }      => { /* seed the local snapshot forward */ }
    Outcome::NoLegacy                 => { /* fresh app, normal first-run */ }
}
```

Decisions are fixed by the driver (probing newest-first; undecodable or
non-real responses and timeouts advance; late responses are single-shot
ignored; exhaustion seeds the local snapshot; a `prepare_forward` hook strips
key-relative metadata like upgrade pointers before any forward PUT). The two
Delta incident decision-bug classes — generation-blind selection and
scalar-recency selection — are structurally inexpressible in it.

Selection policy: `NewestFirstWins` (default; one generation adopted, safe for
delete-by-absence states) or `FoldAll` (folds every real generation; only
sound for tombstoned states with a commutative+idempotent merge, so it takes a
loudly-named ack and `policy_check` property helpers to verify the merge
first). Native callers with awaitable I/O can use the pumped wrapper
`migrate_contract(ops, io, local, &params, lineage, policy)` instead of the
raw driver.

Optionally publish an author-signed pointer from v1 → v2 so clients can discover
the successor:

```rust,ignore
use freenet_migrate::ReleaseSigner;

let signer  = ReleaseSigner::from_key(app_signing_key); // the ONLY constructor
// `sign` returns Result (rejects an empty app_id); pointers carry a
// domain-separated, app-bound signature.
let pointer = signer.sign(successor_code_hash, generation, app_id)?;
// The accept path (deciding whether to FOLLOW a pointer) must check BOTH the
// signature and the anti-rollback ordering, so use verify_and_check_supersedes,
// not a bare verify() (which checks the signature only):
pointer.verify_and_check_supersedes(&signer.public_key(), app_id, current_generation)?;
```

### 3. Delegate secret carry-forward (runtime)

**The app-facing entry point is `migrate_delegate_secrets`** — carry each
predecessor delegate's secrets forward into the successor, with consent required
from day one. The transport underneath (app-side round-trips today, a node-side
copy tomorrow) is an internal detail apps do not program against — that altitude
is the whole point, so a future node copy-forward is a drop-in with no app
re-adoption.

```rust,ignore
use freenet_migrate::{
    migrate_delegate_secrets, MigrationAuthorization, PredecessorSecretsIo,
    SecretSelectionPolicy,
};

// `io` implements PredecessorSecretsIo: `probe_executable` sends a cheap no-op to
// an old delegate key (G1.8 preflight); `fetch_secrets` enumerates its secrets —
// both in the app's own delegate protocol (DelegateRequest::ApplicationMessages),
// with the app's own response correlation (a browser has no request/response
// correlation, so the app supplies it — e.g. a per-request oneshot side-table).
// The report is the source of truth: transport errors become report rows, never a
// bare error that would discard the predecessors already migrated.
let report = migrate_delegate_secrets(
    &mut ctx,                                    // successor SecretStore
    &mut io,                                     // reaches the predecessors
    DELEGATE_LINEAGE,                            // predecessor LIST (codegen'd)
    MigrationAuthorization::app_author_ack(),    // consent — required, no default
    SecretSelectionPolicy::NewestSnapshotWins,   // safe default; or UnionAllGenerations(ack)
).await;

// The #204 UX fix. Gate on completeness first, then classify:
if !report.is_complete() {
    if report.any_unresponsive() {
        // A predecessor could not be reached — its data MAY exist but can't be
        // auto-migrated. Surface "your data may exist but can't auto-migrate";
        // NEVER silently fresh-install.
    } else {
        // Only Incomplete rows remain — a storage write failed mid-import. Safe
        // to retry: re-run migrate_delegate_secrets (already-migrated predecessors
        // are no-ops, the incomplete one re-runs).
    }
}
```

Predecessors are a **list**, processed newest-generation-first. `SecretSelectionPolicy`
decides the cross-generation behavior (the delegate-side analogue of the contract
driver's `NewestFirstWins` / `FoldAll`):

- `NewestSnapshotWins` (safe default): the newest predecessor that yields data is
  authoritative; older ones are not imported after it. Preserves delete-by-absence
  (a key the newer generation deleted can't be resurrected from an older one). Cost:
  a key that only ever lived in an older generation stays unrecovered.
- `UnionAllGenerations(ack)`: import every generation (never-clobber, newest still
  wins conflicts) — the river#204 stranded-data recovery mode. It resurrects
  delete-by-absence data, hence the loud ack.

Each import is keyed by the **predecessor delegate key** (recording whether the
predecessor was data-bearing or empty), so a future node copy-forward writes the
same anti-resurrection marker and a re-run is a no-op. Predecessor data is never
deleted (`no-delete` invariant) — the marker, not deletion, is the
anti-resurrection mechanism, and the intact predecessor is the rollback story.
`register_delegate_with_migration` bundles registering the successor delegate with
the same migration.

Underneath, the delegate-side **export/import primitives** do the mechanical work.
The export enumerates secrets *generically* via `SecretStore::list_secrets`
instead of a hand-maintained per-type fan-out, removing the per-**type** omission
that cost Delta its data. It is **not** an unconditional "copy every secret": the
host caps key enumeration per scope (`HOST_ENUMERATION_CAP`, 4096) and truncates
silently beyond it, so the export **detects** cap saturation and refuses with
`TruncatedExport` rather than shipping a partial set (which would then be locked
in by the completion marker). You choose an `ExportScope`: a key prefix (safe on a
delegate shared by multiple web-apps), or the whole scope via a loudly-named
single-app acknowledgement. The v2 side imports once, guarded by a two-phase
anti-resurrection marker (idempotent, never clobbers existing keys):

```rust,ignore
use freenet_migrate::{
    handle_export_request, import_secrets_once, ExportScope, OriginPolicy,
    SingleAppDelegateAck,
};

// v1 delegate (old WASM): authorize the caller (origin is Option<_>, `None`
// fails closed), export the requesting app's slice.
let out = handle_export_request(
    &ctx,                                 // impl SecretStore
    origin.as_ref(),                      // Option<&MessageOrigin> from `process`
    &OriginPolicy::SameWebApp(app_id),    // safe default: same web-app only
    &ExportScope::Prefix(my_key_prefix),  // isolate this app's slice…
    // …or, on a delegate you certify serves ONE web-app:
    // &ExportScope::EntireDelegate(
    //     SingleAppDelegateAck::i_certify_this_delegate_serves_a_single_web_app()),
    &export_request,
)?;

// v2 delegate (new WASM): import once. The high-level entry point drives the
// delegate-key-keyed `import_predecessor_secrets_once` (seam-safe — a node copy
// writes the same marker). `import_secrets_once` below is the lower-level
// generation-keyed primitive, for a single-generation app-side round-trip.
match import_secrets_once(&mut ctx, &exported, successor_generation)? {
    ImportOutcome::Imported { imported, skipped, .. } => { /* wrote `imported` */ }
    ImportOutcome::AlreadyMigrated { .. }             => { /* no-op */ }
    ImportOutcome::StaleGeneration { .. }             => { /* older gen refused */ }
}
```

> **The transport is an internal, redesigned seam, not part of the app-facing
> API.** Apps call `migrate_delegate_secrets`; today it drives the interim
> app-side `DelegateRequest::ApplicationMessages` round-trips (as River/Delta do).
> When the node-side copy-forward lands (freenet-core#2776), it slots under the
> *unchanged* entry point — it copies secrets between namespaces internally
> without executing old code, killing the `ReRunOldWasm` / #204 landmine, and
> needs no app re-adoption. This is the plan-v2 correction over v1's
> `SecretTransport::export_from(predecessor) -> ExportedSecrets`, which could host
> neither transport (the interim path is async and uncorrelated; the node path
> returns nothing app-side).

### Known limitations

- **`ExportedSecrets` is not authenticated.** Its `source_generation` is echoed
  from the request and travels in an app-level envelope the crate does not sign.
  `import_secrets_once` bounds it against the successor's own generation so an
  injected export cannot poison the completion marker for an implausibly-high
  generation, but full authentication (signing the payload) is future work —
  tracked in [freenet-core#2776](https://github.com/freenet/freenet-core/issues/2776).
- **Pre-registry secret keys.** Secrets written before the host's key-enumeration
  registry (freenet-core #4355) are not returned by `list_secrets` until
  rewritten, and this is undetectable from inside the delegate. Migrating off
  such a delegate must rewrite those keys first or carry them app-side.
- **Interrupted-then-retried import.** The two-phase marker fully blocks
  resurrection after a *completed* migration, but a migration interrupted mid-way
  and then retried re-imports the still-missing keys and cannot distinguish "never
  imported" from "imported then user-deleted", so a key deleted during that narrow
  window can be resurrected by the completing retry.
- **Predecessor registration/availability (G1.8 preflight dependency).** The
  preflight can only tell "predecessor can't execute" from "predecessor has no
  data" while the node the request reaches actually has the predecessor delegate
  registered and available. (freenet-core retains delegate WASM indefinitely —
  only an explicit `UnregisterDelegate` removes it — so this is not time-decay;
  it is per-node registration/availability.) A predecessor the reached node never
  registered is indistinguishable from a broken one — both surface as
  `Unresponsive`, which the app must show rather than silently fresh-installing.
  The node-side copy-forward removes the dependency by reading storage directly.

## Building & testing

```bash
cargo test --all-features          # native tests for both crates
cargo clippy --all-targets --all-features -D warnings
# the delegate wasm bridge is confirmed to compile for wasm:
cargo build -p freenet-migrate --no-default-features --features delegate \
    --target wasm32-unknown-unknown
```

Key derivation is cross-checked **byte-for-byte** against stdlib's real
`ContractInstanceId::from_params_and_code` (see
`freenet-migrate/tests/codegen_stdlib_consistency.rs`).

## Status

The reusable core machinery + tests. 0.2.0 makes the codegen shape canonical
`[u8; 32]` (build-time-validated), accepts hex and base58 registries plus
River-style `[[entry]]` files, adds the byte-array view consts for existing
apps, and restores the `delegate_key` derivation cross-check. 0.3.0 adds the
sans-IO contract backward-probe decision driver + pumped `migrate_contract`
entry point. 0.4.0 adds the delegate-side app-facing entry points
(`migrate_delegate_secrets` / `register_delegate_with_migration`) with consent
(`MigrationAuthorization`) required from day one, the G1.8 executability
preflight (so a broken old delegate surfaces rather than silently
fresh-installing — freenet/river#204), and the redesigned sans-IO transport seam
a future node-side copy-forward (freenet-core#2776) swaps under with no app
re-adoption. Integrating River/Delta (pointing their `build.rs` at the codegen,
then swapping their migration internals for crate calls) is the current adoption
step ([freenet/river#398](https://github.com/freenet/river/issues/398)). Targets
current stdlib **0.8.x**.

## License

LGPL-3.0-only. See [LICENSE](./LICENSE).
