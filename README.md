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

**Contracts published from this repo: [FREENET.md](./FREENET.md)** — including the canonical successor-pointer contract.

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
                              driver.on_response(id, &bytes)  // answered with state
                              driver.on_absent(id)            // answered NotFound
                              driver.on_unknown(id)           // timer fired / send failed */ }
        Step::Done => break,
    }
}
match driver.take_outcome().unwrap() {
    Outcome::Recovered { merged, .. }  => { /* adopt + PUT under the CURRENT key */ }
    Outcome::SeedLocal { local }       => { /* asked everyone, found nothing THIS
                                               TIME: seed forward, but see below
                                               before recording it finished */ }
    Outcome::Indeterminate { .. }      => { /* a predecessor never answered: adopt
                                               NOTHING, retry on the next run */ }
    Outcome::NoLegacy { local }        => { /* fresh app, normal first-run */ }
}
```

**Silence is not absence** ([#19]). A candidate is a miss only when it
*answered* — with state that does not decode or is not real, or with a positive
"nothing here" (`on_absent`, from stdlib's `ContractResponse::NotFound`). A
timeout or transport failure is `on_unknown`: the candidate is recorded
unresolved, so a slow predecessor is retried rather than recorded empty
forever. Wire a real `NotFound` signal through if you have one; a probe whose
candidates answer properly never reaches `Indeterminate`.

**But `NotFound` is not proof either**, and on this network it is wrong more
often than it is right — see [Upgrading to 0.6.0](#upgrading-to-060). `SeedLocal`
means "asked everyone, found nothing this time"; the crate deliberately does not
tell you it is safe to record the migration as finished.

Decisions are fixed by the driver (probing newest-first; undecodable or
non-real responses and answered absences advance; an unanswered candidate stops
the walk under `NewestFirstWins` rather than falling through to an older
generation; late responses are single-shot ignored; an all-answered exhaustion
seeds the local snapshot; a `prepare_forward` hook strips
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

Optionally record an author-signed pointer from v1 → v2 for your own use. Note
this is a **local primitive only**: nothing addresses it, publishes it or
consumes it on the network, and it is not the ecosystem's forward-discovery
mechanism. For that, see 2c, which resolves the canonical pointer contract.
`SuccessorPointer` uses a different signing domain and message layout and the
two are not interchangeable.

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

### 2c. Forward discovery: resolving an author's pointer contract

Everything above looks **backward** — it walks an app's own lineage, which only
helps the app's own author. A **third party** that baked a key into its build
has no lineage to walk. For that, resolve the author's
[canonical pointer contract](./contracts/pointer-contract) (freenet-core#5194):
its address is derivable offline from `(author_vk, app_id)`, and its state names
the app's current `code_hash`.

> **Nothing has published a pointer yet.** The contract's WASM is frozen and
> CI-enforced, but it has not been published to the network and the first
> publish is gated on a manual end-to-end run (see the STOP box in
> [`contracts/pointer-contract/README.md`](./contracts/pointer-contract/README.md)).
> Until then a resolve returns `NeverPublished` if your transport reports a real
> "not found", and `Unavailable` if it cannot tell. So during this period a first-run
> consumer legitimately falls back to its baked-in key.

```rust,ignore
use freenet_migrate::{resolve_app_pointer, PointerFloor, PointerOutcome};

// `floor` is what you already verified, stored per (author_vk, app_id). It is
// the anti-rollback anchor. A consumer that knows the app's version and hash at
// build time should seed from those constants rather than starting empty: a
// first resolve has nothing to compare against and adopts any signed record.
//
// Store the withdrawal as its own fact, and rebuild through the matching
// constructor. `at` REFUSES an all-zero code hash: that is what a defaulted or
// half-written column looks like, and it is also the tombstone, so inferring a
// withdrawal from those bytes would let one bad row retire a healthy app
// permanently.
let floor = match load_floor(&AUTHOR_VK, b"river.room-contract") {
    Some(Stored::Withdrawn { version })      => PointerFloor::withdrawn_at(version)?,
    Some(Stored::Live { version, code_hash}) => PointerFloor::at(version, code_hash)?,
    None => PointerFloor::never_resolved(),
};

let outcome = match resolve_app_pointer(&mut io, &AUTHOR_VK, b"river.room-contract", floor).await {
    Ok(outcome) => outcome,
    // A rejected record says nothing about whether a pointer exists, so this
    // must never fall back. `err.may_use_baked_in_fallback()` is always false.
    // It is equally not a reason to STOP: this peer's answer was refused, not
    // the pointer. Answering one GET with 99 bytes is the cheapest hostile move
    // there is, and on a first run there is nothing last-resolved to keep, so
    // treating it as terminal would leave you with no key at all. Retry.
    Err(err) => return keep_last_resolved_and_retry(err),
};

// Persist first: this is what stops a later replay, including after a
// withdrawal (a tombstone is a signed record at a version like any other, so
// its version has to become your floor or a pre-withdrawal record replays).
if let Some(next) = outcome.next_floor() {
    if next.is_withdrawn() {
        store_withdrawn(&AUTHOR_VK, b"river.room-contract", next.version());
    } else {
        // A non-withdrawn advancing floor always carries a hash.
        let code_hash = next.code_hash().expect("a floor that advances carries a code hash");
        store_floor(&AUTHOR_VK, b"river.room-contract", next.version(), code_hash);
    }
}

match outcome {
    PointerOutcome::Resolved(p) | PointerOutcome::Unchanged(p) => {
        // Step 3, the one integrators get wrong: combine the pointer's
        // code_hash with YOUR OWN params, not the pointer's.
        use_key(p.contract_id(&my_own_params));
    }
    // The author withdrew the app. There is no current code; do not fall back.
    PointerOutcome::Withdrawn { .. } => stop_resolving(),
    // A peer served an older record. Routine on a freshly-bootstrapped node,
    // and not an attack signal. Already refused; keep whatever your floor says
    // (which may itself be a withdrawal) and retry.
    PointerOutcome::Stale { .. } => keep_last_resolved_and_retry(),
    // A DIFFERENT record at your own version lost the tiebreak, so your floor
    // stands. No record is handed back on purpose: the winner is your floor,
    // which this crate never treats as verified. Keep your key; do not derive
    // one from anything here.
    //
    // Two caveats, both about what "your key" means. If your floor is itself a
    // withdrawal, resuming with your last pre-withdrawal key resurrects the
    // code the author retired, out of your own memory — so check first. And on
    // a FIRST resolve from a build-time seed there is nothing last-resolved to
    // keep; see "A seeded floor can reach CompetingRecord" below.
    PointerOutcome::CompetingRecord { .. } if floor.is_withdrawn() => stop_resolving(),
    PointerOutcome::CompetingRecord { .. } => keep_last_resolved_and_retry(),
    // The ONLY case where falling back to your build-time key is safe.
    PointerOutcome::NeverPublished => use_baked_in_key(),
    // Timed out, unreachable, or an empty body. Never downgrade on this.
    PointerOutcome::Unavailable => keep_last_resolved_and_retry(),
    // `PointerOutcome` is #[non_exhaustive]: a future variant must not silently
    // take a fallback path, so treat anything unrecognised as "learned nothing".
    _ => keep_last_resolved_and_retry(),
}
```

Signature verification is local and never trusts the responding node, and
`ResolvedPointer` has no public constructor, so the only way to hold one is to
have resolved it — including in the tiebreak cases: no outcome is ever built
from the floor's `code_hash` bytes, because whatever can write your floor store
would otherwise be choosing your key. `may_use_baked_in_fallback()` exists on
both the outcome and the error so no caller has to re-derive when a fallback is
legitimate: only `NeverPublished`, ever.

### A seeded floor can reach `CompetingRecord` on its first resolve

Seeding from build-time constants is the recommendation above, and it has one
consequence to handle. If the author published two records at the seeded version
— a retried or threshold-signed publish, the only way two valid records exist at
one version — and your seed is the lower-hashed of the pair, then every resolve
returns `CompetingRecord` until the author publishes *v+1*. On a first run that
leaves you with nothing: no record, `may_use_baked_in_fallback()` false, and no
advancing floor.

A seeded consumer is not stuck there. Its floor holds a constant compiled into
its own binary, so it may derive its key from **that constant** — the same value
it would have used on `NeverPublished`. That is not the laundering this crate
refuses. This crate will not read the floor's bytes because it cannot tell a
genuine seed from a tampered store; you can, because you know where your own
floor came from. Nor is it a downgrade: both records at a contested version are
author-signed, the network's `merge` converges on the lower code hash, and
reaching `CompetingRecord` *means* your floor is that lower hash, so using it
agrees with the tiebreak rather than overriding it.

The condition is provenance, not the variant. Derive from your floor only where
you know it came from your own binary or your own prior verified resolution, and
only after the `is_withdrawn()` check — a withdrawal floor reaches this variant
too, and there "keep your key" would resurrect what the author retired. A
consumer whose floor lives somewhere writable has learned nothing here and should
keep its last key and retry.

There is deliberately no separate `PointerFloor::seeded_at`. Splitting the
constructor would only record your *claim* about provenance, since the bytes
arriving are identical either way, so the resolver would be trusting an assertion
it cannot check — and any caller that loaded a stored floor through the seeded
constructor by mistake would get the fail-open back. Provenance stays on the side
of the boundary that actually holds it.

Reaching `NeverPublished` needs a `PointerIo` that can report a real
`PointerFetch::Absent`. Implementing `PointerIo` directly is the recommended
path. `ConservativeProbeIo` wraps an existing `ProbeIo` and is useful for
reusing plumbing you already have; since 0.6.0 its mapping is faithful
(`ProbeAnswer` is three-way too), so it passes a real negative through, with one
inherited cost: `ProbeIo`'s GET is specified with `return_contract_code: true`,
so it pulls the pointer's ~130 KB WASM on every resolve to read a 100-byte
record.

Note also that absence is unauthenticated: Freenet has no proof a contract has
no state, so a responding node can always claim "not found". That is why the
fallback is confined to the case where nothing has ever resolved, where the
worst outcome is the key the consumer already shipped with.

**Trust model:** the `author_vk` you pass in is the entire trust anchor. Per
freenet-core#5194's settled decisions there is no delegated signing and no
in-protocol rotation; rotation is by convention, so publishers should use a
dedicated long-lived pointer key kept offline. A stolen author key is
unmitigated at this layer.

Two limits on recency, in opposite directions. **Backward replay is bounded** by
the floor: nothing that loses to what you already verified is adopted.
**Forward suppression is not bounded, and cannot be at this layer**: a peer that
answers every GET with a genuine, correctly-signed but superseded record holds
you on old code indefinitely, and you cannot detect it — the 100-byte state
carries no timestamp or freshness proof, and the contract's WASM is frozen, so
adding one would re-key every published pointer. What stays bounded is *what*
you can be held on: every record adopted is one the author signed for this exact
app, so suppression can stall an upgrade but never substitute code. The
mitigation is operational: resolve repeatedly over time, since a single honest
response advances the floor for good.

### 3. Delegate secret carry-forward (runtime)

**The app-facing entry point is `migrate_delegate_secrets`** — carry each
predecessor delegate's secrets forward into the successor, with consent required
from day one. The transport underneath (app-side round-trips today, a node-side
copy tomorrow) is an internal detail apps do not program against — that altitude
is the whole point, so a future node copy-forward is a drop-in with no app
re-adoption.

Both ends are thin app-supplied adapters: **`PredecessorSecretsIo`** reads the
predecessors, and **`SuccessorSecretsIo` — the app's own import path — writes the
successor**. The crate decides *what* to migrate; the app does the *writing*.

```rust,ignore
use freenet_migrate::{
    migrate_delegate_secrets, ItemWrite, MigrationAuthorization, PredecessorSecretsIo,
    RecoveredSecret, SecretSelectionPolicy, SuccessorSecretsIo,
};

// `io` implements PredecessorSecretsIo: `probe_executable` sends a cheap no-op to
// an old delegate key (G1.8 preflight); `fetch_secrets` enumerates its secrets —
// both in the app's own delegate protocol (DelegateRequest::ApplicationMessages),
// with the app's own response correlation (a browser has no request/response
// correlation, so the app supplies it — e.g. a per-request oneshot side-table).
//
// `successor` implements SuccessorSecretsIo: `write_secret` applies ONE recovered
// item through the app's own import path, so every invariant the app maintains at
// import time survives the migration (see "Why the app does the writing" below).
// The report is the source of truth: transport errors become report rows, never a
// bare error that would discard the predecessors already migrated.
let report = migrate_delegate_secrets(
    &mut successor,                              // the app's own import path
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
    } else if report.retry_may_help() {
        // Something failed transiently. Safe to retry: re-run
        // migrate_delegate_secrets (completed predecessors are no-ops).
    } else {
        // Only permanently-rejected items remain (`report.rejected_total()`).
        // Retrying will refuse them identically forever — surface them.
    }
}
```

#### Why the app does the writing

Before 0.5.0 the successor end was a raw `(key, value)` copy into a `SecretStore`,
one pair at a time, never-clobber. That is wrong for any app whose stored items
carry **cross-entry invariants**, and it fails *silently*.

The measured case is ghostkeys ([freenet/ghostkeys#32]), which stores each
credential as several entries plus one `gk:index` entry listing which credentials
exist, and one permission grant per credential. A raw pair copy skips exactly four
things ghostkeys' own `ImportGhostKey` handler does:

1. records a **permission grant** — without it the item is unusable even if listed;
2. adds to the **index** the UI reads — without it the item is invisible;
3. **verifies the certificate chain** against the compiled-in master key;
4. **derives the fingerprint** delegate-side.

So the recovered credential's bytes land in the store while nothing lists them and
nothing may read them: permanently invisible, no error. **No `SecretSelectionPolicy`
fixes this** — `UnionAllGenerations` recovers both generations' bytes and the older
index write is still clobber-skipped — because the mover cannot know that entry
needs *merging* rather than *replacing*. Re-run under review, 13 of 14 differential
scenarios disagree between a raw-pair copy and the app's own import path; the single
agreement is the case where nothing is recovered.

An index-merge hook would have fixed one of the four. Routing the write through the
app's own handler fixes all four. That is the argument for the seam: **the mover can
never know an app's invariants and should not try.**

Apps whose secrets genuinely stand alone keep the old behaviour in one line with
`SecretStoreIo`, the raw-pair never-clobber writer over a `SecretStore` (the natural
choice for a delegate-side import over `DelegateCtx`) — gated behind the loud
`NoCrossEntryInvariantsAck` so the choice is visible at the call site:

```rust,ignore
use freenet_migrate::{NoCrossEntryInvariantsAck, SecretStoreIo};

let mut successor = SecretStoreIo::new(
    &mut ctx,
    NoCrossEntryInvariantsAck::i_certify_these_secrets_have_no_cross_entry_invariants(),
);
```

**Aggregate secrets are read-merge-write.** The seam makes correct behaviour
possible; it does not make it automatic. An item whose value is a collection — an
index, a list, a count — must be merged into what the successor already holds. The
two ways to get it wrong are mirror images: *skipping* the write hides entries
(ghostkeys' `gk:index` under never-clobber), while *overwriting* deletes them
(Delta's `StoreKnownSites { sites }` replaces the whole list, so forwarding a
predecessor's `known_sites` straight into it destroys every site the user added on
the new version). Only the app knows which of its secrets are aggregates.

[freenet/ghostkeys#32]: https://github.com/freenet/ghostkeys/pull/32

#### Partial failure, and what a retry is worth

`write_secret` returns `ItemWrite::Written`, `AlreadyAuthoritative` (the successor's
own value stands — already held, or not the app's to copy verbatim), or
`Failed { error, retry }` — where `retry` is `Retryable` or `Permanent`.
`AlreadyAuthoritative` is **not an error channel**: an `Err(_) => …` arm mapped onto
it counts as `skipped`, which reads as success, so the predecessor is sealed and
never walked again. A failed write is `retryable` or `permanent`; when in doubt,
`retryable`. Per predecessor the report carries an `ImportTally`
(`written` / `skipped` / `failed` / `rejected` / `withheld`) plus the first
successor-side failure and the stage it happened at, so an app learns what landed,
what did not, and whether retrying can change anything
(`DelegateMigrationReport::retry_may_help`). A predecessor with anything unresolved
does not get a completion marker, so a retry re-runs it.

**Termination is a policy question, not a failure question.** Before 0.5.0 a partial
write halted the walk under *both* policies, so one storage failure on one key of the
newest predecessor marked every older generation `Superseded` and recovered nothing
from them — even under `UnionAllGenerations`, whose purpose is to walk every
generation. Now a data-bearing predecessor is authoritative under
`NewestSnapshotWins` whether or not its writes all landed (unchanged), and Union
walks on. The one thing the old halt bought is kept by a narrower mechanism: a key
whose write failed *retryably* is **withheld** from older predecessors for the rest
of the run, so an older generation cannot shadow a newer value awaiting a retry. A
*permanently rejected* key is not withheld — an older copy of it may be acceptable.

The same withholding covers a **failed flush**, which is the durability boundary for
a buffering writer: such a writer answers `Written` optimistically and loses the
batch, so a flush failure withholds every key that predecessor resolved (`Written`
and `AlreadyAuthoritative` alike — "already authoritative" can itself be unflushed
buffer state) and re-counts its optimistic `written` as `failed`, so
`imported_total()` never reports data a discarded buffer took with it.

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
anti-resurrection marker (idempotent, never clobbers existing keys). There are two
import primitives: `import_predecessor_secrets_once` (delegate-key-keyed, the
seam-safe one the entry point drives) and the lower-level `import_secrets_once`
(generation-keyed). **Do not mix the two on one delegate's store** — the entry
point defensively honors a legacy generation marker, but the generation-keyed
markers are not what a future node copy-forward writes, so pick one API per store:

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
re-adoption. 0.5.0 reshapes the delegate half so the crate decides what to
migrate and the app does the writing; it is breaking on the delegate half only,
leaving the contract-side surface untouched.

**Published:** `freenet-migrate` **0.5.0**, `freenet-migrate-build` **0.2.0**.
The two halves version independently, so an app can take one without the other.
Targets current stdlib **0.8.x**.

**Unreleased: 0.6.0**, breaking on the **contract** half — silence is no longer
absence ([#19]). Four of the five adopters below need a code change, three of
them to compile at all. See [Upgrading to 0.6.0](#upgrading-to-060) and the
CHANGELOG.

### Adopters

The adoption tracked by
[freenet/river#398](https://github.com/freenet/river/issues/398) has landed.
Five apps now use the crate, and both halves have adopters.

| App | `freenet-migrate` | `freenet-migrate-build` | Migrates |
|-----|-------------------|-------------------------|----------|
| [River](https://github.com/freenet/river) | 0.5 | 0.2 | delegate + contract |
| [Delta](https://github.com/freenet/delta) | 0.5.0 | none | delegate + contract |
| [ghostkeys](https://github.com/freenet/ghostkeys) | 0.5.0 | none | delegate |
| [Atlas](https://github.com/freenet/atlas) | 0.5.0 | 0.2.0 | contract |
| [freenet-git](https://github.com/freenet/freenet-git) | none | 0.2.0 | contract (registry codegen) |

River and Delta each run the crate alongside the hand-rolled sweep they
already had, a deliberate dual-running period that ends when the walk is
field-validated and the sweep is retired. Delta takes the runtime half only
and still hand-rolls its build-time registry codegen.

freenet-git takes the build half only, and the reason is a hard constraint
rather than a scheduling one. The runtime half is built against
freenet-stdlib 0.8.x while that workspace is on 0.6.0, and stdlib exports
`__frnt_set_id` as an unconditional `#[no_mangle] extern "C"` symbol
(`rust/src/global.rs:4-5`), so linking two stdlib versions into one binary is
a hard duplicate-symbol error under rust-lld. Adopting the runtime driver
there is blocked on that workspace moving to stdlib 0.8, which re-keys every
repo and is its own migration event.

## Upgrading to 0.6.0

0.6.0 makes a predecessor's **silence** distinct from its **absence** ([#19]).
The whole migration is one decision, made once at the point where your transport
turns a GET into a result:

| Your transport saw | Answer with | Driver event |
|---|---|---|
| state bytes | `ProbeAnswer::State(bytes)` | `on_response(id, &bytes)` |
| the node's real "not found" — stdlib's **`ContractResponse::NotFound`** | `ProbeAnswer::Absent` | `on_absent(id)` |
| timeout, send failure, dropped transport, cancelled correlation slot, an unexpected reply | `ProbeAnswer::Unknown` | `on_unknown(id)` |

`ProbeIo::get` returns `ProbeAnswer` in place of `Option<Vec<u8>>`;
`ProbeDriver::on_timeout` is deprecated and forwards to `on_unknown`, so
untouched call sites get the *safe* reading — but that preserves behaviour, not
compilation, and an exhaustive `match` over `Outcome` still has to gain an
`Indeterminate` arm.

Then handle the new outcome. `Outcome::SeedLocal` now means "every candidate was
asked and answered, and none had state" — which is evidence that there is nothing
to recover, **not proof of it**, for the reasons below;
`Outcome::Indeterminate` means at least one candidate's state was not
established, so adopt nothing, seal nothing, and retry on the next run.

**The crate cannot do this mapping for you, and deliberately does not try.** It
is sans-IO because each adopter reaches the network differently — River's UI
through a shared-handler `WebApi` with no request/response correlation, Atlas
through its own client wrapper, Delta through its ws layer — so there is no
single response type a helper could accept. What is common is the *rule*, which
is the table above; `ContractResponse::NotFound` is the one stdlib variant that
earns `Absent`, and everything else that is not state is `Unknown`.

### `Absent` is the strongest negative Freenet can give. It is not proof.

Absence is unauthenticated — any responding node can claim "not found" — and a
contract that genuinely exists answers that way while it is momentarily
unfindable. **On the current network that is the common case:** with the
placement migration disabled (freenet-core#4440), present-but-unfindable
dead-ends measured ~99.6% of all `get_not_found` traffic in production
telemetry, and a live-network check found 20 of 25 apparent failures had a
`NotFound` logged for a key that exists.

This is a limit of the network, not of this crate, and it is why `SeedLocal`
does not claim to be sealable. Advancing the probe past an `Absent` candidate is
fine — that is all the crate does with it. Concluding the data is gone is not.

If your app must seal something, harden it:

* **Make it idempotent** so a later run recovers a generation that was
  momentarily unfindable, and tell the operator to re-run. Atlas is the worked
  example: it prints the not-found generation loudly and says re-running will
  pick it up.
* **Require agreement across separate attempts**, spread in time, rather than
  acting on one walk. One `Absent` is a data point; the same `Absent` on three
  runs over an hour is evidence.
* **Require a connectivity witness** — a GET for something you know exists
  succeeding in the same window — before trusting a negative at all.
* **Never let a single all-`Absent` walk trigger an irreversible write.**

Note also that an undecodable answer is a miss too, so a schema break across an
entire lineage produces `SeedLocal` with every generation intact underneath it.
Making that distinguishable is [#8].

### The `on_timeout` shim is not a drop-in

`on_timeout` forwarding can never seal a predecessor as empty, so it is safe in
the way that matters most. It is **not** safe for a call site that also routed
positive not-founds through it. Because an unknown halts the walk under
`NewestFirstWins`, an app whose only failure path is a watchdog — one that never
handles `NotFound`, so an absent generation arrives as a timeout — stops at its
first empty generation and never asks the older ones. If the data lives further
down the lineage it is never probed, and every probe ends `Indeterminate`. That
is a recovery **outage**, not a conservative degradation. River is this shape
today.

## License

LGPL-3.0-only. See [LICENSE](./LICENSE).

[#19]: https://github.com/freenet/freenet-migrate/issues/19
[#8]: https://github.com/freenet/freenet-migrate/issues/8
