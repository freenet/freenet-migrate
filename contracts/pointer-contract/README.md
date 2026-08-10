# freenet-pointer-contract

A contract with a **stable key** whose state names the **current code hash** of
an app's real contract or delegate.

```
version: 12
code_hash: 9xH2…            <- the app's current WASM hash
```

That is the entire state. Everything else in this README is about how to use it.

> ### This solves ADDRESSING ONLY. Read this before you build on it.
>
> The pointer tells you **which code hash is current**. It says **nothing about
> whether any state or any secret held under the previous key survived the
> re-key.** Those are two different problems, and only the first one is fixed.
>
> Concretely, as of 2026-08: a design review of River found that delegate
> secrets written to its dedicated secure namespace do **not** survive a
> delegate re-key, while secrets written to its readable blob **do**, because
> the migration probe only reaches the latter. River re-keys roughly weekly.
>
> So an integrator who resolves a pointer, derives the new key, and assumes the
> user's data came with it will be wrong, and wrong in a way that looks like
> "this user has no data" rather than like an error. Resolving the pointer
> correctly is necessary for a safe upgrade and nowhere near sufficient.
>
> What you get here: you can tell "the thing I was built against moved" apart
> from "this user has no data" — which is exactly the distinction that was
> missing during the ghostkeys incident, and enough to surface an honest message
> instead of a misleading one. What you do **not** get: any guarantee that
> reading the new key returns what the old key held. Verify data survival
> separately, per artifact, and treat it as unsolved until you have.

## Why it exists

A Freenet contract or delegate key is `BLAKE3(BLAKE3(wasm) ‖ params)`. Any byte
change to the WASM — a bug fix, a dependency bump, even a version-string bump —
produces a different key.

The author carries their own data forward (freenet-migrate's backward probe and
fold for contracts, `RegisterDelegateWithPredecessors` for delegate secrets).
A **third party** cannot: its reference is a build-time constant, and after the
upgrade it silently addresses a stale, empty namespace. It cannot even tell
"this user has no data" apart from "the thing I was built against moved".

On 2026-08-03 the ghostkey delegate re-keyed twice, for release-hygiene reasons
with no behaviour change. Integrations kept talking to the old delegate. The
first signal anyone got was a user being told to buy a Ghost Key they already
owned (freenet/ghostkeys#21).

This contract is the missing forward reference. See
[freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194).

---

## Consumer side: resolving a pointer

> ### Rust integrators: use the `freenet-migrate` resolver, not the steps below
>
> `freenet-migrate` ships `freenet_migrate::pointer`, a resolver built directly
> against this contract's wire format. It carries the anti-rollback floor, the
> absence-vs-unreachability distinction, and key derivation, none of which a
> hand-rolled `PointerRecord::decode_verified` call gets for free. Each
> integrator that decodes records itself has to re-derive the rules in Step 4
> below on its own.
>
> ```rust
> use freenet_migrate::pointer::{resolve_app_pointer, PointerFloor, PointerOutcome};
>
> // The floor starts at `PointerFloor::never_resolved()`, or better, seeded
> // from your build-time constants. Persist `outcome.next_floor()` — including
> // for a withdrawal — and pass it back next call, keyed by (author_vk, app_id).
> let outcome = resolve_app_pointer(&mut io, &author_vk, b"river.room-contract", floor).await?;
>
> match &outcome {
>     // Your own instance's params, never the pointer's.
>     PointerOutcome::Resolved(r) | PointerOutcome::Unchanged(r) => {
>         use_key(r.contract_id(&my_own_params))
>     }
>     // The author retired the app. There is no current code; do not fall back.
>     PointerOutcome::Withdrawn { .. } => stop_resolving(),
>     // The only case where your build-time key is safe.
>     PointerOutcome::NeverPublished => use_baked_in_key(),
>     // Stale, CompetingRecord, Unavailable, and any future variant: nothing was
>     // learned, so keep the key you last derived and retry. Never downgrade.
>     // Two of these need care when your floor is a withdrawal or a first-run
>     // build-time seed — see the crate README's full match.
>     _ => keep_last_resolved_and_retry(),
> }
> ```
>
> Handle every arm. A bare `if let Some(record) = outcome.resolved()` silently
> does nothing on the five outcomes that carry no record, which is how a
> withdrawal, a downgrade attempt, and a plain timeout all become "no output".
>
> `io` implements the `PointerIo` trait (an async `PointerFetch` GET); wrap an
> existing `ProbeIo` with `ConservativeProbeIo` if you have one already. See the
> module docs on `freenet_migrate::pointer` for the full API
> (`PointerResolver` is the sans-IO driver for environments without awaitable
> request/response correlation, e.g. the browser's shared-handler `WebApi`).
>
> The rest of this section documents the same resolution by hand: the wire
> format and the raw `PointerRecord` path. It is what the resolver above does
> internally, and it is still where you should look if you are implementing a
> consumer in a language other than Rust, or want the primitives directly.

This is the part integrators get wrong, so here it is exactly.

### The shapes

**Params** — a fixed byte layout, never a serde encoding:

```
author_verifying_key (32 bytes, Ed25519)  ‖  app_id (1..=64 bytes)
```

`app_id` bytes are restricted to `a-z`, `0-9`, `.`, `-`, `_`. Lowercase-only
and ASCII-only, so there is nothing to normalize and no case-confusable or
Unicode-lookalike variant of an app's identity.

**State** — a fixed byte layout, exactly 100 bytes:

```
version (u32, big-endian)  ‖  code_hash (32 bytes)  ‖  signature (64 bytes)
```

`signature` is Ed25519 over
`b"freenet-pointer/state-v1" ‖ params ‖ version_be ‖ code_hash`, made by the
private key matching `author_verifying_key`. The message covers the **whole
params blob**, so a record signed for one app cannot be replayed into another
pointer belonging to the same author.

### Step 0 — depend on this crate

```toml
[dependencies]
freenet-pointer-contract = { git = "https://github.com/freenet/freenet-migrate", rev = "<pin a commit>" }
```

**Pin a `rev`.** Without one you get a floating dependency on the default
branch, which is a strange thing to accept from a crate whose entire premise is
that its bytes never move. It cannot re-key anything — the code hash you embed
is a constant, not something this crate computes — but a resolver that silently
changes your `PointerRecord` parsing is not what you want either.

You do **not** need `default-features = false`: the default feature set is empty
(`default = []`), and the four `#[no_mangle]` WASM entry points are gated behind
`freenet-main-contract`, which is off unless you ask for it. Just never enable
that feature in a native consumer — those exports carry no target gate, so they
would land in your binary and collide at link time with any other contract crate
in your graph.

There is no crates.io release on purpose: a published source crate invites
rebuilding the WASM locally, and a locally rebuilt WASM has a different code
hash, which is a different and empty contract.

### Step 1 — compute the pointer's own key

You need three things, all of which you have at build time: the published
pointer code hash (`CODEHASH` in this directory, a constant you embed — see
"Never rebuild this WASM" below), the author's verifying key, and the `app_id`.

Where does the author's verifying key come from? From the app's own
`FREENET.md`, pinned as a constant in your build, exactly like the code hash.
That 32-byte value is the entire trust anchor: take it from the wrong place and
you will resolve a validly-signed pointer belonging to somebody else.

```rust
use ed25519_dalek::VerifyingKey;
use freenet_pointer_contract::{PointerParams, PointerRecord};
use freenet_stdlib::prelude::{CodeHash, ContractKey, DelegateKey, Parameters};

/// Both constants are pinned at build time and never recomputed.
const POINTER_CODE_HASH: &str = "8wnAPaSRY1oYZCz723fdwK6BgzL6q8ozP3buVovXnt6v";
const AUTHOR_VK: [u8; 32] = [/* from the app's FREENET.md */];

type Error = Box<dyn std::error::Error>;

fn pointer_key() -> Result<(ContractKey, Vec<u8>), Error> {
    let author_vk = VerifyingKey::from_bytes(&AUTHOR_VK)?;
    let params = PointerParams::encode(&author_vk, b"ghostkeys.ghostkey-delegate")?;
    let key = ContractKey::from_params(POINTER_CODE_HASH, Parameters::from(params.clone()))?;
    Ok((key, params))
}
```

`PointerError` implements `std::error::Error`, so it composes with stdlib's
`bs58::decode::Error` under a boxed error and `?` works throughout.

That is `BLAKE3(pointer_code_hash ‖ params)`. It never changes.

### Step 2 — GET it and verify

```rust
/// `state` is the 100 bytes an ordinary GET for the pointer key returned.
fn resolve(state: &[u8], params: &[u8]) -> Result<PointerRecord, Error> {
    let record = PointerRecord::decode_verified(state, params)?;
    // record.version   -> monotonic
    // record.code_hash -> the app's CURRENT wasm hash
    Ok(record)
}
```

`decode_verified` is the only call the accept path should make: it parses the
params, decodes the record, rejects `version == 0`, and checks the signature.
Decoding without verifying would accept anything anyone put on the wire.

### Step 3 — derive the key you actually wanted

**This is the step people get wrong.** The pointer does *not* tell you a
contract key. It tells you a *code hash*. You combine that with **your own
instance's params** — the room owner's key, your delegate's config, whatever it
is for you — to get your key:

```rust
/// `my_own_params` are YOUR instance's params, not the pointer's.
fn derive_contract(record: &PointerRecord, my_own_params: Vec<u8>) -> Result<ContractKey, Error> {
    let code_hash_b58 = CodeHash::new(record.code_hash).encode();
    Ok(ContractKey::from_params(
        &code_hash_b58,
        Parameters::from(my_own_params),
    )?)
}

fn derive_delegate(record: &PointerRecord, my_own_params: Vec<u8>) -> Result<DelegateKey, Error> {
    let code_hash_b58 = CodeHash::new(record.code_hash).encode();
    Ok(DelegateKey::from_params(
        &code_hash_b58,
        &Parameters::from(my_own_params),
    )?)
}
```

Both compute `BLAKE3(code_hash ‖ your params)`, which is exactly what a node
computes when it holds the code. Both paths are pinned against stdlib's own
derivation — `consumer_derivation_matches_stdlib` for contracts and
`consumer_delegate_derivation_matches_stdlib` for delegates — so this
documentation cannot drift from what the network actually does.

Two traps:

- **Use your own params, not the pointer's.** The pointer's params identify the
  pointer. Yours identify your instance. This is precisely why the state carries
  no `current_key` field: one pointer serves *every* instance of an app — every
  River room, every delegate registration — and a `current_key` could only ever
  have been right for one of them.
- **Keep both halves of the key.** `from_params` returns a `ContractKey`
  carrying both the instance id and the code hash. An UPDATE takes a full
  `ContractKey` while a GET takes only a `ContractInstanceId`, so a consumer
  that stores just the instance id can read but can never write
  (freenet-core#4978). Keep the whole thing.

Detecting staleness needs nothing further: compare the derived key against the
one you were built with. To fetch the code, GET the derived key with
`return_contract_code: true`; `BLAKE3(fetched wasm) == record.code_hash` is a
free integrity check.

### Step 3a — when the code hash cannot be fetched

A pointer can verify perfectly and still name code you cannot get. That is a
normal condition on this network, not an edge case: hosting is demand-driven and
contracts are evicted when demand drops, and the project accepts a residual
~5-9% near-miss rate on finding a contract that does exist.

So distinguish three outcomes, and do not collapse them:

| Outcome | Meaning | What to do |
|---|---|---|
| Pointer resolves, derived key fetches | Normal | Proceed. |
| Pointer resolves, derived key does not fetch | The app is current; this lookup did not land | **Retry with backoff.** Keep using the derived key — it is correct. Do not fall back to your baked-in key, and do not alarm on the first failure. |
| Pointer does not resolve at all | Unknown | Step 4's rule: last-known-good if you have one, baked-in only if a pointer has *never* resolved here. |

Alarm only if the derived key stays unfetchable across several attempts spanning
minutes, and report it as "the current version could not be fetched", never as
"you have no data" — conflating those two is the original sin this contract
exists to correct.

A verified pointer whose `code_hash` is all zeros is a **tombstone**: the author
has withdrawn the app. Stop resolving and say so. Do not derive a key from 32
zero bytes; it addresses a contract that does not exist.

**Persist the withdrawal's version as your floor before you stop.** A tombstone
is an ordinary signed record at a version like any other. A consumer that stops
resolving without recording that version leaves its floor at the pre-withdrawal
value, and any peer can then serve a real, validly signed pre-withdrawal record,
which supersedes that stale floor and resurrects code the author explicitly
withdrew.

Persist the **fact** of the withdrawal — a flag, or a distinct row state —
alongside the version, and rebuild the floor from that fact. Do **not** store it
as a zeroed `code_hash` column and treat it like any other floor: a defaulted or
half-written hash column has the same bytes, so a consumer that infers withdrawal
from those bytes lets one bad row retire a healthy app permanently. Rust
integrators have a constructor per case — `PointerFloor::withdrawn_at(version)`
for a withdrawal, `PointerFloor::at(version, code_hash)` otherwise — and `at`
**rejects** an all-zero hash for exactly that reason.

If `at` does reject your stored floor, the floor store is untrustworthy: surface
it. Never recover with `unwrap_or_else(|_| PointerFloor::never_resolved())`. That
is the first thing to reach for and it reinstates the fail-open the rejection
exists to close — it turns a corrupt floor into "first run", the one state that
unlocks the baked-in build-time key, which is the same resurrection this
paragraph is about, reached by a different route.

Also note that the tombstone sorts below every real code hash. Once your floor is
a withdrawal at version *v*, a replayed pre-withdrawal record at *v* loses the
equal-version tiebreak rather than being reported as a withdrawal, so a consumer
that treats "the tiebreak went my way, keep my last key" as its recovery path
resurrects the app from its own memory. Check whether your floor is a withdrawal
before resuming with any key (`PointerFloor::is_withdrawn`).

### Step 4 — persist the right thing

Persist `(highest_version_ever_verified, code_hash_accepted_at_it)`, not merely
"I know a pointer exists". Keep one such pair **per `(author_vk, app_id)`**:
each pointer has its own address and its own independent version space, so a
shared floor either rejects good records or carries a bound that is too low.

- Reject any record whose `version` is strictly less than your highest ever
  seen. The contract enforces monotonicity across the network, but a node that
  holds no copy yet (freshly bootstrapped, recently evicted) can transiently
  serve an older validly signed record, because `validate_state` has no prior
  state to compare against. Your own high-water mark is what closes that
  window for you.
- At an **equal** version, a byte-identical record is a no-op: keep what you
  have. A record that is equal in version but names a **different** code hash
  can only come from the author signing two records at the same version (a
  retried or threshold-signed publish); break the tie the same way the
  contract's own `merge` does, on the **lower** code hash, so that two
  consumers who saw different equal-version records converge on the same
  answer instead of splitting permanently.
- Fall back to your baked-in key **only if a pointer has never resolved on this
  install**. Once one has, an unresolvable pointer means *unavailable* — say so,
  or use the last-known-good resolved key. Silently regressing to the baked-in
  key would turn "make the pointer briefly unreachable" into a working, keyless
  downgrade to a stale key, which is the exact failure this contract exists to
  prevent.
- Re-resolve periodically and on every reconnect. SUBSCRIBE is a best-effort
  accelerant, not the mechanism: subscriptions are dropped and not
  re-established across a client reconnect (freenet/river#556), so a dead
  pointer subscription is currently silent and looks exactly like "nothing
  changed".

---

## Publisher side

Enable the `publish` feature for the signing helpers.

```rust
let params = PointerParams::encode(&author_vk, b"river.room-contract")?;
let record = freenet_pointer_contract::sign_record(
    &author_sk,
    &params,
    version,                       // strictly greater than the last published
    blake3_of_your_new_wasm,
)?;
// PUT (first publish) or UPDATE (every later one) `record.encode()` at the
// pointer key from Step 1.
```

> ### STOP — do not publish yet. One manual check is required first.
>
> The artifact is frozen, CI-enforced, and loads in a real WASM runtime. But
> **nothing has ever executed this contract's logic on `wasm32`**, and nothing
> has exercised the bincode boundary end to end. The unit tests run the same
> Rust compiled natively; the conformance suite loads the module and checks its
> shape, but never calls the four entry points.
>
> So a `wasm32` backend miscompile in `curve25519-dalek` or `blake3`, or a
> `ContractInterfaceResult` encoding mismatch, is invisible to **both** suites.
> A signature check that silently misbehaves only on `wasm32` would pass
> everything in this repository.
>
> **Required before the first publish — about an hour, against a real local
> node:**
>
> 1. PUT a signed record. Confirm it lands and a GET returns the same 100 bytes.
> 2. GET it back and verify the signature client-side, so the round trip is
>    checked and not just the storage.
> 3. Push a **stale** record (lower version). Confirm it is refused, and that the
>    stored record is unchanged.
> 4. Push a **forged** record (right shape, wrong signer). Confirm it is refused.
>
> Steps 3 and 4 matter most: they are the paths where a `wasm32`-only fault
> would look like success rather than like a crash.
>
> Why this blocks publishing and not merging: merging only lands code, and code
> can be changed. Publishing is the moment the freeze becomes load-bearing —
> integrators start deriving keys from this code hash and can no longer be moved
> off it. A fault found before the first publish is an ordinary edit; found
> after, it is a flag day that re-keys every pointer in the ecosystem.
>
> **The durable follow-on**, tracked separately and NOT a substitute for the
> manual run: freenet-core exports `ContractRuntimeInterface` from `dev_tool`
> (it is `pub use`d in its private `wasm_runtime` module today) and drives all
> four entry points against `pointer-v1.wasm` in its own CI. That belongs there
> rather than here because the value is a host we do not control saying no —
> reimplementing the handshake locally would only prove this repository agrees
> with itself.
>
> This box is the gate. Delete it in the commit that records the manual run, and
> not before.

**PUT the committed `pointer-v1.wasm`, and check its hash against `CODEHASH`
first.** Do not build the WASM yourself as part of your release. Building it
locally and PUTting your own bytes silently forks the convention: your pointer
lands at a key nobody else derives, so it is invisible to every consumer while
looking, to you, like a successful publish.

Three further operational requirements, none of which the contract can enforce
for you:

1. **Gate `version` on a single committed monotonic counter**, the way River's
   `published-contract/contract-version.txt` does. Two release machines, or a
   retry after a flaky PUT, can otherwise sign two different records at the same
   version. The contract breaks that tie deterministically rather than letting
   the network split permanently, but it breaks it by comparing hashes, which
   has nothing to do with which one you meant.
2. **Treat the author key as a root key**, not a release key. Offline or
   threshold custody, from day one. Losing an ordinary release key means
   shipping a new app and telling people; losing this one means every consumer
   is permanently, authoritatively pointed at a record that nothing can
   supersede. There is no recovery.
3. **Check that your publish actually landed.** A publish at an already-used
   version is a no-op *success* — the contract deliberately does not error on a
   stale update, because erroring would turn routine anti-entropy from a peer
   that is merely behind into a merge failure. So the network will not tell you
   your release was ignored. Re-read the pointer after publishing and confirm
   the version and code hash are the ones you intended.
4. **Choose `app_id` once.** It is part of the params, so it is part of the key.
   Changing it is publishing a different pointer. Convention:
   `<project>.<artifact>`, e.g. `river.room-contract`, `river.chat-delegate`,
   `ghostkeys.ghostkey-delegate`. Name the artifact, not its kind — this is why
   the state carries no `kind` field.

---

## Never rebuild this WASM

Embed the code hash from `CODEHASH` as a **constant**. Do not derive it by
rebuilding this crate locally, and do not let a build script substitute a
locally-computed hash.

If the pointer's own WASM changes, the pointer's own key changes, and the
problem recurs one level up with nothing left to point at the pointer. That
asymmetry — an app that re-keys is recoverable through its pointer, a pointer
that re-keys is not recoverable at all — is why this crate is pinned, frozen,
path-remapped, and CI-checked. See [WASM-STABILITY.md](WASM-STABILITY.md).

---

## What this does not solve

- **Impersonation.** Nothing binds an author key to a human-meaningful name. A
  typosquatter can publish a validly-signed pointer under a plausible `app_id`
  with their own key. What you gain is a 32-byte key that no longer changes, not
  a verified identity.
- **Forward key compromise.** Monotonic `version` bounds backward replay only.
  Whoever holds the author key can sign a pointer to anything.
- **Calling another app's delegate.** Addressing is only half of it: an
  integrator that wants to *message* another app's delegate also needs the
  runtime to attest who is calling. That is a separate, known, currently
  unfixed problem, tracked privately. This contract is the addressing half.
