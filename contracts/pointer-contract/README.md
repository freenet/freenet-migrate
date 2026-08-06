# freenet-pointer-contract

A contract with a **stable key** whose state names the **current code hash** of
an app's real contract or delegate.

```
version: 12
code_hash: 9xH2…            <- the app's current WASM hash
```

That is the entire state. Everything else in this README is about how to use it.

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

### Step 1 — compute the pointer's own key

You need three things, all of which you have at build time: the published
pointer code hash (`CODEHASH` in this directory, a constant you embed — see
"Never rebuild this WASM" below), the author's verifying key, and the `app_id`.

```rust
use freenet_pointer_contract::PointerParams;
use freenet_stdlib::prelude::{ContractKey, Parameters};

const POINTER_CODE_HASH: &str = "9V7mTtJjz8Y4Vmkhta38fTzvVF1pxfwzC6NWvGx3FiEG";

let params = PointerParams::encode(&author_vk, b"ghostkeys.ghostkey-delegate")?;
let pointer_key = ContractKey::from_params(
    POINTER_CODE_HASH,
    Parameters::from(params.clone()),
)?;
```

That is `BLAKE3(pointer_code_hash ‖ params)`. It never changes.

### Step 2 — GET it and verify

```rust
// ...an ordinary GET for `pointer_key`, giving you the 100-byte state...
let record = PointerRecord::decode_verified(&state, &params)?;
// record.version   -> monotonic
// record.code_hash -> the app's CURRENT wasm hash
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
use freenet_stdlib::prelude::{CodeHash, ContractKey, DelegateKey, Parameters};

let code_hash_b58 = CodeHash::new(record.code_hash).encode();

// A contract:
let current = ContractKey::from_params(
    &code_hash_b58,
    Parameters::from(my_own_params.clone()),   // NOT the pointer's params
)?;

// A delegate:
let current = DelegateKey::from_params(
    &code_hash_b58,
    &Parameters::from(my_own_params.clone()),
)?;
```

Both compute `BLAKE3(code_hash ‖ your params)`, which is exactly what a node
computes when it holds the code — pinned by the
`consumer_derivation_matches_stdlib` test against stdlib's own
`ContractKey::from_params_and_code`.

Two traps:

- **Use your own params, not the pointer's.** The pointer's params identify the
  pointer. Yours identify your instance. This is precisely why the state carries
  no `current_key` field: one pointer serves *every* instance of an app — every
  River room, every delegate registration — and a `current_key` could only ever
  have been right for one of them.
- **Keep both halves of the key.** `from_params` returns a `ContractKey`
  carrying both the instance id and the code hash. An UPDATE is rejected if the
  code hash is missing, so do not reduce the key to its instance id and rebuild
  it later (freenet-core#4978).

Detecting staleness needs nothing further: compare the derived key against the
one you were built with. To fetch the code, GET the derived key with
`return_contract_code: true`; `BLAKE3(fetched wasm) == record.code_hash` is a
free integrity check.

### Step 4 — persist the right thing

Persist `(highest_version_ever_verified, resolved_key)`, not merely "I know a
pointer exists".

- Reject any record whose `version` is `<=` your highest ever seen. The contract
  enforces monotonicity across the network, but a node that holds no copy yet
  (freshly bootstrapped, recently evicted) can transiently serve an older validly
  signed record, because `validate_state` has no prior state to compare against.
  Your own high-water mark is what closes that window for you.
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

Three operational requirements, none of which the contract can enforce for you:

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
3. **Choose `app_id` once.** It is part of the params, so it is part of the key.
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
