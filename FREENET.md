# FREENET.md

This file enumerates the Freenet contracts and delegates published from this repository — what each one is for, where its source lives, and how to depend on it — for anyone integrating with freenet-migrate rather than building it. It's a convention (see [freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194)), not a protocol requirement: a fixed, predictable place to look before reading source.

## Contracts

### pointer-contract (the canonical successor pointer)

- **Purpose:** The ecosystem's stable-identity indirection. Its state names the **current code hash** of some app's contract or delegate, signed by that app's author. A third party resolves the pointer, takes `code_hash`, and combines it with **its own** params to derive the key it actually needs — so an upstream re-key stops silently stranding integrators. This is the fix for the failure class in [freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194) and [freenet/ghostkeys#21](https://github.com/freenet/ghostkeys/issues/21).
- **Source:** [`contracts/pointer-contract/`](contracts/pointer-contract/) — deliberately outside the workspace, with its own lockfile and toolchain pin.
- **Code hash:** `8wnAPaSRY1oYZCz723fdwK6BgzL6q8ozP3buVovXnt6v` — recorded in [`contracts/pointer-contract/CODEHASH`](contracts/pointer-contract/CODEHASH), artifact committed at [`contracts/pointer-contract/pointer-v1.wasm`](contracts/pointer-contract/pointer-v1.wasm).
- **Deployed key:** none fixed — every `(author, app_id)` is its own instance. A pointer's key is `BLAKE3(code_hash ‖ author_verifying_key ‖ app_id)`, so there are as many keys as there are apps publishing pointers.
- **Migration:** **none, ever, by design.** This is the one artifact in the ecosystem with no recovery layer above it: an app that re-keys is recoverable through its pointer, but a pointer that re-keys has nothing left pointing at it. The WASM is frozen — exact dependency pins, committed lockfile, pinned toolchain, path-remapped reproducible build — and CI fails if the code hash moves for any reason. Changing it is an ecosystem-coordinated flag day, not a release. See [`contracts/pointer-contract/WASM-STABILITY.md`](contracts/pointer-contract/WASM-STABILITY.md).
- **Params:** fixed byte layout, never serde — `author_verifying_key (32 bytes) ‖ app_id (1..=64 bytes, `a-z0-9.-_`)`.
- **State:** fixed byte layout, exactly 100 bytes — `version (u32 big-endian) ‖ code_hash (32 bytes) ‖ signature (64 bytes)`.

**Not yet publishable.** The artifact is frozen and CI-enforced, but this contract's logic has never been executed on `wasm32` — the tests run the same Rust compiled natively, and the conformance suite loads the module without calling it. One manual run against a real local node is required before the first publish; see the STOP box in [`contracts/pointer-contract/README.md`](contracts/pointer-contract/README.md). Merging code is fine; publishing is what makes the freeze load-bearing.

**Publisher start here:** the `publish` feature ships a `pointer-record` binary that signs, derives and verifies records, so an app does not grow its own signing code — a second implementation of the record bytes is a second thing that can disagree about what a record IS. Install it pinned (`cargo install --git https://github.com/freenet/freenet-migrate --rev <sha> --features publish --locked freenet-pointer-contract`); it reads the signing key from stdin rather than argv, and refuses to sign unless `--author-vk` matches the key it was given. It is also what a CI freshness gate runs. See [`contracts/pointer-contract/README.md`](contracts/pointer-contract/README.md).

**Integrator start here:** Rust integrators should use `freenet_migrate::pointer::resolve_app_pointer` (see the `freenet-migrate` entry below) rather than hand-rolling resolution, since it carries the anti-rollback floor and the absence-vs-unreachability distinction that a raw `PointerRecord::decode_verified` call does not. [`contracts/pointer-contract/README.md`](contracts/pointer-contract/README.md) still documents the underlying four-step resolution (compute the pointer key, GET and verify, derive your own key from `code_hash` **plus your own params**, and persist the result) for non-Rust implementers and anyone working with the raw primitives directly. Step 3 is the one people get wrong.

## Delegates

None. This repository publishes no delegates.

## Libraries

### freenet-migrate
- **Purpose:** Both halves of the upgrade problem. Author-side: backward probe and fold for contract state, predecessor registries, delegate secret carry-forward, and the older `SuccessorPointer` signing/verification primitives. Consumer-side: a resolver for the pointer contract above, `freenet_migrate::pointer::resolve_app_pointer` (async, over the `PointerIo` trait) plus the sans-IO `PointerResolver` driver for environments without awaitable request/response correlation. It applies the anti-rollback floor, distinguishes absence from unreachability, and derives the caller's own key from the resolved code hash.
- **Source:** [`freenet-migrate/`](freenet-migrate/)
- **Relationship to the pointer contract:** `freenet-migrate::pointer` re-implements the contract's wire format (params, state layout, signing message) rather than depending on the frozen contract crate, and is pinned against it by `tests/pointer_contract_parity.rs`. What is still unreconciled is the **older** `SuccessorPointer` primitive, which predates the pointer contract and is a separate mechanism: it signs `code_hash ‖ generation ‖ app_id` under the domain `freenet-migrate/successor-v1`, little-endian generation, no params binding, while the pointer contract signs `params ‖ version ‖ code_hash` under `freenet-pointer/state-v1` (binding the whole params blob, so a record cannot be replayed across two apps sharing an author key). `SuccessorPointer` is shipped by nobody today; new integrations should use the pointer-contract resolver above instead.

### freenet-migrate-build
- **Purpose:** Build-time (`build.rs`) hashing and codegen for consumers of `freenet-migrate`.
- **Source:** [`freenet-migrate-build/`](freenet-migrate-build/)

## Notes for integrators

- **Embed the pointer code hash as a constant. Never rebuild it locally.** A locally rebuilt WASM will not match — even reformatting the source changes the bytes, because Rust bakes panic-site line numbers into the binary. A substituted hash yields a different, empty contract.
- **Never silently fall back to a baked-in key.** Fall back only if a pointer has *never* resolved on that install; after that, unresolvable means unavailable. Otherwise "make the pointer briefly unreachable" becomes a working keyless downgrade to a stale key — the exact failure the pointer exists to prevent.
- **A pointer proves authorship, not identity.** Nothing binds an author key to a human-meaningful name, so a typosquatter can publish a validly-signed pointer under a plausible `app_id`. The gain is a 32-byte key that no longer changes, not verified identity.
- **The pointer solves ADDRESSING ONLY — not data survival.** It tells you which code hash is current. It says nothing about whether state or secrets held under the previous key survived the re-key. As of 2026-08, River's delegate secrets in its dedicated secure namespace do **not** survive a re-key (the migration probe only reaches its readable blob), and River re-keys roughly weekly. An integrator who assumes a resolved pointer makes an upgrade safe will be misled, because the failure presents as "this user has no data". Verify data survival separately, per artifact.
- **Addressing is only half of cross-app integration.** Messaging another app's delegate also needs the runtime to attest who is calling; that is a separate, currently-unfixed problem and is not solved here.
