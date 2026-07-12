# `freenet-migrate` — design & rationale

Reusable contract/delegate upgrade-migration machinery for [Freenet](https://freenet.org)
dApps. This document explains *why* the crate is shaped the way it is; the
[README](../README.md) is the usage-facing entry point.

Grounded in first-hand reads of freenet-stdlib, freenet-scaffold, River, and
Delta. This is Horizon-A step A3 of the graceful-upgrades effort tracked in
[freenet-core#2776](https://github.com/freenet/freenet-core/issues/2776); the
strategic context (the platform-vs-app-level fork, Ian's #4117 stance, the
threat model) lives on that issue.

## The problem it solves

A Freenet contract's identity is **content-addressed**:

```
code_hash          = blake3(wasm)
ContractInstanceId = blake3(code_hash ‖ params)
DelegateKey        = blake3(code_hash ‖ params)   // for a delegate
```

So *any* rebuild that changes the WASM — a code change, a transitive dependency
bump, a newer compiler — produces a **new key**. The old state and the old
delegate's secrets are still on the network, but under the previous key, which
nothing points at anymore. From the user's perspective the data silently
disappears on upgrade. This bites on ordinary rebuilds, not just deliberate
version changes.

## Framing correction (drove the whole API)

Neither River nor Delta ships the "author-signed successor pointer +
`RelatedContracts`" model. Both ship a **backward-probe from a committed
legacy-code-hash registry**: reconstruct each predecessor key from
`(stable params ‖ old code_hash)`, GET the old state, fold + re-PUT under the
current key (River `common/src/migration.rs` `legacy_contract_keys_for_owner` /
`contract_key_for_code_hash`, `ui/src/room_data.rs` `regenerate_contract_key`,
`backward_probe.rs`; Delta `legacy_contracts.toml` startup loop). The
signed-pointer + `RelatedContracts StateThenSubscribe` model is real but only an
*aspiration* in the dapp-builder skill. **The crate therefore centers the proven
backward-probe; the signed-pointer/subscribe path is an opt-in richer layer**,
not the baseline. Designing around what the apps actually ship — rather than the
aspirational model — is the single decision that shaped everything below.

## Field-validated (2026-07-12)

River's live **0.6 → 0.8** re-key used exactly this pattern and was
**transparent** to users. `freenet-migrate` 0.1.0 (published to crates.io) plus
stdlib 0.8.3 shipped to the live network, both `room_contract.wasm` and
`chat_delegate.wasm` re-keyed, and:

- rooms **auto-migrated for every member on refresh** (backward-probe re-PUT);
- **invites survived** — River anchors identity on the owner `VerifyingKey`, not
  the contract key, so invites, membership, and org secrets were unaffected;
- the **78-member Official room stayed intact** (migrated with all members);
- a **real user's rooms migrated on framework** with the **old delegate left
  byte-identical / untouched** — nothing had to be recreated.

The only required operator step was registering the outgoing code hash in the
legacy registry *before* the WASM changed, then `publish-all`. Recreation /
key-swap is **only** for a deliberate owner-identity change — never for a routine
contract/stdlib re-key. This is the field evidence that the app-level path is the
right default, and it is the outcome summarized back onto #2776.

## 1. Home & scope

A **two-crate pair in the `freenet-delegates` workspace**, published to crates.io:

- `freenet-migrate` — runtime lib (features `contract` / `delegate` = wasm
  no-net, `ui` = native + wasm), mirroring stdlib's target split.
- `freenet-migrate-build` — build-dep: parses legacy TOMLs, codegens lineage
  consts, runs the CI hash-guard.

**Not stdlib.** stdlib *is* the wire/ABI; migration *policy* there recouples to
the protocol version and reopens the trust-model question that #4117 deliberately
left open. **`freenet-delegates` is the natural home** — it already hosts
`upgrade-assistant` (the discovery-registry delegate), currently the workspace's
only crate, so this is the first genuinely reusable member and the two co-evolve
(cross-node predecessor discovery can call upgrade-assistant's `GetPreviousKey`).

The crate owns five things:

1. a unified legacy-hash registry TOML,
2. build-time codegen of the `LEGACY_*` / `*_LINEAGE` consts,
3. contract state carry-forward,
4. delegate secret carry-forward,
5. the CI "WASM hash changed ⇒ old hash must be in the registry" guard.

## 2. API surface

**Registry + codegen.** One `legacy.toml` (a superset of River's two tomls +
Delta's two) with `[[contract]]` / `[[delegate]]` rows (`generation`,
`code_hash`, delegate `delegate_key`, `note`).
`freenet_migrate_build::codegen().registry("legacy.toml").emit()` writes the
`CONTRACT_LINEAGE` / `DELEGATE_LINEAGE` consts into `$OUT_DIR`.

**Contract carry-forward** is bounded on freenet-scaffold's `ComposableState`
(merge + verify; River already implements it at `common/src/room_state.rs`):

```rust
pub trait CarryForward: ComposableState + Serialize + DeserializeOwned {
    fn carry_forward(&mut self, predecessor: &Self, parent: &Self::ParentState, params: &Self::Parameters)
        -> Result<(), MigrateError> {
        self.merge(parent, params, predecessor).map_err(MigrateError::Merge)?;
        self.verify(parent, params).map_err(MigrateError::Verify)?; // self-authorizing gate, fail-closed
        Ok(())
    }
}
impl<T: ComposableState + Serialize + DeserializeOwned> CarryForward for T {}
```

Two ways to obtain the predecessor state:

- **(i) Backward-probe (proven, UI-side):** `predecessor_ids(params, lineage)
  -> Vec<ContractInstanceId>` (id = `blake3(code_hash ‖ params)`, no old WASM
  bytes needed); the UI GETs each, picks the first non-empty, folds it forward,
  and re-PUTs. Ships today.
- **(ii) In-contract pull (richer, opt-in):** `resolve_predecessors(params,
  lineage, related) -> Resolution` wrapping `ValidateResult::RequestRelated` with
  `RelatedMode::StateThenSubscribe` — the node subscribes to the old key so late
  v1 updates keep flowing and (against shipped eviction) the old key is pinned
  during the window.

**Author-signed successor pointer** (neither app has this today; adds
anti-rollback + forward discovery): `SuccessorPointer { successor_code_hash,
generation, sig }`, `verify(release_pk, app_id)`, `supersedes(current_generation)`.
Generation bounds *backward* replay only; forward key-compromise stays
unmitigated and must be documented, not hidden.

**Delegate export/import behind a swappable transport:**

```rust
pub fn handle_export_request(ctx, origin, policy: OriginPolicy, req) -> Result<Vec<OutboundDelegateMsg>, _>; // v1 side; enumerates ctx.list_secrets(b"") generically
pub fn import_secrets_once(ctx, exported) -> Result<ImportOutcome, _>;  // v2 side; writes "migrated:<gen>" marker so a stray old-WASM re-run can't resurrect deleted data
pub trait SecretTransport { fn export_from(&self, predecessor: &DelegateKey) -> Result<ExportedSecrets, _>; }
pub struct ReRunOldWasm; impl SecretTransport for ReRunOldWasm { /* today: node runs old WASM */ }
```

The generic `list_secrets` export copies **every** secret by construction — this
structurally eliminates the per-type-export omission that cost Delta site data in
April 2026. (Pre-crate predecessors still need a `LegacyExportAdapter` wrapping
the app's existing per-type export.)

## 3. Preconditions as first-class

Carry-forward is safe **only** for contracts that are mergeable,
self-authorizing, and release-signed. The crate turns each precondition into
something the compiler or the API enforces, rather than a footnote a dApp author
can miss:

| Precondition | Enforcement | If absent |
|---|---|---|
| **mergeable** | compile-time `CarryForward: ComposableState` bound | does not compile |
| **self-authorizing** | forced fail-closed `verify()` after merge; the bare-probe path is gated behind a `#[must_use]`, un-`Default` `PermissiveValidatorAck` opt-out | the safe API refuses; the opt-out is visibly unsafe-shaped |
| **signing identity** | `ReleaseSigner::from_key(SigningKey)` is the only constructor | can't mint a pointer; the backward-probe still works but the crate warns "no anti-rollback / no forward-discovery" |

The only fully-safe path is `ComposableState` + a passing `verify` + a
`ReleaseSigner`; everything short of that is a compile error or a loudly-named
opt-out, never a silent footgun. A contract with a permissive validator gets **no
safe carry-forward** from this design — with permissionless re-PUT, a malicious
node can inject crafted state under the new key — and the crate refuses to
pretend otherwise.

## 4. Fragility & the Horizon-B hand-off (the `SecretTransport` seam)

Delegate secret copy still bottoms out on **re-running old WASM**
(`ReRunOldWasm` — the node loads and runs the old delegate to answer the export;
the exact path a stdlib/ABI bump breaks, River V4–V6 / #204 data loss). The crate
does not eliminate that fragility; it **contains** it:

- the two-phase anti-resurrection marker bounds the damage of a stray old-WASM
  re-run, and
- `SecretTransport` is the **seam**. When the platform-level primitive (the
  "Horizon-B" node-mediated `SecretsStore::migrate_secrets`, deferred on #2776)
  lands, adding `struct NodeCopyForward; impl SecretTransport` is a **drop-in with
  no API break** — callers are written against the trait, not the concrete
  transport.

Hosted per-user secrets stay un-migratable at rest even under a node-mediated
transport (their DEK keying material is the user's secret, deliberately not the
node KEK), so the crate returns `MigrateError::UserScopeNotAtRest` and documents
the "only while the user is online" limit rather than papering over it.

## 5. Incremental adoption (no flag-day)

**River:**

1. point `ui/build.rs` + `common/build.rs` at `freenet_migrate_build::codegen()`,
   **aliasing** the generated consts to the existing names (`LEGACY_DELEGATES`,
   `LEGACY_ROOM_CONTRACT_CODE_HASHES`) so existing code compiles unchanged;
2. replace the `regenerate_contract_key` / `fire_legacy_migration_request` /
   `migrate_legacy_per_room` internals with crate calls (a `LegacyExportAdapter`
   plugs River's per-room export for pre-crate versions);
3. swap the CI guard to the crate's checker.

Each step is behavior-preserving with tests green.

**Delta:** the same codegen swap; merge its two tomls; retire
`add-migration.sh` / `add-contract-migration.sh` / `check-migration.sh` for a
`freenet-migrate add-predecessor` CLI plus the crate guard in CI (Delta's
predecessor rule is manual-only today — a real hardening). Its "cover every
`Get*` variant" invariant is subsumed by the generic `list_secrets` export.

## Status

Draft: the reusable core machinery + tests, published as 0.1.0 and
**field-validated by River's 0.6 → 0.8 re-key** (above). Integrating River and
Delta (pointing their `build.rs` at the codegen, swapping their migration
internals for crate calls) is a later step. Targets current stdlib **0.8.x**.
