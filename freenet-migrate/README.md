# freenet-migrate

Runtime **upgrade-migration** machinery for [Freenet](https://freenet.org) dApps.
A Freenet contract/delegate key is `blake3(code_hash ‖ params)`, so any rebuild
re-keys it and strands user state under the old key. This crate carries that
state (and a delegate's secrets) forward onto the new key, with the safety
preconditions made mechanical.

Part of the [`freenet-migrate`](https://github.com/freenet/freenet-migrate)
workspace; pair it with the build-dependency
[`freenet-migrate-build`](https://crates.io/crates/freenet-migrate-build) for the
predecessor-registry codegen and CI hash-guard. Horizon-A step A3 of
[freenet-core#2776](https://github.com/freenet/freenet-core/issues/2776).

## What it provides

- **Contract carry-forward** — `CarryForward` (blanket over
  `freenet_scaffold::ComposableState`) with a **fail-closed** `verify()`-after-
  `merge()` gate; `predecessor_ids` (reconstruct old ids from `(code_hash,
  params)`, no old WASM) and `resolve_predecessors` (in-contract pull).
- **Author-signed successor pointer** — `SuccessorPointer` / `ReleaseSigner`
  (Ed25519; `from_key` is the only constructor).
- **Delegate carry-forward** — `handle_export_request` / `import_secrets_once`
  over a generic `SecretStore` trait, with a `"migrated:<gen>"` anti-resurrection
  marker. Generic enumeration structurally can't omit a secret type.

## Features

`contract` / `delegate` (wasm, no-net) and `ui` (native + wasm, default) select
the target profile and dependency wiring, mirroring stdlib's split. The pure
logic is available in every profile; only the wasm-only `DelegateCtx` bridge is
gated, so the crate is fully testable natively.

See the [workspace README](https://github.com/freenet/freenet-migrate#usage-sketch-v1--v2)
for the full v1→v2 usage sketch and the hard preconditions.

## License

LGPL-3.0-only.
