//! # freenet-migrate
//!
//! Reusable contract/delegate **upgrade-migration** machinery for Freenet
//! dApps. Content-addressed identity (`blake3(wasm ‖ params)`) means any rebuild
//! can re-key a contract or delegate and strand user state under the old key;
//! this crate packages the patterns River and Delta already ship to carry that
//! state forward, with the safety preconditions made mechanical.
//!
//! Horizon-A step A3 of the graceful-upgrades design (freenet-core#2776).
//!
//! ## What it provides
//!
//! * [`Lineage`] / [`ContractLineageEntry`] / [`DelegateLineageEntry`] — the
//!   runtime shape of the registry consts emitted by `freenet-migrate-build`.
//! * **Contract carry-forward** — [`CarryForward`] (blanket over
//!   [`freenet_scaffold::ComposableState`]) with a fail-closed `verify()` gate;
//!   [`predecessor_ids`] (backward probe) and [`resolve_predecessors`]
//!   (in-contract pull).
//! * **Author-signed successor pointer** — [`SuccessorPointer`] / [`ReleaseSigner`].
//! * **Delegate carry-forward** — [`handle_export_request`] /
//!   [`import_secrets_once`] over the [`SecretStore`] trait, [`SecretTransport`]
//!   / [`ReRunOldWasm`].
//!
//! ## Preconditions made first-class (design §3)
//!
//! | Precondition | Enforcement |
//! |---|---|
//! | mergeable | the compile-time [`CarryForward`]`: `[`ComposableState`](freenet_scaffold::ComposableState) bound |
//! | self-authorizing | the crate's carry-forward *path* forces a fail-closed, atomic `verify()` after merge; the un-`Default`, `#[must_use]` [`PermissiveValidatorAck`] opt-out |
//! | signing identity | [`ReleaseSigner::from_key`] is the only constructor |
//!
//! The self-authorizing guarantee is about the crate's carry-forward *path*:
//! `ComposableState::merge` is itself a public trait method, so the crate cannot
//! make skipping `verify()` physically impossible — it guarantees that
//! [`CarryForward::carry_forward`] always runs it, and that the only in-crate
//! bypass is the loudly-named [`PermissiveValidatorAck`].
//!
//! ## Features
//!
//! `contract` / `delegate` (wasm, no-net) and `ui` (native + wasm) select the
//! target profile and dependency wiring, mirroring stdlib's split. The pure
//! logic is available in every profile; only the wasm-only `DelegateCtx` bridge
//! is gated (additionally on `target_family = "wasm"`), so the crate is fully
//! testable natively.

#![forbid(unsafe_code)]

pub mod contract;
pub mod delegate;
pub mod driver;
pub mod error;
pub mod lineage;
pub mod successor;

pub use contract::{
    contract_id_from_code_hash, contract_id_from_code_hash_b58, predecessor_ids,
    resolve_predecessors, CarryForward, PermissiveValidatorAck, Resolution,
};
pub use delegate::{
    handle_export_request, import_secrets_once, predecessor_delegate_keys,
    predecessor_delegate_keys_checked, ExportRequest, ExportScope, ExportedSecrets, ImportOutcome,
    OriginPolicy, ReRunOldWasm, SecretStore, SecretTransport, SingleAppDelegateAck,
    HOST_ENUMERATION_CAP,
};
pub use driver::{
    contract_probe, migrate_contract, FoldAllAck, NewestFirst, Outcome, ProbeDriver, ProbeIo,
    ProbeStateOps, SelectionPolicy, Step, DEFAULT_MAX_PROBE_HOPS, RECOMMENDED_PROBE_TIMEOUT_MS,
};
pub use error::MigrateError;
pub use lineage::{ContractLineageEntry, DelegateLineageEntry, Lineage};
pub use successor::{ReleaseSigner, SuccessorPointer};
