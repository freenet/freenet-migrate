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
//! | self-authorizing | the forced fail-closed `verify()` after merge; the un-`Default`, `#[must_use]` [`PermissiveValidatorAck`] opt-out |
//! | signing identity | [`ReleaseSigner::from_key`] is the only constructor |
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
pub mod error;
pub mod lineage;
pub mod successor;

pub use contract::{
    contract_id_from_code_hash, predecessor_ids, resolve_predecessors, CarryForward,
    PermissiveValidatorAck, Resolution,
};
pub use delegate::{
    handle_export_request, import_secrets_once, predecessor_delegate_keys,
    predecessor_delegate_keys_checked, ExportRequest, ExportedSecrets, ImportOutcome, OriginPolicy,
    ReRunOldWasm, SecretStore, SecretTransport,
};
pub use error::MigrateError;
pub use lineage::{ContractLineageEntry, DelegateLineageEntry, Lineage};
pub use successor::{ReleaseSigner, SuccessorPointer};
