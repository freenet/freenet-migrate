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
//! * **Forward discovery** — [`resolve_app_pointer`] / [`PointerResolver`]
//!   resolve an author's canonical pointer contract (freenet-core#5194) to the
//!   `code_hash` that is current *now*, with local signature verification and
//!   an anti-rollback [`PointerFloor`]. This is the only entry point that looks
//!   forward; everything else here walks backward through predecessors.
//! * **Author-signed successor pointer** — [`SuccessorPointer`] / [`ReleaseSigner`],
//!   an older, unrelated primitive with its own signing domain (not the pointer
//!   contract's; the two are not interchangeable).
//! * **Delegate carry-forward** — the app-facing [`migrate_delegate_secrets`] /
//!   [`register_delegate_with_migration`] entry points (consent-parameterized via
//!   [`MigrationAuthorization`]) over two thin adapters: [`PredecessorSecretsIo`]
//!   reads the predecessors, and [`SuccessorSecretsIo`] — **the app's own import
//!   path** — writes the successor, so app-level invariants (a derived index,
//!   permission grants, certificate verification) survive the migration. Apps whose
//!   secrets stand alone wrap a [`SecretStore`] in [`SecretStoreIo`]. Plus the
//!   delegate-side [`handle_export_request`] / [`import_predecessor_secrets_once`]
//!   / [`import_secrets_once`] primitives over the [`SecretStore`] trait. The
//!   transport the entry points drive is an internal, redesigned sans-IO seam
//!   ([`delegate_migrate`]) a future node copy-forward swaps under.
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
// The safety story of `pointer` is carried substantially by its prose, and a
// link to a type that no longer exists is how that prose rots. Two such links
// survived a redesign here and CI did not notice. That is enforced by the
// `docs` CI job (`cargo doc` under `RUSTDOCFLAGS: -D warnings`) rather than by
// a `deny` here: an in-source `deny` on a rustdoc lint is inherited by
// downstream doc builds, so a future rustc that flags something new would break
// consumers of this crate rather than this crate's own CI.

pub mod contract;
pub mod delegate;
pub mod delegate_migrate;
pub mod driver;
pub mod error;
pub mod lineage;
pub mod pointer;
pub mod successor;

pub use contract::{
    contract_id_from_code_hash, contract_id_from_code_hash_b58, predecessor_ids,
    resolve_predecessors, CarryForward, PermissiveValidatorAck, Resolution,
};
pub use delegate::{
    handle_export_request, import_predecessor_secrets_once, import_secrets_once,
    predecessor_delegate_keys, predecessor_delegate_keys_checked, predecessor_done_marker,
    predecessor_migration_had_data, ExportRequest, ExportScope, ExportedSecrets, ImportOutcome,
    OriginPolicy, PredecessorImportOutcome, SecretPair, SecretStore, SingleAppDelegateAck,
    HOST_ENUMERATION_CAP, PRED_DONE_MARKER_KEY_PREFIX, PRED_DONE_MARKER_VALUE_DATA,
    PRED_DONE_MARKER_VALUE_EMPTY, PRED_DONE_MARKER_VERSION,
};
pub use delegate_migrate::{
    migrate_delegate_secrets, register_delegate_with_migration, DelegateMigrationReport,
    ImportTally, ItemWrite, LegacyBridge, MarkerQuery, MigrationAuthorization, MigrationMarker,
    NoCrossEntryInvariantsAck, PredecessorMigration, PredecessorSecretsIo, RecoveredSecret,
    RegisterAndMigrateIo, RetryAdvice, SecretSelectionPolicy, SecretStoreIo,
    SecretStoreWriteFailed, SuccessorSecretsIo, UnionAck, WriterFailure, WriterStage,
};
pub use driver::{
    contract_probe, migrate_contract, FoldAllAck, NewestFirst, Outcome, ProbeAnswer, ProbeDriver,
    ProbeIo, ProbeStateOps, RollbackRiskAck, SelectionPolicy, Step, DEFAULT_MAX_PROBE_HOPS,
    RECOMMENDED_PROBE_TIMEOUT_MS,
};
pub use error::MigrateError;
pub use lineage::{ContractLineageEntry, DelegateLineageEntry, Lineage};
pub use pointer::{
    is_canonical_field_element, is_valid_app_id_byte, parse_pointer_params, pointer_contract_id,
    pointer_params, pointer_signing_message, resolve_app_pointer, ConservativeProbeIo,
    PointerError, PointerFetch, PointerFloor, PointerIo, PointerOutcome, PointerRecord,
    PointerResolver, ResolveError, ResolvedPointer, CODE_HASH_LEN, MAX_APP_ID_LEN,
    MAX_POINTER_PARAMS_LEN, MAX_POINTER_VERSION, MIN_POINTER_PARAMS_LEN, POINTER_CODE_HASH_B58,
    POINTER_SIGNING_DOMAIN, POINTER_STATE_LEN, SIGNATURE_LEN, TOMBSTONE_CODE_HASH,
    VERIFYING_KEY_LEN,
};
pub use successor::{ReleaseSigner, SuccessorPointer};
