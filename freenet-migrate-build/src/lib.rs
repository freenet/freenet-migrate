//! # freenet-migrate-build
//!
//! Build-dependency companion to [`freenet-migrate`]. Three jobs:
//!
//! 1. **Parse** a registry of predecessor contract/delegate code hashes — the
//!    unified `legacy.toml` schema ([`Registry`]) or River-style `[[entry]]`
//!    files ([`Registry::from_entry_path`]). Hashes may be hex or base58; both
//!    decode to a canonical `[u8; 32]` **at build time**, and delegate rows are
//!    cross-checked against the standard `blake3(code_hash ‖ params)` key
//!    derivation ([`Registry::validate`]).
//! 2. **Codegen** lineage consts into `$OUT_DIR` ([`codegen`]): the canonical
//!    `CONTRACT_LINEAGE` / `DELEGATE_LINEAGE` entry slices, and/or plain
//!    byte-array *view* consts matching existing apps' hand-rolled shapes
//!    (`&[[u8; 32]]`, `&[([u8; 32], [u8; 32])]`) so their call sites compile
//!    unchanged with no runtime-crate dependency.
//! 3. **CI hash-guard** ([`check_migration_guard`]): assert that whenever a
//!    built WASM's hash changed, the old hash is registered as a predecessor.
//!
//! Typical `build.rs` (canonical adoption):
//!
//! ```no_run
//! freenet_migrate_build::codegen()
//!     .registry("legacy.toml")
//!     .emit()
//!     .expect("codegen lineage consts");
//! ```
//!
//! Typical `build.rs` (existing app, views-only — e.g. River's
//! `common/build.rs`):
//!
//! ```no_run
//! use freenet_migrate_build::Component;
//! freenet_migrate_build::codegen()
//!     .entry_registry("legacy_room_contracts.toml", Component::Contract)
//!     .canonical_consts(false)
//!     .contract_hash_view("LEGACY_ROOM_CONTRACT_CODE_HASHES")
//!     .out_file("legacy_room_contracts.rs")
//!     .emit()
//!     .expect("codegen legacy room-contract hashes");
//! ```
//!
//! Typical CI guard (e.g. an integration test or a small xtask):
//!
//! ```no_run
//! use freenet_migrate_build::{check_migration_guard, code_hash_b58, Component, Registry};
//! let registry = Registry::from_path("legacy.toml").unwrap();
//! let base = code_hash_b58(&std::fs::read("base/room_contract.wasm").unwrap());
//! let head = code_hash_b58(&std::fs::read("head/room_contract.wasm").unwrap());
//! let outcome = check_migration_guard(Component::Contract, &base, &head, &registry).unwrap();
//! assert!(outcome.passes(), "{}", outcome.advice(Component::Contract).unwrap());
//! ```
//!
//! [`freenet-migrate`]: https://docs.rs/freenet-migrate

mod codegen;
mod error;
mod guard;
mod registry;

pub use codegen::{codegen, Codegen};
pub use error::BuildError;
pub use guard::{check_migration_guard, code_hash_b58, code_hash_hex, GuardOutcome};
pub use registry::{decode_hash32, Component, ContractRow, DelegateRow, Registry};
