//! # freenet-migrate-build
//!
//! Build-dependency companion to [`freenet-migrate`]. Three jobs:
//!
//! 1. **Parse** a unified `legacy.toml` registry ([`Registry`]) of predecessor
//!    contract/delegate code hashes.
//! 2. **Codegen** the `CONTRACT_LINEAGE` / `DELEGATE_LINEAGE` consts into
//!    `$OUT_DIR` ([`codegen`]).
//! 3. **CI hash-guard** ([`check_migration_guard`]): assert that whenever a
//!    built WASM's hash changed, the old hash is registered as a predecessor.
//!
//! Typical `build.rs`:
//!
//! ```no_run
//! freenet_migrate_build::codegen()
//!     .registry("legacy.toml")
//!     .emit()
//!     .expect("codegen lineage consts");
//! ```
//!
//! Typical CI guard (e.g. an integration test or a small xtask):
//!
//! ```no_run
//! use freenet_migrate_build::{check_migration_guard, code_hash_b58, Component, Registry};
//! let registry = Registry::from_path("legacy.toml").unwrap();
//! let base = code_hash_b58(&std::fs::read("base/room_contract.wasm").unwrap());
//! let head = code_hash_b58(&std::fs::read("head/room_contract.wasm").unwrap());
//! let outcome = check_migration_guard(Component::Contract, &base, &head, &registry);
//! assert!(outcome.is_ok(), "{}", outcome.advice(Component::Contract).unwrap());
//! ```
//!
//! [`freenet-migrate`]: https://docs.rs/freenet-migrate

mod codegen;
mod error;
mod guard;
mod registry;

pub use codegen::{codegen, Codegen};
pub use error::BuildError;
pub use guard::{check_migration_guard, code_hash_b58, Component, GuardOutcome};
pub use registry::{ContractRow, DelegateRow, Registry};
