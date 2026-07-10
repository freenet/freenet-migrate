//! The lineage registry shape — the runtime counterpart of the consts emitted
//! by `freenet-migrate-build`'s codegen.
//!
//! A build script calls
//! `freenet_migrate_build::codegen().registry("legacy.toml").emit()`, which
//! writes something like:
//!
//! ```ignore
//! pub const CONTRACT_LINEAGE: &[::freenet_migrate::ContractLineageEntry] = &[
//!     ::freenet_migrate::ContractLineageEntry {
//!         generation: 0,
//!         code_hash: "9xH...",     // base58 blake3(wasm), matches stdlib CodeHash::encode()
//!         note: "v1 room contract",
//!     },
//!     // ...
//! ];
//! ```
//!
//! into `$OUT_DIR`; the consumer `include!`s it. [`Lineage`] wraps such a slice
//! with lookup helpers.

/// One predecessor generation of a *contract*.
///
/// The registry lists **predecessors only**; the currently-live generation's
/// hash is derived at runtime from the bundled WASM and is deliberately absent
/// (mirroring River's `legacy_room_contracts.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractLineageEntry {
    /// Monotonic generation number (older = smaller). Used by
    /// [`crate::SuccessorPointer::supersedes`] for anti-rollback ordering.
    pub generation: u32,
    /// Base58 (Bitcoin alphabet) encoding of the 32-byte code hash
    /// `blake3(wasm)`, matching stdlib `CodeHash::encode()`.
    pub code_hash: &'static str,
    /// Human note (which release, why retired).
    pub note: &'static str,
}

/// One predecessor generation of a *delegate*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegateLineageEntry {
    /// Monotonic generation number (older = smaller).
    pub generation: u32,
    /// Base58 encoding of the 32-byte code hash `blake3(wasm)`.
    pub code_hash: &'static str,
    /// Base58 encoding of the full 32-byte delegate key
    /// `blake3(code_hash ‖ params)`. Stored explicitly so the old delegate can
    /// be addressed without re-deriving; [`crate::predecessor_delegate_keys`]
    /// can also reconstruct and cross-check it.
    pub delegate_key: &'static str,
    /// Human note.
    pub note: &'static str,
}

/// A read-only view over a generated lineage slice, with lookup helpers.
///
/// Generic over the entry type so it wraps both [`ContractLineageEntry`] and
/// [`DelegateLineageEntry`] slices.
#[derive(Debug, Clone, Copy)]
pub struct Lineage<'a, E> {
    entries: &'a [E],
}

impl<'a, E> Lineage<'a, E> {
    /// Wrap a generated const slice.
    pub const fn new(entries: &'a [E]) -> Self {
        Self { entries }
    }

    /// The backing slice.
    pub const fn entries(&self) -> &'a [E] {
        self.entries
    }

    /// Number of predecessor generations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry has no predecessors (fresh app / first release).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entries in registry order (oldest-first by convention).
    pub fn iter(&self) -> core::slice::Iter<'a, E> {
        self.entries.iter()
    }
}

impl<'a, E> From<&'a [E]> for Lineage<'a, E> {
    fn from(entries: &'a [E]) -> Self {
        Self::new(entries)
    }
}

impl<'a, E> AsRef<[E]> for Lineage<'a, E> {
    fn as_ref(&self) -> &[E] {
        self.entries
    }
}

impl<'a> Lineage<'a, ContractLineageEntry> {
    /// The highest generation number present, if any.
    pub fn head_generation(&self) -> Option<u32> {
        self.entries.iter().map(|e| e.generation).max()
    }
}

impl<'a> Lineage<'a, DelegateLineageEntry> {
    /// The highest generation number present, if any.
    pub fn head_generation(&self) -> Option<u32> {
        self.entries.iter().map(|e| e.generation).max()
    }
}
