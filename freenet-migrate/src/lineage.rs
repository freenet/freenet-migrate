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
//!         code_hash: [154, 3, /* … */],  // blake3(wasm), decoded at build time
//!         note: "v1 room contract",
//!     },
//!     // ...
//! ];
//! ```
//!
//! into `$OUT_DIR`; the consumer `include!`s it. [`Lineage`] wraps such a slice
//! with lookup helpers.
//!
//! Hashes are canonical `[u8; 32]`, decoded and validated by the build crate
//! (from hex or base58) — a malformed hash is a **build failure**, so the
//! runtime string-decode error class does not exist here. Use
//! [`ContractLineageEntry::code_hash_b58`] etc. where a display/stdlib string
//! form is needed.

/// Base58 (Bitcoin alphabet) encoding, matching stdlib `CodeHash::encode()`.
fn b58(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

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
    /// The 32-byte code hash `blake3(wasm)`, decoded at build time.
    pub code_hash: [u8; 32],
    /// Human note (which release, why retired).
    pub note: &'static str,
}

impl ContractLineageEntry {
    /// The code hash in stdlib's string form (base58, Bitcoin alphabet).
    pub fn code_hash_b58(&self) -> String {
        b58(&self.code_hash)
    }
}

/// One predecessor generation of a *delegate*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegateLineageEntry {
    /// Monotonic generation number (older = smaller).
    pub generation: u32,
    /// The 32-byte code hash `blake3(wasm)`, decoded at build time.
    pub code_hash: [u8; 32],
    /// The full 32-byte delegate key. Stored explicitly because this is the
    /// key the old delegate **actually had on the network** — the address a
    /// migration probe must target. For regular rows it equals
    /// `blake3(code_hash ‖ params)` (cross-checked at build time); for
    /// [`irregular_key`](Self::irregular_key) rows it is the recorded
    /// historical key, which does *not* derive from `code_hash`.
    pub delegate_key: [u8; 32],
    /// Whether the recorded `delegate_key` predates the standard derivation
    /// (e.g. River's V1/V2) and is trusted as-recorded rather than derivable
    /// from `code_hash`. See the build crate's registry docs.
    pub irregular_key: bool,
    /// Human note.
    pub note: &'static str,
}

impl DelegateLineageEntry {
    /// The code hash in stdlib's string form (base58, Bitcoin alphabet).
    pub fn code_hash_b58(&self) -> String {
        b58(&self.code_hash)
    }

    /// The delegate key in stdlib's string form (base58, Bitcoin alphabet).
    pub fn delegate_key_b58(&self) -> String {
        b58(&self.delegate_key)
    }
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
