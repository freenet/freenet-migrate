//! **Forward** discovery: resolving an author's successor pointer.
//!
//! Everything else in this crate looks *backward* — [`crate::predecessor_ids`]
//! and [`crate::migrate_contract`] walk an app's own lineage to recover state
//! the author already knows about. That only helps the author. A **third
//! party** that baked a contract or delegate key into its build has no lineage
//! to walk: after the app re-keys, its reference addresses a stale, empty
//! namespace, and it cannot even tell "this user has no data" apart from "the
//! thing I was built against moved".
//!
//! This module is the other direction. Given an author's verifying key and an
//! `app_id`, it derives the address of that author's **pointer contract**,
//! reads the record there, verifies it, and reports the app's current
//! `code_hash` — from which the caller derives the key it actually wanted,
//! using **its own** params.
//!
//! The pointer contract itself lives at `contracts/pointer-contract/` in this
//! repository (freenet/freenet-migrate#9) and is a frozen WASM artifact whose
//! code hash is [`POINTER_CODE_HASH_B58`]. See freenet-core#5194 for the
//! locked design and freenet-core#2776 for the wider graceful-upgrades work.
//!
//! # Addressing only
//!
//! Resolving a pointer tells you **which code hash is current**. It says
//! nothing about whether state or secrets held under the previous key survived
//! the re-key; that is a separate, unsolved problem. An integrator who resolves
//! a pointer, derives the new key, and assumes the user's data came with it
//! will be wrong in a way that looks like "this user has no data".
//!
//! # Trust model
//!
//! **The author verifying key the caller passes in is the entire trust anchor,
//! full stop.** A record is accepted only if it carries an Ed25519 signature by
//! that exact key over that exact params blob. There is no delegation, no
//! revocation, and no in-protocol rotation: whoever holds the private key can
//! sign a pointer to arbitrary WASM, and this resolver will follow it.
//!
//! That is the **settled** design, not a gap this module left open.
//! freenet-core#5194 records it under "Settled decisions" (2026-08-06): *no
//! delegated signing* — the author key in params signs directly, because the
//! pointer's WASM must stay frozen for its key to be stable and complexity is
//! what forces a WASM change. **Key rotation is handled by convention rather
//! than by contract logic: use a dedicated, long-lived pointer key and keep it
//! offline.** A publisher who signs pointer records with a key that also does
//! day-to-day work has misread the design; see the contract's README on
//! custody.
//!
//! So the limitation is real but bounded and deliberate: a **forward**
//! compromise (the author's key is stolen) is unmitigated at this layer and
//! always will be. What the resolver *does* bound is **backward** replay: see
//! [`PointerFloor`].
//!
//! # Verification is local, always
//!
//! The node that answers the GET runs the pointer contract's `validate_state`,
//! so in the normal case bad records never get stored. That is not what makes
//! this safe. A GET response is bytes from a peer, so this module re-verifies
//! the signature locally against the caller's own trust anchor and never trusts
//! the responding node's verdict. [`ResolvedPointer`] has private fields and no
//! public constructor for exactly that reason: the only way to obtain one is
//! through verification.
//!
//! # Wire format (mirrored from the frozen contract)
//!
//! * **Params**: `author_verifying_key (32) ‖ app_id (1..=64)`, `app_id`
//!   restricted to `a-z 0-9 . - _`.
//! * **State**: `version (u32 big-endian) ‖ code_hash (32) ‖ signature (64)`,
//!   exactly [`POINTER_STATE_LEN`] bytes.
//! * **Signed message**: [`POINTER_SIGNING_DOMAIN`] `‖ params ‖ version_be ‖
//!   code_hash`, verified with dalek's `verify_strict`.
//!
//! This module deliberately **re-implements** that format rather than
//! depending on the `freenet-pointer-contract` crate: that crate is
//! workspace-excluded and unpublished on purpose (its compiled bytes must never
//! move), and a published crate cannot carry a git or path dependency on it.
//! The duplication is pinned in both directions by
//! `tests/pointer_contract_parity.rs`, which checks this implementation against
//! the contract's committed `TEST-VECTORS.md`, its `CODEHASH` file, and the
//! constants in its source.
//!
//! # Not included
//!
//! Publisher-side signing. A node only ever verifies, the contract crate
//! already carries `sign_record` behind its `publish` feature, and a second
//! signing implementation is a second thing that can disagree.

use ed25519_dalek::{Signature, VerifyingKey};
use freenet_stdlib::prelude::{CodeHash, ContractInstanceId, DelegateKey, Parameters};

use crate::contract::contract_id_from_code_hash;
use crate::driver::{ProbeIo, Step};

/// Domain-separation tag prefixed to every signed pointer record. Without it, a
/// signature the author produced under the same key for another purpose could
/// be replayed as a pointer record.
pub const POINTER_SIGNING_DOMAIN: &[u8] = b"freenet-pointer/state-v1";

/// Code hash of the frozen canonical pointer contract WASM, base58.
///
/// Pinned against `contracts/pointer-contract/CODEHASH` by
/// `pointer_code_hash_matches_the_frozen_artifact`. If that file ever changes,
/// every published pointer re-keys — a flag day, not a bump.
pub const POINTER_CODE_HASH_B58: &str = "8wnAPaSRY1oYZCz723fdwK6BgzL6q8ozP3buVovXnt6v";

/// Length of an Ed25519 verifying key.
pub const VERIFYING_KEY_LEN: usize = 32;
/// Length of a BLAKE3 code hash.
pub const CODE_HASH_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an encoded pointer record: `version_be ‖ code_hash ‖ signature`.
pub const POINTER_STATE_LEN: usize = 4 + CODE_HASH_LEN + SIGNATURE_LEN;

/// Highest resolvable pointer version. `u32::MAX` is reserved by the contract:
/// a record there could never be superseded.
pub const MAX_POINTER_VERSION: u32 = u32::MAX - 1;

/// An all-zero `code_hash` means the app is **withdrawn**. A consumer must stop
/// resolving rather than derive a key from 32 zero bytes; this resolver reports
/// it as [`PointerOutcome::Withdrawn`] and never wraps it in a
/// [`ResolvedPointer`].
pub const TOMBSTONE_CODE_HASH: [u8; CODE_HASH_LEN] = [0u8; CODE_HASH_LEN];

/// Longest permitted `app_id`.
pub const MAX_APP_ID_LEN: usize = 64;
/// Shortest possible params blob: a verifying key plus a one-byte `app_id`.
pub const MIN_POINTER_PARAMS_LEN: usize = VERIFYING_KEY_LEN + 1;
/// Longest possible params blob.
pub const MAX_POINTER_PARAMS_LEN: usize = VERIFYING_KEY_LEN + MAX_APP_ID_LEN;

/// Is `b` permitted inside an `app_id`? A closed, case-less ASCII set:
/// `a-z`, `0-9`, `.`, `-`, `_`.
///
/// Lowercase-and-ASCII-only is what removes any need for Unicode
/// normalization, and with it a class of confusable-identity attack where
/// visually identical `app_id`s address different pointers.
#[inline]
pub const fn is_valid_app_id_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
}

/// Is `bytes` the canonical little-endian encoding of an Ed25519 `y`
/// coordinate, i.e. `y < 2^255 - 19` once the sign bit is cleared?
///
/// `VerifyingKey::from_bytes` accepts non-canonical encodings, so two distinct
/// 32-byte strings can name the same key. For an ordinary signature check that
/// is harmless; here the params blob **is** the contract's address, so it would
/// mean two different pointer keys with the same author. The contract rejects
/// these at parse time, so this resolver must too or it would derive an address
/// the contract can never validate.
#[inline]
#[must_use]
pub fn is_canonical_field_element(bytes: &[u8; VERIFYING_KEY_LEN]) -> bool {
    // p = 2^255 - 19, little-endian.
    const P: [u8; VERIFYING_KEY_LEN] = {
        let mut p = [0xffu8; VERIFYING_KEY_LEN];
        p[0] = 0xed;
        p[31] = 0x7f;
        p
    };
    let mut y = *bytes;
    y[31] &= 0x7f; // the top bit carries the x sign, not part of y
    let mut i = VERIFYING_KEY_LEN;
    while i > 0 {
        i -= 1;
        if y[i] < P[i] {
            return true;
        }
        if y[i] > P[i] {
            return false;
        }
    }
    false // exactly p is not canonical either
}

/// Everything that can be wrong with a pointer's params, its record, or its
/// ordering relative to what the caller already trusts.
///
/// Variant-for-variant a mirror of the contract's own `PointerError`, plus the
/// two ordering outcomes ([`Self::Rollback`], [`Self::Conflict`]) that only a
/// consumer holding a [`PointerFloor`] can detect.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerError {
    /// Params were shorter than a key plus a one-byte `app_id`, or longer than
    /// a key plus [`MAX_APP_ID_LEN`].
    ParamsLength(usize),
    /// The author key is not a valid Ed25519 verifying key.
    ParamsKey,
    /// The author key decodes to a point but is not that point's canonical
    /// encoding (`y >= 2^255 - 19`). See [`is_canonical_field_element`].
    ParamsKeyNonCanonical,
    /// The author key is small-order. `verify_strict` refuses to verify under
    /// such a key, so a pointer with one could never accept any record.
    ParamsKeyWeak,
    /// An `app_id` byte is outside the permitted set.
    ParamsAppId(u8),
    /// The state was not exactly [`POINTER_STATE_LEN`] bytes.
    StateLength(usize),
    /// `version` was 0, which is reserved to mean "no pointer has ever been
    /// published" and must never appear on the wire.
    ZeroVersion,
    /// `version` was `u32::MAX`, which the contract reserves.
    ReservedVersion,
    /// The signature field is all zeros: a record that was built but never
    /// signed. Split out from [`Self::BadSignature`] because it is the one
    /// cause that is mechanically distinguishable, and a common publisher slip.
    SignatureUnset,
    /// The signature did not verify under the author key over these params.
    BadSignature,
}

impl PointerError {
    /// Whether a caller may fall back to its baked-in, build-time key because
    /// of this error. **Always `false`.**
    ///
    /// Every variant here means a peer served something this resolver refused,
    /// which says nothing about whether a pointer exists. Falling back on a
    /// rejection would make "serve 99 bytes of garbage" a cheaper downgrade
    /// than stalling the GET. Mirrors
    /// [`PointerOutcome::may_use_baked_in_fallback`] so a caller can ask the
    /// same question of either arm of a `Result`.
    #[must_use]
    pub fn may_use_baked_in_fallback(&self) -> bool {
        false
    }
}

impl core::fmt::Display for PointerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParamsLength(n) => write!(
                f,
                "pointer params must be {MIN_POINTER_PARAMS_LEN}..={MAX_POINTER_PARAMS_LEN} bytes, got {n}"
            ),
            Self::ParamsKey => write!(f, "pointer params do not start with a valid Ed25519 key"),
            Self::ParamsKeyNonCanonical => write!(
                f,
                "the author key is not a canonical Ed25519 encoding (y >= the field prime)"
            ),
            Self::ParamsKeyWeak => write!(
                f,
                "the author key is small-order; no signature can ever verify under it"
            ),
            Self::ParamsAppId(b) => {
                write!(f, "invalid app_id byte {b:#04x}; allowed: a-z 0-9 . - _")
            }
            Self::StateLength(n) => write!(
                f,
                "pointer state must be exactly {POINTER_STATE_LEN} bytes, got {n}"
            ),
            Self::ZeroVersion => write!(f, "pointer version 0 is reserved and never valid"),
            Self::ReservedVersion => write!(
                f,
                "pointer version {} is reserved: a pointer there could never be superseded",
                u32::MAX
            ),
            Self::SignatureUnset => write!(
                f,
                "the pointer signature is all zeros: the record was built but never signed"
            ),
            Self::BadSignature => write!(
                f,
                "pointer signature verification failed under the author key for these params"
            ),
        }
    }
}

impl std::error::Error for PointerError {}

impl From<PointerError> for crate::error::MigrateError {
    fn from(e: PointerError) -> Self {
        crate::error::MigrateError::Pointer(e)
    }
}

/// Build the pointer params byte string for `(author_vk, app_id)`:
/// `author_vk (32) ‖ app_id`.
///
/// Rejects exactly what the contract rejects, so a caller can never derive an
/// address whose params the contract would refuse. This is the only correct way
/// to construct pointer params: the pointer's key is
/// `BLAKE3(pointer_code_hash ‖ these bytes)`, so one byte of disagreement
/// between publisher and consumer yields a different, empty contract.
pub fn pointer_params(author_vk: &VerifyingKey, app_id: &[u8]) -> Result<Vec<u8>, PointerError> {
    if app_id.is_empty() || app_id.len() > MAX_APP_ID_LEN {
        return Err(PointerError::ParamsLength(VERIFYING_KEY_LEN + app_id.len()));
    }
    if let Some(&bad) = app_id.iter().find(|b| !is_valid_app_id_byte(**b)) {
        return Err(PointerError::ParamsAppId(bad));
    }
    if !is_canonical_field_element(author_vk.as_bytes()) {
        return Err(PointerError::ParamsKeyNonCanonical);
    }
    if author_vk.is_weak() {
        return Err(PointerError::ParamsKeyWeak);
    }
    let mut out = Vec::with_capacity(VERIFYING_KEY_LEN + app_id.len());
    out.extend_from_slice(author_vk.as_bytes());
    out.extend_from_slice(app_id);
    Ok(out)
}

/// Parse a pointer params blob back into `(author_vk, app_id)`.
///
/// The inverse of [`pointer_params`], applying the same rules. Provided so a
/// caller holding raw params (e.g. read back from storage) can check them
/// without reconstructing.
pub fn parse_pointer_params(bytes: &[u8]) -> Result<(VerifyingKey, &[u8]), PointerError> {
    if !(MIN_POINTER_PARAMS_LEN..=MAX_POINTER_PARAMS_LEN).contains(&bytes.len()) {
        return Err(PointerError::ParamsLength(bytes.len()));
    }
    let (key_bytes, app_id) = bytes.split_at(VERIFYING_KEY_LEN);
    let mut key = [0u8; VERIFYING_KEY_LEN];
    key.copy_from_slice(key_bytes);
    if !is_canonical_field_element(&key) {
        return Err(PointerError::ParamsKeyNonCanonical);
    }
    let author_vk = VerifyingKey::from_bytes(&key).map_err(|_| PointerError::ParamsKey)?;
    if author_vk.is_weak() {
        return Err(PointerError::ParamsKeyWeak);
    }
    if let Some(&bad) = app_id.iter().find(|b| !is_valid_app_id_byte(**b)) {
        return Err(PointerError::ParamsAppId(bad));
    }
    Ok((author_vk, app_id))
}

/// The bytes an author signs: `DOMAIN ‖ params ‖ version_be ‖ code_hash`.
///
/// The **whole params blob** is covered, which is what stops a record signed
/// for one of an author's apps being replayed into another pointer of theirs:
/// both verify under the same key, so without the params in the message they
/// would accept each other's records.
#[must_use]
pub fn pointer_signing_message(
    params: &[u8],
    version: u32,
    code_hash: &[u8; CODE_HASH_LEN],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(POINTER_SIGNING_DOMAIN.len() + params.len() + 4 + CODE_HASH_LEN);
    m.extend_from_slice(POINTER_SIGNING_DOMAIN);
    m.extend_from_slice(params);
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(code_hash);
    m
}

/// The address of the pointer contract for `(author_vk, app_id)`:
/// `BLAKE3(pointer_code_hash ‖ params)`.
///
/// Deterministic and offline — deriving a pointer's address needs no network
/// round trip, which is the whole point of binding `app_id` through params.
pub fn pointer_contract_id(
    author_vk: &VerifyingKey,
    app_id: &[u8],
) -> Result<ContractInstanceId, PointerError> {
    let params = pointer_params(author_vk, app_id)?;
    Ok(pointer_contract_id_from_params(&params))
}

/// [`pointer_contract_id`] for a caller that already holds the params blob.
fn pointer_contract_id_from_params(params: &[u8]) -> ContractInstanceId {
    // Infallible: POINTER_CODE_HASH_B58 is a compile-time constant pinned by
    // `pointer_code_hash_matches_the_frozen_artifact`, and a const that does
    // not decode to 32 bytes fails that test rather than any caller's request.
    let code_hash = crate::contract::decode_b58_32(POINTER_CODE_HASH_B58)
        .expect("POINTER_CODE_HASH_B58 is a valid 32-byte base58 constant");
    contract_id_from_code_hash(&code_hash, &Parameters::from(params.to_vec()))
}

/// A pointer record exactly as it appears on the wire.
///
/// Decoding is separate from verifying, and only [`Self::decode_verified`]
/// yields a record you may act on. Prefer the resolver
/// ([`PointerResolver`] / [`resolve_app_pointer`]) over handling records
/// directly: it also enforces the anti-rollback ordering, which no single
/// record can express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerRecord {
    /// Monotonically increasing. Starts at 1; 0 is never valid.
    pub version: u32,
    /// `BLAKE3(current_wasm)` of the app's real contract or delegate.
    pub code_hash: [u8; CODE_HASH_LEN],
    /// Ed25519 signature over [`pointer_signing_message`].
    pub signature: [u8; SIGNATURE_LEN],
}

impl PointerRecord {
    /// Decode the fixed [`POINTER_STATE_LEN`]-byte layout. Checks **nothing**
    /// beyond the length: no signature, no version bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, PointerError> {
        if bytes.len() != POINTER_STATE_LEN {
            return Err(PointerError::StateLength(bytes.len()));
        }
        let mut version = [0u8; 4];
        version.copy_from_slice(&bytes[..4]);
        let mut code_hash = [0u8; CODE_HASH_LEN];
        code_hash.copy_from_slice(&bytes[4..4 + CODE_HASH_LEN]);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[4 + CODE_HASH_LEN..]);
        Ok(Self {
            version: u32::from_be_bytes(version),
            code_hash,
            signature,
        })
    }

    /// Encode to the fixed [`POINTER_STATE_LEN`]-byte layout.
    #[must_use]
    pub fn encode(&self) -> [u8; POINTER_STATE_LEN] {
        let mut out = [0u8; POINTER_STATE_LEN];
        out[..4].copy_from_slice(&self.version.to_be_bytes());
        out[4..4 + CODE_HASH_LEN].copy_from_slice(&self.code_hash);
        out[4 + CODE_HASH_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// Check the version bounds and the Ed25519 signature, using dalek's
    /// `verify_strict` — the same check the contract makes, so this resolver is
    /// neither more nor less permissive than the network.
    pub fn verify(&self, params: &[u8], author_vk: &VerifyingKey) -> Result<(), PointerError> {
        if self.version == 0 {
            return Err(PointerError::ZeroVersion);
        }
        if self.version > MAX_POINTER_VERSION {
            return Err(PointerError::ReservedVersion);
        }
        if self.signature == [0u8; SIGNATURE_LEN] {
            return Err(PointerError::SignatureUnset);
        }
        let msg = pointer_signing_message(params, self.version, &self.code_hash);
        author_vk
            .verify_strict(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| PointerError::BadSignature)
    }

    /// Whether this record withdraws the app rather than naming current code.
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.code_hash == TOMBSTONE_CODE_HASH
    }
}

// NOTE: there is deliberately no `decode_verified(bytes, params)` helper here,
// although the contract crate has one. Inside the contract that is safe: the
// params come from the node's own contract instance. Exported from a *client*
// crate the same signature is a trap, because it takes its trust anchor from
// the same untrusted blob it is checking -- `decode_verified(attacker_state,
// attacker_params)` returns `Ok`, since the attacker signed with the key they
// put in the params. The accept path is `PointerResolver`, which verifies
// against a caller-supplied anchor fixed at construction.

/// A pointer record that has passed signature verification **and** the
/// anti-rollback check, and that names real code (never a tombstone).
///
/// Fields are private and there is no public constructor: the only way to hold
/// one is to have resolved it. That is the trust boundary made structural — a
/// caller cannot fabricate a `ResolvedPointer` and hand it to
/// [`Self::contract_id`], and cannot reach the key-derivation helpers with 32
/// zero bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPointer {
    version: u32,
    code_hash: [u8; CODE_HASH_LEN],
}

impl ResolvedPointer {
    /// The version this record carries. Persist it as the caller's next
    /// [`PointerFloor`].
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// `BLAKE3(current_wasm)` of the app's real contract or delegate.
    /// Guaranteed non-zero.
    #[must_use]
    pub fn code_hash(&self) -> [u8; CODE_HASH_LEN] {
        self.code_hash
    }

    /// The code hash rendered base58, as Freenet renders hashes in text.
    #[must_use]
    pub fn code_hash_b58(&self) -> String {
        CodeHash::new(self.code_hash).encode()
    }

    /// Derive the contract instance id for **your own** params.
    ///
    /// This is the step integrators get wrong. The pointer does not name a
    /// contract key; it names a *code hash*. `my_own_params` are your
    /// instance's params — the room owner's key, your delegate's config —
    /// **not** the pointer's params. That is why one pointer serves every
    /// instance of an app.
    #[must_use]
    pub fn contract_id(&self, my_own_params: &Parameters) -> ContractInstanceId {
        contract_id_from_code_hash(&self.code_hash, my_own_params)
    }

    /// Derive the delegate key for **your own** params. Same derivation,
    /// `BLAKE3(code_hash ‖ params)`, and the same warning as
    /// [`Self::contract_id`].
    #[must_use]
    pub fn delegate_key(&self, my_own_params: &Parameters) -> DelegateKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.code_hash);
        hasher.update(my_own_params.as_ref());
        DelegateKey::new(*hasher.finalize().as_bytes(), CodeHash::new(self.code_hash))
    }
}

/// What the caller already trusts: the highest pointer version it has ever
/// verified, and the code hash it accepted at that version.
///
/// This is the anti-rollback anchor. A resolver refuses any record older than
/// the floor, so an attacker who can serve a stale-but-validly-signed record
/// (or who can replay one from the network) cannot walk a consumer back to
/// superseded code. Persist `(version, code_hash)` alongside the resolved key
/// and pass it back on the next resolve.
///
/// A floor of [`PointerFloor::never_resolved`] means no pointer has ever
/// resolved on this install — the **only** state in which falling back to a
/// baked-in, build-time key is safe. Falling back whenever the pointer is
/// merely unreachable would itself be a keyless downgrade primitive: make the
/// pointer briefly unreachable and every consumer regresses to the stale key.
/// [`PointerOutcome::may_use_baked_in_fallback`] encodes that rule.
///
/// # Persist one floor **per `(author_vk, app_id)`**
///
/// A floor is meaningful only for the one pointer it came from. Each pointer
/// has its own address and its own independent version space, so an app that
/// resolves both `river.room-contract` and `river.chat-delegate` and stores a
/// single shared floor will either see spurious [`PointerOutcome::Stale`] or
/// carry a bound that is silently too low. Key your storage by the pair.
///
/// This is also where the settled rotation-by-convention story lands: rotating
/// to a new author key means a new pointer address and a fresh version space,
/// so it needs a fresh floor, not the old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerFloor {
    version: u32,
    code_hash: Option<[u8; CODE_HASH_LEN]>,
}

impl PointerFloor {
    /// No pointer has ever resolved on this install.
    #[must_use]
    pub fn never_resolved() -> Self {
        Self {
            version: 0,
            code_hash: None,
        }
    }

    /// The caller has previously verified `version` and accepted `code_hash`.
    ///
    /// Both halves are required. An earlier draft had a version-only
    /// constructor; it was removed because without the code hash the resolver
    /// cannot apply the equal-version tiebreak, so it would report a
    /// *substituted* code hash at the caller's current version as
    /// [`PointerOutcome::Unchanged`] — telling the caller nothing had changed
    /// while handing back a different key.
    ///
    /// `version` 0 means "never resolved" everywhere in this module, so
    /// `at(0, _)` is equivalent to [`Self::never_resolved`] and the code hash
    /// is discarded: a floor at version 0 cannot be the result of a real
    /// resolution, because the contract never accepts a version-0 record.
    #[must_use]
    pub fn at(version: u32, code_hash: [u8; CODE_HASH_LEN]) -> Self {
        if version == 0 {
            return Self::never_resolved();
        }
        Self {
            version,
            code_hash: Some(code_hash),
        }
    }

    /// The highest version verified so far; 0 when never resolved.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Whether a pointer has ever resolved on this install.
    #[must_use]
    pub fn has_ever_resolved(&self) -> bool {
        self.version > 0
    }
}

/// The result of a resolution attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerOutcome {
    /// A record strictly newer than the floor. Adopt its code hash, derive your
    /// key, and persist `(version, code_hash)` as the new floor.
    Resolved(ResolvedPointer),
    /// The current record is the one the caller already had: same version, and
    /// (where the floor carried one) the same code hash. Nothing to do.
    Unchanged(ResolvedPointer),
    /// The author has **withdrawn** this app: the current record carries the
    /// all-zero tombstone code hash. Stop resolving. Do not fall back to a
    /// baked-in key — the author is saying there is no current code, not that
    /// the old code is current again.
    Withdrawn {
        /// Version of the withdrawing record.
        version: u32,
    },
    /// No pointer has ever been published for this `(author, app_id)`, and none
    /// has ever resolved on this install. This is the one outcome in which
    /// falling back to a baked-in, build-time key is safe.
    NeverPublished,
    /// A validly-signed record **older** than the caller's floor, refused.
    ///
    /// This is **routine, not an attack signal**. The contract's own README
    /// notes that a node holding no copy yet — freshly bootstrapped, or
    /// recently evicted — can transiently serve an older validly-signed record,
    /// because `validate_state` has no prior state to compare against. It is an
    /// outcome rather than an error precisely so that an integrator does not
    /// treat an ordinary stale peer as an alarm (and, worse, fall back).
    ///
    /// **Keep using whatever you last resolved, and retry.** The rollback is
    /// already refused by the time you see this.
    Stale {
        /// Version the peer served.
        served: u32,
        /// The caller's floor, which it does not supersede.
        floor: u32,
    },
    /// Nothing could be learned: the GET timed out, failed, returned an empty
    /// body, or reported absence for a pointer that has resolved before.
    ///
    /// **Keep using whatever you last resolved.** Do not fall back to a
    /// baked-in key and do not treat this as "no pointer exists": an attacker
    /// who can make the pointer briefly unreachable would otherwise get a free
    /// downgrade. Two cases deliberately land here rather than in
    /// [`Self::NeverPublished`]: a definitively-absent pointer for a caller
    /// that has resolved before (a pointer that once resolved cannot
    /// legitimately become unpublished), and an **empty response body**, which
    /// is peer-supplied and so must never be strong enough to unlock the
    /// fallback — the contract rejects empty state as `Invalid`, so an empty
    /// body is a claim about the transport, not about contract state.
    Unavailable,
}

impl PointerOutcome {
    /// Whether the caller may fall back to the key it baked in at build time.
    ///
    /// True for [`Self::NeverPublished`] only. This is the README's rule in one
    /// place, so no caller has to re-derive it: fall back **only** if no
    /// pointer has ever resolved on this install.
    #[must_use]
    pub fn may_use_baked_in_fallback(&self) -> bool {
        matches!(self, Self::NeverPublished)
    }

    /// The verified record, for the two outcomes that carry one.
    #[must_use]
    pub fn resolved(&self) -> Option<&ResolvedPointer> {
        match self {
            Self::Resolved(r) | Self::Unchanged(r) => Some(r),
            _ => None,
        }
    }

    /// The floor to persist after this outcome, if it advances anything.
    ///
    /// **Includes [`Self::Withdrawn`]**, and that is the point. A withdrawal is
    /// a signed record at a version like any other, so a caller that stops
    /// resolving without persisting its version leaves its floor at the
    /// pre-withdrawal value — and any peer can then serve a real, validly
    /// signed pre-withdrawal record, which supersedes that stale floor and
    /// resurrects code the author explicitly withdrew. Persist this and the
    /// replay is refused as [`Self::Stale`].
    ///
    /// `None` for [`Self::NeverPublished`], [`Self::Stale`] and
    /// [`Self::Unavailable`], which learn nothing that moves the floor.
    #[must_use]
    pub fn next_floor(&self) -> Option<PointerFloor> {
        match self {
            Self::Resolved(r) | Self::Unchanged(r) => {
                Some(PointerFloor::at(r.version, r.code_hash))
            }
            Self::Withdrawn { version } => Some(PointerFloor::at(*version, TOMBSTONE_CODE_HASH)),
            Self::NeverPublished | Self::Stale { .. } | Self::Unavailable => None,
        }
    }
}

#[derive(Debug)]
enum Phase {
    Fetching,
    Done(Option<Result<PointerOutcome, PointerError>>),
}

/// The sans-IO pointer-resolution state machine, in the same shape as
/// [`crate::ProbeDriver`]: ask [`Self::next_action`] what to do, feed the
/// result back in, take the outcome at [`Step::Done`].
///
/// Use this directly in environments without awaitable request/response
/// correlation (the browser's shared-handler `WebApi`); otherwise
/// [`resolve_app_pointer`] pumps it for you over a [`PointerIo`].
///
/// The driver distinguishes a pointer that is **definitively absent**
/// ([`Self::on_absent`]) from one that is merely **unreachable**
/// ([`Self::on_unreachable`]), because conflating them is a downgrade
/// primitive: only a real negative answer may ever unlock a caller's baked-in
/// fallback. [`Self::on_absent`] is the *only* input that can produce
/// [`PointerOutcome::NeverPublished`] — in particular an empty response body
/// delivered to [`Self::on_response`] does not, because those bytes come from a
/// peer.
///
/// Every event method returns whether the event was accepted, so a caller
/// pumping events by hand (the browser's shared-handler `WebApi`, which has no
/// request/response correlation) can tell "ignored, still waiting" apart from
/// "delivered" instead of hanging silently on a mis-correlated id.
#[derive(Debug)]
pub struct PointerResolver {
    params: Vec<u8>,
    author_vk: VerifyingKey,
    pointer_id: ContractInstanceId,
    floor: PointerFloor,
    outstanding: bool,
    phase: Phase,
}

impl PointerResolver {
    /// Start a resolution for `(author_vk, app_id)` against `floor`.
    ///
    /// `author_vk` is the trust anchor and must come from a build-time constant
    /// (the app's `FREENET.md`), never from the network. Fails if the params
    /// would be ones the contract itself rejects.
    pub fn new(
        author_vk: &VerifyingKey,
        app_id: &[u8],
        floor: PointerFloor,
    ) -> Result<Self, PointerError> {
        let params = pointer_params(author_vk, app_id)?;
        let pointer_id = pointer_contract_id_from_params(&params);
        Ok(Self {
            params,
            author_vk: *author_vk,
            pointer_id,
            floor,
            outstanding: false,
            phase: Phase::Fetching,
        })
    }

    /// The pointer contract's address. Deterministic from the constructor's
    /// inputs, so a caller may read it before driving anything.
    #[must_use]
    pub fn pointer_id(&self) -> ContractInstanceId {
        self.pointer_id
    }

    /// The pointer's params blob, as signed over.
    #[must_use]
    pub fn pointer_params(&self) -> &[u8] {
        &self.params
    }

    /// The current instruction. Idempotent in the sense that it never advances
    /// the resolution; it keeps asking for the same GET until an event lands.
    /// (It does not deduplicate: a caller that loops on it without delivering
    /// an event will keep being told to issue the same GET.)
    ///
    /// The [`Step::Get`] this emits wants neither the contract code nor a
    /// subscription — the 100-byte record is the whole answer, and fetching the
    /// pointer's own ~130 KB WASM on every resolve would be pure waste.
    ///
    /// One resolution needs one GET, and the resolver does not retry:
    /// [`PointerOutcome::Unavailable`] is terminal for this instance. To retry,
    /// build a new resolver with the same floor. That keeps the retry policy
    /// (and its backoff) with the app, where the transport is.
    pub fn next_action(&mut self) -> Step {
        if matches!(self.phase, Phase::Done(_)) {
            return Step::Done;
        }
        self.outstanding = true;
        Step::Get(self.pointer_id)
    }

    /// Deliver the GET response for the pointer. Events for any other id, or
    /// after the resolution finished, are ignored.
    ///
    /// An **empty** body yields [`PointerOutcome::Unavailable`], never
    /// [`PointerOutcome::NeverPublished`]. An unpublished contract is a
    /// plausible reason to get nothing back, but so is a hostile or broken
    /// peer, and these bytes are peer-supplied: the contract rejects empty
    /// state as `Invalid`, so no honest node stores it. Treating it as a
    /// definitive negative would make "answer with zero bytes" a cheaper
    /// downgrade than stalling the GET. Use [`Self::on_absent`] for a real
    /// negative answer. Any other wrong length is a hard
    /// [`PointerError::StateLength`].
    ///
    /// Returns whether the event was accepted.
    pub fn on_response(&mut self, id: ContractInstanceId, state: &[u8]) -> bool {
        if !self.accepts(id) {
            return false;
        }
        self.outstanding = false;
        if state.is_empty() {
            self.phase = Phase::Done(Some(Ok(PointerOutcome::Unavailable)));
            return true;
        }
        let result = PointerRecord::decode(state)
            .and_then(|record| {
                record.verify(&self.params, &self.author_vk)?;
                Ok(record)
            })
            .map(|record| self.order(record));
        self.phase = Phase::Done(Some(result));
        true
    }

    /// Report that the pointer is **definitively absent**: the network answered
    /// and there is no contract state at that address.
    ///
    /// Only use this for a real negative answer. A timeout is
    /// [`Self::on_unreachable`]; reporting a timeout here would let anyone who
    /// can stall one GET push a first-run consumer onto its stale baked-in key.
    /// This is the only input that can produce
    /// [`PointerOutcome::NeverPublished`].
    ///
    /// Returns whether the event was accepted.
    pub fn on_absent(&mut self, id: ContractInstanceId) -> bool {
        if !self.accepts(id) {
            return false;
        }
        self.outstanding = false;
        let outcome = if self.floor.has_ever_resolved() {
            // A pointer that once resolved cannot legitimately become
            // unpublished, so this must not unlock the fallback.
            PointerOutcome::Unavailable
        } else {
            PointerOutcome::NeverPublished
        };
        self.phase = Phase::Done(Some(Ok(outcome)));
        true
    }

    /// Report that nothing could be learned: a timeout, a send failure, or any
    /// condition that is not a definitive negative answer.
    ///
    /// Returns whether the event was accepted.
    pub fn on_unreachable(&mut self, id: ContractInstanceId) -> bool {
        if !self.accepts(id) {
            return false;
        }
        self.outstanding = false;
        self.phase = Phase::Done(Some(Ok(PointerOutcome::Unavailable)));
        true
    }

    /// Take the terminal result (once). `None` until [`Step::Done`], or if
    /// already taken.
    pub fn take_outcome(&mut self) -> Option<Result<PointerOutcome, PointerError>> {
        match &mut self.phase {
            Phase::Done(outcome) => outcome.take(),
            Phase::Fetching => None,
        }
    }

    fn accepts(&self, id: ContractInstanceId) -> bool {
        self.outstanding && id == self.pointer_id && !matches!(self.phase, Phase::Done(_))
    }

    /// Anti-rollback ordering, applied only to an already-signature-verified
    /// record.
    ///
    /// The order is the contract's own: greater `version` wins, and at an equal
    /// version the **lower `code_hash`** wins. That tiebreak is not invented
    /// here — the frozen contract's `merge` is a total order on the encoded
    /// record (version, then code hash, then signature) precisely so two peers
    /// holding different equal-version records converge instead of splitting
    /// forever, and only the author can produce such a pair (a retried or
    /// threshold-signed publish is the realistic cause).
    ///
    /// A consumer applying a *different* rule would be worse than either
    /// choice: the network converges on the lower record, so a consumer that
    /// refused the disagreement outright would sit in a permanent error with no
    /// recovery until the author published a new version. Signature bytes are
    /// not compared, because a pair differing only in signature names the same
    /// code hash, which is all a consumer acts on.
    fn order(&self, record: PointerRecord) -> PointerOutcome {
        use core::cmp::Ordering;

        // `PointerFloor::at` never yields a resolved floor without a code hash
        // (and coerces version 0 to `never_resolved`), so `None` here means
        // "nothing has ever resolved" and any valid record supersedes it.
        let Some(floor_hash) = self.floor.code_hash else {
            return self.adopt(record);
        };

        match record.version.cmp(&self.floor.version) {
            // A peer served a strictly older record. Routine, not an attack:
            // a freshly-bootstrapped or recently-evicted node has no prior
            // state to compare against and can serve one transiently.
            Ordering::Less => PointerOutcome::Stale {
                served: record.version,
                floor: self.floor.version,
            },
            Ordering::Greater => self.adopt(record),
            // Equal version: break the tie exactly as the contract's `merge`
            // does, on the lower code hash.
            Ordering::Equal => match record.code_hash.cmp(&floor_hash) {
                Ordering::Less => self.adopt(record),
                // The caller already holds the winner, so this is a no-op --
                // and it reports the FLOOR's hash, never the served one, so a
                // losing record can never be handed back under a variant that
                // says nothing changed.
                Ordering::Equal | Ordering::Greater => self.keep_floor(floor_hash),
            },
        }
    }

    /// The incoming record wins the order.
    fn adopt(&self, record: PointerRecord) -> PointerOutcome {
        if record.is_tombstone() {
            return PointerOutcome::Withdrawn {
                version: record.version,
            };
        }
        PointerOutcome::Resolved(ResolvedPointer {
            version: record.version,
            code_hash: record.code_hash,
        })
    }

    /// The caller's existing floor wins the order: nothing to do.
    fn keep_floor(&self, floor_hash: [u8; CODE_HASH_LEN]) -> PointerOutcome {
        if floor_hash == TOMBSTONE_CODE_HASH {
            return PointerOutcome::Withdrawn {
                version: self.floor.version,
            };
        }
        PointerOutcome::Unchanged(ResolvedPointer {
            version: self.floor.version,
            code_hash: floor_hash,
        })
    }
}

/// What a transport learned about the pointer.
///
/// Three-way on purpose. The whole safety story rests on telling a **real
/// negative answer** apart from **not knowing**, because only the former may
/// unlock a caller's baked-in build-time key. A two-way `Option` cannot carry
/// that, which is why this exists rather than reusing [`ProbeIo`] directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerFetch {
    /// The pointer's raw state bytes, exactly as the network returned them.
    State(Vec<u8>),
    /// The network gave a real negative answer: there is no state at that
    /// address. Only return this for an actual "not found", never for a
    /// timeout — see [`PointerResolver::on_absent`].
    Absent,
    /// Nothing could be learned: a timeout, a send failure, a malformed
    /// response, anything that is not a definitive answer either way.
    Unreachable,
}

/// The per-environment I/O adapter for [`resolve_app_pointer`]: one GET,
/// awaited, with the app's own timeout.
///
/// Deliberately **not** [`ProbeIo`], although it is the same shape and the same
/// sans-IO convention. `ProbeIo::get` returns `Ok(None)` for a timeout, a send
/// failure *and* a miss, and its documented meaning is "a per-candidate miss,
/// the probe advances" — resilient behaviour that is right for a backward probe
/// over a lineage and wrong here, where the difference between "no pointer
/// exists" and "I could not reach it" is the difference between using a stale
/// key and keeping the right one.
///
/// Return `Err` only for conditions that should abort the resolution; the
/// caller sees it as [`ResolveError::Transport`].
///
/// Unlike `ProbeIo::get`, this GET should **not** request the contract code:
/// the 100-byte record is the whole answer, and the pointer's own WASM is
/// ~130 KB.
pub trait PointerIo {
    /// The app's transport error type (for the abort path only).
    type Error;

    /// GET the pointer's state, without subscribing and without requesting the
    /// contract code, bounded by a timeout of roughly
    /// [`crate::RECOMMENDED_PROBE_TIMEOUT_MS`].
    fn get_pointer(
        &mut self,
        id: ContractInstanceId,
    ) -> impl core::future::Future<Output = Result<PointerFetch, Self::Error>>;
}

/// Adapts an existing [`ProbeIo`] to [`PointerIo`] by mapping its ambiguous
/// `Ok(None)` to [`PointerFetch::Unreachable`].
///
/// The name is the warning. This is the **safe** mapping, not the complete one:
/// `ProbeIo` cannot report a real negative answer, so a pointer resolved
/// through this adapter can never return [`PointerOutcome::NeverPublished`] and
/// a first-run consumer can never legitimately reach its baked-in fallback. Use
/// it to reuse an adapter you already have; implement [`PointerIo`] directly
/// when you need the first-run path.
#[derive(Debug)]
pub struct ConservativeProbeIo<T>(pub T);

impl<T: ProbeIo> PointerIo for ConservativeProbeIo<T> {
    type Error = T::Error;

    async fn get_pointer(&mut self, id: ContractInstanceId) -> Result<PointerFetch, Self::Error> {
        Ok(match self.0.get(id).await? {
            Some(bytes) => PointerFetch::State(bytes),
            None => PointerFetch::Unreachable,
        })
    }
}

/// Why a [`resolve_app_pointer`] call did not produce an outcome.
///
/// The two causes are kept apart deliberately: a transport failure says nothing
/// about the pointer, while a [`PointerError`] is a statement about what the
/// network served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError<E> {
    /// The app's transport aborted (a [`PointerIo::get_pointer`] `Err`).
    Transport(E),
    /// The record or its params was rejected.
    Pointer(PointerError),
}

impl<E> ResolveError<E> {
    /// Whether a caller may fall back to its baked-in, build-time key because
    /// of this error. **Always `false`**, for either cause — see
    /// [`PointerError::may_use_baked_in_fallback`].
    #[must_use]
    pub fn may_use_baked_in_fallback(&self) -> bool {
        false
    }
}

impl<E: core::fmt::Display> core::fmt::Display for ResolveError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "pointer transport failed: {e}"),
            Self::Pointer(e) => write!(f, "{e}"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for ResolveError<E> {}

impl<E> From<PointerError> for ResolveError<E> {
    fn from(e: PointerError) -> Self {
        Self::Pointer(e)
    }
}

/// Resolve the current `code_hash` an author publishes for `app_id`.
///
/// The forward-discovery entry point, and the counterpart to this crate's
/// backward [`crate::migrate_contract`]: that one walks an author's own lineage
/// to recover state; this one asks the author's pointer contract what is
/// current now. The two are different operations and share nothing but a
/// sans-IO convention.
///
/// (Named for the *pointer contract*, not for this crate's older, unrelated
/// [`crate::SuccessorPointer`] primitive, which has a different signing domain
/// and message layout and is not interchangeable with it.)
///
/// `author_vk` is the whole trust anchor — see the module docs. `floor` is what
/// the caller already verified; pass [`PointerFloor::never_resolved`] on first
/// run, then persist [`PointerOutcome::next_floor`] and pass it back, **keyed
/// by `(author_vk, app_id)`**.
///
/// # Handling the result
///
/// Only [`PointerOutcome::NeverPublished`] permits falling back to a baked-in
/// key; [`PointerOutcome::may_use_baked_in_fallback`] and
/// [`ResolveError::may_use_baked_in_fallback`] answer that for every arm, so
/// neither an error nor an unreachable pointer can be mistaken for "no pointer
/// exists". Reaching `NeverPublished` at all requires a [`PointerIo`] that
/// reports [`PointerFetch::Absent`]; through [`ConservativeProbeIo`] it is
/// unreachable by construction.
pub async fn resolve_app_pointer<IO: PointerIo>(
    io: &mut IO,
    author_vk: &VerifyingKey,
    app_id: &[u8],
    floor: PointerFloor,
) -> Result<PointerOutcome, ResolveError<IO::Error>> {
    let mut resolver = PointerResolver::new(author_vk, app_id, floor)?;
    loop {
        match resolver.next_action() {
            Step::Get(id) => {
                match io.get_pointer(id).await.map_err(ResolveError::Transport)? {
                    PointerFetch::State(bytes) => resolver.on_response(id, &bytes),
                    PointerFetch::Absent => resolver.on_absent(id),
                    PointerFetch::Unreachable => resolver.on_unreachable(id),
                };
            }
            Step::Done => {
                return resolver
                    .take_outcome()
                    .expect("Step::Done implies an untaken outcome")
                    .map_err(ResolveError::Pointer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const APP_ID: &[u8] = b"river.room-contract";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Publisher-side signing, test-only on purpose: this crate resolves, it
    /// does not publish (the contract crate owns `sign_record`).
    fn sign(key: &SigningKey, params: &[u8], version: u32, code_hash: [u8; 32]) -> PointerRecord {
        let sig = key.sign(&pointer_signing_message(params, version, &code_hash));
        PointerRecord {
            version,
            code_hash,
            signature: sig.to_bytes(),
        }
    }

    fn published(seed: u8, version: u32, code_hash: [u8; 32]) -> (VerifyingKey, Vec<u8>, Vec<u8>) {
        let key = signing_key(seed);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let state = sign(&key, &params, version, code_hash).encode().to_vec();
        (vk, params, state)
    }

    /// Drive a resolver to completion against one canned fetch result.
    fn resolve_with(
        vk: &VerifyingKey,
        floor: PointerFloor,
        fetch: PointerFetch,
    ) -> Result<PointerOutcome, PointerError> {
        let mut r = PointerResolver::new(vk, APP_ID, floor).unwrap();
        let Step::Get(id) = r.next_action() else {
            panic!("a fresh resolver must ask for the pointer");
        };
        let accepted = match &fetch {
            PointerFetch::State(bytes) => r.on_response(id, bytes),
            PointerFetch::Absent => r.on_absent(id),
            PointerFetch::Unreachable => r.on_unreachable(id),
        };
        assert!(accepted, "an event for the outstanding id must be accepted");
        assert_eq!(r.next_action(), Step::Done);
        r.take_outcome().expect("Done implies an outcome")
    }

    fn state(bytes: &[u8]) -> PointerFetch {
        PointerFetch::State(bytes.to_vec())
    }

    // ---- happy path -----------------------------------------------------

    #[test]
    fn resolves_a_validly_signed_record_on_first_run() {
        let (vk, _params, s) = published(7, 3, [0x11; 32]);
        let outcome = resolve_with(&vk, PointerFloor::never_resolved(), state(&s)).unwrap();
        assert!(
            !outcome.may_use_baked_in_fallback(),
            "a resolved pointer must never unlock the baked-in fallback"
        );
        let r = outcome.resolved().expect("Resolved carries a record");
        assert_eq!(r.version(), 3);
        assert_eq!(r.code_hash(), [0x11; 32]);
        assert!(matches!(outcome, PointerOutcome::Resolved(_)));
        assert_eq!(
            outcome.next_floor(),
            Some(PointerFloor::at(3, [0x11; 32])),
            "a resolution must advance the floor"
        );
    }

    #[test]
    fn a_newer_version_supersedes_the_floor() {
        let (vk, _params, s) = published(7, 9, [0x22; 32]);
        let outcome = resolve_with(&vk, PointerFloor::at(4, [0x11; 32]), state(&s)).unwrap();
        assert!(matches!(outcome, PointerOutcome::Resolved(r) if r.version() == 9));
    }

    #[test]
    fn the_same_record_again_is_unchanged_not_stale() {
        let (vk, _params, s) = published(7, 5, [0x33; 32]);
        let outcome = resolve_with(&vk, PointerFloor::at(5, [0x33; 32]), state(&s)).unwrap();
        assert!(matches!(outcome, PointerOutcome::Unchanged(r) if r.code_hash() == [0x33; 32]));
        assert!(!outcome.may_use_baked_in_fallback());
        assert_eq!(outcome.next_floor(), Some(PointerFloor::at(5, [0x33; 32])));
    }

    #[test]
    fn a_full_release_sequence_advances_the_floor_monotonically() {
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let mut floor = PointerFloor::never_resolved();
        for (version, hash) in [(1u32, [0x01u8; 32]), (2, [0x02; 32]), (7, [0x07; 32])] {
            let s = sign(&key, &params, version, hash).encode().to_vec();
            let outcome = resolve_with(&vk, floor, state(&s)).unwrap();
            let PointerOutcome::Resolved(r) = outcome else {
                panic!("release {version} should resolve, got {outcome:?}");
            };
            assert_eq!(r.code_hash(), hash);
            floor = outcome
                .next_floor()
                .expect("a resolution advances the floor");
        }
        assert_eq!(floor.version(), 7);
        // Every earlier record in that sequence is now refused as stale.
        for version in [1u32, 2] {
            let s = sign(&key, &params, version, [version as u8; 32])
                .encode()
                .to_vec();
            assert!(matches!(
                resolve_with(&vk, floor, state(&s)).unwrap(),
                PointerOutcome::Stale { served, floor: f } if served == version && f == 7
            ));
        }
    }

    // ---- signature rejection -------------------------------------------

    #[test]
    fn a_tampered_code_hash_is_rejected() {
        let (vk, _params, s) = published(7, 3, [0x11; 32]);
        let mut tampered = s.clone();
        tampered[4] ^= 0xff; // first code_hash byte
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&tampered)),
            Err(PointerError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_version_is_rejected() {
        let (vk, _params, s) = published(7, 3, [0x11; 32]);
        let mut tampered = s.clone();
        tampered[3] = 9; // claim version 9 under a version-3 signature
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&tampered)),
            Err(PointerError::BadSignature)
        );
    }

    #[test]
    fn a_record_signed_by_another_key_is_rejected() {
        let victim = signing_key(7).verifying_key();
        let attacker = signing_key(200);
        // The attacker signs over the VICTIM's params, so only the key differs.
        let params = pointer_params(&victim, APP_ID).unwrap();
        let s = sign(&attacker, &params, 99, [0xee; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&victim, PointerFloor::never_resolved(), state(&s)),
            Err(PointerError::BadSignature)
        );
    }

    #[test]
    fn a_record_from_another_app_of_the_same_author_is_rejected() {
        let key = signing_key(7);
        let vk = key.verifying_key();
        // Signed for a DIFFERENT app_id, same author key: verifies under the
        // same key, so only the params binding stops the replay.
        let other_params = pointer_params(&vk, b"river.chat-delegate").unwrap();
        let s = sign(&key, &other_params, 42, [0x44; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&s)),
            Err(PointerError::BadSignature)
        );
    }

    #[test]
    fn an_unsigned_record_is_named_as_such() {
        let vk = signing_key(7).verifying_key();
        let s = PointerRecord {
            version: 3,
            code_hash: [0x11; 32],
            signature: [0u8; 64],
        }
        .encode()
        .to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&s)),
            Err(PointerError::SignatureUnset)
        );
    }

    #[test]
    fn a_non_canonical_scalar_s_is_rejected() {
        // NOTE: this pins dalek's S-canonicity check (`s < L`), which BOTH
        // `verify` and `verify_strict` apply -- so it does NOT pin strictness.
        // The properties unique to `verify_strict` (small-order R, non-canonical
        // A, the cofactorless equation) are pinned by the source scrape
        // `the_resolver_still_verifies_the_way_the_contract_does` in
        // tests/pointer_contract_parity.rs. Both are needed; neither replaces
        // the other.
        //
        // L, the order of the Ed25519 base point, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let record = sign(&key, &params, 3, [0x11; 32]);

        // S' = S + L is an equally valid cofactored signature.
        let mut malleable = record;
        let mut carry = 0u16;
        for (i, l) in L.iter().enumerate() {
            let sum = u16::from(record.signature[32 + i]) + u16::from(*l) + carry;
            malleable.signature[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_ne!(malleable.signature, record.signature);
        let s = malleable.encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&s)),
            Err(PointerError::BadSignature)
        );
    }

    // ---- anti-rollback and the equal-version tiebreak --------------------

    #[test]
    fn an_older_validly_signed_record_is_refused_as_stale() {
        // The classic replay -- and also what a freshly-bootstrapped peer
        // serves by accident, which is why it is an outcome, not an error.
        let (vk, _params, old_state) = published(7, 2, [0xaa; 32]);
        let outcome =
            resolve_with(&vk, PointerFloor::at(6, [0xbb; 32]), state(&old_state)).unwrap();
        assert_eq!(
            outcome,
            PointerOutcome::Stale {
                served: 2,
                floor: 6
            }
        );
        assert!(!outcome.may_use_baked_in_fallback());
        assert_eq!(
            outcome.next_floor(),
            None,
            "a stale record must not move the floor"
        );
    }

    #[test]
    fn at_equal_version_the_lower_code_hash_wins_as_the_contract_merges() {
        // Only the author can produce two valid records at one version (a
        // retried or threshold-signed publish). The network converges on the
        // lower encoding, so the consumer must agree or it bricks itself.
        let low = [0x11u8; 32];
        let high = [0x99u8; 32];

        // Holding the HIGHER hash, served the lower: adopt it.
        let (vk, _p, low_state) = published(7, 5, low);
        let outcome = resolve_with(&vk, PointerFloor::at(5, high), state(&low_state)).unwrap();
        assert!(
            matches!(outcome, PointerOutcome::Resolved(r) if r.code_hash() == low),
            "the lower code hash must win, got {outcome:?}"
        );

        // Holding the LOWER hash, served the higher: keep what we have -- and
        // report OUR hash, never the served one.
        let (_vk2, _p2, high_state) = published(7, 5, high);
        let outcome = resolve_with(&vk, PointerFloor::at(5, low), state(&high_state)).unwrap();
        let PointerOutcome::Unchanged(r) = outcome else {
            panic!("expected Unchanged, got {outcome:?}");
        };
        assert_eq!(
            r.code_hash(),
            low,
            "Unchanged must carry the floor's hash, not a losing served one"
        );
    }

    #[test]
    fn the_equal_version_tiebreak_converges_from_both_orderings() {
        // Whichever record a consumer latched first, both end at the same hash
        // -- the property that makes this recoverable rather than a permanent
        // split.
        let low = [0x11u8; 32];
        let high = [0x99u8; 32];
        let (vk, _p, low_state) = published(7, 5, low);
        let (_v, _p2, high_state) = published(7, 5, high);

        let a = resolve_with(&vk, PointerFloor::at(5, high), state(&low_state)).unwrap();
        let b = resolve_with(&vk, PointerFloor::at(5, low), state(&high_state)).unwrap();
        assert_eq!(
            a.next_floor().unwrap(),
            b.next_floor().unwrap(),
            "both orderings must converge on one floor"
        );
        assert_eq!(a.resolved().unwrap().code_hash(), low);
        assert_eq!(b.resolved().unwrap().code_hash(), low);
    }

    #[test]
    fn version_zero_never_resolves() {
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        // Genuinely signed at version 0 -- rejected on the version rule, not
        // because the signature happens not to check out.
        let s = sign(&key, &params, 0, [0x11; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&s)),
            Err(PointerError::ZeroVersion)
        );
    }

    #[test]
    fn the_reserved_max_version_never_resolves() {
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let s = sign(&key, &params, u32::MAX, [0x11; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&s)),
            Err(PointerError::ReservedVersion)
        );
        // One below is fine, and the boundary is the literal the contract uses.
        assert_eq!(MAX_POINTER_VERSION, u32::MAX - 1);
        let ok = sign(&key, &params, MAX_POINTER_VERSION, [0x11; 32])
            .encode()
            .to_vec();
        assert!(matches!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&ok)).unwrap(),
            PointerOutcome::Resolved(_)
        ));
    }

    // ---- absence, unreachability, and the fallback rule -------------------

    #[test]
    fn an_unpublished_pointer_is_never_published_on_first_run() {
        let vk = signing_key(7).verifying_key();
        let outcome =
            resolve_with(&vk, PointerFloor::never_resolved(), PointerFetch::Absent).unwrap();
        assert_eq!(outcome, PointerOutcome::NeverPublished);
        assert!(
            outcome.may_use_baked_in_fallback(),
            "first run with a definitively absent pointer is the one safe case"
        );
        assert_eq!(outcome.next_floor(), None);
    }

    #[test]
    fn an_empty_body_is_unavailable_and_cannot_unlock_the_fallback() {
        // Regression: an empty body is peer-supplied, and the contract rejects
        // empty state as Invalid, so no honest node stores it. Treating it as a
        // definitive negative would make "answer with zero bytes" a CHEAPER
        // downgrade than stalling the GET.
        let vk = signing_key(7).verifying_key();
        let outcome = resolve_with(&vk, PointerFloor::never_resolved(), state(&[])).unwrap();
        assert_eq!(outcome, PointerOutcome::Unavailable);
        assert!(!outcome.may_use_baked_in_fallback());
    }

    #[test]
    fn a_vanished_pointer_cannot_unlock_the_baked_in_fallback() {
        // Absence reported to a caller that HAS resolved before: a pointer
        // cannot legitimately become unpublished, so this must not read as
        // "never published" -- that would be a downgrade primitive.
        let vk = signing_key(7).verifying_key();
        let outcome =
            resolve_with(&vk, PointerFloor::at(4, [0x11; 32]), PointerFetch::Absent).unwrap();
        assert_eq!(outcome, PointerOutcome::Unavailable);
        assert!(!outcome.may_use_baked_in_fallback());
    }

    #[test]
    fn a_timeout_is_unavailable_even_on_first_run() {
        let vk = signing_key(7).verifying_key();
        let outcome = resolve_with(
            &vk,
            PointerFloor::never_resolved(),
            PointerFetch::Unreachable,
        )
        .unwrap();
        assert_eq!(outcome, PointerOutcome::Unavailable);
        assert!(
            !outcome.may_use_baked_in_fallback(),
            "one stalled GET must not push a first-run consumer onto its stale baked-in key"
        );
    }

    #[test]
    fn no_rejection_error_ever_permits_the_baked_in_fallback() {
        // The error path is the attacker's cheapest move (99 bytes of garbage),
        // so it must answer the fallback question the same way as an outcome.
        let vk = signing_key(7).verifying_key();
        for bad in [
            PointerError::StateLength(99),
            PointerError::BadSignature,
            PointerError::SignatureUnset,
            PointerError::ZeroVersion,
            PointerError::ReservedVersion,
            PointerError::ParamsAppId(b'!'),
        ] {
            assert!(!bad.may_use_baked_in_fallback(), "{bad:?}");
            let wrapped: ResolveError<&str> = bad.into();
            assert!(!wrapped.may_use_baked_in_fallback());
        }
        assert!(!ResolveError::Transport("socket closed").may_use_baked_in_fallback());
        // And the outcome side agrees for everything except NeverPublished.
        let (_vk, _p, s) = published(7, 3, [0x11; 32]);
        for outcome in [
            resolve_with(&vk, PointerFloor::never_resolved(), state(&s)).unwrap(),
            resolve_with(&vk, PointerFloor::at(9, [0x11; 32]), state(&s)).unwrap(),
            resolve_with(
                &vk,
                PointerFloor::never_resolved(),
                PointerFetch::Unreachable,
            )
            .unwrap(),
        ] {
            assert!(!outcome.may_use_baked_in_fallback(), "{outcome:?}");
        }
    }

    #[test]
    fn a_wrong_length_body_is_a_hard_error_not_absence() {
        let vk = signing_key(7).verifying_key();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&[0u8; 99])),
            Err(PointerError::StateLength(99))
        );
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), state(&[0u8; 101])),
            Err(PointerError::StateLength(101))
        );
        assert_eq!(POINTER_STATE_LEN, 100);
    }

    // ---- tombstone -------------------------------------------------------

    #[test]
    fn a_tombstone_is_withdrawn_and_carries_no_resolved_pointer() {
        assert_eq!(TOMBSTONE_CODE_HASH, [0u8; 32]);
        let (vk, _params, s) = published(7, 8, TOMBSTONE_CODE_HASH);
        let outcome = resolve_with(&vk, PointerFloor::at(4, [0x11; 32]), state(&s)).unwrap();
        assert_eq!(outcome, PointerOutcome::Withdrawn { version: 8 });
        assert!(outcome.resolved().is_none());
        assert!(
            !outcome.may_use_baked_in_fallback(),
            "withdrawn means there is no current code, not that the old code is current"
        );
    }

    #[test]
    fn a_withdrawal_advances_the_floor_so_it_cannot_be_resurrected() {
        // Regression: if `Withdrawn` did not move the floor, any peer could
        // serve a real pre-withdrawal record afterwards and the consumer would
        // adopt code the author explicitly withdrew.
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();

        let tomb = sign(&key, &params, 8, TOMBSTONE_CODE_HASH)
            .encode()
            .to_vec();
        let outcome = resolve_with(&vk, PointerFloor::at(4, [0x11; 32]), state(&tomb)).unwrap();
        let floor = outcome
            .next_floor()
            .expect("a withdrawal must advance the floor");
        assert_eq!(floor, PointerFloor::at(8, TOMBSTONE_CODE_HASH));

        // A real, validly-signed pre-withdrawal record no longer resurrects it.
        let pre = sign(&key, &params, 5, [0x55; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, floor, state(&pre)).unwrap(),
            PointerOutcome::Stale {
                served: 5,
                floor: 8
            }
        );
        // Re-reading the withdrawal is still a withdrawal, not a resurrection.
        assert_eq!(
            resolve_with(&vk, floor, state(&tomb)).unwrap(),
            PointerOutcome::Withdrawn { version: 8 }
        );
    }

    #[test]
    fn a_rolled_back_tombstone_is_still_refused() {
        let (vk, _params, s) = published(7, 2, TOMBSTONE_CODE_HASH);
        assert_eq!(
            resolve_with(&vk, PointerFloor::at(6, [0x11; 32]), state(&s)).unwrap(),
            PointerOutcome::Stale {
                served: 2,
                floor: 6
            }
        );
    }

    // ---- params ----------------------------------------------------------

    #[test]
    fn app_id_charset_and_length_are_enforced() {
        let vk = signing_key(7).verifying_key();
        assert_eq!(MAX_APP_ID_LEN, 64, "must match the contract's literal");
        assert_eq!(
            pointer_params(&vk, b"River.Room").unwrap_err(),
            PointerError::ParamsAppId(b'R')
        );
        assert_eq!(
            pointer_params(&vk, b"river room").unwrap_err(),
            PointerError::ParamsAppId(b' ')
        );
        assert_eq!(
            pointer_params(&vk, b"").unwrap_err(),
            PointerError::ParamsLength(32)
        );
        let too_long = vec![b'a'; MAX_APP_ID_LEN + 1];
        assert_eq!(
            pointer_params(&vk, &too_long).unwrap_err(),
            PointerError::ParamsLength(32 + MAX_APP_ID_LEN + 1)
        );
        // The boundary itself is fine, and so is every permitted byte class.
        assert!(pointer_params(&vk, &[b'a'; MAX_APP_ID_LEN]).is_ok());
        assert!(pointer_params(&vk, b"abcxyz0123456789.-_").is_ok());
        for b in 0u8..=255 {
            let permitted = b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_".contains(&b);
            assert_eq!(
                is_valid_app_id_byte(b),
                permitted,
                "app_id byte {b:#04x} classified wrongly"
            );
        }
    }

    #[test]
    fn a_bad_app_id_fails_the_resolver_before_any_io() {
        let vk = signing_key(7).verifying_key();
        assert_eq!(
            PointerResolver::new(&vk, b"NOPE", PointerFloor::never_resolved())
                .err()
                .unwrap(),
            PointerError::ParamsAppId(b'N')
        );
    }

    #[test]
    fn a_small_order_author_key_is_refused() {
        // The order-8 point that dalek reports as weak.
        let weak = VerifyingKey::from_bytes(&[
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ])
        .unwrap();
        assert!(weak.is_weak());
        assert_eq!(
            pointer_params(&weak, APP_ID).unwrap_err(),
            PointerError::ParamsKeyWeak
        );
    }

    #[test]
    fn a_non_canonical_author_key_is_refused() {
        // y = p (2^255 - 19) exactly: decodes, but is not the canonical
        // encoding, so it would be a second address for one author.
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0xed;
        bytes[31] = 0x7f;
        assert!(!is_canonical_field_element(&bytes));
        assert_eq!(
            parse_pointer_params(&[&bytes[..], APP_ID].concat()).unwrap_err(),
            PointerError::ParamsKeyNonCanonical
        );
    }

    #[test]
    fn the_sign_bit_is_not_part_of_the_y_coordinate() {
        // Byte 31 bit 7 carries the x sign, so masking it must not make an
        // otherwise-canonical key look out of range.
        let key = signing_key(7);
        let mut bytes = *key.verifying_key().as_bytes();
        assert!(is_canonical_field_element(&bytes));
        bytes[31] |= 0x80;
        assert!(
            is_canonical_field_element(&bytes),
            "setting the sign bit must not change canonicality of y"
        );
    }

    #[test]
    fn params_round_trip() {
        let vk = signing_key(7).verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let (back_vk, back_app) = parse_pointer_params(&params).unwrap();
        assert_eq!(back_vk, vk);
        assert_eq!(back_app, APP_ID);
    }

    #[test]
    fn params_shorter_than_a_key_are_refused() {
        assert_eq!(
            parse_pointer_params(&[0u8; 32]).unwrap_err(),
            PointerError::ParamsLength(32)
        );
        assert_eq!(
            parse_pointer_params(&[]).unwrap_err(),
            PointerError::ParamsLength(0)
        );
    }

    #[test]
    fn record_encode_decode_round_trips() {
        let record = PointerRecord {
            version: 0x0102_0304,
            code_hash: [0x5a; 32],
            signature: [0x7e; 64],
        };
        let bytes = record.encode();
        assert_eq!(bytes.len(), POINTER_STATE_LEN);
        // Version is big-endian on the wire.
        assert_eq!(&bytes[..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(PointerRecord::decode(&bytes).unwrap(), record);
    }

    // ---- the floor -------------------------------------------------------

    #[test]
    fn a_floor_at_version_zero_is_never_resolved() {
        // Version 0 can never be the result of a real resolution, so a floor
        // claiming one is treated as "never resolved" rather than silently
        // trusting a code hash that no record could have carried.
        let floor = PointerFloor::at(0, [0x11; 32]);
        assert_eq!(floor, PointerFloor::never_resolved());
        assert!(!floor.has_ever_resolved());
        assert_eq!(floor.version(), 0);
    }

    // ---- driver semantics ------------------------------------------------

    #[test]
    fn an_event_before_the_get_is_issued_is_ignored() {
        // The browser path pumps events by hand with no request/response
        // correlation, so a late event from a PREVIOUS resolver can land on a
        // fresh one. Accepting it would let a stale `on_absent` unlock the
        // baked-in fallback before this resolver has asked anything.
        let vk = signing_key(7).verifying_key();
        let mut r = PointerResolver::new(&vk, APP_ID, PointerFloor::never_resolved()).unwrap();
        let id = r.pointer_id();
        assert!(!r.on_absent(id), "an event before the GET must be rejected");
        assert!(!r.on_unreachable(id));
        assert!(!r.on_response(id, &[]));
        assert!(r.take_outcome().is_none());
        assert_eq!(
            r.next_action(),
            Step::Get(id),
            "the resolver must still be waiting to issue its GET"
        );
    }

    #[test]
    fn a_response_for_another_contract_is_ignored() {
        let (vk, _params, s) = published(7, 3, [0x11; 32]);
        let mut r = PointerResolver::new(&vk, APP_ID, PointerFloor::never_resolved()).unwrap();
        let Step::Get(id) = r.next_action() else {
            panic!("expected a GET");
        };
        let other = pointer_contract_id(&vk, b"river.chat-delegate").unwrap();
        assert_ne!(other, id);
        assert!(!r.on_response(other, &s), "a mis-correlated id is rejected");
        assert_eq!(
            r.next_action(),
            Step::Get(id),
            "an unrelated response must not finish the resolution"
        );
        assert!(r.take_outcome().is_none());
        // The real answer still lands.
        assert!(r.on_response(id, &s));
        assert_eq!(r.next_action(), Step::Done);
        assert!(matches!(
            r.take_outcome().unwrap().unwrap(),
            PointerOutcome::Resolved(_)
        ));
    }

    #[test]
    fn the_outcome_is_taken_only_once() {
        let (vk, _params, s) = published(7, 3, [0x11; 32]);
        let mut r = PointerResolver::new(&vk, APP_ID, PointerFloor::never_resolved()).unwrap();
        let Step::Get(id) = r.next_action() else {
            panic!("expected a GET");
        };
        assert!(r.on_response(id, &s));
        assert!(r.take_outcome().is_some());
        assert!(r.take_outcome().is_none());
        // And a late event cannot revive it.
        assert!(!r.on_response(id, &s));
        assert!(r.take_outcome().is_none());
    }

    #[test]
    fn the_pointer_address_is_deterministic_and_app_scoped() {
        let vk = signing_key(7).verifying_key();
        let a = pointer_contract_id(&vk, b"river.room-contract").unwrap();
        let b = pointer_contract_id(&vk, b"river.room-contract").unwrap();
        let c = pointer_contract_id(&vk, b"river.chat-delegate").unwrap();
        let d =
            pointer_contract_id(&signing_key(8).verifying_key(), b"river.room-contract").unwrap();
        assert_eq!(a, b, "same inputs must give the same address");
        assert_ne!(a, c, "app_id must scope the address");
        assert_ne!(a, d, "author must scope the address");
    }

    // ---- consumer-side derivation ---------------------------------------

    #[test]
    fn derivation_uses_the_consumers_own_params() {
        let (vk, pointer_params_bytes, s) = published(7, 3, [0x11; 32]);
        let outcome = resolve_with(&vk, PointerFloor::never_resolved(), state(&s)).unwrap();
        let r = outcome.resolved().unwrap();
        let mine = Parameters::from(b"my-own-instance-params".to_vec());
        let theirs = Parameters::from(pointer_params_bytes);
        assert_ne!(
            r.contract_id(&mine),
            r.contract_id(&theirs),
            "the pointer's own params must not be interchangeable with the consumer's"
        );
        assert_eq!(
            r.contract_id(&mine),
            contract_id_from_code_hash(&[0x11; 32], &mine)
        );
    }

    #[test]
    fn delegate_derivation_matches_stdlib() {
        let (vk, _params, s) = published(7, 3, [0x11; 32]);
        let outcome = resolve_with(&vk, PointerFloor::never_resolved(), state(&s)).unwrap();
        let r = outcome.resolved().unwrap();
        let params = Parameters::from(b"delegate-config".to_vec());
        let expected =
            DelegateKey::from_params(CodeHash::new([0x11; 32]).encode(), &params).unwrap();
        assert_eq!(r.delegate_key(&params), expected);
        assert_eq!(r.code_hash_b58(), CodeHash::new([0x11; 32]).encode());
    }

    // ---- errors ----------------------------------------------------------

    #[test]
    fn pointer_errors_convert_into_the_crate_error_type() {
        let e: crate::MigrateError = PointerError::BadSignature.into();
        assert_eq!(e, crate::MigrateError::Pointer(PointerError::BadSignature));
        let rendered = e.to_string();
        assert!(
            rendered.contains("successor-pointer resolution failed")
                && rendered.contains("signature verification failed"),
            "unhelpful rendering: {rendered}"
        );
        // And the two older SuccessorPointer variants stay distinct from it.
        assert_ne!(e, crate::MigrateError::BadSignature);
    }

    // ---- the pumped entry point ------------------------------------------

    struct CannedIo {
        fetch: Result<PointerFetch, &'static str>,
        calls: usize,
    }

    impl PointerIo for CannedIo {
        type Error = &'static str;

        async fn get_pointer(
            &mut self,
            _id: ContractInstanceId,
        ) -> Result<PointerFetch, Self::Error> {
            self.calls += 1;
            self.fetch.clone()
        }
    }

    struct CannedProbeIo(Option<Vec<u8>>);

    impl ProbeIo for CannedProbeIo {
        type Error = &'static str;

        async fn get(&mut self, _id: ContractInstanceId) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.clone())
        }
    }

    /// Every future in these tests is ready on first poll (the canned I/O never
    /// waits), so a no-op waker and a single poll are a complete executor.
    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut f = core::pin::pin!(f);
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("a canned-I/O future must not pend"),
        }
    }

    #[test]
    fn the_pumped_entry_point_resolves() {
        let (vk, _params, s) = published(7, 3, [0x11; 32]);
        let mut io = CannedIo {
            fetch: Ok(PointerFetch::State(s)),
            calls: 0,
        };
        let outcome = block_on(resolve_app_pointer(
            &mut io,
            &vk,
            APP_ID,
            PointerFloor::never_resolved(),
        ))
        .unwrap();
        assert!(matches!(outcome, PointerOutcome::Resolved(r) if r.version() == 3));
        assert_eq!(io.calls, 1, "resolution is exactly one GET");
    }

    #[test]
    fn the_pumped_entry_point_reaches_never_published_on_a_real_negative() {
        // The whole point of PointerIo over ProbeIo: a first-run consumer whose
        // transport can say "not found" CAN legitimately fall back.
        let vk = signing_key(7).verifying_key();
        let mut io = CannedIo {
            fetch: Ok(PointerFetch::Absent),
            calls: 0,
        };
        let outcome = block_on(resolve_app_pointer(
            &mut io,
            &vk,
            APP_ID,
            PointerFloor::never_resolved(),
        ))
        .unwrap();
        assert_eq!(outcome, PointerOutcome::NeverPublished);
        assert!(outcome.may_use_baked_in_fallback());
    }

    #[test]
    fn the_pumped_entry_point_separates_transport_from_pointer_errors() {
        let (vk, _params, s) = published(7, 2, [0xaa; 32]);
        let mut io = CannedIo {
            fetch: Err("socket closed"),
            calls: 0,
        };
        assert_eq!(
            block_on(resolve_app_pointer(
                &mut io,
                &vk,
                APP_ID,
                PointerFloor::never_resolved()
            )),
            Err(ResolveError::Transport("socket closed"))
        );

        let mut io = CannedIo {
            fetch: Ok(PointerFetch::State(vec![0u8; 7])),
            calls: 0,
        };
        assert_eq!(
            block_on(resolve_app_pointer(
                &mut io,
                &vk,
                APP_ID,
                PointerFloor::never_resolved()
            )),
            Err(ResolveError::Pointer(PointerError::StateLength(7)))
        );

        // A stale record is an OUTCOME, not an error: a bootstrapping peer
        // serving one is routine and must not read as an alarm.
        let mut io = CannedIo {
            fetch: Ok(PointerFetch::State(s)),
            calls: 0,
        };
        assert_eq!(
            block_on(resolve_app_pointer(
                &mut io,
                &vk,
                APP_ID,
                PointerFloor::at(6, [0xbb; 32])
            ))
            .unwrap(),
            PointerOutcome::Stale {
                served: 2,
                floor: 6
            }
        );
    }

    #[test]
    fn the_conservative_probe_io_adapter_can_never_unlock_the_fallback() {
        // ProbeIo conflates timeout and miss, so the adapter must take the
        // conservative branch for BOTH of its cases -- including an empty body.
        let vk = signing_key(7).verifying_key();
        for probe in [CannedProbeIo(None), CannedProbeIo(Some(Vec::new()))] {
            let mut io = ConservativeProbeIo(probe);
            let outcome = block_on(resolve_app_pointer(
                &mut io,
                &vk,
                APP_ID,
                PointerFloor::never_resolved(),
            ))
            .unwrap();
            assert_eq!(outcome, PointerOutcome::Unavailable);
            assert!(!outcome.may_use_baked_in_fallback());
        }
        // But it still resolves a real record.
        let (vk, _p, s) = published(7, 3, [0x11; 32]);
        let mut io = ConservativeProbeIo(CannedProbeIo(Some(s)));
        assert!(matches!(
            block_on(resolve_app_pointer(
                &mut io,
                &vk,
                APP_ID,
                PointerFloor::never_resolved()
            ))
            .unwrap(),
            PointerOutcome::Resolved(_)
        ));
    }
}
