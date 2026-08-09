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
//! # Trust model, and the one assumption this module bakes in
//!
//! **The author verifying key the caller passes in is the entire trust anchor,
//! full stop.** A record is accepted only if it carries an Ed25519 signature by
//! that exact key over that exact params blob. There is no delegation, no
//! rotation, no revocation, and no recovery path for a lost or compromised
//! author key: whoever holds the private key can sign a pointer to arbitrary
//! WASM, and this resolver will follow it.
//!
//! That is deliberate, and it is a **limitation, not a design position**. The
//! question of pointer-update authority — who may sign a new record, and how a
//! lost or compromised author key is recovered — is an open design question on
//! freenet-core#5194 that this module does not attempt to answer. It is
//! implemented the only way it can be implemented today, because the pointer
//! contract's own `validate_state` verifies against the key in its params and
//! nothing else, and that WASM is frozen. If and when an authority model is
//! decided, this resolver has to change with the contract.
//!
//! What the resolver *does* bound is **backward** replay: see
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
    /// The record's version is **older** than the highest the caller has
    /// already verified: a rollback, refused.
    Rollback {
        /// Version carried by the record just fetched.
        record: u32,
        /// Highest version the caller has previously verified.
        floor: u32,
    },
    /// The record carries the caller's current version but a **different**
    /// `code_hash`: two validly-signed records exist at one version. Only the
    /// author can produce such a pair, so this is publisher error rather than
    /// attack, but a consumer cannot tell which is intended and must not guess.
    Conflict {
        /// The version at which the two records disagree.
        version: u32,
    },
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
            Self::Rollback { record, floor } => write!(
                f,
                "pointer record version {record} is older than the highest already \
                 verified ({floor}); refusing the rollback"
            ),
            Self::Conflict { version } => write!(
                f,
                "two different code hashes are signed at pointer version {version}; \
                 refusing to guess which the author meant"
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
/// ([`PointerResolver`] / [`resolve_successor_pointer`]) over handling records
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

    /// Decode and verify in one step, so a caller cannot decode and then forget
    /// to verify.
    ///
    /// Still not sufficient on its own: a validly-signed *older* record passes
    /// this. Anti-rollback lives in [`PointerResolver`].
    pub fn decode_verified(bytes: &[u8], params: &[u8]) -> Result<Self, PointerError> {
        let (author_vk, _app_id) = parse_pointer_params(params)?;
        let record = Self::decode(bytes)?;
        record.verify(params, &author_vk)?;
        Ok(record)
    }
}

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
    /// Prefer this over [`Self::at_version_only`]: carrying the code hash is
    /// what lets the resolver detect two different records signed at one
    /// version ([`PointerError::Conflict`]).
    #[must_use]
    pub fn at(version: u32, code_hash: [u8; CODE_HASH_LEN]) -> Self {
        Self {
            version,
            code_hash: Some(code_hash),
        }
    }

    /// The caller has previously verified `version` but did not keep the code
    /// hash.
    ///
    /// **Weaker than [`Self::at`].** Rollback is still refused, but the
    /// equal-version conflict check cannot run, so if the author ever signed
    /// two different code hashes at one version this floor will accept
    /// whichever one the network serves. Use [`Self::at`] wherever the code
    /// hash can be persisted.
    #[must_use]
    pub fn at_version_only(version: u32) -> Self {
        Self {
            version,
            code_hash: None,
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
    /// Nothing could be learned: the GET timed out, failed, or returned no
    /// state for a pointer that has resolved before.
    ///
    /// **Keep using whatever you last resolved.** Do not fall back to a
    /// baked-in key and do not treat this as "no pointer exists": an attacker
    /// who can make the pointer briefly unreachable would otherwise get a free
    /// downgrade. A definitively-absent pointer for a caller that has resolved
    /// before also lands here rather than in [`Self::NeverPublished`], because
    /// a pointer that once resolved cannot legitimately become unpublished.
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
/// [`resolve_successor_pointer`] pumps it for you over a [`ProbeIo`].
///
/// The driver distinguishes a pointer that is **definitively absent**
/// ([`Self::on_absent`]) from one that is merely **unreachable**
/// ([`Self::on_unreachable`]), because conflating them is a downgrade
/// primitive. [`ProbeIo`] cannot express that distinction — its `Ok(None)`
/// covers both — so the pumped entry point always takes the conservative
/// branch. A caller whose transport can tell a "contract not found" response
/// apart from a timeout should drive this type directly and report precisely.
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

    /// The current instruction. Idempotent: re-asking never advances anything.
    ///
    /// The [`Step::Get`] this emits wants neither the contract code nor a
    /// subscription — the record is the whole answer.
    ///
    /// A resolution is exactly one GET and the resolver does not retry:
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
    /// An **empty** body is treated as absence (a pointer with no state), not
    /// as a malformed record: an unpublished contract is the ordinary reason to
    /// get nothing back. Any other wrong length is a hard
    /// [`PointerError::StateLength`].
    pub fn on_response(&mut self, id: ContractInstanceId, state: &[u8]) {
        if !self.accepts(id) {
            return;
        }
        self.outstanding = false;
        if state.is_empty() {
            self.finish_absent();
            return;
        }
        let result = PointerRecord::decode(state)
            .and_then(|record| {
                record.verify(&self.params, &self.author_vk)?;
                Ok(record)
            })
            .and_then(|record| self.order(record));
        self.phase = Phase::Done(Some(result));
    }

    /// Report that the pointer is **definitively absent**: the network answered
    /// and there is no contract state at that address.
    ///
    /// Only use this for a real negative answer. A timeout is
    /// [`Self::on_unreachable`]; reporting a timeout here would let anyone who
    /// can stall one GET push a first-run consumer onto its stale baked-in key.
    pub fn on_absent(&mut self, id: ContractInstanceId) {
        if !self.accepts(id) {
            return;
        }
        self.outstanding = false;
        self.finish_absent();
    }

    /// Report that nothing could be learned: a timeout, a send failure, or any
    /// condition that is not a definitive negative answer.
    pub fn on_unreachable(&mut self, id: ContractInstanceId) {
        if !self.accepts(id) {
            return;
        }
        self.outstanding = false;
        self.phase = Phase::Done(Some(Ok(PointerOutcome::Unavailable)));
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

    /// Absence is only `NeverPublished` for a caller that has never resolved.
    /// For anyone else it is `Unavailable`, so a disappearing pointer can never
    /// unlock the baked-in fallback.
    fn finish_absent(&mut self) {
        let outcome = if self.floor.has_ever_resolved() {
            PointerOutcome::Unavailable
        } else {
            PointerOutcome::NeverPublished
        };
        self.phase = Phase::Done(Some(Ok(outcome)));
    }

    /// Anti-rollback ordering, applied only to an already-signature-verified
    /// record.
    fn order(&self, record: PointerRecord) -> Result<PointerOutcome, PointerError> {
        if record.version < self.floor.version {
            return Err(PointerError::Rollback {
                record: record.version,
                floor: self.floor.version,
            });
        }
        if record.version == self.floor.version
            && self
                .floor
                .code_hash
                .is_some_and(|known| known != record.code_hash)
        {
            return Err(PointerError::Conflict {
                version: record.version,
            });
        }
        if record.is_tombstone() {
            return Ok(PointerOutcome::Withdrawn {
                version: record.version,
            });
        }
        let resolved = ResolvedPointer {
            version: record.version,
            code_hash: record.code_hash,
        };
        if record.version == self.floor.version {
            Ok(PointerOutcome::Unchanged(resolved))
        } else {
            Ok(PointerOutcome::Resolved(resolved))
        }
    }
}

/// Why a [`resolve_successor_pointer`] call did not produce an outcome.
///
/// The two causes are kept apart deliberately: a transport failure says nothing
/// about the pointer, while a [`PointerError`] is a statement about what the
/// network served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError<E> {
    /// The app's transport aborted (a [`ProbeIo::get`] `Err`).
    Transport(E),
    /// The record, its params, or its ordering was rejected.
    Pointer(PointerError),
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
/// to recover state; this one asks the author's pointer what is current now.
/// The two are different operations and share nothing but the [`ProbeIo`]
/// transport seam.
///
/// `author_vk` is the whole trust anchor — see the module docs for the
/// authority and rotation limitation. `floor` is what the caller already
/// verified; pass [`PointerFloor::never_resolved`] on first run and persist the
/// resolved `(version, code_hash)` for next time.
///
/// # Absence versus unreachability
///
/// [`ProbeIo::get`] returns `Ok(None)` for a timeout, a send failure **and** a
/// miss, so this wrapper cannot tell absence from unreachability and always
/// takes the conservative branch: `Ok(None)` becomes
/// [`PointerOutcome::Unavailable`], never [`PointerOutcome::NeverPublished`].
/// A first-run caller that needs the baked-in fallback path therefore needs a
/// transport that reports a real negative answer — drive [`PointerResolver`]
/// directly and call [`PointerResolver::on_absent`]. Erring the other way would
/// mean one stalled GET could push a consumer onto a stale key.
pub async fn resolve_successor_pointer<IO: ProbeIo>(
    io: &mut IO,
    author_vk: &VerifyingKey,
    app_id: &[u8],
    floor: PointerFloor,
) -> Result<PointerOutcome, ResolveError<IO::Error>> {
    let mut resolver = PointerResolver::new(author_vk, app_id, floor)?;
    loop {
        match resolver.next_action() {
            Step::Get(id) => match io.get(id).await.map_err(ResolveError::Transport)? {
                Some(bytes) => resolver.on_response(id, &bytes),
                None => resolver.on_unreachable(id),
            },
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

    /// Publisher-side signing, test-only on purpose: this crate resolves,
    /// it does not publish (the contract crate owns `sign_record`).
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

    /// Drive a resolver to completion against one canned GET response.
    fn resolve_with(
        vk: &VerifyingKey,
        floor: PointerFloor,
        response: Option<&[u8]>,
    ) -> Result<PointerOutcome, PointerError> {
        let mut r = PointerResolver::new(vk, APP_ID, floor).unwrap();
        let Step::Get(id) = r.next_action() else {
            panic!("a fresh resolver must ask for the pointer");
        };
        match response {
            Some(bytes) => r.on_response(id, bytes),
            None => r.on_absent(id),
        }
        assert_eq!(r.next_action(), Step::Done);
        r.take_outcome().expect("Done implies an outcome")
    }

    // ---- happy path -----------------------------------------------------

    #[test]
    fn resolves_a_validly_signed_record_on_first_run() {
        let (vk, _params, state) = published(7, 3, [0x11; 32]);
        let outcome = resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)).unwrap();
        assert!(
            !outcome.may_use_baked_in_fallback(),
            "a resolved pointer must never unlock the baked-in fallback"
        );
        let r = outcome.resolved().expect("Resolved carries a record");
        assert_eq!(r.version(), 3);
        assert_eq!(r.code_hash(), [0x11; 32]);
        assert!(matches!(outcome, PointerOutcome::Resolved(_)));
    }

    #[test]
    fn a_newer_version_supersedes_the_floor() {
        let (vk, _params, state) = published(7, 9, [0x22; 32]);
        let outcome = resolve_with(&vk, PointerFloor::at(4, [0x11; 32]), Some(&state)).unwrap();
        assert!(matches!(outcome, PointerOutcome::Resolved(r) if r.version() == 9));
    }

    #[test]
    fn the_same_record_again_is_unchanged_not_a_rollback() {
        let (vk, _params, state) = published(7, 5, [0x33; 32]);
        let outcome = resolve_with(&vk, PointerFloor::at(5, [0x33; 32]), Some(&state)).unwrap();
        assert!(matches!(outcome, PointerOutcome::Unchanged(r) if r.code_hash() == [0x33; 32]));
        assert!(!outcome.may_use_baked_in_fallback());
    }

    // ---- signature rejection -------------------------------------------

    #[test]
    fn a_tampered_code_hash_is_rejected() {
        let (vk, _params, state) = published(7, 3, [0x11; 32]);
        let mut tampered = state.clone();
        tampered[4] ^= 0xff; // first code_hash byte
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&tampered)),
            Err(PointerError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_version_is_rejected() {
        let (vk, _params, state) = published(7, 3, [0x11; 32]);
        let mut tampered = state.clone();
        tampered[3] = 9; // claim version 9 under a version-3 signature
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&tampered)),
            Err(PointerError::BadSignature)
        );
    }

    #[test]
    fn a_record_signed_by_another_key_is_rejected() {
        let victim = signing_key(7).verifying_key();
        let attacker = signing_key(200);
        // The attacker signs over the VICTIM's params, so only the key differs.
        let params = pointer_params(&victim, APP_ID).unwrap();
        let state = sign(&attacker, &params, 99, [0xee; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&victim, PointerFloor::never_resolved(), Some(&state)),
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
        let state = sign(&key, &other_params, 42, [0x44; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)),
            Err(PointerError::BadSignature)
        );
    }

    #[test]
    fn an_unsigned_record_is_named_as_such() {
        let vk = signing_key(7).verifying_key();
        let state = PointerRecord {
            version: 3,
            code_hash: [0x11; 32],
            signature: [0u8; 64],
        }
        .encode()
        .to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)),
            Err(PointerError::SignatureUnset)
        );
    }

    #[test]
    fn signature_malleability_is_rejected_by_verify_strict() {
        // L, the order of the Ed25519 base point, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let record = sign(&key, &params, 3, [0x11; 32]);

        // S' = S + L is an equally valid cofactored signature; verify_strict
        // must refuse it, or a third party could mint a distinct-but-accepted
        // encoding of a record they did not sign.
        let mut malleable = record;
        let mut carry = 0u16;
        for (i, l) in L.iter().enumerate() {
            let sum = u16::from(record.signature[32 + i]) + u16::from(*l) + carry;
            malleable.signature[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_ne!(malleable.signature, record.signature);
        let state = malleable.encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)),
            Err(PointerError::BadSignature)
        );
    }

    // ---- anti-rollback --------------------------------------------------

    #[test]
    fn an_older_validly_signed_record_is_refused() {
        // The classic replay: the attacker serves a real, correctly-signed
        // record the author published two releases ago.
        let (vk, _params, old_state) = published(7, 2, [0xaa; 32]);
        assert_eq!(
            resolve_with(&vk, PointerFloor::at(6, [0xbb; 32]), Some(&old_state)),
            Err(PointerError::Rollback {
                record: 2,
                floor: 6
            })
        );
    }

    #[test]
    fn rollback_is_refused_even_when_the_floor_kept_no_code_hash() {
        let (vk, _params, old_state) = published(7, 2, [0xaa; 32]);
        assert_eq!(
            resolve_with(&vk, PointerFloor::at_version_only(6), Some(&old_state)),
            Err(PointerError::Rollback {
                record: 2,
                floor: 6
            })
        );
    }

    #[test]
    fn two_code_hashes_at_one_version_are_refused_rather_than_guessed() {
        let (vk, _params, state) = published(7, 5, [0x33; 32]);
        assert_eq!(
            resolve_with(&vk, PointerFloor::at(5, [0x99; 32]), Some(&state)),
            Err(PointerError::Conflict { version: 5 })
        );
    }

    #[test]
    fn version_zero_never_resolves() {
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        // Genuinely signed at version 0 — rejected on the version rule, not
        // because the signature happens not to check out.
        let state = sign(&key, &params, 0, [0x11; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)),
            Err(PointerError::ZeroVersion)
        );
    }

    #[test]
    fn the_reserved_max_version_never_resolves() {
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let state = sign(&key, &params, u32::MAX, [0x11; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)),
            Err(PointerError::ReservedVersion)
        );
        // One below is fine.
        let ok = sign(&key, &params, MAX_POINTER_VERSION, [0x11; 32])
            .encode()
            .to_vec();
        assert!(matches!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&ok)).unwrap(),
            PointerOutcome::Resolved(_)
        ));
    }

    // ---- absence and unreachability -------------------------------------

    #[test]
    fn an_unpublished_pointer_is_never_published_on_first_run() {
        let vk = signing_key(7).verifying_key();
        let outcome = resolve_with(&vk, PointerFloor::never_resolved(), None).unwrap();
        assert_eq!(outcome, PointerOutcome::NeverPublished);
        assert!(
            outcome.may_use_baked_in_fallback(),
            "first run with no pointer is the one case the baked-in key is safe"
        );
    }

    #[test]
    fn an_empty_state_body_counts_as_absence_not_a_malformed_record() {
        let vk = signing_key(7).verifying_key();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&[])).unwrap(),
            PointerOutcome::NeverPublished
        );
    }

    #[test]
    fn a_vanished_pointer_cannot_unlock_the_baked_in_fallback() {
        // Absence reported to a caller that HAS resolved before: a pointer
        // cannot legitimately become unpublished, so this must not read as
        // "never published" — that would be a downgrade primitive.
        let vk = signing_key(7).verifying_key();
        let outcome = resolve_with(&vk, PointerFloor::at(4, [0x11; 32]), None).unwrap();
        assert_eq!(outcome, PointerOutcome::Unavailable);
        assert!(!outcome.may_use_baked_in_fallback());
    }

    #[test]
    fn a_timeout_is_unavailable_even_on_first_run() {
        let vk = signing_key(7).verifying_key();
        let mut r = PointerResolver::new(&vk, APP_ID, PointerFloor::never_resolved()).unwrap();
        let Step::Get(id) = r.next_action() else {
            panic!("expected a GET");
        };
        r.on_unreachable(id);
        assert_eq!(r.next_action(), Step::Done);
        let outcome = r.take_outcome().unwrap().unwrap();
        assert_eq!(outcome, PointerOutcome::Unavailable);
        assert!(
            !outcome.may_use_baked_in_fallback(),
            "one stalled GET must not push a first-run consumer onto its stale baked-in key"
        );
    }

    #[test]
    fn a_wrong_length_body_is_a_hard_error_not_absence() {
        let vk = signing_key(7).verifying_key();
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&[0u8; 99])),
            Err(PointerError::StateLength(99))
        );
        assert_eq!(
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&[0u8; 101])),
            Err(PointerError::StateLength(101))
        );
    }

    // ---- tombstone -------------------------------------------------------

    #[test]
    fn a_tombstone_is_withdrawn_and_carries_no_resolved_pointer() {
        let (vk, _params, state) = published(7, 8, TOMBSTONE_CODE_HASH);
        let outcome = resolve_with(&vk, PointerFloor::at(4, [0x11; 32]), Some(&state)).unwrap();
        assert_eq!(outcome, PointerOutcome::Withdrawn { version: 8 });
        assert!(outcome.resolved().is_none());
        assert!(
            !outcome.may_use_baked_in_fallback(),
            "withdrawn means there is no current code, not that the old code is current"
        );
    }

    #[test]
    fn a_rolled_back_tombstone_is_still_a_rollback() {
        let (vk, _params, state) = published(7, 2, TOMBSTONE_CODE_HASH);
        assert_eq!(
            resolve_with(&vk, PointerFloor::at(6, [0x11; 32]), Some(&state)),
            Err(PointerError::Rollback {
                record: 2,
                floor: 6
            })
        );
    }

    // ---- params ----------------------------------------------------------

    #[test]
    fn app_id_charset_and_length_are_enforced() {
        let vk = signing_key(7).verifying_key();
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
        // The boundary itself is fine.
        assert!(pointer_params(&vk, &[b'a'; MAX_APP_ID_LEN]).is_ok());
    }

    #[test]
    fn a_bad_app_id_fails_the_resolver_before_any_io() {
        let vk = signing_key(7).verifying_key();
        assert_eq!(
            PointerResolver::new(&vk, b"NOPE", PointerFloor::never_resolved()).unwrap_err(),
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

    // ---- addressing ------------------------------------------------------

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

    #[test]
    fn a_response_for_another_contract_is_ignored() {
        let (vk, _params, state) = published(7, 3, [0x11; 32]);
        let mut r = PointerResolver::new(&vk, APP_ID, PointerFloor::never_resolved()).unwrap();
        let Step::Get(id) = r.next_action() else {
            panic!("expected a GET");
        };
        let other = pointer_contract_id(&vk, b"river.chat-delegate").unwrap();
        assert_ne!(other, id);
        r.on_response(other, &state);
        assert_eq!(
            r.next_action(),
            Step::Get(id),
            "an unrelated response must not finish the resolution"
        );
        assert!(r.take_outcome().is_none());
        // The real answer still lands.
        r.on_response(id, &state);
        assert_eq!(r.next_action(), Step::Done);
        assert!(matches!(
            r.take_outcome().unwrap().unwrap(),
            PointerOutcome::Resolved(_)
        ));
    }

    #[test]
    fn the_outcome_is_taken_only_once() {
        let (vk, _params, state) = published(7, 3, [0x11; 32]);
        let mut r = PointerResolver::new(&vk, APP_ID, PointerFloor::never_resolved()).unwrap();
        let Step::Get(id) = r.next_action() else {
            panic!("expected a GET");
        };
        r.on_response(id, &state);
        assert!(r.take_outcome().is_some());
        assert!(r.take_outcome().is_none());
        // And a late event cannot revive it.
        r.on_response(id, &state);
        assert!(r.take_outcome().is_none());
    }

    // ---- consumer-side derivation ---------------------------------------

    #[test]
    fn derivation_uses_the_consumers_own_params() {
        let (vk, pointer_params_bytes, state) = published(7, 3, [0x11; 32]);
        let PointerOutcome::Resolved(r) =
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)).unwrap()
        else {
            panic!("expected Resolved");
        };
        let mine = Parameters::from(b"my-own-instance-params".to_vec());
        let theirs = Parameters::from(pointer_params_bytes);
        assert_ne!(
            r.contract_id(&mine),
            r.contract_id(&theirs),
            "the pointer's own params must not be interchangeable with the consumer's"
        );
        // And it agrees with the crate's existing reconstruction.
        assert_eq!(
            r.contract_id(&mine),
            contract_id_from_code_hash(&[0x11; 32], &mine)
        );
    }

    #[test]
    fn delegate_derivation_matches_stdlib() {
        let (vk, _params, state) = published(7, 3, [0x11; 32]);
        let PointerOutcome::Resolved(r) =
            resolve_with(&vk, PointerFloor::never_resolved(), Some(&state)).unwrap()
        else {
            panic!("expected Resolved");
        };
        let params = Parameters::from(b"delegate-config".to_vec());
        let expected =
            DelegateKey::from_params(CodeHash::new([0x11; 32]).encode(), &params).unwrap();
        assert_eq!(r.delegate_key(&params), expected);
        assert_eq!(r.code_hash_b58(), CodeHash::new([0x11; 32]).encode());
    }

    // ---- the pumped entry point ------------------------------------------

    struct CannedIo {
        response: Result<Option<Vec<u8>>, &'static str>,
        calls: usize,
    }

    impl ProbeIo for CannedIo {
        type Error = &'static str;

        async fn get(&mut self, _id: ContractInstanceId) -> Result<Option<Vec<u8>>, Self::Error> {
            self.calls += 1;
            self.response.clone()
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
        let (vk, _params, state) = published(7, 3, [0x11; 32]);
        let mut io = CannedIo {
            response: Ok(Some(state)),
            calls: 0,
        };
        let outcome = block_on(resolve_successor_pointer(
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
    fn the_pumped_entry_point_never_reports_never_published() {
        // ProbeIo conflates timeout and miss, so the wrapper must take the
        // conservative branch: no baked-in fallback from an Ok(None).
        let vk = signing_key(7).verifying_key();
        let mut io = CannedIo {
            response: Ok(None),
            calls: 0,
        };
        let outcome = block_on(resolve_successor_pointer(
            &mut io,
            &vk,
            APP_ID,
            PointerFloor::never_resolved(),
        ))
        .unwrap();
        assert_eq!(outcome, PointerOutcome::Unavailable);
        assert!(!outcome.may_use_baked_in_fallback());
    }

    #[test]
    fn the_pumped_entry_point_separates_transport_from_pointer_errors() {
        let (vk, _params, state) = published(7, 2, [0xaa; 32]);
        let mut io = CannedIo {
            response: Err("socket closed"),
            calls: 0,
        };
        assert_eq!(
            block_on(resolve_successor_pointer(
                &mut io,
                &vk,
                APP_ID,
                PointerFloor::never_resolved()
            )),
            Err(ResolveError::Transport("socket closed"))
        );

        let mut io = CannedIo {
            response: Ok(Some(state)),
            calls: 0,
        };
        assert_eq!(
            block_on(resolve_successor_pointer(
                &mut io,
                &vk,
                APP_ID,
                PointerFloor::at(6, [0xbb; 32])
            )),
            Err(ResolveError::Pointer(PointerError::Rollback {
                record: 2,
                floor: 6
            }))
        );
    }

    #[test]
    fn a_full_release_sequence_advances_the_floor_monotonically() {
        let key = signing_key(7);
        let vk = key.verifying_key();
        let params = pointer_params(&vk, APP_ID).unwrap();
        let mut floor = PointerFloor::never_resolved();
        for (version, hash) in [(1u32, [0x01u8; 32]), (2, [0x02; 32]), (7, [0x07; 32])] {
            let state = sign(&key, &params, version, hash).encode().to_vec();
            let PointerOutcome::Resolved(r) = resolve_with(&vk, floor, Some(&state)).unwrap()
            else {
                panic!("release {version} should resolve");
            };
            assert_eq!(r.code_hash(), hash);
            floor = PointerFloor::at(r.version(), r.code_hash());
        }
        assert_eq!(floor.version(), 7);
        // Every earlier record in that sequence is now refused.
        for version in [1u32, 2] {
            let state = sign(&key, &params, version, [version as u8; 32])
                .encode()
                .to_vec();
            assert!(matches!(
                resolve_with(&vk, floor, Some(&state)),
                Err(PointerError::Rollback { .. })
            ));
        }
    }
}
