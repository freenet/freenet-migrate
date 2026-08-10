//! **Forward** discovery: resolving an author's **pointer contract**.
//!
//! (Named for that contract, and unrelated to this crate's older
//! [`crate::SuccessorPointer`] primitive, which has its own signing domain and
//! message layout. Errors from here render as "pointer-contract resolution
//! failed"; the other one renders as "successor pointer …".)
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
//! always will be. What the resolver bounds is **backward** replay, and only
//! relative to a floor the caller supplies: see [`PointerFloor`].
//!
//! Two further assumptions worth stating, because they are easy to read past:
//!
//! * **Absence is unauthenticated.** Freenet has no proof that a contract has
//!   no state; a responding node can always answer "not found". So
//!   [`PointerOutcome::NeverPublished`], the one outcome that unlocks a
//!   baked-in fallback, ultimately rests on a peer's unverifiable claim. The
//!   blast radius is bounded (it applies only when nothing has ever resolved,
//!   and the result is the key the consumer already shipped with), which is why
//!   the fallback is confined to that case.
//! * **A first resolve has no recency bound.** Against
//!   [`PointerFloor::never_resolved`] there is nothing to compare with, so any
//!   validly-signed record is adopted, including a genuine but superseded one a
//!   peer chooses to serve. It self-heals on the next honest response. A
//!   consumer that knows the app's version and code hash at build time should
//!   seed its floor with [`PointerFloor::at`] instead of starting empty.
//! * **Forward suppression is unbounded, and is not closable at this layer.**
//!   The floor bounds *backward* replay: nothing that loses to what the caller
//!   already verified is adopted. There is no matching bound in the other
//!   direction. A peer that answers every GET with a genuine, correctly-signed
//!   but **superseded** record keeps a consumer on old code indefinitely, and
//!   the consumer cannot tell: the 100-byte state carries no timestamp and no
//!   freshness proof, and the contract's WASM is frozen, so one cannot be added
//!   without re-keying every published pointer. (This is the same reasoning
//!   that reserved [`TOMBSTONE_CODE_HASH`] up front, while it was still free.)
//!   What is bounded is *what* you can be held on: every record adopted is one
//!   the author signed for this exact app, so suppression can stall an upgrade
//!   but cannot substitute code. Mitigation is operational rather than
//!   cryptographic — resolve repeatedly over time and across sessions, since
//!   one honest response is enough to advance the floor permanently.
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
/// A mirror of the contract's own `PointerError`, plus [`Self::FloorVersion`]
/// for a caller-supplied [`PointerFloor`] that no real resolution could have
/// produced. Ordering is **not** an error here: a record that loses to the
/// caller's floor is [`PointerOutcome::Stale`], because the contract documents
/// a bootstrapping peer serving one as routine.
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
    /// A [`PointerFloor`] was built at a version outside `1..=MAX_POINTER_VERSION`.
    ///
    /// No real resolution can produce one: the contract refuses to sign or
    /// accept version 0 or `u32::MAX`. So a floor at either end is corrupt
    /// caller state (a defaulted database column, a partial write), and it is
    /// refused rather than interpreted. The ends are unsafe in opposite
    /// directions: version 0 would read as "never resolved" and unlock the
    /// baked-in fallback, while a version above the maximum could never be
    /// superseded by any valid record, wedging the caller on `Stale` forever.
    FloorVersion(u32),
    /// [`PointerFloor::at`] was handed the all-zero [`TOMBSTONE_CODE_HASH`].
    ///
    /// The same corruption class as [`Self::FloorVersion`], on the other
    /// column. 32 zero bytes is what a defaulted or partially-written
    /// `code_hash` column reads as, and it is also the tombstone, so accepting
    /// it in the ordinary constructor would let one bad row convince a consumer
    /// that the author withdrew an app that is perfectly healthy — permanently,
    /// since the floor is re-persisted on every resolve and a healthy app that
    /// never bumps its version never supersedes it.
    ///
    /// A genuine withdrawal floor is still required (that is what stops a
    /// pre-withdrawal record replaying), so it has its own explicit
    /// constructor: [`PointerFloor::withdrawn_at`].
    FloorTombstone,
}

impl PointerError {
    /// Whether a caller may fall back to its baked-in, build-time key because
    /// of this error. **Always `false`.**
    ///
    /// Every variant here means a peer served something this resolver refused,
    /// which says nothing about whether a pointer exists. Falling back on a
    /// rejection would make "serve 99 bytes of garbage" a cheaper downgrade
    /// than stalling the GET. It is equally not a reason to *stop*: retry with
    /// a fresh [`PointerResolver`] and the same floor, or that same 99 bytes
    /// becomes a hard stop instead. Mirrors
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
            Self::FloorVersion(v) => write!(
                f,
                "pointer floor version {v} is outside 1..={MAX_POINTER_VERSION}; no real \
                 resolution produces one, so this floor is corrupt caller state"
            ),
            Self::FloorTombstone => write!(
                f,
                "pointer floor code hash is all zeros, which is the withdrawal tombstone; \
                 build a withdrawal floor with PointerFloor::withdrawn_at so a defaulted \
                 column cannot read as one"
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
/// Decoding is separate from verifying: [`Self::decode`] checks only the
/// length, and [`Self::verify`] is what makes a record safe to act on. There is
/// deliberately no combined helper (see the note below the impl).
///
/// Prefer the resolver ([`PointerResolver`] / [`resolve_app_pointer`]) over
/// handling records directly: it also enforces the anti-rollback ordering,
/// which no single record can express.
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
/// **A floor is caller state, and this crate never treats it as verified.** It
/// gates what a served record may do, and that is all: no outcome is ever built
/// from its `code_hash` bytes, because whatever can write the caller's store
/// (a shared config file, a restored backup, a browser consumer's local
/// storage) could otherwise choose a code hash the author never signed. That is
/// why the equal-version tiebreak reports [`PointerOutcome::CompetingRecord`]
/// rather than handing back the floor as a [`ResolvedPointer`], and why
/// [`Self::at`] refuses an all-zero hash instead of reading it as a withdrawal.
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
    /// [`PointerOutcome::Unchanged`], telling the caller nothing had changed
    /// while handing back a different key.
    ///
    /// # Errors
    ///
    /// Fails with [`PointerError::FloorVersion`] unless `version` is in
    /// `1..=MAX_POINTER_VERSION`. Neither end is reachable from a real
    /// resolution, so a floor at either one is corrupt caller state, and
    /// guessing at it is unsafe in both directions: version 0 would read as
    /// "never resolved" and unlock the baked-in fallback, while a version above
    /// the maximum can never be superseded by a valid record. Surfacing the
    /// corruption lets the caller decide.
    ///
    /// Fails with [`PointerError::FloorTombstone`] if `code_hash` is 32 zero
    /// bytes. That is the same corruption class on the other column — a
    /// defaulted or partially-written `code_hash` reads as exactly that — and
    /// it is also [`TOMBSTONE_CODE_HASH`], so interpreting it here would let one
    /// bad row turn a healthy app into a permanent "the author withdrew this".
    /// A real withdrawal floor is built with [`Self::withdrawn_at`], which says
    /// so at the call site.
    ///
    /// **Do not recover with `unwrap_or_else(|_| PointerFloor::never_resolved())`.**
    /// That is the first thing to reach for and it reinstates exactly the
    /// fail-open this rejects: it turns a corrupt floor into "first run", which
    /// is the one state that unlocks a baked-in build-time key. Treat the error
    /// as "my stored floor is untrustworthy" and surface it.
    ///
    /// # Seeding from build-time knowledge
    ///
    /// A consumer that ships knowing the app's current version and code hash
    /// should seed its first floor from those constants rather than starting at
    /// [`Self::never_resolved`]. A first resolve has nothing to compare
    /// against, so it adopts any validly-signed record, including a genuine but
    /// superseded one that a peer chooses to serve. A build-time floor bounds
    /// that.
    ///
    /// One consequence to handle. If the author published two records at the
    /// seeded version (a retried or threshold-signed publish) and the seed is
    /// the lower-hashed of the pair, every resolve returns
    /// [`PointerOutcome::CompetingRecord`] until *v+1* is published: no record,
    /// no fallback, no advancing floor. A seeded caller is not stuck there —
    /// its floor holds a constant compiled into its own binary, so it may
    /// derive its key from that constant, which is the same value it would have
    /// used on [`PointerOutcome::NeverPublished`] and is also the side of the
    /// tiebreak the network converges on. See
    /// [`PointerOutcome::CompetingRecord`] for why that is the caller's call to
    /// make and not this crate's, and check [`Self::is_withdrawn`] first.
    ///
    /// This is why there is no separate `seeded_at` constructor. Splitting one
    /// would only record the caller's *claim* about provenance — the bytes
    /// arriving here are identical either way — so the resolver would end up
    /// trusting an assertion it cannot check, and any caller that loaded a
    /// stored floor through the seeded constructor by mistake would get the
    /// fail-open back. Provenance is knowledge the caller has and this crate
    /// does not, so it stays on the caller's side of the boundary.
    pub fn at(version: u32, code_hash: [u8; CODE_HASH_LEN]) -> Result<Self, PointerError> {
        if version == 0 || version > MAX_POINTER_VERSION {
            return Err(PointerError::FloorVersion(version));
        }
        if code_hash == TOMBSTONE_CODE_HASH {
            return Err(PointerError::FloorTombstone);
        }
        Ok(Self {
            version,
            code_hash: Some(code_hash),
        })
    }

    /// The caller previously verified a **withdrawal** at `version`: a signed
    /// record carrying [`TOMBSTONE_CODE_HASH`].
    ///
    /// Separate from [`Self::at`] on purpose. A withdrawal floor is genuinely
    /// needed — without it, any peer can serve a real pre-withdrawal record and
    /// resurrect code the author retired — but "all-zero code hash" is also
    /// what a defaulted or half-written database column looks like. Keeping the
    /// two constructors apart means a corrupt row fails
    /// [`Self::at`] loudly instead of silently becoming a withdrawal, while a
    /// caller that really did see [`PointerOutcome::Withdrawn`] says so
    /// explicitly.
    ///
    /// So persist the *fact* of withdrawal (a flag, a distinct row state), not
    /// merely a hash column that happens to be zeros, and rebuild through this.
    /// [`PointerOutcome::next_floor`] already returns the right shape; this is
    /// how you reconstruct it after a restart.
    ///
    /// # Errors
    ///
    /// Fails with [`PointerError::FloorVersion`] unless `version` is in
    /// `1..=MAX_POINTER_VERSION`, exactly as [`Self::at`] does and for the same
    /// reason.
    pub fn withdrawn_at(version: u32) -> Result<Self, PointerError> {
        if version == 0 || version > MAX_POINTER_VERSION {
            return Err(PointerError::FloorVersion(version));
        }
        Ok(Self {
            version,
            code_hash: Some(TOMBSTONE_CODE_HASH),
        })
    }

    /// The code hash accepted at [`Self::version`], or `None` when nothing has
    /// ever resolved.
    ///
    /// Persist this together with the version, **and** with whether the floor
    /// is a withdrawal ([`Self::is_withdrawn`]) — rebuild with [`Self::at`] or
    /// [`Self::withdrawn_at`] accordingly. Do not reconstruct by testing the
    /// stored hash for zeros: that is precisely the inference [`Self::at`]
    /// refuses to make on the caller's behalf, because a defaulted column is
    /// indistinguishable from a tombstone by its bytes alone.
    #[must_use]
    pub fn code_hash(&self) -> Option<[u8; CODE_HASH_LEN]> {
        self.code_hash
    }

    /// Whether this floor records a verified **withdrawal**.
    ///
    /// True only for a floor built by [`Self::withdrawn_at`] (or persisted from
    /// a [`PointerOutcome::Withdrawn`] via [`PointerOutcome::next_floor`]).
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.code_hash == Some(TOMBSTONE_CODE_HASH)
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
///
/// `#[non_exhaustive]`: a future outcome (for example, surfacing that a
/// competing equal-version record exists) must not be a source break for
/// downstream `match` sites.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerOutcome {
    /// A record strictly newer than the floor. Adopt its code hash, derive your
    /// key, and persist `(version, code_hash)` as the new floor.
    Resolved(ResolvedPointer),
    /// The network served the byte-identical record the caller's floor already
    /// holds. Nothing to do.
    ///
    /// The [`ResolvedPointer`] is built from the **served, signature-verified**
    /// record, not from the floor. That distinction is the whole reason this
    /// variant is narrower than it once was: a floor is unverified caller
    /// state, so minting a `ResolvedPointer` from its bytes would have walked
    /// straight through the trust boundary that type exists to be. The case
    /// where the floor *wins* a tiebreak against a different equal-version
    /// record is [`Self::CompetingRecord`], which deliberately carries no
    /// record at all.
    Unchanged(ResolvedPointer),
    /// The network served a **different** record at the caller's own version,
    /// and it lost the lower-code-hash tiebreak, so the caller's floor stands.
    ///
    /// Only the author can produce two valid records at one version (a retried
    /// or threshold-signed publish), so this is a publisher mistake rather than
    /// an attack — but it is also what a tampered floor store looks like from
    /// in here, which is why no [`ResolvedPointer`] is carried.
    ///
    /// **Carrying no record is the point.** The winner here is the floor, and a
    /// floor is unverified caller state: this resolver checked a signature over
    /// the record it was *served*, and that record lost. Handing back a
    /// [`ResolvedPointer`] built from the floor's bytes would have re-affirmed
    /// whatever an attacker (a shared config file, a restored backup, XSS in a
    /// browser consumer, a build-time floor seeded from the wrong release) had
    /// written there, under a variant that says nothing changed. So: **keep
    /// using whatever key you last derived, and do not derive one from
    /// anything here.** [`Self::next_floor`] is `None`, because nothing was
    /// learned that moves the floor.
    ///
    /// # Check [`PointerFloor::is_withdrawn`] before keeping your key
    ///
    /// A withdrawal floor reaches this variant too, and it is the one case
    /// where "keep the key you last derived" is wrong. A tombstone sorts below
    /// every real code hash, so once a caller holds a withdrawal floor at
    /// version *v*, any genuine pre-withdrawal record replayed at *v* loses the
    /// tiebreak and lands here. Resuming with the key that floor superseded
    /// resurrects, out of the caller's own memory, exactly the code the author
    /// retired — the same outcome the withdrawal floor exists to prevent, just
    /// reached from the other side. If `floor.is_withdrawn()`, stop resolving
    /// as you would for [`Self::Withdrawn`]; otherwise keep your key and retry.
    ///
    /// # A build-time-seeded caller may use its own constant
    ///
    /// [`PointerFloor::at`] recommends seeding the first floor from build-time
    /// constants, and such a caller can reach this variant on its very first
    /// resolve, with nothing last-derived to keep: no key, no fallback
    /// ([`Self::may_use_baked_in_fallback`] is false), and no advancing floor,
    /// until the author publishes *v+1*.
    ///
    /// That caller may derive its key from **its own build-time constant** —
    /// which is what its floor holds. This is not the laundering this variant
    /// refuses. This crate will not touch the floor's bytes because it cannot
    /// tell a genuine seed from a tampered store; the caller can, because it
    /// knows where its own floor came from. And the answer is not a downgrade
    /// in the first place: both records at a contested version are
    /// author-signed, the network's `merge` converges on the lower code hash,
    /// and reaching this variant *means* the caller's floor is that lower hash.
    /// Using it is agreeing with the tiebreak, not overriding it.
    ///
    /// The condition is provenance, not this variant: derive from your floor
    /// only where you know it came from your own binary or your own prior
    /// verified resolution, and only after the `is_withdrawn` check above. A
    /// caller that reads its floor from somewhere writable has learned nothing
    /// here and should keep its last key and retry.
    ///
    /// `#[non_exhaustive]` on the variant for the same reason as
    /// [`Self::Withdrawn`]: it has a public field, and enum-level
    /// `#[non_exhaustive]` alone would leave it constructible downstream.
    #[non_exhaustive]
    CompetingRecord {
        /// The contested version, which is also the caller's floor version.
        version: u32,
    },
    /// The author has **withdrawn** this app: the current record carries the
    /// all-zero tombstone code hash. Stop resolving. Do not fall back to a
    /// baked-in key: the author is saying there is no current code, not that
    /// the old code is current again.
    ///
    /// `#[non_exhaustive]` on the **variant**, not merely on the enum, because
    /// enum-level `#[non_exhaustive]` restricts matching and variant addition
    /// while leaving a struct-like variant with a public field constructible
    /// downstream. Matching still works with `Withdrawn { .. }`.
    ///
    /// On its own that is not sufficient, and the guarantee does not rest on
    /// it: the attribute blocks *construction*, not *mutation*, and
    /// `PointerOutcome` is `Clone`, so downstream can still take a genuine
    /// `Withdrawn` and overwrite `version`. What actually closes the hole is
    /// [`PointerOutcome::next_floor`] re-validating through
    /// [`PointerFloor::at`], so a tampered version yields `None` rather than a
    /// floor that no valid record could ever supersede.
    #[non_exhaustive]
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
    ///
    /// One corner reports `served == floor` rather than something strictly
    /// older: a floor carrying a version but no code hash (unconstructible
    /// through the public API, handled defensively in `order`) has no tiebreak
    /// available, so an equal-version record is refused rather than guessed at.
    /// That is tie-refusal rather than rollback, and it is deliberately
    /// fail-closed: `next_floor()` is `None`, so such a floor is only ever
    /// repaired by a strictly newer version.
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
    /// `None` for [`Self::NeverPublished`], [`Self::Stale`],
    /// [`Self::CompetingRecord`] and [`Self::Unavailable`], which learn nothing
    /// that moves the floor.
    ///
    /// To persist it across a restart, store [`PointerFloor::version`],
    /// [`PointerFloor::code_hash`] **and** [`PointerFloor::is_withdrawn`], then
    /// rebuild with [`PointerFloor::at`] or [`PointerFloor::withdrawn_at`]
    /// respectively. Store it per `(author_vk, app_id)`. Do not infer the
    /// withdrawal from a zeroed hash column — see [`PointerFloor::at`].
    #[must_use]
    pub fn next_floor(&self) -> Option<PointerFloor> {
        // Every arm re-validates through `at` rather than a private
        // skip-validation constructor. For an outcome this crate produced the
        // version came off a record that passed `PointerRecord::verify`, so
        // `at` cannot fail and this is behaviour-preserving. It matters because
        // `Withdrawn`'s `version` is a public field of an obtainable value and
        // `PointerOutcome` is `Clone`: `#[non_exhaustive]` stops downstream
        // *constructing* the variant, but not mutating a genuine one to
        // `u32::MAX` and calling this. Routing through `at` turns that into
        // `None` ("learned nothing") instead of the wedged-forever floor `at`
        // exists to refuse.
        match self {
            Self::Resolved(r) | Self::Unchanged(r) => PointerFloor::at(r.version, r.code_hash).ok(),
            Self::Withdrawn { version } => PointerFloor::withdrawn_at(*version).ok(),
            Self::NeverPublished
            | Self::Stale { .. }
            | Self::CompetingRecord { .. }
            | Self::Unavailable => None,
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
/// "delivered" rather than hanging silently. The gate catches an event for a
/// *different* contract and one arriving before the GET was issued; it cannot
/// separate two in-flight GETs for the **same** pointer, because there is no
/// per-request nonce. Do not run two concurrent resolutions for one
/// `(author_vk, app_id)` on a shared handler.
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
    /// Calling this **arms the event gate**: an event delivered before the
    /// first `next_action()` is rejected (see [`Self::on_response`]), so use
    /// [`Self::pointer_id`] if you only want to look at the address. The gate
    /// correlates on the contract id alone, and a pointer's id is a pure
    /// function of `(author_vk, app_id)`, so on a hand-pumped shared handler a
    /// late event from a *superseded* GET for the same pointer is
    /// indistinguishable from the live one. Ordering safety does not depend on
    /// this (the floor gates every record), but it is why a shared handler
    /// should not run two concurrent resolutions for one pointer.
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

    /// The `Done` check is defensive redundancy: `outstanding` is set only by
    /// `next_action`, which returns early once the phase is `Done`, and every
    /// event handler clears `outstanding` before setting it. Kept because the
    /// cost is one comparison and the failure it guards against (a finished
    /// resolver accepting an event) is exactly the kind a future refactor
    /// reintroduces.
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
    ///
    /// The asymmetry with the contract is deliberate and is the point of this
    /// method's care: the contract's `merge` is a total order over two records
    /// that **both** passed `validate_state`, while here exactly one operand is
    /// verified — the served record — and the other is the caller's floor,
    /// which is untrusted storage. So the order decides only whether the served
    /// record is adopted; it never turns the floor's bytes into a result.
    fn order(&self, record: PointerRecord) -> PointerOutcome {
        use core::cmp::Ordering;

        // Matched as a pair so the shape fails CLOSED. A floor with no code
        // hash but a non-zero version is unconstructible today (private fields;
        // `at` rejects version 0 and always stores a hash), but if a future
        // constructor broke that invariant, an unconditional `adopt` on `None`
        // would silently disable anti-rollback. Here it degrades to the version
        // check instead.
        let floor_hash = match self.floor.code_hash {
            None if self.floor.version == 0 => return self.adopt(record),
            None => {
                return if record.version > self.floor.version {
                    self.adopt(record)
                } else {
                    PointerOutcome::Stale {
                        served: record.version,
                        floor: self.floor.version,
                    }
                };
            }
            Some(hash) => hash,
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
                // Byte-identical to the floor. Report the SERVED record, which
                // this resolver signature-verified; the floor's copy of the
                // same bytes is unverified caller state and never a source of
                // anything handed back.
                Ordering::Equal => self.unchanged(record),
                // The floor wins the tiebreak, and the only thing this resolver
                // verified is the record that LOST. There is nothing here it
                // can vouch for, so it mints no `ResolvedPointer` -- doing so
                // would launder whatever hash the caller's floor store happened
                // to hold into a type whose entire promise is "this was
                // verified". See `PointerOutcome::CompetingRecord`.
                //
                // The version comes off the RECORD even though this branch has
                // already established the two are equal. Reading it from the
                // floor would be correct today and would also make this the one
                // place an outcome field is sourced from unverified caller
                // state, which is the invariant the rest of this function is
                // built to state without exception.
                Ordering::Greater => PointerOutcome::CompetingRecord {
                    version: record.version,
                },
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

    /// The served record ties the caller's floor byte for byte: nothing to do.
    ///
    /// Takes the **record**, not the floor's hash, although in this branch they
    /// are equal. The record is the one of the two this resolver verified, and
    /// building the outcome from it is what keeps the `ResolvedPointer`
    /// constructor unreachable from unverified caller state.
    fn unchanged(&self, record: PointerRecord) -> PointerOutcome {
        if record.is_tombstone() {
            return PointerOutcome::Withdrawn {
                version: record.version,
            };
        }
        PointerOutcome::Unchanged(ResolvedPointer {
            version: record.version,
            code_hash: record.code_hash,
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
/// The name is the warning. Two limitations, both inherited from `ProbeIo`:
///
/// * **It cannot report a real negative answer**, so a pointer resolved through
///   this adapter never returns [`PointerOutcome::NeverPublished`] and a
///   first-run consumer never reaches its baked-in fallback.
/// * **It fetches the contract code.** `ProbeIo::get` is specified as a GET
///   with `return_contract_code: true`, which is right for a backward probe and
///   pure waste here: it pulls the pointer's own ~130 KB WASM on every resolve
///   to read a 100-byte record.
///
/// Implement [`PointerIo`] directly for anything that resolves often or needs
/// the first-run path. Reach for this adapter to reuse plumbing you already
/// have.
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
///
/// # Both arms are retryable, and neither is a reason to stop
///
/// Neither ever permits the baked-in fallback (see
/// [`Self::may_use_baked_in_fallback`]), but "do not fall back" is not "give
/// up". A [`Self::Pointer`] error means *this peer's answer* was refused, not
/// that the pointer is unresolvable: answering one GET with 99 bytes is the
/// cheapest hostile move there is, and on a first run there is nothing
/// last-resolved to keep, so a consumer that treats a rejection as terminal
/// ends with no key at all. Retry with a fresh [`PointerResolver`] and the same
/// floor, under the app's own backoff.
#[non_exhaustive]
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
///
/// Everything that is neither `Resolved`/`Unchanged` nor `NeverPublished` —
/// including an `Err` of either kind, [`PointerOutcome::Stale`],
/// [`PointerOutcome::CompetingRecord`] and [`PointerOutcome::Unavailable`] —
/// means the same two things: keep the key you last derived, and **retry**.
/// Only [`PointerOutcome::Withdrawn`] says stop.
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
                let accepted = match io.get_pointer(id).await.map_err(ResolveError::Transport)? {
                    PointerFetch::State(bytes) => resolver.on_response(id, &bytes),
                    PointerFetch::Absent => resolver.on_absent(id),
                    PointerFetch::Unreachable => resolver.on_unreachable(id),
                };
                // The id came straight from `Step::Get`, so the resolver always
                // accepts it and this loop runs at most twice. Bailing on a
                // rejected event keeps a future change from spinning here
                // forever: an unbounded loop turns a broken resolver into a
                // CI *hang* rather than a test failure, which is far harder to
                // read. The `debug_assert` makes it loud in development.
                debug_assert!(
                    accepted,
                    "the resolver must accept the id it just asked for"
                );
                if !accepted {
                    return Ok(PointerOutcome::Unavailable);
                }
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

    /// `PointerFloor::at` for a version these tests already know is in range.
    fn floor(version: u32, code_hash: [u8; 32]) -> PointerFloor {
        PointerFloor::at(version, code_hash).expect("test floor version is in range")
    }

    /// A floor recording a verified withdrawal at `version`.
    fn withdrawn_floor(version: u32) -> PointerFloor {
        PointerFloor::withdrawn_at(version).expect("test floor version is in range")
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
            Some(floor(3, [0x11; 32])),
            "a resolution must advance the floor"
        );
    }

    #[test]
    fn a_newer_version_supersedes_the_floor() {
        let (vk, _params, s) = published(7, 9, [0x22; 32]);
        let outcome = resolve_with(&vk, floor(4, [0x11; 32]), state(&s)).unwrap();
        assert!(matches!(outcome, PointerOutcome::Resolved(r) if r.version() == 9));
    }

    #[test]
    fn the_same_record_again_is_unchanged_not_stale() {
        let (vk, _params, s) = published(7, 5, [0x33; 32]);
        let outcome = resolve_with(&vk, floor(5, [0x33; 32]), state(&s)).unwrap();
        assert!(matches!(outcome, PointerOutcome::Unchanged(r) if r.code_hash() == [0x33; 32]));
        assert!(!outcome.may_use_baked_in_fallback());
        assert_eq!(outcome.next_floor(), Some(floor(5, [0x33; 32])));
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
        // `the_resolver_source_still_pins_strict_verification` in
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
        let outcome = resolve_with(&vk, floor(6, [0xbb; 32]), state(&old_state)).unwrap();
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
        let outcome = resolve_with(&vk, floor(5, high), state(&low_state)).unwrap();
        assert!(
            matches!(outcome, PointerOutcome::Resolved(r) if r.code_hash() == low),
            "the lower code hash must win, got {outcome:?}"
        );

        // Holding the LOWER hash, served the higher: the floor wins, and the
        // outcome carries NO record. The floor's hash is unverified caller
        // state, so re-affirming it as a `ResolvedPointer` would be the
        // laundering `pointer_floor_bytes_are_never_laundered_into_a_resolved_pointer`
        // exists to forbid; the served record lost, so it cannot be reported
        // either. Nothing here is both verified and winning.
        let (_vk2, _p2, high_state) = published(7, 5, high);
        let outcome = resolve_with(&vk, floor(5, low), state(&high_state)).unwrap();
        assert_eq!(outcome, PointerOutcome::CompetingRecord { version: 5 });
        assert!(
            outcome.resolved().is_none(),
            "a losing tiebreak must hand back no record at all"
        );
        assert_eq!(
            outcome.next_floor(),
            None,
            "the floor already holds the winner, so nothing advances"
        );
        assert!(!outcome.may_use_baked_in_fallback());
    }

    #[test]
    fn pointer_floor_bytes_are_never_laundered_into_a_resolved_pointer() {
        // MUST-FIX regression. `ResolvedPointer` documents that the only way to
        // hold one is to have resolved it, and the README tells integrators to
        // derive their contract key from `code_hash()` for BOTH `Resolved` and
        // `Unchanged`. A floor, though, is unverified caller state: a shared
        // config file, a restored backup, XSS in a browser consumer, or a
        // build-time floor copied from the wrong release can all put arbitrary
        // bytes there.
        //
        // Before the fix, a floor whose hash merely sorted BELOW the author's
        // genuine record at the same version was re-affirmed on every resolve
        // as `Unchanged(ResolvedPointer { code_hash: <attacker's> })` -- no
        // error, nothing `Stale`, and `next_floor()` re-persisted it, so it
        // survived restarts until the author published v+1.
        let genuine = [0x99u8; 32];
        let forged = [0x11u8; 32]; // sorts below, so the floor wins the tiebreak
        let (vk, _p, s) = published(7, 5, genuine);

        let outcome = resolve_with(&vk, floor(5, forged), state(&s)).unwrap();
        assert!(
            outcome.resolved().is_none(),
            "the forged floor hash escaped into a ResolvedPointer: {outcome:?}"
        );
        assert_eq!(outcome, PointerOutcome::CompetingRecord { version: 5 });
        // And it is not silently re-persisted, so it cannot outlive the
        // corrupt read that produced it.
        assert_eq!(outcome.next_floor(), None);

        // The same must hold for every reachable floor/record pairing, on both
        // channels by which floor bytes could survive a resolve: the outcome's
        // own record AND `next_floor`, which the caller persists and re-reads.
        //
        // Both axes carry the tombstone. A withdrawal floor and a withdrawal
        // record are ordinary values in the ordering, not special cases handled
        // elsewhere, and that quadrant is where the sibling of the laundering
        // bug lives: the tombstone sorts below every real hash, so a withdrawal
        // floor meets a replayed pre-withdrawal record on the tiebreak path.
        // (`forged` and `other` here just play "some hash the resolver was not
        // served".)
        let other = [0x55u8; 32];
        let key = signing_key(7);
        let params = pointer_params(&key.verifying_key(), APP_ID).unwrap();

        let mut floors = vec![PointerFloor::never_resolved()];
        for floor_version in [4u32, 5, 6] {
            for floor_hash in [forged, genuine, other] {
                floors.push(floor(floor_version, floor_hash));
            }
            floors.push(PointerFloor::withdrawn_at(floor_version).unwrap());
        }

        for served_version in [4u32, 5, 6] {
            for served_hash in [genuine, forged, TOMBSTONE_CODE_HASH] {
                let served = sign(&key, &params, served_version, served_hash)
                    .encode()
                    .to_vec();
                for &f in &floors {
                    let outcome = resolve_with(&vk, f, state(&served)).unwrap();

                    if let Some(r) = outcome.resolved() {
                        assert_eq!(
                            (r.version(), r.code_hash()),
                            (served_version, served_hash),
                            "outcome {outcome:?} carries a record this resolve never verified \
                             (floor {f:?})"
                        );
                        assert_ne!(
                            served_hash, TOMBSTONE_CODE_HASH,
                            "a tombstone record must never surface as a ResolvedPointer, \
                             or the caller derives a key from 32 zero bytes: {outcome:?}"
                        );
                    }

                    // A floor handed back is a floor the caller persists, so it
                    // is a laundering channel of its own: it must describe the
                    // record just verified, never the floor that went in.
                    if let Some(next) = outcome.next_floor() {
                        assert_eq!(
                            (next.version(), next.code_hash()),
                            (served_version, Some(served_hash)),
                            "next_floor {next:?} does not describe the verified record \
                             (outcome {outcome:?}, floor {f:?})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_unchanged_outcome_reports_the_served_verified_record() {
        // The byte-equal case is the one where a record CAN be handed back:
        // the served record was signature-verified and ties the floor, so the
        // `ResolvedPointer` is built from it rather than from storage.
        let (vk, _p, s) = published(7, 5, [0x33; 32]);
        let outcome = resolve_with(&vk, floor(5, [0x33; 32]), state(&s)).unwrap();
        let PointerOutcome::Unchanged(r) = outcome else {
            panic!("expected Unchanged, got {outcome:?}");
        };
        assert_eq!(r.version(), 5);
        assert_eq!(r.code_hash(), [0x33; 32]);
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

        // Holding `high`, served `low`: adopt, so the floor moves to `low`.
        let a_floor = floor(5, high);
        let a = resolve_with(&vk, a_floor, state(&low_state)).unwrap();
        // Holding `low`, served `high`: keep the floor, which is already `low`.
        let b_floor = floor(5, low);
        let b = resolve_with(&vk, b_floor, state(&high_state)).unwrap();

        // Convergence is about the floor a caller ENDS on, which is
        // `next_floor()` when it advances and the previous floor when it does
        // not. Both paths land on `low`, which is what makes an author's
        // double-publish recoverable rather than a permanent split.
        assert_eq!(a.next_floor().unwrap(), floor(5, low));
        assert_eq!(a.resolved().unwrap().code_hash(), low);
        assert_eq!(
            b.next_floor(),
            None,
            "keeping the floor must not rewrite it"
        );
        assert_eq!(b_floor.code_hash(), Some(low));
        assert_eq!(a.next_floor().unwrap(), b_floor);
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
        let outcome = resolve_with(&vk, floor(4, [0x11; 32]), PointerFetch::Absent).unwrap();
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
            PointerError::FloorVersion(0),
            PointerError::FloorTombstone,
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
            resolve_with(&vk, floor(9, [0x11; 32]), state(&s)).unwrap(),
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
        let outcome = resolve_with(&vk, floor(4, [0x11; 32]), state(&s)).unwrap();
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
        let outcome = resolve_with(&vk, floor(4, [0x11; 32]), state(&tomb)).unwrap();
        let after = outcome
            .next_floor()
            .expect("a withdrawal must advance the floor");
        assert_eq!(after, withdrawn_floor(8));
        // And it round-trips through a caller's own storage, which is what the
        // documented persist flow depends on. The withdrawal is carried by
        // `is_withdrawn()`, NOT by inferring it from a zeroed hash column --
        // `at` refuses that inference, which is the whole point of the split.
        assert_eq!(after.version(), 8);
        assert!(after.is_withdrawn());
        assert_eq!(after.code_hash(), Some(TOMBSTONE_CODE_HASH));
        assert_eq!(PointerFloor::withdrawn_at(after.version()).unwrap(), after);

        // A real, validly-signed pre-withdrawal record no longer resurrects it.
        let pre = sign(&key, &params, 5, [0x55; 32]).encode().to_vec();
        assert_eq!(
            resolve_with(&vk, after, state(&pre)).unwrap(),
            PointerOutcome::Stale {
                served: 5,
                floor: 8
            }
        );
        // Re-reading the withdrawal is still a withdrawal, not a resurrection.
        assert_eq!(
            resolve_with(&vk, after, state(&tomb)).unwrap(),
            PointerOutcome::Withdrawn { version: 8 }
        );
    }

    #[test]
    fn a_tombstone_wins_an_equal_version_tie_against_real_code() {
        // TOMBSTONE_CODE_HASH is all zeros, the minimum, so "lower code hash
        // wins" makes a same-version withdrawal beat a real hash, in the
        // contract's merge and here alike. Withdrawal is the safe way to
        // resolve that tie.
        let (vk, _params, tomb) = published(7, 5, TOMBSTONE_CODE_HASH);
        assert_eq!(
            resolve_with(&vk, floor(5, [0x11; 32]), state(&tomb)).unwrap(),
            PointerOutcome::Withdrawn { version: 5 }
        );
    }

    #[test]
    fn real_code_cannot_win_an_equal_version_tie_against_a_tombstone() {
        // The mirror image: already withdrawn at v, served real code at the
        // same v. The tombstone is the lower hash, so the floor holds and the
        // withdrawal is not undone without a version bump.
        //
        // The outcome is `CompetingRecord`, not `Withdrawn`: the withdrawal
        // lives in the caller's floor, and this resolve verified only the
        // record that LOST, so it has nothing of its own to assert about the
        // app's status. The caller keeps what it had -- which
        // `PointerFloor::is_withdrawn` still reports -- and no key is derived
        // from the served record.
        let (vk, _params, real) = published(7, 5, [0x11; 32]);
        let outcome = resolve_with(&vk, withdrawn_floor(5), state(&real)).unwrap();
        assert_eq!(outcome, PointerOutcome::CompetingRecord { version: 5 });
        assert!(
            outcome.resolved().is_none(),
            "the losing real-code record must not become a usable key"
        );
        assert_eq!(outcome.next_floor(), None);
        assert!(withdrawn_floor(5).is_withdrawn());
    }

    #[test]
    fn a_rolled_back_tombstone_is_still_refused() {
        let (vk, _params, s) = published(7, 2, TOMBSTONE_CODE_HASH);
        assert_eq!(
            resolve_with(&vk, floor(6, [0x11; 32]), state(&s)).unwrap(),
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
        // p + 3: decodes to the large-order point y = 3, but is not that
        // point's canonical encoding, so it would be a second address for one
        // usable author key. (y = p would reduce to the small-order y = 0 and
        // would be caught by the weak-key guard instead, proving nothing about
        // this one.)
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0xf0;
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
    fn a_floor_outside_the_valid_version_range_is_refused() {
        // Neither end can come from a real resolution, so both are corrupt
        // caller state, and guessing is unsafe in OPPOSITE directions: version
        // 0 would read as "never resolved" and unlock the baked-in fallback,
        // while a version above the maximum could never be superseded.
        assert_eq!(
            PointerFloor::at(0, [0x11; 32]).unwrap_err(),
            PointerError::FloorVersion(0)
        );
        assert_eq!(
            PointerFloor::at(u32::MAX, [0x11; 32]).unwrap_err(),
            PointerError::FloorVersion(u32::MAX)
        );
        assert!(PointerFloor::at(1, [0x11; 32]).is_ok());
        assert!(PointerFloor::at(MAX_POINTER_VERSION, [0x11; 32]).is_ok());
        // The same range rule applies to a withdrawal floor.
        assert_eq!(
            PointerFloor::withdrawn_at(0).unwrap_err(),
            PointerError::FloorVersion(0)
        );
        assert_eq!(
            PointerFloor::withdrawn_at(u32::MAX).unwrap_err(),
            PointerError::FloorVersion(u32::MAX)
        );
        assert!(PointerFloor::withdrawn_at(1).is_ok());
        assert!(PointerFloor::withdrawn_at(MAX_POINTER_VERSION).is_ok());
    }

    #[test]
    fn a_defaulted_code_hash_column_is_refused_rather_than_read_as_a_withdrawal() {
        // MUST-FIX regression. `at` already refused a defaulted VERSION column
        // with an explicit "corrupt caller state (a defaulted database column,
        // a partial write)" rationale, while accepting a defaulted CODE HASH --
        // 32 zero bytes, which is also TOMBSTONE_CODE_HASH. That made one
        // partial write say "the author withdrew this app", and stickily: the
        // README maps `Withdrawn` to `stop_resolving()`, `next_floor()`
        // re-persisted the tombstone, and a healthy app that never bumps its
        // version never supersedes it. Same corruption class, so same
        // treatment: refuse, and let the caller decide.
        assert_eq!(
            PointerFloor::at(5, TOMBSTONE_CODE_HASH).unwrap_err(),
            PointerError::FloorTombstone
        );
        assert_eq!(
            PointerFloor::at(5, [0u8; 32]).unwrap_err(),
            PointerError::FloorTombstone
        );
        assert!(!PointerError::FloorTombstone.may_use_baked_in_fallback());
        assert!(
            PointerError::FloorTombstone
                .to_string()
                .contains("withdrawn_at"),
            "the error must name the constructor that DOES express a withdrawal"
        );

        // The reproduction, end to end: floor (5, all-zeros) plus a genuine
        // signed v5 record used to yield `Withdrawn { version: 5 }`. Now the
        // corrupt floor never comes into existence, so the resolve that used to
        // retire a healthy app cannot be set up at all.
        let (_vk, _p, _s) = published(7, 5, [0x11; 32]);
        assert!(PointerFloor::at(5, TOMBSTONE_CODE_HASH).is_err());

        // A genuine withdrawal is still expressible, and is what a real
        // `Withdrawn` outcome round-trips through.
        let deliberate = PointerFloor::withdrawn_at(5).unwrap();
        assert!(deliberate.is_withdrawn());
        assert_eq!(deliberate.code_hash(), Some(TOMBSTONE_CODE_HASH));
        assert!(!floor(5, [0x11; 32]).is_withdrawn());
        assert!(!PointerFloor::never_resolved().is_withdrawn());
    }

    #[test]
    fn a_tampered_outcome_version_cannot_produce_a_wedged_floor() {
        // `#[non_exhaustive]` stops downstream CONSTRUCTING `Withdrawn`, but
        // not mutating a genuine one, and `PointerOutcome` is `Clone`. So the
        // guarantee has to come from `next_floor` re-validating rather than
        // from the attribute. A version outside 1..=MAX_POINTER_VERSION must
        // yield `None` ("learned nothing"), never a floor that no valid record
        // could ever supersede.
        let (vk, _p, tomb) = published(7, 8, TOMBSTONE_CODE_HASH);
        let mut outcome = resolve_with(&vk, PointerFloor::never_resolved(), state(&tomb)).unwrap();
        assert_eq!(outcome.next_floor(), Some(withdrawn_floor(8)));

        if let PointerOutcome::Withdrawn { version, .. } = &mut outcome {
            *version = u32::MAX;
        }
        assert_eq!(
            outcome.next_floor(),
            None,
            "a tampered version must not become a floor no record can supersede"
        );

        if let PointerOutcome::Withdrawn { version, .. } = &mut outcome {
            *version = 0;
        }
        assert_eq!(outcome.next_floor(), None);
    }

    #[test]
    fn a_degraded_floor_shape_still_enforces_anti_rollback() {
        // `(version > 0, code_hash: None)` is unconstructible through the public
        // API, which is exactly why the arm handling it is easy to delete by
        // accident: reverting it to a bare `adopt` disables anti-rollback for a
        // shape no test covers. The unit tests are in-module, so the private
        // fields are reachable here and the fail-closed claim can be a test
        // rather than a comment.
        let broken = PointerFloor {
            version: 6,
            code_hash: None,
        };
        let vk = signing_key(7).verifying_key();

        let (_v, _p, older) = published(7, 2, [0xaa; 32]);
        assert_eq!(
            resolve_with(&vk, broken, state(&older)).unwrap(),
            PointerOutcome::Stale {
                served: 2,
                floor: 6
            }
        );

        // Equal version must NOT be adopted: without a floor hash there is no
        // tiebreak to apply, so the conservative answer is to keep the floor.
        let (_v2, _p2, same) = published(7, 6, [0x01; 32]);
        assert_eq!(
            resolve_with(&vk, broken, state(&same)).unwrap(),
            PointerOutcome::Stale {
                served: 6,
                floor: 6
            }
        );

        // Strictly newer is still adopted, so the degradation refuses rollback
        // without wedging the caller.
        let (_v3, _p3, newer) = published(7, 9, [0x33; 32]);
        assert!(matches!(
            resolve_with(&vk, broken, state(&newer)).unwrap(),
            PointerOutcome::Resolved(r) if r.version() == 9
        ));
    }

    #[test]
    fn a_floor_round_trips_through_a_callers_own_storage() {
        // The documented persist flow is "store version + code_hash, rebuild
        // with at()". If the accessors could not express a floor, that flow
        // would be unimplementable and the withdrawal-replay guard unbuildable.
        let (vk, _p, s) = published(7, 3, [0x11; 32]);
        let outcome = resolve_with(&vk, PointerFloor::never_resolved(), state(&s)).unwrap();
        let next = outcome
            .next_floor()
            .expect("a resolution advances the floor");
        let restored = PointerFloor::at(next.version(), next.code_hash().unwrap()).unwrap();
        assert_eq!(restored, next);
        assert_eq!(restored.version(), 3);
        assert_eq!(restored.code_hash(), Some([0x11; 32]));
        assert_eq!(PointerFloor::never_resolved().code_hash(), None);
    }

    /// Both params functions must apply the SAME rules.
    ///
    /// `pointer_params` builds the address the resolver actually derives, and
    /// `parse_pointer_params` reads one back. A guard present in only one of
    /// them is invisible to a test that exercises the other, which is exactly
    /// how four deletions survived an earlier suite: the canonical-key check in
    /// `pointer_params`, and the weak-key, charset and upper-length checks in
    /// `parse_pointer_params`. Driving one bad-input table through both closes
    /// that and stops the two drifting apart.
    #[test]
    fn both_params_functions_apply_the_same_rules() {
        let good = signing_key(7).verifying_key();

        // A non-canonical encoding of y = 3, i.e. the value p + 3, which is
        // >= the field prime and so not the canonical encoding of anything.
        //
        // Deliberately NOT y = p (the obvious choice): that reduces to y = 0,
        // which is a small-order point, so it trips `is_weak` too and the case
        // would still fail with the canonical guard deleted, just with a
        // different error. y = 3 is on the curve and large-order, so this
        // witness isolates the canonical check.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xf0;
        non_canonical[31] = 0x7f;
        assert!(!is_canonical_field_element(&non_canonical));
        // The guard is only meaningful if dalek accepts such a key, so prove it
        // does rather than assuming the check is reachable at all.
        let non_canonical_vk = VerifyingKey::from_bytes(&non_canonical)
            .expect("dalek accepts a non-canonical y, which is why we check it ourselves");
        assert!(
            !non_canonical_vk.is_weak(),
            "the witness must not ALSO be small-order, or it cannot isolate the \
             canonical-encoding guard from the weak-key guard"
        );

        let weak = VerifyingKey::from_bytes(&[
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ])
        .unwrap();
        assert!(weak.is_weak());

        let long = vec![b'a'; MAX_APP_ID_LEN + 1];
        let cases: [(&str, VerifyingKey, &[u8], PointerError); 5] = [
            (
                "non-canonical author key",
                non_canonical_vk,
                APP_ID,
                PointerError::ParamsKeyNonCanonical,
            ),
            (
                "small-order author key",
                weak,
                APP_ID,
                PointerError::ParamsKeyWeak,
            ),
            (
                "uppercase app_id byte",
                good,
                b"River.Room",
                PointerError::ParamsAppId(b'R'),
            ),
            (
                "over-long app_id",
                good,
                &long,
                PointerError::ParamsLength(VERIFYING_KEY_LEN + MAX_APP_ID_LEN + 1),
            ),
            (
                "empty app_id",
                good,
                b"",
                PointerError::ParamsLength(VERIFYING_KEY_LEN),
            ),
        ];

        for (what, vk, app_id, expected) in cases {
            assert_eq!(
                pointer_params(&vk, app_id).unwrap_err(),
                expected,
                "pointer_params accepted {what}"
            );
            // Feed the same bad input to the parser as a raw blob.
            let blob = [vk.as_bytes().as_slice(), app_id].concat();
            assert_eq!(
                parse_pointer_params(&blob).unwrap_err(),
                expected,
                "parse_pointer_params accepted {what}"
            );
        }

        // Sweep the WHOLE byte range through both functions, not one sample.
        // A single `b"River.Room"` case is satisfied by any guard that happens
        // to reject uppercase, so a mutant checking `is_ascii_uppercase()`
        // instead of the real charset would pass while accepting spaces, NUL
        // and non-ASCII. Pinning the predicate in isolation is not enough
        // either: it proves nothing about which predicate a call site uses.
        for b in 0u8..=255 {
            let app_id = [b];
            if is_valid_app_id_byte(b) {
                assert!(
                    pointer_params(&good, &app_id).is_ok(),
                    "pointer_params rejected permitted app_id byte {b:#04x}"
                );
                let blob = [good.as_bytes().as_slice(), &app_id[..]].concat();
                assert!(
                    parse_pointer_params(&blob).is_ok(),
                    "parse_pointer_params rejected permitted app_id byte {b:#04x}"
                );
            } else {
                assert_eq!(
                    pointer_params(&good, &app_id).unwrap_err(),
                    PointerError::ParamsAppId(b),
                    "pointer_params accepted forbidden app_id byte {b:#04x}"
                );
                let blob = [good.as_bytes().as_slice(), &app_id[..]].concat();
                assert_eq!(
                    parse_pointer_params(&blob).unwrap_err(),
                    PointerError::ParamsAppId(b),
                    "parse_pointer_params accepted forbidden app_id byte {b:#04x}"
                );
            }
        }

        // Both ACCEPTING boundaries, through both functions and round-tripped.
        // Rejection cases alone leave a mutant free to tighten a bound and
        // refuse legal params, which the contract would have accepted.
        // Cycled rather than a repeated byte: `[b'a'; N]` round-trips through
        // a reordering or truncate-and-pad bug undetected.
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-_";
        let cycled =
            |n: usize| -> Vec<u8> { (0..n).map(|i| ALPHABET[i % ALPHABET.len()]).collect() };
        for (what, app_id) in [
            ("the shortest legal app_id", cycled(1)),
            ("the longest legal app_id", cycled(MAX_APP_ID_LEN)),
        ] {
            let built = pointer_params(&good, &app_id)
                .unwrap_or_else(|e| panic!("pointer_params rejected {what}: {e}"));
            assert_eq!(built.len(), VERIFYING_KEY_LEN + app_id.len());
            let (back_vk, back_app) = parse_pointer_params(&built)
                .unwrap_or_else(|e| panic!("parse_pointer_params rejected {what}: {e}"));
            assert_eq!(back_vk, good);
            assert_eq!(back_app, &app_id[..]);
        }
    }

    #[test]
    fn an_author_key_that_is_not_on_the_curve_is_refused() {
        // Canonical `y`, but no corresponding curve point: the
        // `VerifyingKey::from_bytes` failure path, which nothing else covers.
        let mut bytes = [0u8; 32];
        bytes[0] = 2; // y = 2 is not a valid compressed Ed25519 point
        assert!(is_canonical_field_element(&bytes));
        assert!(VerifyingKey::from_bytes(&bytes).is_err());
        let blob = [&bytes[..], APP_ID].concat();
        assert_eq!(
            parse_pointer_params(&blob).unwrap_err(),
            PointerError::ParamsKey
        );
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
            rendered.contains("pointer-contract resolution failed")
                && rendered.contains("signature verification failed"),
            "unhelpful rendering: {rendered}"
        );
        // And the two older SuccessorPointer variants stay distinct from it --
        // in the TEXT, not merely as values. Both mechanisms used to render as
        // "successor pointer ...", so a caller logging error text could not
        // tell which one had failed, which is the exact confusion this module's
        // prose works to prevent.
        assert_ne!(e, crate::MigrateError::BadSignature);
        let older = crate::MigrateError::BadSignature.to_string();
        assert!(
            older.contains("successor pointer signature is invalid"),
            "unexpected rendering for the older primitive: {older}"
        );
        assert!(
            !rendered.contains("successor"),
            "the pointer contract must not render as a 'successor pointer': {rendered}"
        );
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
                floor(6, [0xbb; 32])
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
