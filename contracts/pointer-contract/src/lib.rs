//! The canonical Freenet **successor-pointer contract**.
//!
//! # The problem it solves
//!
//! A Freenet contract or delegate key is `BLAKE3(BLAKE3(wasm) ‖ params)`. Any
//! byte change to the WASM -- a bug fix, a dependency bump, even a version
//! string -- produces a different key. The author carries their own data
//! forward, but every third party that baked the old key into its build now
//! addresses a stale, empty namespace, with no way to learn a successor exists.
//!
//! This contract is one level of indirection with a **stable** key: its state
//! names the current code hash of the app's real contract or delegate. A
//! consumer reads the pointer, takes `code_hash`, and combines it with *its own*
//! params to derive the key it actually needs. See `README.md` for the
//! integrator-facing derivation.
//!
//! # Shape
//!
//! * **Params** (fixed byte layout, never serde):
//!   `author_verifying_key (32 bytes) ‖ app_id (1..=64 bytes)`.
//! * **State** (fixed byte layout, never serde, exactly 100 bytes):
//!   `version (u32 big-endian) ‖ code_hash (32 bytes) ‖ signature (64 bytes)`.
//!
//! Both layouts are fixed-width and dependency-free on purpose. `Parameters`
//! and `State` are opaque byte blobs at the platform boundary, so any
//! serialization crate's own version drift would silently re-key every pointer
//! in the ecosystem. See `WASM-STABILITY.md`.
//!
//! # Ordering
//!
//! `validate_state` never receives the prior state -- the `ContractInterface`
//! trait does not provide one -- so it can only check well-formedness,
//! `version != 0`, and the signature. Monotonicity is enforced **only** in
//! `update_state`, which is the sole place a prior version is available.

use ed25519_dalek::{Signature, VerifyingKey};
use freenet_stdlib::prelude::*;

/// Domain-separation tag prefixed to every signed message. Without it, a
/// signature an author produced for some other purpose under the same key could
/// be replayed as a pointer record. Bump the suffix only if the signed layout
/// changes, which is a flag day (see `WASM-STABILITY.md`).
pub const SIGNING_DOMAIN: &[u8] = b"freenet-pointer/state-v1";

/// Length of an Ed25519 verifying key.
pub const VERIFYING_KEY_LEN: usize = 32;
/// Length of a BLAKE3 code hash.
pub const CODE_HASH_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an encoded pointer record: `u32 ‖ code_hash ‖ signature`.
pub const STATE_LEN: usize = 4 + CODE_HASH_LEN + SIGNATURE_LEN;

/// Highest publishable version. `u32::MAX` is reserved: a pointer sitting there
/// could never be superseded, because every rule here requires a strictly
/// greater version to move it, and the equal-version tiebreak takes the LOWER
/// encoding -- so an author who re-signed at `MAX` would lose to their own
/// mistake. An author deriving `version` from a timestamp would land there.
///
/// Rejected in `sign_record` AND in the contract. The publisher-side guard
/// alone would not cover the non-Rust publishers `TEST-VECTORS.md` exists for.
pub const MAX_VERSION: u32 = u32::MAX - 1;

/// A `code_hash` of all zeros means **this app is withdrawn**: there is no
/// current code, and a consumer must stop resolving rather than derive a key
/// from 32 zero bytes.
///
/// Defined now, while it is free, precisely because it cannot be added later.
/// Without a reserved value, retiring an app would need a new state field, and
/// a new state field is a flag day that re-keys every pointer in the ecosystem.
/// The contract does not treat a tombstone specially -- it is an ordinary
/// signed record, subject to the same monotonicity -- so this costs nothing in
/// the frozen WASM beyond one documented constant.
pub const TOMBSTONE_CODE_HASH: [u8; CODE_HASH_LEN] = [0u8; CODE_HASH_LEN];

/// Longest permitted `app_id`. Bounded so params length is bounded, and so a
/// pointer's params can never grow into something a consumer must stream.
pub const MAX_APP_ID_LEN: usize = 64;

/// Shortest possible params: a verifying key plus a one-byte `app_id`.
pub const MIN_PARAMS_LEN: usize = VERIFYING_KEY_LEN + 1;
/// Longest possible params.
pub const MAX_PARAMS_LEN: usize = VERIFYING_KEY_LEN + MAX_APP_ID_LEN;

/// Is `b` permitted inside an `app_id`?
///
/// Deliberately a closed, case-less ASCII set: `a-z`, `0-9`, `.`, `-`, `_`.
///
/// This is why the contract needs no Unicode normalization (and therefore no
/// `unicode-normalization` dependency, which would be one more crate whose
/// version drift could re-key the pointer). It also removes a whole class of
/// confusable-identity attack: `App`, `app`, and a decomposed-accent lookalike
/// would otherwise be three distinct pointer keys that render identically.
#[inline]
pub const fn is_valid_app_id_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
}

/// Is `bytes` the canonical little-endian encoding of an Ed25519 y coordinate,
/// i.e. is `y < 2^255 - 19` once the sign bit is cleared?
///
/// curve25519-dalek decompresses non-canonical encodings happily, so two
/// distinct 32-byte strings can name the same public key. For an ordinary
/// signature check that is harmless; here the params blob IS the contract's
/// address, so it would mean two different pointer keys with the same author.
#[inline]
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

/// Everything that can be wrong with a pointer's params or state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerError {
    /// Params were shorter than a key plus a one-byte `app_id`, or longer than
    /// a key plus [`MAX_APP_ID_LEN`].
    ParamsLength(usize),
    /// The first 32 params bytes are not a valid Ed25519 verifying key.
    ParamsKey,
    /// The first 32 params bytes decode to a point, but are not that point's
    /// canonical encoding (the y coordinate is >= the field prime).
    ///
    /// `VerifyingKey::from_bytes` accepts these, so without this check two
    /// different params blobs -- and therefore two different pointer keys --
    /// would carry the same effective author. Same class of confusable identity
    /// the `app_id` charset rules out, so it is ruled out here too.
    ParamsKeyNonCanonical,
    /// The author key is small-order. `verify_strict` refuses to verify under
    /// such a key, so a pointer with one could never accept any record at all.
    /// Rejected at parse rather than leaving a pointer that is silently
    /// permanently empty.
    ParamsKeyWeak,
    /// An `app_id` byte is outside the permitted set.
    ParamsAppId(u8),
    /// The state was not exactly [`STATE_LEN`] bytes.
    StateLength(usize),
    /// `version` was 0. Version numbering starts at 1, so 0 is reserved to mean
    /// "no pointer has ever been published", and must never appear on the wire.
    ZeroVersion,
    /// The signature field is all zeros -- almost always an unsigned record
    /// from a publisher that built the state but never signed it. Split out
    /// from [`Self::BadSignature`] because it is the one cause of a
    /// verification failure that is mechanically distinguishable, and it is a
    /// common enough publisher mistake to be worth naming.
    SignatureUnset,
    /// The signature did not verify under the params' author key.
    ///
    /// Ed25519 cannot say which of the remaining causes it was, so the message
    /// enumerates them rather than asserting one. Do not "improve" this later:
    /// this text ships inside the frozen WASM.
    BadSignature,
    /// `version` was `u32::MAX`, which is reserved. See [`MAX_VERSION`].
    ReservedVersion,
}

impl core::fmt::Display for PointerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParamsLength(n) => write!(
                f,
                "pointer params must be {MIN_PARAMS_LEN}..={MAX_PARAMS_LEN} bytes, got {n}"
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
            Self::StateLength(n) => {
                write!(
                    f,
                    "pointer state must be exactly {STATE_LEN} bytes, got {n}"
                )
            }
            Self::ZeroVersion => write!(f, "pointer version 0 is reserved and never valid"),
            Self::ReservedVersion => write!(
                f,
                "pointer version {} is reserved: a pointer there could never be \
                 superseded. Use a counter, not a timestamp",
                u32::MAX
            ),
            Self::SignatureUnset => write!(
                f,
                "the pointer signature is all zeros: the record was built but never signed"
            ),
            Self::BadSignature => write!(
                f,
                "pointer signature verification failed. Ed25519 cannot distinguish the \
                 cause; check, in this order: (1) you signed with the private key \
                 matching the author_verifying_key in these exact params; (2) you signed \
                 over these exact params bytes, app_id included, not a different app's; \
                 (3) your signed message is DOMAIN || params || version_be || code_hash \
                 with version big-endian -- see TEST-VECTORS.md"
            ),
        }
    }
}

impl std::error::Error for PointerError {}

impl From<PointerError> for ContractError {
    fn from(e: PointerError) -> Self {
        match e {
            // A malformed or unacceptable STATE is an invalid state.
            PointerError::StateLength(_)
            | PointerError::ZeroVersion
            | PointerError::ReservedVersion
            | PointerError::SignatureUnset
            | PointerError::BadSignature => ContractError::InvalidState,
            // A malformed PARAMS blob is a misconfigured contract, not a bad
            // state, so it keeps a distinct classification.
            other => ContractError::Other(other.to_string()),
        }
    }
}

/// A parsed view over a pointer contract's params.
#[derive(Debug, Clone)]
pub struct PointerParams<'a> {
    /// The publisher's Ed25519 verifying key. Every valid state for this
    /// pointer is signed by the matching private key.
    pub author_vk: VerifyingKey,
    /// Which app this pointer is for, e.g. `river.room-contract`.
    pub app_id: &'a [u8],
}

impl<'a> PointerParams<'a> {
    /// Parse the fixed params layout: `author_vk (32) ‖ app_id (1..=64)`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PointerError> {
        if !(MIN_PARAMS_LEN..=MAX_PARAMS_LEN).contains(&bytes.len()) {
            return Err(PointerError::ParamsLength(bytes.len()));
        }
        let (key_bytes, app_id) = bytes.split_at(VERIFYING_KEY_LEN);
        let mut key = [0u8; VERIFYING_KEY_LEN];
        key.copy_from_slice(key_bytes);
        // `VerifyingKey::from_bytes` accepts non-canonical y encodings and
        // small-order keys, so neither is caught for us.
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
        Ok(Self { author_vk, app_id })
    }

    /// Build the params byte string for `(author_vk, app_id)`.
    ///
    /// Rejects exactly what [`Self::parse`] rejects, so a publisher cannot mint
    /// params the contract will refuse.
    ///
    /// This is the *only* correct way to construct pointer params: the pointer's
    /// key is `BLAKE3(pointer_code_hash ‖ these bytes)`, so a single byte of
    /// disagreement between publisher and consumer yields a different, empty
    /// contract.
    pub fn encode(author_vk: &VerifyingKey, app_id: &[u8]) -> Result<Vec<u8>, PointerError> {
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
}

/// The pointer record: which code hash is current, and at what version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerRecord {
    /// Monotonically increasing. Starts at 1; 0 is never valid.
    pub version: u32,
    /// `BLAKE3(current_wasm)` of the app's real contract or delegate.
    pub code_hash: [u8; CODE_HASH_LEN],
    /// Ed25519 signature over [`signing_message`].
    pub signature: [u8; SIGNATURE_LEN],
}

/// The bytes an author signs: `DOMAIN ‖ params ‖ version_be ‖ code_hash`.
///
/// Binding the **whole params blob** (not just the version and code hash) is
/// what stops a record signed for one app being replayed into another pointer
/// belonging to the same author -- both pointers verify under the same key, so
/// without the params in the message they would accept each other's records.
pub fn signing_message(params: &[u8], version: u32, code_hash: &[u8; CODE_HASH_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNING_DOMAIN.len() + params.len() + 4 + CODE_HASH_LEN);
    m.extend_from_slice(SIGNING_DOMAIN);
    m.extend_from_slice(params);
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(code_hash);
    m
}

impl PointerRecord {
    /// Decode the fixed 100-byte state layout. Does **not** check the signature
    /// or the version; see [`PointerRecord::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, PointerError> {
        if bytes.len() != STATE_LEN {
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

    /// Encode to the fixed 100-byte state layout.
    pub fn encode(&self) -> [u8; STATE_LEN] {
        let mut out = [0u8; STATE_LEN];
        out[..4].copy_from_slice(&self.version.to_be_bytes());
        out[4..4 + CODE_HASH_LEN].copy_from_slice(&self.code_hash);
        out[4 + CODE_HASH_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// Check the version is in `1..=MAX_VERSION`, that the signature is not
    /// unset, and that it verifies under the params' author key over the params
    /// those bytes came from.
    pub fn verify(&self, params: &[u8], author_vk: &VerifyingKey) -> Result<(), PointerError> {
        if self.version == 0 {
            return Err(PointerError::ZeroVersion);
        }
        if self.version > MAX_VERSION {
            return Err(PointerError::ReservedVersion);
        }
        if self.signature == [0u8; SIGNATURE_LEN] {
            return Err(PointerError::SignatureUnset);
        }
        let msg = signing_message(params, self.version, &self.code_hash);
        author_vk
            .verify_strict(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| PointerError::BadSignature)
    }

    /// Whether this record withdraws the app rather than naming current code.
    /// A consumer seeing this must stop resolving; deriving a key from 32 zero
    /// bytes would silently address a contract that does not exist.
    pub fn is_tombstone(&self) -> bool {
        self.code_hash == TOMBSTONE_CODE_HASH
    }

    /// Decode and verify in one step -- the only call the accept path should
    /// make, so a caller cannot decode and then forget to verify.
    pub fn decode_verified(bytes: &[u8], params: &[u8]) -> Result<Self, PointerError> {
        let parsed = PointerParams::parse(params)?;
        let record = Self::decode(bytes)?;
        record.verify(params, &parsed.author_vk)?;
        Ok(record)
    }
}

/// Publisher-side signing. Not compiled into the canonical WASM: a node only
/// ever verifies, so the frozen artifact carries no signing code.
#[cfg(any(test, feature = "publish"))]
pub fn sign_record(
    signing_key: &ed25519_dalek::SigningKey,
    params: &[u8],
    version: u32,
    code_hash: [u8; CODE_HASH_LEN],
) -> Result<PointerRecord, PointerError> {
    use ed25519_dalek::Signer;
    if version == 0 {
        return Err(PointerError::ZeroVersion);
    }
    if version > MAX_VERSION {
        return Err(PointerError::ReservedVersion);
    }
    // Reject params the contract itself would reject, so a publisher cannot
    // sign a record for a pointer whose params can never validate.
    PointerParams::parse(params)?;
    let sig = signing_key.sign(&signing_message(params, version, &code_hash));
    Ok(PointerRecord {
        version,
        code_hash,
        signature: sig.to_bytes(),
    })
}

pub struct PointerContract;

#[contract]
impl ContractInterface for PointerContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        // Params are checked first and separately. A malformed params blob is a
        // misconfigured contract, not a bad state, and `Err` is the honest
        // answer for it.
        let params = PointerParams::parse(parameters.as_ref())?;

        // A state-level rejection returns `Ok(Invalid)`, NOT `Err`. `Invalid` is
        // the trait's own way to say "this state is not valid for this
        // contract"; `Err` means the contract could not reach a verdict, and
        // core classifies it as an execution error, which is a different and
        // more alarming thing. This is state a peer supplied, so a bad
        // signature is an expected outcome, not a malfunction.
        match PointerRecord::decode(state.as_ref())
            .and_then(|record| record.verify(parameters.as_ref(), &params.author_vk))
        {
            Ok(()) => Ok(ValidateResult::Valid),
            Err(_) => Ok(ValidateResult::Invalid),
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = parameters.as_ref();
        let parsed = PointerParams::parse(params)?;

        // Unusable local state -- empty, truncated, or unverifiable -- is
        // treated as "this peer holds no pointer yet", so a validly-signed
        // candidate can always heal it.
        //
        // Returning `Err` here instead would brick the contract on that peer
        // permanently: every later update would bail before even looking at the
        // candidates, the network PUT path for an already-held contract also
        // routes through `update_state`, and each rejection would feed the
        // node's per-(contract, sender) merge backoff -- so the honest peers
        // trying to heal it would be the ones suppressed. This is not a
        // weakening: every record that can survive to be stored still had to
        // pass `verify()` below.
        let mut best = PointerRecord::decode_verified(state.as_ref(), params).ok();

        let mut saw_candidate = false;
        for update in &data {
            // `get_state_delta` emits the full record as the delta, so a delta
            // and a state carry identical bytes here. Handling only
            // `UpdateData::State` would make anti-entropy silently fail.
            let bytes: &[u8] = match update {
                UpdateData::State(s) => s.as_ref(),
                UpdateData::Delta(d) => d.as_ref(),
                UpdateData::StateAndDelta { state, .. } => state.as_ref(),
                // This contract has no related contracts; any other variant is
                // not something it can act on.
                _ => continue,
            };
            // An empty payload carries no candidate. Core filters empty deltas
            // on the peer path but not on the client fan-out, so an integrator
            // echoing a notification's delta back would otherwise turn a no-op
            // into a rejection.
            if bytes.is_empty() {
                continue;
            }
            saw_candidate = true;

            // A malformed or forged candidate is rejected -- but deliberately
            // NOT as `InvalidUpdate` / `InvalidUpdateWithInfo`.
            //
            // Both of those render with the prefix core matches on
            // (`is_invalid_update_rejection`, "invalid contract update"), which
            // gates `send_summary_back_on_rejection`. Core documents that
            // predicate as matching ONLY the benign "version not higher" case
            // and explicitly not validation failures, because those are
            // attacker-inducible and must not amplify into extra messages.
            //
            // Nothing honest reaches here: a peer that is merely behind sends a
            // validly-signed stale record, which is a no-op success below. The
            // only inputs that reach this branch are malformed or forged, so
            // replying would hand any peer a `summarize_state` call plus a
            // message back per forgery, and log the forgery as a stale
            // rebroadcast. `Deser`/`Other` still classify as a merge failure, so
            // the node's per-(contract, sender) backoff quarantines the bad
            // sender -- which is the response that actually helps.
            let candidate =
                PointerRecord::decode(bytes).map_err(|e| ContractError::Deser(e.to_string()))?;
            candidate
                .verify(params, &parsed.author_vk)
                .map_err(|e| ContractError::Other(e.to_string()))?;

            best = Some(match best {
                None => candidate,
                Some(current) => merge(current, candidate),
            });
        }

        // Nothing applicable arrived. If we hold a good record, that is a no-op
        // success -- there is nothing to do and our state is still valid. Only
        // when we have nothing to fall back on is it an error, and even then not
        // an `InvalidUpdate*` one, for the amplification reason above.
        if !saw_candidate {
            return match best {
                Some(current) => Ok(UpdateModification::valid(State::from(
                    current.encode().to_vec(),
                ))),
                None => Err(ContractError::Deser(
                    "no usable pointer record in the update, and no local state to keep".into(),
                )),
            };
        }

        // A stale or equal update is a **no-op success**, never an error.
        // Returning `Err` here would turn routine anti-entropy from a peer that
        // is merely behind into a merge failure, feeding the node's merge
        // backoff. `best` is unchanged in that case, so the node stores what it
        // already had.
        let winner = best.expect("saw_candidate implies best is Some");
        Ok(UpdateModification::valid(State::from(
            winner.encode().to_vec(),
        )))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        // An empty summary means "I have nothing", and any local state we
        // cannot decode AND verify is worth exactly as much as nothing -- so it
        // is advertised the same way, rather than erroring.
        //
        // `update_state` deliberately tolerates unusable local state so a valid
        // record can heal it. That is pointless unless this function can ASK for
        // the heal: erroring here would mean the peer never advertises its
        // ignorance, never attracts a record, and fails a WASM call on every
        // heartbeat instead. Verifying (not merely decoding) matters too -- a
        // right-length but corrupt state would otherwise be published as this
        // peer's summary, and every honest peer would compute that it owes this
        // peer nothing, permanently.
        let Ok(record) = PointerRecord::decode_verified(state.as_ref(), parameters.as_ref()) else {
            return Ok(StateSummary::from(Vec::new()));
        };
        // The summary is the WHOLE record, not just the version.
        //
        // This is load-bearing, and a version-only summary is the trap. The
        // node decides two peers have converged by comparing their summaries
        // BYTE-FOR-BYTE, and skips the delta probe entirely when they match.
        // With a version-only summary, two peers holding validly-signed but
        // different records at the same version emit identical summaries, so
        // they are declared converged, never exchange records, and `merge` --
        // whose entire job is to break that tie -- is never called. The split
        // the tiebreak exists to prevent would survive it.
        //
        // At 100 bytes the record is its own cheapest summary, so there is
        // nothing to gain from a narrower one.
        Ok(StateSummary::from(record.encode().to_vec()))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let params = parameters.as_ref();

        // Nothing to offer if our own state is missing or unusable. Same
        // tolerance as `summarize_state`, and for the same reason.
        let Ok(ours) = PointerRecord::decode_verified(state.as_ref(), params) else {
            return Ok(StateDelta::from(Vec::new()));
        };

        // The peer's summary is VERIFIED, not merely decoded.
        //
        // Without the signature check this is a downgrade oracle: a peer sends a
        // hand-crafted 100-byte summary claiming version 0xFFFFFFFF with
        // garbage where the signature goes, every honest peer computes that it
        // owes that peer nothing, and the liar is never sent the real record --
        // so it keeps answering GETs with a stale version forever. That turns
        // the transient rollback window the README describes into a permanent,
        // self-maintaining one. Requiring a valid signature means a peer can
        // only ever claim a position the author actually signed.
        //
        // Any summary we cannot read or cannot verify -- empty, truncated,
        // garbage, forged -- means "I cannot tell what this peer holds", and the
        // safe answer is "here is everything". Deliberately NOT an error: the
        // summary is peer-supplied, so erroring would let any peer turn one
        // malformed byte into a failed WASM call on every heartbeat.
        let theirs = PointerRecord::decode_verified(summary.as_ref(), params).ok();

        // Send when we hold something their record would not win against.
        // Because `merge` is a total order, exactly one of two diverged peers
        // owes the other a delta, so a divergence resolves in a single round.
        let owed = match theirs {
            None => true,
            Some(theirs) => merge(theirs, ours) != theirs,
        };

        if owed {
            // The delta *is* the whole record. At 100 bytes there is nothing
            // to gain from a narrower encoding, and a full record is
            // self-verifying at the receiver.
            Ok(StateDelta::from(ours.encode().to_vec()))
        } else {
            Ok(StateDelta::from(Vec::new()))
        }
    }
}

/// Deterministic merge of two validly-signed records.
///
/// Higher version always wins. At an *equal* version with different bytes --
/// which only the author can produce, by signing twice at one version from two
/// release machines or a retried publish -- the **lower** encoded record wins,
/// comparing `code_hash` first and then the signature.
///
/// This is a **total order**, and that is the point. Comparing `code_hash`
/// alone would leave two records with the same version and same code hash but
/// different signatures unordered, so each peer would keep its own and the
/// split would be permanent. That is not hypothetical: this crate's own signer
/// is deterministic, but `README.md` tells authors to hold the key in offline
/// or threshold custody, and threshold Ed25519 and hedged HSM signers use
/// randomized nonces -- so re-signing identical content, which is exactly the
/// retried-publish case, yields two different valid signatures.
///
/// Without a tiebreak at all, two peers holding byte-different equal-version
/// records would each treat the other's as stale forever: a permanent
/// anti-entropy split (freenet-core#5158 documents six contracts stuck exactly
/// this way). Neither outcome recovers the author's intent without a version
/// bump, so deterministic convergence is strictly better than a permanent
/// split. The primary defence is still operational: gate publishing on a single
/// committed monotonic counter (see `README.md`).
///
/// `summarize_state` must expose enough for this to be reachable -- see the
/// note there on why a version-only summary silently disarms it.
fn merge(current: PointerRecord, candidate: PointerRecord) -> PointerRecord {
    use core::cmp::Ordering;
    match candidate.version.cmp(&current.version) {
        Ordering::Greater => candidate,
        Ordering::Less => current,
        // The version is equal and occupies the leading bytes, so comparing the
        // full encoding compares `code_hash` and then `signature`.
        Ordering::Equal => {
            if candidate.encode() < current.encode() {
                candidate
            } else {
                current
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const APP_ID: &[u8] = b"river.room-contract";

    /// Deterministic test keys -- no RNG, so the test suite needs no `rand`.
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn params_for(sk: &SigningKey, app_id: &[u8]) -> Vec<u8> {
        PointerParams::encode(&sk.verifying_key(), app_id).unwrap()
    }

    fn code_hash(seed: u8) -> [u8; CODE_HASH_LEN] {
        [seed; CODE_HASH_LEN]
    }

    fn state_bytes(sk: &SigningKey, params: &[u8], version: u32, ch: u8) -> Vec<u8> {
        sign_record(sk, params, version, code_hash(ch))
            .unwrap()
            .encode()
            .to_vec()
    }

    /// Build a record at `version` without going through `sign_record`'s
    /// version check, so the zero-version case can actually be constructed.
    fn forced_state(sk: &SigningKey, params: &[u8], version: u32, ch: u8) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let hash = code_hash(ch);
        let sig = sk.sign(&signing_message(params, version, &hash));
        PointerRecord {
            version,
            code_hash: hash,
            signature: sig.to_bytes(),
        }
        .encode()
        .to_vec()
    }

    /// A state-level rejection: `Ok(Invalid)`, never `Err`. Asserting the exact
    /// variant matters -- `Err` would mean the contract could not reach a
    /// verdict, which core classifies as an execution error.
    #[track_caller]
    fn assert_state_rejected(params: &[u8], state: &[u8]) {
        match validate(params, state) {
            Ok(ValidateResult::Invalid) => {}
            other => panic!("expected Ok(Invalid), got {other:?}"),
        }
    }

    /// Core gates `send_summary_back_on_rejection` on the rendered error
    /// starting with "invalid contract update". That reply is meant for the
    /// benign version-not-higher case only; ours is a no-op success, so nothing
    /// honest reaches an error at all. Anything that does is malformed or
    /// forged, and must not buy the sender a `summarize_state` call plus a
    /// message back.
    #[track_caller]
    fn assert_non_amplifying(err: &ContractError) {
        let rendered = err.to_string();
        assert!(
            !rendered.starts_with("invalid contract update"),
            "error would trigger core's summary-back amplification: {rendered}"
        );
    }

    fn validate(params: &[u8], state: &[u8]) -> Result<ValidateResult, ContractError> {
        PointerContract::validate_state(
            Parameters::from(params.to_vec()),
            State::from(state.to_vec()),
            RelatedContracts::default(),
        )
    }

    fn update(
        params: &[u8],
        state: &[u8],
        incoming: Vec<u8>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        PointerContract::update_state(
            Parameters::from(params.to_vec()),
            State::from(state.to_vec()),
            vec![UpdateData::State(State::from(incoming))],
        )
    }

    // ---------------------------------------------------------------- validate

    #[test]
    fn accepts_a_well_formed_signed_record() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let s = state_bytes(&sk, &p, 1, 0xAA);
        assert!(matches!(validate(&p, &s), Ok(ValidateResult::Valid)));
    }

    #[test]
    fn rejects_version_zero() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        // Correctly signed, correctly framed -- only the version is 0.
        let s = forced_state(&sk, &p, 0, 0xAA);
        assert_state_rejected(&p, &s);
        // ...and the cause is distinguishable at the PointerError level.
        assert_eq!(
            PointerRecord::decode_verified(&s, &p),
            Err(PointerError::ZeroVersion)
        );
    }

    #[test]
    fn rejects_a_bad_signature() {
        let author = key(1);
        let impostor = key(2);
        let p = params_for(&author, APP_ID);
        // Signed by the wrong key, against the author's params.
        let s = state_bytes(&impostor, &p, 1, 0xAA);
        assert_state_rejected(&p, &s);
    }

    #[test]
    fn rejects_a_record_replayed_from_another_app_under_the_same_key() {
        // The signature must bind the params, or one author's two pointers
        // would happily accept each other's records.
        let sk = key(1);
        let p_room = params_for(&sk, b"river.room-contract");
        let p_delegate = params_for(&sk, b"river.chat-delegate");
        let s = state_bytes(&sk, &p_room, 7, 0xAA);
        assert!(matches!(validate(&p_room, &s), Ok(ValidateResult::Valid)));
        assert_state_rejected(&p_delegate, &s);
    }

    #[test]
    fn rejects_malformed_state_length() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let mut s = state_bytes(&sk, &p, 1, 0xAA);
        s.push(0);
        assert_state_rejected(&p, &s);
        assert_state_rejected(&p, &[]);
        assert_state_rejected(&p, &s[..STATE_LEN - 1]);
    }

    #[test]
    fn rejects_malformed_params() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let s = state_bytes(&sk, &p, 1, 0xAA);

        // No app_id at all.
        assert!(validate(&sk.verifying_key().to_bytes(), &s).is_err());
        // Uppercase is outside the permitted set -- no case-confusable pointers.
        assert!(PointerParams::encode(&sk.verifying_key(), b"River").is_err());
        // Over-long app_id.
        assert!(PointerParams::encode(&sk.verifying_key(), &[b'a'; MAX_APP_ID_LEN + 1]).is_err());
        // Empty app_id.
        assert!(PointerParams::encode(&sk.verifying_key(), b"").is_err());
    }

    // ------------------------------------------------------------------ update

    #[test]
    fn accepts_a_strictly_higher_version() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 4, 0xAA);
        let next = state_bytes(&sk, &p, 5, 0xBB);

        let result = update(&p, &current, next.clone()).unwrap();
        let stored = result.unwrap_valid();
        assert_eq!(stored.as_ref(), next.as_slice());
        assert_eq!(PointerRecord::decode(stored.as_ref()).unwrap().version, 5);
    }

    #[test]
    fn a_replayed_or_lower_version_is_a_no_op_success() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 5, 0xBB);

        // A strictly lower version, and a byte-identical replay of the record
        // already stored. Both must succeed (never `Err`, or routine
        // anti-entropy from a behind peer feeds the node's merge backoff) and
        // both must leave the stored record untouched.
        let lower = state_bytes(&sk, &p, 4, 0xAA);
        let exact_replay = current.clone();

        for (label, stale) in [("lower v4", lower), ("exact replay of v5", exact_replay)] {
            let result = update(&p, &current, stale)
                .unwrap_or_else(|e| panic!("{label} must not error: {e}"));
            let stored = result.unwrap_valid();
            assert_eq!(
                stored.as_ref(),
                current.as_slice(),
                "{label} must leave the stored record untouched"
            );
        }
    }

    /// Pins S1: no rejection `update_state` can produce may render with core's
    /// `is_invalid_update_rejection` prefix, or any peer could buy itself a
    /// `summarize_state` call plus a reply per forged 100 bytes.
    #[test]
    fn no_rejection_path_triggers_core_summary_back_amplification() {
        let author = key(1);
        let impostor = key(2);
        let p = params_for(&author, APP_ID);
        let current = state_bytes(&author, &p, 5, 0xAA);

        let forged = state_bytes(&impostor, &p, 99, 0xFF);
        let zero_version = forced_state(&author, &p, 0, 0xBB);
        let reserved = forced_state(&author, &p, u32::MAX, 0xBB);
        let unsigned = {
            let mut r = PointerRecord::decode(&state_bytes(&author, &p, 9, 0xCC)).unwrap();
            r.signature = [0u8; SIGNATURE_LEN];
            r.encode().to_vec()
        };
        let cross_app = state_bytes(&author, &params_for(&author, b"other.app"), 9, 0xDD);

        for (label, bad) in [
            ("forged", forged),
            ("version 0", zero_version),
            ("reserved version", reserved),
            ("unsigned", unsigned),
            ("cross-app replay", cross_app),
            ("truncated", vec![0u8; STATE_LEN - 1]),
            ("over-long", vec![0u8; STATE_LEN + 1]),
            ("one byte", vec![7u8]),
        ] {
            let err = update(&p, &current, bad).expect_err(&format!("{label} must be rejected"));
            assert_non_amplifying(&err);
        }
    }

    /// I7: a malformed-LENGTH candidate. The pre-existing malformed-state test
    /// covers the opposite direction (a corrupt STORED state healed by a good
    /// record), so without this the length check on the candidate path had no
    /// coverage and deleting it would have failed nothing.
    #[test]
    fn update_rejects_a_candidate_of_the_wrong_length() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 5, 0xAA);
        let good = state_bytes(&sk, &p, 6, 0xBB);

        for wrong in [
            good[..STATE_LEN - 1].to_vec(),
            [good.clone(), vec![0u8]].concat(),
            good[..4].to_vec(),
        ] {
            let err = update(&p, &current, wrong).unwrap_err();
            assert!(
                matches!(err, ContractError::Deser(_)),
                "a wrong-length candidate is a framing error, got {err:?}"
            );
            assert_non_amplifying(&err);
        }
    }

    #[test]
    fn update_rejects_an_unsigned_or_forged_candidate() {
        let author = key(1);
        let impostor = key(2);
        let p = params_for(&author, APP_ID);
        let current = state_bytes(&author, &p, 1, 0xAA);
        // Higher version, but signed by the wrong key.
        let forged = state_bytes(&impostor, &p, 99, 0xFF);
        let err = update(&p, &current, forged).unwrap_err();
        assert!(matches!(err, ContractError::Other(_)));
        assert_non_amplifying(&err);
    }

    #[test]
    fn update_rejects_a_version_zero_candidate() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 1, 0xAA);
        let zero = forced_state(&sk, &p, 0, 0xBB);
        assert!(update(&p, &current, zero).is_err());
    }

    #[test]
    fn update_onto_empty_state_accepts_any_valid_record() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let first = state_bytes(&sk, &p, 3, 0xAA);
        let stored = update(&p, &[], first.clone()).unwrap().unwrap_valid();
        assert_eq!(stored.as_ref(), first.as_slice());
    }

    #[test]
    fn update_applies_a_delta_not_just_a_state() {
        // `get_state_delta` emits the full record, so `update_state` must accept
        // it arriving as `UpdateData::Delta`. Handling only `State` would make
        // anti-entropy a silent no-op.
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 1, 0xAA);
        let next = state_bytes(&sk, &p, 2, 0xBB);

        let stored = PointerContract::update_state(
            Parameters::from(p.clone()),
            State::from(current),
            vec![UpdateData::Delta(StateDelta::from(next.clone()))],
        )
        .unwrap()
        .unwrap_valid();
        assert_eq!(stored.as_ref(), next.as_slice());
    }

    #[test]
    fn equal_version_conflicts_converge_deterministically() {
        // Two validly-signed records at the same version must not leave two
        // peers permanently disagreeing.
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let low = state_bytes(&sk, &p, 9, 0x11);
        let high = state_bytes(&sk, &p, 9, 0x99);

        let a = update(&p, &low, high.clone()).unwrap().unwrap_valid();
        let b = update(&p, &high, low.clone()).unwrap().unwrap_valid();
        assert_eq!(
            a.as_ref(),
            b.as_ref(),
            "peers seeing the same pair in either order must converge"
        );
        assert_eq!(a.as_ref(), low.as_slice());
    }

    #[test]
    fn update_with_no_usable_data_keeps_what_we_have() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 1, 0xAA);

        // No entries at all, and an empty delta -- which core does NOT filter on
        // the client fan-out path, so an integrator echoing a notification's
        // delta back arrives here. Both are no-ops, not rejections.
        for data in [
            vec![],
            vec![UpdateData::Delta(StateDelta::from(Vec::new()))],
            vec![UpdateData::State(State::from(Vec::new()))],
        ] {
            let stored = PointerContract::update_state(
                Parameters::from(p.clone()),
                State::from(current.clone()),
                data,
            )
            .expect("an empty update must not be a rejection")
            .unwrap_valid();
            assert_eq!(stored.as_ref(), current.as_slice());
        }

        // With nothing to keep either, it is an honest error -- but not an
        // `InvalidUpdate*` one, which would trigger core's summary-back reply.
        let err = PointerContract::update_state(
            Parameters::from(p),
            State::from(Vec::new()),
            vec![UpdateData::Delta(StateDelta::from(Vec::new()))],
        )
        .unwrap_err();
        assert_non_amplifying(&err);
    }

    // --------------------------------------------------------- summary / delta

    #[test]
    fn summary_and_delta_round_trip() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let state = state_bytes(&sk, &p, 7, 0xAA);

        let summary = PointerContract::summarize_state(
            Parameters::from(p.clone()),
            State::from(state.clone()),
        )
        .unwrap();
        // The summary is the whole record, not just the version: a version-only
        // summary would make same-version divergence invisible to anti-entropy.
        // See `diverged_peers_at_the_same_version_are_visible_to_anti_entropy`.
        assert_eq!(summary.as_ref(), state.as_slice());
        assert_eq!(PointerRecord::decode(summary.as_ref()).unwrap().version, 7);

        // A peer that is behind gets the whole record back.
        let behind = StateSummary::from(state_bytes(&sk, &p, 3, 0xCC));
        let delta = PointerContract::get_state_delta(
            Parameters::from(p.clone()),
            State::from(state.clone()),
            behind,
        )
        .unwrap();
        assert_eq!(delta.as_ref(), state.as_slice());

        // ...and applying that delta lands it at version 7.
        let older = state_bytes(&sk, &p, 3, 0xCC);
        let stored = PointerContract::update_state(
            Parameters::from(p.clone()),
            State::from(older),
            vec![UpdateData::Delta(StateDelta::from(delta.as_ref().to_vec()))],
        )
        .unwrap()
        .unwrap_valid();
        assert_eq!(PointerRecord::decode(stored.as_ref()).unwrap().version, 7);

        // A peer that is level or ahead gets nothing.
        for v in [7u32, 8] {
            let theirs = state_bytes(&sk, &p, v, 0xAA);
            let d = PointerContract::get_state_delta(
                Parameters::from(p.clone()),
                State::from(state.clone()),
                StateSummary::from(theirs),
            )
            .unwrap();
            assert!(d.as_ref().is_empty(), "no delta owed to a peer at v{v}");
        }
    }

    #[test]
    fn an_empty_summary_asks_for_everything() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let state = state_bytes(&sk, &p, 1, 0xAA);
        let delta = PointerContract::get_state_delta(
            Parameters::from(p),
            State::from(state.clone()),
            StateSummary::from(Vec::new()),
        )
        .unwrap();
        assert_eq!(delta.as_ref(), state.as_slice());
    }

    #[test]
    fn an_empty_state_summarizes_and_deltas_to_nothing() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let summary =
            PointerContract::summarize_state(Parameters::from(p.clone()), State::from(vec![]))
                .unwrap();
        assert!(summary.as_ref().is_empty());
        let delta = PointerContract::get_state_delta(
            Parameters::from(p),
            State::from(vec![]),
            StateSummary::from(Vec::new()),
        )
        .unwrap();
        assert!(delta.as_ref().is_empty());
    }

    // ------------------------------------------------------------- wire format

    #[test]
    fn state_layout_is_exactly_the_documented_100_bytes() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let s = state_bytes(&sk, &p, 0x01020304, 0xAA);
        assert_eq!(s.len(), 100);
        assert_eq!(
            &s[..4],
            &[0x01, 0x02, 0x03, 0x04],
            "version is u32 big-endian"
        );
        assert_eq!(&s[4..36], &[0xAAu8; 32], "code_hash follows the version");
        assert_eq!(s[36..].len(), 64, "signature is the trailing 64 bytes");
        assert_eq!(PointerRecord::decode(&s).unwrap().version, 0x01020304);
    }

    #[test]
    fn params_layout_is_key_then_app_id() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        assert_eq!(&p[..32], sk.verifying_key().as_bytes());
        assert_eq!(&p[32..], APP_ID);
    }

    #[test]
    fn signing_domain_is_frozen() {
        // Changing this tag invalidates every pointer record ever published.
        assert_eq!(SIGNING_DOMAIN, b"freenet-pointer/state-v1");
    }

    /// The whole point of the contract: `code_hash` plus the consumer's own
    /// params derives the key the consumer actually needs. This pins the
    /// derivation documented in README.md against stdlib's real implementation.
    #[test]
    fn consumer_derivation_matches_stdlib() {
        // Stand in for the app's real contract WASM.
        let wasm = b"pretend this is the app's contract wasm".to_vec();
        // Whatever params *this* consumer's own instance uses -- a room owner's
        // verifying key, a delegate's config, anything.
        let consumer_params = Parameters::from(b"the consumer's own params".to_vec());

        // What a node computes when it actually holds the code.
        let authoritative = ContractKey::from_params_and_code(
            consumer_params.clone(),
            ContractCode::from(wasm.clone()),
        );

        // What a consumer computes from a pointer's `code_hash` alone, without
        // ever having seen the WASM. This is the README's derivation.
        let code_hash = CodeHash::from_code(&wasm);
        let derived =
            ContractKey::from_params(code_hash.encode(), consumer_params).expect("valid base58");

        assert_eq!(
            derived.id(),
            authoritative.id(),
            "pointer code_hash + own params must reproduce the node's own key derivation"
        );
        assert_eq!(derived.encoded_code_hash(), code_hash.encode());
    }

    // ------------------------------------------- convergence of diverged peers

    /// The bug this pins: with a version-only summary, two peers holding
    /// different validly-signed records at the SAME version emit identical
    /// summaries. The node compares summaries byte-for-byte to decide two peers
    /// have converged, so it skips the delta probe, the records never meet, and
    /// `merge` -- whose whole job is to break that tie -- is never called.
    ///
    /// `equal_version_conflicts_converge_deterministically` cannot catch this:
    /// it hands both records to `update_state` directly, bypassing the exact
    /// layer that keeps them apart.
    #[test]
    fn diverged_peers_at_the_same_version_are_visible_to_anti_entropy() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let a = state_bytes(&sk, &p, 9, 0x11);
        let b = state_bytes(&sk, &p, 9, 0x99);
        assert_ne!(a, b);

        let sum = |st: &[u8]| {
            PointerContract::summarize_state(Parameters::from(p.clone()), State::from(st.to_vec()))
                .unwrap()
                .as_ref()
                .to_vec()
        };
        assert_ne!(
            sum(&a),
            sum(&b),
            "diverged peers must not summarize identically, or the node calls them converged"
        );

        // Exactly one side owes the other a delta, so it resolves in one round.
        let delta = |mine: &[u8], theirs: &[u8]| {
            PointerContract::get_state_delta(
                Parameters::from(p.clone()),
                State::from(mine.to_vec()),
                StateSummary::from(sum(theirs)),
            )
            .unwrap()
            .as_ref()
            .to_vec()
        };
        let a_owes = !delta(&a, &b).is_empty();
        let b_owes = !delta(&b, &a).is_empty();
        assert!(
            a_owes ^ b_owes,
            "exactly one peer must owe a delta (a_owes={a_owes}, b_owes={b_owes})"
        );

        // Applying it lands both peers on the same record.
        let owed = if a_owes { delta(&a, &b) } else { delta(&b, &a) };
        let loser = if a_owes { b.clone() } else { a.clone() };
        let healed = PointerContract::update_state(
            Parameters::from(p.clone()),
            State::from(loser),
            vec![UpdateData::Delta(StateDelta::from(owed.clone()))],
        )
        .unwrap()
        .unwrap_valid();
        let winner = if a_owes { a } else { b };
        assert_eq!(healed.as_ref(), winner.as_slice(), "peers must converge");
    }

    #[test]
    fn merge_is_a_total_order_even_when_only_the_signature_differs() {
        // Only the author can produce this (it needs their key), but a
        // threshold or hedged-nonce signer re-signing identical content is
        // exactly the retried-publish case the README anticipates.
        let a = PointerRecord {
            version: 9,
            code_hash: code_hash(0x11),
            signature: [1u8; SIGNATURE_LEN],
        };
        let b = PointerRecord {
            version: 9,
            code_hash: code_hash(0x11),
            signature: [2u8; SIGNATURE_LEN],
        };
        assert_eq!(merge(a, b), merge(b, a), "merge must be commutative");

        // ...and associative across three records, in every order.
        let c = PointerRecord {
            version: 9,
            code_hash: code_hash(0x11),
            signature: [3u8; SIGNATURE_LEN],
        };
        let expected = merge(merge(a, b), c);
        for (x, y, z) in [(a, c, b), (b, a, c), (b, c, a), (c, a, b), (c, b, a)] {
            assert_eq!(merge(merge(x, y), z), expected, "merge must be associative");
        }
    }

    #[test]
    fn a_malformed_stored_state_is_healed_rather_than_bricking_the_peer() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let good = state_bytes(&sk, &p, 5, 0xAA);

        for corrupt in [vec![0u8; STATE_LEN], vec![9u8; 7], vec![]] {
            let stored = update(&p, &corrupt, good.clone())
                .expect("a valid record must be able to heal unusable local state")
                .unwrap_valid();
            assert_eq!(stored.as_ref(), good.as_slice());
        }
    }

    // ------------------------------------------------------ contract-side gates

    /// The confusability defence lives in `parse`, which is what the node runs.
    /// Asserting only against `encode` would leave it untested: `encode` is a
    /// publisher-side helper that is not even in the frozen WASM.
    #[test]
    fn the_contract_itself_rejects_out_of_charset_app_ids() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let s = state_bytes(&sk, &p, 1, 0xAA);

        for bad_id in [
            b"River".to_vec(),      // uppercase: case-confusable
            b"river room".to_vec(), // space
            b"river/room".to_vec(), // path separator
            vec![0u8],              // NUL
            vec![b'a'; MAX_APP_ID_LEN + 1],
            vec![],
        ] {
            let mut params = sk.verifying_key().to_bytes().to_vec();
            params.extend_from_slice(&bad_id);
            assert!(
                validate(&params, &s).is_err(),
                "the contract must reject app_id {bad_id:?}"
            );
        }
    }

    #[test]
    fn app_id_alphabet_is_exactly_the_documented_set() {
        let allowed: Vec<u8> = b"abcdefghijklmnopqrstuvwxyz0123456789.-_".to_vec();
        for b in 0u8..=255 {
            assert_eq!(
                is_valid_app_id_byte(b),
                allowed.contains(&b),
                "byte {b:#04x} classified wrongly"
            );
        }
    }

    #[test]
    fn app_id_length_bounds_agree_between_parse_and_encode() {
        let sk = key(1);
        for n in [
            0usize,
            1,
            2,
            MAX_APP_ID_LEN - 1,
            MAX_APP_ID_LEN,
            MAX_APP_ID_LEN + 1,
        ] {
            let id = vec![b'a'; n];
            let encoded = PointerParams::encode(&sk.verifying_key(), &id);
            let mut raw = sk.verifying_key().to_bytes().to_vec();
            raw.extend_from_slice(&id);
            let parsed = PointerParams::parse(&raw);
            assert_eq!(
                encoded.is_ok(),
                parsed.is_ok(),
                "publisher and contract must agree on app_id length {n}"
            );
            if let Ok(q) = parsed {
                assert_eq!(q.app_id, &id[..]);
            }
        }
    }

    #[test]
    fn params_with_a_non_canonical_key_are_rejected() {
        let sk = key(1);
        let s = state_bytes(&sk, &params_for(&sk, APP_ID), 1, 0xAA);
        let mut params = vec![0xFFu8; VERIFYING_KEY_LEN];
        params.extend_from_slice(APP_ID);
        assert!(validate(&params, &s).is_err());
    }

    #[test]
    fn sign_record_refuses_what_the_contract_would_refuse() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        assert!(sign_record(&sk, &p, 0, code_hash(1)).is_err(), "version 0");
        let mut bad = sk.verifying_key().to_bytes().to_vec();
        bad.extend_from_slice(b"River");
        assert!(
            sign_record(&sk, &bad, 1, code_hash(1)).is_err(),
            "bad app_id"
        );
    }

    #[test]
    fn a_bad_signature_is_reported_as_a_signature_failure() {
        // `ContractError::Other` is the catch-all for three distinct causes, so
        // assert at the `PointerError` level where they are distinguishable.
        let author = key(1);
        let impostor = key(2);
        let p = params_for(&author, APP_ID);
        let record = sign_record(&impostor, &p, 1, code_hash(0xAA)).unwrap();
        assert_eq!(
            record.verify(&p, &author.verifying_key()),
            Err(PointerError::BadSignature)
        );
    }

    // ----------------------------------------------------------- update batches

    #[test]
    fn update_folds_over_every_entry_regardless_of_order() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let base = state_bytes(&sk, &p, 1, 0x01);
        let v3 = state_bytes(&sk, &p, 3, 0x03);
        let v9 = state_bytes(&sk, &p, 9, 0x09);
        let v5 = state_bytes(&sk, &p, 5, 0x05);

        for order in [[&v3, &v9, &v5], [&v9, &v5, &v3], [&v5, &v3, &v9]] {
            let data = order
                .iter()
                .map(|s| UpdateData::State(State::from(s.to_vec())))
                .collect();
            let stored = PointerContract::update_state(
                Parameters::from(p.clone()),
                State::from(base.clone()),
                data,
            )
            .unwrap()
            .unwrap_valid();
            assert_eq!(PointerRecord::decode(stored.as_ref()).unwrap().version, 9);
        }
    }

    #[test]
    fn update_uses_the_state_half_of_a_state_and_delta_entry() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 1, 0xAA);
        let next = state_bytes(&sk, &p, 2, 0xBB);
        let stored = PointerContract::update_state(
            Parameters::from(p.clone()),
            State::from(current),
            vec![UpdateData::StateAndDelta {
                state: State::from(next.clone()),
                delta: StateDelta::from(next.clone()),
            }],
        )
        .unwrap()
        .unwrap_valid();
        assert_eq!(stored.as_ref(), next.as_slice());
    }

    #[test]
    fn a_garbage_summary_asks_for_everything_rather_than_erroring() {
        // The summary is peer-supplied; erroring would let any peer turn one
        // malformed byte into a failed WASM call on every heartbeat.
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let state = state_bytes(&sk, &p, 4, 0xAA);
        for junk in [vec![0u8; 3], vec![0u8; 5], vec![0xFFu8; 99], vec![7u8; 200]] {
            let delta = PointerContract::get_state_delta(
                Parameters::from(p.clone()),
                State::from(state.clone()),
                StateSummary::from(junk.clone()),
            )
            .expect("an unreadable summary must not be an error");
            assert_eq!(delta.as_ref(), state.as_slice());
        }
    }

    #[test]
    fn the_reserved_maximum_version_is_refused_everywhere() {
        // A pointer at u32::MAX could never be superseded: every rule requires a
        // strictly greater version, and the equal-version tiebreak takes the
        // LOWER encoding, so even the author re-signing at MAX would lose to
        // their own mistake. An author deriving version from a timestamp lands
        // there. Refused publisher-side AND in the contract, because the
        // publisher-side guard is not in the frozen WASM and would not cover the
        // non-Rust publishers TEST-VECTORS.md exists for.
        let sk = key(1);
        let p = params_for(&sk, APP_ID);

        assert_eq!(
            sign_record(&sk, &p, u32::MAX, code_hash(0xAA)),
            Err(PointerError::ReservedVersion),
            "the publisher-side helper must refuse it"
        );

        let max = forced_state(&sk, &p, u32::MAX, 0xAA);
        assert_state_rejected(&p, &max);

        // ...and it cannot be smuggled in as an update either.
        let prev = state_bytes(&sk, &p, MAX_VERSION, 0xBB);
        let err = update(&p, &prev, max).unwrap_err();
        assert_non_amplifying(&err);

        // MAX_VERSION itself is publishable.
        assert!(sign_record(&sk, &p, MAX_VERSION, code_hash(0xAA)).is_ok());
        assert!(matches!(validate(&p, &prev), Ok(ValidateResult::Valid)));
    }

    // -------------------------------------------------------- frozen byte layout

    /// A known-answer test over the whole wire format.
    ///
    /// Every other test signs and verifies through the same `signing_message`,
    /// so any mutation that changes both sides together -- big-endian to
    /// little-endian, or reordering the segments -- passes them all. Only a
    /// literal fixture catches that, and a third party implementing this layout
    /// in another language has nothing else to check itself against.
    #[test]
    fn wire_format_known_answer() {
        let sk = key(1);
        let p = params_for(&sk, b"river.room-contract");
        let msg = signing_message(&p, 7, &code_hash(0xAA));
        assert_eq!(
            hex(&msg),
            concat!(
                // b"freenet-pointer/state-v1"
                "667265656e65742d706f696e7465722f73746174652d7631",
                // params: 32-byte author verifying key...
                "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
                // ...then the app_id, b"river.room-contract"
                "72697665722e726f6f6d2d636f6e7472616374",
                // version 7, u32 big-endian
                "00000007",
                // code_hash
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "the signed message layout is frozen"
        );
        let state = state_bytes(&sk, &p, 7, 0xAA);
        assert_eq!(state.len(), STATE_LEN);
        assert_eq!(&hex(&state)[..8], "00000007", "version is u32 big-endian");
        assert!(matches!(validate(&p, &state), Ok(ValidateResult::Valid)));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// S2. `TEST-VECTORS.md` is the only thing a non-Rust reimplementer has to
    /// check itself against, and it previously claimed to be "pinned by the
    /// wire_format_known_answer test" while that test pinned only the signing
    /// message and four state bytes. The signature, the full state, the pointer
    /// key and both derived keys were asserted nowhere.
    ///
    /// This recomputes every published value and asserts it appears verbatim in
    /// the file, so a WRONG or MISSING vector fails here.
    ///
    /// What it does NOT catch, stated precisely rather than claimed away: it is
    /// a `contains` check, so an EXTRA stale value left behind in the document
    /// still passes. For base58 values CI closes that gap (it rejects any
    /// base58 of code-hash shape that is neither the current `CODEHASH` nor
    /// listed in `KNOWN-BASE58`); for hex values nothing does, so a stale hex
    /// blob would survive both. Re-derive the hex vectors by hand when editing
    /// them.
    ///
    /// The pointer key is derived from `CODEHASH` read at runtime, because
    /// hard-coding it here would be circular: it depends on the hash of the WASM
    /// built from this very file.
    #[test]
    fn every_published_test_vector_is_correct_and_present() {
        let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/TEST-VECTORS.md"))
            .expect("TEST-VECTORS.md");
        let codehash = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/CODEHASH"))
            .expect("CODEHASH");
        let pointer_code_hash = codehash
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .expect("a hash line")
            .trim();

        let sk = key(1);
        let vk = sk.verifying_key();
        let app_id: &[u8] = b"river.room-contract";
        let params = params_for(&sk, app_id);
        let ch = code_hash(0xAA);
        let record = sign_record(&sk, &params, 7, ch).unwrap();

        let mut published = vec![
            ("verifying_key", hex(vk.as_bytes())),
            ("app_id", hex(app_id)),
            ("params", hex(&params)),
            ("signing_message", hex(&signing_message(&params, 7, &ch))),
            ("signature", hex(&record.signature)),
            ("state", hex(&record.encode())),
            ("pointer_code_hash", pointer_code_hash.to_string()),
        ];

        // The pointer's own key.
        let pointer_key =
            ContractKey::from_params(pointer_code_hash, Parameters::from(params.clone()))
                .expect("valid base58");
        published.push(("pointer_key", pointer_key.id().to_string()));

        // The consumer-side derivation, both flavours.
        let consumer: Vec<u8> = b"example-consumer-params".to_vec();
        let ch_b58 = CodeHash::new(ch).encode();
        published.push(("code_hash_b58", ch_b58.clone()));
        published.push(("consumer_params", hex(&consumer)));
        published.push((
            "derived_contract",
            ContractKey::from_params(&ch_b58, Parameters::from(consumer.clone()))
                .unwrap()
                .id()
                .to_string(),
        ));
        published.push((
            "derived_delegate",
            DelegateKey::from_params(&ch_b58, &Parameters::from(consumer))
                .unwrap()
                .to_string(),
        ));

        // The document wraps long hex across lines and annotates some of them
        // with a trailing `<- ...` note, so compare against a normalized copy:
        // annotations dropped, all whitespace removed, table pipes removed.
        let flattened: String = doc
            .lines()
            .map(|line| line.split("<-").next().unwrap_or(line))
            .collect::<Vec<_>>()
            .concat()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '|' && *c != '`')
            .collect();

        for (label, value) in &published {
            assert!(
                flattened.contains(value.as_str()),
                "TEST-VECTORS.md does not publish the correct {label}\n  expected: {value}"
            );
        }

        // ...and the document must not claim a guarantee it does not have.
        assert!(
            doc.contains("every_published_test_vector_is_correct_and_present"),
            "TEST-VECTORS.md must name the test that actually pins it"
        );
    }

    // ------------------------------------------- consumer derivation, delegates

    /// The contract half is pinned by `consumer_derivation_matches_stdlib`; the
    /// incident that motivated this contract (ghostkeys, 2026-08-03) was a
    /// DELEGATE re-key, so pin that path too -- it is a different stdlib
    /// function with a different signature.
    #[test]
    fn consumer_delegate_derivation_matches_stdlib() {
        let wasm = b"pretend this is the app's delegate wasm".to_vec();
        let my_own_params = Parameters::from(b"the consumer's own delegate params".to_vec());

        let authoritative = Delegate::from((&DelegateCode::from(wasm.clone()), &my_own_params))
            .key()
            .clone();

        // Go through a real signed record, so the 32 bytes actually travel the
        // path an integrator uses rather than being handed over directly.
        let sk = key(1);
        let p = params_for(&sk, b"ghostkeys.ghostkey-delegate");
        let code_hash = CodeHash::from_code(&wasm);
        let record = sign_record(
            &sk,
            &p,
            1,
            code_hash.as_ref().try_into().expect("32-byte code hash"),
        )
        .unwrap();
        let resolved = PointerRecord::decode_verified(&record.encode(), &p).unwrap();

        let derived =
            DelegateKey::from_params(CodeHash::new(resolved.code_hash).encode(), &my_own_params)
                .expect("valid base58");
        assert_eq!(derived.bytes(), authoritative.bytes());
    }

    // ------------------------------------------------ the downgrade oracle (B1)

    /// Pins B1. `get_state_delta` must VERIFY the peer's summary, not merely
    /// decode it.
    ///
    /// Without that, a peer advertises a hand-crafted summary claiming a huge
    /// version with garbage where the signature goes; every honest peer computes
    /// that it owes that peer nothing; the liar is never sent the real record
    /// and keeps serving a stale version forever. That converts the transient
    /// rollback window into a permanent, self-maintaining downgrade.
    #[test]
    fn a_forged_summary_cannot_suppress_the_real_record() {
        let author = key(1);
        let impostor = key(2);
        let p = params_for(&author, APP_ID);
        let ours = state_bytes(&author, &p, 5, 0xAA);

        let liars = [
            // Right length, absurd version, garbage signature.
            (
                "unsigned max-version claim",
                PointerRecord {
                    version: MAX_VERSION,
                    code_hash: code_hash(0xFF),
                    signature: [0xFFu8; SIGNATURE_LEN],
                }
                .encode()
                .to_vec(),
            ),
            // Correctly signed, but by somebody who is not the author.
            (
                "forged by another key",
                state_bytes(&impostor, &p, MAX_VERSION, 0xFF),
            ),
            // Signed by the real author, but for a different app.
            (
                "cross-app replay",
                state_bytes(
                    &author,
                    &params_for(&author, b"other.app"),
                    MAX_VERSION,
                    0xFF,
                ),
            ),
            // Right length, right shape, corrupt body.
            ("corrupt", vec![0x5Au8; STATE_LEN]),
        ];

        for (label, forged_summary) in liars {
            let delta = PointerContract::get_state_delta(
                Parameters::from(p.clone()),
                State::from(ours.clone()),
                StateSummary::from(forged_summary),
            )
            .unwrap();
            assert_eq!(
                delta.as_ref(),
                ours.as_slice(),
                "{label}: an unverifiable summary must be owed the full record"
            );
        }

        // A genuinely ahead peer is still owed nothing -- the check must not
        // simply always send.
        let ahead = state_bytes(&author, &p, 6, 0xBB);
        let delta = PointerContract::get_state_delta(
            Parameters::from(p.clone()),
            State::from(ours),
            StateSummary::from(ahead),
        )
        .unwrap();
        assert!(
            delta.as_ref().is_empty(),
            "a legitimately ahead peer is owed nothing"
        );
    }

    /// Pins I1 for the right-length-but-corrupt case: a peer whose local state
    /// is unusable must advertise "I have nothing" so it attracts the heal that
    /// `update_state` was made tolerant for, rather than failing a WASM call on
    /// every heartbeat.
    #[test]
    fn unusable_local_state_advertises_nothing_and_is_healed() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let good = state_bytes(&sk, &p, 5, 0xAA);

        for (label, broken) in [
            ("wrong length", vec![9u8; 7]),
            ("right length, corrupt", vec![0x5Au8; STATE_LEN]),
            ("right length, unsigned", {
                let mut r = PointerRecord::decode(&good).unwrap();
                r.signature = [0u8; SIGNATURE_LEN];
                r.encode().to_vec()
            }),
        ] {
            let summary = PointerContract::summarize_state(
                Parameters::from(p.clone()),
                State::from(broken.clone()),
            )
            .unwrap_or_else(|e| panic!("{label}: summarize must not error: {e}"));
            assert!(
                summary.as_ref().is_empty(),
                "{label}: must advertise nothing"
            );

            let delta = PointerContract::get_state_delta(
                Parameters::from(p.clone()),
                State::from(broken.clone()),
                StateSummary::from(good.clone()),
            )
            .unwrap_or_else(|e| panic!("{label}: delta must not error: {e}"));
            assert!(delta.as_ref().is_empty(), "{label}: has nothing to offer");

            // ...and a peer seeing that empty summary owes it everything.
            let owed = PointerContract::get_state_delta(
                Parameters::from(p.clone()),
                State::from(good.clone()),
                StateSummary::from(Vec::new()),
            )
            .unwrap();
            assert_eq!(owed.as_ref(), good.as_slice());

            let healed = update(&p, &broken, good.clone()).unwrap().unwrap_valid();
            assert_eq!(healed.as_ref(), good.as_slice(), "{label}: must heal");
        }
    }

    // ------------------------------------------------------- author key hygiene

    /// I6. The previous version of this test signed with a different key than it
    /// put in params, so `verify_strict` failed on its own and it passed whether
    /// or not the key check existed. This calls `parse` directly and asserts the
    /// exact variant.
    #[test]
    fn params_reject_non_canonical_and_weak_author_keys() {
        // y = p - 1 + 2^255 style: a y value at or above the field prime is a
        // non-canonical encoding of a point that still decompresses.
        let mut non_canonical = [0xffu8; VERIFYING_KEY_LEN];
        non_canonical[0] = 0xee; // p = ...ed, so ...ee > p
        non_canonical[31] = 0x7f;
        assert!(
            !is_canonical_field_element(&non_canonical),
            "fixture must actually be non-canonical"
        );
        let mut params = non_canonical.to_vec();
        params.extend_from_slice(APP_ID);
        assert_eq!(
            PointerParams::parse(&params).unwrap_err(),
            PointerError::ParamsKeyNonCanonical
        );

        // The identity point is small-order: verify_strict can never accept it,
        // so a pointer carrying it would be permanently, silently empty.
        let mut identity = [0u8; VERIFYING_KEY_LEN];
        identity[0] = 1;
        let mut params = identity.to_vec();
        params.extend_from_slice(APP_ID);
        assert_eq!(
            PointerParams::parse(&params).unwrap_err(),
            PointerError::ParamsKeyWeak
        );

        // Bytes that are not a point at all.
        let mut not_a_point = [0xffu8; VERIFYING_KEY_LEN];
        not_a_point[31] = 0x00;
        let mut params = not_a_point.to_vec();
        params.extend_from_slice(APP_ID);
        assert!(matches!(
            PointerParams::parse(&params),
            Err(PointerError::ParamsKey | PointerError::ParamsKeyNonCanonical)
        ));

        // A real key still parses.
        assert!(PointerParams::parse(&params_for(&key(1), APP_ID)).is_ok());
    }

    #[test]
    fn canonical_field_element_boundaries() {
        // p itself is not canonical; p - 1 is.
        let mut p_bytes = [0xffu8; VERIFYING_KEY_LEN];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert!(!is_canonical_field_element(&p_bytes));
        let mut below = p_bytes;
        below[0] = 0xec;
        assert!(is_canonical_field_element(&below));
        // The top bit is the x sign and must be ignored.
        let mut signed = below;
        signed[31] |= 0x80;
        assert!(is_canonical_field_element(&signed));
        assert!(is_canonical_field_element(&[0u8; VERIFYING_KEY_LEN]));
    }

    #[test]
    fn a_tombstone_is_an_ordinary_record_that_consumers_can_recognise() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let live = sign_record(&sk, &p, 4, code_hash(0xAA)).unwrap();
        let dead = sign_record(&sk, &p, 5, TOMBSTONE_CODE_HASH).unwrap();

        assert!(!live.is_tombstone());
        assert!(dead.is_tombstone());
        // It is a normal signed record: valid, and subject to the same ordering.
        assert!(matches!(
            validate(&p, &dead.encode()),
            Ok(ValidateResult::Valid)
        ));
        let stored = update(&p, &live.encode(), dead.encode().to_vec())
            .unwrap()
            .unwrap_valid();
        assert!(PointerRecord::decode(stored.as_ref())
            .unwrap()
            .is_tombstone());
    }

    /// N1. The sampled version of this covered `update_state`'s candidate
    /// branch and missed the params-parse rejection, which is reachable from
    /// BOTH `update_state` and `validate_state`.
    ///
    /// Enumerating beats adding the missing case: the `match` below has no
    /// wildcard arm, so adding a variant to `PointerError` fails to COMPILE
    /// until it is listed here and therefore checked. A future variant cannot
    /// quietly acquire an amplifying mapping.
    #[test]
    fn no_pointer_error_maps_to_an_amplifying_contract_error() {
        let all = [
            PointerError::ParamsLength(0),
            PointerError::ParamsKey,
            PointerError::ParamsKeyNonCanonical,
            PointerError::ParamsKeyWeak,
            PointerError::ParamsAppId(b'!'),
            PointerError::StateLength(0),
            PointerError::ZeroVersion,
            PointerError::ReservedVersion,
            PointerError::SignatureUnset,
            PointerError::BadSignature,
        ];

        for e in &all {
            // Exhaustiveness gate. No wildcard: a new variant breaks the build.
            match e {
                PointerError::ParamsLength(_)
                | PointerError::ParamsKey
                | PointerError::ParamsKeyNonCanonical
                | PointerError::ParamsKeyWeak
                | PointerError::ParamsAppId(_)
                | PointerError::StateLength(_)
                | PointerError::ZeroVersion
                | PointerError::ReservedVersion
                | PointerError::SignatureUnset
                | PointerError::BadSignature => {}
            }
            assert_non_amplifying(&ContractError::from(e.clone()));
        }

        // Every variant must be represented above, or the enumeration is a
        // sample wearing an exhaustive match's clothes.
        let mut seen: Vec<String> = all.iter().map(|e| format!("{e:?}")).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(
            seen.len(),
            all.len(),
            "duplicate variants in the enumeration"
        );
    }

    /// The params-parse rejection specifically, through the real entry points
    /// rather than through `From`. Malformed params are reachable from both.
    #[test]
    fn malformed_params_rejections_are_also_non_amplifying() {
        let sk = key(1);
        let good = params_for(&sk, APP_ID);
        let state = state_bytes(&sk, &good, 3, 0xAA);
        let candidate = state_bytes(&sk, &good, 4, 0xBB);

        let bad_params = [
            ("empty", Vec::new()),
            (
                "key only, no app_id",
                sk.verifying_key().to_bytes().to_vec(),
            ),
            ("uppercase app_id", {
                let mut p = sk.verifying_key().to_bytes().to_vec();
                p.extend_from_slice(b"River");
                p
            }),
            ("over-long app_id", {
                let mut p = sk.verifying_key().to_bytes().to_vec();
                p.extend_from_slice(&[b'a'; MAX_APP_ID_LEN + 1]);
                p
            }),
            ("small-order key", {
                let mut p = vec![0u8; VERIFYING_KEY_LEN];
                p[0] = 1;
                p.extend_from_slice(APP_ID);
                p
            }),
        ];

        for (label, params) in bad_params {
            let err = PointerContract::update_state(
                Parameters::from(params.clone()),
                State::from(state.clone()),
                vec![UpdateData::State(State::from(candidate.clone()))],
            )
            .unwrap_err();
            assert_non_amplifying(&err);

            // `validate_state` returns Err (not Ok(Invalid)) for malformed
            // params, because that is a misconfigured contract rather than a bad
            // state -- but it must still not amplify.
            let err = PointerContract::validate_state(
                Parameters::from(params),
                State::from(state.clone()),
                RelatedContracts::default(),
            )
            .expect_err(&format!("{label}: malformed params must not validate"));
            assert_non_amplifying(&err);
        }
    }
}
