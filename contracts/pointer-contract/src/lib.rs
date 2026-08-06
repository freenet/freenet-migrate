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

/// Everything that can be wrong with a pointer's params or state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerError {
    /// Params were shorter than a key plus a one-byte `app_id`, or longer than
    /// a key plus [`MAX_APP_ID_LEN`].
    ParamsLength(usize),
    /// The first 32 params bytes are not a valid Ed25519 verifying key.
    ParamsKey,
    /// An `app_id` byte is outside the permitted set.
    ParamsAppId(u8),
    /// The state was not exactly [`STATE_LEN`] bytes.
    StateLength(usize),
    /// `version` was 0. Version numbering starts at 1, so 0 is reserved to mean
    /// "no pointer has ever been published", and must never appear on the wire.
    ZeroVersion,
    /// The signature did not verify under the params' author key.
    BadSignature,
}

impl core::fmt::Display for PointerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParamsLength(n) => write!(
                f,
                "pointer params must be {MIN_PARAMS_LEN}..={MAX_PARAMS_LEN} bytes, got {n}"
            ),
            Self::ParamsKey => write!(f, "pointer params do not start with a valid Ed25519 key"),
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
            Self::BadSignature => write!(f, "pointer signature verification failed"),
        }
    }
}

impl From<PointerError> for ContractError {
    fn from(e: PointerError) -> Self {
        match e {
            PointerError::StateLength(_) | PointerError::ZeroVersion => ContractError::InvalidState,
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
        let author_vk = VerifyingKey::from_bytes(&key).map_err(|_| PointerError::ParamsKey)?;
        if let Some(&bad) = app_id.iter().find(|b| !is_valid_app_id_byte(**b)) {
            return Err(PointerError::ParamsAppId(bad));
        }
        Ok(Self { author_vk, app_id })
    }

    /// Build the params byte string for `(author_vk, app_id)`.
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

    /// Check `version != 0` and that the signature verifies under the params'
    /// author key, over the params those bytes came from.
    pub fn verify(&self, params: &[u8], author_vk: &VerifyingKey) -> Result<(), PointerError> {
        if self.version == 0 {
            return Err(PointerError::ZeroVersion);
        }
        let msg = signing_message(params, self.version, &self.code_hash);
        author_vk
            .verify_strict(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| PointerError::BadSignature)
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
        PointerRecord::decode_verified(state.as_ref(), parameters.as_ref())?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = parameters.as_ref();
        let parsed = PointerParams::parse(params)?;

        // An empty state means this peer holds no pointer yet -- any valid
        // record supersedes nothing and is accepted.
        let mut best = if state.as_ref().is_empty() {
            None
        } else {
            Some(PointerRecord::decode_verified(state.as_ref(), params)?)
        };

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
            saw_candidate = true;

            // A malformed or unsigned candidate is a genuinely invalid update
            // and is rejected. A *stale* candidate is not -- see below.
            let candidate = PointerRecord::decode(bytes).map_err(ContractError::from)?;
            candidate.verify(params, &parsed.author_vk).map_err(|e| {
                ContractError::InvalidUpdateWithInfo {
                    reason: e.to_string(),
                }
            })?;

            best = Some(match best {
                None => candidate,
                Some(current) => merge(current, candidate),
            });
        }

        if !saw_candidate {
            return Err(ContractError::InvalidUpdate);
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
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            // "I have nothing." A peer receiving this must send its full record.
            return Ok(StateSummary::from(Vec::new()));
        }
        let record = PointerRecord::decode(state.as_ref()).map_err(ContractError::from)?;
        Ok(StateSummary::from(record.version.to_be_bytes().to_vec()))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        let record = PointerRecord::decode(state.as_ref()).map_err(ContractError::from)?;

        let summary_version = match summary.as_ref().len() {
            // Empty summary: the peer holds nothing, so everything is news.
            0 => 0,
            4 => {
                let mut v = [0u8; 4];
                v.copy_from_slice(summary.as_ref());
                u32::from_be_bytes(v)
            }
            _ => {
                return Err(ContractError::Deser(
                    "pointer summary must be 4 bytes".into(),
                ))
            }
        };

        if record.version > summary_version {
            // The delta *is* the whole record. At 100 bytes there is nothing
            // to gain from a narrower encoding, and a full record is
            // self-verifying at the receiver.
            Ok(StateDelta::from(record.encode().to_vec()))
        } else {
            Ok(StateDelta::from(Vec::new()))
        }
    }
}

/// Deterministic merge of two validly-signed records.
///
/// Higher version always wins. At an *equal* version with different bytes --
/// which only the author can produce, by signing twice at one version from two
/// release machines or a retried publish -- the tie is broken by comparing
/// `code_hash` lexicographically.
///
/// Without a tiebreak, two peers holding byte-different equal-version records
/// would each treat the other's as stale forever: a permanent anti-entropy
/// split (freenet-core#5158 documents six contracts stuck exactly this way).
/// Neither outcome recovers the author's intent without a version bump, so
/// deterministic convergence is strictly better than a permanent split. The
/// primary defence is still operational: gate publishing on a single committed
/// monotonic counter (see `README.md`).
fn merge(current: PointerRecord, candidate: PointerRecord) -> PointerRecord {
    use core::cmp::Ordering;
    match candidate.version.cmp(&current.version) {
        Ordering::Greater => candidate,
        Ordering::Less => current,
        Ordering::Equal => {
            if candidate.code_hash < current.code_hash {
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
        assert!(
            matches!(validate(&p, &s), Err(ContractError::InvalidState)),
            "version 0 must be rejected: it is reserved to mean 'no pointer published'"
        );
    }

    #[test]
    fn rejects_a_bad_signature() {
        let author = key(1);
        let impostor = key(2);
        let p = params_for(&author, APP_ID);
        // Signed by the wrong key, against the author's params.
        let s = state_bytes(&impostor, &p, 1, 0xAA);
        assert!(matches!(validate(&p, &s), Err(ContractError::Other(_))));
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
        assert!(
            matches!(validate(&p_delegate, &s), Err(ContractError::Other(_))),
            "a record signed for one app_id must not validate under another"
        );
    }

    #[test]
    fn rejects_malformed_state_length() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let mut s = state_bytes(&sk, &p, 1, 0xAA);
        s.push(0);
        assert!(matches!(validate(&p, &s), Err(ContractError::InvalidState)));
        assert!(matches!(
            validate(&p, &[]),
            Err(ContractError::InvalidState)
        ));
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

    #[test]
    fn update_rejects_an_unsigned_or_forged_candidate() {
        let author = key(1);
        let impostor = key(2);
        let p = params_for(&author, APP_ID);
        let current = state_bytes(&author, &p, 1, 0xAA);
        // Higher version, but signed by the wrong key.
        let forged = state_bytes(&impostor, &p, 99, 0xFF);
        assert!(matches!(
            update(&p, &current, forged),
            Err(ContractError::InvalidUpdateWithInfo { .. })
        ));
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
    fn update_with_no_usable_data_is_an_error() {
        let sk = key(1);
        let p = params_for(&sk, APP_ID);
        let current = state_bytes(&sk, &p, 1, 0xAA);
        assert!(matches!(
            PointerContract::update_state(Parameters::from(p), State::from(current), vec![]),
            Err(ContractError::InvalidUpdate)
        ));
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
        assert_eq!(summary.as_ref(), &7u32.to_be_bytes());

        // A peer that is behind gets the whole record back.
        let behind = StateSummary::from(3u32.to_be_bytes().to_vec());
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
            let d = PointerContract::get_state_delta(
                Parameters::from(p.clone()),
                State::from(state.clone()),
                StateSummary::from(v.to_be_bytes().to_vec()),
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
}
