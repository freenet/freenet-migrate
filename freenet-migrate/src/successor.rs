//! Author-signed successor pointer (anti-rollback + forward discovery).
//!
//! Neither River nor Delta ships this today; it is the opt-in richer layer. A
//! release holder signs a pointer to the next generation's code hash. Clients
//! verify it against the app's release public key and only follow it if its
//! generation strictly supersedes the current one.
//!
//! Security note (design §6): the release-signing key is a catastrophic SPOF —
//! whoever holds it can sign a pointer to malicious WASM. Monotonic
//! `generation` bounds *backward* replay only; forward key-compromise is
//! **unmitigated** and must be managed out of band. The only constructor for a
//! signer is [`ReleaseSigner::from_key`], so a pointer cannot be minted without
//! the key.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::MigrateError;

/// The bytes signed by a [`ReleaseSigner`]: `successor_code_hash ‖ generation_le ‖ app_id`.
fn signing_message(successor_code_hash: &[u8; 32], generation: u32, app_id: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 4 + app_id.len());
    m.extend_from_slice(successor_code_hash);
    m.extend_from_slice(&generation.to_le_bytes());
    m.extend_from_slice(app_id);
    m
}

/// An author-signed pointer from one generation to its successor.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessorPointer {
    /// `blake3(successor_wasm)` — the code hash of the generation this points to.
    pub successor_code_hash: [u8; 32],
    /// Monotonic generation of the successor. Must strictly exceed the current
    /// generation for a client to follow the pointer.
    pub generation: u32,
    /// Ed25519 signature over `successor_code_hash ‖ generation_le ‖ app_id`.
    #[serde_as(as = "[_; 64]")]
    pub sig: [u8; 64],
}

impl SuccessorPointer {
    /// Verify the signature against the app's release public key and `app_id`.
    ///
    /// `app_id` binds the pointer to a specific application (e.g. the app's
    /// stable contract instance id bytes or a domain string) so a signature
    /// cannot be replayed across apps sharing a release key.
    pub fn verify(&self, release_pk: &VerifyingKey, app_id: &[u8]) -> Result<(), MigrateError> {
        let msg = signing_message(&self.successor_code_hash, self.generation, app_id);
        let sig = Signature::from_bytes(&self.sig);
        release_pk
            .verify_strict(&msg, &sig)
            .map_err(|_| MigrateError::BadSignature)
    }

    /// Whether this pointer's generation strictly supersedes `current_generation`.
    /// Bounds backward replay only.
    pub fn supersedes(&self, current_generation: u32) -> bool {
        self.generation > current_generation
    }

    /// Verify the signature **and** the anti-rollback ordering in one call.
    pub fn verify_and_check_supersedes(
        &self,
        release_pk: &VerifyingKey,
        app_id: &[u8],
        current_generation: u32,
    ) -> Result<(), MigrateError> {
        self.verify(release_pk, app_id)?;
        if !self.supersedes(current_generation) {
            return Err(MigrateError::StaleGeneration {
                pointer: self.generation,
                current: current_generation,
            });
        }
        Ok(())
    }
}

/// Holds the app's release signing key. The **only** way to mint a
/// [`SuccessorPointer`]; without the key you cannot produce a valid pointer
/// (the "signing identity" precondition).
pub struct ReleaseSigner {
    key: SigningKey,
}

impl ReleaseSigner {
    /// The only constructor: from an Ed25519 signing key.
    pub fn from_key(key: SigningKey) -> Self {
        Self { key }
    }

    /// The corresponding public key, to embed in the app so clients can verify.
    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign a pointer to `successor_code_hash` at `generation`, bound to `app_id`.
    pub fn sign(
        &self,
        successor_code_hash: [u8; 32],
        generation: u32,
        app_id: &[u8],
    ) -> SuccessorPointer {
        let msg = signing_message(&successor_code_hash, generation, app_id);
        let sig: Signature = self.key.sign(&msg);
        SuccessorPointer {
            successor_code_hash,
            generation,
            sig: sig.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MigrateError;

    fn signer(seed: u8) -> ReleaseSigner {
        ReleaseSigner::from_key(SigningKey::from_bytes(&[seed; 32]))
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let s = signer(42);
        let pk = s.public_key();
        let ptr = s.sign([9u8; 32], 5, b"app-1");
        ptr.verify(&pk, b"app-1").expect("valid signature verifies");
    }

    #[test]
    fn verify_rejects_wrong_app_id_wrong_key_and_tamper() {
        let s = signer(42);
        let pk = s.public_key();
        let ptr = s.sign([9u8; 32], 5, b"app-1");

        assert!(matches!(
            ptr.verify(&pk, b"app-2").unwrap_err(),
            MigrateError::BadSignature
        ));
        let other_pk = signer(1).public_key();
        assert!(matches!(
            ptr.verify(&other_pk, b"app-1").unwrap_err(),
            MigrateError::BadSignature
        ));

        let mut tampered = ptr.clone();
        tampered.generation = 6;
        assert!(matches!(
            tampered.verify(&pk, b"app-1").unwrap_err(),
            MigrateError::BadSignature
        ));

        let mut tampered_hash = ptr.clone();
        tampered_hash.successor_code_hash = [1u8; 32];
        assert!(matches!(
            tampered_hash.verify(&pk, b"app-1").unwrap_err(),
            MigrateError::BadSignature
        ));
    }

    #[test]
    fn supersedes_is_strictly_monotonic() {
        let ptr = signer(7).sign([0u8; 32], 5, b"a");
        assert!(ptr.supersedes(4));
        assert!(!ptr.supersedes(5));
        assert!(!ptr.supersedes(6));
    }

    #[test]
    fn verify_and_check_supersedes_enforces_ordering() {
        let s = signer(7);
        let pk = s.public_key();
        let ptr = s.sign([0u8; 32], 5, b"a");

        ptr.verify_and_check_supersedes(&pk, b"a", 4).unwrap();
        let err = ptr.verify_and_check_supersedes(&pk, b"a", 5).unwrap_err();
        assert!(matches!(
            err,
            MigrateError::StaleGeneration {
                pointer: 5,
                current: 5
            }
        ));
    }

    #[test]
    fn serde_roundtrip_preserves_the_64_byte_signature() {
        let ptr = signer(3).sign([255u8; 32], 9, b"round-trip");
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&ptr, &mut bytes).unwrap();
        let back: SuccessorPointer = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, ptr);
        // and the recovered pointer still verifies
        back.verify(&signer(3).public_key(), b"round-trip").unwrap();
    }
}
