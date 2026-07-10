//! Error type for the migration machinery.

use core::fmt;

/// Errors produced by the migration APIs.
///
/// `#[non_exhaustive]` so future variants (e.g. Horizon-B node-mediated
/// transports) can be added without a source-level break; downstream `match`
/// sites must carry a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateError {
    /// `ComposableState::merge` rejected the predecessor fold. Carries the
    /// scaffold error string.
    Merge(String),
    /// `ComposableState::verify` rejected the merged state. This is the
    /// fail-closed self-authorizing gate: a merge that produces state the
    /// successor's own validator would reject is refused rather than carried
    /// forward.
    Verify(String),
    /// A base58 code hash / delegate key in the lineage registry could not be
    /// decoded to 32 bytes.
    BadCodeHash(String),
    /// An author-signed successor pointer failed Ed25519 verification.
    BadSignature,
    /// The successor pointer's generation does not supersede the current one
    /// (anti-rollback).
    StaleGeneration {
        /// Generation carried by the pointer.
        pointer: u32,
        /// Generation currently in effect.
        current: u32,
    },
    /// The requesting origin is not authorized by the configured
    /// [`crate::delegate::OriginPolicy`].
    UnauthorizedOrigin,
    /// The secret transport could not produce the predecessor's secrets.
    /// [`crate::delegate::ReRunOldWasm`] returns this today (see its docs).
    TransportUnavailable(String),
    /// Hosted per-user (user-scope) secrets cannot be migrated at rest, because
    /// the node cannot decrypt them without the user's live token (design §2.3
    /// / §4). Surfaced rather than papered over.
    UserScopeNotAtRest,
    /// A serialized payload could not be encoded/decoded.
    Codec(String),
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrateError::Merge(e) => write!(f, "predecessor merge failed: {e}"),
            MigrateError::Verify(e) => {
                write!(f, "verify() rejected the merged state (fail-closed): {e}")
            }
            MigrateError::BadCodeHash(e) => write!(f, "invalid code hash in lineage: {e}"),
            MigrateError::BadSignature => write!(f, "successor pointer signature is invalid"),
            MigrateError::StaleGeneration { pointer, current } => write!(
                f,
                "successor pointer generation {pointer} does not supersede current {current}"
            ),
            MigrateError::UnauthorizedOrigin => {
                write!(f, "export request origin is not authorized by policy")
            }
            MigrateError::TransportUnavailable(e) => {
                write!(f, "secret transport unavailable: {e}")
            }
            MigrateError::UserScopeNotAtRest => write!(
                f,
                "hosted per-user secrets cannot be migrated at rest (only while the user is online)"
            ),
            MigrateError::Codec(e) => write!(f, "payload codec error: {e}"),
        }
    }
}

impl std::error::Error for MigrateError {}
