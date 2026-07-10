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
    /// [`crate::delegate::OriginPolicy`]. Also returned (fail-closed) when the
    /// runtime supplied no origin at all (`origin: None`).
    UnauthorizedOrigin,
    /// The host's per-scope key enumeration was truncated at its cap
    /// (freenet-core `MAX_REGISTERED_KEYS_PER_SCOPE`), so an export over the
    /// whole scope could silently omit keys. Refused rather than exported —
    /// exporting a truncated set and then writing the completion marker would
    /// permanently block a corrected re-import. See
    /// [`crate::delegate::HOST_ENUMERATION_CAP`].
    TruncatedExport {
        /// Number of keys the host returned (>= `cap`).
        returned: usize,
        /// The host enumeration cap that was hit.
        cap: usize,
    },
    /// A secret import did not fully complete: at least one `set_secret` write
    /// failed (or the completion marker could not be written). The completion
    /// marker was deliberately NOT written, so the migration is left in its
    /// in-progress state and a retry re-runs it. Never counts a failed write as
    /// imported (the bug this replaced silently lost the secret).
    PartialImport {
        /// Generation being imported from.
        generation: u32,
        /// Secrets successfully written on this attempt.
        imported: usize,
        /// Secrets skipped because the successor already held that key.
        skipped: usize,
        /// Secrets whose write failed.
        failed: usize,
    },
    /// An [`crate::delegate::ExportedSecrets`] carried a `source_generation`
    /// that is not a plausible predecessor of the importing successor (>= the
    /// successor's own generation). `source_generation` is echoed from the
    /// (unauthenticated) request, so bounding it stops an injected export from
    /// stamping a completion marker for an implausibly-high generation and
    /// thereby blocking every real future migration via the monotonicity guard.
    ImplausibleGeneration {
        /// The generation the export claimed to be migrating from.
        source: u32,
        /// The successor's own generation (the exclusive upper bound).
        ceiling: u32,
    },
    /// A [`crate::SuccessorPointer`] was signed or verified with an empty
    /// `app_id`. Refused fail-closed: an empty binding lets a signature be
    /// replayed across apps that share a release key.
    EmptyAppId,
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
            MigrateError::TruncatedExport { returned, cap } => write!(
                f,
                "secret enumeration truncated at host cap ({returned} keys returned, cap {cap}); \
                 refusing to export a possibly-incomplete secret set"
            ),
            MigrateError::PartialImport {
                generation,
                imported,
                skipped,
                failed,
            } => write!(
                f,
                "secret import from generation {generation} did not complete \
                 (imported {imported}, skipped {skipped}, failed {failed}); \
                 completion marker withheld so a retry re-runs the import"
            ),
            MigrateError::ImplausibleGeneration { source, ceiling } => write!(
                f,
                "exported source_generation {source} is not a plausible predecessor \
                 (must be < successor generation {ceiling})"
            ),
            MigrateError::EmptyAppId => {
                write!(f, "successor pointer app_id must not be empty")
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
