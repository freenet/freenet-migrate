//! Build-time error type.

use core::fmt;

/// Errors from parsing the registry, codegen, or the CI guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The registry TOML failed to parse.
    Toml(String),
    /// An I/O error reading the registry or writing the generated file.
    Io(String),
    /// A required environment variable (e.g. `OUT_DIR`) was not set.
    Env(String),
    /// No registry path was configured before `emit`/`generate_string`.
    NoRegistry,
    /// A `code_hash` / `delegate_key` was neither 64 hex chars nor base58 for
    /// exactly 32 bytes.
    InvalidCodeHash {
        /// The offending string.
        value: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A `params_hex` field was not valid hex.
    InvalidParams {
        /// The offending string.
        value: String,
        /// Why it was rejected.
        reason: String,
    },
    /// Two rows in a component share a generation number.
    DuplicateGeneration {
        /// "contract" or "delegate".
        component: &'static str,
        /// The repeated generation.
        generation: u32,
    },
    /// Two rows in a component share a code hash.
    DuplicateCodeHash {
        /// "contract" or "delegate".
        component: &'static str,
        /// The repeated code hash, as written in the registry.
        code_hash: String,
    },
    /// A delegate row's stored `delegate_key` does not equal
    /// `blake3(code_hash ‖ params)` and the row is not marked
    /// `irregular_key = true`.
    DelegateKeyMismatch {
        /// The failing row's generation.
        generation: u32,
        /// The derived key (base58) the row was expected to store.
        expected: String,
        /// The key actually stored, as written in the registry.
        found: String,
    },
    /// An `[[entry]]`-format registry did not match the requested component
    /// (e.g. a contract import found `delegate_key` fields, or a delegate
    /// import was missing them).
    EntrySchema(String),
    /// Codegen was configured to emit nothing (canonical consts disabled and
    /// no views requested).
    NothingToEmit,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Toml(e) => write!(f, "failed to parse registry TOML: {e}"),
            BuildError::Io(e) => write!(f, "I/O error: {e}"),
            BuildError::Env(e) => write!(f, "environment error: {e}"),
            BuildError::NoRegistry => {
                write!(f, "no registry path configured; call .registry(path)")
            }
            BuildError::InvalidCodeHash { value, reason } => {
                write!(f, "invalid code hash {value:?}: {reason}")
            }
            BuildError::InvalidParams { value, reason } => {
                write!(f, "invalid params_hex {value:?}: {reason}")
            }
            BuildError::DuplicateGeneration {
                component,
                generation,
            } => write!(f, "duplicate {component} generation {generation}"),
            BuildError::DuplicateCodeHash {
                component,
                code_hash,
            } => write!(f, "duplicate {component} code hash {code_hash:?}"),
            BuildError::DelegateKeyMismatch {
                generation,
                expected,
                found,
            } => write!(
                f,
                "delegate generation {generation}: stored delegate_key {found:?} != \
                 blake3(code_hash ‖ params) = {expected}; fix the row, or if this is a \
                 grandfathered pre-standard key set `irregular_key = true` on it"
            ),
            BuildError::EntrySchema(e) => write!(f, "[[entry]] registry schema error: {e}"),
            BuildError::NothingToEmit => write!(
                f,
                "codegen configured to emit nothing: canonical consts are disabled and no \
                 view consts were requested"
            ),
        }
    }
}

impl std::error::Error for BuildError {}
