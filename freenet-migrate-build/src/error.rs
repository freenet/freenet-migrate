//! Build-time error type.

use core::fmt;

/// Errors from parsing the registry, codegen, or the CI guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The `legacy.toml` failed to parse.
    Toml(String),
    /// An I/O error reading the registry or writing the generated file.
    Io(String),
    /// A required environment variable (e.g. `OUT_DIR`) was not set.
    Env(String),
    /// No registry path was configured before `emit`/`generate_string`.
    NoRegistry,
    /// A `code_hash` / `delegate_key` was not valid base58 for exactly 32 bytes.
    InvalidCodeHash {
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
        /// The repeated (base58) code hash.
        code_hash: String,
    },
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
            BuildError::DuplicateGeneration {
                component,
                generation,
            } => write!(f, "duplicate {component} generation {generation}"),
            BuildError::DuplicateCodeHash {
                component,
                code_hash,
            } => write!(f, "duplicate {component} code hash {code_hash:?}"),
        }
    }
}

impl std::error::Error for BuildError {}
