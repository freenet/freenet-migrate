//! The unified `legacy.toml` registry — a superset of River's two TOMLs and
//! Delta's two, with one `[[contract]]` / `[[delegate]]` schema.
//!
//! ```toml
//! [[contract]]
//! generation = 0
//! code_hash  = "9xH..."          # base58 blake3(wasm), matches stdlib CodeHash::encode()
//! note       = "v1 room contract (stdlib 0.6.1)"
//!
//! [[delegate]]
//! generation = 0
//! code_hash    = "Def..."
//! delegate_key = "Ghi..."        # base58 blake3(code_hash ‖ params)
//! note         = "v1 chat delegate"
//! ```
//!
//! Only **predecessor** generations are listed; the currently-live generation's
//! hash is derived at runtime from the bundled WASM.
//!
//! Note on encoding: River/Delta store lowercase hex today; this crate's
//! canonical form is **base58** (stdlib's own string form). Adoption converts
//! hex → base58 as part of moving to the crate.

use serde::Deserialize;

use crate::error::BuildError;

/// A parsed registry.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Registry {
    /// Contract predecessor generations.
    #[serde(default)]
    pub contract: Vec<ContractRow>,
    /// Delegate predecessor generations.
    #[serde(default)]
    pub delegate: Vec<DelegateRow>,
}

/// A `[[contract]]` row.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ContractRow {
    /// Monotonic generation (older = smaller).
    pub generation: u32,
    /// Base58 blake3(wasm) code hash.
    pub code_hash: String,
    /// Human note.
    #[serde(default)]
    pub note: String,
}

/// A `[[delegate]]` row.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DelegateRow {
    /// Monotonic generation (older = smaller).
    pub generation: u32,
    /// Base58 blake3(wasm) code hash.
    pub code_hash: String,
    /// Base58 full delegate key blake3(code_hash ‖ params).
    pub delegate_key: String,
    /// Human note.
    #[serde(default)]
    pub note: String,
}

impl Registry {
    /// Parse a registry from TOML text.
    pub fn from_toml_str(s: &str) -> Result<Self, BuildError> {
        toml::from_str(s).map_err(|e| BuildError::Toml(e.to_string()))
    }

    /// Read and parse a registry from a file.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, BuildError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| BuildError::Io(format!("reading {}: {e}", path.as_ref().display())))?;
        Self::from_toml_str(&text)
    }

    /// Validate encodings and uniqueness. Returns `Ok(())` for an empty registry
    /// (a fresh app with no predecessors yet).
    pub fn validate(&self) -> Result<(), BuildError> {
        validate_rows(
            "contract",
            self.contract
                .iter()
                .map(|r| (r.generation, r.code_hash.as_str())),
            std::iter::empty(),
        )?;
        validate_rows(
            "delegate",
            self.delegate
                .iter()
                .map(|r| (r.generation, r.code_hash.as_str())),
            self.delegate.iter().map(|r| r.delegate_key.as_str()),
        )
    }

    /// The generation of the (contract) predecessor whose base58 code hash
    /// equals `code_hash_b58`, if present.
    pub fn find_contract_code_hash(&self, code_hash_b58: &str) -> Option<u32> {
        self.contract
            .iter()
            .find(|r| r.code_hash == code_hash_b58)
            .map(|r| r.generation)
    }

    /// The generation of the (delegate) predecessor whose base58 code hash
    /// equals `code_hash_b58`, if present.
    pub fn find_delegate_code_hash(&self, code_hash_b58: &str) -> Option<u32> {
        self.delegate
            .iter()
            .find(|r| r.code_hash == code_hash_b58)
            .map(|r| r.generation)
    }
}

/// Decode a base58 (Bitcoin alphabet) string, requiring exactly 32 bytes.
fn require_b58_32(value: &str) -> Result<(), BuildError> {
    let mut out = [0u8; 32];
    let n = bs58::decode(value)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut out)
        .map_err(|e| BuildError::InvalidCodeHash {
            value: value.to_string(),
            reason: e.to_string(),
        })?;
    if n != 32 {
        return Err(BuildError::InvalidCodeHash {
            value: value.to_string(),
            reason: format!("decoded {n} bytes, expected 32"),
        });
    }
    Ok(())
}

fn validate_rows<'a>(
    component: &'static str,
    gens_and_hashes: impl Iterator<Item = (u32, &'a str)>,
    delegate_keys: impl Iterator<Item = &'a str>,
) -> Result<(), BuildError> {
    let mut seen_gen = std::collections::HashSet::new();
    let mut seen_hash = std::collections::HashSet::new();
    for (generation, code_hash) in gens_and_hashes {
        require_b58_32(code_hash)?;
        if !seen_gen.insert(generation) {
            return Err(BuildError::DuplicateGeneration {
                component,
                generation,
            });
        }
        if !seen_hash.insert(code_hash.to_string()) {
            return Err(BuildError::DuplicateCodeHash {
                component,
                code_hash: code_hash.to_string(),
            });
        }
    }
    for key in delegate_keys {
        require_b58_32(key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b58(b: [u8; 32]) -> String {
        bs58::encode(b)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string()
    }

    fn sample() -> (String, Registry) {
        let ch0 = b58([1; 32]);
        let ch1 = b58([2; 32]);
        let dch0 = b58([4; 32]);
        let dk0 = b58([3; 32]);
        let toml = format!(
            r#"
[[contract]]
generation = 0
code_hash = "{ch0}"
note = "v1 room contract"

[[contract]]
generation = 1
code_hash = "{ch1}"

[[delegate]]
generation = 0
code_hash = "{dch0}"
delegate_key = "{dk0}"
note = "v1 delegate"
"#
        );
        let reg = Registry::from_toml_str(&toml).unwrap();
        (toml, reg)
    }

    #[test]
    fn parses_unified_schema_and_optional_note() {
        let (_t, reg) = sample();
        assert_eq!(reg.contract.len(), 2);
        assert_eq!(reg.delegate.len(), 1);
        assert_eq!(reg.contract[0].generation, 0);
        assert_eq!(reg.contract[0].note, "v1 room contract");
        assert_eq!(reg.contract[1].note, ""); // omitted -> default
        assert_eq!(reg.delegate[0].delegate_key, b58([3; 32]));
        reg.validate().unwrap();
    }

    #[test]
    fn lookups_return_generation() {
        let (_t, reg) = sample();
        assert_eq!(reg.find_contract_code_hash(&b58([2; 32])), Some(1));
        assert_eq!(reg.find_delegate_code_hash(&b58([4; 32])), Some(0));
        assert_eq!(reg.find_contract_code_hash("not-present"), None);
    }

    #[test]
    fn empty_registry_is_valid() {
        Registry::default().validate().unwrap();
        Registry::from_toml_str("").unwrap().validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_generation() {
        let ch0 = b58([1; 32]);
        let ch1 = b58([2; 32]);
        let toml = format!(
            "[[contract]]\ngeneration = 0\ncode_hash = \"{ch0}\"\n\
             [[contract]]\ngeneration = 0\ncode_hash = \"{ch1}\"\n"
        );
        let err = Registry::from_toml_str(&toml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(
            err,
            BuildError::DuplicateGeneration {
                component: "contract",
                generation: 0
            }
        ));
    }

    #[test]
    fn rejects_duplicate_code_hash() {
        let ch = b58([1; 32]);
        let toml = format!(
            "[[contract]]\ngeneration = 0\ncode_hash = \"{ch}\"\n\
             [[contract]]\ngeneration = 1\ncode_hash = \"{ch}\"\n"
        );
        let err = Registry::from_toml_str(&toml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(
            err,
            BuildError::DuplicateCodeHash {
                component: "contract",
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_code_hash() {
        // Valid base58 but too short.
        let toml = "[[contract]]\ngeneration = 0\ncode_hash = \"abc\"\n";
        let err = Registry::from_toml_str(toml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(err, BuildError::InvalidCodeHash { .. }));
    }

    #[test]
    fn rejects_invalid_delegate_key() {
        let ch = b58([1; 32]);
        let toml = format!(
            "[[delegate]]\ngeneration = 0\ncode_hash = \"{ch}\"\ndelegate_key = \"0OIl\"\n"
        );
        let err = Registry::from_toml_str(&toml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(err, BuildError::InvalidCodeHash { .. }));
    }
}
