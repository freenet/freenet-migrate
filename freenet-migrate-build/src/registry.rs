//! The unified `legacy.toml` registry — a superset of River's two TOMLs and
//! Delta's two, with one `[[contract]]` / `[[delegate]]` schema.
//!
//! ```toml
//! [[contract]]
//! generation = 0
//! code_hash  = "9xH..."          # blake3(wasm): base58 (stdlib CodeHash::encode()) or 64-char hex
//! note       = "v1 room contract (stdlib 0.6.1)"
//!
//! [[delegate]]
//! generation = 0
//! code_hash    = "Def..."
//! delegate_key = "Ghi..."        # blake3(code_hash ‖ params); base58 or hex
//! note         = "v1 chat delegate"
//! ```
//!
//! Only **predecessor** generations are listed; the currently-live generation's
//! hash is derived at runtime from the bundled WASM.
//!
//! # Hash encodings: hex and base58 both accepted
//!
//! River and Delta store lowercase hex (what `b3sum` prints); stdlib's own
//! string form is base58. Both are accepted everywhere a hash appears, decoded
//! **at build time** to the canonical `[u8; 32]`: a 64-char all-hex string is
//! hex, anything else must be base58 (Bitcoin alphabet) decoding to exactly 32
//! bytes. The two cannot collide: 32 bytes in base58 is 43–44 chars, never 64.
//!
//! # The delegate-key cross-check
//!
//! `validate()` re-derives each delegate row's key as
//! `blake3(code_hash ‖ params)` (params from the optional `params_hex` field,
//! default empty — the River/Delta case) and requires it to equal the stored
//! `delegate_key`. This restores at build time the compile check Delta's
//! hand-rolled `build.rs` had, so a typo'd or wrongly-derived key (the Feb 2026
//! SHA256-instead-of-BLAKE3 incident class) cannot enter a registry.
//!
//! Grandfathered rows whose *recorded* key predates the standard derivation
//! (River's V1/V2) set `irregular_key = true`: the recorded key is trusted
//! as-is — it is the key the old delegate actually had on the network, which is
//! what a migration probe must target. Never set the flag on new rows; a row
//! marked irregular whose key *does* derive correctly is rejected so stale
//! flags cannot rot in place.
//!
//! # Importing River-style `[[entry]]` registries
//!
//! Existing apps keep their `legacy_delegates.toml` / `legacy_room_contracts.toml`
//! files unchanged: [`Registry::from_entry_path`] parses the `[[entry]]` schema
//! (`version` / `description` / `date` / `code_hash` [/ `delegate_key`]) into
//! the unified shape, deriving `generation` from `V<n>` version strings and
//! folding the metadata into `note`.

use serde::Deserialize;

use crate::error::BuildError;

/// Which registry component a guard / lookup / import targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// The `[[contract]]` list.
    Contract,
    /// The `[[delegate]]` list.
    Delegate,
}

impl Component {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Component::Contract => "contract",
            Component::Delegate => "delegate",
        }
    }
}

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
    /// `blake3(wasm)` code hash — base58 or 64-char hex, as written.
    pub code_hash: String,
    /// Human note.
    #[serde(default)]
    pub note: String,
}

impl ContractRow {
    /// The decoded 32-byte code hash.
    pub fn code_hash_bytes(&self) -> Result<[u8; 32], BuildError> {
        decode_hash32(&self.code_hash)
    }
}

/// A `[[delegate]]` row.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DelegateRow {
    /// Monotonic generation (older = smaller).
    pub generation: u32,
    /// `blake3(wasm)` code hash — base58 or 64-char hex, as written.
    pub code_hash: String,
    /// The full delegate key `blake3(code_hash ‖ params)` — base58 or hex.
    /// Stored explicitly because this is the key the old delegate actually had
    /// on the network (the address a migration probe targets).
    pub delegate_key: String,
    /// Hex of the delegate's parameters, if non-empty. Default: empty params
    /// (the River/Delta case), i.e. `delegate_key = blake3(code_hash)`.
    #[serde(default)]
    pub params_hex: String,
    /// Trust the recorded `delegate_key` as-is instead of requiring it to equal
    /// the derived `blake3(code_hash ‖ params)`. Only for grandfathered rows
    /// that predate the standard derivation (e.g. River V1/V2). Never set this
    /// on new rows.
    #[serde(default)]
    pub irregular_key: bool,
    /// Human note.
    #[serde(default)]
    pub note: String,
}

impl DelegateRow {
    /// The decoded 32-byte code hash.
    pub fn code_hash_bytes(&self) -> Result<[u8; 32], BuildError> {
        decode_hash32(&self.code_hash)
    }

    /// The decoded 32-byte delegate key.
    pub fn delegate_key_bytes(&self) -> Result<[u8; 32], BuildError> {
        decode_hash32(&self.delegate_key)
    }

    /// The decoded delegate parameters (empty for the default empty
    /// `params_hex`).
    pub fn params_bytes(&self) -> Result<Vec<u8>, BuildError> {
        decode_hex(&self.params_hex).map_err(|reason| BuildError::InvalidParams {
            value: self.params_hex.clone(),
            reason,
        })
    }
}

/// The `[[entry]]` row shape used by River's existing registries.
#[derive(Debug, Clone, Deserialize)]
struct EntryRow {
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    date: String,
    code_hash: String,
    #[serde(default)]
    delegate_key: Option<String>,
    #[serde(default)]
    params_hex: String,
    #[serde(default)]
    irregular_key: bool,
}

#[derive(Debug, Default, Deserialize)]
struct EntryFile {
    #[serde(default)]
    entry: Vec<EntryRow>,
}

impl Registry {
    /// Parse a unified-schema registry from TOML text.
    pub fn from_toml_str(s: &str) -> Result<Self, BuildError> {
        toml::from_str(s).map_err(|e| BuildError::Toml(e.to_string()))
    }

    /// Read and parse a unified-schema registry from a file.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, BuildError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| BuildError::Io(format!("reading {}: {e}", path.as_ref().display())))?;
        Self::from_toml_str(&text)
    }

    /// Parse a River-style `[[entry]]` registry (fields `version` /
    /// `description` / `date` / `code_hash` [/ `delegate_key`]) into the
    /// unified shape, populating only the requested `component`.
    ///
    /// * `generation`: if **every** entry's `version` matches `V<n>` (e.g.
    ///   `"V7"` → 7), the numbers are used directly — this preserves sparse
    ///   histories like River's removed V4–V6. Otherwise generations are
    ///   assigned sequentially from 0 in file order.
    /// * `note`: `"{version}: {description} ({date})"`, omitting empty parts.
    /// * A [`Component::Contract`] import rejects entries carrying
    ///   `delegate_key`; a [`Component::Delegate`] import requires it.
    /// * Entries may carry `params_hex` / `irregular_key`, forwarded verbatim
    ///   (see the module docs on the delegate-key cross-check).
    pub fn from_entry_toml_str(s: &str, component: Component) -> Result<Self, BuildError> {
        let file: EntryFile = toml::from_str(s).map_err(|e| BuildError::Toml(e.to_string()))?;
        let generations = entry_generations(&file.entry);

        let mut registry = Registry::default();
        for (row, generation) in file.entry.iter().zip(generations) {
            let note = entry_note(row);
            match component {
                Component::Contract => {
                    if let Some(dk) = &row.delegate_key {
                        return Err(BuildError::EntrySchema(format!(
                            "entry {:?} has delegate_key {dk:?} but was imported as a \
                             contract registry",
                            row.version
                        )));
                    }
                    registry.contract.push(ContractRow {
                        generation,
                        code_hash: row.code_hash.clone(),
                        note,
                    });
                }
                Component::Delegate => {
                    let delegate_key = row.delegate_key.clone().ok_or_else(|| {
                        BuildError::EntrySchema(format!(
                            "entry {:?} is missing delegate_key but was imported as a \
                             delegate registry",
                            row.version
                        ))
                    })?;
                    registry.delegate.push(DelegateRow {
                        generation,
                        code_hash: row.code_hash.clone(),
                        delegate_key,
                        params_hex: row.params_hex.clone(),
                        irregular_key: row.irregular_key,
                        note,
                    });
                }
            }
        }
        Ok(registry)
    }

    /// Read and parse a River-style `[[entry]]` registry from a file. See
    /// [`Registry::from_entry_toml_str`].
    pub fn from_entry_path(
        path: impl AsRef<std::path::Path>,
        component: Component,
    ) -> Result<Self, BuildError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| BuildError::Io(format!("reading {}: {e}", path.as_ref().display())))?;
        Self::from_entry_toml_str(&text, component)
    }

    /// Validate encodings, uniqueness, and the delegate-key derivation
    /// cross-check. Returns `Ok(())` for an empty registry (a fresh app with no
    /// predecessors yet).
    pub fn validate(&self) -> Result<(), BuildError> {
        validate_unique(
            "contract",
            self.contract
                .iter()
                .map(|r| (r.generation, r.code_hash.as_str())),
        )?;
        validate_unique(
            "delegate",
            self.delegate
                .iter()
                .map(|r| (r.generation, r.code_hash.as_str())),
        )?;
        for row in &self.delegate {
            let code_hash = row.code_hash_bytes()?;
            let delegate_key = row.delegate_key_bytes()?;
            let params = row.params_bytes()?;
            let derived = derive_delegate_key(&code_hash, &params);
            let matches = derived == delegate_key;
            if row.irregular_key && matches {
                // A stale flag is as much a data error as a wrong key: the row
                // claims a pre-standard derivation it doesn't have.
                return Err(BuildError::DelegateKeyMismatch {
                    generation: row.generation,
                    expected: "the stored key itself — it derives correctly, so remove \
                               `irregular_key = true`"
                        .to_string(),
                    found: row.delegate_key.clone(),
                });
            }
            if !row.irregular_key && !matches {
                return Err(BuildError::DelegateKeyMismatch {
                    generation: row.generation,
                    expected: b58(&derived),
                    found: row.delegate_key.clone(),
                });
            }
        }
        Ok(())
    }

    /// The generation of the (contract) predecessor whose code hash equals
    /// `code_hash` (hex or base58), if present. Returns `None` for an
    /// undecodable argument.
    pub fn find_contract_code_hash(&self, code_hash: &str) -> Option<u32> {
        let wanted = decode_hash32(code_hash).ok()?;
        self.find_contract_code_hash_bytes(&wanted)
    }

    /// The generation of the (contract) predecessor with this decoded code
    /// hash, if present.
    pub fn find_contract_code_hash_bytes(&self, code_hash: &[u8; 32]) -> Option<u32> {
        self.contract
            .iter()
            .find(|r| r.code_hash_bytes().is_ok_and(|b| b == *code_hash))
            .map(|r| r.generation)
    }

    /// The generation of the (delegate) predecessor whose code hash equals
    /// `code_hash` (hex or base58), if present. Returns `None` for an
    /// undecodable argument.
    pub fn find_delegate_code_hash(&self, code_hash: &str) -> Option<u32> {
        let wanted = decode_hash32(code_hash).ok()?;
        self.find_delegate_code_hash_bytes(&wanted)
    }

    /// The generation of the (delegate) predecessor with this decoded code
    /// hash, if present.
    pub fn find_delegate_code_hash_bytes(&self, code_hash: &[u8; 32]) -> Option<u32> {
        self.delegate
            .iter()
            .find(|r| r.code_hash_bytes().is_ok_and(|b| b == *code_hash))
            .map(|r| r.generation)
    }
}

/// Derive generations for an `[[entry]]` import: `V<n>` numbers if uniform,
/// else sequential file order.
fn entry_generations(rows: &[EntryRow]) -> Vec<u32> {
    let parsed: Option<Vec<u32>> = rows.iter().map(|r| parse_v_number(&r.version)).collect();
    parsed.unwrap_or_else(|| (0..rows.len() as u32).collect())
}

fn parse_v_number(version: &str) -> Option<u32> {
    let rest = version
        .strip_prefix('V')
        .or_else(|| version.strip_prefix('v'))?;
    rest.parse().ok()
}

fn entry_note(row: &EntryRow) -> String {
    let mut note = row.version.clone();
    if !row.description.is_empty() {
        note.push_str(": ");
        note.push_str(&row.description);
    }
    if !row.date.is_empty() {
        note.push_str(&format!(" ({})", row.date));
    }
    note
}

/// The standard delegate-key derivation: `blake3(code_hash ‖ params)`.
pub(crate) fn derive_delegate_key(code_hash: &[u8; 32], params: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(code_hash);
    hasher.update(params);
    *hasher.finalize().as_bytes()
}

/// Decode a hash string into exactly 32 bytes, accepting 64-char hex or base58
/// (Bitcoin alphabet). See the module docs for the (collision-free)
/// disambiguation rule.
pub fn decode_hash32(value: &str) -> Result<[u8; 32], BuildError> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| {
                BuildError::InvalidCodeHash {
                    value: value.to_string(),
                    reason: e.to_string(),
                }
            })?;
        }
        return Ok(out);
    }
    let mut out = [0u8; 32];
    let n = bs58::decode(value)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .onto(&mut out)
        .map_err(|e| BuildError::InvalidCodeHash {
            value: value.to_string(),
            reason: format!("not 64-char hex, and not base58: {e}"),
        })?;
    if n != 32 {
        return Err(BuildError::InvalidCodeHash {
            value: value.to_string(),
            reason: format!("base58 decoded {n} bytes, expected 32"),
        });
    }
    Ok(out)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("odd length {}", value.len()));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub(crate) fn b58(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

fn validate_unique<'a>(
    component: &'static str,
    gens_and_hashes: impl Iterator<Item = (u32, &'a str)>,
) -> Result<(), BuildError> {
    let mut seen_gen = std::collections::HashSet::new();
    let mut seen_hash = std::collections::HashSet::new();
    for (generation, code_hash) in gens_and_hashes {
        let decoded = decode_hash32(code_hash)?;
        if !seen_gen.insert(generation) {
            return Err(BuildError::DuplicateGeneration {
                component,
                generation,
            });
        }
        // Compare decoded bytes so the same hash written once as hex and once
        // as base58 is still caught.
        if !seen_hash.insert(decoded) {
            return Err(BuildError::DuplicateCodeHash {
                component,
                code_hash: code_hash.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b58s(b: [u8; 32]) -> String {
        b58(&b)
    }

    fn hex(b: [u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A delegate (code_hash, delegate_key) pair satisfying the standard
    /// derivation with empty params.
    fn regular_delegate_pair(code: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        (code, derive_delegate_key(&code, &[]))
    }

    fn sample() -> (String, Registry) {
        let ch0 = b58s([1; 32]);
        let ch1 = b58s([2; 32]);
        let (dch0, dk0) = regular_delegate_pair([4; 32]);
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
code_hash = "{}"
delegate_key = "{}"
note = "v1 delegate"
"#,
            b58s(dch0),
            b58s(dk0),
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
        reg.validate().unwrap();
    }

    #[test]
    fn hex_and_base58_hashes_both_decode() {
        let bytes = [7u8; 32];
        assert_eq!(decode_hash32(&hex(bytes)).unwrap(), bytes);
        assert_eq!(decode_hash32(&b58s(bytes)).unwrap(), bytes);
        // Uppercase hex too (b3sum prints lowercase, but be liberal).
        assert_eq!(decode_hash32(&hex(bytes).to_uppercase()).unwrap(), bytes);
    }

    #[test]
    fn hex_registry_validates_and_matches_base58_lookup() {
        let (ch, dk) = regular_delegate_pair([9u8; 32]);
        let toml = format!(
            "[[delegate]]\ngeneration = 3\ncode_hash = \"{}\"\ndelegate_key = \"{}\"\n",
            hex(ch),
            hex(dk),
        );
        let reg = Registry::from_toml_str(&toml).unwrap();
        reg.validate().unwrap();
        // A base58 query finds the hex-stored row.
        assert_eq!(reg.find_delegate_code_hash(&b58s(ch)), Some(3));
        assert_eq!(reg.find_delegate_code_hash_bytes(&ch), Some(3));
    }

    #[test]
    fn lookups_return_generation() {
        let (_t, reg) = sample();
        assert_eq!(reg.find_contract_code_hash(&b58s([2; 32])), Some(1));
        assert_eq!(reg.find_delegate_code_hash(&b58s([4; 32])), Some(0));
        assert_eq!(reg.find_contract_code_hash("not-present"), None);
    }

    #[test]
    fn empty_registry_is_valid() {
        Registry::default().validate().unwrap();
        Registry::from_toml_str("").unwrap().validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_generation() {
        let ch0 = b58s([1; 32]);
        let ch1 = b58s([2; 32]);
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
    fn rejects_duplicate_code_hash_across_encodings() {
        // Same hash, written once as base58 and once as hex — still a dup.
        let toml = format!(
            "[[contract]]\ngeneration = 0\ncode_hash = \"{}\"\n\
             [[contract]]\ngeneration = 1\ncode_hash = \"{}\"\n",
            b58s([1; 32]),
            hex([1; 32]),
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
        let (ch, _dk) = regular_delegate_pair([1; 32]);
        let toml = format!(
            "[[delegate]]\ngeneration = 0\ncode_hash = \"{}\"\ndelegate_key = \"0OIl\"\n",
            b58s(ch)
        );
        let err = Registry::from_toml_str(&toml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(err, BuildError::InvalidCodeHash { .. }));
    }

    #[test]
    fn delegate_key_cross_check_rejects_wrong_key() {
        // A delegate_key that is NOT blake3(code_hash ‖ params) must be caught
        // at build time (the Feb 2026 wrong-derivation incident class).
        let toml = format!(
            "[[delegate]]\ngeneration = 0\ncode_hash = \"{}\"\ndelegate_key = \"{}\"\n",
            b58s([1; 32]),
            b58s([2; 32]), // wrong: not the derived key
        );
        let err = Registry::from_toml_str(&toml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(
            matches!(err, BuildError::DelegateKeyMismatch { generation: 0, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn delegate_key_cross_check_honors_params() {
        let code = [5u8; 32];
        let params = b"delegate params";
        let dk = derive_delegate_key(&code, params);
        let params_hex: String = params.iter().map(|b| format!("{b:02x}")).collect();
        let toml = format!(
            "[[delegate]]\ngeneration = 0\ncode_hash = \"{}\"\ndelegate_key = \"{}\"\n\
             params_hex = \"{params_hex}\"\n",
            b58s(code),
            b58s(dk),
        );
        Registry::from_toml_str(&toml).unwrap().validate().unwrap();
    }

    #[test]
    fn irregular_key_opt_out_trusts_recorded_key() {
        // River V1/V2 class: recorded key predates the standard derivation.
        let toml = format!(
            "[[delegate]]\ngeneration = 1\ncode_hash = \"{}\"\ndelegate_key = \"{}\"\n\
             irregular_key = true\n",
            b58s([1; 32]),
            b58s([2; 32]), // does not derive from code_hash — trusted as-is
        );
        Registry::from_toml_str(&toml).unwrap().validate().unwrap();
    }

    #[test]
    fn stale_irregular_flag_is_rejected() {
        // A row marked irregular whose key actually derives correctly is a
        // data error (the flag should be removed).
        let (ch, dk) = regular_delegate_pair([6; 32]);
        let toml = format!(
            "[[delegate]]\ngeneration = 0\ncode_hash = \"{}\"\ndelegate_key = \"{}\"\n\
             irregular_key = true\n",
            b58s(ch),
            b58s(dk),
        );
        let err = Registry::from_toml_str(&toml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(err, BuildError::DelegateKeyMismatch { .. }));
    }

    // --- [[entry]] import ---

    fn entry_delegate_toml() -> String {
        let (ch1, dk1) = regular_delegate_pair([1; 32]);
        let (ch7, dk7) = regular_delegate_pair([7; 32]);
        format!(
            r#"
[[entry]]
version = "V1"
description = "Before signing API was added"
date = "2026-01-15"
delegate_key = "{}"
code_hash = "{}"

[[entry]]
version = "V7"
description = "Before stdlib bump"
date = "2026-03-12"
delegate_key = "{}"
code_hash = "{}"
"#,
            hex(dk1),
            hex(ch1),
            hex(dk7),
            hex(ch7),
        )
    }

    #[test]
    fn entry_import_preserves_sparse_v_numbers_and_builds_notes() {
        let reg =
            Registry::from_entry_toml_str(&entry_delegate_toml(), Component::Delegate).unwrap();
        assert_eq!(reg.contract.len(), 0);
        assert_eq!(reg.delegate.len(), 2);
        // Sparse V numbers preserved (V4–V6-removed histories keep their gaps).
        assert_eq!(reg.delegate[0].generation, 1);
        assert_eq!(reg.delegate[1].generation, 7);
        assert_eq!(
            reg.delegate[0].note,
            "V1: Before signing API was added (2026-01-15)"
        );
        reg.validate().unwrap();
    }

    #[test]
    fn entry_import_contract_component() {
        let toml = format!(
            "[[entry]]\nversion = \"V1\"\ndescription = \"first\"\ndate = \"2025-08-11\"\n\
             code_hash = \"{}\"\n",
            hex([3; 32])
        );
        let reg = Registry::from_entry_toml_str(&toml, Component::Contract).unwrap();
        assert_eq!(reg.contract.len(), 1);
        assert_eq!(reg.contract[0].generation, 1);
        assert_eq!(reg.contract[0].note, "V1: first (2025-08-11)");
        reg.validate().unwrap();
    }

    #[test]
    fn entry_import_falls_back_to_sequential_generations() {
        let toml = format!(
            "[[entry]]\nversion = \"first\"\ncode_hash = \"{}\"\n\
             [[entry]]\nversion = \"second\"\ncode_hash = \"{}\"\n",
            hex([3; 32]),
            hex([4; 32]),
        );
        let reg = Registry::from_entry_toml_str(&toml, Component::Contract).unwrap();
        assert_eq!(reg.contract[0].generation, 0);
        assert_eq!(reg.contract[1].generation, 1);
        // Version without description/date → bare-version note.
        assert_eq!(reg.contract[0].note, "first");
    }

    #[test]
    fn entry_import_component_mismatch_is_rejected() {
        // Delegate file imported as contracts.
        let err =
            Registry::from_entry_toml_str(&entry_delegate_toml(), Component::Contract).unwrap_err();
        assert!(matches!(err, BuildError::EntrySchema(_)));
        // Contract file imported as delegates.
        let toml = format!(
            "[[entry]]\nversion = \"V1\"\ncode_hash = \"{}\"\n",
            hex([3; 32])
        );
        let err = Registry::from_entry_toml_str(&toml, Component::Delegate).unwrap_err();
        assert!(matches!(err, BuildError::EntrySchema(_)));
    }

    #[test]
    fn entry_import_forwards_irregular_key() {
        // River V1/V2 class row imported through the [[entry]] schema.
        let toml = format!(
            "[[entry]]\nversion = \"V1\"\ndelegate_key = \"{}\"\ncode_hash = \"{}\"\n\
             irregular_key = true\n",
            hex([2; 32]), // not the derived key
            hex([1; 32]),
        );
        let reg = Registry::from_entry_toml_str(&toml, Component::Delegate).unwrap();
        assert!(reg.delegate[0].irregular_key);
        reg.validate().unwrap();
    }
}
