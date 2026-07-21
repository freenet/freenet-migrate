//! Codegen: emit lineage consts into `$OUT_DIR`.
//!
//! Two kinds of output, from the same validated registry:
//!
//! * **Canonical consts** (`CONTRACT_LINEAGE` / `DELEGATE_LINEAGE`): slices of
//!   the runtime crate's `ContractLineageEntry` / `DelegateLineageEntry`, with
//!   `[u8; 32]` hashes decoded and validated at build time.
//! * **View consts**: plain byte-array shapes matching what existing apps'
//!   hand-rolled build scripts emit, so their call sites compile unchanged —
//!   [`Codegen::contract_hash_view`] (`&[[u8; 32]]`, River's
//!   `LEGACY_ROOM_CONTRACT_CODE_HASHES`) and [`Codegen::delegate_pair_view`]
//!   (`&[([u8; 32], [u8; 32])]` in `(delegate_key, code_hash)` order, River's
//!   `LEGACY_DELEGATES`). Views need no dependency on the `freenet-migrate`
//!   runtime crate; disable the canonical consts with
//!   [`Codegen::canonical_consts`]`(false)` for a views-only (build-dep-only)
//!   adoption.

use std::path::{Path, PathBuf};

use crate::error::BuildError;
use crate::registry::{Component, Registry};

/// Start a codegen builder.
///
/// ```no_run
/// // in build.rs:
/// freenet_migrate_build::codegen()
///     .registry("legacy.toml")
///     .emit()
///     .unwrap();
/// // then in the crate: include!(concat!(env!("OUT_DIR"), "/lineage.rs"));
/// ```
pub fn codegen() -> Codegen {
    Codegen::default()
}

/// Builder for the generated lineage consts.
#[derive(Debug, Clone)]
pub struct Codegen {
    registry_path: Option<PathBuf>,
    entry_component: Option<Component>,
    out_file: Option<String>,
    contract_const: Option<String>,
    delegate_const: Option<String>,
    crate_path: Option<String>,
    canonical: bool,
    contract_hash_view: Option<String>,
    delegate_pair_view: Option<String>,
    rerun_if_changed: bool,
    allow_missing_registry: bool,
}

impl Default for Codegen {
    fn default() -> Self {
        Self {
            registry_path: None,
            entry_component: None,
            out_file: None,
            contract_const: None,
            delegate_const: None,
            crate_path: None,
            canonical: true,
            contract_hash_view: None,
            delegate_pair_view: None,
            rerun_if_changed: true,
            allow_missing_registry: false,
        }
    }
}

impl Codegen {
    /// Path to a unified-schema (`[[contract]]` / `[[delegate]]`) registry.
    pub fn registry(mut self, path: impl Into<PathBuf>) -> Self {
        self.registry_path = Some(path.into());
        self.entry_component = None;
        self
    }

    /// Path to a River-style `[[entry]]` registry, imported as `component`.
    /// See [`Registry::from_entry_toml_str`] for the import rules.
    pub fn entry_registry(mut self, path: impl Into<PathBuf>, component: Component) -> Self {
        self.registry_path = Some(path.into());
        self.entry_component = Some(component);
        self
    }

    /// Output file name within `$OUT_DIR` (default `lineage.rs`).
    pub fn out_file(mut self, name: impl Into<String>) -> Self {
        self.out_file = Some(name.into());
        self
    }

    /// Whether to emit the canonical `ContractLineageEntry` /
    /// `DelegateLineageEntry` consts (default `true`). Set `false` for a
    /// views-only output that needs no `freenet-migrate` runtime dependency.
    pub fn canonical_consts(mut self, emit: bool) -> Self {
        self.canonical = emit;
        self
    }

    /// Name of the emitted canonical contract const (default
    /// `CONTRACT_LINEAGE`).
    pub fn contract_const_name(mut self, name: impl Into<String>) -> Self {
        self.contract_const = Some(name.into());
        self
    }

    /// Name of the emitted canonical delegate const (default
    /// `DELEGATE_LINEAGE`).
    pub fn delegate_const_name(mut self, name: impl Into<String>) -> Self {
        self.delegate_const = Some(name.into());
        self
    }

    /// Also emit `pub const {name}: &[[u8; 32]]` — the contract code hashes in
    /// registry order. Matches River's hand-rolled
    /// `LEGACY_ROOM_CONTRACT_CODE_HASHES` shape.
    pub fn contract_hash_view(mut self, name: impl Into<String>) -> Self {
        self.contract_hash_view = Some(name.into());
        self
    }

    /// Also emit `pub const {name}: &[([u8; 32], [u8; 32])]` — the delegate
    /// rows in registry order, each tuple **`(delegate_key, code_hash)`** (that
    /// order — matching River's hand-rolled `LEGACY_DELEGATES` shape).
    pub fn delegate_pair_view(mut self, name: impl Into<String>) -> Self {
        self.delegate_pair_view = Some(name.into());
        self
    }

    /// Path to the `freenet-migrate` crate in the consumer (default
    /// `::freenet_migrate`). Override if the consumer re-exports it elsewhere.
    pub fn crate_path(mut self, path: impl Into<String>) -> Self {
        self.crate_path = Some(path.into());
        self
    }

    /// Whether [`emit`](Self::emit) prints `cargo:rerun-if-changed` for the
    /// registry (default `true`). Set `false` in a build script that relies on
    /// Cargo's default re-run-on-any-change heuristic (e.g. to keep a
    /// `BUILD_TIMESTAMP` env fresh) — printing ANY `rerun-if-changed` would
    /// disable that heuristic for the whole script.
    pub fn rerun_if_changed(mut self, emit: bool) -> Self {
        self.rerun_if_changed = emit;
        self
    }

    /// Treat a **missing** registry file as an empty registry (default
    /// `false`, i.e. hard error). For build scripts that must also work where
    /// the registry isn't shipped — docs.rs and other non-workspace builds
    /// reading a file outside the crate (River's `ui/build.rs` case). Emits a
    /// `cargo:warning` when the fallback engages; any error other than
    /// file-not-found still fails.
    pub fn allow_missing_registry(mut self, allow: bool) -> Self {
        self.allow_missing_registry = allow;
        self
    }

    /// Render the generated Rust source as a string (pure; no I/O beyond
    /// reading the registry file). Useful for tests.
    pub fn generate_string(&self) -> Result<String, BuildError> {
        let path = self.registry_path.as_ref().ok_or(BuildError::NoRegistry)?;
        if self.allow_missing_registry && !path.exists() {
            println!(
                "cargo:warning=registry {} not found, generating empty lineage consts",
                path.display()
            );
            return self.render(&Registry::default());
        }
        let registry = match self.entry_component {
            Some(component) => Registry::from_entry_path(path, component)?,
            None => Registry::from_path(path)?,
        };
        self.render(&registry)
    }

    /// Render from an already-parsed registry (no file I/O). Validates first.
    pub fn render(&self, registry: &Registry) -> Result<String, BuildError> {
        registry.validate()?;
        if !self.canonical && self.contract_hash_view.is_none() && self.delegate_pair_view.is_none()
        {
            return Err(BuildError::NothingToEmit);
        }

        let mut out = String::new();
        out.push_str("// @generated by freenet-migrate-build — do not edit.\n\n");

        if self.canonical {
            self.render_canonical(registry, &mut out)?;
        }
        if let Some(name) = &self.contract_hash_view {
            render_contract_hash_view(registry, name, &mut out)?;
        }
        if let Some(name) = &self.delegate_pair_view {
            render_delegate_pair_view(registry, name, &mut out)?;
        }
        Ok(out)
    }

    fn render_canonical(&self, registry: &Registry, out: &mut String) -> Result<(), BuildError> {
        let crate_path = self.crate_path.as_deref().unwrap_or("::freenet_migrate");
        let contract_const = self.contract_const.as_deref().unwrap_or("CONTRACT_LINEAGE");
        let delegate_const = self.delegate_const.as_deref().unwrap_or("DELEGATE_LINEAGE");

        out.push_str(&format!(
            "pub const {contract_const}: &[{crate_path}::ContractLineageEntry] = &[\n"
        ));
        for row in &registry.contract {
            out.push_str(&format!(
                "    {crate_path}::ContractLineageEntry {{ generation: {}u32, code_hash: {}, note: {} }},\n",
                row.generation,
                fmt_bytes32(&row.code_hash_bytes()?),
                rust_str(&row.note),
            ));
        }
        out.push_str("];\n\n");

        out.push_str(&format!(
            "pub const {delegate_const}: &[{crate_path}::DelegateLineageEntry] = &[\n"
        ));
        for row in &registry.delegate {
            out.push_str(&format!(
                "    {crate_path}::DelegateLineageEntry {{ generation: {}u32, code_hash: {}, delegate_key: {}, irregular_key: {}, note: {} }},\n",
                row.generation,
                fmt_bytes32(&row.code_hash_bytes()?),
                fmt_bytes32(&row.delegate_key_bytes()?),
                row.irregular_key,
                rust_str(&row.note),
            ));
        }
        out.push_str("];\n\n");
        Ok(())
    }

    /// Read the registry, render the consts, and write them into `$OUT_DIR`.
    /// Emits `cargo:rerun-if-changed` for the registry (unless disabled via
    /// [`rerun_if_changed`](Self::rerun_if_changed)`(false)`), and skips the
    /// write when the content is unchanged (avoiding spurious recompilation
    /// for build scripts that re-run unconditionally). Returns the output
    /// path.
    pub fn emit(self) -> Result<PathBuf, BuildError> {
        let out_dir =
            std::env::var("OUT_DIR").map_err(|_| BuildError::Env("OUT_DIR not set".to_string()))?;
        let file = self
            .out_file
            .clone()
            .unwrap_or_else(|| "lineage.rs".to_string());
        let dest = Path::new(&out_dir).join(&file);
        let code = self.generate_string()?;
        let existing = std::fs::read_to_string(&dest).unwrap_or_default();
        if existing != code {
            std::fs::write(&dest, code)
                .map_err(|e| BuildError::Io(format!("writing {}: {e}", dest.display())))?;
        }
        for directive in self.cargo_directives() {
            println!("{directive}");
        }
        Ok(dest)
    }

    /// The `cargo:` directives [`emit`](Self::emit) prints (factored out so
    /// tests can pin them without capturing stdout).
    fn cargo_directives(&self) -> Vec<String> {
        match (&self.registry_path, self.rerun_if_changed) {
            (Some(reg), true) => vec![format!("cargo:rerun-if-changed={}", reg.display())],
            _ => vec![],
        }
    }
}

fn render_contract_hash_view(
    registry: &Registry,
    name: &str,
    out: &mut String,
) -> Result<(), BuildError> {
    out.push_str(&format!("pub const {name}: &[[u8; 32]] = &[\n"));
    for row in &registry.contract {
        if !row.note.is_empty() {
            out.push_str(&format!("    // {}\n", comment_safe(&row.note)));
        }
        out.push_str(&format!("    {},\n", fmt_bytes32(&row.code_hash_bytes()?)));
    }
    out.push_str("];\n\n");
    Ok(())
}

fn render_delegate_pair_view(
    registry: &Registry,
    name: &str,
    out: &mut String,
) -> Result<(), BuildError> {
    out.push_str(&format!("pub const {name}: &[([u8; 32], [u8; 32])] = &[\n"));
    for row in &registry.delegate {
        if !row.note.is_empty() {
            out.push_str(&format!("    // {}\n", comment_safe(&row.note)));
        }
        // Tuple order is (delegate_key, code_hash) — River's LEGACY_DELEGATES.
        out.push_str(&format!(
            "    ({}, {}),\n",
            fmt_bytes32(&row.delegate_key_bytes()?),
            fmt_bytes32(&row.code_hash_bytes()?),
        ));
    }
    out.push_str("];\n\n");
    Ok(())
}

/// Make a note safe for a single-line `//` comment: line breaks would leave
/// the remainder of the note as bare (uncompilable) tokens in the generated
/// file.
fn comment_safe(note: &str) -> String {
    note.replace(['\n', '\r'], " ")
}

/// Format a 32-byte array as a Rust literal.
fn fmt_bytes32(bytes: &[u8; 32]) -> String {
    let inner: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", inner.join(", "))
}

/// Format `s` as a Rust string literal (quotes + escaped body).
fn rust_str(s: &str) -> String {
    format!("\"{}\"", s.escape_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{derive_delegate_key, ContractRow, DelegateRow};

    fn b58(b: [u8; 32]) -> String {
        bs58::encode(b)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string()
    }

    fn regular_delegate_row(code: [u8; 32], generation: u32, note: &str) -> DelegateRow {
        let dk = derive_delegate_key(&code, &[]);
        DelegateRow {
            generation,
            code_hash: b58(code),
            delegate_key: b58(dk),
            params_hex: String::new(),
            irregular_key: false,
            note: note.to_string(),
        }
    }

    fn sample_registry() -> Registry {
        Registry {
            contract: vec![
                ContractRow {
                    generation: 0,
                    code_hash: b58([1; 32]),
                    note: "v1".to_string(),
                },
                ContractRow {
                    generation: 1,
                    code_hash: b58([2; 32]),
                    note: String::new(),
                },
            ],
            delegate: vec![regular_delegate_row([4; 32], 0, "delegate v1")],
        }
    }

    #[test]
    fn renders_default_const_names_and_byte_entries() {
        let reg = sample_registry();
        let out = codegen().render(&reg).unwrap();
        assert!(out.contains(
            "pub const CONTRACT_LINEAGE: &[::freenet_migrate::ContractLineageEntry] = &["
        ));
        assert!(out.contains(
            "pub const DELEGATE_LINEAGE: &[::freenet_migrate::DelegateLineageEntry] = &["
        ));
        // Hashes are emitted as byte arrays, decoded at build time.
        assert!(out.contains(&format!(
            "::freenet_migrate::ContractLineageEntry {{ generation: 0u32, code_hash: {}, note: \"v1\" }},",
            fmt_bytes32(&[1; 32])
        )));
        let dk = derive_delegate_key(&[4; 32], &[]);
        assert!(out.contains(&format!(
            "::freenet_migrate::DelegateLineageEntry {{ generation: 0u32, code_hash: {}, delegate_key: {}, irregular_key: false, note: \"delegate v1\" }},",
            fmt_bytes32(&[4; 32]),
            fmt_bytes32(&dk),
        )));
        // No base58 strings survive into the generated code.
        assert!(!out.contains(&b58([1; 32])));
    }

    #[test]
    fn honors_alias_names_and_crate_path() {
        let reg = sample_registry();
        let out = codegen()
            .contract_const_name("MY_CONTRACTS")
            .delegate_const_name("MY_DELEGATES")
            .crate_path("crate::migrate")
            .render(&reg)
            .unwrap();
        assert!(
            out.contains("pub const MY_CONTRACTS: &[crate::migrate::ContractLineageEntry] = &[")
        );
        assert!(out.contains("pub const MY_DELEGATES: &[crate::migrate::DelegateLineageEntry]"));
        assert!(!out.contains("::freenet_migrate::"));
    }

    #[test]
    fn contract_hash_view_matches_river_shape() {
        let reg = sample_registry();
        let out = codegen()
            .canonical_consts(false)
            .contract_hash_view("LEGACY_ROOM_CONTRACT_CODE_HASHES")
            .render(&reg)
            .unwrap();
        assert!(out.contains("pub const LEGACY_ROOM_CONTRACT_CODE_HASHES: &[[u8; 32]] = &["));
        assert!(out.contains("    // v1\n"));
        assert!(out.contains(&format!("    {},\n", fmt_bytes32(&[1; 32]))));
        assert!(out.contains(&format!("    {},\n", fmt_bytes32(&[2; 32]))));
        // Views-only output must not reference the runtime crate.
        assert!(!out.contains("::freenet_migrate::"));
    }

    #[test]
    fn delegate_pair_view_is_delegate_key_then_code_hash() {
        let code = [4u8; 32];
        let dk = derive_delegate_key(&code, &[]);
        let reg = Registry {
            contract: vec![],
            delegate: vec![regular_delegate_row(code, 0, "delegate v1")],
        };
        let out = codegen()
            .canonical_consts(false)
            .delegate_pair_view("LEGACY_DELEGATES")
            .render(&reg)
            .unwrap();
        assert!(out.contains("pub const LEGACY_DELEGATES: &[([u8; 32], [u8; 32])] = &["));
        // Order pinned: (delegate_key, code_hash) — NOT (code_hash, delegate_key).
        assert!(out.contains(&format!(
            "    ({}, {}),\n",
            fmt_bytes32(&dk),
            fmt_bytes32(&code)
        )));
        assert!(out.contains("    // delegate v1\n"));
    }

    #[test]
    fn views_and_canonical_can_coexist() {
        let reg = sample_registry();
        let out = codegen()
            .contract_hash_view("HASHES")
            .delegate_pair_view("PAIRS")
            .render(&reg)
            .unwrap();
        assert!(out.contains("pub const CONTRACT_LINEAGE"));
        assert!(out.contains("pub const HASHES"));
        assert!(out.contains("pub const PAIRS"));
    }

    #[test]
    fn empty_registry_emits_empty_views() {
        let out = codegen()
            .canonical_consts(false)
            .contract_hash_view("HASHES")
            .render(&Registry::default())
            .unwrap();
        assert!(out.contains("pub const HASHES: &[[u8; 32]] = &[\n];\n"));
    }

    #[test]
    fn nothing_to_emit_is_an_error() {
        let err = codegen()
            .canonical_consts(false)
            .render(&Registry::default())
            .unwrap_err();
        assert_eq!(err, BuildError::NothingToEmit);
    }

    #[test]
    fn view_note_with_newline_stays_single_comment_line() {
        // A multi-line note must not leak bare tokens past the `//` comment
        // (which would make the generated file uncompilable).
        let reg = Registry {
            contract: vec![ContractRow {
                generation: 0,
                code_hash: b58([1; 32]),
                note: "line one\nline two\r\nline three".to_string(),
            }],
            delegate: vec![],
        };
        let out = codegen()
            .canonical_consts(false)
            .contract_hash_view("HASHES")
            .render(&reg)
            .unwrap();
        assert!(out.contains("    // line one line two  line three\n"));
        // Every non-empty line in the output is a comment, a const header, an
        // entry, or a closing bracket — nothing dangling.
        for line in out.lines().filter(|l| !l.trim().is_empty()) {
            let t = line.trim_start();
            assert!(
                t.starts_with("//")
                    || t.starts_with("pub const")
                    || t.starts_with('[')
                    || t == "];",
                "dangling line in generated output: {line:?}"
            );
        }
    }

    #[test]
    fn emit_writes_then_skips_unchanged() {
        // emit() must write on first call and skip the write when the content
        // is unchanged (pinned by making the file read-only: a skipped write
        // succeeds, an attempted rewrite errors).
        let dir =
            std::env::temp_dir().join(format!("freenet-migrate-emit-test-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok(); // clear any read-only leftover
        std::fs::create_dir_all(&dir).unwrap();
        let registry_path = dir.join("legacy.toml");
        std::fs::write(&registry_path, "").unwrap();
        std::env::set_var("OUT_DIR", &dir);

        let build = || {
            codegen()
                .registry(&registry_path)
                .out_file("lineage_emit_test.rs")
        };
        let dest = build().emit().unwrap();
        let first = std::fs::read_to_string(&dest).unwrap();
        assert!(first.contains("pub const CONTRACT_LINEAGE"));

        let mut perms = std::fs::metadata(&dest).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&dest, perms.clone()).unwrap();
        // Unchanged content: the write is skipped, so read-only is no obstacle.
        build().emit().unwrap();
        // Changed registry → changed content → a real write is attempted and
        // fails against the read-only file, proving the skip wasn't a no-op.
        std::fs::write(
            &registry_path,
            format!(
                "[[contract]]\ngeneration = 0\ncode_hash = \"{}\"\n",
                b58([3; 32])
            ),
        )
        .unwrap();
        let err = build().emit().unwrap_err();
        assert!(matches!(err, BuildError::Io(_)));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(not(unix))]
        {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            std::fs::set_permissions(&dest, perms).unwrap();
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_registry_errors_by_default_but_can_fall_back_empty() {
        let missing = std::env::temp_dir().join("freenet-migrate-definitely-not-here.toml");
        let base = codegen()
            .registry(&missing)
            .canonical_consts(false)
            .contract_hash_view("HASHES");
        // Default: a missing file is a hard error (a typo'd path must not
        // silently produce an empty lineage).
        assert!(matches!(
            base.clone().generate_string().unwrap_err(),
            BuildError::Io(_)
        ));
        // Opted in (docs.rs / non-workspace builds): empty consts.
        let out = base.allow_missing_registry(true).generate_string().unwrap();
        assert!(out.contains("pub const HASHES: &[[u8; 32]] = &[\n];\n"));
    }

    #[test]
    fn rerun_if_changed_directive_can_be_disabled() {
        // A build script relying on Cargo's default re-run heuristic (e.g. for
        // a BUILD_TIMESTAMP env) must be able to suppress the directive —
        // printing ANY rerun-if-changed disables that heuristic script-wide.
        let with = codegen().registry("legacy.toml");
        assert_eq!(
            with.cargo_directives(),
            vec!["cargo:rerun-if-changed=legacy.toml".to_string()]
        );
        let without = codegen().registry("legacy.toml").rerun_if_changed(false);
        assert!(without.cargo_directives().is_empty());
    }

    #[test]
    fn escapes_note_string_literals() {
        let reg = Registry {
            contract: vec![ContractRow {
                generation: 0,
                code_hash: b58([1; 32]),
                note: "quote \" and backslash \\ here".to_string(),
            }],
            delegate: vec![],
        };
        let out = codegen().render(&reg).unwrap();
        assert!(out.contains(r#"note: "quote \" and backslash \\ here""#));
    }

    #[test]
    fn render_fails_on_invalid_registry() {
        let reg = Registry {
            contract: vec![ContractRow {
                generation: 0,
                code_hash: "not-32-bytes".to_string(),
                note: String::new(),
            }],
            delegate: vec![],
        };
        assert!(codegen().render(&reg).is_err());
    }

    #[test]
    fn generate_string_requires_a_registry_path() {
        assert_eq!(
            codegen().generate_string().unwrap_err(),
            BuildError::NoRegistry
        );
    }
}
