//! Real-data fixtures: actual rows from River's shipped registries
//! (`legacy_delegates.toml`, `common/legacy_room_contracts.toml`).
//!
//! These pin the `[[entry]]` import + validation + view codegen against the
//! data the first adopter will actually feed it — including the two properties
//! synthetic fixtures missed on first contact with the real files:
//!
//! * River's V1 delegate key predates the standard
//!   `blake3(code_hash ‖ params)` derivation (it derives from *nothing*
//!   reconstructible), so the cross-check MUST have a per-row opt-out and the
//!   probe MUST target the stored key. (River's own `migration_test.rs` skips
//!   V1 *and* V2 by name — but V2's key in fact derives correctly, which the
//!   stale-flag check here surfaced. The per-row flag replaces that over-broad
//!   name-based exemption with full validation for V2.)
//! * River's delegate history is sparse (V4–V6 removed as unrecoverable), so
//!   generation numbers must survive import with their gaps intact.

use freenet_migrate_build::{codegen, Component, Registry};

/// Verbatim rows from River's `legacy_delegates.toml` (V1, V2, V3, V7), with
/// `irregular_key` added to the one genuinely pre-standard-derivation row —
/// exactly the edit River's adoption PR makes.
const RIVER_DELEGATES: &str = r#"
[[entry]]
version = "V1"
description = "Before signing API was added"
date = "2026-01-15"
delegate_key = "1a9330820e806cda54eca7dab22b84f20cfa793ebe61a2615312cc6e6ebcfff6"
code_hash = "783996bde3bc2235affec9deb8a0f7e9d21fa131dcf003000bb03f467db0f831"
irregular_key = true

[[entry]]
version = "V2"
description = "After scaffold 0.2.2 update with relaxed verify"
date = "2026-02-11"
delegate_key = "e3ad5c5b1a821089536be84d674329b37f46d2fba3e7026008fae85f3556511f"
code_hash = "cfb9774c03cd95424955adab70a41d7575cd3312f09fd3f16d6ef548ba8cf051"

[[entry]]
version = "V3"
description = "Before stdlib 0.1.40 bump, stdlib 0.1.35 with scaffold 0.2.2"
date = "2026-02-27"
delegate_key = "1da41b5e49067bce3804a52ea7b1b7bbdffd326a4c734e00a946ed23ec41dab6"
code_hash = "f399f3bfb435d51a6f233b4201e71ee5f6c5c2a4dd8c96e9d36e5c907317bed5"

[[entry]]
version = "V7"
description = "Before freenet-stdlib 0.3.2 MessageOrigin API change"
date = "2026-03-12"
delegate_key = "5fc0fc05bf778a0817c651c9021fd4e08e68e7916bf61d0f2843d32aa5931622"
code_hash = "77944fa2386b3b53733e3386b61e1a1e142fd802e3bceea78e283ca8feb6b79d"
"#;

/// Verbatim rows from River's `common/legacy_room_contracts.toml` (V1, V2).
const RIVER_CONTRACTS: &str = r#"
[[entry]]
version = "V1"
description = "ci: resilient prefetch to fix Build failure (#31)"
date = "2025-08-11"
code_hash = "415d03916cccddca057d343ce0f5c8dc89606221d0b260f3dfc7344f64dd5b38"

[[entry]]
version = "V2"
description = "feat(cli): add subscription-based streaming mode"
date = "2025-12-17"
code_hash = "da9cc449afaed575633cbff6cda171ba5323a0d3a5fe5c9d9e513b3801f8d020"
"#;

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn river_delegate_registry_imports_and_validates() {
    let reg = Registry::from_entry_toml_str(RIVER_DELEGATES, Component::Delegate).unwrap();
    // Sparse generations survive (V4–V6 removed → 1, 2, 3, 7).
    let gens: Vec<u32> = reg.delegate.iter().map(|r| r.generation).collect();
    assert_eq!(gens, vec![1, 2, 3, 7]);
    // V2/V3/V7 pass the derivation cross-check; V1 passes via irregular_key.
    reg.validate().unwrap();
    assert_eq!(
        reg.delegate[0].note,
        "V1: Before signing API was added (2026-01-15)"
    );
}

#[test]
fn river_v1_without_irregular_flag_is_rejected() {
    // The flag is load-bearing on real data: drop it from V1 and validation
    // must fail (its recorded key does not derive from its code hash).
    let stripped = RIVER_DELEGATES.replacen("irregular_key = true\n", "", 1);
    let reg = Registry::from_entry_toml_str(&stripped, Component::Delegate).unwrap();
    let err = reg.validate().unwrap_err();
    assert!(
        matches!(
            err,
            freenet_migrate_build::BuildError::DelegateKeyMismatch { generation: 1, .. }
        ),
        "got {err:?}"
    );
}

#[test]
fn river_delegate_view_matches_hand_rolled_shape() {
    let reg = Registry::from_entry_toml_str(RIVER_DELEGATES, Component::Delegate).unwrap();
    let out = codegen()
        .canonical_consts(false)
        .delegate_pair_view("LEGACY_DELEGATES")
        .render(&reg)
        .unwrap();
    assert!(out.contains("pub const LEGACY_DELEGATES: &[([u8; 32], [u8; 32])] = &["));
    // Spot-check V1: tuple is (delegate_key, code_hash) with the exact bytes
    // River's hand-rolled ui/build.rs emits today.
    let dk = hex32("1a9330820e806cda54eca7dab22b84f20cfa793ebe61a2615312cc6e6ebcfff6");
    let ch = hex32("783996bde3bc2235affec9deb8a0f7e9d21fa131dcf003000bb03f467db0f831");
    let dk_lit: Vec<String> = dk.iter().map(|b| b.to_string()).collect();
    let ch_lit: Vec<String> = ch.iter().map(|b| b.to_string()).collect();
    assert!(out.contains(&format!(
        "([{}], [{}])",
        dk_lit.join(", "),
        ch_lit.join(", ")
    )));
    // No runtime-crate references in a views-only output.
    assert!(!out.contains("::freenet_migrate::"));
}

#[test]
fn full_river_registries_import_and_validate() {
    // The complete shipped registries (24 delegate rows, 27 contract rows) —
    // the actual input River's adoption feeds the crate — not just a sample.
    // Delegates: verbatim except `irregular_key = true` on V1, the single
    // required edit (V2–V27 all satisfy the standard derivation).
    let delegates = Registry::from_entry_toml_str(
        include_str!("fixtures/river_legacy_delegates.toml"),
        Component::Delegate,
    )
    .unwrap();
    assert_eq!(delegates.delegate.len(), 24);
    assert_eq!(
        delegates
            .delegate
            .iter()
            .filter(|r| r.irregular_key)
            .map(|r| r.generation)
            .collect::<Vec<_>>(),
        vec![1],
        "V1 must be the ONLY irregular row in River's registry"
    );
    delegates.validate().unwrap();
    // Sparse V4–V6 gap preserved.
    assert!(!delegates
        .delegate
        .iter()
        .any(|r| (4..=6).contains(&r.generation)));

    // Contracts: byte-for-byte the shipped file, zero edits required.
    let contracts = Registry::from_entry_toml_str(
        include_str!("fixtures/river_legacy_room_contracts.toml"),
        Component::Contract,
    )
    .unwrap();
    assert_eq!(contracts.contract.len(), 27);
    contracts.validate().unwrap();

    // Both render through the view codegen (what River's build.rs will run).
    codegen()
        .canonical_consts(false)
        .delegate_pair_view("LEGACY_DELEGATES")
        .render(&delegates)
        .unwrap();
    codegen()
        .canonical_consts(false)
        .contract_hash_view("LEGACY_ROOM_CONTRACT_CODE_HASHES")
        .render(&contracts)
        .unwrap();
}

#[test]
fn river_contract_registry_imports_and_renders_hash_view() {
    let reg = Registry::from_entry_toml_str(RIVER_CONTRACTS, Component::Contract).unwrap();
    assert_eq!(
        reg.contract
            .iter()
            .map(|r| r.generation)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    reg.validate().unwrap();

    let out = codegen()
        .canonical_consts(false)
        .contract_hash_view("LEGACY_ROOM_CONTRACT_CODE_HASHES")
        .render(&reg)
        .unwrap();
    assert!(out.contains("pub const LEGACY_ROOM_CONTRACT_CODE_HASHES: &[[u8; 32]] = &["));
    let ch = hex32("415d03916cccddca057d343ce0f5c8dc89606221d0b260f3dfc7344f64dd5b38");
    let lit: Vec<String> = ch.iter().map(|b| b.to_string()).collect();
    assert!(out.contains(&format!("[{}]", lit.join(", "))));
}
