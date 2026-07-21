//! Compile-smoke for the codegen: the emitted Rust is `include!`d here, so a
//! change that renders uncompilable output (bad escaping, a note that breaks a
//! `//` comment, a type drift between codegen and the runtime entry structs)
//! fails `cargo test` instead of failing the first adopter's build.
//!
//! The committed fixture (`fixtures/lineage_fixture.rs`) is pinned against a
//! fresh render of `fixtures/lineage_fixture.toml`, so it cannot go stale:
//! regenerate with `cargo run -p freenet-migrate-build --example gen_fixture >
//! freenet-migrate/tests/fixtures/lineage_fixture.rs`.

mod generated {
    include!("fixtures/lineage_fixture.rs");
}

#[test]
fn committed_fixture_matches_fresh_render() {
    let registry = freenet_migrate_build::Registry::from_toml_str(include_str!(
        "fixtures/lineage_fixture.toml"
    ))
    .unwrap();
    let fresh = freenet_migrate_build::codegen()
        .contract_hash_view("FIXTURE_CONTRACT_HASHES")
        .delegate_pair_view("FIXTURE_DELEGATE_PAIRS")
        .render(&registry)
        .unwrap();
    assert_eq!(
        fresh,
        include_str!("fixtures/lineage_fixture.rs"),
        "codegen output drifted from the committed fixture; regenerate it with \
         `cargo run -p freenet-migrate-build --example gen_fixture > \
         freenet-migrate/tests/fixtures/lineage_fixture.rs`"
    );
}

#[test]
fn generated_consts_have_expected_contents() {
    // Canonical consts: typed entries with build-time-decoded hashes.
    assert_eq!(generated::CONTRACT_LINEAGE.len(), 2);
    assert_eq!(generated::CONTRACT_LINEAGE[1].code_hash, [2u8; 32]);
    assert_eq!(
        generated::CONTRACT_LINEAGE[0].note,
        "V1: quote \" and backslash \\ (2025-08-11)"
    );
    assert_eq!(generated::DELEGATE_LINEAGE.len(), 3);
    assert!(generated::DELEGATE_LINEAGE[0].irregular_key);
    assert!(!generated::DELEGATE_LINEAGE[1].irregular_key);
    // Regular row: stored key equals the standard derivation.
    assert_eq!(
        generated::DELEGATE_LINEAGE[1].delegate_key,
        freenet_migrate_build::derive_delegate_key(&generated::DELEGATE_LINEAGE[1].code_hash, &[])
    );

    // Views: byte-array shapes for existing consumers, (delegate_key,
    // code_hash) tuple order.
    assert_eq!(generated::FIXTURE_CONTRACT_HASHES.len(), 2);
    assert_eq!(
        generated::FIXTURE_CONTRACT_HASHES[1],
        generated::CONTRACT_LINEAGE[1].code_hash
    );
    assert_eq!(generated::FIXTURE_DELEGATE_PAIRS.len(), 3);
    for (pair, entry) in generated::FIXTURE_DELEGATE_PAIRS
        .iter()
        .zip(generated::DELEGATE_LINEAGE)
    {
        assert_eq!(pair.0, entry.delegate_key);
        assert_eq!(pair.1, entry.code_hash);
    }

    // The probe path consumes the canonical consts directly.
    let keys = freenet_migrate::predecessor_delegate_keys(generated::DELEGATE_LINEAGE);
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0].bytes(), generated::DELEGATE_LINEAGE[0].delegate_key);
}
