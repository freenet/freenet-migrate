//! One-off generator for freenet-migrate/tests/fixtures/lineage_fixture.rs,
//! reading the registry from freenet-migrate/tests/fixtures/lineage_fixture.toml.
//! Run: cargo run -p freenet-migrate-build --example gen_fixture \
//!        > freenet-migrate/tests/fixtures/lineage_fixture.rs

fn main() {
    let toml = include_str!("../../freenet-migrate/tests/fixtures/lineage_fixture.toml");
    let registry = freenet_migrate_build::Registry::from_toml_str(toml).unwrap();
    let code = freenet_migrate_build::codegen()
        .contract_hash_view("FIXTURE_CONTRACT_HASHES")
        .delegate_pair_view("FIXTURE_DELEGATE_PAIRS")
        .render(&registry)
        .unwrap();
    print!("{code}");
}
