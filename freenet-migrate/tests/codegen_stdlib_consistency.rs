//! End-to-end pin across the three layers that must agree on key derivation:
//! the build crate's hashing, stdlib's real derivation, and the runtime
//! backward-probe reconstruction. If any drifts, migration reconstructs the
//! wrong key and silently strands state — so this is worth a cross-crate test.

use freenet_migrate::contract_id_from_code_hash;
use freenet_migrate_build::code_hash_b58;
use freenet_stdlib::prelude::{CodeHash, ContractCode, ContractInstanceId, Parameters};

const WASM: &[u8] = b"room_contract v7 pretend wasm bytes";

#[test]
fn build_crate_code_hash_matches_stdlib() {
    // What freenet-migrate-build writes into legacy.toml must equal stdlib's own
    // CodeHash string form.
    assert_eq!(code_hash_b58(WASM), CodeHash::from_code(WASM).encode());
}

#[test]
fn codegen_hash_reconstructs_stdlib_instance_id() {
    let params = Parameters::from(b"owner-parameters".to_vec());
    let code = ContractCode::from(WASM.to_vec());
    let stdlib_id = ContractInstanceId::from_params_and_code(&params, &code);

    // The base58 the build crate would record as a predecessor code hash...
    let ch_b58 = code_hash_b58(WASM);
    // ...fed to the runtime backward-probe reconstruction, reproduces exactly
    // the instance id stdlib derives from the real (code, params).
    let reconstructed = contract_id_from_code_hash(&ch_b58, &params).unwrap();
    assert_eq!(reconstructed, stdlib_id);
}
