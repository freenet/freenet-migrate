//! End-to-end pin across the three layers that must agree on key derivation:
//! the build crate's hashing, stdlib's real derivation, and the runtime
//! backward-probe reconstruction. If any drifts, migration reconstructs the
//! wrong key and silently strands state — so this is worth a cross-crate test.

use freenet_migrate::{contract_id_from_code_hash, contract_id_from_code_hash_b58};
use freenet_migrate_build::{code_hash_b58, code_hash_hex, decode_hash32, derive_delegate_key};
use freenet_stdlib::prelude::{
    CodeHash, ContractCode, ContractInstanceId, DelegateKey, Parameters,
};

const WASM: &[u8] = b"room_contract v7 pretend wasm bytes";

#[test]
fn build_crate_code_hash_matches_stdlib() {
    // What freenet-migrate-build writes into legacy.toml must equal stdlib's own
    // CodeHash string form.
    assert_eq!(code_hash_b58(WASM), CodeHash::from_code(WASM).encode());
    // And the hex form decodes to the same bytes stdlib holds.
    assert_eq!(
        decode_hash32(&code_hash_hex(WASM)).unwrap(),
        *CodeHash::from_code(WASM)
    );
}

#[test]
fn codegen_hash_reconstructs_stdlib_instance_id() {
    let params = Parameters::from(b"owner-parameters".to_vec());
    let code = ContractCode::from(WASM.to_vec());
    let stdlib_id = ContractInstanceId::from_params_and_code(&params, &code);

    // The bytes the build crate would decode into a generated lineage entry...
    let ch_bytes = decode_hash32(&code_hash_b58(WASM)).unwrap();
    // ...fed to the runtime backward-probe reconstruction, reproduce exactly
    // the instance id stdlib derives from the real (code, params).
    assert_eq!(contract_id_from_code_hash(&ch_bytes, &params), stdlib_id);
    // The string-form entry point agrees.
    assert_eq!(
        contract_id_from_code_hash_b58(&code_hash_b58(WASM), &params).unwrap(),
        stdlib_id
    );
}

#[test]
fn build_delegate_derivation_matches_stdlib() {
    // The build crate's delegate-key cross-check (Registry::validate) is only
    // as good as derive_delegate_key's agreement with what the node actually
    // derives — pin it against stdlib's real DelegateKey::from_params, for
    // empty params (the River/Delta case) and non-empty params.
    let code_hash = CodeHash::from_code(WASM);
    for params_bytes in [b"".to_vec(), b"delegate parameters".to_vec()] {
        let params = Parameters::from(params_bytes.clone());
        let stdlib_key = DelegateKey::from_params(code_hash.encode(), &params).unwrap();
        assert_eq!(
            derive_delegate_key(&code_hash, &params_bytes),
            stdlib_key.bytes(),
            "build-crate delegate derivation diverged from stdlib (params len {})",
            params_bytes.len()
        );
    }
}
