//! Parity between this crate's pointer resolver and the frozen pointer
//! contract it must agree with, byte for byte.
//!
//! `freenet-migrate/src/pointer.rs` deliberately re-implements the pointer wire
//! format instead of depending on `contracts/pointer-contract/`: that crate is
//! workspace-excluded and unpublished on purpose (its compiled bytes must never
//! move), and a crates.io crate cannot carry a git or path dependency on it.
//!
//! Duplication is only safe if drift is loud, so this file pins it from both
//! sides:
//!
//! 1. Against the contract's committed `TEST-VECTORS.md` — the artifact that
//!    exists so a non-Rust implementation can be checked, and which the
//!    contract's own CI recomputes against its implementation. Every value here
//!    is asserted to be **both** what this crate produces **and** present in
//!    that document, so a change on either side goes red.
//! 2. Against the contract's `CODEHASH`, the root of the whole convention.
//! 3. Against the constants and the verification call in the contract's source,
//!    so a change to the signing domain, the layout, or the strictness of the
//!    signature check cannot land silently on the other side of the repo.
//!
//! These read files outside this package. They are integration tests, never
//! compiled into the published artifact, and a missing file is a hard failure
//! rather than a skip: a pin that can quietly not run is not a pin.

use ed25519_dalek::{Signer, SigningKey};
use freenet_migrate::pointer::{
    pointer_contract_id, pointer_params, pointer_signing_message, PointerRecord,
    POINTER_CODE_HASH_B58, POINTER_SIGNING_DOMAIN,
};
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, Parameters};

// ---------------------------------------------------------------------------
// The published vectors. Changing any of these is a change to the ecosystem's
// wire format, not a test fixup.
// ---------------------------------------------------------------------------

/// 32 bytes of 0x01 — the seed `TEST-VECTORS.md` publishes.
const SEED: [u8; 32] = [1u8; 32];
const AUTHOR_VK_HEX: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const APP_ID: &[u8] = b"river.room-contract";
const VERSION: u32 = 7;
const CODE_HASH: [u8; 32] = [0xAAu8; 32];

const PARAMS_HEX: &str = concat!(
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    "72697665722e726f6f6d2d636f6e7472616374",
);

const SIGNING_MESSAGE_HEX: &str = concat!(
    "667265656e65742d706f696e7465722f73746174652d7631",
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    "72697665722e726f6f6d2d636f6e7472616374",
    "00000007",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);

const SIGNATURE_HEX: &str = concat!(
    "ee3c33cf7bac4f2c2dc4d3a0eff2300a12174d44084f340d6d68c98d63a63953",
    "5fece9eed85c2218af2ba566bda24f4c63ec2fca140f6a35bc6230811f27a10d",
);

const STATE_HEX: &str = concat!(
    "00000007",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ee3c33cf7bac4f2c2dc4d3a0eff2300a12174d44084f340d6d68c98d63a63953",
    "5fece9eed85c2218af2ba566bda24f4c63ec2fca140f6a35bc6230811f27a10d",
);

const POINTER_KEY_B58: &str = "Hjus5Fnb6NWxKGN64MQwmbgk1Vd6YojykLtxnXipR6Lx";
const CONSUMER_PARAMS: &[u8] = b"example-consumer-params";
const CONSUMER_INSTANCE_ID_B58: &str = "k2Nt3AT6K7L9obj1GwogHN2dpzY1MVaz9AAhXbLBkAS";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The part of a Rust source file before its test module.
///
/// A source-scrape needle satisfied by a string literal inside `#[cfg(test)]`
/// pins nothing, so every scrape in this file is scoped through here. Panics if
/// no marker is found rather than returning the whole file: failing open would
/// discard the protection silently.
fn production_prefix<'a>(source: &'a str, what: &str) -> &'a str {
    // EARLIEST occurrence across both spellings, not the first spelling that
    // happens to match. Taking them in list order re-opens the fail-open this
    // exists to close: the contract's module marker is the target-gated form,
    // so a nested plain `#[cfg(test)]` INSIDE that module would match later in
    // the file and hand back a prefix containing the whole test module.
    let cut = ["#[cfg(test)]", "#[cfg(all(test"]
        .iter()
        .filter_map(|m| source.find(m))
        .min();
    match cut {
        Some(i) => &source[..i],
        None => panic!(
            "{what} has no recognised #[cfg(test)] marker, so this scrape cannot be \
             scoped to production code. Add the new spelling to `production_prefix` \
             rather than letting the scrape silently cover the test module."
        ),
    }
}

fn contract_file(relative: &str) -> String {
    let path = format!(
        "{}/../contracts/pointer-contract/{relative}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the pointer contract's {relative} must be readable to pin parity against it \
             ({path}): {e}"
        )
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// `TEST-VECTORS.md` with its inline `<- annotations` and all whitespace
/// removed, so a multi-line hex block reads as one contiguous string.
fn normalized_vectors() -> String {
    contract_file("TEST-VECTORS.md")
        .lines()
        .map(|line| line.split("<-").next().unwrap_or(line))
        .collect::<Vec<_>>()
        .join("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

fn assert_published(doc: &str, label: &str, value: &str) {
    assert!(
        doc.contains(value),
        "{label} is not in the contract's TEST-VECTORS.md any more: {value}\n\
         Either the contract's wire format moved (this resolver must move with it) \
         or the vectors were edited. Do not update this constant without \
         establishing which."
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn pointer_code_hash_matches_the_frozen_artifact() {
    let committed = contract_file("CODEHASH");
    let value = committed
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .expect("CODEHASH carries one non-comment line");
    assert_eq!(
        value, POINTER_CODE_HASH_B58,
        "the frozen pointer WASM's code hash moved. Every published pointer \
         re-keys when that happens; this is a flag day, not a constant bump."
    );
}

#[test]
fn params_encoding_matches_the_published_vector() {
    let vk = SigningKey::from_bytes(&SEED).verifying_key();
    assert_eq!(hex(vk.as_bytes()), AUTHOR_VK_HEX);

    let params = pointer_params(&vk, APP_ID).unwrap();
    assert_eq!(hex(&params), PARAMS_HEX);
    assert_eq!(params.len(), 51);

    let doc = normalized_vectors();
    assert_published(&doc, "the author verifying key", AUTHOR_VK_HEX);
    assert_published(&doc, "the params encoding", PARAMS_HEX);
}

#[test]
fn signing_message_matches_the_published_vector() {
    let params = unhex(PARAMS_HEX);
    let msg = pointer_signing_message(&params, VERSION, &CODE_HASH);
    assert_eq!(hex(&msg), SIGNING_MESSAGE_HEX);
    assert_eq!(msg.len(), 111);
    // The domain is a prefix, and it is the one the contract uses.
    assert!(msg.starts_with(POINTER_SIGNING_DOMAIN));
    assert_eq!(POINTER_SIGNING_DOMAIN, b"freenet-pointer/state-v1");

    assert_published(
        &normalized_vectors(),
        "the signing message",
        SIGNING_MESSAGE_HEX,
    );
}

#[test]
fn the_published_signature_verifies_and_is_reproduced_byte_for_byte() {
    let key = SigningKey::from_bytes(&SEED);
    let vk = key.verifying_key();
    let params = pointer_params(&vk, APP_ID).unwrap();

    // Ed25519 signing is deterministic (RFC 8032), so this must be the exact
    // published signature — not merely *a* valid one.
    let produced = key.sign(&pointer_signing_message(&params, VERSION, &CODE_HASH));
    assert_eq!(hex(&produced.to_bytes()), SIGNATURE_HEX);

    // And this crate's verifier accepts the published record.
    let record = PointerRecord::decode(&unhex(STATE_HEX)).unwrap();
    assert_eq!(record.version, VERSION);
    assert_eq!(record.code_hash, CODE_HASH);
    assert_eq!(hex(&record.signature), SIGNATURE_HEX);
    record
        .verify(&params, &vk)
        .expect("the published vector must verify under this crate's rules");
    assert_eq!(hex(&record.encode()), STATE_HEX);

    let doc = normalized_vectors();
    assert_published(&doc, "the signature", SIGNATURE_HEX);
    assert_published(&doc, "the state encoding", STATE_HEX);
}

#[test]
fn derived_addresses_match_the_published_vectors() {
    let vk = SigningKey::from_bytes(&SEED).verifying_key();

    // The pointer's own address, from the frozen code hash + its params.
    let pointer = pointer_contract_id(&vk, APP_ID).unwrap();
    assert_eq!(pointer.encode(), POINTER_KEY_B58);

    // And step 3: the consumer's own key, from the record's code_hash plus the
    // CONSUMER's params — not the pointer's.
    let record = PointerRecord::decode(&unhex(STATE_HEX)).unwrap();
    let mine = Parameters::from(CONSUMER_PARAMS.to_vec());
    let derived = freenet_migrate::contract_id_from_code_hash(&record.code_hash, &mine);
    assert_eq!(derived.encode(), CONSUMER_INSTANCE_ID_B58);

    // The vectors cannot cover this leg (no WASM is known whose hash is
    // 0xAA…AA), so pin the derivation itself against stdlib over real code:
    // whatever a node computes from (code, params), step 3 computes from
    // (code_hash, params).
    let code = ContractCode::from(b"pretend this is the app's current wasm".to_vec());
    assert_eq!(
        freenet_migrate::contract_id_from_code_hash(code.hash(), &mine),
        ContractInstanceId::from_params_and_code(&mine, &code),
        "step-3 derivation diverged from stdlib's own key derivation"
    );

    let doc = normalized_vectors();
    assert_published(&doc, "the pointer key", POINTER_KEY_B58);
    assert_published(&doc, "the derived consumer id", CONSUMER_INSTANCE_ID_B58);
    assert_published(&doc, "the frozen pointer code hash", POINTER_CODE_HASH_B58);
}

/// `production_prefix` must cut at the EARLIEST test marker, whichever spelling
/// it is.
///
/// Taking the markers in list order instead re-opens the fail-open the helper
/// exists to close: the contract's module marker is the target-gated spelling,
/// so a nested plain `#[cfg(test)]` inside that module sits LATER in the file,
/// and a list-order search would return the later offset and hand back a prefix
/// containing the whole test module. Any needle could then be satisfied by a
/// string literal in a test.
#[test]
fn the_scrape_cuts_at_the_earliest_test_marker() {
    let gated_first = "pub const REAL: u8 = 1;\n\
                       #[cfg(all(test, not(target_arch = \"wasm32\")))]\n\
                       mod tests {\n\
                       #[cfg(test)]\n\
                       fn nested() {}\n\
                       const DECOY: u8 = 2;\n\
                       }\n";
    let prefix = production_prefix(gated_first, "synthetic");
    assert!(prefix.contains("pub const REAL"));
    assert!(
        !prefix.contains("DECOY") && !prefix.contains("mod tests"),
        "the scrape must not reach into the test module: {prefix:?}"
    );

    // The plain spelling first is the ordinary case and must still work.
    let plain_first = "pub const REAL: u8 = 1;\n#[cfg(test)]\nmod tests { const D: u8 = 2; }\n";
    assert!(!production_prefix(plain_first, "synthetic").contains("mod tests"));
}

/// The resolver's own mirrored constants, asserted against **literals**.
///
/// Every unit test in `pointer.rs` refers to these symbolically, so it checks
/// the code against itself and a drift here would pass unnoticed. The contract
/// source-scrape below pins the same numbers on the other side, so together
/// these two tests make a divergence in either direction fail.
#[test]
fn the_resolvers_mirrored_constants_match_their_expected_literals() {
    use freenet_migrate::pointer::{
        MAX_APP_ID_LEN, MAX_POINTER_PARAMS_LEN, MAX_POINTER_VERSION, MIN_POINTER_PARAMS_LEN,
        POINTER_STATE_LEN, SIGNATURE_LEN, TOMBSTONE_CODE_HASH, VERIFYING_KEY_LEN,
    };
    assert_eq!(POINTER_SIGNING_DOMAIN, b"freenet-pointer/state-v1");
    assert_eq!(POINTER_STATE_LEN, 100);
    assert_eq!(MAX_APP_ID_LEN, 64);
    assert_eq!(MAX_POINTER_VERSION, u32::MAX - 1);
    assert_eq!(TOMBSTONE_CODE_HASH, [0u8; 32]);
    assert_eq!(VERIFYING_KEY_LEN, 32);
    assert_eq!(SIGNATURE_LEN, 64);
    assert_eq!(MIN_POINTER_PARAMS_LEN, 33);
    assert_eq!(MAX_POINTER_PARAMS_LEN, 96);
}

/// Strip `//` line comments from source.
///
/// Without this, commenting the old call out and writing a new one below it
/// satisfies a `contains` needle, which is ordinary developer behaviour rather
/// than a contrived attack. The thing that silently un-pins here is the
/// resolver becoming MORE permissive than the frozen network.
///
/// Scope, so the next reader does not over-trust it: this handles `//` only.
/// A needle inside a `/* */` block or a string literal still satisfies a
/// `contains` check. Neither production prefix contains a block comment today.
/// It is applied BEFORE [`production_prefix`], so a `#[cfg(test)]` mentioned in
/// a comment cannot truncate the scrape early and report every needle as
/// missing.
fn strip_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The resolver must verify **exactly as strictly** as the contract.
///
/// A silent `verify_strict` -> `verify` regression would make this resolver
/// strictly MORE permissive than the frozen node (small-order `R`,
/// non-canonical `A`, the cofactored equation), i.e. it would adopt a code hash
/// the network would never store. That mutation is invisible to the behavioural
/// tests, because the `S + L` malleability vector is rejected by dalek's
/// S-canonicity check under both functions -- so it is pinned here on the
/// source instead. Reads `src/pointer.rs`; the needles live in this file, so
/// there is no self-match.
#[test]
fn the_resolver_source_still_pins_strict_verification() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/pointer.rs"))
        .expect("the resolver's own source must be readable");
    // Scope to production code: a needle satisfied by a string literal inside
    // `mod tests` would pin nothing. `expect` rather than a fallback, because a
    // fallback would silently revert to scanning the whole file if the marker
    // ever changed, losing the protection with no signal. (The sibling contract
    // crate already spells its marker differently, which is how a fallback here
    // would rot unnoticed.)
    let stripped = strip_line_comments(&raw);
    let src: String = production_prefix(&stripped, "src/pointer.rs")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    for (what, needle) in [
        (
            "strict signature verification",
            ".verify_strict(&msg,&Signature::from_bytes(&self.signature))",
        ),
        (
            // Two DISTINCT needles, one per function. A single needle written
            // against `parse_pointer_params` (which spells the argument `&key`)
            // silently failed to pin `pointer_params`, and `pointer_params` is
            // the load-bearing one: it builds the address the resolver derives.
            "the canonical-encoding check when PARSING a params blob",
            "if!is_canonical_field_element(&key){returnErr(PointerError::ParamsKeyNonCanonical);}",
        ),
        (
            "the canonical-encoding check when BUILDING params",
            concat!(
                "if!is_canonical_field_element(author_vk.as_bytes())",
                "{returnErr(PointerError::ParamsKeyNonCanonical);}",
            ),
        ),
        (
            "the signed-message field order",
            concat!(
                "m.extend_from_slice(POINTER_SIGNING_DOMAIN);",
                "m.extend_from_slice(params);",
                "m.extend_from_slice(&version.to_be_bytes());",
                "m.extend_from_slice(code_hash);",
            ),
        ),
    ] {
        assert!(
            src.contains(needle),
            "{what} changed in freenet-migrate/src/pointer.rs. The resolver must stay exactly \
             as strict as the frozen contract; being more permissive means adopting a code \
             hash the network would never store. Expected to find: {needle}"
        );
    }

    assert_weak_key_guard_at_both_sites(&src, "freenet-migrate/src/pointer.rs");

    // Presence of the strict call is not enough on its own. Count the
    // verification sites instead of hunting for the permissive spelling: an
    // absence needle like `.verify(&msg` is evaded by UFCS or by renaming the
    // local, and false-fires when an unrelated `verify` happens to take a
    // binding called `msg`. Exactly one signature check must exist, and it must
    // be the strict one.
    assert_eq!(
        src.matches(".verify_strict(").count(),
        1,
        "freenet-migrate/src/pointer.rs must contain exactly one strict signature \
         check; found {}. A second verification path is how a permissive one gets \
         added beside the pinned one.",
        src.matches(".verify_strict(").count()
    );
    assert_eq!(
        src.matches("Signature::from_bytes(").count(),
        1,
        "freenet-migrate/src/pointer.rs must construct exactly one Signature; found {}. \
         More than one means a verification path this pin does not cover.",
        src.matches("Signature::from_bytes(").count()
    );
}

/// Both of a file's params functions must reject a small-order author key.
///
/// The two guards are textually identical, and a `contains` needle matching N
/// sites pins only N-1 deletions, because deleting one leaves the needle
/// satisfied by its sibling. Count instead. Applies to the resolver and to the
/// contract alike, which is why it is shared.
fn assert_weak_key_guard_at_both_sites(src: &str, what: &str) {
    let weak_guard = "ifauthor_vk.is_weak(){returnErr(PointerError::ParamsKeyWeak);}";
    let found = src.matches(weak_guard).count();
    assert_eq!(
        found, 2,
        "{what}: both the build and the parse path must reject a small-order author \
         key; found {found} of the 2 expected is_weak guards"
    );
}

/// Whitespace-stripped source scrape of the contract, so `cargo fmt` on the
/// other side of the repo cannot break the pin, but a semantic change does.
#[test]
fn the_contract_source_still_says_what_this_resolver_assumes() {
    let raw = contract_file("src/lib.rs");
    let stripped = strip_line_comments(&raw);
    let src: String = production_prefix(&stripped, "contracts/pointer-contract/src/lib.rs")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    for (what, needle) in [
        (
            "the signing domain",
            r#"pubconstSIGNING_DOMAIN:&[u8]=b"freenet-pointer/state-v1";"#,
        ),
        (
            "the 100-byte state layout",
            "pubconstSTATE_LEN:usize=4+CODE_HASH_LEN+SIGNATURE_LEN;",
        ),
        (
            "the reserved top version",
            "pubconstMAX_VERSION:u32=u32::MAX-1;",
        ),
        (
            "the app_id length bound",
            "pubconstMAX_APP_ID_LEN:usize=64;",
        ),
        (
            "the app_id charset",
            "b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'.'||b==b'-'||b==b'_'",
        ),
        (
            "the tombstone code hash",
            "pubconstTOMBSTONE_CODE_HASH:[u8;CODE_HASH_LEN]=[0u8;CODE_HASH_LEN];",
        ),
        (
            "the signed-message field order",
            concat!(
                "m.extend_from_slice(SIGNING_DOMAIN);",
                "m.extend_from_slice(params);",
                "m.extend_from_slice(&version.to_be_bytes());",
                "m.extend_from_slice(code_hash);",
            ),
        ),
        (
            "strict signature verification",
            ".verify_strict(&msg,&Signature::from_bytes(&self.signature))",
        ),
        (
            // The resolver's `order()` derives its equal-version tiebreak
            // direction from this function. If the contract flipped to
            // higher-encoding-wins, consumers would diverge from the network
            // permanently, which is the exact split the tiebreak prevents.
            "the merge tiebreak direction",
            "ifcandidate.encode()<current.encode(){candidate}else{current}",
        ),
        (
            "the canonical-encoding check on the author key",
            "if!is_canonical_field_element(&key){returnErr(PointerError::ParamsKeyNonCanonical);}",
        ),
    ] {
        assert!(
            src.contains(needle),
            "{what} changed in contracts/pointer-contract/src/lib.rs. \
             freenet-migrate's resolver mirrors that format and must be updated \
             with it (and the contract's WASM freeze reviewed).\nExpected to \
             find: {needle}"
        );
    }

    // Same counting pin as the resolver side. The contract also has TWO
    // identical small-order guards (its params `parse` and `encode`), so a
    // plain `contains` here would pin only one of the two deletions -- the
    // exact weakness the shared helper was extracted to remove.
    assert_weak_key_guard_at_both_sites(&src, "contracts/pointer-contract/src/lib.rs");
}
