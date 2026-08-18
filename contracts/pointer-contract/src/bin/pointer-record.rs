//! Sign, derive and verify pointer records — the publisher-side and CI-gate tool.
//!
//! One tool for every app that publishes a pointer, rather than a signing
//! script per app. A second signing implementation is a second thing that can
//! disagree with this crate about what a record's bytes are, and the whole
//! convention rests on every publisher producing the same 100 bytes for the
//! same inputs. So this delegates every cryptographic and derivation step to
//! the library above it and does nothing itself but parse arguments.
//!
//! ```text
//! pointer-record key    --author-vk VK --app-id ID
//! pointer-record sign   --author-vk VK --app-id ID --version N --code-hash H  < keyfile
//! pointer-record verify --author-vk VK --app-id ID --state S [--expect-… …]
//! ```
//!
//! Output is `key=value` lines, one per line, so a shell gate can `eval` or
//! `grep` it without a JSON parser. Failures go to stderr and exit non-zero.
//!
//! # The signing key is read from stdin, never from a flag
//!
//! Anything on `argv` is visible in `ps` to every other user on the machine and
//! lands in shell history. `sign` therefore reads the key from stdin, and
//! accepts a whole key file so the common invocation is a redirect:
//!
//! ```text
//! pointer-record sign … < ~/.config/river/web-container-keys.toml
//! ```
//!
//! # `--author-vk` is required for signing, and that is the point
//!
//! `sign` derives the verifying key from the private key it was given and
//! refuses to emit a record unless it matches the `--author-vk` the caller
//! passed — which the caller is expected to take from the app's published
//! `FREENET.md`, not from the key file. Signing with a key file that has drifted
//! from the app's published identity produces a record every integrator will
//! reject, and it produces it silently, because the record is perfectly valid
//! under the wrong key. That check cannot be optional and still be worth having.

use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_pointer_contract::{sign_record, PointerParams, PointerRecord};
use freenet_stdlib::prelude::{ContractKey, Parameters};

/// The published pointer code hash, baked in from `CODEHASH` at compile time.
///
/// Baked in rather than computed: deriving it by rebuilding the WASM locally is
/// the one mistake that silently forks the whole convention, so this tool has no
/// code path that can compute it. Included from the file rather than retyped, so
/// the constant and the file cannot drift apart.
///
/// `CODEHASH` carries a comment header explaining why it is load-bearing, so the
/// value is the first line that is neither blank nor a comment — the same
/// parse the library's test vectors use.
fn pointer_code_hash() -> &'static str {
    include_str!("../../CODEHASH")
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .expect("CODEHASH must contain a hash line")
        .trim()
}

type R<T> = Result<T, String>;

fn main() {
    if let Err(e) = run() {
        eprintln!("pointer-record: {e}");
        std::process::exit(1);
    }
}

const USAGE: &str = "\
usage:
  pointer-record key    --author-vk VK --app-id ID
  pointer-record sign   --author-vk VK --app-id ID --version N --code-hash HASH  < keyfile
  pointer-record verify --author-vk VK --app-id ID --state STATE
                        [--expect-version N] [--expect-code-hash HASH] [--expect-key KEY]

  VK     author verifying key: 'app:v1:vk:<base58>', bare base58, or 64-char hex
  ID     app id, e.g. river.room-contract  (a-z 0-9 . - _ only, 1..=64 bytes)
  HASH   a code hash: 64-char hex or base58
  STATE  the 100-byte record: hex, or a path to a file holding the raw bytes
         ('-' reads raw bytes from stdin)

  sign reads the signing key from STDIN, never from a flag. A whole TOML key
  file is accepted: the value of the first 'signing_key' line is used.
";

fn run() -> R<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let opts = Opts::parse(&args[args.len().min(1)..])?;

    match cmd {
        "key" => cmd_key(&opts),
        "sign" => cmd_sign(&opts),
        "verify" => cmd_verify(&opts),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        "" => Err(format!("no subcommand given\n\n{USAGE}")),
        other => Err(format!("unknown subcommand '{other}'\n\n{USAGE}")),
    }
}

// ---------------------------------------------------------------- subcommands

fn cmd_key(o: &Opts) -> R<()> {
    let vk = o.author_vk()?;
    let app_id = o.app_id()?;
    let (key, params) = derive(&vk, app_id)?;
    println!("key={}", key.id());
    println!("params={}", to_hex(&params));
    Ok(())
}

fn cmd_sign(o: &Opts) -> R<()> {
    let expected_vk = o.author_vk()?;
    let app_id = o.app_id()?;
    let version = o.req_u32("--version")?;
    let code_hash = o.code_hash("--code-hash")?;

    let sk = read_signing_key_from_stdin()?;
    let actual_vk = sk.verifying_key();

    // See the module docs: this is the check that stops a drifted key file from
    // producing a record that is valid, unusable, and indistinguishable from a
    // good one until an integrator tries to verify it.
    if actual_vk.to_bytes() != expected_vk.to_bytes() {
        return Err(format!(
            "the signing key on stdin does NOT match --author-vk.\n\
             \x20 --author-vk (expected, from the app's FREENET.md): {}\n\
             \x20 stdin key derives to                             : {}\n\
             Refusing to sign. Either the key file is not the app's author key, or\n\
             FREENET.md publishes a key the app no longer signs with. Both are\n\
             worth stopping for.",
            to_hex(&expected_vk.to_bytes()),
            to_hex(&actual_vk.to_bytes()),
        ));
    }

    let (key, params) = derive(&actual_vk, app_id)?;
    let record = sign_record(&sk, &params, version, code_hash).map_err(|e| e.to_string())?;
    let bytes = record.encode();

    // Verify what we just produced, through the same path a consumer uses. If
    // signing and verification ever disagree, the publisher is the right place
    // to find out, not the network.
    PointerRecord::decode_verified(&bytes, &params)
        .map_err(|e| format!("BUG: freshly signed record does not verify: {e}"))?;

    println!("key={}", key.id());
    println!("params={}", to_hex(&params));
    println!("version={version}");
    println!("code_hash={}", to_hex(&code_hash));
    println!("state={}", to_hex(&bytes));
    Ok(())
}

fn cmd_verify(o: &Opts) -> R<()> {
    let vk = o.author_vk()?;
    let app_id = o.app_id()?;
    let state = o.state()?;
    let (key, params) = derive(&vk, app_id)?;

    let record = PointerRecord::decode_verified(&state, &params).map_err(|e| {
        format!(
            "record does not verify under author_vk={} app_id={}: {e}",
            to_hex(&vk.to_bytes()),
            String::from_utf8_lossy(app_id),
        )
    })?;

    // Every expectation is checked, and all mismatches are reported together.
    // Reporting only the first would send a caller round the loop once per
    // wrong field, and these are usually wrong together (a hand-edited hash
    // with the version left behind).
    let mut bad = Vec::new();
    if let Some(want) = o.opt_u32("--expect-version")? {
        if record.version != want {
            bad.push(format!(
                "version: expected {want}, record has {}",
                record.version
            ));
        }
    }
    if let Some(want) = o.opt_code_hash("--expect-code-hash")? {
        if record.code_hash != want {
            bad.push(format!(
                "code_hash: expected {}, record has {}",
                to_hex(&want),
                to_hex(&record.code_hash)
            ));
        }
    }
    if let Some(want) = o.get("--expect-key") {
        if key.id().to_string() != want {
            bad.push(format!("key: expected {want}, derives to {}", key.id()));
        }
    }
    if !bad.is_empty() {
        return Err(format!(
            "the record's SIGNATURE is valid, but it does not say what was expected:\n  {}",
            bad.join("\n  ")
        ));
    }

    println!("key={}", key.id());
    println!("version={}", record.version);
    println!("code_hash={}", to_hex(&record.code_hash));
    println!("verified=true");
    Ok(())
}

// ------------------------------------------------------------------- helpers

fn derive(vk: &VerifyingKey, app_id: &[u8]) -> R<(ContractKey, Vec<u8>)> {
    let params = PointerParams::encode(vk, app_id).map_err(|e| e.to_string())?;
    let key = ContractKey::from_params(pointer_code_hash(), Parameters::from(params.clone()))
        .map_err(|e| format!("deriving the pointer key from CODEHASH failed: {e}"))?;
    Ok((key, params))
}

/// Reads the signing key from stdin. Accepts a whole key file, so the caller
/// never has to extract the secret itself and risk it landing in a shell
/// variable or a temp file on the way.
fn read_signing_key_from_stdin() -> R<SigningKey> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("reading the signing key from stdin: {e}"))?;
    if buf.trim().is_empty() {
        return Err("no signing key on stdin (redirect a key file into this command)".into());
    }

    let token = match buf
        .lines()
        .find(|l| l.trim_start().starts_with("signing_key"))
    {
        Some(line) => line
            .split('=')
            .nth(1)
            .map(|v| v.trim().trim_matches('"').trim().to_string())
            .ok_or_else(|| "a 'signing_key' line was found but has no '= value'".to_string())?,
        None => buf.trim().to_string(),
    };

    let bytes = decode_key_material(&token, 32, "signing key")?;
    let arr: [u8; 32] = bytes.try_into().expect("length checked above");
    Ok(SigningKey::from_bytes(&arr))
}

/// Accepts the three shapes a 32-byte key is actually written in around this
/// ecosystem: a prefixed `app:v1:vk:<base58>` value, bare base58, or hex.
///
/// Hex is tried first and only for an exactly-64-character input, because the
/// base58 and hex alphabets overlap: a 64-character base58 string of the right
/// length would otherwise be silently decoded as hex into different bytes.
fn decode_key_material(s: &str, want: usize, what: &str) -> R<Vec<u8>> {
    let token = s.rsplit(':').next().unwrap_or(s).trim();
    if token.is_empty() {
        return Err(format!("empty {what}"));
    }

    if token.len() == want * 2 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return from_hex(token).map_err(|e| format!("{what}: {e}"));
    }

    let decoded = bs58::decode(token)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| format!("{what} is neither {}-char hex nor base58: {e}", want * 2))?;
    if decoded.len() != want {
        return Err(format!(
            "{what} decoded to {} bytes, expected {want}",
            decoded.len()
        ));
    }
    Ok(decoded)
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string has an odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// --------------------------------------------------------------- arg parsing

/// A deliberately small flag parser. The alternative is a `clap` dependency in
/// a crate whose manifest is a freeze surface (WASM-STABILITY.md), which is a
/// steep price for `--flag value`.
struct Opts(Vec<(String, String)>);

impl Opts {
    fn parse(args: &[String]) -> R<Self> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if !a.starts_with("--") {
                return Err(format!("unexpected argument '{a}'\n\n{USAGE}"));
            }
            // `--flag=value` and `--flag value` both work; a caller who mixes
            // them should not have to find out which one this tool wanted.
            if let Some((k, v)) = a.split_once('=') {
                out.push((k.to_string(), v.to_string()));
                i += 1;
            } else {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| format!("'{a}' needs a value\n\n{USAGE}"))?;
                out.push((a.clone(), v.clone()));
                i += 2;
            }
        }
        Ok(Self(out))
    }

    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
    }

    fn req(&self, k: &str) -> R<&str> {
        self.get(k).ok_or_else(|| format!("missing {k}\n\n{USAGE}"))
    }

    fn author_vk(&self) -> R<VerifyingKey> {
        let raw = self.req("--author-vk")?;
        let bytes = decode_key_material(raw, 32, "author verifying key")?;
        let arr: [u8; 32] = bytes.try_into().expect("length checked");
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("--author-vk is not a valid ed25519 verifying key: {e}"))
    }

    fn app_id(&self) -> R<&[u8]> {
        Ok(self.req("--app-id")?.as_bytes())
    }

    fn req_u32(&self, k: &str) -> R<u32> {
        self.req(k)?
            .parse()
            .map_err(|e| format!("{k} must be a u32: {e}"))
    }

    fn opt_u32(&self, k: &str) -> R<Option<u32>> {
        match self.get(k) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|e| format!("{k} must be a u32: {e}")),
        }
    }

    fn code_hash(&self, k: &str) -> R<[u8; 32]> {
        let raw = self.req(k)?;
        let bytes = decode_key_material(raw, 32, k)?;
        Ok(bytes.try_into().expect("length checked"))
    }

    fn opt_code_hash(&self, k: &str) -> R<Option<[u8; 32]>> {
        match self.get(k) {
            None => Ok(None),
            Some(_) => self.code_hash(k).map(Some),
        }
    }

    /// The record bytes: inline hex, a file of raw bytes, or `-` for stdin.
    fn state(&self) -> R<Vec<u8>> {
        let raw = self.req("--state")?;
        if raw == "-" {
            use std::io::Read;
            let mut b = Vec::new();
            std::io::stdin()
                .read_to_end(&mut b)
                .map_err(|e| format!("reading --state from stdin: {e}"))?;
            return Ok(b);
        }
        // A path is tried first: a file always wins over a same-named hex
        // string, and 200 hex characters is not a plausible filename.
        if std::path::Path::new(raw).is_file() {
            return std::fs::read(raw).map_err(|e| format!("reading --state file '{raw}': {e}"));
        }
        from_hex(raw.trim()).map_err(|e| format!("--state is neither a readable file nor hex: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constant every derivation in this tool hangs off. A truncated
    /// checkout, or an edit that left only the comment header behind, would
    /// otherwise surface as keys that are wrong rather than as an error.
    #[test]
    fn the_baked_in_code_hash_is_the_frozen_one() {
        let parsed = pointer_code_hash();
        assert!(!parsed.starts_with('#'), "parsed a comment line: {parsed}");
        let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/CODEHASH"))
            .expect("CODEHASH");
        let expected = raw
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .expect("a hash line")
            .trim();
        assert_eq!(parsed, expected);
        // It must be base58 of exactly 32 bytes, or every key derived from it
        // is silently addressing nothing.
        let bytes = bs58::decode(parsed).into_vec().expect("base58");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn hex_and_base58_key_material_decode_to_the_same_bytes() {
        let bytes = [0xAB_u8; 32];
        let hex = to_hex(&bytes);
        let b58 = bs58::encode(bytes).into_string();
        assert_eq!(decode_key_material(&hex, 32, "k").unwrap(), bytes);
        assert_eq!(decode_key_material(&b58, 32, "k").unwrap(), bytes);
        // And through a prefixed value, the form an app's key file actually uses.
        assert_eq!(
            decode_key_material(&format!("river:v1:vk:{b58}"), 32, "k").unwrap(),
            bytes
        );
    }

    /// The overlap that makes ordering matter: a 64-character base58 string is
    /// also a syntactically valid hex string only when every character happens
    /// to be a hex digit. Pin that hex wins for exactly-64 hex-only input, so
    /// the two alphabets can never silently swap a key's bytes.
    #[test]
    fn a_64_char_hex_string_is_read_as_hex_not_base58() {
        let bytes = [0x0a_u8; 32];
        let hex = to_hex(&bytes);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(decode_key_material(&hex, 32, "k").unwrap(), bytes);
    }

    #[test]
    fn a_key_file_yields_its_signing_key_line() {
        // Shape of the real file, comments and all.
        let file = "# River web container keys\n[keys]\nsigning_key = \"river:v1:sk:11111111111111111111111111111111\"\nverifying_key = \"river:v1:vk:xyz\"\n";
        let line = file
            .lines()
            .find(|l| l.trim_start().starts_with("signing_key"))
            .unwrap();
        let token = line.split('=').nth(1).unwrap().trim().trim_matches('"');
        assert_eq!(token, "river:v1:sk:11111111111111111111111111111111");
        assert_eq!(decode_key_material(token, 32, "sk").unwrap(), [0u8; 32]);
    }

    #[test]
    fn flags_parse_in_both_spellings() {
        let a = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        let o = Opts::parse(&a("--app-id river.room-contract --version 3")).unwrap();
        assert_eq!(o.get("--app-id"), Some("river.room-contract"));
        assert_eq!(o.req_u32("--version").unwrap(), 3);
        let o = Opts::parse(&a("--app-id=river.chat-delegate --version=7")).unwrap();
        assert_eq!(o.get("--app-id"), Some("river.chat-delegate"));
        assert_eq!(o.req_u32("--version").unwrap(), 7);
    }

    #[test]
    fn a_flag_with_no_value_is_an_error_rather_than_a_default() {
        let args = vec!["--app-id".to_string()];
        assert!(Opts::parse(&args).is_err());
    }

    /// The derivation this tool exists to keep honest: the key must come out of
    /// the frozen `CODEHASH` and the params, and must change when the app_id
    /// changes. If these ever collide, one app's record is addressable as
    /// another's.
    #[test]
    fn distinct_app_ids_derive_distinct_keys_under_one_author() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let vk = sk.verifying_key();
        let (a, pa) = derive(&vk, b"river.room-contract").unwrap();
        let (b, pb) = derive(&vk, b"river.chat-delegate").unwrap();
        assert_ne!(a.id().to_string(), b.id().to_string());
        assert_ne!(pa, pb);
    }

    #[test]
    fn a_signed_record_verifies_and_carries_what_was_asked_for() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let vk = sk.verifying_key();
        let (_k, params) = derive(&vk, b"river.room-contract").unwrap();
        let rec = sign_record(&sk, &params, 9, [0x5a; 32]).unwrap();
        let bytes = rec.encode();
        let back = PointerRecord::decode_verified(&bytes, &params).unwrap();
        assert_eq!(back.version, 9);
        assert_eq!(back.code_hash, [0x5a; 32]);
        // The same bytes under a different app's params must NOT verify: this is
        // the cross-app replay the params-covering signature is there to stop.
        let (_k2, other) = derive(&vk, b"river.chat-delegate").unwrap();
        assert!(PointerRecord::decode_verified(&bytes, &other).is_err());
    }
}
