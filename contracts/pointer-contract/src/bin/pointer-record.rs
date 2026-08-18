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
use zeroize::Zeroizing;

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

/// Flags each subcommand accepts. Anything else is an ERROR, never ignored.
///
/// This list is the whole reason the parser is not three lines. A gate script
/// that misspells `--expect-code-hash` must fail, not quietly check one fewer
/// thing and print `verified=true`: the caller of `verify` is usually CI, and a
/// silently-relaxed expectation there is a gate that has stopped gating while
/// still reporting success. The same trap was found and fixed once already in
/// this crate's `build-wasm.sh`, whose `--check` used to accept `-check` and
/// `--check=1` and compare nothing.
const FLAGS_KEY: &[&str] = &["--author-vk", "--app-id"];
const FLAGS_SIGN: &[&str] = &["--author-vk", "--app-id", "--version", "--code-hash"];
const FLAGS_VERIFY: &[&str] = &[
    "--author-vk",
    "--app-id",
    "--state",
    "--expect-version",
    "--expect-code-hash",
    "--expect-key",
];

fn run() -> R<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => return Err(format!("no subcommand given\n\n{USAGE}")),
    };

    let allowed = match cmd {
        "key" => FLAGS_KEY,
        "sign" => FLAGS_SIGN,
        "verify" => FLAGS_VERIFY,
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            return Ok(());
        }
        other => return Err(format!("unknown subcommand '{other}'\n\n{USAGE}")),
    };

    let opts = Opts::parse(rest, allowed)?;
    match cmd {
        "key" => cmd_key(&opts),
        "sign" => cmd_sign(&opts),
        "verify" => cmd_verify(&opts),
        _ => unreachable!("allowed-flag lookup already rejected other subcommands"),
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
    for line in sign_record_lines(&sk, &expected_vk, app_id, version, code_hash)? {
        println!("{line}");
    }
    Ok(())
}

/// Everything `sign` does except read stdin and print, so it can be TESTED.
///
/// The vk-match refusal below is the property this tool leans on hardest, and
/// before this split no test could reach it: every test stopped one level lower,
/// at argument parsing. It was verified once, by hand, at a terminal. A refactor
/// could have dropped it with CI green.
fn sign_record_lines(
    sk: &SigningKey,
    expected_vk: &VerifyingKey,
    app_id: &[u8],
    version: u32,
    code_hash: [u8; 32],
) -> R<Vec<String>> {
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
    let record = sign_record(sk, &params, version, code_hash).map_err(|e| e.to_string())?;
    let bytes = record.encode();

    // Verify what we just produced, through the same path a consumer uses. If
    // signing and verification ever disagree, the publisher is the right place
    // to find out, not the network.
    PointerRecord::decode_verified(&bytes, &params)
        .map_err(|e| format!("BUG: freshly signed record does not verify: {e}"))?;

    Ok(vec![
        format!("key={}", key.id()),
        format!("params={}", to_hex(&params)),
        format!("version={version}"),
        format!("code_hash={}", to_hex(&code_hash)),
        format!("state={}", to_hex(&bytes)),
    ])
}

fn cmd_verify(o: &Opts) -> R<()> {
    let vk = o.author_vk()?;
    let app_id = o.app_id()?;
    let state = o.state()?;
    for line in verify_record_lines(
        &vk,
        app_id,
        &state,
        o.opt_u32("--expect-version")?,
        o.opt_code_hash("--expect-code-hash")?,
        o.get("--expect-key"),
    )? {
        println!("{line}");
    }
    Ok(())
}

/// Everything `verify` does except read arguments and print, so it can be
/// TESTED — in particular the rule that ALL `--expect-*` mismatches are
/// reported together rather than only the first. That behaviour was designed
/// deliberately and had no test; a regression to short-circuit on the first
/// mismatch would have shipped silently.
fn verify_record_lines(
    vk: &VerifyingKey,
    app_id: &[u8],
    state: &[u8],
    expect_version: Option<u32>,
    expect_code_hash: Option<[u8; 32]>,
    expect_key: Option<&str>,
) -> R<Vec<String>> {
    let (key, params) = derive(vk, app_id)?;

    let record = PointerRecord::decode_verified(state, &params).map_err(|e| {
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
    if let Some(want) = expect_version {
        if record.version != want {
            bad.push(format!(
                "version: expected {want}, record has {}",
                record.version
            ));
        }
    }
    if let Some(want) = expect_code_hash {
        if record.code_hash != want {
            bad.push(format!(
                "code_hash: expected {}, record has {}",
                to_hex(&want),
                to_hex(&record.code_hash)
            ));
        }
    }
    if let Some(want) = expect_key {
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

    Ok(vec![
        format!("key={}", key.id()),
        format!("version={}", record.version),
        format!("code_hash={}", to_hex(&record.code_hash)),
        "verified=true".to_string(),
    ])
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
    // `Zeroizing` so the key file's bytes are overwritten when this returns
    // rather than merely freed. See `signing_key_from_text`.
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("reading the signing key from stdin: {e}"))?;
    signing_key_from_text(&buf)
}

/// The whole key parse, separated from the reading so it can be TESTED.
///
/// It previously lived inside `read_signing_key_from_stdin`, which meant no
/// test could reach it — and the one test named after it re-implemented the
/// extraction inline and asserted that copy against itself, so the real
/// function could have been reverted to the buggy `split('=').nth(1)` with the
/// suite still green. An adversarial review caught that; this split is the fix.
fn signing_key_from_text(text: &str) -> R<SigningKey> {
    if text.trim().is_empty() {
        return Err("no signing key on stdin (redirect a key file into this command)".into());
    }

    // The key must be EXACTLY `signing_key`, not merely a line starting with
    // it: a `signing_key_backup = …` line sitting above the real one would
    // otherwise be picked instead, and the record comes out signed by the wrong
    // key. The `--author-vk` check downstream catches that, but only depending
    // on which key is which, and the error it prints does not point here.
    let token = Zeroizing::new(match text.lines().find(|l| is_signing_key_line(l)) {
        // `split_once`, not `split('=').nth(1)`: the latter silently truncates
        // at a second `=`, quietly mangling any padded encoding a key file
        // happens to use.
        Some(line) => line
            .split_once('=')
            .map(|(_, v)| unquote_toml_value(v))
            .ok_or_else(|| "a 'signing_key' line was found but has no '= value'".to_string())?,
        None => text.trim().to_string(),
    });

    reject_wrong_key_type(&token, "sk", "signing key")?;
    let bytes = Zeroizing::new(decode_key_material(&token, 32, "signing key")?);
    // `Zeroizing` on the ARRAY too, not only on the Vec it came from.
    // `try_into` for `[u8; 32]` is a memcpy into a fresh stack array, so this is
    // a second, independent copy of the raw private key — freed rather than
    // overwritten when the function returns, which is exactly what the rest of
    // this path exists to prevent. Caught in review after the first zeroize
    // pass wrapped everything else and missed it.
    //
    // The `SigningKey` this constructs is covered separately, by ed25519-dalek's
    // own zeroizing Drop (enabled through the `publish` feature).
    let arr = Zeroizing::new(<[u8; 32]>::try_from(bytes.as_slice()).expect("length checked above"));
    Ok(SigningKey::from_bytes(&arr))
}

/// Accepts the three shapes a 32-byte key is actually written in around this
/// ecosystem: a prefixed `app:v1:vk:<base58>` value, bare base58, or hex.
///
/// Hex is tried first and only for an exactly-64-character input, because the
/// base58 and hex alphabets overlap: a 64-character base58 string of the right
/// length would otherwise be silently decoded as hex into different bytes.
/// The value half of a `key = value` line, with quotes and any trailing comment
/// removed.
///
/// A quoted value ends at its CLOSING quote, so `"abc" # note` yields `abc` and
/// a `#` inside the quotes survives. Without that, the old
/// `trim().trim_matches('"').trim()` left `abc" # note` — the leading quote was
/// stripped, the trailing one was not there to strip, and the whole thing went
/// to the decoder. It failed loudly rather than silently, which is why nobody
/// noticed, but a trailing comment on a key line is an ordinary thing to write.
fn unquote_toml_value(v: &str) -> String {
    let v = v.trim();
    if let Some(rest) = v.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => rest[..end].to_string(),
            None => rest.trim().to_string(),
        };
    }
    match v.split_once('#') {
        Some((before, _)) => before.trim().to_string(),
        None => v.to_string(),
    }
}

/// True only for a real `signing_key = …` line, never for `signing_key_backup`.
fn is_signing_key_line(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("signing_key")
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// Refuse a value whose own type tag says it is something else.
///
/// A verifying key and a signing key are both 32 bytes, both base58, and in
/// these key files they sit on adjacent lines differing by three letters. Two
/// things follow, and the second is the serious one:
///
/// * `VerifyingKey::from_bytes` rejects a non-point, so passing a signing key
///   as `--author-vk` errors only about half the time — the rest of the time it
///   derives a plausible key for a pointer nobody will ever query.
/// * `--author-vk river:v1:sk:…` would put a PRIVATE KEY on `argv`, where it is
///   visible in `ps` and lands in shell history. This tool reads the signing key
///   from stdin precisely so that cannot happen; ignoring an `sk` tag in a flag
///   would leave the same hole open through the front door.
///
/// Untagged values (bare base58, or hex) are unaffected: the tag is checked
/// only when the caller actually supplied one.
fn reject_wrong_key_type(s: &str, want_tag: &str, what: &str) -> R<()> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 2 {
        return Ok(()); // untagged; nothing claimed, so nothing to contradict
    }
    let tag = parts[parts.len() - 2];
    if !matches!(tag, "vk" | "sk" | "sig") || tag == want_tag {
        return Ok(());
    }
    if tag == "sk" {
        return Err(format!(
            "refusing to read a SIGNING key as the {what}: the value is tagged ':sk:'.\n\
             A private key must never be passed as a flag - it is visible in `ps` to\n\
             every user on this machine and lands in your shell history. Pass the\n\
             VERIFYING key (':vk:') here; the signing key is read from stdin."
        ));
    }
    Err(format!(
        "the value given for the {what} is tagged ':{tag}:', not ':{want_tag}:'"
    ))
}

fn decode_key_material(s: &str, want: usize, what: &str) -> R<Vec<u8>> {
    let token = s.rsplit(':').next().unwrap_or(s).trim();
    if token.is_empty() {
        return Err(format!("empty {what}"));
    }

    if token.len() == want * 2 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return from_hex(token).map_err(|e| format!("{what}: {e}"));
    }

    // The decoder's own error names the offending CHARACTER — bs58 0.5's
    // `InvalidCharacter` Display prints it literally. For a public value that
    // is helpful; for the SIGNING KEY it puts one character of the secret on
    // stderr, where CI captures it. So secret-bearing callers get a message
    // that says what is wrong without quoting the input.
    let decoded = bs58::decode(token)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| {
            if what.contains("signing key") {
                format!("{what} is neither {}-char hex nor valid base58", want * 2)
            } else {
                format!("{what} is neither {}-char hex nor base58: {e}", want * 2)
            }
        })?;
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

/// Decode hex, rejecting anything that is not hex rather than panicking on it.
///
/// The alphabet is checked BEFORE any slicing, and the slicing is then done on
/// bytes. `&s[i..i + 2]` on a `&str` panics when `i + 2` lands inside a
/// multi-byte character, and `"\u{20AC}1"` ("EUR1") is four bytes, so it passes
/// an even-length check and then panics on the first slice. `--state` and
/// `--code-hash` are exactly the arguments that carry untrusted or
/// copy-pasted text, so this has to be a clean error.
///
/// A panic here fails closed — a CI gate sees a non-zero exit either way — but
/// "byte index 2 is not a char boundary" tells the person reading the log
/// nothing about what they actually typed wrong.
fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(format!("hex string has an odd length ({} chars)", b.len()));
    }
    if let Some(bad) = b.iter().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!(
            "not a hex string: contains the byte 0x{bad:02x}, which is not a hex digit"
        ));
    }
    Ok(b.chunks_exact(2)
        .map(|p| {
            // Both bytes are ASCII hex digits, checked above, so neither
            // conversion can fail.
            let hi = (p[0] as char).to_digit(16).expect("checked ascii hex");
            let lo = (p[1] as char).to_digit(16).expect("checked ascii hex");
            (hi * 16 + lo) as u8
        })
        .collect())
}

// --------------------------------------------------------------- arg parsing

/// A deliberately small flag parser. The alternative is a `clap` dependency in
/// a crate whose manifest is a freeze surface (WASM-STABILITY.md), which is a
/// steep price for `--flag value`.
struct Opts(Vec<(String, String)>);

impl Opts {
    /// Parses `--flag value` / `--flag=value` pairs, rejecting anything the
    /// subcommand did not ask for.
    ///
    /// Both rejections matter and neither is pedantry:
    ///
    /// * **Unknown flags** would otherwise be collected and never looked at, so
    ///   a typo'd `--expect-code-hash` silently removes a check while `verify`
    ///   still exits 0.
    /// * **Duplicate flags** are ambiguous — a caller writing one twice means
    ///   "last wins", `get` returns the FIRST, and the two readings differ
    ///   exactly when it matters. There is no reading that is safe to guess, so
    ///   this refuses instead of picking one.
    fn parse(args: &[String], allowed: &[&str]) -> R<Self> {
        let mut out: Vec<(String, String)> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if !a.starts_with("--") {
                return Err(format!("unexpected argument '{a}'\n\n{USAGE}"));
            }
            // `--flag=value` and `--flag value` both work; a caller who mixes
            // them should not have to find out which one this tool wanted.
            let (k, v) = if let Some((k, v)) = a.split_once('=') {
                i += 1;
                (k.to_string(), v.to_string())
            } else {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| format!("'{a}' needs a value\n\n{USAGE}"))?;
                i += 2;
                (a.clone(), v.clone())
            };
            if !allowed.contains(&k.as_str()) {
                return Err(format!(
                    "unknown flag '{k}' for this subcommand.\n\
                     Accepted here: {}\n\n{USAGE}",
                    allowed.join(" ")
                ));
            }
            if out.iter().any(|(existing, _)| *existing == k) {
                return Err(format!(
                    "'{k}' given more than once. Refusing to guess which one you meant."
                ));
            }
            out.push((k, v));
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
        reject_wrong_key_type(raw, "vk", "author verifying key")?;
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

    /// Found by an adversarial review: `&s[i..i + 2]` on a `&str` panics when
    /// the index lands inside a multi-byte character. "EUR1" is four bytes, so
    /// it passed the even-length check and then panicked — reachable from
    /// `--state`, which is exactly where copy-pasted or network-sourced text
    /// arrives.
    #[test]
    fn multibyte_input_is_an_error_not_a_panic() {
        for bad in [
            "\u{20AC}1",
            "\u{20AC}\u{20AC}",
            "z\u{00E9}",
            "\u{00E9}\u{00E9}",
        ] {
            let err = from_hex(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} must not decode as hex"));
            assert!(!err.is_empty());
        }
        // And the same input through the public entry points, which is how it
        // would actually arrive.
        assert!(decode_key_material("\u{20AC}1", 32, "k").is_err());
    }

    #[test]
    fn non_hex_ascii_is_rejected_with_a_useful_message() {
        let err = from_hex("zz").expect_err("zz is not hex");
        assert!(err.contains("not a hex digit"), "{err}");
        // Odd length is still its own distinct error.
        let err = from_hex("abc").expect_err("odd length");
        assert!(err.contains("odd length"), "{err}");
    }

    /// Uppercase hex must decode identically — a code hash pasted from a tool
    /// that renders uppercase is not a different value.
    #[test]
    fn hex_is_case_insensitive() {
        assert_eq!(from_hex("DEADbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
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

    /// Found by an adversarial review: `starts_with("signing_key")` also matched
    /// `signing_key_backup`, so a key file carrying a backup line above the real
    /// one signed with the WRONG key. The `--author-vk` check downstream happened
    /// to catch it, but only depending on which key was which.
    #[test]
    fn a_signing_key_line_is_matched_exactly_not_by_prefix() {
        let file = "[keys]\nsigning_key_backup = \"river:v1:sk:1111\"\nsigning_key = \"river:v1:sk:2222\"\n";
        let picked = file
            .lines()
            .find(|l| is_signing_key_line(l))
            .expect("the real signing_key line");
        assert!(picked.contains("2222"), "picked the backup line: {picked}");
        assert!(!is_signing_key_line("signing_key_backup = \"x\""));
        assert!(!is_signing_key_line("# signing_key = \"x\""));
        assert!(is_signing_key_line("  signing_key   =  \"x\""));
    }

    /// A verifying key and a signing key are both 32 base58 bytes and sit on
    /// adjacent lines of the same file. Passing the private one as `--author-vk`
    /// would put it on argv, where `ps` and shell history can see it — the exact
    /// exposure the stdin-only design exists to prevent.
    #[test]
    fn a_signing_key_is_refused_where_a_verifying_key_is_expected() {
        let err = reject_wrong_key_type("river:v1:sk:1111", "vk", "author verifying key")
            .expect_err("an sk-tagged value must be refused as a vk");
        assert!(err.contains("SIGNING key"), "{err}");
        // The right tag passes, and so does an untagged value: the tag is
        // consulted only when the caller actually supplied one.
        assert!(reject_wrong_key_type("river:v1:vk:1111", "vk", "x").is_ok());
        assert!(reject_wrong_key_type("1111", "vk", "x").is_ok());
        assert!(reject_wrong_key_type("deadbeef", "vk", "x").is_ok());
        // ...and the mirror direction, so a vk cannot be fed in as the key.
        assert!(reject_wrong_key_type("river:v1:vk:1111", "sk", "signing key").is_err());
    }

    /// Replaces a test that carried this name and was VACUOUS: it never called
    /// `read_signing_key_from_stdin`, it re-implemented the extraction inline
    /// with `split('=').nth(1)` — the very pattern the production code had just
    /// been fixed away from — and asserted that copy against itself. Reverting
    /// the real `split_once('=')` left it green. Found by an adversarial review;
    /// `signing_key_from_text` was split out of the stdin read so a test can
    /// reach the real thing.
    #[test]
    fn a_key_file_yields_the_signing_key_the_real_parser_finds() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let b58 = bs58::encode(sk.to_bytes()).into_string();
        let file = format!(
            "# River web container keys\n[keys]\nsigning_key = \"river:v1:sk:{b58}\"\nverifying_key = \"river:v1:vk:zzz\"\n"
        );
        let got = signing_key_from_text(&file).expect("the real parser must read this file");
        assert_eq!(got.to_bytes(), sk.to_bytes());

        // A bare token with no TOML around it, the other accepted shape.
        assert_eq!(
            signing_key_from_text(&b58).unwrap().to_bytes(),
            sk.to_bytes()
        );
        // Empty input is refused BY THE EARLY CHECK, asserted on its specific
        // message. `decode_key_material` would also reject an empty token, so a
        // bare `is_err()` here would still pass with the early check deleted --
        // it would just say something less useful.
        let err = signing_key_from_text("   \n\t ").expect_err("empty input must be refused");
        assert!(err.contains("no signing key on stdin"), "{err}");
    }

    /// Pins `unquote_toml_value`'s quote/comment handling.
    ///
    /// **This test was originally named and documented as pinning the
    /// `split_once('=')` vs `split('=').nth(1)` distinction, and that was
    /// wrong.** A reviewer re-ran the mutation properly — changing ONLY the
    /// split and keeping `unquote_toml_value` — and the suite stayed green. My
    /// own "mutation verified" run had replaced the whole expression, including
    /// the call to `unquote_toml_value`, so the red I saw came from reverting
    /// the helper, not the split.
    ///
    /// The distinction really is subsumed: `unquote_toml_value` ends a quoted
    /// value at its closing quote, and neither hex nor base58 contains `=`, so
    /// for every input this tool accepts the quote is found before any second
    /// `=` and the earlier truncation removes nothing that would have survived.
    /// `split_once` is kept because it is clearer and correct for an unquoted
    /// value, not because a test defends it.
    ///
    /// What this test actually defends is the helper: revert its quoted branch
    /// to `trim_matches('"')` and this goes red.
    #[test]
    fn a_quoted_signing_key_value_survives_a_trailing_comment() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let hex: String = sk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        // A trailing comment introduces the second `=`.
        let file = format!("signing_key = \"{hex}\" # rotated, v=2\n");
        // Quoted, so the value ends at the closing quote and the comment is
        // dropped -- the point is that the parse does not stop at the second `=`.
        let got = signing_key_from_text(&file);
        assert!(got.is_ok(), "{:?}", got.err());
        assert_eq!(got.unwrap().to_bytes(), sk.to_bytes());

        // Unquoted with a trailing comment, and a `#` INSIDE quotes, which must
        // survive because it is part of the value rather than a comment.
        assert_eq!(unquote_toml_value(" abc # note "), "abc");
        assert_eq!(unquote_toml_value(" \"ab#cd\" # note "), "ab#cd");
        assert_eq!(unquote_toml_value(" plain "), "plain");
    }

    /// A decode failure on the SIGNING KEY must not quote the input.
    ///
    /// bs58 0.5's `InvalidCharacter` Display prints the offending character
    /// literally, so an unfiltered error puts one character of the secret on
    /// stderr, where CI captures it. Public values keep the detail, because for
    /// them it is genuinely useful — so this asserts BOTH directions, and a fix
    /// that simply redacted everything would fail the second half.
    #[test]
    fn a_decode_failure_never_quotes_the_signing_key() {
        // '0' is not in the Bitcoin base58 alphabet, so this fails to decode.
        let secret_ish = "0OIl_not_base58_and_not_hex";
        let err = decode_key_material(secret_ish, 32, "signing key").expect_err("must not decode");
        assert!(
            !err.contains('0') || !err.contains("provided string contained"),
            "the signing-key error must not carry bs58's character detail: {err}"
        );
        assert!(err.contains("neither"), "{err}");

        // The same input as a PUBLIC value keeps the detailed message.
        let pub_err = decode_key_material(secret_ish, 32, "author verifying key")
            .expect_err("must not decode");
        assert!(
            pub_err.len() > err.len(),
            "public values should keep the detail the secret path drops:\n  secret: {err}\n  public: {pub_err}"
        );
    }

    /// THE property this tool leans on hardest, and it had no test at all:
    /// `sign` must refuse when the key it was handed does not derive the
    /// `--author-vk` the caller supplied. Verified once by hand before; now
    /// pinned.
    #[test]
    fn sign_refuses_when_the_key_does_not_match_the_author_vk() {
        let real = SigningKey::from_bytes(&[1u8; 32]);
        let other = SigningKey::from_bytes(&[2u8; 32]);
        let err = sign_record_lines(
            &real,
            &other.verifying_key(),
            b"river.room-contract",
            1,
            [0xaa; 32],
        )
        .expect_err("signing with a key that does not match --author-vk must be refused");
        assert!(err.contains("does NOT match --author-vk"), "{err}");

        // ...and the matching case still produces a record, so the test above
        // is about the mismatch and not about signing being broken outright.
        let ok = sign_record_lines(
            &real,
            &real.verifying_key(),
            b"river.room-contract",
            1,
            [0xaa; 32],
        )
        .expect("a matching key must sign");
        assert!(ok.iter().any(|l| l.starts_with("state=")));
    }

    /// `verify` reports EVERY `--expect-*` mismatch, not just the first. That
    /// was a deliberate design choice with no test, so a regression to
    /// short-circuit would have shipped silently.
    #[test]
    fn verify_reports_all_expectation_mismatches_together() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let vk = sk.verifying_key();
        let (key, params) = derive(&vk, b"river.room-contract").unwrap();
        let state = sign_record(&sk, &params, 4, [0x11; 32]).unwrap().encode();

        let err = verify_record_lines(
            &vk,
            b"river.room-contract",
            &state,
            Some(9),          // wrong
            Some([0x22; 32]), // wrong
            Some("nope"),     // wrong
        )
        .expect_err("three wrong expectations must fail");
        assert!(err.contains("version:"), "{err}");
        assert!(err.contains("code_hash:"), "{err}");
        assert!(err.contains("key:"), "{err}");

        // All three correct -> verified, so the assertions above are about the
        // expectations and not about verification failing for another reason.
        let ok = verify_record_lines(
            &vk,
            b"river.room-contract",
            &state,
            Some(4),
            Some([0x11; 32]),
            Some(&key.id().to_string()),
        )
        .expect("matching expectations must verify");
        assert!(ok.contains(&"verified=true".to_string()));

        // A tampered signature is refused regardless of expectations.
        let mut bad = state;
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(verify_record_lines(&vk, b"river.room-contract", &bad, None, None, None).is_err());
    }

    /// The published TEST-VECTORS.md values, driven through THIS TOOL's own
    /// code path rather than the library's.
    ///
    /// The library already pins those vectors, but through `sign_record` /
    /// `ContractKey::from_params` directly — never through the binary's hex
    /// formatting or its `state=` output. So the tool's agreement with the
    /// document was established once, by hand, and nothing would have caught a
    /// later divergence in casing, field order or encoding.
    #[test]
    fn the_tool_reproduces_the_published_test_vectors() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let vk = sk.verifying_key();
        assert_eq!(
            to_hex(&vk.to_bytes()),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        let lines =
            sign_record_lines(&sk, &vk, b"river.room-contract", 7, [0xaa; 32]).expect("sign");
        let get = |k: &str| {
            lines
                .iter()
                .find_map(|l| l.strip_prefix(k))
                .unwrap_or_else(|| panic!("no {k} line"))
                .to_string()
        };
        assert_eq!(get("key="), "Hjus5Fnb6NWxKGN64MQwmbgk1Vd6YojykLtxnXipR6Lx");
        assert_eq!(
            get("params="),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c\
             72697665722e726f6f6d2d636f6e7472616374"
                .replace(['\n', ' '], "")
        );
        assert_eq!(
            get("state="),
            "00000007\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             ee3c33cf7bac4f2c2dc4d3a0eff2300a12174d44084f340d6d68c98d63a63953\
             5fece9eed85c2218af2ba566bda24f4c63ec2fca140f6a35bc6230811f27a10d"
                .replace(['\n', ' '], "")
        );
        // And the document's own file agrees, so this cannot drift from it
        // without one of the two failing.
        let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/TEST-VECTORS.md"))
            .expect("TEST-VECTORS.md");
        let compact: String = doc.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            compact.contains(&get("state=")),
            "state not in TEST-VECTORS.md"
        );
        assert!(compact.contains("Hjus5Fnb6NWxKGN64MQwmbgk1Vd6YojykLtxnXipR6Lx"));
    }

    #[test]
    fn flags_parse_in_both_spellings() {
        let a = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        let o = Opts::parse(&a("--app-id river.room-contract --version 3"), FLAGS_SIGN).unwrap();
        assert_eq!(o.get("--app-id"), Some("river.room-contract"));
        assert_eq!(o.req_u32("--version").unwrap(), 3);
        let o = Opts::parse(&a("--app-id=river.chat-delegate --version=7"), FLAGS_SIGN).unwrap();
        assert_eq!(o.get("--app-id"), Some("river.chat-delegate"));
        assert_eq!(o.req_u32("--version").unwrap(), 7);
    }

    #[test]
    fn a_flag_with_no_value_is_an_error_rather_than_a_default() {
        let args = vec!["--app-id".to_string()];
        assert!(Opts::parse(&args, FLAGS_SIGN).is_err());
    }

    /// The gate-goes-vacuous case, and the reason the allowed-flag lists exist.
    ///
    /// A CI script that misspells `--expect-code-hash` must FAIL. Before this
    /// was enforced, the unknown flag was collected, never read, and `verify`
    /// printed `verified=true` having checked one fewer thing than the author
    /// believed — a gate reporting success while no longer gating.
    #[test]
    fn a_misspelled_expectation_is_rejected_rather_than_ignored() {
        let a = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        let err = Opts::parse(&a("--app-id x --expect-codehash deadbeef"), FLAGS_VERIFY)
            .err()
            .expect("a misspelled expectation must not parse");
        assert!(err.contains("--expect-codehash"), "{err}");

        // Correctly spelled, it parses — so the test above is about the typo and
        // not about the flag being unsupported outright.
        assert!(Opts::parse(&a("--app-id x --expect-code-hash deadbeef"), FLAGS_VERIFY).is_ok());
    }

    /// A flag the subcommand does not take is an error even when another
    /// subcommand accepts it: `verify` must not silently swallow `--version`
    /// (whose `verify` spelling is `--expect-version`).
    #[test]
    fn a_flag_belonging_to_another_subcommand_is_rejected() {
        let a = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert!(Opts::parse(&a("--version 3"), FLAGS_SIGN).is_ok());
        assert!(Opts::parse(&a("--version 3"), FLAGS_VERIFY).is_err());
    }

    /// "Last wins" and "first wins" differ exactly when a caller has made a
    /// mistake, so neither is safe to guess.
    #[test]
    fn a_duplicated_flag_is_refused_rather_than_resolved() {
        let a = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        let err = Opts::parse(&a("--expect-version 7 --expect-version 999"), FLAGS_VERIFY)
            .err()
            .expect("a duplicated flag must not parse");
        assert!(err.contains("more than once"), "{err}");
        // Mixed spellings are still the same flag.
        assert!(Opts::parse(&a("--app-id=a --app-id b"), FLAGS_KEY).is_err());
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
