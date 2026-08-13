//! Wherever this crate tells an adopter to wire the network's "not found" into
//! [`ProbeAnswer::Absent`], it must also say what that answer is worth.
//!
//! # Why a test reads the prose
//!
//! freenet-migrate#19 removed one unsafe equivalence — a predecessor's silence
//! read as its absence. The first fix for it introduced a second one in the
//! documentation: it named `ContractResponse::NotFound` as the thing to map to
//! `Absent`, and described the resulting `SeedLocal` as "safe to record the
//! migration as finished". On Freenet that is not true. Absence is
//! unauthenticated, and a contract that exists answers `NotFound` while it is
//! momentarily unfindable — measured at ~99.6% of all `get_not_found` traffic
//! while the placement migration is disabled (freenet-core#4440). So the fix
//! moved the data-loss trigger from a timeout to a dead-end rather than
//! removing it, and a review found thirteen mentions of `NotFound` across the
//! crate carrying zero caveats.
//!
//! That is a prose failure, so no ordinary test could catch it — the same gap
//! `pointer_docs_consistency.rs` exists to close for the floor rules.
//!
//! Both checks are POSITIVE ("must mention"), never negative ("must not
//! claim"). A negative check cannot tell an assertion from its denial: the
//! sentence that corrects a claim quotes it, so the check fires on the prose it
//! exists to protect, and the next person deletes the check or the caveat. Also
//! note both match against whitespace-NORMALIZED text -- a literal search is
//! defeated by the `///` line wrapping that prose is made of.
//!
//! This check is deliberately mechanical rather than an attempt to review
//! English: **a document that tells you to map `NotFound` to `Absent` must also
//! state that the answer is not proof.** That is enough to have failed on the
//! revision this closes, and an ordinary rewording does not trip it.

use std::path::{Path, PathBuf};

/// Prose surfaces that recommend the `NotFound` wiring. Paths are repo-relative.
///
/// Whole-document checks are right for these: the caveat is a property of the
/// document. `driver.rs` is checked per **doc block** instead — see
/// [`doc_block_before`] for why a whole-file check there is a false pass.
const WIRING_DOCS: &[&str] = &["README.md", "CHANGELOG.md"];

/// The claim the caveat has to make. Short and central enough that a rewrite
/// keeping the meaning keeps the phrase, and a rewrite dropping the meaning
/// drops it.
const CAVEAT: &str = "not proof";

fn repo_root() -> PathBuf {
    // `freenet-migrate/` -> repo root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate directory always has a parent")
        .to_path_buf()
}

/// The `///` doc block immediately preceding `marker`, normalized.
///
/// # Why a whole-file check on `driver.rs` is a false pass
///
/// The caveat is deliberately repeated: `ProbeAnswer::Absent` states it,
/// `on_absent` cross-references it, `Outcome::SeedLocal` relies on it. So
/// deleting it from the variant that *grants* the licence leaves the phrase in
/// the file twice, and a `src.contains(..)` check stays green while the site an
/// adopter actually reads has lost it.
///
/// That is not hypothetical: it was measured against the first version of this
/// file. Deleting the caveat from the `Absent` variant alone left both checks
/// passing, with two occurrences surviving elsewhere. A doc pin has to be
/// scoped to the block that carries the obligation.
fn doc_block_before(src: &str, marker: &str) -> String {
    let at = src
        .find(marker)
        .unwrap_or_else(|| panic!("{marker:?} moved; re-point this pin rather than deleting it"));
    let mut lines: Vec<&str> = Vec::new();
    for line in src[..at].lines().rev() {
        let t = line.trim_start();
        if t.starts_with("///") {
            lines.push(t);
        } else if t.is_empty() || t.starts_with("#[") {
            // Attributes and blank lines sit inside a declaration's preamble.
            continue;
        } else {
            break;
        }
    }
    lines.reverse();
    normalized(&lines.join("\n"))
}

/// Strip doc-comment markers and collapse all runs of whitespace to one space.
///
/// Without this, a phrase check is defeated by the line wrapping that prose is
/// *made of*: rustdoc splits a sentence across `///` lines wherever it happens
/// to reach the margin, so a literal substring search finds nothing and the
/// check passes vacuously. Measured: an earlier version of this file survived a
/// mutation that re-asserted the sealing claim, purely because the mutation's
/// wording wrapped one word earlier than the original's.
fn normalized(text: &str) -> String {
    let stripped: String = text
        .lines()
        .map(|line| {
            let l = line.trim_start();
            l.strip_prefix("//!")
                .or_else(|| l.strip_prefix("///"))
                .unwrap_or(l)
        })
        .collect::<Vec<_>>()
        .join(" ");
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn docs_that_recommend_the_notfound_wiring_say_it_is_not_proof() {
    let root = repo_root();
    let mut checked = 0usize;

    for rel in WIRING_DOCS {
        let path = root.join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} is a documented wiring surface: {e}", path.display()));
        let text = normalized(&raw);

        // Only text that actually names the stdlib variant is in scope; prose
        // that never recommends the mapping has no caveat to omit.
        if !text.contains("ContractResponse::NotFound") {
            continue;
        }
        checked += 1;

        assert!(
            text.contains(CAVEAT),
            "{rel} tells an adopter to map `ContractResponse::NotFound` to \
             `ProbeAnswer::Absent` without stating that the answer is {CAVEAT:?}. \
             On this network a contract that EXISTS answers NotFound while it is \
             momentarily unfindable (freenet-core#4440), so absence-by-answer is \
             evidence and not certainty. Text that recommends the wiring and omits \
             that is how freenet-migrate#19's data-loss shape came back with a \
             dead-end trigger instead of a timeout trigger."
        );
    }

    assert!(
        checked >= 2,
        "expected all {} wiring surfaces to name `ContractResponse::NotFound`, found {checked}. \
         If the guidance moved, move this check with it rather than letting it pass vacuously.",
        WIRING_DOCS.len()
    );
}

/// `driver.rs`, checked per doc block rather than per file.
///
/// Two blocks carry the obligation, for different reasons:
///
/// * `ProbeAnswer::Absent` is where the caveat is **stated**. It is the answer
///   an adapter constructs, so it is where the reliability of the answer
///   belongs.
/// * `Outcome::SeedLocal` is where the caveat is **cashed**. It is the doc an
///   adopter reads while writing the `match` arm that decides whether to stop
///   asking — and someone writing `Outcome::SeedLocal { local } => …` has no
///   reason to open `ProbeAnswer::Absent`'s docs. A caveat that lives only at
///   the definition site is a caveat the person making the decision never sees.
#[test]
fn the_absent_and_seed_local_doc_blocks_each_carry_the_caveat() {
    let root = repo_root();
    let driver = root.join("freenet-migrate/src/driver.rs");
    let src = std::fs::read_to_string(&driver).expect("driver.rs is the definition site");

    let absent = doc_block_before(&src, "    Absent,");
    assert!(
        absent.contains(CAVEAT),
        "`ProbeAnswer::Absent`'s own doc block no longer says the answer is {CAVEAT:?}. \
         This is the block that grants the answer its meaning; the caveat surviving \
         elsewhere in the file does not help an adapter reading this variant."
    );
    assert!(
        absent.contains("unauthenticated"),
        "`ProbeAnswer::Absent`'s doc lost the REASON the caveat holds — absence on \
         Freenet is unauthenticated, so any responding node can claim not-found. \
         Without the reason the caveat reads as boilerplate and gets trimmed."
    );

    let seed_local = doc_block_before(&src, "    SeedLocal {");
    // Deliberately NOT `contains(CAVEAT) || contains("ProbeAnswer::Absent")`.
    // A cross-reference link is not a caveat, and accepting one as a substitute
    // reopens the only drift that realistically happens here: rewrite the block
    // to re-assert that sealing is safe, delete the caveat, and leave the
    // `See [ProbeAnswer::Absent]` link untouched — nobody deletes a rustdoc link
    // that still resolves. The `||` form stays green through exactly that edit;
    // this form does not. Measured both ways.
    assert!(
        seed_local.contains(CAVEAT),
        "`Outcome::SeedLocal`'s doc block does not itself say the finding is {CAVEAT:?}. \
         A link to `ProbeAnswer::Absent` does not count: this is the doc an adopter reads \
         while writing the match arm that stops the migration asking, and someone writing \
         that arm has no reason to follow the link. The caveat has to be where the \
         conclusion is acted on, not only where the answer is defined."
    );
    assert!(
        seed_local.contains("freenet-migrate#8"),
        "`Outcome::SeedLocal`'s doc block does not point at freenet-migrate#8. \
         `decode -> None` and `is_real -> false` are misses too, so a schema break \
         across an ENTIRE lineage produces this outcome with every generation's data \
         intact underneath it."
    );
}
