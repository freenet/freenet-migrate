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

/// Surfaces that recommend the `NotFound` wiring. Paths are repo-relative.
const WIRING_DOCS: &[&str] = &["README.md", "CHANGELOG.md", "freenet-migrate/src/driver.rs"];

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

/// Strip doc-comment markers and collapse all runs of whitespace to one space.
///
/// Without this, a phrase check is defeated by the line wrapping that prose is
/// *made of*: rustdoc splits a sentence across `///` lines wherever it happens
/// to reach the margin, so a literal substring search finds nothing and the
/// check passes vacuously. Verified the hard way — the first version of the
/// sealing-claim check below survived a mutation that re-asserted the claim,
/// purely because the mutation's wording wrapped one word earlier.
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
        checked >= 3,
        "expected all {} wiring surfaces to name `ContractResponse::NotFound`, found {checked}. \
         If the guidance moved, move this check with it rather than letting it pass vacuously.",
        WIRING_DOCS.len()
    );
}

/// The other half: the outcome an app would seal on has to name the *other*
/// reason it is not conclusive — an undecodable answer is a miss too, so a
/// schema break across a whole lineage lands there with every generation intact
/// underneath (freenet-migrate#8).
///
/// # Why this is phrased as "must mention" and not "must not claim"
///
/// The obvious check is the negative one: assert the docs never say
/// `SeedLocal` is "safe to record the migration as finished". That does not
/// work, and it is worth writing down why rather than rediscovering it.
/// A substring search cannot tell an assertion from its denial — the sentence
/// that *corrects* the claim quotes the claim, so the negative check fires on
/// the very prose it was meant to protect. A check that goes red on correct
/// writing does not survive: the next person deletes it, or "fixes" it by
/// deleting the caveat. Positive assertions are the only durable shape for a
/// prose test.
#[test]
fn the_sealable_outcome_names_the_schema_break_that_also_lands_there() {
    let root = repo_root();
    let driver = root.join("freenet-migrate/src/driver.rs");
    let raw = std::fs::read_to_string(&driver).expect("driver.rs is the outcome's definition");
    let text = normalized(&raw);

    assert!(
        text.contains("SeedLocal"),
        "this check is pinned to `Outcome::SeedLocal`; if it was renamed, rename it here too"
    );
    assert!(
        text.contains("freenet-migrate#8"),
        "`driver.rs` documents `Outcome::SeedLocal` without pointing at \
         freenet-migrate#8. `ProbeStateOps::decode` returning `None` and `is_real` \
         returning `false` are both misses, so a schema break across an ENTIRE lineage \
         produces the same outcome as a genuinely empty one, with every generation's \
         data intact underneath it. An outcome an app may act on has to name that."
    );
}
