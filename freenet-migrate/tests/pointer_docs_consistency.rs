//! The pointer resolver's safety rules live in prose as much as in code, and
//! they are written down in two places: this crate's README and the pointer
//! contract's own README. That is a drift surface, and it drifted.
//!
//! `PointerFloor::at` refuses an all-zero code hash, so a withdrawal floor can
//! only be rebuilt through `PointerFloor::withdrawn_at`. The contract README
//! kept instructing integrators to store a tombstone as an ordinary floor with
//! a zeroed hash column — advice the constructor now rejects, whose natural
//! recovery (`unwrap_or_else(|_| PointerFloor::never_resolved())`) fails **open**
//! into the baked-in key and re-opens the resurrection the withdrawal floor
//! exists to close. Nothing in CI noticed, because no test reads the prose.
//!
//! So this does. It is deliberately a weak, mechanical check rather than an
//! attempt to review English: a document that discusses tombstone floors at all
//! must name the constructor that builds one. That is enough to have failed on
//! the drifted revision, and it is not the kind of assertion an ordinary
//! rewording trips.

use std::path::{Path, PathBuf};

/// Docs that carry the floor-persistence rules. Paths are repo-relative.
const FLOOR_DOCS: &[&str] = &["README.md", "contracts/pointer-contract/README.md"];

fn repo_root() -> PathBuf {
    // `freenet-migrate/` -> repo root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate directory always has a parent")
        .to_path_buf()
}

#[test]
fn docs_that_discuss_tombstone_floors_name_the_constructor_that_builds_one() {
    let root = repo_root();
    let mut checked = 0usize;

    for rel in FLOOR_DOCS {
        let path = root.join(rel);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{} is a documented floor rule surface: {e}", path.display())
        });

        // Only documents that actually discuss withdrawal are in scope; a doc
        // that never mentions it has no rule to get wrong.
        if !text.contains("tombstone") {
            continue;
        }
        checked += 1;

        assert!(
            text.contains("withdrawn_at"),
            "{rel} explains tombstone floors without naming `PointerFloor::withdrawn_at`. \
             A withdrawal floor cannot be rebuilt any other way -- `PointerFloor::at` rejects \
             the all-zero hash -- so guidance that omits it sends integrators to a call that \
             fails, and the obvious recovery from that failure re-opens the resurrection the \
             withdrawal floor prevents."
        );

        // Wherever the ordinary constructor is named, its withdrawal sibling
        // has to be named too: presenting `at` as *the* way to rebuild a floor
        // is exactly how the rejected zeroed-hash advice got written.
        if text.contains("PointerFloor::at") {
            assert!(
                text.contains("PointerFloor::withdrawn_at"),
                "{rel} names `PointerFloor::at` without its withdrawal sibling. \
                 The two constructors are a pair; documenting one alone is what produced \
                 the guidance that told integrators to store a tombstone as a zeroed floor."
            );
        }
    }

    assert!(
        checked >= 2,
        "expected both floor-rule documents to discuss tombstones, found {checked}. \
         If the prose moved, move this check with it rather than letting it pass vacuously."
    );
}
