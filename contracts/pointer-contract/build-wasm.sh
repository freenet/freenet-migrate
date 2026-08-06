#!/usr/bin/env bash
#
# Build the canonical pointer-contract WASM, reproducibly, and print its code
# hash.
#
# This is the ONLY supported way to build this artifact. A bare `cargo build`
# embeds absolute paths from your machine (panic locations name
# `$CARGO_HOME/registry/src/.../foo.rs`), so two developers get two different
# WASMs, two different code hashes, and two different pointer keys -- which is
# the exact failure this contract exists to prevent. See WASM-STABILITY.md.
#
#   ./build-wasm.sh          build, verify, print the code hash
#   ./build-wasm.sh --check  additionally fail if the hash moved from CODEHASH
set -euo pipefail

# Argument handling is strict on purpose. This used to be a bare
# `if [[ "${1:-}" == "--check" ]]`, so `-check`, `--check=1` and
# `--quiet --check` all built, printed, and exited 0 having compared nothing --
# a guard that cannot fail, in the guard the docs call the one that matters.
CHECK=0
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=1 ;;
        *)
            echo "FATAL: unknown argument '$arg' (expected nothing, or --check)" >&2
            exit 2
            ;;
    esac
done

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CRATE_DIR"

# Canonicalized: a trailing slash or a symlinked $HOME would make the remap
# prefix not match what rustc emits, producing different bytes while Guard 2
# still saw nothing under a known root.
CARGO_HOME_DIR="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"

# The build must not depend on the caller's environment. CARGO_ENCODED_RUSTFLAGS
# takes precedence over RUSTFLAGS (so invoking this from inside another cargo
# process would silently discard the remapping below), CARGO_INCREMENTAL changes
# codegen-unit partitioning, and a stray RUSTC_WRAPPER or CARGO_TARGET_DIR can
# change the output too. Each of these alters the bytes with no guard to notice.
unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_TARGET_DIR RUSTC_BOOTSTRAP
export CARGO_INCREMENTAL=0

# Set the release profile through the environment, which outranks any
# .cargo/config.toml up the tree or in $CARGO_HOME that would otherwise override
# the manifest's [profile.release].
export CARGO_PROFILE_RELEASE_OPT_LEVEL=s
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_PROFILE_RELEASE_STRIP=true

# Every path that can reach the binary is remapped to a fixed synthetic root, so
# the output does not depend on where the source or the registry happens to live.
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME_DIR}=/cargo --remap-path-prefix=${CRATE_DIR}=/crate"
# Belt and braces against any timestamp-sensitive step.
export SOURCE_DATE_EPOCH=0

# `--locked` is load-bearing: without it a missing or stale lockfile lets cargo
# re-resolve and pick different dependency versions, changing the bytes.
cargo build --release --target wasm32-unknown-unknown --locked --features freenet-main-contract

WASM="target/wasm32-unknown-unknown/release/freenet_pointer_contract.wasm"

# --- Guard 1: the four entry points the node calls must actually be exported,
# as real functions in the module's export section.
#
# Enabling `freenet-main-contract` without stdlib's `contract` feature (or vice
# versa) yields a ~150-byte WASM with no exports that a node loads happily and
# that does nothing. Catch that here, not in production.
#
# Deliberately parses the export section rather than grepping the bytes: a
# `grep` for "validate_state" would be satisfied by the name appearing anywhere
# at all -- in a panic message, a debug string, a data segment -- so it would
# keep passing after the exports themselves disappeared. That is a check that
# cannot fail for the reason it exists. (Python is used only here, in the build
# script; it is not a dependency of the artifact, so it cannot affect the bytes.)
python3 - "$WASM" <<'PY'
import re
import sys

data = open(sys.argv[1], "rb").read()
if data[:8] != b"\x00asm\x01\x00\x00\x00":
    sys.exit(f"FATAL: {sys.argv[1]} is not a WASM module")

def uleb(buf, i):
    result = shift = 0
    while True:
        byte = buf[i]; i += 1
        result |= (byte & 0x7F) << shift; shift += 7
        if not byte & 0x80:
            return result, i

funcs, memories, i = set(), set(), 8
while i < len(data):
    section_id = data[i]; i += 1
    size, i = uleb(data, i); end = i + size
    if section_id == 7:  # export section
        count, j = uleb(data, i)
        for _ in range(count):
            name_len, j = uleb(data, j)
            name = data[j:j + name_len].decode(); j += name_len
            kind = data[j]; j += 1
            _idx, j = uleb(data, j)
            (funcs if kind == 0 else memories if kind == 2 else set()).add(name)
    i = end

required = {"validate_state", "update_state", "summarize_state", "get_state_delta"}
missing = sorted(required - funcs)
if missing:
    sys.exit(
        f"FATAL: not exported as functions: {', '.join(missing)}\n"
        f"       exported functions were: {sorted(funcs)}\n"
        "       Check that the `freenet-main-contract` feature is enabled."
    )
if "memory" not in memories:
    sys.exit("FATAL: the module does not export `memory`; the node cannot call it")
print(f"exports:   OK ({len(required)} entry points + memory)")

# --- Guard 2: no path from the builder's machine may survive into the artifact.
#
# An ALLOW-list, not a deny-list. Listing suspicious roots (/home/, /Users/)
# only catches the ones somebody thought of: /root/, /build/, /workspace/,
# /builds/ and C:\Users\ would all sail through. Every absolute path in a
# correctly remapped build begins with one of the three synthetic roots below,
# so anything else is a leak by definition.
#
# Folded into this Python block on purpose. As a separate `if strings ... |
# grep`, a missing binutils made the whole guard exit non-zero and read as
# "clean" -- `set -e` does not fire inside an `if` condition. That is the same
# cannot-fail-for-its-own-reason shape as the old grep-based export check.
# /rust/ and /rustc/ come from the precompiled `std` that rustup ships, so they
# are fixed by the toolchain pin rather than by this machine. The deny-list this
# replaced never noticed them; the allow-list surfaced them immediately, which is
# the argument for the allow-list.
allowed = (b"/cargo/", b"/crate/", b"/rustc/", b"/rust/")
# Unix-style absolute paths only. An earlier version also matched a
# `C:\\Users\\` shape, but then discarded anything not starting with "/", so the
# Windows arm was dead code and the comment claiming it was covered was wrong.
# The toolchain is pinned to a Linux build and the artifact is produced by CI on
# ubuntu, so Windows paths cannot arise; saying so is better than a branch that
# looks like a check and is not one.
leaks = sorted({
    m.group(0)
    for m in re.finditer(rb"/[\w./-]{6,}", data)
    if not m.group(0).startswith(allowed) and m.group(0).count(b"/") >= 2
})
if leaks:
    shown = "\n".join(f"       {p.decode(errors='replace')}" for p in leaks[:10])
    sys.exit(
        "FATAL: build is not reproducible -- absolute paths leaked into the artifact:\n"
        f"{shown}\n"
        "       Every path must be under /cargo/, /crate/ or /rustc/.\n"
        "       Check --remap-path-prefix, and that CARGO_HOME has no trailing slash."
    )
print(f"paths:     OK (all absolute paths under {', '.join(a.decode() for a in allowed)})")
PY

# The code hash, computed by stdlib's own `CodeHash::from_code` so it is the
# same value a node derives, by construction rather than by reimplementation.
HASH="$(cargo run --quiet --release --locked --features publish --bin pointer-codehash -- "$WASM")"

echo
echo "wasm:      $CRATE_DIR/$WASM"
echo "size:      $(wc -c < "$WASM" | tr -d ' ') bytes"
echo "code hash: $HASH"

if [[ "$CHECK" == 1 ]]; then
    EXPECTED="$(grep -v '^#' CODEHASH | tr -d '[:space:]')"
    if [[ "$HASH" != "$EXPECTED" ]]; then
        cat >&2 <<EOF

FATAL: the pointer contract's code hash has changed.

  expected (CODEHASH): $EXPECTED
  built:               $HASH

This is not a routine test failure. This contract's key is
BLAKE3(code_hash || params); if the code hash moves, every published pointer
re-keys and every consumer that resolved through one is stranded -- with no
pointer left to point at the pointer.

Something changed the compiled bytes. In rough order of likelihood:

  * the source -- INCLUDING comments and whitespace, because Rust bakes
    panic-site file and line strings into the binary;
  * a dependency version (check `git diff Cargo.lock`);
  * the toolchain, cargo included, not just rustc (`rustup show active-toolchain`);
  * the build flags, or a `.cargo/config.toml` anywhere up the tree;
  * a registry protocol or mirror difference: `[source]` replacement,
    `[registries]`, or CARGO_REGISTRIES_* / CARGO_NET_GIT_FETCH_WITH_CLI, which
    change the embedded registry path strings.

Find out which, and revert it unless you are deliberately running the flag-day
process in WASM-STABILITY.md.
EOF
        exit 1
    fi
    echo "check:     OK (matches CODEHASH)"
fi
