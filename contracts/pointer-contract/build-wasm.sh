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

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CRATE_DIR"

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

# Every path that can reach the binary is remapped to a fixed synthetic root, so
# the output does not depend on where the source or the registry happens to live.
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME_DIR}=/cargo --remap-path-prefix=${CRATE_DIR}=/crate"
# Belt and braces against any timestamp-sensitive step.
export SOURCE_DATE_EPOCH=0

# `--locked` is load-bearing: without it a missing or stale lockfile lets cargo
# re-resolve and pick different dependency versions, changing the bytes.
cargo build --release --target wasm32-unknown-unknown --locked

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
PY

# --- Guard 2: no absolute paths from this machine may survive into the artifact.
if strings "$WASM" | grep -qE "${CARGO_HOME_DIR}|${CRATE_DIR}|/home/|/Users/"; then
    echo "FATAL: build is not reproducible -- absolute paths leaked into $WASM:" >&2
    strings "$WASM" | grep -oE "(${CARGO_HOME_DIR}|${CRATE_DIR}|/home/|/Users/)[^ ]*" | head >&2
    exit 1
fi

# The code hash, computed by stdlib's own `CodeHash::from_code` so it is the
# same value a node derives, by construction rather than by reimplementation.
HASH="$(cargo run --quiet --release --features publish --bin pointer-codehash -- "$WASM")"

echo
echo "wasm:      $CRATE_DIR/$WASM"
echo "size:      $(stat -c%s "$WASM") bytes"
echo "code hash: $HASH"

if [[ "${1:-}" == "--check" ]]; then
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

Something changed the compiled bytes: the source, a dependency version, the
pinned toolchain, or the build flags. Find out which, and revert it unless you
are deliberately running the flag-day process in WASM-STABILITY.md.
EOF
        exit 1
    fi
    echo "check:     OK (matches CODEHASH)"
fi
