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

# --- Guard 1: the four entry points the node calls must actually be exported.
# Enabling `freenet-main-contract` without stdlib's `contract` feature (or vice
# versa) yields a ~150-byte WASM with no exports that loads fine and does
# nothing. Catch that here, not in production.
for sym in validate_state update_state summarize_state get_state_delta; do
    if ! grep -qa "$sym" "$WASM"; then
        echo "FATAL: '$sym' is not exported by $WASM" >&2
        exit 1
    fi
done

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
