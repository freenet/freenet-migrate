# WASM stability

**This contract's compiled bytes must not change.** Not "should rarely change" —
must not.

Everything else in the ecosystem has a recovery layer above it. An app contract
that re-keys is recoverable through its pointer. A pointer that re-keys has
nothing pointing at it. Every consumer that resolved through it is stranded, and
there is no second level of indirection to consult.

So the code hash in [`CODEHASH`](CODEHASH) is a **published spec constant**,
embedded verbatim in consumer code, not something anyone recomputes.

## What can change the bytes, and what stops it

| Cause | Guard |
|---|---|
| Source edits — **including comments and whitespace** | Review. Any PR touching `src/` must justify why re-keying the whole ecosystem is worth it. See "Even formatting moves the hash" below. |
| A dependency picking a newer semver-compatible release | Exact `=` pins in `Cargo.toml`, plus a committed `Cargo.lock`, plus `--locked` in `build-wasm.sh`. A caret range would let a fresh resolve on a machine without the lockfile change the bytes. |
| A transitive dependency drifting | The committed `Cargo.lock` pins the entire graph, not just the direct dependencies. |
| A dependency bump elsewhere in this repository | This crate is **not** a workspace member. It declares its own empty `[workspace]`, so it has its own `Cargo.lock` that a bump in `freenet-migrate` cannot perturb. |
| A different rustc | `rust-toolchain.toml` pins `1.96.0`, matching the repository CI. |
| Different build flags | `[profile.release]` is pinned in `Cargo.toml`; `build-wasm.sh` is the only supported build path. |
| Absolute paths from the builder's machine | `build-wasm.sh` sets `--remap-path-prefix` for both `$CARGO_HOME` and the crate directory, then **fails** if any absolute path survives into the artifact. Verified: building the same source from two unrelated directory paths yields byte-identical output. |
| A half-configured feature set | `build-wasm.sh` fails unless all four entry points are exported. Enabling `freenet-main-contract` without stdlib's `contract` feature silently produces a ~150-byte WASM with no exports, which loads fine and does nothing. |
| Any of the above slipping through anyway | CI runs `./build-wasm.sh --check`, which rebuilds and fails if the hash moved from `CODEHASH`. This is the backstop: it does not care *why* the bytes changed. |

That last row is the one that matters. The others are best-effort; the rebuild
check is the one that cannot be reasoned around.

## Even formatting moves the hash

Observed while building this crate: running `cargo fmt` changed the code hash,
with no semantic change whatsoever.

Rust bakes `core::panic::Location` strings — file **and line number** — into the
binary for every panicking operation. Reformatting shifted line numbers, so the
embedded strings changed, so the bytes changed. Adding or deleting a comment
above a panicking line does the same thing.

Two consequences, both intended:

- **`src/` is frozen against its exact bytes**, doc comments included. There is
  no such thing as a cosmetic change here. Improving a comment in this crate,
  after adoption, costs a flag day — so get the comments right now, and then
  stop editing.
- **Run `cargo fmt` before freezing, never after.** The CI check would catch it
  either way, which is the point of having the check rather than a convention.

`-Z location-detail=none` would strip these strings and remove the sensitivity
entirely, but it is nightly-only, and a nightly dependency is a far worse
stability risk than line numbers.

## Why the dependencies are what they are

**`freenet-stdlib = "=0.8.5"`** — the current release at freeze time. It is
unavoidable: the `#[contract]` macro and the WASM memory interface the node
calls both live there. Taking the current release rather than an older one means
we start on the ABI the network actually runs, so we are not forced into an
early bump. `default-features` is empty upstream, so nothing optional is pulled
in.

**`ed25519-dalek = "=2.1.1"`, `alloc` only** — signature verification, and
nothing else. `rand_core` is deliberately **off**: it would pull in `getrandom`
and, on `wasm32`, `wasm-bindgen` contamination. Verification never needs an RNG,
and the publisher-side signing helper is behind the non-default `publish`
feature, so it is not in the frozen artifact at all.

**Nothing else.** In particular there is no serialization crate. Both the params
and the state are hand-written fixed byte layouts. `Parameters` and `State` are
opaque, unframed byte blobs at the platform boundary, so a serde or CBOR crate's
own version drift would silently re-key every pointer in the ecosystem — the
same reasoning Atlas records in its `AGENTS.md` for its own params encoding.
That is also why `app_id` is restricted to lowercase ASCII: it removes any need
for a `unicode-normalization` dependency.

## The flag day

If the bytes genuinely must change — an ABI break in the node, or a
vulnerability in the signature path — it is an ecosystem-coordinated event, not
routine maintenance:

1. Agree it is necessary, in public, before writing the change.
2. Bump the crate to `2.0.0` and the `SIGNING_DOMAIN` suffix to `-v2`.
3. Build with `build-wasm.sh`, commit the new `pointer-v1.wasm`'s successor and
   the new `CODEHASH`.
4. Publish **both** hashes. Consumers must resolve v2 and fall back to v1 for as
   long as unmigrated pointers exist, which is a long time.
5. Every publisher republishes their pointer at the new key. Until they do, their
   v2 pointer does not exist.

Step 5 is why this is expensive: it needs every author's root key, which is by
design in cold storage.

## Deliberately not solved here

Rust builds are not bit-for-bit reproducible in general, and this ecosystem has
no reproducible-build tooling. What is achieved here is narrower and honest:
**given the pinned toolchain and the pinned lockfile, the output does not depend
on where the source or the registry lives**, verified by building from two
unrelated paths. A different rustc, or a different libc affecting rustc's own
codegen, could still differ — which is what the CI rebuild check exists to
detect, loudly, rather than to prevent.
