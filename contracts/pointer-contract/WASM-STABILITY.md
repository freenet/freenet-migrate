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
| A different rustc | `rust-toolchain.toml` pins `1.96.0`. The pointer CI job hardcodes the same value rather than using the repo-wide `RUST_TOOLCHAIN` var, deliberately: the two happen to be equal today and must stay independent, so bumping the repo pin cannot silently re-key this artifact. |
| Different build flags | `[profile.release]` is pinned in `Cargo.toml`; `build-wasm.sh` is the only supported build path. |
| Absolute paths from the builder's machine | `build-wasm.sh` sets `--remap-path-prefix` for both `$CARGO_HOME` (canonicalized, so a trailing slash or symlinked `$HOME` cannot skew it) and the crate directory, then **fails** unless every absolute path in the artifact is under `/cargo/`, `/crate/`, `/rustc/` or `/rust/`. Verified: GitHub CI reproduces nova's bytes exactly, from a different `$HOME`, checkout path and `$CARGO_HOME`. |
| The caller's environment | `build-wasm.sh` unsets `CARGO_ENCODED_RUSTFLAGS` (which silently outranks `RUSTFLAGS`, so invoking the script from inside another cargo process would discard the path remapping), `RUSTC_WRAPPER`, `CARGO_TARGET_DIR` and friends; forces `CARGO_INCREMENTAL=0`; and sets the release profile through `CARGO_PROFILE_RELEASE_*`, which outranks any `.cargo/config.toml` up the tree. |
| A stale lockfile rewritten by an earlier CI step | Every cargo invocation in the pointer job passes `--locked`, and CI fails if `Cargo.lock` changed during the build. Without that, an unlocked `cargo test` earlier in the same job would rewrite the lock, and the artifact build's own `--locked` would then compare against the rewritten file and pass for the wrong reason. |
| A doc quoting a stale code hash | CI fails unless `README.md`, `TEST-VECTORS.md` and `FREENET.md` all quote the current `CODEHASH` and no other value of that shape. Consumers copy the constant out of the docs, so a stale copy sends them to an empty contract. |
| A half-configured feature set | `build-wasm.sh` fails unless all four entry points are exported. Enabling `freenet-main-contract` without stdlib's `contract` feature silently produces a ~150-byte WASM with no exports, which loads fine and does nothing. |
| crates.io or the rustup archive losing a file | `vendor-archive/` holds the exact `.crate` tarballs for the wasm32 build graph. `--locked` survives a yank but not a deletion. Read `vendor-archive/README.md` first: vendoring must never become the *build path*, because `cargo vendor` changes the embedded registry path strings and re-keys the contract. |
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

**No direct dependency beyond those two**, and in particular **no serialization
crate is used for the params or the state**. Both are hand-written fixed byte
layouts. `Parameters` and `State` are opaque, unframed byte blobs at the platform
boundary, so a serde or CBOR crate's own version drift would silently re-key
every pointer in the ecosystem — the same reasoning Atlas records in its
`AGENTS.md` for its own params encoding. That is also why `app_id` is restricted
to lowercase ASCII: it removes any need for a `unicode-normalization` dependency.

Said carefully, because the blunter version of this sentence was wrong: serde
and **bincode 1 are in the wasm32 build graph** — they arrive transitively
through `freenet-stdlib`, they are in `vendor-archive/`, and the bincode
tripwires section below depends on them being there. What the fixed layouts buy
is that no serialization crate's version drift can change the encoding of the
two things that determine this contract's *address* and its *state*. It does not
mean the artifact is free of serialization code.

## The gate on the first publish: run and passed

The freeze was once only partly verified, and the missing part blocked
**publishing** rather than merging.

Verified by CI: the committed artifact loads in a real wasmtime engine, imports
exactly `freenet_contract_io::__frnt__fill_buffer` and nothing else, exports the
four entry points with the signatures the node calls, and runs its own allocator
(`../pointer-contract-conformance/`).

Not verified until 2026-08-17: **that this contract's logic is correct when
compiled to `wasm32`.** Every test of the logic ran the same Rust compiled
natively, and the conformance suite never called the entry points. A `wasm32`
backend miscompile in `curve25519-dalek` or `blake3`, or a
`ContractInterfaceResult` encoding mismatch, would have passed both suites — and
a signature check that misbehaves only on `wasm32` fails silently rather than
loudly, which is the worst shape for a fault in this particular contract.

**That run has now happened: 10 checks, 0 failures**, against throwaway loopback
nodes on freenet 0.2.128 / fdev 0.3.273. The evidence, including the control
that keeps the forgery check from being confounded and the one coverage caveat
(`update_state` exercised in local mode only, because of freenet-core#4978), is
recorded in the corresponding box in `README.md`. Read it there rather than
trusting this sentence.

The freenet-core end-to-end test — exporting `ContractRuntimeInterface` from
`dev_tool` and driving all four entry points there — remains the durable
follow-on. It was never a substitute for the manual run, and now that the manual
run is done it is the thing that keeps this true on every future toolchain.


## Inspection inherits the author's blind spots; execution does not

`WASM-STABILITY.md` — this file — once stated that the artifact needed no host
imports at all. That was false. It imports
`freenet_contract_io::__frnt__fill_buffer`, and that import is precisely what
tells a node to use the streaming buffer protocol rather than the legacy
one-shot path.

The claim survived being written, an export-section parser hardened specifically
to stop guards that cannot fail, and a full green CI run. Every one of those
checks looked at **exports**. The import was invisible to all of them, because
nobody thought to look at imports — and a suite written by the same person who
wrote the claim inherits that blind spot exactly.

What caught it was not inspection. It was instantiation refusing to proceed
without the host function: reality objecting to something nobody had enumerated.

Keep that in mind before adding another static check here. A check you write can
only test what you already suspected. Prefer making something actually run.

## Two guards that could once pass without checking anything

Recorded because the shape recurs, and because both were found by review rather
than by the guards themselves.

The export check began as `grep -qa validate_state "$WASM"`. That is satisfied by
the name appearing anywhere at all — a panic message, a debug string, a data
segment — so it would have kept passing after the exports themselves
disappeared. It now parses the module's export section.

The path check began as `if strings "$WASM" | grep -qE ...`. If `strings` is not
installed, it exits 127, `grep` sees empty input, and the `if` reads that as
"no leak" — `set -e` does not fire inside an `if` condition. It also listed
suspicious roots (`/home/`, `/Users/`), which only catches the ones somebody
thought of; `/root/`, `/build/`, `/workspace/`, `/builds/` and `C:\Users\` all
sailed through. It is now an allow-list inside the same Python block that
already has the bytes in memory. Inverting it immediately surfaced two paths the
deny-list had never noticed (`/rust/deps/...`, baked into the `std` rustup
ships) — harmless, but previously unaccounted for.

The general question worth asking of any guard here: **what input makes this go
red?** If there isn't an easy answer, the guard is decoration.

## The bincode tripwires: what an upstream change can break silently

The artifact talks to the node over **bincode 1**, which is positional and
unframed. There are no field names and no tags on the wire, so a change upstream
that Rust considers source-compatible can silently change the bytes this frozen
WASM produces or expects. Nothing in this repository can detect it, because the
frozen side never recompiles.

Named explicitly, because these are the types on that boundary:

| Change | Effect |
|---|---|
| Appending a field to `UpdateModification` or `RelatedContracts` | The frozen WASM writes/reads the old arity; the node reads/writes the new one. Silent misparse. |
| Inserting a variant **mid-list** into `ContractError`, `ValidateResult`, or `UpdateData` | Variants are encoded by index. Every variant after the insertion point shifts, so the frozen WASM's `Valid` could decode as `Invalid`. |
| Appending a variant at the end | Safe for what the frozen WASM emits, but it can never emit or understand the new one. |
| Changing a field's type | Silent misparse. |

**`UpdateData` carries `#[non_exhaustive]`, and that attribute is misleading
here.** It advertises "new variants may be added safely", which is true at the
Rust source level and **false at the bincode layer** for an artifact that will
never be recompiled. Treat adding a variant anywhere but the end as a flag day.

The same applies to the guest/host buffer protocol
(`__frnt__fill_buffer`, `__frnt__initiate_buffer`, `BufferBuilder`'s `#[repr(C)]`
layout, the `ContractInterfaceResult{ptr,kind,size}` return convention). That
surface is not historically stable: freenet-stdlib changed it in `0af23c0`
(streaming refill buffers), `925f34b`, and the `feat!` at `a87b998`, and
`contract_interface/` took 14 commits in 12 months across 0.1.24 to 0.8.5.

The `pointer-contract-conformance` crate is the guard: it loads the **committed**
artifact into a real wasmtime engine and asserts its import set, entry-point
signatures and buffer-header layout are exactly what a node provides and calls.
It caught a real error while being written -- the artifact does import
`freenet_contract_io::__frnt__fill_buffer`, contradicting an earlier assumption
here that it needed no host imports at all.

## The flag day

If the bytes genuinely must change — an ABI break in the node, or a
vulnerability in the signature path — it is an ecosystem-coordinated event, not
routine maintenance:

0. Note that the rebuild check is the one guard that is *off* during this
   process: step 3 regenerates `CODEHASH` from one developer's machine, with
   nothing to compare against. A polluted environment at that moment freezes the
   wrong bytes as canonical. So a new `CODEHASH` is committed only after CI, or
   a second independent machine, has reproduced it.
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
