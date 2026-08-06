# vendor-archive

The exact `.crate` tarballs for every dependency in this contract's
`wasm32-unknown-unknown` build graph, at the versions pinned by `Cargo.lock`.

## Why

The freeze check rebuilds the artifact and compares its hash to `CODEHASH`. That
rebuild needs crates.io to keep serving these exact files, and rustup to keep
serving toolchain 1.96.0, forever. `--locked` survives a yank; it does not
survive a *deletion*, and neither does it survive a toolchain disappearing.

If that happened, CI would go permanently red, and the obvious way to make it
green again would be to bump something — which is the one act this whole
directory exists to prevent. These tarballs mean the inputs can always be
reconstructed and inspected, so a future maintainer can prove what the bytes
were built from rather than guessing.

## This is an archive, NOT the build path

**Never make this directory the source of the build.** `cargo vendor` and
`[source]` replacement change the registry path strings that rustc embeds in
panic locations, so building from vendored sources produces a *different* code
hash than building from the registry — it would re-key the contract while
looking like a faithful reconstruction. That is the exact trap this note exists
to flag.

`build-wasm.sh` deliberately unsets the registry-redirect environment variables
for the same reason.

To recover from a registry loss, restore these files into a cargo registry cache
so the normal path resolves them, rather than pointing cargo at this directory.

## Not included

`android_system_properties` is in `Cargo.lock` but not in this graph: it is an
Android-only target dependency of `chrono` and is never compiled for
`wasm32-unknown-unknown` or for the host tools. Nothing else in the build graph
is absent.
