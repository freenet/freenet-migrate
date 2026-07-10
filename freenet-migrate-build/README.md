# freenet-migrate-build

Build-dependency companion to
[`freenet-migrate`](https://crates.io/crates/freenet-migrate). Consumers add it
under `[build-dependencies]` and call it from `build.rs`. Three jobs:

1. **Parse** a unified `legacy.toml` registry of predecessor contract/delegate
   code hashes (`[[contract]]` / `[[delegate]]` rows: `generation`, base58
   `code_hash`, delegate `delegate_key`, `note`).
2. **Codegen** the `CONTRACT_LINEAGE` / `DELEGATE_LINEAGE` consts into `$OUT_DIR`
   for `freenet-migrate` to consume at runtime.
3. **CI hash-guard** (`check_migration_guard`): assert that whenever a built
   WASM's hash changed, the old hash is registered as a predecessor — so an
   unregistered re-key fails CI instead of silently stranding user data.

```rust,no_run
// build.rs
freenet_migrate_build::codegen()
    .registry("legacy.toml")
    .emit()
    .expect("codegen lineage consts");
```

It has **no** `freenet-stdlib` dependency and is independent of `freenet-migrate`
at build time. Part of the
[`freenet-migrate`](https://github.com/freenet/freenet-migrate) workspace;
Horizon-A step A3 of
[freenet-core#2776](https://github.com/freenet/freenet-core/issues/2776).

## License

LGPL-3.0-only.
