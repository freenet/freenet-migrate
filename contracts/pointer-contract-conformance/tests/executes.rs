//! Does the FROZEN artifact actually load and run?
//!
//! Everything else in this repository checks the pointer contract's *source*:
//! the unit tests call the Rust functions natively, `build-wasm.sh` parses the
//! export section, and CI hashes the bytes. None of that executes
//! `pointer-v1.wasm`.
//!
//! That gap matters more here than it would anywhere else. The artifact is
//! frozen forever, so if it cannot be instantiated by a node -- because a
//! dependency pulled in a host import, or the entry points have the wrong
//! arity -- the fix is a flag day that re-keys every pointer in the ecosystem.
//! And the node-facing surface is not historically stable: freenet-stdlib's
//! `contract_interface/` changed across 14 commits in 12 months.
//!
//! Scope, stated honestly: this loads the committed bytes into a real wasmtime
//! engine and exercises the module's own allocator, which proves the artifact
//! is loadable and its code runs. Driving the four entry points through the
//! full host handshake additionally needs freenet-core to export
//! `ContractRuntimeInterface` (today `pub use`d in its private `wasm_runtime`
//! module but absent from `dev_tool`'s re-export list); reimplementing that
//! handshake here would only prove this file agrees with itself.

use wasmtime::{Caller, Config, Engine, Instance, Linker, Module, Store, ValType};

const WASM: &[u8] = include_bytes!("../../pointer-contract/pointer-v1.wasm");

/// The host functions a node actually provides, mirrored from freenet-core's
/// `wasmtime_engine.rs` linker setup. Nothing else is defined here on purpose:
/// if the artifact ever needs an import the node does not supply, instantiation
/// must fail HERE rather than on every node in the network.
fn module() -> (Store<()>, Instance, Module) {
    let mut config = Config::new();
    config.epoch_interruption(true); // the node runs with this on
    let engine = Engine::new(&config).expect("engine");
    let module = Module::new(&engine, WASM).expect("the frozen artifact must be a valid module");
    let mut store = Store::new(&engine, ());
    store.set_epoch_deadline(u64::MAX);

    let mut linker: Linker<()> = Linker::new(&engine);
    linker
        .func_wrap(
            "freenet_contract_io",
            "__frnt__fill_buffer",
            |_caller: Caller<'_, ()>, _id: i64, _buf_ptr: i64| -> u32 { 0 },
        )
        .expect("host stub");

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("the frozen artifact must instantiate against the node's host imports");
    (store, instance, module)
}

/// The single most valuable check here.
///
/// A node defines exactly one host function for contracts. If a future
/// dependency bump ever pulled in `getrandom`, `wasm-bindgen` or a WASI shim,
/// the module would declare an import no node provides, instantiation would
/// fail on every node, and the contract would be permanently dead at an address
/// nobody can change.
///
/// Asserting the set EXACTLY, not merely "instantiates", because the linker
/// stub above is ours: a new import would otherwise be silently absorbed the
/// moment somebody added a matching stub.
#[test]
fn the_artifact_imports_exactly_what_a_node_provides() {
    let (_store, _instance, module) = module();
    let mut imports: Vec<String> = module
        .imports()
        .map(|i| format!("{}::{}", i.module(), i.name()))
        .collect();
    imports.sort();
    assert_eq!(
        imports,
        vec!["freenet_contract_io::__frnt__fill_buffer".to_string()],
        "the frozen artifact's host imports changed"
    );

    // ...and with the signature core's linker actually registers,
    // `(i64, i64) -> u32`. A mismatch is an instantiation failure on every node.
    let import = module.imports().next().unwrap();
    let func = import.ty().unwrap_func().clone();
    let params: Vec<ValType> = func.params().collect();
    let results: Vec<ValType> = func.results().collect();
    assert!(
        matches!(params.as_slice(), [ValType::I64, ValType::I64]),
        "__frnt__fill_buffer params: {params:?}"
    );
    assert!(
        matches!(results.as_slice(), [ValType::I32]),
        "__frnt__fill_buffer must return u32, got {results:?}"
    );
}

/// Importing `freenet_contract_io` is what tells a node this contract speaks the
/// streaming buffer protocol rather than the legacy one-shot one
/// (`WasmtimeEngine::module_has_streaming_io`). Losing that import would not
/// fail instantiation -- it would silently select the legacy path.
#[test]
fn the_artifact_selects_the_streaming_io_protocol() {
    let (_store, _instance, module) = module();
    assert!(
        module
            .imports()
            .any(|i| i.module() == "freenet_contract_io"),
        "the node would fall back to the legacy one-shot buffer protocol"
    );
}

#[test]
fn the_artifact_instantiates_in_a_real_runtime() {
    let (mut store, instance, _) = module();
    instance
        .get_memory(&mut store, "memory")
        .expect("the node addresses contract memory through the `memory` export");
}

/// Arity and types, from the module itself rather than from a name grep. The
/// node calls these with packed i64 buffer pointers and reads back an i64
/// `ContractInterfaceResult`; a signature change is an instant hard failure on
/// every node.
#[test]
fn the_four_entry_points_have_the_abi_the_node_calls() {
    let (mut store, instance, _) = module();
    for (name, arity) in [
        ("validate_state", 3),
        ("update_state", 3),
        ("summarize_state", 2),
        ("get_state_delta", 3),
    ] {
        let func = instance
            .get_func(&mut store, name)
            .unwrap_or_else(|| panic!("`{name}` must be exported"));
        let ty = func.ty(&store);
        let params: Vec<ValType> = ty.params().collect();
        let results: Vec<ValType> = ty.results().collect();
        assert_eq!(params.len(), arity, "`{name}` arity");
        assert!(
            params.iter().all(|p| matches!(p, ValType::I64)),
            "`{name}` must take i64 buffer pointers, got {params:?}"
        );
        assert!(
            matches!(results.as_slice(), [ValType::I64]),
            "`{name}` must return one i64 ContractInterfaceResult, got {results:?}"
        );
    }
}

/// Actually run guest code. `__frnt__initiate_buffer` is the allocator the host
/// calls before every entry point, so if the module is inert -- compiled but
/// non-functional -- this is where it shows.
#[test]
fn the_modules_own_allocator_runs() {
    let (mut store, instance, _) = module();
    let initiate = instance
        .get_typed_func::<u32, i64>(&mut store, "__frnt__initiate_buffer")
        .expect("`__frnt__initiate_buffer` must be exported for the host to allocate");

    let memory = instance.get_memory(&mut store, "memory").unwrap();

    for capacity in [1u32, 100, 4096, 64 * 1024] {
        let ptr = initiate
            .call(&mut store, capacity)
            .unwrap_or_else(|e| panic!("allocator trapped at capacity {capacity}: {e}"));
        // Read the size AFTER the call: allocating can grow linear memory, and
        // the returned pointer legitimately lands in the newly grown region.
        let mem_size = memory.data_size(&store) as i64;
        assert!(
            ptr > 0 && ptr < mem_size,
            "allocator returned {ptr} for capacity {capacity}, \
             outside linear memory (size {mem_size})"
        );
    }
}

/// The layout the host writes into. `BufferBuilder` is `#[repr(C)]`
/// `{ start: i64, capacity: u32, last_read: i64, last_write: i64 }`; the host
/// reads `start` and `capacity` back out to know where to put the payload. If a
/// stdlib change ever moved these fields, the host would write the payload to
/// the wrong offset, and this catches that without reimplementing the whole
/// streaming protocol.
#[test]
fn the_buffer_header_matches_the_layout_the_host_assumes() {
    let (mut store, instance, _) = module();
    let initiate = instance
        .get_typed_func::<u32, i64>(&mut store, "__frnt__initiate_buffer")
        .unwrap();
    let memory = instance.get_memory(&mut store, "memory").unwrap();

    const CAPACITY: u32 = 256;
    let builder_ptr = initiate.call(&mut store, CAPACITY).unwrap() as usize;
    let data = memory.data(&store);

    let read_i64 = |off: usize| i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    let read_u32 = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());

    let start = read_i64(builder_ptr);
    let capacity = read_u32(builder_ptr + 8);
    let last_read = read_i64(builder_ptr + 16);
    let last_write = read_i64(builder_ptr + 24);

    assert_eq!(
        capacity, CAPACITY,
        "capacity must sit at offset 8 of BufferBuilder"
    );
    for (label, p) in [
        ("start", start),
        ("last_read", last_read),
        ("last_write", last_write),
    ] {
        assert!(
            p > 0 && (p as usize) < data.len(),
            "BufferBuilder.{label} = {p} is outside linear memory"
        );
    }
    assert_eq!(read_u32(last_read as usize), 0, "last_read starts at 0");
    assert_eq!(read_u32(last_write as usize), 0, "last_write starts at 0");
}
