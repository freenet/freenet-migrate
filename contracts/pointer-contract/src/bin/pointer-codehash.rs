//! Print the Freenet code hash of a WASM file, exactly as a node computes it.
//!
//! Deliberately delegates to `freenet_stdlib::prelude::CodeHash::from_code`
//! rather than reimplementing BLAKE3 + base58: if this printed a value derived
//! by a parallel implementation, it could agree with itself while disagreeing
//! with every node on the network.

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: pointer-codehash <path-to.wasm>");
            std::process::exit(2);
        }
    };
    let wasm = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(2);
    });
    println!(
        "{}",
        freenet_stdlib::prelude::CodeHash::from_code(&wasm).encode()
    );
}
