# Test vectors

For implementing pointer resolution in a language other than Rust — the case
that motivated this contract in the first place, since Freenet Directory (the
app broken by the ghostkeys re-key) is not Rust.

All values hex unless marked base58. Base58 is the **Bitcoin** alphabet
(`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`, no `0OIl`), which
is what Freenet uses everywhere a key or hash is rendered as text.

Every value below is recomputed and checked against this file by the
`every_published_test_vector_is_correct_and_present` test, so the document
cannot drift from the implementation in either direction. (An earlier version of
this file claimed to be pinned by `wire_format_known_answer`, which pinned only
the signing message and the first four state bytes — the signature, the full
state and all three derived keys were asserted nowhere.)

## Inputs

| Field | Value |
|---|---|
| Ed25519 seed (private) | `0101…01` (32 bytes of `0x01`) |
| `author_verifying_key` | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| `app_id` (ASCII) | `river.room-contract` |
| `app_id` (hex) | `72697665722e726f6f6d2d636f6e7472616374` |
| `version` | `7` |
| `code_hash` | `aaaa…aa` (32 bytes of `0xAA`) |

## Params — `author_verifying_key ‖ app_id`

51 bytes:

```
8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
72697665722e726f6f6d2d636f6e7472616374
```

## Signing message — `DOMAIN ‖ params ‖ version_be ‖ code_hash`

The domain is the 24 ASCII bytes `freenet-pointer/state-v1`. Total 111 bytes:

```
667265656e65742d706f696e7465722f73746174652d7631   <- domain, 24 bytes
8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121b
f3748801b40f6f5c                                   <- params: verifying key, 32
72697665722e726f6f6d2d636f6e7472616374             <- params: app_id, 19
00000007                                           <- version, u32 BIG-endian
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa                                   <- code_hash, 32
```

Note the params segment is the **whole params blob**, verbatim, exactly as it
appears in the contract key derivation. Do not re-encode or re-order it.

## Signature

Ed25519 over the message above, verified with dalek's `verify_strict`. Match its
rejection rules exactly or your implementation will be more permissive than the
contract on adversarial input:

- **Non-canonical `S`**: reject unless the scalar `S` (the trailing 32 bytes of
  the signature) is fully reduced, i.e. `S < L` where
  `L = 2^252 + 27742317777372353535851937790883648493`. This is the standard
  malleability check.
- **Small-order `A`**: reject if the public key is one of the 8 small-order
  points. (This contract additionally rejects such keys at params-parse time, so
  they cannot appear in a valid pointer's params at all.)
- **Small-order `R`**: reject if the signature's `R` component is small-order.
- **Non-canonical point encodings**: reject a 32-byte encoding whose `y` is
  `>= 2^255 - 19`. `VerifyingKey::from_bytes` does *not* do this for you, so the
  contract checks it explicitly for the author key.
- **Cofactored vs cofactorless**: `verify_strict` uses the **cofactorless**
  equation, `[8][S]B = [8]R + [8][k]A` is *not* what it checks; it checks
  `[S]B = R + [k]A` directly. A cofactored verifier accepts signatures this
  contract rejects.

```
ee3c33cf7bac4f2c2dc4d3a0eff2300a12174d44084f340d6d68c98d63a63953
5fece9eed85c2218af2ba566bda24f4c63ec2fca140f6a35bc6230811f27a10d
```

Ed25519 signing here is deterministic (RFC 8032), so a correct implementation
reproduces these exact bytes from the seed.

## State — `version_be ‖ code_hash ‖ signature`

Exactly 100 bytes:

```
00000007
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ee3c33cf7bac4f2c2dc4d3a0eff2300a12174d44084f340d6d68c98d63a63953
5fece9eed85c2218af2ba566bda24f4c63ec2fca140f6a35bc6230811f27a10d
```

Any other length is invalid. There is no framing, no length prefix, no version
byte — the layout is fixed forever.

## Key derivation

Both derivations are `BLAKE3(code_hash_bytes ‖ params_bytes)`, over **raw
32-byte** hashes, not their base58 text.

**The pointer's own key**, from the frozen pointer code hash plus the params
above:

| | |
|---|---|
| pointer code hash (base58) | `8wnAPaSRY1oYZCz723fdwK6BgzL6q8ozP3buVovXnt6v` |
| pointer key (base58) | `Hjus5Fnb6NWxKGN64MQwmbgk1Vd6YojykLtxnXipR6Lx` |

**Your own instance's key**, from the `code_hash` carried in the state plus
**your own** params (not the pointer's) — this is step 3, the one integrators
get wrong:

| | |
|---|---|
| `code_hash` (base58) | `CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB` |
| example consumer params (ASCII) | `example-consumer-params` |
| example consumer params (hex) | `6578616d706c652d636f6e73756d65722d706172616d73` |
| derived contract instance id (base58) | `k2Nt3AT6K7L9obj1GwogHN2dpzY1MVaz9AAhXbLBkAS` |
| derived delegate key (base58) | `k2Nt3AT6K7L9obj1GwogHN2dpzY1MVaz9AAhXbLBkAS` |

Contract and delegate derivation are the same function over the same inputs, so
for identical inputs they produce identical bytes. That is expected, not a
mistake in the table.

## Summary and delta

- `summarize_state` returns the **whole 100-byte record**, not just the version.
  A version-only summary would make two peers holding different records at the
  same version look converged to the node, which compares summaries byte-for-byte.
- `get_state_delta` returns the whole record when the peer's summary loses the
  merge, and empty otherwise. An unreadable summary means "send everything".
- Merge order: higher `version` wins; at equal version the **lower** 100-byte
  encoding wins (so `code_hash` first, then `signature`). This is a total order,
  which is what makes two diverged peers converge in one round.
