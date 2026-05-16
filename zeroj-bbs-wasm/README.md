# zeroj-bbs-wasm

Full Rust-WASM CFRG BBS draft-10 provider. The entire BBS algorithm runs
inside WebAssembly via [zkryptium 0.6.1](https://docs.rs/zkryptium) compiled
to `wasm32-unknown-unknown`, executed through Chicory. ZeroJ's Java layer
only serializes requests, parses responses, and supplies entropy via a single
documented host import.

See [ADR-0019](../docs/adr/0019-cfrg-bbs-pure-java-and-wasm-providers.md) §7
for the design rationale.

## When to use this module

Use the full Rust-WASM provider when you want the BBS algorithm to run
end-to-end inside a Rust-derived WebAssembly module and are OK with shipping
a small WebAssembly artifact. Signing and verification use coarse WASM calls
against a long-lived instance. Proof generation also uses a coarse call, but
ZeroJ intentionally creates a fresh WASM instance for each `proofGen` call so
the caller-supplied `SecureRandom` is honored for every proof.

```java
import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.bbs.wasm.WasmBbsProvider;

var provider = WasmBbsProvider.createDefault(BbsCiphersuite.BLS12381_SHA256);
var service = new BbsService(provider);

var keyPair = service.keyPair(keyMaterial, keyInfo);
var signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
var presentation = service.derivePresentation(
        keyPair.publicKey(), signature, messages, header, presentationHeader,
        new int[]{0, 2});
boolean valid = service.verifyPresentation(keyPair.publicKey(), presentation);
```

## When NOT to use this module

If you only need to swap the BLS12-381 primitive layer (pairings, scalar
mul) — for example to benchmark WASM-backed BLS while keeping the BBS
algorithm in Java — use the hybrid path directly from `zeroj-bbs`:

```java
// Java BBS algorithm + WASM BLS primitives:
var service = BbsService.withBlsProvider(
        BbsCiphersuite.BLS12381_SHA256,
        WasmBls12381Provider.createDefault());

// Java BBS algorithm + native blst BLS primitives:
var service = BbsService.withBlsProvider(
        BbsCiphersuite.BLS12381_SHA256,
        BlstBls12381Provider.createDefault());
```

`zeroj-bbs/src/test/java/.../BbsBlsProviderConformanceTest` already runs the
full CFRG draft-10 fixture suite (10 signatures + 15 proofs + keypair + h2s
+ generators + MapMessageToScalar + mockedRng, both ciphersuites) across all
three BLS providers via `withBlsProvider`. No separate hybrid module exists.

## ABI

The WASM module exposes:

- `zeroj_bbs_version() -> i32` (ABI version 1)
- `alloc(len) -> *mut u8`
- `dealloc(ptr, len)`
- `zeroj_bbs_keygen(req_ptr, req_len) -> *mut u8`
- `zeroj_bbs_sk_to_pk(req_ptr, req_len) -> *mut u8`
- `zeroj_bbs_sign(req_ptr, req_len) -> *mut u8`
- `zeroj_bbs_verify(req_ptr, req_len) -> *mut u8`
- `zeroj_bbs_proof_gen(req_ptr, req_len) -> *mut u8`
- `zeroj_bbs_proof_verify(req_ptr, req_len) -> *mut u8`

Every response is laid out as `[u32 LE length | status byte | payload]`.
Status `0` = success, status `1` = error (payload is UTF-8 error message).
Callers free the response buffer with `dealloc(ptr, length + 4)`.

The module imports exactly one host function:

- `env.zeroj_host_getrandom(ptr: i32, len: i32) -> i32` — `0` on success,
  non-zero on error. Java wires this to `java.security.SecureRandom`.

A test (`wasmModule_hasExactlyOneImportAndExpectedExports`) asserts that no
other imports are present.

## Runtime behavior

`keyGen`, `skToPk`, `sign`, `verify`, and `proofVerify` run on a long-lived
WASM instance owned by the provider. These operations are deterministic and
should never call the host RNG import.

`proofGen` needs fresh zero-knowledge blinding randomness. The Rust dependency
uses an internal thread-local RNG, so ZeroJ builds a transient WASM instance
per `proofGen` call and wires that instance's `env.zeroj_host_getrandom`
import to the `SecureRandom` supplied to the Java API call. This avoids
silently reusing or bypassing the per-call random source after the first
proof.

The tradeoff is performance: `proofGen` includes WASM instantiation overhead
in addition to the BBS proof computation. This is correctness-first behavior,
not a protocol limitation. For high-throughput proof issuance, benchmark this
provider under the target workload and compare it with `zeroj-bbs` using the
native `zeroj-blst` BLS provider. A future optimization can remove the
per-proof instantiation cost if the Rust dependency exposes an API that
accepts caller-provided randomness directly.

## Building

The `.wasm` artifact is built on demand by Gradle during `processResources`.
Install Rust with the pinned toolchain (`rust-toolchain.toml` selects
`rustc 1.94.0` with the `wasm32-unknown-unknown` target). Gradle uses
`~/.cargo/bin/cargo` by default; override via the `CARGO` environment
variable if needed.

```bash
./gradlew :zeroj-bbs-wasm:build
./gradlew :zeroj-bbs-wasm:test
```

## Trust boundary

The CFRG draft-10 algorithm correctness is owned by zkryptium upstream and
gated on the ZeroJ side by the pure-Java `PureJavaBbsProvider` running all
30 CFRG mocked-RNG proof fixtures × 2 ciphersuites byte-for-byte in
`BbsBlsProviderConformanceTest`. The WASM tests in this module focus on the
ZeroJ-owned boundary: request encoding, response framing, error mapping,
alloc/dealloc balance under failure, no-unexpected-host-imports, and a
small "trust ladder" of byte-exact CFRG fixtures (keygen, sk_to_pk, sign)
plus a proof_gen → proof_verify roundtrip. CFRG mocked-RNG proof
byte-equality is not retestable in this module because `proof_gen` uses
real RNG via the host import.
