# zeroj-bbs-wasm

Reserved for the **full Rust-WASM** CFRG BBS provider, per ADR-0019 §7.

The Rust BBS algorithm is compiled to `wasm32-unknown-unknown` and executed
through Chicory. Unlike the hybrid path (Java BBS + WASM BLS primitives), the
entire BBS algorithm runs inside WebAssembly, eliminating per-pairing and
per-scalar-mul cross-boundary calls.

> **Status:** scaffolding only. Source code is not yet committed pending the
> `zkryptium` POC gates (compiles to `wasm32-unknown-unknown`, no unexpected
> host imports, passes pinned CFRG draft-10 vectors byte-for-byte). See
> ADR-0019 §7 for the gate criteria.

## If you only want WASM-backed BLS primitives, you do not need this module

Hybrid mode — Java BBS algorithm with WASM BLS pairings and scalar muls — is
reachable directly from `zeroj-bbs`:

```java
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bls12381.wasm.WasmBls12381Provider;

var service = BbsService.withBlsProvider(
        BbsCiphersuite.BLS12381_SHA256,
        WasmBls12381Provider.createDefault());
```

The same pattern works for the native `blst` BLS provider from `zeroj-blst`:

```java
import com.bloxbean.cardano.zeroj.blst.BlstBls12381Provider;

var service = BbsService.withBlsProvider(
        BbsCiphersuite.BLS12381_SHA256,
        BlstBls12381Provider.createDefault());
```

`zeroj-bbs/src/test/java/com/bloxbean/cardano/zeroj/bbs/BbsBlsProviderConformanceTest`
already runs the full CFRG draft-10 fixture suite against all three BLS
providers via this `withBlsProvider` entry point.

## What `zeroj-bbs-wasm` will be for

When ready, this module will expose a `WasmBbsProvider` whose `keyGen`,
`skToPk`, `sign`, `verify`, `proofGen`, and `proofVerify` methods are all
single WASM calls dispatching to coarse `zeroj_bbs_*` ABI exports. Production
callers opt in:

```java
var provider = com.bloxbean.cardano.zeroj.bbs.wasm.WasmBbsProvider.createDefault();
var service = new com.bloxbean.cardano.zeroj.bbs.BbsService(provider);
```

The generated WASM artifact is built from this module's own `rust/` crate
during the Gradle build; install Rust with the pinned toolchain and the
`wasm32-unknown-unknown` target before running the module's tests.
