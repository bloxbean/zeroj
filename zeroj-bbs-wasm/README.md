# zeroj-bbs-wasm

Optional CFRG BBS provider backed by `zeroj-bls12381-wasm`.

The BBS draft-10 algorithm is shared with `zeroj-bbs`; this module swaps the
BLS12-381 primitive provider to the Rust `bls12_381` WASM backend executed by
Chicory. Provider selection is explicit:

```java
var provider = com.bloxbean.cardano.zeroj.bbs.wasm.WasmBbsProvider.createDefault();
var service = new com.bloxbean.cardano.zeroj.bbs.BbsService(provider);
```

The generated WASM artifact comes from `zeroj-bls12381-wasm` during the Gradle
build. Install Rust with the pinned toolchain and the `wasm32-unknown-unknown`
target before running this module's tests.
