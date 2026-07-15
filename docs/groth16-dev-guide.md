# Groth16 developer guide — setup, prove, verify from Java

This is the programmatic counterpart of the account-ownership CLI: how to run a Groth16
(BLS12-381) trusted setup, generate proofs, and verify them from your own code or tests using
`zeroj-crypto`. **Start at `Groth16Keys`** — one handle for the key material wherever it lives,
and one `prove` that works identically against all of them. The only decision you make is *where
the proving key lives*, once, at setup time:

| key home | when | memory profile |
|---|---|---|
| heap (`setupInMemory`) | tests, small circuits | whole proving key on heap — impractical for large circuits |
| key store, sparse (`setupToStore(..., true)`) | **the default for real circuits** | streamed setup + `mmap`'d key (page cache, not heap) — keeps large circuits within commodity memory (ADR-0033/0034/0035) |
| key store, dense (`setupToStore(..., false)`) | interchange with pre-sparse tools | same profile; larger on-disk key |
| snarkjs ceremony import | production keys | external ceremony; `mmap`'d key at prove time |

All flows below assume the single-party dev setup opt-in (never in production):

```java
System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
// or: -Dzeroj.allowInsecureTrustedSetup=true
```

## Flow 1 — tests and small circuits (everything in memory)

```java
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;

List<R1CSConstraint> constraints = ...;      // your circuit
BigInteger[] witness = ...;                  // witness[0] must be 1
BigInteger tau = PowersOfTauBLS381.generate(logDomain + 2).tauScalar();

try (var keys = Groth16Keys.setupInMemory(constraints, numWires, numPublic, tau)) {
    Groth16ProofBLS381 proof = keys.prove(witness, constraints);
}
```

Nothing touches disk; the proving key lives on the heap. Fine up to a few hundred thousand
constraints — beyond that, use Flow 2.

## Flow 2 — real circuits (key store on disk)

Setup **streams** every proving-key point straight into memory-mapped store files
(ADR-0035: a 19M-constraint circuit's setup fits within commodity memory), then proves from the
same handle. `sparse = true` (recommended) stores infinity points as one bit each — a much smaller
on-disk key than dense:

```java
R1CSFlat flat = ...;                          // packed CSR constraints (R1CSFlat.builder(), or
                                              // your compiler's flat output)
try (var keys = Groth16Keys.setupToStore(flat, numWires, numPublic, tau, keysDir, true)) {
    Groth16ProofBLS381 proof = keys.prove(witness, constraints);
}
```

Every later run reopens the bundle — dense or sparse is auto-detected from the manifest:

```java
try (var keys = Groth16Keys.load(keysDir)) {
    Groth16ProofBLS381 proof = keys.prove(witness, constraints);
}
```

The store files are mmap'd, so the key occupies page cache, not heap — a 19M-constraint proof
stays within commodity heap (ADR-0033/0034). Close the handle (try-with-resources) to unmap.

For very large circuits, the packed prove overload avoids boxing 43M+ `BigInteger`s
(ADR-0034 — this is what the account-ownership CLI uses):

```java
FlatScalars w = FlatScalars.pack(witness, witness.length);
Groth16ProofBLS381 proof = keys.prove(ProverBackend.PURE_JAVA, w, flat, /*bindingRows*/ 0);
```

`ProverBackend.PURE_JAVA` is the default and matches blst's speed at large sizes without blst's
extra native MSM buffers; pass `ProverBackend` explicitly only to opt into blst on big-RAM
machines.

## Flow 3 — production keys from a snarkjs ceremony

Run the multi-party ceremony externally (snarkjs), then import the `.zkey` once into the same
store layout; from there it's Flow 2's load-and-prove:

```java
ZkeyPkStoreImporter.importToPkStore(zkeyPath, keysDir);   // one-time; writes the dense store

try (var keys = Groth16Keys.load(keysDir)) {
    // a snarkjs setup appends numPublic+1 public-input binding rows after the circuit rows —
    // tell the H computation about them (0 for locally-generated bundles):
    Groth16ProofBLS381 proof = keys.prove(ProverBackend.PURE_JAVA, w, flat, numPublic + 1);
}
```

The importer always writes the dense format, and dense stays readable forever — ceremony
bundles are never affected by the sparse default.

## Verifying

Proof + public inputs travel as snarkjs-compatible JSON; verification lives in
`zeroj-verifier-groth16` (`Groth16BLS12381PureJavaVerifier`, or the blst-backed
`Groth16BLS12381Verifier`) behind the `ZkVerifier` SPI, and on-chain via the Plutus validator
codecs. The handle exposes the VK components (`keys.pk().alphaG1()`, `keys.pk().betaG2()`,
`keys.gammaG2()`, `keys.pk().deltaG2()`, `keys.ic()`) if you need to emit a `vk.json` or run a
raw pairing check — see `Groth16KeysTest.pairingVerify` for the four-pairing equation inline.

## The pipeline layer — `Groth16Pipeline` (big-circuit orchestration)

For CLI-grade behaviour at 19M scale — the compile-skip constraint cache, the deferred mmap'd
constraint load, and the measured release-ordering — use `Groth16Pipeline` instead of wiring the
expert seams yourself. It is the exact orchestration the account-ownership CLI runs (extracted
from it), parameterised by the only two circuit-specific pieces, passed as suppliers:

```java
// setup: streamed store + r1cs.bin constraint cache emitted in the same pass
var cc = new Groth16Pipeline.Compiled(flat, numConstraints, numWires, numPublic);
/* drop your circuit/graph references here — the pipeline can't release what it never sees */
var setup = Groth16Pipeline.setup(cc, tau, keysDir, /*sparse*/ true);

// prove: compile runs ONLY if the cache misses; witness runs before the mapped constraint load
try (var keys = Groth16Keys.load(keysDir)) {
    var proof = Groth16Pipeline.prove(keys,
            keysDir.resolve(Groth16Pipeline.R1CS_CACHE),
            expectedFingerprint,                    // from your bundle metadata; fails fast on mismatch
            () -> compileMyCircuit(),               // -> Compiled; invoked only on cache miss
            () -> computeMyWitness(),               // -> FlatScalars; must release the graph internally
            /*bindingRows*/ 0, ProverBackend.PURE_JAVA);
}
```

`Groth16Pipeline.fingerprint(nc, nw, np)` is the canonical circuit fingerprint
(`c…-w…-p…`) gating the cache and bundle compatibility; `estimateProvePhaseHeapBytes` gives a
heap-floor lower bound for preflight checks (the witness-generation peak is circuit-specific and
can exceed it — measure your real floor). A `Progress` listener surfaces stage events for CLIs.

## The expert layer (when `Groth16Keys`/`Groth16Pipeline` aren't enough)

Everything above is delegation — these seams stay public for differential tests and for
pipelines with needs the orchestrator doesn't cover:

| entry point | what it's for |
|---|---|
| `Groth16SetupBLS381.setup(...)` | classic in-heap setup; deterministic overload (explicit α/β/γ/δ) for byte-equality tests |
| `Groth16SetupBLS381.setupToStore(...)` | streaming setup; byte-identical output to `setup` + `PkStore.save` (gated by `StreamingSetupDifferentialTest`) |
| `Groth16PkStore.load/save`, `Loaded` | the store format itself; `Loaded` is the raw (pk, readers, vk, arena) tuple |
| `Groth16ProverBLS381.computeH` / `computeHFlat` | compute H separately, drop the constraints/circuit references, *then* prove — peels ~GBs off the MSM phase |
| `Groth16ProverBLS381.proveWithHCoeffs(...)` | prove from a precomputed H (pairs with the above) |
| `Groth16ProverBLS381.proveWithReaders(...)` | reader-supplied key without the handle |
| `R1CSFlatIO.write/readIfMatches` | fingerprint-gated `r1cs.bin` constraint cache — skip the frontend compile on warm proves |

Memory numbers, formats, and the full optimization history: ADR-0033 (prove memory),
ADR-0034 (frontend + prove speed), ADR-0035 (setup memory/time + sparse store).
