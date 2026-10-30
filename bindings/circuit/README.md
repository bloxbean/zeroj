# Typed circuits in TypeScript and Wasm

Experimental first implementation under [ADR-0064](../../docs/adr/0064-portable-circuits-and-typescript-frontend.md).
The [plan](PLAN.md) tracks the remaining milestones; [validation](VALIDATION.md) records what actually ran.
The API reuses ZeroJ's Java symbolic types, gadgets, R1CS compiler, witness calculator and Groth16 implementation.
The [format contract](FORMAT.md) specifies canonical graphs/recipes and their separate identities.
No cryptography is reimplemented in TS. The packages are not published to npm.

## Try the examples

From the ZeroJ repository root, with the pinned GraalVM/Binaryen/Node prerequisites in [bindings](../README.md):

```sh
export JAVA_HOME="$GRAALVM_HOME"
python3 bindings/wasm/circuit-check.py
cd bindings/js
python3 scripts/serve.py --port 8791
# http://127.0.0.1:8791/examples/circuit/
# another terminal in bindings/js:
node --experimental-wasm-exnref examples/circuit/node.mjs age_check
```

The focused check installs pinned dependencies, builds the TS API, exports public recipes,
runs JVM parity/negative tests, builds/packages the compiler image, creates disposable snarkjs
keys, tests Node and Chromium/Firefox, and verifies an isolated local npm-tarball consumer.
Generated images, keys, logs, screenshots and raw vectors remain ignored. No npm publication occurs.

The six browser scenarios cover a Java graph, typed field arithmetic, an age threshold, boolean
selection, Poseidon and SHA-256. The first four generate fresh proofs and reject changed public
inputs. Poseidon/SHA compile and check witnesses; **their browser proof path remains beyond the
current adapter limits**. This is the first milestone, not completion of the whole plan.

## Author and prove

Inside the built workspace or an installation of the local tarballs:

```ts
import {createRuntime, hexToBytes} from '@zeroj/runtime';
import {defineCircuit, uint, createCircuitCompiler} from '@zeroj/circuit';
import {bundle} from '@zeroj/bundle-circuit';

const ageCheck = defineCircuit({
  name: 'age_check',
  public: {threshold: uint(8)},
  secret: {age: uint(8)},
}, ({public: p, secret: s}) => {
  s.age.gte(p.threshold).assertTrue();
});

// manifest, zkeyBytes and verificationKey are authenticated application artifacts.
const runtime = createRuntime({bundles: [bundle], experimentalSecrets: true});
try {
  const compiled = await createCircuitCompiler(runtime).compile(ageCheck, {
    expectedGraphSha256: manifest.graphSha256,
    fingerprint: manifest.fingerprint,
  });
  const key = await compiled.loadKey({
    zkey: zkeyBytes,
    expectedSha256: hexToBytes(manifest.keySha256),
    verificationKey,
  });
  const proof = await compiled.prove(key, {
    public: {threshold: 18n}, secret: {age: 21n},
  });
  // Verify against the intended VK and expected public statement in your application.
  await compiled.dispose();
} finally {
  await runtime.dispose();
}
```

The complete runnable equivalents are in [examples/circuit](../js/examples/circuit/).
Use a fresh runtime per compiled circuit. `compiled.checkWitness()` returns success and timings,
never witness values or witness digests. `compiled.description` exposes public identities/counts
and dimensions; `withinProverDimensions` does not guarantee a supplied key fits the byte cap.
Closing a compiled circuit releases its owned keys. Disposing the runtime terminates its worker;
this does not prove erasure of every immutable Java/JS copy.

`@zeroj/circuit/graph` also exports the earlier arithmetic `CircuitBuilder`. For Java-exported
canonical graph text, use `compiler.compileGraph(graphText, identity)`. That path accepts flattened
input names mapped to bigint; higher-level byte/UInt shapes are represented by constraints, not
reconstructed into TS types from a raw graph.

## Produce artifacts for a new TS-only circuit

A circuit definition is public build data. Save `definition.recipe` using Node's filesystem API;
no Java circuit class needs to be authored. Export the public graph, `.r1cs` and identity manifest
with the JVM build tool (paths below are relative to `bindings/wasm`):

```sh
./gradlew -p bindings/wasm :adapter-circuit:exportRecipe \
  -PrecipeFile=../js/build/my-recipe.json \
  -PartifactDir=../js/build/my-artifacts
```

The exporter writes `recipe.json`, `graph.json`, `circuit.r1cs`, and `manifest.json`, including
public/private input layout. It creates no keys and receives no witness. A separate trusted
ceremony/build process must produce the matching BLS12-381 key/VK and authenticate their hashes.
The local test harness's disposable keys are not production ceremony artifacts. The consumer
image excludes the exporter and setup implementation. Java is build tooling here, not a browser
runtime dependency.

Recipe hash, graph hash and constraint fingerprint are distinct. The manifest must be trusted by
the application: fetching an arbitrary graph and its self-declared hash does not authorize its
statement. Compilation requires the expected graph hash/fingerprint before private-input calls.
An edited compiler or circuit can require different setup artifacts.

## Supported authoring subset

- Field arithmetic/equality, constants; unsigned integers with Java's checked widening/range rules.
- Boolean logic/assertions and field/UInt/Bool `select`; fixed nonempty bytes/indexing/equality.
- Existing `zk.gadgets.poseidonBls12381T3` and one-block `zk.gadgets.sha256`.
- bigint/boolean/Uint8Array inputs with exact public/private names. Arrays/bits and broader gadget
  profiles are later milestones.

Use explicit symbolic assertions. `isEqual()` returns a symbolic boolean; ignoring it adds no
assertion that it is true. `if(symbol)`, `symbol === other`, `symbol + other` and `Boolean(symbol)`
are host operations. Use `select`, `isEqual().assertTrue()` and symbolic arithmetic instead.
Run the typed authoring lint on source files:

```sh
cd bindings/js
node packages/circuit-lint/src/index.mjs examples/circuit/symbolic-examples.ts
# The installed local package also exposes: zeroj-circuit-lint path/to/circuits.ts
```

The CLI is a guardrail, not a JS sandbox or a complete ESLint plugin. `any`, reflection and
aliased conversion functions can bypass it. Callback code is trusted application build code;
do not embed private values in public definition constants or shape choices. Witness-dependent
branching/shape is unsupported.

## Limits and security

The first milestone keeps the research compilation bounds and the existing 256 KiB key /
4,096-wire/domain prover budgets. The measured Poseidon fixture's key is 1,090,303 bytes;
SHA-256 has 103,259 wires. Witness success is not proof-generation success. Broader key transport
and hard allocation accounting are the next milestone, with independent parser/point/relation
checks retained. The present schema limits are not proven heap containment for hostile graphs.

Compiled graph acceptance is not a circuit-soundness audit. Hints are advice, not constraints;
review intended equations and trust the application-selected statement/VK. Existing gadget
vectors and independent prover checks complement frontend parity tests. Inherited key import
checks and post-proof self-verification do not replace application-authenticated artifacts or
resolve all production ceremony/key-consistency assurance gates.

The age example does not authenticate an age, the fixed salt offers no privacy demonstration,
and proving a hash preimage does not interpret a document. No new Yaci transaction/fee benchmark
is claimed here. Real Cardano applications must bind their public inputs and proof to validator
policy, transaction context and replay/state-transition rules. Groth16/EC primitives here are
not post-quantum. Browser/Node secret operations remain experimental and unassessed for side
channels under ADR-0057.
