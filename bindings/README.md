# ZeroJ for JavaScript and TypeScript

Experimental Java-to-Wasm bindings under [ADR-0057](../docs/adr/0057-webassembly-and-native-library-bindings.md),
implemented in PR #92. See the [measured report](REPORT.md), [progress ledger](PROGRESS.md),
[reviews](reviews/W4-W5.md) and [distribution status](DISTRIBUTION.md).

The separate circuit-compiler stack adds [typed TS authoring and portable graph import](circuit/README.md)
under [ADR-0064](../docs/adr/0064-portable-circuits-and-typescript-frontend.md).
Its [plan](circuit/PLAN.md) distinguishes the implemented first slice from larger-key,
Merkle and Cardano-application milestones.

The adapters reuse ZeroJ's Java implementation. Typed ESM packages expose `Uint8Array`, `bigint`,
Promises and worker-local handles. Browsers use Web Workers; Node uses worker threads. Importing
an API or bundle descriptor does not fetch Wasm. An application explicitly selects its images.
No JVM is needed at runtime. These images require a JavaScript host and are not generic WASI modules.

## Build and try it

Prerequisites: Java 25; **Oracle GraalVM 25.3.4.1+1.1**, **Binaryen 132** on PATH, Python 3 and
Node 22+. Set `GRAALVM_HOME` to your installation; no machine-specific path is embedded in scripts.
Node versions before 25 need `--experimental-wasm-exnref`.

From the repository root:

```sh
export JAVA_HOME="$GRAALVM_HOME"
cd bindings/js
npm ci --ignore-scripts
npx playwright install chromium firefox
cd ../..
python3 bindings/wasm/check.py
```

This opt-in check builds nine images (seven consumer choices and two private entropy probes),
generates development-only proof fixtures, runs adapter and SDK/browser tests, and installs
local npm tarballs outside the workspace, including a separate compiler consumer. It never publishes packages. The default Java
build/BOM/publication does not depend on Node, Binaryen or Web Image.

After the check, from `bindings/js`:

```sh
python3 scripts/serve.py
# Open http://127.0.0.1:8788/examples/browser/

node --experimental-wasm-exnref examples/node/hash.mjs
node --experimental-wasm-exnref examples/node/all.mjs
node --experimental-wasm-exnref scripts/benchmark.mjs
```

The seven browser cards run real hashing, commitments, credentials, a small Groth16 proof,
encrypted tally, local DKG and note delivery. No input is uploaded. The local server accepts no
POSTs and uses CSP, same-origin worker assets and no request logging. Use disposable data.
The DKG loop simulates all trustees in one process; it is not a distributed deployment.

For incremental work, the corresponding commands are:

```sh
./gradlew -p bindings/wasm :bundles:classpath :adapter-common:test :adapter-hash:test
python3 bindings/wasm/build.py hash crypto verifier prover confidential all probe unprotected
python3 bindings/wasm/package.py hash crypto verifier prover confidential all probe unprotected
python3 bindings/wasm/tutorial-fixture.py
./gradlew -p bindings/wasm :bundles:confidentialFixtures
cd bindings/js
npm run build
npm test
node tests/browser.mjs
node scripts/pack-test.mjs
```

Finish packaging before running consumers: pins deliberately reject assets that do not match.
Generated images, keys, tarballs, screenshots and logs stay in ignored build/assets directories.
To rerun the affected core regressions, see [REPORT.md](REPORT.md).

## Packages and physical images

| Logical package | Factory | Capability / usual image |
|---|---|---|
| `@zeroj/runtime` | `createRuntime` | Host/worker loading and lifecycle; no image dependency |
| `@zeroj/hash` | `createHash` | `hash` / `bundle-hash`; ordinary SHA defaults to native WebCrypto |
| `@zeroj/pedersen` | `createPedersen` | `pedersen` / `bundle-crypto` |
| `@zeroj/bbs` | `createBbs` | `bbs` / `bundle-crypto` |
| `@zeroj/groth16-verifier` | `createGroth16Verifier` | `groth16-verifier` / `bundle-verifier` |
| `@zeroj/groth16-prover` | `createGroth16Prover` | `groth16-prover` / `bundle-prover` |
| `@zeroj/elgamal` | `createElGamal` | `elgamal` / `bundle-confidential` |
| `@zeroj/threshold` | `createThreshold` | `threshold` / `bundle-confidential` |
| `@zeroj/confidential-notes` | `createConfidentialNotes` | `confidential-notes` / `bundle-confidential` |
| `@zeroj/circuit` | `defineCircuit`, `createCircuitCompiler` | `circuit` / `bundle-circuit`; selected experimental graph/recipe compiler |
| `@zeroj/circuit-lint` | `zeroj-circuit-lint` CLI | Type-aware authoring checks; no Wasm |

`@zeroj/bundle-all` is optional: it combines the original cryptographic capabilities. The new
compiler uses the separately selected `bundle-circuit`, which also supplies verification. Do not register
it together with a second provider for the same capability. Several wrappers can share a single
runtime/image; they do not dynamically link Java heaps across images. Default package imports
never select or download all images for you. The two probe packages are test-only.

## API example

Inside the built workspace, or after installing local tarballs:

```ts
import { createRuntime } from '@zeroj/runtime';
import { createPedersen } from '@zeroj/pedersen';
import { bundle } from '@zeroj/bundle-crypto';

const runtime = createRuntime({ bundles: [bundle], experimentalSecrets: true });
try {
  const pedersen = createPedersen(runtime).bls12381;
  const blinding = await pedersen.randomBlinding();
  const commitment = await pedersen.commitScalar({ value: 42n, blinding });
  // This opening is now deliberately disclosed (class V1 verification).
  const valid = await pedersen.verifyOpening({ commitment, value: 42n, blinding });
} finally {
  await runtime.dispose();
}
```

Each package's declarations and [shared examples](js/examples/shared/scenarios.js) show the
remaining methods. Keys/openings are retained inside the worker where supported; explicit
export methods make sensitive export visible. A handle is local to its runtime and image.
`release(handle)` invalidates it; `dispose()` terminates workers and settles pending calls.
These operations do not prove erasure of every immutable Java/JS copy. A timeout terminates the
worker; do not blindly replay secret operations or a partially completed protocol.

## Hashes and circuits

`sha256` and `sha512` are ordinary hashes. Select `{shaBackend: 'wasm'}` to run Java instead of
WebCrypto. `blake2b(data, outputBytes)` exposes the existing unkeyed implementation; the default
output is 32 bytes. `poseidonBls12381T3(left, right)` explicitly selects the existing two-input
Fr profile (t=3, alpha=5, RF=8, RP=57), rejects non-canonical scalars and requires the experimental
secret-path opt-in because its Java arithmetic is variable-time.

None of these ordinary calls builds ZK constraints. SHA-2/Poseidon circuit gadgets remain Java
circuit components. The shipped prover demonstrates `y = x³ + x + 5` with private x. Custom
small circuits implement [CompiledCircuit](wasm/adapter-groth16/src/main/java/org/zeroj/bindings/groth16/CompiledCircuit.java),
register in a Java entry point, and compile into an explicit image. Import a ceremony key pinned
by trusted hash and exact fingerprint; do not implement setup in the consumer image. The existing
Java witness/circuit APIs can be used by a custom adapter. The current typed convenience method
is `proveCubic`; the transport supports only the compiled adapter's allowlisted input contract.

## Deployment and bundlers

The tested deployment uses ESM plus an import map and serves package `dist/` and `assets/` files
unchanged from the same origin. Node reads packaged assets by file URL. HTTPS (or localhost) is
required for browser WebCrypto. Preserve the runtime worker, launcher and Wasm assets; do not
minify/rewrite the launcher or Wasm after pins are generated. Serve Wasm with its normal MIME type
and use HTTP gzip/Brotli if desired. Compression measurements in the report do not mean `.br`
files are automatically served by the example server.

A framework build must retain the `new URL(..., import.meta.url)` assets and worker. The descriptor
uses literal asset URLs to support that tooling; automatic Vite/Webpack/Next integration is not
validated here. Use the tested static ESM deployment first, or explicitly copy the package layout
and resolve imports through an import map. Production CSP must allow the selected same-origin
assets, Web Workers, Wasm compilation and the checked launcher's Blob import; the sample server
shows the policy without enabling general JavaScript `unsafe-eval`.

## Security and application obligations

- Browser/Node Wasm secret operations are **unassessed**, experimental and outside inherited
  dedicated-host/offline assurance profiles. Workers are a responsiveness/isolation mechanism,
  not protection against the host page, malicious dependencies or timing/cache observations.
- The application, origin, runtime and descriptor are trusted. Checksums catch mismatched bytes
  relative to the descriptor; replacing the whole host can also replace its trust anchor.
- SecureRandom is installed through WebCrypto before Java dispatch. Missing/throwing entropy
  fails closed, and actual-image negative tests observe no Math.random calls. The core factory
  rejects the compiler's unapproved default when the pinned Web Image reports `os.name=Browser`.
  Ordinary JVM provider selection and caller-supplied RNG responsibilities remain unchanged.
- Native blst and trusted setup are excluded by classpath and reachability guards. Java crypto
  equations and transcript definitions are reused unchanged.
- Groth16 verification needs an application-trusted VK and expected public inputs. Imported
  proving keys need an independently trusted content hash/fingerprint. Validity is not authority.
- Imported ElGamal key shares/ciphertexts/decryption shares require existing exact relations.
  Register a trusted six-input DLEQ or encryption VK at the exact width. Java derives the public
  statement; no sender's `verified` flag or supplied public-input list can replace the check.
- DKG callers authenticate sender identities and private channels, establish broadcast agreement
  and deadlines, and close rounds consistently. Threshold t means t+1 decryption shares and
  requires 2t+1 <= n. External context admission, durable state restoration and network transport
  are not implemented by this initial binding. Keep qualified trustee identities distinct.
- Notes are delivery primitives, not a private ledger. Authenticate reader registration and
  ownership; enforce spend authorization, ranges/balances, nullifiers, replay rules and actual
  old/new state binding separately. Viewing keys are separate from ElGamal/spending/signing keys.
- No curve-based feature is claimed post-quantum or production-ready. No npm package is published.
  Generated bundle distribution has additional [release gates](DISTRIBUTION.md).

## Resource limits

| Boundary | Initial limit |
|---|---|
| Request JSON | 1,048,576 characters; depth 24; duplicate fields/trailing tokens rejected |
| Byte array / proving key | 262,144 bytes |
| Key import allocations | <=4,096 wires, <=4,096 domain cells, <=16,384 coefficients; compiled relation must also match |
| Groth16 public inputs | 64 |
| BBS messages | 64, each <=4,096 bytes |
| Worker | 64 queued/in-flight calls; 256 retained objects; default 120-second startup/call deadline |
| DKG | 3..16 participants; <=1,024 distinct accepted messages per round; overflow permanently invalidates participant |
| Discrete-log recovery | Explicit search maximum <=1,000,000, covering the ciphertext bound |
| Notes | 1..32 distinct readers; existing 89-byte delivery format |

These limits do not make a large circuit small. The earlier account-ownership browser POC did
not complete full proving; its multigigabyte proving key is also outside this transport. Use
appropriate off-browser proving for large circuits and verify the result in a browser when suitable.

Core changes: a guarded default-RNG factory and existing default-construction replacements;
public access to the existing unkeyed BLAKE2b methods; additive tightening-only zkey allocation
limits. No primitive, proof equation or cryptographic parameter is changed.
