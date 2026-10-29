# ZeroJ for JavaScript and TypeScript

Experimental Java-to-Wasm bindings, implemented under [ADR-0057](../docs/adr/0057-webassembly-and-native-library-bindings.md)
in PR #92. The implementation ledger is [PROGRESS.md](PROGRESS.md).

The Java adapters reuse ZeroJ cryptography. Typed ESM packages expose Uint8Array, bigint and
Promise APIs. Logical APIs select explicitly registered physical images; importing a wrapper
does not download Wasm. Node uses worker threads; browsers use Web Workers. No JVM is needed
to run a built image. These images need a JavaScript host and are not generic WASI modules.

## Build and test the current milestone

Prerequisites: Java 25; Oracle GraalVM 25.3.4.1+1.1 (GRAALVM_HOME), Binaryen 132 on PATH,
Python 3 and Node 22+. Node 22–24 needs --experimental-wasm-exnref.

From the repository root:

```sh
export JAVA_HOME="$GRAALVM_HOME"
./gradlew -p bindings/wasm :adapter-common:test :adapter-hash:test
python3 bindings/wasm/build.py hash crypto probe unprotected
python3 bindings/wasm/package.py hash crypto probe unprotected
cd bindings/js
npm ci --ignore-scripts
npm run build
npm test
node tests/browser.mjs
node --experimental-wasm-exnref examples/node/hash.mjs
python3 scripts/serve.py
```

The local browser example is http://127.0.0.1:8788/examples/browser/.
Install the pinned Playwright Chromium/Firefox browsers first if absent:
`npx playwright install chromium firefox`.

The probe/unprotected images are private test packages, never consumer artifacts. The latter
intentionally omits the WebCrypto provider to prove that ZeroJ's core default-RNG guard rejects
the weak compiler default. No setup or ceremony operation is reachable in consumer images.

## API shape

```ts
import { createRuntime } from "@zeroj/runtime";
import { createPedersen } from "@zeroj/pedersen";
import { bundle } from "@zeroj/bundle-crypto";

const runtime = createRuntime({
  bundles: [bundle],
  experimentalSecrets: true, // Research opt-in; not a security certification.
});
try {
  const pedersen = createPedersen(runtime).bls12381;
  const blinding = await pedersen.randomBlinding();
  const commitment = await pedersen.commitScalar({ value: 42n, blinding });
  // Verify an already-disclosed opening (class V1).
  const valid = await pedersen.verifyOpening({ commitment, value: 42n, blinding });
} finally {
  await runtime.dispose();
}
```

Pedersen and BBS can share the crypto image and worker. A key handle is local to its runtime
and image; serialization does not preserve it. Explicit release and runtime disposal invalidate
handles. Disposing cannot guarantee erasure of all immutable Java/JS copies.

## Current security boundaries

- Secret paths are browser/Node Wasm **unassessed**, experimental and outside the inherited
  dedicated-host/offline assurance profiles. Workers do not prevent timing/cache observations
  and do not protect against the embedding application or a compromised origin.
- The application, package descriptor and origin are trusted. Launcher/Wasm checksums detect
  mismatched or modified assets relative to that descriptor; replacing the whole application
  can replace its trust anchor too.
- WebCrypto is installed before Java dispatch. A missing or throwing source fails closed.
  The new core SecureRandoms factory rejects unapproved providers when the measured Web Image
  runtime reports os.name=Browser. Ordinary JVM creation is unchanged. Supplying an RNG to an
  existing Java API remains the caller's cryptographic responsibility.
- The binding classpath excludes native blst, selects pure Java explicitly, and uses build-time
  reachability guards. Trusted setup is not a browser method.
- Pedersen disclosed verification is for public openings. It does not make a still-private
  opening safe to verify under observation.
- Proof validity does not authorize a transaction or authenticate a caller. DKG transports and
  note state-machine policy retain their application obligations.
- No curve-based capability is claimed post-quantum or production-ready.

Core changes at this checkpoint: a guarded default randomness factory and replacements at
existing default-construction sites; additive public access to existing unkeyed BLAKE2b methods.
No hash/curve/transcript/proof equation is changed.

Generated images, npm tarballs and raw logs stay out of Git. npm packages have not been
published. Distribution/legal notices, packed-consumer testing and the remaining capabilities
are still in progress; do not treat this checkpoint as a completed release.
