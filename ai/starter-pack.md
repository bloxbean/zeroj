<!-- ZeroJ AI Starter Pack · zerojVersion: 0.1.0-pre12 · julcVersion: 0.1.0-pre18 · cclVersion: 0.8.0-pre5 · source: https://zeroj.dev/ai/starter-pack.md -->

# AI Starter Pack

> **AI agents: read this whole document before generating ZeroJ code.** It condenses the rules, idioms, and failure modes of ZeroJ into one file. Humans looking for a tutorial should start at the [quickstart](https://zeroj.dev/start/quickstart/) instead.
>
> Save it as `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/zeroj.mdc` or `.github/copilot-instructions.md`:
> `curl -o CLAUDE.md https://zeroj.dev/ai/starter-pack.md`. The downloadable Markdown version also contains a circuit API catalog generated from the Java sources ([JSON](https://zeroj.dev/ai/catalog.json)).

## 1. What ZeroJ is

ZeroJ is a **Java-first zero-knowledge proof toolkit for Cardano** (Java 25, Maven group `org.zeroj`, version `0.1.0-pre12`).

- **Define** circuits in Java — annotation style (`@ZKCircuit`, recommended) or the `CircuitSpec`/`SignalBuilder` DSL.
- **Prove** with a pure-Java **Groth16** prover on **BLS12-381** (no native libraries; optional blst backend).
- **Verify** off-chain in any JVM (`zeroj-verifier-groth16`) and on-chain in Cardano **Plutus V3** validators compiled from Java by **JuLC** (`zeroj-onchain-julc`, JuLC `0.1.0-pre18`).
- Also: BBS selective-disclosure credentials (`zeroj-bbs`), snarkjs/circom interop, Poseidon-rooted authenticated state (experimental).

**Status — say this honestly in anything you write for users:** ZeroJ is experimental research software. It is not externally audited and must not protect real value on mainnet. "Beta" means feature-complete and correctness-tested, not audited.

**Scope for the current release:** Groth16 on BLS12-381 is the supported path. **PlonK is experimental** (prover, verifier and validators): never choose it by default and never describe it as correct or production-ready. **BN254 is legacy and disabled by default** — never use it for Cardano.

## 2. Project setup

```groovy title="build.gradle"
plugins {
    id 'java'
    id 'application'
}

java { toolchain { languageVersion = JavaLanguageVersion.of(25) } }

repositories { mavenCentral() }

dependencies {
    implementation platform('org.zeroj:zeroj-bom-core:0.1.0-pre12')
    annotationProcessor platform('org.zeroj:zeroj-bom-core:0.1.0-pre12')

    implementation 'org.zeroj:zeroj-circuit-annotation-api'
    annotationProcessor 'org.zeroj:zeroj-circuit-annotation-processor'
    implementation 'org.zeroj:zeroj-circuit-dsl'
    implementation 'org.zeroj:zeroj-circuit-lib'          // Poseidon, Merkle, gadgets
    implementation 'org.zeroj:zeroj-crypto'               // prover, setup, snarkjs JSON export
    implementation 'org.zeroj:zeroj-codec'                // snarkjs JSON parsing
    implementation 'org.zeroj:zeroj-verifier-groth16'     // pure-Java verifier
    // implementation 'org.zeroj:zeroj-onchain-julc'     // Cardano validators + codecs
}

// Dev/test only: allows the single-party trusted setup used in examples.
application { applicationDefaultJvmArgs = ['-Dzeroj.allowInsecureTrustedSetup=true'] }
tasks.withType(Test).configureEach { systemProperty 'zeroj.allowInsecureTrustedSetup', 'true' }
```

- The BOM pins the core modules. Opt-in modules are outside the BOM and need an explicit version: `zeroj-verifier-plonk`, `zeroj-bbs`, `zeroj-mpf-poseidon`, `zeroj-jmt-poseidon`.
- Releases up to `0.1.0-pre11` used group `com.bloxbean.cardano` and packages `com.bloxbean.cardano.zeroj.*`. From `0.1.0-pre12` both are `org.zeroj`. Do **not** rename other `com.bloxbean.cardano` dependencies (Cardano Client Lib, JuLC).
- Details: [Installation](https://zeroj.dev/start/installation/).

## 3. The canonical flow (copy this shape)

```java title="SecretMultiplier.java"
import org.zeroj.circuit.annotation.*;

@ZKCircuit(name = "secret-multiplier", version = 1)
public class SecretMultiplier {
    @Prove
    ZkBool prove(ZkContext zk, @Public ZkField a, @Public ZkField product, @Secret ZkField b) {
        return a.mul(b).isEqual(product);
    }
}
```

```java title="Main.java"
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        // 1. Circuit + witness (generated companion: SecretMultiplierCircuit)
        var circuit = SecretMultiplierCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var inputs = SecretMultiplierCircuit.inputs().a(3).product(33).b(11);
        BigInteger[] witness = inputs.calculateWitness(circuit, CurveId.BLS12_381);

        // 2. DEV-ONLY trusted setup (needs -Dzeroj.allowInsecureTrustedSetup=true)
        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
        try (var keys = Groth16Keys.setupInMemory(
                r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), tau)) {

            // 3. Prove (fresh randomness every call)
            Groth16ProofBLS381 proof = keys.prove(witness, r1cs.constraints());

            // 4. Export snarkjs-compatible JSON and verify with the pure-Java verifier
            BigInteger[] pub = Arrays.copyOfRange(witness, 1, 1 + r1cs.numPublicInputs());
            String vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);
            String proofJson = SnarkjsGroth16Json.proofJson(proof);
            String publicJson = SnarkjsGroth16Json.publicJson(pub);

            CircuitId id = SecretMultiplierCircuit.circuitId();
            var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, id);
            var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                    ProofSystemId.GROTH16, CurveId.BLS12_381, id);
            boolean valid = new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
            System.out.println("valid = " + valid);
        }
    }
}
```

Facts about this flow (it is the [quickstart](https://zeroj.dev/start/quickstart/) program, compiled and run against the published artifacts):

- The witness is a `BigInteger[]`; `witness[0]` is the constant `1`, followed by the public inputs in schema order, then private wires. `Arrays.copyOfRange(witness, 1, 1 + numPublicInputs)` is exactly what the verifier needs; `inputs.publicValues()` gives the same values as a `List<BigInteger>`.
- For Groth16 only `tauScalar()` is used and the setup sizes its own domain from the constraint count, so `PowersOfTauBLS381.generate(4)` (the minimum; allowed range 4–32) is enough for a dev key.
- `VerificationResult.proofValid()` is the cryptographic result. `accepted()` also requires policy validity and stays `false` when you call a verifier directly — check `proofValid()` and apply your own policy.
- `Groth16Keys` is `AutoCloseable` — always use try-with-resources.
- Proofs are freshly blinded on every `prove` call. There is **no** deterministic or unblinded prove API; do not try to create one.
- Proof size: 192 bytes compressed (G1 48 + G2 96 + G1 48).

## 4. Writing circuits (annotation style)

Rules that make or break soundness:

1. Proof code uses **symbolic types only**: `ZkField`, `ZkBool`, `ZkUInt`, `ZkArray<T>`, `ZkBits`, `ZkBytes` (package `org.zeroj.circuit.annotation`).
2. `@Prove` returns `ZkBool` (or uses explicit assertion methods). Never return a Java `boolean`.
3. **Never use Java `if`, `?:`, `&&`, `||`, `!`, loops with data-dependent bounds, or `==` on symbolic values.** Circuits describe relations; they do not execute. Use `ZkBool.and(..)`, `or(..)`, `not()`, `select(..)`.
4. Every `ZkUInt` input carries `@UInt(bits = N)` — this emits the range constraints. Without it, field arithmetic wraps around modulo a 255-bit prime and "age − 18" can be huge instead of negative.
5. Every `ZkArray`, `ZkBits`, `ZkBytes` carries `@FixedSize(n)` or `@FixedSize(param = "name")`. Shapes are fixed at compile time.
6. Values that change the circuit's shape (tree depth, array length) are constructor parameters annotated `@CircuitParam("name")`. A different parameter value is a different circuit with different keys.
7. Inputs are either **fields** of the class (field style) or **parameters** of the `@Prove` method (parameter style). Static `@Prove` methods must use parameter style. No private `@Prove` methods, no private field inputs, no nested `@ZKCircuit` classes.
8. Add a `ZkContext zk` parameter when a gadget needs it (Poseidon, Merkle, Pedersen…).

```java
@ZKCircuit(name = "range-proof", version = 1)
public class RangeProof {
    @Secret @UInt(bits = 16) ZkUInt secret;
    @Public @UInt(bits = 16) ZkUInt lo;
    @Public @UInt(bits = 16) ZkUInt hi;

    @Prove
    ZkBool inRange() {
        return secret.gte(lo).and(secret.lte(hi));
    }
}
```

```java
@ZKCircuit(name = "merkle-bls12-381", nameTemplate = "merkle-bls-d{depth}")
public class MerkleMembership {
    public MerkleMembership(@CircuitParam("depth") int depth) { }

    @Prove
    ZkBool prove(ZkContext zk,
                 @Secret ZkField leaf,
                 @Public ZkField root,
                 @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
                 @Secret @FixedSize(param = "depth") ZkArray<ZkBool> pathBits) {
        return ZkMerkle.isMemberPoseidon(zk, PoseidonParamsBLS12_381T3.INSTANCE,
                leaf, root, siblings, pathBits);
    }
}
// MerkleMembershipCircuit.build(32); MerkleMembershipCircuit.inputs(32)
```

The annotation processor generates `<ClassName>Circuit` with: `build(...)`, `schema(...)`, `inputs(...)` (a typed builder with one method per input, plus `toWitnessMap()`, `publicValues()`, `toPublicInputs()`, `calculateWitness(circuit, curve)`), `calculateWitness(circuit, inputs, curve)`, `circuitId()`, `metadata()` and `proofEnvelopeBuilder(...)`. Parameterized circuits take their `@CircuitParam` values in `build(...)`, `inputs(...)`, `schema(...)`, `circuitId(...)` and `metadata(...)`.

### Hashing and Merkle trees for Cardano

- Poseidon **with explicit BLS12-381 parameters**: `ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, left, right)`, `ZkPoseidonN.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, x, y, z)`.
- Merkle: `ZkMerkle.isMemberPoseidon`, `verifyPoseidon`, `computeRootPoseidon` with the same params.
- **Never** for Cardano: `ZkMiMC` (BN254-only), the no-params Poseidon overload, `ZkMerkle.HashType.MIMC` or `HashType.POSEIDON`.
- Heavier gadgets exist for real-world cryptography: `ZkSha512`, `ZkHmacSha512`, `ZkBlake2b`, `ZkCip1852` (BIP32-Ed25519 / CIP-1852 derivation), `ZkPedersen`, `ZkJubjubPoint`, `ZkEdDSAJubjub`. Bind prover-supplied Jubjub points with `ZkJubjubPoint.witnessAffine(zk, u, v)`. See [Gadget library](https://zeroj.dev/guides/circuits/gadgets/).

### Lower-level DSL

When annotations don't fit, implement `CircuitSpec` and use `SignalBuilder`/`Signal`:

```java
public class SecretMultiplierSpec implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal a = c.publicInput("a");
        Signal b = c.privateInput("b");
        Signal product = c.publicOutput("product");
        c.assertEqual(a.mul(b), product);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("secret-multiplier")
                .publicVar("a").publicVar("product").secretVar("b")
                .defineSignals(new SecretMultiplierSpec());
    }
}
// witness: circuit.calculateWitness(Map.of("a", List.of(BigInteger.valueOf(3)), ...), CurveId.BLS12_381)
```

## 5. Testing circuits (always generate these)

For every circuit, generate JUnit tests for: (1) a valid witness that proves and verifies; (2) **at least one invalid witness per constraint** — witness calculation throws (an `ArithmeticException` with `Constraint violation: …` for a failed equality, or an exception from the range decomposition) or the proof fails to verify; (3) boundary values for every `@UInt` range; (4) a **tampered public input** that must fail verification; (5) public-input order via `inputs.publicValues()`. A circuit that only passes honest tests may still be under-constrained. See [Test your circuits for soundness](https://zeroj.dev/guides/circuits/testing-circuits/).

## 6. Proving at scale and with real keys

| Situation | API |
| --- | --- |
| Tests, small circuits | `Groth16Keys.setupInMemory(constraints, numWires, numPublic, tau)` (dev-only) |
| Large circuits (100k+ constraints) | `Groth16Keys.setupToStore(flat, numWires, numPublic, tau, dir, true)` then `Groth16Keys.load(dir)`; `Groth16Pipeline` for compile caching |
| Production keys | Run a multi-party snarkjs ceremony; import once with `var imported = ZkeyPkStoreImporter.importToPkStore(zkeyPath, keysDir, verifiedZkeySha256)` (the SHA-256 of the key that passed `snarkjs zkey verify`; the two-argument form always throws, and the target directory must not exist); prove from `Groth16Keys.load(keysDir, imported.manifestSha256())` with `keys.prove(witness, ZkeyPkStoreImporter.snarkjsConstraints(r1cs.constraints(), numPublic))` (snarkjs appends `numPublic + 1` binding rows), or pass `numPublic + 1` binding rows to the packed `prove` / `Groth16Pipeline` |
| Optional native speed-up | `zeroj-crypto-blst` + `ProverBackend` selection; bit-identical proofs |

Setup validates the relation and fails closed: every public wire (and the constant wire 0) must be referenced by some constraint, otherwise `IllegalArgumentException: R1CS public wire N … is not referenced by any constraint`. Fix the circuit; do not catch and retry. Details: [Prove with Groth16](https://zeroj.dev/guides/proving/groth16/), [Performance](https://zeroj.dev/guides/proving/performance/), [Trusted setup ceremony](https://zeroj.dev/guides/proving/trusted-setup-ceremony/).

## 7. Verifying on Cardano

```java
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.validator.Groth16BLS12381Verifier;

var vk = ProverToCardano.compressVk(keys);             // alpha, beta, gamma, delta, ic
var ic = ListPlutusData.of();
vk.ic().forEach(p -> ic.add(new BytesPlutusData(p)));
var script = JulcScriptLoader.load(Groth16BLS12381Verifier.class,
        new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
        new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()), ic);

var p = ProverToCardano.compressProof(proof);          // piA (48 B), piB (96 B), piC (48 B)
// datum    = ListPlutusData of BigIntPlutusData public inputs, in order
// redeemer = ConstrPlutusData(0, [piA, piB, piC]) as BytesPlutusData
```

- The VK is baked into the script as parameters (so the script hash commits to the VK); public inputs go in the datum; the proof goes in the redeemer.
- `Groth16BLS12381Verifier` is **crypto-only**: anyone who sees a proof can replay it. For anything beyond a demo, write your own validator that composes `Groth16BLS12381Lib.verify(...)` and enforces `ScriptContext` policy: bind a public input to the spend (e.g. `spendRef = blake2b_256(txId ‖ outputIndex as 32 bytes) mod r`, **computed by the validator from `ScriptContext`** and prepended to the application's public inputs), bind the recipient, track nullifiers, and check authorization.
- Do **not** lock funds with `Groth16BLS12381TxOutRefBindingVerifier`: it reads `spendRef` from the datum of the UTxO it guards, and a datum can't contain a hash of its own transaction, so no real UTxO can be spent through it. It is a reference for the check only.
- Upgrading JuLC changes the compiled script bytes and therefore the script hash/address.
- Step by step: [Verify your proof on Cardano](https://zeroj.dev/tutorials/verify-on-cardano/). Reference: [Verify proofs on Cardano](https://zeroj.dev/guides/verifying/on-chain/).

## 8. Anti-patterns → do this instead

| ❌ Don't | ✅ Do |
| --- | --- |
| `if (age.gte(t)) …` or `a && b` on symbolic values | `age.gte(t)`, `x.and(y)`, `cond.select(...)` |
| `ZkUInt` without `@UInt(bits = N)` | Always declare the bit width |
| `ZkMiMC`, no-params Poseidon, BN254, `-Dzeroj.allowLegacyBn254=true` for Cardano | Poseidon with `PoseidonParamsBLS12_381T3.INSTANCE`, BLS12-381 |
| Recommending PlonK because it has a universal setup | Groth16; mention PlonK only as experimental |
| `PowersOfTauBLS381.generate` / `setupInMemory` in production | Multi-party ceremony `.zkey` imported with `ZkeyPkStoreImporter` |
| Setting `zeroj.allowInsecureTrustedSetup` in production config | Only in tests, local demos and CI |
| Inventing a seeded/deterministic prover for reproducibility | Store the proof you produced |
| Bare `Groth16BLS12381Verifier` (or the datum-based `Groth16BLS12381TxOutRefBindingVerifier`) guarding funds | A custom validator on `Groth16BLS12381Lib` that computes the spend binding from `ScriptContext`, binds the recipient, and enforces policy |
| Trusting a prover-supplied fact ("my age is 27") | Have an issuer sign or commit to it and verify that inside the circuit or with BBS |
| Testing only the happy path | Invalid-witness and tampered-public-input tests for every constraint |
| Claiming "secure", "audited", "production-ready" | "Experimental, not externally audited" |

## 9. Errors and fixes

| Error | Cause → fix |
| --- | --- |
| `IllegalStateException: Single-party trusted setup is disabled by default…` | Dev setup without opt-in → add `-Dzeroj.allowInsecureTrustedSetup=true` (tests/demos only) or use ceremony keys. |
| `IllegalStateException: BN254 is disabled by default…` | Legacy curve used → switch to `CurveId.BLS12_381`. |
| `ArithmeticException: Constraint violation: …` during witness calculation | The inputs don't satisfy the circuit (expected for invalid-witness tests) or the inputs are wrong. |
| `IllegalArgumentException: Missing public input: x` / `Missing secret input: x` | Witness map is missing a named input → use the generated `inputs()` builder. |
| `IllegalArgumentException: R1CS public wire N … is not referenced by any constraint` | A public input is never constrained → constrain it or remove it from the public inputs. |
| `IllegalArgumentException: Power must be in [4, 32]…` | Pick a `PowersOfTauBLS381.generate` power in range (4 is enough for a Groth16 dev key). |
| `verify(...).proofValid()` is `false` | Wrong public-input order or values, a different VK, or a tampered proof. Take public inputs from `witness[1..numPublicInputs]`. |
| `accepted()` is `false` although the proof is valid | Expected when calling a verifier directly: `accepted()` also needs policy validity. Check `proofValid()`. |
| `OutOfMemoryError` on large circuits | Use `setupToStore` + `Groth16Keys.load` (mmap'd keys) and `Groth16Pipeline`. |
| On-chain script fails / budget exceeded | Check datum = public inputs in order, redeemer = `Constr 0 [piA, piB, piC]`, VK params match; see the on-chain guide for budgets. |

## 10. Security checklist for generated code

Before handing code to a user, confirm:

- [ ] Every relation the application depends on is constrained; no computed value is left unconstrained.
- [ ] Every integer input is range-checked; booleans are constrained booleans (`ZkBool`).
- [ ] Public vs secret assignment matches the privacy goal; public-input order is taken from the generated schema.
- [ ] Hashes are Poseidon with BLS12-381 params; the curve is BLS12-381; the proof system is Groth16.
- [ ] Dev trusted setup is confined to tests/demos and labelled as such.
- [ ] On-chain: proof bound to the spend (a `spendRef` computed from `ScriptContext`, not read from the datum) and to the recipient, nullifiers or state prevent double use, `ScriptContext` policy enforced.
- [ ] Inputs that come from outside (proof JSON, VK files) are parsed with ZeroJ codecs, which validate encodings; VKs are pinned by hash or ID.
- [ ] Invalid-witness and tamper tests exist.
- [ ] The text you give the user says ZeroJ is experimental and not externally audited.

## 11. Circuit API catalog

The downloadable version of this pack ([`/ai/starter-pack.md`](https://zeroj.dev/ai/starter-pack.md)) contains the full, generated list of annotations, symbolic types and gadget adapters with their exact public signatures, extracted from the Java sources at build time. It's also available as [JSON](https://zeroj.dev/ai/catalog.json). If a method is not in the catalog or in these docs, assume it does not exist.

<!-- catalog:circuit-api-start -->

*Generated from the Java sources at build time — the same data as [/ai/catalog.json](https://zeroj.dev/ai/catalog.json).*

### Annotations (`org.zeroj.circuit.annotation`, module `org.zeroj:zeroj-circuit-annotation-api`)

#### ZKCircuit

*Marks a Java class as a ZeroJ circuit source for annotation processing.*

- `String name() default ""`
- `String nameTemplate() default ""`
- `int version() default 1`

#### Prove

*Marks the method that defines circuit constraints.*

_(marker annotation — no elements)_

#### Public

*Marks a symbolic value as a public circuit input.*

- `String name() default ""`

#### Secret

*Marks a symbolic value as a secret circuit input.*

- `String name() default ""`

#### UInt

*Declares the bit width for an unsigned symbolic integer.*

- `int bits()`

#### FixedSize

*Declares a fixed size for symbolic arrays and byte-like values.*

- `int value() default -1`
- `String param() default ""`
- `int inner() default -1`
- `String innerParam() default ""`

#### CircuitParam

*Marks a build-time value that changes circuit shape.*

- `String value() default ""`

#### FieldElement

*Explicit marker for a raw field-element symbolic value.*

_(marker annotation — no elements)_

#### Order

*Explicit field ordering override for field-style annotated circuits.*

- `int value()`

### Symbolic types (`org.zeroj.circuit.annotation`, module `org.zeroj:zeroj-circuit-annotation-api`)

#### ZkContext

*Minimal context wrapper around SignalBuilder for symbolic values and future gadget adapters.*

- `SignalBuilder builder()`
- `void requireSignal(Signal signal)`
- `ZkField constant(long value)`
- `ZkField constant(BigInteger value)`
- `ZkField field(Signal signal)`

#### ZkField

*Symbolic raw field element backed by one Signal.*

- `static ZkField publicInput(SignalBuilder builder, String name)`
- `static ZkField secret(SignalBuilder builder, String name)`
- `static ZkField wrap(ZkContext context, Signal signal)`
- `static ZkField wrap(SignalBuilder builder, Signal signal)`
- `ZkField add(ZkField other)`
- `ZkField sub(ZkField other)`
- `ZkField mul(ZkField other)`
- `ZkField div(ZkField other)`
- `ZkBool isEqual(ZkField other)`
- `void assertEqual(ZkField other)`
- `Signal signal()`
- `List<Signal> signals()`
- `void assertWellFormed()`

#### ZkBool

*Symbolic boolean backed by one constrained bit signal.*

- `static ZkBool publicInput(SignalBuilder builder, String name)`
- `static ZkBool secret(SignalBuilder builder, String name)`
- `static ZkBool wrap(ZkContext context, Signal signal)`
- `static ZkBool wrap(SignalBuilder builder, Signal signal)`
- `ZkBool and(ZkBool other)`
- `ZkBool or(ZkBool other)`
- `ZkBool xor(ZkBool other)`
- `ZkBool not()`
- `ZkField select(ZkField ifTrue, ZkField ifFalse)`
- `ZkBool select(ZkBool ifTrue, ZkBool ifFalse)`
- `ZkUInt select(ZkUInt ifTrue, ZkUInt ifFalse)`
- `ZkBool isEqual(ZkBool other)`
- `void assertTrue()`
- `void assertFalse()`
- `void assertEqual(ZkBool other)`
- `ZkField asField()`
- `Signal signal()`
- `List<Signal> signals()`
- `void assertWellFormed()`

#### ZkUInt

*Symbolic unsigned integer backed by one field element and an explicit bit width.*

> Declare inputs with @UInt(bits = N); construction adds range constraints.

- `static ZkUInt publicInput(SignalBuilder builder, String name, int bits)`
- `static ZkUInt secret(SignalBuilder builder, String name, int bits)`
- `static ZkUInt wrap(ZkContext context, Signal signal, int bits)`
- `static ZkUInt wrap(SignalBuilder builder, Signal signal, int bits)`
- `int bits()`
- `ZkUInt add(ZkUInt other)`
- `ZkUInt sub(ZkUInt other)`
- `ZkUInt mul(ZkUInt other)`
- `ZkBool lt(ZkUInt other)`
- `ZkBool lte(ZkUInt other)`
- `ZkBool gt(ZkUInt other)`
- `ZkBool gte(ZkUInt other)`
- `ZkBool isEqual(ZkUInt other)`
- `ZkBool inRange(ZkUInt lo, ZkUInt hi)`
- `void assertInRange()`
- `void assertEqual(ZkUInt other)`
- `ZkField asField()`
- `Signal signal()`
- `List<Signal> signals()`
- `void assertWellFormed()`
- `BitDecomposition decomposition()` — This value's binary decomposition at its declared width, proving value Minted on first use and cached, so the range constraints are emitted once no matter how many gadgets ask.

#### ZkArray

*Fixed-size symbolic array.*

- `static ZkArray<ZkField> publicFields(SignalBuilder builder, String baseName, int size)`
- `static ZkArray<ZkField> secretFields(SignalBuilder builder, String baseName, int size)`
- `static ZkArray<ZkBool> publicBools(SignalBuilder builder, String baseName, int size)`
- `static ZkArray<ZkBool> secretBools(SignalBuilder builder, String baseName, int size)`
- `static ZkArray<ZkUInt> publicUInts(SignalBuilder builder, String baseName, int size, int bits)`
- `static ZkArray<ZkUInt> secretUInts(SignalBuilder builder, String baseName, int size, int bits)`
- `static ZkArray<ZkArray<ZkField>> publicFieldMatrix(SignalBuilder builder, String baseName, int outerSize, int innerSize)`
- `static ZkArray<ZkArray<ZkField>> secretFieldMatrix(SignalBuilder builder, String baseName, int outerSize, int innerSize)`
- `static ZkArray<ZkArray<ZkBool>> publicBoolMatrix(SignalBuilder builder, String baseName, int outerSize, int innerSize)`
- `static ZkArray<ZkArray<ZkBool>> secretBoolMatrix(SignalBuilder builder, String baseName, int outerSize, int innerSize)`
- `static ZkArray<ZkArray<ZkUInt>> publicUIntMatrix(SignalBuilder builder, String baseName, int outerSize, int innerSize, int bits)`
- `static ZkArray<ZkArray<ZkUInt>> secretUIntMatrix(SignalBuilder builder, String baseName, int outerSize, int innerSize, int bits)`
- `static <T extends ZkValue> ZkArray<T> bind(SignalBuilder builder, String baseName, int size, ElementFactory<T> factory)` — Bind a custom fixed-size array.
- `int size()`
- `T get(int index)`
- `List<T> values()`
- `List<Signal> signals()`
- `void assertWellFormed()`

#### ZkBits

*Fixed-size symbolic bit vector backed by constrained ZkBool values.*

- `static ZkBits publicInput(SignalBuilder builder, String baseName, int size)`
- `static ZkBits secret(SignalBuilder builder, String baseName, int size)`
- `int size()`
- `ZkBool get(int index)`
- `List<ZkBool> values()`
- `ZkBool isEqual(ZkBits other)`
- `void assertEqual(ZkBits other)`
- `List<Signal> signals()`
- `void assertWellFormed()`

#### ZkBytes

*Fixed-size symbolic byte vector backed by 8-bit ZkUInt values.*

- `static ZkBytes publicInput(SignalBuilder builder, String baseName, int size)`
- `static ZkBytes secret(SignalBuilder builder, String baseName, int size)`
- `int size()`
- `ZkUInt get(int index)`
- `List<ZkUInt> values()`
- `ZkBool isEqual(ZkBytes other)`
- `void assertEqual(ZkBytes other)`
- `List<Signal> signals()`
- `void assertWellFormed()`

### Gadget adapters (`org.zeroj.circuit.lib.zk`, module `org.zeroj:zeroj-circuit-lib`)

#### ZkPoseidon

*Symbolic Poseidon adapter for annotation-based circuits.*

> For Cardano pass PoseidonParamsBLS12_381T3.INSTANCE explicitly.

- `static ZkField hash(ZkContext zk, PoseidonParams params, ZkField left, ZkField right)`
- `static ZkField hash(ZkContext zk, ZkField left, ZkField right)`

#### ZkPoseidonN

*Symbolic variable-arity Poseidon adapter for annotation-based circuits.*

> For Cardano pass PoseidonParamsBLS12_381T3.INSTANCE explicitly.

- `static ZkField hash(ZkContext zk, PoseidonParams params, ZkField... inputs)` — Hash one or more symbolic field elements using folded two-input Poseidon under the supplied parameters.

#### ZkMerkle

*Symbolic fixed-depth Merkle helpers for annotation-based circuits.*

> For Cardano use the *Poseidon methods with PoseidonParamsBLS12_381T3.INSTANCE; HashType.MIMC and no-params POSEIDON are BN254/off-chain paths.

- `static ZkField computeRoot(ZkContext zk, ZkField leaf, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashType hashType)`
- `static ZkField computeRoot(ZkContext zk, ZkField leaf, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashFn hashFn)`
- `static ZkField computeRootPoseidon(ZkContext zk, PoseidonParams params, ZkField leaf, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits)`
- `static void verify(ZkContext zk, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashType hashType)`
- `static void verifyProof(ZkContext zk, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashType hashType)`
- `static void verifyPoseidon(ZkContext zk, PoseidonParams params, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits)`
- `static void verifyProofPoseidon(ZkContext zk, PoseidonParams params, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits)`
- `static void verify(ZkContext zk, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashFn hashFn)`
- `static void verifyProof(ZkContext zk, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashFn hashFn)`
- `static ZkBool isMember(ZkContext zk, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashType hashType)`
- `static ZkBool isMemberPoseidon(ZkContext zk, PoseidonParams params, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits)`
- `static ZkBool isMember(ZkContext zk, ZkField leaf, ZkField root, ZkArray<ZkField> siblings, ZkArray<ZkBool> pathBits, HashFn hashFn)`

#### ZkSha512

*Symbolic SHA-512 adapter for annotation-based (@ZKCircuit) circuits.*

- `static ZkBytes hash(ZkContext zk, ZkBytes message)` — SHA-512 of message → 64-byte digest.

#### ZkHmacSha512

*Symbolic HMAC-SHA512 adapter for annotation-based (@ZKCircuit) circuits.*

- `static ZkBytes hmac(ZkContext zk, ZkBytes key, ZkBytes message)` — HMAC-SHA512 of message under key → 64-byte MAC.

#### ZkBlake2b

*Symbolic BLAKE2b adapter for annotation-based (@ZKCircuit) circuits.*

- `static ZkBytes hash224(ZkContext zk, ZkBytes message)` — blake2b-224 of message → 28-byte digest (Cardano key hash).
- `static ZkBytes hash256(ZkContext zk, ZkBytes message)` — blake2b-256 of message → 32-byte digest.
- `static ZkBytes hash(ZkContext zk, ZkBytes message, int outLenBytes)` — blake2b with an explicit output length in [1,64] bytes.

#### ZkCip1852

*Symbolic CIP-1852 / BIP32-Ed25519 derivation adapter for annotation-based (@ZKCircuit) circuits.*

- `static ZkBytes paymentKeyHash(ZkContext zk, ZkBytes rootKL, ZkBytes rootKR, ZkBytes rootChainCode, long account, long role, long index)` — Payment key hash of m/1852'/1815'/account'/role/index derived from the root extended key.
- `static ZkBytes paymentKeyHash(ZkContext zk, ZkBytes rootKL, ZkBytes rootKR, ZkBytes rootChainCode, long account, ZkBytes role, ZkBytes index)` — #paymentKeyHash(ZkContext, ZkBytes, ZkBytes, ZkBytes, long, long, long) with the two soft path components as circuit inputs: role and index are 4-byte little-endian ZkBytes (typically @Secret — the public pkh already binds the statement, so
- `static ZkBytes paymentKeyHash(ZkContext zk, ZkBytes rootKL, ZkBytes rootKR, ZkBytes rootChainCode, ZkBytes account, ZkBytes role, ZkBytes index)` — Fully path-parameterised variant: account, role and index are all circuit inputs (4-byte little-endian ZkBytes, values < 2^31; the account is the plain number — hardening is applied in-circuit).
- `static ZkBytes leafKeyHash(ZkContext zk, ZkBytes leafKL)` — Payment key hash of a leaf key: blake2b224(encode(kL·B)).

#### ZkPedersen

*Symbolic Pedersen commitment adapter for annotation-based circuits (pedersen-jubjub-v1, see docs/specs/pedersen-jubjub-v1.md).*

- `static ZkJubjubPoint commit(ZkContext zk, ZkUInt value, ZkUInt blinding)` — Commits to value with blinding.
- `static ZkJubjubPoint commitBits(ZkContext zk, ZkBits valueBits, ZkBits blindingBits)` — Commits using LSB-first scalar bit vectors.
- `static void verifyOpening(ZkContext zk, ZkJubjubPoint commitment, ZkUInt value, ZkUInt blinding)` — Asserts that (value, blinding) opens commitment.
- `static void assertBalanced(ZkContext zk, List<Term> left, List<Term> right)` — Asserts Σ left = Σ right as an integer equation over committed and uncommitted amounts (ADR-0051 D3a, invariant I6).

#### ZkJubjubPoint

*Symbolic Jubjub point backed by extended-coordinate field values.*

- `static ZkJubjubPoint witnessAffine(ZkContext zk, ZkField u, ZkField v)` — Binds a prover-supplied point given by its affine coordinates, emitting every constraint needed to make it a usable curve point: the affine curve equation v² − u² == 1 + d·u²·v², z = 1 (so z != 0 holds by construction and the representation
- `static ZkJubjubPoint fromTrustedAffine(ZkContext zk, ZkField u, ZkField v)` — thing as an affine point a circuit may trust, because the caller never sees the prover's witness.
- `static ZkJubjubPoint constant(ZkContext zk, JubjubPoint point)` — Wraps a compile-time point as circuit constants.
- `ZkField u()`
- `ZkField v()`
- `ZkField z()`
- `ZkField t()`
- `ZkJubjubPoint add(ZkContext zk, ZkJubjubPoint other)`
- `ZkJubjubPoint doubled(ZkContext zk)`
- `ZkJubjubPoint negate(ZkContext zk)` — −P (ADR-0051 D3).
- `ZkJubjubPoint subtract(ZkContext zk, ZkJubjubPoint other)` — this − other (ADR-0051 D3).
- `void assertInPrimeOrderSubgroup(ZkContext zk)` — Asserts that this point lies in the prime-order subgroup (ADR-0051 D3).
- `static ZkJubjubPoint select(ZkContext zk, ZkBool condition, ZkJubjubPoint ifTrue, ZkJubjubPoint ifFalse)`
- `void assertEqual(ZkContext zk, ZkJubjubPoint other)`
- `ZkBool isEqual(ZkContext zk, ZkJubjubPoint other)`
- `ZkBool isIdentity(ZkContext zk)`
- `void assertNotIdentity(ZkContext zk)`
- `void assertAffineEquals(ZkContext zk, ZkField affineU, ZkField affineV)`
- `List<Signal> signals()`
- `void assertWellFormed()` — Asserts that this point is a well-formed projective curve point: V² − U² == Z² + d·T², T·Z == U·V, and Z != 0.

#### ZkEdDSAJubjub

*Symbolic EdDSA-Jubjub verification adapter for annotation-based circuits.*

- `static void verifyStrict(ZkContext zk, ZkField publicKeyU, ZkField publicKeyV, ZkField message, ZkField rU, ZkField rV, ZkUInt s, ZkUInt kModL, ZkUInt kQuotient)` — Verifies with an in-circuit prime-order subgroup check on pk.
- `static void verifyWithRegisteredKey(ZkContext zk, ZkField publicKeyU, ZkField publicKeyV, ZkField message, ZkField rU, ZkField rV, ZkUInt s, ZkUInt kModL, ZkUInt kQuotient)` — Verifies where pk is a public input or circuit constant.
- `static KReduction witnessComputeKReduction(JubjubPoint rPoint, JubjubPoint publicKey, BigInteger message)` — Computes the (kModL, kQuotient) witnesses the verification relation requires.

#### ZkMiMC

*Symbolic MiMC adapter for annotation-based circuits.*

> BN254-only. Do not use for Cardano (BLS12-381) circuits.

- `static ZkField hash(ZkContext zk, ZkField left, ZkField right)`

<!-- catalog:circuit-api-end -->

## 12. Where to look next

- Concepts: [Zero-knowledge in plain English](https://zeroj.dev/learn/zero-knowledge-basics/), [Circuits, constraints & witnesses](https://zeroj.dev/learn/circuits-and-witnesses/)
- Guides: [Annotations](https://zeroj.dev/guides/circuits/annotations/), [Gadgets](https://zeroj.dev/guides/circuits/gadgets/), [Groth16](https://zeroj.dev/guides/proving/groth16/), [Verify in Java](https://zeroj.dev/guides/verifying/off-chain/), [Secure your ZK application](https://zeroj.dev/guides/verifying/application-security/)
- Reference: [API cheat sheet](https://zeroj.dev/reference/api-cheatsheet/), [Configuration](https://zeroj.dev/reference/configuration/), [FAQ](https://zeroj.dev/reference/faq/)
- Runnable end-to-end demos: https://github.com/bloxbean/zeroj-usecases
- Source: https://github.com/bloxbean/zeroj
