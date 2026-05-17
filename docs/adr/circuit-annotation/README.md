# ADR: Annotation-Based Circuit Authoring for Java Developers

## Status
Accepted for implementation

## Date
2026-05-18

## Vision

ZeroJ already lets Java developers define zero-knowledge circuits without
leaving the Java ecosystem. Today there are two authoring styles:

- `CircuitBuilder#define(...)`, a functional DSL over `CircuitAPI`
- `CircuitSpec#define(SignalBuilder)`, an object-oriented DSL over `Signal`

Both styles are powerful and reusable, but they still require developers to
think in terms of circuit variables, builder declarations, witness maps, and
manual public/private input wiring. The next step is to make circuit authoring
feel more like ordinary Java application code while keeping the generated
circuits explicit, testable, and compatible with the existing ZeroJ compiler
pipeline.

The target developer experience is:

```java
@ZKCircuit(name = "range-proof")
public class RangeProof {
    @Secret
    @UInt(bits = 64)
    ZkUInt secret;

    @Public
    @UInt(bits = 64)
    ZkUInt lo;

    @Public
    @UInt(bits = 64)
    ZkUInt hi;

    @Prove
    ZkBool inRange() {
        return secret.gte(lo).and(secret.lte(hi));
    }
}
```

The generated companion class should expose the normal ZeroJ circuit API:

```java
var circuit = RangeProofCircuit.build();

var witness = circuit.calculateWitness(RangeProofCircuit.inputs()
        .secret(BigInteger.valueOf(42))
        .lo(BigInteger.valueOf(18))
        .hi(BigInteger.valueOf(99))
        .toWitnessMap(), CurveId.BLS12_381);

var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
var plonk = circuit.compilePlonK(CurveId.BLS12_381);
```

Parameterized circuits should keep the current Java-as-template advantage:

```java
var merkle16 = MerkleMembershipCircuit.build(16, HashType.POSEIDON);
var merkle32 = MerkleMembershipCircuit.build(32, HashType.POSEIDON);
```

This feature should not replace `CircuitSpec` or the current DSL. It should
generate code that sits on top of them.

## Why We Are Doing This

ZeroJ's core direction is Java-first circuit authoring, pure Java verification,
and production proving paths over Cardano-relevant curves. The current circuit
DSL is already a major improvement over requiring circom, Go, or Rust, but there
is still ceremony around:

- declaring public and secret variables in `CircuitBuilder`
- binding variable names in the proof body
- remembering bit-width constraints for integer-like values
- constructing `Map<String, List<BigInteger>>` witness inputs
- keeping field names, witness names, and public input order aligned
- explaining to Java developers why `BigInteger` values in a proof body are not
  ordinary runtime values

Annotation-based authoring can reduce that ceremony while preserving the
important circuit model:

- all values inside a circuit are symbolic
- all constraints are generated through the existing `SignalBuilder` and
  `CircuitAPI`
- all circuits still compile to the existing proof-system-agnostic
  `ConstraintGraph`
- all existing circuit libraries remain usable
- advanced users can drop down to `Signal` and `CircuitSpec` when needed

## Non-Goal: Translating Arbitrary Java

The most attractive syntax would be ordinary Java:

```java
@ZKCircuit
public class RangeProof {
    @Witness BigInteger secret;
    @Public BigInteger lo;
    @Public BigInteger hi;

    @Prove
    boolean inRange() {
        return secret.compareTo(lo) >= 0
                && secret.compareTo(hi) <= 0;
    }
}
```

This is not a good v1 target.

`BigInteger.compareTo` computes with concrete runtime values. A circuit proof
body must build symbolic constraints over wires. Supporting the example above
would require Java AST or bytecode translation, a restricted Java subset, and
special handling for method calls, control flow, short-circuit boolean logic,
loops, and object state. That path is possible later, but it is high-risk and
would make circuit behavior harder to reason about.

The v1 design uses symbolic `Zk*` types instead:

```java
@Prove
ZkBool inRange() {
    return secret.gte(lo).and(secret.lte(hi));
}
```

This keeps the code Java-native while making the symbolic nature of circuit
values explicit.

## Decision

Introduce an annotation-based circuit authoring layer built from two modules:

```text
zeroj-circuit-annotation-api
zeroj-circuit-annotation-processor
```

The annotation API module contains annotations, symbolic `Zk*` value types, and
small support abstractions. The annotation processor scans annotated circuits at
compile time and generates companion classes that build normal `CircuitBuilder`
instances.

The generated code must target the existing circuit stack:

```text
Annotated user class
        |
        v
Generated companion class
        |
        v
CircuitBuilder + CircuitSpec + SignalBuilder
        |
        v
ConstraintGraph
        |
        v
R1CS / PlonK / Halo2 compilers and witness calculator
```

No new constraint representation is introduced.

## Module Design

### `zeroj-circuit-annotation-api`

Purpose: public compile-time and runtime API used by application code.

Suggested package:

```text
com.bloxbean.cardano.zeroj.circuit.annotation
```

Dependencies:

```gradle
dependencies {
    api project(':zeroj-circuit-dsl')
}
```

This module should not depend on `zeroj-circuit-lib`. Foundational symbolic
types should stay independent of optional gadgets such as Poseidon, Merkle,
Jubjub, or Pedersen.

Contents:

- annotations: `@ZKCircuit`, `@Prove`, `@Public`, `@Secret`,
  `@CircuitParam`, `@UInt`, `@FieldElement`, `@FixedSize`, `@Order`
- symbolic values: `ZkValue`, `ZkField`, `ZkBool`, `ZkUInt`, `ZkArray`
- deferred symbolic values: `ZkBits`, `ZkBytes`
- support abstractions: `ZkContext`, `ZkTypeAdapter`, `ZkTypeDescriptor`,
  `ZkInputMap`, `ZkCircuitSchema`, `ZkSignalRef`

### `zeroj-circuit-annotation-processor`

Purpose: compile-time source generator.

Suggested package:

```text
com.bloxbean.cardano.zeroj.circuit.annotation.processor
```

Dependencies:

```gradle
dependencies {
    implementation project(':zeroj-circuit-annotation-api')
}
```

Consumer Gradle usage:

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-annotation-api'
    annotationProcessor 'com.bloxbean.cardano:zeroj-circuit-annotation-processor'
}
```

The processor should register with Java's standard annotation processing
mechanism through:

```text
META-INF/services/javax.annotation.processing.Processor
```

The processor should generate source code only. It should not compile circuits
or calculate witnesses during annotation processing.

## Symbolic Type Foundation

### `ZkValue`

Base interface implemented by all symbolic values.

```java
public interface ZkValue {
    List<Signal> signals();
    void assertWellFormed();
}
```

`signals()` returns the flattened signals backing this value. This is used by
generated schema and witness mapping code.

`assertWellFormed()` adds constraints required by the value type. Examples:

- `ZkBool` asserts its signal is boolean
- `ZkUInt` asserts its signal fits the configured bit width
- `ZkArray` asserts every element is well-formed

Public and secret factory methods add required well-formedness constraints
eagerly. `assertWellFormed()` is idempotent and exists as a defensive hook for
generated code and manually wrapped values.

### `ZkField`

Represents one raw field element backed by one `Signal`.

Use cases:

- hash inputs and outputs
- commitments
- nullifiers
- raw scalar field arithmetic

Typical methods:

```java
ZkField add(ZkField other);
ZkField sub(ZkField other);
ZkField mul(ZkField other);
ZkField div(ZkField other);
ZkBool isEqual(ZkField other);
void assertEqual(ZkField other);
Signal signal();
```

### `ZkBool`

Represents one constrained bit.

Typical methods:

```java
ZkBool and(ZkBool other);
ZkBool or(ZkBool other);
ZkBool xor(ZkBool other);
ZkBool not();
<T extends ZkValue> T select(T ifTrue, T ifFalse);
void assertTrue();
void assertFalse();
void assertEqual(ZkBool other);
ZkField asField();
Signal signal();
```

`ZkBool` should call `Signal.assertBoolean()` when constructed from public or
secret input unless the constructor is explicitly internal and trusted.

### `ZkUInt`

Represents an unsigned bounded integer backed by one field element and a bit
width.

Use cases:

- range proofs
- ages and thresholds
- amounts and balances
- bounded counters
- indexes into fixed arrays

Typical methods:

```java
int bits();
ZkUInt add(ZkUInt other);
ZkUInt sub(ZkUInt other);
ZkUInt mul(ZkUInt other);
ZkBool lt(ZkUInt other);
ZkBool lte(ZkUInt other);
ZkBool gt(ZkUInt other);
ZkBool gte(ZkUInt other);
ZkBool isEqual(ZkUInt other);
ZkBool inRange(ZkUInt lo, ZkUInt hi);
void assertInRange();
void assertEqual(ZkUInt other);
ZkField asField();
Signal signal();
```

`ZkUInt` comparisons should use the same algorithm as the existing comparator
gadgets. To avoid a foundational dependency on `zeroj-circuit-lib`, the first
version can use `SignalBuilder.api().lessThan` directly, matching the current
`SignalComparators` implementation.

### `ZkArray<T extends ZkValue>`

Represents a fixed-size symbolic array.

Use cases:

- Merkle siblings
- Merkle path bits
- fixed-size credential fields
- public input vectors
- multi-input commitments

Example:

```java
@Secret
@FixedSize(32)
ZkArray<ZkField> siblings;

@Secret
@FixedSize(32)
ZkArray<ZkBool> pathBits;
```

V1 arrays must have fixed size known at circuit-generation time. The size may be
a literal, or it may reference a build-time `@CircuitParam`. Dynamic arrays
should be modeled later as `maxSize + length + selectors`.

### Deferred: `ZkBits`

Represents a fixed-length bit vector backed by `Signal[]`.

Use cases:

- bit decomposition
- bitwise operations
- fixed byte packing
- cryptographic gadgets that operate on bits

`ZkBits` is useful but not required for the first annotation slice because most
early privacy templates can absorb field elements directly through Poseidon or
MiMC. It should be added after range, array, and hash-gadget workflows are
stable.

### Deferred: `ZkBytes`

Represents a fixed-length byte sequence.

Use cases:

- credential attributes
- messages
- serialized public keys
- serialized signatures
- off-chain data that must be committed inside a circuit

`ZkBytes` should require explicit length. Unbounded strings or byte arrays
should not be allowed. The first implementation can prefer one `ZkUInt(8)` per
byte for clarity, with packed representations added later.

## Annotation Set

### `@ZKCircuit`

Marks a class as a circuit source.

```java
@Target(TYPE)
@Retention(SOURCE)
public @interface ZKCircuit {
    String name() default "";
    String nameTemplate() default "";
}
```

If `name` is empty, use the Java class name converted to a stable circuit name.
For parameterized circuits, `nameTemplate` may include build-time parameters,
for example `merkle-{depth}-{hashType}`. If `nameTemplate` is empty and the
circuit has `@CircuitParam` values, generated code must append a canonical
parameter suffix to avoid reusing one circuit identity for different constraint
systems.

### `@Prove`

Marks the method that defines the circuit constraints.

```java
@Target(METHOD)
@Retention(SOURCE)
public @interface Prove {}
```

V1 rules:

- exactly one `@Prove` method per circuit class
- return type must be `void` or `ZkBool`
- if return type is `ZkBool`, generated code asserts it is true
- if return type is `void`, the method is responsible for adding assertions

The `ZkBool` return form is convenience syntax for single-statement circuits and
small predicates. Complex circuits often mix direct assertions with derived
boolean checks; for those, `void` is equally first-class and may be clearer:

```java
@Prove
void prove(...) {
    amount.assertInRange();
    newBalance.assertInRange();
    senderBalance.sub(amount).assertEqual(newBalance);
    amount.assertEqual(publicAmount);
}
```

### `@Public` and `@Secret`

Mark symbolic inputs.

```java
@Target({FIELD, PARAMETER})
@Retention(SOURCE)
public @interface Public {
    String name() default "";
}

@Target({FIELD, PARAMETER})
@Retention(SOURCE)
public @interface Secret {
    String name() default "";
}
```

Use `@Secret`, not `@Witness`, as the first-class term. ZeroJ already has an
API-level `Witness` type for opaque witness bytes, so using `@Witness` for
input visibility would create naming ambiguity.

### `@CircuitParam`

Marks a build-time parameter that changes the generated constraint system.

```java
@Target({FIELD, PARAMETER})
@Retention(SOURCE)
public @interface CircuitParam {
    String value() default "";
}
```

Circuit parameters are not public inputs and are not secret witnesses. They are
ordinary Java values known before the circuit is built. They control circuit
shape: Merkle depth, hash choice, Poseidon arity, credential schema, or feature
flags that select which fixed constraints are generated.

V1 supported parameter types:

- primitive integers and boxed integer types
- `boolean`
- `String`
- enums

Generated companion classes should expose parameterized build methods:

```java
var circuit = MerkleMembershipCircuit.build(32, HashType.POSEIDON);
```

Each unique parameter set represents a distinct circuit and normally requires a
distinct setup/VK lifecycle.

### `@UInt`

Defines the unsigned bit width for `ZkUInt`.

```java
@Target({FIELD, PARAMETER})
@Retention(SOURCE)
public @interface UInt {
    int bits();
}
```

Rules:

- required for `ZkUInt`
- `bits` must be in the supported range of the underlying circuit API
- v1 should reject `bits <= 0`
- v1 should reject widths greater than the current safe decomposition limit

### `@FieldElement`

Optional explicit marker for `ZkField`.

```java
@Target({FIELD, PARAMETER})
@Retention(SOURCE)
public @interface FieldElement {}
```

This is mostly useful for readability and future validation.

### `@FixedSize`

Defines fixed length for arrays and byte values.

```java
@Target({FIELD, PARAMETER})
@Retention(SOURCE)
public @interface FixedSize {
    int value() default -1;
    String param() default "";
}
```

Required for `ZkBytes` and `ZkArray`. Use `value` for a literal size and
`param` to reference a build-time `@CircuitParam`.

Examples:

```java
@Secret
@FixedSize(32)
ZkArray<ZkField> fixedSiblings;

@Secret
@FixedSize(param = "depth")
ZkArray<ZkField> parametricSiblings;
```

Exactly one of `value` or `param` must be set. `param` must reference a visible
integer `@CircuitParam`.

### `@Order`

Optional explicit field ordering annotation.

```java
@Target(FIELD)
@Retention(SOURCE)
public @interface Order {
    int value();
}
```

V1 naming uses `@Public(name = "...")` and `@Secret(name = "...")`; there is no
separate `@Name` annotation in v1. `@Order` is optional for field style and
exists for callers who want explicit ordering independent of source position.

Ordering rules:

- order public and secret groups separately
- reject negative `@Order` values
- reject duplicate `@Order` values within a visibility group
- sort ordered fields by ascending `@Order`
- append unordered fields in source declaration order after ordered fields
- fail if stable source declaration order is unavailable

## Authoring Styles

### Field Style

Field style is closer to typical Java model classes.

```java
@ZKCircuit(name = "range-proof")
public class RangeProof {
    @Secret @UInt(bits = 64)
    ZkUInt secret;

    @Public @UInt(bits = 64)
    ZkUInt lo;

    @Public @UInt(bits = 64)
    ZkUInt hi;

    @Prove
    ZkBool inRange() {
        return secret.gte(lo).and(secret.lte(hi));
    }
}
```

Generated code must instantiate the class, assign symbolic fields, then call the
proof method.

V1 field-style rules for symbolic input fields:

- fields cannot be `final`
- fields must be package-private, protected, or public
- private fields are rejected unless setter/constructor binding is added later
- a no-arg constructor must be visible to generated code
- exactly one visibility annotation is required per symbolic field
- field ordering is deterministic: public fields first, then secret fields; each
  group sorts ordered fields by ascending non-negative `@Order`, rejects
  duplicates within the group, then appends unordered fields in source
  declaration order as reported by `javac`; processors that cannot recover
  stable source order must fail with a diagnostic and suggest `@Order` or
  parameter style

Advantages:

- concise for small circuits
- resembles normal Java data models
- easy to add helper methods using instance fields

Disadvantages:

- mutation during generated binding is less elegant
- private/final fields complicate generation
- constructor requirements must be documented clearly

Recommendation: support in the MVP because this is the primary target syntax for
Java developers writing small and medium circuits. Generated code must avoid
reflection by emitting the companion class in the same package.

### Parameter Style

Parameter style avoids field injection for symbolic inputs and is the best fit
for tests, small pure functions, and circuits where the proof method should make
all symbolic dependencies explicit.

```java
@ZKCircuit(name = "range-proof")
public class RangeProof {
    @Prove
    ZkBool prove(
            @Secret @UInt(bits = 64) ZkUInt secret,
            @Public @UInt(bits = 64) ZkUInt lo,
            @Public @UInt(bits = 64) ZkUInt hi) {
        return secret.gte(lo).and(secret.lte(hi));
    }
}
```

Generated shape:

```java
public final class RangeProofCircuit {
    public static CircuitBuilder build() {
        return CircuitBuilder.create("range-proof")
                .publicVar("lo")
                .publicVar("hi")
                .secretVar("secret")
                .defineSignals(c -> {
                    var instance = new RangeProof();
                    var secret = ZkUInt.secret(c, "secret", 64);
                    var lo = ZkUInt.publicInput(c, "lo", 64);
                    var hi = ZkUInt.publicInput(c, "hi", 64);
                    instance.prove(secret, lo, hi).assertTrue();
                });
    }
}
```

Advantages:

- no mutable field injection for symbolic inputs
- proof method is easy to unit test directly
- easier compiler validation

Disadvantages:

- repeated annotations on long method signatures can get noisy
- sharing values across helper methods requires passing parameters or storing in
  local variables
- instance `@Prove` methods still need a visible no-arg constructor unless the
  method is static

Recommendation: support in the MVP alongside field style.

### Hybrid Style

Advanced circuits may need access to the current `SignalBuilder`.

```java
@Prove
ZkBool prove(ZkContext zk,
             @Secret @UInt(bits = 64) ZkUInt amount,
             @Public ZkField commitment) {
    var hash = zk.poseidon().hash(amount.asField(), zk.constant(0));
    return hash.isEqual(commitment);
}
```

The `ZkContext` wraps `SignalBuilder` and exposes:

- constants
- raw `SignalBuilder` access for advanced interop
- factory methods for symbolic values
- optional gadget namespaces

V1 should include a minimal `ZkContext` because the first usable slice includes
hash and Merkle adapters. Simple range/comparison circuits can still avoid it.

## Build-Time Parametric Circuits

Real circuits are often templates: the same source code produces different
constraint systems for different depths, arities, hash functions, credential
schemas, or feature flags. The annotation layer must preserve the existing Java
template capability shown by `NWayMerkleCircuit(int depth, HashType hashType)`.

Use `@CircuitParam` for values that shape the circuit at build time:

```java
@ZKCircuit(
        name = "merkle-membership",
        nameTemplate = "merkle-membership-d{depth}-{hashType}")
public class MerkleMembership {
    private final int depth;
    private final HashType hashType;

    public MerkleMembership(@CircuitParam("depth") int depth,
                            @CircuitParam("hashType") HashType hashType) {
        if (depth < 1) throw new IllegalArgumentException("depth must be >= 1");
        this.depth = depth;
        this.hashType = hashType;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkField leaf,
            @Public ZkField root,
            @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "depth") ZkArray<ZkBool> pathBits) {

        var computed = ZkMerkle.computeRoot(zk, leaf, siblings, pathBits, hashType);
        return computed.isEqual(root);
    }
}
```

Generated shape:

```java
public final class MerkleMembershipCircuit {
    public static CircuitBuilder build(int depth, HashType hashType) {
        var instance = new MerkleMembership(depth, hashType);
        return CircuitBuilder.create(circuitName(depth, hashType))
                .publicVar("root")
                .secretVar("leaf")
                // generated loops declare sibling_0..sibling_{depth-1}
                // and pathBit_0..pathBit_{depth-1}
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var leaf = ZkField.secret(c, "leaf");
                    var root = ZkField.publicInput(c, "root");
                    var siblings = ZkArray.secret(c, "sibling", depth, ZkField::secret);
                    var pathBits = ZkArray.secret(c, "pathBit", depth, ZkBool::secret);
                    // bind symbolic arrays using the concrete depth
                    instance.prove(zk, leaf, root, siblings, pathBits).assertTrue();
                });
    }
}
```

Rules:

- a `@CircuitParam` is never a public input and never a secret witness
- changing a circuit parameter changes the circuit identity and VK lifecycle
- generated `schema()` must include parameter names and values
- generated input builders for parameterized circuits are produced from a
  concrete parameter set, e.g. `MerkleMembershipCircuit.inputs(32, POSEIDON)`
- `@FixedSize(param = "...")` can reference integer circuit parameters
- parameter validation remains ordinary Java constructor validation

## Existing Circuit Library Interop

The annotation layer must make existing gadget libraries easy to use.

Every symbolic type should expose its underlying signal:

```java
Signal signal();
```

For multi-signal values:

```java
Signal[] signalsArray();
List<Signal> signals();
```

This allows users and generated adapters to call existing functions when no
symbolic adapter exists yet:

```java
var hash = SignalMiMC.hash(zk.builder(),
        secret.signal(),
        nullifier.signal());

return ZkField.wrap(zk, hash).isEqual(commitment);
```

This fallback is useful for escape hatches, but it should not be the main v1
developer experience. The MVP needs symbolic adapters for the gadgets used by
the first real privacy templates:

```java
ZkField hash = ZkPoseidon.hash(zk, left, right);
ZkMerkle.verify(zk, leaf, root, siblings, pathBits, ZkPoseidon::hash);
```

Proposed package for these adapters:

```text
com.bloxbean.cardano.zeroj.circuit.lib.zk
```

MVP adapters:

- `ZkMiMC`
- `ZkPoseidon`
- `ZkMerkle` for fixed-depth membership proofs

These adapters live in `zeroj-circuit-lib`, not in
`zeroj-circuit-annotation-api`, so the dependency direction remains:

```text
zeroj-circuit-dsl
    ^
    |
zeroj-circuit-annotation-api
    ^
    |
zeroj-circuit-lib symbolic adapters
```

### Dual API Maintenance Policy

The symbolic layer creates a second public surface over the same constraint
logic. This is useful, but it is a real maintenance commitment.

Policy:

- `Zk*` gadget adapters must be thin wrappers around existing `Signal*` or
  `Variable` gadgets whenever possible
- public reusable gadgets that are expected to be used from annotated circuits
  should ship both a `Signal*` API and a `Zk*` adapter
- each `Zk*` adapter must have differential tests against the existing DSL
- if a gadget intentionally remains `Signal`-only, document it as an advanced
  escape hatch
- new privacy-template work should budget time for both surfaces

## Generated Artifacts

For a source class:

```java
com.example.RangeProof
```

Generate:

```text
com.example.RangeProofCircuit
```

The final generated class should include:

- `build()`
- parameterized `build(...)` when the source uses `@CircuitParam`
- `schema()`
- parameterized `schema(...)` when the source uses `@CircuitParam`
- `inputs()`
- parameterized `inputs(...)` when the source uses `@CircuitParam`
- `publicInputs(...)` helper if useful
- constants for generated input names

Phase 4 generates only `build(...)` and constants. Phase 5 adds `schema(...)`,
`inputs(...)`, and `publicInputs(...)`. Examples at the top of this ADR describe
the final target surface after Phase 5.

Example generated public API:

```java
public final class RangeProofCircuit {
    public static final String CIRCUIT_NAME = "range-proof";
    public static final String SECRET = "secret";
    public static final String LO = "lo";
    public static final String HI = "hi";

    public static CircuitBuilder build();

    public static ZkCircuitSchema schema();

    public static Inputs inputs();

    public static final class Inputs {
        public Inputs secret(BigInteger value);
        public Inputs lo(BigInteger value);
        public Inputs hi(BigInteger value);
        public Map<String, List<BigInteger>> toWitnessMap();
        public List<BigInteger> publicValues();
    }
}
```

Generated input builders are important because the current witness calculator
takes `Map<String, List<BigInteger>>`. Hand-written maps are easy to mistype and
do not preserve the schema in a developer-friendly way.

For parameterized circuits, generated helpers take the same build-time
parameters and produce schema/input builders for that concrete circuit shape:

```java
var circuit = MerkleMembershipCircuit.build(32, HashType.POSEIDON);
var schema = MerkleMembershipCircuit.schema(32, HashType.POSEIDON);
var inputs = MerkleMembershipCircuit.inputs(32, HashType.POSEIDON);
```

## Input Naming and Ordering

Stable public input order is critical because public inputs are part of proof
verification.

Rules:

- public inputs are declared before secret inputs in `CircuitBuilder`, matching
  current wire numbering
- within each visibility group, preserve source order
- for method parameter style, source order is method parameter order
- for field style, use explicit `@Order` where provided; otherwise use source
  declaration order from `javac`; ordered fields sort before unordered fields
  within the same visibility group; duplicate or negative `@Order` values fail
- generated `schema()` must expose the exact order
- circuit parameters are recorded in schema metadata but are not public or
  secret inputs
- generated/flattened input names must be unique within the circuit; duplicate
  names fail at compile time

Nested names should flatten with `.` or `_`. The v1 choice should be `_` to
match existing circuit variable naming patterns:

```text
credential_age
credential_countryCode
path_0
path_1
```

## Type Adapter Design

`ZkTypeAdapter<T>` bridges Java host values, symbolic circuit values, and
flattened input maps.

Conceptual interface:

```java
public interface ZkTypeAdapter<T extends ZkValue> {
    T bindPublic(ZkContext zk, String name, ZkTypeDescriptor descriptor);
    T bindSecret(ZkContext zk, String name, ZkTypeDescriptor descriptor);
    List<String> signalNames(String name, ZkTypeDescriptor descriptor);
    List<BigInteger> encodeHostValue(Object value, ZkTypeDescriptor descriptor);
}
```

Built-in adapters:

- `ZkFieldAdapter`
- `ZkBoolAdapter`
- `ZkUIntAdapter`
- `ZkArrayAdapter`

Deferred built-in adapters:

- `ZkBitsAdapter`
- `ZkBytesAdapter`

Later adapters:

- `ZkJubjubPointAdapter`
- `ZkEdDSASignatureAdapter`
- `ZkMerklePathAdapter`
- `ZkCredentialAdapter`

Adapters let complex circuits stay readable without hardcoding every domain
type into the annotation processor.

## Circuit Examples

### Range Proof

```java
@ZKCircuit(name = "range-proof")
public class RangeProof {
    @Prove
    ZkBool prove(
            @Secret @UInt(bits = 64) ZkUInt secret,
            @Public @UInt(bits = 64) ZkUInt lo,
            @Public @UInt(bits = 64) ZkUInt hi) {
        return secret.gte(lo).and(secret.lte(hi));
    }
}
```

### Age Verification

```java
@ZKCircuit(name = "age-check")
public class AgeCheck {
    @Prove
    ZkBool prove(
            @Secret @UInt(bits = 8) ZkUInt age,
            @Public @UInt(bits = 8) ZkUInt threshold) {
        return age.gte(threshold);
    }
}
```

### Private Transfer

```java
@ZKCircuit(name = "private-transfer")
public class PrivateTransfer {
    @Prove
    ZkBool prove(
            @Secret @UInt(bits = 64) ZkUInt senderBalance,
            @Secret @UInt(bits = 64) ZkUInt amount,
            @Secret @UInt(bits = 64) ZkUInt newBalance,
            @Public @UInt(bits = 64) ZkUInt publicAmount) {

        amount.assertInRange();
        newBalance.assertInRange();

        var balanceMatches = senderBalance.sub(amount).isEqual(newBalance);
        var amountMatches = amount.isEqual(publicAmount);

        return balanceMatches.and(amountMatches);
    }
}
```

### Hash Commitment With Existing Gadget

```java
@ZKCircuit(name = "vote-commitment")
public class VoteCommitment {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkBool vote,
            @Secret ZkField nullifier,
            @Public ZkField commitment) {

        return ZkMiMC.hash(zk, vote.asField(), nullifier).isEqual(commitment);
    }
}
```

### Merkle Proof

```java
@ZKCircuit(
        name = "membership-proof",
        nameTemplate = "membership-proof-d{depth}-{hashType}")
public class MembershipProof {
    private final int depth;
    private final HashType hashType;

    public MembershipProof(@CircuitParam("depth") int depth,
                           @CircuitParam("hashType") HashType hashType) {
        this.depth = depth;
        this.hashType = hashType;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkField leaf,
            @Public ZkField root,
            @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "depth") ZkArray<ZkBool> pathBits) {

        var computed = ZkMerkle.computeRoot(
                zk,
                leaf,
                siblings,
                pathBits,
                hashType);

        return computed.isEqual(root);
    }
}
```

This example depends on the MVP circuit-lib symbolic adapters.

## Unit Testing Strategy

Annotation-based circuits must be as easy to test as existing `CircuitSpec`
circuits. Testing should happen at nine levels.

### 1. Symbolic Type Unit Tests

Test the `Zk*` types directly by building tiny circuits.

Example:

```java
@Test
void uintGreaterOrEqualAcceptsValidWitness() {
    var circuit = CircuitBuilder.create("gte")
            .publicVar("ok")
            .secretVar("age")
            .publicVar("threshold")
            .defineSignals(c -> {
                var age = ZkUInt.secret(c, "age", 8);
                var threshold = ZkUInt.publicInput(c, "threshold", 8);
                var ok = ZkBool.publicInput(c, "ok");

                age.gte(threshold).assertEqual(ok);
            });

    assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
            "age", List.of(BigInteger.valueOf(25)),
            "threshold", List.of(BigInteger.valueOf(18)),
            "ok", List.of(BigInteger.ONE)), CurveId.BN254));
}
```

These tests verify that symbolic wrappers generate the same constraints as the
current `Signal` API.

### 2. Annotation Processor Compile Tests

Use compile-testing style tests to compile small annotated source files and
assert generated source.

Goals:

- valid circuits compile
- invalid circuits fail with clear messages
- generated `build()` compiles
- generated input names are stable
- generated public/secret ordering is deterministic

Recommended test cases:

- one valid parameter-style range proof
- one valid field-style range proof
- one valid parameterized Merkle proof
- missing `@Prove` method fails
- two `@Prove` methods fail
- `ZkUInt` without `@UInt` fails
- `@UInt(bits = 0)` fails
- field with both `@Public` and `@Secret` fails
- unsupported `BigInteger` proof parameter fails with a message pointing to
  `ZkField` or `ZkUInt`
- `@Prove boolean` fails with a message explaining symbolic `ZkBool`
- private field-style binding fails in v1
- non-fixed `ZkArray` fails
- `@FixedSize(param = "depth")` fails if `depth` is not a known integer
  `@CircuitParam`
- Phase 4 parameterized circuits generate `build(...)` methods with matching
  parameter lists; Phase 5 adds `schema(...)` and `inputs(...)`

The processor should prefer precise compiler diagnostics over runtime
exceptions.

### 3. Generated Circuit Behavior Tests

Use generated companion classes from test fixtures.

Example:

```java
@Test
void generatedRangeProofAcceptsValidWitness() {
    var circuit = RangeProofCircuit.build();

    var inputs = RangeProofCircuit.inputs()
            .secret(BigInteger.valueOf(42))
            .lo(BigInteger.valueOf(18))
            .hi(BigInteger.valueOf(99))
            .toWitnessMap();

    assertDoesNotThrow(() ->
            circuit.calculateWitness(inputs, CurveId.BLS12_381));
}

@Test
void generatedRangeProofRejectsInvalidWitness() {
    var circuit = RangeProofCircuit.build();

    var inputs = RangeProofCircuit.inputs()
            .secret(BigInteger.valueOf(12))
            .lo(BigInteger.valueOf(18))
            .hi(BigInteger.valueOf(99))
            .toWitnessMap();

    assertThrows(ArithmeticException.class, () ->
            circuit.calculateWitness(inputs, CurveId.BLS12_381));
}
```

These tests confirm end-to-end behavior through the existing witness calculator.

### 4. Backend Compilation Tests

Every representative generated circuit should compile to each backend currently
supported by `CircuitBuilder`:

```java
assertNotNull(circuit.compileR1CS(CurveId.BN254));
assertNotNull(circuit.compilePlonK(CurveId.BN254));
assertNotNull(circuit.compileHalo2(CurveId.BN254));
```

For field-specific gadgets such as Poseidon over BLS12-381, tests should also
verify `requireField` behavior.

### 5. Golden Schema Tests

Generated schema should be stable and testable.

Example assertions:

```java
var schema = RangeProofCircuit.schema();

assertEquals("range-proof", schema.name());
assertEquals(List.of("lo", "hi"), schema.publicInputs().names());
assertEquals(List.of("secret"), schema.secretInputs().names());
assertEquals(64, schema.input("secret").bits());
```

This prevents accidental public input reordering.

### 6. Negative Witness Tests

Each circuit example should include invalid witness tests:

- range proof below lower bound
- range proof above upper bound
- boolean input set to `2`
- `ZkUInt` value exceeding its bit width
- wrong commitment
- wrong Merkle sibling
- wrong public root

Negative tests are essential because a circuit that accepts valid witnesses but
also accepts invalid witnesses is broken.

### 7. Differential Tests Against Existing DSL

For simple circuits, build the same circuit with both styles:

- hand-written `CircuitSpec`
- generated annotation companion

Then compare:

- witness behavior
- public input order
- approximate constraint count
- output values

The exact gate list may differ if wrappers add explicit well-formedness
constraints earlier, but behavior must match.

### 8. Parametric Circuit Tests

For circuits with `@CircuitParam`, test more than one concrete shape:

- `MerkleMembershipCircuit.build(16, POSEIDON)`
- `MerkleMembershipCircuit.build(32, POSEIDON)`
- `MerkleMembershipCircuit.build(32, MIMC)`

Assertions:

- generated circuit names differ by parameter set
- schema records the concrete parameters
- array input builders generate the expected number of elements
- witness calculation succeeds for a valid proof path
- changing depth or hash type without changing inputs fails clearly

### 9. Symbolic Gadget Adapter Tests

For every `Zk*` adapter in `zeroj-circuit-lib`, test against the corresponding
existing gadget:

- `ZkPoseidon` versus `SignalPoseidon`
- `ZkMiMC` versus `SignalMiMC`
- `ZkMerkle` versus `SignalMerkle`

The adapter should add no new cryptographic logic unless it is unavoidable.

## Validation and Error Messages

Processor errors should be written for Java developers who may not know circuit
internals.

Examples:

```text
@Prove method RangeProof.inRange returns boolean.
Circuit proof methods must return ZkBool or void because circuit values are
symbolic. Use ZkBool and methods such as gte(...).and(...).
```

```text
Field secret has type ZkUInt but no @UInt(bits = ...).
Unsigned integer circuit values need an explicit bit width so ZeroJ can add
range constraints.
```

```text
Field message has type ZkBytes but no @FixedSize.
Circuit byte arrays must have a fixed length at compile time.
```

```text
Field x cannot be both @Public and @Secret.
Choose exactly one visibility annotation.
```

## Security and Soundness Requirements

The annotation layer must not silently weaken circuits.

Rules:

- `ZkBool` inputs must always be boolean-constrained
- `ZkUInt` inputs must always be range-constrained
- `ZkBytes` inputs must constrain each byte to 8 bits
- `ZkArray` length must be fixed at circuit generation time
- `@CircuitParam` values must be included in circuit identity/schema metadata
- data-dependent branching must use symbolic `select`, not Java `if`
- `@Prove` returning `ZkBool` must assert true in generated code
- public input order must be deterministic and exposed in schema
- unsupported Java types must fail at compile time

## Control Flow Rules

Normal Java loops are allowed when they are circuit-generation loops with fixed
bounds.

Good:

```java
for (int i = 0; i < siblings.size(); i++) {
    current = hash(current, siblings.get(i));
}
```

Bad:

```java
if (secret.gte(lo)) {
    return doOneThing();
} else {
    return doAnotherThing();
}
```

`secret.gte(lo)` returns `ZkBool`, not Java `boolean`. Developers must use:

```java
condition.select(ifTrue, ifFalse);
```

The symbolic API should make invalid Java branching impossible by type.

## Documentation Requirements

The public documentation should explain:

- circuit values are symbolic
- `ZkBool` is not Java `boolean`
- `ZkUInt` is not `BigInteger`
- when to use annotations versus `CircuitSpec`
- how public input order is derived
- how build-time `@CircuitParam` values affect circuit identity and setup
- how to test circuits
- how to use existing `zeroj-circuit-lib` gadgets
- how to inspect generated source

Minimum docs:

- `zeroj-circuit-annotation-api/README.md`
- examples under `zeroj-examples`
- one migration guide from `CircuitSpec` to annotations
- one advanced interop example using `SignalMiMC` or `SignalPoseidon`

## Phased Implementation Plan

The timeline below assumes one primary contributor and starts after this ADR is
accepted. The estimates are working-time estimates, not calendar commitments.

### Phase 0: ADR and API Review

Estimated time: 1 to 2 days.

Deliverables:

- review this ADR
- agree on module names
- agree on annotation names: `@Secret` versus `@PrivateInput`
- agree that field style and parameter style both ship in the MVP
- agree that `@CircuitParam` is required before the MVP processor is complete
- agree that `ZkMiMC`, `ZkPoseidon`, and `ZkMerkle` adapters move into the first
  usable slice
- agree on the dual-API maintenance policy for future gadgets

Exit criteria:

- maintainers agree that the annotation layer generates `CircuitSpec` /
  `CircuitBuilder` code and does not introduce a new constraint engine

### Phase 1: Module Scaffolding

Estimated time: 0.5 to 1 day.

Deliverables:

- add `zeroj-circuit-annotation-api`
- add `zeroj-circuit-annotation-processor`
- add modules to `settings.gradle`
- add BOM entries to `zeroj-bom-core` and `zeroj-bom-all`
- add basic README placeholders
- add processor service registration

Exit criteria:

- `./gradlew :zeroj-circuit-annotation-api:test`
- `./gradlew :zeroj-circuit-annotation-processor:test`
- all modules compile with no generated circuits yet

### Phase 2: Foundational Symbolic Types and Parameters

Estimated time: 5 to 7 days.

Deliverables:

- `ZkValue`
- `ZkField`
- `ZkBool`
- `ZkUInt`
- `ZkArray<T>`
- minimal `ZkContext`
- `@CircuitParam`
- `@FixedSize` with literal and parameter-reference modes
- direct factory methods for public and secret inputs
- unit tests comparing behavior to hand-written `Signal` circuits

Initial scope:

```java
ZkUInt.secret(c, "secret", 64);
ZkUInt.publicInput(c, "lo", 64);
ZkBool.assertTrue();
ZkUInt.gte(...);
ZkArray.secret(c, "sibling", depth, ZkField::secret);
```

Exit criteria:

- a hand-written symbolic range circuit works without annotations
- a hand-written symbolic fixed-depth Merkle input shape works without
  annotations
- valid witnesses pass
- invalid witnesses fail
- backend compilation works for R1CS, PlonK, and Halo2 where supported

### Phase 3: MVP Symbolic Gadget Adapters

Estimated time: 3 to 5 days.

Deliverables in `zeroj-circuit-lib`:

- `ZkMiMC`
- `ZkPoseidon`
- `ZkMerkle` for fixed-depth membership proofs
- differential tests against `SignalMiMC`, `SignalPoseidon`, and `SignalMerkle`

Exit criteria:

- hash commitment can be written without `.signal()` / `wrap(...)` boilerplate
- Merkle membership can be written with `ZkArray`
- adapters reuse existing `Signal` or `Variable` gadgets

### Phase 4: MVP Annotation Processor

Estimated time: 6 to 9 days.

Deliverables:

- process `@ZKCircuit`
- process field-style `@Prove`
- process parameter-style `@Prove`
- process `@CircuitParam`
- process `@FixedSize(param = "...")`
- support `@Public`, `@Secret`, `@UInt`, `@FieldElement`
- generate `*Circuit.build(...)`
- generate constants for input names
- emit useful compile-time errors
- add compile tests

MVP supported circuits:

- field-style range proof
- parameter-style range proof
- parameterized Merkle membership with depth and hash type

Exit criteria:

- generated `RangeProofCircuit.build()` compiles
- generated `MerkleMembershipCircuit.build(32, POSEIDON)` compiles
- generated circuits calculate witnesses successfully for valid inputs
- generated circuits reject invalid inputs
- processor rejects unsupported `boolean` and `BigInteger` proof methods
- processor rejects invalid `@FixedSize(param = "...")` references

### Phase 5: Generated Input Builders and Schema

Estimated time: 3 to 5 days.

Deliverables:

- `ZkCircuitSchema`
- generated `schema(...)`
- generated `inputs(...)` builder
- generated `publicInputs(...)` helper
- parameter metadata in schema
- schema tests for stable ordering

Exit criteria:

- users no longer need to hand-write `Map<String, List<BigInteger>>` for simple
  generated circuits
- parameterized input builders produce concrete array element methods or indexed
  setters for the selected depth
- public and secret input order is exposed and tested

### Phase 6: Examples and Documentation

Estimated time: 2 to 4 days.

Deliverables:

- `zeroj-examples` field-style range proof
- parameter-style age verification
- private transfer example
- hash commitment example
- parameterized Merkle proof example
- README with authoring rules and testing examples

Exit criteria:

- a new Java developer can copy an annotated circuit example and run tests
- docs explain when to use annotations and when to use `CircuitSpec`
- docs explain how `@CircuitParam` affects circuit identity and VK lifecycle

### Phase 7: Deferred Bits and Bytes

Estimated time: 3 to 5 days.

Deliverables:

- `ZkBits`
- `ZkBytes`
- byte and bit input encoding
- unit tests and generated circuit tests

Exit criteria:

- fixed-size byte messages can be represented
- invalid byte values are rejected
- byte/bit APIs do not complicate the v1 range/hash/Merkle surface

### Phase 8: Advanced Circuit Library Symbolic Adapters

Estimated time: 4 to 8 days.

Deliverables in `zeroj-circuit-lib`:

- `ZkPedersen`
- Jubjub point/signature adapters where needed
- credential-template adapters
- additional hash arity adapters as real templates require them

Exit criteria:

- advanced adapters follow the dual-API maintenance policy
- privacy-template examples use symbolic adapters instead of raw `Signal`
  plumbing

### Phase 9: Integration With Proving Flows

Estimated time: 3 to 6 days.

Deliverables:

- generated helpers for public input extraction
- examples feeding generated circuits into existing prover paths
- optional helper to produce `PublicInputs`
- optional helper to export witness bytes if needed by a prover path
- generated circuit ID/version metadata suitable for proof envelopes

Exit criteria:

- annotated circuit can go from source code to compile, witness, prove, verify
  in an example

## Suggested Release Slices

### Slice 1: Developer Preview

Includes:

- modules
- `ZkField`, `ZkBool`, `ZkUInt`, `ZkArray`
- `@CircuitParam`
- field-style and parameter-style annotation processing
- generated `build(...)`
- `ZkMiMC`, `ZkPoseidon`, and basic `ZkMerkle`
- range proof, age check, hash commitment, and parameterized Merkle examples

This is enough to validate ergonomics against realistic privacy templates, not
only trivial range proofs.

### Slice 2: Usable MVP

Includes:

- generated schema
- generated input builders
- parameter metadata in schema
- better diagnostics
- negative tests
- private transfer example

This is enough for early users to write simple and medium circuits without
hand-written witness maps.

### Slice 3: Complex Circuit Support

Includes:

- `ZkBits`, `ZkBytes`
- fixed-size nested data
- advanced symbolic circuit-lib adapters
- credential-oriented examples

This is enough for richer credential templates and byte-oriented integrations.

### Slice 4: Production Hardening

Includes:

- stronger compile-testing coverage
- generated source stability tests
- native-image review
- documentation polish
- end-to-end prover examples

## Phase 0 Decisions

| Topic | Decision |
|-------|----------|
| Public visibility annotation | Use `@Public`. |
| Secret visibility annotation | Use `@Secret`. |
| Input renaming | Use `@Public(name = "...")` and `@Secret(name = "...")`; no separate `@Name` in v1. |
| Generated class suffix | Use `Circuit`, e.g. `RangeProofCircuit`. |
| Field style | Ship in MVP; reject private/final symbolic input fields in v1. |
| Parameter style | Ship in MVP alongside field style. |
| Field ordering | Public fields first, then secret fields; within each group sort non-negative unique `@Order` values first, then unordered fields by stable javac source order; fail if stable order is unavailable. |
| Circuit parameters | Support constructor parameters and final fields initialized from those parameters. |
| Parameterized names | Use `nameTemplate` when provided; otherwise append a canonical parameter suffix. |
| Processor output | Generate source code only. |
| First generated API slice | Phase 4 emits `build(...)` and constants; Phase 5 adds `schema(...)`, `inputs(...)`, and `publicInputs(...)`. |
| First usable gadget adapters | `ZkMiMC`, `ZkPoseidon`, and basic `ZkMerkle`. |
| BOM scope | Include annotation modules in `zeroj-bom-core` and `zeroj-bom-all` during Phase 1. |
| UInt arithmetic width | Be conservative; arithmetic methods document range behavior and callers assert output range where overflow matters. |

## Remaining Open Questions

None for the MVP plan. Future phases may reopen private field binding, metadata
resource generation, richer ordering policies, or byte packing strategies if a
real use case requires them.

## Risks and Mitigations

### Risk: Developers think `ZkBool` is Java `boolean`

Mitigation:

- make examples consistently use `ZkBool`
- reject `@Prove boolean` with clear diagnostics
- document symbolic control flow

### Risk: Public input ordering changes accidentally

Mitigation:

- generated schema exposes ordering
- golden schema tests
- source-order preservation rules
- explicit `@Order` for field style when source order needs to be pinned

### Risk: Annotation processor becomes too smart

Mitigation:

- generate straightforward Java code
- do not analyze method bodies
- require explicit symbolic types
- keep AST/bytecode translation out of v1

### Risk: Foundational API depends on too many gadgets

Mitigation:

- keep `zeroj-circuit-annotation-api` dependent only on `zeroj-circuit-dsl`
- put Poseidon, Merkle, Jubjub, and Pedersen symbolic adapters in
  `zeroj-circuit-lib`

### Risk: Symbolic adapters drift from existing gadgets

Mitigation:

- make `Zk*` adapters thin wrappers over `Signal*` or `Variable` gadgets
- require differential tests for every adapter
- treat `Signal*` as the implementation surface and `Zk*` as the typed
  authoring surface unless a gadget has a documented exception

### Risk: Parameterized circuits reuse the wrong VK

Mitigation:

- include `@CircuitParam` names and values in generated schema metadata
- include parameter values in generated circuit names or name templates
- document that each parameter set is a distinct circuit/setup/VK lifecycle
- test that `build(16, POSEIDON)` and `build(32, POSEIDON)` produce different
  circuit identities

### Risk: Range constraints are forgotten

Mitigation:

- `ZkUInt` construction must add range constraints automatically
- generated code must call `assertWellFormed()` for every input
- unit tests must include out-of-range negative cases

### Risk: Generated code is hard to debug

Mitigation:

- generate readable Java source
- use stable variable names
- include comments in generated code sparingly
- expose `schema()`
- include generated source in compile-test assertions

## Acceptance Criteria

The feature should be considered successful when:

- a range proof can be written with fewer than 20 lines of user circuit code
- generated code builds a normal `CircuitBuilder`
- parameterized circuits can generate distinct concrete circuit builders from
  one Java source class
- valid and invalid witnesses are easy to test with JUnit
- public input ordering is visible and stable
- common circuit libraries can be called through `Zk*` adapters from annotated
  circuits
- unsupported ordinary Java proof styles fail at compile time with clear
  messages
- at least one end-to-end example compiles, calculates witness, proves, and
  verifies through an existing ZeroJ proving path
