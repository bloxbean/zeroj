# zeroj-circuit-dsl

Java API for defining ZeroJ arithmetic circuits and compiling them into backend
constraint systems.

This module lets application code define circuits in Java, calculate witnesses
in-process, and compile the same circuit definition to R1CS, PlonK, or Halo2
shapes. It is proof-system agnostic at the circuit-definition layer.

## What It Provides

| Type | Purpose |
|------|---------|
| `CircuitBuilder` | Fluent entry point for declaring public/secret variables and constraints |
| `CircuitAPI` | Functional arithmetic API used by `define(...)` |
| `SignalBuilder` / `Signal` | Object-style API for reusable circuit components |
| `WitnessCalculator` | Evaluates declared circuits against concrete inputs |
| `R1CSCompiler` / `R1CSSerializer` | Groth16-oriented R1CS compilation and serialization |
| `PlonKCompiler` | PlonK gate table and permutation compilation |
| `Halo2Compiler` | Halo2-style PLONKish circuit shape compilation |

## Example

```java
var circuit = CircuitBuilder.create("multiplier")
        .publicVar("z")
        .secretVar("x")
        .secretVar("y")
        .define(api -> {
            var product = api.mul(api.var("x"), api.var("y"));
            api.assertEqual(product, api.var("z"));
        });

var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
var plonk = circuit.compilePlonK(CurveId.BLS12_381);

var witness = circuit.calculateWitness(Map.of(
        "z", List.of(BigInteger.valueOf(33)),
        "x", List.of(BigInteger.valueOf(3)),
        "y", List.of(BigInteger.valueOf(11))
), CurveId.BLS12_381);
```

## Why It Is Useful

- Keeps circuit authoring in Java instead of switching to circom or another DSL.
- Produces reusable circuit definitions that can target multiple proving paths.
- Gives tests and applications a common witness calculation path.
- Supports field consistency checks so field-specific gadgets are not compiled
  against the wrong curve.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'
}
```
