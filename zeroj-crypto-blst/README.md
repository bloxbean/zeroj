# zeroj-crypto-blst

**Opt-in blst-accelerated Groth16 prover backend** for `zeroj-crypto` (ADR-0029). ~**5× faster**
proving, proofs **bit-identical** to pure Java.

## Why a separate module

This is the *bridge* between two modules, and it exists so neither has to depend on the other:

- **`zeroj-crypto`** (the prover) stays **pure-Java / GraalVM-native-image-clean by default** — it
  never depends on native code. Apps that don't want blst don't pull it in.
- **`zeroj-blst`** (the FFM `libblst` binding) stays a **standalone low-level library** — usable on
  its own (e.g. by julc) without dragging in the whole prover.

The prover-to-blst adapter (`BlstProverBackend`) needs *both*, so it lives here. Add this module only
when you want the fast prover; it transitively brings in `zeroj-crypto` + `zeroj-blst`.

## Use

```java
import com.bloxbean.cardano.zeroj.cryptoblst.BlstProverBackend;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;

var readers = Groth16ProverBLS381.heapReaders(pk);
var proof = Groth16ProverBLS381.proveWithReaders(
        pk, readers, BlstProverBackend.create(),          // <- blst backend (G1 + G2)
        witness, constraints, numWires, domainSize);
```

The default pure-Java path is `ProverBackend.PURE_JAVA` (or just `Groth16ProverBLS381.prove(...)`).
`BlstProverBackend.create()` routes both the G1 and G2 MSMs through blst's native Pippenger
(`blst_p1s/p2s_mult_pippenger`).

## Runtime requirement

FFM downcalls into `libblst` need native access enabled:

```
--enable-native-access=ALL-UNNAMED
```

The bundled `libblst` binaries and their build are documented in
[`zeroj-blst/BUILDING.md`](../zeroj-blst/BUILDING.md).

## Benchmark

```bash
./gradlew :zeroj-crypto-blst:blstBench     # blst MSM + full-prove speedup vs pure-Java (heavy)
```

Measured full-prove speedup (squaring-chain, 2¹²–2¹⁶): **~5× (4.94–6.03×)** over the optimized
pure-Java prover, bit-identical proofs.
