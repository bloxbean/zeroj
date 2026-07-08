# zeroj-blst

BLS12-381 native operations via [supranational/blst](https://github.com/supranational/blst) — the
standalone "blst for the JVM" module. Usable on its own (verifiers, BBS, or downstream projects like
julc) without depending on the ZeroJ prover.

It hosts **two** bindings during an in-progress migration:

| binding | package | used for | mechanism |
|---|---|---|---|
| **FFM binding** (ADR-0029) | `blst.ffm.*` | native MSM (`blst_p1s/p2s_mult_pippenger`) for the ~5× Groth16 prover backend | Java 25 **FFM** (Panama) — no JNI, no third-party wrapper |
| `Bls12381Provider` / pairing | `blst.*` | pairing for Groth16 verification + BBS | `foundation.icon:blst-java` (JNI/SWIG) |

The FFM binding is the new, preferred path (native-image-friendlier, source-built `libblst`). The
JNI provider remains for pairing/BBS until it is migrated to FFM too (the "full swap").

## Native library — built from source

supranational publishes **no precompiled binaries**, so `zeroj-blst` **builds `libblst` from source**
(no third-party binary), pinned to **v0.3.15**, and bundles the shared libraries as jar resources.
The FFM loader (`BlstFfm`) extracts the matching one per platform at runtime.

- **Local build / testing + CI + release:** see **[`BUILDING.md`](BUILDING.md)**.
- Provenance note: [`src/main/resources/native/README.md`](src/main/resources/native/README.md).

## Key types

| Type | Description |
|------|-------------|
| `ffm.BlstFfm` | FFM loader — extracts + maps `libblst`, binds `blst_*` downcalls |
| `ffm.BlstG1Msm` / `ffm.BlstG2Msm` | batched G1/G2 MSM via `blst_p1s/p2s_mult_pippenger` |
| `BlstBls12381Provider` | native-backed `Bls12381Provider` (pairing, point ops) |
| `BlstPairing` | multi-pairing / point validation |

## Consumers

- **Verification / BBS** — pairing via `BlstBls12381Provider` (pulled in transitively by
  `zeroj-verifier-groth16`).
- **Faster Groth16 proving** — the FFM MSM is wrapped by **[`zeroj-crypto-blst`](../zeroj-crypto-blst)**
  (the opt-in prover backend); `zeroj-crypto` itself stays pure-Java by default.
- **Other JVM projects (e.g. julc)** — depend on `zeroj-blst` directly for native blst.

## Runtime

FFM downcalls need `--enable-native-access=ALL-UNNAMED`. GraalVM native-image config is bundled
under `META-INF/native-image/`.

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-blst'
}
```
