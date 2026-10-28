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
JNI provider remains for pairing/BBS until it is migrated to FFM too (the "full swap",
[ADR-0062](../docs/adr/0062-bls12381-independent-review-and-remediation.md) D3).

> **Two native binaries today.** The JNI half loads the `libblst` bundled inside the third-party
> `foundation.icon:blst-java:0.3.2` jar (Sep 2023); its upstream blst version is unknown and it is
> **not** the source-built library below. Until the D3 migration lands, one process can load two
> blst builds of different versions.

## Native library — built from source (FFM half)

supranational publishes **no precompiled binaries**, so `zeroj-blst` **builds the FFM `libblst` from
source**, pinned to **v0.3.15**, and bundles the shared libraries as jar resources. The FFM loader
(`BlstFfm`) extracts the matching one per platform at runtime.

## Side channels

No ZeroJ provider has an evidenced side-channel contract. `BlstBls12381Provider`'s secret-scalar
methods currently delegate to its public scalar multiplication, and ZeroJ has not evaluated blst's
scalar multiplication for side channels (ADR-0062 D2, Q2). Secret-bearing generation is
offline/isolated only, whichever provider is selected.

- **Local build / testing + CI + release:** see **[`BUILDING.md`](BUILDING.md)**.
- Provenance note: [`src/main/resources/native/README.md`](src/main/resources/native/README.md).

## Key types

| Type | Description |
|------|-------------|
| `ffm.BlstFfm` | FFM loader — extracts + maps `libblst`, binds `blst_*` downcalls |
| `ffm.BlstG1Msm` / `ffm.BlstG2Msm` | batched G1/G2 MSM via `blst_p1s/p2s_mult_pippenger` |
| `BlstBls12381Provider` | native-backed `Bls12381Provider` (pairing, point ops) |
| `BlstPairing` | raw JNI pairing / point helpers — **validate nothing**; use `BlstBls12381Provider` |

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
    implementation 'org.zeroj:zeroj-blst'
}
```
