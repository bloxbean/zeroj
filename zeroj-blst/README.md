# zeroj-blst

BLS12-381 native operations via [supranational/blst](https://github.com/supranational/blst) — the
standalone "blst for the JVM" module. Usable on its own (verifiers, BBS, or downstream projects like
julc) without depending on the ZeroJ prover.

All native code is the source-built `libblst` (pinned commit, see below), called through Java 25
**FFM** (Panama): no JNI and no third-party wrapper or binary
([ADR-0062](../docs/adr/0062-bls12381-independent-review-and-remediation.md) D3 removed the former
`foundation.icon:blst-java` JNI binding).

| binding | package | used for |
|---|---|---|
| MSM (ADR-0029) | `blst.ffm.BlstG1Msm` / `BlstG2Msm` | native MSM (`blst_p1s/p2s_mult_pippenger`) for the Groth16 prover backend |
| curve + pairing (ADR-0062) | `blst.ffm.BlstCurve` | validated point arithmetic and multi-pairing for the Groth16 verifier and BBS |
| provider | `blst.BlstBls12381Provider` | the `Bls12381Provider` SPI over `BlstCurve` |

Platforms: linux amd64/aarch64 and macOS aarch64. macOS x86_64 is not supported (the former JNI
binary covered it; Intel macOS runners are retired); use the pure-Java provider there.

## Native library — built from source

supranational publishes **no precompiled binaries**, so `zeroj-blst` **builds `libblst` from
source**, pinned to **v0.3.15** by commit hash, and bundles the shared libraries as jar resources.
The FFM loader (`BlstFfm`) extracts the matching one per platform at runtime. It loads only that
bundled resource; no system property or `java.library.path` lookup can redirect it.

- **Local build / testing + CI + release:** see **[`BUILDING.md`](BUILDING.md)**.
- Provenance note: [`src/main/resources/native/README.md`](src/main/resources/native/README.md).

## Validation and side channels

Every `BlstCurve` method validates its point inputs (length, no compression/sort flag, coordinates
`< p`, on the curve, in the subgroup) and checks every `BLST_ERROR`; scalars are reduced mod `r`.
The MSM hot path is caller-validated; `msmValidated` checks the bases (ADR-0062 D4).

No ZeroJ provider has an evidenced side-channel contract. `BlstBls12381Provider` has a dedicated
secret-scalar path (fixed-width scalar, `nbits = 255`, no zero-scalar early return, zeroed
temporaries), but ZeroJ has not evaluated blst's scalar multiplication for side channels
(ADR-0062 D2, Q2). Secret-bearing generation is offline/isolated only, whichever provider is
selected.

## Key types

| Type | Description |
|------|-------------|
| `ffm.BlstFfm` | FFM loader — extracts + maps `libblst`, binds `blst_*` downcalls |
| `ffm.BlstG1Msm` / `ffm.BlstG2Msm` | batched G1/G2 MSM via `blst_p1s/p2s_mult_pippenger` |
| `ffm.BlstCurve` | validated G1/G2 arithmetic, point status, multi-pairing |
| `BlstBls12381Provider` | native-backed `Bls12381Provider` (pairing, point ops) |

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
