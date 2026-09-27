---
title: Migration notes
description: Move from com.bloxbean.cardano to the org.zeroj namespace, and from the pre-cleanup module set to today's focused module surface.
sidebar:
  order: 5
---

ZeroJ is pre-1.0 and its coordinates have changed twice. This page covers both changes. Neither
one changes cryptography, proof bytes, keys, transcripts or public-input order, and neither
upgrades any maturity claim.

## The `org.zeroj` namespace

Starting with **`0.1.0-pre12`**, ZeroJ moved from the `com.bloxbean.cardano` Maven group and the
`com.bloxbean.cardano.zeroj.*` package root to **`org.zeroj`** for both. Every class keeps its
simple name and behaviour.

There is **no compatibility shim**: no type aliases, and no `com.bloxbean.cardano:zeroj-*`
artifacts after `0.1.0-pre11`. If you can't migrate yet, stay on `0.1.0-pre11`, which remains on
Maven Central unchanged.

### Two rules

1. **Group:** `com.bloxbean.cardano:zeroj-…` → `org.zeroj:zeroj-…`. Artifact ids don't change.
2. **Packages:** `com.bloxbean.cardano.zeroj.` → `org.zeroj.`. Sub-packages don't change.

So `com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381` becomes
`org.zeroj.crypto.groth16.Groth16ProverBLS381`.

For most projects that is three `sed` passes over your own sources and build files:

```bash
# packages (source, and any FQN in config, resources or docs)
grep -rl 'com\.bloxbean\.cardano\.zeroj' . | xargs sed -i '' 's#com\.bloxbean\.cardano\.zeroj#org.zeroj#g'
# slash-separated paths (architecture tests, scripts, docs)
grep -rl 'com/bloxbean/cardano/zeroj' . | xargs sed -i '' 's#com/bloxbean/cardano/zeroj#org/zeroj#g'
# Maven coordinates
grep -rl 'com\.bloxbean\.cardano:zeroj' . | xargs sed -i '' 's#com\.bloxbean\.cardano:zeroj#org.zeroj:zeroj#g'
```

On GNU `sed` (Linux), drop the `''` after `-i`.

:::danger[Don't blanket-replace `com.bloxbean.cardano`]
It still owns ZeroJ's dependencies, which have **not** moved: Cardano Client Lib
(`com.bloxbean.cardano:cardano-client-*`), JuLC (`com.bloxbean.cardano.julc.*`, group
`com.bloxbean.cardano`) and VDS (`com.bloxbean.cardano.vds.*`). Anchor every replacement on
`zeroj`, as the commands above do.
:::

If **your own** packages live under `com.bloxbean.cardano.zeroj.*` (the zeroj-usecases apps do,
for example), rule 2 renames them too, which also means moving source directories. Decide that
deliberately. To keep your packages, anchor the replacement on the ZeroJ sub-packages you actually
import instead of the bare prefix.

### Coordinates

| Before (≤ `0.1.0-pre11`) | After (≥ `0.1.0-pre12`) |
|---|---|
| `com.bloxbean.cardano:zeroj-bom-core` | `org.zeroj:zeroj-bom-core` |
| `com.bloxbean.cardano:zeroj-api` | `org.zeroj:zeroj-api` |
| `com.bloxbean.cardano:zeroj-codec` | `org.zeroj:zeroj-codec` |
| `com.bloxbean.cardano:zeroj-backend-spi` | `org.zeroj:zeroj-backend-spi` |
| `com.bloxbean.cardano:zeroj-verifier-groth16` | `org.zeroj:zeroj-verifier-groth16` |
| `com.bloxbean.cardano:zeroj-verifier-plonk` | `org.zeroj:zeroj-verifier-plonk` |
| `com.bloxbean.cardano:zeroj-bls12381` | `org.zeroj:zeroj-bls12381` |
| `com.bloxbean.cardano:zeroj-blst` | `org.zeroj:zeroj-blst` |
| `com.bloxbean.cardano:zeroj-crypto` | `org.zeroj:zeroj-crypto` |
| `com.bloxbean.cardano:zeroj-crypto-blst` | `org.zeroj:zeroj-crypto-blst` |
| `com.bloxbean.cardano:zeroj-circuit-dsl` | `org.zeroj:zeroj-circuit-dsl` |
| `com.bloxbean.cardano:zeroj-circuit-lib` | `org.zeroj:zeroj-circuit-lib` |
| `com.bloxbean.cardano:zeroj-circuit-annotation-api` | `org.zeroj:zeroj-circuit-annotation-api` |
| `com.bloxbean.cardano:zeroj-circuit-annotation-processor` | `org.zeroj:zeroj-circuit-annotation-processor` |
| `com.bloxbean.cardano:zeroj-onchain-julc` | `org.zeroj:zeroj-onchain-julc` |
| `com.bloxbean.cardano:zeroj-tools` | `org.zeroj:zeroj-tools` |
| `com.bloxbean.cardano:zeroj-bbs` | `org.zeroj:zeroj-bbs` |
| `com.bloxbean.cardano:zeroj-mpf-poseidon` | `org.zeroj:zeroj-mpf-poseidon` |
| `com.bloxbean.cardano:zeroj-jmt-poseidon` | `org.zeroj:zeroj-jmt-poseidon` |

Modules removed by the earlier cleanup (below) are **not** reissued under `org.zeroj`.

A minimal build after the move:

```groovy title="build.gradle"
dependencies {
    implementation platform("org.zeroj:zeroj-bom-core:%ZEROJ_VERSION%")

    implementation 'org.zeroj:zeroj-circuit-dsl'      // version from the BOM
    implementation 'org.zeroj:zeroj-crypto'
    implementation 'org.zeroj:zeroj-verifier-groth16'

    // opt-in artifacts stay outside the BOM and carry their own version
    implementation 'org.zeroj:zeroj-bbs:%ZEROJ_VERSION%'
}
```

### Easy to miss

- **`META-INF/services` files** have no extension, so filters by file type skip them. If you
  register your own `ZkVerifier`, rename the provider file from
  `com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier` to `org.zeroj.backend.spi.ZkVerifier`, and
  update its contents if your own packages moved. A half-done rename **compiles cleanly** and
  gives a verifier registry that finds nothing at runtime.
- **GraalVM native-image config** directories are resolved from the Maven group. If you ship your
  own config for ZeroJ types, move it to `META-INF/native-image/org.zeroj/…` and update class names
  inside `reflect-config.json` / `resource-config.json`. Stale config is skipped **silently**.
- **Fully qualified names in strings**: `Class.forName`, logging configuration,
  `--initialize-at-build-time=` arguments, Gradle test filters, `Main-Class` manifest attributes
  and `-cp … <FQN>` in scripts.
- **Slash-separated paths** in architecture tests, resource lookups and shell scripts.
- **The ceremony CLI class** is now `org.zeroj.ceremony.CeremonyCli`. The `zeroj-ceremony` command
  name, behaviour, transcript bytes and release asset names are unchanged.

### What does not change

- Proof bytes, verification keys, proving keys and every serialized artifact. None encode a Java
  package name, so keys and proofs from `0.1.0-pre11` verify unchanged.
- Circuit constraint systems and their fingerprints, transcripts, domain separators and
  public-input order.
- Artifact ids, the module graph and the core/opt-in split.
- **On-chain script hashes.** JuLC doesn't carry the Java package name into compiled code; ZeroJ
  measured an identical script hash for its state-transition validator before and after the
  rename. Your own validators keep their hash too, as long as nothing else about them changes
  (including the JuLC version).

## The focused module surface

An earlier pre-release narrowed ZeroJ to its Java-first product path. If you come from a release
that still had the modules below, here is where things went. (This change happened while ZeroJ still
used `com.bloxbean.cardano`. The replacements now live at `org.zeroj:<artifact>`.)

| Removed module | What to do |
|---|---|
| `zeroj-verifier-core` | Depend on `zeroj-backend-spi`. `VerifierRegistry` and `VerifierOrchestrator` moved there and kept their `verifier.core` package. |
| `zeroj-prover-spi` | No replacement. Use the concrete `zeroj-crypto` APIs (`Groth16Keys`, `Groth16Pipeline`, `Groth16ProverBLS381`, …) or `zeroj-crypto-blst`. |
| `zeroj-prover-gnark` | No runtime replacement. Use `zeroj-crypto`, optionally with `zeroj-crypto-blst`. |
| `zeroj-verifier-halo2`, `zeroj-prover-wasm` | No replacement. Pin the last release that had them if you depend on them. |
| `zeroj-ceremony` | Use `zeroj-tools`; `CeremonyCli` moved there, and the `zeroj-ceremony` command is unchanged. |
| `zeroj-cardano`, `zeroj-ccl` | Use Cardano Client Lib directly in your application. The proof-anchor helpers were reference code. |
| `zeroj-patterns` | Use application-specific policies (see [zeroj-usecases](https://github.com/bloxbean/zeroj-usecases)). ZeroJ provides no generic authorization, replay or nullifier guarantee. |
| `zeroj-bom-all` | Use `zeroj-bom-core` plus explicitly versioned opt-in modules. |
| `zeroj-bls12381-wasm`, `zeroj-bbs-wasm` | No longer runtime products; they are unpublished assurance projects built with `-PincludeAssurance`. |

The core modules (in the BOM) are now `zeroj-api`, `zeroj-codec`, `zeroj-backend-spi`,
`zeroj-verifier-groth16`, `zeroj-bls12381`, `zeroj-blst`, `zeroj-crypto`, `zeroj-crypto-blst`,
`zeroj-circuit-dsl`, `zeroj-circuit-lib`, `zeroj-circuit-annotation-api`,
`zeroj-circuit-annotation-processor`, `zeroj-onchain-julc` and `zeroj-tools`. The opt-in modules,
published with an explicit version, are `zeroj-verifier-plonk`, `zeroj-bbs`, `zeroj-mpf-poseidon`
and `zeroj-jmt-poseidon`. See [Modules](/reference/modules/).

The default build of the repository is pure Java. It needs no Go, Rust, Node.js, WASM toolchain or
RocksDB.

## Further reading

Design notes: [ADR-0048](https://github.com/bloxbean/zeroj/blob/main/docs/adr/0048-org-zeroj-namespace-and-central-portal-publishing.md)
and [ADR-0044](https://github.com/bloxbean/zeroj/blob/main/docs/adr/0044-focused-module-surface-and-optional-provider-isolation.md).
Full migration texts: [namespace](https://github.com/bloxbean/zeroj/blob/main/docs/migration/0048-org-zeroj-namespace.md),
[module cleanup](https://github.com/bloxbean/zeroj/blob/main/docs/migration/0044-module-cleanup.md).

## Next steps

- [Modules](/reference/modules/)
- [Installation](/start/installation/)
