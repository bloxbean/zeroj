# Migration 0048: the `org.zeroj` namespace

[ADR-0048](../adr/0048-org-zeroj-namespace-and-central-portal-publishing.md) moves ZeroJ from the
`com.bloxbean.cardano` Maven group and the `com.bloxbean.cardano.zeroj.*` package root to
`org.zeroj` for both, starting with `0.1.0-pre12`.

This is a **namespace** change. No cryptographic algorithm, proof equation, transcript, domain
separator, public-input order, circuit relation, canonical encoding, validation rule, or
trusted-setup rule changes, and no maturity, audit, or production claim is upgraded. Every class
keeps its simple name and its behavior.

There is **no compatibility shim**: no type aliases and no `com.bloxbean.cardano:zeroj-*`
artifacts after `0.1.0-pre11`. If you cannot migrate now, pin `0.1.0-pre11`, which stays on
Maven Central and is unaffected.

## The whole migration, in two rules

1. **Group:** `com.bloxbean.cardano:zeroj-…` → `org.zeroj:zeroj-…`. Artifact ids are unchanged.
2. **Packages:** `com.bloxbean.cardano.zeroj.` → `org.zeroj.`. Sub-packages are unchanged.

So `com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381` becomes
`org.zeroj.crypto.groth16.Groth16ProverBLS381`, and nothing else about it changes.

For most projects that is two `sed` passes over your own sources and build files:

```bash
# packages (source, and any FQN in config, resources or docs)
grep -rl 'com\.bloxbean\.cardano\.zeroj' . | xargs sed -i '' 's#com\.bloxbean\.cardano\.zeroj#org.zeroj#g'
# slash-separated paths, if you have any (architecture tests, scripts, docs)
grep -rl 'com/bloxbean/cardano/zeroj' . | xargs sed -i '' 's#com/bloxbean/cardano/zeroj#org/zeroj#g'
# Maven coordinates
grep -rl 'com\.bloxbean\.cardano:zeroj' . | xargs sed -i '' 's#com\.bloxbean\.cardano:zeroj#org.zeroj:zeroj#g'
```

(On GNU `sed`, drop the `''` after `-i`.)

**Do not blanket-replace `com.bloxbean.cardano`.** It still owns ZeroJ's dependencies — Cardano
Client Lib (`com.bloxbean.cardano:cardano-client-*`), Julc (`com.bloxbean.cardano.julc.*`), and
VDS (`com.bloxbean.cardano.vds.*`) — and those are unchanged. Anchor every replacement on
`zeroj`, as above.

**If your own packages live under `com.bloxbean.cardano.zeroj.*`** — for example
`com.bloxbean.cardano.zeroj.usecases.*` — the first rule above would rename *your* packages too,
which also means moving your source directories. Decide that deliberately; if you want to keep
them, anchor on the ZeroJ sub-packages you actually import instead of the bare prefix.

## Coordinates

| Before (`≤ 0.1.0-pre11`) | After (`≥ 0.1.0-pre12`) |
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

Coordinates that ADR-0044 removed are **not** reissued under `org.zeroj`; see
[migration 0044](0044-module-cleanup.md), whose table stays written in the old namespace because
that is the namespace those artifacts were published under.

A minimal build file after the move:

```groovy
dependencies {
    implementation platform("org.zeroj:zeroj-bom-core:0.1.0-pre12")

    implementation 'org.zeroj:zeroj-circuit-dsl'      // version from the BOM
    implementation 'org.zeroj:zeroj-crypto'
    implementation 'org.zeroj:zeroj-verifier-groth16'

    // opt-in product artifacts stay outside the BOM and carry their own version
    implementation 'org.zeroj:zeroj-verifier-plonk:0.1.0-pre12'
}
```

## Things that are easy to miss

- **`META-INF/services` files.** They have no extension, so a filter by file type skips them. If
  you register your own `ZkVerifier`, the provider file must be renamed on disk from
  `com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier` to `org.zeroj.backend.spi.ZkVerifier`, and
  its contents (your provider's FQN) updated if your own packages moved. Getting this half-right
  **compiles cleanly** and produces a verifier registry that finds nothing at runtime.
- **GraalVM native-image config.** `META-INF/native-image/<groupId>/<artifactId>/` is resolved
  from the Maven group. If you ship your own config for ZeroJ types, move the directory to
  `META-INF/native-image/org.zeroj/…` and update the class names inside
  `reflect-config.json` / `resource-config.json`. Config that no longer resolves is skipped
  **silently** — a JVM build cannot see the problem.
- **Fully qualified names in strings**, not just imports: `Class.forName`, logging
  configuration, `--initialize-at-build-time=` arguments, Gradle test filters
  (`includeTestsMatching`), `Main-Class` manifest attributes, and `-cp … <FQN>` in scripts.
- **Slash-separated paths** in architecture tests that assert on source layout, in resource
  lookups, and in shell scripts. A dotted replace does not see them.
- **The ceremony CLI class**, if you invoke it directly, is now
  `org.zeroj.ceremony.CeremonyCli`. The `zeroj-ceremony` command name, its CLI behavior, its
  transcript bytes, and the release asset names are unchanged.

## What does not change

- Proof bytes, verification keys, proving keys, and every serialized artifact. None of them
  encode a Java package name, so keys and proofs produced by `0.1.0-pre11` verify unchanged
  under `0.1.0-pre12`.
- Circuit constraint systems and their fingerprints, which derive from the constraints.
- Transcripts, domain separators, and public-input order.
- Every artifact id, the module graph, and the ADR-0044 stable/opt-in split.
- `com.bloxbean.cardano:zeroj-*:0.1.0-pre11` and earlier on Maven Central.

## On-chain script hashes are unchanged (measured)

`zeroj-onchain-julc` compiles Java validator sources to UPLC through Julc, so it was worth
checking whether the compiled script bytes — and with them the **Cardano script hash and script
address** — move when the package moves.

They do not. `unappliedValidatorSha256` of the compiled
`Groth16AuthenticatedStateTransitionValidator` is
`6ee3ad3fbb38e9da14fa5b829ff206c1cf278c7208fb31c5d6be83a1b9d41874` both before the rename
(`com.bloxbean.cardano.zeroj.onchain.julc.…`) and after (`org.zeroj.onchain.julc.…`). Julc does
not carry the Java package name into the compiled term.

A deployed ZeroJ-derived validator therefore keeps its script hash and its address across this
upgrade. If your own validator sources move packages as part of your migration, the same is
true of them — but only if nothing else about them changes.
