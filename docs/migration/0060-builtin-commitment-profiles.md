# Migration 0060: built-in commitment profiles are owned by `zeroj-api`

ADR-0060 decision D8 (milestone M1, issue #99) moves the descriptors of the built-in commitment
profiles into `zeroj-api`. Source code that uses the profile constants keeps compiling. Binaries
must be upgraded together.

## Why

Before this change each profile module created its own descriptor in a static initialiser by
calling the public `CommitmentProfile.define`. Any code that called `define` with a built-in
identifier first, for example `define(CommitmentProfileId.of("pedersen-jubjub-v1"), …)`, made that
profile's class fail initialisation for the rest of the JVM. The failure was closed, but any
caller could disable a ZeroJ profile.

## What changed

| Before | After |
|---|---|
| `PedersenScalarCommitment.PROFILE` and its peers called `CommitmentProfile.define` | they are the same instances as the new `CommitmentProfiles` constants |
| — | new `org.zeroj.api.commitment.CommitmentProfiles` with `PEDERSEN_JUBJUB_V1`, `PEDERSEN_JUBJUB_BYTES_V1`, `PEDERSEN_JUBJUB_VECTOR_V1`, `PEDERSEN_BLS12_381_G1_V1`, `PEDERSEN_BLS12_381_G1_BYTES_V1` |
| `define` of a built-in identifier disabled that profile | it is rejected with `CommitmentFormatException` (`INVALID_CONFIGURATION`) at the call, and the profile keeps working |

The two BLS12-381 G1 constants are descriptors only. The registry still lists those profiles as
`reserved` until ADR-0060 admits them; a descriptor is not admission.

No commitment, encoding, base, vector, circuit or key changes.

## What you must do

1. **Upgrade `zeroj-api`, `zeroj-circuit-lib` and `zeroj-bls12381` together.** A
   `zeroj-circuit-lib` binary from an earlier release still calls `define` for its own built-in
   identifier. Against the new `zeroj-api` that identifier is already registered, so the profile
   class fails with `ExceptionInInitializerError`, and every later use with
   `NoClassDefFoundError`. Mixed versions are not supported.
2. Import the ZeroJ BOM, which manages all three modules:

   ```groovy
   implementation platform('org.zeroj:zeroj-bom-core:<version>')
   implementation 'org.zeroj:zeroj-api'
   implementation 'org.zeroj:zeroj-circuit-lib'
   ```

   or pin one version for all three. Then check the resolved versions
   (`./gradlew dependencies` or `mvn dependency:tree`) so that a transitive dependency does not
   bring in a different `zeroj-api`.
3. If your own code called `CommitmentProfile.define` with a built-in identifier, remove the call
   and use the `CommitmentProfiles` constant. Profiles that are not built into ZeroJ still use
   `define`, with their own identifiers.

ZeroJ's build enforces the rule for its own modules: `verifyNoBuiltinProfileDefine` fails if any
main source outside `zeroj-api` calls `CommitmentProfile.define`.
