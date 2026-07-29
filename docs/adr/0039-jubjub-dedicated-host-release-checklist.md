# Jubjub validated dedicated-host release checklist

## Current status

**No validated platform profile is published. Do not enable network-reachable signing.**

`JubjubSigners.validatedDedicatedHostJavaRequired()` must continue to fail closed while the
matrix below has no approved row. This checklist is the M8 deployment scaffold; filling it
requires M4 cryptographic approval, M6 platform evidence, and M7 external implementation
review. The concrete profile decision and validation sequence are tracked in
[ADR-0040](0040-jubjub-dedicated-host-signing-profile-v1.md).

## Supported profile matrix

| Profile ID | JDK/JVM build | CPU/microcode | OS/container | GC and flags | CSPRNG implementation/algorithm/provider/configuration | Review evidence | Status |
|---|---|---|---|---|---|---|---|
| _none_ | — | — | — | — | — | — | **Not validated** |

A row is an allow-list entry, not an example. Runtime matching must include every field and
must fail before key material is accessed. A new JDK patch, JVM vendor, CPU family/microcode,
provider version, flag set, or arithmetic build requires revalidation rather than inheriting
the label.

## Cryptographic/design gates

- [ ] The hedged nonce specification and profile identifier have independent cryptographic
      approval.
- [ ] Domain separation, full transcript binding, repeated/weak auxiliary randomness,
      `(x mod(l-1))+1` bias, nonce re-derivation, fault scope, and deterministic-dependency
      migration were reviewed.
- [ ] Fixed-limb carry/borrow/Montgomery/point/Poseidon implementation review has no unresolved
      HIGH or MEDIUM finding.
- [ ] The full candidate vector set was reproduced independently.
- [ ] No secret-bearing `BigInteger` or unclassified transitive call is reachable.
- [ ] Key provisioning is performed by the attested validated factory or an unforgeable
      installation handle; a general caller-created `HardenedJubjubKey` cannot be relabelled.
- [ ] Key establishment rejects a zero derived nonce key.

## Platform gates

- [ ] Exact interpreter, C1, C2, OSR, and deoptimization behavior is exercised.
- [ ] Generated code is inspected; every conditional jump/indexed access in secret regions is
      classified as public/fixed-control.
- [ ] Key-close and per-operation wipe stores remain present in generated code.
- [ ] The timing harness detects its negative controls and shows no unexplained signal across
      key, nonce, scalar patterns, message, and auxiliary-randomness classes.
- [ ] Allocation count/size is fixed per admitted request and GC effects are characterized.
- [ ] The CSPRNG implementation class, algorithm, provider/version, parameters, thread-safety,
      exception behavior, and declared health alarms are pinned.
- [ ] The profile-owned randomness source is bounded, non-reentrant, and closeable; shutdown
      waits for admitted draws and then destroys provider-owned state.
- [ ] The approved factory rejects arbitrary subclasses/providers and test sources before key
      access.
- [ ] Warmed compiled-state attestation and deoptimization detection are operational.

## Service/deployment gates

- [ ] The signer runs on a dedicated or single-tenant host with the reviewed isolation model.
- [ ] The service enforces request-size, concurrency, queue, timeout, and rate limits outside
      the arithmetic API.
- [ ] Cross-client scheduling/request isolation is tested with remote timing experiments.
- [ ] Sustained/burst load meets the approved SLO without swap, crash dumps, excessive GC, or
      readiness flapping.
- [ ] Key provisioning uses the approved canonical 32-byte boundary and documents ownership/
      wiping at every hop.
- [ ] Logs, traces, metrics, exceptions, heap dumps, core dumps, and support bundles contain no
      key, nonce-key, auxiliary randomness, scratch, or signature pre-release state.
- [ ] Provider error, health alarm, self-check failure, unexpected deoptimization, key close,
      and failed release verification remove readiness and return no partial signature.
- [ ] Crash/restart, rolling upgrade, rollback, and key rotation are rehearsed.
- [ ] Known downstream uses of deterministic signature bytes have migrated.
- [ ] The account-ownership recovery application pins its approved complete graph/R1CS
      dimensions and digest; print-only measurement is not accepted as VK evidence.

## Startup sequence

1. Match the exact allow-listed platform row.
2. Construct the profile-owned CSPRNG; attest implementation, algorithm, provider/version, and
   configuration before loading a key.
3. Import/provision the key through the approved boundary.
4. Run fixed public known-answer tests and non-secret arithmetic self-tests.
5. Warm every reviewed signing path to its approved compiled state.
6. Attest generated-state/deoptimization monitoring.
7. Enable readiness only after every step succeeds.

There is no fallback. Failure closes/wipes the key where possible, keeps readiness false, and
requires operator remediation.

## Per-request sequence

1. Apply service request-size/rate/concurrency admission without reading key material.
2. Construct `JubjubMessage` through the caller-selected canonical-field or `hashToField`
   route.
3. Admit the key operation.
4. Draw exactly 32 secret auxiliary bytes from the profile-owned source before copying the
   persistent key.
5. Execute the fixed-limb candidate, nonce re-derivation, and independent release verify.
6. Wipe operation scratch and auxiliary bytes on success or failure.
7. Return only the completed public signature.

## Operational stop conditions

Immediately remove readiness and stop signing on:

- platform/profile mismatch;
- unapproved randomness source or provider drift;
- declared RNG health alarm or provider exception;
- unexplained timing signal;
- unexpected deoptimization or lost compiled-state attestation;
- release-check, nonce-invariant, or arithmetic self-test failure;
- unresolved HIGH/MEDIUM security finding;
- stable verifier/circuit/R1CS/PLONK regression.

Verification and in-circuit proving may remain available if their independently documented
health and readiness are unaffected.
