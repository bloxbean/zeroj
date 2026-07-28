# ADR-0040: Jubjub Validated Dedicated-Host Signing Profile v1

## Status

**Proposed.**

This ADR records the work required to select and validate ZeroJ's first concrete
network-reachable Jubjub signing profile. It does not approve the current candidate for
network-reachable use.

Accepting this ADR will freeze an architecture and a specific platform profile. It will not,
by itself, change that profile's release state from `UNVALIDATED` to `VALIDATED`.

## Date

2026-07-27

## Relationship to earlier decisions

This ADR implements the concrete deployment work left open by:

- [ADR-0039](0039-jubjub-online-and-offline-readiness.md), especially M4, M6, M7 and M8;
- the [ADR-0039 implementation status](0039-jubjub-implementation-status.md); and
- the
  [validated dedicated-host release checklist](0039-jubjub-dedicated-host-release-checklist.md).

ADR-0037 through ADR-0039 remain authoritative for curve soundness, circuit verification,
fixed-limb arithmetic, the hedged nonce candidate, and compatibility/offline classifications.

## Decision summary

ZeroJ will define at most one initial **validated dedicated-host profile** for
network-reachable Jubjub signing. The profile will:

- remain pure Java, with no Rust/C, JNI, FFM, or native-library fallback;
- run on a dedicated or single-tenant host;
- assume remote clients choose messages, request timing and request concurrency, and can
  collect many valid signatures and latency observations;
- identify one exact JDK/JVM/OS/CPU/GC/CSPRNG configuration, with no wildcard inheritance;
- construct and attest its own approved randomness source rather than accept an arbitrary
  caller-provided `SecureRandom`;
- provision the key only after platform and randomness attestation;
- process secret values only through the ADR-0039 fixed-limb path;
- expose readiness only after generated-code, remote-timing, external-review and operational
  gates pass; and
- fail closed without falling back to deterministic-v1 or legacy `BigInteger` signing.

Until every required value and evidence item in this ADR is complete,
`JubjubSigners.validatedDedicatedHostJavaRequired()` continues to throw.

---

## 1. Why another ADR is required

ADR-0039 specifies a hardened arithmetic and API architecture. It deliberately does not pick
one production JDK, CPU, randomness provider, service scheduling model, key store, or remote
timing threshold.

Those choices are security-relevant:

- `new SecureRandom()` selects a provider-dependent default that can vary by OS, JDK and
  security configuration;
- requesting `DRBG` identifies a JCA service, but the effective parameters and entropy source
  still belong to a particular provider and platform;
- fixed-schedule Java source does not define the machine code emitted by the interpreter,
  C1, C2, on-stack replacement, or deoptimization paths;
- a dedicated host removes a hostile co-tenant but not a remote client that can choose
  messages, control request timing, create load and collect many timing samples; and
- queueing, concurrency, response ordering, GC and provider blocking can expose or amplify
  small execution-time differences.

The first validated profile therefore needs a concrete, reviewable decision rather than a
generic statement that `SecureRandom` and a non-shared host are sufficient.

---

## 2. Threat model

### 2.1 In scope

The validated profile must remain safe when a remote client can:

- submit arbitrary payloads or canonical Jubjub field messages;
- choose request order, timing, repetition and concurrency;
- collect every returned signature and precise end-to-end response timing;
- use multiple client identities and connections;
- cause bounded queue pressure, retries, cancellations and timeouts;
- repeat messages and compare signatures;
- trigger public validation errors and provider/service failures; and
- continue sampling up to the profile's documented per-key operational limit.

The signer host is dedicated or single-tenant. Other ordinary processes and operating-system
noise may exist, but no hostile tenant is scheduled on the same host.

### 2.2 Out of scope

The first profile does not claim resistance to:

- a privileged local attacker, compromised kernel or hostile hypervisor;
- a malicious JDK, provider, application dependency, agent or instrumentation hook;
- invasive physical observation, voltage/clock fault injection, or direct memory probing;
- a hostile co-tenant sharing cores, caches, memory buses or power/frequency domains; or
- supply-chain compromise of the attested image.

These exclusions do not permit silent downgrade. Detecting a profile mismatch, unexpected
agent, unsupported runtime state or failed self-check removes readiness.

### 2.3 Assets and security goals

The profile protects:

- the Jubjub secret scalar and derived nonce key;
- auxiliary randomness and nonce intermediates;
- signing scratch, projective coordinates and `S` intermediates; and
- the integrity of the signature returned to the caller.

The primary goals are no practical key recovery through remote timing, no algebraic nonce
failure, no partial output on failure, and no use of an unapproved signing path.

---

## 3. Required concrete profile

Before this ADR can be accepted, the following table must contain no `TBD` value:

| Property | Profile v1 value |
|---|---|
| Profile identifier/version | `TBD` |
| Deployment requirement and SLO | `TBD` |
| Operating system and immutable image digest | `TBD` |
| CPU architecture/model/stepping and microcode | `TBD` |
| JDK vendor, distribution and exact build | `TBD` |
| JVM mode, flags, GC and heap configuration | `TBD` |
| Allowed agents/instrumentation | `TBD` |
| CSPRNG implementation class | `TBD` |
| CSPRNG algorithm/provider/version | `TBD` |
| DRBG/native parameters and entropy source | `TBD` |
| Reseed and provider-health policy | `TBD` |
| Key-provisioning source and ownership boundary | `TBD` |
| Signing workers and concurrency per key | `TBD` |
| Queue/admission limits | `TBD` |
| Response-release policy | `TBD` |
| Per-client and per-key request/signature limits | `TBD` |
| Rotation and emergency-stop policy | `TBD` |
| Remote-timing sample budget and thresholds | `TBD` |
| Generated-code evidence digest/location | `TBD` |
| External review evidence | `TBD` |

A new JDK patch, JVM vendor, provider version, CPU family/stepping, microcode, GC, flag set,
container image, arithmetic build, or service scheduling policy creates a new profile version
and requires revalidation. It does not inherit the earlier profile's label automatically.

---

## 4. Decisions

### Decision 1 — Keep public preprocessing outside the key operation

The network layer must make preprocessing explicit:

1. enforce public request-size and framing limits;
2. choose either canonical-field decoding or the normative `JubjubMessage.hashToField` route;
3. complete public hashing, parsing and validation before key admission; and
4. pass exactly one canonical 32-byte `JubjubMessage` value to the signer.

No signing API guesses whether bytes are a field element or an arbitrary payload. Variable
payload length may affect public preprocessing time, but it must not alter the secret-bearing
operation's shape.

### Decision 2 — Bound execution and scheduling per key

The service will use a declared, bounded worker and queue model. The selected profile must
choose one of:

- one serialized signing lane per key; or
- a fixed number of per-call scratch lanes with isolated randomness sources and a reviewed
  concurrency limit.

The request cannot create threads, scratch sizes, randomness instances, or secret-operation
parallelism dynamically. Admission happens before the key is read. Overload is rejected by
public policy before secret processing starts.

Cross-client response ordering and HTTP/2 or multiplexed concurrency are part of the remote
timing assessment, not assumed harmless.

### Decision 3 — Timing padding is defense-in-depth, not the primary fix

The profile may release responses on fixed service slots or enforce a public minimum response
time, but random sleeps or padding do not establish side-channel safety. Repeated samples can
average ordinary noise, and concurrent requests can reveal relative ordering without relying
on absolute latency.

The primary defense remains a fixed-schedule secret implementation plus validation of the
exact generated code and service. If a fixed release slot is used:

- its duration and scheduling rule are public and profile-pinned;
- deadline misses are monitored;
- an unexplained miss removes readiness rather than returning partial output; and
- the remote timing test includes the complete release mechanism.

### Decision 4 — The validated factory owns an exact randomness source

The validated profile will not accept `SecureRandom`, `Supplier<SecureRandom>`, an arbitrary
provider object, or a test adapter from its caller.

The profile factory must:

1. select the exact approved JCA algorithm and installed provider;
2. request explicit parameters where the algorithm supports them;
3. verify the implementation class, algorithm, provider name/version and effective parameters;
4. verify all profile-pinned security properties and entropy-source configuration;
5. instantiate and exercise the source before key material is accessed;
6. draw exactly 32 auxiliary bytes for every admitted signature;
7. reject provider drift, unsupported parameters, provider exceptions and declared health
   alarms; and
8. expose no fallback to a default provider, deterministic test source, legacy signer or
   deterministic-v1 signer.

The candidate selection to be evaluated is an explicitly configured 256-bit JDK `DRBG`.
The M4 design review must choose and record the exact mechanism, digest/cipher, capability,
personalization, reseed policy and entropy source. An explicitly pinned OS-backed
`NativePRNG` profile may be evaluated as an alternative for one specific operating system.
`new SecureRandom()` and `SecureRandom.getInstanceStrong()` are not profile definitions.

Generic `SecureRandom` cannot report every entropy degradation. ZeroJ claims detection only
for provider exceptions and explicitly supported health alarms. Any repetition test or
persisted RNG-health state must be normative and must not introduce an unreviewed
secret-dependent failure.

Auxiliary randomness remains secret, operation-owned and wiped after success or failure.
Under the externally approved hedged construction, repeated or attacker-known auxiliary
input must degrade to deterministic-signature security rather than create algebraic nonce
reuse. This property does not remove the requirement for an approved source.

### Decision 5 — Key provisioning occurs after attestation

The validated factory or an unforgeable profile-owned installation handle provisions the key
only after:

- the complete platform manifest matches;
- the approved randomness source is constructed and checked;
- public arithmetic known-answer tests pass; and
- the service is not yet accepting signing requests.

The boundary imports exactly 32 unsigned big-endian canonical bytes satisfying
`0 < sk < l`. Secret key material never crosses through `BigInteger`, immutable text, command
line arguments, system properties, logs, metrics or exceptions.

Caller, transport and factory buffer ownership must be explicit. Every owned mutable copy is
wiped in `finally`; JVM/register/crash-dump limitations remain documented. A general
caller-created `HardenedJubjubKey` cannot be relabelled as validated.

Key generation is normally offline. If profile v1 generates keys online, it must use the same
approved source and retain ADR-0039's unbiased rejection sampling, failure and wiping rules.

### Decision 6 — Validate every reachable JVM execution mode

For the exact platform, the release evidence must cover:

- cold/interpreted execution;
- C1 and C2 compiled execution where reachable;
- on-stack replacement and forced deoptimization;
- GC, safepoints, allocation and thread scheduling;
- generated machine code for every hardened secret-processing method;
- preservation of scratch/key wipe stores; and
- every conditional branch and indexed memory access reachable from the signer.

Each branch or indexed access must be classified as depending only on public data or fixed
control structure. A source-level review is insufficient.

The service warms the reviewed path before loading or admitting production-key operations.
If the chosen JVM can reliably attest compiled state and observe deoptimization, unexpected
loss of that state removes readiness. Otherwise, every reachable tier and transition must
pass the timing assessment.

### Decision 7 — Remote timing validation is a release gate

The profile must define a reproducible end-to-end experiment before collecting release data:

- exact machine image, network topology, service configuration and load;
- controlled test keys and declared secret/input classes;
- message, auxiliary-randomness, concurrency, queue and repetition classes;
- warmup, sample count, exclusions and statistical tests;
- predeclared pass/fail thresholds and false-positive handling;
- a deliberately leaky implementation that the harness must detect; and
- an attacker sample budget at least as large as the per-key production budget.

Testing covers direct latency and relative/concurrent response ordering. It runs across
independent processes and repeated host boots. A local microbenchmark or one negative Welch
test is supporting evidence, not release evidence.

Any repeatable unexplained signal blocks the profile. No detected signal approves only the
declared platform and attacker budget; it is not a proof about every JVM or network.

### Decision 8 — Limit observation volume operationally

Even after validation, the service enforces:

- public request-size, queue, concurrency and timeout bounds;
- per-client and global rate limits;
- a profile-defined maximum number of signatures per key;
- key rotation before that maximum;
- anomaly monitoring for distributed sampling and timing probes; and
- immediate readiness removal on provider, timing, self-check, release-check or platform
  failure.

Rate limits and rotation reduce exposure; they do not repair a secret-dependent arithmetic
channel. Limits are enforced outside the cryptographic kernel.

Logs, traces, metrics, heap dumps, core dumps and support bundles must not contain key
material, nonce keys, auxiliary randomness, scratch, pre-release signatures or provider
state.

### Decision 9 — Enablement remains fail-closed

`JubjubSigners.validatedDedicatedHostJavaRequired()` remains unavailable until:

- the profile table is complete;
- the hedged profile has external cryptographic design approval;
- fixed-limb and integration reviews have no unresolved HIGH or MEDIUM finding;
- generated-code and remote-timing gates pass;
- the exact randomness and key-installation boundary is implemented;
- the supported-platform manifest and evidence digests are published; and
- the operational owner approves the deployment runbook.

The enabled factory must verify the exact manifest before key access. A mismatch fails
readiness. There is no warning-only mode and no fallback.

### Decision 10 — Preserve stable components

ADR-0040 is a host signing/deployment decision. It must not change:

- Jubjub signature verification equations or encodings;
- in-circuit verifier equations;
- R1CS, PLONK or Halo2 circuit shapes;
- proving or verification keys;
- Poseidon parameters or domain tags; or
- the compatibility/offline signing transcript.

Any necessary change to those surfaces requires a separate reviewed ADR and migration plan.
The internal hardened Pedersen candidate is not promoted by this profile.

---

## 5. Implementation and validation sequence

| Milestone | Work | Exit gate |
|---|---|---|
| **V0 — select target** | Record the concrete production use case, host, SLO, attacker/request budget and operational owner | Profile table has deployment, host and SLO values |
| **V1 — freeze normative profile** | Select JDK/OS/CPU/JVM/CSPRNG/key-source/concurrency/response values and publish the profile specification | No `TBD`; M4 design review approves the randomness and hedged transcript |
| **V2 — implement attested boundary** | Add profile manifest checks, approved source, key provisioning and fail-closed factory without general-key relabelling | Downgrade, provider drift and pre-attestation key-access tests pass |
| **V3 — build service harness** | Fixed admission/worker/queue/release model plus rate, rotation and failure handling | Lifecycle, overload, cancellation and concurrency tests pass |
| **V4 — platform evidence** | Generated-code classification, wipe inspection, tier/deoptimization tests, allocation and timing experiments | M6 evidence satisfies every declared profile gate |
| **V5 — independent review** | Cryptographic, fixed-limb/JVM and integration review with remediation | M7 has no unresolved HIGH or MEDIUM finding |
| **V6 — controlled release** | Publish profile manifest/evidence/runbook, enable only its factory and conduct staged load/remote monitoring | M8 row becomes `VALIDATED` for that exact profile |

The sequence may collect exploratory evidence earlier, but V6 cannot bypass an earlier gate.

---

## 6. Required artifacts

Before validation, the repository or release evidence bundle must contain:

1. `docs/specs/jubjub-dedicated-host-profile-v1.md` with every exact profile value;
2. an immutable machine/container image digest and dependency manifest;
3. the approved CSPRNG/provider parameter and entropy-source record;
4. the key-provisioning and mutable-buffer ownership specification;
5. generated C1/C2 or otherwise reachable-tier code-review evidence;
6. local and remote timing datasets, harness version and negative-control results;
7. allocation, load, throughput and tail-latency results;
8. external design and implementation review reports;
9. the completed ADR-0039 release checklist; and
10. the deployment, incident, rotation, upgrade and rollback runbook.

Evidence may be stored outside Git when it contains machine-specific or operational material,
but the repository must pin its immutable digest and approval record.

---

## 7. Consequences

### Positive

- Network readiness becomes an enforceable exact profile rather than a broad Java claim.
- `SecureRandom` is used through a selected and attested implementation rather than assumed
  safe by type name.
- Remote chosen-message/timing clients are explicitly within the validation model.
- JDK, provider and CPU upgrades cannot silently inherit a security label.
- The work remains pure Java and additive to existing verification/circuit components.

### Negative

- Supporting each additional platform multiplies review and timing work.
- Some ordinary JDK upgrades must wait for revalidation.
- Fixed concurrency, response scheduling and per-key limits constrain service throughput.
- Generated-code and remote timing evidence require specialist security engineering.
- Java/JVM validation remains profile-specific and does not become a universal constant-time
  proof.

---

## 8. References

- [ADR-0039: Pure-Java Jubjub Online and Offline Readiness](0039-jubjub-online-and-offline-readiness.md)
- [ADR-0039 implementation status](0039-jubjub-implementation-status.md)
- [ADR-0039 dedicated-host release checklist](0039-jubjub-dedicated-host-release-checklist.md)
- [Java SE 25 `SecureRandom`](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/SecureRandom.html)
- [JDK 25 Providers Documentation](https://docs.oracle.com/en/java/javase/25/security/oracle-providers.html)
- [OpenJDK JEP 273: DRBG-Based SecureRandom Implementations](https://openjdk.org/jeps/273)
- [NIST SP 800-90A Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
- [Remote Timing Attacks are Practical](https://crypto.stanford.edu/~dabo/pubs/papers/ssl-timing.pdf)
- [Timeless Timing Attacks](https://www.usenix.org/conference/usenixsecurity20/presentation/van-goethem)
