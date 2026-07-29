# ADR-0039: Pure-Java Jubjub Online and Offline Readiness

## Status

Accepted — architecture and implementation plan. Acceptance does **not** approve the current
secret-bearing implementation, or any future implementation before its release gates, for
network-reachable use.

This ADR supersedes the deferred secret-arithmetic plan in
[ADR-0038 Decision 6](0038-jubjub-dsl-remediation-plan.md) and refines the readiness
classification in the
[ADR-0037 production-readiness addendum](0037-jubjub-production-readiness-status.md).
The soundness and verifier decisions in ADR-0037 and ADR-0038 remain unchanged.

## Date

2026-07-27

## Decision summary

ZeroJ will remain a **pure-Java Jubjub implementation**. Native Rust/C code, JNI, FFM, and
native-library fallback are out of scope for this plan.

ZeroJ will support two explicit assurance classes:

1. **Compatibility/offline Java** — the existing `BigInteger` implementation, with its current
   scalar blinding and verify-before-release checks. It remains suitable only where an
   untrusted observer cannot measure the operation and the host is not shared with an
   adversary. The future fixed-limb deterministic-v1 implementation remains in this same
   assurance class as a compatibility/testing signer.
2. **Validated dedicated-host Java** — a new pure-Java path over fixed-size 4×64-bit
   field/scalar representations, fixed operation schedules, masked selection, dedicated
   secret-key types, a reviewed hedged nonce profile, and no `BigInteger` operation on secret
   data.

Replacing `BigInteger` is necessary and removes the largest known implementation problem, but
it is not by itself a constant-time proof. Java does not specify the machine code produced by
the JIT, object movement/collection, or all microarchitectural behavior. Only the hedged
signer may be approved for **network-reachable signing on a dedicated or single-tenant host**
after platform-specific timing, generated-code, fault, performance, and external-review gates
pass. The fixed-limb deterministic-v1 signer is a compatibility/testing profile, not an
online profile. Neither profile claims resistance to a hostile co-tenant, privileged local
attacker, hypervisor, or invasive physical observer.

There will be no automatic fallback from the hardened path to `BigInteger`. If the hardened
key type, supported JVM/platform profile, secure randomness, or self-check is unavailable, an
online-required request fails closed.

---

## 1. Current problem

### 1.1 `BigInteger` is the main blocker

The current signer processes secrets through variable-size arbitrary-precision arithmetic:

```text
r = Poseidon_t3(NONCE_TAG; sk, msg) mod l
R = [r]G
S = r + k*sk mod l
```

The relevant paths include:

- Poseidon field addition, multiplication, exponentiation, and reduction over secret `sk`;
- scalar multiplication over secret `r` and, during key derivation, secret `sk`;
- `S = r + k*sk mod l`;
- scalar blinding and reduction;
- conversion/import through `BigInteger`.

`BigInteger` is not designed as a constant-time cryptographic integer:

- its magnitude length is data-dependent;
- multiplication and division/reduction select algorithms based on operand shape and size;
- values are immutable, allocated, copied by the runtime, and cannot be reliably zeroized;
- `mod` performs general division rather than fixed-modulus reduction.

The current fixed 316-iteration and multiple-of-`l`-blinded scalar multiplication removes the
previously measured loop-bound/trailing-zero structure. It does not make the underlying
coordinate arithmetic, scalar reduction, or nonce derivation constant-time.

### 1.2 `BigInteger` is not the only consideration

A hardened implementation must also remove or control:

- secret-dependent branches and array indices;
- secret-dependent loop counts;
- variable operation sequences in point multiplication;
- data-dependent normalization/inversion paths;
- allocation patterns that vary with secret data;
- provider-dependent nonce hashing behavior;
- faults that corrupt `R`, `S`, the public-key relation, or the release check;
- key copies and accidental logging.

Replacing `BigInteger` with another general arbitrary-precision class is therefore not enough.
The replacement must be specialized fixed-modulus arithmetic with a uniform schedule.

### 1.3 Nonzero nonce is a required invariant

If nonce scalar `r` were zero, then `R` would be the identity and:

```text
S = k * sk mod l
```

A valid released signature with `k != 0` would disclose `sk`. The probability under the
current hash/reduction is negligible, but production signing must not rely on “this should
never happen.”

Before the next release, the existing compatibility signer must fail closed if `r == 0`.
Every future nonce profile must derive/map into `[1, l)` or fail without releasing a
signature. The exact mapping must have a bias analysis and bounded, fixed-schedule behavior.

The deterministic-v1 compatibility signer computes the existing transcript exactly, including
`r = Poseidon(...) mod l`, then fails closed if the result is zero. This catastrophic invariant
check is a deliberate exception to the online path's no-secret-dependent-failure rule: it
runs only after the complete nonce-derivation schedule, releases no partial output, and the
profile is never approved for network-reachable signing. The hedged profile must instead use
an externally reviewed fixed-schedule mapping into `[1, l)`.

### 1.4 Requirement gate for the online path

M0 is required regardless of whether the hardened project continues. M1 and later milestones
are justified by this concrete target:

> A network-reachable credential/signing microservice in which untrusted remote clients
> control message contents and request timing, deployed on a dedicated or single-tenant host,
> where an offline signing workflow does not meet the required availability or latency.

Before M1 begins, the project must record the intended signing volume, latency/throughput
targets, supported host-isolation model, key-provisioning boundary, and why an offline workflow
is insufficient. If that requirement is withdrawn, the correct outcome is M0 plus the
compatibility/offline profile, not completion of M1–M9 for its own sake.

---

## 2. Current and target readiness

Every positive cryptographic verdict remains gated on the external review required by
ADR-0037.

| Component | Current online status | Current offline status | Target |
|---|---|---|---|
| In-circuit Jubjub/Pedersen gadgets and `verifyStrict` | Ready pending external review | Ready pending external review | No secret-path change |
| `verifyWithRegisteredKey` | Conditional on protocol registry binding | Same | No change |
| `EdDSAJubjub.verify` | Ready pending external review | Ready pending external review | No change |
| `PedersenCommitment.verify` | Ready pending external review; disclosed opening uses public scalars | Ready pending external review | No change |
| R1CS compiler/proving pipeline | Ready under existing regression gates | Ready | No change |
| Current `BigInteger` `EdDSAJubjub.sign` | **Not approved** | Isolated/offline only | Retain as compatibility profile |
| Current `BigInteger` Pedersen generation | **Not approved for secret inputs** | Isolated/offline only | Retain as compatibility profile |
| Current `BigInteger` key generation/import | **Not approved** | Isolated/offline only | Retain for compatibility |
| Deterministic-v1 fixed-limb signer | Implemented; **not online-approved** | Compatibility/testing only | Retain as compatibility oracle |
| Hedged fixed-limb Java signer | Implemented as an internal review candidate; validated factory remains fail-closed | Candidate only; no validated label | Validated dedicated-host profile only after all gates |
| Fixed-limb Java Pedersen generation | Implemented as an internal/package-private, explicitly unapproved review candidate | Candidate only; no validated label | Separate validated dedicated-host candidate |

Changing nonce generation does not change verification. Existing and new signatures use the
same `(R, S)` encoding, challenge, and verification equation. Consequently:

- existing signatures remain valid;
- existing verifiers and in-circuit gadgets can accept signatures from a future hedged
  profile;
- R1CS shapes, proving keys, and verification keys do not change;
- newly generated signature bytes and deterministic signing fixtures differ under the hedged
  profile.

The signer profile must still be versioned because nonce domain separation, deterministic
reproducibility, and operational assurance change even when the verifier does not.

This verifier compatibility does **not** imply application compatibility. Before the hedged
profile is enabled, ZeroJ and known downstream users must be audited for any use of `R`, `S`,
or the encoded signature as a nullifier, uniqueness key, cache/database key, deterministic
identifier, commitment input, or derivation seed. Such a use may turn nondeterministic
signatures into a protocol correctness change. Protocols should derive nullifiers and stable
identifiers from an explicit credential or application identifier instead of signature
randomness.

---

## 3. Assurance profiles

### 3.1 Compatibility/offline Java

Required deployment properties:

- no network-originated signing requests while the key is present;
- no untrusted co-resident process, tenant, browser content, or plugin;
- no attacker-visible high-resolution timing, cache, power, or scheduling observation;
- the complete operation runs inside the isolated boundary;
- signatures are exported only after verify-before-release succeeds.

The current APIs remain available for compatibility and testing, but their names/Javadoc must
not imply online approval.

### 3.2 Validated dedicated-host Java

The first online target includes:

- untrusted remote clients controlling messages and request timing;
- high request volume, repeated messages, malformed inputs, and concurrent requests;
- observation of end-to-end request latency;
- a dedicated or single-tenant signer host;
- one explicitly supported Java version, JVM implementation, CPU architecture, and runtime
  configuration per validated profile.

It excludes:

- a malicious same-host tenant;
- root/kernel/hypervisor access;
- arbitrary cache/branch-predictor attacks from another local process;
- invasive physical measurements or fault injection beyond modeled tests;
- a compromised signer process or JVM.

The label is therefore **validated dedicated-host profile for the reviewed remote threat
model**. It is not a universal network-deployment or “provably constant-time Java” claim.

### 3.3 Shared-host/high-assurance online

Pure Java cannot presently support a strong claim against a hostile co-tenant or privileged
local observer. Such deployment remains not recommended even after the fixed-limb work.
Isolation, a complete-operation HSM/enclave, or another reviewed boundary would be an
application-level requirement, not something this pure-Java ADR supplies.

---

## 4. Decisions

### Decision 1 — Separate assurance in the API

Introduce an explicit signer abstraction. Illustrative shape:

```java
interface JubjubSigner extends AutoCloseable {
    JubjubSigningProfile profile();
    JubjubPoint publicKey();
    EdDSAJubjub.Signature sign(JubjubMessage message);
}

JubjubSigner offline = JubjubSigners.compatibilityOffline(keypair);
JubjubSigner online  = JubjubSigners.validatedDedicatedHostJavaRequired();
```

The zero-argument validated method is intentionally a fail-closed placeholder while no
approved platform profile exists. It accepts no caller-constructed `HardenedJubjubKey`
because that general-purpose object carries no unforgeable provisioning provenance. A future
validated implementation must provision/import the key itself after platform attestation, or
accept an opaque installation handle minted only by that approved boundary. It must not
enable the profile by simply accepting and relabelling a key produced by the public general
factories.

Add the symmetric `EdDSAJubjub` off-circuit overload:

```java
public static boolean verify(
    JubjubPoint publicKey,
    JubjubMessage message,
    EdDSAJubjub.Signature signature
);
```

`JubjubMessage` is a final value class with a non-public constructor and two unambiguous
factory families:

```java
JubjubMessage.fromCanonicalFieldBytes(byte[] encodedFieldElement);
JubjubMessage.hashToField(byte[] arbitraryMessage);
JubjubMessage.toPublicFieldElement();
```

`fromCanonicalFieldBytes` accepts exactly 32 unsigned **big-endian** bytes, interprets them
with OS2IP, and rejects values `>= p`; it neither reduces nor accepts alternate-length
encodings. This field/message codec follows the suite's existing big-endian OS2IP convention
for tags and `hashToField`. It is deliberately different from the independent compressed
point codec, which remains the Zcash/zkcrypto little-endian convention.

`hashToField` is a prehash-to-field operation with these normative v1 semantics, matching
[`docs/specs/jubjub-eddsa-v1.md`](../specs/jubjub-eddsa-v1.md):

```text
DST  = ASCII("ZeroJ-JubjubEdDSA-v1-hashToField")
wide = SHA-512(I2OSP(len(DST), 1) || DST
             || I2OSP(len(message), 8) || message)
out  = OS2IP_BE(wide) mod p
```

The message length is an unsigned 64-bit big-endian byte count. The cryptographic `byte[]` API
adds no suite-specific lower cap: it accepts zero through the largest array supported by the
JVM (never greater than `Integer.MAX_VALUE`). Service-level request-size limits belong to the
deployment profile, not this mapping. SHA-512 and this exact DST, framing, byte order, and
reduction are versioned together. For this modulus, the relative probability difference
between the high- and low-probability reduction buckets is approximately `2^-257.14`; the
resulting total statistical distance from uniform is approximately `2^-261.23`. Both are
negligible at the target security level. Independent empty, short, SHA-512 block-boundary, and
multiblock vectors are release gates.

The signature cryptographically binds only the resulting field element. A verifier starting
from the original payload must reproduce this exact `hashToField` operation; neither the
signature encoding nor `JubjubMessage` metadata records which preprocessing factory was used.
No bare `byte[]` signing or verification overload is provided because callers must choose
explicitly between a canonical field element and an arbitrary payload.

The byte hash is application preprocessing, not a new in-circuit SHA-512 gadget. Circuit
callers obtain the resulting canonical public field element explicitly through
`toPublicFieldElement()` and supply it as the circuit public/witness input. Integration
vectors must prove that application preprocessing, off-circuit verification, and circuit
inputs all use the same value.

The class defensively copies mutable input and returns copies from any encoding accessor.
All new signer and off-circuit verifier APIs accept `JubjubMessage`. Existing public
`BigInteger msg` signer and verifier APIs remain compatibility adapters after validating
`0 <= msg < p`; `BigInteger` is acceptable for public compatibility data, but is not the
preferred hardened API. Verification never implicitly chooses between canonical-field and
arbitrary-payload preprocessing. The typed verifier may delegate internally to the existing
public-data verifier after an explicit canonical conversion.

The typed legacy static signer is exposed with the explicit
`signCompatibilityOffline(Keypair, JubjubMessage)` name. Its generic
`sign(Keypair, JubjubMessage)` alias remains compatible but is deprecated so migrating to the
message type cannot silently look like migration to the hardened signer.

Adding reference-type overloads makes a Java call containing an untyped `null` literal
potentially ambiguous at compile time. Existing calls with a statically typed `BigInteger`
remain source-compatible and existing bytecode remains binary-compatible; callers testing
null rejection should cast the literal or use a typed variable. This is an API-source caveat,
not a runtime fallback.

These additional rules are binding:

- `validatedDedicatedHostJavaRequired` constructs only the approved hedged profile and never
  delegates to the deterministic-v1 or legacy `BigInteger` signer;
- the validated factory obtains auxiliary randomness only through the declared platform
  profile's approved source factory; it does not accept an arbitrary caller-supplied
  `SecureRandom`;
- the validated factory also owns key installation/provisioning after platform attestation;
  a public untagged `HardenedJubjubKey` is never sufficient evidence for the validated label;
- the platform profile pins the exact randomness implementation class, algorithm, provider
  identity/version, and construction configuration; an unexpected subclass, provider, or
  deterministic test source is rejected before key material is accessed;
- unsupported JVM/CPU configuration, closed key, unapproved randomness source, provider
  exception, declared RNG-health alarm, or failed self-check aborts;
- the legacy static `EdDSAJubjub.sign` remains source-compatible but is documented and
  deprecated for network-reachable issuance;
- assurance is a property of the signer implementation and deployment, not of `(R, S)` bytes;
- there is no generic “best available” factory that can silently weaken assurance.

### Decision 2 — Add specialized fixed-limb storage and arithmetic kernels

The hardened signer needs two distinct 4×64-bit Montgomery domains:

1. **Jubjub base field `Fq`**

   ```text
   p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
   ```

   This is exactly the modulus already represented by `MontFr381`.

2. **Jubjub subgroup scalar field `Fr`**

   ```text
   l = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
   ```

   ZeroJ does not currently have a fixed-limb type for this modulus.

`MontFr381` is a useful correctness/performance starting point for `Fq`, but is not suitable
unchanged for secret operations:

- `add`, `sub`, and conditional reduction branch on carries/borrows/comparisons;
- `fromBigInteger` and `toBigInteger` cross the variable-time boundary;
- inversion/exponentiation methods use branches and `BigInteger` exponents;
- the object API allocates results and exposes conversion methods inappropriate for key
  storage.

Do not model secret field elements as immutable heap value objects. Use this explicit split:

- `CtJubjubFqOps` and `CtJubjubFrOps` are stateless, package-private arithmetic kernels;
- `SigningScratch` owns the fixed-size mutable limb regions used by one signing operation;
- `HardenedJubjubKey` owns its persistent mutable scalar/nonce-key storage; and
- every operation writes into caller-supplied output regions and accepts only fixed/public
  region offsets.

The exact storage may be fixed-size `long[]` regions or an equivalently auditable mutable
four-limb layout. It must not allocate one object per field operation. The kernels provide:

- exactly four limbs in every field/scalar storage region;
- unrolled/fixed-count Montgomery multiplication and squaring;
- arithmetic carry/borrow propagation;
- unconditional candidate subtraction followed by mask-based selection;
- constant-index loads/stores;
- fixed public-exponent inversion or a reviewed fixed addition chain;
- canonical fixed-size byte import/export;
- no `BigInteger` constructor, reducer, comparison, or conversion in a secret-bearing method.

The kernels may share verified constants/low-level helpers with `MontFr381` only after that
shared code meets the hardened rules. Otherwise, keep the new path internal and
differential-test it against `MontFr381`/`BigInteger` rather than changing the stable BLS
implementation.

### Decision 3 — Build a separate hardened point implementation

Do not retrofit `JubjubPoint` in place. Its public `BigInteger` coordinates are useful for
public-data interoperability but unsuitable for storing intermediate secrets.

Add a stateless internal `CtJubjubPointOps` kernel operating on extended-coordinate
four-limb storage regions through `CtJubjubFqOps`:

- complete unified addition and doubling;
- fixed 252-bit scalar schedule for raw subgroup scalars;
- fixed schedule for any scalar blinding retained after measurement;
- mask-based point selection, with no secret branch or secret-indexed table;
- mutable, caller-supplied output/work buffers inside the hardened kernel rather than chains of
  immutable secret-bearing value objects;
- one fixed-shape `SigningScratch` owned exclusively by each signing operation;
- one fixed-schedule normalization at the public-output boundary;
- explicit handling of identity without a cheap special path.

Every persistent or heap-resident secret representation—including Poseidon state, nonce and
scalar limbs, `k*sk+r`, and projective coordinates—must live in that operation's mutable
scratch or another explicitly owned mutable buffer. Short-lived arithmetic intermediates may
exist in primitive locals, JVM operand stacks, CPU registers, or compiler-generated spills;
they are covered by the JVM/generated-code assessment rather than a false zeroization claim.

The complete scratch is wiped in a `finally` block after success or failure. It is never
cached in the signer or shared between concurrent operations. Generated-code inspection must
confirm that the final wipe stores were not optimized away on every supported platform. The
fixed allocation count/size is part of the supported-platform profile; this reduces avoidable
heap copies but does not overclaim erasure of locals, registers, spills, or runtime copies.

After the fixed-limb nonce point is normalized, `R`, `pk`, and the message are public and may
be converted to existing `JubjubPoint`/`BigInteger` types to compute the public challenge.
`S` is converted only after the secret-bearing scalar equation and nonce re-derivation checks
complete. Timing of these public conversions may depend on released public values; they must
not read or convert the secret key, nonce key, nonce scalar, or secret intermediates.

### Decision 4 — Remove `BigInteger` from the whole signing secret path

The hardened path must cover more than `[r]G`:

| Operation | Hardened representation |
|---|---|
| secret-key storage/import | `HardenedJubjubKey` four-limb scalar storage / owned canonical 32-byte input |
| public message | canonical `JubjubMessage`; fixed-limb import after canonical validation |
| public-key derivation | `CtJubjubPointOps` over operation-owned scratch |
| Poseidon nonce state | four-limb `Fq` scratch regions via `CtJubjubFqOps` |
| Poseidon output reduction `p -> l` | fixed-limb bounded reduction |
| nonce point `R` | `CtJubjubPointOps` over operation-owned scratch |
| public challenge hash/reduction | existing independent public-data implementation; canonical `k` is imported into fixed-limb `Fr` before `k*sk` |
| `k * sk + r mod l` | four-limb `Fr` scratch regions via `CtJubjubFrOps` |
| public conversions | normalized `R` before public challenge; `S` only after nonce re-derivation |

Since `p = 8l + c` for `0 < c < l`, a canonical `x < p` has quotient at most eight on
division by `l`. The `Fq -> Fr` reducer therefore performs **exactly eight** unconditional
candidate subtractions of `l`, selecting each candidate with a carry/borrow-derived mask. It
must not use division, early exit, or a value-dependent loop. Mutation and boundary tests pin
all eight rounds.

Once `R`, the public key, and `JubjubMessage` are finalized, challenge computation operates
only on public data. It may reuse the hardened Poseidon/reduction kernel for consistency and
implementation simplicity, but it is classified public-data-only rather than part of the
secret-confidentiality boundary. Nonce derivation and `k*sk+r`, by contrast, remain
secret-bearing.

A change that replaces only point multiplication but leaves `Poseidon(sk, msg)` or
`k*sk mod l` on `BigInteger` does not qualify for the hardened profile.

### Decision 5 — Use a dedicated pure-Java secret-key type

The hardened path must not accept `EdDSAJubjub.Keypair`, because that type stores `sk` as an
immutable `BigInteger`.

Add a non-serializable, redacted, `AutoCloseable` `HardenedJubjubKey` type:

- generated directly from `SecureRandom` into fixed-size mutable storage using the sampling
  rule below;
- imported from an owned canonical 32-byte unsigned big-endian scalar, never from
  `BigInteger` in the validated factory;
- validates `0 < sk < l` without variable-length arithmetic;
- stores the scalar and any dedicated nonce key in mutable fixed-size arrays/fields;
- has no secret accessor and no secret-bearing `equals`, `hashCode`, or `toString`;
- atomically rejects new signing operations once close starts, permits already-admitted
  operations to finish, and wipes owned key material only after they finish;
- treats double-close as a safe no-op and rejects sign-after-close;
- documents that JVM moves, copies, registers, crash dumps, and caller-owned input buffers
  limit zeroization guarantees.

Hardened key generation is specified independently from the signing schedule:

1. obtain exactly 32 fresh bytes from the caller-supplied cryptographically secure
   `SecureRandom`;
2. clear the high four bits of byte 0, producing a uniform 252-bit unsigned big-endian
   candidate;
3. accept iff `0 < candidate < l`; otherwise overwrite the candidate buffer and repeat;
4. on a provider exception or declared RNG-health alarm, wipe every owned buffer and fail
   without returning a key.

This is exact rejection sampling and therefore produces an unbiased scalar; its per-draw
acceptance probability is `(l - 1) / 2^252`, approximately `90.57%`. Its variable draw count
is permitted because key generation is not a network signing operation and, assuming the
CSPRNG draws are independent, the number of rejected draws does not reveal the accepted
scalar. Key generation must not share the signing endpoint or its timing label. If a future
deployment requires fixed-schedule key generation, it needs a separately reviewed
multiple-candidate construction and failure bound; `random mod l` is not an acceptable
shortcut.

The general key-generation API may continue to accept a caller-supplied `SecureRandom`, but
that alone does not confer validated-source provenance. A key is eligible for the validated
signer only if it was generated through the declared platform profile's approved source
factory or imported through a separately approved key-provisioning boundary. Test-only or
unapproved generation sources must not be relabelled as validated through a public flag or
caller-asserted metadata.

The compatibility/review factories that accept a `HardenedJubjubKey` transfer destructive
ownership to the signer. A signer close closes and wipes that key. If a caller deliberately
constructs multiple wrappers over one key, they share the same destruction domain: closing
any wrapper invalidates every other wrapper. The validated factory does not expose this
untagged-key form.

One signer instance supports concurrent calls using a separate fixed-shape
`SigningScratch` and fresh auxiliary-randomness buffer per admitted call. Key material is
read-only while calls are active; no secret-bearing scratch is stored on the signer instance
or shared across calls. This concurrency and close protocol must be specified in API Javadoc
and exercised under races.

An explicit migration helper may convert a legacy `BigInteger` key into the hardened type, but
that import operation and the original `BigInteger` remain offline-only. The resulting
hardened key may subsequently be installed on the dedicated online host through a canonical
secret-key provisioning process.

### Decision 6 — Retain v1 compatibility and specify a hedged nonce profile

Two nonce profiles are needed:

1. **Deterministic v1 compatibility**

   ```text
   r = Poseidon_t3(NONCE_TAG; sk, msg) mod l
   ```

   Reimplement this exactly with `CtJubjubFqOps`/`CtJubjubFrOps`. For every nonzero result it
   preserves existing golden signatures and provides the strongest differential oracle for
   the new arithmetic. If the reduced result is zero, complete nonce derivation, wipe the
   candidate, and fail closed before point multiplication or any output. This exceptional
   failure is allowed only for this compatibility/testing profile; deterministic v1 is not
   eligible for the validated dedicated-host label.

2. **Hedged validated dedicated-host profile**

   The recommended online signer combines dedicated secret nonce material, the canonical
   public key, canonical message, a versioned domain, and fresh auxiliary randomness. Fresh
   randomness improves resilience to repeatable side-channel and fault behavior, while the
   secret-derived component ensures weak/repeated randomness alone does not make the nonce
   public or repeat it across different messages.

The implementation phase records a concrete, versioned transcript in
[`docs/specs/jubjub-eddsa-hedged-v1-candidate.md`](../specs/jubjub-eddsa-hedged-v1-candidate.md).
It remains a **candidate for external cryptographic review**, not an approved profile. The
validated factory stays fail-closed and the public online API is not frozen until that review
accepts this construction or its replacement. The candidate specification selects:

- the Poseidon-based construction and exact permutation sequence;
- exact domains, framing, byte order, and field/scalar mapping;
- a separately derived/stored nonce key and its lifecycle;
- auxiliary-randomness length, approved source factory/implementation/algorithm/provider, and
  failure/health-alarm behavior;
- the exact 32-byte auxiliary input and stateless operation model;
- the eight-round `(x mod (l-1))+1` mapping into `[1,l)`, with no ordinary
  secret-dependent retry or failure;
- its `~2^-129.8353` statistical-distance bound and independent vectors.

Auxiliary randomness is secret signing material. It must be freshly generated by an approved
CSPRNG for every operation, remain in an operation-owned mutable buffer, never appear directly
in a signature, log, metric, exception, or tracing context, and be wiped in the signing
operation's `finally` block. The draw occurs after operation admission but before persistent
key material is read into scratch; a provider exception or declared RNG-health alarm therefore
aborts before secret signing work.

The signer owns the approved randomness source. Its source contract must be bounded,
non-reentrant, thread-safe for the declared concurrency, and explicitly closeable; signer
close waits for admitted draws/operations, then closes or wipes provider-owned state. A
provider that can block without a platform-enforced bound is not eligible for the validated
profile.

For the validated profile, “approved CSPRNG” is enforceable configuration, not caller
documentation. The M4 specification and platform profile identify the exact source factory,
implementation class, algorithm, provider identity/version, construction parameters, and
health alarms. The validated factory rejects an arbitrary `SecureRandom` instance, unexpected
subclass/provider, and deterministic test source before touching key material. Deterministic
sources remain available only through explicitly non-validated test/compatibility APIs.

Repeating auxiliary randomness must degrade to the documented deterministic-signature
security rather than enable algebraic key recovery. Provider exceptions and explicitly
supported health-test failures abort signing. ZeroJ does not claim that the generic
`SecureRandom` API detects every entropy degradation. Any cross-operation repetition test,
persisted RNG-health state, or response to detected weak/repeated output must be defined by
the normative profile. Hedging mitigates only reviewed fault/side-channel classes; it is not
a general fault-resistance claim.

If a byte-oriented hash is selected, ZeroJ must use a reviewed fixed-schedule Java
implementation or pin and validate the exact JCA provider/JVM combination. Merely requesting
`MessageDigest.getInstance(...)` does not establish a portable constant-time property.

BIP 340 and the expired CFRG hedged-signature Internet-Draft inform the desired properties but
do not normatively specify this custom ZeroJ suite. The draft is work in progress, has no
formal IETF standing, and warns that hedging does not stop every fault attack. External
cryptographic design review of ZeroJ's normative profile gates implementation.

Both profiles retain the existing public challenge and verifier, so signatures and circuits
remain compatible. No unqualified online factory exists: the
`validatedDedicatedHostJavaRequired` factory selects only the approved hedged profile.

Before accepting that profile, audit ZeroJ and known downstream protocols for any dependency
on deterministic `R`, `(R,S)`, or signature bytes. Record migrations for nullifiers,
derivation seeds, database keys, idempotency keys, and deterministic test fixtures. The
normative profile must also decide whether any nonce state is persisted; an unstated stateful
nonce design is prohibited.

### Decision 7 — Keep independent verify-before-release

The hardened signer:

1. derives the secret nonce and computes `R` in the hardened path;
2. after `R` is normalized and therefore public, converts it and computes the public challenge
   through the independently implemented existing public-data path;
3. computes secret-bearing `S = r + k*sk mod l` in fixed-limb `Fr`;
4. after computing `S`, re-derives the nonce through the complete fixed schedule into a
   disjoint scratch region and mask-compares it with the nonce actually used;
5. rejects a mismatch or zero before release;
6. converts `S`, assembles the completed public candidate, and verifies it with the existing
   `EdDSAJubjub.verify`;
7. returns only if every check succeeds.

The earlier `R` conversion processes only a finalized public group element; no secret scalar,
nonce, nonce key, or secret-bearing intermediate crosses into `BigInteger`. This sequence
provides implementation diversity for challenge/release verification and catches modeled
computation/conversion faults. The nonce re-derivation is necessary because a
fault that coherently replaces `r` before both `[r]G` and `S = r+k*sk` can produce a
mathematically valid signature that public verification alone accepts; if the replacement is
known, that signature can disclose the key. Re-derivation catches the modeled single
nonce-state/computation fault at a small fixed cost. It does not claim resistance to a
common-mode fault that corrupts both derivations identically, or an attacker able to
skip/corrupt both signing and all checks.

The mismatch/zero failure is a catastrophic fault invariant, not an ordinary nonce-mapping
outcome. The correct hedged mapping always produces a nonzero value and identical
re-derivation. Both derivations and the rest of the signing schedule complete before this
fault-only branch releases no partial output.

No unchecked public online signing entry point is provided.

The `r == 0` guard is a signer invariant, not a verifier change. This ADR does not add an
off-circuit-only `R != identity` rejection because the current in-circuit verifier has no
matching constraint; changing only one side would create acceptance divergence. Any future
third-party signature hardening must update and cost both verifier paths deliberately.

### Decision 8 — Extend the approach to Pedersen only after signing

For Pedersen:

- verification remains on the existing public-scalar path;
- hardened generation uses `CtJubjubFrOps`, `CtJubjubFqOps`, and `CtJubjubPointOps` over
  operation-owned mutable storage for both legs;
- value/blinding imports have explicit widths and modulo-`l` semantics;
- a dedicated mutable secret opening type replaces secret `BigInteger` inputs in the hardened
  API;
- if a later Java proof/witness workflow converts the opening back to `BigInteger`, the
  end-to-end workflow remains outside the strongest online profile.

Signing is the priority. Pedersen hardening is a separate release milestone and does not gate
the signer. Its implementation remains package-private until those separate timing,
platform, and external-review gates pass; an unapproved class named “hardened” is not a
public assurance label.

### Decision 9 — Preserve stable components

The hardened implementation is additive and internal:

- no change to `JubjubPoint` public algebra or encoding;
- no change to `EdDSAJubjub.verify`;
- no change to in-circuit verifier equations;
- no change to Poseidon parameters;
- no change to R1CS rows, nonzeros, domains, proving keys, or verification keys;
- no native module or runtime dependency;
- no change to `MontFr381` unless its complete BLS regression/performance suite remains green.

Legacy and hardened results are differentially tested. Stable public verification and circuit
components remain on their existing paths.

### Decision 10 — External and platform review are hard gates

Required review scopes:

1. **cryptographic design** — signature scheme, deterministic and hedged nonce profiles,
   nonzero/bias handling, key derivation, fault posture, and Pedersen semantics;
2. **fixed-limb implementation** — carry/borrow proofs, Montgomery constants/reduction,
   point formulas, scalar multiplication, Poseidon, byte codecs, and zeroization;
3. **JVM/platform behavior** — generated machine code, timing measurements, supported JVM
   flags/versions/CPUs, GC/allocation behavior, and concurrency;
4. **integration** — API downgrade resistance, lifecycle, release check, compatibility, and
   deployment instructions.

No internal test count or negative timing experiment replaces those reviews.

---

## 5. Required validation

### 5.1 Arithmetic correctness

For both `CtJubjubFqOps` and `CtJubjubFrOps`:

- exhaustive small/boundary values;
- random differential add/sub/mul/square/neg/inverse/reduce tests against `BigInteger`;
- aliasing tests for every supported input/output overlap;
- canonical import rejection for modulus and larger values;
- round-trip fixed 32-byte encoding;
- Montgomery constants independently generated and digest-pinned;
- property tests for closure, identities, distributivity, inversion, and reduction;
- mutation tests for every carry, borrow, mask, reduction round, and limb.

For hardened key generation:

- scripted-RNG fixtures cover zero, `l`, values above `l`, `1`, and `l-1`;
- rejection sampling consumes fresh 32-byte candidates and never reduces modulo `l`;
- provider exceptions and declared RNG-health alarms at every draw boundary wipe owned
  candidate storage and return no key;
- validated key generation accepts only the platform profile's approved source factory and
  rejects caller-asserted provenance;
- import rejects wrong lengths, zero, `l`, and noncanonical values;
- distribution tests are diagnostic only; the unbiased claim rests on the reviewed sampling
  argument and exact implementation.

For hardened points:

- differential add/double/negate/scalar multiplication against `JubjubPoint`;
- identity and boundary scalars `0`, `1`, `l-1`;
- subgroup/generator and existing zkcrypto/Zcash encoding fixtures;
- projective invariant checks after every test operation;
- no exceptional identity or zero-scalar schedule.

### 5.2 Signing and nonce correctness

- deterministic v1 signatures with nonzero nonce are byte-identical to current golden
  vectors and the profile is not exposed by the validated dedicated-host factory;
- hardened public-key derivation matches current keypairs;
- hardened signatures verify off-circuit and in both circuit entry points under their
  documented key preconditions;
- the `JubjubMessage` verifier overload accepts the same canonical field element as the
  signer, matches the range-checked `BigInteger` compatibility adapter, and never performs
  implicit payload hashing;
- deterministic-v1 `r == 0` is forced through a test hook only after the full derivation
  schedule and no point multiplication, partial output, or signature is released;
- repeated-nonce and publicly derivable-nonce test implementations demonstrate the standard
  key-recovery equations, ensuring those failure classes remain understood and detectable;
- the approved hedged profile has independent vectors for every transcript input and maps
  into `[1,l)` with the specified fixed schedule;
- fixed/repeated auxiliary randomness remains safe under the profile's documented security
  argument, while provider exceptions and declared health-test failures fail closed;
- the validated signer accepts the exact approved randomness implementation/algorithm/provider
  and rejects arbitrary subclasses, alternate providers, and deterministic test sources before
  any key access;
- key establishment rejects a zero derived nonce key before returning the key; this is
  defense-in-depth for a negligible bad-key event and not a substitute for fault review;
- test vectors with specified distinct auxiliary-randomness inputs produce distinct valid
  signatures for the same message; in production, fresh auxiliary randomness produces
  distinct signatures with overwhelming probability;
- all domains are distinct and pinned;
- `JubjubMessage.fromCanonicalFieldBytes` and `hashToField` have cross-implementation vectors
  for byte order, empty input, framing, SHA-512 block boundaries, multiblock input, and
  boundary field values;
- the determinism-dependency audit covers ZeroJ and known downstream uses of `R`, `(R,S)`,
  and signature encodings before the hedged profile is enabled.

### 5.3 Constant-schedule/source gates

The validated dedicated-host signing path must have:

- fixed loop bounds independent of secret data;
- no secret-dependent `if`, `switch`, exception, allocation size, array index, or table lookup;
- unconditional point add/double work and mask-based selection;
- fixed-count reduction and normalization;
- no `BigInteger`, `BigDecimal`, generic modular arithmetic, reflection, streams, boxing, or
  data-dependent collections;
- no call from hardened code to a method not classified as hardened or public-data-only.

The key-generation rejection loop and deterministic-v1 catastrophic zero check are scoped
exceptions described in Decisions 5 and 6; neither executes in the validated hedged signing
schedule. Public failures such as closed-key admission, randomness-source mismatch, provider
exception, or declared RNG-health alarm occur before secret signing work begins.

The architecture gate is transitive, not merely a package import check. Every method reachable
from the secret-bearing signing entry point must be classified as:

1. hardened secret processing;
2. public-data-only processing;
3. an approved platform primitive under the declared JVM/provider profile; or
4. the explicitly approved public release check after candidate conversion.

Module/package boundaries and bytecode call-graph/dependency checks must reject unclassified
edges and indirect access to forbidden APIs. Review is still required because a static
architecture test cannot establish timing behavior. For every conditional branch and indexed
memory access reachable in hardened secret processing, the implementation review must record
whether it depends only on public data or a fixed control structure.

### 5.4 JVM and timing gates

For every supported Java/JVM/CPU profile:

- warmup and steady-state measurements for secret key, nonce, Hamming weight, bit length,
  trailing zeros, zero/boundary scalars, messages, and auxiliary randomness;
- a `dudect`-style Welch-test harness with enough samples and predeclared thresholds;
- deliberately leaky negative controls that the harness must detect;
- cold/interpreted, C1, C2, on-stack-replacement, and forced-deoptimization timing exercises;
- generated C1 and C2 machine-code inspection, plus documented treatment of interpreter and
  deoptimization paths;
- generated-code inspection confirms operation-scratch and key-close wipe stores have not
  been removed or shortened by dead-store elimination;
- classification of every conditional branch and indexed memory access in secret-processing
  regions as public-data-dependent or fixed-control-structure-dependent;
- tests with the exact production JVM flags, GC, and approved randomness
  implementation/algorithm/provider/configuration;
- allocation profiling proving fixed allocation count/size per signing request;
- remote timing experiments under realistic request concurrency;
- rerun after every supported JDK, JVM vendor, compiler, CPU, or arithmetic change.

A production profile must warm and attest the reviewed compiled state before accepting signing
requests. Unexpected deoptimization or loss of that state removes the instance from readiness
until it is re-established. If the chosen JVM cannot enforce/observe that policy reliably,
every reachable tier and transition becomes part of the accepted timing assessment instead
of being assumed away.

A detected unexplained signal blocks release. No detected signal is evidence for that tested
profile, not proof for every JVM or machine.

### 5.5 Fault, lifecycle, and concurrency gates

- corrupt/skip `R`, `S`, challenge, nonce state, key relation, and conversion steps;
- verify-before-release rejects all modeled corruptions;
- no partial signature is returned on failure;
- concurrent signing is defined and race-free, not deterministic: every hedged operation has
  independent scratch and auxiliary randomness;
- close rejects new operations, allows already-admitted operations to finish, then wipes the
  key; close/sign races, double close, and sign-after-close match this contract;
- the signer owns and closes its auxiliary-randomness source after admitted operations finish;
  approved sources are bounded and non-reentrant so a provider cannot indefinitely prevent
  destruction;
- randomness-source mismatch, provider exceptions, and declared RNG-health-test failures
  abort before key access;
- key `toString`, logging, serialization, heap dumps in tests, and exception messages do not
  expose secret material;
- per-operation secret buffers are wiped on success and failure; persistent key buffers are
  wiped on close.

### 5.6 Performance and regression gates

Security takes precedence over matching the legacy latency. After the prototype:

- record median, p95, p99, throughput, allocation, and concurrency scaling;
- compare hardened deterministic, hardened hedged, legacy sign, key generation, and public
  verification;
- set a performance budget only from the secure implementation's baseline;
- require no material regression in public verification, circuits, R1CS compilation, or
  proving;
- keep exact circuit row/nonzero/domain pins and the opt-in CIP-1852 gate unchanged;
- require the downstream account-ownership recovery application to pin its complete approved
  graph/R1CS dimensions and digest before claiming verification-key compatibility; a
  print-only measurement is not a release gate;
- run the full repository test suite and end-to-end Groth16 prove/verify.

### 5.7 Deployment and service gates

These are properties of the supported microservice/runbook, not arithmetic-library claims:

- dedicated/single-tenant placement matches the declared threat model;
- request-size, concurrency, and rate limits prevent resource exhaustion and timing
  amplification;
- request isolation prevents one client from observing another client's detailed scheduling;
- readiness is withheld until JVM warmup/attestation and self-tests pass;
- provider exceptions, declared RNG-health alarms, unexpected deoptimization, release-check
  failure, and key-close events fail closed and are observable without logging secret
  material;
- the runbook pins the reviewed JDK/JVM/CPU, flags, GC, provider, container/host isolation,
  crash-dump policy, and upgrade procedure.

---

## 6. Delivery plan

| Milestone | Work | Exit gate |
|---|---|---|
| **M0 — immediate posture** | Keep current secret operations offline-only; reject `r == 0`; add generic nonce-failure/key-recovery fixtures; correct docs | Existing suite and golden vectors green |
| **M1 — requirement and arithmetic specification** | Approve the §1.4 microservice requirement and measurable target; specify `CtJubjubFqOps`/`CtJubjubFrOps`, mutable storage ownership, key sampling, constants, codecs, masked carry/borrow, exact eight-round `p -> l` reduction, and proof notes | Requirement owner/targets recorded; independent constants and `BigInteger` oracle tests |
| **M2 — fixed-limb kernels** | Implement internal pure-Java arithmetic and architecture guard against forbidden APIs | Arithmetic/property/mutation tests green |
| **M3 — hardened points, Poseidon, and deterministic compatibility** | Implement `CtJubjubPointOps`, fixed-schedule scalar multiplication/normalization, Poseidon through `CtJubjubFqOps`, and an internal deterministic-v1 compatibility signer | Differential curve/Poseidon tests and nonzero v1 golden vectors; zero nonce fails closed |
| **M4 — hedged nonce normative specification** | Decide the transcript, profile/version identifiers, dedicated nonce-key derivation/storage, auxiliary-randomness contract and approved source identity, fixed-schedule nonzero mapping, bias analysis, state model, independent vectors, and downstream determinism migration | External cryptographic design approval and determinism-dependency audit complete |
| **M5 — hardened key and signer API** | Add `JubjubMessage`, symmetric typed signer/verifier overloads, the public circuit-field bridge, `HardenedJubjubKey`, zero-nonce-key rejection, approved randomness-source ownership, per-call scratch, explicit shared destruction semantics, full hardened `S` arithmetic, public conversion, and release check; keep the validated placeholder keyless until an attested provisioning boundary exists; freeze the public API only after M4 | No secret `BigInteger`; canonical message adapters, provenance/randomness downgrade tests, and lifecycle/fault/concurrency tests green |
| **M6 — platform validation** | Timing harness, negative controls, randomness implementation/provider attestation, tier/deoptimization assessment, generated-code inspection, allocation profiling, and remote/concurrent benchmarks | No unexplained leakage on declared JVM/CPU/provider profiles |
| **M7 — external implementation review** | Review arithmetic, signer, nonce, JVM evidence, lifecycle, and integration | HIGH/MEDIUM findings fixed and retested |
| **M8 — validated dedicated-host release** | Publish supported JVM/CPU/randomness-provider matrix and operational runbook, including warmup/readiness, request isolation, rate/concurrency limits, RNG/deoptimization handling, and upgrade policy | Validated label applies only to reviewed configurations and deployment controls |
| **M9 — Pedersen hardening** | Reuse fixed-limb point/scalar path with dedicated opening types | Separate correctness/timing/review gates |

M0 proceeds unconditionally. M1 cannot start until its requirement record is accepted. The
validated dedicated-host label cannot precede M4–M8; a fixed-limb or deterministic-v1
prototype alone is not production readiness.

Implementation progress and measured local evidence are tracked separately in
[the ADR-0039 implementation status](0039-jubjub-implementation-status.md). That document may
record completed engineering, but it cannot waive this ADR's external/platform/deployment
gates.

---

## 7. Release decisions

### Ready now, subject to external cryptographic review

- public-data off-circuit verification;
- `verifyStrict`;
- other in-circuit Jubjub/Pedersen gadgets under their documented preconditions;
- disclosed-opening Pedersen verification;
- R1CS/proving pipeline under its existing gates.

### Offline-only now

- current `EdDSAJubjub.sign`;
- current `keypairFromSecret` and `generateKeypair`;
- current secret-bearing `PedersenCommitment.commit`;
- any secret workflow using `BigInteger`.

### Future validated dedicated-host pure Java

Only the hardened signer, on an explicitly reviewed dedicated/single-tenant
JVM/CPU/randomness-provider configuration after M0–M8, and only with the approved hedged
profile. The label does not transfer to:

- the legacy `BigInteger` signer;
- the fixed-limb deterministic-v1 compatibility signer;
- an unreviewed JDK/JVM/CPU or runtime configuration;
- an arbitrary `SecureRandom`, unapproved provider, or deterministic test source;
- a custom downstream arithmetic build;
- a hostile shared host;
- a workflow that converts the hardened key/nonce/opening back to `BigInteger`.

### Stop conditions

Do not ship the validated dedicated-host label if:

- the §1.4 service requirement and deployment target are not accepted;
- any secret-bearing `BigInteger` operation remains;
- the nonce design lacks external cryptographic review;
- timing negative controls are not detected;
- generated code contains unexplained secret-dependent control/memory flow;
- leakage is measured and unexplained;
- stable component/circuit pins change;
- hardened factory fallback is possible;
- the validated factory can accept a randomness source outside its declared platform profile;
- the validated factory can relabel a general caller-created key without an attested
  provisioning boundary;
- the supported JVM/CPU/randomness-provider/runtime profile is not documented and
  reproducible.

---

## 8. Consequences

### Positive

- ZeroJ remains pure Java with no native packaging or FFM surface.
- Existing signatures, verifiers, circuits, proving keys, and verification keys remain
  compatible.
- Secret arithmetic moves from variable-size general integers to fixed-size specialized
  kernels.
- Online/offline assurance becomes an explicit API choice.
- The hardened path is additive, limiting regressions in stable public/circuit components.
- Deterministic v1 compatibility provides exact differential vectors while a hedged profile
  improves the eventual online posture.

### Costs and limitations

- Two fixed-modulus arithmetic kernels and a second point implementation require substantial
  verification and maintenance.
- Java/JIT behavior requires a supported platform matrix and repeated generated-code/timing
  review.
- Pure Java cannot provide a universal hard constant-time guarantee.
- The first validated label is dedicated/single-tenant, not arbitrary hostile shared
  infrastructure.
- Mutable secret-key hygiene improves control but cannot guarantee erasure of JVM/register/
  crash-dump copies.
- Hardened signing will likely cost more than the current best-effort path; the secure
  implementation establishes the acceptable performance baseline.

---

## 9. References

- [OpenJDK JEP 324 — Key Agreement with Curve25519 and Curve448](https://openjdk.org/jeps/324) —
  Java precedent for replacing `BigInteger` with fixed-size integer arithmetic
- [OpenJDK `BigInteger` source](https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/java/math/BigInteger.java)
- [RFC 8032 — EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 6979 — Deterministic DSA/ECDSA](https://www.rfc-editor.org/rfc/rfc6979)
- [BIP 340 — Schnorr signatures and synthetic nonces](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [Expired CFRG Internet-Draft: Hedged ECDSA and EdDSA Signatures, revision 05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-det-sigs-with-noise-05) —
  informative work in progress, not a normative standard
- [dudect](https://github.com/oreparaz/dudect) and [paper](https://eprint.iacr.org/2016/1123)
- [zkcrypto/jubjub](https://github.com/zkcrypto/jubjub) — curve/encoding differential oracle
  only, not a ZeroJ runtime dependency or assurance authority; its project currently states
  that it has not been reviewed or audited
- [ADR-0037](0037-jubjub-soundness-and-hardening.md)
- [ADR-0037 production-readiness addendum](0037-jubjub-production-readiness-status.md)
- [ADR-0038](0038-jubjub-dsl-remediation-plan.md)
- [`docs/specs/jubjub-eddsa-v1.md`](../specs/jubjub-eddsa-v1.md)
