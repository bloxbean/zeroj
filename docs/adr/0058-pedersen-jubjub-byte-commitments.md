# ADR-0058: Arbitrary-byte commitments over the existing Jubjub Pedersen profile

## Status

**Proposed — design review only.** Addresses [issue #93](https://github.com/bloxbean/zeroj/issues/93),
phase 1 of #93–#96. This PR adds only this ADR. It implements no API or profile and does not
close #93. Acceptance authorizes the milestones below; it is not a security certification.

**Risk: R3** for the byte-to-scalar mapping and secret-bearing execution; **R2** for API,
validation, serialization boundaries and compatibility. Correctness and security invariants
take precedence over performance. Performance and bounded memory are implementation gates,
not optional follow-ups. Existing experimental/offline restrictions remain in force.

## Date

2026-10-15

## Context

ZeroJ can commit to subgroup scalars but has no specified way to commit to a document or
arbitrary binary data. Interpreting an arbitrary byte array as an integer and reducing it
modulo the subgroup order loses binding to the original representation: leading zeroes and
integers differing by the order alias. Treating bytes as text introduces further ambiguity.

We need a versioned, collision-resistant byte-to-scalar mapping followed by the existing
two-base commitment. Large documents must not require a second payload-sized allocation or
one curve operation per chunk. Numeric commitments, circuit shapes, serialized points and
confidential notes must retain their current meaning.

### Current API audit

Audit baseline: ZeroJ `43c7b32e96fd231eca8b26abbb63c7bc002090b9` (`main`). Paths in this table
are relative to `zeroj-circuit-lib/src/main/java/org/zeroj/circuit/lib/` unless stated otherwise.

| Surface | Actual behavior | Consequence for #93 |
|---|---|---|
| `jubjub/PedersenCommitment.commit(BigInteger, BigInteger)` | Reduces **both** inputs modulo `l`, including negative integers; computes `[v]G + [r]H` using two independently blinded, fixed 316-iteration secret schedules; returns a normalized `JubjubPoint` | Preserve exactly. The current numeric method is named `commit`, not `commitScalar` |
| `PedersenCommitment.verify(JubjubPoint, BigInteger, BigInteger)` | Same modular semantics; uses faster, variable-time public scalar multiplication and projective equality | Only for an opening disclosed to the verifier; private local checks must recompute through `commit` |
| `PedersenCommitment.randomBlinding(SecureRandom)` | Draws 64 random bytes, interprets unsigned big-endian, reduces modulo `l`, wipes the temporary array | Reuse. Approximately uniform, not an exact-uniform sampler; immutable `BigInteger` copies cannot be erased |
| `PedersenCommitment.decode(byte[])` | Strict 32-byte point decoding followed by `[l]P = O`; accepts identity | Reuse at the new serialized commitment boundary; `JubjubPoint.fromBytes` alone is insufficient |
| `jubjub/JubjubCurve`, `JubjubPoint`, `PedersenCommitment.H` | Jubjub base field is BLS12-381's scalar field `p`; subgroup order is the different prime `l`; `G` and Poseidon-derived `H` are pinned by the numeric spec | Hash modulo **`l`**, never `p`; reuse both bases without re-derivation or changes |
| `jubjub/InCircuitPedersen`, `zk/ZkPedersen` | Low-level bit relations represent residues; symbolic layer establishes canonical scalars. Blinding width is 252 and its public/constant/narrowing guard rails remain required | No byte hashing gadget is added; no circuit or proving/verification key changes |
| `zk/ZkPedersenCommitment`, `ZkPedersen.assertBalanced` | Numeric commitments and bounded integer balance statements; received points have explicit validation obligations | Do not present byte commitments as numeric amounts or balance terms |
| `jubjub/HardenedPedersen`, `HardenedPedersenOpening`, `PedersenScratch` | Package-private fixed-limb candidate with its own unpassed release gates under ADR-0039 M9 | Do not expose or silently select it for this feature |
| `jubjub/JubjubMessage.hashToField` | EdDSA-specific SHA-512 framing and reduction modulo **`p`**, intended for public messages | Not a reusable byte-commitment hash; different domain, target field and secret lifetime |
| `jubjub/NoteOpening`, `ConfidentialNotes`, `NoteScanner` | `confidential-note-jubjub-v1`: amount in `[0, 2^64)`, canonical `r`, numeric commitment, fixed opening delivery; recipient recomputation uses the blinded path | #79 stays numeric. A byte hash is neither a note amount nor an encrypted document |

The controlling records are [ADR-0051](0051-pedersen-commitment-profiles.md),
[the numeric spec](../specs/pedersen-jubjub-v1.md),
[ADR-0038](0038-jubjub-dsl-remediation-plan.md),
[ADR-0039](0039-jubjub-online-and-offline-readiness.md), and
[ADR-0055](0055-confidential-notes-jubjub.md). ADR-0051 D7's unresolved G1 sigma-proof
decision is unaffected. `settings.gradle` and the architecture/support matrices put this
host API in `zeroj-circuit-lib`; blst accelerates BLS12-381, not this Jubjub operation.

## Threat model and trust assumptions

- **Untrusted:** payload bytes and lengths, stream behavior, supplied blindings, serialized
  commitment points, profile labels and claimed application context. An attacker can submit
  malformed points, attempt type/profile substitution, change an opening, or supply a very
  large or stalled stream.
- **Secrets:** the original bytes, hash-derived scalar, blinding, digest state/intermediates
  and temporary input buffers during commitment generation. For a disclosed-opening check,
  the bytes and blinding are intentionally known to that verifier. A method name containing
  `verify` does not make a still-private opening public.
- **Trusted:** the frozen numeric profile and its unknown-discrete-log assumption for `G,H`;
  the RFC 9380/SHA-512 assumptions; a correctly seeded CSPRNG; the JDK's implementations;
  and an offline/isolated boundary for the **whole** secret operation, including hashing and
  reduction. No constant-time claim is inherited from an algorithm specification.
- **Application obligations:** authenticate the expected profile and original issuance context
  when they matter, bound accepted input sizes and execution time, preserve the exact bytes,
  and store/deliver the opening securely. Commitments do not provide encryption, document
  availability, authorization, provenance, replay prevention or `ScriptContext` binding.

Binding to bytes rests on both computational Pedersen binding and collision resistance of the
**reduced** hash-to-scalar map. A collision in that map gives two byte openings with the same
blinding. The approximately 252-bit group/scalar space limits generic security to about
126 bits; SHA-512 and a 128-bit statistical mapping parameter do not turn Jubjub into a
256-bit- or exact 128-bit-security system. Ideal uniform, independent `r` gives perfect
hiding of the point; the existing wide-reduction sampler gives statistically close hiding.
Neither statement covers timing leakage, exposed hashes, reused blindings or application
metadata such as document length.

## Pinned normative references

1. **RFC 9380, August 2023**, [§§3.1, 4, 5, 5.2, 5.3.1, 10.3, 10.5–10.7 and Appendix K.3](https://www.rfc-editor.org/rfc/rfc9380.html).
   §5 explicitly says `hash_to_field` is “also suitable for securely hashing to scalars.”
   We instantiate it over `GF(l)`; we do **not** claim an RFC-standardized Jubjub
   hash-to-curve suite. §10.3's timing requirements explain why this implementation remains
   restricted rather than advertised as safe for exposed secret operations.
2. **ZeroJ `pedersen-jubjub-v1`, 2026-10-03**, at the audit commit above:
   [§§1–4](../specs/pedersen-jubjub-v1.md) define curve, generators, blinding sampling and
   point encoding; §§5–7 define existing circuit and integer semantics. This is the normative
   source for the reused commitment, including `H`'s derivation. It is not replaced by a new
   generator recipe.
3. **ZIP 216**, [Specification, pinned at `929a92f7383e036b6f6a48f43ec88c5bdd130003`](https://github.com/zcash/zips/blob/929a92f7383e036b6f6a48f43ec88c5bdd130003/zips/zip-0216.rst):
   “MUST reject non-canonical Jubjub point encodings.” Use its canonical-point rule, as
   already incorporated into the numeric spec. Sapling's separate key identity restrictions
   are not commitment identity restrictions.
4. **ZeroJ `confidential-note-jubjub-v1`, 2026-10-09**, at the audit commit:
   [§§3–5](../specs/confidential-note-jubjub-v1.md), for the opening format and recipient check
   that this proposal must not alter.

The external references were fetched and checked for this draft. The RFC supplies the
hash-to-field algorithm, not this application profile: the profile ID, domain string,
length framing, API and composition with the frozen Pedersen scheme below are ZeroJ choices
requiring review. M0 publishes the complete normative profile before production code.

## Decision

### D1 — Add a separate byte profile; freeze the numeric profile (R2)

Introduce **`pedersen-jubjub-bytes-v1`** in `zeroj-circuit-lib`, under `org.zeroj`.
Reuse the numeric profile's curve, `G`, `H`, point encoding and identity policy. The byte
commitment is:

```text
C_bytes(B, r) = [HashBytesToScalar(B)]G + [r]H
```

`B` is a sequence of octets, not an integer, string, JSON object, file path or a digest
supplied by the caller. Empty bytes are valid and hashed normally; null is invalid.
Leading/trailing zeroes, invalid UTF-8, byte-order marks and all other octets are significant.
No implicit normalization, decompression or decoding occurs.

Changing the hash, domain, framing, scalar mapping, bases or encoding requires a new profile
identifier. No configurable digest or caller-supplied DST exists in the public byte API.
The current `commit`/`verify` names, modulo semantics and point serialization remain unchanged.
A numeric `commitScalar` alias and a general multi-curve interface are left to #94.

### D2 — Exact domain-separated hash-to-scalar (R3)

Use RFC 9380 `hash_to_field` (§5.2), with `count = 1`, extension degree `m = 1`, target
prime **`l`**, statistical security parameter `k = 128`, and
`expand_message_xmd` (§5.3.1) using **SHA-512**.

```text
l   = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
DST = ASCII("ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-512")
n   = number of octets in B, 0 <= n <= 2^63 - 1
msg = I2OSP(n, 8) || B
L   = ceil((ceil(log2(l)) + 128) / 8) = 48
u   = expand_message_xmd_SHA512(msg, DST, 48)
s   = OS2IP(u) mod l
```

`I2OSP`/`OS2IP` are unsigned **big-endian** per RFC 9380 §4. `||` means concatenation of
octets. The eight-byte length has its top bit clear because v1 limits lengths to Java's
non-negative `long` range; length is measured before any hashing. No terminator is added.
`DST` is exactly 46 bytes (no newline/NUL):

```text
5a65726f4a2d706564657273656e2d6a75626a75622d62797465732d76312d4832532d584d443a5348412d353132
```

For clarity, the exact specialization of XMD is:

```text
DST_prime = DST || 0x2e
b0 = SHA-512( zero_octets(128) || I2OSP(n,8) || B || 0x0030 || 0x00 || DST_prime )
b1 = SHA-512( b0 || 0x01 || DST_prime )
u  = first 48 octets of b1
s  = OS2IP(u) mod l
```

Here `0x0030` is two octets; `0x00`, `0x01`, `0x2e` are one each. SHA-512's output/block
sizes are 64/128 bytes, so `ell = ceil(48/64) = 1`. Preserve the 128-zero-byte prefix; do
not substitute a plain SHA-512 digest. RFC Appendix K.3 tests XMD itself with its own DST
and output lengths; those are not the ZeroJ profile parameters.

Reduction is once, modulo `l`, with a fixed 48-byte input. No rejection sampling, clamping,
modulo-`p` reduction, sign interpretation, or retry when `s = 0`. Zero is a valid scalar.
Under the uniform-expander model, the conservative reduction-distance bound is
`l / 2^384 < 2^-132`, smaller than the RFC's `2^-128` target. This is a statistical bound,
not a statement of collision resistance or implementation timing.

Length framing is injective before hashing; it does not make the finite scalar mapping
injective. A one-pass streaming implementation is the same algorithm, not a different
chunked/Merkle profile. Unknown-length inputs must be counted from a stable source first or
spooled by the caller; the library never silently buffers them to discover the length.

### D3 — Add typed entry points and explicit validation (R2)

Proposed signatures, illustrative until M0's API contract is reviewed:

```java
// Additive static methods on PedersenCommitment; original methods remain unchanged.
PedersenBytesCommitment commitBytes(byte[] payload, BigInteger blinding);
PedersenBytesCommitment commitBytes(InputStream payload, long length, BigInteger blinding)
        throws IOException;
boolean verifyBytes(PedersenBytesCommitment commitment, byte[] payload, BigInteger blinding);
boolean verifyBytes(PedersenBytesCommitment commitment, InputStream payload,
                    long length, BigInteger blinding) throws IOException;

// New immutable, profile-specific value. No opening or payload retained.
PedersenBytesCommitment decode(String profileId, byte[] pointBytes);
String profileId();
byte[] toPointBytes();
```

The final three signatures are on `PedersenBytesCommitment` (`decode` is static). Instances
have no public raw-point constructor and no numeric-balance, addition or subtraction methods.
They hold a normalized validated point and a fixed profile identity; encoding returns a fresh
32-byte array. They never retain `B`, `s`, `r` or a digest object. Equality is point equality
within this final profile-specific type, not equality with a naked `JubjubPoint`.

- New methods require `0 <= r < l`; reject negative `r`, `l`, `l+1` and larger values
  rather than normalize them. `r = 0` remains algebraically valid (including tests), but
  caller-chosen zero/predictable blindings provide no hiding. Runtime range validation cannot
  establish entropy. Numeric `commit`/`verify` keep their existing modular acceptance.
- Null arguments throw `NullPointerException`. Invalid length, profile, encoding or scalar
  throws `IllegalArgumentException`. A well-formed opening that does not match returns
  `false`. I/O failures propagate as `IOException`; provider unavailability is a platform
  failure (`IllegalStateException`), never a successful verification or a fallback hash.
  Applications translate these explicit failures into rejection at their external boundary.
- `decode` compares the supplied ID **exactly**, without case folding, whitespace trimming,
  aliases or defaulting, then calls `PedersenCommitment.decode`. Reject wrong lengths,
  `v >= p`, non-square recovery, ZIP 216 aliases, small-order non-identity and mixed-order
  points. Do not cofactor-clear an attacker-supplied point to make it acceptable.
- Identity remains a valid encoded commitment; accepting the point does not accept an
  opening. `verifyBytes` must still check its equation. In particular, empty bytes with zero
  blinding are not defined to be the identity.
- Validate nulls, lengths, profile and scalar range before hashing or reading a payload.
  Received points are validated when the typed object is created, once per object; subsequent
  checks can reuse that invariant. No global cache of attacker-supplied points is introduced.

The serialized contract in this phase is the **pair** `(exact profile ID, 32 point bytes)`
with its binding supplied by the enclosing protocol. `toPointBytes()` is deliberately named
as a raw point encoding, not a self-describing commitment envelope. #94 decides the generic
envelope, opening codecs and verification-result interfaces; this ADR reserves no binary tag
or cross-curve encoding. `r` is an integer API input here, not a new scalar wire format.

### D4 — Authenticate semantics; do not promise profile separation from a point (R2)

Hash-domain separation makes a different mapping of bytes. It does **not** make the point
sets of numeric and byte commitments disjoint. In fact:

```text
C_bytes(B, r) = C_scalar(HashBytesToScalar(B), r)
```

An owner of a byte opening therefore also knows a numeric opening. A Java wrapper or a
prover-supplied label cannot establish original issuance semantics. The verifier selects its
expected profile from trusted configuration. When consuming an existing issued commitment,
it must authenticate the association of the exact point, expected profile and application
context, for example via an issuer-signed record or policy-guarded state. If the application
depends on that association and it is absent, reject. A successful opening check alone is
not evidence of where or under which profile a point was issued.

Negative profile tests must demonstrate both facts: the byte decoder refuses a numeric label,
and the bare numeric equation for `s = HashBytesToScalar(B)` can still pass. Do not write a
test asserting that all numeric openings for byte commitments are impossible.

For byte commitments, homomorphic addition only relates the derived **scalars modulo `l`**.
It is not document concatenation, JSON merge, integer addition on the source bytes or a useful
range statement about the document. The typed API exposes no such arithmetic. Anyone can
manually extract a point, but doing so leaves the byte API's semantic protections.

### D5 — Keep secret execution on the established restricted path (R3)

`commitBytes` hashes and reduces in the same offline/isolated boundary as
`PedersenCommitment.commit(s, r)`, then uses that method's two blinded secret schedules.
Do not use public `scalarMul`, `FastJubjubPoint`, MSM, or a secret-indexed lookup table because
the payload is large or because the value is called a hash. Both `s` and `r` can be secret.
The additive multiple-of-`l` scalar blinding inside the arithmetic is separate from commitment
blinding `r`; it must remain fresh even when a caller intentionally recomputes a commitment.

`verifyBytes` is explicitly a **disclosed-opening** operation: it recomputes the mapping and
uses `PedersenCommitment.verify(C, s, r)`. A local integrity check on a private document or
decrypted opening instead uses `commitBytes` and compares the resulting public commitment.
The distinction follows ADR-0055's recipient-side check; new docs must show it.

Generate blindings with existing `randomBlinding(SecureRandom)`: 64 CSPRNG bytes interpreted
big-endian and reduced modulo `l`, statistical distance below `2^-259`. Never derive `r`
from the payload/hash, truncate it to a small width, reuse it across independent commitments,
or replace it with ordinary PRNG output. Sampling can return zero; rejecting it would change
the specified distribution and is not necessary for the scheme. Entropy-source failure
propagates, with no deterministic fallback.

Use operation-owned digest state and buffers. Wipe owned stream buffers, digest outputs and
scalar byte temporaries in `finally`, including I/O and provider failures; never wipe the
caller-owned payload. Do not log contents, hashes, scalars or blindings, or include them in
exception messages. Best-effort cleanup cannot erase immutable `BigInteger`, JCA provider,
JIT or GC copies. No reusable secret-bearing `ThreadLocal`, payload/hash cache or pool is
introduced. Hardened fixed-limb promotion still needs ADR-0039 M9 and a review of the entire
hash/reduction path. #93 does not satisfy those gates.

### D6 — One pass and bounded auxiliary memory (R1, constrained by D2/D5)

The array path feeds the existing array directly to `MessageDigest.update`; it never clones
the payload, builds `msg`, hex/base64-encodes it, converts it to `BigInteger`, or calls a
whole-buffer concatenation helper. A caller must not mutate that array during the synchronous
call. The implementation retains no reference after return; concurrent mutation is outside
the contract. Callers needing snapshot semantics own the snapshot.

The stream overload is required in the initial implementation for large documents:

1. The caller provides a finite stream of exactly `length` octets, within `[0, 2^63-1]`.
   Feed the length prefix before the first payload byte. Read with a reusable **8 KiB** buffer
   initially; buffer size is non-normative and benchmark-tunable, capped at 64 KiB.
2. Track a non-negative `long remaining`, subtracting actual reads. Never cast total length
   to `int`, allocate by total length, or count in an overflowing `int`. Short reads are
   normal. A zero-progress bulk read falls back to a one-byte read rather than a busy loop.
3. Early EOF is an `IOException`. After exactly `length` bytes, probe once for EOF; any
   extra byte is an `IOException`. No commitment or successful result is returned for a
   truncated or longer stream. The probe can consume one extra octet on failure. Callers
   using a multiplexed transport must supply a correctly bounded, finite substream.
4. The library never closes the stream, seeks, reopens a file, calls `available()` to infer
   length, or retries an operation on partially consumed input. This applies on every exit.
   The caller owns deadlines/cancellation and transport limits, including the EOF probe,
   which can block. Do not pass an unbounded live socket directly.
5. Finish `b0`, compute `b1`, reduce and perform the fixed-size curve work only after successful
   complete input consumption. Chunk boundaries never enter the transcript. There is no
   public prehashed bypass or incremental accumulator with ambiguous finalization semantics.

There is one pass over the payload, two SHA-512 invocations (only `b0` processes the payload),
one fixed-size reduction and two scalar multiplications. Auxiliary space is `O(1)` in payload
length: a bounded buffer for streams, constant digest/scalar storage, and existing fixed-size
curve work. This does **not** mean zero allocation: the current curve code allocates
`BigInteger` intermediates, independent of payload length. Array inputs already occupy
caller memory; end-to-end memory measurements must report that separately.

No new native provider, runtime dependency, resource-loading trick or digest-state cloning is
needed. Use Java 25's SHA-512 JCA API; test JVM and GraalVM outputs. New performance work on
curve arithmetic or generator tables requires a separate design if it crosses D5's boundary.

## Exact invariants

| ID | Testable invariant | Decisions |
|---|---|---|
| I1 | Existing numeric/vector outputs, scalar acceptance, encodings, circuits and keys are unchanged; no automatic conversion to note amounts | D1, D3, D4 |
| I2 | Every accepted byte opening uses the exact D2 frame, DST, XMD and modulus; `0 <= s < l`; zero is not retried | D2 |
| I3 | All octets and the exact length are inputs; arrays and all successful stream chunkings give identical results | D1, D2, D6 |
| I4 | New APIs reject noncanonical blindings; the old modular API still accepts its old inputs | D1, D3 |
| I5 | Every imported byte commitment has the exact profile label and canonical subgroup point; identity acceptance never skips opening verification | D3 |
| I6 | `verifyBytes` accepts iff the well-formed disclosed opening satisfies the byte equation; malformed input, I/O or provider failure cannot succeed | D2, D3, D6 |
| I7 | Secret generation uses two fresh blinded schedules and no public multiplication by `s` or `r`; public verification is explicitly distinguished | D5 |
| I8 | No payload, derived scalar or blinding is retained in the commitment; owned scratch is cleaned on all exits, without erasing caller input | D3, D5 |
| I9 | Hashing makes one pass with bounded auxiliary memory; no payload-sized copy, whole-stream buffering, per-chunk curve work or unbounded cache | D6 |
| I10 | Tests and examples reject mismatched authenticated profile/context; none asserts that a raw point proves its profile or that byte arithmetic is integer arithmetic | D4 |

## Compatibility

This is additive. `pedersen-jubjub-v1`, `pedersen-jubjub-vector-v1`, `JubjubMessage`,
EdDSA, circuit public-input order `(u,v)`, fixed-limb candidates and provider selection do
not change. Existing proofs require no new setup, key regeneration, migration or reissuance.
The new profile must not replace a numeric commitment automatically based on input length.

`confidential-note-jubjub-v1` still carries its fixed-format numeric opening. Do not put a
truncated byte hash into its 64-bit amount, change its delivery format, or claim the delivery
encrypts/reconstructs a document. Such a protocol needs another accepted design.

Existing scalar gadgets can constrain an opening of `s`, but **do not prove that `s` was
derived from specific bytes**. No byte-to-scalar circuit, private document predicate, new
Groth16 statement, JuLC validator or Yano-X integration is added by #93. On-chain use of an
existing scalar-opening proof must describe only that scalar relation. #94 owns the broader
verification matrix and serialization contracts, #95 the separate BLS G1 profile, and #96
numeric Bulletproof range proofs. This choice makes no claim of native Cardano SHA-512
availability or efficient on-chain verification of the byte mapping.

## Alternatives considered

| Alternative | Decision and reason |
|---|---|
| Interpret bytes as an integer modulo `l` | Reject: trivial representation/modular aliases; no binding to arbitrary byte strings |
| Plain domain-prefixed SHA-512 modulo `l` | Less expander overhead, but RFC 9380 gives a specified scalar mapping and primitive vectors; retain its exact XMD construction |
| RFC 9380 XMD/SHA-256 | Valid candidate with the same 48-byte output, but two output blocks (`ell=2`) rather than one. SHA-512 is proposed for this Java host profile; actual speed is platform-dependent, so M0 compares both before freezing |
| Poseidon packing/sponge over bytes | Defer: requires its own injective packing, padding, domain and published sponge construction; existing two-field Poseidon helper is not an arbitrary-byte hash specification |
| Sapling Pedersen hash or a vector commitment per byte/chunk | Different construction/semantics, with curve work and potentially tables proportional to payload size; unnecessary for this host byte-opening feature |
| Rejection sampling for the hash-derived scalar | Reject: conflicts with RFC 9380 §5 and introduces data-dependent retries |
| New generators for byte commitments | Could change separation properties, but violates the bounded reuse objective and adds a generator-design review. Keep explicit authenticated semantics under D4 |
| Return a bare `JubjubPoint` or build the #94 generic framework now | A bare point loses semantic type information; a full framework expands scope. Use the small final byte type and explicit pair contract |
| Buffer all bytes, prehash externally, or silently hash chunks independently | Reject: first loses the memory requirement; the others change the committed statement/transcript |
| Promote fixed-limb candidate or use public fast arithmetic for generation | Reject: would bypass existing secret-execution release gates |

## Implementation milestones

No implementation milestone is complete in this ADR PR. Each implementation PR is independently
reviewed; changed cryptographic choices return to design review before coding continues.

| Milestone | Entry gate | Deliverable and exit criteria |
|---|---|---|
| M0 — Freeze specification and vectors | ADR design accepted; Q1–Q3 resolved | Publish and review `docs/specs/pedersen-jubjub-bytes-v1.md` with the exact D2 algorithm, API/errors/stream contract and compatibility. Add an independently authored reference and pinned positive/negative fixtures; verify RFC K.3 first. Benchmark SHA-512 vs SHA-256 to validate the choice before freezing v1; if the evidence warrants a different choice, amend this ADR and re-review the spec before implementation. No production implementation until spec review passes. Covers I1–I6, I10 |
| M1 — Bounded host implementation | Reviewed M0 spec, fixtures and baseline cost records | Add byte type, strict decoder, array and stream methods. Reuse existing generation/verification paths. Pass vectors, stream faults, validation order and schedule instrumentation. Cover I2–I9; do not modify old profile semantics |
| M2 — Regression and resource gates | M1 correctness evidence | Full affected module tests, existing independent numeric/vector/note fixtures, circuit cost/key compatibility, disclosed/private path regression, memory/throughput matrix and GraalVM probe. Differential implementations agree. Covers I1–I10 |
| M3 — Documentation and release review | M2 passes; security limitations reviewed | Raw-byte, string, JSON and document examples; profile authentication and privacy caveats; updated gadget/support matrix and maturity wording. Audit hash/encoding/randomness/side-channel handling; retain external production gates |

## Verification and test-vector strategy

**Independent evidence.** A reference author works from the reviewed specification, RFC and
existing independent Pedersen reference, not the new Java implementation. Use Python
`hashlib` plus independently specified curve arithmetic; record interpreter/hash backend,
reference source revision and generation command. Pin inputs, `n`, DST, frame description,
`b0`, `b1`, 48-byte expander output, canonical scalar (32-byte unsigned big-endian **fixture
notation**), test blinding, affine coordinates, compressed point and expected outcome.
These are public test data, never a recommended opening-storage format. Store large cases
as exact deterministic generation recipes plus expected intermediates/results, not large
checked-in payloads. RFC vectors test the primitive, not the new ZeroJ composition.

Required evidence:

- **Positive:** empty, single zero, leading/trailing zeroes, every byte value, embedded NUL,
  non-UTF8, UTF-8 text, and binary documents; lengths around SHA-512 padding/block and stream
  buffer boundaries; at least a multi-megabyte case. Two fixed full-width blindings per
  selected payload, and fresh CSPRNG-generated blindings with opening checks. Fixed fixture
  blindings are not hiding examples. Check equality across one-byte, irregular, short and
  full-buffer reads. Check literal generator/numeric fixtures separately.
- **Negative:** modified byte/length/blinding/commitment; `r=-1,l,l+1`; nulls; malformed point
  lengths, noncanonical field coordinates/sign bits, off-curve, torsion and mixed-order
  points. Identity must decode but fail an unrelated opening. Mutate DST, domain case,
  length endianness, omitted length, XMD prefix, output length, hash function, output slice,
  unsigned interpretation and modulus (`p` instead of `l`); published expected fixtures must
  catch each mutation.
- **Boundary behavior:** premature EOF, trailing bytes, zero-progress reads, I/O faults at
  every stage, invalid negative length, provider failure, and stream ownership on success and
  failure. Instrument invalid scalar/profile/point paths to confirm no payload read or hash.
  Exercise long counters across `2^31` with a generated stream in the opt-in resource suite;
  use smaller injected boundary tests in ordinary CI. Never allocate a multi-gigabyte array.
- **Secret handling:** operation observers detect the two blinded schedules and any public
  scalar path used for a secret; negative controls must detect an accidental call to `verify`.
  Fault injection checks cleanup and absence of secret diagnostics. Baseline/JVM timing
  measurements remain diagnostics, not constant-time proofs.
- **Semantics:** an explicit example of the scalar/byte equality from D4; wrong trusted
  profile/context rejected by an example consumer; no false claim of mathematical profile
  disjointness. Numeric wraparound behavior and note amount limits remain unchanged.
- **Cross-path:** array/stream, JDK SHA-512/independent hash implementation (BouncyCastle is
  already test-only), JVM/GraalVM, and private-generation/public-verification agreement.
  No claim that blst/WASM tests cover Jubjub; any future Jubjub provider must pass the same
  fixtures and its own secret-operation gates.

Run `./gradlew :zeroj-circuit-lib:test` and affected annotation/integration tests. Preserve
existing circuit row/nonzero pins and compare representative compiled circuit/key fixtures
against the baseline where available; honest witness tests alone do not prove compatibility.
Run the existing Pedersen/note Groth16 and JuLC regressions for the implementation release;
record which Yaci/native-image/opt-in gates were actually exercised. No new on-chain feature
or trusted setup is required for the host byte API.

### Performance and memory gates

Benchmark the same commit/JDK/CPU/provider, with cold initialization separated from steady
state, warmup and multiple forks. Record payload shape, random-source cost, latency distribution,
bytes/s, allocation/op, GC time and peak live heap/RSS. Report separately: hash/reduction,
numeric generation, numeric disclosed verification, decode/subgroup validation, byte generation
and byte verification (both prevalidated and received-point paths). Do not compare a secret
generation path against a faster public path as if they had the same security contract.

Use payloads of 0 B, 32 B, 1 KiB, 8 KiB, 1 MiB, 16 MiB and a generated 256 MiB stream,
plus concurrency 1 and 8 within a fixed worker count. These are proposed workloads, not measured
performance claims. Acceptance requires:

1. Instrumented work matches D6: one payload pass, constant count of curve operations, no
   retries based on the mapped scalar. Validation is not removed to improve timings.
2. A 256 MiB generated stream completes under a 64 MiB Java heap with no external payload
   spool; input generator memory is separately accounted for. The 1/16/256 MiB stream runs
   must show a flat auxiliary-live-memory trend, bounded buffers, and no allocation per
   payload chunk introduced by ZeroJ. Record provider allocation separately; investigate
   growth rather than merely increasing the heap. Check long-counter behavior separately.
3. Array mapping allocates no payload-sized duplicate; no secrets remain in caches or pools.
   Concurrency scales scratch with in-flight operations, not bytes already processed.
4. Publish the overhead relative to staged `hash/reduce + existing numeric operation`, the
   SHA-256/SHA-512 comparison, and regressions of existing numeric operations. Unexplained
   overhead or numeric regressions block release pending investigation. Establish numeric
   latency/throughput tolerances from M0 measurements before M1; this draft invents none.

## Consequences

Applications can commit to exact binary payloads with a constant-size point and bounded
working memory. Existing numeric applications stay compatible. There is no need to grow
generator tables or a circuit with document size just to create/check an off-chain opening.

The new API carries an explicit semantic type and stricter blinding validation. It requires
applications to know the document length and preserve profile/context association. Opening
verification reveals the bytes and blinding to its verifier; private assertions about bytes
require a separately designed proof. The point does not store or recover a document.

### Required examples

- **Raw bytes:** generate `r` using `randomBlinding`, call `commitBytes`, store the exact
  profile/point association, and demonstrate disclosed verification versus private local
  recomputation. Keep `r` and payload out of public logs/metadata.
- **Strings:** explicitly select `StandardCharsets.UTF_8`; compare composed/decomposed Unicode
  to show that visually similar strings can commit differently. No built-in text overload.
- **JSON:** commit exact serialized bytes; whitespace/property-order differences are significant.
  Semantic JSON canonicalization is an application protocol choice requiring its own version,
  not a silent option in this profile.
- **Documents:** open a stable finite source with an explicit byte length and stream it; show
  EOF failure, caller-owned close and limits. File paths/names are not hashed unless the caller
  explicitly includes them in a separately specified application payload. A changing file is
  not a guaranteed snapshot; applications must supply one when necessary.

## Risks and production/audit gates

- Hash framing/domain/reduction errors can create incompatible or ambiguous openings. M0's
  independent intermediate vectors and mutation tests are mandatory.
- Reusing bases makes profile substitution possible at the raw group layer. D4's explicit
  application binding is essential where issuance semantics matter; wrappers are not provenance.
- Small message dictionaries become testable if `r` or the deterministic derived scalar is
  exposed. Neither the byte mapping nor SHA-512 is encryption or a password-hardening function.
- Large inputs and an EOF probe can consume time or block despite bounded memory. Callers
  enforce size/deadline policy; this library does not create network services or async workers.
- `BigInteger`, provider state and JVM behavior retain timing/erasure limits. No exposed
  secret-operation claim, hardened promotion or maturity upgrade follows from this ADR,
  passing tests, benchmark results or successful on-chain regression tests.
- **Production remains gated** on independent cryptographic review of the composition,
  generator assumptions, encoding/profile trust boundary, blinding lifecycle, side channels,
  target JVM/GraalVM deployment and the application's authorization/replay policy. The
  experimental profile is not approved for value-bearing/mainnet use.

## Related findings (out of scope)

`JubjubMessage.hashToField` is deliberately a different public-message mapping; factoring it
into a shared helper would risk changing EdDSA semantics. The existing public numeric
`verify(JubjubPoint, ...)` does not itself call the strict serialized commitment decoder;
do not copy that boundary into the new typed API or silently change the old method here.
ADR-0051 D7 and ADR-0039 M9 retain their separate unresolved/release gates.

## Open questions for design acceptance

These are proposed choices, not hidden implementation discretion. They need resolution before
M0 freezes the profile; no blocking disagreement between fetched references was found.

- **Q1 — Hash selection.** Accept D2's RFC 9380 XMD/SHA-512 with M0 performance validation,
  or require the candidate comparison before accepting a hash choice? Lean: SHA-512 for one XMD output block, Java availability and
  a bounded-memory host implementation. Do not decide from presumed Cardano support or
  unmeasured speed. Changing the decision before publication updates the DST and fixtures;
  changing it after the profile freezes requires a new version.
- **Q2 — Minimal typed surface.** Accept D3's final byte-specific type and `(profile, point)`
  boundary, or move these methods to a separate `PedersenBytes` facade? Lean: additive methods
  on the current facade with a separate returned type, keeping #94's general interfaces open.
  The return type's validation and D4's limitations are required under either naming choice.
- **Q3 — Streaming in phase 1.** Accept the explicit-length, EOF-checked overload in M1, or
  defer it and limit the first release to in-memory arrays? Lean: include it; otherwise the
  large-document memory objective is not met. EOF/ownership/error semantics must not be left
  to implementation guesswork.

## Evidence for this design-only PR

At baseline `43c7b32e96fd231eca8b26abbb63c7bc002090b9`, Java 25.0.2:

```bash
./gradlew :zeroj-circuit-lib:test --tests '*Pedersen*Test' \
  --tests '*ConfidentialNote*Test' --tests '*NoteScheduleTest' --console=plain
```

**Passed: 243 tests, 18 suites, zero failures/errors/skips.** This is baseline compatibility
evidence, not tests of an unimplemented byte API.
A scratch Python `hashlib` check reproduced RFC 9380 K.3's empty-message/32-byte-output vector
and checked `bitLength(l)=252`, `L=48`, DST bytes/length and the stated reduction bound. That
sanity check is not the independent profile reference required by M0. No byte-profile
benchmark, new circuit, native-image run or on-chain test was claimed for this documentation PR.

## Revision history

- **r1 (2026-10-15):** Initial proposal for #93: audited API and compatibility boundaries,
  exact RFC 9380 mapping, typed validation, restricted secret path, one-pass stream contract,
  independent evidence plan, and performance/memory release gates.
