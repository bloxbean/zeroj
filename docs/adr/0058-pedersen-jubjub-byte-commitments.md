# ADR-0058: Arbitrary-byte commitments over the existing Jubjub Pedersen profile

## Status

**Accepted — design (2026-10-16); implementation in progress (M0–M3).** Addresses
[issue #93](https://github.com/bloxbean/zeroj/issues/93), phase 1 of #93–#96. The design was
approved in review at `b4e8c2c2a6db3dfadf288c1305a7fbcb5449438e` and the maintainer resolved
Q1–Q3 as recorded below. Acceptance authorizes the milestones below; it is not a security
certification. Each milestone is reviewed in the same PR before the next begins.

**Risk: R3** for the byte-to-scalar mapping and secret-bearing execution; **R2** for API,
validation, serialization boundaries and compatibility. Correctness and security invariants
take precedence over performance. Performance and bounded memory are implementation gates,
not optional follow-ups. Existing experimental/offline restrictions remain in force.

## Date

2026-10-15 (initial proposal); 2026-10-16 (r4: accepted, Q1–Q3 decided)

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
  the RFC 9380/SHA-256 assumptions; a correctly seeded CSPRNG; the JDK's implementations;
  and an offline/isolated boundary for the **whole** secret operation, including hashing and
  reduction. No constant-time claim is inherited from an algorithm specification.
- **Application obligations:** authenticate the expected profile and original issuance context
  when they matter, bound accepted input sizes and execution time, preserve the exact bytes,
  and store/deliver the opening securely. Commitments do not provide encryption, document
  availability, authorization, provenance, replay prevention or `ScriptContext` binding.

Binding to bytes rests on both computational Pedersen binding and collision resistance of the
**reduced** hash-to-scalar map. A collision in that map gives two byte openings with the same
blinding. The approximately 252-bit group/scalar space limits generic security to about
126 bits; SHA-256 and a 128-bit statistical mapping parameter do not turn Jubjub into a
256-bit- or exact 128-bit-security system. Ideal uniform, independent `r` gives perfect
hiding of the point; the existing wide-reduction sampler gives statistically close hiding.
Neither statement covers timing leakage, exposed hashes, reused blindings or application
metadata such as document length.

## Pinned normative references

1. **RFC 9380, August 2023**, [§§3.1, 4, 5, 5.2, 5.3.1, 10.3, 10.5–10.7 and Appendix K.1](https://www.rfc-editor.org/rfc/rfc9380.html).
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
5. **FIPS 180-4, August 2015**, [§§5.1.1 and 6.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf),
   for SHA-256 and its input-length bound below `2^64` bits. The protocol maximum below
   includes the XMD framing overhead, not just payload length.

Additional implementation evidence, not new cryptographic specifications:

- ZeroJ at the audit commit: `Bls12381Hash.expandMessageXmdSha256` in `zeroj-bls12381`,
  `CfrgBbsCore.hashToScalar` in `zeroj-bbs`, and `BbsHashToScalar` / `BbsHashToScalarVmTest`
  in `zeroj-onchain-julc`. These use XMD/SHA-256 with a 48-byte expansion for BBS. Their
  **BLS scalar modulus is not `l`**; D2 specifies how to cross-check without confusing them.
- Plutus [`DefaultFun` and `Sha2_256` implementation at `f1c00c06816a7bc44b9ab03fdb88e44cdffc201c`](https://github.com/IntersectMBO/plutus/blob/f1c00c06816a7bc44b9ab03fdb88e44cdffc201c/plutus-core/plutus-core/src/PlutusCore/Default/Builtins.hs):
  supplies `sha2_256`, with no `sha2_512` builtin in that list. The existing Julc BBS path
  demonstrates use of the SHA-256 builtin; this does not establish a byte-profile cost budget.

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
`expand_message_xmd` (§5.3.1) using **SHA-256** (decided under Q1).

```text
l   = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
DST = ASCII("ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-256")
MAX_PAYLOAD_BYTES = 2^61 - 256
n   = number of octets in B, 0 <= n <= MAX_PAYLOAD_BYTES
msg = B || I2OSP(n, 8)
L   = ceil((ceil(log2(l)) + 128) / 8) = 48
u   = expand_message_xmd_SHA256(msg, DST, 48)
s   = OS2IP(u) mod l
```

`I2OSP`/`OS2IP` are unsigned **big-endian** per RFC 9380 §4. `||` means concatenation of
octets. The eight-byte length is a suffix: arrays use their length; streams count the bytes
actually read and append that count at EOF. No terminator is added. A declared length is an
additional integrity check, never a substitute for the actual count.
`DST` is exactly 46 bytes (no newline/NUL):

```text
5a65726f4a2d706564657273656e2d6a75626a75622d62797465732d76312d4832532d584d443a5348412d323536
```

For clarity, the exact specialization of XMD is:

```text
DST_prime = DST || 0x2e
b0 = SHA-256( zero_octets(64) || B || I2OSP(n,8) || 0x0030 || 0x00 || DST_prime )
b1 = SHA-256( b0 || 0x01 || DST_prime )
b2 = SHA-256( (b0 XOR b1) || 0x02 || DST_prime )
u  = b1 || first 16 octets of b2
s  = OS2IP(u) mod l
```

Here `0x0030` is two octets; `0x00`, `0x01`, `0x02`, `0x2e` are one each. XOR operates on
the two 32-byte strings. SHA-256's output/block sizes are 32/64 bytes, so `ell = 2`.
Preserve the 64-zero-byte prefix; do not substitute a plain SHA-256 digest.
RFC Appendix K.1 tests XMD itself with its own DST
and output lengths; those are not the ZeroJ profile parameters.

Reduction is once, modulo `l`, with a fixed 48-byte input. No rejection sampling, clamping,
modulo-`p` reduction, sign interpretation, or retry when `s = 0`. Zero is a valid scalar.
Under the uniform-expander model, the conservative reduction-distance bound is
`l / 2^384 < 2^-132`, smaller than the RFC's `2^-128` target. This is a statistical bound,
not a statement of collision resistance or implementation timing.

Length framing is injective before hashing: remove the fixed XMD suffix, then the final
eight octets identify `n` and all preceding `msg` octets are `B`. Prefix framing offers no
extra binding here. This does not make the finite scalar mapping injective. Suffix framing
lets unknown-length streams be hashed and counted in one pass with bounded memory; arrays,
declared-length streams and bounded read-to-EOF streams use exactly the same mapping.

`b0`'s input has `n + 122` octets: 64 zeroes, `n` payload octets, 8 length octets,
3 length/counter octets, and 47 `DST_prime` octets. Thus `n <= 2^61 - 256` ensures
`n + 122 < 2^61`, within SHA-256's strict bit-length bound. Reject excessive declared lengths
or caller limits before reading; enforce the same cap while counting unknown-length input.
The cap also avoids the reviewed JDK SHA-512 implementation's low-64-bit length limitation
if SHA-512 is reconsidered; the bound is normative, not an estimate of feasible file sizes.

**Selection rationale (F2).** Both hashes satisfy RFC 9380's `b >= 2k`; both are standard
Java digests and allow bounded memory. SHA-256 is recommended because the local bulk probe
favours it, Plutus provides its builtin, and existing off-chain/on-chain XMD/SHA-256 paths
provide useful differential evidence. The small fixed cost of SHA-256's second output block
is not a deciding factor; payload throughput and the existing curve work matter more.
Against this choice, the current gadget library has `hash/Sha512` but no SHA-256 gadget,
so a future byte-to-scalar circuit would need new work. That future circuit is outside #93.
M0 must compare x86-64 with/without SHA acceleration, aarch64 and GraalVM native image;
the local result does not predict those results. SHA-256 preserves a native-hash option
for future disclosed-byte checks on Cardano, not a claim of feasible cost or implementation.

**Reuse boundary.** Keep a bounded, profile-local streaming XMD implementation in
`zeroj-circuit-lib` for this milestone. The existing `Bls12381Hash` expander constructs a
payload-sized concatenation for `b0`, so reusing it as-is would violate D6. Use it as a
test oracle for the 48 **pre-reduction bytes** on bounded fixtures with the identical frame
and DST. Do not reuse `CfrgBbsCore.hashToScalar` or `BbsHashToScalar` as the Jubjub scalar
mapper: they reduce modulo the BLS order. Keep BBS production code/modulus/DST unchanged;
no BBS runtime dependency or shared-helper refactor is required. Cross-check the existing
BBS reductions separately modulo their own order and use independent reference arithmetic
for the final reduction modulo `l`.

### D3 — Add typed entry points and explicit validation (R2)

Proposed signatures, illustrative until M0's API contract is reviewed:

```java
// Additive static methods on PedersenCommitment; original methods remain unchanged.
PedersenBytesCommitment commitBytes(byte[] payload, BigInteger blinding);
PedersenBytesCommitment commitBytes(InputStream payload, long length, BigInteger blinding)
        throws IOException;
PedersenBytesCommitment commitBytesToEnd(InputStream payload, long maxBytes,
                                        BigInteger blinding) throws IOException;
boolean verifyBytes(PedersenBytesCommitment commitment, byte[] payload, BigInteger blinding);
boolean verifyBytes(PedersenBytesCommitment commitment, InputStream payload,
                    long length, BigInteger blinding) throws IOException;
boolean verifyBytesToEnd(PedersenBytesCommitment commitment, InputStream payload,
                         long maxBytes, BigInteger blinding) throws IOException;

// New immutable, profile-specific value. No opening or payload retained.
public static final String PROFILE_ID = "pedersen-jubjub-bytes-v1";
PedersenBytesCommitment decode(byte[] pointBytes);
String profileId();
byte[] toPointBytes();
```

The constant and final three signatures are on `PedersenBytesCommitment` (`decode` is static).
The `ToEnd` names distinguish a maximum from an exact declared length; neither meaning is
selected implicitly from a `long` value. Instances have no public raw-point constructor and
no numeric-balance, addition or subtraction methods.
They hold a normalized validated point and a fixed profile identity; encoding returns a fresh
32-byte array. They never retain `B`, `s`, `r` or a digest object. Equality is point equality
within this final profile-specific type, not equality with a naked `JubjubPoint`.

- New methods require `0 <= r < l`; reject negative `r`, `l`, `l+1` and larger values
  rather than normalize them. `r = 0` remains algebraically valid (including tests), but
  caller-chosen zero/predictable blindings provide no hiding. Runtime range validation cannot
  establish entropy. Numeric `commit`/`verify` keep their existing modular acceptance.
- Null arguments throw `NullPointerException`. Invalid declared length, maximum, encoding or scalar
  throws `IllegalArgumentException`. A well-formed opening that does not match returns
  `false`. I/O failures propagate as `IOException`; provider unavailability is a platform
  failure (`IllegalStateException`), never a successful verification or a fallback hash.
  Applications translate these explicit failures into rejection at their external boundary.
- `decode` calls `PedersenCommitment.decode`; the profile is fixed by this type, not selected
  by an untrusted string. Reject wrong lengths,
  `v >= p`, non-square recovery, ZIP 216 aliases, small-order non-identity and mixed-order
  points. Do not cofactor-clear an attacker-supplied point to make it acceptable.
- Identity remains a valid encoded commitment; accepting the point does not accept an
  opening. Both verification methods must still check their equation. In particular, empty bytes with zero
  blinding are not defined to be the identity.
- Validate nulls, declared lengths/limits and scalar range before hashing or reading a payload.
  Received points are validated when the typed object is created, once per object; subsequent
  checks can reuse that invariant. No global cache of attacker-supplied points is introduced.

The wire format in this phase is exactly the **32-byte point** from the numeric spec §4.
The profile is fixed by the enclosing protocol's trusted configuration, which must select
this byte type explicitly. No profile string is serialized by this API; `PROFILE_ID` and
`profileId()` are metadata for configuration/documentation, not proof of provenance.
`toPointBytes()` is a raw point encoding, not a self-describing commitment envelope. #94
decides the generic envelope, opening codecs and verification-result interfaces; this ADR
reserves no binary tag or cross-curve encoding. An application transmitting profile metadata
must separately define its encoding and authentication. `r` is an integer API input here,
not a new scalar wire format.

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

Profile tests must demonstrate both facts: an example consumer rejects an authenticated
record whose profile disagrees with its trusted expected byte profile, and the bare numeric
equation for `s = HashBytesToScalar(B)` can still pass. The decoder alone cannot distinguish
their identical point bytes. Do not write a test asserting that all numeric openings for byte
commitments are impossible or that decoding a point authenticates a profile label.

For byte commitments, homomorphic addition only relates the derived **scalars modulo `l`**.
It is not document concatenation, JSON merge, integer addition on the source bytes or a useful
range statement about the document. The typed API exposes no such arithmetic. Anyone can
manually extract a point, but doing so leaves the byte API's semantic protections.

### D5 — Keep secret execution on the established restricted path (R3)

`commitBytes` and `commitBytesToEnd` hash and reduce in the same offline/isolated boundary as
`PedersenCommitment.commit(s, r)`, then use that method's two blinded secret schedules.
Do not use public `scalarMul`, `FastJubjubPoint`, MSM, or a secret-indexed lookup table because
the payload is large or because the value is called a hash. Both `s` and `r` can be secret.
The additive multiple-of-`l` scalar blinding inside the arithmetic is separate from commitment
blinding `r`; it must remain fresh even when a caller intentionally recomputes a commitment.

`verifyBytes` and `verifyBytesToEnd` are explicitly **disclosed-opening** operations: they
recompute the mapping and use `PedersenCommitment.verify(C, s, r)`. A local integrity check
on a private document or decrypted opening instead uses `commitBytes` or `commitBytesToEnd`
and compares the resulting public commitment.
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

Both stream variants are required in the initial implementation for large documents:

1. A declared-length stream must contain exactly `length` octets. A `ToEnd` stream has no
   declared length and is read to EOF, with mandatory caller limit `maxBytes`. Require
   `0 <= length <= MAX_PAYLOAD_BYTES`, or `0 <= maxBytes <= MAX_PAYLOAD_BYTES`, respectively;
   otherwise throw `IllegalArgumentException` before any read. Applications normally choose
   a much smaller maximum. Both paths count actual payload octets while feeding them to
   `b0`; append `I2OSP(actualCount,8)` only after EOF and successful integrity/limit checks.
2. Read with a reusable **8 KiB** buffer initially; size is non-normative and tunable, capped
   at 64 KiB. Keep a non-negative `long remaining` budget and actual count. Bound each read
   to that remaining budget before adding/subtracting counts, so neither addition nor the
   normative cap can overflow. Never cast total length to `int` or allocate by total length.
   Short reads are normal. A zero-progress bulk read falls back to a one-byte read rather
   than a busy loop, under the same budget checks.
3. EOF before a declared `length` is an `IOException`; EOF below `maxBytes` is valid for
   `ToEnd`. At the exact length/limit, probe once for EOF; an extra octet is an `IOException`
   and is not hashed. Read at most `length+1` or `maxBytes+1` octets, respectively. No success
   is returned for truncation when a length was declared, or for input beyond either bound.
   Suffix framing removes the need for counting passes/spooling unknown-length sources,
   **not** the need to observe EOF or detect an extra byte. Such detection can consume one
   extra octet on failure. Multiplexed transports must supply a correctly bounded substream.
4. The library never closes the stream, seeks, reopens a file, calls `available()` to infer
   length, or retries an operation on partially consumed input. This applies on every exit.
   The caller owns deadlines/cancellation and transport limits, including the EOF probe,
   which can block. Do not pass an unbounded live socket directly.
5. Finish `b0`, compute `b1` and `b2`, reduce and perform the fixed-size curve work only after
   successful complete input consumption. Chunk boundaries never enter the transcript. There is no
   public prehashed bypass or incremental accumulator with ambiguous finalization semantics.

There is one pass over the payload, three SHA-256 invocations (only `b0` processes the payload),
one fixed-size reduction and two scalar multiplications. Auxiliary space is `O(1)` in payload
length: a bounded buffer for streams, constant digest/scalar storage, and existing fixed-size
curve work. This does **not** mean zero allocation: the current curve code allocates
`BigInteger` intermediates, independent of payload length. Array inputs already occupy
caller memory; end-to-end memory measurements must report that separately.

No new native provider, runtime dependency, resource-loading trick or digest-state cloning is
needed. Use Java 25's SHA-256 JCA API; test JVM and GraalVM outputs. New performance work on
curve arithmetic or generator tables requires a separate design if it crosses D5's boundary.

## Exact invariants

| ID | Testable invariant | Decisions |
|---|---|---|
| I1 | Existing numeric/vector outputs, scalar acceptance, encodings, circuits and keys are unchanged; no automatic conversion to note amounts | D1, D3, D4 |
| I2 | Every accepted byte opening uses the exact D2 suffix frame, DST, XMD and modulus; `0 <= s < l`; zero is not retried | D2 |
| I3 | All octets and their actual count are inputs; arrays, declared-length streams and bounded read-to-EOF streams agree for every successful chunking. Excess declared lengths/limits are refused before reading; actual input cannot exceed its bound or `MAX_PAYLOAD_BYTES` | D1, D2, D6 |
| I4 | New APIs reject noncanonical blindings; the old modular API still accepts its old inputs | D1, D3 |
| I5 | Every imported byte commitment is decoded by the profile-specific type as a canonical subgroup point; no caller label selects the algorithm. Identity acceptance never skips opening verification; decoding does not authenticate issuance semantics | D3, D4 |
| I6 | `verifyBytes` and `verifyBytesToEnd` accept iff the well-formed disclosed opening satisfies the byte equation; malformed input, I/O or provider failure cannot succeed | D2, D3, D6 |
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
numeric Bulletproof range proofs. SHA-256 preserves a native-hash option for future Cardano
byte checks; this phase claims neither an on-chain implementation nor a feasible cost budget.

## Alternatives considered

| Alternative | Decision and reason |
|---|---|
| Interpret bytes as an integer modulo `l` | Reject: trivial representation/modular aliases; no binding to arbitrary byte strings |
| Plain domain-prefixed digest modulo `l` | Less expander overhead, but RFC 9380 gives a specified scalar mapping and primitive vectors; retain its exact XMD construction |
| RFC 9380 XMD/SHA-512 (r1 recommendation, replaced in r2) | Equally suitable cryptographically and has an existing SHA-512 circuit gadget, but lacks a Plutus SHA-512 builtin and is slower in the local bulk probe. Not selected under Q1; it remains the measured comparison in the platform matrix. XMD output-block count is not the deciding metric |
| Length prefix (r1 proposal, replaced in r2) | Equally injective, but requires a prior count or spool for unknown-length sources. There is no existing byte-profile wire compatibility to preserve and no extra binding benefit. Choose an eight-byte suffix so generated/compressed/pipe input needs one bounded-memory pass |
| Poseidon packing/sponge over bytes | Defer: requires its own injective packing, padding, domain and published sponge construction; existing two-field Poseidon helper is not an arbitrary-byte hash specification |
| Sapling Pedersen hash or a vector commitment per byte/chunk | Different construction/semantics, with curve work and potentially tables proportional to payload size; unnecessary for this host byte-opening feature |
| Rejection sampling for the hash-derived scalar | Reject: conflicts with RFC 9380 §5 and introduces data-dependent retries |
| New generators for byte commitments | Could change separation properties, but violates the bounded reuse objective and adds a generator-design review. Keep explicit authenticated semantics under D4 |
| Return a bare `JubjubPoint` or build the #94 generic framework now | A bare point loses semantic type information; a full framework expands scope. Use the small final byte type, raw point wire format and trusted enclosing-protocol selection |
| Free-string profile argument or an unspecified `(ID, point)` envelope | Reject: redundant for a final profile-specific type and not an interoperable encoding. The type fixes the profile; generic encoded IDs remain #94's responsibility |
| Buffer all bytes, prehash externally, or silently hash chunks independently | Reject: first loses the memory requirement; the others change the committed statement/transcript |
| Promote fixed-limb candidate or use public fast arithmetic for generation | Reject: would bypass existing secret-execution release gates |

## Implementation milestones

No implementation milestone is complete in this ADR PR. Each implementation PR is independently
reviewed; changed cryptographic choices return to design review before coding continues.

| Milestone | Entry gate | Deliverable and exit criteria |
|---|---|---|
| M0 — Freeze specification and vectors | ADR design accepted; Q1–Q3 resolved (done in r4) | Publish and review `docs/specs/pedersen-jubjub-bytes-v1.md` with the exact D2 suffix frame, SHA-256 mapping, length cap, API/errors/stream contracts and compatibility. Add an independently authored reference and pinned positive/negative fixtures; verify RFC K.1 first and compare the existing XMD expander before reduction. Benchmark SHA-256 vs SHA-512 on every available platform of the target matrix and record unavailable platforms as open release evidence; if the evidence contradicts the Q1 decision, amend this ADR and re-review the spec before implementation. No production implementation until spec review passes. Covers I1–I6, I10 |
| M1 — Bounded host implementation | Reviewed M0 spec, fixtures and baseline cost records | Add byte type, strict decoder, array, declared-length and bounded read-to-EOF methods. Reuse existing generation/verification paths. Pass vectors, stream faults, cap/counter boundaries, validation order and schedule instrumentation. Cover I2–I9; do not modify old profile semantics |
| M2 — Regression and resource gates | M1 correctness evidence | Full affected module tests, existing independent numeric/vector/note fixtures, circuit cost/key compatibility, disclosed/private path regression, memory/throughput matrix and GraalVM probe. Differential implementations agree. Covers I1–I10 |
| M3 — Documentation and release review | M2 passes; security limitations reviewed | Raw-byte, string, JSON and document examples; profile authentication and privacy caveats; updated gadget/support matrix and maturity wording. Audit hash/encoding/randomness/side-channel handling; retain external production gates |

## Verification and test-vector strategy

**Independent evidence.** A reference author works from the reviewed specification, RFC and
existing independent Pedersen reference, not the new Java implementation. Use Python
`hashlib` plus independently specified curve arithmetic; record interpreter/hash backend,
reference source revision and generation command. Pin inputs, `n`, DST, frame description,
`b0`, `b1`, `b2`, 48-byte expander output, canonical scalar (32-byte unsigned big-endian **fixture
notation**), test blinding, affine coordinates, compressed point and expected outcome.
These are public test data, never a recommended opening-storage format. Store large cases
as exact deterministic generation recipes plus expected intermediates/results, not large
checked-in payloads. RFC vectors test the primitive, not the new ZeroJ composition.

Required evidence:

- **Positive:** empty, single zero, leading/trailing zeroes, every byte value, embedded NUL,
  non-UTF8, UTF-8 text, and binary documents; lengths around SHA-256 padding/block and stream
  buffer boundaries; at least a multi-megabyte case. Two fixed full-width blindings per
  selected payload, and fresh CSPRNG-generated blindings with opening checks. Fixed fixture
  blindings are not hiding examples. Check equality across one-byte, irregular, short and
  full-buffer reads across arrays and both stream modes, including unknown-length generated
  output. Check literal generator/numeric fixtures separately.
- **Negative:** modified byte/length/blinding/commitment; `r=-1,l,l+1`; nulls; malformed point
  lengths, noncanonical field coordinates/sign bits, off-curve, torsion and mixed-order
  points. Identity must decode but fail an unrelated opening. Mutate DST, domain case,
  length endianness/placement, omitted length, XMD prefix, output length, hash function,
  missing XOR/counter/second block, output slice,
  unsigned interpretation and modulus (`p` instead of `l`); published expected fixtures must
  catch each mutation.
- **Boundary behavior:** premature EOF with declared length, valid EOF below a `ToEnd` limit,
  exact limit plus EOF, excess bytes in both modes, zero-progress reads, I/O faults at every
  stage, invalid negative length/limit, provider failure, and stream ownership on every exit.
  Test `MAX_PAYLOAD_BYTES` and `MAX_PAYLOAD_BYTES+1` through injected counter/length seams
  without exabyte I/O, including the extra-octet check at the cap and no overflow. Instrument
  invalid scalar/point/length/limit and wrong authenticated-context paths to confirm no payload
  read or hash (context rejection belongs to the example consumer, not the decoder).
  Exercise long counters across `2^31` with a generated stream in the opt-in resource suite;
  use smaller injected boundary tests in ordinary CI. Never allocate a multi-gigabyte array.
- **Secret handling:** operation observers detect the two blinded schedules and any public
  scalar path used for a secret; negative controls must detect an accidental call to `verify`.
  Fault injection checks cleanup and absence of secret diagnostics. Baseline/JVM timing
  measurements remain diagnostics, not constant-time proofs.
- **Semantics:** an explicit example of the scalar/byte equality from D4; wrong trusted
  profile/context rejected by an example consumer; no false claim of mathematical profile
  disjointness. Numeric wraparound behavior and note amount limits remain unchanged.
- **Cross-path:** array/both stream modes, JDK SHA-256/independent hash implementation
  (BouncyCastle is already test-only), JVM/GraalVM, and private-generation/public-verification agreement.
  Use `Bls12381Hash.expandMessageXmdSha256(frame, DST, 48)` on bounded fixtures as an existing
  implementation oracle for `u`, then compare `OS2IP(u) mod l` with the independent Jubjub
  reference. Also retain `BbsHashToScalarVmTest` as evidence that the existing BBS host/Julc
  mapping agrees modulo the **BLS** order; do not compare its reduced result directly with
  the new Jubjub result or claim it tests a new on-chain Jubjub implementation.
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

Use payloads of 0 B, 32 B, 1 KiB, 8 KiB, 1 MiB, 16 MiB and a generated 256 MiB stream in
both declared-length and read-to-EOF modes, plus concurrency 1 and 8 within a fixed worker
count. These are proposed workloads, not measured
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
   SHA-256/SHA-512 comparison on x86-64 with/without SHA acceleration, aarch64 and GraalVM
   native image (record exact provider/hardware flags; identify any unavailable platform),
   and regressions of existing numeric operations. Unexplained
   overhead or numeric regressions block release pending investigation. Establish numeric
   latency/throughput tolerances from M0 measurements before M1; this draft invents none.

## Consequences

Applications can commit to exact binary payloads with a constant-size point and bounded
working memory. Existing numeric applications stay compatible. There is no need to grow
generator tables or a circuit with document size just to create/check an off-chain opening.

The new API carries an explicit semantic type and stricter blinding validation. Applications
can provide an exact length or a maximum for a finite unknown-length stream, and must preserve
profile/context association. Opening verification reveals the bytes and blinding to its
verifier; private assertions about bytes
require a separately designed proof. The point does not store or recover a document.

### Required examples

- **Raw bytes:** generate `r` using `randomBlinding`, call `commitBytes`, store the exact
  point with its authenticated application context, and demonstrate disclosed verification versus private local
  recomputation. Keep `r` and payload out of public logs/metadata.
- **Strings:** explicitly select `StandardCharsets.UTF_8`; compare composed/decomposed Unicode
  to show that visually similar strings can commit differently. No built-in text overload.
- **JSON:** commit exact serialized bytes; whitespace/property-order differences are significant.
  Semantic JSON canonicalization is an application protocol choice requiring its own version,
  not a silent option in this profile.
- **Documents:** stream a stable finite source with an exact byte length, or stream generated
  output to EOF with an explicit maximum; show both modes produce the same commitment for
  the same bytes. Demonstrate declared-length truncation, excess input, caller-owned close
  and limits. File paths/names are not hashed unless the caller
  explicitly includes them in a separately specified application payload. A changing file is
  not a guaranteed snapshot; applications must supply one when necessary.

## Risks and production/audit gates

- Hash framing/domain/reduction errors can create incompatible or ambiguous openings. M0's
  independent intermediate vectors and mutation tests are mandatory.
- Reusing bases makes profile substitution possible at the raw group layer. D4's explicit
  application binding is essential where issuance semantics matter; wrappers are not provenance.
- Small message dictionaries become testable if `r` or the deterministic derived scalar is
  exposed. Neither the byte mapping nor SHA-256 is encryption or a password-hardening function.
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

## Design questions — decided (r4, 2026-10-16)

These were open at design approval (`b4e8c2c`). The maintainer resolved them as follows before
M0; the options considered are retained for the record.

- **Q1 — Hash selection. Decided: RFC 9380 XMD/SHA-256** (D2 as written). Alternative was
  SHA-512, retained for its existing circuit gadget at the cost of native on-chain availability
  and measured host throughput. Reasons: measured local bulk throughput, the verified Plutus
  `sha2_256` builtin, and existing XMD/SHA-256 differential oracles. SHA-512's circuit gadget
  remains a real advantage for future byte-to-scalar circuits, which are outside #93. The
  platform comparison stays a recorded gate: M0/M2 measure every available platform and record
  unavailable ones (for example x86-64 with/without SHA extensions) as open release evidence;
  contradicting evidence returns the profile to design review before publication. After the
  profile freezes, changing the hash requires a new profile version.
- **Q2 — Minimal typed surface. Decided: additive static methods on `PedersenCommitment`**
  returning the final `PedersenBytesCommitment` with the raw 32-byte point encoding and trusted
  protocol selection (D3). Alternative was a separate `PedersenBytes` facade. #94's general
  interfaces stay open. The return type's validation and D4's limitations apply unchanged.
- **Q3 — Streaming in phase 1. Decided: ship both** the declared-length and the bounded
  read-to-EOF variants with suffix framing in M1 (D6). Alternative was arrays only, which
  would not meet the large-document memory objective. EOF, ownership and error semantics are
  fixed by D6 and the M0 specification, not left to implementation.

## Evidence for this design-only PR

At baseline `43c7b32e96fd231eca8b26abbb63c7bc002090b9`, Java 25.0.2:

```bash
./gradlew :zeroj-circuit-lib:test --tests '*Pedersen*Test' \
  --tests '*ConfidentialNote*Test' --tests '*NoteScheduleTest' --console=plain
```

**Passed: 243 tests, 18 suites, zero failures/errors/skips.** This is baseline compatibility
evidence, not tests of an unimplemented byte API.
For **r1**, a scratch Python `hashlib` check reproduced RFC 9380 K.3's SHA-512
empty-message/32-byte-output vector and checked `bitLength(l)=252`, `L=48`, the then-proposed
DST bytes/length and the stated reduction bound. That framing/hash recommendation is replaced
in r2.

For **r2**, scratch checks against the same source baseline established:

- RFC 9380 K.1 SHA-256 empty/`abc` 32-byte vectors reproduced with Python `hashlib`.
  A Java probe invoked `Bls12381Hash.expandMessageXmdSha256(frame, DST, 48)` using D2's new
  suffix frame and domain. Its pre-reduction outputs matched the Python implementation
  for payload lengths 0, 1, 256 and 8193, with `payload[i] = (131*i + 17) mod 256`.
  Streaming updates of 1, 7, 64 and 8192 bytes matched the one-shot reference in all 16 cases.
  DST ASCII/hex/46-byte length and `MAX_PAYLOAD_BYTES + 122 < 2^61` checked.
- A standalone Java `MessageDigest` probe (recipe below)
  measured SHA-256 at **3182 MiB/s median** (3174–3188) and SHA-512 at **1784 MiB/s median**
  (1777–1795) on Apple M4 Max, BellSoft JDK `25.0.2+12-LTS`, aarch64, SUN provider 25.
  Recipe: one reused 8192-byte buffer (`buffer[i] = (byte)i`); four 64 MiB warmup passes
  per algorithm; five 256 MiB timed passes per algorithm in alternating order; update plus
  digest timed, result consumed through a volatile sink. One JVM fork, no payload allocation
  per pass. These are local primitive-throughput observations, **not** complete profile
  benchmarks or platform qualification. M0 requires multiple forks and the wider matrix.
- Read the local JDK `java.base/sun/security/provider/SHA5.java` in `lib/src.zip`:
  `implDigest` uses `bytesProcessed << 3` and writes only the low 64 length bits.
  FIPS 180-4 independently supplies SHA-256's strict length limit. D2's cap satisfies both.
- Inspected the existing BBS host/Julc SHA-256 paths, their modulus and differential tests,
  the SHA-512-only gadget availability, and the pinned Plutus builtin list. Existing BBS
  tests are code evidence here; no new Julc execution was performed for r2.

These author sanity checks are not the independently authored profile reference required by
M0. No byte API, new circuit, native-image run or new on-chain execution is claimed by this
documentation PR. The scratch files are outside the repository; the PR remains ADR-only.

## Revision history

- **r1 (2026-10-15):** Initial proposal for #93: audited API and compatibility boundaries,
  exact RFC 9380 mapping, typed validation, restricted secret path, one-pass stream contract,
  independent evidence plan, and performance/memory release gates.
- **r2 (2026-10-16; responds to review of `7b2a9fb3cd7d71f922e96ef77f8b137da98c3732`):**
  F1 → suffix framing and bounded read-to-EOF methods alongside strict declared-length
  methods (D2/D3/D6, I2/I3, M0/M1 and tests); F2 → SHA-256 recommendation based on measured
  local throughput, Plutus availability and existing XMD differential oracles, with the
  SHA-512 circuit advantage and platform gates retained (D2, alternatives, Q1 and tests);
  F3 → final-type profile constant, `decode(byte[])` and exact raw-point wire contract with
  trusted external context (D3/D4, I5, Q2 and tests); F4 → normative `2^61 - 256` payload cap,
  explicit XMD-overhead arithmetic and injected boundary tests (D2/D6, I3 and M0/M1).
- **r3 (2026-10-16; responds to review of `fee20ead2cc1748ba9f7d8036cc6b2e9993db19e`):**
  F5 → removed the local scratch-probe path while retaining the measurement recipe and
  corrected the subject/verb agreement in D5. No design or implementation change; Q1–Q3
  remain open for maintainer decision.
- **r4 (2026-10-16):** Design approved at `b4e8c2c`. Status → Accepted (design). Maintainer
  decisions recorded: Q1 XMD/SHA-256, Q2 additive methods on `PedersenCommitment` with the
  final byte type, Q3 both stream modes in phase 1. M0 entry gate updated; unavailable
  benchmark platforms are recorded as open release evidence rather than silently skipped.
  No change to D1–D6, invariants or the profile bytes.
