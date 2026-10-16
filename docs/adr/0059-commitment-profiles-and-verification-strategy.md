# ADR-0059: Commitment profiles, typed contracts and verification matrix

## Status

**Proposed** — design only. Addresses [issue #94](https://github.com/bloxbean/zeroj/issues/94),
phase 2 of the #93–#96 Pedersen roadmap. Stacked on PR #97 (ADR-0058,
`pedersen-jubjub-bytes-v1`), which it cites as an accepted input. The maintainer decided the
four design questions in r2 (see "Design questions — decided"); the ADR as a whole still
awaits design review. Acceptance would be design acceptance only; it certifies no
implementation, test or security property.

**Risk: R2.** This ADR defines profile identity, serialization formats, validation and
API contracts at security boundaries, and the verification matrix applications rely on. It
introduces no new primitive, generator, hash mapping or transcript. The R3 decisions of the
roadmap stay with their own ADRs: BLS12-381 G1 generators and the G1 byte mapping with #95,
Bulletproof transcripts with #96, the G1 sigma-proof transcript with ADR-0051 D7.

## Date

2026-10-16 (r1); 2026-10-16 (r2: Q1–Q4 decided)

## Context

ZeroJ has three Pedersen commitment profiles on Jubjub, each specified separately:

| Profile | Spec | Governing ADR | Message | Main Java type |
|---|---|---|---|---|
| `pedersen-jubjub-v1` | [`pedersen-jubjub-v1.md`](../specs/pedersen-jubjub-v1.md) | ADR-0051 D1–D4 | integer, reduced mod `l` | static `PedersenCommitment`; commitments are raw `JubjubPoint` |
| `pedersen-jubjub-vector-v1` | [`pedersen-jubjub-vector-v1.md`](../specs/pedersen-jubjub-vector-v1.md) | ADR-0051 D5 | up to 16 integers under a schema | `PedersenVectorCommitment` (carries its schema) |
| `pedersen-jubjub-bytes-v1` | [`pedersen-jubjub-bytes-v1.md`](../specs/pedersen-jubjub-bytes-v1.md) | ADR-0058 | arbitrary bytes, XMD/SHA-256 to scalar | `PedersenBytesCommitment` |

Two application protocols consume `pedersen-jubjub-v1`: `confidential-note-jubjub-v1`
(ADR-0055) and, for its auditor relation, ElGamal (`elgamal-jubjub-v1`, ADR-0052). The roadmap
adds a BLS12-381 G1 profile for direct Cardano verification (#95) and Bulletproof range proofs
(#96).

Each spec is precise about its own profile. What is missing is the layer above them:

1. **No registry or identity rules.** Profile identifiers exist as spec titles and, for the
   byte profile, a Java constant. Nothing states the identifier grammar, what a profile's
   immutable parameter set contains, or how a new profile is admitted.
2. **No common contract.** The numeric profile returns a bare `JubjubPoint`, the vector
   profile a schema-carrying type, the byte profile a final profile-specific type. There is
   no shared notion of a commitment value, an opening, a profile-checked decoder or a
   verification outcome. ADR-0058 D3 left "the generic envelope, opening codecs and
   verification-result interfaces" to this issue.
3. **No statement of what each environment can verify.** Jubjub has no Plutus builtins, so
   Cardano L1 sees Jubjub commitments only as Groth16 public inputs. BLS12-381 G1 has
   builtins, so #95 can check openings and linear relations natively, but a byte opening
   additionally needs the profile's hash on-chain. Applications need one table saying what
   is checked where, what is disclosed and what needs an additional proof.
4. **Cross-profile hazards are spread across ADRs.** Point-set non-disjointness of numeric
   and byte commitments (ADR-0058 D4), schema relabelling (ADR-0051 D5), wraparound (ADR-0051
   D3a) and provenance (ADR-0051 I11, ADR-0058 D4) each appear once, in their own profile.
   A G1 profile will reproduce all of them, plus curve mixing.

### Facts this design depends on

Audit baseline: the PR #97 head this branch is stacked on,
`3a5ebea16b5727a5d9690e5b25c0e8971680acbc`.

- **Module graph.** `zeroj-api` has no dependencies and already holds shared contracts
  (`VerificationResult`, which separates cryptographic validity from policy validity with
  typed reason codes; `ZkProofEnvelope`; `CurveId`). `zeroj-circuit-dsl`, `zeroj-bbs`,
  `zeroj-crypto` and `zeroj-onchain-julc` depend on it with `api` scope; `zeroj-circuit-lib`
  reaches it through `zeroj-circuit-dsl`. `zeroj-bls12381` does not depend on it.
- **Shared vectors.** `zeroj-test-vectors` (test-only, unpublished) holds JSON vectors with a
  `schema` identifier, a `profileId`, hex fields and `negativeMutations`, for example
  `test-vectors/poseidon-authenticated-state-v1/vectors.json`. The Pedersen profiles instead
  keep independent Python references with `key=value` outputs under
  `zeroj-circuit-lib/src/test/resources/` (`pedersen-reference/`, `pedersen-vector-reference/`,
  `pedersen-bytes-reference/`).
- **Cardano mainnet**, read from Koios on 2026-10-16 (epoch 661): protocol version 11.0;
  `maxTxExecutionUnits` 16,500,000 memory / 10,000,000,000 steps; `maxTxSize` 16,384 bytes;
  `txFeePerByte` 44; `txFeeFixed` 155,381; prices 0.0577 per memory unit and 0.0000721 per
  step; `minFeeRefScriptCostPerByte` 15; PlutusV3 cost model of 350 parameters. Protocol
  version 11 ("van Rossem") activated at the epoch 643/644 boundary (2026-07-18), bringing
  CIP-0133 `bls12_381_G1_multiScalarMul`. These are governance parameters and can change;
  benchmarks record the epoch they used.
- **CIP-0381** defines the G1 builtins `add`, `neg`, `scalarMul :: Integer -> G1 -> G1`,
  `equal`, `compress`, `uncompress` and `hashToGroup :: ByteString -> ByteString -> G1`
  (DST at most 255 bytes). The element type is stated to admit only prime-order-subgroup
  points. The CIP does **not** say whether `scalarMul` reduces its integer argument or
  accepts negatives, and does not state which non-canonical encodings `uncompress` rejects
  (ADR-0056 records the same gap).
- **Measured builtin costs** under the PV11 cost model (ADR-0056, Julc pre18 and Yaci
  DevKit): G1 `uncompress` 52,948,122 steps; G1 `scalarMul` intercept 76,433,006 steps.
- **On-chain precedent.** No Jubjub arithmetic runs on-chain. The library code in
  `zeroj-onchain-julc` is `Groth16BLS12381Lib.verify` (G1/G2 `uncompress`, `scalarMul`, `add`,
  pairings; no `multiScalarMul`, no `hashToGroup`), `BbsHashToScalar.hashToScalar` (XMD/SHA-256,
  48 bytes, three `sha2_256` calls; 14.2M steps / 45.8k memory per ADR-0050) and
  `BbsProofVerify` (about 2.4×10⁹ steps). The Pedersen and note validators are **reference
  validators in test sources** (`zeroj-integration-tests`: `ConfidentialNoteValidator`
  3.66×10⁹ steps, `VectorCommitmentConsumerValidator` 3.07×10⁹ steps, ADR-0051 M4;
  `AuditedConfidentialNoteValidator`, ADR-0055). They see Jubjub commitments only as affine
  `(u, v)` Groth16 public inputs. Plutus has no `sha2_512` and no SHAKE builtin (ADR-0051 D7).
- **Current Java surface.** No common commitment interface exists. `pedersen-jubjub-v1` has
  no profile-identifier constant; `pedersen-jubjub-vector-v1` appears only as the
  package-private schema-encoding tag (hashed into `σ`); `PedersenBytesCommitment.PROFILE_ID`
  is documentation metadata, never serialized. `PedersenVectorCommitment` does not override
  `equals`, `hashCode` or `toString`. `PedersenBytesApiSurfaceTest` pins the exact public
  method sets of `PedersenBytesCommitment` and `PedersenCommitment`; `ElGamalApiSurfaceTest`
  and `ConfidentialNotesTest.apiSurface` pin their types. Unused `PROFILE` constants exist on
  `ElGamal` and `DkgConfig`.

## Threat model and trust assumptions

- **Untrusted:** every serialized commitment, envelope, profile label, opening, payload,
  relation delta, proof and public input received from another party; redeemers and datums
  on-chain; the claimed issuance context of a commitment.
- **Secret:** committed values and payloads when the application hides them, every blinding,
  every hash-derived scalar, and opening objects in memory. A verifier that receives a
  **disclosed** opening learns it; on Cardano L1 a disclosed opening is public forever.
- **Trusted:** the profile specifications and their pinned constants; the discrete-log
  assumption in each profile's prime-order group with no known relation between its bases;
  the profile's hash for byte mappings; a correctly seeded CSPRNG; the verifier's own trusted
  configuration (expected profile, schema registry, provenance source); the ledger's
  builtins for on-chain checks.
- **Attacker goals considered** (the issue #94 list): exploiting generator trapdoors;
  smuggling non-subgroup or identity points; scalar wraparound and non-canonical scalars;
  encoding ambiguity; malformed-input crashes or resource exhaustion; substituting one
  profile, schema, curve or proof context for another; replaying a valid opening or proof;
  and learning committed data through disclosed openings, reused blindings, small message
  spaces or metadata.
- **Out of scope** (ADR-0006): authorization, replay protection, nullifiers, `ScriptContext`
  binding and business policy. A valid opening, relation or proof authorizes nothing. This
  ADR states which of these each matrix cell leaves to the application; it does not supply
  them.

## Pinned normative references

1. ZeroJ `pedersen-jubjub-v1` (2026-10-03), `pedersen-jubjub-vector-v1` (2026-10-03) and
   `pedersen-jubjub-bytes-v1` (2026-10-16) specs at the audit baseline; ADR-0051, ADR-0055
   and ADR-0058. These remain normative for their profiles; this ADR changes none of their
   bytes.
2. [CIP-0381](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0381/README.md),
   *Plutus support for pairings over BLS12-381*, §Specification (builtin names, types,
   `hashToGroup` DST limit), as cited above; ADR-0056 pins the same CIP at `86b89208`.
3. CIP-0133, *Plutus support for multi-scalar multiplication over BLS12-381*, enacted with
   protocol version 11 (see Facts).
4. RFC 9380 (August 2023) — referenced only as the family #95 is expected to use for G1
   generators and byte mapping. This ADR fixes neither.
5. ADR-0006 (cryptographic versus policy verification), ADR-0044 (module surface and provider
   isolation), ADR-0045 (every public wire constrained), ADR-0056 (PV11 on-chain costs).

## Decision

### D1 — Normative profile registry and identity rules (R2)

Publish one registry, `docs/specs/commitment-profiles-v1.md`, that lists every commitment
profile and its immutable parameter record. The per-profile specs stay authoritative for
their algorithms; the registry links them and adds the cross-profile rules.

- **Identifier grammar.** ASCII, 1–64 bytes, matching
  `^[a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*$`. All three existing identifiers conform.
  Identifiers compare byte-for-byte; there is no case folding or normalization.
- **Immutability.** A profile identifier names one parameter record forever. Changing any
  field of the record is a new identifier (generalizing ADR-0051 I7). An identifier is never
  reused, including after withdrawal; withdrawn profiles stay listed with their status.
- **Parameter record.** Every profile states, or links to the spec section that states:
  1. kind: `scalar`, `bytes` or `vector` (D2);
  2. group: curve, prime subgroup order `q`, cofactor, identity element;
  3. bases: their derivation procedure, domain strings and pinned encodings, and the
     independent reproduction that checks them;
  4. message map: reduction mod `q` (scalar), the hash-to-scalar specification with its DST
     and length rules (bytes), or the schema rules (vector);
  5. scalar domain: which API layers accept integers mod `q` and which require canonical
     `[0, q)` (D4);
  6. point encoding: length, canonical-encoding rule, subgroup rule and identity policy;
  7. circuit public-input encoding, where the profile is used in circuits;
  8. opening encoding (D4);
  9. proof transcript domain, when a proof system is bound to the profile (none today;
     #95/#96 fill it);
  10. maturity and the governing ADR.
- **Generator rule** (generalizes ADR-0051 I1 to every profile). A profile's bases come from
  a published hash-to-group procedure applied to a profile-specific domain string; each is in
  the prime-order subgroup, not the identity and distinct from the others; none is defined as
  a known multiple of another; and an implementation independent of the code under test
  reproduces them. The existing profiles satisfy this (`H` by Poseidon try-and-increment, the
  vector bases by Zcash `FindGroupHash`). For G1, #95 chooses the procedure; a derivation that
  `bls12_381_G1_hashToGroup` can reproduce on-chain is preferred, because it gives an on-chain
  differential check (ADR-0051 D7 direction).
- **Identity policy.** Each profile states whether a received identity point is accepted.
  The Jubjub profiles accept it (`pedersen-jubjub-v1` §4.1); #95 states the G1 policy and
  tests what `bls12_381_G1_uncompress` does with the infinity encoding.
- **Registered now:** `pedersen-jubjub-v1`, `pedersen-jubjub-vector-v1`,
  `pedersen-jubjub-bytes-v1`.
- **Reserved, parameters undefined:** `pedersen-bls12-381-g1-v1` and
  `pedersen-bls12-381-g1-bytes-v1` (Q3, decided). Reservation fixes only the names; #95's ADR and spec
  define the generators, the byte mapping and the encodings, and admit the entries.
- **Admission rule.** A profile enters the registry only with an accepted ADR, a normative
  spec, an independent reproduction of its constants, vectors in the D6 format, and one public
  Java descriptor constant carrying its identifier (today only the byte profile has one).

Consuming protocols (`confidential-note-jubjub-v1`, `elgamal-jubjub-v1`) are listed in a
separate "protocols using a profile" table, because they are not commitment profiles.

### D2 — Kinds and semantic separation (R2)

| Kind | Opens to | Homomorphism means | Must never be presented as |
|---|---|---|---|
| `scalar` | an integer residue mod `q` | addition of residues mod `q` | integer arithmetic, unless the D3a width rule of ADR-0051 holds for every term |
| `bytes` | an exact octet string | addition of the **hash-derived scalars** mod `q` | arithmetic, concatenation, merge or comparison of the original bytes |
| `vector` | `n` residues under one schema | component-wise addition within one schema digest | anything across schemas (ADR-0051 D5) |

Rules the typed API enforces and the spec states:

- **No cross-profile arithmetic.** Homomorphic operations exist only on concrete
  profile-specific types and accept only the same type. A runtime profile check backs the
  compile-time one where a generic path exists. Mixing curves is impossible by type and by
  encoding length; mixing profiles on one curve is rejected by type.
- **No arithmetic on byte commitments in the typed API** (ADR-0058 D3). A caller who extracts
  the point leaves the byte API's protections.
- **Point sets are not disjoint.** Profiles that share bases produce the same points: a byte
  commitment `C_bytes(B, r)` equals the scalar commitment `C(H(B), r)` (ADR-0058 D4), and a
  future G1 byte profile would do the same over its scalar profile. Kind and profile are
  therefore never inferred from a point; they come from trusted configuration (D3).

### D3 — Verification classes and the profile-selection rule (R2)

Every check an application performs falls into exactly one class. The class determines what
is disclosed and what is established.

| Class | Input | Discloses to the verifier | Establishes | Does not establish |
|---|---|---|---|---|
| **V1 Disclosed opening** | `C`, message, `r` | message and `r` | `C` opens to the message under the expected profile | integer range beyond the profile's own bound; provenance; authorization |
| **V2 Private recomputation** | `C` and an opening the holder keeps secret | nothing | the same as V1, for the holder only | as V1 |
| **V3 Public relation** | commitments, public coefficients and deltas | coefficients and deltas | a linear relation between hidden residues mod `q` | non-negativity, integer conservation (needs per-term range proofs), knowledge of any opening |
| **V4 Proof** | commitments, proof, public inputs | what the proof's public inputs expose | the proof system's statement (knowledge, range, relation) | anything outside the statement; provenance; authorization |
| **P Policy** | application records, configuration, context | application data | expected profile, schema, issuance provenance, context binding, replay rules | — (not cryptographic) |

**Profile-selection rule (normative).** A verifier takes the expected profile (and, for
vectors, the expected schema digest) from its trusted configuration. It never selects a
profile from a label, envelope, datum field or proof that travels with the input. A label
that disagrees with the expected profile is a rejection; a label that agrees is not evidence
of provenance. Where provenance matters, the application authenticates the association of
the exact point, profile and context (ADR-0051 I11, ADR-0058 D4) and fails closed without it.

**Proof-context binding.** A proof about commitments (V4) binds the profile and its full
statement: in Groth16/PlonK circuits through the verification key and constrained public
inputs (the affine coordinates, the schema digest for vectors; ADR-0045); in Fiat–Shamir
proofs (#95/#96) by absorbing the profile identifier, every base, every commitment and the
application context into the transcript (strong Fiat–Shamir, ADR-0051 I9). A proof verified
under one profile or context is never accepted under another.

V2 uses the profile's secret-bearing generation path and keeps its maturity restriction
(ADR-0038 offline/isolated for Jubjub). V1 may use variable-time arithmetic because its
inputs are disclosed.

### D4 — Encodings: raw points, an optional envelope, canonical openings (R2)

- **Raw point encodings stay per profile and unchanged.** Jubjub profiles: the 32-byte
  ZIP 216 encoding of `pedersen-jubjub-v1` §4 with the §4.1 subgroup rule; in circuits, the
  affine `(u, v)` public inputs (§5). G1 profiles: defined by #95 (48-byte compressed is the
  expected form). On-chain datums and redeemers use the raw form fixed by the validator's
  parameters, never an envelope.
- **Commitment envelope v1** (off-chain storage and transport; Q1, decided: implemented in
  M1):

  ```
  envelope = 0x01                        # envelope format version
          || u8(len(profileId)) || profileId
          || point                       # exactly the profile's raw encoding
  ```

  Decoding takes the **expected** profile's codec as an argument (for vectors, a codec bound
  to the expected schema, as `PedersenVectorCommitment.decode(schema, bytes)` already
  requires). It rejects a version other than `0x01`, an identifier that is not byte-identical to the expected one, a point whose length
  differs from the profile's encoding length, and trailing or missing bytes; then it applies
  the profile's strict point decoder. The public API offers no decoder that dispatches on the
  embedded identifier. The envelope prevents accidental mix-ups and makes stored data
  self-describing; it is not authentication. Vector commitments are enveloped without their
  schema: the schema digest stays a configuration and provenance matter (ADR-0051 D5).
  For `pedersen-jubjub-bytes-v1` the envelope is 1 + 1 + 24 + 32 = 58 bytes.
- **Canonical opening encodings.** At every serialization boundary (vectors, delivery
  formats, redeemers, cross-language interchange) scalars are canonical: `0 ≤ m < q` and
  `0 ≤ r < q`, rejected otherwise rather than reduced. `I2OSP` is unsigned big-endian, as in
  the note plaintext (`confidential-note-jubjub-v1` §3.1).

  | Kind | Opening encoding |
  |---|---|
  | `scalar` (Jubjub) | `I2OSP(m, 32) ‖ I2OSP(r, 32)` |
  | `bytes` | `I2OSP(r, 32)`; the payload travels separately as its exact octets (no transcoding, no implied length beyond its own framing) |
  | `vector` | `u8(n) ‖ I2OSP(v_0, 32) ‖ … ‖ I2OSP(v_{n−1}, 32) ‖ I2OSP(r, 32)`, each `v_i < 2^{k_i}` for the configured schema |

  The existing numeric Java methods keep accepting any integer mod `l` (ADR-0058 D3); the
  canonical rule applies to new typed entry points and every wire format. A non-canonical
  opening such as `(m + q, r)` satisfies the group equation; accepting it at a boundary that
  later reads `m` as an integer is a wraparound bug.
- **On-chain scalar rule.** Because CIP-0381 does not specify how `scalarMul` treats
  out-of-range or negative integers, a validator checks `0 ≤ m < 2^k` (its application bound,
  `2^k ≤ q`) and `0 ≤ r < q` itself before using either, whatever the builtin does. #95 adds
  vectors that pin the builtin's observed behaviour as evidence, not as the guard.

### D5 — Java contracts in `zeroj-api` (R2)

A small package `org.zeroj.api.commitment` in `zeroj-api` (no dependencies; already the home
of `VerificationResult`) holds the profile-independent contracts. Concrete profiles implement
them in their own modules. Illustrative shapes, fixed by the M0 spec review:

```java
public final class CommitmentProfileId { ... }    // validated D1 grammar; value-based equality
public enum CommitmentKind { SCALAR, BYTES, VECTOR }
public enum CommitmentGroup { JUBJUB, BLS12_381_G1 }

public interface CommitmentProfile {              // descriptor; one constant per profile
    CommitmentProfileId id();
    CommitmentKind kind();
    CommitmentGroup group();                      // new enum: JUBJUB, BLS12_381_G1
    int pointEncodingLength();
}

public interface Commitment {                     // a validated point under one profile
    CommitmentProfile profile();
    byte[] toPointBytes();                        // fresh copy of the raw encoding
}

public interface CommitmentCodec<C extends Commitment> {   // the expected profile's decoder
    CommitmentProfile profile();
    C decodePoint(byte[] rawPoint);               // strict: canonical, subgroup, identity policy
}

public final class CommitmentEnvelope {           // D4
    static byte[] encode(Commitment c);
    static <C extends Commitment> C decode(byte[] envelope, CommitmentCodec<C> expected);
}
```

- **No arithmetic on the shared interfaces.** `add`, `subtract` and `negate` live only on
  concrete types and take the same concrete type (D2).
- **Openings are not records.** Opening holders are final classes with a redacted
  `toString`, no `equals`/`hashCode` on secret fields and no `Serializable`. `BigInteger`
  values cannot be wiped; the Javadoc says so, as ADR-0058 does.
- **Verification outcomes.** Opening checks keep the existing contract: `false` for a
  well-formed mismatch, an exception for malformed input. A new `CommitmentCheck` result,
  modelled on `VerificationResult`, is returned only by a composed acceptance helper that
  combines decode, expected-profile, provenance and opening checks. It separates cryptographic
  from policy outcomes and carries a reason code (`MALFORMED_ENCODING`, `PROFILE_MISMATCH`,
  `NON_CANONICAL_SCALAR`, `OPENING_MISMATCH`, `PROVENANCE_MISSING`, `PROVENANCE_MISMATCH`,
  `OUT_OF_RANGE`). Reason codes and messages never contain secrets.
- **Existing types adopt the contracts additively.** `PedersenBytesCommitment` and
  `PedersenVectorCommitment` implement `Commitment`. Per Q2,
  `pedersen-jubjub-v1` gains a typed commitment and `commitScalar`/`verifyScalar` entry points
  that require canonical `m` and `r`.
  `PedersenCommitment.commit`/`verify` and `JubjubPoint` returns remain unchanged.
- **Provider parity** (ADR-0044): when #95 adds pure-Java and blst G1 implementations, both
  implement the same contracts and must agree on every vector and verdict.

### D6 — Cross-language vector format (R2)

New vectors use one JSON format, `zeroj-commitment-vectors-v1`, stored per profile in
`zeroj-test-vectors` under `test-vectors/commitment-profiles-v1/<profileId>.json`, following
the existing `schema`/`profileId`/hex conventions of that module:

- header: `schema`, `profileId`, the spec path and date, and the generator's provenance
  (tool, version or commit, and the SHA-256 of the generating script);
- `positive` cases: operation (`commit`, `hashToScalar`, `decode`, `verifyOpening`,
  `relation`, `envelope`), hex inputs, and expected outputs including intermediates where the
  spec defines them;
- `negative` cases: the same operations with an expected **error class**, not an exception
  name: `MALFORMED_ENCODING`, `NOT_IN_SUBGROUP`, `NON_CANONICAL_SCALAR`, `PROFILE_MISMATCH`,
  `LENGTH_OUT_OF_RANGE`, `OPENING_MISMATCH`. Each profile's spec maps error classes to its
  Java exceptions (for example ADR-0058's `IllegalArgumentException`/`false` contract).

Expected values come from an independent implementation, never from the code under test.
The existing independent Python references (`pedersen-reference`,
`pedersen-vector-reference`, `pedersen-bytes-reference`) are extended to emit this format;
their current `key=value` outputs stay as additional pins. For each Jubjub profile the minimum negative set is: wrong length, `v ≥ p`, the ZIP 216 sign alias,
off-curve, small-order (orders 2, 4, 8), mixed-order (subgroup point plus torsion),
non-canonical `m` and `r` (`q`, `q + 1`, `−1`), envelope version, identifier and length
mismatches, and an opening for the wrong message. JuLC consumers (from #95) load the same
files in their VM tests.

### D7 — Verification matrix (R2, normative in the registry spec)

"Native" means using ledger builtins directly; "in a proof" means through a Groth16/PlonK
verifier that has the commitment as public inputs. Every cell leaves authorization, replay
protection and context binding to the application (class P).

| Profile | Class | Java off-chain | Cardano L1 (JuLC) | Public after the check |
|---|---|---|---|---|
| `pedersen-jubjub-v1` | V1 opening | Implemented (`PedersenCommitment.verify`) | **Not native** (no Jubjub builtins). Possible only as a proof statement | message and `r` |
| | V3 relation | Implemented point arithmetic; balance rule of ADR-0051 D3a | In a proof only (reference: `ConfidentialNoteValidator`, test sources) | deltas |
| | V4 proof | Groth16/PlonK with `ZkPedersen` | Library: `Groth16BLS12381Lib.verify` with affine `(u, v)` public inputs. Reference validators exist only in test sources | public inputs |
| `pedersen-jubjub-vector-v1` | V1, V3, V4 | Implemented (ADR-0051 M3) | V4 only, with the schema digest as a public input and an issuance record (reference: `VectorCommitmentConsumerValidator`, test sources) | as above plus `σ` |
| `pedersen-jubjub-bytes-v1` | V1 opening | Implemented (ADR-0058), streaming to `2^61 − 256` bytes | **Not native**, and not provided in a proof (no in-circuit SHA-256 gadget; ADR-0058) | payload and `r` |
| | V3/V4 | Not offered (D2) | Not offered | — |
| `pedersen-bls12-381-g1-v1` (#95) | V1 opening | Planned | Planned native: `uncompress`, two `scalarMul` or one MSM, `add`, `equal`, plus the D4 scalar checks | message and `r` |
| | V3 relation | Planned | Planned native (`C_new = C_old + [δ]G`, sums) | deltas |
| | V4 proof | Sigma proofs blocked by ADR-0051 D7; range proofs by #96 | Blocked / feasibility only (#96) | — |
| `pedersen-bls12-381-g1-bytes-v1` (#95) | V1 opening | Planned | Native only if the validator recomputes the byte mapping with `sha2_256`; the payload must fit in the transaction (`maxTxSize` 16,384 bytes in total). A validator that accepts a supplied scalar instead authenticates **only that scalar**, not the bytes | payload (or scalar) and `r` |

Consequences the spec states explicitly:

- **Disclosed openings on-chain are public forever.** A V1 check in a validator publishes
  the message and the blinding. It suits public reveals (sealed bids after the deadline,
  audits), not private balances.
- **Relations prove residues, not balances.** A V3 sum on G1 says nothing about
  non-negativity; integer conservation needs a range proof per term (#96) or a circuit
  (ADR-0051 D3a). Validators that combine commitments apply the side-bound rule to declared
  widths.
- **Hiding is the committer's job.** It needs a fresh uniform blinding per commitment. Two
  commitments with the same blinding reveal `[m₁ − m₂]·G`, so small differences can be
  enumerated; a disclosed opening of a low-entropy message space (votes, small amounts, short
  strings) is a disclosure of the message.
- **Byte mapping on-chain costs scale with payload size** and are bounded by the transaction
  size limit. Larger documents can only be committed and opened off-chain; on-chain
  references them by commitment.

### D8 — Benchmark methodology (R2; executed by #95/#96)

Benchmarks are records, not assertions, and never trade a check for a number (ADR-0051 I12).

- **Java:** a standalone harness (not a Gradle test run for timing claims), warm-up and
  measured iterations, multiple forks, p50 and p95, allocation per operation
  (`ThreadMXBean`), one and eight threads, on JVM and GraalVM native image, aarch64 and
  x86-64 (recording any platform that is unavailable). Operations: commit, decode, V1
  verify, V3 relation, envelope round trip, and byte mapping at 0 B, 1 KiB, 1 MiB and
  16 MiB.
- **Cardano:** CPU steps and memory per operation under the named cost model (Julc VM), then
  confirmed on Yaci DevKit; script size in bytes; the fee
  `44 × txSize + 155,381 + ⌈0.0577 × mem + 0.0000721 × steps⌉` plus the reference-script fee,
  with the epoch whose parameters were used; and each figure as a fraction of
  `maxTxExecutionUnits`. Operations: G1 V1 scalar opening, V3 delta update, n-term sum, and
  the byte opening at representative payload sizes up to the largest that fits.
- **Proofs (#96):** proof size in bytes, prover and verifier time, verifier memory.

## Alternatives considered

| Alternative | Why not |
|---|---|
| One generic `Commitment` interface with `add`/`subtract` | Invites cross-profile and cross-curve arithmetic that only a runtime check would stop. Arithmetic stays on concrete types (D2, D5) |
| Profile chosen by an embedded label (dispatching decoder) | Lets the sender choose the profile; contradicts ADR-0051 I11 and ADR-0058 D4 |
| Envelope in datums and redeemers | Costs bytes and execution for no security gain: a validator's parameters already fix the profile |
| Numeric profile codes instead of string identifiers | Shorter, but another registry to keep consistent; the identifiers already exist in specs and DSTs |
| CBOR or Plutus Data envelope | Adds a codec dependency to `zeroj-api` and a second canonical-encoding problem for little benefit off-chain |
| A separate `zeroj-commitment-api` module | One more published module against ADR-0044's consolidation; `zeroj-api` already holds the equivalent proof contracts |
| Reuse `CurveId` for the commitment group | It names proof-system curves and is matched exhaustively in main code; adding Jubjub would change unrelated switches |
| Contracts in `zeroj-circuit-lib` | `zeroj-bls12381`-based G1 code (#95) would have to depend on the circuit library |
| Change existing methods to return typed results | Breaks callers of a public API for no security gain; additive entry points suffice |
| Define the G1 generators here | Maintainer decision (2026-10-16): they belong with #95's implementation and review |

## Exact invariants

- **I1 — Registry and bases.** Every commitment profile ZeroJ ships has a registry entry
  with a complete parameter record; every identifier matches the D1 grammar and is never
  reused; every profile's bases satisfy the D1 generator rule. (D1)
- **I2 — Expected profile.** No API or validator selects a profile, kind or schema from
  untrusted input; envelope and label mismatches reject; label agreement is never treated as
  provenance. (D3, D4)
- **I3 — No cross-profile arithmetic.** Homomorphic operations accept only the same
  concrete profile type; byte commitments expose none. (D2, D5)
- **I4 — Strict decoding.** Every decoder accepts exactly one encoding per point, enforces
  subgroup membership, applies its profile's identity policy, and never cofactor-clears a
  received point. (D4)
- **I5 — Canonical scalars at boundaries.** Every wire format and new typed entry point
  rejects scalars outside `[0, q)` and values outside the profile or schema bound; on-chain
  validators check this before using a scalar. (D4)
- **I6 — Disclosure is explicit.** Every matrix cell states what becomes public; APIs name
  disclosed verification (V1) separately from private recomputation (V2). (D3, D7)
- **I7 — Residues, not integers.** Relations are documented and tested as statements mod
  `q`; integer readings require the ADR-0051 D3a rule or range proofs. (D2, D7)
- **I8 — Secrets.** Opening types are not records, redact `toString`, are not
  `Serializable`, and appear in no reason code or message. (D5)
- **I9 — Independent vectors.** Expected values in D6 files come from an implementation
  independent of the code under test, with recorded provenance; every profile has the
  minimum negative set. (D6)
- **I10 — Compatibility.** No existing profile's bases, encodings, vectors, circuits or
  verification keys change, and no existing public method is removed or changes its
  semantics; additions are listed under Compatibility. (Compatibility)
- **I11 — Provider and environment parity.** Every implementation of a profile (pure Java,
  blst, JuLC) passes the same vector file and returns the same verdicts. (D5, D6)

## Compatibility

- All three Jubjub profiles keep their bytes: bases, encodings, DSTs, vectors, circuits,
  public-input order and keys. No reissuance or key regeneration.
- `PedersenCommitment`, `PedersenBytesCommitment`, `PedersenVectorCommitment` and the
  `ZkPedersen*` gadgets keep every public method and its semantics. New interfaces, entry
  points and the envelope are additive.
- `PedersenBytesApiSurfaceTest` pins exact method sets, so implementing `Commitment` (a new
  `profile()` method) and Q2's entry points change its expected sets. M1 updates those
  expectations explicitly in the same reviewed commit, keeping every existing assertion
  (final, not a record, not `Serializable`, no public constructor, no `BigInteger` field).
- `PedersenVectorCommitment` keeps its current (reference) equality; the contract does not
  require value equality, so no existing comparison changes.
- `CurveId` is not extended. It names proof-system curves, is used by 27 main source files
  and is matched exhaustively (for example `FieldConfig`); a separate `CommitmentGroup` enum
  avoids changing that surface.
- The envelope is new; nothing stored today uses it, so there is no migration. Data stored as
  raw points stays valid and is read with the expected profile's raw decoder.
- `confidential-note-jubjub-v1` and `elgamal-jubjub-v1` are unaffected.

## Implementation milestones (after acceptance)

| Milestone | Entry gate | Deliverables and exit criteria |
|---|---|---|
| M0 — Registry spec | ADR accepted (Q1–Q4 decided in r2) | `docs/specs/commitment-profiles-v1.md`: D1 grammar and records for the three Jubjub profiles, the two reserved names, D2 kinds, D3 classes, D4 envelope and opening encodings, D6 format with its error classes, D7 matrix, D8 methodology. Reviewed (Claude and Codex) before code. Covers I1, I2, I5–I7 |
| M1 — Contracts and adapters | M0 reviewed | `org.zeroj.api.commitment`; adapters for the three profiles; typed `pedersen-jubjub-v1` commitment and `commitScalar`/`verifyScalar` (Q2); envelope codec (Q1); composed acceptance helper. API-surface tests (no records, no public raw constructors, no shared arithmetic). Covers I2–I5, I8, I10 |
| M2 — Vectors | M1 | Python references extended to emit D6 files for the three profiles, with provenance; Java loader runs every positive and negative case; mutated-file self-test. Covers I4, I5, I9, I11 |
| M3 — Documentation | M2 | Registry and matrix on the docsite and in the gadget/support matrix; API examples for scalar, bytes, opening and relation checks; maturity unchanged. Covers I6, I7 |

#95 and #96 consume this ADR: each adds its registry entry, vector file, matrix cells and D8
measurements as part of its own milestones.

## Verification and test strategy

- **Registry (M0):** every listed identifier matches the grammar; every parameter record
  links a spec section that exists; reserved names have no parameters.
- **Envelope (M1, M2):** round trip for every profile; rejection of each malformed case in
  D4, including an identifier differing in one byte and a vector or byte commitment decoded
  as the numeric profile; a fuzz pass over random byte strings with no exception other than
  the documented ones.
- **Profile substitution (M1):** an acceptance helper configured for
  `pedersen-jubjub-bytes-v1` rejects a matching envelope labelled `pedersen-jubjub-v1`, and a
  test shows the numeric equation for `H(B)` still holds on the raw point — demonstrating that
  only configuration and provenance separate them (ADR-0058 D4).
- **Canonical scalars (M1, M2):** `m` and `r` at `q − 1` accepted, `q`, `q + 1` and `−1`
  rejected at every new entry point and decoder; the numeric `commit`/`verify` still accept
  them (compatibility).
- **API surface (M1):** reflection tests: no shared arithmetic, opening types are final,
  not records and not `Serializable`, and their `toString` does not contain any scalar.
- **Regression:** the full `:zeroj-circuit-lib:test` and `:zeroj-api:test`; existing
  Pedersen reference fixtures and circuit pins unchanged.

## Consequences

- Applications get one place to find a profile's parameters, its encodings and what each
  environment can check.
- #95 and #96 start from fixed contracts, a vector format and a measurement method instead
  of inventing their own.
- `zeroj-api` gains a small package with its own `CommitmentGroup` enum.
- The matrix makes some limits explicit that applications may not expect: no native L1 check
  of Jubjub openings, and public-forever disclosure for on-chain openings.

## Risks and production/audit gates

- **False sense of safety from the envelope.** It is not authentication; I2 and the
  substitution test exist to keep that visible.
- **Matrix drift.** Cells marked "planned" must be updated by #95/#96; the registry's
  admission rule makes the entry and its vectors part of those milestones.
- **Builtin behaviour.** CIP-0381 leaves `scalarMul` reduction and `uncompress` canonicity
  unspecified; validators carry their own checks (D4) and #95 pins the observed behaviour.
- **Parameter changes.** Fees and limits are governance parameters; benchmark records name
  their epoch.
- **No maturity change.** External cryptographic review of the profiles, ADR-0039 M9 for any
  hardened generation path, and application-level authorization remain outstanding.

## Related findings (out of scope)

- `JubjubPoint` is still the return type of the numeric `commit`; Q2 adds a typed
  alternative and does not deprecate it.
- Yano-X and other downstream verifiers are applications of the Java column; their
  determinism and resource limits are their own design.
- ADR-0051 D7 (G1 sigma-proof transcript) remains escalated and blocks G1 V4 proofs.

## Design questions — decided by the maintainer (2026-10-16, r2)

The maintainer accepted the recommended option for each question. The alternatives are kept
for the record. These decisions do not replace design review of the ADR as a whole.

- **Q1 — Envelope now or with #95. Decided: (a)** specify and implement the D4 envelope in
  M0/M1. It is small, and #95 introduces the first case where two curves' raw encodings could
  be confused in storage. Alternatives: (b) specify only and implement with #95; (c) omit and
  rely on raw points plus configuration.
- **Q2 — Typed numeric commitment. Decided: (a)** add a typed `pedersen-jubjub-v1`
  commitment with `commitScalar`/`verifyScalar` entry points that require canonical `m` and
  `r`. It gives the numeric profile the same contract as the others and matches #95's
  `commitScalar` naming. The existing `commit`/`verify` stay unchanged. Alternative: (b) keep
  the bare `JubjubPoint` API and adapt it only inside the acceptance helper.
- **Q3 — G1 profile identifiers. Decided: (a)** two identifiers, `pedersen-bls12-381-g1-v1`
  (scalar) and `pedersen-bls12-381-g1-bytes-v1` (bytes), sharing bases, mirroring ADR-0058 D1
  where the message map is part of the profile. Alternative: (b) one identifier covering both
  kinds, as #95's text suggests. #95 still defines all G1 parameters.
- **Q4 — Contract module. Decided: (a)** `zeroj-api`. Alternative: (b) a new
  `zeroj-commitment-api` module.

## Revision history

- **r1 (2026-10-16):** Initial proposal for #94.
- **r2 (2026-10-16):** Maintainer decisions recorded: Q1 (a) envelope in M0/M1, Q2 (a) typed
  numeric commitment with canonical `commitScalar`/`verifyScalar`, Q3 (a) two G1 identifiers,
  Q4 (a) `zeroj-api`. D1, D4, D5, Compatibility, milestones and related findings updated to
  match. Status stays Proposed pending design review.
