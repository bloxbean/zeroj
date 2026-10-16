# ADR-0059: Commitment profiles, typed contracts and verification matrix

## Status

**Accepted — design (2026-10-16), by maintainer Satya**, who reviewed the design rounds and
directed implementation. Implementation of M0–M3 proceeds on this PR, one reviewed milestone
at a time; the M0 registry spec needs the same maintainer's sign-off before any code. Review
evidence: Codex approved r3 `2e51e04`; a second, independent reviewer had nothing outstanding
at r6 `cfbdcaf`; Codex has not re-reviewed r4–r6. Addresses [issue #94](https://github.com/bloxbean/zeroj/issues/94),
phase 2 of the #93–#96 Pedersen roadmap. Stacked on PR #97 (ADR-0058,
`pedersen-jubjub-bytes-v1`), which it cites as an accepted input. The maintainer decided the
four design questions in r2 (see "Design questions — decided"). AI review (Claude and Codex
on this PR) is input to the decision, not the decision: acceptance is recorded only by a named
human maintainer, and no AI verdict upgrades a maturity or security claim (AGENTS.md).
Acceptance would be design acceptance only; it certifies no implementation, test or security
property.

**Risk: R2.** This ADR defines profile identity, serialization formats, validation and
API contracts at security boundaries, and the verification matrix applications rely on. It
introduces no new primitive, generator, hash mapping or transcript. The R3 decisions of the
roadmap stay with their own ADRs: BLS12-381 G1 generators and the G1 byte mapping with #95,
Bulletproof transcripts with #96, the G1 sigma-proof transcript with ADR-0051 D7.

## Date

2026-10-16 (r1); 2026-10-16 (r2: Q1–Q4 decided); 2026-10-16 (r3: review round 1); 2026-10-16 (r4: second review); 2026-10-16 (r5: second review, round 2); 2026-10-16 (r6: second review, round 3); 2026-10-17 (r7: accepted, design)

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
   constants, encodings or algorithms. M3 adds only editorial, non-normative pointers to them
   (see M3).
2. [CIP-0381 at `86b89208d3b2aabb5dcc5b778dfbe09096b4e114`](https://github.com/cardano-foundation/CIPs/blob/86b89208d3b2aabb5dcc5b778dfbe09096b4e114/CIP-0381/README.md),
   *Plutus support for pairings over BLS12-381*, §Specification: builtin names and types, the
   subgroup-only element type, the `hashToGroup` DST limit of 255 bytes. It does not specify
   how `scalarMul` treats out-of-range or negative integers, nor which non-canonical encodings
   `uncompress` rejects. ADR-0056 pins the same revision.
3. [CIP-0133 at `86b89208d3b2aabb5dcc5b778dfbe09096b4e114`](https://github.com/cardano-foundation/CIPs/blob/86b89208d3b2aabb5dcc5b778dfbe09096b4e114/CIP-0133/README.md),
   *Plutus support for Multi-Scalar Multiplication over BLS12-381*:
   - §Specification → Function definition: `bls12_381_G1_multiScalarMul :: [Integer] ->
     [bls12_381_G1_element] -> bls12_381_G1_element`; "The arrays of scalars and group
     elements must be non-empty and of equal size", otherwise the function fails.
   - §Specification → Cost model: "all scalars have to be reduced modulo the order of the group
     before being passed to the blst functions". The CIP states no valid input range or rule for
     negative scalars.

   That revision is the latest change to both READMEs as of 2026-10-16. Deployment state (the
   protocol-version 11 activation and the Koios parameters under Facts) is a dated observation,
   not part of these normative definitions.
4. RFC 9380 (August 2023) — referenced only as the family #95 is expected to use for G1
   generators and byte mapping. This ADR fixes neither.
5. ADR-0006 (cryptographic versus policy verification), ADR-0044 (module surface and provider
   isolation), ADR-0045 (every public wire constrained), ADR-0056 (PV11 on-chain costs).

## Decision

### D1 — Normative profile registry and identity rules (R2)

Publish one registry, `docs/specs/commitment-profiles-v1.md`, that lists every commitment
profile with its immutable cryptographic core, its lifecycle metadata and any proof protocols
bound to it. The per-profile specs stay authoritative for their algorithms; the registry links
them and adds the cross-profile rules.

- **Identifier grammar and namespace.** ASCII, 4–64 bytes (the shortest match is `a-v1`),
  matching `^[a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*$`. Commitment profiles, proof protocols and
  basis sets all use this grammar and share **one namespace**: an identifier names exactly one
  registry entry of one type, and admission rejects a collision with any existing or withdrawn
  entry. The three existing profile identifiers and the two reserved G1 names conform.
  Identifiers compare byte-for-byte; there is no case folding or normalization.
- **Cryptographic core (immutable).** A profile identifier names one cryptographic core
  forever. Changing any core field is a new identifier (generalizing ADR-0051 I7). An
  identifier is never reused, including after withdrawal. Every profile states, or links to
  the spec section that states:
  1. kind: `scalar`, `bytes` or `vector` (D2);
  2. group: curve, prime subgroup order `q`, cofactor, identity element;
  3. basis set: its identifier, and the
     derivation or pinned definition of each base (see the basis rule below);
  4. message map: reduction mod `q` (scalar), the hash-to-scalar specification with its DST
     and length rules (bytes), or the schema rules (vector);
  5. scalar domain: which API layers accept integers mod `q` and which require canonical
     `[0, q)` (D4);
  6. point encoding: length, canonical-encoding rule, subgroup rule and identity policy;
  7. circuit public-input encoding, where the profile is used in circuits;
  8. opening encoding (D4).
- **Lifecycle metadata (maintained).** Maturity, status (active, deprecated, withdrawn),
  governing ADRs, evidence links, implementations and providers. These change through a
  reviewed registry revision, recorded in the registry's history, and never change what a
  commitment or opening means. A withdrawn profile stays listed.
- **Proof protocols (separately versioned).** A proof system over commitments (a G1 sigma
  protocol, #96's range proofs) is its own record with its own identifier under the same
  grammar. It names the commitment profile it consumes and fixes its transcript exactly:
  domain strings, absorbed items and their order, challenge derivation and proof encoding.
  Changing any of these is a new protocol identifier; a transcript is never replaced under an
  existing identifier. Adding a protocol does not change or rename the commitment profile.
  A change that alters what a commitment means still requires a new commitment profile.
- **Basis rule** (generalizes ADR-0051 I1). Every base of a basis set is a validated element
  of the prime-order subgroup, is not the identity, and is distinct from the other bases of the
  set. No discrete-log relation between bases of the set is known, and none is defined as a
  known multiple of another. Every base's definition is pinned, and an implementation
  independent of the code under test reproduces it.
  - **Existing sets are preserved exactly.** The `pedersen-jubjub-v1` set is `G = [8]·G_full`,
    the pinned standard Jubjub subgroup generator (spec §2.1, not hash-derived), and `H`,
    derived by Poseidon try-and-increment from `"zeroj.pedersen.v1.H"` (§2.3). The
    `pedersen-jubjub-vector-v1` set is derived by Zcash `FindGroupHash` under `"ZeroJ_PV"`.
    Neither changes.
  - **A reviewed profile may reference an existing basis set** instead of deriving its own:
    `pedersen-jubjub-bytes-v1` uses the `pedersen-jubjub-v1` set, and the two G1 identifiers
    (Q3) will share one set. Domain separation then comes from the message map, not the
    bases, and the point sets coincide (D2).
  - **Newly derived bases** come from a published hash-to-group procedure under a domain string
    specific to the new basis set (not to each profile that later consumes it). For G1, #95
    chooses the procedure; one that `bls12_381_G1_hashToGroup` can reproduce on-chain is
    preferred, because it gives an on-chain differential check (ADR-0051 D7 direction).
- **Basis-set identifiers.** Because the namespace is shared, a basis set's identifier is
  distinct from every profile identifier, including the profile that introduced it. M0 names
  the existing sets without changing them, for example `pedersen-jubjub-basis-v1` (used by
  `pedersen-jubjub-v1` and `pedersen-jubjub-bytes-v1`) and `pedersen-jubjub-vector-basis-v1`;
  the exact names are fixed in the M0 spec.
- **Identity policy.** Each profile states whether a received identity point is accepted.
  The Jubjub profiles accept it (`pedersen-jubjub-v1` §4.1); #95 states the G1 policy and
  tests what `bls12_381_G1_uncompress` does with the infinity encoding.
- **Registered now:** `pedersen-jubjub-v1`, `pedersen-jubjub-vector-v1`,
  `pedersen-jubjub-bytes-v1`.
- **Reserved, parameters undefined:** `pedersen-bls12-381-g1-v1` and
  `pedersen-bls12-381-g1-bytes-v1` (Q3, decided). Reservation fixes only the names; #95's ADR
  and spec define the basis set, the byte mapping and the encodings, and admit the entries.
- **Admission and update rules.** A profile or proof protocol enters the registry only with
  an accepted ADR, a normative spec, an independent reproduction of its constants (bases,
  domain strings, transcript labels), vectors in the D6 format, and one public Java descriptor
  constant carrying its identifier (today only the byte profile has one). A metadata update
  needs a reviewed registry revision citing its evidence; it may not touch a core field or a
  protocol's transcript.

Consuming protocols (`confidential-note-jubjub-v1`, `elgamal-jubjub-v1`) are listed in a
separate "protocols using a profile" table, because they are not commitment profiles.

### D2 — Kinds and semantic separation (R2)

| Kind | Opens to | Homomorphism means | Must never be presented as |
|---|---|---|---|
| `scalar` | an integer residue mod `q` | addition of residues mod `q` | integer arithmetic, unless the D3a width rule of ADR-0051 holds for every term |
| `bytes` | an exact octet string | addition of the **hash-derived scalars** mod `q` | arithmetic, concatenation, merge or comparison of the original bytes |
| `vector` | `n` residues under one schema | component-wise addition within one schema digest; a sum's components may exceed the schema widths (see D4) | anything across schemas (ADR-0051 D5) |

Rules the typed API enforces and the spec states:

- **No cross-profile arithmetic.** Homomorphic operations exist only on concrete
  profile-specific types and accept only the same type. Mixing profiles, on one curve or
  across curves, is rejected by type and by the expected-profile check; that today's Jubjub
  and G1 encodings differ in length is a coincidence, not a rule to rely on.
- **Runtime profile check.** `Commitment` is an open interface (a `sealed` interface in
  `zeroj-api` cannot permit classes in other modules), so any class can claim any
  `profile()`. Where a generic path needs a runtime check, it compares the commitment's
  concrete class with the expected codec's class **and** its `profile()` with the expected
  descriptor constant by identity, never by a caller-supplied string. Only ZeroJ's own final
  implementations are trusted to report their profile; producer-side helpers such as
  `CommitmentEnvelope.encode` trust their input, and the consumer-side decoder trusts nothing
  (D4).
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
proofs (#95/#96) by absorbing the proof-protocol identifier (D1), the commitment profile
identifier, every base, every commitment and the application context into the transcript (strong Fiat–Shamir, ADR-0051 I9). A proof verified
under one profile or context is never accepted under another.

V2 uses the profile's secret-bearing generation path and keeps its maturity restriction
(ADR-0038 offline/isolated for Jubjub). **"Disclosed to this verifier" is not "public".** V1
may use variable-time arithmetic only when the opening is already public (for example, it is
published on-chain) or when no party from whom it is still secret can observe the verifier's
timing. Otherwise — an auditor checking an opening that is secret from third parties on an
observable host — the V2 restriction (offline/isolated) applies to the V1 check as well. This
qualifies the "disclosed values" wording of `pedersen-jubjub-v1` §3.2 and ADR-0058's disclosed
verification; it changes no algorithm.

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
  requires). It rejects a version other than `0x01`, an identifier that is not byte-identical
  to the expected one, a point whose length differs from the profile's encoding length, and trailing or missing bytes; then it applies
  the profile's strict point decoder. The public API offers no decoder that dispatches on the
  embedded identifier. The envelope prevents accidental mix-ups and makes stored data
  self-describing; it is not authentication. Vector commitments are enveloped without their
  schema: the schema digest stays a configuration and provenance matter (ADR-0051 D5).
  For `pedersen-jubjub-bytes-v1` the envelope is 1 + 1 + 24 + 32 = 58 bytes.
- **Two separate scalar checks.** They must not be conflated:
  1. **Canonical residue (always).** Every scalar used as a residue — the scalar message `m`,
     each vector component `v_i`, and every blinding `r` — is an integer in `[0, q)`, rejected
     otherwise rather than reduced. For the byte kind the scalar is never an input: it is the
     hash output `s`, which the verifier recomputes and which is in `[0, q)` by construction.
     The canonical rule therefore accepts `q − 1` and rejects `q`, `q + 1` and `−1`.
  2. **Application range bound (only when requested).** An application that reads `m` as an
     amount additionally requires `m < 2^k` for its chosen `k`. This is a policy check on top of
     (1) and may reject a valid residue. For vectors issued under a schema, the schema's
     widths are this bound, so `v_i < min(2^{k_i}, q)`. No range bound applies to `r` or to a
     byte-derived `s`.
  3. **Derived commitments.** A sum or difference of commitments (`add`, `subtract`) opens to
     component-wise residues that may exceed the schema widths. Its opening is checked with
     (1) only, unless the application declares a widened bound derived by ADR-0051 D3a: for
     `n` added terms, component `i` gets `k_i + ⌈log₂ n⌉` bits, and the policy is rejected when
     it is configured if any `2^{k_i + ⌈log₂ n⌉} > q`. That bound replaces the schema widths. The strict adapter therefore takes the bound policy
     explicitly — schema widths (issued commitments), residue only, or a declared widened
     bound — and never infers it. A difference with a negative component opens to the residue
     `q − x`, which only (1) accepts. The legacy `verify` keeps rejecting over-width values.
- **Canonical opening encodings.** At every serialization boundary (vectors, delivery
  formats, redeemers, cross-language interchange) openings satisfy check (1), (2) where the
  application or schema sets a bound, and for vectors the configured bound policy of (3). `I2OSP` is unsigned big-endian, as in the note
  plaintext (`confidential-note-jubjub-v1` §3.1).

  | Kind | Opening encoding |
  |---|---|
  | `scalar` (Jubjub) | `I2OSP(m, 32) ‖ I2OSP(r, 32)` |
  | `scalar`, `bytes` (G1) | defined by #95's spec for its group order and encodings |
  | `bytes` | `I2OSP(r, 32)`; the payload travels separately as its exact octets (no transcoding, no implied length beyond its own framing) |
  | `vector` | `u8(n) ‖ I2OSP(v_0, 32) ‖ … ‖ I2OSP(v_{n−1}, 32) ‖ I2OSP(r, 32)`, with `n` equal to the configured schema's dimension and each `v_i` within the configured bound policy (check 3; schema widths `v_i < min(2^{k_i}, q)` for issued commitments) |

  The existing legacy Java methods keep their behaviour (D5, Compatibility); the canonical
  rule applies to new typed entry points and every wire format. A non-canonical opening such
  as `(m + q, r)` satisfies the group equation; accepting it at a boundary that later reads
  `m` as an integer is a wraparound bug.
- **Public deltas and coefficients (V3).** They are public application values, not opening
  scalars, and are validated separately:
  - A **delta** `δ` (as in `C_new = C_old + [δ]·G`) travels as a signed integer with an
    application bound `|δ| < 2^{k_δ}`, `2^{k_δ} ≤ q`. Its residue is `δ mod q`. A validator
    computes `[|δ|]·G` with a canonical scalar and negates the resulting point when `δ < 0`; it
    never passes a negative or out-of-range integer to a builtin.
  - **Coefficients** of a sum are small non-negative integers fixed by the verifier or
    validator, never supplied by the prover (ADR-0051 D3a). A negative coefficient moves its
    term to the other side.
- **On-chain scalar rule.** CIP-0381 does not specify how `scalarMul` treats out-of-range or
  negative integers. CIP-0133 says only that MSM scalars are reduced modulo the group order
  before blst is called, and requires non-empty, equal-length inputs. A validator therefore
  applies check (1) to every opening scalar it receives, check (2) only where its application
  asks for a numeric range, and the delta rule above, before any builtin sees the value. For
  a G1 byte opening it recomputes `s` itself, or (scalar-only mode, D7) applies check (1) to
  the supplied scalar. #95 adds vectors that pin the builtins' observed behaviour as evidence,
  never as the guard.

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
    CommitmentGroup group();
    int pointEncodingLength();
}

public interface Commitment {                     // a validated point under one profile
    CommitmentProfile profile();
    byte[] toPointBytes();                        // fresh copy of the raw encoding
}

public interface CommitmentCodec<C extends Commitment> {   // the expected profile's decoder
    CommitmentProfile profile();
    Class<C> commitmentType();                    // exact concrete class, for the D2 runtime check
    C decodePoint(byte[] rawPoint);               // strict: canonical, subgroup, identity policy
}

public final class CommitmentKey {               // profile id + raw point (+ schema digest); value equality
    public static <C extends Commitment> CommitmentKey of(C c, CommitmentCodec<C> expected);
}

public final class CommitmentEnvelope {           // D4
    public static byte[] encode(Commitment c);    // producer side: trusts its input
    public static <C extends Commitment> C decode(byte[] envelope, CommitmentCodec<C> expected);
}
```

- **No arithmetic on the shared interfaces.** `add`, `subtract` and `negate` live only on
  concrete types and take the same concrete type (D2).
- **Equality is not part of the contract.** Existing types differ
  (`PedersenBytesCommitment` compares encodings, `PedersenVectorCommitment` compares
  references) and keep their behaviour (I10). Generic code — deduplication, map keys, replay
  sets — never relies on `equals`/`hashCode` of a `Commitment`. It uses
  `CommitmentKey.of(c, expectedCodec)`, a value type over the profile identifier, the raw
  point encoding and, for vectors, the schema digest (the same point under two schemas is two
  different commitments). `of` takes the expected codec from the caller's trusted
  configuration and applies the same D2 runtime check: `c`'s concrete class must equal
  `expectedCodec.commitmentType()` and `c.profile()` must be the codec's descriptor by
  identity; for vectors, `c`'s schema must equal the codec's schema. Anything else is rejected,
  so a foreign implementation cannot forge a key for a replay or deduplication set.
  `zeroj-api` therefore needs no registry of implementations, no `ServiceLoader` and no
  native-image configuration.
- **Openings are not records.** Opening holders are final classes with a redacted
  `toString`, no `equals`/`hashCode` on secret fields and no `Serializable`. `BigInteger`
  values cannot be wiped; the Javadoc says so, as ADR-0058 does.
- **Legacy methods keep their exact behaviour** (I10), which differs by profile:
  - `PedersenCommitment.commit`/`verify` reduce both scalars mod `l`, negatives included.
  - `PedersenVectorCommitment.commit` validates each value against its schema width and
    reduces the blinding mod `l`. `verify` returns `false` for a missing list, a wrong
    dimension, a null, negative, over-width or `≥ l` value, reduces the blinding mod `l`, and
    throws only for a null blinding. Consequently `verify(values, l + r)` succeeds wherever
    `verify(values, r)` does (reviewer probe at `45242fd`: `verify([1], q) = true` for
    `C = commit([1], 0)`).
  - The byte methods (ADR-0058) already require canonical `r` and throw on malformed input.
- **Strict adapters for the new contracts.** The new entry points never delegate unchecked
  input to a legacy method. Each validates first, then delegates:
  - scalar (Q2): nulls, then `m` and `r` in `[0, l)`;
  - vector: nulls, dimension equal to the configured schema's, each `v_i` in `[0, l)` and
    within the explicit bound policy of D4 (schema widths by default for issued commitments),
    `r` in `[0, l)`;
  - bytes: the existing ADR-0058 contract.

  Malformed input throws `IllegalArgumentException` (the D6 error classes), and a well-formed
  mismatch returns `false`. Paired tests show the strict rejection next to the unchanged legacy
  result for the same input. The Java spelling is fixed in M0.
- **Verification outcomes.** A new `CommitmentCheck` result,
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
mismatches, and an opening for the wrong message. JuLC consumers (from #95, G1 profiles
only) load the same files in their VM tests. A validator can only succeed or fail, so on-chain
every error class and `OPENING_MISMATCH` map to "script fails". JuLC vector tests assert
failure for every negative case and success for every positive one; they do not, and cannot,
distinguish error classes. Off-chain implementations must match the error class.

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
| `pedersen-bls12-381-g1-v1` (#95) | V1 opening | Planned | Planned native: canonical-residue checks on `m` and `r` (D4 check 1), an amount bound only if the application asks (check 2), then `uncompress`, two `scalarMul` or one non-empty MSM, `add`, `equal` | message and `r` |
| | V3 relation | Planned | Planned native: `C_new = C_old + [δ]·G` with the D4 signed-delta rule; sums with verifier-fixed coefficients | deltas |
| | V4 proof | Sigma proofs blocked by ADR-0051 D7; range proofs by #96 | Blocked / feasibility only (#96) | — |
| `pedersen-bls12-381-g1-bytes-v1` (#95) | V1 opening | Planned | Native only if the validator recomputes the byte mapping with `sha2_256`. The payload limit is whichever binds first: the execution budget (`sha2_256` and byte-string costs grow with payload length, against `maxTxExecutionUnits`), or the size of the place the payload comes from (redeemer, datum, or an inline datum on a reference input, each bounded by the 16,384-byte `maxTxSize` of the transaction that carries it). #95 measures and documents that limit. The recomputed `s` is canonical by construction and gets no amount bound. A validator that accepts a supplied scalar instead (after check 1) authenticates **only that scalar**, not the bytes | payload (or scalar) and `r` |

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
- **Byte mapping on-chain costs scale with payload size.** The usable payload is bounded by
  the execution budget and by the size of the redeemer, datum or reference-input inline datum
  that carries it, whichever binds first; #95 measures which. Larger documents can only be
  committed and opened off-chain; on-chain references them by commitment.

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

- **I1 — Registry and bases.** Every commitment profile and proof protocol ZeroJ ships has
  a registry entry; every identifier matches the D1 grammar and is never reused; a
  profile's cryptographic core and a protocol's transcript never change under an existing
  identifier, while lifecycle metadata changes only by reviewed registry revision; every
  basis set satisfies the D1 basis rule, and the existing sets (including the pinned
  `pedersen-jubjub-v1` `G`) are unchanged. (D1)
- **I2 — Expected profile.** No API or validator selects a profile, kind or schema from
  untrusted input; envelope and label mismatches reject; label agreement is never treated as
  provenance. (D3, D4)
- **I3 — No cross-profile arithmetic.** Homomorphic operations accept only the same
  concrete profile type; byte commitments expose none. (D2, D5)
- **I4 — Strict decoding.** Every decoder accepts exactly one encoding per point, enforces
  subgroup membership, applies its profile's identity policy, and never cofactor-clears a
  received point. (D4)
- **I5 — Canonical scalars at boundaries.** Every wire format and new typed entry point
  rejects opening scalars outside `[0, q)` (check 1) and applies an amount or schema bound
  (check 2) only where the application or schema sets one, never to `r` or to a byte-derived
  `s`. Public deltas follow the signed-delta rule. On-chain validators perform these checks
  before any builtin sees the value. Legacy methods keep their behaviour; new entry points
  validate before delegating. (D4, D5)
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
- **I11 — Provider and environment parity.** Every implementation of a profile passes the
  same vector file: off-chain implementations (pure Java, blst) return the same verdicts and
  error classes; JuLC implementations, which exist only for profiles with native on-chain
  support (the G1 profiles of #95, not the Jubjub profiles), return the same accept/fail
  verdicts under the D6 on-chain mapping. (D5, D6)

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
- Legacy opening behaviour is preserved exactly, including the cases the new contracts
  reject: numeric `commit`/`verify` reduce any integer mod `l`; `PedersenVectorCommitment`
  `commit`/`verify` reduce the blinding mod `l`, and `verify` returns `false` (rather than
  throwing) for malformed value lists. Only the new strict adapters (D5) reject these inputs.
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
| M0 — Registry spec | ADR accepted by a named human maintainer (Q1–Q4 decided in r2) | `docs/specs/commitment-profiles-v1.md`: D1 grammar, core records, lifecycle metadata, basis sets and admission/update rules for the three Jubjub profiles, the two reserved names, the proof-protocol record format, D2 kinds, D3 classes, D4 envelope and opening encodings, D6 format with its error classes, D7 matrix, D8 methodology. Exit: sign-off by a named human maintainer before any code; Claude and Codex reviews are additional input, not the gate. Covers I1, I2, I5–I7 |
| M1 — Contracts and adapters | M0 signed off | `org.zeroj.api.commitment`; adapters for the three profiles; typed `pedersen-jubjub-v1` commitment and `commitScalar`/`verifyScalar` (Q2); strict validating adapters for the scalar and vector openings, with paired legacy-behaviour tests (D5); envelope codec (Q1); composed acceptance helper. API-surface tests (no records, no public raw constructors, no shared arithmetic). Covers I2–I5, I8, I10 |
| M2 — Vectors | M1 | Python references extended to emit D6 files for the three profiles, with provenance; Java loader runs every positive and negative case; mutated-file self-test. Covers I4, I5, I9, I11 |
| M3 — Documentation | M2 | Registry and matrix on the docsite and in the gadget/support matrix; API examples for scalar, bytes, opening and relation checks; editorial, non-normative pointers from `pedersen-jubjub-v1` §3.2, `pedersen-jubjub-bytes-v1` §6 and ADR-0058 to the D3 timing qualification of V1 (no change to their constants, encodings or algorithms); maturity unchanged. Covers I6, I7 |

#95 and #96 consume this ADR: each adds its registry entry, vector file, matrix cells and D8
measurements as part of its own milestones.

## Verification and test strategy

- **Registry (M0):** every listed identifier matches the grammar; every core record links a
  spec section that exists; reserved names have no parameters; the `pedersen-jubjub-v1` basis
  entry reproduces the pinned `G` and `H` and the byte profile references that set rather than
  a derivation of its own.
- **Envelope (M1, M2):** round trip for every profile; rejection of each malformed case in
  D4, including an identifier differing in one byte and a vector or byte commitment decoded
  as the numeric profile; a fuzz pass over random byte strings with no exception other than
  the documented ones.
- **Profile substitution (M1):** an acceptance helper configured for
  `pedersen-jubjub-bytes-v1` rejects a matching envelope labelled `pedersen-jubjub-v1`, and a
  test shows the numeric equation for `H(B)` still holds on the raw point — demonstrating that
  only configuration and provenance separate them (ADR-0058 D4).
- **Canonical scalars (M1, M2):** `m` and `r` at `q − 1` accepted as residues; `q`, `q + 1`
  and `−1` rejected at every new entry point and decoder. With an amount bound `k` configured,
  `2^k − 1` accepted and `2^k` rejected even though it is a valid residue. Byte openings apply
  no amount bound to the recomputed `s`. Vectors: wrong dimension, `v_i = 2^{k_i}` and
  `r = l` rejected by the strict adapter. Paired legacy tests: the numeric
  `commit`/`verify` still reduce these inputs, and `PedersenVectorCommitment.verify` still
  returns `false` for malformed values and accepts `r + l`. #95 repeats the residue and bound
  cases across Java and JuLC, plus negative deltas, and an empty or unequal-length MSM input
  that must fail.
- **API surface (M1):** reflection tests: no shared arithmetic, opening types are final,
  not records and not `Serializable`, and their `toString` does not contain any scalar.
- **Generic paths (M1):** a test-only `Commitment` implementation that claims the byte
  profile is rejected by the runtime check (wrong concrete class) and by the acceptance
  helper; `CommitmentKey` distinguishes the same point under the numeric and byte profiles and
  under two vector schemas, is equal for equal inputs regardless of the types' own
  `equals`, and `CommitmentKey.of` rejects the test-only foreign implementation, a commitment
  of another profile, and a vector commitment whose schema differs from the codec's.
- **Derived vector openings (M1, M2):** for a schema with different per-component widths, the
  sum of two commitments with a component of `2^{k_i}` or more is rejected under the
  schema-width policy, accepted under the residue-only policy and under the declared
  per-component `k_i + 1`-bit widened policy, and serializes under that policy; the legacy
  `verify` still rejects it. A widened policy for a 252-bit component with `n = 2` is rejected
  at configuration (`2^253 > l`).
- **Registry namespace (M0):** an identifier already used by a profile, proof protocol or basis
  set (including a withdrawn one) is rejected at admission; every basis-set identifier differs
  from every profile identifier; `a-v1` is the shortest valid
  identifier.
- **On-chain mapping (#95):** every negative vector makes the JuLC validator fail and every
  positive one succeeds.
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
- **r3 (2026-10-16; responds to review of `45242fd734dfe5d67b6ea309fed64ab120fec609`):**
  F1 → D4 separates the always-applied canonical-residue check from an application amount
  bound, exempts `r` and byte-derived `s` from amount bounds, and adds the signed-delta and
  verifier-fixed-coefficient rules for V3 (D4, D7, I5, tests); F2 → the generator rule becomes
  a basis-set rule that preserves the pinned `pedersen-jubjub-v1` `G`, lets reviewed profiles
  reference an existing set, and requires domain separation only for newly derived bases (D1,
  I1, tests); F3 → D1 splits an immutable cryptographic core from maintained lifecycle
  metadata and from separately versioned proof-protocol records with immutable transcripts
  (D1, D3 proof-context binding, I1, M0); F4 → D5 documents the actual legacy numeric and
  vector behaviour and requires strict validating adapters with paired tests (D5,
  Compatibility, M1, tests); F5 → CIP-0381 and CIP-0133 pinned at
  `86b89208d3b2aabb5dcc5b778dfbe09096b4e114` with section-level quotes, and deployment
  observations separated from normative definitions (references, D4).
- **r4 (2026-10-16; responds to a second, independent review of
  `2e51e047687ff0fdc131cd904f96a701c709e357`, supplied by the maintainer):** A1 → acceptance
  and the M0 exit gate require a named human maintainer; AI reviews are input only (Status,
  milestones). A2 → variable-time V1 only for public openings or unobservable verifiers,
  otherwise the V2 restriction applies (D3). Derived vector commitments get an explicit bound
  policy: schema widths, residue only, or a declared D3a widened bound (D2, D4, D5, tests). One
  shared identifier namespace for profiles, proof protocols and basis sets, and length 4–64
  (D1, tests). Equality is not part of the contract; generic code uses `CommitmentKey` (D5,
  tests). The runtime profile check compares concrete class and descriptor identity; the
  envelope encoder trusts its input (D2, D5, tests). On-chain error classes map to script
  failure, and JuLC parity covers only natively supported profiles (D6, I11, tests). The G1
  byte-opening limit is the tighter of the execution budget and the carrying data's size (D7).
  Nits: duplicate enum comment, `public` statics, G1 opening encodings deferred to #95,
  encoding length no longer cited as a mixing guard. No algorithm, constant or encoding
  changed.
- **r5 (2026-10-16; responds to the same reviewer's re-review of
  `9952630e8f809655c4cbebb057a3ac6ce3dcd5e9`):** the vector opening-encoding row and its
  paragraph now follow the check-3 bound policy (D4); `CommitmentCodec` gains
  `commitmentType()` for the runtime check (D5); the widened bound is per component,
  `k_i + ⌈log₂ n⌉`, rejected at configuration if it reaches `q` (D4); `CommitmentKey.of`
  applies the runtime check and rejects foreign implementations (D5); M3 adds non-normative
  pointers to the A2 timing qualification in the numeric and byte specs and ADR-0058, and M0
  gives existing basis sets identifiers distinct from profile names (D1, references, M3).
  No algorithm, constant or encoding changed.
- **r6 (2026-10-16; responds to the same reviewer's re-review of
  `62cde750846560371c272d5617eb6a9a0e31b096`):** `CommitmentKey.of(c)` could not know which
  implementations are ZeroJ's own, because `zeroj-api` has no dependencies. It becomes
  `CommitmentKey.of(c, expectedCodec)`, which reuses the D2 class-and-descriptor check (plus
  schema equality for vectors) and needs no registry, `ServiceLoader` or native-image
  configuration (D5 sketch and text, tests). No algorithm, constant or encoding changed.
- **r7 (2026-10-17):** Status → Accepted (design) by maintainer Satya, who directed
  implementation. Review evidence recorded in Status, including that Codex has not
  re-reviewed r4–r6. No design change.
