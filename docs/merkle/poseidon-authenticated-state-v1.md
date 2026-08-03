# ZeroJ Poseidon authenticated-state profiles v1

This document is the executable-format companion to ADR-0042. Numeric domains,
byte order, field canonicality, tree commitments, proof normalization, circuit
statements, and manifest identities in this document are compatibility rules.
Changing any of them requires a new profile identifier and new vectors.

## Shared cryptographic parameters

Both profiles use the BLS12-381 scalar field and ZeroJ's reviewed Poseidon
`t=3`, `alpha=5`, `R_F=8`, `R_P=57` parameter bundle. Its compatibility
fingerprint is:

```text
4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2
```

The v1 fingerprint preimage is, exactly, `u32(len(tag)) || tag ||
u32(len(curve)) || curve || u32(t) || u32(alpha) || u32(rf) || u32(rp) ||
u32(len(modulus)) || modulus || C || M`. The tag is
`zeroj-poseidon-parameter-fingerprint-v1`; strings are ASCII; integers are
big-endian; modulus/C/M elements use the modulus byte width; and C/M counts
are derived from `t/rf/rp`. The old constants-only fingerprint beginning
`3920ef...` is migration metadata only.
Field elements are encoded as exactly 32 unsigned big-endian bytes. Decoders
MUST reject a value greater than or equal to the scalar modulus; reduction is
not decoding. Key paths use the high nibble and then the low nibble of each
key-hash byte, yielding exactly 64 nibbles, each constrained to `[0, 15]`.

Let `Permute([s0,s1,s2])` be the following exact 65-round (`R_F=8`,
`R_P=57`) permutation. Number rounds `r=0..64`. First add round constant
`C[3*r+j]` to state cell `j`, modulo the field. In rounds `0..3` and
`61..64`, replace all three cells by `x^5`; in rounds `4..60`, replace only
cell zero by `x^5`. Finally replace each output cell `i` by
`sum(M[3*i+j] * state[j], j=0..2)` modulo the field. The next round receives
that complete MDS output. The authoritative literal `C` and row-major `M`
arrays are in
[`PoseidonParamsBLS12_381T3.java`](../../zeroj-circuit-lib/src/main/java/com/bloxbean/cardano/zeroj/circuit/lib/poseidon/PoseidonParamsBLS12_381T3.java);
that file is generated from the Poseidon reference Grain LFSR at hadeshash
commit `208b5a164c6a252b137997694d90931b2bb851c5`. The fingerprint binds those
exact arrays and all generation parameters.

Define
`P(capacity,left,right) = Permute([capacity,left,right])[0]`. Define ZeroJ's
variable-arity `H` only as follows: `H(x) = P(0,x,0)`;
`H(x1,x2) = P(0,x1,x2)`; and, for `n > 2`, start with
`a = P(0,x1,x2)` and replace `a = P(0,a,xi)` for `i=3..n`, returning `a`.
There is no implicit length or delimiter in `H`; every variable-length use
below includes its length explicitly. Lengths are field elements. Raw bytes
are packed as unsigned big-endian integers; 31-byte raw chunks are always
canonical field elements.

The ASCII curve string in the parameter-fingerprint preimage is exactly
`BLS12_381` (including the underscore and uppercase letters). `C` is the
`(R_F+R_P)*t = 195` row-major round constants, followed by the `t*t = 9`
row-major MDS elements in `M`; each uses exactly 32 unsigned big-endian bytes.

## MPF profile

Profile identifier: `zeroj-poseidon-mpf-v1`.

This is a metadata rename of the unreleased `zeroj-poseidon-mpf-v2` benchmark
alias. All numeric domains and commitments are unchanged:

| Purpose | Field domain (hex) |
|---|---:|
| fixed internal byte digest | `0x5a4d5046` |
| leaf | `0x5a4d5047` |
| key-path commitment | `0x5a4d5048` |
| key-path nullifier | `0x5a4d5049` |
| total raw-byte fallback | `0x5a4d504a` |

For an input accepted by the fixed internal encoding, the digest is
`H(DOMAIN_BYTES, byteLength, chunk0, chunk1, chunk2)`. Chunking follows the
following exact rule. Let `r = byteLength mod 32`. If `r != 0`, `chunk0` is
the first `r` bytes interpreted unsigned big-endian; the remaining bytes are
split left-to-right into 32-byte unsigned big-endian scalars. If any 32-byte
scalar is at least the modulus, or the resulting list has more than three
elements, the fixed encoding is unavailable. Otherwise append scalar zeroes
on the right to exactly three chunks. The fallback is
`H(DOMAIN_RAW_BYTES_V1, byteLength, chunk31...)`, where the complete input is
split left-to-right into consecutive 31-byte chunks (the last may be shorter)
with no implicit trailing chunk. Thus empty fallback input is never selected.

An MPF leaf commits its remaining Patricia suffix (zero to 64 nibble-bytes),
split into 31/31/2-byte chunks, and value digest:

```text
H(DOMAIN_LEAF, suffixLength, suffix0, suffix1, suffix2, valueDigest)
```

An MPF radix branch is a four-level binary tree over exactly sixteen child
digests. A null child is the canonical 32-byte scalar zero; an empty byte
array is also treated as null by CCL compatibility code, while every nonempty
child must be exactly 32 bytes and canonical. Each ordered binary pair is:

```text
pair(left,right) = H(DOMAIN_BYTES, 64, left, right, 0)
```

where `left` and `right` are decoded canonical fields. Pair `(0,1)`, `(2,3)`,
and so on, repeating left-to-right for four levels. Let the final field be
encoded as 32 bytes `subroot`. The branch commitment is the MPF byte digest
defined above over `prefixNibbleBytes || subroot`, where every prefix byte is
exactly one nibble in `[0,15]`. An extension commitment is the same byte
digest over `extensionNibbleBytes || childDigest`. This ordering and the
leading-remainder chunk rule are part of the root format.

## JMT profile

Profile identifier: `zeroj-poseidon-jmt-v1`.

CCL persistence descriptor:

```text
profileId       = zeroj-poseidon-jmt-v1
hashAlgorithmId = zeroj-poseidon-bls12-381-t3-a5-jmt-v1
hashLength      = 32
proofCodecId    = ccl-classic-jmt-proof-cbor-v1
```

JMT domains use ASCII `ZJMT` followed by a 16-bit purpose code:

| Purpose | Field domain (hex) |
|---|---:|
| fixed byte digest | `0x5a4a4d540001` |
| total raw-byte fallback | `0x5a4a4d540002` |
| empty child | `0x5a4a4d540003` |
| leaf | `0x5a4a4d540004` |
| binary branch levels 0..3 | `0x5a4a4d540010` .. `0x5a4a4d540013` |
| key-path/application binding | `0x5a4a4d540020` |
| transition/batch binding | `0x5a4a4d540030` |

JMT byte hashing uses the same fixed-versus-total chunking rule as MPF with
the JMT-specific byte domains. The empty child is `P(DOMAIN_EMPTY, 0, 0)`. A leaf
binds the complete canonical 32-byte key hash and value hash:

```text
leaf = P(DOMAIN_LEAF, keyHash, valueHash)
```

A branch has sixteen logical child slots. Missing slots are the fixed empty
commitment. Starting at the child level, adjacent nodes are combined four
times:

```text
pair(level, left, right) = P(DOMAIN_BRANCH_LEVEL_level, left, right)
```

Here `P(capacity, left, right)` is one Poseidon permutation with the domain in
the capacity cell and the two inputs filling the rate. This fixed-arity form
avoids the two-permutation cost of a three-element left-fold. The result after
level 3 is the branch commitment. A normalized proof carries
four siblings per branch in bottom-up order. Bit `level` of the child nibble
selects whether the running digest is left or right.

CCL dev1 deliberately passes an empty prefix while creating stored branch
hashes and a proof prefix while object-verifying them; its wire verifier also
uses an empty prefix. Therefore `zeroj-poseidon-jmt-v1` branch commitments are
prefix-independent. Circuit witnesses still constrain the ordered branch
cursor/skip and child nibble against the complete leaf key so that they prove
the CCL lookup statement, not merely an arbitrary Merkle path.

MPF and JMT domains, leaf formats, empty values, and branch formats are
different. No root conversion or profile alias is defined.

The proof codec identifier freezes CCL dev1's `ClassicJmtProofCodec` bounded
CBOR wire grammar for v1 vectors. It is profile metadata alongside (not inside)
`JmtFormatDescriptor`, whose API stores only profile/hash/length identity.

## Proof normalization invariants

All bounded witnesses obey these rules:

1. valid entries form one prefix and padding forms one suffix;
2. every kind/valid/index/length value is range constrained;
3. the cursor advances monotonically and never beyond 64 nibbles;
4. an inclusion path consumes the complete path expected by its profile;
5. padding has zero canonical fields and never changes the running digest;
6. a witness deeper than its circuit bound is rejected before proving;
7. proof-form selection is compile-time (separate circuit), not an
   attacker-controlled inclusion/non-inclusion flag; and
8. every field decoded from 32 bytes is canonical rather than reduced.

In addition, a JMT v1 branch step at array index `i` MUST have prefix length
exactly `i`, its prefix MUST equal query-path nibbles `0..i-1`, and its child
index MUST equal query-path nibble `i`. JMT v1 has no compressed or skipped
branch levels. Merely increasing prefix lengths is unsound because JMT v1
branch commitments are prefix-independent; it can turn an unrelated empty
child into a forged absence statement.

## P0/P1 primitive statements and schemas

The reusable gadgets are visibility-neutral. The standalone schemas below
use only roots as public inputs unless the statement must also bind an
application-selected commitment, as the tombstone primitive does.
Applications normally add a key/value commitment, nullifier, owner, version,
or transaction binding.

| Template family | Public fields, in order | Private witness | Soundness statement |
|---|---|---|---|
| `zeroj-mpf-v1-inclusion-sN-p1` | `root` | normalized inclusion path, value commitment | some canonical MPF v1 key path maps to the value commitment under `root` |
| `zeroj-mpf-v1-non-inclusion-empty-sN-p1` | `root` | query path and authenticated empty-child path | the query path reaches an authenticated empty child under `root` |
| `zeroj-mpf-v1-non-inclusion-different-leaf-sN-p1` | `root` | query path, conflicting leaf and authenticated path | an authenticated different leaf proves the query path absent; terminal forks fail closed |
| `zeroj-mpf-v1-value-update-sN-p2` | `oldRoot,newRoot` | one key path, old/new values, shared path | only the value commitment at the authenticated path changes |
| `zeroj-mpf-v1-insert-empty-sN-p2` | `oldRoot,newRoot` | authenticated empty-child absence plus canonical rewrite | insertion into an authenticated empty child transforms the roots |
| `zeroj-mpf-v1-insert-different-leaf-sN-p2` | `oldRoot,newRoot` | authenticated conflicting leaf plus canonical rewrite | insertion beside an authenticated different leaf transforms the roots |
| `zeroj-jmt-v1-inclusion-sN-p1` | `root` | canonical full key/value hashes and path | the complete key hash maps to the value hash under `root` |
| `zeroj-jmt-v1-non-inclusion-empty-sN-p1` | `root` | query key and empty-terminal path | the query route reaches the authenticated empty commitment |
| `zeroj-jmt-v1-non-inclusion-different-leaf-sN-p1` | `root` | query key, conflicting full leaf and path | a different authenticated full key occupies the terminal route |
| `zeroj-jmt-v1-value-update-sN-p2` | `oldRoot,newRoot` | key, old/new values and shared path | exactly one authenticated leaf value changes |
| `zeroj-jmt-v1-insert-empty-sN-p2` | `oldRoot,newRoot` | authenticated empty-terminal absence plus rewrite | insertion of the supplied full-key leaf at an empty terminal transforms the roots |
| `zeroj-jmt-v1-insert-different-leaf-sN-p2` | `oldRoot,newRoot` | authenticated conflicting leaf plus rewrite | insertion beside an authenticated different full-key leaf transforms the roots |
| `zeroj-jmt-v1-tombstone-update-sN-p3` | `oldRoot,newRoot,jmt_tombstone_value_hash` | key, live value and shared path | the live included value is replaced by the exact public tombstone commitment; the result remains inclusion, not absence |

`N` is the compiled maximum step count. Initial release candidates are MPF
S8/S9/S12 and JMT S8/S64. The release manifest, not the class name, is the
authority for the exact public-input order and R1CS fingerprint.

## Circuit manifest v1

Every setup/proof artifact is accompanied by a manifest conforming to
[`circuit-manifest-v1.schema.json`](circuit-manifest-v1.schema.json). A valid
manifest binds the structure profile, operation, bound, public schema,
Poseidon fingerprint, canonical R1CS digest, frontend dimension fingerprint,
proving system, curve, and verification-key digest. Dimension equality alone
is not a circuit identity.

`zeroj-r1cs-canonical-v1` identifies ZeroJ's implemented deterministic R1CS binary
digest preimage. The serializer, strict reader, streaming SHA-256 calculation,
tamper tests, and exact cache/key binding are implemented. An independent Python
parser/checker shares no JVM serialization code, reproduces the canonical digest,
and rejects relation tampering. The Java manifest validator nevertheless rejects
`productionApproved=true` unconditionally until an externally reviewed release
policy and exact-circuit ceremony are accepted.

The checker closes the local identity gate; it does not make benchmark setup
material production approved. Likewise, `productionApproved` is descriptive metadata, not trust:
deployment policy must authenticate and allowlist the complete manifest hash,
verification-key hash, and ceremony transcript hash.

The complete-manifest hash is SHA-256 over the versioned
`zeroj-circuit-manifest-json-v1` encoding. It is compact UTF-8 JSON with the
following top-level field order: `schemaVersion`, `templateId`,
`structureProfile`, `operation`, `maxSteps`, `publicInputs`,
`poseidonParameterFingerprint`, `r1csFormat`, `r1csSha256`,
`dimensionFingerprint`, `provingSystem`, `curve`, `verificationKeyFormat`,
`verificationKeySha256`, optional `provingKeyFormat`, optional
`provingKeySha256`, then `setupProvenance`. Each public-input object is
ordered `index,name,type,encoding`. Setup provenance is ordered
`kind,setupId`, optional `transcriptSha256`, then `productionApproved`.
Array order is preserved, there is no insignificant
whitespace, JSON lowercase booleans/decimal integers, and deterministic string
escaping: quote and reverse solidus use their two-character escapes; code
points U+0000 through U+001F use lowercase `\u00xx`; valid non-control Unicode
is emitted directly as UTF-8; unpaired surrogates are rejected. JSON object/map
iteration order is never part of the identity. The API test suite pins one
complete literal Base64 byte vector containing both optional fields and these
escaping cases, plus SHA-256
`ee8ea2bf894be5f6cfe0ec7b609cd441bb625bc4a0095095f5d01d828dd0025b`.

The two v1 structure profiles require Poseidon parameter fingerprint
`4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2`;
a syntactically valid different digest is invalid. In this release candidate,
`productionApproved` is exactly `false` in both the JSON schema and Java semantic validator.

`AuthenticatedStateCircuitManifest` performs semantic validation that JSON
Schema alone cannot: structure/operation/`sN`/`pN` components of the template
identifier must match the explicit fields and the dimension fingerprint.
Production approval additionally requires a multi-party ceremony transcript
digest.

## Groth16 Cardano bundle and deployment identity

`zeroj-cardano-groth16-bundle-v2` is SHA-256 over a domain tag followed by
length-prefixed bytes for the canonical circuit manifest, canonical encoded verification key,
compressed proof A/B/C, and each ordered canonical 32-byte public input. The proof point lengths
are fixed at 48/96/48 bytes; VK IC count must be public-input count plus one; and public scalars
must be below the BLS12-381 scalar modulus. The directory hierarchy is:

```text
cardano-artifacts/<templateId>/<exactR1csFingerprint>/
  vk-<verificationKeySha256>/bundle-<bundleSha256>/
```

The outer `zeroj-cardano-groth16-artifacts-v2` manifest repeats the complete canonical setup
provenance, names every public-input file in statement order, and hashes every identity-bearing
file. The optional Julc artifact test gate in `zeroj-onchain-julc/src/test` rejects
unknown/coercively typed fields, duplicate JSON keys, nested or escaping file names, symlinks,
omitted/extra files, digest/length drift, directory-identity drift, manifest/VK arity drift, and
non-canonical public inputs before evaluating the proof. It is a release/integration test reader,
not a published runtime artifact parser.

For two-root transitions, `zeroj-groth16-authenticated-state-deployment-v2` additionally binds:

- the audited exact unapplied validator UPLC SHA-256 and fixed Julc/Plutus V3 compiler profile;
- the audited canonical circuit-manifest SHA-256, exact R1CS fingerprint, and VK digest;
- state policy ID, token name, authorized signer, and an externally evidenced one-shot token
  genesis reference;
- the applied validator SHA-256, internally derived Cardano Plutus V3 script hash, and typed
  network identity; and
- a release ID embedded in the redeemer and applied validator parameters.

The validator enforces transaction-local conservation of exactly one state token, no mint/burn,
one continuing output at the same full address and value, inline `(newRoot, version+1)` state,
the authorized signer, release ID, and Groth16 public inputs `(oldRoot,newRoot)`. Global token
uniqueness cannot be inferred from one transaction, so deployment metadata explicitly records the
external one-shot-policy/supply-one attestation. Benchmark manifests cannot produce a mainnet
deployment manifest.

## Vector suite

`test-vectors/poseidon-authenticated-state-v1` contains literal vectors for:

- total raw hashing, including empty, non-canonical 32-byte, and long inputs;
- MPF leaf suffix boundaries and all sixteen branch positions;
- JMT empty, complete-key leaves, all sixteen branch positions, and roots;
- the MPF CCL root plus independently decoded/re-encoded branch-path
  inclusion, missing-branch, and different-leaf wire fixtures;
- CCL dev1 JMT multi-level object and wire proofs for inclusion and both
  non-inclusion forms, including all branch-neighbor metadata;
- a JMT single-neighbor object/wire case and a literal valid root-leaf
  different-leaf proof with zero branch steps;
- strict/trailing/non-canonical/oversized MPF wire failures and JMT statement
  type/depth-gap mutations; and
- canonical field-boundary and malformed child-count checks.

The MPF leaf suffix pattern is explicitly recorded alongside its vectors.
The Phase 0A commitment/MPF corpus and Phase 0B CCL dev1 JMT object, wire,
persistence, profile-mismatch, and negative corpus are present. Phase 2 adds
operation-specific circuit witness and R1CS vectors without changing these
profile vectors.

The literal vectors are checked both by the optimized profile implementation
and a small reference checker that uses generic `PoseidonHash` and reconstructs
the commitments without calling either structure adapter.
