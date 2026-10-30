# Experimental portable graph and symbolic recipe formats

Governed by [ADR-0064](../../docs/adr/0064-portable-circuits-and-typescript-frontend.md).
The promoted tags are deliberately distinct from the research tags. This is an experimental
versioned format, not a stable `.circuit` standard. Its compiled output can use the existing
iden3 `.r1cs` exporter; Circom source/witness programs do not consume this input format.

Canonical UTF-8 JSON has no whitespace and exactly this property order:

```json
{"format":"zeroj-graph","version":1,"compiler":"zeroj-r1cs-bls12381-v1","field":"bls12-381-fr","name":"multiplier","public":["product"],"secret":["x","y"],"wires":5,"gates":[["c",0,"1"],["m",4,2,3],["e",4,1]]}
```

Input arrays contain flattened names. IDs: 0 = one; then public inputs in declaration order,
then secret inputs in declaration order; all remaining IDs are intermediate wires. `wires`
counts all wires, including one. The first gate must be exactly `["c",0,"1"]`. This is the
existing builder's mandatory constant declaration, and the only permitted write to wire 0.
Every intermediate must be assigned once. Operations read only already assigned wires.
Names match `[A-Za-z_][A-Za-z0-9_-]{0,95}` and input names are unique across both visibilities.

| Opcode | Array | Existing ZeroJ meaning |
|---|---|---|
| c | `["c", out, "value"]` | Constant reduced to canonical Fr at export |
| a | `["a", out, left, right]` | Field addition |
| m | `["m", out, left, right]` | Field multiplication |
| e | `["e", left, right]` | Assert equality |
| b | `["b", wire]` | Assert boolean |
| l | `["l", out, [[wire,"coefficient"],...]]` | Ordered linear combination |
| h | `["h", out, "INVERSE", input]` | Existing hint enum; also IS_ZERO_RESULT, IS_ZERO_INVERSE |
| d | `["d", [outputs...], input, bits]` | Existing bit-decomposition witness hint |

`h` and `d` do not independently constrain their output. Imported graphs must retain the
gadget's surrounding equality/boolean/range constraints. A compiler accepts a relation;
it cannot determine whether that relation implements an application's intended policy.
Bare hints are therefore not automatically proof of an inverse, bit decomposition or range.
`HintN` and raw `Select` reject in v1. There is no `eval`, custom callback or Java deserialization
entry point. The image's compiler-generated runtime can contain Java deserialization machinery,
but the adapter accepts only the described JSON graph and existing cryptographic codecs.

Field values use nonnegative decimal strings, no sign/leading zero/exponent, and are strictly
less than BLS12-381 Fr. IDs/counts are integral JSON numbers. Duplicate/unknown fields,
trailing content, different key ordering, escaped alternative spellings and whitespace reject
through exact re-encoding. Parsing/re-encoding costs are explicitly measured as decode time.

The JSON parser has a depth cap of 12, strings of at most 128 characters, numeric tokens of at
most 8 characters, and an outer 16 MiB cap. Names/scalars have tighter semantic bounds.
Counts are validated before graph arrays are allocated; JSON tree parsing necessarily occurs
first. Detailed limits are in ADR-0064. These bounds are not a hard worker-heap reservation.

The graph has no witness values and no proving/VK bytes. Type widths are represented by the
generated constraints, not recovered as an ergonomic schema; higher-level metadata is carried separately in the recipe/export manifest. Shape parameters have already been expanded by the Java companion. Changing
them requires a newly exported graph, or a circuit factory built into Wasm (an alternative).

## Two identities

`graphSha256` hashes exact canonical graph bytes, including names and witness instructions.
`fingerprint` is ZeroJ's existing canonical R1CS content identity, including wire/public counts.
Different witness programs can describe the same constraints. Bind both identities plus the
compiler version and trusted key provenance in an application manifest. Do not allow the
prover to choose the verifier's verification key or to declare its own relation trusted.

## Symbolic recipe

```json
{"format":"zeroj-symbolic","version":1,"compiler":"zeroj-r1cs-bls12381-v1","field":"bls12-381-fr","name":"age_check","inputs":[{"name":"threshold","visibility":"public","type":"uint","bits":8},{"name":"age","visibility":"secret","type":"uint","bits":8}],"commands":[["u.gte",1,0],["b.assertTrue",2]]}
```

Root and input-record key ordering is canonical. Logical input symbols receive IDs in input
order, independent of their flattened wire count. Each value-returning command appends one
symbolic object to the table; assertions append none. References must point backward and have
the expected Java symbolic type. Bytes use names `base_0` through `base_(length-1)` and every
flattened name must be unique across public/secret input declarations. Public declarations
precede secret declarations. V1 types are field, bool, uint (bits 1..253) and bytes (length 1..64).

Commands call the existing Java methods; they do not carry constraint formulas or user code:

| Family | Operations |
|---|---|
| `f` | constant(decimal string), add/sub/mul/div(a,b), isEqual(a,b), assertEqual(a,b) |
| `u` | add/sub/mul, lt/lte/gt/gte/isEqual/assertEqual (a,b); inRange(value,lo,hi); asField(value) |
| `b` | and/or/xor/isEqual/assertEqual(a,b); not/asField/assertTrue/assertFalse(value); selectField/selectUInt/selectBool(condition,left,right) |
| `bytes` | get(value,index); isEqual/assertEqual(left,right) |
| `g` | poseidonBls12381T3(left,right); sha256(bytes) |

Operands other than constants/indexes are symbolic IDs. Invalid arity, type, width, profile or
forward reference rejects. Existing Java constraints determine UInt widening/underflow and
boolean soundness. SHA-256 is limited to one invocation with 1..55 input bytes in this version.
No raw signal wrapping, custom parameters or additional hints are exposed.

## Recipe v2: fixed arrays and Poseidon Merkle paths

Existing TS definitions still emit **identical v1 bytes**. Definitions using arrays or Merkle
emit version 2. Java accepts both versions, but v1 rejects v2 vocabulary. Graph version 1 and
compiler policy `zeroj-r1cs-bls12381-v1` are unchanged: the existing Java Merkle gadget expands
into already-admitted boolean, linear-combination, multiplication, addition and equality gates.

An array input uses this exact order (the outer recipe order is unchanged):

```json
{"name":"siblings","visibility":"secret","type":"array","element":{"type":"field"},"length":2}
```

Elements are `{"type":"field"}`, `{"type":"bool"}` or `{"type":"uint","bits":8}` with
UInt widths 1..253. Length is 1..64. Nested/byte arrays are excluded. One logical input ID
represents the array; flattened scalar names are `siblings_0`, `siblings_1`, etc. Public arrays
retain public declaration order. Logical names and flattened names must be unique, including
collisions with scalars/bytes. The existing 64 logical / 256 flattened input caps remain.

- `["a.get",arrayId,index]` returns one scalar symbol. The index is a literal nonnegative integer
  strictly below the declared length; witness-dependent indexing rejects.
- `["g.merkleRootBls12381T3",leafId,siblingsId,pathBitsId,depth]` returns one field symbol using
  `ZkMerkle.computeRootPoseidon` with `PoseidonParamsBLS12_381T3.INSTANCE`. The leaf is a field;
  siblings are fields; directions are booleans. Both array lengths must equal the explicit
  depth, which is 1..32. Arrays run from leaf to root: false = current node left, true = right.
  There is no implicit leaf hash, domain separator, document encoding or nullifier.

Only one Merkle invocation is admitted per recipe. Its preflight cost is 5,000 per explicit
level, then actual array lengths are checked before gadget expansion; callers cannot understate
work with a false depth. Array declaration cost accounts for every element and its UInt width.
The existing 180,000 expansion budget, four direct Poseidon calls and one SHA-256 call remain.
These work estimates are admission guards, not a proven bound on total heap use.

TS uses `array(field(), depth)`, `array(bool(), depth)` or `array(uint(bits), depth)`, read-only
`.length`, and `.get(index)`. Input arrays are ordinary exact-length arrays of bigint/boolean;
values, ranges and sparse arrays are checked. Frozen copied descriptors and recorder ownership
prevent shape mutation or cross-definition symbolic handles. Java independently checks the
untrusted recipe and the existing constraints enforce ranges/booleans. Application manifests
still authenticate the exact expanded graph and R1CS fingerprint before private inputs.

## Consumer worker protocol

Prefer `@zeroj/circuit` to raw calls. The selected image supplies capabilities `circuit` and
`groth16-verifier` in one heap. Every compilation is bound to an application-trusted expected
graph hash and R1CS fingerprint, not a self-authenticating hash supplied by an arbitrary prover.

1. Recipe path: `compileRecipe({recipe,expectedGraphSha256,fingerprint})`.
2. Graph path: `beginGraph({length,expectedGraphSha256,fingerprint})`, sequential
   `appendGraph({offset,text})` with 1..200,000 characters, then `compileGraph({})`.
3. Either compilation returns a compiled handle, public identity/dimensions/layout and timings.
   Only one compilation attempt is admitted per worker; create a fresh runtime for another.
4. `checkWitness({circuit,input})` checks constraints and returns only a boolean/timings.
   It requires secret opt-in. No witness or witness digest crosses the consumer boundary.
5. `beginKey({circuit,fingerprint,length,expectedSha256,verificationKey})` returns `upload` and
   `chunkBytes` (65,536). Length is 1..2,097,152 raw bytes. `appendKey({circuit,upload,offset,chunk})`
   accepts 1..65,536 lowercase-hex-encoded bytes at the exact byte offset. A valid owned-upload
   request with bad chunk/offset terminates that upload; requests rejected before ownership is
   established cannot cancel another upload. Malformed outer JSON cannot dispatch cleanup.
   `finishKey({circuit,upload})` consumes the upload, requires exact completion, checks the hash
   before parsing and invokes the unchanged cryptographic importer/relation validator. It returns
   a key handle and public import timings/domain/byte count. `abortKey({circuit,upload})` abandons
   the upload. Both successful and failed finish are terminal; retries need a new upload.
   One active upload and one successfully imported key per compiled circuit. An explicit raw
   release of the upload handle also drops its buffer. Key release does not reset the one-key slot.
   `keyResources({circuit})` returns exact staging/reservation counters, not heap usage.
   Small direct `loadKey({circuit,fingerprint,zkey,expectedSha256,verificationKey})` requests remain
   compatible at the original 256 KiB cap and share the single-key slot. `prove({circuit,key,input})`
   checks ownership and self-verifies before returning a proof and public inputs.
6. Typed `compiled.dispose()` releases the circuit and its keys. Runtime disposal/timeout
   terminates the worker and invalidates local handles. No secure-erasure claim is made.

Wasm compilation is not Java source compilation. Gadget implementations are compiled into the
selected image; a recipe selects those implementations. Arbitrary graphs require application
review: accepting a graph does not certify that every intended relation was constrained.
