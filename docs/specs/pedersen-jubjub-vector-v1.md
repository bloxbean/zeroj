# ZeroJ Pedersen-Jubjub Vector v1 — Normative Specification

**Profile identifier:** `pedersen-jubjub-vector-v1`
**Status:** Candidate. This is the ADR-0051 M3 entry gate: it must be reviewed before any M3
code lands.
**Date:** 2026-10-03

This document defines a Pedersen commitment to up to 16 values at once on Jubjub, together with
the schema, statement and provenance rules ADR-0051 D5 and invariant I11 require. Anything not
written here is not part of the profile. Changing any value, tag or encoding produces a
different profile and requires a new identifier.

The curve, field and point encoding are those of [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md)
§1 and §4, including ZIP 216 canonical decoding. This profile shares no base with
`pedersen-jubjub-v1`.

---

## 1. Group hash (Zcash `FindGroupHash^J`)

Bases are derived with the Zcash Sapling group hash into Jubjub: Zcash Protocol Specification
v2026.7.0 [NU6.2], §5.4.9.5 "Group Hash into Jubjub", as implemented by `zcash/sapling-crypto`
0.9.0 (commit `adaeb7aadd491de66185cc963bce9e92090d300d`), `src/group_hash.rs` and the
`find_group_hash` helper in `src/constants.rs`.

```
URS = ASCII "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0"   (64 bytes)

GroupHash(D, M):                           # D: 8-byte personalisation, M: byte string
    h = BLAKE2s-256(data = URS || M, personalisation = D)    # RFC 7693, no key, no salt
    P = decode(h)                          # pedersen-jubjub-v1 §4, ZIP 216 strict
    if P is ⊥: return ⊥
    Q = [8]·P                              # cofactor clearing
    if Q is the identity: return ⊥
    return Q

FindGroupHash(D, M):
    for j = 0, 1, ..., 254:
        Q = GroupHash(D, M || [j])         # one appended counter byte
        if Q is not ⊥: return Q
    fail
```

The counter bound is 254: `sapling-crypto`'s `find_group_hash` asserts `tag[i] != u8::MAX`
before incrementing, so it panics rather than try counter byte 255. No base in this document
needs a counter above 5.

### 1.1 Known answers (Zcash Sapling generators)

An implementation of §1 must reproduce these `sapling-crypto` 0.9.0 constants bit-for-bit. The
coordinates are the integers whose little-endian 64-bit limbs appear in `constants.rs`.

| Constant | `D` | `M` | Counter | `u` | `v` |
|---|---|---|---:|---|---|
| `VALUE_COMMITMENT_VALUE_GENERATOR` | `Zcash_cv` | `"v"` | 0 | `0x273f910d9ecc1615d8618ed1d15fef4e9472c89ac043042d36183b2cb4d7ef51` | `0x466a7e3a82f67ab1d32294fd89774ad6bc3332d0fa1ccd18a77a81f50667c8d7` |
| `VALUE_COMMITMENT_RANDOMNESS_GENERATOR` | `Zcash_cv` | `"r"` | 0 | `0x6800f4fa0f001cfc7ff6826ad58004b4d1d8da41af03744e3bce3b7793664337` | `0x6d81d3a9cb45dedbe6fb2a6e1e22ab50ad46f1b0473b803b3caefab9380b6a8b` |
| `NOTE_COMMITMENT_RANDOMNESS_GENERATOR` | `Zcash_PH` | `"r"` | 4 | `0x26eb9f8a9ec72a8ca1409aa1f33bec2cf0919d06ffb1ecdaa5143b34a8e36462` | `0x114b7501ad104c57949d77476e262c9596b78beafa9cc44cd4fc6365796c77ac` |
| `PEDERSEN_HASH_GENERATORS[0]` | `Zcash_PH` | `LE32(0)` | 5 | `0x73c016a42ded9578b5ea25de7ec0e3782f0c718f6f0fbadd194e42926f661b51` | `0x289e87a2d3521b5779c9166b837edc5ef9472e8bc04e463277bfabd432243cca` |
| `PEDERSEN_HASH_GENERATORS[1]` | `Zcash_PH` | `LE32(1)` | 0 | `0x15a36d1f0f390d8852a35a8c1908dd87a361ee3fd48fdf77b9819dc82d90607e` | `0x015d8c7f5b43fe33f7891142c001d9251f3abeeb98fad3e87b0dc53c4ebf1891` |
| `PEDERSEN_HASH_GENERATORS[2]` | `Zcash_PH` | `LE32(2)` | 0 | `0x664321a58246e2f6eb69ae39f5c84210bae8e5c46641ae5c76d6f7c2b67fc475` | `0x362e1500d24eee9ee000a46c8e8ce8538bb22a7f1784b49880ed502c9793d457` |
| `PEDERSEN_HASH_GENERATORS[3]` | `Zcash_PH` | `LE32(3)` | 0 | `0x323a6548ce9d9876edc5f4a9cff29fd57d02d50e654b87f24c767804c1c4a2cc` | `0x2f7ee40c4b56cad891070acbd8d947b75103afa1a11f6a8584714beca33570e9` |
| `PEDERSEN_HASH_GENERATORS[4]` | `Zcash_PH` | `LE32(4)` | 0 | `0x3bd2666000b5479689b64b4e03362796efd5931305f2f0bf46809430657f82d1` | `0x494bc52103ab9d0a397832381406c9e5b3b9d8095859d14c99968299c3658aef` |
| `PEDERSEN_HASH_GENERATORS[5]` | `Zcash_PH` | `LE32(5)` | 0 | `0x63447b2ba31bb28ada049746d76d3ee51d9e5ca21135ff6fcb3c023258d32079` | `0x64ec4689e8bfb6e564cdb1070a136a28a80200d2c66b13a7436082119f8d629a` |
| `SPENDING_KEY_GENERATOR` | `Zcash_G_` | `""` | 2 | `0x0926d4f32059c712d418a7ff26753b6ad5b9a7d3ef8e282747bf46920a95a753` | `0x57a1019e6de9b67553bb37d0c21cfd056d65674dcedbddbc305632adaaf2b530` |
| `PROOF_GENERATION_KEY_GENERATOR` | `Zcash_H_` | `""` | 1 | `0x1457a50231cde2df704303f1e8906081adf2d038f2fbb8203af2dbefb96e2571` | `0x54b6d10718df2a7adec901840f4948cc50df51eaf5a149d2467af9f7e05de8e7` |
| `NULLIFIER_POSITION_GENERATOR` | `Zcash_J_` | `""` | 1 | `0x2400c2e2e3362644db56b6db8d8075ede81cee09a561229e2ce33921888d30db` | `0x61369d5440bf84a5fc9e8a15a096ba8fe155b8e8ffff2e42a3f7fa36c72b0065` |

`LE32(i)` is the 4-byte little-endian encoding of `i`, as in Zcash's Pedersen-hash generators.

---

## 2. Bases

Personalisation `D_PV = "ZeroJ_PV"` (8 ASCII bytes). `N_MAX = 16`.

- Value bases: `G_i = FindGroupHash(D_PV, LE32(i))` for `i = 0..15`.
- Blinding base: `H_V = FindGroupHash(D_PV, "r")`.

All 17 bases are in the prime-order subgroup, are not the identity, are pairwise distinct, and
differ from `pedersen-jubjub-v1`'s `G` and `H`. Implementations ship them as pinned constants;
the derivation is re-run only in tests.

| Base | Counter | `u` | `v` | `encode` |
|---|---:|---|---|---|
| `G_0` | 2 | `0x205bd2fbee3a4c6ce5d86e1920570e03bc56a7022824b699f52c1c995bc219cd` | `0x198d9863b0bca88ca66fdb18401979acfbe41fb895fba4b1651aa01899814063` | `6340819918a01a65b1a4fb95b81fe4fbac79194018db6fa68ca8bcb063988d99` |
| `G_1` | 1 | `0x4e02f0535dc84503f2188554692a83c5153081b0b3c28b5c2375783d3ad0b476` | `0x18afa800d969a6c757412d84d3284cfbe86990f6e4ac160271500dc908dcb31c` | `1cb3dc08c90d50710216ace4f69069e8fb4c28d3842d4157c7a669d900a8af18` |
| `G_2` | 1 | `0x2ade969eb6c2c98e405c91cbe90cbc8fbf1864c8ead95251b5d21ddf3e46ed2c` | `0x0e716ed2cf186aa591aa9331ae9bec5fbed8f030d5cd22d73327fc256e1b3495` | `95341b6e25fc2733d722cdd530f0d8be5fec9bae3193aa91a56a18cfd26e710e` |
| `G_3` | 0 | `0x2ce6d5b335f6cdd1fdd6be89fbf1ab0d95a61fa9563e19bc617df9b9b70fcccc` | `0x44d41301a7fa84fea9b7aea46982062abf0afb636196eb22a9c37915809c66b0` | `b0669c801579c3a922eb966163fb0abf2a068269a4aeb7a9fe84faa70113d444` |
| `G_4` | 1 | `0x3dd1f3a1f9f3218b7c49b8f469b605ae4bb58856df54477fbf0f3b85e482096a` | `0x3f7b9652faee7c79b1e4abebd1b398a5742af0dc41b073aaeeae25656fc7b272` | `72b2c76f6525aeeeaa73b041dcf02a74a598b3d1ebabe4b1797ceefa52967b3f` |
| `G_5` | 0 | `0x41cca7be1d0decf9af9659d8d20a5564345859c3aa991c0d4cbb45105cb851e4` | `0x13901ab53c6dab65341a6f592923de467f32e70d70a76cbec9ac3b93edee3e2c` | `2c3eeeed933bacc9be6ca7700de7327f46de2329596f1a3465ab6d3cb51a9013` |
| `G_6` | 3 | `0x3923fbc5240948f5efa9bf0b57ceba7da7ba30e004ed820db7f12dfe86bfadb4` | `0x0da742aecc54316b7b1dbd6deaff5148a3962e3c4099ac5781fe26a9490b430f` | `0f430b49a926fe8157ac99403c2e96a34851ffea6dbd1d7b6b3154ccae42a70d` |
| `G_7` | 0 | `0x3b40a4262c7d1b97a3a72bbcbda882ffb7a529e2145e7139a8de2791b955a72c` | `0x25dc303cf8713eec63506ed2601122297224d9c342ece2686c10ea01ee86241a` | `1a2486ee01ea106c68e2ec42c3d9247229221160d26e5063ec3e71f83c30dc25` |
| `G_8` | 1 | `0x6e18437fdfc7340f81e71c9d19e59a44827ade01e54aba3c0a14f68618a07d95` | `0x3fb405b55b3f2d600a6bfc2f88a92af6c425173d0d7cf329abaee3a32c514643` | `4346512ca3e3aeab29f37c0d3d1725c4f62aa9882ffc6b0a602d3f5bb505b4bf` |
| `G_9` | 3 | `0x3c653e6b470268a5c5024c6afd3668fef4387469c086e54073e981956bf67f6b` | `0x141919c7c72c1a39ee95e665a314bf0f51f9d240e67a04cf44855565f3eb2b2d` | `2d2bebf365558544cf047ae640d2f9510fbf14a365e695ee391a2cc7c7191994` |
| `G_10` | 1 | `0x1edcbd164e09b7a1a29cb90f892eb41ae2f3047197bb896c55b17524b6c56ca0` | `0x453e79a85942dc545aa75647b7679d9eed80a249bcb8d27d212b7ae29fb58ecb` | `cb8eb59fe27a2b217dd2b8bc49a280ed9e9d67b74756a75a54dc4259a8793e45` |
| `G_11` | 0 | `0x46217b4002cdc01ef2bfd29604c5ca3ff99f891c2f0e92a36e964eb2b9d2d490` | `0x0d85850a30916e2724ea60f51e136635bea94286507523b9e820f2497f699871` | `7198697f49f220e8b92375508642a9be3566131ef560ea24276e91300a85850d` |
| `G_12` | 0 | `0x3a10cd28295ec714214c39bc4c67c91c594e7dcba8f2889f27964ff3c595ed01` | `0x63b66ec90ce4ed01a85ec01d80ed14cf54e03feaf8efa010ec93cc28206bb77b` | `7bb76b2028cc93ec10a0eff8ea3fe054cf14ed801dc05ea801ede40cc96eb6e3` |
| `G_13` | 0 | `0x126f5e93926d05326023e31f332a85a5440337af361d486da32629ef756659c6` | `0x602458f2c4708bd3f3a311aa243bd35ae9d3266bfb669d43d712a701ca64bc76` | `76bc64ca01a712d7439d66fb6b26d3e95ad33b24aa11a3f3d38b70c4f2582460` |
| `G_14` | 0 | `0x0b8a62a6d1ab30aa503eaccfffe8886185699a8efcabc02f1cd60f69def66358` | `0x184dba5d05a379b5c133004a6c97d8831381eaa871e99bd3f2015f1d80665d57` | `575d66801d5f01f2d39be971a8ea811383d8976c4a0033c1b579a3055dba4d18` |
| `G_15` | 3 | `0x1dace0af9586ea8eeae2ab9ba2ff30a562e8339726708e4a7b630a54603e2412` | `0x1d6c1121e30cf03f24e0459083bc4ea8b11da6ee2f6f224d8b298db9aeab169f` | `9f16abaeb98d298b4d226f2feea61db1a84ebc839045e0243ff00ce321116c1d` |
| `H_V` | 0 | `0x55dcba07bdee766192d665cb67368bed334b2a598e9f16cf56a95c75f862d553` | `0x3bae3b23568241df571d423838dc54b23ec96650db57f4ad64f3bce1f5481c75` | `751c48f5e1bcf364adf457db5066c93eb254dc3838421d57df418256233baebb` |

Raising `N_MAX` later is additive: existing bases never change.

---

## 3. Commitment

For a dimension `n` with `1 ≤ n ≤ 16`, integers `v_0..v_{n−1}` and a blinding `r`:

```
C(v_0..v_{n−1}, r) = Σ_{i<n} [v_i mod l]·G_i + [r mod l]·H_V
```

`x mod l` is the least non-negative residue. Binding is to residues, as in `pedersen-jubjub-v1`
§3. Hiding requires `r` uniform in `[0, l)`; the sampler of `pedersen-jubjub-v1` §3.1 applies.

**The commitment binds neither its length nor its schema.** All dimensions share the base
prefix, so a dimension-`n` commitment equals its zero-padded extension to any larger dimension:
`C([a], r) = C([a, 0], r)`. Applications bind the schema as §5 and §6 require.

### 3.1 Test vectors

| Case | Value |
|---|---|
| `C([1000, 7], 12345).u` | `0x4ce6f49eec1e5fc89b3d3fc3932c6f6823c240e21a19bb89b580304cb7ed1d36` |
| `C([1000, 7], 12345).v` | `0x4306903aeb81cc5b6a5ac517fa9e48a7dbcab0b6920ef58cfb7ef85f569c48b8` |
| `encode(C([1000, 7], 12345))` | `b8489c565ff87efb8cf50e92b6b0cadba7489efa17c55a6a5bcc81eb3a900643` |
| `encode(C([1000], 12345))` = `encode(C([1000, 0], 12345))` | `258119dd13e51c79d80b108918c6bc3d2117b83eb0a9068e4ce8b158d7a1ffe7` |

---

## 4. Vector schema

A schema fixes what each index of a vector commitment means:

| Field | Rule |
|---|---|
| `id` | 1–64 ASCII bytes from `[a-z0-9._-]`, starting with `[a-z0-9]` |
| `version` | unsigned 16-bit integer |
| entries | `n` entries, `1 ≤ n ≤ 16`, in index order |
| entry `label` | 1–32 ASCII bytes from `[a-z0-9._-]`, any of which may come first (unlike `id`); labels are unique within the schema |
| entry `width` | `k_i` with `1 ≤ k_i ≤ 252`: the value at index `i` is in `[0, 2^{k_i})` |

The blinding width is always 252 bits and is not part of the schema.

### 4.1 Canonical encoding

```
encode(schema) =
    UTF-8("pedersen-jubjub-vector-v1") || 0x00
 || u8(len(id)) || id
 || u16_be(version)
 || u8(n)
 || for i in 0..n−1:  u8(k_i) || u8(len(label_i)) || label_i
```

A decoder rejects any input that is not exactly this layout: trailing bytes, out-of-range
fields, a disallowed character or a duplicate label. Whether an input is rejected is normative;
which rule is reported first is not.

### 4.2 Schema digest

```
σ(schema) = OS2IP(SHA-256(encode(schema))) mod p
```

`OS2IP` reads the 32-byte digest as an unsigned big-endian integer; `p` is the BLS12-381 scalar
field. `σ` is an element of the circuit field, so it can be a public input. It is an identifier
compared for equality, not a uniformly distributed value.

### 4.3 Test vectors

| Schema | `encode` | `σ` |
|---|---|---|
| `zeroj.example.balance` v1: `amount`/64, `asset`/32 | `706564657273656e2d6a75626a75622d766563746f722d763100157a65726f6a2e6578616d706c652e62616c616e63650001024006616d6f756e7420056173736574` | `0x26a0f201bd5af51641a74a2b9193d2a361dfa1b629e358f99ae97ff72fe2870d` |
| same, version 2 | `…0002024006616d6f756e7420056173736574` | `0x1acbc92525173b9be489f9eac5df349cccf41db6a9343d5d8bd2cdc695146857` |
| v1, labels swapped (`asset`/64, `amount`/32) | `…000102400561737365742006616d6f756e74` | `0x31ec633914dff2bcda6e69d694320b168a556d0de3377b5aa53aabfc5169e7a2` |
| v1, `asset` width 33 | `…0001024006616d6f756e7421056173736574` | `0x1260c5c7d40c4b2ef61cc43a2b1210006546e6da4e4eff625000c785edd9c6d8` |

`…` stands for the 48-byte prefix shared with the first row: the tag, `0x00`, `u8(21)` and
the id `zeroj.example.balance`.

All four schemas have dimension 2. The version-2 and labels-swapped schemas also have the same
widths, in the same order, as the first schema, so their circuits have the same shape. Their
digests still differ, which is what statement binding relies on.

---

## 5. Statement binding (ADR-0051 D5, I11)

A schema held by circuit code is not part of the proof statement: two schemas with the same
dimension and widths generate identical equations. Every proof that creates, opens or consumes
vector commitments therefore:

1. **declares a public input `schemaDigest`** and constrains it to equal the constant
   `σ(schema)`. One public input per schema per circuit. The constraint makes verification keys
   of same-shape schemas differ, and the input is constrained (ADR-0045);
2. constrains every committed value at index `i` to exactly the schema width `k_i` by its own
   decomposition, and the blinding to 252 bits (`pedersen-jubjub-v1` §6).

The verifier holds a **trusted registry** mapping each accepted verification key to exactly
one expected schema digest. Before accepting a proof it checks that the public `schemaDigest`
equals the registry's expected digest for that key. The expected digest never comes from the
prover or from data travelling with the proof.

---

## 6. Provenance of received commitments (ADR-0051 D5, I11)

A valid proof is not provenance. Anyone who knows an opening of a commitment can produce a
fresh, valid proof that the same point opens under any other schema of the same shape, and the
digest, key and circuit of that schema all agree.

A consumer therefore accepts a commitment it did not create only together with an
**authenticated issuance record** that binds the commitment's exact encoding to its schema
digest, and obtains the expected original schema from that record:

- **On-chain:** a referenced output whose datum holds `(encode(C), σ)` and which only the
  issuing validator or minting policy can create. The consuming validator checks that exact
  reference, and that the commitment and digest it is given match the record.
- **Off-chain:** a trusted registry or an authorised issuer's signed record with the same
  binding.

A consumer that cannot obtain such a record **rejects** the commitment (fail closed). Producing
a new valid proof never authorises creating, replacing or reinterpreting the schema of an
existing commitment. Schema-separated bases, which would bind the schema at the commitment
level, are a separate future profile, not a fallback.

---

## 7. Homomorphism

`C(a, r) + C(b, s) = C(a + b, r + s)` component-wise, mod `l`, **only between commitments with
the same schema digest**. Combining or reinterpreting across schemas is outside the profile.
Reading a component-wise sum as integer conservation requires `pedersen-jubjub-v1` §7 for each
index.

---

## 8. References

- Zcash Protocol Specification v2026.7.0 [NU6.2], §5.4.9.5 *Group Hash into Jubjub*.
- `zcash/sapling-crypto` 0.9.0 (`adaeb7aadd491de66185cc963bce9e92090d300d`): `src/group_hash.rs`,
  `src/constants.rs`.
- ZIP 216, *Require Canonical Jubjub Point Encodings*.
- RFC 7693 (BLAKE2s); FIPS 180-4 (SHA-256).
- [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md); ADR-0051 D5, I11; ADR-0045.
