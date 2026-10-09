# ZeroJ ElGamal-Jubjub v1 — Normative Specification

**Profile identifier:** `elgamal-jubjub-v1`
**Status:** Normative. Required by ADR-0052 (milestone M0).
**Date:** 2026-10-05

This document pins every value, procedure and encoding that a second implementation needs to
produce, combine, check and decrypt the same ciphertexts as ZeroJ's exponential ("lifted")
ElGamal profile on Jubjub. It is the normative form of ADR-0052 D1, D2a–D2c, D3, D5 and D7.
Anything not written here is not part of the profile.

Changing any constant, procedure or encoding produces a different profile. Ciphertexts made
under this one would not decrypt under the changed one. Such a change requires a new profile
identifier (`-v2`), not an edit to this file.

Conventions:

- `x mod l` is the least non-negative residue, in `[0, l)`.
- `OS2IP` reads bytes as an unsigned **big-endian** integer. `I2OSP32(x)` writes `x` as 32
  big-endian bytes.
- Point encodings (§7) are **little-endian**, per ZIP 216. Points are written additively;
  `[s]·P` is scalar multiplication, `O` is the identity.

---

## 1. Curve, field and generator

The curve, field and constants are those of [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §1:
`p`, `l`, `a = −1`, `d = −10240/10241 mod p`, cofactor `8`. `𝔾` is the prime-order subgroup
of order `l`.

The **only generator** is `G`, the `pedersen-jubjub-v1` value base
([`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §2.1):

| Field | Value |
|---|---|
| `G.u` | `0x3ea5c4673a121ca35ed37ee3b172f5ee04315c657fbe375f512dfea318d56fe5` |
| `G.v` | `0x57137b83ea6edb4f78f7d30d3f616cb3b9aa6e8e40808413c10cea38d50c55cb` |
| `encode(G)` | `cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7` |

`G` is both the key base and the message base (ADR-0052 Q3, decided: one generator).

---

## 2. Scalar sampling

`sample(rng)`: draw 64 bytes from a cryptographically secure random generator, compute
`OS2IP(bytes) mod l`. This is the `pedersen-jubjub-v1` §3.1 sampler. Its statistical distance
from uniform on `[0, l)` is below `2⁻²⁵⁹`.

- **Secret keys** use `sample` and are resampled while the result is `0`, so `sk ∈ [1, l)`.
- **Encryption randomness** `k = sample(rng)`, so `k ∈ [0, l)`.

---

## 3. Keys

### 3.1 Single key

A secret key is an integer `sk ∈ [1, l)`. Its public key is `PK = [sk]·G`.

A **public key received from elsewhere** is accepted only if it decodes canonically (§7.1),
lies in `𝔾`, and is **not the identity**. Encryption under the identity publishes `[m]·G`.

### 3.2 Joint key from n-of-n shares

Trustee `j` (of `n ≥ 1`) holds `sk_j ∈ [1, l)` and publishes `PK_j = [sk_j]·G`. The joint key is

```
PK = Σ_j PK_j            (secret key Σ_j sk_j mod l, held by nobody)
```

Aggregation is defined only over **possession-verified** shares (§3.3). It is refused when
any of the following holds:

1. the share list is empty;
2. a share is the identity or not in `𝔾`;
3. two shares are equal;
4. the sum is the identity.

**Registered share set.** The joint key's context consists of `PK` together with the set of
verified shares, sorted by `encode(PK_j)` in **unsigned lexicographic byte order, starting at
byte 0** of the 32-byte encoding. That is not the order of the encoding read as an integer:
the encoding is little-endian, so byte 0 is its least significant byte. The `sortvec` vector
of §12 separates the plausible wrong comparators.

Two contexts are equal if and only if their sorted share encodings are equal; the joint key
then agrees too. A single key `{PK}` and a three-share context whose shares sum to the same
`PK` are therefore **different** contexts, and their ciphertexts cannot be combined.

A single key (§3.1) is the case `n = 1`.

**Partial cancellation.** The rules refuse only a sum that is the identity. With shares
`{P, −P, Q}`, the joint key is `Q`, and `Q`'s holder can decrypt alone. This is not a break:
registering both `P` and `−P` requires possession of both secrets, so one party (or a
coalition) chose to cancel its own contribution. Privacy still needs every *other* trustee. An
application that requires each registered trustee to be necessary for decryption must exclude
such registrations itself.

### 3.3 Proof of possession

A share `PK_j` is possession-verified if one of the following holds:

- a verifier accepted the DLEQ statement (§9.2) with `X = G`, `P = PK_j`, `D = PK_j`;
- the share was computed locally as `[sk_j]·G` from a secret `sk_j` held by the same party.
  Local knowledge of the discrete logarithm is possession.

This blocks rogue keys: a party that publishes `PK_n = [x]·G − Σ_{j<n} PK_j` cannot prove
knowledge of its discrete logarithm.

The possession statement carries no application context. It shows knowledge of the key, not
who registered it, for which election, or when, and the same proof can be replayed wherever
the same key is registered. Applications authenticate key registration separately. Trustees **should** commit to their keys before revealing
them, so that no trustee chooses its key after seeing the others (protocol guidance; not
enforced by this profile).

---

## 4. Encryption

Encryption is parameterised by a **width** `w` with `1 ≤ w ≤ 64`. The message is an integer
`m` with `0 ≤ m < 2^w`.

```
k ← sample(rng)                  # §2; k ∈ [0, l)
A = [k]·G                        # decryption handle
B = [m]·G + [k]·PK               # blinded message
```

The ciphertext is `(A, B)`. Its **plaintext bound** is `2^w − 1`. `Enc(m; k, PK)` denotes this
ciphertext for message `m`, randomness `k` and key `PK`.

`k = 0` is not excluded. It gives `A = O` and reveals `[m]·G`, but under §2 it occurs with
probability `1/l`, about `2⁻²⁵²`. Only secret keys are resampled at zero.

Because `2^64 − 1 < l`, every admitted message is its own residue mod `l`, so no two in-range
messages share a ciphertext. At `w = 252` they could: `m` and `m + l` both fit, and
`[m]·G = [m + l]·G`. This is why `w ≤ 64`.

---

## 5. Homomorphism and bounds

These operations are defined **only between ciphertexts under the same key context** (§3.2).

| Operation | Result | Result bound |
|---|---|---|
| `add((A₁, B₁), (A₂, B₂))` | `(A₁ + A₂, B₁ + B₂)` | `b₁ + b₂` |
| `scale(c, (A, B))`, integer `c` with `1 ≤ c < l` | `([c]·A, [c]·B)` | `c·b` |

An operation whose result bound is `≥ l` is **refused**.

Plaintexts live mod `l`. A result can be read as an integer only if every input's bound was
established (§10.1) and the result's bound stays below `l`. A small discrete logarithm does
not detect an earlier wraparound: the raw sum of encryptions of `l − 1` and `1` decrypts to
`0`. With `w ≤ 64` and the bound rule, such inputs cannot be admitted.

---

## 6. Decryption

### 6.1 Single key

Given `sk` with `[sk]·G = PK`, where `PK` is the ciphertext's **joint** key:

```
M = B − [sk]·A           # = [m]·G
```

A secret whose public key differs from the joint key is refused. Without that check, a wrong
secret can yield a wrong in-range value: `(G, 4G)` encrypts `1` under `PK = 3G` (`k = 1`), and
the secret `4` gives `4G − [4]·G = O`, which reads as `0`.

### 6.2 n-of-n

Each registered trustee `j` computes a **decryption share** `D_j = [sk_j]·A`, and then:

```
M = B − Σ_j D_j
```

This requires exactly one **verified** share (§10.2) per registered trustee: none missing,
repeated or foreign.

### 6.3 Recovering `m`

The plaintext is the **unique integer `t ∈ [0, bound]` with `[t]·G = M`**. It is unique because
`bound < l` and `G` has order `l`. If no such `t` exists, decryption **fails**: it never
returns an out-of-range or approximate value.

The caller supplies an explicit search maximum `maxPlaintext`. Decryption is refused unless
`bound ≤ maxPlaintext`.

The search algorithm is not part of the profile, since any algorithm returns the same unique
`t`. [CGS97] §3 footnote 3 gives a linear search and baby-step giant-step. Implementations
publish their memory and time limits and refuse searches beyond them.

---

## 7. Encodings

### 7.1 Points

`encode(P)` and `decode(bytes)` are exactly
[`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §4:
- 32 bytes;
- little-endian `v`, with bit 7 of byte 31 holding the parity of `u`;
- canonical-only decoding, including the ZIP 216 rule.

### 7.2 Ciphertexts

`encode(A, B) = encode(A) ‖ encode(B)`, 64 bytes.

Decoding a ciphertext requires the length to be exactly 64, and each half to decode (§7.1) and
lie in `𝔾`. The identity is a valid `A` or `B`.

A decoder rejects an input if **any** rule of this section fails. The profile defines no
precedence among rejection reasons: implementations must agree on accept versus reject, not
on which rule fired first.

A decoded ciphertext is **raw**. The encoding carries **neither a key nor a plaintext bound**,
and both are restored only by admission (§10.1). Serialising an admitted ciphertext and
decoding it again yields a raw ciphertext.

### 7.3 Public keys

A public key is `encode(PK)`, 32 bytes. Decoding requires §7.1, membership of `𝔾`, and
`PK ≠ O`.

### 7.4 Affine coordinates

A point given as integers `(u, v)`, for example from a ledger datum, is accepted only if all
of the following hold:

1. `0 ≤ u < p` and `0 ≤ v < p`, with no reduction mod `p`;
2. the curve equation holds;
3. the point lies in `𝔾`;
4. for keys only, the point is not the identity.

---

## 8. Public-input encodings

Each coordinate is a canonical element of `F_p`, which is the BLS12-381 scalar field. The
orders are:

| Statement | Public inputs, in order |
|---|---|
| Ciphertext | `A.u, A.v, B.u, B.v` |
| Public key | `PK.u, PK.v` |
| Encryption statement (§9.1) | `PK.u, PK.v, A.u, A.v, B.u, B.v`, at a width `w` fixed by the circuit |
| DLEQ statement (§9.2) | `X.u, X.v, P.u, P.v, D.u, D.v` |

An application circuit may embed these groups among its own public inputs, for example a
ballot with an election id and a nullifier. Within each group the order above is kept. The
width `w` is a property of the circuit, not a public input, so a verifier selects the circuit
(verification key) for exactly `w`.

---

## 9. In-circuit relations

All relations are over the BLS12-381 scalar field. Scalars are witnessed through one owned bit
decomposition each.

### 9.1 Encryption relation `R_enc(w)`

- **Public:** `PK = (PK.u, PK.v)`, `A = (A.u, A.v)`, `B = (B.u, B.v)`.
- **Witness:** `m` (declared `w` bits, `1 ≤ w ≤ 64`) and `k` (declared 252 bits).
- **Asserted:**
  1. `PK` satisfies the curve equation and `PK ≠ O`;
  2. `m < 2^w`, by its decomposition;
  3. `A = [k]·G` and `B = [m]·G + [k]·PK`, where **one** decomposition of `k` drives both
     scalar multiplications;
  4. `A` and `B` equal the public coordinates.
- **Definition-time rules:**
  - a width above 64 is refused when the circuit is defined;
  - the `k` wire must not be a public input or a constant, and must not be range-confined
    below 252 bits (the `pedersen-jubjub-v1` §6 guard rails).
- **Key membership.** `PK ∈ 𝔾` is either asserted in-circuit (a witnessed key) or is the
  **verifier's obligation** (a key whose coordinates are public inputs fixed by the verifier).
- **Scalar range.** `k` ranges over `[0, 2^252)`. Values `k ≥ l` give the same points as
  `k mod l`, which is harmless because `G` and `PK` lie in `𝔾`.

### 9.2 Discrete-log equality `R_dleq`

- **Public:** `X`, `P`, `D` (six coordinates).
- **Witness:** `x` (declared 252 bits).
- **Asserted:**
  1. `X` satisfies the curve equation;
  2. `P = [x]·G` and `D = [x]·X`, with one decomposition of `x`.
- **Definition-time rules:**
  - all six coordinates must be **public inputs**, so a prover can never choose the base;
  - `x` carries the guard rails of §9.1.
- **Identity.** `P` and `D` may be the identity.
- **Verifier precondition: `X ∈ 𝔾`.** If `X` had a small-order component, then for
  `x < 2^252 − l` both `x` and `x + l` fit the width and could give two different `D`.
- **Uses:**
  - a proof of possession takes `X = G` and `D = P = PK_j` (§3.3);
  - a decryption-share proof takes `X = A` of the admitted ciphertext, `P = PK_j` registered
    in its context, and `D = D_j` (§10.2).

### 9.3 Verifier obligations

1. Every public input is a canonical `F_p` element, and every public input is constrained (the
   ADR-0045 rule).
2. A key whose coordinates are public inputs lies in `𝔾`.
3. A DLEQ base `X` lies in `𝔾`.
4. The verification key is the one for the intended relation and width.

---

## 10. Admission and verified shares

### 10.1 Admission

A ciphertext obtains a key context and a plaintext bound in exactly these ways:

1. **Local encryption** (§4) under the context, giving the bound `2^w − 1`.
2. **Verified admission.** A verifier checks `R_enc(w)` for exactly this `(PK, A, B)`, at
   exactly this `w`, where `PK` is the context's joint key. The bound is then `2^w − 1`.
   - This is a **delegated verifier obligation**.
   - One legitimate delegation is an on-chain validator that verified the statement before
     the ciphertext reached the ledger. The caller must then establish, from chain data, that
     the ciphertext is one such validator accepted.

3. **Homomorphic combination** (§5) of ciphertexts that are themselves admitted, under the same
   context. The result carries the combined bound of §5. It is admitted because its inputs
   were, not because of a new check.

No other way to attach a bound or a key exists. In particular, no claimed bound or claimed key
is accepted.

### 10.2 Verified decryption shares

A claimed share `D_j` is used only after a verifier accepts the DLEQ statement
`(X = A, P = PK_j, D = D_j)`, where:

- `A` comes from the admitted ciphertext, never from the share's sender;
- `PK_j` is a share registered in that ciphertext's context;
- `D_j` decodes (§7.1) and lies in `𝔾`.

A share computed locally as `[sk_j]·A`, from a secret whose public key is registered, counts
as verified. The verified share is bound to that exact ciphertext, `(A, B, context)`, and that
trustee.

Without verification, a trustee who has seen the other shares can choose the result. The
forged-share example: keys `3G` and `5G`, `m = 1`, `k = 7`, honest share `21G`. The forged
second share `36G` (instead of `35G`) makes the result `0`, an in-range value.

---

## 11. Secret handling

The following operations take secret inputs. They are **compatibility/offline-class**
(ADR-0039 §3.1): variable-time arithmetic, with no constant-time claim.

| Operation | Secret inputs |
|---|---|
| Key generation, `[sk]·G` | `sk` |
| Encryption, `[k]·G`, `[m]·G`, `[k]·PK` | `k`, `m` |
| Decryption share, `[sk_j]·A` | `sk_j` |
| Single-key decryption, `[sk]·A` | `sk` |
| Plaintext recovery (§6.3) | `M = [m]·G`, so the running time can depend on `m` |

The following operations take only public data and may use variable-time arithmetic freely:
- decoding and subgroup checks;
- homomorphic `add` and `scale`;
- statement construction;
- combining verified shares.

---

## 12. Test vectors

Test-vector scalars are derived as
`scalar(tag) = OS2IP(SHA-256(UTF-8("zeroj.elgamal.v1.test." + tag))) mod l`. This derivation
is for test vectors only. Real keys and randomness use §2.

- In tags such as `"share" + j` and `"ballot" + i`, the number is written in decimal, unpadded
  and 1-based: `share1`, `ballot5`.
- None of the derived secrets is zero. A vector set whose secret derived to zero would be
  invalid, not resampled.

**Single key.**
- `sk = scalar("sk")`, `PK = [sk]·G`.
- Encryptions:
  - `m = 0` (`w = 1`, `k = scalar("k0")`);
  - `m = 1` (`w = 1`, `k = scalar("k1")`);
  - `m = 12345` (`w = 16`, `k = scalar("k16")`);
  - `m = 2^64 − 1` (`w = 64`, `k = scalar("k64")`).
- Homomorphism: `add(Enc(0), Enc(1))`, and `scale(3, Enc(12345))`.

**n-of-n, three trustees.**
- `sk_j = scalar("share" + j)` for `j = 1, 2, 3`, and the joint `PK`.
- Five ciphertexts of the messages `1, 0, 1, 1, 0` at `w = 1`, with `k_i = scalar("ballot" + i)`.
- Their sum (bound 5), the shares `D_j = [sk_j]·A_sum`, `M`, and the tally `3`.
- The DLEQ statements of the three shares (`X = A_sum`), the three possession statements, and
  the encryption statement of ballot 1 under the joint key.

**Share order.** The keys `[1]·G`, `[2]·G`, `[4]·G` register in the order `[2]·G`, `[4]·G`,
`[1]·G` (`sortvec`).

**ADR counterexamples.**
- `(G, 4G)` under `PK = 3G`: the secret `4` gives `0`.
- The mixed-key sum `Enc(1; 1, 3G) + Enc(1; 1, 2G)` decrypts to `1` under the secret `3`.
- The forged share `36G`, from keys `3G`/`5G` with `m = 1` and `k = 7`, gives `0`.

Pinned values:

| Case | Value |
|---|---|
| `scalar("sk")` | `0x0281799c40fb5bca4f8cc6af4812fae96cdf7113e1ab203ea4d73fb7027e8343` |
| `encode(PK)`, single key | `36d7d5a69ac65a6761ac10fd3338bd4692939aefc4f5d5a1eb37477b29423e68` |
| `encode(Enc(1; scalar("k1"), PK))` | `5c60657a3d709bbc2e68f03e5146b357b45066b21f21e914decbddefef876ea20115a214bbe47745f99a8130d1bd2b48b788883d95d468069d0677081dc5f772` |
| `encode(Enc(12345; scalar("k16"), PK))` | `b1998f709303f197722bef1f1105d9b65ad7d9b77d32c8859419a27c53928d5a38f7c38d98efd9f2f89698d45c5546a17a4a76534a006429bd6af0be8ce93383` |
| `encode(scale(3, Enc(12345; …)))`, decrypts to `37035`, bound `196605` | `193f16f9951d03a1f3d4c9c1e1489e1ee5b61d09cb9804457f4e18cbbd4bc3532ceebd9fcc067159ff73bb2b58f59afba36be6f7e1d3750f04ade95531663f00` |
| `encode(PK)`, joint key of `share1..3` | `0d6095aa0f3192593b2f5df4c71235d38aed8bcae0aa96d6763365aeefcc7bbd` |
| Registered order of `share1..3` | `share2`, `share3`, `share1` |
| `encode(sum of the five ballots)`, bound `5` | `d9e1c0c05d495f6eeca22c9257dd65c9b3e91798295aaf55ce74b3f507a097a39beef4b740256ead8bd03fb5b2d2f6bb9ea524d684f79cc83ba4f640687122b4` |
| `encode(D_1)` on the sum | `cbff0fffd39cf2f7462faadf945014bea3dec8f82531dbd32d3d93db5a1ab887` |
| Tally | `3` |
| Forged-share result (`36G` for `35G`) | `0`; the honest result is `1` |

An independent reproduction of §1–§10 and of these vectors, written from this document and
[`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) alone, is at
`zeroj-circuit-lib/src/test/resources/elgamal-reference/`. Its pinned output is checked against
the library at every build.

---

## 13. Non-goals

- Threshold `t`-of-`n` keys. These are in `elgamal-jubjub-threshold-v1` (ADR-0053).
- A Σ-protocol for the DLEQ relation, and its transcript (ADR-0052 D4, Q1 decided: SNARK
  relation only).
- Range proofs on plaintexts outside a circuit.
- Re-encryption, mix-nets and shuffles.
- Constant-time host arithmetic (ADR-0039).
- Application rules such as "decrypt once, after a deadline". Decrypting running totals lets
  an observer recover individual messages by differencing. ZeroJ documents the rule but cannot
  enforce it.

## 14. References

- **[CGS97]** R. Cramer, R. Gennaro, B. Schoenmakers, *A Secure and Optimally Efficient
  Multi-Authority Election Scheme*, EUROCRYPT '97: §2.2, §2.3, §2.5, and §3 footnote 3.
- **[RY07]** T. Ristenpart, S. Yilek, *The Power of Proofs-of-Possession*, EUROCRYPT 2007.
  Cited by analogy, for proof of possession.
- [`pedersen-jubjub-v1.md`](pedersen-jubjub-v1.md) §1–§4; ZIP 216.
- ADR-0039 (assurance classes), ADR-0045 (public wires bound), ADR-0051, ADR-0052.
