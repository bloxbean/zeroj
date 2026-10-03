# ZeroJ Pedersen-Jubjub v1 — Normative Specification

**Profile identifier:** `pedersen-jubjub-v1`
**Status:** Normative. Required by ADR-0051 Decision D1 (milestone M0).
**Date:** 2026-10-03

This document pins every value, procedure and encoding that a second implementation needs in
order to produce and check the same commitments as ZeroJ's two-base Jubjub Pedersen profile.
It records the profile **as already implemented** by `PedersenCommitment`,
`InCircuitPedersen` and `ZkPedersen`; it changes no point and no commitment value. Anything not
written here is not part of the profile.

Changing any constant, tag, procedure or encoding in this document produces a different
profile. Commitments made under this one would not open under the changed one. Such a change
requires a new profile identifier (`-v2`), not an edit to this file (ADR-0051 invariant I7).

Sections marked *(enforced from Mn)* state rules that ADR-0051 adds at a later milestone. They
are normative for applications now; the library enforces them once that milestone lands.

---

## 1. Curve and field

The curve, field and generator are identical to [`jubjub-eddsa-v1.md`](jubjub-eddsa-v1.md) §1.

| Symbol | Meaning | Value |
|---|---|---|
| `p` | Jubjub base field = BLS12-381 scalar field | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| `l` | Jubjub prime-order subgroup order | `0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7` |
| `a` | Twisted Edwards `a` | `-1 mod p` |
| `d` | Twisted Edwards `d` | `0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1` |
| `h` | Cofactor | `8` |

Curve equation, affine: `−u² + v² = 1 + d·u²·v²`. The identity is `(0, 1)`. Negation is
`−(u, v) = (−u, v)`. Point addition is the complete unified twisted-Edwards addition; Jubjub
has no exceptional inputs for it.

---

## 2. Bases

### 2.1 Value base `G`

`G = [8]·G_full`, where
`G_full = (0x62edcbb8bf3787c88b0f03ddd60a8187caf55d1b29bf81afe4b3d35df1a7adfe, 11)`.

| Field | Value |
|---|---|
| `G.u` | `0x3ea5c4673a121ca35ed37ee3b172f5ee04315c657fbe375f512dfea318d56fe5` |
| `G.v` | `0x57137b83ea6edb4f78f7d30d3f616cb3b9aa6e8e40808413c10cea38d50c55cb` |
| `encode(G)` | `cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7` |

### 2.2 Poseidon instance used by the derivation

`PoseidonT3(x, y)` is the original Poseidon permutation (Grassi et al., 2021 — not the later
"Poseidon2" design) over BLS12-381, as pinned by ADR-0015:

- Parameters `t = 3`, `α = 5`, `RF = 8`, `RP = 57`, over `p`.
- Round constants `C[0..194]` and the 3×3 MDS matrix `M` are those produced by the hadeshash
  Grain LFSR generator (`generate_parameters_grain.sage`, commit
  `208b5a164c6a252b137997694d90931b2bb851c5`) with arguments `1 0 255 3 8 57 <p>`. The
  generation procedure is defined by that script, not restated here. Its output is
  reproduced by the independent Sage reference in
  `zeroj-circuit-lib/src/test/resources/poseidon-sage/`, whose golden file lists the first six
  round constants and the full `M`, and is committed by value in ZeroJ's
  `PoseidonParamsBLS12_381T3`.
- Round `r` (0-based) adds `C[r·3 + j]` to cell `j`, applies `x^5` to all cells in the first
  `RF/2` and last `RF/2` rounds and to cell 0 only in the `RP` partial rounds, then applies
  the linear layer **`s'[i] = Σ_j M[i][j]·s[j]`** (the matrix times the state column vector;
  `M` is not symmetric, so the orientation matters).
- Input state `[0, x mod p, y mod p]`. Output: cell 0 after the final round.

Known answers, from the independent SageMath reference
(`zeroj-circuit-lib/src/test/resources/poseidon-sage/sage-reference-output.txt`):

| Input | Output |
|---|---|
| `PoseidonT3(0, 0)` | `0x57c7e6cea4c40c3956e13ae6f8d644edff6f14577a581058eaa651b4675c7156` |
| `PoseidonT3(1, 2)` | `0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a` |
| `PoseidonT3(123, 456)` | `0x6eadb49364ff22d841d40765ef4ac418f19467e8511541850aebf2936338a0fa` |

### 2.3 Blinding base `H`

`H` is derived from the domain tag `TAG = "zeroj.pedersen.v1.H"` by the following procedure.
All arithmetic is in `F_p` unless stated otherwise.

```
tagInt = OS2IP(UTF-8(TAG)) mod p     # unsigned big-endian integer of the tag bytes
for counter = 0, 1, 2, ..., 999_999:
    v   = PoseidonT3(tagInt, counter)
    num = v² − 1
    den = d·v² + 1
    if den == 0: continue            # defensive: unreachable on Jubjub (see §4)
    w = num · den⁻¹                  # candidate u²
    if w is not a square: continue
    u = a square root of w           # u = 0 when w = 0
    u = min(u, (p − u) mod p)        # both reduced into [0, p); for u = 0 both are 0
    P = [8]·(u, v)                   # cofactor clearing
    if P is the identity: continue
    return H = P
fail (the derivation is defined to succeed long before the bound)
```

`tagInt = 0x7a65726f6a2e706564657273656e2e76312e48`. The first success occurs at
`counter = 1` (informative). The result is pinned:

| Field | Value |
|---|---|
| `H.u` | `0x72963e7766b3cd553a1525a17da810e6b4cdeb70541dac5b52a3210f5c372db6` |
| `H.v` | `0x60bb97d81759e04503194aeb9eb8faa23b0092c941d1139bfe99907794c8e37d` |
| `encode(H)` | `7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60` |

`H` lies in the prime-order subgroup, is not the identity and differs from `G`. Its discrete
logarithm with respect to `G` is unknown: the derivation is a hash output followed by
cofactor clearing, and no step introduces a known relation to `G`.

---

## 3. Commitment

For integers `v` (value) and `r` (blinding), negative values included:

```
C(v, r) = [v mod l]·G + [r mod l]·H
```

`x mod l` always denotes the least non-negative residue, in `[0, l)`.

- **Binding is to residues mod `l`**, not to integers: `C(v, r) = C(v + l, r)`. An application
  that needs integer semantics must range-bound the committed values (§7).
- **Hiding** requires `r` uniformly distributed in `[0, l)` and independent of everything
  else. A predictable, reused or low-entropy `r` forfeits hiding.
- The commitment of `(0, 0)` is the identity.

### 3.1 Blinding sampling *(enforced from M1)*

The reference sampler draws 64 bytes from a cryptographically secure random generator, reads
them as an unsigned big-endian integer, and reduces mod `l`. Its statistical distance from
uniform on `[0, l)` is below `2⁻²⁵⁹`.

### 3.2 Opening verification

An opening `(v, r)` for `C` is accepted iff `C = [v mod l]·G + [r mod l]·H`. Opening
verification handles disclosed values and may use variable-time arithmetic.

---

## 4. Point encoding

`encode(P)` is 32 bytes. Bytes 0–31 hold the affine `v`-coordinate as an unsigned
little-endian integer; bit 7 of byte 31 is set iff the affine `u`-coordinate, as an integer in
`[0, p)`, is odd.

`decode(bytes)` accepts exactly one encoding per point and rejects when:

1. the length is not 32;
2. `v ≥ p`, after clearing the sign bit;
3. `d·v² + 1 = 0` (unreachable on Jubjub: `d` is a non-square and `−1` is a square, so
   `v² = −1/d` has no solution; kept as a defensive check);
4. `(v² − 1)·(d·v² + 1)⁻¹` is not a square;
5. the recovered `u` is 0 and the sign bit is set (ZIP 216 canonicity).

Otherwise `u` is the square root whose parity matches the sign bit.

### 4.1 Received commitments *(enforced from M2)*

A commitment received from another party is accepted only if it decodes as above **and** lies
in the prime-order subgroup (`[l]·P` is the identity). Decoding alone does not establish
subgroup membership.

**Identity policy.** The identity is a valid commitment point and is accepted. It is the
commitment to `(0, 0)` and can legitimately arise as a homomorphic combination. Rejecting it
adds no binding. An application that must exclude it asserts non-identity explicitly. This
policy is separate from point validity: an invalid representation (for example `Z = 0` in
projective coordinates) is never "the identity" and is always rejected.

---

## 5. Public-input encoding in circuits

A commitment is exposed to a verifier as **two public inputs: the affine `u`, then the affine
`v`**, each a canonical element of `F_p` (Jubjub's base field is the BLS12-381 scalar field).
The 32-byte compressed form does not fit in one field element and is not used as a public
input.

---

## 6. In-circuit semantics

- `InCircuitPedersen` (low level) computes `[Σ bᵢ·2ⁱ]·G + [Σ cᵢ·2ⁱ]·H` for boolean bit
  vectors of width 1–252. It proves the residues those bit vectors represent and does **not**
  assert canonicity (`< l`).
- `ZkPedersen` (symbolic) additionally asserts that both scalars are `< l` and consumes each
  scalar's owned decomposition at its declared width.
- *(enforced from M1)* The blinding is full width: declared width exactly 252 bits, with the
  `< l` assertion. A blinding wire that is directly a public input or a circuit constant is
  rejected at circuit-definition time. The value keeps its own declared width (1–252).
- *(enforced from M2)* A commitment the circuit did not compute enters only through a
  constructor that either proves subgroup membership in-circuit or requires public/constant
  coordinates and leaves subgroup membership to the verifier (ADR-0051 D3, I4).

---

## 7. Homomorphic relations and wraparound

`C(v₁, r₁) + C(v₂, r₂) = C(v₁ + v₂, r₁ + r₂)` holds **mod `l`**. With canonical openings,
`C(l − 1, 17) + C(1, 23) = C(0, 40)`.

An application may read a relation `Σ aᵢ·vᵢ = Σ bⱼ·wⱼ (+ public terms)` as an integer
equation only if all of the following hold (ADR-0051 D3a, I6):

1. every term on both sides is range-bounded by its own decomposition to a declared width
   `kᵢ` — bounding only the claimed total is insufficient;
2. the coefficients are small non-negative integers fixed when the circuit is defined, with
   negative coefficients moved to the other side;
3. each side's maximum `Σ aᵢ·(2^{kᵢ} − 1)` (public terms at their declared bounds) is `< l`.

Both sides are then integers in `[0, l)`, so equality mod `l` implies integer equality.
Because `l < p`, the same bound excludes aliasing mod `p` when the values are summed as field
elements.

---

## 8. Test vectors

| Case | Value |
|---|---|
| `C(42, 12345).u` | `0x478a0bd6a0eebdffc610618ad979b39d6237f240125534886d38720cbd76a025` |
| `C(42, 12345).v` | `0x6387c33be7b7177b74ce909592456d7c81dab375a6ba3182eb7f5e2974e0d357` |
| `encode(C(42, 12345))` | `57d3e074295e7feb8231baa675b3da817c6d45929590ce747b17b7e73bc387e3` |

The blinding `12345` above is a fixed test value, not a valid hiding blinding (§3).

An independent reproduction of §2.2–§3 and of this table, written from this document alone,
is at `zeroj-circuit-lib/src/test/resources/pedersen-reference/`. Its pinned output is checked
against the library at every build.

---

## 9. Non-goals

- Commitment to several values at once (see the vector profile, ADR-0051 D5).
- Commitments on BLS12-381 G1 (ADR-0051 D7).
- Any statement about constant-time generation. Secret-bearing off-circuit generation remains
  restricted to offline or isolated use (ADR-0038; ADR-0039 M9).

## 10. References

- T. P. Pedersen, *Non-Interactive and Information-Theoretic Secure Verifiable Secret
  Sharing*, CRYPTO '91.
- ADR-0015 (Poseidon constants), ADR-0016 (Jubjub in-circuit), ADR-0037/0038/0039 (Jubjub
  hardening), ADR-0051 (this profile).
- ZIP 216, *Require Canonical Jubjub Point Encodings*.
- [`jubjub-eddsa-v1.md`](jubjub-eddsa-v1.md) §1 (shared curve constants).
