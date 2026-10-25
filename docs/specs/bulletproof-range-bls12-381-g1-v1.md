# ZeroJ Bulletproof Range Proof over BLS12-381 G1 v1 — Normative Specification

**Identifier:** `bulletproof-range-bls12-381-g1-v1` (proof protocol, `commitment-profiles-v1` §5)
**Generator set:** `bulletproof-bls12-381-g1-gens-v1`
**Consumes:** `pedersen-bls12-381-g1-v1` (`pedersen-bls12-381-g1-v1.md`)
**Status:** draft r2 (ADR-0061 M1); registry status `reserved`
**Date:** 2026-10-24 (r1); 2026-10-25 (r2)
**Governing ADR:** [ADR-0061](../adr/0061-bulletproof-range-proofs-bls12-381-g1.md)

This document fixes every byte of the protocol: the generators, the transcript, the codecs, the
proof encoding, the prover and the verifier. An implementation that follows it exactly produces
and accepts the same proofs as any other.

`sigma-proofs_Shake128_BLS12381` means its definition in `draft-irtf-cfrg-sigma-protocols-03`, and
the transcript is that of `draft-irtf-cfrg-fiat-shamir-03`. A new protocol identifier is required
for any change to:
- a constant;
- the tag;
- the transcript;
- a codec;
- a pinned draft revision.

A transcript is never replaced under an existing identifier (registry §5).

The key words MUST, MUST NOT, SHOULD and MAY are normative, as in RFC 2119 and RFC 8174.

The protocol is the single-value range proof of Bünz et al., *Bulletproofs* (ePrint 2017/1066,
revision of 2022-04-14), §4.1–§4.2 with the inner-product argument of §3 (Protocols 1 and 2) and
the verifier of §6.2. It is made non-interactive with the duplex-sponge Fiat–Shamir transformation
of `draft-irtf-cfrg-fiat-shamir-03`, instantiated with SHAKE128, using the codecs of the
`sigma-proofs_Shake128_BLS12381` ciphersuite of `draft-irtf-cfrg-sigma-protocols-03` §8.2.
**No standard specifies Bulletproofs.** The placement of the paper's rounds in the
fiat-shamir-03 framework (§5) is this specification's own.

Status: experimental. Nothing here is a security or production claim.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `q` | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`, the order of the BLS12-381 G1 prime-order subgroup and of its scalar field |
| `O` | the identity of G1 |
| `G`, `H` | the value base and the blinding base of `pedersen-bls12-381-g1-basis-v1` (`pedersen-bls12-381-g1-v1.md` §2) |
| `n` | the bit width, `n ∈ {16, 32, 64}` |
| `k` | `log₂ n`, so `k ∈ {4, 5, 6}` |
| `[s]·P` | scalar multiplication; all scalars are integers mod `q` |
| `⟨a, b⟩` | `Σ a_i·b_i mod q` |
| `a ∘ b` | the component-wise product |
| `cᵗ` | the vector `(1, c, c², …, c^{t−1})` (so `2ⁿ = (1, 2, 4, …, 2^{n−1})` and `yⁿ = (1, y, …, y^{n−1})`) |
| `1ⁿ` | the all-ones vector of length `n` |
| `x⁻¹` | the inverse of `x` mod `q` (defined only for `x ≠ 0`) |
| `I2OSP`, `OS2IP` | big-endian conversions (RFC 8017) |
| `LE(v, w)`, `LE2IP` | little-endian conversions (fiat-shamir-03 §2.1) |
| `compress(P)` | the 48-octet compressed G1 encoding: the Zcash form of `pedersen-bls12-381-g1-v1.md` §4, which is the encoding of pairing-friendly-curves Appendix C that sigma-03 §8.2 names |
| `‖` | concatenation |

Vectors are indexed from `0`. A vector of length `t` is split as `a[:t/2]` (indices `0 … t/2 − 1`)
and `a[t/2:]` (indices `t/2 … t − 1`).

### 1.1 Statement and its integer meaning

For a commitment `V ≠ O` of `pedersen-bls12-381-g1-v1`, the prover shows knowledge of `(v, γ)`
with `V = [v]·G + [γ]·H` and `0 ≤ v < 2^n` **as integers**, where `n ∈ {16, 32, 64}` comes from
the verifier's configuration. Because `2^n ≤ 2^64 < q`, the committed residue has exactly one
representative in `[0, 2^n)`. That representative is what the proof bounds.

A range proof is not a balance. To read a relation between commitments as integer conservation,
an application applies ADR-0051 D3a:
- every term on both sides carries its own verified range proof, at the width that application
  configured for it;
- coefficients are small non-negative integers fixed by the verifier, never chosen by the prover;
- each side's maximum, `Σ coefficient·(2^{n_i} − 1)` plus any public terms at their bounds, is
  below `q`.

A range proof on a **derived** commitment, such as `V₁ − V₂`, shows `(v₁ − v₂) mod q ∈ [0, 2^n)`. It implies the integer statement `v₁ ≥ v₂` only if `v₁` and `v₂` are themselves bounded,
for example each proved below `2^{n'}` with `2^{n'} + 2^n ≤ q`.

---

## 2. Generator set `bulletproof-bls12-381-g1-gens-v1`

### 2.1 Derivation

```
DST_BP = "ZeroJ-bulletproof-bls12-381-g1-gens-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"   (US-ASCII, 70 octets)

G_i = hash_to_curve("G" ‖ I2OSP(i, 4), DST_BP)   for i = 0 … 63
H_i = hash_to_curve("H" ‖ I2OSP(i, 4), DST_BP)   for i = 0 … 63
U   = hash_to_curve("U", DST_BP)
```

- `hash_to_curve` is RFC 9380 §3 with the suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` (§8.8.1), the
  random-oracle variant. `encode_to_curve` MUST NOT be used.
- `"G"`, `"H"` and `"U"` are the single octets `0x47`, `0x48` and `0x55`. `I2OSP(i, 4)` is the
  4-octet big-endian index, so the message for `G_5` is `47 00 00 00 05`.
- A proof of width `n` uses `G_0 … G_{n−1}` and `H_0 … H_{n−1}`, the prefixes of the set.

### 2.2 Checks at derivation

A deriver MUST check that none of the 131 points `G_0 … G_63`, `H_0 … H_63`, `U`, `G`, `H` is `O`,
and that for any two of them `P ≠ Q` and `P ≠ −Q`. RFC 9380 `hash_to_curve` outputs are in the
prime-order subgroup by construction (`clear_cofactor`), and a deriver checks membership as
well. If a check fails, the set is invalid and a new
version is required; an implementation does not continue.

### 2.3 Digest

```
D_gens = SHA-256( compress(G_0) ‖ … ‖ compress(G_63) ‖ compress(H_0) ‖ … ‖ compress(H_63) ‖ compress(U) )
```

The input is `129 · 48 = 6,192` octets.

### 2.4 Pinned values

Implementations use the pinned encodings of Appendix A and do not hash at run time. A test
recomputes them. `D_gens` and the 129 encodings are pinned in Appendix A. Three independent
reproductions agree on them (ADR-0061 I1).

---

## 3. Codecs (sigma-03 §8.2, `sigma-proofs_Shake128_BLS12381`)

| Type | Size | Serialize | Deserialize |
|---|---|---|---|
| Group element | `Ne = 48` | `compress(P)`; never produced for `P = O` | the strict decoder of `pedersen-bls12-381-g1-v1.md` §4 (length, flags, `x < P_381`, on curve, subgroup), then **reject `O`** (sigma-03 §8.2.1: infinity is "neither produced … nor accepted") |
| Scalar | `Ns = 32` | `I2OSP(s, 32)`, `0 ≤ s < q` | `OS2IP`; fail unless the value is in `[0, q)` (check 1) |
| Challenge | 48 squeezed octets | — | `DecodeField(buf, q, 1) = LE2IP(buf) mod q` (fiat-shamir-03 §4.2.2–§4.2.3; sigma-03 §8) |

Note the two byte orders: serialized scalars are **big-endian**; challenge octets are read
**little-endian**.

---

## 4. Duplex sponge (fiat-shamir-03 §3.2, §9.1)

The duplex sponge is the XOF duplex sponge with SHAKE128 (FIPS 202), rate `R = 168`.

- `Init(session_id)`: a fresh SHAKE128 state, updated with `session_id ‖ zeros(136)`
  (`session_id` is 32 octets; `R − 32 = 136`).
- `Absorb(x)`: update the state with `x`. Absorbing `""` changes nothing.
- `Squeeze(m)`: if the sponge is absorbing, finalize a **copy** of the state and keep its output
  reader; return the next `m` octets of that reader. Consecutive squeezes continue one stream; an
  `Absorb` of a non-empty string ends it.

`DeriveSessionID(tag)` (fiat-shamir-03 §5.1):

```
ds = Init("irtf-cfrg-fiat-shamir/session-id")      (that 32-octet US-ASCII string as session_id)
ds.Absorb(tag)
return ds.Squeeze(32)
```

---

## 5. Transcript

### 5.1 Session tag

The tag is US-ASCII:

```
tag = "ZeroJ:bulletproof-range-bls12-381-g1-v1"
    ‖ "/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
    ‖ "/N" ‖ D3(n)
    ‖ "/A96S96.A96S48.A96S48.(A96S48)x" ‖ D1(k)
    ‖ "/CTX" ‖ D4(len(ctx)) ‖ ":" ‖ hex(ctx)

session_id = DeriveSessionID(tag)
```

- `D1`, `D3` and `D4` are fixed-width decimal digits with leading zeros: `n = 64` is `"064"`, and
  `len(ctx) = 5` is `"0005"`.
- `hex(ctx)` is lowercase hexadecimal, two characters per octet.
- `ctx` is the application context: caller-supplied, **1 to 1,024 octets**. It MUST be non-empty
  and unique to the application, for example a namespace string such as
  `"https://example.com/payroll/v1"` or a chain identifier with a message domain. This is how the
  tag satisfies fiat-shamir-03 §5.1 requirement 3. An empty `ctx` would identify only the
  protocol, so a proof could be accepted by any other application that also used an empty
  context.
- Every field before `ctx` has a fixed width or a fixed delimiter, and `ctx` carries its length,
  so no two `(n, ctx)` pairs give the same tag.

**What `ctx` must contain, and what the proof does not give.**
- `ctx` begins with a namespace under the application's control, for example
  `"https://example.com/payroll/v1"` or a chain identifier with a message domain. Two applications
  that choose the same `ctx` accept each other's proofs.
- An application that builds `ctx` from several fields encodes them injectively itself, with
  fixed widths or length prefixes (fiat-shamir-03 §5.1 gives the `("SV1", "22")` /
  `("SV12", "2")` example). The tag is injective only in the bytes of `ctx`.
- Within one `ctx`, a proof for `V` is valid wherever `V` appears. An application that needs a
  proof bound to one message, sender or epoch puts that binding into `ctx`, as fiat-shamir-03 §8.3
  recommends for freshness.
- Replay protection, ownership and authorization are the application's job. The proof
  establishes only the §1.1 statement.
- fiat-shamir-03 §5.1 requirement 2 (the order and types of the codecs) is met by the protocol
  identifier together with the ciphersuite `sigma-proofs_Shake128_BLS12381`, which fix every
  message's type and encoding in §5.3. The round string adds the absorb (`A`) and squeeze (`S`)
  octet counts. It lists only absorbs and squeezes: the trailing `a`, `b` are never absorbed
  (§5.3).

Example (`n = 16`, `ctx = "hello"`):

```
ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0005:68656c6c6f
```

### 5.2 Instance

The instance is absorbed first (fiat-shamir-03 §5.2). Its encoding is:

```
instance = SerializeVarLenString("pedersen-bls12-381-g1-v1")
         ‖ compress(G) ‖ compress(H)
         ‖ SerializeVarLenString("bulletproof-bls12-381-g1-gens-v1")
         ‖ D_gens
         ‖ SerializeUint(n, 2^32)
         ‖ compress(V)
```

- `SerializeVarLenString(s) = LE(len(s), 4) ‖ s` (fiat-shamir-03 §6.1.1).
- `SerializeUint(n, 2^32) = LE(n, 4)` (§6.1.3).
- `D_gens` is the 32-octet digest of §2.3.
- `V` is the commitment. It is never `O` (§7.1).

The encoding is prefix-free: the two strings carry their lengths, and everything else has a fixed
length.

### 5.3 Rounds

```
ds = Init(session_id)
ds.Absorb(instance)

ds.Absorb(ser(A) ‖ ser(S))                 # 96 octets
y = DecodeField(ds.Squeeze(48))
z = DecodeField(ds.Squeeze(48))            # the same output stream as y

ds.Absorb(ser(T₁) ‖ ser(T₂))               # 96 octets
x = DecodeField(ds.Squeeze(48))

ds.Absorb(ser(t̂) ‖ ser(τ_x) ‖ ser(μ))      # 96 octets
x_u = DecodeField(ds.Squeeze(48))

for j = 1 … k:
    ds.Absorb(ser(L_j) ‖ ser(R_j))         # 96 octets
    x_j = DecodeField(ds.Squeeze(48))

# a and b end the NARG string. They are not absorbed: no challenge follows them.
```

An implementation that absorbed them would still derive the same challenges.

`ser` is §3's serialization. The bytes absorbed are exactly the proof bytes (§6) in order, except
the final 64 octets (`a`, `b`). The proof is the NARG string (fiat-shamir-03 §6).

**Zero challenges.** If any of `y`, `z`, `x`, `x_u`, `x_1 … x_k` is `0`, the proof is rejected by
the verifier, and an honest prover restarts with fresh nonces (§7.3).

---

## 6. Proof encoding

```
proof = ser(A) ‖ ser(S) ‖ ser(T₁) ‖ ser(T₂)
      ‖ ser(t̂) ‖ ser(τ_x) ‖ ser(μ)
      ‖ ser(L_1) ‖ ser(R_1) ‖ … ‖ ser(L_k) ‖ ser(R_k)
      ‖ ser(a) ‖ ser(b)
```

Length: `48·(4 + 2k) + 32·5` octets.

| `n` | `k` | Length |
|---:|---:|---:|
| 16 | 4 | 736 |
| 32 | 5 | 832 |
| 64 | 6 | 928 |

---

## 7. Prover

The prover is a secret-bearing operation. It runs offline or isolated only (ADR-0038), on both
providers, and makes no constant-time claim.

### 7.1 Inputs and refusals

Inputs: a `pedersen-bls12-381-g1-v1` opening `(v, γ)`, the width `n`, and `ctx`.

Before any curve work, the prover refuses with a fixed error, in this order:

1. `n ∉ {16, 32, 64}`, or `len(ctx) ∉ [1, 1024]` → `INVALID_CONFIGURATION`.
2. `v` or `γ` outside `[0, q)` → `NON_CANONICAL_SCALAR` (check 1).
3. `v ≥ 2^n` → `OUT_OF_RANGE`.

It then computes `V = [v]·G + [γ]·H`, and refuses with `INVALID_STATEMENT` if `V = O`. It checks
the commitment, not the pair: `(0, 0)` is the known case, and any other opening of `O` would
reveal `log_H(G)`. It never re-blinds the commitment and never retries nonces for this case.

### 7.2 Algorithm (paper §4.1, lines (40)–(63), with §4.2 and Protocols 1–2)

```
a_L[i] = bit i of v   (i = 0 … n−1, least significant first; so ⟨a_L, 2ⁿ⟩ = v)
a_R    = a_L − 1ⁿ     (entries 0 or q − 1)

α, ρ, τ₁, τ₂ ← nonces;  s_L, s_R ← n nonces each          (§7.3)

A = [α]·H + Σ_i [a_L[i]]·G_i + Σ_i [a_R[i]]·H_i
S = [ρ]·H + Σ_i [s_L[i]]·G_i + Σ_i [s_R[i]]·H_i
    → absorb A, S; squeeze y, z                              (§5.3)

l₀ = a_L − z·1ⁿ               l₁ = s_L
r₀ = yⁿ ∘ (a_R + z·1ⁿ) + z²·2ⁿ r₁ = yⁿ ∘ s_R
t₁ = ⟨l₀, r₁⟩ + ⟨l₁, r₀⟩        t₂ = ⟨l₁, r₁⟩

T₁ = [t₁]·G + [τ₁]·H
T₂ = [t₂]·G + [τ₂]·H
    → absorb T₁, T₂; squeeze x

l   = l₀ + x·l₁
r   = r₀ + x·r₁
t̂   = ⟨l, r⟩
τ_x = τ₂·x² + τ₁·x + z²·γ
μ   = α + ρ·x
    → absorb t̂, τ_x, μ; squeeze x_u
```

**Inner-product argument** (Protocol 1 with Protocol 2). The inputs are:
- `g⃗ = (G_0 … G_{n−1})`;
- `h⃗' = (h'_0 … h'_{n−1})` with `h'_i = [y^{−i}]·H_i`;
- `u' = [x_u]·U`;
- the vectors `a⃗ = l` and `b⃗ = r`.

For `j = 1 … k`, with `t` the current length and `t' = t/2`:

```
c_L = ⟨a⃗[:t'], b⃗[t':]⟩
c_R = ⟨a⃗[t':], b⃗[:t']⟩
L_j = Σ_i [a⃗[:t'][i]]·g⃗[t':][i] + Σ_i [b⃗[t':][i]]·h⃗'[:t'][i] + [c_L]·u'
R_j = Σ_i [a⃗[t':][i]]·g⃗[:t'][i] + Σ_i [b⃗[:t'][i]]·h⃗'[t':][i] + [c_R]·u'
    → absorb L_j, R_j; squeeze x_j
g⃗  = [x_j⁻¹]·g⃗[:t'] + [x_j]·g⃗[t':]        (component-wise)
h⃗' = [x_j]·h⃗'[:t'] + [x_j⁻¹]·h⃗'[t':]
a⃗  = x_j·a⃗[:t'] + x_j⁻¹·a⃗[t':]
b⃗  = x_j⁻¹·b⃗[:t'] + x_j·b⃗[t':]
```

After round `k`, `a⃗` and `b⃗` have length 1. Their entries are the scalars `a` and `b`.

**Output:** the proof of §6.

### 7.3 Nonces and restarts

- Every nonce (`α`, `ρ`, `τ₁`, `τ₂`, each entry of `s_L` and `s_R`) is fresh per proof: 64 octets
  from a cryptographically secure source, `OS2IP` reduced mod `q`. This is the sampler of
  `G1Pedersen.randomBlinding`.
- No API accepts nonces from the caller. Reusing nonces across two proofs leaks the witness.
- **The prover owns its randomness source.**
  - It creates its own `SecureRandom` at run time, and never accepts one from the caller: a
    caller-seeded `SHA1PRNG` would be deterministic.
  - It never creates it in a static initialiser that a native-image build could run at build
    time.
  - **The entropy behind it is trusted platform configuration.** Java gives no way to verify
    entropy quality. A stock `DRBG` instance will run on a configured non-entropy seed source
    (Codex M0 F8 reproduced this with `-Djava.security.egd=file:/dev/zero`). The JDK, its security
    providers and properties (`securerandom.source`, `securerandom.strongAlgorithms`,
    `java.security.egd`) and the operating system's entropy source are therefore part of the
    trusted deployment, like the provider code. A misconfigured runtime defeats the hiding and
    zero-knowledge of every proof it makes.
  - As a **sanity check only**, the prover accepts a `SecureRandom` only if its `getAlgorithm()` is
    `NativePRNG`, `NativePRNGNonBlocking`, `DRBG` or `Windows-PRNG`, and otherwise raises
    `IllegalStateException` before any work. This rejects an obviously wrong or substituted
    algorithm. It does not establish that the entropy is real.
  - Targets that cannot provide such a source do not ship the prover. The GraalVM Web Image proof
    of concept, with its `Math.random`-backed RNG, is one. The deployment documentation (ADR-0061
    M6) states the entropy trust assumption.
- The prover restarts with all-fresh nonces if any of `A`, `S`, `T₁`, `T₂`, `L_j`, `R_j` is `O`,
  or any challenge is `0`. Both happen with negligible probability.
- Restarts are bounded at **8 attempts**. Exhausting them raises an `IllegalStateException`, and
  no proof is emitted.

### 7.4 Secret handling

- `V` (§7.1), `A`, `S`, `T₁` and `T₂` involve secret scalars. They are computed with the
  provider's secret-scalar entry point (`g1SecretScalarMul`), never the public one, as
  `G1Pedersen.commitScalar` does for `V`.
- `A` is computed as a full sum over all `2n` generators, with scalars `0` or `1` on `G_i` and `0`
  or `q − 1` on `H_i`. The **sequence of calls** therefore does not depend on the bits of `v`. The
  cost of each call can still depend on its scalar (`0`, `1` and `q − 1` differ sharply in a
  variable-time multiplier), and the §7.1 comparison `v < 2^n` also depends on `v`. This is a
  schedule property, not a constant-time guarantee.
- After `x`, the vectors `l` and `r` are blinded by `s_L` and `s_R`; paper §4.1 sends them in the
  clear. The inner-product rounds use the public multiplication.
- Temporary arrays holding secrets are wiped (best-effort) when the prover returns.

### 7.5 Test-only deterministic nonces

Vectors need reproducible proofs, so implementations provide a test seam. It is fenced the way
ADR-0046 fences its deterministic prover:
- The seed → nonce expansion below lives **only in test or test-fixture code**, never in a
  published artifact. In Java that is `TestNonceProver` in the unpublished `testFixtures` source
  set of `zeroj-bls12381`, guarded by its module-metadata check.
- Production code exposes at most package-private test seams. Package-private is not a security
  boundary in the classpath world, so each seam is bounded: a caller must already hold the opening,
  and the worst it can do is reuse nonces it chose itself or emit a proof that does not verify. The
  Java binding has three:
  - a nonce-source hook, which accepts only a source object, never a seed. The only
    implementation of that source in published code is the §7.3 `SecureRandom` source;
  - a path that skips the §7.1 range and canonical refusals (but still checks the configuration),
    so a test can force an out-of-range value through the prover and show that the proof fails
    (ADR-0061 I6);
  - a challenge tap that can only replace a challenge by zero, so a test can exercise the restart
    rule (ADR-0061 I4).
- An API-surface reflection test asserts that no public or protected member of the
  `org.zeroj.bls12381.bulletproofs` package, including nested types, accepts a seed, a nonce, a
  nonce source or a `SecureRandom`. The existing `G1Pedersen.randomBlinding(SecureRandom)` is
  outside that scope.

Misuse is not a side issue. Three test-nonce proofs of one opening under the same seed reveal `γ`
by solving the three `τ_x` equations, and from `γ`, `v` (reviewer (b), M0).

The seam replaces §7.3's source with:

```
nonce_ds = Init(DeriveSessionID("ZeroJ:bulletproof-range-bls12-381-g1-v1/test-nonces-v1"))
nonce_ds.Absorb(seed)                    (seed: exactly 32 octets)
nonces, in this order: α, ρ, s_L[0 … n−1], s_R[0 … n−1], τ₁, τ₂
each = LE2IP(nonce_ds.Squeeze(48)) mod q   (one continuous output stream)
```

If §7.3 would restart, a test-nonce prover fails closed instead, and the vector generator picks
another seed.

The nonces depend only on the seed, not on `v`, `γ`, `n` or `ctx`. Every positive vector therefore
uses its own seed: two proofs with the same nonces would leak their witnesses, which is exactly
what §7.3 forbids in production.

---

## 8. Verifier

Inputs:
- from the verifier's own configuration: `n` and `ctx`;
- the commitment `V`, as a decoded `pedersen-bls12-381-g1-v1` commitment or as 48 octets;
- the proof octets.

The verifier never takes `n` or `ctx` from the proof. An API that accepts an already-decoded proof
object uses only the configured `n`. If the object was decoded for a different width, the result
is `MALFORMED_ENCODING` at the `length` layer, exactly as for a wrong-length octet string. The
proof is never reinterpreted at another width.

### 8.1 Decoding, in order

| Step | Rule | Outcome |
|---|---|---|
| 1 | `n ∉ {16, 32, 64}`, or `len(ctx) ∉ [1, 1024]` | `INVALID_CONFIGURATION` |
| 2 | `len(proof) ≠ 48·(4 + 2k) + 160` | `MALFORMED_ENCODING`, **before anything is decoded or indexed** (including `V`) |
| 3 | the proof's fields **in proof order** (§6, as fiat-shamir-03 §6.2 reads a NARG string): each group element by §3's deserializer, each scalar by §3's deserializer. The first failure is reported | group element: `MALFORMED_ENCODING` (including `O`) or `NOT_IN_SUBGROUP`; scalar: `NON_CANONICAL_SCALAR` |
| 4 | `V` given as octets: the profile's strict decoder (`pedersen-bls12-381-g1-v1.md` §4). A `V` given already decoded MUST be a validated element of the prime-order subgroup (for example, the `G1PedersenCommitment` type). An API MUST NOT accept raw coordinates for `V` without the strict decoder's on-curve and subgroup checks | the decoder's classes (`MALFORMED_ENCODING`, `NOT_IN_SUBGROUP`) |
| 5 | `V = O` | verification returns **false**: no valid proof exists for an identity `V` |

Steps 2 and 3 are the proof's format checks, and step 4 is `V`'s. A format failure raises the
class; it carries no secret and no partial verification state. A well-formed proof against an
identity `V` is not a format failure, so step 5 comes last. The proof fields in order are `A`, `S`,
`T₁`, `T₂` (points), `t̂`, `τ_x`, `μ` (scalars), `L_1`, `R_1`, …, `L_k`, `R_k` (points), and `a`,
`b` (scalars).

**Why a non-subgroup `V` matters.** A point with a small-order component, such as
`[7]·G + [11]·H + (0, 2)` where `(0, 2)` has order 3, has no Pedersen opening. Yet check 1 can still
pass for it when the integer representative of `−z² mod q` in `[0, q)` is divisible by 3. That
happens for about one challenge in three, because the multiplier applies that representative to
the order-3 component. The subgroup
check on `V` is therefore required for soundness, not only for hygiene (Codex M0 F1).

### 8.2 Challenges

Recompute `y`, `z`, `x`, `x_u`, `x_1 … x_k` by §5. If any is `0`, return **false**.

### 8.3 The two checks (paper §6.2, equations (97)–(105), checked separately)

```
δ(y, z) = (z − z²)·⟨1ⁿ, yⁿ⟩ − z³·⟨1ⁿ, 2ⁿ⟩        (⟨1ⁿ, 2ⁿ⟩ = 2ⁿ − 1)
```

**Check 1** (paper (98), five terms):

```
[t̂ − δ(y, z)]·G + [τ_x]·H + [−z²]·V + [−x]·T₁ + [−x²]·T₂  ==  O
```

**Challenge products.** For `i = 0 … n−1`:

```
s_i = Π_{j=1…k} x_j^{e(i, j)},   e(i, j) = +1 if bit (k − j) of i is 1, else −1
```

Bit `k − j` is the `j`-th most significant of the `k` bits of `i`, so `x_1` (the first round)
selects the half of the vector. `s_i⁻¹` is the same product with every exponent negated.

Paper (99) says "the jth bit of i − 1" without fixing the bit order. Most-significant-first is the
order the folding of Protocol 2 (29)–(30) forces. Least-significant-first rejects honest proofs.
For example, with `n = 16` and `i = 1` (bits `0001`): `s_1 = x_1⁻¹·x_2⁻¹·x_3⁻¹·x_4`.

**Check 2** (paper (105), with the independent `U`; `2n + 2k + 4` terms). Paper (105) writes
`g^{x_u·(a·b − t̂)}`, using the value base as the inner-product element. This protocol uses the
independent generator `U` (§2, Protocol 1), so an implementation of the paper's equation as printed
does not interoperate with it.

```
Σ_i [a·s_i + z]·G_i
+ Σ_i [y^{−i}·(b·s_i⁻¹ − z²·2^i) − z]·H_i
+ [x_u·(a·b − t̂)]·U
+ [μ]·H
+ [−1]·A + [−x]·S
+ Σ_j ([−x_j²]·L_j + [−x_j^{−2}]·R_j)
==  O
```

Return **true** if and only if both checks hold. Check 1 is evaluated before check 2. A
vector's `layer` (§11) names the first check that fails. Both checks are evaluated in every case;
the verdict does not depend on which one fails, only the `layer` record does.

### 8.4 Determinism and resources

- Verification uses no randomness and no unordered iteration.
- Its work is bounded by a function of `n` from configuration, never by proof contents; it may
  stop early on a format failure.
- Its **verdict** is one of: accept; reject (`false`); or a raised error class (§9). It is a pure
  function of `(V, proof, n, ctx)` and the pinned constants, identical on every provider.
- No provider may throw on adversarial but well-formed input inside the checks: zero scalars,
  coefficients that are zero mod `q`, and identity partial sums. All scalars passed to the
  provider are reduced into `[0, q)` first. An unexpected provider exception would split a
  replicated host.
- The `layer` of §11 is diagnostic only. Hosts MUST NOT branch consensus behaviour on it.
- An implementation MAY evaluate each check with one multi-scalar multiplication, or term by term;
  the verdict is the same.
- It MUST NOT merge the two checks with a random weight (ADR-0061 D5).

---

## 9. Error classes

The proof protocol uses the registry classes of `commitment-profiles-v1` §11, plus one new class:

| Class | Where | Meaning |
|---|---|---|
| `INVALID_CONFIGURATION` | prover, verifier | `n` not in the set, or `ctx` empty or longer than 1,024 octets |
| `MALFORMED_ENCODING` | verifier | wrong proof length, a malformed point, or an identity proof point; also from `V`'s decoder |
| `NOT_IN_SUBGROUP` | verifier | a proof point or `V` outside the subgroup |
| `NON_CANONICAL_SCALAR` | prover, verifier | check 1 failed (`v`, `γ`, or a proof scalar) |
| `OUT_OF_RANGE` | prover | `v ≥ 2^n` |
| `INVALID_STATEMENT` (new) | prover | `V = O`; carried by `CommitmentFormatException` like the other prover refusals (registry §11) |
| (verification returns `false`) | verifier | `V = O`, a zero challenge, or a failed check |

---

## 10. Conformance vectors (ADR-0061 I12)

Pinned at the draft repository `mmaker/draft-irtf-cfrg-sigma-protocols`, commit
`91cc933051af88b58e350af78a8ea961c56a30c6` (2026-08-17). Both tags, `draft-irtf-cfrg-fiat-shamir-03`
and `draft-irtf-cfrg-sigma-protocols-03`, point to that commit. The JSON files under `poc/vectors/`
are the drafts' machine-readable copies. On 2026-10-24 they were checked to carry the same
records as the `-03` text appendices.

ZeroJ keeps unchanged copies, with their provenance, in
`zeroj-test-vectors/src/main/resources/test-vectors/cfrg-drafts-03/`.

| File (`poc/vectors/`) | SHA-256 |
|---|---|
| `fiatShamirCodecVectors.json` | `97d85f96e252111fd01e4147d9ebc48c80203e5783fef1eea2204211d847c821` |
| `fiatShamirShake128Vectors.json` | `f04cdf455b60239d20392813ffd5dd8d079fb1c0d5b0e07de3e50899bd6f6502` |
| `sigma-proofs_Shake128_BLS12381.json` | `e9f942c2d76f2086793b771fbb32cc8452e51dcf274cf163258d36b8d9906e94` |
| `sigma-proofs-invalid_Shake128_BLS12381.json` | `1da51dc890c0d9fe550d14c9f0f71c5175c5c5b6c6a698ef53074bb4c58bc740` |

**In scope:**

- **fiat-shamir-03 codec:** B.1.1 `serialize_varlen`, B.1.2 `serialize_uint`, B.1.4 `varlen_empty`,
  B.1.5 `decode_uint_wraparound`, B.1.6 `serialize_field_be`, B.1.7
  `deserialize_uint_reject_modulus`, B.1.8 `deserialize_uint_reject_short`, B.1.10
  `deserialize_varlen_reject_truncated`, and B.1.11 `deserialize_varlen_reject_overflow`.
- **SHAKE128:** B.2.1–B.2.11 (`init_squeeze`, `absorb_squeeze`, `absorb_split`, `stream`,
  `empty_absorb`, `interleave`, `multiblock`, `rate_block`, `squeeze_zero`, `derive_sid`, and
  `decode_uint`).
- **sigma-03 A.3.1 valid proofs:** `discrete_logarithm` and `pedersen_commitment`, each `batchable`
  and `compact`. The checks:
  - the session identifier is reproduced from the tag;
  - every challenge is reproduced;
  - the proof verifies.
- **sigma-03 A.3.2:** all 32 adversarial vectors. They share the `discrete_logarithm` base
  identifier, but some carry other instances: F2 and F2b use a `dleq` tag with a two-equation
  instance, and E1–E3 are synthetic multi-element instances that sigma-03 §3.5 instance
  validation rejects (E1–E4).
  - 28 must be rejected.
  - The four non-reject controls (`batchable/F1`, `compact/F1`, `batchable/F2` and `compact/F2`)
    must be accepted.
  - A1 and A3–A6 (points) and B1–B2 (scalars) must fail **at deserialization, before any
    challenge is derived**. They also run directly against §3's decoders.
- **The sigma harness** is test-only. To run the A.3.2 set it needs a small generic
  linear-relation verifier (sigma-03 §2–§5), so it also verifies the other ten A.3.1 valid
  proofs. Those ten are reported separately and are not part of the gate.
- **SHAKE128 outputs:** they are also compared with an implementation ZeroJ did not write (CPython
  `hashlib.shake_128`).

**Out of scope:**
- B.1.3 and B.1.9 (extension fields);
- B.1.12, B.1.13, B.2.12 and B.2.13 (the sumcheck example over Mersenne31);
- B.3 (TurboSHAKE128);
- the other five A.3.1 relations (ten vectors) as a gate. They are verified by the harness, but
  not required.

Valid-proof checks assert reproduced challenges. Rejection checks assert only the rejection and the
layer it happens at.

---

## 11. Vector file (`zeroj-proof-vectors-v1`)

One JSON file per protocol at
`zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/<protocolId>.json`. It
follows the conventions of `commitment-profiles-v1` §13.2: string values, lowercase hex in `…Hex`
fields, and decimal integers.

```json
{
  "schema": "zeroj-proof-vectors-v1",
  "protocolId": "bulletproof-range-bls12-381-g1-v1",
  "profileId": "pedersen-bls12-381-g1-v1",
  "generatorSetId": "bulletproof-bls12-381-g1-gens-v1",
  "generatorDigestHex": "<D_gens>",
  "generators": [ { "name": "G_0", "compressedHex": "..." } ],
  "spec": [ { "path": "...", "revision": "...", "date": "...", "sha256": "..." } ],
  "generator": { "script": "...", "scriptSha256": "...", "python": "..." },
  "positive": [
    { "id": "...", "bits": "16", "ctxHex": "...", "value": "...", "blinding": "...",
      "commitmentHex": "...", "nonceSeedHex": "...", "sessionIdHex": "...",
      "challenges": { "y": "...", "z": "...", "x": "...", "xu": "...", "xj": ["..."] },
      "proofHex": "..." }
  ],
  "negative": [
    { "id": "...", "bits": "16", "ctxHex": "...", "commitmentHex": "...", "proofHex": "...",
      "expected": "MALFORMED_ENCODING | NOT_IN_SUBGROUP | NON_CANONICAL_SCALAR | INVALID_CONFIGURATION | false",
      "layer": "configuration | statement | length | point | scalar | challenge | check1 | check2" }
  ]
}
```

- **`generators`** lists all 129 encodings in Appendix A order, and the file has at least one
  `n = 64` positive case. Together these cover the generator set's admission vectors (registry
  §2.4 item 4).
- **Positive cases:**
  - the prover with the §7.5 test nonces, for `value` and `blinding`, at `bits` and `ctxHex`,
    MUST produce `proofHex`;
  - the verifier MUST accept it;
  - `sessionIdHex` and `challenges` MUST be reproduced.
- **Negative cases:** the verifier MUST give `expected`. `layer` records where it fails. Failures
  in decoding `V` (§8.1 step 4) and an identity `V` (step 5) both use `statement`.
- A missing (null) argument is a `NullPointerException`. An argument of the wrong type is an
  API-binding error, not a vector case (registry §11).
- **Prover refusals** (§7.1) are listed separately in M2 under `proverNegative`, with the same
  conventions.

---

## 12. On-chain

There is **no on-chain verifier** for this protocol. Its challenges are SHAKE128 outputs, and
Plutus V3 has no SHAKE128 builtin. A script that took the challenges as inputs would not be a
verifier.

ADR-0061 M4 measures the cost of the algebra in the JuLC VM as a study labelled
"not a verifier". It publishes nothing.

---

## 13. Deterministic-verifier contract (Yano-X; ADR-0061 D9)

A host that runs the verifier inside a replicated state machine relies on these properties:

1. The verdict is a pure function of `(V, proof, n, ctx)` and the pinned constants.
2. There is no randomness, clock, I/O, environment read or unordered iteration on the
   verification path.
3. Every provider gives the same verdict.
4. The proof length is known from `n` before decoding. Work is bounded by `n ≤ 64`.
5. `n` and `ctx` come from the host's configuration and state, never from the message. A host
   that supports several widths picks `n` for each term by its own state rule, never from the
   proof length.
6. The verifier provides **no** authorization, replay protection or balance rule. The host
   applies them, including the integer-balance rule of §1.1 (ADR-0051 D3a), using for each term
   the configured `n` under which that term's proof verified.
7. "Verdict" has the §8.4 meaning, and `layer` is diagnostic only.

---

## 14. Revision history

- **r1 (2026-10-24):** initial specification (ADR-0061 M0), with Appendix A pinned. Before publication it incorporated
  the M0 second implementation's findings:
  - `ctx` must be non-empty;
  - the proof is decoded in proof order after the length check, `V` is decoded after the proof's
    format checks, a decoded `V` must be a validated subgroup element (the Codex M0 review), and
    the identity-`V` verdict comes last;
  - the check evaluation order, the `layer` rule and the `U` deviation from paper (105) are
    stated;
  - `a` and `b` are not absorbed;
  - work is bounded by `n`;
  - deriving the generators includes subgroup membership;
  - each vector uses its own nonce seed;
  - the sigma-03 A.3.2 scope is described accurately;
  - the round string in the tag no longer ends with `.A64` (reviewer (a) F2);
  - requirement 2 is met through the protocol and ciphersuite identifiers;
  - the change rule and the MSB-first example are stated;
  - from the M0 security review: the statement and integer meaning (§1.1); `ctx` guidance; `V` is
    computed with the secret entry point and the schedule claim is narrowed (§7.4); constraints on
    the nonce source and a restart bound (§7.3); the test seam fenced as ADR-0046 does (§7.5);
    decoded-proof width (§8); the verdict definition, provider no-throw rule and `layer` as
    diagnostic only (§8.4, §13).
- **r2 (2026-10-25, ADR-0061 M1):** the Java binding. No byte, check or order changes; the M0
  Python known-answer proof is reproduced byte for byte by the Java prover.
  - The proof-protocol descriptor type is `ProofProtocol`, with the constant
    `ProofProtocols.BULLETPROOF_RANGE_BLS12_381_G1_V1` (`commitment-profiles-v1` §12.1).
  - The Java types are `G1RangeProof`, `G1RangeProver` and `G1RangeVerifier` in
    `org.zeroj.bls12381.bulletproofs`; the §7.5 seam is `TestNonceProver` in the test fixtures.
  - SHAKE128 is `org.zeroj.bls12381.Shake128`, on the Keccak-f[1600] permutation that
    `Bls12381Hash` already used for SHAKE256.
  - §7.5 lists the three bounded package-private test seams of the Java binding (M1 review,
    reviewer (b) F1).

## 15. References

- B. Bünz, J. Bootle, D. Boneh, A. Poelstra, P. Wuille, G. Maxwell, *Bulletproofs*, IACR ePrint
  2017/1066, revision of 2022-04-14 (§3, §4.1–§4.2, §4.4, §6.2). The copy used was retrieved via
  web.archive.org, because eprint.iacr.org blocks direct downloads; its SHA-256 is
  `2204cf02c3818543adcdd4325b5d4ca205e43d428701300214f198d19e86de61`.
- `draft-irtf-cfrg-fiat-shamir-03` (2026-08-17): §2.1, §3.2, §4.2.2–§4.2.3, §5.1–§5.2, §6, §9.1,
  Appendix B.
- `draft-irtf-cfrg-sigma-protocols-03` (2026-08-17): §8.2, Table 1, Appendix A.3.
- FIPS 202, *SHA-3 Standard*, NIST, August 2015 (SHAKE128). The PDF's SHA-256 is
  `1592607831ff0908cc590632ce371c6c95e94025bb1a0c8ae90a4d0ec1ed025e`.
- RFC 9380, *Hashing to Elliptic Curves*: §3, §8, §8.8.1.
- ZeroJ: `pedersen-bls12-381-g1-v1.md` (r2), `commitment-profiles-v1.md`, ADR-0038, ADR-0051 D3a,
  ADR-0060, ADR-0061.

---

## Appendix A. Pinned generator encodings

```
D_gens = 69abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef19
```

There are three reproductions, all from RFC 9380 and none reading the others' code:

- Java `Bls12381Hash.hashToG1`, in `BulletproofGeneratorReproductionTest`;
- the stand-alone Python implementation in `zeroj-bls12381/src/test/resources/bulletproof-g1-reference/`,
  whose machine-readable copy is `generators-v1.json` there;
- py_ecc 8.0.0, run by the ADR-0061 design reviewer on 2026-10-24.

They agree on every encoding below. Order: `G_0 … G_63`, `H_0 … H_63`, `U`. Each value is
`compress(P)`, 48 octets.

| Point | Compressed encoding |
|---|---|
| `G_0` | `82ca0040fdcaae82d1dd666dbddaa09c3cd9546ab3a31150cd56385b167c7e0ac100305d0896a5615281c9aa8712190b` |
| `G_1` | `ac1f919ad08cf6a24a80d52f4c1172410b3ab1b270374b74c4da4ea21437fd1825b142af9722681a66c06aa0409b7403` |
| `G_2` | `aa4c2692fef0dbb5a11daaf2c19b891d5d050a99d836535825c83d5fd2637d177aac09bd0d8635c62f6551cc19abacb7` |
| `G_3` | `8c9dfe0243bfe1e91df7600949ad27fbe8ff0e164abc6c4fc1cf8cadd390c9ce431adad19e2131cc23853c9d587e308d` |
| `G_4` | `83887742c598d9379529b8ea56833714a755263464eed57d2f706017c0965b55c875d399e4fc213217870cb429ea1dec` |
| `G_5` | `8112ec3a3970c6b161517be9556db196d38edbe3ebd711e8e63cf3a3784e85b1aecee28cde8489e4288d32194a616c43` |
| `G_6` | `a223e918ab25d78ad06114eeb0f1faceec148762b1a3c0986ef33395d67c3ede73dc31bc492c0cf5b03ebf3a7f715e22` |
| `G_7` | `8580881b258e4aebcd9d96890a69931681b039611655dddedb51ea0ac8adc8536b3287e01518972b14f5ba71c024c8d9` |
| `G_8` | `946af27a4477e27a09d34533ab02fef35ae67845c032f6fe5a443b005ffbb4881f0acd9ff3cfb88a744139933fab48c2` |
| `G_9` | `80b182fafc8dafe415f496029412ffb94fd25495640448863f52469e218844721005ca243868793ef16839fe36f1f914` |
| `G_10` | `8b2db246d53eeebd0a0ea1bee579f26fba41a9547926585a358f9f2490a449a0774f2c9ff6c46168c0b3d55ad1276ee6` |
| `G_11` | `b8575f5c69058ead8d9a5f5e043eb4960da3fa3239103c95a45f5eda9281074bab5d6b5b2189fd68b4c40e901a3cb583` |
| `G_12` | `8ace2f20ae4f5465ea892a72b824b32ef76e0e2a5178f0f4cb8f0fef386ff4a7fbb1951e7b53706761cdc582824f58ab` |
| `G_13` | `b9eee450b606958308b270dba17b26c072796b455183f7e260d33b4f10b9b574ef1c1e291ee7c18eec76a38348a31644` |
| `G_14` | `b73ef17b180e6ca9e44ecea3b00036d9ad1bd3a8193c0fb48bb65968add218fbf02c8e60d809990ddc6f58af51451f7b` |
| `G_15` | `b4c7d95f314229cd84c4d45ef6e92e803d9caffeb0ee574f3f2578f5404382e160924bd0ebff8226e78ace6af44a4176` |
| `G_16` | `80c7604574dafa6d29d33a0b28702598f6be7f63786b258586d96b520d05c9c5c3b40bf71f27367e94c6df49082c82a1` |
| `G_17` | `a86a50f44ac52c51ef9deb036fa9eb1e79a7938113102daceb90d0ecd415f593a8aec64767ad4111db0bd95226b48f58` |
| `G_18` | `8444d6d94457f70f175317e0af70e1add29801bbf75fcb5f0c567e4ac5925bf54b816e365239ecf3f6a6004ec7beddc9` |
| `G_19` | `95acecda5b597c997f57f255e87ee1c5cb03e83db81cf9506f161fc5f57f1de2fe16f85d453226c4f8ff03482585ac59` |
| `G_20` | `84cd34e19db686d063279702d2e64d951cf496fe1c2ff6f983a3ac4f1813449955a466de037e276ae62848eb6ccd093c` |
| `G_21` | `96ffe43ad0dad038094fcd1bc1f356aec4973b0b144019da92ea0bed3f0a9feced6a2a454f586e906de512e6be2e4227` |
| `G_22` | `b659f7c852783d758f75ecdfb23efb73833cd64e2f49d0a75c1d955bb7d9f5b8683b0282d5c61ee70663e5c6ca0cf5d6` |
| `G_23` | `b3e968cc78943241b0e176bb24363de75542858591d2ff5f3327660627488853a8ea107594a59209fa0a5b10e5415d80` |
| `G_24` | `9828e791bd610281fb29bdbfc1699682bc46b658d2982f6b77a2b67825d697646a655d1fba2f7816327bd6254706deeb` |
| `G_25` | `94f0127fb8bfbfd0e34c6b5c3349301f5222781a7ce44d3334a684e9971be6f07658d47bc6ef7b565cef4b17d9c72813` |
| `G_26` | `a75d23a5ba467f71cde7dbb0529069ae26ee0fa75465433548e0e9cc3d6cda82dac718d98924c82326d5d8bf3b88a7e1` |
| `G_27` | `ae38be5289776c4d56e8caac024a408b9c70f99aa38658afb45ca8f5d91b07c1ef0295caf806126f0e8df92c5d94e6db` |
| `G_28` | `a92a2020233d3305d9cbf8561ac6dace8873c54ae2a13aed29832f8df315763815905e5271b33f5e29ea47fc6b6b4f11` |
| `G_29` | `b94aa4e0546775b028733e90fdcda6e22a5d3ff3521d5316ea66c6475f59edb40471d117e1a179143c308867ef47b3d7` |
| `G_30` | `b799a248151f5fbbe2b1925dbb973dc560c6359bd27fa3a1bf1cbf0597d373a12af54d10ef710648b01db0c797cb9249` |
| `G_31` | `b5aa689d9a7af0eed59d0e628d437dba8d04ad2c50b976d7a1c9ea2814c4242dc40bbad3228da413cb293f7d0996765d` |
| `G_32` | `b8bb2238b78bf1c3d1215fa2410d8887c3160aafa7e37e2b72f737de1ee2fb6ccd0ddfd40e9c7cf5d0a18906f31c6cd2` |
| `G_33` | `b985146a8b6d2b9405ad75ac7768b2bf00b98b92be8cf61d099543eb19d1461e1c1ca2423a0fe498d1e0066d51722d7c` |
| `G_34` | `b8a851df1b4b378eca406b50d88ed3a8586bae1f07545f426295bba6ac2ff527fbac25ef67db1e5285753eeb73499280` |
| `G_35` | `b3432854210f5ba00992dba5510fe94d5f806d587b2d6a59dd5bbcf44962615a5f6a04da532ca656773b05d414be8be4` |
| `G_36` | `a1d420a83be98aecc722b72c8ffdd7ad7f9193753e688fecef39336655405bc041d825f2b3e4432a9785b6b9e8087230` |
| `G_37` | `a2f4e5cf5bcf295db725e36b0b0f64dd2c2e9af9677efb869ebb71f22d32548862a4592a2f793add358d4fa413c96554` |
| `G_38` | `a1b65f34dc9f903c5467f5880a04f48d208705341dcca5909692af1a3ba8a49b1ee5a343915f3f3a50a3d39fcff4d312` |
| `G_39` | `8d820ca564f17e9b03e34c2e39704ce38904f2f83d9af763be566a4ae3ce70fd63c797492850d672197294a2ece300f5` |
| `G_40` | `ac50be30f2fe0de55e957544a4f400ab2b43716a30a4dbf1cdb1c980d15459632fc3cd1249b3ec3bc71e5b4e5b9d8e0b` |
| `G_41` | `979a715d1b76cef6090b972eccd5fdfff26a62577d3fb29359f23ba2a1c3e985b9f16bc59eb6169f0b2ab9c926e420a8` |
| `G_42` | `a070feb73c96b54d34be3ce931c51d34ffbdf0a2c0eed717e2d19f995995a7055ff199b68543826f0522202bf452ea26` |
| `G_43` | `a6be88ef610278f4861fe4a880bbf019e86b5bee439514160240dbb224935639c1c898b7f89e2fcc0219edd593275d7d` |
| `G_44` | `9705f3e8c23af393d7a0cd1592ab49e2417d57167c36a5e6d10abe12335d4fcf789fafb503098bc291d247333822fa8a` |
| `G_45` | `a7daa703335505a3722caa69f80b2d50168bfef796a8aaafffd9d23e8882f475d026a6b3f6bdca2895304ab571158685` |
| `G_46` | `903946088346bb0631f9f498aa0badd47755038c83ad817a1c28a2babfda7cf18474da3d7e6b9f58731510ce2cb0da73` |
| `G_47` | `b30c1cbe2ecd3d5c41d892e22986059686f1728934d788aaefb0b9ed4a4b073316b192a1ec4149142f4613e1ba5478e8` |
| `G_48` | `86a7f5df2e571bd95f1e2b4f880db041affaed014e4e9d3a8533ede275ff25728d964036e5c68b80adfbfb4845cc7795` |
| `G_49` | `842b7407d3ca099cc7e8635bf60ae8e7922cd01bd762947759107e127aad754da9476731cdeaa4be163e84c42a8b12e6` |
| `G_50` | `a327ab9093ef86e9bec231c3e25c49ac7d3310f9b7adff09ebcf70759a46134971c33d56c506dd5932f12ad313d9c520` |
| `G_51` | `ae12b7cb46c52023517c5d24ad07d28015b4dd3d3d7685fcecdd144253a1175d90dfd6cbed50370807a46ca84e9e2e62` |
| `G_52` | `97d6ebd5e99c2b8a2469c9bfc866e16308bdc483fa2ebbac311140035648a87efb705731731fe6e5b714b9ea7bfa5608` |
| `G_53` | `83c5493642d54e49748ef3fb20fe56a5f158b12bc2191e5e65abe8f7b4673ba67602a5a18a4a91328c330b8ca83177d3` |
| `G_54` | `a68efd028f7a853a827310c8a7d6fd8655a72ebd891184e57cb98faa35fbb3adc529e093f17426c5529785e5df198e0e` |
| `G_55` | `b24765b4823fbb60d3954da4845683834aea69d0ea1cb934559b150250c60cc52042936cb28aeaa214fc699fcfc43905` |
| `G_56` | `aebb8f8c489c8c5882eb5fbbd0899cb2986a51af823956a128c1521fc2b3357e64b99a5a9cc25254086aed73f689fdc3` |
| `G_57` | `aa9e1e0b820556457f429ce36d879c88f4798681ea49e1bfb0f940279eeaa0b1851a4a6295fdb626a71d0a7db237779c` |
| `G_58` | `97f556bb64501b0790d9bd161318f8380d77ca798013d6dd0b083e4cd3e2588517131bdc2b7eee1cf7b342231210ba2a` |
| `G_59` | `8349bf7cda99b9a62d4293121581a2a2dc019c20622b097d808aa2424d3f9c3d1371f7d4da29a2815f6b6af38fa51ed8` |
| `G_60` | `b56aa2e47c241c227f260a6e8c16a40dfadf874edb17dc2185e77f204fc6d4f6283c4e4443b40dd907e7d63bbb98495a` |
| `G_61` | `a5bc5bec83102faef7b09517c740c72ef2ae0481b5223e0b94efa47383d6b6078f324fb6984f552b421a26b6bf55da72` |
| `G_62` | `8518f5a10b8e32f97c057adab4ac6ad07322caa9fb8555de9c367c58cb5765ecfbbb23ccdd041cd4cadeec420663089d` |
| `G_63` | `ad1cbd97688003fb6963288fa9af2d6830a1798bdc5ad10fa0ffa0b0a7f804ab92150660f961111b8fb3b94477f1ba10` |
| `H_0` | `b93983422e013af87d7cf978597e1acaff89d2d8179b6442a3519542d92e7bfaa8d9d6a55ca0ef231f9f5e9408ef21e7` |
| `H_1` | `98c0cbce702916378201cfceb6838a5faf9967a4828d6205b54328ddd316ed5585d950466d2e43787923b3ef5ff38446` |
| `H_2` | `8dc6dbc198f08040efda1e1cfc5863f33fc44c036de4021a0db61c869eb8c4106f0dbfb59eb1e6a1a2eecfd428bc4416` |
| `H_3` | `b15e4a50d068f4d7e562b31e3ef2a2d14ca9962ad5250a189227a3db71c1ddb6bd8982215eb0654306ffb749a0c9f7e1` |
| `H_4` | `9610c10418a4164b3278e953e90d6dd8745ec241ced30f6a5e714e1bd9e7acb61b901fd69af42a927da276ced872fb9a` |
| `H_5` | `85a73b9a6c3f8cbd0cac63727a05e703596323d0e9238f423e91416cc56796231af8364f0a00e1b9166e507673ebe530` |
| `H_6` | `b89b942c13dc91f981c69e394645ebca82690556ab9f4280c55a09dbad1084851f48013a5828ab01d056cfd832d29ce8` |
| `H_7` | `90359fc6d85f732610202d8d4c5f8dfa35510a2898389bbc32e6490131d5aa8e820269499a6699fe9b2f637ee09023f4` |
| `H_8` | `a7c80ebac1fd184bdb1dfdb9133cfe900f79ef5b5bb87e82f75e4ced6d469d15da7cf7353f15e460d7c875d08ad6ba8f` |
| `H_9` | `887c7d989cd51e063734ba8c065fa85e43e846fd90d019a79353d0732232422c938ecdb82c26f56f9cfb456b60a925c1` |
| `H_10` | `b7ecae415bd559a9f0d0e5b44b24c7007f7e75d31f04bbbf95c8a98fd40bd51a2f6a2aa5cec8a367740857932e86c428` |
| `H_11` | `87e5bc155a914d529f9c22eb0ae196bf1e4dbde2a8042f9f17e31e13965c7bd405479a481a77baeb279f6108f408e191` |
| `H_12` | `812f854ccad3328712724c5e28da74e288009e4dd75915a3218cabf2c79d4ca6438fe1d96779067b4f8997f39bd5c7d5` |
| `H_13` | `af24e7fa99a91f1243b3bbd4e26d474a9205d4354f4d26cd0778820098a9208f24c9745d193e313d4ba85f009f72e5ce` |
| `H_14` | `aff29eb712a5dc8b57b8eef5a45405e4fc9361173729d15110145f11cf1070ad7b19a1044ed3940e19302e4d241f17ec` |
| `H_15` | `8daf8ea644e5938c43819d5d149f83875dc58272f1a78e750f2904355a37e9844265f7df1a2ffa88752fe56015c494de` |
| `H_16` | `909b1a4b82fef76f8a97a3db2cc66ab401eb5aefd2b1faa1423be8e9db982ded6143de772dd1615bbd0978308b731ce5` |
| `H_17` | `b909ea71b4dc9624b156d90380c84968751e60962610831d20b105d23c25e7997f9db6dcf848c107b047450aa3feb1f8` |
| `H_18` | `a23a8111494471d2982ca5f5d42101d1ce4591d9f87c0311b262264db276d5aa1df84f9c88dfb8d6d9ac5420afd9a35e` |
| `H_19` | `8f21ea555da04f49321dbc9919e442e82f40f2c2efeb1d941521d06010fc4a0864f9012d7f1c955899d11964e7218103` |
| `H_20` | `85a617bc5631eb1050c0770387b0c213c110afa1ea93c1f36c4802685aeb88ec4c079ae7e16f4ec5473ff4039ea8aa9e` |
| `H_21` | `8b28fdc6815faf9e3709e9f01ccc3f588c49f53161a61f1e5bd80eb29bb6390ef907d044cf43dc77c109d283e31cd71d` |
| `H_22` | `b083bc506c6360c4151d73dde36ee0ebf155966c2554bd8d9e196823e59cfeef21ce49854a67d227f6095d978b00520d` |
| `H_23` | `82aa105d3b4c0417969ac37cf98583fa6b6b3a9eb60182bc0b3ff8693eac561a023b78b351d616e11e234de8f37bbf5c` |
| `H_24` | `9808fbded822ae330fa51cbbb8e0046773eedd991a0b41ec6d434ba795b349e8c3c0fe20928055bc5350564d39f6a1f0` |
| `H_25` | `afca6f5a4a3dc2033ddf8119115d707d6027455996e82d29a014669569eb33890f29bf747d5c530153dd8c6e8ff9ad41` |
| `H_26` | `8fd266d359c0f5046bf6185a5f58b55723dd1de7dd40449d31ffefba7f8167fecfd259e15d2a5d7a948f3e7302850aca` |
| `H_27` | `96332b95406828450172f540f9e15aa1030db766c76b6dc8a62faf3ec67eb5a1c92499b8655ff3d38676e61261270c23` |
| `H_28` | `83b7c7eead6d61f312088469bd2929763a48dedde38d0bdc390dfe39a514f6a0b565cedd05e54841c2e45f3e17b95a06` |
| `H_29` | `b16ce8ced752a85e3fd0a46d037eceb9c35a88a583c42c2899de72dd1439c9def2adb3294941960d21ab0763b6accae0` |
| `H_30` | `8d879228c967e8aee06d0deac0f4b3eb31a99fdebe8966df72487466198a8d12de21808f34d7828eaa92446bddb67579` |
| `H_31` | `8d7a70096660d9de71785e2c0f3dedc22247818afb7b0700a67a1e0b47fb07bdcd194604da086d252adaeb54316cd6ed` |
| `H_32` | `800aa1a19081f1e07f14d782facbd3b4327722d6ee70d60ce43d003c537853cb0f3283dabf045cfa56875387447e5302` |
| `H_33` | `8383ee315aa3a320095d6ee1c2813bb29d8eceb4c9cba4acfb87ecd0e76054015952f9a143a585b472cb29ad1a6202a3` |
| `H_34` | `a0230d60740bd1d84ce8eaf532a5ef547a164c49331ab14c87f4ee9a4a45de74938c6e47523649bd2c526068d8586416` |
| `H_35` | `b1548ba89e0be98bb31cc8a6a848f8d9dc8463de2411b2421ebfd13a7899477ed06c77da08f62ac6cf698292aa7b2ecb` |
| `H_36` | `b5f868d03d5b36127f772072d07da73e8ffa628a343193e29e3b628a20168218fca3958e544f96e3893b87039d01b6ac` |
| `H_37` | `86295f005c35fe3e82fee184dde649b6a31e436eacf6454310c8349473f4222229c555bac27ec018c281f4c3533a5254` |
| `H_38` | `acfee6ad9cf49d4b40f3b31230b7eb72bcf51914aad8d44232c1fe0a56e61db45b4b9f0b75a047955a3e185f4ab4f674` |
| `H_39` | `85dbd71550c1a526c82e0c207afc42266f87308f34d1dbdfbade4baaa8e0950955cd6fb39a9064d6ff23f34979eff616` |
| `H_40` | `98e71b85be177e2e439366f5480cb62d0b81052275cd3c43373a7c3a7d3fcac8c056debbd40d46fa5faff8fb8a933d44` |
| `H_41` | `98934b2e522118f7ff9176b826313325b6de2b164dac70a44994d3335a28d6ff89a9c58b94fa82ce35e980618842b122` |
| `H_42` | `b3b9214dd640019a3811b54708cbbd8b19d448b82f29d4d26c7b57b286ba2c9cef91a585346c46eec825ea61845823f4` |
| `H_43` | `9365a88f37cf72a3c9eec14dab305dc4a145c585caa1962acdc68405adf3297b14de7322ada63efd2e9cd18d2aa09596` |
| `H_44` | `984d815b09dfd668901862a3fb6c79dea02b2188b5a109600a1dcdb392e0948a6a243688fa0f27d94eb5af68bb53125a` |
| `H_45` | `91dd73a88b28a9cd722952e0d4525af6e8e45c594fe6b60d6fe6977fb128c8b439504750337acc3a7e2dc849dcf3d918` |
| `H_46` | `b47925aa8b0ad20a5e587db49534e050e28492395bf07d08dff1244181a3bd3b24142b311c1468a5b21a20ef22f19e15` |
| `H_47` | `9240a367e5231aa3993d484d7558ad069cd47db0f911c7d84072260d18d375db0050c1c7cea9de993957bd5d8540b54d` |
| `H_48` | `a4e2d1215644d063c6ffe28d174e57b4a2ff0ac136c9c4ef9241099cec2fe59cbc62dfea816282cb78bddbe26827123f` |
| `H_49` | `a35617504745af2d67ab32618294917bb34a0f5f50f31b7870a0dd041bd309c1a59fad1ef59bd468a3020ddac5ab51bc` |
| `H_50` | `9157aaa70da86db7d9d4c6752f0644c7071812992604607107cd149acf5627e1bb4ce653c9f916f0d12a3064e3778a6c` |
| `H_51` | `b026929d3cf8d84202724fb7563bad8e899f48986d1c985a4dc72b728bbb293b980a99d8d834aad3763a05d95c8caa57` |
| `H_52` | `89ebe83fa9044802819eb419a430c735904b186362336f56ae58fed133f523bcbef167e0e6992fbaf17fcd3d1fbb8024` |
| `H_53` | `8c3cbe032a1076bf6820ce04c6b97ae9faf8d58d9c568defa643d75684f331dd17d35a4535f2918e29d776fb66aec531` |
| `H_54` | `858698028abfaa4dec69ad78c98681a95e51f601ae3d13d84cad5ff619d351a7f7ea348f3caafdb5dd395f6046f9a934` |
| `H_55` | `8c169e54240803ba610dc5cd28d642f776531d46f8bc3eed83341a59ad9fe6c0f3607cef54f287d0ff8fd26c7a4671af` |
| `H_56` | `a040ee5baf6f8b0eca5b804e940df9396c3a68448bb75de7793c8de6d8ecdd532daa0f01aad7c5a623525433f95f03c1` |
| `H_57` | `a46e4ccfe8aac7e57e0573a3939e8b0e0a119a8f0a7a5bd5fdcdb34028f7b05bb13042bb6eb8a2e6e8c46e97d3059cd9` |
| `H_58` | `b34ca23cb48f86d1b621c7cd30a6424d8bb5ed1efcac94e44c3e3dced6f98807474462357e995a07306c898798d761de` |
| `H_59` | `b59a0e9cd2cdca9fde74bd79173fb49e73c2d03a99eef390badcc2c577aca17b3b80ef8565a8871e256afe5f91bce6d1` |
| `H_60` | `a8c1ed6549aadd56d03b37b4c2c11095226a78cdf6edde242b5d1e0de54966f1f044a6c5bf128dc73bf5b27e985d404e` |
| `H_61` | `85e8bace88c1dd31d9f664907acba0f5c12859854226b4ba9be8fddef48f9be0a84f109e2bc33929ff3c3f1c1ccd0120` |
| `H_62` | `b70f2a8733a09e9fb58f577b495d8a9a7b10959300047c3796ccd01b530807c6d3ac80d896c66a7a69bab8d5ec26279f` |
| `H_63` | `82c6faca133082265707f8e2422692c79663999e3e87b919dddccfd3a67c23dcff5a5910bf58425b02deebcc56aa327b` |
| `U` | `aaf94b4c700852ac8db3659ccfe7b0bbb7157c18ee881878fe1c2222b7eb31d73943af9a7d1c341dd2a1eb49eec7696e` |
