# ZeroJ Jubjub EdDSA hedged-v1 candidate nonce profile

## Status

**Candidate for external cryptographic review. Not an approved or validated signing
profile.**

This document is the normative M4 candidate required by
[ADR-0039](../adr/0039-jubjub-online-and-offline-readiness.md). It fixes a transcript so the
implementation, independent vectors, timing work, and external review can evaluate the same
construction. Acceptance of ADR-0039 did not approve this custom nonce design. A review finding
may require a new profile identifier and new vectors before any validated dedicated-host
factory is enabled.

The signature equation, public challenge, point/scalar encodings, and verifier remain those in
[`jubjub-eddsa-v1.md`](jubjub-eddsa-v1.md). This profile changes only nonce generation.

## 1. Parameters and conventions

- `p` is the Jubjub base-field modulus.
- `l` is the prime subgroup order.
- `G` is the prime-order subgroup generator.
- `P3` is the exact BLS12-381-scalar-field Poseidon permutation with `t=3`, `alpha=5`,
  `RF=8`, and `RP=57` already pinned by the v1 suite.
- Every field element below is canonical in `[0,p)`.
- `OS2IP_BE` interprets bytes as an unsigned big-endian integer.
- Point inputs are canonical normalized affine coordinates.
- Addition within a Poseidon state is modulo `p`.

The profile identifier is:

```text
ZeroJ-JubjubEdDSA-hedged-v1
```

Capacity tags are fixed literals derived as
`OS2IP_BE(SHA-512(ASCII(label))) mod p`:

```text
NONCE_KEY_LABEL = "ZeroJ-JubjubEdDSA-hedged-v1-nonce-key"
NONCE_KEY_TAG   = 0x28c87335b019e6e7ca819222776c84073ddfcc06b031d9fdbbafedbb65a0e991

NONCE_LABEL     = "ZeroJ-JubjubEdDSA-hedged-v1-nonce"
NONCE_TAG       = 0x6b9458c0423a2e488bcd71ca3b3ccd905536ded5996c97715b0885971d11f6b1
```

These domains are distinct from the deterministic-v1 nonce, challenge, message
hash-to-field, Pedersen, and every other suite domain.

## 2. Persistent nonce key

For canonical secret scalar `sk` in `[1,l)`, derive:

```text
nonceKey = P3(NONCE_KEY_TAG, sk, 0)[0]
```

`sk` is embedded into `Fq` by its canonical integer value; `l < p`, so no reduction or
alternate representation exists. `nonceKey` is persistent secret key material. It is stored,
copied, synchronized, and wiped under the same lifecycle rules as `sk`. It is never exported.
Key establishment fails closed if `nonceKey == 0`. Under the Poseidon-output-as-uniform model
this excludes a negligible `1/p` bad-key event; it is also cheap defense-in-depth against a
zeroing fault during provisioning. This check occurs during key establishment, not on the
ordinary signing schedule.

The profile is stateless apart from `sk` and `nonceKey`; it has no counter or persisted nonce
state.

## 3. Auxiliary randomness

Each signature consumes exactly 32 fresh secret bytes `aux` from the platform profile's
approved CSPRNG:

```text
auxHi = OS2IP_BE(aux[0..15])
auxLo = OS2IP_BE(aux[16..31])
```

Both halves are at most 128 bits and therefore embed injectively into `Fq`; they are not
reduced or truncated. The draw occurs after lifecycle admission and before persistent key
material is copied into operation scratch. Provider exceptions and declared health alarms
release no output.

The validated factory will construct its own approved source and will reject arbitrary
`SecureRandom` instances or test sources. The exact implementation/provider/JVM identity is a
platform-profile decision, not part of the portable cryptographic transcript.
The signer owns that source. The approved provider contract must be bounded, non-reentrant,
thread-safe for the supported concurrency, and closeable; after admitted operations finish,
signer close releases or wipes provider-owned state.

Repeating `aux` for the same `(sk,pk,msg)` repeats the signature. Repeating or weak auxiliary
randomness does not by itself make the nonce public: `nonceKey` remains a secret input.
Freshness is nevertheless required because hedging is intended to diversify repeated signing
operations and reviewed fault/side-channel observations.

## 4. Nonce transcript

Inputs are the persistent `nonceKey`, canonical public message field element `msg`, canonical
public key `pk=(pk.u,pk.v)`, and `aux`:

```text
state = (NONCE_TAG, 0, 0)

state[1] = state[1] + nonceKey
state[2] = state[2] + msg
state    = P3(state)

state[1] = state[1] + pk.u
state[2] = state[2] + pk.v
state    = P3(state)

state[1] = state[1] + auxHi
state[2] = state[2] + auxLo
state    = P3(state)

x = state[0]
r = (x mod (l - 1)) + 1
```

The arity and number of permutations are fixed. There is no padding, optional field, retry,
message-dependent loop, secret-indexed table, or implicit byte-to-field conversion.

## 5. Fixed-schedule nonzero mapping

Let `q = l - 1`. For canonical `x < p`:

```text
p = 8q + 0x207c9f6499bdd7e87b478d0848469a51
```

and the remainder is less than `q`. Therefore `floor(x/q) <= 8`. The implementation computes
`x mod q` with exactly eight unconditional candidate subtractions, choosing each candidate by
an arithmetic borrow mask, then adds one. The result is always in `[1,l)`; ordinary signing
has no zero-nonce branch, rejection loop, or failure case.

Under the Poseidon-output-as-uniform model, the total statistical distance introduced by this
mapping is:

```text
rem * (q - rem) / (p * q) ≈ 2^-129.8353
```

This is above the suite's 128-bit target. The custom construction and this bound still require
external cryptographic review.

## 6. Signing and release

After deriving `r`, signing is unchanged:

```text
R = [r]G
k = Poseidon_t6(CHALLENGE_TAG; R.u, R.v, pk.u, pk.v, msg) mod l
S = r + k*sk mod l
```

After `R` and `S` are complete, the implementation re-runs the complete nonce transcript into
a disjoint scratch region. It mask-compares the re-derived scalar with the scalar used for
both equations and checks that it is nonzero before release. This is required because public
verification cannot detect a coherent fault that replaces `r` before both `R` and `S`; such a
signature is still algebraically valid and a known replacement could disclose `sk`. The
correct mapping has no zero or mismatch outcome, so this is a catastrophic fault invariant,
not ordinary secret-dependent retry behavior.

The candidate `(R,S)` is then converted to the existing public representation and
independently verified by the existing public-data verifier before release. Verification does
not encode or detect the nonce profile.

No public unchecked candidate signer or automatic fallback is permitted.

## 7. Candidate vector

All integers are hexadecimal without an implicit reduction:

```text
sk      = 0x01
msg     = 0x00
aux     = 00000000000000000000000000000000
          00000000000000000000000000000000

pk.u    = 0x3ea5c4673a121ca35ed37ee3b172f5ee04315c657fbe375f512dfea318d56fe5
pk.v    = 0x57137b83ea6edb4f78f7d30d3f616cb3b9aa6e8e40808413c10cea38d50c55cb

nonceKey =
  0x52c14c92d2f6eb95966adf00ac7290d81e760d596c21e0cd09cef989497fe3fa
r =
  0x023e724ba6d51119660d8509733cd24556685b635eb8b1fedaa52b0331cbc5c2

R.u =
  0x3d88964c92cd3be8cc36c0c816109969026c063aaf38783413d2eddfdede4703
R.v =
  0x0b972b74f628eddc4b677f51357356bc374e087d90b6f39ad2df5c0758fa3205
S =
  0x079c82bc79d94d80361209007bb81f2e8bf13f747360d8d08aa0966c444c18c1
```

The fixed-limb tests also reconstruct the transcript through the independent existing
`BigInteger` Poseidon implementation, rather than merely pinning output produced by the new
kernel.

## 8. Review questions and stop conditions

External review must explicitly assess:

- the nonce-key derivation and separation from deterministic-v1/challenge domains;
- the three-permutation additive transcript and fixed arity;
- binding of `pk`, `msg`, and all 256 auxiliary bits;
- repeated/weak auxiliary-randomness behavior;
- the `(x mod (l-1))+1` mapping and bias;
- fault behavior, release checking, and lack of nonce state;
- nonce re-derivation, its single-fault model, and its common-mode limitations;
- whether the profile needs a different standard construction or identifier.

Until that review and ADR-0039 M5–M8 gates pass, this remains a candidate exposed only to
tests/benchmarks and cannot be obtained from
`JubjubSigners.validatedDedicatedHostJavaRequired`.
