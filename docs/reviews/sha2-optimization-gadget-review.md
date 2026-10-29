# SHA-2 optimization gadget review

Date: 2026-10-29. AI-assisted review by the Boolean-assertion implementation
agent, independently examining the parent agent's SHA gadget changes. This is
not an independent audit of the compiler change authored by this reviewer.

## Scope and disposition

Reviewed the majority-product reuse, deferred T1/T2 reduction, helper boundaries,
and `Sha2OptimizationTest`, against the pre-optimization commit `3f1570f` and
[FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), sections
4.1, 6.2.2 and 6.4.2. **No blocking correctness or soundness finding identified
in these gadget changes.** Approval remains conditional on the overall change's
standard-vector, independent compiled-relation, proof, full-build and performance
gates. This source review covers the implementation; the subsequently completed
checks and measured performance trade-offs are in the
[results report](sha2-optimization-results.md).

Reviewed source SHA-256 identities:

| File | SHA-256 |
|---|---|
| `Sha256.java` | `76089dca42c5f18e952db1af4abf21194def1d38c9f808f3144a3e148cc39f18` |
| `Sha512.java` | `dddc62aadf03223fc10ce2f659e11ccd12a0d9069ab2c0bdbfdf70f76c05ccb9` |
| `Sha2OptimizationTest.java` | `9112c4f6b65c423d0e374b279bea0cdd059d2a95a3d0e122ccc7f0028b8ea83f` |

## Relation argument

For Boolean a,b,c, `ab + c*(a+b-2ab)` is exactly majority: when a=b, the
second term is zero and the result is a; when a differs from b, ab=0 and the
result is c. Reusing ab changes the graph, not this equation. Choice and XOR
still preserve Booleanity algebraically from constrained bits.

Each state word and schedule word is a vector of constrained bits. Initial
state/padding words are fixed constants. Consequently each word is an integer
in `[0, 2^w-1]`, for w=32 or 64. T1 comprises five such words and T2 two.
T1+d is below `6*2^w`; T1+T2 is below `7*2^w`. Both fit w+3 bits and are
strictly below the scalar modulus on all three supported fields. Thus the
field additions implement the required exact integer sums before reduction.

`lowWord` decomposes the entire sum into w+3 Boolean bits and constrains their
recomposition. Retaining the low w bits is therefore reduction modulo 2^w.
The high three bits remain constrained despite not being returned. A separate
constraint excluding carry=7 is unnecessary: sum equality and the derived
seven-word bound already exclude it. Equality cannot wrap around the scalar
field because both full representations are below that field's modulus.

Associativity of addition modulo 2^w gives the same a/e outputs as reducing
T1 and T2 earlier. T1 and T2 are constrained arithmetic expressions, not advice
or unverified host values. State reassignment order remains correct: both
temporaries are constructed before changing the state references. The arrays
being referenced are not modified in place. Message schedule, round count,
constants, final feed-forward, padding and digest order are unchanged.

## Tests and remaining boundaries

The new gadget tests cover all majority triples in all supported fields,
altered output and non-Boolean input witnesses, high-carry message patterns
at padding/block boundaries, and direct mutations of both low-bit extremes
and all three carry positions in selected a/e decompositions. The test checks
the total number of round decompositions; it mutates a sample of rounds, not
every intermediate in every round. Existing NIST/JCA and assurance tests remain
necessary and are not replaced by these tests.

This reviewer separately ran the complete DSL suite for the new explicit
Boolean gate: 123 cases, zero failures/errors, one opt-in benchmark skipped.
That is author validation of the compiler change, not independent compiler
review. Another agent must review that portion.

Changed circuit shapes require fresh circuit-specific keys and artifact
fingerprints. No constant-time, secure-ceremony, production-readiness or
post-quantum guarantee is established. Performance acceptance requires the
parent's controlled baseline/candidate measurements at 6 GiB and 8 GiB heaps.
