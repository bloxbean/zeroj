# SHA-512 review for issue #111

Date: 2026-10-29. Scope: the existing `Sha512`, `ZkSha512`, their DSL operations and
compiled-constraint tests, under ADR-0063. Baseline: `d0b1f32` (`origin/main` when this
work began). This is a bounded AI-assisted implementation review, not a human or
external security audit. A separate review agent inspected SHA-512 and authored its
hardening/tests; other agents independently reviewed those changes.

## Findings and change

No incorrect round constant, rotation, schedule, padding encoding, digest ordering or
missing input/carry constraint was identified in the inspected SHA-512 construction.
The byte API already decomposes each input into eight Boolean bits with a reconstruction
constraint. The raw bit API already asserts every input Boolean. Both return the full
digest; callers must constrain that returned value to their intended statement.

One concrete hardening issue was found: `messageBytes.length * 8` and the padded-array
rounding used unchecked Java `int` arithmetic. Very large array lengths could overflow
and fail with an incidental allocation/index error, after earlier work had already been
done. This is a fail-fast/resource correctness issue; the review did not demonstrate an
accepted false hash proof from it.

The fix adds package-private `messageBitLength(int)` and `paddedBitLength(int)` helpers
using checked arithmetic. Both public entry points validate the padded length before
emitting message constraints or allocating the derived bit arrays. Negative/non-byte-
aligned helper inputs reject with `IllegalArgumentException`; arithmetic overflow rejects
with `ArithmeticException`. Tests exercise the arithmetic boundary without allocating
enormous arrays. Passing these integer bounds does not promise that a particular JVM has
enough memory to build a circuit of that size.

No round arithmetic, constant, bit ordering, emitted Boolean check, public method
signature or supported ordinary-length relation changes. The checked helpers perform
host-side arithmetic on the public array length and emit no gates. The existing
constant/multiplication/decomposition call sequence is preserved for valid lengths.

## Constraint reasoning

The review used [FIPS 180-4 (August 2015)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf),
especially §§4.1.3, 4.2.3, 5.1.2, 5.2.2, 5.3.5 and 6.4. All eight initial words and 80
round constants were inspected against the published hexadecimal values. The large
sigma rotations are 28/34/39 and 14/18/41; the small sigma rotations/shifts are 1/8/7
and 19/61/6. The schedule covers 80 words, followed by 80 rounds and eight feed-forward
additions. Padding and the complete 128-bit length suffix are circuit constants; Java
array lengths fit in the suffix's low 64 bits.

The Boolean invariant follows the implemented data flow. Initial/padding bits are
constants; message bits are constrained. Rotations/shifts only select existing bits or
zero. XOR is Boolean on Boolean operands. `g + e*(f-g)` selects `f` or `g`, and
`a*b + c*(a XOR b)` equals a Boolean majority for every Boolean input assignment.
Every modular addition decomposes the complete field sum into value and carry bits,
then returns its low 64 bits. The largest sum is at most five 64-bit words, below 2^67,
which is smaller than every currently supported circuit field. Reconstruction plus
Booleanity therefore constrains the intended integer sum before truncating its carry.

`CircuitAPI.toBinary` supplies constrained decomposition, not just a witness-generation
hint. `assertBoolean` is idempotent, so the byte entry point's call into the checked bit
entry point does not emit a second Boolean constraint for the same wire.

## API boundaries

- `hashBits` intentionally accepts byte-aligned messages only, in MSB-first byte order.
  It is not a general arbitrary-bit-length SHA-512 API.
- Low-level `hashBytes`/`hashBits` support empty messages. The existing `ZkBytes` type
  forbids empty vectors, so `ZkSha512.hash` cannot represent that case. This PR preserves
  that container convention rather than changing all symbolic byte APIs.
- The symbolic adapter checks null arguments and calls `ZkBytesSupport.toVariables`,
  which verifies that every signal belongs to the current context before unwrapping it.
- The inputs are field elements. The DSL normalizes host input integers modulo the
  field; a gadget's byte constraint concerns the resulting field value. Canonical
  external serialization must be enforced by the application/codec when relevant.
- Circuit length is public. Witness arithmetic uses the existing Java DSL, which is
  not claimed constant-time for secret values.

## Added evidence

`Sha512SecurityTest` adds direct checks over the compiled R1CS, independent of the
witness calculator's assertion execution:

- All 13 SHA-512 cases in the vendored NIST CAVP selection, including empty, one-byte,
  padding-boundary and multi-block messages, with expected digests from NIST.
- Raw-bit MSB ordering and high-bit bytes, Boolean-input rejection, and bit-API empty /
  111 / 112 / 128-byte cases against JCA.
- Byte values -1, 256 and 257, and a changed legitimate message with the previous digest.
- Direct mutations of every public digest byte, every input byte, a referenced addition
  carry and a referenced low bit; these bypass witness-generation assertions.
- BLS12-381 symbolic-adapter equality, changed digest, foreign-context and null rejection.
- Checked length arithmetic at ordinary padding transitions and the Java `int` boundary.

The focused Gradle run passed all 39 tests across `Sha256Test` (10), `Sha512Test` (9),
`Sha512SecurityTest` (8), `HmacSha512Test` (10) and `ZkSha256Test` (2), with no failures
or errors. All eight new SHA-512 security tests ran, including the 13 official vectors
inside the vector test. The original SHA-512 and HMAC tests remain in place. Reproduce:

```sh
./gradlew :zeroj-circuit-lib:test \
  --tests '*Sha256Test' --tests '*Sha512Test' --tests '*Sha512SecurityTest' \
  --tests '*HmacSha512Test' --tests '*ZkSha256Test'
```

The existing symbolic hash-adapter tests remain in the full module suite. The optional
Circom assurance harness adds a separate implementation/compiled-relation comparison;
its result and toolchain provenance are reported separately rather than inferred from
this source review.

The change adds constant-cost length checks, not a new compression optimization. The
review makes no new throughput, constant-time, trusted-setup or production-readiness
claim. Independent circuit/compiler review, secure setup for the chosen proof system
and authenticated application/state binding remain separate requirements.
