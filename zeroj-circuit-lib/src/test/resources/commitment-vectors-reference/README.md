# Commitment-profile vector emitter (`zeroj-commitment-vectors-v1`)

`emit_commitment_vectors_v1.py` is an independent Python 3 (standard library only) reference
that writes the cross-language vector files of
[`commitment-profiles-v1.md`](../../../../../docs/specs/commitment-profiles-v1.md) §13
(ADR-0059 milestone M2), one per Jubjub profile:

```
zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/
    pedersen-jubjub-v1.json
    pedersen-jubjub-vector-v1.json
    pedersen-jubjub-bytes-v1.json
```

The files are evidence against the Java implementation, so their expected values must not come
from it. This script was written without reading any ZeroJ Java source, Java test or build
output (see "Independence").

## Running

From this directory:

```bash
python3 -I -B emit_commitment_vectors_v1.py              # write the three files
python3 -I -B emit_commitment_vectors_v1.py --check      # regenerate in memory, compare with disk
python3 -I -B emit_commitment_vectors_v1.py --self-test  # mutation self-test; writes nothing
```

`--repo-root DIR` overrides the repository root (default: five directories above this file);
`--out-dir DIR` overrides the output directory. `-I` isolates the interpreter (no user site, no
script directory on `sys.path`); the script inserts the three reference directories itself and
sets `sys.dont_write_bytecode`, so nothing is written next to them. A run takes about a second.

Every run, in every mode, first:

1. re-derives `G`, `H` (Poseidon try-and-increment), `G_0..G_15` and `H_V` (`FindGroupHash^J`)
   through the imported references and compares them with the values pinned in the specs
   (`encode(G)`, `encode(H)`, the Poseidon known answers, the 17 vector-base encodings,
   `C(42, 12345)`, `C([1000, 7], 12345)`, `C([1000], 12345) = C([1000, 0], 12345)`, `σ` of the
   balance schema, and the bytes-v1 §10 table, including `b0`, `uniform_bytes`, three `s` values
   and three byte commitments) — transcribed by hand into this script, never read from the
   references;
2. cross-checks its own strict point decoder against both imported decoders, the imported affine
   arithmetic against the imported extended-coordinate arithmetic, and its own octet-form
   `HashBytesToScalar` against the imported RFC 9380 one on eight payloads up to 64 KiB;
3. runs every case and asserts that the outcome equals the outcome the case was written to pin
   (each case carries an intended `ok` or error class); any disagreement aborts;
4. asserts the §13.3 "Streams" rule over every bytes case before writing: `declaredLength`
   equals the payload length and `maxBytes` is at least the payload length, except in
   `LENGTH_OUT_OF_RANGE` cases, where the value is outside `[0, MAX_PAYLOAD_BYTES]` and the
   payload is empty;
5. generates the files twice in-process and requires identical text.

It exits non-zero on any failure. The output is deterministic: fixed constants only, no
randomness, stable case order. Two runs give byte-identical files (verified).

The header records provenance: each spec's path, revision, date and SHA-256, and the
generator's repo-relative path, SHA-256 and Python version. Only `commitment-profiles-v1.md` has
a revision, and the header gives the revision the vectors **implement** (`r3`), pinned in the
script. It is not read from the document. A later metadata-only revision of the document
changes its date and SHA-256 but not this label; the script prints a warning when the
document's revision differs. Date and SHA-256 are read from the files at run time. Loaders need
not check these fields (§13.1).

**`--check` rule.** `--check` regenerates in memory and compares with the files on disk. It
treats `generator.python` and each `spec[]` entry's `sha256` and `date` as provenance: a
difference in them, or in formatting alone, is printed as a warning. Any other difference fails
`--check` (exit 1), and each differing, missing or extra case is named. That covers the cases
and their order, the header fields, spec paths, the `revision` label and `generator.scriptSha256`.
So a different Python version or a metadata-only spec revision does not fail `--check`, but an
edited emitter whose output was not regenerated does.

Comparison works on the two documents with only those provenance fields removed. Any
inequality left is an error, at every level, and an absent key is distinct from a key whose
value is `null`: an extra `"unexpected": null` anywhere fails `--check`. A JSON number in place
of a string also fails, as do a reordered, duplicated or missing case. Both `--check` and
`--self-test` first run a **check regression**: 18 in-memory tampered copies of a regenerated
file, each of which must be judged correctly. Among them are the extra-null-key cases at the
top level, in `generator`, in a `spec` entry, in a case and in a case input; a header value set
to `null`; a changed `scriptSha256` or revision; and the provenance-only and key-order-only
changes, which must give warnings only. A misjudged copy makes the run fail.

## What is imported and what is implemented here

Imported, unmodified, from the sibling independent references (paths resolved relative to this
file; their `main()` is never run):

| Reference | Used for |
|---|---|
| `../pedersen-reference/pedersen_jubjub_v1_reference.py` | `G_FULL`, affine `scalar_mul`/`encode`/`decode`/`on_curve`, `sqrt_mod`, `poseidon_parameters`, `poseidon2`, `derive_h` |
| `../pedersen-vector-reference/pedersen_jubjub_vector_v1_reference.py` | `derive_bases` (`G_0..G_15`, `H_V`), `schema_encode` (schema validation and canonical encoding), `schema_digest`, `pt_add` (differential) |
| `../pedersen-bytes-reference/pedersen_jubjub_bytes_v1_reference.py` | `hash_bytes_to_scalar` (with `b0`, `b1`, `b2`, `uniform_bytes`), extended-coordinate `ext_add`/`ext_mul`/`to_ext`/`to_affine`, `in_prime_subgroup`, `small_order`, `receive` (differential) |

SHA-256 of the imported scripts when the committed files were generated:

| Script | SHA-256 |
|---|---|
| `pedersen-reference/pedersen_jubjub_v1_reference.py` | `9803bdc6547530b78eb500559e387600ea7ba7fcdb780995de0e6ccacc04c9d4` |
| `pedersen-vector-reference/pedersen_jubjub_vector_v1_reference.py` | `b3cc1b39853b87c7cd8c79e52ee1ce7a6d8a16cb1369e10d8b8530758e77d2cc` |
| `pedersen-bytes-reference/pedersen_jubjub_bytes_v1_reference.py` | `24dbc3b5d620fa05161dd4b940fd43dde0afb5745dc06da66a9f64c3b4154791` |

Implemented here from `commitment-profiles-v1.md`: the §2.1 identifier grammar (whole-string
match, 4–64 octets); the §10 strict point decoder and its classes (`MALFORMED_ENCODING` for rules
1–5 of `pedersen-jubjub-v1.md` §4 in order, then `NOT_IN_SUBGROUP`; no cofactor clearing; identity
accepted); check 1 (never reduced), check 2 (`1 ≤ k ≤ 251`) and check 3 with its three policies,
including `widened(n)` with `2 ≤ n ≤ 65536` and every `2^{k_i+⌈log₂ n⌉} ≤ q`; the §8.1–§8.3
opening encodings with their decode orders; envelope v1 encode/decode with the §9 step order; the
§12.3 strict-path orders; the §13.3 execution order (configuration → points → operation order →
equation); and the §13 file format with its value conventions (no JSON numbers, decimal
integers, lowercase hex in `…Hex` fields — checked before writing). Also an octet-form
`HashBytesToScalar` (bytes-v1 §3.1, used as a differential and by one mutation), the fixture
search for the torsion and off-curve points, and the case lists.

## Cases

Per file, at least every item of §13.4, plus:

- point negatives (lengths 0/31/33, `v = p`, `v = p + 1`, `v = 2^255 − 1`, both `u = 0` sign
  aliases of §10, off-curve, orders 2, 4 and 8, mixed order with an order-8 and with an order-2
  component) under both `decodePoint` and `decodeEnvelope`;
- envelope negatives (empty, version-only, version `0x00`/`0x02`, truncations, trailing octet,
  point-length mismatches, identifier length octet too large / off by one / zero, the other two
  active profiles, the reserved `pedersen-bls12-381-g1-v1`, a one-octet change, an upper-case
  first octet) and multi-defect envelope order cases;
- scalar negatives `q`, `q + 1`, `−1` on every strict operation of §13.4 and `q`, `q + 1` on
  `decodeOpening`;
- multi-defect cases pinning the §13.3 execution order (for example a bad point before a
  non-canonical value, `amountBits` read in step 1 but validated after the point, `amountBits`
  before check 1, check 1 before check 2/3 for every component and the blinding, the policy
  schema comparison before the dimension, policy configuration before the point, a bytes
  point before a non-canonical blinding, a non-canonical blinding before a mismatching payload,
  and `relation` with an order-2 point before an empty encoding);
- for scalars, order cases whose defects have different classes, for example a non-canonical
  blinding before a wrong value, giving `NON_CANONICAL_SCALAR` rather than `OPENING_MISMATCH`, and
  check 2 before the equation;
- for bytes, `hashToScalar` at the SHA-256 block boundaries of `b0`'s `(n + 122)`-octet input:
  `n` = 5/6 (127/128 octets), 61/62 (183/184, where the padding moves into a new block) and 69/70
  (191/192), besides 0, 1, 16, 55, 56, 64, 1000 and 65536;
- for vectors, a 16-entry schema `zeroj.test.dim16` (`N_MAX`; widths 8, with entry 7 at 16 bits
  and entry 15 at 32 bits; labels `c0`..`c15`). It has a legacy `commit` with every component
  nonzero, and strict `verifyOpening` under `schema-widths`, `residue-only` and `widened(2)`. It
  also has a 545-octet opening round trip, `n` octets `0x0f`/`0x11`, `v_15` at `q`/`q + 1`
  (`NON_CANONICAL_SCALAR`) and at `2^32` (`OUT_OF_RANGE` under `schema-widths`, accepted under
  `residue-only`), and `OPENING_MISMATCH` from swapping components 13 and 14;
- for vectors, the two §13.3.1 example records verbatim, and points with components `≥ 2^{k_i}`
  or `q − 1`, which the legacy width-checked `commit` cannot produce, built by `relation` records
  in the same file.

Each run prints the case counts per file and operation. Current totals:

| File | Positive | Negative |
|---|---|---|
| `pedersen-jubjub-v1.json` | 56 | 104 |
| `pedersen-jubjub-bytes-v1.json` | 50 | 84 |
| `pedersen-jubjub-vector-v1.json` | 74 | 150 |

## Self-test

`--self-test` re-runs every case with one deliberate defect switched on in this script's own
implementation at a time (case inputs stay fixed; only outcomes may change) and reports, per
mutation, how many cases in which file change. A mutation that changes no case "survives" and
the self-test fails. The 25 mutations: check 1 accepting `q`; check 1 reducing `−1`; the decoder
skipping the subgroup check; cofactor-clearing; accepting the sign aliases; reducing `v ≥ p`; the
envelope not comparing the identifier; accepting any version; checking the point length before
the identifier; `widened` with `⌊log₂ n⌋`; checking only the first entry; no 65536 limit;
accepting `n = 1`; `schema-widths` accepting `2^{k_i}`; little-endian opening scalars;
`amountBits = 252` accepted; `amountBits` validated before the point; dimension before the
schema comparison; no schema comparison; check 3 before check 1; the vector opening decoder
ignoring its `n` octet; the bytes `verifyOpening` equation evaluated before check 1 on the
blinding; `subtract` reversed; the vector commitment using `G_{i mod 2}` for component `i`
(killed only by the dimension-16 cases);
and a length prefix instead of a suffix in `HashBytesToScalar`. All 25 are killed.

## Independence

Files read while writing this emitter (nothing else in the repository was opened):

- `docs/specs/commitment-profiles-v1.md` (in full)
- `docs/specs/pedersen-jubjub-v1.md`, `docs/specs/pedersen-jubjub-vector-v1.md`,
  `docs/specs/pedersen-jubjub-bytes-v1.md` (in full)
- `docs/adr/0059-commitment-profiles-and-verification-strategy.md`: §D6 and the lines a search
  for "D6" returned (milestone table row M2, invariant I9)
- `../pedersen-reference/pedersen_jubjub_v1_reference.py`, `../pedersen-vector-reference/
  pedersen_jubjub_vector_v1_reference.py`, `../pedersen-bytes-reference/
  pedersen_jubjub_bytes_v1_reference.py`: their definitions (to call them correctly), not their
  `main()` bodies in full
- `../pedersen-bytes-reference/reference-output.txt`: its header and its `pattern_8192` /
  `pattern_65536` lines (the emitted 64 KiB intermediates were compared with them by eye)

The READMEs of the three reference directories were not read. No `.java` file, nothing under
`src/main/java` or `src/test/java`, and no `build/` output was opened.

## Limitations

- Independence is from the Java code, not from the sibling references: the bases, curve
  arithmetic and `HashBytesToScalar` are theirs, so an error shared with them would not be caught
  here. They are in turn checked against values pinned in the specs, which this script re-checks.
- The §9 step 6 check (concrete class and descriptor) cannot fail for a codec that only builds
  its own type, so the files have no step-6 case; it belongs to the Java tests.
- The bytes-v1 §6 order "blinding before declared length or maximum" is not a file case: a
  fixture with an out-of-range length whose class is not `LENGTH_OUT_OF_RANGE` would break the
  §13.3 "Streams" rule, so the Java tests pin that order instead.
- Null arguments, stream I/O failures, `IllegalStateException` and `CommitmentAcceptance` are
  outside the file format (§11, §13.3) and are not covered.
- `expectedProfileId` is always the file's own profile: a file selects one codec.
- Vector `commit` (legacy) is used only with canonical, width-respecting inputs; legacy
  behaviour for other inputs is not pinned.
- JSON key order is fixed but keys are not sorted; consumers must not depend on order.
- The `python` header field is the interpreter that produced the files; another interpreter
  produces the same cases with a different header line.

## Changes

- **2026-10-17 (second generation).** Removed the two bytes `commit` order cases with an
  out-of-range length but a `NON_CANONICAL_SCALAR` class (blinding `q` with `declaredLength`
  `-1`; blinding `-1` with `maxBytes` `MAX_PAYLOAD_BYTES + 1`), which broke §13.3 "Streams".
  Added `verify-order-blinding-before-equation` (a non-canonical blinding with a mismatching
  payload, which gives `NON_CANONICAL_SCALAR`), and the Streams self-check above. The mutation
  "bytes length check before blinding" no longer has a file case to fail on, so it was replaced
  by "bytes `verifyOpening` equation before check 1".
- **2026-10-17 (third generation), after review.**
  - Added the dimension-16 vector cases and the `G_{i mod 2}` mutation.
  - Added the `hashToScalar` block-boundary payloads.
  - Replaced the scalar `verify-order-value-before-blinding` (both of its defects are
    `NON_CANONICAL_SCALAR`, so it pinned no order) with `verify-order-blinding-check1-before-equation`
    and `verify-order-check2-before-equation`.
  - Pinned the implemented revision label (`r3`).
  - Made `--check` treat provenance fields as warnings.
  - Gave the full SHA-256 of each imported script.
- **2026-10-17 (fourth generation).** `--check` now normalizes only the provenance fields
  and treats any remaining inequality as an error, with an absent key distinct from `null` at
  every level. Previously an extra top-level key with value `null` was reported as "formatting
  differs" with exit 0. Added the 18-copy check regression. No emitted case changed: the three
  files are byte-identical to the previous generation apart from `generator.scriptSha256`.
