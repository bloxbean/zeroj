# ADR-0061 M2: external algebra check against dalek bulletproofs 5.0.0

This directory checks the **algebra** of the single-value Bulletproof range proof against an
independent, audited implementation: dalek/zkcrypto `bulletproofs` 5.0.0 (Rust, ristretto255,
Merlin). One group-generic and transcript-generic prover and verifier, `bulletproof_generic.py`,
is run with two bindings:

- the **dalek binding**: ristretto255, Merlin, dalek's generators, transcript, IPA base `Q = w·B`
  and byte layout;
- the **spec binding**: BLS12-381 G1, the fiat-shamir-03 SHAKE128 transcript, the
  `bulletproof-bls12-381-g1-gens-v1` generators and the independent `U` of
  `bulletproof-range-bls12-381-g1-v1`.

The check runs in two directions:

1. **Direction 1.** The generic verifier, with the dalek binding, accepts dalek's published test
   proofs. It rejects tampered copies.
2. **Direction 2.** dalek 5.0.0's `RangeProof::verify_single`, run by the Rust harness in
   `dalek-harness/`, accepts proofs that the generic prover made. It rejects tampered ones.

The same unchanged core, with the spec binding, reproduces the pinned known-answer proof of
`bulletproof-range-bls12-381-g1-v1` byte for byte, and verifies it.

Everything is test-only. Nothing here is constant-time, and nothing here may handle real secrets.

## What this shows, and what it does not

**What it shows.** The protocol algebra in `bulletproof_generic.py` agrees with an independent
implementation that ZeroJ did not write:

- the prover of paper §4.1 (40)–(63) and §4.2;
- the inner-product argument of Protocols 1–2;
- `δ(y, z)`;
- the `s_i` challenge products and their most-significant-bit-first order;
- the two verification equations of §6.2 (98) and (105).

The same file, with no group-, hash- or transcript-specific code, then produces the spec's
BLS12-381 known-answer proof byte for byte. So the algebra used for this protocol is the algebra
that dalek verifies and produces.

**What it does not show.**

- **It does not validate this protocol's transcript or generators.** dalek uses Merlin and its
  own generators, so the dalek directions say nothing about the SHAKE128 sponge, the session tag,
  the instance encoding, `D_gens`, `U` or the BLS12-381 codecs. Other evidence covers those:
  - the CFRG fiat-shamir-03 vectors, of which this check also runs B.2.1–B.2.11;
  - the spec Appendix A reproductions (Java, Python, py_ecc);
  - Java/Python agreement on the M2 vector file.
- **The known-answer reproduction is not independent evidence for the BLS12-381 binding.** The
  pinned proof came from ZeroJ's own implementations. The new fact is narrower: a core that
  dalek checks gives the same bytes.
- **It is not evidence of soundness, zero-knowledge or production safety.**
  - dalek and this code could share a misreading of the paper. The paper is the common source.
  - Agreement on honest proofs and on the tampers tried here is not a security proof.
  - dalek's verifier merges its two equations with a random weight. The generic verifier checks
    them separately (ADR-0061 D5). The two verdicts are therefore equivalent on honest proofs and
    on these tampers, not on every input.
- **It does not check dalek's `H_i` generators directly.** dalek keeps
  `BulletproofGensShare::H` `pub(crate)`. The `H_i` are checked only through the two
  verification directions.

## Files

| File | Content |
|---|---|
| `bulletproof_generic.py` | The generic prover (`prove`, `prove_with_restarts`) and verifier (`verify`, with check 1 and check 2 evaluated separately). Also an independent recursive Protocol 1/2 verifier (`verify_ipa_recursive`), a generic Straus multi-scalar multiplication, and `FixedLayoutCodec`. It imports only `__future__` and `dataclasses`, which the self-test checks. |
| `ristretto255.py` | RFC 9496 ristretto255: SQRT_RATIO_M1, decode with all its validity rules, encode, equality, element derivation (`from_uniform_bytes`), and the scalar field. Written from the RFC text. |
| `rfc9496-appendix-a.json` | RFC 9496 Appendix A (A.1–A.4), machine-extracted from the fetched RFC text by `ristretto255.py --emit-vectors`. |
| `merlin.py` | Keccak-f[1600] (FIPS 202: round constants and offsets computed, not transcribed), STROBE-128 (meta-AD, AD, PRF, KEY) and the Merlin 1.0 transcript, following merlin 3.0.0's source. |
| `dalek_binding.py` | dalek's `PedersenGens::default()`, `BulletproofGens` (the SHAKE256 `GeneratorsChain`), its transcript protocol, `Q = w·B`, its codec, and the extractor for `tests/range_proof.rs`. |
| `bls_binding.py` | The spec binding. The curve module `../../pedersen-g1-reference/bls12_381_g1_reference.py` is imported by path, unmodified. `../generators-v1.json` supplies the generators. The fiat-shamir-03 duplex sponge is written here on `hashlib.shake_128`, with copy semantics. Also the spec §5 tag and instance, the §3 codecs and the §7.5 test nonces. |
| `run_dalek_check.py` | `--self-test`: runs everything below. `--regenerate`: rewrites the pinned JSON files. |
| `dalek-test-proofs.json` | dalek's published proofs `proofs[i][0]` (`m = 1`, `n = 8 << i`) with `vc[0..7]` and the transcript label, extracted from `tests/range_proof.rs`. |
| `dalek-gens.json` | `B`, `B_blinding` and `G_0 … G_63`, as printed by dalek 5.0.0 (`dalek-harness gens`). |
| `merlin-conformance.json` | merlin 3.0.0's own outputs (`dalek-harness merlin-vectors`) for the conformance sequences in `merlin.py`. |
| `dalek-harness-proofs.json` | Proofs made by dalek 5.0.0 itself (`prove_single_with_rng`, ChaCha seeds) for `v = 0` and `2^n − 1` at every `n`. They give direction 1 more coverage. |
| `python-proofs-for-dalek.json` | The direction-2 cases: 16 honest generic-prover proofs, 182 tampered proofs, and one positive control (dalek's published `n = 8` proof). |
| `dalek-harness/` | The Rust harness. `Cargo.toml` pins `bulletproofs = "=5.0.0"`, `curve25519-dalek = "=4.1.3"` and `merlin = "=3.0.0"`, and `Cargo.lock` is committed. Subcommands: `verify`, `merlin-vectors`, `gens`, `prove`. |

## Sources and pins

| Source | Pin |
|---|---|
| `bulletproofs-5.0.0.crate` (crates.io) | SHA-256 `012e2e5f88332083bd4235d445ae78081c00b2558443821a9ca5adfe1070073d` (equals its `Cargo.lock` checksum); packaged from git `86eadbeeb4a96d8da41427137b45ead810d03b41` (`.cargo_vcs_info.json`) |
| `bulletproofs-5.0.0/tests/range_proof.rs` | SHA-256 `d87b7cde288d25212c3cf24957ea100adf04914be6011ca7e2ecc1e9870b29a8` |
| `merlin-3.0.0.crate` | SHA-256 `58c38e2799fc0978b65dfff8023ec7843e2330bb462f19198840b34b6582397d` |
| `curve25519-dalek-4.1.3.crate` | SHA-256 `97fb8b7c4503de7d6ae7b42ab72a5a59857b4c937ec27a3d4539dba95b5ab2be` |
| `keccak-0.1.6.crate` / `sha3-0.10.9.crate` | SHA-256 `cb26cec98cce3a3d96cbb7bced3c4b16e3d13f27ec56dbd62cbc8f39cfb9d653` / `77fd7028345d415a4034cf8777cd4f8ab1851274233b45f84e3d955502d93874` |
| RFC 9496, fetched 2026-10-25 from `https://www.rfc-editor.org/rfc/rfc9496.txt` | SHA-256 `d875c6e703827da487eae8f0656fd25e4a278f1dcb0f06041669adad27c03ff3`. The text is not committed; `--rfc9496 PATH` re-checks the hash and re-parses Appendix A against `rfc9496-appendix-a.json`. |
| `fiatShamirShake128Vectors.json` (repo copy, spec §10) | SHA-256 `f04cdf455b60239d20392813ffd5dd8d079fb1c0d5b0e07de3e50899bd6f6502` |
| Bulletproofs paper, ePrint 2017/1066 (2022-04-14 text extraction) | §3, §4.1–§4.2, §6.2 |
| `docs/specs/bulletproof-range-bls12-381-g1-v1.md` r2 | §2–§8, Appendix A |

**Pin mismatch to note.** ADR-0061 reference 10 pins zkcrypto `bulletproofs` at commit
`04bce4e66013ff857ed462fd4206210544101461` (2025-09-13), for its notes and transcript order. The
crate 5.0.0 that this check runs was packaged from `86eadbee…` instead. This check pins the
crate, not the commit. Someone should confirm that the transcript order in `src/transcript.rs`
and `src/range_proof/mod.rs` is the same at both commits, or the ADR could cite the crate.

**Merlin conformance: no hardcoded bytes upstream.** merlin-3.0.0's `src/` tests have no hard-coded
expected bytes:
- `strobe.rs` `test_conformance` and the `transcript.rs` `equivalence_*` tests compare against
  the `strobe_rs` crate;
- `strobe_rs` is not in the local registry.

The check therefore uses merlin 3.0.0 itself as the oracle:
- `dalek-harness merlin-vectors` runs the same sequences through the real crate, including
  `equivalence_simple`, all 32 `equivalence_complex` challenges, a `TranscriptRng` that
  exercises KEY, and a 500-octet challenge;
- `merlin.py` must match those outputs, pinned and live.

The `equivalence_simple` challenge is
`d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615`. Keccak-f[1600] is checked
separately: SHA3-256, SHA3-512, SHAKE128 and SHAKE256 built on it must equal `hashlib`.

## Independence

- No `.java` file was read.
- ZeroJ's existing Bulletproof Python (`../bulletproof_range_reference.py`) was not read.
- `../README.md` was read, as the coordinator allowed; it contains no code.
- The protocol algebra was written from the paper and the spec.
- Read from the repository:
  - the spec;
  - ADR-0061 D2, D3, D4, D5, the M2 row and the verification strategy;
  - the curve module, for its API (`point_add`, `scalar_mul`, `compress`, `strict_decode`,
    `derive_basis`, `i2osp`, `os2ip`);
  - `generators-v1.json`;
  - the Pedersen spec's pinned `G` and `H`;
  - the CFRG SHAKE128 vector file.
- The dalek binding was written from the crate source, which is the oracle and may be read.
- The known-answer values (commitment, session id, challenges, the full proof hex) came from the
  coordinator, with the spec/ADR as their source. They are literals in `run_dalek_check.py`.

## Deviations of dalek 5.0.0 from `bulletproof-range-bls12-381-g1-v1`

| # | Item | dalek 5.0.0 | This spec |
|---|---|---|---|
| 1 | Group | ristretto255, order `l ≈ 2^252`, 32-octet encodings; prime order by construction | BLS12-381 G1, order `q ≈ 2^255`, 48-octet compressed points, strict decoder with an explicit subgroup check |
| 2 | Pedersen bases | `B` = ristretto255 base point; `B_blinding = from_uniform_bytes(SHA3-512(encode(B)))` | `G`, `H` = RFC 9380 `hash_to_curve` under `DST_B` (`pedersen-bls12-381-g1-basis-v1`) |
| 3 | Vector generators | One SHAKE256 chain per vector: `SHAKE256("GeneratorsChain" ‖ "G"‖LE32(party))`, each 64 output octets → `from_uniform_bytes` (Elligator twice) | Per-index `hash_to_curve("G" ‖ I2OSP(i, 4), DST_BP)`; big-endian index; pinned encodings and `D_gens` |
| 4 | Inner-product element | `Q = w·B`: the **value base** scaled by a transcript challenge `w` | An **independent** generator `U` (paper Protocol 1), scaled by `x_u`. Paper (105) as printed also uses the value base (spec §8.3 states this) |
| 5 | Transcript construction | Merlin (STROBE-128 on Keccak-f[1600], rate 166); labelled, length-prefixed messages; caller-chosen initial label | fiat-shamir-03 XOF duplex sponge on SHAKE128 (rate 168); no labels; session id from a tag |
| 6 | Statement binding | `dom-sep "rangeproof v1"`, `n` (u64 LE), `m`, then `V`. **No binding of the generators or of `B`, `B_blinding`**; the application context is only the caller's label | The tag binds the protocol, the ciphersuite, `n`, `k` and `ctx` (1–1,024 octets). The instance binds the profile id, `G`, `H`, the generator-set id, `D_gens`, `n` and `V` |
| 7 | Labels and order | `A`,`S` → `y`,`z`; `T_1`,`T_2` → `x`; `t_x`,`t_x_blinding`,`e_blinding` → `w`; `dom-sep "ipp v1"` and `n`; then per round `L`,`R` → `u` | The same order of messages and challenges, with no labels and no IPA separator; `x_u` takes the place of `w` |
| 8 | Challenge derivation | `challenge_scalar`: 64 PRF octets, little-endian, wide reduction mod `l` | `DecodeField`: 48 squeezed octets, little-endian, mod `q` |
| 9 | Scalar encoding | 32 octets **little-endian**; canonical (`< l`, top bit clear) | 32 octets **big-endian**; canonical (`< q`) |
| 10 | Identity points | Proof points: `validate_and_append_point` rejects the identity encoding (`A`, `S`, `T_1`, `T_2`, `L_j`, `R_j`). `V`: **accepted** (`append_point`; a comment allows `v = 0`, `γ = 0`) | Every proof point and `V = O` are rejected (`V = O` → `false`) |
| 11 | Zero challenges | Not rejected by the verifier (the prover refuses `x = 0`) | Any zero challenge → `false`; the prover restarts |
| 12 | Verification | **One** multi-scalar multiplication: the two equations merged with a random weight `c = Scalar::random(rng)`, so the computation is randomized | **Two** separate checks (98) and (105), deterministic (ADR-0061 D5) |
| 13 | Decoding | `from_bytes`: length a multiple of 32, at least 7·32, canonical scalars, IPA element count even; points decompressed lazily at verification; `n` against `lg n` checked in `verification_scalars` | Exact length first, then the fields in proof order (strict), then `V`; error classes (§8.1) |
| 14 | Widths and aggregation | `n ∈ {8, 16, 32, 64}`; aggregation `m` a power of two | `n ∈ {16, 32, 64}`; single value only |
| 15 | Proof layout | `A S T_1 T_2 t_x t_x_blinding e_blinding (L R)^k a b`, `32·(9 + 2k)` octets | The same field order, `48·(4 + 2k) + 32·5` octets |
| 16 | `s_i` | Computed inductively, from challenges in creation order | The closed-form most-significant-bit-first rule (§8.3). Direction 1 confirms the two are the same |
| 17 | Sign convention | The merged check is the negation of the spec's form (coefficient `+1` on `A`) | Spec §8.3 form; algebraically the same |
| 18 | Prover randomness | Caller's `RngCore + CryptoRng` (default `thread_rng`); draw order `a_blinding`, `s_blinding`, `s_L`, `s_R`, `t_1`, `t_2`; `A` built with constant-time selects | Own `SecureRandom` (§7.3); the same draw order (§7.5 for test nonces); `A` built as a full sum over `2n` generators (§7.4) |

How the generic code handles 10–12:
- **Separate checks.** The generic verifier always evaluates the two checks separately (row 12),
  with both bindings.
- **Zero challenges.** It always rejects a zero challenge (row 11). Against dalek this differs
  only with probability about `2^−252`.
- **Identity `V`.** It allows an identity `V` only when the binding sets
  `allow_identity_commitment`: the dalek binding does (row 10), and the spec binding does not.

## Running

Python 3.13 (3.13.5 was used), standard library only, in isolated mode. The scripts insert their
own directory into `sys.path`, which `-I` drops.

```bash
# build the harness (crates from the local cargo registry; Cargo.lock pins checksums)
cd dalek-harness && cargo build --release --offline --locked && cd ..

# the M2 gate: everything, harness required
python3 -I -B run_dalek_check.py --self-test --require-harness \
    [--rfc9496 /path/to/rfc9496.txt] \
    [--dalek-src ~/.cargo/registry/src/index.crates.io-*/bulletproofs-5.0.0]

# without the harness, direction 2 and the live comparisons are SKIP lines (not passes)
python3 -I -B run_dalek_check.py --self-test

python3 -I -B ristretto255.py --self-test [--rfc9496 PATH]
python3 -I -B run_dalek_check.py --regenerate --harness PATH --dalek-src DIR   # rewrites the pinned JSON
```

Options:
- `--harness PATH`, default `dalek-harness/target/release/zeroj-dalek-harness`.
- `--resources DIR`, the `zeroj-bls12381/src/test/resources` directory; by default it is found
  relative to this file.
- `--cfrg-dir DIR` and `--spec PATH`, default to their repository locations.

The run exits non-zero on any FAIL. Every unexpected exception is a counted FAIL.

## Results (2026-10-25, macOS, cargo 1.97.0, rustc 1.97.0, Python 3.13.5)

`--self-test --require-harness --rfc9496 … --dalek-src …`: **85 passed, 0 failed, 0 skipped**,
in about 60–75 s. The BLS12-381 section takes about 48 s of that, because the curve module uses
affine arithmetic with Fermat inversion. The run covers:

- **Generic core:** the import and name isolation checks.
- **ristretto255:**
  - the constants, checked against their defining relations;
  - the RFC 9496 file hash and the re-parse of its appendix;
  - A.1, all 16 generator multiples (encode, add, decode, scalar multiplication);
  - A.2, all 29 invalid encodings, each rejected at the rule its RFC group names;
  - A.3, all 7 element-derivation vectors and the 4 same-output inputs;
  - A.4, all 6 SQRT_RATIO_M1 vectors;
  - the canonical-scalar check.
- **Keccak and Merlin:**
  - Keccak-f[1600] against `hashlib`;
  - the Merlin sequences against merlin 3.0.0, both pinned and live.
- **dalek generators:** `B`, `B_blinding` and `G_0 … G_63` equal dalek's, pinned and live.
- **Direction 1:**
  - The published proofs at `n = 8, 16, 32, 64` (`proofs[i][0]`, `vc[0]`, label
    `"Deserialize-And-Verify Test"`) are accepted. Check 1 and check 2 each hold, and the
    recursive Protocol 1/2 cross-check holds.
  - 20, 22, 24 and 25 tampered copies per width are all rejected:
    - one bit flipped in each field;
    - the wrong `V`;
    - the wrong label;
    - truncated;
    - verified at `2n`;
    - `L_1` and `R_1` swapped.
  - The 8 proofs that dalek's own prover made are accepted, and their live regeneration matches.
- **Direction 2:**
  - The 16 honest generic-prover proofs (`n = 8, 16, 32, 64`; `v = 0`, `1`, `2^n − 1` and one
    other value) and the control are all accepted by dalek 5.0.0 `verify_single`.
  - All **182** tampered proofs are rejected:
    - a bit flip in each field;
    - `a + 1`;
    - `V + B`;
    - another label;
    - another `n`;
    - truncated.
  - The case file regenerates byte for byte.
- **fiat-shamir-03 sponge:** the vector file's hash, and B.2.1–B.2.11 on `bls_binding.DuplexSponge`.
- **BLS12-381 tie-in:**
  - `D_gens` and the `G`, `H` pins;
  - the spec Appendix A table equals `generators-v1.json`;
  - the tag, the session id (`aefa01ae…7556`), `V`, the 244-octet instance and all eight
    challenges are reproduced;
  - **the 736-octet proof (`adad082dfddd9ed6…88f086`) is reproduced byte for byte**;
  - the proof verifies, and the recursive cross-check holds;
  - four tampers are rejected at their expected layers: `t̂` (check 1), `a` (check 2), `ctx`, and
    `n = 32` (length).

**Mutation check (scratch only, not committed).** Seven single-line mutations were made to the
generic core, and the full self-test was run on each. Every one failed:

| Mutation | FAILs (direction 1 / direction 2 / BLS) |
|---|---|
| LSB-first `s_i` | 12 / 1 / 1 |
| `δ` sign flipped | 12 / 1 / 2 |
| check 2 `H_i` coefficient `+z` | 12 / 1 / 1 |
| prover fold of `a⃗` with `x_j`, `x_j⁻¹` swapped | 0 / 3 / 3 |
| check 1 `V` coefficient `−z` | 12 / 1 / 2 |
| prover `r₀` with `z` for `z²` | 0 / 3 / 3 |
| prover `h'_i = [yⁱ]·H_i` | 0 / 3 / 3 |

The three prover mutations show that the external check works. Under each of them, dalek 5.0.0
rejected every honest proof and accepted 1/17: the control only.
