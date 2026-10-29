# SHA-2 circuit interoperability assurance

Optional, standalone assurance for [ADR-0063](../../docs/adr/0063-sha256-gadget-and-sha2-assurance.md)
and [issue #111](https://github.com/bloxbean/zeroj/issues/111). It compares the actual
ZeroJ `Sha256` / `Sha512` byte and bit APIs with established Circom implementations,
using the complete standard digest. It is outside the default Gradle build and all
published runtime artifacts.

## Run

Requirements: the repository's Java 25/Gradle environment, Python 3.11+, Node.js 18+,
npm, Git, curl and **Circom 2.2.3** on `PATH`. Set `CIRCOM` to another executable path
if necessary; its version must still match. No developer-specific paths are embedded.

From the repository root:

```sh
bash assurance/sha2-circom/bootstrap.sh
python3 assurance/sha2-circom/run.py all
```

For scheduled/shared-host runs, the equivalent phases are:

```sh
python3 assurance/sha2-circom/run.py export
python3 assurance/sha2-circom/run.py check
```

The first phase prepares the fixtures and invokes the Gradle wrapper with the explicit
`-I assurance/sha2-circom/export.gradle` init script. Only that invocation adds an
unpublished `sha2Assurance` source set and export task to `zeroj-circuit-lib`. It reuses
the existing integration-test `WitnessExporter`, source compilers and dependencies.
Ordinary `./gradlew build` does not run this lane, download Node dependencies, or compile
the assurance source. Run one export/check job at a time and finish source edits first;
the checker rejects exports whose gadget/compiler/fixture hashes changed.

`bootstrap.sh` fetches and verifies exact dependency commits and uses `npm ci` with the
committed lockfile. It also downloads the official NIST ZIP, checks its pinned SHA-256
and checks all selected messages/digests against their original response-file entries.
An unexpected upstream hash fails; pins are never silently updated.

## Checks

- 21 selected official NIST CAVP vectors, including empty messages and both algorithms'
  padding boundaries; expected digests are unchanged published values.
- Four additional ascending-byte profiles: SHA-256/SHA-512 at 32 and 128 bytes.
- JCA and Python `hashlib` independently agree with all expected full digests.
- For each of the 25 messages, compile ZeroJ's **byte and bit APIs** into R1CS and export
  their actual witnesses. Compile the corresponding Circom byte circuit with
  `--prime bls12381 --O2`. The independent snarkjs checker must accept **all 75**
  compiled relations. Digest limbs and private message values are also checked directly
  in the exported witnesses, including Circom's `.sym` wire mapping.
- The statement exposes two SHA-256 / four SHA-512 consecutive big-endian 128-bit limbs.
  Every digest bit is retained, without reduction of the full digest modulo the field.
- For each 32/128-byte profile, mutate every public limb and the first private input
  directly in the binary witnesses, bypassing witness-generation assertions. Non-Boolean
  bit values (`2` and `Fr-1`) and invalid byte values (`256` and `Fr-1`) must fail the
  actual relation. This produces **60 compiled-witness rejection checks** across the
  three circuit paths. Circom O2 can eliminate a byte and some of its decomposition
  bits. The harness reconstructs their values with the compiler's exact
  [affine substitution map](https://docs.circom.io/circom-language/formats/simplification-json/),
  including nested substitutions, and checks every byte and all eight Boolean bits.
  When the byte is eliminated, mutations target a retained decomposition bit. The
  `.sym` sentinel `-1` is never treated as a witness wire. Results hash the substitution
  map and label which kind of input was mutated.
- Circom witness calculation must also reject `256` and `-1` input bytes for each of the
  four profiles: **eight additional generator checks**. A generic process crash is not
  accepted as rejection: expected constraint-failure text and exit status are required.

This bounded mutation set is not an exhaustive search for malicious witnesses. The
default Java gadget tests add further output/intermediate/carry checks. Passing NIST
vectors is not CAVP validation, formal circuit soundness or an independent audit.

## Outputs and measurements

The [retained 2026-10-29 result](evidence/2026-10-29.json) passed all **75 positive
R1CS checks**, **60 compiled-witness rejection checks** and **eight invalid-input
generator checks** across 25 messages. It records the exact tested working-tree
source hashes, dependency pins, per-case relation identities and adversarial checks.

The four fixed-message profiles produced these constraint counts over BLS12-381:

| Hash | Message bytes | Public 128-bit digest limbs | ZeroJ byte API | ZeroJ bit API | Circom O2 |
|---|---:|---:|---:|---:|---:|
| SHA-256 | 32 | 2 | 42,694 | 42,662 | 29,636 |
| SHA-256 | 128 | 2 | 130,219 | 130,091 | 90,633 |
| SHA-512 | 32 | 4 | 106,332 | 106,300 | 74,952 |
| SHA-512 | 128 | 4 | 215,913 | 215,785 | 152,453 |

All rows bind the entire standard digest. These counts reflect different circuit
shapes and compiler backends; they establish circuit cost, not a proof-time ranking.

Generated material stays under ignored `build/`: exported R1CS/WTNS, compiled WASM,
individual command logs, append-only `commands.jsonl`, dependency checkouts and
`result.json`. Witnesses are intentionally public fixtures; this runner is not a
production service for private documents. The result records gadget/compiler hashes,
dependency pins, full digests, constraint/wire counts and individual check outcomes.

ZeroJ compile and witness times are one-shot in-process diagnostics. Circom compile and
witness times include process startup and file I/O. They can run on a shared host, have
different circuit shapes, and do not establish an isolated speed ranking. There are no
wall-clock assertions. This lane does **not** perform trusted setup, prove Groth16,
submit ledger transactions or measure fees; those are distinct integration tests.

## Independent sources and licenses

| Dependency | Exact version/revision | Scope |
|---|---|---|
| [Circom](https://github.com/iden3/circom) | 2.2.3 | External compiler on PATH |
| [snarkjs](https://github.com/iden3/snarkjs) | 0.7.6 | Locked optional npm dependency |
| [circomlib](https://github.com/iden3/circomlib/tree/35e54ea21da3e8762557234298dbb553c175ea8d) | `35e54ea21da3e8762557234298dbb553c175ea8d` | SHA-256, byte decomposition and SHA-512 helper dependencies |
| [Electron-Labs SHA-512](https://github.com/Electron-Labs/sha512/tree/be9f01d870c40c3fe4e0ff27c93232d205bc46f7) | `be9f01d870c40c3fe4e0ff27c93232d205bc46f7` | SHA-512 circuit |
| [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) | ZIP SHA-256 `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8` | Published expected-message/digest pairs |

Circom, circomlib and snarkjs carry GPL-3.0 licensing. Electron-Labs SHA-512 declares
GPL-3.0, with inherited files carrying GPL-3.0-or-later notices. The optional downloaded
sources retain their upstream notices; they are not copied into the Java runtime
implementation or bundled in its artifact. Reuse/distribution of those dependencies
must follow their own licenses. The NIST fixture source/provenance is documented in
the [standard-vector directory](../../zeroj-circuit-lib/src/test/resources/standard-vectors/README.md).
