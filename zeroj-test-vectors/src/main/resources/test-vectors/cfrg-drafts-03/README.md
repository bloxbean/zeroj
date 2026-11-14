# CFRG Fiat–Shamir and sigma-protocol test vectors (`-03` drafts)

These are the official test vectors of two IRTF CFRG Internet-Drafts, copied unchanged from
the drafts' repository, https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols (commit
`91cc933`, `poc/vectors/`). ADR-0061 (`bulletproof-range-bls12-381-g1-v1`, invariant
I12) uses them to check ZeroJ's transcript layer: the SHAKE128 duplex sponge, its codecs, and the
`sigma-proofs_Shake128_BLS12381` encodings.

| Draft | Date | Appendix |
|---|---|---|
| `draft-irtf-cfrg-fiat-shamir-03` | 2026-08-17 | B (test vectors) |
| `draft-irtf-cfrg-sigma-protocols-03` | 2026-08-17 | A.3 (`sigma-proofs_Shake128_BLS12381`) |

## Provenance

- **Source:** `https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols`, files
  `poc/vectors/*.json`.
- **Pinned commit:** `91cc933051af88b58e350af78a8ea961c56a30c6` (2026-08-17). The tags
  `draft-irtf-cfrg-fiat-shamir-03` and `draft-irtf-cfrg-sigma-protocols-03` both point to it.
- **Check against the drafts:** on 2026-10-24 the JSON records were compared with the Key = Value
  vectors in the `-03` text appendices. They carry the same records (same identifiers and
  values), so the JSON is used in place of parsing the text.

| File | SHA-256 |
|---|---|
| `fiatShamirCodecVectors.json` | `97d85f96e252111fd01e4147d9ebc48c80203e5783fef1eea2204211d847c821` |
| `fiatShamirShake128Vectors.json` | `f04cdf455b60239d20392813ffd5dd8d079fb1c0d5b0e07de3e50899bd6f6502` |
| `sigma-proofs_Shake128_BLS12381.json` | `e9f942c2d76f2086793b771fbb32cc8452e51dcf274cf163258d36b8d9906e94` |
| `sigma-proofs-invalid_Shake128_BLS12381.json` | `1da51dc890c0d9fe550d14c9f0f71c5175c5c5b6c6a698ef53074bb4c58bc740` |

Only these four files are included. The drafts also have TurboSHAKE128 and P-256 vectors, which
ADR-0061 does not use. Which vectors are in scope is set in
`docs/specs/bulletproof-range-bls12-381-g1-v1.md` §10.

## Licence

The vectors are not ZeroJ's work. They come from IETF documents, which are subject to BCP 78 and
the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info).
The source repository's `LICENSE.md` refers to its `CONTRIBUTING.md`, which places all its
material under BCP 78, BCP 79 and those provisions. See [`NOTICE`](NOTICE) in this directory for
the full notice, the credits and the links.

They are included as test data only. `zeroj-test-vectors` is never published (root `build.gradle`,
`nonPublishable`), so the files are in the source repository but in no ZeroJ release artifact.
