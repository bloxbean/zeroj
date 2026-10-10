# Standard test vectors (third-party, vendored)

These are published test vectors, used unchanged as known-answer and negative tests by the
`dkg-share-delivery-hpke-v1` (ADR-0054) and `confidential-note-jubjub-v1` (ADR-0055)
implementations. None of their values were produced by ZeroJ code. They were fetched on
2026-10-09.

| File | Source | Pinned revision | SHA-256 of the fetched source file | Licence |
|---|---|---|---|---|
| `hpke-x25519-sha256-chacha20poly1305-base.json` | `test-vectors.json` of [cfrg/draft-irtf-cfrg-hpke](https://github.com/cfrg/draft-irtf-cfrg-hpke): the RFC 9180 Appendix A test vectors in full. **Filtered** to the single vector with `mode = 0`, `kem_id = 32`, `kdf_id = 1`, `aead_id = 3`, and re-serialized as JSON with every value unchanged. That is RFC 9180 Appendix A.2.1, including all 257 encryptions (sequence numbers 0–256) and the exported values. | commit `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb` | `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` (unfiltered `test-vectors.json`) | Published with RFC 9180 (IETF Trust Legal Provisions, BCP 78) |
| `wycheproof-x25519_test.json` | `testvectors_v1/x25519_test.json` of [C2SP/wycheproof](https://github.com/C2SP/wycheproof) (518 tests: RFC 7748 vectors, small-order points, non-canonical and twist inputs) | commit `12fd3aaf33eb5fa1f52e026912ee00c054f9d984` | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` | Apache-2.0 |
| `wycheproof-chacha20_poly1305_test.json` | `testvectors_v1/chacha20_poly1305_test.json` of C2SP/wycheproof (325 tests) | same commit | `fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d` | Apache-2.0 |
| `wycheproof-hkdf_sha256_test.json` | `testvectors_v1/hkdf_sha256_test.json` of C2SP/wycheproof (86 tests) | same commit | `bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e` | Apache-2.0 |
| `zcash-sapling-note-encryption.json` | `test-vectors/json/sapling_note_encryption.json` of [zcash/zcash-test-vectors](https://github.com/zcash/zcash-test-vectors): 10 Sapling note-encryption vectors (Sapling key agreement, `KDF^Sapling`, ChaCha20-Poly1305 with the zero nonce). Used with the Zcash personalization for conformance only (ADR-0055 I10). | commit `78321beacb0e0477e33cd002b56585a107c2708c` | `dda3bed301e90915c2bf35209307d6c9e2d0de103a7ca93e5d15a2c00729f294` | MIT or Apache-2.0, at the user's option |

The Wycheproof and Zcash files are copied byte for byte. Their SHA-256 values match the table.

Wycheproof is Copyright Google LLC and contributors, under the Apache License, Version 2.0.
zcash-test-vectors is licensed under either the Apache License, Version 2.0, or the MIT
licence, at the user's option (its `COPYING.md` at the pinned commit).

The RFC vectors quoted directly in tests are:
- RFC 7748 §5.2 and §6.1;
- RFC 8439 §2.8.2;
- RFC 5869 Appendix A.1–A.3.

Each test cites the section it quotes.
