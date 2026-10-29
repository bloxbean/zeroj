# RFC 9380 test vectors (machine-extracted)

ADR-0062 D9. Every value here is copied from the RFC text by `extract_rfc9380.py`; nothing is
computed, so the vectors are independent of the code under test.

| File | RFC 9380 | Content |
|---|---|---|
| `j9_1_bls12381g1_xmd_sha256_sswu_ro.json` | J.9.1 | 5 messages: `u[0]`, `u[1]`, `Q0`, `Q1`, `P` |
| `j9_2_bls12381g1_xmd_sha256_sswu_nu.json` | J.9.2 | 5 messages: `u[0]`, `Q`, `P` |
| `j10_1_bls12381g2_xmd_sha256_sswu_ro.json` | J.10.1 | 5 messages: `u[0]`, `u[1]`, `Q0`, `Q1`, `P` (Fp2 values are `[c0, c1]`) |
| `j10_2_bls12381g2_xmd_sha256_sswu_nu.json` | J.10.2 | 5 messages: `u[0]`, `Q`, `P` |
| `k1_expand_message_xmd_sha256.json` | K.1 | 10 vectors |
| `k2_expand_message_xmd_sha256_long_dst.json` | K.2 | 10 vectors, 256-octet DST |
| `k6_expand_message_xof_shake256.json` | K.6 | 10 vectors |

Regenerate:

```bash
curl -sSfL -o rfc9380.txt https://www.rfc-editor.org/rfc/rfc9380.txt
# extracted from rfc9380.txt with SHA-256
# a2e6ab02b2117d6f52ac293020857752972b2e23ae005c33f612e40436ff4b6d
python3 -I extract_rfc9380.py rfc9380.txt .
```

RFC 9380 has no BLS12-381 hash-to-curve suite over `expand_message_xof`; the XOF variants are
covered by the CFRG BBS fixtures in `zeroj-bbs`. Licence: see `NOTICE`.
