# Independent references for zeroj-bls12381 (ADR-0062 D9)

Public test references. They are not constant-time and must not handle real secrets.

| File | Produces | Independence |
|---|---|---|
| `fp12_tower_reference.py` | `fp12_tower_vectors.json`: Fp6/Fp12 `mul`, `square`, `inv` | Models Fp12 as `Fp[w]/(w^12 − 2w^6 + 2)` with schoolbook arithmetic and Fermat inversion; shares no formula with the Java tower. Standard library only. |
| `pyecc_gt_kat.py` | the GT values in `BLS12381PairingAdversarialTest` | py_ecc 8.0.0 (pinned); the script maps py_ecc's orientation (ZeroJ = py_ecc⁻¹) and basis to ZeroJ's layout. |
| `xof_oversize_dst_kat.py` | the oversize-DST known answers in `Bls12381HashToCurveTest` | RFC 9380 §5.3.2 `expand_message_xof` with SHAKE256 and the §5.3.3 reduction (`k = 128`, 32-byte reduced DST), written from the RFC with `hashlib`; shares no code with `Bls12381Hash`. Standard library only. |

Regenerate:

```bash
python3 -I fp12_tower_reference.py > fp12_tower_vectors.json
python3 -I xof_oversize_dst_kat.py
python3 -m venv venv && venv/bin/pip install py_ecc==8.0.0 && venv/bin/python -I pyecc_gt_kat.py
```

The py_ecc `e(G1, G2)` output equals the self-pinned vector in `BLS12381PairingTest` and the
ffjavascript-corroborated one in `zeroj-crypto` (`ExternalPairingKatTest`).
