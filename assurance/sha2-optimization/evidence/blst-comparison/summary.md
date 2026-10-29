# SHA-2 optimization comparison

All timings are diagnostic measurements of this host; negative reductions mean regressions.
Heap limits are JVM `-Xmx`, not total-process memory limits. RSS includes native/off-heap memory.

| Profile | Constraints, before → after | Prove median ms, before → after | Prove change |
|---|---:|---:|---:|
| 6g/blst/sha256-128 | 130,219 → 79,027 | 740.73 → 615.53 | 16.90% reduction |
| 6g/blst/sha256-32 | 42,694 → 25,758 | 425.30 → 438.92 | -3.20% reduction |
| 6g/blst/sha512-128 | 215,913 → 132,569 | 1814.28 → 1494.61 | 17.62% reduction |
| 6g/blst/sha512-32 | 106,332 → 64,980 | 649.11 → 461.66 | 28.88% reduction |
| 8g/blst/sha256-128 | 130,219 → 79,027 | 814.10 → 662.71 | 18.60% reduction |
| 8g/blst/sha256-32 | 42,694 → 25,758 | 426.43 → 337.13 | 20.94% reduction |
| 8g/blst/sha512-128 | 215,913 → 132,569 | 1843.14 → 1775.97 | 3.64% reduction |
| 8g/blst/sha512-32 | 106,332 → 64,980 | 657.50 → 643.39 | 2.15% reduction |

Complete compile/witness/setup/verification, term, domain, key and memory comparisons are in `summary.json`.
Independent snarkjs checks are separate; a successful benchmark does not imply that they ran.
