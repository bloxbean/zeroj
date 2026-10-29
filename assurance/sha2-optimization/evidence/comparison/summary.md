# SHA-2 optimization comparison

All timings are diagnostic measurements of this host; negative reductions mean regressions.
Heap limits are JVM `-Xmx`, not total-process memory limits. RSS includes native/off-heap memory.

| Profile | Constraints, before → after | Prove median ms, before → after | Prove change |
|---|---:|---:|---:|
| 6g/pure-java/sha256-1024 | 749,691 → 456,915 | 11315.97 → 8408.12 | 25.70% reduction |
| 6g/pure-java/sha256-128 | 130,219 → 79,027 | 3804.67 → 3374.95 | 11.29% reduction |
| 6g/pure-java/sha256-32 | 42,694 → 25,758 | 1496.97 → 1151.33 | 23.09% reduction |
| 6g/pure-java/sha512-1024 | 989,329 → 610,249 | 14995.51 → 12529.80 | 16.44% reduction |
| 6g/pure-java/sha512-128 | 215,913 → 132,569 | 5985.41 → 3945.32 | 34.08% reduction |
| 6g/pure-java/sha512-32 | 106,332 → 64,980 | 3273.07 → 1554.08 | 52.52% reduction |
| 8g/pure-java/sha256-1024 | 749,691 → 456,915 | 11508.92 → 10685.77 | 7.15% reduction |
| 8g/pure-java/sha256-128 | 130,219 → 79,027 | 3968.90 → 2910.45 | 26.67% reduction |
| 8g/pure-java/sha256-32 | 42,694 → 25,758 | 1440.60 → 1107.46 | 23.13% reduction |
| 8g/pure-java/sha512-1024 | 989,329 → 610,249 | 12200.07 → 11320.24 | 7.21% reduction |
| 8g/pure-java/sha512-128 | 215,913 → 132,569 | 5316.37 → 5627.99 | -5.86% reduction |
| 8g/pure-java/sha512-32 | 106,332 → 64,980 | 3429.12 → 1912.77 | 44.22% reduction |

Complete compile/witness/setup/verification, term, domain, key and memory comparisons are in `summary.json`.
Independent snarkjs checks are separate; a successful benchmark does not imply that they ran.
