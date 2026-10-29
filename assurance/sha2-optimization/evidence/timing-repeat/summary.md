# SHA-2 optimization comparison

All timings are diagnostic measurements of this host; negative reductions mean regressions.
Heap limits are JVM `-Xmx`, not total-process memory limits. RSS includes native/off-heap memory.

| Profile | Constraints, before → after | Prove median ms, before → after | Prove change |
|---|---:|---:|---:|
| 8g/pure-java/sha512-128 | 215,913 → 132,569 | 5293.72 → 4778.57 | 9.73% reduction |

Complete compile/witness/setup/verification, term, domain, key and memory comparisons are in `summary.json`.
Independent snarkjs checks are separate; a successful benchmark does not imply that they ran.
