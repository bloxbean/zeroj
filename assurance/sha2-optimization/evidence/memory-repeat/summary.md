# SHA-2 optimization comparison

All timings are diagnostic measurements of this host; negative reductions mean regressions.
Heap limits are JVM `-Xmx`, not total-process memory limits. RSS includes native/off-heap memory.

| Profile | Constraints, before → after | Prove median ms, before → after | Prove change |
|---|---:|---:|---:|
| 6g/pure-java/sha512-1024 | 989,329 → 610,249 | 12369.50 → 11020.79 | 10.90% reduction |

Complete compile/witness/setup/verification, term, domain, key and memory comparisons are in `summary.json`.
Independent snarkjs checks are separate; a successful benchmark does not imply that they ran.
