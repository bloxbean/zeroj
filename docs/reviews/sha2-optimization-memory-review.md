# SHA-512 memory follow-up review

Date: 2026-10-29. Scope: the pure-Java SHA-512/1,024-byte profile in PR #112.
This independent review inspected completed benchmark records and GC logs; it did
not launch another workload or change the implementation/harness.
The raw optimization outputs remain local and ignored, not tracked in Git. This
report records the inspected values and their limits. See the
[comparison harness](../../assurance/sha2-optimization/README.md) and the
[results report's repeat controls](sha2-optimization-results.md#reproducing-local-outputs)
to generate fresh local measurements.

## Observed trade-off

The candidate passed at both heap limits, but lower peak memory is **not** a
universal outcome. The primary 6 GiB case increased sampled heap by 88.5% and RSS
by 52.9%. A separate 6 GiB repeat, with baseline running first instead of second,
still increased them by 8.3% and 4.2%. The 8 GiB primary case decreased both.
All results must remain visible; the repeat does not replace the original result.

| Run | Sampled heap, baseline → candidate (GiB) | Peak RSS, baseline → candidate (GiB) | Median proof, baseline → candidate (s) |
|---|---:|---:|---:|
| Primary, `-Xmx6g` | 2.161 → 4.072 | 2.827 → 4.323 | 14.996 → 12.530 |
| Diagnostic repeat, `-Xmx6g` | 3.657 → 3.961 | 4.361 → 4.545 | 12.369 → 11.021 |
| Primary, `-Xmx8g` | 5.314 → 4.162 | 5.934 → 4.469 | 12.200 → 11.320 |

The repeat's local baseline/candidate `result.json` records were checked alongside
their `process.json` RSS records. Each reported the actual 6,442,450,944-byte maximum
heap and eight visible processors. The measurements above remain shared-host
diagnostics, not a general speed or memory guarantee. Heap sampling can miss brief
peaks; RSS also includes non-heap memory and resident mapped-key pages.

## What the GC logs establish

Both repeat JVMs used G1, 4 MiB regions, a 2 GiB initial heap and a 6 GiB maximum.
Values below were parsed from completed pause records in the local baseline and
candidate GC logs. Those raw logs are not published in the repository.
The logs' `M` units are MiB and are rounded, unlike the byte-valued sampler.

| GC-log observation | Baseline | Candidate |
|---|---:|---:|
| Young collection pauses, including mixed/start variants | 93 | 68 |
| Sum of young pause durations (ms) | 752.055 | 641.782 |
| Median occupancy immediately after a young pause (MiB) | 1,120 | 825.5 |
| Maximum occupancy immediately after a young pause (MiB) | 1,439 | 1,500 |
| Last young pause, before → after (MiB) | 3,801 → 1,262 | 3,905 → 1,445 |
| Maximum occupancy before a young pause (MiB) | 3,801 | 4,112 |
| Final committed heap (MiB) | 3,996 | 4,360 |
| Completed concurrent mark cycles | 1 | 0 |
| Mixed collection pauses | 1 | 0 |

Young pauses repeatedly reclaim large amounts of transient allocation. Summing
their rounded before-minus-after occupancy gives 141,817 MiB for baseline and
108,006 MiB for candidate. This is repeated heap turnover, **not** an exact total
of allocated bytes: concurrent reclamation, allocations outside those intervals
and rounding are not accounted for. Whole-process log totals also need not equal
MXBean deltas sampled after harness initialization.

The candidate's final ordinary-old-region count is lower, 194 versus 246, while its
humongous-region count is higher, 129 versus 47. The baseline's last young pause
reclaims 106 humongous regions; the candidate's last pause reclaims none. Baseline
also completed a concurrent mark/mixed cycle that candidate did not. Reclamation
and heap-sizing behavior therefore differ visibly. Neither log contains a full
collection, evacuation failure or to-space-exhaustion event.

These post-young occupancies are **not fully collected live-object measurements**.
Old-generation garbage may remain, and the pauses are not matched phase checkpoints.
The candidate's higher final occupancy cannot establish a larger retained relation
or a leak; its lower median cannot establish the opposite. The logs show GC behavior
consistent with the variable peak results, but do not prove the root cause.

## Source interpretation and disposition

Known retained relation dimensions shrink: rows 989,329 → 610,249, wires
3,196,464 → 2,334,600, and sparse terms 4,679,273 → 3,635,963. The CSR integer-array
payload falls from 49,306,144 to 36,410,704 bytes, excluding array headers and the
coefficient dictionary. Key-store files shrink from 369,567,626 to 274,469,130 bytes.
Both versions retain the same 2^20 FFT domain, so domain-sized buffers do not shrink.

The benchmark uses the list-compatible proving API. `R1CSFlat.asList()` creates
temporary row maps on access; validation/evaluation traverse that view, and the H
polynomial is boxed before packing for MSM. Those maps are not cached. Compiler
expression maps are local and removed on their last use; setup's wire-sized scalar
arrays become smaller. This identifies substantial temporary-allocation paths,
but is not a measured allocation profile or a complete retained-heap inventory.

No strong signal of unbounded retained growth or memory exhaustion warrants an
additional forced-GC/JFR campaign for this bounded PR. The cause remains unresolved
beyond the observed GC behavior. Report the measured memory regressions honestly;
do not claim that the optimization preserves or improves every performance metric.
A future memory investigation should use comparable phase checkpoints and live
heap/allocation profiles, separately from ordinary timing measurements.
