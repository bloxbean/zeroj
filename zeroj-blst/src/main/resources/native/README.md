# Bundled libblst — provenance

These `libblst.{so,dylib}` binaries are **temporary, for validating the FFM binding only**
(ADR-0029 M6 / Rung B). They were lifted from the old (2023) `foundation.icon:blst-java:0.3.2`
jar. The raw `blst_*` C symbols they export are stable, so they correctly validate
`BlstG1Msm` / `blst_p1s_mult_pippenger` and its ~2.5–3.8× MSM speedup.

**Do NOT ship these for release.** Before `zeroj-blst` is published as a standalone dependency:

1. Replace with a **current `libblst`** — either blst's official release binaries, or (preferred)
   **built from source in a CI matrix** (Linux/Mac/Windows × x86_64/aarch64), assembled into one
   all-platform jar. This gives release-grade supply-chain provenance and Windows/aarch64 coverage.
2. The FFM binding (`BlstFfm`, `BlstG1Msm`, …) is **unchanged** by the binary version — only these
   files get swapped.

Layout: `native/<os>/<arch>/libblst.<ext>` where `<os>` ∈ {linux, mac, windows},
`<arch>` ∈ {amd64, x86_64, aarch64}.
